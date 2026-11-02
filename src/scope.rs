//! SPDX-License-Identifier: GPL-3.0-or-later
//! Capture scope. The BPF side observes nothing until a filter is
//! installed — scope is always explicit, and system-wide capture requires
//! the explicit system scope, never a missing filter.

use crate::attach::{CapturePolicy, Scope};
use anyhow::{Context as _, Result, bail};
use aya::Ebpf;
use aya::maps::{Array, CgroupArray, HashMap};
use p11scope_ebpf_common::{
    CFG_FLAGS, FLAG_CGROUP_FILTER, FLAG_PAUSE_ENABLED, FLAG_PID_FILTER, FLAG_POLICY_INVENTORY,
    FLAG_SYSTEM_FILTER, FLAG_TRACK_SHORT_LIVED, valid_config, valid_inventory_config,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::path::Path;
use std::sync::Arc;

// The bounded inventory collector is wired by the cgroup integration packages.
#[allow(dead_code)]
pub(crate) mod inventory_cgroup;

/// Opens and retains a cgroup directory for userspace walking and kernel publication.
/// Every path component must be a real directory: symlinks are refused
/// (ELOOP surfaces as a loud error) so scope can never silently wander.
pub fn cgroup(path: &Path) -> Result<Scope> {
    use std::os::unix::fs::MetadataExt as _;
    let dir =
        open_cgroup_dir(path).with_context(|| format!("reading cgroup path {}", path.display()))?;
    let id = dir
        .metadata()
        .with_context(|| format!("reading cgroup path {}", path.display()))?
        .ino();
    Ok(Scope::Cgroup {
        id,
        path: path.to_path_buf(),
        dir: Arc::new(dir),
    })
}

/// `CGROUP2_SUPER_MAGIC` from `<linux/magic.h>`.
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

/// `--cgroup` as an operator names it (M-3): [`cgroup`] plus proof, taken
/// from the retained directory with `fstatfs`, that it lives on cgroup v2.
/// A plain directory would otherwise be accepted as a scope whose inode no
/// task ever matches — a full-duration capture of nothing that exits 0 —
/// and `/` would send discovery walking the whole filesystem.
pub fn capture_cgroup(path: &Path) -> Result<Scope> {
    let scope = cgroup(path)?;
    let Scope::Cgroup { dir, .. } = &scope else {
        unreachable!("cgroup() returns a cgroup scope")
    };
    let magic =
        filesystem_magic(dir).with_context(|| format!("reading cgroup path {}", path.display()))?;
    if magic != CGROUP2_SUPER_MAGIC {
        bail!(
            "--cgroup {}: not a cgroup v2 directory (its filesystem magic is {magic:#x}, not \
             cgroup2's {CGROUP2_SUPER_MAGIC:#x}); name a directory under /sys/fs/cgroup, for \
             example /sys/fs/cgroup/system.slice/<unit>.service",
            path.display()
        );
    }
    Ok(scope)
}

fn filesystem_magic(dir: &File) -> std::io::Result<u64> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `fstatfs` fills the buffer on success; the fd is open.
    if unsafe { libc::fstatfs(dir.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the successful call above initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
    Ok(stat.f_type as u64)
}

/// Best-effort human label for a `cgroup_id`, for the per-cgroup profile
/// breakdown (`render::profile_json`'s `cgroups[]`): walks `root` (the
/// caller passes `/sys/fs/cgroup`) looking for the one directory whose
/// inode matches `target`, returning its path relative to `root` (e.g.
/// `"kubepods.slice/kubepods-pod1234.slice/cri-containerd-abcd.scope"`).
/// `None` when no match is found anywhere under `root` — an absent label
/// is fine, a wrong one is not: this never guesses, and a cgroup that has
/// since been removed (the capture ended, the container exited) simply
/// yields no label rather than a stale or mismatched one.
pub fn label(root: &Path, target: u64) -> Option<String> {
    use std::os::unix::fs::MetadataExt as _;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if std::fs::metadata(&dir).is_ok_and(|md| md.ino() == target) {
            return dir
                .strip_prefix(root)
                .ok()
                .map(|p| p.display().to_string())
                .filter(|s| !s.is_empty());
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(entry.path());
                }
            }
        }
    }
    None
}

fn publish_cgroup_fd_with(dir: &File, set: impl FnOnce(File) -> Result<()>) -> Result<()> {
    set(dir.try_clone()?)
}

/// Opens a cgroup directory without following any symlink component:
/// openat2 `RESOLVE_NO_SYMLINKS` first, then a per-component `O_NOFOLLOW`
/// walk when the kernel or seccomp refuses openat2 itself. Mirrors the
/// `output.rs` directory opener minus its trust validation, which is an
/// output-path concern, not a scope concern.
fn open_cgroup_dir(path: &Path) -> std::io::Result<File> {
    match openat2_nofollow_dir(path) {
        Ok(dir) => Ok(dir),
        Err(error) if matches!(error.raw_os_error(), Some(code) if code == libc::ENOSYS || code == libc::EPERM) => {
            open_dir_nofollow_walk(path)
        }
        Err(error) => Err(symlink_loud_error(error)),
    }
}

fn symlink_loud_error(error: std::io::Error) -> std::io::Error {
    if error.raw_os_error() == Some(libc::ELOOP) {
        std::io::Error::other("cgroup path contains a symlink, which scope refuses to follow")
    } else {
        error
    }
}

fn openat2_nofollow_dir(path: &Path) -> std::io::Result<File> {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL byte")
    })?;
    // SAFETY: open_how is a plain kernel input struct; zero initializes all
    // fields not used by this call, including future non-exhaustive fields.
    let mut how = unsafe { std::mem::zeroed::<libc::open_how>() };
    how.flags = (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd == -1 {
        Err(symlink_loud_error(std::io::Error::last_os_error()))
    } else {
        Ok(unsafe { File::from_raw_fd(fd as _) })
    }
}

fn open_dir_nofollow_walk(path: &Path) -> std::io::Result<File> {
    use std::os::unix::ffi::OsStrExt as _;
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cgroup fallback walk requires an absolute path",
        ));
    }
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let root = std::ffi::CString::new("/").expect("root has no NUL");
    let fd = unsafe { libc::open(root.as_ptr(), flags) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let mut directory = unsafe { File::from_raw_fd(fd) };
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            match component {
                std::path::Component::RootDir | std::path::Component::CurDir => continue,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cgroup fallback walk rejects parent or prefix components",
                    ));
                }
            }
        };
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL byte")
        })?;
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd == -1 {
            return Err(symlink_loud_error(std::io::Error::last_os_error()));
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}

/// Publishes one exact scope and policy and verifies every supported
/// readback. The retained cgroup descriptor is cloned into the kernel map.
pub(crate) fn publish(
    ebpf: &mut Ebpf,
    scope: &Scope,
    policy: CapturePolicy,
    generation_token: Option<u64>,
    track_short_lived: bool,
    pid_start: Option<u64>,
) -> Result<()> {
    publish_detailed_with(
        scope,
        policy,
        generation_token,
        track_short_lived,
        pid_start,
        &mut EbpfScopeIo(ebpf),
    )
}

/// I4: the PID scope target's thread-group start tick (clock ticks since
/// boot, the `/proc/PID/stat` field 22 the kernel compares), read while
/// the target is alive at scope publication. `None` for cgroup/system
/// scopes, which the witness never binds. A dead target refuses loudly
/// here instead of publishing a number-only scope for a marker build.
pub(crate) fn pid_start_tick_of(
    scope: &Scope,
    _pin: Option<&crate::process::PidPin>,
) -> Result<Option<u64>> {
    match scope {
        Scope::Pid(pid) => crate::process::process_start_time(*pid)
            .map(Some)
            .with_context(|| format!("reading the start time of PID scope target {pid}")),
        Scope::Cgroup { .. } | Scope::System => Ok(None),
    }
}

/// I4: whether publication reads the PID witness: only PID scope on an
/// object carrying the witness map; anything else skips the read.
#[cfg(test)]
pub(crate) fn reads_pid_witness(_scope: &Scope, _has_witness_map: bool) -> bool {
    true
}

pub(crate) fn publish_inventory(ebpf: &mut Ebpf, scope: &Scope) -> Result<()> {
    publish_inventory_with(scope, &mut EbpfScopeIo(ebpf))
}

fn scope_flag(scope: &Scope) -> u64 {
    match scope {
        Scope::Pid(_) => FLAG_PID_FILTER,
        Scope::Cgroup { .. } => FLAG_CGROUP_FILTER,
        Scope::System => FLAG_SYSTEM_FILTER,
    }
}

fn publish_detailed_with(
    scope: &Scope,
    policy: CapturePolicy,
    generation_token: Option<u64>,
    track_short_lived: bool,
    pid_start: Option<u64>,
    io: &mut impl ScopePublicationIo,
) -> Result<()> {
    if generation_token == Some(0) {
        bail!("pause generation token must be non-zero");
    }
    if generation_token.is_some() && !matches!(scope, Scope::Pid(_)) {
        bail!("pause generation requires PID scope");
    }
    // 6.14 Option B: the extensive CONFIG bit publishes for Detailed
    // policies only; a counter policy refuses before any map writes.
    if track_short_lived && !policy.allows_track_short_lived() {
        bail!(
            "--track-short-lived arms Detailed captures only; refusing it for counter mode {}",
            policy
                .counter_mode()
                .expect("non-Detailed policy here is a counter policy")
                .name()
        );
    }
    let pause_flag = generation_token.map_or(0, |_| FLAG_PAUSE_ENABLED);
    // 6.14 Option B: extensive mode arms the kernel exe-identity read
    // on EXEC. Default off; inventory never sets this bit.
    let extensive_flag = if track_short_lived {
        FLAG_TRACK_SHORT_LIVED
    } else {
        0
    };
    let config = scope_flag(scope) | policy.config_bit() | pause_flag | extensive_flag;
    if !valid_config(config) {
        bail!("refusing invalid CONFIG {config:#x}");
    }
    publish_validated_scope_with(
        scope,
        generation_token.unwrap_or(1),
        config,
        false,
        pid_start,
        io,
    )
}

fn publish_inventory_with(scope: &Scope, io: &mut impl ScopePublicationIo) -> Result<()> {
    let config = scope_flag(scope) | FLAG_POLICY_INVENTORY;
    if !valid_inventory_config(config) {
        bail!("refusing invalid Inventory CONFIG {config:#x}");
    }
    // Inventory objects never carry the witness map, so no witness is
    // published here even for PID scope.
    publish_validated_scope_with(scope, 1, config, true, None, io)
}

// Only the two mode-specific wrappers above construct the validated config.
// Sharing map I/O does not allow Inventory to pass a Detailed policy validator.
fn publish_validated_scope_with(
    scope: &Scope,
    token: u64,
    config: u64,
    reserved_config_zero: bool,
    pid_start: Option<u64>,
    io: &mut impl ScopePublicationIo,
) -> Result<()> {
    let mut expected_pids = BTreeMap::new();
    let mut expected_starts = BTreeMap::new();
    match scope {
        Scope::Pid(pid) => {
            if *pid == 0 {
                bail!("pid must be non-zero");
            }
            io.insert_pid(*pid, token)
                .context("publishing PID_FILTER")?;
            expected_pids.insert(*pid, token);
            // I4: the witness rides next to the PID. Objects without
            // the witness map (builds that carry no marker to bind)
            // skip it; anything published reads back exactly, or the
            // publication is refused rather than falling back.
            if let Some(tick) = pid_start
                && io
                    .insert_pid_start(*pid, tick)
                    .context("publishing PID_START_TICK")?
            {
                expected_starts.insert(*pid, tick);
            }
        }
        Scope::Cgroup { dir, .. } => {
            // CgroupArray has no userspace lookup; its exact metadata and
            // successful publication of this retained FD are the content proof.
            publish_cgroup_fd_with(dir, |directory| io.insert_cgroup(directory))
                .context("publishing CGROUP_FILTER")?;
        }
        Scope::System => {}
    }
    if io.read_pids().context("reading PID_FILTER")? != expected_pids {
        bail!("PID_FILTER exact readback differs from the selected scope");
    }
    if io.read_pid_starts().context("reading PID_START_TICK")? != expected_starts {
        bail!("PID_START_TICK exact readback differs from the selected scope");
    }
    io.write_config(CFG_FLAGS, config)
        .context("publishing CONFIG")?;
    let readback = io.read_config(CFG_FLAGS).context("reading CONFIG flags")?;
    if readback != config {
        bail!("CONFIG exact readback {readback:#x} differs from {config:#x}");
    }
    if reserved_config_zero && io.read_config(1).context("reading reserved CONFIG cell")? != 0 {
        bail!("Inventory CONFIG reserved cell 1 must remain zero");
    }
    Ok(())
}

trait ScopePublicationIo {
    fn insert_pid(&mut self, pid: u32, token: u64) -> Result<()>;
    /// Publishes the PID witness, returning whether the object carries
    /// the witness map. `Ok(false)` (no map, nothing published) is the
    /// honest shape for builds without a marker to bind; a present but
    /// misshapen map errors loudly instead of skipping.
    fn insert_pid_start(&mut self, pid: u32, tick: u64) -> Result<bool>;
    fn insert_cgroup(&mut self, directory: File) -> Result<()>;
    fn read_pids(&mut self) -> Result<BTreeMap<u32, u64>>;
    /// The exact witness contents: empty when the object carries no
    /// witness map, exactly what was published otherwise.
    fn read_pid_starts(&mut self) -> Result<BTreeMap<u32, u64>>;
    fn write_config(&mut self, index: u32, value: u64) -> Result<()>;
    fn read_config(&mut self, index: u32) -> Result<u64>;
}

struct EbpfScopeIo<'a>(&'a mut Ebpf);
impl ScopePublicationIo for EbpfScopeIo<'_> {
    fn insert_pid(&mut self, pid: u32, token: u64) -> Result<()> {
        let mut map: HashMap<_, u32, u64> =
            HashMap::try_from(self.0.map_mut("PID_FILTER").context("PID_FILTER map")?)?;
        map.insert(pid, token, 0)?;
        Ok(())
    }

    fn insert_pid_start(&mut self, pid: u32, tick: u64) -> Result<bool> {
        let Some(map) = self.0.map_mut("PID_START_TICK") else {
            return Ok(false);
        };
        let mut starts: HashMap<_, u32, u64> =
            HashMap::try_from(map).context("PID_START_TICK map")?;
        starts.insert(pid, tick, 0)?;
        Ok(true)
    }

    fn insert_cgroup(&mut self, directory: File) -> Result<()> {
        let mut groups: CgroupArray<_> = CgroupArray::try_from(
            self.0
                .map_mut("CGROUP_FILTER")
                .context("CGROUP_FILTER map")?,
        )?;
        groups.set(0, directory, 0)?;
        Ok(())
    }

    fn read_pids(&mut self) -> Result<BTreeMap<u32, u64>> {
        let map: HashMap<_, u32, u64> =
            HashMap::try_from(self.0.map("PID_FILTER").context("PID_FILTER map")?)?;
        Ok(map.iter().collect::<Result<_, _>>()?)
    }

    fn read_pid_starts(&mut self) -> Result<BTreeMap<u32, u64>> {
        let Some(map) = self.0.map("PID_START_TICK") else {
            return Ok(BTreeMap::new());
        };
        let starts: HashMap<_, u32, u64> = HashMap::try_from(map).context("PID_START_TICK map")?;
        Ok(starts.iter().collect::<Result<_, _>>()?)
    }

    fn write_config(&mut self, index: u32, value: u64) -> Result<()> {
        let mut map: Array<_, u64> =
            Array::try_from(self.0.map_mut("CONFIG").context("CONFIG map")?)?;
        map.set(index, value, 0)?;
        Ok(())
    }

    fn read_config(&mut self, index: u32) -> Result<u64> {
        let map: Array<_, u64> = Array::try_from(self.0.map("CONFIG").context("CONFIG map")?)?;
        Ok(map.get(&index, 0)?)
    }
}

#[cfg(test)]
#[path = "scope/inventory_tests.rs"]
mod inventory_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::{
        FLAG_POLICY_AGGREGATE, FLAG_POLICY_ALLOWLISTED, FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA,
        FLAG_SYSTEM_FILTER, valid_config,
    };

    #[test]
    fn config_requires_exactly_one_scope_and_one_policy() {
        for scope in [FLAG_PID_FILTER, FLAG_CGROUP_FILTER, FLAG_SYSTEM_FILTER] {
            for policy in [
                FLAG_POLICY_ALLOWLISTED,
                FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA,
                FLAG_POLICY_AGGREGATE,
            ] {
                assert!(valid_config(scope | policy));
            }
        }

        for invalid in [
            0,
            FLAG_PID_FILTER,
            FLAG_SYSTEM_FILTER,
            FLAG_POLICY_ALLOWLISTED,
            FLAG_PID_FILTER | FLAG_CGROUP_FILTER | FLAG_POLICY_ALLOWLISTED,
            FLAG_PID_FILTER | FLAG_SYSTEM_FILTER | FLAG_POLICY_ALLOWLISTED,
            FLAG_CGROUP_FILTER | FLAG_SYSTEM_FILTER | FLAG_POLICY_ALLOWLISTED,
            FLAG_PID_FILTER | FLAG_POLICY_ALLOWLISTED | FLAG_POLICY_AGGREGATE,
            FLAG_PID_FILTER | FLAG_POLICY_ALLOWLISTED | FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA,
            FLAG_PID_FILTER | FLAG_POLICY_ALLOWLISTED | (1 << 63),
        ] {
            assert!(
                !valid_config(invalid),
                "accepted invalid CONFIG {invalid:#x}"
            );
        }
    }

    #[test]
    fn cgroup_constructor_uses_the_directory_inode() {
        let root = tempfile::tempdir().unwrap();
        use std::os::unix::fs::MetadataExt as _;
        let expected = std::fs::metadata(root.path()).unwrap().ino();
        let Scope::Cgroup { id, .. } = cgroup(root.path()).unwrap() else {
            unreachable!()
        };
        assert_eq!(id, expected);
    }

    /// M-3: only a cgroup2 directory is a capture scope.
    #[test]
    fn capture_cgroup_refuses_a_directory_that_is_not_cgroup_v2() {
        let plain = tempfile::tempdir().unwrap();
        let error = format!("{:#}", capture_cgroup(plain.path()).unwrap_err());
        assert!(error.contains("not a cgroup v2 directory"), "{error}");
        assert!(error.contains("/sys/fs/cgroup"), "{error}");
        if filesystem_magic(&File::open("/sys/fs/cgroup").unwrap()).unwrap() == CGROUP2_SUPER_MAGIC
        {
            assert!(capture_cgroup(Path::new("/sys/fs/cgroup")).is_ok());
        }
    }

    #[test]
    fn missing_cgroup_path_errors_loudly() {
        let e = cgroup(Path::new("/sys/fs/cgroup/definitely-not-here")).unwrap_err();
        assert!(e.to_string().contains("reading cgroup path"));
    }

    #[test]
    fn cgroup_path_refuses_symlink_components() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real.slice");
        std::fs::create_dir(&real).unwrap();
        let link = root.path().join("link.slice");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = cgroup(&link).unwrap_err();
        assert!(
            format!("{e:?}").contains("symlink"),
            "symlinked cgroup scope must fail loudly, not follow: {e:?}"
        );
        // Intermediate components are covered too.
        let nested = link.join("real.slice");
        let e = cgroup(&nested).unwrap_err();
        assert!(
            format!("{e:?}").contains("symlink"),
            "nested symlinked cgroup scope must fail loudly: {e:?}"
        );
    }

    #[test]
    fn publish_uses_the_retained_cgroup_fd() {
        use std::os::unix::fs::MetadataExt as _;

        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("target.scope");
        let impostor = root.path().join("impostor.scope");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&impostor).unwrap();
        let scope = cgroup(&real).unwrap();
        let Scope::Cgroup { dir, .. } = &scope else {
            unreachable!()
        };
        let retained_inode = dir.metadata().unwrap().ino();
        let stash = root.path().join("moved.scope");
        std::fs::rename(&real, &stash).unwrap();
        std::fs::rename(&impostor, &real).unwrap();

        publish_cgroup_fd_with(dir, |candidate| {
            assert_eq!(candidate.metadata().unwrap().ino(), retained_inode);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn label_finds_a_nested_directory_by_inode() {
        use std::os::unix::fs::MetadataExt as _;
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("kubepods.slice").join("pod-123.slice");
        std::fs::create_dir_all(&nested).unwrap();
        let target = std::fs::metadata(&nested).unwrap().ino();

        let got = label(root.path(), target).expect("nested directory must be found");
        assert_eq!(got, "kubepods.slice/pod-123.slice");
    }

    #[test]
    fn label_is_none_when_no_directory_matches() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("a")).unwrap();
        assert_eq!(label(root.path(), 0xdead_beef), None);
    }

    /// I4 witness publication fake: models a marker object when
    /// `witness_map` is set, a marker-less object otherwise.
    #[derive(Default)]
    struct WitnessMaps {
        pids: BTreeMap<u32, u64>,
        starts: BTreeMap<u32, u64>,
        config: BTreeMap<u32, u64>,
        witness_map: bool,
        starts_readback: Option<BTreeMap<u32, u64>>,
    }

    impl ScopePublicationIo for WitnessMaps {
        fn insert_pid(&mut self, pid: u32, token: u64) -> Result<()> {
            self.pids.insert(pid, token);
            Ok(())
        }

        fn insert_pid_start(&mut self, pid: u32, tick: u64) -> Result<bool> {
            if !self.witness_map {
                return Ok(false);
            }
            self.starts.insert(pid, tick);
            Ok(true)
        }

        fn insert_cgroup(&mut self, directory: File) -> Result<()> {
            let _ = directory;
            Ok(())
        }

        fn read_pids(&mut self) -> Result<BTreeMap<u32, u64>> {
            Ok(self.pids.clone())
        }

        fn read_pid_starts(&mut self) -> Result<BTreeMap<u32, u64>> {
            if !self.witness_map {
                return Ok(BTreeMap::new());
            }
            Ok(self
                .starts_readback
                .clone()
                .unwrap_or_else(|| self.starts.clone()))
        }

        fn write_config(&mut self, index: u32, value: u64) -> Result<()> {
            self.config.insert(index, value);
            Ok(())
        }

        fn read_config(&mut self, index: u32) -> Result<u64> {
            Ok(self.config.get(&index).copied().unwrap_or(0))
        }
    }

    #[test]
    fn pid_scope_publishes_the_start_tick_next_to_the_pid() {
        let mut maps = WitnessMaps {
            witness_map: true,
            ..WitnessMaps::default()
        };
        publish_detailed_with(
            &Scope::Pid(4242),
            CapturePolicy::Allowlisted,
            None,
            false,
            Some(777),
            &mut maps,
        )
        .unwrap();
        assert_eq!(maps.pids, BTreeMap::from([(4242, 1)]));
        assert_eq!(maps.starts, BTreeMap::from([(4242, 777)]));
        assert_eq!(
            maps.config.get(&CFG_FLAGS),
            Some(&(FLAG_PID_FILTER | FLAG_POLICY_ALLOWLISTED))
        );
    }

    #[test]
    fn pid_scope_start_tick_readback_mismatch_is_refused_never_a_fallback() {
        for actual in [
            BTreeMap::new(),
            BTreeMap::from([(4242, 778)]),
            BTreeMap::from([(4243, 777)]),
            BTreeMap::from([(4242, 777), (4243, 777)]),
        ] {
            let mut maps = WitnessMaps {
                witness_map: true,
                starts_readback: Some(actual),
                ..WitnessMaps::default()
            };
            let error = publish_detailed_with(
                &Scope::Pid(4242),
                CapturePolicy::Allowlisted,
                None,
                false,
                Some(777),
                &mut maps,
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("PID_START_TICK"),
                "a witness mismatch must refuse loudly: {error:#}"
            );
        }
    }

    #[test]
    fn pid_scope_without_a_witness_map_skips_the_witness_and_succeeds() {
        let mut maps = WitnessMaps::default();
        publish_detailed_with(
            &Scope::Pid(4242),
            CapturePolicy::Allowlisted,
            None,
            false,
            Some(777),
            &mut maps,
        )
        .unwrap();
        assert_eq!(maps.pids, BTreeMap::from([(4242, 1)]));
        assert!(maps.starts.is_empty());
    }

    #[test]
    fn non_pid_scopes_publish_no_witness() {
        let root = tempfile::tempdir().unwrap();
        for scope in [Scope::System, cgroup(root.path()).unwrap()] {
            let mut maps = WitnessMaps {
                witness_map: true,
                ..WitnessMaps::default()
            };
            publish_detailed_with(
                &scope,
                CapturePolicy::Allowlisted,
                None,
                false,
                pid_start_tick_of(&scope, None).unwrap(),
                &mut maps,
            )
            .unwrap();
            assert!(maps.starts.is_empty());
        }
    }

    #[test]
    fn pid_start_tick_of_reads_the_live_target_and_refuses_the_dead() {
        let live = std::process::id();
        assert_eq!(
            pid_start_tick_of(&Scope::Pid(live), None).unwrap(),
            Some(crate::process::process_start_time(live).unwrap())
        );
        assert_eq!(pid_start_tick_of(&Scope::System, None).unwrap(), None);
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            pid_start_tick_of(&cgroup(root.path()).unwrap(), None).unwrap(),
            None
        );
        let error = pid_start_tick_of(&Scope::Pid(u32::MAX), None).unwrap_err();
        assert!(
            format!("{error:#}").contains("start time"),
            "a dead target must refuse loudly: {error:#}"
        );
    }

    #[test]
    fn pid_start_tick_with_a_matching_pin_accepts() {
        // I4: the bound witness accepts when the fresh read equals the
        // selected pin and the pin is still the same process.
        let live = std::process::id();
        let pin = crate::process::PidPin::open(live).expect("pin self");
        assert_eq!(
            pid_start_tick_of(&Scope::Pid(live), Some(&pin)).expect("matching pin accepts"),
            Some(crate::process::process_start_time(live).expect("read self tick"))
        );
    }

    #[test]
    fn pid_start_tick_with_a_mismatched_pin_refuses() {
        // I4: a PID reused between selection and publication carries
        // another tick; the witness refuses instead of binding the reuser.
        let live = std::process::id();
        let pin = crate::process::PidPin::test_proc_only(live);
        let error = pid_start_tick_of(&Scope::Pid(live), Some(&pin))
            .expect_err("a mismatched pin must refuse");
        assert!(
            format!("{error:#}").contains("differs from the pinned"),
            "mismatch refusal names both ticks: {error:#}"
        );
    }

    #[test]
    fn pid_start_tick_with_a_stale_pin_refuses() {
        // I4: the target exits after selection but before publication (a
        // zombie: its /proc stat still reads, with the pinned tick); the
        // witness refuses instead of binding the dead number.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let pin = crate::process::PidPin::open(pid).expect("pin the child");
        let pinned = pin.start_time().expect("the pin retains a start time");
        child.kill().expect("kill the child");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while pin.still_the_same() {
            assert!(
                std::time::Instant::now() < deadline,
                "the killed child must exit promptly"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // The zombie's stat still reads with the pinned tick: only the
        // sameness check refuses, never a read failure.
        assert_eq!(
            crate::process::process_start_time(pid).expect("zombie stat reads"),
            pinned
        );
        let result = pid_start_tick_of(&Scope::Pid(pid), Some(&pin));
        child.wait().expect("reap the child");
        let error = result.expect_err("a stale pin must refuse");
        assert!(
            format!("{error:#}").contains("no longer the same"),
            "stale refusal names the cause: {error:#}"
        );
    }

    #[test]
    fn witness_read_skips_scopes_and_objects_without_a_witness_map() {
        // I4: publication reads the PID witness only for PID scope on an
        // object carrying the witness map; anything else skips the read.
        let root = tempfile::tempdir().unwrap();
        let cgroup = cgroup(root.path()).unwrap();
        for has_map in [false, true] {
            assert_eq!(
                reads_pid_witness(&Scope::Pid(4242), has_map),
                has_map,
                "PID scope reads exactly when the map exists (map {has_map})"
            );
            assert!(
                !reads_pid_witness(&Scope::System, has_map),
                "system scope never reads (map {has_map})"
            );
            assert!(
                !reads_pid_witness(&cgroup, has_map),
                "cgroup scope never reads (map {has_map})"
            );
        }
    }
}
