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
use std::path::{Path, PathBuf};
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

/// A cgroup v2 subgroup owned by one `run`: the owned child is placed in
/// it before its barrier release, so every descendant is born in scope.
/// Dropping removes the directory best-effort; a nonempty directory
/// (handed-back survivors still in it) is left in place, never forced —
/// but never silently: the retention notice names it for the operator.
#[derive(Debug)]
pub struct RunCgroup {
    path: PathBuf,
    cgroup_root: PathBuf,
    verbose: bool,
}

impl RunCgroup {
    /// Creates the run subgroup directly under `base`. Tests pass a
    /// tmpfs dir; production must use [`RunCgroup::create_under_observer`]
    /// instead, under the observer's own cgroup; that is the root only
    /// when the observer itself runs in the root cgroup. No controllers
    /// are enabled, so the subgroup itself carries no resource state;
    /// the cgroup2 proof stays with scope construction (`capture_cgroup`),
    /// which must build on this path before use.
    pub fn create(base: &Path) -> Result<Self> {
        let production_root = Path::new("/sys/fs/cgroup");
        let cgroup_root = if base.starts_with(production_root) {
            production_root.to_path_buf()
        } else {
            base.to_path_buf()
        };
        Self::create_with_root(base, &cgroup_root)
    }

    fn create_with_root(base: &Path, cgroup_root: &Path) -> Result<Self> {
        let path = base.join(
            run_cgroup_name()
                .with_context(|| format!("naming a run cgroup under {}", base.display()))?,
        );
        std::fs::create_dir(&path)
            .with_context(|| format!("creating run cgroup {}", path.display()))?;
        Ok(Self {
            path,
            cgroup_root: cgroup_root.to_path_buf(),
            verbose: false,
        })
    }

    /// Creates the run subgroup under the observer's own cgroup (see
    /// [`observer_run_cgroup_base`]): the command keeps its ancestor
    /// limits and unit kill semantics, and no resource controllers are
    /// touched. Any failure (unreadable membership, no v2 line,
    /// permission, delegation) degrades the run to its exact child; the
    /// caller must never fall back to the cgroup root. The group lives
    /// under the observer's own cgroup; that is the root only when the
    /// observer itself runs in the root cgroup.
    pub fn create_under_observer(cgroup_root: &Path) -> Result<Self> {
        let base = observer_run_cgroup_base(cgroup_root)?;
        Self::create_with_root(&base, cgroup_root)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the retention notice may name the full cgroup path: only
    /// under `-v`. By default it names the leaf only, since the full
    /// path carries the observer's UID/session slices.
    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    /// Moves the whole process `pid` into the run cgroup and proves the
    /// landing via `/proc/<pid>/cgroup`: a misplaced child would flip
    /// every later scope assertion, so a silent miss fails here instead.
    /// The readback is relative to the v2 mount root, so it joins with
    /// the stored cgroup root — never with the run cgroup's own parent,
    /// which is the observer's nested base, not the root.
    pub fn place(&self, pid: u32) -> Result<()> {
        std::fs::write(self.path.join("cgroup.procs"), format!("{pid}\n"))
            .with_context(|| format!("moving {pid} to run cgroup {}", self.path.display()))?;
        let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .with_context(|| format!("reading the cgroup of {pid}"))?;
        let relative = parse_cgroup_v2_relative(&text)
            .with_context(|| format!("no cgroup v2 entry for process {pid}: {text:?}"))?;
        let placed = self.cgroup_root.join(relative);
        anyhow::ensure!(
            placed == self.path,
            "process {pid} did not land in {} (in {})",
            self.path.display(),
            placed.display()
        );
        Ok(())
    }

    /// Members still present in the run cgroup, excluding `pid` (the
    /// direct child, settled separately): the handed-back survivor
    /// count. Presence, not aliveness, is what's measured.
    pub fn survivors_excluding(&self, pid: u32) -> std::io::Result<u64> {
        let members = std::fs::read_to_string(self.path.join("cgroup.procs"))?;
        Ok(members
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .filter(|member| *member != pid)
            .count() as u64)
    }

    /// Removes the directory best-effort, returning the
    /// operator-facing retention notice when it survives: an empty
    /// or already-gone directory stays silent.
    fn remove_best_effort(&self) -> Option<String> {
        match std::fs::remove_dir(&self.path) {
            Ok(()) => None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => Some(self.retention_notice()),
        }
    }

    /// Who keeps the directory alive, by count from the membership
    /// file (never PIDs): the operator removes the named path once
    /// its members exit. An unreadable file reads as empty rather
    /// than refusing the notice. By default the notice names the leaf
    /// only; the full path (which carries UID/session slices) appears
    /// only when verbose was armed.
    fn retention_notice(&self) -> String {
        let members = std::fs::read_to_string(self.path.join("cgroup.procs"))
            .map(|text| {
                text.lines()
                    .filter_map(|line| line.trim().parse::<u32>().ok())
                    .count()
            })
            .unwrap_or(0);
        let held = if members == 1 {
            "1 member is".to_string()
        } else {
            format!("{members} members are")
        };
        let shown = if self.verbose {
            self.path.display().to_string()
        } else {
            self.path
                .file_name()
                .and_then(|leaf| leaf.to_str())
                .unwrap_or("p11scope-run-unknown")
                .to_string()
        };
        format!(
            "p11scope: the run cgroup {shown} is retained: {held} still present; remove it after they exit"
        )
    }
}

impl Drop for RunCgroup {
    fn drop(&mut self) {
        if let Some(notice) = self.remove_best_effort() {
            eprintln!("{notice}");
        }
    }
}

/// One run-subgroup leaf name: fixed prefix plus 64 bits from `getrandom`
/// as lowercase hex. Random, never the observer PID: a best-effort
/// cgroup label may publish the name, and profile output never carries
/// PIDs.
pub fn run_cgroup_name() -> Result<String> {
    let mut word = [0u8; 8];
    let mut filled = 0;
    while filled < word.len() {
        // SAFETY: the slice is live and entirely writable; getrandom
        // writes at most the remaining length, with no other effects.
        let got =
            unsafe { libc::getrandom(word[filled..].as_mut_ptr().cast(), word.len() - filled, 0) };
        if got < 0 {
            let errno = std::io::Error::last_os_error();
            if errno.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(errno).context("reading run cgroup randomness");
        }
        if got == 0 {
            return Err(std::io::Error::other("getrandom returned no randomness"))
                .context("reading run cgroup randomness");
        }
        filled += got as usize;
    }
    Ok(format!("p11scope-run-{:016x}", u64::from_ne_bytes(word)))
}

/// The cgroup v2 path of a `/proc/<pid>/cgroup` text, relative to the v2
/// mount: the `0::` line with its leading slash stripped (`0::/` is the
/// mount itself, `Some("")`). `None` when no v2 line exists.
pub fn parse_cgroup_v2_relative(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|path| path.strip_prefix('/').unwrap_or(path))
}

/// The observer's own cgroup directory under `cgroup_root`
/// (production: `/sys/fs/cgroup`), from a `/proc/self/cgroup` text:
/// the v2 relative path joined to the root. The kernel never emits
/// `..`, but a parent component is refused anyway so the base can
/// never escape the root. Without a v2 line the run must degrade,
/// never guess a base.
pub fn observer_run_cgroup_base_from_text(
    cgroup_root: &Path,
    proc_self_cgroup_text: &str,
) -> Result<PathBuf> {
    let relative = parse_cgroup_v2_relative(proc_self_cgroup_text)
        .with_context(|| "the observer has no cgroup v2 membership".to_string())?;
    if relative.split('/').any(|component| component == "..") {
        bail!("the observer cgroup path escapes its root");
    }
    Ok(cgroup_root.join(relative))
}

/// The observer's own cgroup directory: [`observer_run_cgroup_base_from_text`]
/// over the live `/proc/self/cgroup`.
pub fn observer_run_cgroup_base(cgroup_root: &Path) -> Result<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup")
        .context("reading the observer cgroup membership")?;
    observer_run_cgroup_base_from_text(cgroup_root, &text)
}

/// Proves the owned path's scope names the owned child: PID scope by
/// exact equality, cgroup scope by live membership through the retained
/// descriptor (never the path). System scope never names one child.
pub fn scope_names_child(scope: &Scope, pid: u32) -> Result<()> {
    match scope {
        Scope::Pid(scope_pid) => {
            if *scope_pid == pid {
                Ok(())
            } else {
                bail!("owned scope names PID {scope_pid}, not the owned child {pid}")
            }
        }
        Scope::Cgroup { dir, .. } => {
            let members =
                std::fs::read_to_string(format!("/proc/self/fd/{}/cgroup.procs", dir.as_raw_fd()))
                    .with_context(|| {
                        format!("reading cgroup scope membership for the owned child {pid}")
                    })?;
            let member = members
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .any(|member| member == pid);
            if member {
                Ok(())
            } else {
                bail!("the owned child {pid} is not a member of its cgroup scope")
            }
        }
        Scope::System => bail!("system scope never names one owned child"),
    }
}

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
/// A run-cgroup leaf (`p11scope-run-*`) publishes as its leaf name only:
/// the full nested path would carry the observer's UID/session slices.
/// `None` when no match is found anywhere under `root` — an absent label
/// is fine, a wrong one is not: this never guesses, and a cgroup that has
/// since been removed (the capture ended, the container exited) simply
/// yields no label rather than a stale or mismatched one.
pub fn label(root: &Path, target: u64) -> Option<String> {
    use std::os::unix::fs::MetadataExt as _;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if std::fs::metadata(&dir).is_ok_and(|md| md.ino() == target) {
            let relative = dir.strip_prefix(root).ok()?;
            if relative.as_os_str().is_empty() {
                return None;
            }
            if let Some(leaf) = relative.file_name().and_then(|name| name.to_str())
                && leaf.starts_with("p11scope-run-")
            {
                return Some(leaf.to_string());
            }
            return Some(relative.display().to_string());
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
    owned_pid: Option<u32>,
) -> Result<()> {
    publish_detailed_with(
        scope,
        policy,
        generation_token,
        track_short_lived,
        pid_start,
        owned_pid,
        &mut EbpfScopeIo(ebpf),
    )
}

/// I4: the PID scope target's thread-group start tick (clock ticks since
/// boot, the `/proc/PID/stat` field 22 the kernel compares), read while
/// the target is alive at scope publication. `None` for cgroup/system
/// scopes, which the witness never binds. When the caller holds the
/// selected or owned pin, the fresh read must equal the pin's retained
/// start time and the pin must still be the same process; anything else
/// refuses loudly instead of binding a PID reused during the object
/// load. Without a pin there is no earlier identity to contradict, so
/// the fresh read stands. A dead target refuses loudly here instead of
/// publishing a number-only scope for a marker build.
pub(crate) fn pid_start_tick_of(
    scope: &Scope,
    pin: Option<&crate::process::PidPin>,
) -> Result<Option<u64>> {
    match scope {
        Scope::Pid(pid) => {
            // I4 minor: field 22 adds the reader's time-namespace
            // boottime offset; a skewed reader would bind a tick the
            // kernel never matches, so PID births refuse loudly here
            // instead of failing closed silently.
            if reader_timens_skews_boottime()? {
                bail!(
                    "refusing PID_START_TICK for PID scope target {pid}: nonzero time-namespace boottime offset (/proc/self/timens_offsets)"
                );
            }
            let fresh = crate::process::process_start_time(*pid)
                .with_context(|| format!("reading the start time of PID scope target {pid}"))?;
            if let Some(pin) = pin {
                if pin.start_time() != Some(fresh) {
                    bail!(
                        "refusing PID_START_TICK for PID scope target {pid}: the fresh start tick {fresh} differs from the pinned {:?}",
                        pin.start_time()
                    );
                }
                if !pin.still_the_same() {
                    bail!(
                        "refusing PID_START_TICK for PID scope target {pid}: the pinned process is no longer the same"
                    );
                }
            }
            Ok(Some(fresh))
        }
        Scope::Cgroup { .. } | Scope::System => Ok(None),
    }
}

/// I4: whether publication reads the PID witness: only PID scope on an
/// object carrying the witness map; anything else skips the read.
pub(crate) fn reads_pid_witness(scope: &Scope, has_witness_map: bool) -> bool {
    has_witness_map && matches!(scope, Scope::Pid(_))
}

/// I4 minor: whether `text` (the content of `/proc/self/timens_offsets`)
/// shows a nonzero boottime offset. `/proc/PID/stat` field 22 adds the
/// reader's time-namespace boottime offset, so a skewed reader would
/// bind a tick the kernel never matches. `None` when the boottime line
/// is missing or malformed; callers fail closed.
fn timens_boottime_offset(text: &str) -> Option<bool> {
    let line = text
        .lines()
        .find(|line| line.split_whitespace().next() == Some("boottime"))?;
    let fields: Vec<&str> = line.split_whitespace().skip(1).collect();
    if fields.is_empty() {
        return None;
    }
    let mut offset = false;
    for field in fields {
        offset |= field.parse::<i64>().ok()? != 0;
    }
    Some(offset)
}

/// I4 minor: whether this process's time namespace skews the boottime
/// clock the PID witness reads through. An absent file (no
/// time-namespace support) means no skew; anything unreadable fails
/// closed toward refusal.
fn reader_timens_skews_boottime() -> Result<bool> {
    let text = match std::fs::read_to_string("/proc/self/timens_offsets") {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("reading /proc/self/timens_offsets"),
    };
    Ok(timens_boottime_offset(&text).unwrap_or(true))
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
    owned_pid: Option<u32>,
    io: &mut impl ScopePublicationIo,
) -> Result<()> {
    if generation_token == Some(0) {
        bail!("pause generation token must be non-zero");
    }
    // The owned child rides beside the scope: a run-tree session
    // publishes its pause row next to the cgroup filter, a degraded
    // exact-PID run beside the matching PID. Anything else — an
    // anonymous cgroup generation, a mismatched PID, any owned child
    // on system scope — refuses before any map write.
    match (scope, generation_token, owned_pid) {
        (Scope::Pid(pid), _, Some(owned)) if *pid != owned => {
            bail!("owned child PID {owned} does not match selected PID {pid}")
        }
        (Scope::Cgroup { .. }, Some(_), None) => {
            bail!("pause generation on cgroup scope requires the owned child")
        }
        (Scope::Cgroup { .. }, Some(_), Some(owned)) => {
            scope_names_child(scope, owned)?;
        }
        (Scope::System, Some(_), _) => {
            bail!("pause generation requires PID or run-cgroup scope")
        }
        (Scope::System, None, Some(_)) => {
            bail!("system scope never names one owned child")
        }
        _ => {}
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
        // The pause row exists only beside a generation: without one
        // the owned child rides through untouched and the cgroup
        // filter publishes bare.
        owned_pid.filter(|_| generation_token.is_some()),
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
    publish_validated_scope_with(scope, 1, config, true, None, None, io)
}

// Only the two mode-specific wrappers above construct the validated config.
// Sharing map I/O does not allow Inventory to pass a Detailed policy validator.
fn publish_validated_scope_with(
    scope: &Scope,
    token: u64,
    config: u64,
    reserved_config_zero: bool,
    pid_start: Option<u64>,
    owned_pid: Option<u32>,
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
            // The run-tree pause row: the owned child's generation
            // token, proven a member above. The exact readback below
            // covers the row too.
            if let Some(owned) = owned_pid {
                io.insert_pid(owned, token)
                    .context("publishing PID_FILTER")?;
                expected_pids.insert(owned, token);
            }
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

    #[test]
    fn label_returns_only_the_run_cgroup_leaf_for_nested_run_groups() {
        use std::os::unix::fs::MetadataExt as _;
        let root = tempfile::tempdir().unwrap();
        let nested = root
            .path()
            .join("user.slice")
            .join("user-1000.slice")
            .join("p11scope-run-0123456789abcdef");
        std::fs::create_dir_all(&nested).unwrap();
        let target = std::fs::metadata(&nested).unwrap().ino();

        let got = label(root.path(), target).expect("nested run group must be found");
        assert_eq!(got, "p11scope-run-0123456789abcdef");
        assert!(
            !got.contains('/'),
            "the published label is the leaf only, never the full path: {got:?}"
        );
    }

    #[test]
    fn run_cgroup_place_uses_the_stored_cgroup_root() {
        let root = tempfile::tempdir().unwrap();
        let group = RunCgroup::create(root.path()).expect("create the run group under tmpfs");
        let error = format!("{:#}", group.place(1).unwrap_err());
        assert!(
            error.contains(&root.path().display().to_string()),
            "place must join the readback with the stored root, not /sys/fs/cgroup: {error}"
        );
        assert!(
            !error.contains("/sys/fs/cgroup"),
            "place must not hardcode the production root for a tmpfs group: {error}"
        );
    }

    #[test]
    fn run_cgroup_retention_notice_names_the_leaf_unless_verbose() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("user.slice").join("user-1000.slice");
        std::fs::create_dir_all(&nested).unwrap();
        let mut group = RunCgroup::create(&nested).expect("create the run group");
        let leaf = group
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a leaf name")
            .to_string();
        let quiet = group.retention_notice();
        assert!(
            quiet.contains(&leaf) && !quiet.contains("user.slice"),
            "the default notice names the leaf only: {quiet:?}"
        );
        group.set_verbose(true);
        let loud = group.retention_notice();
        assert!(
            loud.contains(&group.path().display().to_string()),
            "the verbose notice may name the full path: {loud:?}"
        );
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
            None,
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
                None,
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
            None,
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
                None,
                &mut maps,
            )
            .unwrap();
            assert!(maps.starts.is_empty());
        }
    }

    /// A run-tree session publishes the cgroup filter beside one
    /// PID_FILTER row: the owned child's pause token. Membership is
    /// proven through the retained descriptor before any map write.
    #[test]
    fn publish_run_cgroup_writes_owned_child_pause_row() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("cgroup.procs"), "4242\n").unwrap();
        let scope = cgroup(root.path()).unwrap();
        let mut maps = WitnessMaps::default();
        publish_detailed_with(
            &scope,
            CapturePolicy::Allowlisted,
            Some(99),
            false,
            None,
            Some(4242),
            &mut maps,
        )
        .unwrap();
        assert_eq!(maps.pids, BTreeMap::from([(4242, 99)]));
        assert_eq!(
            maps.config.get(&CFG_FLAGS),
            Some(&(FLAG_CGROUP_FILTER | FLAG_POLICY_ALLOWLISTED | FLAG_PAUSE_ENABLED))
        );
        assert!(valid_config(maps.config[&CFG_FLAGS]));
    }

    /// A pause generation on a cgroup scope without the owned child
    /// refuses loudly: no token source, no anonymous pause row.
    #[test]
    fn publish_cgroup_pause_without_owned_child_refuses() {
        let root = tempfile::tempdir().unwrap();
        let scope = cgroup(root.path()).unwrap();
        let mut maps = WitnessMaps::default();
        let error = publish_detailed_with(
            &scope,
            CapturePolicy::Allowlisted,
            Some(99),
            false,
            None,
            None,
            &mut maps,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("requires the owned child"),
            "{error:#}"
        );
        assert!(maps.pids.is_empty());
    }

    /// An owned child that is not the selected PID refuses: only the
    /// exact child, or none, rides beside a PID scope.
    #[test]
    fn publish_pid_scope_rejects_foreign_owned_child() {
        let mut maps = WitnessMaps::default();
        let error = publish_detailed_with(
            &Scope::Pid(41),
            CapturePolicy::Allowlisted,
            Some(99),
            false,
            None,
            Some(42),
            &mut maps,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("does not match"), "{error:#}");
        assert!(maps.pids.is_empty());
    }

    /// System scope never names one owned child; the combination is
    /// a caller bug and refuses instead of publishing.
    #[test]
    fn publish_system_scope_rejects_owned_child() {
        let mut maps = WitnessMaps::default();
        let error = publish_detailed_with(
            &Scope::System,
            CapturePolicy::Allowlisted,
            None,
            false,
            None,
            Some(42),
            &mut maps,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("never names one owned child"),
            "{error:#}"
        );
    }

    /// Without a pause generation the owned child rides through
    /// untouched: an unpaused run-tree session publishes the bare
    /// cgroup filter, exactly like an unowned cgroup scope.
    #[test]
    fn publish_cgroup_without_generation_ignores_owned_child() {
        let root = tempfile::tempdir().unwrap();
        let scope = cgroup(root.path()).unwrap();
        let mut maps = WitnessMaps::default();
        publish_detailed_with(
            &scope,
            CapturePolicy::Allowlisted,
            None,
            false,
            None,
            Some(4242),
            &mut maps,
        )
        .unwrap();
        assert!(maps.pids.is_empty());
        assert_eq!(
            maps.config.get(&CFG_FLAGS),
            Some(&(FLAG_CGROUP_FILTER | FLAG_POLICY_ALLOWLISTED))
        );
    }

    /// A degraded exact-PID run carries its owned child beside the
    /// matching PID scope: the publication is the ordinary PID row.
    #[test]
    fn publish_pid_scope_accepts_matching_owned_child() {
        let mut maps = WitnessMaps::default();
        publish_detailed_with(
            &Scope::Pid(42),
            CapturePolicy::Allowlisted,
            Some(99),
            false,
            None,
            Some(42),
            &mut maps,
        )
        .unwrap();
        assert_eq!(maps.pids, BTreeMap::from([(42, 99)]));
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
    fn timens_boottime_offset_reads_the_boottime_line() {
        // I4 minor: the offset detector fires on any nonzero field and
        // stays quiet on zeros; a missing or malformed boottime line
        // fails closed (None), never quiet.
        for (text, expected) in [
            (
                "monotonic           0         0\nboottime            0         0\n",
                Some(false),
            ),
            (
                "monotonic           0         0\nboottime         3600         0\n",
                Some(true),
            ),
            ("boottime            0         5\n", Some(true)),
            ("boottime           -1         0\n", Some(true)),
            ("monotonic           0         0\n", None),
            ("boottime            0         x\n", None),
            ("boottime\n", None),
            ("", None),
        ] {
            assert_eq!(timens_boottime_offset(text), expected, "{text:?}");
        }
    }

    #[test]
    fn reader_timens_check_agrees_with_the_live_offsets_file() {
        // I4 minor: the live check parses the same file the same way;
        // self-consistent on any host, with or without an offset.
        match std::fs::read_to_string("/proc/self/timens_offsets") {
            Ok(text) => assert_eq!(
                reader_timens_skews_boottime().expect("live check reads"),
                timens_boottime_offset(&text).unwrap_or(true)
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                assert!(!reader_timens_skews_boottime().expect("absent file means no skew"))
            }
            Err(error) => panic!("unexpected offsets read failure: {error}"),
        }
    }

    #[test]
    fn run_cgroup_name_is_hex_suffixed_unique_and_pid_free() {
        // The run cgroup name carries a random suffix: fixed prefix, 16
        // lowercase hex digits, unique across calls, and never the
        // observer's PID (a best-effort cgroup label may publish it).
        let pid = std::process::id().to_string();
        let mut names = std::collections::BTreeSet::new();
        for _ in 0..256 {
            let name = run_cgroup_name().expect("naming never fails on a live host");
            assert!(name.starts_with("p11scope-run-"), "{name}");
            let suffix = name.strip_prefix("p11scope-run-").unwrap();
            assert_eq!(suffix.len(), 16, "{name}");
            assert!(
                suffix
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "{name}"
            );
            assert!(
                !name.contains(&pid),
                "the name must not leak the PID: {name}"
            );
            assert!(
                names.insert(name.clone()),
                "duplicate run cgroup name: {name}"
            );
        }
    }

    #[test]
    fn run_cgroup_create_then_drop_removes_the_empty_dir() {
        let base = tempfile::tempdir().unwrap();
        let path = {
            let group = RunCgroup::create(base.path()).expect("create in a writable dir");
            assert!(group.path().starts_with(base.path()));
            assert!(group.path().is_dir());
            group.path().to_path_buf()
        };
        assert!(!path.exists(), "dropping removes the empty run cgroup");
    }

    #[test]
    fn run_cgroup_drop_keeps_a_nonempty_dir() {
        // Handed-back survivors keep the directory alive: Drop only
        // retries the removal, never forces it.
        let base = tempfile::tempdir().unwrap();
        let group = RunCgroup::create(base.path()).expect("create in a writable dir");
        let path = group.path().to_path_buf();
        std::fs::write(path.join("cgroup.procs"), "1\n").unwrap();
        drop(group);
        assert!(path.is_dir(), "a nonempty run cgroup must survive Drop");
    }

    #[test]
    fn run_cgroup_drop_notices_a_retained_dir() {
        // The retention notice names the leaf and counts planted
        // members (never PIDs); an empty or already-gone directory
        // stays silent. The full path appears only when verbose.
        let base = tempfile::tempdir().unwrap();
        let group = RunCgroup::create(base.path()).expect("create in a writable dir");
        assert_eq!(group.remove_best_effort(), None);
        assert!(!group.path().exists(), "the empty dir is removed");
        assert_eq!(
            group.remove_best_effort(),
            None,
            "an already-gone dir stays silent"
        );
        let group = RunCgroup::create(base.path()).expect("create in a writable dir");
        std::fs::write(group.path().join("cgroup.procs"), "11\n22\n").unwrap();
        let notice = group.remove_best_effort().expect("a retained dir notices");
        assert!(
            notice.contains("is retained: 2 members are still present"),
            "{notice}"
        );
        let leaf = group
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a leaf name");
        assert!(notice.contains(leaf), "{notice}");
        assert!(group.path().is_dir(), "retention still never forces");
    }

    #[test]
    fn run_cgroup_create_names_its_base_on_failure() {
        let base = tempfile::tempdir().unwrap();
        let missing = base.path().join("no-such-base");
        let error = RunCgroup::create(&missing).expect_err("a missing base must fail");
        assert!(
            format!("{error:#}").contains("no-such-base"),
            "the failure names the base: {error:#}"
        );
    }

    #[test]
    fn run_cgroup_place_reports_a_failed_landing() {
        // Placement writes the PID then proves the landing via
        // /proc/<pid>/cgroup: on a tmpfs stand-in the write lands but the
        // kernel never moves the process, so the readback must refuse loudly.
        let base = tempfile::tempdir().unwrap();
        let group = RunCgroup::create(base.path()).expect("create in a writable dir");
        let pid = std::process::id();
        let error = group.place(pid).expect_err("a tmpfs stand-in cannot place");
        let text = format!("{error:#}");
        let proc =
            std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("own cgroup reads");
        let expected = if proc.lines().any(|line| line.starts_with("0::")) {
            "did not land"
        } else {
            "no cgroup v2 entry"
        };
        assert!(text.contains(expected), "{text}");
        assert_eq!(
            std::fs::read_to_string(group.path().join("cgroup.procs")).unwrap(),
            format!("{pid}\n"),
            "the placement write precedes the readback"
        );
    }

    #[test]
    fn run_cgroup_placement_parser_reads_the_v2_line() {
        for (text, expected) in [
            (
                "12:memory:/user.slice\n0::/user.slice/user-1000.slice\n",
                Some("user.slice/user-1000.slice"),
            ),
            ("0::/\n", Some("")),
            ("0::/p11scope-run-abc\n", Some("p11scope-run-abc")),
            ("12:memory:/user.slice\n", None),
            ("", None),
        ] {
            assert_eq!(parse_cgroup_v2_relative(text), expected, "{text:?}");
        }
    }

    #[test]
    fn observer_run_cgroup_base_stays_under_the_observer_cgroup() {
        // The run cgroup must be created under the observer's own cgroup;
        // that is the root only when the observer itself runs in the root
        // cgroup: that keeps ancestor limits and unit kill semantics. Pure
        // text-to-path mapping, so no cgroup rights are needed here.
        let root = Path::new("/sys/fs/cgroup");
        for (text, expected) in [
            (
                "0::/user.slice/user-1000.slice/session-c2.scope\n",
                "user.slice/user-1000.slice/session-c2.scope",
            ),
            ("0::/\n", ""),
            (
                "0::/system.slice/p11scope.service\n",
                "system.slice/p11scope.service",
            ),
        ] {
            let base = observer_run_cgroup_base_from_text(root, text).expect("v2 line resolves");
            assert_eq!(base, root.join(expected), "{text:?}");
            assert!(
                base.starts_with(root),
                "the base never escapes the cgroup root: {}",
                base.display()
            );
        }
        for text in ["12:memory:/user.slice\n", ""] {
            observer_run_cgroup_base_from_text(root, text)
                .expect_err("without a v2 line the run must degrade, not guess");
        }
    }

    #[test]
    #[ignore = "privileged: moves a real child into a real run cgroup; run as root with --ignored --test-threads=1"]
    fn privileged_run_cgroup_place_moves_a_real_child() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run as root: placement needs cgroup rights"
        );
        if filesystem_magic(&File::open("/sys/fs/cgroup").expect("cgroup root opens"))
            .expect("magic reads")
            != CGROUP2_SUPER_MAGIC
        {
            panic!("run as root on cgroup v2: placement needs a v2 mount");
        }
        let group = RunCgroup::create(Path::new("/sys/fs/cgroup")).expect("create the run cgroup");
        assert!(group.path().starts_with("/sys/fs/cgroup"));
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let placed = group.place(child.id());
        child.kill().expect("kill the child");
        child.wait().expect("reap the child");
        placed.expect("a real child lands in the run cgroup");
        let path = group.path().to_path_buf();
        drop(group);
        assert!(!path.exists(), "the emptied run cgroup is removed");
    }

    #[test]
    #[ignore = "privileged: creates a run cgroup under the observer cgroup; run as root with --ignored --test-threads=1"]
    fn privileged_run_cgroup_create_under_observer_stays_nested() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run as root: creation needs cgroup rights"
        );
        if filesystem_magic(&File::open("/sys/fs/cgroup").expect("cgroup root opens"))
            .expect("magic reads")
            != CGROUP2_SUPER_MAGIC
        {
            panic!("run as root on cgroup v2: creation needs a v2 mount");
        }
        let base =
            observer_run_cgroup_base(Path::new("/sys/fs/cgroup")).expect("observer base resolves");
        let group = RunCgroup::create_under_observer(Path::new("/sys/fs/cgroup"))
            .expect("create the run cgroup under the observer");
        assert!(
            group.path().starts_with(&base),
            "the run cgroup {} is under the observer base {}",
            group.path().display(),
            base.display()
        );
        assert!(
            group.path() != base,
            "the run cgroup is a child, not the base itself"
        );
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let placed = group.place(child.id());
        child.kill().expect("kill the child");
        child.wait().expect("reap the child");
        placed.expect("a real child lands in the nested run cgroup");
        let path = group.path().to_path_buf();
        drop(group);
        assert!(!path.exists(), "the emptied run cgroup is removed");
    }

    #[test]
    fn scope_names_child_accepts_the_exact_pid() {
        scope_names_child(&Scope::Pid(4242), 4242).expect("the exact PID is named");
    }

    #[test]
    fn scope_names_child_refuses_a_different_pid() {
        let error = scope_names_child(&Scope::Pid(18), 17).expect_err("another PID is not named");
        assert!(
            format!("{error:#}").contains("not the owned child"),
            "{error:#}"
        );
    }

    #[test]
    fn scope_names_child_accepts_a_cgroup_member() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cgroup.procs"), "4242\n").unwrap();
        let scope = cgroup(dir.path()).unwrap();
        scope_names_child(&scope, 4242).expect("a member is named");
    }

    #[test]
    fn scope_names_child_refuses_a_cgroup_nonmember() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cgroup.procs"), "99999999\n").unwrap();
        let scope = cgroup(dir.path()).unwrap();
        let error = scope_names_child(&scope, 4242).expect_err("a nonmember is not named");
        assert!(format!("{error:#}").contains("not a member"), "{error:#}");
    }

    #[test]
    fn scope_names_child_refuses_an_unreadable_cgroup() {
        let dir = tempfile::tempdir().unwrap();
        let scope = cgroup(dir.path()).unwrap();
        let error =
            scope_names_child(&scope, 4242).expect_err("an unreadable cgroup names nothing");
        assert!(format!("{error:#}").contains("membership"), "{error:#}");
    }

    #[test]
    fn run_cgroup_survivors_excluding_counts_other_members() {
        let base = tempfile::tempdir().unwrap();
        let group = RunCgroup::create(base.path()).unwrap();
        std::fs::write(group.path().join("cgroup.procs"), "100\n200\n300\n").unwrap();
        assert_eq!(group.survivors_excluding(100).unwrap(), 2);
        assert_eq!(group.survivors_excluding(999).unwrap(), 3);
        assert_eq!(group.survivors_excluding(200).unwrap(), 2);
    }

    #[test]
    fn run_cgroup_survivors_excluding_ignores_malformed_lines() {
        let base = tempfile::tempdir().unwrap();
        let group = RunCgroup::create(base.path()).unwrap();
        std::fs::write(group.path().join("cgroup.procs"), "abc\n\n100\n").unwrap();
        assert_eq!(group.survivors_excluding(200).unwrap(), 1);
    }

    #[test]
    fn run_cgroup_survivors_excluding_fails_on_an_unreadable_cgroup() {
        let base = tempfile::tempdir().unwrap();
        let group = RunCgroup::create(base.path()).unwrap();
        let error = group
            .survivors_excluding(100)
            .expect_err("a missing cgroup.procs fails the count");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn scope_names_child_refuses_system_scope() {
        let error =
            scope_names_child(&Scope::System, 4242).expect_err("system scope names no child");
        assert!(format!("{error:#}").contains("never names"), "{error:#}");
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
