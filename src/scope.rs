//! Capture scope. The BPF side observes nothing until a filter is
//! installed — there is no implicit system-wide capture.

use crate::attach::{CapturePolicy, Scope};
use anyhow::{Context as _, Result, bail};
use aya::Ebpf;
use aya::maps::{Array, CgroupArray, HashMap, MapType};
use p11scope_ebpf_common::{CFG_FLAGS, FLAG_CGROUP_FILTER, FLAG_PID_FILTER, valid_config};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;

/// A cgroup's kernel id is its directory inode number — the value returned
/// by `bpf_get_current_cgroup_id()` for a task directly inside it. Scope
/// matching itself uses a `CgroupArray`, including descendants.
pub fn cgroup_id(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::metadata(path)
        .with_context(|| format!("reading cgroup path {}", path.display()))?;
    Ok(md.ino())
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

#[derive(Debug)]
pub struct PublishedScope {
    pub config: u64,
    pub cgroup_file: Option<File>,
}

/// Publishes one exact scope and policy and verifies every supported
/// readback. The returned cgroup descriptor may be dropped once publication
/// succeeds — the kernel holds its own cgroup reference through the map, so
/// the caller does not need to keep the fd open.
pub fn publish(ebpf: &mut Ebpf, scope: &Scope, policy: CapturePolicy) -> Result<PublishedScope> {
    let scope_flag = match scope {
        Scope::Pid(_) => FLAG_PID_FILTER,
        Scope::Cgroup { .. } => FLAG_CGROUP_FILTER,
    };
    let config = scope_flag | policy.config_bit();
    if !valid_config(config) {
        bail!("refusing invalid CONFIG {config:#x}");
    }

    let pid_info = crate::attach::policy_map_data(
        "PID_FILTER",
        ebpf.map("PID_FILTER").context("PID_FILTER map")?,
    )?
    .info()
    .context("reading PID_FILTER map info")?;
    if pid_info.map_type()? != MapType::Hash || pid_info.max_entries() != 1024 {
        bail!(
            "PID_FILTER has type {:?} and capacity {}, expected Hash and 1024",
            pid_info.map_type()?,
            pid_info.max_entries()
        );
    }

    let cgroup_info = crate::attach::policy_map_data(
        "CGROUP_FILTER",
        ebpf.map("CGROUP_FILTER").context("CGROUP_FILTER map")?,
    )?
    .info()
    .context("reading CGROUP_FILTER map info")?;
    if cgroup_info.map_type()? != MapType::CgroupArray || cgroup_info.max_entries() != 1 {
        bail!(
            "CGROUP_FILTER has type {:?} and capacity {}, expected CgroupArray and 1",
            cgroup_info.map_type()?,
            cgroup_info.max_entries()
        );
    }

    let mut expected_pids = BTreeMap::new();
    let mut cgroup_file = None;
    match scope {
        Scope::Pid(pid) => {
            if *pid == 0 {
                bail!("pid must be non-zero");
            }
            let mut m: HashMap<_, u32, u8> =
                HashMap::try_from(ebpf.map_mut("PID_FILTER").context("PID_FILTER map")?)?;
            m.insert(*pid, 1, 0)?;
            expected_pids.insert(*pid, 1);
        }
        Scope::Cgroup { id, path } => {
            use std::os::unix::fs::MetadataExt as _;
            let directory =
                File::open(path).with_context(|| format!("opening cgroup {}", path.display()))?;
            let opened_id = directory
                .metadata()
                .with_context(|| format!("reading opened cgroup {}", path.display()))?
                .ino();
            if opened_id != *id {
                bail!(
                    "cgroup {} changed from inode {} to {}; refusing mismatched scope",
                    path.display(),
                    id,
                    opened_id
                );
            }
            let mut groups: CgroupArray<_> =
                CgroupArray::try_from(ebpf.map_mut("CGROUP_FILTER").context("CGROUP_FILTER map")?)?;
            groups.set(0, directory.try_clone()?, 0)?;
            cgroup_file = Some(directory);
        }
    }

    let pids: HashMap<_, u32, u8> =
        HashMap::try_from(ebpf.map("PID_FILTER").context("PID_FILTER map")?)?;
    let actual_pids = pids.iter().collect::<Result<BTreeMap<_, _>, _>>()?;
    if actual_pids != expected_pids {
        bail!("PID_FILTER exact readback differs from the selected scope");
    }

    let config_info =
        crate::attach::policy_map_data("CONFIG", ebpf.map("CONFIG").context("CONFIG map")?)?
            .info()
            .context("reading CONFIG map info")?;
    if config_info.map_type()? != MapType::Array || config_info.max_entries() != 1 {
        bail!(
            "CONFIG has type {:?} and capacity {}, expected Array and 1",
            config_info.map_type()?,
            config_info.max_entries()
        );
    }
    let mut cfg: Array<_, u64> = Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map")?)?;
    cfg.set(CFG_FLAGS, config, 0)?;
    let cfg: Array<_, u64> = Array::try_from(ebpf.map("CONFIG").context("CONFIG map")?)?;
    let readback = cfg.get(&CFG_FLAGS, 0)?;
    if readback != config || !valid_config(readback) {
        bail!("CONFIG exact readback {readback:#x} differs from {config:#x}");
    }

    Ok(PublishedScope {
        config,
        cgroup_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::{
        FLAG_POLICY_AGGREGATE, FLAG_POLICY_ALLOWLISTED, FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA,
        valid_config,
    };

    #[test]
    fn config_requires_exactly_one_scope_and_one_policy() {
        for scope in [FLAG_PID_FILTER, FLAG_CGROUP_FILTER] {
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
            FLAG_POLICY_ALLOWLISTED,
            FLAG_PID_FILTER | FLAG_CGROUP_FILTER | FLAG_POLICY_ALLOWLISTED,
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
    fn cgroup_id_is_the_directory_inode() {
        // The unified hierarchy root always exists on a cgroup2 system;
        // if it does not, there is nothing meaningful to assert.
        let root = Path::new("/sys/fs/cgroup");
        if !root.exists() {
            eprintln!("SKIP: no /sys/fs/cgroup");
            return;
        }
        use std::os::unix::fs::MetadataExt as _;
        let expected = std::fs::metadata(root).unwrap().ino();
        assert_eq!(cgroup_id(root).unwrap(), expected);
    }

    #[test]
    fn missing_cgroup_path_errors_loudly() {
        let e = cgroup_id(Path::new("/sys/fs/cgroup/definitely-not-here")).unwrap_err();
        assert!(e.to_string().contains("reading cgroup path"));
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
}
