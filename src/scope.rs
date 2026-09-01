//! Capture scope. The BPF side observes nothing until a filter is
//! installed — there is no implicit system-wide capture.

use crate::attach::{CapturePolicy, Scope};
use anyhow::{Context as _, Result, bail};
use aya::Ebpf;
use aya::maps::{Array, CgroupArray, HashMap};
use p11scope_ebpf_common::{
    CFG_FLAGS, FLAG_CGROUP_FILTER, FLAG_PAUSE_ENABLED, FLAG_PID_FILTER, valid_config,
};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

/// Opens and retains a cgroup directory for userspace walking and kernel publication.
pub fn cgroup(path: &Path) -> Result<Scope> {
    use std::os::unix::fs::MetadataExt as _;
    let dir =
        File::open(path).with_context(|| format!("reading cgroup path {}", path.display()))?;
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

/// Publishes one exact scope and policy and verifies every supported
/// readback. The retained cgroup descriptor is cloned into the kernel map.
pub(crate) fn publish(
    ebpf: &mut Ebpf,
    scope: &Scope,
    policy: CapturePolicy,
    generation_token: Option<u64>,
) -> Result<()> {
    if generation_token == Some(0) {
        bail!("pause generation token must be non-zero");
    }
    if generation_token.is_some() && !matches!(scope, Scope::Pid(_)) {
        bail!("pause generation requires PID scope");
    }
    let scope_flag = match scope {
        Scope::Pid(_) => FLAG_PID_FILTER,
        Scope::Cgroup { .. } => FLAG_CGROUP_FILTER,
    };
    let pause_flag = generation_token.map_or(0, |_| FLAG_PAUSE_ENABLED);
    let config = scope_flag | policy.config_bit() | pause_flag;
    if !valid_config(config) {
        bail!("refusing invalid CONFIG {config:#x}");
    }

    let mut expected_pids = BTreeMap::new();
    match scope {
        Scope::Pid(pid) => {
            if *pid == 0 {
                bail!("pid must be non-zero");
            }
            let mut m: HashMap<_, u32, u64> =
                HashMap::try_from(ebpf.map_mut("PID_FILTER").context("PID_FILTER map")?)?;
            let token = generation_token.unwrap_or(1);
            m.insert(*pid, token, 0)?;
            expected_pids.insert(*pid, token);
        }
        Scope::Cgroup { dir, .. } => {
            let mut groups: CgroupArray<_> =
                CgroupArray::try_from(ebpf.map_mut("CGROUP_FILTER").context("CGROUP_FILTER map")?)?;
            // CgroupArray has no userspace lookup; exact metadata, this
            // retained descriptor, and successful set are the content proof.
            publish_cgroup_fd_with(dir, |directory| {
                groups.set(0, directory, 0)?;
                Ok(())
            })?;
        }
    }

    let pids: HashMap<_, u32, u64> =
        HashMap::try_from(ebpf.map("PID_FILTER").context("PID_FILTER map")?)?;
    let actual_pids = pids.iter().collect::<Result<BTreeMap<_, _>, _>>()?;
    if actual_pids != expected_pids {
        bail!("PID_FILTER exact readback differs from the selected scope");
    }

    let mut cfg: Array<_, u64> = Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map")?)?;
    cfg.set(CFG_FLAGS, config, 0)?;
    let cfg: Array<_, u64> = Array::try_from(ebpf.map("CONFIG").context("CONFIG map")?)?;
    let readback = cfg.get(&CFG_FLAGS, 0)?;
    if readback != config || !valid_config(readback) {
        bail!("CONFIG exact readback {readback:#x} differs from {config:#x}");
    }

    Ok(())
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
    fn cgroup_constructor_uses_the_directory_inode() {
        let root = tempfile::tempdir().unwrap();
        use std::os::unix::fs::MetadataExt as _;
        let expected = std::fs::metadata(root.path()).unwrap().ino();
        let Scope::Cgroup { id, .. } = cgroup(root.path()).unwrap() else {
            unreachable!()
        };
        assert_eq!(id, expected);
    }

    #[test]
    fn missing_cgroup_path_errors_loudly() {
        let e = cgroup(Path::new("/sys/fs/cgroup/definitely-not-here")).unwrap_err();
        assert!(e.to_string().contains("reading cgroup path"));
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
}
