//! Capture scope. The BPF side observes nothing until a filter is
//! installed — there is no implicit system-wide capture.

use crate::attach::Scope;
use anyhow::{Context as _, Result};
use aya::Ebpf;
use aya::maps::{Array, CgroupArray, HashMap};
use p11scope_ebpf_common::{CFG_FLAGS, FLAG_CGROUP_FILTER, FLAG_PID_FILTER};
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

pub fn apply(ebpf: &mut Ebpf, scope: &Scope) -> Result<()> {
    let mut flags: u64 = 0;
    match scope {
        Scope::Pid(pid) => {
            let mut m: HashMap<_, u32, u8> =
                HashMap::try_from(ebpf.map_mut("PID_FILTER").context("PID_FILTER map")?)?;
            m.insert(*pid, 1, 0)?;
            flags |= FLAG_PID_FILTER;
        }
        Scope::Cgroup { path, .. } => {
            let directory = std::fs::File::open(path)
                .with_context(|| format!("opening cgroup {}", path.display()))?;
            let mut groups: CgroupArray<_> =
                CgroupArray::try_from(ebpf.map_mut("CGROUP_FILTER").context("CGROUP_FILTER map")?)?;
            groups.set(0, directory, 0)?;
            flags |= FLAG_CGROUP_FILTER;
        }
    }
    let mut cfg: Array<_, u64> = Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map")?)?;
    cfg.set(CFG_FLAGS, flags, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
