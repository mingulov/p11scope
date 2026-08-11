//! Capture scope. The BPF side observes nothing until a filter is
//! installed — there is no implicit system-wide capture.

use crate::attach::Scope;
use anyhow::{Context as _, Result, anyhow};
use aya::Ebpf;
use aya::maps::{Array, HashMap};
use p11scope_ebpf_common::{CFG_CGROUP_LEVEL, CFG_FLAGS, FLAG_CGROUP_FILTER, FLAG_PID_FILTER};
use std::path::Path;

/// A cgroup's kernel id is its directory inode number — the same value
/// `bpf_get_current_cgroup_id()` (and `bpf_get_current_ancestor_cgroup_id`
/// at the matching level) returns for a task inside it.
pub fn cgroup_id(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::metadata(path)
        .with_context(|| format!("reading cgroup path {}", path.display()))?;
    Ok(md.ino())
}

/// The target cgroup's level in the hierarchy — root (`/sys/fs/cgroup`
/// itself) is level 0, each path component below it adds one — for
/// `bpf_get_current_ancestor_cgroup_id`. Purely lexical (no filesystem
/// access): the path's component list under the fixed `/sys/fs/cgroup`
/// prefix *is* the level, so this cannot disagree with what the BPF side
/// computes at attach time.
pub fn cgroup_level(path: &Path) -> Result<u32> {
    let root = Path::new("/sys/fs/cgroup");
    let rel = path
        .strip_prefix(root)
        .map_err(|_| anyhow!("--cgroup path {} is not under {}", path.display(), root.display()))?;
    Ok(rel.components().count() as u32)
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
    let mut cgroup_level_val: u64 = 0;
    match scope {
        Scope::Pid(pid) => {
            let mut m: HashMap<_, u32, u8> =
                HashMap::try_from(ebpf.map_mut("PID_FILTER").context("PID_FILTER map")?)?;
            m.insert(*pid, 1, 0)?;
            flags |= FLAG_PID_FILTER;
        }
        Scope::Cgroup { id, level } => {
            // Ancestor match: the BPF side reads CFG_CGROUP_LEVEL and calls
            // bpf_get_current_ancestor_cgroup_id(level), so any task whose
            // ancestor at exactly this level is `id` matches — a
            // descendant of the target, at any depth, but never a sibling
            // subtree (whose ancestor at this same level has a different
            // id). Published before attach, like every other scope input.
            let mut m: HashMap<_, u64, u8> =
                HashMap::try_from(ebpf.map_mut("CGROUP_FILTER").context("CGROUP_FILTER map")?)?;
            m.insert(*id, 1, 0)?;
            flags |= FLAG_CGROUP_FILTER;
            cgroup_level_val = *level as u64;
        }
    }
    let mut cfg: Array<_, u64> =
        Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map")?)?;
    cfg.set(CFG_FLAGS, flags, 0)?;
    cfg.set(CFG_CGROUP_LEVEL, cgroup_level_val, 0)?;
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
    fn cgroup_level_from_representative_paths() {
        assert_eq!(cgroup_level(Path::new("/sys/fs/cgroup")).unwrap(), 0);
        assert_eq!(cgroup_level(Path::new("/sys/fs/cgroup/a")).unwrap(), 1);
        assert_eq!(cgroup_level(Path::new("/sys/fs/cgroup/a/b")).unwrap(), 2);
        assert_eq!(
            cgroup_level(Path::new(
                "/sys/fs/cgroup/kubepods.slice/kubepods-pod123.slice/cri-containerd-abc.scope"
            ))
            .unwrap(),
            3
        );
    }

    #[test]
    fn cgroup_level_rejects_paths_outside_the_cgroup_root() {
        let e = cgroup_level(Path::new("/tmp/not-a-cgroup")).unwrap_err();
        assert!(e.to_string().contains("is not under"));
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
