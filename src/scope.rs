//! Capture scope. The BPF side observes nothing until a filter is
//! installed — there is no implicit system-wide capture.

use crate::attach::Scope;
use anyhow::{Context as _, Result};
use aya::Ebpf;
use aya::maps::{Array, HashMap};
use p11scope_ebpf_common::{CFG_FLAGS, FLAG_CGROUP_FILTER, FLAG_PID_FILTER};
use std::path::Path;

/// A cgroup's kernel id is its directory inode number — the same value
/// `bpf_get_current_cgroup_id()` returns for a task inside it.
pub fn cgroup_id(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::metadata(path)
        .with_context(|| format!("reading cgroup path {}", path.display()))?;
    Ok(md.ino())
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
        Scope::Cgroup(id) => {
            // Exact-match only: bpf_get_current_cgroup_id() returns the
            // task's leaf cgroup, so processes living in a *descendant* of
            // this cgroup are not matched. Ancestor matching is Phase 2
            // work.
            let mut m: HashMap<_, u64, u8> =
                HashMap::try_from(ebpf.map_mut("CGROUP_FILTER").context("CGROUP_FILTER map")?)?;
            m.insert(*id, 1, 0)?;
            flags |= FLAG_CGROUP_FILTER;
        }
    }
    let mut cfg: Array<_, u64> =
        Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map")?)?;
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
}
