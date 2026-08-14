use crate::attach::Scope;
use anyhow::{Result, anyhow};
use p11scope_manifest::identity::{ElfLoader, inspect_elf_loader, open_object};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OracleMode {
    TrustedWorkload,
    Hardened,
}

pub(crate) struct OracleSelection {
    pub(crate) mode: OracleMode,
}

struct HardenedFacts<'a> {
    observer_loader: ElfLoader,
    observer_owner: u32,
    observer_mode: u32,
    observer_status: &'a str,
    target_status: &'a str,
    observer_uid_map: &'a str,
    observer_user_namespace: (u64, u64),
    init_user_namespace: (u64, u64),
}

#[derive(Debug, PartialEq, Eq)]
struct ProcessStatus {
    uids: [u32; 4],
    capabilities: u64,
}

fn trusted_required(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow!(
        "{reason}; pass --trusted-workload only when the observed workload is explicitly trusted"
    )
}

fn select_from_facts(
    scope: &Scope,
    trusted_workload: bool,
    facts: Option<HardenedFacts<'_>>,
) -> Result<OracleMode> {
    let eligible = (|| -> Result<()> {
        if matches!(scope, Scope::Cgroup { .. }) {
            return Err(anyhow!(
                "hostile-workload oracle mode cannot prove the identity of future cgroup members"
            ));
        }
        let facts = facts.ok_or_else(|| anyhow!("hardened oracle facts are unavailable"))?;
        if facts.observer_loader.interpreter.is_some() || !facts.observer_loader.needed.is_empty() {
            return Err(anyhow!(
                "hostile-workload oracle mode requires the fully static observer",
            ));
        }
        if facts.observer_owner != 0
            || facts.observer_mode & libc::S_IFMT != libc::S_IFREG
            || facts.observer_mode & 0o022 != 0
        {
            return Err(anyhow!(
                "hostile-workload oracle mode requires a root-owned non-group/world-writable observer",
            ));
        }
        let observer = parse_status(facts.observer_status)?;
        if observer.uids != [0; 4] {
            return Err(anyhow!(
                "hostile-workload oracle mode requires all observer UIDs to be root",
            ));
        }
        let mut uid_map_lines = facts.observer_uid_map.lines();
        let uid_map = uid_map_lines
            .next()
            .ok_or_else(|| anyhow!("observer user namespace has no UID mapping"))?;
        let uid_map = uid_map
            .split_ascii_whitespace()
            .map(str::parse)
            .collect::<Result<Vec<u64>, _>>()
            .map_err(|_| anyhow!("observer user namespace has an invalid UID mapping"))?;
        if uid_map_lines.next().is_some() || uid_map != [0, 0, u64::from(u32::MAX)] {
            return Err(anyhow!(
                "hostile-workload oracle mode requires one full initial-namespace UID mapping"
            ));
        }
        if facts.observer_user_namespace.1 == 0
            || facts.observer_user_namespace != facts.init_user_namespace
        {
            return Err(anyhow!(
                "hostile-workload oracle mode requires the observer and PID 1 user namespaces to match"
            ));
        }
        let target = parse_status(facts.target_status)?;
        if target.uids.contains(&0) {
            return Err(anyhow!(
                "the observed process has a root UID and can share authority with the observer",
            ));
        }
        let dangerous = (1u64 << 5) | (1u64 << 7) | (1u64 << 19);
        if target.capabilities & dangerous != 0 {
            return Err(anyhow!(
                "the observed process has signal, set-UID, or ptrace capability over the observer",
            ));
        }
        Ok(())
    })();
    match eligible {
        Ok(()) => Ok(OracleMode::Hardened),
        Err(_) if trusted_workload => Ok(OracleMode::TrustedWorkload),
        Err(error) => Err(trusted_required(error)),
    }
}

pub(crate) fn select(scope: &Scope, trusted_workload: bool) -> Result<OracleSelection> {
    let Scope::Pid(pid) = scope else {
        return select_from_facts(scope, trusted_workload, None)
            .map(|mode| OracleSelection { mode });
    };
    let selected = (|| -> Result<OracleMode> {
        let observer = open_object(Path::new("/proc/self/exe")).map_err(|error| {
            trusted_required(format!("opening the running observer failed: {error}"))
        })?;
        let metadata = observer.metadata().map_err(|error| {
            trusted_required(format!(
                "reading the running observer metadata failed: {error}"
            ))
        })?;
        let observer_loader = inspect_elf_loader(&observer).map_err(|error| {
            trusted_required(format!("inspecting the running observer failed: {error}"))
        })?;
        let observer_status = std::fs::read_to_string("/proc/self/status").map_err(|error| {
            trusted_required(format!(
                "reading the observer process status failed: {error}"
            ))
        })?;
        let target_status =
            std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|error| {
                trusted_required(format!(
                    "reading observed process {pid} status failed: {error}"
                ))
            })?;
        let observer_uid_map = std::fs::read_to_string("/proc/self/uid_map").map_err(|error| {
            trusted_required(format!("reading the observer UID map failed: {error}"))
        })?;
        let observer_user_namespace =
            namespace_id(Path::new("/proc/self/ns/user")).map_err(|error| {
                trusted_required(format!(
                    "opening the observer user namespace failed: {error}"
                ))
            })?;
        let init_user_namespace = namespace_id(Path::new("/proc/1/ns/user")).map_err(|error| {
            trusted_required(format!("opening the PID 1 user namespace failed: {error}"))
        })?;
        select_from_facts(
            scope,
            false,
            Some(HardenedFacts {
                observer_loader,
                observer_owner: metadata.uid(),
                observer_mode: metadata.mode(),
                observer_status: &observer_status,
                target_status: &target_status,
                observer_uid_map: &observer_uid_map,
                observer_user_namespace,
                init_user_namespace,
            }),
        )
    })();
    let mode = match selected {
        Err(_) if trusted_workload => Ok(OracleMode::TrustedWorkload),
        result => result,
    }?;
    Ok(OracleSelection { mode })
}

fn namespace_id(path: &Path) -> Result<(u64, u64)> {
    let metadata = std::fs::File::open(path)?.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

fn parse_status(status: &str) -> Result<ProcessStatus> {
    let mut uids = None;
    let mut capabilities = 0u64;
    let mut seen_caps = 0u8;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            if uids.is_some() {
                return Err(anyhow!("process status contains duplicate Uid fields"));
            }
            let values = value
                .split_ascii_whitespace()
                .map(str::parse)
                .collect::<Result<Vec<u32>, _>>()
                .map_err(|_| anyhow!("process status contains an invalid Uid field"))?;
            uids = Some(
                values
                    .try_into()
                    .map_err(|_| anyhow!("process status Uid field must contain four values"))?,
            );
            continue;
        }
        for (index, name) in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
            .into_iter()
            .enumerate()
        {
            let Some(value) = line.strip_prefix(name) else {
                continue;
            };
            let bit = 1u8 << index;
            if seen_caps & bit != 0 {
                return Err(anyhow!("process status contains duplicate {name} fields"));
            }
            seen_caps |= bit;
            capabilities |= u64::from_str_radix(value.trim(), 16)
                .map_err(|_| anyhow!("process status contains an invalid {name} field"))?;
        }
    }
    if seen_caps != 0b1111 {
        return Err(anyhow!("process status is missing capability fields"));
    }
    Ok(ProcessStatus {
        uids: uids.ok_or_else(|| anyhow!("process status is missing its Uid field"))?,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attach::Scope;
    use p11scope_manifest::identity::ElfLoader;
    use std::ffi::OsString;
    use std::path::PathBuf;

    const ROOT_STATUS: &str = "Uid:\t0\t0\t0\t0\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n";
    const TARGET_STATUS: &str = "Uid:\t1000\t1000\t1000\t1000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n";
    const FULL_UID_MAP: &str = "         0          0 4294967295\n";

    fn static_loader() -> ElfLoader {
        ElfLoader {
            interpreter: None,
            needed: vec![],
            soname: None,
        }
    }

    #[test]
    fn valid_static_root_pid_facts_select_hardened_mode() {
        let mode = select_from_facts(
            &Scope::Pid(42),
            false,
            Some(HardenedFacts {
                observer_loader: static_loader(),
                observer_owner: 0,
                observer_mode: 0o100755,
                observer_status: ROOT_STATUS,
                target_status: TARGET_STATUS,
                observer_uid_map: FULL_UID_MAP,
                observer_user_namespace: (4, 1),
                init_user_namespace: (4, 1),
            }),
        )
        .unwrap();

        assert_eq!(mode, OracleMode::Hardened);
    }

    #[test]
    fn trusted_acknowledgement_is_only_a_fallback() {
        let mode = select_from_facts(
            &Scope::Pid(42),
            true,
            Some(HardenedFacts {
                observer_loader: static_loader(),
                observer_owner: 0,
                observer_mode: 0o100755,
                observer_status: ROOT_STATUS,
                target_status: TARGET_STATUS,
                observer_uid_map: FULL_UID_MAP,
                observer_user_namespace: (4, 1),
                init_user_namespace: (4, 1),
            }),
        )
        .unwrap();
        assert_eq!(mode, OracleMode::Hardened);
        assert_eq!(
            select_from_facts(&Scope::Pid(42), true, None).unwrap(),
            OracleMode::TrustedWorkload
        );
    }

    #[test]
    fn cgroup_requires_explicit_trusted_acknowledgement() {
        let scope = Scope::Cgroup {
            id: 7,
            path: PathBuf::from("/sys/fs/cgroup/test"),
        };
        let error = select_from_facts(&scope, false, None).unwrap_err();

        assert!(
            error.to_string().contains("--trusted-workload"),
            "{error:#}"
        );
        assert_eq!(
            select_from_facts(&scope, true, None).unwrap(),
            OracleMode::TrustedWorkload
        );
    }

    #[test]
    fn dynamic_or_non_root_observer_facts_are_refused() {
        for (loader, owner, mode, status) in [
            (
                ElfLoader {
                    interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
                    needed: vec![OsString::from("libc.so.6")],
                    soname: None,
                },
                0,
                0o100755,
                ROOT_STATUS,
            ),
            (static_loader(), 1000, 0o100755, ROOT_STATUS),
            (static_loader(), 0, 0o100775, ROOT_STATUS),
            (static_loader(), 0, 0o100755, TARGET_STATUS),
        ] {
            let error = select_from_facts(
                &Scope::Pid(42),
                false,
                Some(HardenedFacts {
                    observer_loader: loader,
                    observer_owner: owner,
                    observer_mode: mode,
                    observer_status: status,
                    target_status: TARGET_STATUS,
                    observer_uid_map: FULL_UID_MAP,
                    observer_user_namespace: (4, 1),
                    init_user_namespace: (4, 1),
                }),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("--trusted-workload"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn target_root_or_kill_setuid_ptrace_capability_is_refused() {
        for status in [
            ROOT_STATUS.to_string(),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "0\t1000\t1000\t1000"),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "1000\t0\t1000\t1000"),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "1000\t1000\t0\t1000"),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "1000\t1000\t1000\t0"),
            TARGET_STATUS.replace("CapInh:\t0000000000000000", "CapInh:\t0000000000080000"),
            TARGET_STATUS.replace("CapPrm:\t0000000000000000", "CapPrm:\t0000000000000080"),
            TARGET_STATUS.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000080000"),
            TARGET_STATUS.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000020"),
        ] {
            let error = select_from_facts(
                &Scope::Pid(42),
                false,
                Some(HardenedFacts {
                    observer_loader: static_loader(),
                    observer_owner: 0,
                    observer_mode: 0o100755,
                    observer_status: ROOT_STATUS,
                    target_status: &status,
                    observer_uid_map: FULL_UID_MAP,
                    observer_user_namespace: (4, 1),
                    init_user_namespace: (4, 1),
                }),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("--trusted-workload"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn partial_or_different_user_namespace_is_refused() {
        for (uid_map, observer_namespace, init_namespace) in [
            ("0 0 65536\n", (4, 1), (4, 1)),
            ("0 0 4294967295\n1 1 1\n", (4, 1), (4, 1)),
            (FULL_UID_MAP, (4, 1), (4, 2)),
            (FULL_UID_MAP, (0, 0), (0, 0)),
        ] {
            let error = select_from_facts(
                &Scope::Pid(42),
                false,
                Some(HardenedFacts {
                    observer_loader: static_loader(),
                    observer_owner: 0,
                    observer_mode: 0o100755,
                    observer_status: ROOT_STATUS,
                    target_status: TARGET_STATUS,
                    observer_uid_map: uid_map,
                    observer_user_namespace: observer_namespace,
                    init_user_namespace: init_namespace,
                }),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("--trusted-workload"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn malformed_or_incomplete_proc_status_is_refused() {
        for status in [
            "",
            "Uid:\t1000\t1000\t1000\n",
            "Uid:\t1000\t1000\t1000\t1000\nCapInh:\tnot-hex\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n",
            "Uid:\t1000\t1000\t1000\t1000\nUid:\t1000\t1000\t1000\t1000\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n",
        ] {
            let error = parse_status(status).unwrap_err();
            assert!(error.to_string().contains("process status"), "{error:#}");
        }
    }
}
