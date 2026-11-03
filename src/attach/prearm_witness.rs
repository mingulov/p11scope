//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pre-arm mapping-instant witness (WU-13 P-C phase 2): short-lived startup
//! object proving no scope member had the pinned provider mapped between
//! scope start and attach-complete.

pub(crate) static WITNESS_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf-prearm-witness"));

pub(crate) const PROGRAM_UNMAP: &str = "p11_pw_unmap";
pub(crate) const PROGRAM_DEPART_EXIT: &str = "p11_pw_depart_exit";
pub(crate) const PROGRAM_DEPART_EXEC: &str = "p11_pw_depart_exec";
pub(crate) const PROGRAM_DEPART: &str = "p11_pw_depart";
pub(crate) const PROGRAM_TORN: &str = "p11_pw_torn";
pub(crate) const PROGRAM_MIGRATE: &str = "p11_pw_migrate";
pub(crate) const PROGRAM_WALK: &str = "p11_pw_walk";

/// ABI mirrors of `crates/ebpf/native/prearm_witness.h`. Sizes are pinned by
/// the object-shape test below; change both together.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PwCfg {
    pub active: u32,
    pub scope_kind: u32,
    pub target_tgid: u32,
    pub calib_tid: u32,
    pub cgroup_id: u64,
    pub calib_index: u32,
    pub pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PwWatchedKey {
    pub s_dev: u64,
    pub i_ino: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PwCalibSlot {
    pub hits: u64,
    pub s_dev: u64,
    pub i_ino: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PwState {
    pub busy: u64,
    pub seq: u64,
    pub latch_slots: u64,
    pub torn_slots: u64,
    pub found_slots: u64,
    pub migrations: u64,
    pub pending_in: u64,
    pub pending_out: u64,
    pub faults: u64,
    pub stuck: u64,
    pub walk_end: u64,
    pub walk_runs: u64,
    pub walk_vmas: u64,
}

const _: () = assert!(size_of::<PwCfg>() == 32);
const _: () = assert!(size_of::<PwWatchedKey>() == 16);
const _: () = assert!(size_of::<PwCalibSlot>() == 24);
const _: () = assert!(size_of::<PwState>() == 104);

/// Load error for the witness object.
#[derive(Debug)]
pub(crate) enum LoadError {
    /// A required program is missing from the object.
    MissingProgram(&'static str),
    /// aya failed to load (includes unparseable bytes).
    Aya(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::MissingProgram(name) => write!(f, "witness program missing: {name}"),
            LoadError::Aya(detail) => write!(f, "witness load failed: {detail}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// A loaded witness object with verified programs. The departure family
/// (exit/exec pair vs single) is resolved by the caller (P2-3); this loader
/// verifies the five family-independent programs plus whichever depart
/// programs the caller names.
pub(crate) struct StrictWitness {
    pub ebpf: aya::Ebpf,
}

/// Strict load: maps plus the named programs, with CO-RE relocated against
/// readable `btf`. Every named program must verify; a missing target fails
/// here (no silent skip).
pub(crate) fn load_witness_programs(
    btf: &aya::Btf,
    depart_programs: &[&'static str],
) -> Result<StrictWitness, LoadError> {
    let mut loader = aya::EbpfLoader::new();
    loader.btf(Some(btf));
    let mut ebpf = loader
        .load(WITNESS_OBJECT)
        .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
    for name in [PROGRAM_UNMAP, PROGRAM_TORN, PROGRAM_MIGRATE, PROGRAM_WALK]
        .into_iter()
        .chain(depart_programs.iter().copied())
    {
        let program = ebpf
            .program_mut(name)
            .ok_or(LoadError::MissingProgram(name))?;
        match name {
            PROGRAM_WALK => {
                let program: &mut aya::programs::Iter = program
                    .try_into()
                    .map_err(|error: aya::programs::ProgramError| {
                        LoadError::Aya(format!("{error:#}"))
                    })?;
                program
                    .load(crate::attach::identity_iter::ITER_TYPE_TASK_VMA, btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_TORN => {
                let program: &mut aya::programs::FExit = program
                    .try_into()
                    .map_err(|error: aya::programs::ProgramError| {
                        LoadError::Aya(format!("{error:#}"))
                    })?;
                program
                    .load("exit_mmap", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_UNMAP => {
                let program: &mut aya::programs::FEntry = program
                    .try_into()
                    .map_err(|error: aya::programs::ProgramError| {
                        LoadError::Aya(format!("{error:#}"))
                    })?;
                program
                    .load("uprobe_munmap", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_MIGRATE => {
                let program: &mut aya::programs::FEntry = program
                    .try_into()
                    .map_err(|error: aya::programs::ProgramError| {
                        LoadError::Aya(format!("{error:#}"))
                    })?;
                program
                    .load("cgroup_migrate", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_DEPART_EXIT => {
                let program: &mut aya::programs::FEntry = program
                    .try_into()
                    .map_err(|error: aya::programs::ProgramError| {
                        LoadError::Aya(format!("{error:#}"))
                    })?;
                program
                    .load("exit_mm_release", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_DEPART_EXEC => {
                let program: &mut aya::programs::FEntry = program
                    .try_into()
                    .map_err(|error: aya::programs::ProgramError| {
                        LoadError::Aya(format!("{error:#}"))
                    })?;
                program
                    .load("exec_mm_release", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_DEPART => {
                let program: &mut aya::programs::FEntry = program
                    .try_into()
                    .map_err(|error: aya::programs::ProgramError| {
                        LoadError::Aya(format!("{error:#}"))
                    })?;
                program
                    .load("mm_exit_exec_release", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            _ => return Err(LoadError::MissingProgram(name)),
        }
    }
    Ok(StrictWitness { ebpf })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    #[test]
    fn witness_object_carries_exact_programs_and_maps() {
        let parsed =
            aya_obj::Object::parse(super::WITNESS_OBJECT).expect("witness object parses");
        let programs: BTreeSet<&str> = parsed.programs.keys().map(String::as_str).collect();
        let expected_programs: BTreeSet<&str> = [
            "p11_pw_unmap",
            "p11_pw_depart_exit",
            "p11_pw_depart_exec",
            "p11_pw_depart",
            "p11_pw_torn",
            "p11_pw_migrate",
            "p11_pw_walk",
        ]
        .into_iter()
        .collect();
        assert_eq!(programs, expected_programs, "exact 7 witness programs");
        for (name, section_kind) in [
            ("p11_pw_unmap", "fentry"),
            ("p11_pw_depart_exit", "fentry"),
            ("p11_pw_depart_exec", "fentry"),
            ("p11_pw_depart", "fentry"),
            ("p11_pw_torn", "fexit"),
            ("p11_pw_migrate", "fentry"),
            ("p11_pw_walk", "iter"),
        ] {
            let program = parsed.programs.get(name).unwrap();
            let kind = match program.section {
                aya_obj::ProgramSection::FEntry { .. } => "fentry",
                aya_obj::ProgramSection::FExit { .. } => "fexit",
                aya_obj::ProgramSection::Iter { .. } => "iter",
                ref other => panic!("{name} has unexpected section {other:?}"),
            };
            assert_eq!(kind, section_kind, "{name} section kind");
        }
        // Eight maps with exact shapes (addendum §4.0; PW_CALIB is 64 slots
        // plus the self-departs cell at index 64).
        let expected_maps: &[(&str, u32, u32, u32, u32, u32)] = &[
            ("PW_CFG", 2, 4, 32, 1, 128),
            ("PW_WATCHED", 1, 16, 4, 64, 128),
            ("PW_CALIB", 2, 4, 24, 65, 0),
            ("PW_STATE", 2, 4, 104, 1, 0),
            ("PW_DEPARTED", 1, 8, 24, 16384, 1),
            ("PW_VISITED", 1, 8, 1, 65536, 1),
            ("PW_SELF", 2, 4, 8, 1, 0),
            ("PW_RUN", 2, 4, 56, 1, 0),
        ];
        let maps: BTreeSet<&str> = parsed.maps.keys().map(String::as_str).collect();
        let expected_names: BTreeSet<&str> =
            expected_maps.iter().map(|(name, ..)| *name).collect();
        assert_eq!(maps, expected_names, "exact 8 witness maps");
        for (name, map_type, key_size, value_size, max_entries, flags) in expected_maps {
            let actual = parsed.maps.get(*name).unwrap();
            assert_eq!(actual.map_type(), *map_type, "{name} type");
            assert_eq!(actual.key_size(), *key_size, "{name} key");
            assert_eq!(actual.value_size(), *value_size, "{name} value");
            assert_eq!(actual.max_entries(), *max_entries, "{name} entries");
            assert_eq!(actual.map_flags(), *flags, "{name} flags");
        }
    }

    /// Privileged: the witness object loads and attaches on the host kernel.
    /// Records per-program verifier instruction counts via eprintln (copied
    /// into the phase report and P2-9 budgets).
    #[test]
    #[ignore = "privileged: loads the witness object on the host kernel"]
    fn privileged_prearm_witness_loads_and_attaches() {
        let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
        // Departure family by kernel: 7.3+ has the single, older the pair.
        let has_single = btf
            .id_by_type_name_kind("mm_exit_exec_release", aya_obj::btf::BtfKind::Func)
            .is_ok();
        let depart: &[&'static str] = if has_single {
            &[super::PROGRAM_DEPART]
        } else {
            &[super::PROGRAM_DEPART_EXIT, super::PROGRAM_DEPART_EXEC]
        };
        let mut loaded =
            super::load_witness_programs(&btf, depart).expect("witness programs verify");
        // Attach every loaded program; links drop at scope end.
        let mut attached = Vec::new();
        for name in [
            super::PROGRAM_UNMAP,
            super::PROGRAM_TORN,
            super::PROGRAM_MIGRATE,
            super::PROGRAM_WALK,
        ]
        .into_iter()
        .chain(depart.iter().copied())
        {
            if name == super::PROGRAM_WALK {
                let program: &mut aya::programs::Iter = loaded
                    .ebpf
                    .program_mut(name)
                    .unwrap()
                    .try_into()
                    .unwrap();
                let link = program.attach().expect("attach walk");
                attached.push(format!("{name}: iter link"));
                drop(link);
                continue;
            }
            if name == super::PROGRAM_TORN {
                let program: &mut aya::programs::FExit = loaded
                    .ebpf
                    .program_mut(name)
                    .unwrap()
                    .try_into()
                    .unwrap();
                let _link = program.attach().expect("attach fexit");
                attached.push(format!("{name}: fexit"));
                continue;
            }
            let program: &mut aya::programs::FEntry = loaded
                .ebpf
                .program_mut(name)
                .unwrap()
                .try_into()
                .unwrap();
            let _link = program.attach().expect("attach fentry");
            attached.push(format!("{name}: fentry"));
        }
        eprintln!("witness attach ok: {}", attached.join(", "));
        // Instruction counts come from the verifier-stats probe in P2-7/P2-9;
        // this cell proves load+attach on the host.
        assert!(!attached.is_empty());
    }
}
