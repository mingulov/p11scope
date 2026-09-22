//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::os::unix::fs::MetadataExt as _;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Operation {
    InsertPid(u32, u64),
    InsertCgroup(u64),
    ReadPids,
    WriteConfig(u32, u64),
    ReadConfig(u32),
}

#[derive(Default)]
struct ScopeMaps {
    pids: BTreeMap<u32, u64>,
    config: [u64; 2],
    cgroup: Option<File>,
    pid_readback: Option<BTreeMap<u32, u64>>,
    config_readback: BTreeMap<u32, u64>,
    operations: Vec<Operation>,
    fail_at: Option<usize>,
}

impl ScopeMaps {
    fn operation(&mut self, operation: Operation) -> Result<()> {
        self.operations.push(operation);
        if self.fail_at == Some(self.operations.len() - 1) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        Ok(())
    }
}

impl ScopePublicationIo for ScopeMaps {
    fn insert_pid(&mut self, pid: u32, token: u64) -> Result<()> {
        self.operation(Operation::InsertPid(pid, token))?;
        self.pids.insert(pid, token);
        Ok(())
    }

    fn insert_cgroup(&mut self, directory: File) -> Result<()> {
        self.operation(Operation::InsertCgroup(directory.metadata()?.ino()))?;
        self.cgroup = Some(directory);
        Ok(())
    }

    fn read_pids(&mut self) -> Result<BTreeMap<u32, u64>> {
        self.operation(Operation::ReadPids)?;
        Ok(self
            .pid_readback
            .clone()
            .unwrap_or_else(|| self.pids.clone()))
    }

    fn write_config(&mut self, index: u32, value: u64) -> Result<()> {
        self.operation(Operation::WriteConfig(index, value))?;
        self.config[index as usize] = value;
        Ok(())
    }

    fn read_config(&mut self, index: u32) -> Result<u64> {
        self.operation(Operation::ReadConfig(index))?;
        Ok(self
            .config_readback
            .get(&index)
            .copied()
            .unwrap_or(self.config[index as usize]))
    }
}

#[test]
fn inventory_pid_publication_writes_its_policy_directly_and_reads_both_config_cells() {
    let mut maps = ScopeMaps::default();
    publish_inventory_with(&Scope::Pid(101), &mut maps).unwrap();
    assert_eq!(maps.pids, BTreeMap::from([(101, 1)]));
    assert_eq!(maps.config, [0x81, 0]);
    assert_eq!(
        maps.operations,
        [
            Operation::InsertPid(101, 1),
            Operation::ReadPids,
            Operation::WriteConfig(0, 0x81),
            Operation::ReadConfig(0),
            Operation::ReadConfig(1),
        ]
    );
    assert!(p11scope_ebpf_common::valid_inventory_config(maps.config[0]));
    assert!(!p11scope_ebpf_common::valid_config(maps.config[0]));
    assert!(maps.cgroup.is_none());
}

#[test]
fn inventory_system_publication_requires_an_empty_pid_readback_and_explicit_system_bit() {
    let mut maps = ScopeMaps::default();
    publish_inventory_with(&Scope::System, &mut maps).unwrap();
    assert_eq!(maps.config, [0xc0, 0]);
    assert!(maps.pids.is_empty());
    assert!(maps.cgroup.is_none());
    assert_eq!(
        maps.operations,
        [
            Operation::ReadPids,
            Operation::WriteConfig(0, 0xc0),
            Operation::ReadConfig(0),
            Operation::ReadConfig(1),
        ]
    );
    let mut maps = ScopeMaps {
        pids: BTreeMap::from([(101, 1)]),
        ..ScopeMaps::default()
    };
    let error = publish_inventory_with(&Scope::System, &mut maps).unwrap_err();
    assert!(format!("{error:#}").contains("PID_FILTER"));
    assert_eq!(maps.operations, [Operation::ReadPids]);
}

#[test]
fn inventory_pid_zero_reaches_no_publication_operation() {
    let mut maps = ScopeMaps::default();
    assert!(publish_inventory_with(&Scope::Pid(0), &mut maps).is_err());
    assert!(maps.operations.is_empty());
}

#[test]
fn inventory_pid_readback_refuses_missing_foreign_wrong_and_zero_tokens_before_policy_write() {
    for actual in [
        BTreeMap::new(),
        BTreeMap::from([(101, 0)]),
        BTreeMap::from([(101, 2)]),
        BTreeMap::from([(102, 1)]),
        BTreeMap::from([(101, 1), (102, 1)]),
    ] {
        let mut maps = ScopeMaps {
            pid_readback: Some(actual),
            ..ScopeMaps::default()
        };
        let error = publish_inventory_with(&Scope::Pid(101), &mut maps).unwrap_err();
        assert!(format!("{error:#}").contains("PID_FILTER"));
        assert_eq!(
            maps.operations,
            [Operation::InsertPid(101, 1), Operation::ReadPids]
        );
        assert_eq!(maps.config, [0, 0]);
    }
}

#[test]
fn inventory_config_readback_rejects_detailed_pause_mixed_unknown_and_reserved_word_drift() {
    for bad in [
        0,
        0x01,
        0x05,
        0x09,
        0x11,
        0x83,
        0xa1,
        0xc1,
        0x81 | (1 << 63),
    ] {
        let mut maps = ScopeMaps {
            config_readback: BTreeMap::from([(0, bad)]),
            ..ScopeMaps::default()
        };
        let error = publish_inventory_with(&Scope::Pid(101), &mut maps).unwrap_err();
        assert!(
            format!("{error:#}").contains("CONFIG"),
            "{bad:#x}: {error:#}"
        );
        assert_eq!(maps.config, [0x81, 0]);
    }
    for reserved in [1, u64::MAX] {
        let mut maps = ScopeMaps {
            config_readback: BTreeMap::from([(1, reserved)]),
            ..ScopeMaps::default()
        };
        assert!(publish_inventory_with(&Scope::Pid(101), &mut maps).is_err());
        assert_eq!(maps.operations.last(), Some(&Operation::ReadConfig(1)));
    }
}

#[test]
fn inventory_cgroup_publication_clones_retained_directory_after_path_replacement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("selected.scope");
    let displaced = root.path().join("original.scope");
    std::fs::create_dir(&path).unwrap();
    let scope = cgroup(&path).unwrap();
    let original_inode = std::fs::metadata(&path).unwrap().ino();
    std::fs::rename(&path, &displaced).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_ne!(std::fs::metadata(&path).unwrap().ino(), original_inode);
    let mut maps = ScopeMaps::default();
    publish_inventory_with(&scope, &mut maps).unwrap();
    assert_eq!(maps.config, [0x82, 0]);
    assert_eq!(
        maps.operations,
        [
            Operation::InsertCgroup(original_inode),
            Operation::ReadPids,
            Operation::WriteConfig(0, 0x82),
            Operation::ReadConfig(0),
            Operation::ReadConfig(1),
        ]
    );
    drop(scope);
    assert_eq!(
        maps.cgroup.unwrap().metadata().unwrap().ino(),
        original_inode
    );
}

#[test]
fn inventory_scope_stops_at_each_io_failure_and_preserves_the_source_error() {
    let expected = [
        Operation::InsertPid(101, 1),
        Operation::ReadPids,
        Operation::WriteConfig(0, 0x81),
        Operation::ReadConfig(0),
        Operation::ReadConfig(1),
    ];
    for failed in 0..expected.len() {
        let mut maps = ScopeMaps {
            fail_at: Some(failed),
            ..ScopeMaps::default()
        };
        let error = publish_inventory_with(&Scope::Pid(101), &mut maps).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(maps.operations, expected[..=failed]);
    }
}

#[test]
fn detailed_scope_factoring_preserves_policies_pause_tokens_and_reserved_config_use() {
    for (policy, bit) in [
        (CapturePolicy::Allowlisted, 4),
        (CapturePolicy::UnsafeUnvalidatedMetadata, 8),
        (CapturePolicy::AggregateOnly, 16),
    ] {
        for token in [None, Some(17)] {
            let mut maps = ScopeMaps {
                config: [0, 0x1234],
                ..ScopeMaps::default()
            };
            publish_detailed_with(&Scope::Pid(101), policy, token, &mut maps).unwrap();
            assert_eq!(maps.pids, BTreeMap::from([(101, token.unwrap_or(1))]));
            assert_eq!(
                maps.config,
                [1 | bit | if token.is_some() { 32 } else { 0 }, 0x1234]
            );
            assert!(p11scope_ebpf_common::valid_config(maps.config[0]));
            assert!(!p11scope_ebpf_common::valid_inventory_config(
                maps.config[0]
            ));
            assert!(!maps.operations.contains(&Operation::ReadConfig(1)));
        }
    }
    for (scope, token) in [(Scope::Pid(101), Some(0)), (Scope::System, Some(17))] {
        let mut maps = ScopeMaps::default();
        assert!(
            publish_detailed_with(&scope, CapturePolicy::Allowlisted, token, &mut maps).is_err()
        );
        assert!(maps.operations.is_empty());
    }
}
