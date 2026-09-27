//! SPDX-License-Identifier: GPL-3.0-or-later
//! Caller preparation contracts. Only kernel allocation/IO is replaced;
//! validators and the preparation transaction are the production seams.

use super::*;
use aya::maps::MapType;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};

fn endpoint_budget(n: u64) -> InventoryBudget {
    InventoryBudget::new(n, n * 8).unwrap()
}

fn caller_budget() -> CallerBudget {
    // N=3, P=5: additional 24 + 280 = 304 bytes; global payload is 24.
    CallerBudget::new(endpoint_budget(3), 5, 304).unwrap()
}

#[test]
fn caller_budget_retains_distinct_endpoint_and_pair_payloads() {
    let caller = caller_budget();
    assert_eq!(caller.endpoint_budget(), endpoint_budget(3));
    assert_eq!(caller.pair_limit(), 5);
    assert_eq!(caller.additional_payload_bytes(), 304);
    assert_eq!(caller.endpoint_budget().payload_bytes(), 24);
    let maximum = CallerBudget::new(
        endpoint_budget(4_294_967_295),
        4_294_967_295,
        274_877_906_880,
    )
    .expect("u32 maximum N and P fit checked u64 payload accounting");
    assert_eq!(maximum.pair_limit(), 4_294_967_295);
}

#[test]
fn caller_budget_rejects_zero_out_of_range_and_overflowing_pair_counts() {
    for (pairs, bytes) in [
        (0, 24),
        (4_294_967_296, 240_518_168_600),
        (u64::MAX, u64::MAX),
    ] {
        assert!(
            CallerBudget::new(endpoint_budget(3), pairs, bytes).is_err(),
            "unusable pair count {pairs} was admitted"
        );
    }
}

#[test]
fn caller_budget_rejects_missing_or_surplus_additional_payload() {
    for bytes in [0, 24, 280, 303, 305, 328, u64::MAX] {
        assert!(
            CallerBudget::new(endpoint_budget(3), 5, bytes).is_err(),
            "N=3/P=5 requires exactly 304 additional bytes, not {bytes}"
        );
    }
}

fn map_fixture() -> BTreeMap<String, (InventoryMapKind, ExactMapMetadata)> {
    use InventoryMapKind as K;
    [
        ("CONFIG", K::Array, MapType::Array, 4, 8, 2, 128),
        ("PID_FILTER", K::Hash, MapType::Hash, 4, 8, 1024, 128),
        (
            "CGROUP_FILTER",
            K::CgroupArray,
            MapType::CgroupArray,
            4,
            4,
            1,
            0,
        ),
        (
            "TAIL_CALLS",
            K::ProgramArray,
            MapType::ProgramArray,
            4,
            4,
            2,
            0,
        ),
        (
            "STACK_GUARD",
            K::ProgramArray,
            MapType::ProgramArray,
            4,
            4,
            1,
            0,
        ),
        ("EVIDENCE", K::PerCpuArray, MapType::PerCpuArray, 4, 8, 9, 0),
        ("COUNTERS", K::PerCpuArray, MapType::PerCpuArray, 4, 8, 5, 0),
        ("DISCOVERY", K::RingBuf, MapType::RingBuf, 0, 0, 65_536, 0),
        ("DISCOVERY_STATE", K::Hash, MapType::Hash, 24, 24, 64, 0),
        (
            "THREAD_OWNER",
            K::Unsupported,
            MapType::TaskStorage,
            4,
            544,
            0,
            1,
        ),
        ("OWNER_CTL", K::Array, MapType::Array, 4, 56, 1, 0),
        ("USAGE", K::Array, MapType::Array, 4, 8, 3, 0),
        ("USAGE_CONFIG", K::Array, MapType::Array, 4, 8, 1, 128),
        (
            "USAGE_EVIDENCE",
            K::PerCpuArray,
            MapType::PerCpuArray,
            4,
            8,
            3,
            0,
        ),
        ("ENDPOINT_OBJECT", K::Array, MapType::Array, 4, 8, 3, 128),
        ("CALLER_USE", K::Hash, MapType::Hash, 24, 32, 5, 0),
        (
            "CALLER_EVIDENCE",
            K::PerCpuArray,
            MapType::PerCpuArray,
            4,
            8,
            4,
            0,
        ),
        (
            "TASK_COOKIE",
            K::Unsupported,
            MapType::TaskStorage,
            4,
            8,
            0,
            1,
        ),
        ("COOKIE_CTL", K::Array, MapType::Array, 4, 40, 1, 0),
    ]
    .into_iter()
    .map(
        |(name, kind, map_type, key_size, value_size, max_entries, flags)| {
            (
                name.to_owned(),
                (
                    kind,
                    ExactMapMetadata {
                        map_type,
                        key_size,
                        value_size,
                        max_entries,
                        flags,
                    },
                ),
            )
        },
    )
    .collect()
}

#[test]
fn caller_map_contract_accepts_exact_runtime_n3_p5_and_unsupported_task_storage() {
    let result = validate_caller_maps(&map_fixture(), caller_budget());
    assert!(
        result.is_ok(),
        "exact caller manifest was refused: {result:?}"
    );
}

#[test]
fn caller_map_contract_refuses_missing_extra_and_each_new_metadata_mutation() {
    let original = map_fixture();
    for name in [
        "ENDPOINT_OBJECT",
        "CALLER_USE",
        "CALLER_EVIDENCE",
        "TASK_COOKIE",
        "COOKIE_CTL",
    ] {
        let mut missing = original.clone();
        missing.remove(name);
        assert!(
            validate_caller_maps(&missing, caller_budget()).is_err(),
            "missing {name}"
        );
        for field in 0..6 {
            let mut changed = original.clone();
            let (kind, metadata) = changed.get_mut(name).unwrap();
            match field {
                0 => *kind = InventoryMapKind::RingBuf,
                1 => metadata.map_type = MapType::RingBuf,
                2 => metadata.key_size ^= 1,
                3 => metadata.value_size ^= 1,
                4 => metadata.max_entries ^= 1,
                5 => metadata.flags ^= 1,
                _ => unreachable!(),
            }
            assert!(
                validate_caller_maps(&changed, caller_budget()).is_err(),
                "{name}/{field}"
            );
        }
    }
    for name in ["EVENTS", "START", "ROOT_AFFILIATION", "EXTRA"] {
        let mut extra = original.clone();
        extra.insert(name.into(), original["CALLER_USE"]);
        assert!(
            validate_caller_maps(&extra, caller_budget()).is_err(),
            "extra {name}"
        );
    }
    for (name, wrong) in [("USAGE", 5), ("ENDPOINT_OBJECT", 5), ("CALLER_USE", 3)] {
        let mut changed = original.clone();
        changed.get_mut(name).unwrap().1.max_entries = wrong;
        assert!(
            validate_caller_maps(&changed, caller_budget()).is_err(),
            "N/P substitution {name}"
        );
    }
}

#[test]
fn caller_control_rejects_any_nonfresh_word_or_changed_lifetime_ticket_limit() {
    validate_caller_control(ImageIdentityControl {
        limit: 16_384,
        ..Default::default()
    })
    .unwrap();
    for word in 0..5 {
        let mut control = ImageIdentityControl {
            limit: 16_384,
            ..Default::default()
        };
        match word {
            0 => control.limit = 16_385,
            1 => control.next_ticket = 1,
            2 => control.unavailable = 1,
            3 => control.create_failures = 1,
            4 => control.retry_exhausted = 1,
            _ => unreachable!(),
        }
        assert!(
            validate_caller_control(control).is_err(),
            "nonfresh control word {word}"
        );
    }
    assert!(validate_caller_control(ImageIdentityControl::default()).is_err());
}

#[test]
fn caller_preparation_initializes_and_freezes_native_maps_before_loading_any_program() {
    use InventoryPreparation::*;
    let mut observed = vec![];
    prepare_caller_inventory_with(
        endpoint_budget(3),
        caller_budget(),
        AttachBackend::Singles,
        (),
        |_, step| {
            observed.push(step);
            Ok(())
        },
    )
    .unwrap();
    let first_program = observed
        .iter()
        .position(|step| matches!(step, LoadProgram(_, _)))
        .unwrap();
    let before_program = &observed[..first_program];
    for required in [
        WriteCallerControl,
        ReadCallerControl,
        Freeze("TASK_COOKIE"),
        Freeze("COOKIE_CTL"),
        Freeze("CALLER_USE"),
    ] {
        assert!(
            before_program.contains(&required),
            "missing pre-producer caller preparation: {required:?}"
        );
    }
    let position = |step| observed.iter().position(|actual| *actual == step).unwrap();
    assert!(position(WriteCallerControl) < position(ReadCallerControl));
    assert!(position(ReadCallerControl) < position(Freeze("COOKIE_CTL")));
    assert!(
        !observed.contains(&Freeze("ENDPOINT_OBJECT")),
        "endpoint bindings do not exist during preparation"
    );
    assert_eq!(
        observed
            .iter()
            .filter(|step| matches!(step, LoadProgram(_, _)))
            .count(),
        12
    );
    assert!(position(RetainDiscovery) < position(RecheckCustody));
}

#[test]
fn caller_preparation_refuses_budget_substitution_before_any_kernel_operation() {
    let operations = Cell::new(0);
    let result = prepare_caller_inventory_with(
        endpoint_budget(4),
        caller_budget(),
        AttachBackend::Singles,
        (),
        |_, _| {
            operations.set(operations.get() + 1);
            Ok(())
        },
    );
    assert!(result.is_err(), "different endpoint budgets were accepted");
    assert_eq!(
        operations.get(),
        0,
        "budget refusal happened after allocation"
    );
}

#[derive(Debug)]
struct OwnedFailure;
impl std::fmt::Display for OwnedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owned caller preparation failure")
    }
}
impl std::error::Error for OwnedFailure {}

struct Resources {
    drops: Rc<Cell<usize>>,
}
impl Drop for Resources {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

#[test]
fn caller_preparation_each_native_step_failure_keeps_original_error_and_drops_custody_once() {
    use InventoryPreparation::*;
    for failed in [
        WriteCallerControl,
        ReadCallerControl,
        Freeze("TASK_COOKIE"),
        Freeze("COOKIE_CTL"),
        Freeze("CALLER_USE"),
    ] {
        let drops = Rc::new(Cell::new(0));
        let seen = RefCell::new(vec![]);
        let result = prepare_caller_inventory_with(
            endpoint_budget(3),
            caller_budget(),
            AttachBackend::Singles,
            Resources {
                drops: drops.clone(),
            },
            |_, step| {
                seen.borrow_mut().push(step);
                if step == failed {
                    return Err(OwnedFailure.into());
                }
                Ok(())
            },
        );
        let error = match result {
            Ok(state) => {
                drop(state);
                panic!("caller preparation skipped failure point {failed:?}");
            }
            Err(error) => error,
        };
        assert!(
            error.downcast_ref::<OwnedFailure>().is_some(),
            "original error lost: {error:#}"
        );
        assert_eq!(drops.get(), 1);
        assert_eq!(seen.borrow().last(), Some(&failed));
        assert!(
            !seen
                .borrow()
                .iter()
                .any(|step| matches!(step, LoadProgram(_, _)))
        );
    }
}

#[derive(Default)]
struct EndpointIo {
    cells: [EndpointObject; 3],
    reads: usize,
    writes: usize,
    fail_read: Option<usize>,
    fail_write: bool,
    corrupt_readback: bool,
}

impl CallerEndpointIo for EndpointIo {
    fn read_endpoint(&mut self, endpoint: u32) -> Result<EndpointObject> {
        self.reads += 1;
        if self.fail_read == Some(self.reads) {
            bail!("injected endpoint read {}", self.reads);
        }
        let cell = self.cells[endpoint as usize];
        if self.corrupt_readback && self.reads == 2 {
            return Ok(EndpointObject { class: 3, ..cell });
        }
        Ok(cell)
    }

    fn write_endpoint(&mut self, endpoint: u32, value: EndpointObject) -> Result<()> {
        self.writes += 1;
        if self.fail_write {
            bail!("injected endpoint write");
        }
        self.cells[endpoint as usize] = value;
        Ok(())
    }
}

#[test]
fn caller_publication_commits_zero_cell_and_reads_exact_object_zero_back() {
    let mut io = EndpointIo::default();
    publish_caller_endpoint_with(&mut io, 1, PinnedObjectId(0)).unwrap();
    assert_eq!(
        io.cells[1],
        EndpointObject {
            object_id: 0,
            class: 1
        }
    );
    assert_eq!((io.reads, io.writes), (2, 1));
    assert_eq!(io.cells[0], EndpointObject::default());
}

#[test]
fn caller_publication_refuses_every_nonzero_or_malformed_cell_without_write() {
    for cell in [
        EndpointObject {
            object_id: 0,
            class: 1,
        },
        EndpointObject {
            object_id: 3,
            class: 1,
        },
        EndpointObject {
            object_id: 3,
            class: 0,
        },
        EndpointObject {
            object_id: 0,
            class: 2,
        },
        EndpointObject {
            object_id: 3,
            class: 2,
        },
    ] {
        let mut io = EndpointIo::default();
        io.cells[1] = cell;
        assert!(publish_caller_endpoint_with(&mut io, 1, PinnedObjectId(7)).is_err());
        assert_eq!(io.cells[1], cell);
        assert_eq!((io.reads, io.writes), (1, 0));
    }
}

#[test]
fn caller_publication_never_rewrites_a_committed_endpoint() {
    let mut io = EndpointIo::default();
    publish_caller_endpoint_with(&mut io, 0, PinnedObjectId(9)).unwrap();
    assert!(publish_caller_endpoint_with(&mut io, 0, PinnedObjectId(9)).is_err());
    assert!(publish_caller_endpoint_with(&mut io, 0, PinnedObjectId(10)).is_err());
    assert_eq!(
        io.cells[0],
        EndpointObject {
            object_id: 9,
            class: 1
        }
    );
    assert_eq!(io.writes, 1);
}

#[test]
fn caller_publication_preserves_read_write_and_readback_failures() {
    for (read, write, corrupt) in [
        (Some(1), false, false),
        (None, true, false),
        (Some(2), false, false),
        (None, false, true),
    ] {
        let mut io = EndpointIo {
            fail_read: read,
            fail_write: write,
            corrupt_readback: corrupt,
            ..Default::default()
        };
        let error = publish_caller_endpoint_with(&mut io, 2, PinnedObjectId(4)).unwrap_err();
        if read.is_some() {
            assert!(format!("{error:#}").contains("injected endpoint read"));
        } else if write {
            assert!(format!("{error:#}").contains("injected endpoint write"));
        } else {
            assert!(format!("{error:#}").contains("readback"));
        }
    }
}

#[derive(Default)]
struct HealthIo {
    visited: Vec<u32>,
    control_reads: usize,
    fail_cell: Option<u32>,
    fail_control: bool,
}

impl CallerHealthIo for HealthIo {
    fn evidence_cell(&mut self, index: u32) -> Result<u64> {
        self.visited.push(index);
        if self.fail_cell == Some(index) {
            bail!("injected CALLER_EVIDENCE[{index}] read");
        }
        Ok(u64::from(index + 1))
    }

    fn identity_control(&mut self) -> Result<ImageIdentityControl> {
        self.control_reads += 1;
        if self.fail_control {
            bail!("injected COOKIE_CTL read");
        }
        Ok(ImageIdentityControl {
            limit: 16_384,
            next_ticket: 2,
            ..Default::default()
        })
    }
}

#[test]
fn caller_health_retains_all_four_evidence_cells_and_native_control() {
    let mut io = HealthIo::default();
    let health = read_caller_health_with(&mut io, Instant::now() + Duration::from_secs(1));
    assert_eq!(health.evidence, Some([1, 2, 3, 4]));
    assert_eq!(health.control.unwrap().next_ticket, 2);
    assert!(health.failures.is_empty());
    assert_eq!(io.visited, [0, 1, 2, 3]);
    assert_eq!(io.control_reads, 1);
}

#[test]
fn caller_health_failed_evidence_or_control_is_unknown_not_clean() {
    let mut io = HealthIo {
        fail_cell: Some(2),
        ..Default::default()
    };
    let health = read_caller_health_with(&mut io, Instant::now() + Duration::from_secs(1));
    assert_eq!(health.evidence, None);
    assert!(health.control.is_some());
    assert_eq!(io.visited, [0, 1, 2, 3]);
    assert!(
        health
            .failures
            .iter()
            .any(|e| e.contains("CALLER_EVIDENCE[2]"))
    );

    let mut io = HealthIo {
        fail_control: true,
        ..Default::default()
    };
    let health = read_caller_health_with(&mut io, Instant::now() + Duration::from_secs(1));
    assert_eq!(health.evidence, Some([1, 2, 3, 4]));
    assert!(health.control.is_none());
    assert!(health.failures.iter().any(|e| e.contains("COOKIE_CTL")));
}

#[test]
fn caller_health_expired_deadline_is_unknown_without_map_access() {
    let mut io = HealthIo::default();
    let health = read_caller_health_with(&mut io, Instant::now() - Duration::from_secs(1));
    assert!(health.evidence.is_none());
    assert!(health.control.is_none());
    assert!(health.failures.iter().any(|e| e.contains("deadline")));
    assert!(io.visited.is_empty());
    assert_eq!(io.control_reads, 0);
}
