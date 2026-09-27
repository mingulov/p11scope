//! SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use crate::inventory_mark_used_with;
use core::cell::Cell;

const ENDPOINT_CAPACITY: u32 = 10;
const PAIR_CAPACITY: usize = 4;
const A: ImageIdentity = ImageIdentity {
    task_cookie: 41,
    exec_id: 9,
};
const B: ImageIdentity = ImageIdentity {
    task_cookie: 42,
    exec_id: 9,
};
const A_EXEC: ImageIdentity = ImageIdentity {
    task_cookie: 41,
    exec_id: 10,
};

#[derive(Clone, Copy)]
enum InsertBehavior {
    Normal,
    Fail,
    Race(Option<CallerObjectUse>),
}

/// Fixed-capacity map/helper adapter for the same algorithm used by the BPF
/// producer. It supplies storage operations, not a second caller algorithm.
struct MemoryEntryIo {
    endpoints: [EndpointObject; ENDPOINT_CAPACITY as usize],
    usage: [Cell<u64>; ENDPOINT_CAPACITY as usize],
    image: Option<ImageIdentity>,
    rows: [Option<(CallerObjectKey, CallerObjectUse)>; PAIR_CAPACITY],
    pair_limit: usize,
    insert_behavior: InsertBehavior,
    next_ns: u64,
    identity_reads: usize,
    clock_reads: usize,
    insert_calls: usize,
    lookup_calls: usize,
}

impl MemoryEntryIo {
    fn new() -> Self {
        let mut endpoints = [EndpointObject::default(); ENDPOINT_CAPACITY as usize];
        endpoints[7] = EndpointObject {
            object_id: 2,
            class: 1,
        };
        endpoints[8] = endpoints[7];
        endpoints[9] = EndpointObject {
            object_id: 3,
            class: 1,
        };
        Self {
            endpoints,
            usage: core::array::from_fn(|_| Cell::new(0)),
            image: Some(A),
            rows: [None; PAIR_CAPACITY],
            pair_limit: PAIR_CAPACITY,
            insert_behavior: InsertBehavior::Normal,
            next_ns: 101,
            identity_reads: 0,
            clock_reads: 0,
            insert_calls: 0,
            lookup_calls: 0,
        }
    }

    fn with_existing_a() -> Self {
        let mut io = Self::new();
        io.usage[7].set(1);
        let key = key(A);
        let value = witness(77, 100);
        assert!(key.is_valid());
        assert!(value.is_valid(ENDPOINT_CAPACITY));
        io.rows[0] = Some((key, value));
        io
    }

    fn row(&self, key: &CallerObjectKey) -> Option<CallerObjectUse> {
        self.rows
            .iter()
            .flatten()
            .find_map(|(candidate, value)| (*candidate == *key).then_some(*value))
    }

    fn row_count(&self) -> usize {
        self.rows.iter().flatten().count()
    }
}

impl CallerEntryIo for MemoryEntryIo {
    fn endpoint_object(&mut self, endpoint: u32) -> Option<EndpointObject> {
        self.endpoints.get(endpoint as usize).copied()
    }

    fn mark_usage(&mut self, endpoint: u32) -> bool {
        let Some(cell) = self.usage.get(endpoint as usize) else {
            return false;
        };
        inventory_mark_used_with(
            || cell.get(),
            || {
                let previous = cell.get();
                if previous == 0 {
                    cell.set(1);
                }
                previous
            },
        )
    }

    fn current_identity(&mut self) -> Option<ImageIdentity> {
        self.identity_reads += 1;
        self.image
    }

    fn lookup(&mut self, key: &CallerObjectKey) -> Option<CallerObjectUse> {
        self.lookup_calls += 1;
        self.row(key)
    }

    fn insert_noexist(
        &mut self,
        key: &CallerObjectKey,
        value: &CallerObjectUse,
    ) -> Result<(), PairInsertError> {
        self.insert_calls += 1;
        match self.insert_behavior {
            InsertBehavior::Normal => {}
            InsertBehavior::Fail => return Err(PairInsertError::Failed),
            InsertBehavior::Race(winner) => {
                if let Some(value) = winner {
                    let cell = self.rows.iter_mut().find(|cell| cell.is_none()).unwrap();
                    *cell = Some((*key, value));
                }
                return Err(PairInsertError::Exists);
            }
        }
        if self.row(key).is_some() {
            return Err(PairInsertError::Exists);
        }
        if self.row_count() >= self.pair_limit {
            return Err(PairInsertError::Failed);
        }
        let Some(cell) = self.rows.iter_mut().find(|cell| cell.is_none()) else {
            return Err(PairInsertError::Failed);
        };
        *cell = Some((*key, *value));
        Ok(())
    }

    fn now_ns(&mut self) -> u64 {
        self.clock_reads += 1;
        let now = self.next_ns;
        self.next_ns += 1;
        now
    }
}

fn key(image: ImageIdentity) -> CallerObjectKey {
    CallerObjectKey {
        image,
        object_id: 2,
        reserved: 0,
    }
}

fn witness(recorded_at_ns: u64, host_tgid: u32) -> CallerObjectUse {
    CallerObjectUse {
        recorded_at_ns,
        recent_bucket: 0,
        host_tgid,
        witness_endpoint: 7,
        flags: 1,
        reserved: 0,
    }
}

fn enter(io: &mut MemoryEntryIo, image: ImageIdentity, host_tgid: u32, endpoint: u32) {
    io.image = Some(image);
    record_caller_use_with(io, endpoint, ENDPOINT_CAPACITY, host_tgid).unwrap();
}

#[test]
fn second_caller_is_recorded_after_global_usage_is_already_one() {
    let mut io = MemoryEntryIo::with_existing_a();
    enter(&mut io, B, 200, 7);
    assert_eq!(io.usage[7].get(), 1);
    assert_eq!(
        io.row(&key(B)),
        Some(witness(101, 200)),
        "second caller B is missing after USAGE[7] was already one"
    );
    assert_eq!(io.row(&key(A)), Some(witness(77, 100)));
    assert_eq!(io.row_count(), 2);
    assert_eq!(io.clock_reads, 1);
    assert_eq!(io.insert_calls, 1);
}

#[test]
fn new_exec_is_recorded_after_global_usage_is_already_one() {
    let mut io = MemoryEntryIo::with_existing_a();
    enter(&mut io, A_EXEC, 100, 7);
    assert_eq!(io.usage[7].get(), 1);
    assert_eq!(
        io.row(&key(A_EXEC)),
        Some(witness(101, 100)),
        "new image at the same TGID is missing after USAGE[7] was already one"
    );
    assert_eq!(io.row(&key(A)), Some(witness(77, 100)));
    assert_eq!(io.row_count(), 2);
    assert_eq!(io.clock_reads, 1);
    assert_eq!(io.insert_calls, 1);
}

#[test]
fn a_repeat_b_and_new_exec_keep_exactly_three_physical_pairs() {
    let mut io = MemoryEntryIo::new();
    enter(&mut io, A, 100, 7);
    enter(&mut io, A, 100, 7);
    enter(&mut io, B, 200, 7);
    enter(&mut io, A_EXEC, 100, 7);
    assert_eq!(io.usage[7].get(), 1);
    assert_eq!(
        io.row_count(),
        3,
        "the global bit cannot replace caller rows"
    );
    assert_eq!(io.row(&key(A)), Some(witness(101, 100)));
    assert_eq!(io.row(&key(B)), Some(witness(102, 200)));
    assert_eq!(io.row(&key(A_EXEC)), Some(witness(103, 100)));
    assert_eq!(io.clock_reads, 3);
    assert_eq!(io.insert_calls, 3);
}

#[test]
fn existing_pair_keeps_another_endpoint_witness_without_clock_or_insert() {
    let mut io = MemoryEntryIo::with_existing_a();
    enter(&mut io, A, 100, 7);
    enter(&mut io, A, 100, 8);
    assert_eq!(io.usage[7].get(), 1);
    assert_eq!(io.usage[8].get(), 1);
    assert_eq!(io.row(&key(A)), Some(witness(77, 100)));
    assert_eq!(io.row_count(), 1);
    assert_eq!(io.clock_reads, 0);
    assert_eq!(io.insert_calls, 0);
}

#[test]
fn invalid_global_state_preserves_existing_positive_pairs() {
    let mut io = MemoryEntryIo::with_existing_a();
    io.usage[7].set(2);
    assert_eq!(
        record_caller_use_with(&mut io, 7, ENDPOINT_CAPACITY, 100),
        Err(CallerEntryFailure::GlobalStateInvalid)
    );
    assert_eq!(io.usage[7].get(), 2);
    assert_eq!(io.row(&key(A)), Some(witness(77, 100)));
    assert_eq!(io.row_count(), 1);
    assert_eq!(io.identity_reads, 0);
    assert_eq!(io.clock_reads, 0);
    assert_eq!(io.insert_calls, 0);
}

#[test]
fn another_physical_object_gets_its_own_pair_for_the_same_image() {
    let mut io = MemoryEntryIo::new();
    enter(&mut io, A, 100, 7);
    enter(&mut io, A, 100, 9);
    assert_eq!(io.row_count(), 2);
    assert_eq!(io.row(&key(A)), Some(witness(101, 100)));
    assert_eq!(
        io.row(&CallerObjectKey {
            object_id: 3,
            ..key(A)
        }),
        Some(CallerObjectUse {
            witness_endpoint: 9,
            ..witness(102, 100)
        })
    );
    assert_eq!(io.usage[7].get(), 1);
    assert_eq!(io.usage[9].get(), 1);
}

#[test]
fn full_pair_map_keeps_positives_and_allows_an_existing_pair() {
    let mut io = MemoryEntryIo::new();
    io.pair_limit = 2;
    enter(&mut io, A, 100, 7);
    enter(&mut io, B, 200, 7);
    let before = io.rows;
    io.image = Some(A_EXEC);
    assert_eq!(
        record_caller_use_with(&mut io, 7, ENDPOINT_CAPACITY, 100),
        Err(CallerEntryFailure::Caller(
            CallerEvidence::PairInsertFailure
        ))
    );
    assert_eq!(io.rows, before);
    assert_eq!(io.usage[7].get(), 1);
    assert_eq!(io.clock_reads, 3);
    assert_eq!(io.insert_calls, 3);
    enter(&mut io, A, 100, 7);
    assert_eq!(io.rows, before);
    assert_eq!(io.clock_reads, 3);
    assert_eq!(io.insert_calls, 3);
}

#[test]
fn insertion_allocation_failure_does_not_erase_global_or_existing_use() {
    let mut io = MemoryEntryIo::with_existing_a();
    io.image = Some(B);
    io.insert_behavior = InsertBehavior::Fail;
    let before = io.rows;
    assert_eq!(
        record_caller_use_with(&mut io, 7, ENDPOINT_CAPACITY, 200),
        Err(CallerEntryFailure::Caller(
            CallerEvidence::PairInsertFailure
        ))
    );
    assert_eq!(io.rows, before);
    assert_eq!(io.usage[7].get(), 1);
    assert_eq!(io.lookup_calls, 1);
    assert_eq!(io.insert_calls, 1);
}

#[test]
fn concurrent_valid_winner_is_read_once_and_never_overwritten() {
    let mut io = MemoryEntryIo::new();
    let winner = CallerObjectUse {
        witness_endpoint: 8,
        ..witness(0, 100)
    };
    io.insert_behavior = InsertBehavior::Race(Some(winner));
    enter(&mut io, A, 100, 7);
    assert_eq!(io.row(&key(A)), Some(winner));
    assert_eq!(io.lookup_calls, 2);
    assert_eq!(io.insert_calls, 1);
    assert_eq!(io.clock_reads, 1);
}

#[test]
fn eexist_without_a_valid_winner_is_integrity_failure_without_retry() {
    for winner in [
        None,
        Some(CallerObjectUse {
            flags: 0,
            ..witness(77, 100)
        }),
        Some(witness(77, 200)),
        Some(CallerObjectUse {
            witness_endpoint: 9,
            ..witness(77, 100)
        }),
    ] {
        let mut io = MemoryEntryIo::new();
        io.insert_behavior = InsertBehavior::Race(winner);
        assert_eq!(
            record_caller_use_with(&mut io, 7, ENDPOINT_CAPACITY, 100),
            Err(CallerEntryFailure::Caller(
                CallerEvidence::PairIntegrityFailure
            ))
        );
        assert_eq!(io.usage[7].get(), 1);
        assert_eq!(io.row(&key(A)), winner);
        assert_eq!(io.lookup_calls, 2);
        assert_eq!(io.insert_calls, 1);
        assert_eq!(io.clock_reads, 1);
    }
}

#[test]
fn malformed_existing_pair_is_not_repaired_or_replaced() {
    for value in [
        CallerObjectUse {
            flags: 0,
            ..witness(77, 100)
        },
        CallerObjectUse {
            flags: 3,
            ..witness(77, 100)
        },
        CallerObjectUse {
            reserved: 1,
            ..witness(77, 100)
        },
        CallerObjectUse {
            recent_bucket: 1,
            ..witness(77, 100)
        },
        CallerObjectUse {
            witness_endpoint: ENDPOINT_CAPACITY,
            ..witness(77, 100)
        },
        CallerObjectUse {
            witness_endpoint: 9,
            ..witness(77, 100)
        },
        witness(77, 200),
    ] {
        let mut io = MemoryEntryIo::with_existing_a();
        io.rows[0] = Some((key(A), value));
        assert_eq!(
            record_caller_use_with(&mut io, 7, ENDPOINT_CAPACITY, 100),
            Err(CallerEntryFailure::Caller(
                CallerEvidence::PairIntegrityFailure
            ))
        );
        assert_eq!(io.row(&key(A)), Some(value));
        assert_eq!(io.lookup_calls, 1);
        assert_eq!(io.insert_calls, 0);
        assert_eq!(io.clock_reads, 0);
    }
}

#[test]
fn invalid_object_metadata_stops_before_global_or_identity_mutation() {
    for value in [
        EndpointObject::default(),
        EndpointObject {
            object_id: 2,
            class: 0,
        },
        EndpointObject {
            object_id: 2,
            class: 3,
        },
    ] {
        let mut io = MemoryEntryIo::new();
        io.endpoints[7] = value;
        assert_eq!(
            record_caller_use_with(&mut io, 7, ENDPOINT_CAPACITY, 100),
            Err(CallerEntryFailure::Caller(
                CallerEvidence::InvalidEndpointObject
            ))
        );
        assert_eq!(io.usage[7].get(), 0);
        assert_eq!(io.identity_reads, 0);
        assert_eq!(io.row_count(), 0);
        assert_eq!(io.clock_reads, 0);
    }
    for (endpoint, capacity) in [(7, 0), (ENDPOINT_CAPACITY, ENDPOINT_CAPACITY)] {
        let mut io = MemoryEntryIo::new();
        assert_eq!(
            record_caller_use_with(&mut io, endpoint, capacity, 100),
            Err(CallerEntryFailure::Caller(
                CallerEvidence::InvalidEndpointObject
            ))
        );
        assert!(io.usage.iter().all(|cell| cell.get() == 0));
        assert_eq!(io.identity_reads, 0);
    }
}

#[test]
fn unavailable_identity_keeps_global_use_without_guessing_a_pair() {
    for image in [
        None,
        Some(ImageIdentity {
            task_cookie: 0,
            exec_id: 9,
        }),
    ] {
        let mut io = MemoryEntryIo::new();
        io.image = image;
        assert_eq!(
            record_caller_use_with(&mut io, 7, ENDPOINT_CAPACITY, 100),
            Err(CallerEntryFailure::Caller(
                CallerEvidence::IdentityUnavailable
            ))
        );
        assert_eq!(io.usage[7].get(), 1);
        assert_eq!(io.identity_reads, 1);
        assert_eq!(io.row_count(), 0);
        assert_eq!(io.insert_calls, 0);
        assert_eq!(io.clock_reads, 0);
    }
}

#[test]
fn zero_object_exec_and_timestamp_are_positive_when_explicitly_valid() {
    let mut io = MemoryEntryIo::new();
    let image = ImageIdentity {
        task_cookie: 1,
        exec_id: 0,
    };
    io.endpoints[7] = EndpointObject {
        object_id: 0,
        class: 1,
    };
    io.next_ns = 0;
    enter(&mut io, image, 17, 7);
    assert_eq!(
        io.row(&CallerObjectKey {
            image,
            object_id: 0,
            reserved: 0
        }),
        Some(witness(0, 17))
    );
    assert_eq!(io.clock_reads, 1);
    assert_eq!(io.insert_calls, 1);
}

#[test]
fn zero_tgid_cannot_publish_a_malformed_positive() {
    let mut io = MemoryEntryIo::new();
    assert_eq!(
        record_caller_use_with(&mut io, 7, ENDPOINT_CAPACITY, 0),
        Err(CallerEntryFailure::Caller(
            CallerEvidence::PairIntegrityFailure
        ))
    );
    assert_eq!(io.usage[7].get(), 1);
    assert_eq!(io.row_count(), 0);
    assert_eq!(io.clock_reads, 0);
    assert_eq!(io.insert_calls, 0);
}
