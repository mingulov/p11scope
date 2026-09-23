//! SPDX-License-Identifier: GPL-3.0-or-later
//! Package G (SYSPLAN): capacity and long-lived capture architecture.
//!
//! RED suite: every test names one Package G checkbox. The `capacity` module
//! does not exist yet, so this file fails to compile until the GREEN
//! implementation lands.

use p11scope::capacity::{
    AttachCost, FirstTouchLedger, ReclamationPolicy, SlotIdentityAllocator, SlotIdentityError,
    StorageModel, admission_envelope, broader_admission_qualified, experimental_candidate_slots,
    inventory, native_slot_bound, production_slots, reclamation_policy,
};
use p11scope_ebpf_common::{
    IMAGE_IDENTITY_TICKET_LIMIT, MAX_DESCRIPTORS, MAX_SLOTS, RING_BYTES, ROOT_AFFILIATION_LIMIT,
    RV_ENTRIES, START_ENTRIES, THREAD_OWNER_LIMIT,
};

// Checkbox 1: inventory capacity/occupancy for every G resource.
#[test]
fn inventory_names_every_resource_with_its_exact_limit() {
    let table = inventory();
    let limit_of = |name: &str| {
        table
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| panic!("inventory must name {name}"))
            .limit
    };
    for entry in table {
        assert!(
            entry.limit > 0,
            "resource {} needs a positive limit",
            entry.name
        );
        assert!(
            !entry.occupancy_source.is_empty(),
            "resource {} needs an occupancy source",
            entry.name
        );
    }
    assert_eq!(limit_of("stats_slots"), u64::from(MAX_SLOTS));
    assert_eq!(limit_of("start_inflight"), u64::from(START_ENTRIES));
    assert_eq!(limit_of("rv_keys"), u64::from(RV_ENTRIES));
    assert_eq!(limit_of("descriptors"), u64::from(MAX_DESCRIPTORS));
    assert_eq!(limit_of("task_owners"), THREAD_OWNER_LIMIT);
    assert_eq!(
        limit_of("image_identity_tickets"),
        IMAGE_IDENTITY_TICKET_LIMIT
    );
    assert_eq!(limit_of("root_affiliations"), ROOT_AFFILIATION_LIMIT);
    assert_eq!(limit_of("ring_bytes"), u64::from(RING_BYTES));
    for name in [
        "candidates",
        "interfaces",
        "history_records",
        "semantic_keys",
        "links",
        "rings",
    ] {
        assert!(
            table.iter().any(|entry| entry.name == name),
            "inventory must name {name}"
        );
    }
}

// Checkbox 2: dense vs bounded non-evicting sparse storage comparison.
#[test]
fn storage_comparison_covers_tiers_and_residency_without_sufficiency_claim() {
    assert_eq!(production_slots(), MAX_SLOTS);
    assert_eq!(experimental_candidate_slots(), 8_192);
    assert_ne!(
        experimental_candidate_slots(),
        production_slots(),
        "8,192 is an experimental candidate, never the production admission limit"
    );
    assert!(
        !broader_admission_qualified(),
        "broader admission stays unqualified until the contract review lands"
    );
    let rows = StorageModel::compare();
    for cpus in [2u32, 12, 64] {
        for residency in ["idle", "sparse", "full"] {
            let row = rows
                .iter()
                .find(|row| row.cpus == cpus && row.residency == residency)
                .unwrap_or_else(|| panic!("comparison must cover {cpus} CPUs at {residency}"));
            assert!(row.dense_bytes > 0);
            if residency == "idle" {
                assert_eq!(row.sparse_bytes, 0, "idle sparse storage holds no entries");
            } else {
                assert!(row.sparse_bytes > 0);
            }
            assert!(
                row.sparse_bounded_non_evicting,
                "sparse storage must stay bounded and non-evicting"
            );
        }
    }
    let full: Vec<_> = rows.iter().filter(|row| row.residency == "full").collect();
    assert_eq!(full.len(), 3);
    // Dense per-CPU STATS scales with the CPU tier; the sparse bound does not
    // evict, so full sparse occupancy never exceeds its published bound.
    assert!(full[0].dense_bytes < full[1].dense_bytes);
    assert!(full[1].dense_bytes < full[2].dense_bytes);
    for row in &full {
        assert!(row.sparse_bytes <= row.sparse_bound_bytes);
    }
    // RV keeps its own key budget, independent of the slot budget.
    let rv = StorageModel::rv_key_budget();
    assert_eq!(rv, u64::from(RV_ENTRIES));
    assert!(rv >= 2 * u64::from(MAX_SLOTS));
}

// Checkbox 3: first-touch initialization/relookup under concurrency.
#[test]
fn first_touch_under_concurrency_has_exactly_one_initializer_and_counted_failures() {
    let ledger = FirstTouchLedger::new(64);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..1_000 {
                    let _ = ledger.first_touch_or_relookup(7);
                }
            });
        }
    });
    let snapshot = ledger.snapshot();
    assert_eq!(
        snapshot.initializations, 1,
        "exactly one thread initializes key 7"
    );
    assert_eq!(snapshot.initializations + snapshot.relookups, 8_000);
    assert_eq!(snapshot.insert_failures, 0);
    assert_eq!(snapshot.relookup_failures, 0);
    // Exhaustion is explicit, never silent.
    let tight = FirstTouchLedger::new(1);
    assert!(tight.first_touch_or_relookup(1).is_ok());
    assert!(tight.first_touch_or_relookup(2).is_err());
    assert_eq!(tight.snapshot().insert_failures, 1);
}

// Checkbox 3 (native side): slot checks, counts and cleanup move together.
#[test]
fn native_slot_checks_counts_and_cleanup_share_one_bound() {
    assert_eq!(native_slot_bound(), MAX_SLOTS);
    let source = std::fs::read_to_string("crates/ebpf/native/task_owner.c")
        .expect("native task_owner.c must be readable");
    for site in [
        "key->slot < P11SCOPE_OWNER_SLOT_BOUND",
        "key->slot >= P11SCOPE_OWNER_SLOT_BOUND",
        "owner->start_count >= P11SCOPE_OWNER_SLOT_BOUND",
        "owner->start_count > P11SCOPE_OWNER_SLOT_BOUND",
        "i < P11SCOPE_OWNER_SLOT_BOUND",
        "start.slot = i",
    ] {
        assert!(
            source.contains(site),
            "native site must stay pinned: {site}"
        );
    }
    assert!(
        source
            .matches("key->slot >= P11SCOPE_OWNER_SLOT_BOUND")
            .count()
            == 2,
        "both native lookup and removal paths check the same slot bound"
    );
}

// Checkbox 4: append-only historical identity; no slot or runtime-view recycling.
#[test]
fn historical_identity_is_append_only_and_never_recycles() {
    assert_eq!(reclamation_policy(), ReclamationPolicy::AppendOnly);
    let mut allocator = SlotIdentityAllocator::new(4);
    let ids: Vec<u32> = (0..4)
        .map(|_| allocator.allocate().expect("in-budget"))
        .collect();
    assert_eq!(ids, vec![0, 1, 2, 3]);
    allocator.retire(1);
    assert!(
        allocator.resolve(1).is_retired(),
        "retired ids stay tombstoned"
    );
    let next = allocator.allocate().expect("lifetime budget remains");
    assert_eq!(next, 4, "allocation never reuses retired slot 1");
    assert!(
        allocator.resolve(1).is_retired(),
        "old evidence still sees the tombstone"
    );
    let err = allocator.allocate().unwrap_err();
    assert!(matches!(err, SlotIdentityError::Exhausted { .. }));
    assert!(
        err.to_string().contains("slots/lifetime"),
        "exhaustion names the resource: {err}"
    );
}

// Checkbox 5: attach/program-load/teardown measured separately; links cost.
#[test]
fn attach_program_load_teardown_and_links_are_accounted_separately() {
    let cost = AttachCost::for_endpoints(10);
    assert_eq!(cost.links, 10);
    assert!(cost.program_loads >= 1);
    assert!(!cost.map_value_sharing_removes_link_cost);
    assert!(
        cost.teardown_steps >= cost.links,
        "teardown walks every link"
    );
    let empty = AttachCost::for_endpoints(0);
    assert_eq!(empty.links, 0);
    assert_eq!(empty.teardown_steps, 0);
}

// Admission envelope: qualification only after this contract.
#[test]
fn admission_envelope_publishes_limits_and_qualification_state() {
    let envelope = admission_envelope();
    assert!(
        envelope.contains(&format!("stats_slots={MAX_SLOTS}")),
        "envelope: {envelope}"
    );
    assert!(
        envelope.contains("start_inflight=16384"),
        "envelope: {envelope}"
    );
    assert!(
        envelope.contains(&format!("rv_keys={RV_ENTRIES}")),
        "envelope: {envelope}"
    );
    assert!(
        envelope.contains("broader_admission=unqualified"),
        "envelope: {envelope}"
    );
}
