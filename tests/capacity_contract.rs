//! SPDX-License-Identifier: GPL-3.0-or-later
//! Package G (SYSPLAN): capacity and long-lived capture architecture.
//!
//! Capacity contracts and checked Detailed component accounting.

use p11scope::capacity::{
    AttachCost, DetailedResources, FirstTouchLedger, ReclamationPolicy, SlotIdentityAllocator,
    SlotIdentityError, StorageModel, admission_envelope, broader_admission_qualified,
    experimental_candidate_slots, inventory, native_slot_bound, production_slots,
    reclamation_policy,
};
use p11scope_ebpf_common::{
    CallStart, IMAGE_IDENTITY_TICKET_LIMIT, MAX_DESCRIPTORS, MAX_SLOTS, RING_BYTES,
    ROOT_AFFILIATION_LIMIT, RV_ENTRIES, RvKey, START_ENTRIES, SlotSemantics, SlotStats, StartKey,
    THREAD_OWNER_LIMIT,
};
use std::mem::size_of;

#[test]
fn detailed_resources_profiles_use_possible_cpu_allocation() {
    for (n, rv, stats, rv_values) in [
        (
            512,
            4096,
            [303104, 1818624, 9699328],
            [65536, 393216, 2097152],
        ),
        (
            2112,
            8192,
            [1250304, 7501824, 40009728],
            [131072, 786432, 4194304],
        ),
    ] {
        for (index, cpus) in [2, 12, 64].into_iter().enumerate() {
            let facts = DetailedResources::new(n, rv, cpus).unwrap();
            assert_eq!(facts.resources.stats_values_bytes, stats[index]);
            assert_eq!(facts.resources.rv_values_bytes, rv_values[index]);
            assert_eq!(facts.resources.rv_keys_bytes, rv * 16);
            assert_eq!(facts.resources.static_singles_links, n * 2);
        }
    }
}

#[test]
fn detailed_resources_idle_keeps_full_stats_allocation() {
    let resources = DetailedResources::compiled(12).unwrap();
    let rows = StorageModel::compare();
    for residency in ["idle", "sparse", "full"] {
        let row = rows
            .iter()
            .find(|row| row.cpus == 12 && row.residency == residency)
            .unwrap();
        assert_eq!(resources.resources.stats_values_bytes, row.dense_bytes);
    }
}

#[test]
fn detailed_resources_rv_capacity_is_independent_of_slots() {
    let small = DetailedResources::new(512, 8192, 12).unwrap();
    let wide = DetailedResources::new(2112, 8192, 12).unwrap();
    assert_eq!(small.resources.rv_values_bytes, 786432);
    assert_eq!(small.resources.rv_keys_bytes, 131072);
    assert_eq!(
        small.resources.rv_values_bytes,
        wide.resources.rv_values_bytes
    );
    assert_eq!(small.resources.rv_keys_bytes, wide.resources.rv_keys_bytes);
    let rv_changed = DetailedResources::new(2112, 4096, 12).unwrap();
    assert_eq!(
        rv_changed.resources.stats_values_bytes,
        wide.resources.stats_values_bytes
    );
    assert_eq!(rv_changed.resources.rv_values_bytes, 393216);
}

#[test]
fn detailed_resources_fixed_maps_do_not_scale_with_slots_or_cpus() {
    let small = DetailedResources::new(512, 4096, 2).unwrap();
    let wide = DetailedResources::new(2112, 8192, 64).unwrap();
    for facts in [small, wide] {
        assert_eq!(
            facts.resources.start_keys_bytes,
            u64::from(START_ENTRIES) * size_of::<StartKey>() as u64
        );
        assert_eq!(
            facts.resources.start_values_bytes,
            u64::from(START_ENTRIES) * size_of::<CallStart>() as u64
        );
        assert_eq!(facts.resources.descriptor_declared_values_bytes, 1890);
        assert_eq!(facts.resources.descriptor_aligned_values_bytes, 2520);
    }
    assert_eq!(
        small.resources.start_values_bytes,
        wide.resources.start_values_bytes
    );
}

#[test]
fn detailed_resources_declared_and_aligned_arrays_are_distinct() {
    for (n, declared, aligned) in [(512, 2048, 4096), (2112, 8448, 16896)] {
        let facts = DetailedResources::new(n, 4096, 12).unwrap();
        assert_eq!(facts.resources.slot_file_declared_values_bytes, declared);
        assert_eq!(facts.resources.slot_file_aligned_values_bytes, aligned);
    }
}

#[test]
fn detailed_resources_compiled_constructor_uses_current_abi() {
    let compiled = DetailedResources::compiled(12).unwrap();
    assert_eq!(
        compiled,
        DetailedResources::new(u64::from(MAX_SLOTS), u64::from(RV_ENTRIES), 12).unwrap()
    );
    assert_eq!(compiled.inputs.start_capacity, u64::from(START_ENTRIES));
    assert_eq!(
        compiled.inputs.descriptor_capacity,
        u64::from(MAX_DESCRIPTORS)
    );
    assert_eq!(
        compiled.abi_sizes.stats_value_bytes,
        size_of::<SlotStats>() as u64
    );
    assert_eq!(compiled.abi_sizes.rv_key_bytes, size_of::<RvKey>() as u64);
    assert_eq!(compiled.abi_sizes.rv_value_bytes, size_of::<u64>() as u64);
    assert_eq!(
        compiled.abi_sizes.start_key_bytes,
        size_of::<StartKey>() as u64
    );
    assert_eq!(
        compiled.abi_sizes.start_value_bytes,
        size_of::<CallStart>() as u64
    );
    assert_eq!(
        compiled.abi_sizes.descriptor_value_bytes,
        size_of::<SlotSemantics>() as u64
    );
    assert_eq!(
        compiled.abi_sizes.slot_file_value_bytes,
        size_of::<u32>() as u64
    );
}

#[test]
fn detailed_resources_reject_zero_conversion_and_overflow() {
    for (n, rv, cpus) in [
        (0, 4096, 12),
        (512, 0, 12),
        (512, 4096, 0),
        (u64::MAX, 4096, 12),
        (512, u64::MAX, 12),
        (512, 4096, u64::MAX),
        (
            u64::from(u32::MAX),
            u64::from(u32::MAX),
            u64::from(u32::MAX),
        ),
    ] {
        assert!(
            DetailedResources::new(n, rv, cpus).is_err(),
            "must refuse {n}/{rv}/{cpus}"
        );
    }
}

#[test]
fn detailed_resources_component_sum_excludes_links_and_declared_duplicates() {
    let facts = DetailedResources::new(512, 4096, 12).unwrap();
    assert_eq!(
        facts.resources.component_payload_bytes,
        2546136 + u64::from(START_ENTRIES) * size_of::<CallStart>() as u64
    );
    // Each variable component fits u64 here, but their combined sum does not.
    assert!(
        DetailedResources::new(20_000_000, 2_000_000_000, 1_000_000_000)
            .unwrap_err()
            .contains("sum overflowed")
    );
}

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
