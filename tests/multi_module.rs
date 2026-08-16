//! One attach plan over many modules: distinct slots per module, one slot for a
//! target two modules share, and a capacity ceiling that refuses whole modules.

use p11scope::plan::{ModuleId, build_from_modules};
use p11scope_manifest::maps::{Device, ObjectKey};

fn key(inode: u64) -> ObjectKey {
    ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode,
    }
}

fn module(
    inode: u64,
    path: &str,
    entries: &[(&'static str, u64, u64)],
) -> p11scope::discovery::scan::ScannedModule {
    use p11scope::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
    ScannedModule {
        key: key(inode),
        path: path.to_string(),
        exports: vec!["C_GetFunctionList".into()],
        tables: vec![ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: entries
                .iter()
                .map(|&(name, object_inode, offset)| ScannedEntry {
                    name,
                    object: key(object_inode),
                    object_path: format!("/opt/obj{object_inode}.so"),
                    file_offset: offset,
                })
                .collect(),
            null_entries: vec![],
            address: 0x1000 + inode,
        }],
        interfaces: vec![],
    }
}

#[test]
fn two_modules_get_distinct_slots_and_distinct_module_ids() {
    let plan = build_from_modules(&[
        module(
            10,
            "/opt/proxy.so",
            &[("C_Initialize", 10, 0x100), ("C_Sign", 10, 0x200)],
        ),
        module(
            20,
            "/opt/backend.so",
            &[("C_Initialize", 20, 0x100), ("C_Sign", 20, 0x200)],
        ),
    ]);
    assert_eq!(plan.slots.len(), 4, "no target is shared here");
    assert_eq!(plan.modules.len(), 2);
    assert_eq!(plan.module_ambiguous, 0);
    let ids: Vec<ModuleId> = plan.slots.iter().map(|s| s.module_ids[0]).collect();
    assert_eq!(ids.iter().filter(|id| **id == ModuleId(0)).count(), 2);
    assert_eq!(ids.iter().filter(|id| **id == ModuleId(1)).count(), 2);
    // Slot indices are dense and unique across modules.
    let mut indices: Vec<u32> = plan.slots.iter().map(|s| s.index).collect();
    indices.sort();
    assert_eq!(indices, vec![0, 1, 2, 3]);
}

#[test]
fn a_target_claimed_by_two_modules_is_attached_once_and_marked_ambiguous() {
    let plan = build_from_modules(&[
        module(10, "/opt/proxy.so", &[("C_Sign", 30, 0x400)]),
        module(20, "/opt/backend.so", &[("C_Sign", 30, 0x400)]),
    ]);
    assert_eq!(
        plan.slots.len(),
        1,
        "one {{object, offset}} ⇒ one slot, never two probes"
    );
    assert_eq!(plan.slots[0].module_ids, vec![ModuleId(0), ModuleId(1)]);
    assert_eq!(plan.module_ambiguous, 1);
    assert_eq!(
        plan.slots[0].semantics,
        p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
        "an ambiguous slot may not carry semantics"
    );
    assert!(plan.slots[0].semantic_ambiguous);
}

#[test]
fn a_target_three_modules_share_is_one_ambiguity_not_three() {
    let plan = build_from_modules(&[
        module(10, "/opt/a.so", &[("C_Sign", 30, 0x400)]),
        module(20, "/opt/b.so", &[("C_Sign", 30, 0x400)]),
        module(40, "/opt/c.so", &[("C_Sign", 30, 0x400)]),
    ]);
    assert_eq!(plan.slots.len(), 1);
    assert_eq!(
        plan.slots[0].module_ids,
        vec![ModuleId(0), ModuleId(1), ModuleId(2)]
    );
    assert_eq!(
        plan.module_ambiguous, 1,
        "one shared target, however many modules claim it"
    );
    assert_eq!(
        plan.module_of_slot(0),
        None,
        "no single module owns an ambiguous slot"
    );
}

#[test]
fn capacity_overflow_skips_whole_modules_and_says_which() {
    // 512 slots available; three modules of 200 unique targets each.
    let big = |inode: u64| {
        let entries: Vec<(&'static str, u64, u64)> = (0..200u64)
            .map(|i| ("C_Sign", inode, 0x1000 + i * 0x10))
            .collect();
        module(inode, "/opt/big.so", &entries)
    };
    let plan = build_from_modules(&[big(1), big(2), big(3)]);
    assert!(plan.slots.len() <= 512, "never exceed MAX_SLOTS");
    assert_eq!(plan.modules.len(), 2, "two modules fit");
    assert_eq!(plan.modules_skipped.len(), 1);
    assert!(
        plan.modules_skipped[0].reason.contains("512"),
        "the ceiling must be named: {:?}",
        plan.modules_skipped[0]
    );
}
