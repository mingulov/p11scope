//! SPDX-License-Identifier: GPL-3.0-or-later
//! SG-T7B guard (owner ruling B, 2026-09-25): the two tail-call
//! continuations release the stop-gate admission their caller took, so
//! they must never be attached directly. A direct attach would release
//! without entering, wrap the gate's count into the stop bit mid-capture,
//! and turn a proven quiescence into a false one. Every Detailed
//! direct-attach selector is driven here over its whole input space, and
//! the only by-name lookups of either continuation are pinned to the
//! tail-call publication.

use super::*;

const CONTINUATIONS: [&str; 2] = ["interface_list_worker", "p11_entry_template_second"];

fn semantics_shapes() -> Vec<SlotSemantics> {
    let base = SlotSemantics::COUNT_ONLY;
    let mut template_pair = base;
    template_pair.template0_arg = 1;
    template_pair.template1_arg = 2;
    let mut template_types = base;
    template_types.semantic_flags |= p11scope_ebpf_common::semantic_flags::TEMPLATE0_TYPES_ONLY;
    let mut template = base;
    template.template0_arg = 1;
    vec![base, template_pair, template_types, template]
}

#[test]
fn tail_call_continuations_are_never_selected_for_direct_attach() {
    let mut selected = BTreeSet::new();
    for policy in [
        CapturePolicy::Allowlisted,
        CapturePolicy::UnsafeUnvalidatedMetadata,
        CapturePolicy::AggregateOnly,
    ] {
        for object_has_unsafe in [false, true] {
            for abi in [ElfAbi::Lp64, ElfAbi::Ilp32] {
                for semantics in semantics_shapes() {
                    let program = entry_program(&semantics, policy, object_has_unsafe, abi);
                    assert!(
                        static_probe_side(program).is_some(),
                        "{program} is a static endpoint"
                    );
                    selected.insert(program);
                }
            }
        }
    }
    selected.insert("p11_return");
    for abi in [
        HookAbi::FunctionList,
        HookAbi::InterfaceList,
        HookAbi::Interface,
    ] {
        let (entry, ret) = export_programs(abi);
        selected.extend([entry, ret]);
    }
    let mut lifecycle = Vec::new();
    attach_lifecycle_with(
        &mut lifecycle,
        |attached, program| {
            attached.push(program);
            Ok(())
        },
        |_, _, ()| Ok(()),
    )
    .unwrap();
    selected.extend(lifecycle);
    // The dynamic loader hook is its own literal (`attach_dynamic_loader`).
    selected.insert("dl_debug_state");
    for continuation in CONTINUATIONS {
        assert!(
            !selected.contains(continuation),
            "{continuation} must never be attached directly: {selected:?}"
        );
        assert_eq!(static_probe_side(continuation), None, "{continuation}");
    }
    // The selectors still reach every directly attached Detailed program.
    let attachable: BTreeSet<&str> = DEFAULT_PROGRAMS
        .iter()
        .chain(UNSAFE_PROGRAMS.iter())
        .copied()
        .filter(|program| !CONTINUATIONS.contains(program))
        .collect();
    assert_eq!(selected, attachable);
}

#[test]
fn tail_call_continuations_are_looked_up_only_for_tail_call_publication() {
    let source = include_str!("../attach.rs");
    let publication = source
        .split_once("fn publish_and_freeze_tail_calls(")
        .unwrap()
        .1
        .split_once("\n}\n")
        .unwrap()
        .0;
    for continuation in CONTINUATIONS {
        let lookup = format!(".program(\"{continuation}\")");
        assert_eq!(source.matches(&lookup).count(), 1, "{lookup}");
        assert!(publication.contains(&lookup), "{lookup}");
        for direct in [
            format!(".program_mut(\"{continuation}\")"),
            format!("attach(\"{continuation}\""),
        ] {
            assert!(!source.contains(&direct), "{direct}");
        }
    }
}
