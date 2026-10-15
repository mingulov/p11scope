//! SPDX-License-Identifier: GPL-3.0-or-later
//! H7 slice D: reviewed finite object capture activation gates.
//!
//! Production publication lifts ONLY on the reviewed allowlisted attested
//! lane: BPF emits 608-byte records for marker-bound calls, userspace
//! decodes them against the frozen receipt-bound table and carries the
//! private validated tail through the owned H3 routed call into the
//! consuming admission result. No model construction, no public object
//! projection. These tests pin the emission preconditions (a)-(d), the
//! lane gate and the absence properties; the full-record cursor/pending
//! behavior lives in `object_producer_full_record_mixed_cursor_and_pending`.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/object_adapter.rs"]
mod adapter;

fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("missing source marker {start:?}"));
    let rest = &source[from + start.len()..];
    let until = rest
        .find(end)
        .unwrap_or_else(|| panic!("missing source marker {end:?}"));
    &rest[..until]
}

fn bpf_source() -> String {
    std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF return root")
}

fn embedded_object(directory: &Path) -> PathBuf {
    let object = directory.join("p11scope-ebpf");
    std::fs::write(&object, p11scope::EBPF_OBJECT).expect("write actual embedded BPF object");
    object
}

/// Precondition (a): pair slot-1 keeps a raw retained pointer with ABSENT
/// status while slot-0 VALUE is pre-cross-check. Emission recomputes
/// alias/duplicate/partial from the retained pointers; it never trusts
/// slot-0 as final.
#[test]
fn object_producer_emission_recomputes_pair_from_retained_pointers() {
    // The executed shared return fill reads the second retained result
    // pointer (pair second slot) instead of trusting slot-0 alone.
    let flow = std::fs::read_to_string("crates/ebpf-common/src/object_flow.rs")
        .expect("read shared adapter flow");
    let fill = source_between(
        &flow,
        "pub fn adapter_fill_return(",
        "pub unsafe fn adapter_tail_fill(",
    );
    assert!(
        fill.contains("result_ptrs[1]"),
        "return emission must read the retained second result pointer"
    );
    // The pair cross-checks run on the return path: overlap refuses the
    // pair, equal nonzero handles invalidate both, one readable member
    // is explicitly partial.
    for marker in ["ALIAS", "DUPLICATE", "PARTIAL"] {
        assert!(
            fill.contains(marker),
            "return emission must compute the pair {marker} cross-check"
        );
    }
}

/// Precondition (b): Find `result_ptrs[0]` holds the array base, never a
/// handle. The emitted Find single-handle result cell is pinned to the
/// constant unavailable cell; Find facts live in the Find section only.
#[test]
fn object_producer_find_emits_result_cell_not_array_base() {
    let source = bpf_source();
    let returned = source_between(
        &source,
        "fn p11_return_impl(ctx: RetProbeContext) -> u32 {",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    // The Find section is populated on the return path (bounded element
    // reads into the reserved tail), and the single-handle result cell
    // carries the constant unavailable status, never the array word.
    assert!(
        returned.contains("find_handles") || source.contains("fn object_emit_find"),
        "return emission must populate the Find section"
    );
    let flow = std::fs::read_to_string("crates/ebpf-common/src/object_flow.rs")
        .expect("read shared adapter flow");
    assert!(
        flow.contains("PROTOCOL_UNAVAILABLE"),
        "Find result cell must use the constant unavailable status"
    );
    // The array base word must never be stored as an observed handle.
    let fill = source_between(
        &flow,
        "pub fn adapter_fill_return(",
        "pub unsafe fn adapter_tail_fill(",
    );
    assert!(
        !fill.contains("result_ptrs[0]).write(word"),
        "Find must not overwrite its array base with a handle word"
    );
}

/// Precondition (c): uninspected attribute lists are all-zero, which
/// validates as inspected-empty. Emission marks lists whose inspection
/// never ran with the uninspected marker instead of emitting a fake
/// inspected-empty list.
#[test]
fn object_producer_uninspected_lists_carry_marker() {
    // The wire validator accepts the honest uninspected marker.
    let wire = std::fs::read_to_string("crates/ebpf-common/src/object_wire.rs")
        .expect("read object wire validator");
    assert!(
        wire.contains("UNINSPECTED"),
        "the tail validator must name the uninspected list marker"
    );
    // BPF emission marks request lists it never inspected.
    let flow = std::fs::read_to_string("crates/ebpf-common/src/object_flow.rs")
        .expect("read shared adapter flow");
    assert!(
        flow.contains("UNINSPECTED"),
        "BPF emission must mark uninspected attribute lists"
    );
}

/// Precondition (d): Derive return is currently gated on entry evidence
/// only. Emission wires the full S1 return match (existing
/// MECHANISM_VALUE evidence exactly equal to the entry code) into the
/// gate before any phKey read.
#[test]
fn object_producer_derive_return_requires_s1_match() {
    let source = bpf_source();
    let returned = source_between(
        &source,
        "fn p11_return_impl(ctx: RetProbeContext) -> u32 {",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    // The S1 return-time mechanism read supplies Derive return evidence,
    // so it must precede emission (which precedes the drain retire).
    let mechanism_read = returned
        .find("MECHANISM_VALUE")
        .expect("return must read S1 return-time mechanism evidence");
    let fill_site = returned
        .find("object_fill_return(")
        .expect("emission fills");
    assert!(
        mechanism_read < fill_site,
        "S1 mechanism evidence must precede emission"
    );
    // The shared Derive gate wires the full S1 match; a bare
    // entry-nonzero check no longer authorizes the result read.
    let flow = std::fs::read_to_string("crates/ebpf-common/src/object_flow.rs")
        .expect("read shared adapter flow");
    let fill = source_between(
        &flow,
        "pub fn adapter_fill_return(",
        "pub unsafe fn adapter_tail_fill(",
    );
    assert!(
        fill.contains("authorize_derive_return"),
        "Derive return must wire the full S1 mechanism match"
    );
    assert!(
        !fill.contains("side.derive != 0"),
        "Derive return must not gate on entry evidence alone"
    );
}

/// Slice D lifts the production gate ONLY on the reviewed allowlisted
/// attested lane: marker-bound calls emit 608-byte records through the
/// frozen descriptor row; everything else keeps the ordinary form.
#[test]
fn object_producer_publication_lifts_gate_only_on_attested_lane() {
    let source = bpf_source();
    // Emission exists now: the return path constructs the object tail.
    assert!(
        source.contains("ObjectCallWire")
            || source.contains("object: ObjectCallWire")
            || source.contains("ObjectEventRecord"),
        "slice D must construct the object tail on the return path"
    );
    // ... behind the required-object marker: ordinary calls keep one
    // 368-byte reservation and never touch the tail.
    let returned = source_between(
        &source,
        "fn p11_return_impl(ctx: RetProbeContext) -> u32 {",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    assert!(
        returned.contains("object_required"),
        "emission stays behind the required-object marker"
    );
    assert_eq!(
        returned.matches("EVENTS.reserve").count(),
        2,
        "return reserves exactly the ordinary and the object record forms"
    );
    // The userspace decode gate needs the receipt-bound table: the
    // session freezes object rows against its attested receipt.
    let attach = std::fs::read_to_string("src/attach.rs").expect("read attach");
    assert!(
        attach.contains("object_decode_table") || attach.contains("ObjectDecodeTable"),
        "the session must freeze object rows for the attested decode lane"
    );
}

/// The private validated tail accompanies the owned H3 routed call into
/// the consuming admission result, but it cannot construct the H9 model:
/// no ObjectDomain, OriginFact, RefCut, CallToken, CompleteInputPrefix,
/// and no ObjectSemantics::{begin,complete,settle} in the transport.
#[test]
fn object_producer_tail_builds_no_model() {
    // Existence: the transport carries the tail end to end.
    let capture = std::fs::read_to_string("src/semantic_capture.rs").expect("read capture router");
    assert!(
        capture.contains("decoded: DecodedEventRecord"),
        "RoutedCall must carry the decoded envelope with its tail"
    );
    assert!(
        capture.contains("fn into_object_tail(self) -> Option<ValidatedObjectCall>"),
        "RoutedCall must hand its tail move-only to the sole consumer"
    );
    let input = std::fs::read_to_string("src/discovery/caller_registry/instance_input.rs")
        .expect("read evidence adapter");
    assert!(
        input.matches("object: Option<ValidatedObjectCall>").count() >= 2,
        "CallEvidence and the admission result must carry the tail"
    );
    // Absence: no model construction in the H7 transport windows.
    for (name, body) in [
        (
            "events",
            std::fs::read_to_string("src/events.rs").expect("read events"),
        ),
        ("capture", capture),
        ("evidence", input),
    ] {
        for marker in [
            "ObjectDomain",
            "OriginFact",
            "RefCut",
            "CallToken",
            "CompleteInputPrefix",
            "ObjectSemantics",
        ] {
            assert!(
                !body.contains(marker),
                "{name} transport must not name the H9 model ({marker})"
            );
        }
    }
    let coordinator = std::fs::read_to_string("src/discovery/inventory_coordinator/semantics.rs")
        .expect("read coordinator");
    for marker in [
        "ObjectDomain",
        "OriginFact",
        "RefCut",
        "CallToken",
        "CompleteInputPrefix",
        "ObjectSemantics",
    ] {
        assert!(
            !coordinator.contains(marker),
            "coordinator transport must not name the H9 model ({marker})"
        );
    }
}

/// The tail and its envelopes carry raw target words: no raw-value
/// Debug/Serialize anywhere on the H7 transport path.
#[test]
fn object_producer_tail_has_no_raw_debug_or_serialize() {
    let wire =
        std::fs::read_to_string("crates/ebpf-common/src/object_wire.rs").expect("read object wire");
    let validated = source_between(
        &wire,
        "pub struct ValidatedObjectCall {",
        "/// Meaning of a START `object_required` marker word against the frozen",
    );
    // No Debug derive/impl and no Serialize: only the doc comment names
    // the deliberately absent Debug.
    assert!(
        !validated.contains("Serialize")
            && !validated.contains("Debug for ValidatedObjectCall")
            && !validated.contains("derive("),
        "ValidatedObjectCall must stay Debug/Serialize-free"
    );
    let head = wire
        .find("pub struct ValidatedObjectCall {")
        .expect("validated tail struct");
    assert!(
        wire[head.saturating_sub(200)..head].contains("#[derive(Clone, Copy)]"),
        "ValidatedObjectCall derives only Clone and Copy"
    );
    // Existence: the envelopes that must stay redacted.
    for (path, redacted) in [
        ("src/events.rs", "pub(crate) struct DecodedEventRecord {"),
        (
            "src/discovery/caller_registry/instance_input.rs",
            "pub(crate) struct CallEvidence {",
        ),
    ] {
        let body = std::fs::read_to_string(path).expect("read envelope");
        assert!(
            body.contains("Option<ValidatedObjectCall>"),
            "{path} must carry the private validated tail"
        );
        assert!(
            !body.contains("Serialize"),
            "{path} transport must not Serialize raw tails"
        );
        let _ = redacted;
    }
    let input = std::fs::read_to_string("src/discovery/caller_registry/instance_input.rs")
        .expect("read evidence adapter");
    assert!(
        input.contains("CallEvidence(<private>)"),
        "CallEvidence Debug must stay redacted"
    );
}

/// H7 publishes no object arrays, IDs, birth/destruction or key-use
/// labels: the admission result carries the tail privately with no
/// public object projection.
#[test]
fn object_producer_public_surface_has_no_object_labels() {
    let input = std::fs::read_to_string("src/discovery/caller_registry/instance_input.rs")
        .expect("read evidence adapter");
    // Existence: the admission result carries the tail.
    let admitted = source_between(
        &input,
        "pub(crate) struct AdmittedInstanceCall {",
        "enum InstanceScope {",
    );
    assert!(
        admitted.contains("Option<ValidatedObjectCall>"),
        "the admission result must carry the private tail"
    );
    // Absence: no public object projection on the result.
    for marker in [
        "pub fn objects",
        "pub fn object_ids",
        "pub fn birth",
        "pub fn destruction",
        "pub fn key_use",
        "object_ids",
        "key_use_labels",
    ] {
        assert!(
            !admitted.contains(marker),
            "the admission result must not project {marker}"
        );
    }
}

/// The outlined emission helpers survive in the embedded object next to
/// the five adapter helpers; no monolithic native drain appears.
#[test]
fn object_producer_emission_helpers_in_elf() {
    let directory = tempfile::tempdir().expect("temporary emission ELF check");
    let object = embedded_object(directory.path());
    let output = Command::new("nm")
        .arg("--defined-only")
        .arg(&object)
        .output()
        .expect("run nm on embedded object");
    assert!(
        output.status.success(),
        "nm failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let symbols = String::from_utf8_lossy(&output.stdout).into_owned();
    for helper in ["object_tail_fill", "object_emit_find"] {
        let hits: Vec<&str> = symbols
            .lines()
            .filter(|line| line.contains(helper) && (line.contains(" T ") || line.contains(" t ")))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "expected one .text {helper}, saw {}: {hits:?}",
            hits.len()
        );
    }
    assert!(
        !symbols.contains("p11_object_return_remove"),
        "no monolithic native drain"
    );
}

/// A joinable entry/return stamp pair: equal epochs, a watched file, the
/// VALID bit and no refusal flag.
fn clean_stamps() -> (
    p11scope_ebpf_common::InstanceStamp,
    p11scope_ebpf_common::InstanceStamp,
) {
    let stamp = p11scope_ebpf_common::InstanceStamp {
        epoch: 7,
        global: 9,
        fault: 11,
        file_slot_plus1: 3,
        flags: p11scope_ebpf_common::instance::STAMP_VALID,
    };
    (stamp, stamp)
}

/// Every continuity refusal the return gate must enforce: absent entry
/// (all-zero stamp), straddled epoch/global/fault/file-slot, missing
/// VALID, and each blocking flag.
fn refused_stamp_pairs() -> Vec<(
    &'static str,
    p11scope_ebpf_common::InstanceStamp,
    p11scope_ebpf_common::InstanceStamp,
)> {
    use p11scope_ebpf_common::instance;
    let (entry, ret) = clean_stamps();
    let zero = p11scope_ebpf_common::InstanceStamp::default();
    let mut cases = Vec::new();
    cases.push(("absent entry", zero, ret));
    for (name, mutate) in [
        ("epoch straddle", 0u8),
        ("global straddle", 1u8),
        ("fault straddle", 2u8),
        ("file-slot straddle", 3u8),
    ] {
        let mut moved = ret;
        match mutate {
            0 => moved.epoch = moved.epoch.wrapping_add(1),
            1 => moved.global = moved.global.wrapping_add(1),
            2 => moved.fault = moved.fault.wrapping_add(1),
            _ => moved.file_slot_plus1 = moved.file_slot_plus1.wrapping_add(1),
        };
        cases.push((name, entry, moved));
    }
    let mut no_valid = ret;
    no_valid.flags &= !instance::STAMP_VALID;
    cases.push(("missing VALID", entry, no_valid));
    for (name, flag) in [
        ("NO_FILE", instance::STAMP_NO_FILE),
        ("NO_TASK", instance::STAMP_NO_TASK),
        ("SHARED_MM", instance::STAMP_SHARED_MM),
        ("OVERFLOW", instance::STAMP_OVERFLOW),
        ("LOCAL_FAULT", instance::STAMP_LOCAL_FAULT),
    ] {
        let mut flagged = entry;
        flagged.flags |= flag;
        cases.push((name, flagged, flagged));
    }
    cases
}

/// H7-E1 return-arm harness. Executes the REAL production adapter bodies
/// (`object_flow::{continuity_joins, adapter_fill_return, adapter_tail_fill,
/// adapter_emit_find, adapter_emit_get_attributes}` — the same functions the
/// BPF wrappers call) in the root's order (gate → fill → tail → find → get,
/// each `&&` short-circuiting like the root) with instrumented readers and
/// a caller-owned side row. Every outcome below is computed by production
/// code; the only modeled input is the native retirement result (the C
/// fixture executes the real removal; see G03). The order pins below bind
/// the harness sequence to the root.
struct EmissionOutcome {
    joined: bool,
    filled: bool,
    tailed: bool,
    emitted: bool,
    fault_required: bool,
    side: p11scope_ebpf_common::object_wire::ObjectStart,
    tail: p11scope_ebpf_common::object_wire::ObjectCallWire,
}

/// A frozen descriptor row for the harness: `descriptor` names function
/// `descriptor - 1`, one result arg, no templates, valid action/guard.
fn harness_row(
    descriptor: u32,
    action: u8,
    result_args: [u8; 2],
) -> p11scope_ebpf_common::object_wire::ObjectDescriptorWire {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::object_wire::{OBJECT_GUARD_NAMED, ObjectDescriptorWire};
    ObjectDescriptorWire {
        function: descriptor.wrapping_sub(1),
        input_args: [ARG_NONE; 2],
        result_args,
        template_args: [ARG_NONE; 4],
        find_capacity_arg: ARG_NONE,
        find_count_arg: ARG_NONE,
        action,
        guard: OBJECT_GUARD_NAMED,
    }
}

/// A READY (phase 2) caller-owned side row, as the required=1 return query
/// hands it to the fill adapter.
fn ready_side(descriptor: u32) -> p11scope_ebpf_common::object_wire::ObjectStart {
    p11scope_ebpf_common::object_wire::ObjectStart {
        descriptor_index: descriptor,
        phase: 2,
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn run_production_return_arm(
    target: &std::cell::RefCell<adapter::FakeTarget>,
    layout: p11scope_ebpf_common::LinuxLayout,
    mut side: p11scope_ebpf_common::object_wire::ObjectStart,
    row: &p11scope_ebpf_common::object_wire::ObjectDescriptorWire,
    rv: u64,
    continuity: &p11scope_ebpf_common::InstanceContinuity,
    mech_status: u32,
    mech: u64,
    retire_ok: bool,
) -> EmissionOutcome {
    use p11scope_ebpf_common::object_flow::{
        adapter_emit_find, adapter_emit_get_attributes, adapter_fill_return, adapter_tail_fill,
        continuity_joins, emission_finalize,
    };
    use p11scope_ebpf_common::object_wire::ObjectCallWire;
    let descriptor = side.descriptor_index;
    // Gate: the production predicate on the reserved record's stamps.
    let joined = continuity_joins(continuity);
    // Fills in root order; each stage short-circuits like the root, so a
    // refused fill runs no later adapter and touches no tail.
    let (reader, _) = adapter::readers(target);
    let filled = adapter_fill_return(
        Some(&mut side),
        descriptor,
        Some(row),
        rv,
        layout,
        mech_status,
        mech,
        joined,
        reader,
    );
    let mut tail = ObjectCallWire::default();
    let tailed = filled
        && unsafe { adapter_tail_fill(&mut tail as *mut _, Some(&side), descriptor, Some(row)) };
    let (reader, _) = adapter::readers(target);
    let emitted = tailed
        && unsafe {
            adapter_emit_find(
                &mut tail as *mut _,
                Some(&side),
                descriptor,
                Some(row),
                layout,
                rv,
                joined,
                reader,
            )
        };
    // The root's fourth emission stage: Get result establishment. The G02
    // vectors are all non-Get rows, so this stage succeeds trivially with
    // zero reads here; it executes for root fidelity.
    let (reader, bytes) = adapter::readers(target);
    let emitted = emitted
        && unsafe {
            adapter_emit_get_attributes(
                &mut tail as *mut _,
                Some(&side),
                descriptor,
                Some(row),
                layout,
                rv,
                joined,
                reader,
                bytes,
            )
        };
    // The fault decision is production's `emission_finalize` (the same
    // function the BPF return root calls); only the native `retire_ok`
    // input is modeled here.
    let outcome = emission_finalize(emitted, || retire_ok);
    EmissionOutcome {
        joined,
        filled,
        tailed,
        emitted,
        fault_required: !joined || outcome.faulted,
        side,
        tail,
    }
}

/// Wrap an entry/return stamp pair the way the reserved record carries it.
fn continuity_of(
    entry: p11scope_ebpf_common::InstanceStamp,
    ret: p11scope_ebpf_common::InstanceStamp,
) -> p11scope_ebpf_common::InstanceContinuity {
    p11scope_ebpf_common::InstanceContinuity {
        entry_ip: 0,
        entry_stamp: entry,
        return_stamp: ret,
    }
}

/// Every production attribute read must be a read the oracle also
/// performs: the production path may read less (nothing, while E4 is
/// unwired) but never more. Guards a wired E4 against over-reading.
fn assert_reads_subset(
    prod: &std::cell::RefCell<adapter::FakeTarget>,
    oracle: &std::cell::RefCell<adapter::FakeTarget>,
    what: &str,
) {
    for entry in prod.borrow().log().iter() {
        assert!(
            oracle.borrow().log().contains(entry),
            "{what}: production read {entry:?} is outside the oracle set"
        );
    }
}

fn pin_continuity_gate_precedes_fills() {
    let source = bpf_source();
    let returned = source_between(
        &source,
        "fn p11_return_impl(ctx: RetProbeContext) -> u32 {",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    // The continuity fill and its join gate precede every object result
    // read; the gate arm discards the reservation, retires ownership and
    // faults instead of emitting.
    let continuity = returned
        .find("p11_instance_return(&key,")
        .expect("return must fill continuity on the object arm");
    let gate = returned
        .find("continuity_joins(")
        .expect("return must gate object reads on the shared stamp join");
    let fill = returned
        .find("object_fill_return(")
        .expect("emission fills after the gate");
    let find = returned
        .find("object_emit_find(")
        .expect("Find emits after the gate");
    assert!(
        continuity < gate && gate < fill && fill < find,
        "continuity fill, join gate, result fill and Find emission must run in that order"
    );
    let arm = &returned[gate..fill];
    for marker in [
        "entry.discard(0)",
        "owned_start_remove(&key, true)",
        "p11_object_fault()",
    ] {
        assert!(
            arm.contains(marker),
            "the refused gate arm must {marker} before any object read"
        );
    }
    // The root threads its verdict into the fill adapters, which enforce
    // it again inside the executed production flow.
    let filled_call = source_between(returned, "let filled = object_fill_return(", ");");
    assert!(
        filled_call.contains("joined"),
        "the result fill must receive the root continuity verdict"
    );
    let emitted_call = source_between(returned, "let emitted =", ";");
    assert!(
        emitted_call.contains("joined"),
        "Find emission must receive the root continuity verdict"
    );
    // Delegation: the BPF wrappers bind BPF-local state and call the
    // shared adapters the harness executes — no second inline copy.
    for (wrapper, shared) in [
        ("fn object_fill_return(", "adapter_fill_return("),
        ("fn object_tail_fill(", "adapter_tail_fill("),
        ("fn object_emit_find(", "adapter_emit_find("),
    ] {
        let body = source_between(&source, wrapper, "\n}\n");
        assert_eq!(
            body.matches(shared).count(),
            1,
            "{wrapper} must delegate to exactly one shared {shared}"
        );
    }
    // Executed order: inside the shared fill, the continuity gate runs
    // before any slot read.
    let flow = std::fs::read_to_string("crates/ebpf-common/src/object_flow.rs")
        .expect("read shared adapter flow");
    let shared_fill = source_between(
        &flow,
        "pub fn adapter_fill_return(",
        "pub unsafe fn adapter_tail_fill(",
    );
    let shared_gate = shared_fill
        .find("if !joined")
        .expect("the shared fill must gate on continuity");
    let first_read = shared_fill
        .find("slot_word(")
        .expect("the shared fill reads result words");
    assert!(
        shared_gate < first_read,
        "the executed fill must gate before its first read"
    );
}

/// G02/E1: refused continuity performs zero result-handle reads. Healthy
/// twin reads the exact expected result once and retains the joined
/// stamps; every refusal (absent entry, straddled epoch/global/fault/
/// file-slot, missing VALID, each blocking flag) reads nothing, runs no
/// later adapter, leaves the tail zero and faults visibly. All fills run
/// through the production adapters, so neutering the production gate
/// fails this test.
#[test]
fn object_return_continuity_refuses_before_reads() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::capture;
    use p11scope_ebpf_common::object_capture::handle_status;
    use p11scope_ebpf_common::object_wire::{OBJECT_ACTION_CREATE, ObjectCallWire};
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let row = harness_row(23, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        let healthy_side = || {
            let mut side = ready_side(23);
            side.result_ptrs = [0x10000, 0];
            side
        };
        // Healthy twin: one present result, CKR_OK, joined stamps.
        let target = adapter::FakeTarget::new(w);
        let target = std::cell::RefCell::new(target);
        target.borrow_mut().set_word(0x10000, 0x42);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            adapter::rv_ok(),
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            true,
        );
        assert_eq!(
            target.borrow().log(),
            &[(adapter::READ_WORD, 0x10000, w)],
            "{layout:?} healthy twin must read the exact result once"
        );
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert_eq!(
            outcome.side.result_statuses,
            [handle_status::VALUE, handle_status::ABSENT]
        );
        assert_eq!(outcome.side.result_ptrs, [0x42, 0]);
        assert_eq!(outcome.side.phase, 3);
        assert_eq!(outcome.tail.result_handles, [0x42, 0]);
        assert_eq!(
            outcome.tail.result_status,
            [handle_status::VALUE, handle_status::ABSENT]
        );
        assert!(!outcome.fault_required, "healthy twin faults nothing");
        assert!(
            p11scope_ebpf_common::instance::stamp_joinable(entry, ret),
            "healthy twin retains the joined stamps"
        );
        // Failed reads are distinct from refused reads: a joined call
        // whose result word is unreadable attempts the read once and
        // carries UNREADABLE, never VALUE and never zero-read silence.
        // The finite failure still completes every stage.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        target.borrow_mut().set_fail(0x10000);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            adapter::rv_ok(),
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            true,
        );
        assert_eq!(
            target.borrow().log(),
            &[(adapter::READ_WORD, 0x10000, w)],
            "{layout:?} failed result word is attempted once"
        );
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert_eq!(
            outcome.side.result_statuses,
            [handle_status::UNREADABLE, handle_status::ABSENT]
        );
        assert_eq!(outcome.side.result_ptrs, [0, 0]);
        // Ordinary accounting stays truthful: joined stamps with a
        // non-OK RV read nothing, keep the honest tail (unavailable
        // cells, never values) and fault nothing.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        target.borrow_mut().set_word(0x10000, 0x42);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            7,
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            true,
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} result reads on RV 7"));
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert_eq!(
            outcome.side.result_statuses,
            [handle_status::PROTOCOL_UNAVAILABLE, handle_status::ABSENT]
        );
        assert_eq!(
            outcome.tail.result_status,
            [handle_status::PROTOCOL_UNAVAILABLE, handle_status::ABSENT]
        );
        assert!(!outcome.fault_required, "non-OK RV faults nothing");
        // A failed native retirement faults even when every adapter
        // stage succeeded (the native half is executed by the G03 C
        // fixture; this input only threads its verdict).
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        target.borrow_mut().set_word(0x10000, 0x42);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            adapter::rv_ok(),
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            false,
        );
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert!(
            outcome.fault_required,
            "{layout:?} failed retirement faults visibly"
        );
        // Every refusal: zero reads, no later adapter, zero tail, the
        // retained pointers preserved, visible fault.
        for (name, entry, ret) in refused_stamp_pairs() {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            target.borrow_mut().set_word(0x10000, 0x42);
            let outcome = run_production_return_arm(
                &target,
                layout,
                healthy_side(),
                &row,
                adapter::rv_ok(),
                &continuity_of(entry, ret),
                capture::MECHANISM_VALUE,
                0,
                true,
            );
            adapter::assert_no_target_reads(&target, &format!("{layout:?} result reads on {name}"));
            assert!(
                !outcome.joined && !outcome.filled && !outcome.tailed && !outcome.emitted,
                "{layout:?} {name}: refused continuity runs no adapter stage"
            );
            assert!(
                outcome.tail == ObjectCallWire::default(),
                "{layout:?} {name}: refused continuity leaves the tail zero"
            );
            assert_eq!(
                outcome.side.result_ptrs,
                [0x10000, 0],
                "{layout:?} {name}: refused continuity preserves retained pointers"
            );
            assert_eq!(outcome.side.phase, 2, "{layout:?} {name}: side stays READY");
            assert!(
                outcome.fault_required,
                "{layout:?} {name}: refused continuity faults visibly"
            );
        }
    }
    pin_continuity_gate_precedes_fills();
}

/// G02/E1: refused continuity performs zero Find reads: no count read,
/// no element reads, no reread. Healthy twin streams the exact
/// count/element/reread sequence through the production Find adapter;
/// every refusal reads nothing and streams no Find section.
#[test]
fn object_find_continuity_refuses_before_reads() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::capture;
    use p11scope_ebpf_common::object_capture::handle_status;
    use p11scope_ebpf_common::object_wire::{OBJECT_ACTION_FIND, ObjectCallWire};
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let row = harness_row(23, OBJECT_ACTION_FIND, [ARG_NONE, ARG_NONE]);
        let program_find = |target: &std::cell::RefCell<adapter::FakeTarget>| {
            let mut borrowed = target.borrow_mut();
            borrowed.set_word(0x21000, 2);
            borrowed.set_word(0x20000, 0x51);
            borrowed.set_word(0x20000 + w, 0x52);
        };
        let healthy_side = || {
            let mut side = ready_side(23);
            side.result_ptrs = [0x20000, 0];
            side.find_capacity = 8;
            side.find_count_ptr = 0x21000;
            side
        };
        // Healthy twin: count read, two elements, count reread.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_find(&target);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            adapter::rv_ok(),
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            true,
        );
        assert_eq!(
            target.borrow().log(),
            &[
                (adapter::READ_WORD, 0x21000, w),
                (adapter::READ_WORD, 0x20000, w),
                (adapter::READ_WORD, 0x20000 + w, w),
                (adapter::READ_WORD, 0x21000, w),
            ],
            "{layout:?} healthy Find twin must stream count, elements, reread"
        );
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert_eq!(outcome.tail.find_valid, 1, "healthy Find twin validates");
        assert_eq!(outcome.tail.find_len, 2);
        assert_eq!(
            outcome.tail.find_status[..2],
            [handle_status::VALUE, handle_status::VALUE]
        );
        assert_eq!(outcome.tail.find_handles[..2], [0x51, 0x52]);
        assert_eq!(
            outcome.tail.result_status,
            [handle_status::PROTOCOL_UNAVAILABLE, handle_status::ABSENT],
            "{layout:?} Find result cell stays the constant unavailable cell"
        );
        assert!(!outcome.fault_required, "healthy Find twin faults nothing");
        // Ordinary accounting stays truthful: joined stamps with a
        // non-OK RV read neither count nor elements, validate nothing
        // and fault nothing, while every stage still completes.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_find(&target);
        let (entry, ret) = clean_stamps();
        let outcome = run_production_return_arm(
            &target,
            layout,
            healthy_side(),
            &row,
            7,
            &continuity_of(entry, ret),
            capture::MECHANISM_VALUE,
            0,
            true,
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} Find reads on RV 7"));
        assert!(outcome.joined && outcome.filled && outcome.tailed && outcome.emitted);
        assert_eq!(
            outcome.tail.find_valid, 0,
            "non-OK RV validates no Find batch"
        );
        assert!(!outcome.fault_required, "non-OK RV faults nothing");
        // Every refusal: the count word itself is unread.
        for (name, entry, ret) in refused_stamp_pairs() {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            program_find(&target);
            let outcome = run_production_return_arm(
                &target,
                layout,
                healthy_side(),
                &row,
                adapter::rv_ok(),
                &continuity_of(entry, ret),
                capture::MECHANISM_VALUE,
                0,
                true,
            );
            adapter::assert_no_target_reads(&target, &format!("{layout:?} Find reads on {name}"));
            assert!(
                !outcome.joined && !outcome.filled && !outcome.tailed && !outcome.emitted,
                "{layout:?} {name}: refused continuity runs no adapter stage"
            );
            assert!(
                outcome.tail == ObjectCallWire::default(),
                "{layout:?} {name}: refused continuity leaves the tail zero"
            );
            assert!(
                outcome.fault_required,
                "{layout:?} {name}: refused continuity faults visibly"
            );
        }
    }
    pin_continuity_gate_precedes_fills();
}

/// Fix round 1 mutation control for the G02 probe: the production gate
/// and adapter custody are load-bearing. Deleting `if !joined` from the
/// shared adapters, or substituting one stamp for the other in
/// `continuity_joins`, fails this test (verified by manual mutant during
/// the fix round). Refused custody reads nothing on every adapter.
#[test]
fn object_return_gate_and_custody_refuse_without_reads() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::capture;
    use p11scope_ebpf_common::object_flow::{
        adapter_derive_entry, adapter_emit_find, adapter_fill_return, adapter_tail_fill,
        continuity_joins,
    };
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_ACTION_DERIVE, ObjectCallWire,
    };
    // The shared predicate joins clean stamps and refuses every
    // asymmetric pair.
    let (entry, ret) = clean_stamps();
    assert!(continuity_joins(&continuity_of(entry, ret)));
    for (name, entry, ret) in refused_stamp_pairs() {
        assert!(
            !continuity_joins(&continuity_of(entry, ret)),
            "{name} must not join"
        );
    }
    // Substituting the current stamp for the retained one would join the
    // absent-entry case: the predicate genuinely reads both fields, so a
    // substitution mutant fails the refusal asserts above.
    let (_, absent_entry, clean_ret) = refused_stamp_pairs()[0];
    assert!(continuity_joins(&continuity_of(clean_ret, clean_ret)));
    assert!(!continuity_joins(&continuity_of(absent_entry, clean_ret)));
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let row = harness_row(23, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        // `joined = false` refuses inside every reading adapter with
        // zero reads, however the adapter was reached.
        for gate in [true, false] {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            target.borrow_mut().set_word(0x10000, 0x42);
            let mut side = ready_side(23);
            side.result_ptrs = [0x10000, 0];
            let (reader, _) = adapter::readers(&target);
            let filled = adapter_fill_return(
                Some(&mut side),
                23,
                Some(&row),
                adapter::rv_ok(),
                layout,
                capture::MECHANISM_VALUE,
                0,
                gate,
                reader,
            );
            assert_eq!(filled, gate, "{layout:?} fill follows the gate");
            if gate {
                assert_eq!(
                    target.borrow().log(),
                    &[(adapter::READ_WORD, 0x10000, w)],
                    "{layout:?} joined fill reads its result once"
                );
            } else {
                adapter::assert_no_target_reads(&target, &format!("{layout:?} gated fill"));
            }
            // Find emission follows the same gate.
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            target.borrow_mut().set_word(0x21000, 1);
            let mut side = ready_side(23);
            side.phase = 3;
            side.result_ptrs = [0x20000, 0];
            side.find_capacity = 8;
            side.find_count_ptr = 0x21000;
            let mut tail = ObjectCallWire::default();
            let (reader, _) = adapter::readers(&target);
            let emitted = unsafe {
                adapter_emit_find(
                    &mut tail as *mut _,
                    Some(&side),
                    23,
                    Some(&harness_row(
                        23,
                        p11scope_ebpf_common::object_wire::OBJECT_ACTION_FIND,
                        [ARG_NONE, ARG_NONE],
                    )),
                    layout,
                    adapter::rv_ok(),
                    gate,
                    reader,
                )
            };
            assert_eq!(emitted, gate, "{layout:?} Find emission follows the gate");
            if !gate {
                adapter::assert_no_target_reads(&target, &format!("{layout:?} gated Find"));
            }
        }
        // Custody failures refuse without reads: missing side, wrong
        // phase, missing or mismatched row, null tail.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        target.borrow_mut().set_word(0x10000, 0x42);
        let mut side = ready_side(23);
        side.result_ptrs = [0x10000, 0];
        let (reader, _) = adapter::readers(&target);
        assert!(
            !adapter_fill_return(
                None,
                23,
                Some(&row),
                adapter::rv_ok(),
                layout,
                capture::MECHANISM_VALUE,
                0,
                true,
                reader,
            ),
            "{layout:?} missing side refuses the fill"
        );
        let mut wrong_phase = ready_side(23);
        wrong_phase.phase = 1;
        wrong_phase.result_ptrs = [0x10000, 0];
        let (reader, _) = adapter::readers(&target);
        assert!(
            !adapter_fill_return(
                Some(&mut wrong_phase),
                23,
                Some(&row),
                adapter::rv_ok(),
                layout,
                capture::MECHANISM_VALUE,
                0,
                true,
                reader,
            ),
            "{layout:?} non-READY phase refuses the fill"
        );
        let (reader, _) = adapter::readers(&target);
        assert!(
            !adapter_fill_return(
                Some(&mut side),
                23,
                None,
                adapter::rv_ok(),
                layout,
                capture::MECHANISM_VALUE,
                0,
                true,
                reader,
            ),
            "{layout:?} missing row refuses the fill"
        );
        let bad_row = harness_row(24, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        let (reader, _) = adapter::readers(&target);
        assert!(
            !adapter_fill_return(
                Some(&mut side),
                23,
                Some(&bad_row),
                adapter::rv_ok(),
                layout,
                capture::MECHANISM_VALUE,
                0,
                true,
                reader,
            ),
            "{layout:?} mismatched row refuses the fill"
        );
        let mut tail = ObjectCallWire::default();
        assert!(
            !unsafe { adapter_tail_fill(core::ptr::null_mut(), Some(&side), 23, Some(&row),) },
            "{layout:?} null tail refuses"
        );
        let (reader, _) = adapter::readers(&target);
        assert!(
            !unsafe {
                adapter_emit_find(
                    &mut tail as *mut _,
                    None,
                    23,
                    Some(&row),
                    layout,
                    adapter::rv_ok(),
                    true,
                    reader,
                )
            },
            "{layout:?} missing side refuses Find emission"
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} custody refusals"));
        // The Derive adapter needs no continuity gate (entry runs before
        // any return stamp exists) but keeps its custody checks.
        let derive_row = harness_row(23, OBJECT_ACTION_DERIVE, [5, ARG_NONE]);
        let (reader, _) = adapter::readers(&target);
        let mut fetch = |_: u8| None;
        assert!(
            !adapter_derive_entry(None, 23, Some(&derive_row), layout, &mut fetch, reader),
            "{layout:?} missing side refuses Derive entry"
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} Derive custody"));
    }
}

// H7-E4 production attribute paths (see `object_flow` seams). The tests
// below run the REAL shared protocol on each vector as the oracle (with
// independent literal expectations) and require the PRODUCTION path —
// same vectors, same readers — to match it cell for cell. RED while the
// production path is unwired (zero reads, zero cells); a budgeted E4
// implements the seams and flips these tests with no fixture change.

fn program_attr_slot(
    target: &std::cell::RefCell<adapter::FakeTarget>,
    base: u64,
    index: u64,
    w: u64,
    selector: u64,
    ptr: u64,
    len: u64,
) {
    let slot = base + index * 3 * w;
    let mut mem = target.borrow_mut();
    mem.set_word(slot, selector);
    mem.set_word(slot + w, ptr);
    mem.set_word(slot + 2 * w, len);
}

/// Program one eight-slot six-field template: class, key type, token,
/// value length, modulus bits and all three curves. Values live away
/// from the headers so no selected span aliases inspected headers.
fn program_six_field_template(
    target: &std::cell::RefCell<adapter::FakeTarget>,
    base: u64,
    values: u64,
    w: u64,
) {
    program_attr_slot(target, base, 0, w, 0x0000, values, w);
    target.borrow_mut().set_word(values, 3);
    program_attr_slot(target, base, 1, w, 0x0100, values + 0x10, w);
    target.borrow_mut().set_word(values + 0x10, 0x1f);
    program_attr_slot(target, base, 2, w, 0x0001, values + 0x20, 1);
    target.borrow_mut().set_bytes(values + 0x20, &[1]);
    program_attr_slot(target, base, 3, w, 0x0161, values + 0x30, w);
    target.borrow_mut().set_word(values + 0x30, 32);
    program_attr_slot(target, base, 4, w, 0x0121, values + 0x40, w);
    target.borrow_mut().set_word(values + 0x40, 2048);
    program_attr_slot(target, base, 5, w, 0x0180, values + 0x50, 10);
    target.borrow_mut().set_bytes(
        values + 0x50,
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
    );
    program_attr_slot(target, base, 6, w, 0x0180, values + 0x60, 7);
    target
        .borrow_mut()
        .set_bytes(values + 0x60, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]);
    program_attr_slot(target, base, 7, w, 0x0180, values + 0x70, 7);
    target
        .borrow_mut()
        .set_bytes(values + 0x70, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]);
}

/// Strip Rust line comments, (nested) block comments, string literals
/// and character literals, so static pins count code tokens — never
/// prose. A `'` only opens a character literal when its closing quote
/// lands on the same line within four bytes, so lifetimes survive.
fn strip_rust_prose(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < bytes.len() {
        let rest = &bytes[i..];
        if rest.starts_with(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if rest.starts_with(b"/*") {
            let mut depth = 0;
            while i < bytes.len() {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                } else {
                    i += 1;
                    if bytes[i - 1] == b'"' {
                        break;
                    }
                }
            }
            out.push(' ');
        } else if bytes[i] == b'\'' {
            let mut end = i + 1;
            while end < bytes.len() && bytes[end] != b'\'' && bytes[end] != b'\n' && end - i <= 4 {
                end += 1;
            }
            if end < bytes.len() && bytes[end] == b'\'' && end - i <= 4 {
                i = end + 1;
                out.push(' ');
            } else {
                out.push('\'');
                i += 1;
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// G05/E4 production-wiring pin: the BPF attribute wrappers must delegate
/// to the shared adapters the suite executes — no second inline copy.
/// Comment-proof: prose is stripped before counting, so comments (or
/// strings) naming the adapters cannot satisfy it. The adapter-to-seam edge
/// needs no pin: the G05 tests drive the adapters, so a missing seam
/// call observes zero cells (the disconnect mutant keeps wired seams
/// RED). The BPF wrapper-to-adapter edge itself is host-inexecutable, like
/// every other BPF call edge — this pin requires it textually, and live
/// populated transport (U10) qualifies it end to end.
fn pin_attribute_wrappers_delegate_to_shared_adapters() {
    let stripped = strip_rust_prose(&bpf_source());
    for (wrapper, shared, end) in [
        (
            "fn object_entry_attributes(",
            "adapter_attributes_entry(",
            "fn object_fill_return(",
        ),
        (
            "fn object_emit_get_attributes(",
            "adapter_emit_get_attributes(",
            "fn owned_start_discard(",
        ),
    ] {
        let body = source_between(&stripped, wrapper, end);
        assert_eq!(
            body.matches(shared).count(),
            1,
            "{wrapper} must delegate to exactly one shared {shared}"
        );
        assert!(
            !body.contains("production_"),
            "{wrapper} must not bypass its adapter with a direct seam call"
        );
    }
    // Exactly one production caller per wrapper: the definition plus the
    // single root call site, counted over stripped code.
    for wrapper in ["object_entry_attributes(", "object_emit_get_attributes("] {
        assert_eq!(
            stripped.matches(wrapper).count(),
            2,
            "{wrapper} keeps its single definition plus one root call site"
        );
    }
}

/// Drive one creation-template vector through the PRODUCTION entry path:
/// the shared `adapter_attributes_entry` the BPF entry adapter calls,
/// programmed with the pair scalars at the row's template args — then the
/// production tail emission from the stored side row. Returns the side
/// row AFTER the production entry store plus the emitted tail. The
/// harness never writes `side.requested` itself: a missing production
/// entry-store operation observes zero cells here.
#[allow(clippy::type_complexity)]
fn run_production_request_path(
    target: &std::cell::RefCell<adapter::FakeTarget>,
    layout: p11scope_ebpf_common::LinuxLayout,
    action: u8,
    pairs: [(u64, u64); 2],
    template_args: [u8; 4],
) -> (
    p11scope_ebpf_common::object_wire::ObjectStart,
    p11scope_ebpf_common::object_wire::ObjectCallWire,
) {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::object_flow::{adapter_attributes_entry, adapter_tail_fill};
    use p11scope_ebpf_common::object_wire::{
        OBJECT_LAYOUT_ILP32, OBJECT_LAYOUT_LP64, ObjectCallWire,
    };
    let mut row = harness_row(23, action, [5, ARG_NONE]);
    row.template_args = template_args;
    let mut side = p11scope_ebpf_common::object_wire::ObjectStart {
        descriptor_index: 23,
        layout: if layout == p11scope_ebpf_common::LinuxLayout::Lp64 {
            OBJECT_LAYOUT_LP64
        } else {
            OBJECT_LAYOUT_ILP32
        },
        ..Default::default()
    };
    let mut fetch_arg = |arg: u8| {
        if arg == template_args[0] {
            Some(pairs[0].0)
        } else if arg == template_args[1] {
            Some(pairs[0].1)
        } else if arg == template_args[2] {
            Some(pairs[1].0)
        } else if arg == template_args[3] {
            Some(pairs[1].1)
        } else {
            None
        }
    };
    let (reader, bytes) = adapter::readers(target);
    assert!(
        adapter_attributes_entry(
            Some(&mut side),
            23,
            Some(&row),
            layout,
            &mut fetch_arg,
            reader,
            bytes,
        ),
        "{layout:?} production entry adapter accepts the vector"
    );
    // RETURNING arrival state (harness sequencing, as the fill adapter
    // would leave it); the inspected pair lists arrive only via the
    // production entry store above.
    side.phase = 3;
    let mut tail = ObjectCallWire::default();
    let tailed = unsafe { adapter_tail_fill(&mut tail as *mut _, Some(&side), 23, Some(&row)) };
    assert!(tailed, "{layout:?} production tail fills");
    (side, tail)
}

/// Drive one Get vector through the PRODUCTION Get path: entry retention
/// via the shared `adapter_attributes_entry` the BPF entry adapter
/// calls, then return emission via the shared
/// `adapter_emit_get_attributes` the BPF return path calls. Returns the
/// side row after retention plus the emitted tail. The harness never
/// writes the Get fields or the emitted list itself.
#[allow(clippy::type_complexity)]
fn run_production_get_path(
    target: &std::cell::RefCell<adapter::FakeTarget>,
    layout: p11scope_ebpf_common::LinuxLayout,
    template_base: u64,
    count: u64,
) -> (
    p11scope_ebpf_common::object_wire::ObjectStart,
    p11scope_ebpf_common::object_wire::ObjectCallWire,
) {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::object_flow::{
        adapter_attributes_entry, adapter_emit_get_attributes, adapter_tail_fill,
    };
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_GET, OBJECT_LAYOUT_ILP32, OBJECT_LAYOUT_LP64, ObjectCallWire,
    };
    let mut row = harness_row(23, OBJECT_ACTION_GET, [ARG_NONE, ARG_NONE]);
    row.template_args = [2, 3, ARG_NONE, ARG_NONE];
    let mut side = p11scope_ebpf_common::object_wire::ObjectStart {
        descriptor_index: 23,
        layout: if layout == p11scope_ebpf_common::LinuxLayout::Lp64 {
            OBJECT_LAYOUT_LP64
        } else {
            OBJECT_LAYOUT_ILP32
        },
        ..Default::default()
    };
    let mut fetch_arg = |arg: u8| match arg {
        2 => Some(template_base),
        3 => Some(count),
        _ => None,
    };
    let (reader, bytes) = adapter::readers(target);
    assert!(
        adapter_attributes_entry(
            Some(&mut side),
            23,
            Some(&row),
            layout,
            &mut fetch_arg,
            reader,
            bytes,
        ),
        "{layout:?} production Get entry accepts the vector"
    );
    // RETURNING arrival state (harness sequencing); retention arrives
    // only via the production entry store above.
    side.phase = 3;
    let mut tail = ObjectCallWire::default();
    let tailed = unsafe { adapter_tail_fill(&mut tail as *mut _, Some(&side), 23, Some(&row)) };
    assert!(tailed, "{layout:?} production Get tail fills");
    let (reader, bytes) = adapter::readers(target);
    assert!(
        unsafe {
            adapter_emit_get_attributes(
                &mut tail as *mut _,
                Some(&side),
                23,
                Some(&row),
                layout,
                adapter::rv_ok(),
                true,
                reader,
                bytes,
            )
        },
        "{layout:?} production Get emission accepts the vector"
    );
    (side, tail)
}

/// Retained Get slots pack densely (the shared protocol only appends),
/// so the retained count is the leading selected-slot prefix.
fn retained_get_prefix_count(side: &p11scope_ebpf_common::object_wire::ObjectStart) -> u8 {
    let mut count = 0;
    while count < 8 && side.slots[count as usize].kind != 0 {
        count += 1;
    }
    count
}

/// Today's production attribute transport, executed through the
/// production tail and Get emission adapters: entry leaves request
/// state zero (no inspection runs), so present pairs carry the honest
/// UNINSPECTED marking with zero cells, the Get result list is marked
/// UNINSPECTED through the full return path with zero reads, and absent
/// pairs stay all-zero. This pins the transport the G05 RED tests below
/// require E4 to replace with inspected cells.
#[test]
fn object_attributes_uninspected_marking_is_production() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::attr_list_flag;
    use p11scope_ebpf_common::object_flow::{adapter_emit_get_attributes, adapter_tail_fill};
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_ACTION_GET, OBJECT_LAYOUT_ILP32, OBJECT_LAYOUT_LP64,
        ObjectAttributeListWire, ObjectCallWire,
    };
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        // Present pair 0, absent pair 1: the entry leaves every
        // request word zero (E4 unwired).
        let mut row = harness_row(23, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        row.template_args = [2, 3, ARG_NONE, ARG_NONE];
        let mut side = ready_side(23);
        side.phase = 3;
        side.layout = if layout == LinuxLayout::Lp64 {
            OBJECT_LAYOUT_LP64
        } else {
            OBJECT_LAYOUT_ILP32
        };
        let mut tail = ObjectCallWire::default();
        let tailed = unsafe { adapter_tail_fill(&mut tail as *mut _, Some(&side), 23, Some(&row)) };
        assert!(tailed, "{layout:?} production tail fills");
        assert_eq!(tail.requested[0].flags, attr_list_flag::UNINSPECTED);
        assert_eq!(tail.requested[0].inspected, 0);
        assert!(
            tail.requested[0].cells == [ObjectAttributeListWire::default().cells[0]; 8],
            "{layout:?} present pair carries zero cells"
        );
        assert!(
            tail.requested[1] == ObjectAttributeListWire::default(),
            "{layout:?} absent pair stays all-zero"
        );
        // A Get tail marks its result list UNINSPECTED rather than
        // claiming an inspected-empty result.
        let get_row = harness_row(23, OBJECT_ACTION_GET, [ARG_NONE, ARG_NONE]);
        let mut tail = ObjectCallWire::default();
        let tailed =
            unsafe { adapter_tail_fill(&mut tail as *mut _, Some(&side), 23, Some(&get_row)) };
        assert!(tailed, "{layout:?} production Get tail fills");
        assert_eq!(tail.result_attributes.flags, attr_list_flag::UNINSPECTED);
        assert_eq!(tail.result_attributes.inspected, 0);
        assert!(
            tail.result_attributes
                == ObjectAttributeListWire {
                    flags: attr_list_flag::UNINSPECTED,
                    ..ObjectAttributeListWire::default()
                },
            "{layout:?} Get result list is marked-only"
        );
        // The production Get emission keeps the honest marking (E4
        // unwired): it establishes nothing, reads nothing, and the
        // emitted list stays marked-only rather than collapsing to an
        // inspected-empty claim.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(layout.word_bytes() as u64));
        let (reader, bytes) = adapter::readers(&target);
        assert!(
            unsafe {
                adapter_emit_get_attributes(
                    &mut tail as *mut _,
                    Some(&side),
                    23,
                    Some(&get_row),
                    layout,
                    adapter::rv_ok(),
                    true,
                    reader,
                    bytes,
                )
            },
            "{layout:?} production Get emission accepts"
        );
        assert!(
            tail.result_attributes
                == ObjectAttributeListWire {
                    flags: attr_list_flag::UNINSPECTED,
                    ..ObjectAttributeListWire::default()
                },
            "{layout:?} emitted Get list stays marked-only"
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} unwired Get emission"));
    }
}

/// Today's production entry attribute path (E4 unwired): the shared
/// entry adapter accepts creation and Get vectors, performs zero target
/// reads and stores zero attribute state — side request lists, Get
/// fields and flags stay allocated-zero. The Get emission refuses before
/// any read unless continuity joined, and keeps the UNINSPECTED marking
/// on return values outside the Get acceptance set. E4 replaces the
/// zero-store behavior with inspected retention; the refusal gates stay.
#[test]
fn object_attributes_unwired_entry_stores_nothing() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::attr_list_flag;
    use p11scope_ebpf_common::object_flow::{
        adapter_attributes_entry, adapter_emit_get_attributes, adapter_tail_fill,
    };
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_ACTION_GET, OBJECT_ACTION_SET, ObjectAttributeListWire,
        ObjectAttributeSlot, ObjectCallWire,
    };
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // Creation vector through the production entry adapter: accepted,
        // zero reads, zero stores.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&target, 0x40000, 0x50000, w);
        let (side, tail) = run_production_request_path(
            &target,
            layout,
            OBJECT_ACTION_CREATE,
            [(0x40000, 8), (0, 0)],
            [2, 3, ARG_NONE, ARG_NONE],
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} unwired entry"));
        assert!(
            side.requested == [ObjectAttributeListWire::default(); 2],
            "{layout:?} unwired entry stores no request state"
        );
        assert_eq!(
            side.flags, 0,
            "{layout:?} unwired entry contributes no flags"
        );
        assert_eq!(
            tail.requested[0].flags,
            attr_list_flag::UNINSPECTED,
            "{layout:?} unwired entry still emits the honest marking"
        );
        // Set authorizes no template: the adapter accepts the row and
        // touches nothing (its pair ordinals are all absent).
        let set_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        let (set_side, _) = run_production_request_path(
            &set_target,
            layout,
            OBJECT_ACTION_SET,
            [(0x40000, 8), (0, 0)],
            [ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE],
        );
        adapter::assert_no_target_reads(&set_target, &format!("{layout:?} Set entry"));
        assert!(
            set_side.requested == [ObjectAttributeListWire::default(); 2],
            "{layout:?} Set entry stores no request state"
        );
        // Get retention through the production entry adapter: accepted,
        // zero reads, zero retained fields.
        let get_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&get_target, 0x40000, 0x50000, w);
        let (get_side, get_tail) = run_production_get_path(&get_target, layout, 0x40000, 8);
        adapter::assert_no_target_reads(&get_target, &format!("{layout:?} unwired Get path"));
        assert_eq!(get_side.get_template_base, 0);
        assert_eq!(get_side.inspected_header_end, 0);
        assert_eq!(get_side.get_inspected, 0);
        assert!(
            get_side.slots == [ObjectAttributeSlot::default(); 8],
            "{layout:?} unwired Get entry retains no slots"
        );
        assert_eq!(
            get_tail.result_attributes.flags,
            attr_list_flag::UNINSPECTED,
            "{layout:?} unwired Get path emits the honest marking"
        );
        // The Get emission refuses before any read unless continuity
        // joined, and keeps the marking on refused return values.
        let get_row = harness_row(23, OBJECT_ACTION_GET, [ARG_NONE, ARG_NONE]);
        let mut refused_tail = ObjectCallWire::default();
        let mut refused_side = get_side;
        refused_side.phase = 3;
        let refused_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        let (reader, bytes) = adapter::readers(&refused_target);
        assert!(
            !unsafe {
                adapter_emit_get_attributes(
                    &mut refused_tail as *mut _,
                    Some(&refused_side),
                    23,
                    Some(&get_row),
                    layout,
                    adapter::rv_ok(),
                    false,
                    reader,
                    bytes,
                )
            },
            "{layout:?} refused continuity refuses Get emission"
        );
        adapter::assert_no_target_reads(
            &refused_target,
            &format!("{layout:?} refused Get emission"),
        );
        let bad_rv_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        let mut bad_rv_tail = ObjectCallWire::default();
        assert!(
            unsafe {
                adapter_tail_fill(
                    &mut bad_rv_tail as *mut _,
                    Some(&refused_side),
                    23,
                    Some(&get_row),
                )
            },
            "{layout:?} production Get tail fills"
        );
        let (reader, bytes) = adapter::readers(&bad_rv_target);
        assert!(
            unsafe {
                adapter_emit_get_attributes(
                    &mut bad_rv_tail as *mut _,
                    Some(&refused_side),
                    23,
                    Some(&get_row),
                    layout,
                    5,
                    true,
                    reader,
                    bytes,
                )
            },
            "{layout:?} refused RV keeps the Get list without failing emission"
        );
        assert_eq!(
            bad_rv_tail.result_attributes.flags,
            attr_list_flag::UNINSPECTED,
            "{layout:?} refused RV keeps the UNINSPECTED marking"
        );
        adapter::assert_no_target_reads(&bad_rv_target, &format!("{layout:?} refused-RV Get"));
        // Non-Get families leave the result list zero through the Get
        // emission (their result list stays absent, never marked).
        let create_row = harness_row(23, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        let plain_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        let mut plain_tail = ObjectCallWire::default();
        assert!(
            unsafe {
                adapter_tail_fill(
                    &mut plain_tail as *mut _,
                    Some(&refused_side),
                    23,
                    Some(&create_row),
                )
            },
            "{layout:?} production tail fills"
        );
        let (reader, bytes) = adapter::readers(&plain_target);
        assert!(
            unsafe {
                adapter_emit_get_attributes(
                    &mut plain_tail as *mut _,
                    Some(&refused_side),
                    23,
                    Some(&create_row),
                    layout,
                    adapter::rv_ok(),
                    true,
                    reader,
                    bytes,
                )
            },
            "{layout:?} non-Get emission succeeds trivially"
        );
        assert!(
            plain_tail.result_attributes == ObjectAttributeListWire::default(),
            "{layout:?} non-Get result list stays all-zero"
        );
        // Custody: the entry adapter refuses missing rows without reads.
        let custody_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        let create_row = harness_row(23, OBJECT_ACTION_CREATE, [5, ARG_NONE]);
        let mut fetch_arg = |_: u8| None;
        let (reader, bytes) = adapter::readers(&custody_target);
        assert!(
            !adapter_attributes_entry(
                None,
                23,
                Some(&create_row),
                layout,
                &mut fetch_arg,
                reader,
                bytes
            ),
            "{layout:?} missing side refuses entry"
        );
        let (reader, bytes) = adapter::readers(&custody_target);
        assert!(
            !adapter_attributes_entry(
                Some(&mut refused_side),
                23,
                None,
                layout,
                &mut fetch_arg,
                reader,
                bytes,
            ),
            "{layout:?} missing row refuses entry"
        );
        adapter::assert_no_target_reads(&custody_target, &format!("{layout:?} entry custody"));
    }
}

/// G05/E4 BPF delegation: the entry and Get emission wrappers bind
/// BPF-local state and call the shared adapters the suite executes.
/// Comment-proof (prose stripped before counting): comments or strings
/// naming the adapters cannot satisfy this pin.
#[test]
fn object_attributes_bpf_wrappers_delegate_to_shared_adapters() {
    pin_attribute_wrappers_delegate_to_shared_adapters();
}

/// G05/E4: the production attribute path captures all six attribute
/// fields, not UNINSPECTED-only transport. Creation-request and
/// GetAttributeValue vectors on LP64/ia32 must yield nonempty finite
/// cells for class, key type, token, value length, modulus bits and all
/// three curves, with distinct pair templates and no promotion of
/// requests to established results. Both halves drive the PRODUCTION
/// adapters the BPF programs call and assert on production side state
/// plus the EMITTED wire lists. RED while E4 is unwired (zero cells vs
/// the oracle's VALUE cells, UNINSPECTED transport); a budgeted E4 flips
/// these tests with zero test changes.
#[test]
#[ignore = "RED: H7-E4 budgeted attribute capture pending"]
fn object_attributes_real_adapter_six_fields() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::{
        GetEntryState, attr_kind, attr_list_flag, attr_status, capture_get_entry,
        capture_get_return, inspect_request_template,
    };
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_ACTION_PAIR, ObjectAttributeListWire,
    };
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // Creation request: the oracle proves the vectors valid (with
        // independent literal expectations) on its own target, then the
        // PRODUCTION entry adapter — the same shared function the BPF
        // entry calls — runs on an identically programmed target and must
        // store the oracle wire cell for cell while reading only what it
        // reads. The harness never writes the side pair itself.
        let oracle_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&oracle_target, 0x40000, 0x50000, w);
        let (reader, bytes) = adapter::readers(&oracle_target);
        let expected = inspect_request_template(0x40000, 8, None, layout, reader, bytes);
        assert_eq!(expected.inspected, 8, "{layout:?} oracle inspects eight");
        assert_eq!(
            expected.flags & attr_list_flag::PRESENT,
            attr_list_flag::PRESENT
        );
        let kinds: Vec<u8> = expected.cells.iter().map(|cell| cell.kind).collect();
        assert_eq!(
            kinds,
            [
                attr_kind::CLASS,
                attr_kind::KEY_TYPE,
                attr_kind::TOKEN,
                attr_kind::VALUE_LEN,
                attr_kind::MODULUS_BITS,
                attr_kind::EC_PARAMS,
                attr_kind::EC_PARAMS,
                attr_kind::EC_PARAMS,
            ],
            "{layout:?} oracle classifies all six fields"
        );
        for (i, cell) in expected.cells.iter().enumerate() {
            assert_eq!(
                cell.status,
                attr_status::VALUE,
                "{layout:?} oracle cell {i} is VALUE"
            );
        }
        assert_eq!(
            expected
                .cells
                .iter()
                .map(|cell| cell.value)
                .collect::<Vec<u16>>(),
            [3, 0x1f, 1, 32, 2048, 1, 2, 3],
            "{layout:?} oracle values are the finite codes"
        );
        let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&prod_target, 0x40000, 0x50000, w);
        let (prod_side, prod_tail) = run_production_request_path(
            &prod_target,
            layout,
            OBJECT_ACTION_CREATE,
            [(0x40000, 8), (0, 0)],
            [2, 3, ARG_NONE, ARG_NONE],
        );
        assert_reads_subset(
            &prod_target,
            &oracle_target,
            &format!("{layout:?} creation-request inspection"),
        );
        assert!(
            prod_side.requested[0].cells == expected.to_wire().cells,
            "{layout:?} the production entry path must capture the six fields, not UNINSPECTED"
        );
        assert_eq!(
            prod_side.requested[0].inspected, expected.inspected,
            "{layout:?} the production entry path must report its inspection"
        );
        assert!(
            prod_side.requested[1] == ObjectAttributeListWire::default(),
            "{layout:?} the absent pair stays all-zero in production side state"
        );
        // Production transport: the stored list must EMIT as the oracle
        // wire through the production tail — UNINSPECTED stays RED at the
        // flags until E4 wires inspected emission.
        assert!(
            prod_tail.requested[0] == expected.to_wire(),
            "{layout:?} production tail must emit the inspected request list, not UNINSPECTED"
        );
        assert!(
            prod_tail.requested[1] == ObjectAttributeListWire::default(),
            "{layout:?} absent pair stays all-zero"
        );
        // GetAttributeValue: the production entry retains headers into
        // production side state and the production return emission
        // establishes the same six fields on the EMITTED Get wire list.
        let oracle_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&oracle_target, 0x40000, 0x50000, w);
        let mut oracle_state = GetEntryState::default();
        let (reader, _) = adapter::readers(&oracle_target);
        let oracle_entry = capture_get_entry(0x40000, 8, layout, &mut oracle_state, reader);
        assert_eq!(
            oracle_entry.inspected, 8,
            "{layout:?} Get oracle entry inspects eight"
        );
        assert_eq!(
            oracle_entry.slot_count, 8,
            "{layout:?} Get oracle entry retains eight"
        );
        let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&prod_target, 0x40000, 0x50000, w);
        let (prod_side, prod_tail) = run_production_get_path(&prod_target, layout, 0x40000, 8);
        assert_eq!(
            prod_side.get_template_base, oracle_state.template_base,
            "{layout:?} the production Get entry must retain the template base"
        );
        assert_eq!(
            prod_side.inspected_header_end, oracle_state.header_end,
            "{layout:?} the production Get entry must retain the header end"
        );
        assert_eq!(
            prod_side.get_inspected, oracle_state.inspected,
            "{layout:?} the production Get entry must report its inspection"
        );
        assert_eq!(
            retained_get_prefix_count(&prod_side),
            oracle_state.slot_count,
            "{layout:?} the production Get entry must retain eight headers"
        );
        for k in 0..8 {
            assert_eq!(
                prod_side.slots[k].value_ptr, oracle_state.slots[k].value_ptr,
                "{layout:?} the production Get entry must retain slot {k} pointer"
            );
            assert_eq!(
                prod_side.slots[k].entry_capacity, oracle_state.slots[k].entry_capacity,
                "{layout:?} the production Get entry must retain slot {k} capacity"
            );
            assert_eq!(
                prod_side.slots[k].kind, oracle_state.slots[k].kind,
                "{layout:?} the production Get entry must retain slot {k} kind"
            );
            assert_eq!(
                prod_side.slots[k].slot_index, oracle_state.slots[k].slot_index,
                "{layout:?} the production Get entry must retain slot {k} index"
            );
        }
        let (reader, bytes) = adapter::readers(&oracle_target);
        let expected = capture_get_return(
            &oracle_state,
            adapter::rv_ok(),
            adapter::owner_ready_authority(),
            layout,
            reader,
            bytes,
        );
        assert_eq!(expected.inspected, 8);
        for (i, cell) in expected.cells.iter().enumerate() {
            assert_eq!(
                cell.status,
                attr_status::VALUE,
                "{layout:?} Get oracle cell {i} is VALUE"
            );
        }
        assert_reads_subset(
            &prod_target,
            &oracle_target,
            &format!("{layout:?} GetAttributeValue inspection"),
        );
        // The EMITTED Get wire list (cells plus flags) must equal the
        // oracle wire: seam-outcome comparisons alone cannot observe Get
        // transport, so this assert executes the production return-side
        // emission. RED today (UNINSPECTED emitted vs VALUE expected).
        assert!(
            prod_tail.result_attributes == expected.to_wire(),
            "{layout:?} production Get emission must establish the six fields, not UNINSPECTED"
        );
        // Pair separation: a second template keeps its own cells while
        // the peer's headers (not values) are re-read for alias checks.
        // The oracle proves the shape; the PRODUCTION entry adapter must
        // then store both pairs (pair one with pair zero as its alias
        // peer) and emit both as their oracle wires.
        let oracle_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&oracle_target, 0x40000, 0x50000, w);
        program_attr_slot(&oracle_target, 0x60000, 0, w, 0x0000, 0x70000, w);
        oracle_target.borrow_mut().set_word(0x70000, 2);
        let (reader, bytes) = adapter::readers(&oracle_target);
        let expected_pair0 = inspect_request_template(0x40000, 8, None, layout, reader, bytes);
        let before = oracle_target.borrow().log().len();
        let (reader, bytes) = adapter::readers(&oracle_target);
        let pair = inspect_request_template(0x60000, 1, Some((0x40000, 8)), layout, reader, bytes);
        assert_eq!(pair.cells[0].kind, attr_kind::CLASS);
        assert_eq!(pair.cells[0].status, attr_status::VALUE);
        assert_eq!(pair.cells[0].value, 2);
        assert!(
            oracle_target.borrow().log()[before..]
                .iter()
                .any(|(_, addr, _)| *addr == 0x40000),
            "{layout:?} pair inspection re-reads peer headers"
        );
        assert_eq!(
            oracle_target.borrow().log()[before..]
                .iter()
                .filter(|(_, addr, _)| *addr == 0x50000)
                .count(),
            0,
            "{layout:?} pair inspection reads no peer value"
        );
        let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&prod_target, 0x40000, 0x50000, w);
        program_attr_slot(&prod_target, 0x60000, 0, w, 0x0000, 0x70000, w);
        prod_target.borrow_mut().set_word(0x70000, 2);
        let (prod_side, prod_tail) = run_production_request_path(
            &prod_target,
            layout,
            OBJECT_ACTION_PAIR,
            [(0x40000, 8), (0x60000, 1)],
            [2, 3, 4, 5],
        );
        assert_reads_subset(
            &prod_target,
            &oracle_target,
            &format!("{layout:?} pair inspection"),
        );
        assert!(
            prod_side.requested[0] == expected_pair0.to_wire(),
            "{layout:?} the production entry path must capture pair zero"
        );
        assert!(
            prod_side.requested[1] == pair.to_wire(),
            "{layout:?} the production entry path must capture pair one with its peer"
        );
        assert!(
            prod_tail.requested[0] == expected_pair0.to_wire(),
            "{layout:?} production tail must emit pair zero"
        );
        assert!(
            prod_tail.requested[1] == pair.to_wire(),
            "{layout:?} production tail must emit pair one"
        );
        // No promotion: a fresh Get call without entry state establishes
        // nothing, however valid the creation request was.
        let fresh = GetEntryState::default();
        let (reader, bytes) = adapter::readers(&oracle_target);
        let unestablished = capture_get_return(
            &fresh,
            adapter::rv_ok(),
            adapter::owner_ready_authority(),
            layout,
            reader,
            bytes,
        );
        assert_eq!(unestablished.inspected, 0);
        for (i, cell) in unestablished.cells.iter().enumerate() {
            assert_eq!(
                (cell.kind, cell.status, cell.value),
                (0, 0, 0),
                "{layout:?} fresh Get cell {i} stays zero"
            );
        }
    }
}

/// G05/E4: the production attribute path refuses before unsafe reads.
/// Unknown and excluded selectors authorize no pointer/length reads;
/// rejected cells carry finite status while usable disjoint neighbors
/// survive; SetAttributeValue authorizes zero template reads under the
/// approved policy. Contamination vectors are representable on their
/// layout (a 64-bit-only vector cannot arrive through a four-byte read).
/// Both layers drive the PRODUCTION entry adapter the BPF entry calls:
/// the stored side pair plus the emitted wire list. RED while E4 is
/// unwired; a budgeted E4 flips this test with zero test changes.
#[test]
#[ignore = "RED: H7-E4 budgeted attribute capture pending"]
fn object_attributes_refuse_before_unsafe_read() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::{
        DeriveEntry, attr_kind, attr_status, authorize_entry_templates, inspect_request_template,
    };
    use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;
    let set_fn: u32 = pkcs11_module::FUNCTION_NAMES
        .iter()
        .position(|name| *name == "C_SetAttributeValue")
        .expect("C_SetAttributeValue exists") as u32;
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // The fixture enforces target width: high bits programmed on a
        // four-byte target never reach the reader.
        if layout == LinuxLayout::Ilp32 {
            let width = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            width.borrow_mut().set_word(0x90000, 0x1_0000_0021);
            assert_eq!(width.borrow_mut().read_word(0x90000), Ok(0x21));
        }
        // Unknown and excluded selectors: no pointer/length reads, the
        // secret sentinel behind them unread, all-zero cells. The
        // full-width vector is LP64-only; ia32 uses the representable
        // high-bit refusal.
        let contamination = if layout == LinuxLayout::Lp64 {
            0x1_0000_0000u64
        } else {
            0x8000_0000u64
        };
        for (name, selector) in [
            ("unknown selector", 0xdead_beefu64),
            ("excluded CKA_ID", 0x0102u64),
            ("full-width contamination", contamination),
        ] {
            let oracle_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            program_attr_slot(&oracle_target, 0x40000, 0, w, selector, 0x50000, w);
            oracle_target.borrow_mut().set_word(0x50000, 0x5ec4e7);
            let slot = 0x40000;
            let (reader, bytes) = adapter::readers(&oracle_target);
            let expected = inspect_request_template(0x40000, 1, None, layout, reader, bytes);
            assert_eq!(
                (
                    expected.cells[0].kind,
                    expected.cells[0].status,
                    expected.cells[0].value
                ),
                (0, 0, 0),
                "{layout:?} {name} leaves an all-zero cell"
            );
            assert_eq!(
                oracle_target.borrow().reads_of(slot + w),
                0,
                "{layout:?} {name} reads no pointer field"
            );
            assert_eq!(
                oracle_target.borrow().reads_of(slot + 2 * w),
                0,
                "{layout:?} {name} reads no length field"
            );
            assert_eq!(
                oracle_target.borrow().reads_of(0x50000),
                0,
                "{layout:?} {name} reads no secret value"
            );
            // The PRODUCTION entry adapter runs on the identically
            // programmed target: its stored cells must agree with the
            // silent oracle (and keep agreeing once E4 wires it), while
            // the stored list and the emitted wire must carry the
            // inspected refusal (PRESENT with silent cells), not the
            // UNINSPECTED marking.
            let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            program_attr_slot(&prod_target, 0x40000, 0, w, selector, 0x50000, w);
            prod_target.borrow_mut().set_word(0x50000, 0x5ec4e7);
            let (prod_side, prod_tail) = run_production_request_path(
                &prod_target,
                layout,
                OBJECT_ACTION_CREATE,
                [(0x40000, 1), (0, 0)],
                [2, 3, ARG_NONE, ARG_NONE],
            );
            assert_reads_subset(
                &prod_target,
                &oracle_target,
                &format!("{layout:?} {name} inspection"),
            );
            assert!(
                prod_side.requested[0].cells == expected.to_wire().cells,
                "{layout:?} {name}: the production path stays silent"
            );
            assert!(
                prod_side.requested[0] == expected.to_wire(),
                "{layout:?} {name}: production entry stores the inspected refusal"
            );
            assert!(
                prod_tail.requested[0] == expected.to_wire(),
                "{layout:?} {name}: production tail emits the inspected refusal"
            );
        }
        // A rejected cell carries finite status while its usable
        // disjoint neighbor survives as VALUE. The production path must
        // match the oracle on both.
        let oracle_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_attr_slot(&oracle_target, 0x40000, 0, w, 0x0001, 0x50000, 2);
        oracle_target.borrow_mut().set_bytes(0x50000, &[1, 0]);
        program_attr_slot(&oracle_target, 0x40000, 1, w, 0x0000, 0x50010, w);
        oracle_target.borrow_mut().set_word(0x50010, 4);
        let (reader, bytes) = adapter::readers(&oracle_target);
        let expected = inspect_request_template(0x40000, 2, None, layout, reader, bytes);
        assert_eq!(expected.cells[0].kind, attr_kind::TOKEN);
        assert_eq!(expected.cells[0].status, attr_status::INVALID_LENGTH);
        assert_eq!(expected.cells[1].status, attr_status::VALUE);
        assert_eq!(expected.cells[1].value, 4);
        let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_attr_slot(&prod_target, 0x40000, 0, w, 0x0001, 0x50000, 2);
        prod_target.borrow_mut().set_bytes(0x50000, &[1, 0]);
        program_attr_slot(&prod_target, 0x40000, 1, w, 0x0000, 0x50010, w);
        prod_target.borrow_mut().set_word(0x50010, 4);
        let (prod_side, prod_tail) = run_production_request_path(
            &prod_target,
            layout,
            OBJECT_ACTION_CREATE,
            [(0x40000, 2), (0, 0)],
            [2, 3, ARG_NONE, ARG_NONE],
        );
        assert_reads_subset(
            &prod_target,
            &oracle_target,
            &format!("{layout:?} neighbor inspection"),
        );
        assert!(
            prod_side.requested[0].cells[1] == expected.cells[1].to_wire(),
            "{layout:?} the production path must keep the usable neighbor"
        );
        assert!(
            prod_side.requested[0].cells[0] == expected.cells[0].to_wire(),
            "{layout:?} the production path must carry the finite rejection"
        );
        assert!(
            prod_tail.requested[0] == expected.to_wire(),
            "{layout:?} production tail emits neighbor and rejection"
        );
        // SetAttributeValue is an invalidation/control call: zero
        // template reads under the approved policy.
        let templates =
            authorize_entry_templates(set_fn, [(0x40000, 2), (0, 0)], DeriveEntry::Unavailable);
        assert_eq!(
            templates,
            [None, None],
            "{layout:?} Set authorizes no template"
        );
    }
}
