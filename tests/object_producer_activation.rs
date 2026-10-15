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
    let source = bpf_source();
    // The outlined return fill reads the second retained result pointer
    // (pair second slot) instead of trusting slot-0 alone.
    let fill = source_between(
        &source,
        "fn object_fill_return(",
        "fn owned_start_discard(key: &StartKey) {",
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
    assert!(
        source.contains("PROTOCOL_UNAVAILABLE"),
        "Find result cell must use the constant unavailable status"
    );
    // The array base word must never be stored as an observed handle.
    let fill = source_between(
        &source,
        "fn object_fill_return(",
        "fn owned_start_discard(key: &StartKey) {",
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
    let source = bpf_source();
    assert!(
        source.contains("UNINSPECTED"),
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
    // The outlined Derive gate wires the full S1 match; a bare
    // entry-nonzero check no longer authorizes the result read.
    let fill = source_between(
        &source,
        "fn object_fill_return(",
        "fn owned_start_discard(key: &StartKey) {",
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

/// H7-E1 return-emission mirror. Replicates the `p11_return_impl` object
/// arm step order (reserve → fills → continuity → retire → submit) and
/// calls the REAL production protocol (`capture_return_handles`,
/// `capture_find_return`, `instance::stamp_joinable`) with instrumented
/// readers. RED state: authority ignores continuity exactly like the
/// current root, so refused stamps still read and emit. The E1 fix moves
/// the continuity fill plus the join gate ahead of the fills in both the
/// root and this mirror; the order pins below bind them line for line.
struct EmissionOutcome {
    tail_emitted: bool,
    fault_required: bool,
    retired: bool,
    handles: p11scope_ebpf_common::object_capture::ReturnHandlesVerdict,
    words: [u64; 2],
    find: p11scope_ebpf_common::object_capture::FindVerdict,
    find_words: [u64; 8],
}

#[allow(clippy::too_many_arguments)]
fn run_emission_mirror(
    target: &std::cell::RefCell<adapter::FakeTarget>,
    layout: p11scope_ebpf_common::LinuxLayout,
    present: [bool; 2],
    authorized: [bool; 2],
    result_ptrs: [u64; 2],
    rv: u64,
    entry_stamp: p11scope_ebpf_common::InstanceStamp,
    ret_stamp: p11scope_ebpf_common::InstanceStamp,
    find: Option<(u64, u64, u64)>,
) -> EmissionOutcome {
    use p11scope_ebpf_common::instance;
    use p11scope_ebpf_common::object_capture::{capture_find_return, capture_return_handles};
    // Step 1 (mirror of the `object_fill_return` call site): reads run
    // under owner/phase authority only. Continuity is not consulted.
    let authority = adapter::owner_ready_authority();
    let (reader, _) = adapter::readers(target);
    let (handles, words) = capture_return_handles(
        present,
        authorized,
        result_ptrs,
        rv,
        authority,
        layout,
        reader,
    );
    // Step 2 (mirror of the `object_emit_find` call site): same
    // continuity-blind authority.
    let (find_verdict, find_words) = match find {
        Some((array, capacity, count_ptr)) => {
            let (reader, _) = adapter::readers(target);
            capture_find_return(array, capacity, count_ptr, rv, authority, layout, reader)
        }
        None => (
            p11scope_ebpf_common::object_capture::FindVerdict {
                statuses: [0; 8],
                len: 0,
                valid: false,
                flags: 0,
                result_cell: (7, 0),
            },
            [0u64; 8],
        ),
    };
    // Step 3 (mirror of the `p11_instance_return` site): continuity is
    // filled into the reserved record AFTER the reads and never gates
    // them; the tail emits whenever the fills ran.
    let _joined = instance::stamp_joinable(entry_stamp, ret_stamp);
    EmissionOutcome {
        tail_emitted: true,
        fault_required: false,
        retired: true,
        handles,
        words,
        find: find_verdict,
        find_words,
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
        .find("stamp_joinable")
        .expect("return must gate object reads on the stamp join");
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
}

/// G02/E1: refused continuity performs zero result-handle reads. Healthy
/// twin reads the exact expected result once and retains the joined
/// stamps; every refusal (absent entry, straddled epoch/global/fault/
/// file-slot, missing VALID, each blocking flag) reads nothing, emits no
/// tail, faults visibly and retires through E2 without a success claim.
#[test]
#[ignore = "RED: H7-E1 continuity gate pending"]
fn object_return_continuity_refuses_before_reads() {
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::handle_status;
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // Healthy twin: one present result, CKR_OK, joined stamps.
        let target = adapter::FakeTarget::new(w);
        let target = std::cell::RefCell::new(target);
        target.borrow_mut().set_word(0x10000, 0x42);
        let (entry, ret) = clean_stamps();
        let outcome = run_emission_mirror(
            &target,
            layout,
            [true, false],
            [true, false],
            [0x10000, 0],
            adapter::rv_ok(),
            entry,
            ret,
            None,
        );
        assert_eq!(
            target.borrow().log(),
            &[(adapter::READ_WORD, 0x10000, w)],
            "{layout:?} healthy twin must read the exact result once"
        );
        assert_eq!(
            outcome.handles.statuses,
            [handle_status::VALUE, handle_status::ABSENT]
        );
        assert_eq!(outcome.words, [0x42, 0]);
        assert!(outcome.tail_emitted, "healthy twin emits its tail");
        assert!(!outcome.fault_required, "healthy twin faults nothing");
        assert!(
            p11scope_ebpf_common::instance::stamp_joinable(entry, ret),
            "healthy twin retains the joined stamps"
        );
        // Failed reads are distinct from refused reads: a joined call
        // whose result word is unreadable attempts the read once and
        // carries UNREADABLE, never VALUE and never zero-read silence.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        target.borrow_mut().set_fail(0x10000);
        let (entry, ret) = clean_stamps();
        let outcome = run_emission_mirror(
            &target,
            layout,
            [true, false],
            [true, false],
            [0x10000, 0],
            adapter::rv_ok(),
            entry,
            ret,
            None,
        );
        assert_eq!(
            target.borrow().log(),
            &[(adapter::READ_WORD, 0x10000, w)],
            "{layout:?} failed result word is attempted once"
        );
        assert_eq!(
            outcome.handles.statuses,
            [handle_status::UNREADABLE, handle_status::ABSENT]
        );
        assert_eq!(outcome.words, [0, 0]);
        // Every refusal: zero reads, no tail, visible fault, retired.
        for (name, entry, ret) in refused_stamp_pairs() {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            target.borrow_mut().set_word(0x10000, 0x42);
            let outcome = run_emission_mirror(
                &target,
                layout,
                [true, false],
                [true, false],
                [0x10000, 0],
                adapter::rv_ok(),
                entry,
                ret,
                None,
            );
            adapter::assert_no_target_reads(&target, &format!("{layout:?} result reads on {name}"));
            assert!(
                !outcome.tail_emitted,
                "{layout:?} {name}: refused continuity emits no object tail"
            );
            assert!(
                outcome.fault_required,
                "{layout:?} {name}: refused continuity faults visibly"
            );
            assert!(outcome.retired, "{layout:?} {name}: refused arm retires");
        }
    }
    pin_continuity_gate_precedes_fills();
}

/// G02/E1: refused continuity performs zero Find reads: no count read,
/// no element reads, no reread. Healthy twin streams the exact
/// count/element/reread sequence; every refusal reads nothing and emits
/// no Find section.
#[test]
#[ignore = "RED: H7-E1 continuity gate pending"]
fn object_find_continuity_refuses_before_reads() {
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::handle_status;
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let program_find = |target: &std::cell::RefCell<adapter::FakeTarget>| {
            let mut borrowed = target.borrow_mut();
            borrowed.set_word(0x21000, 2);
            borrowed.set_word(0x20000, 0x51);
            borrowed.set_word(0x20000 + w, 0x52);
        };
        // Healthy twin: count read, two elements, count reread.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_find(&target);
        let (entry, ret) = clean_stamps();
        let outcome = run_emission_mirror(
            &target,
            layout,
            [false, false],
            [false, false],
            [0x20000, 0],
            adapter::rv_ok(),
            entry,
            ret,
            Some((0x20000, 8, 0x21000)),
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
        assert!(outcome.find.valid, "healthy Find twin validates");
        assert_eq!(outcome.find.len, 2);
        assert_eq!(
            outcome.find.statuses[..2],
            [handle_status::VALUE, handle_status::VALUE]
        );
        assert_eq!(outcome.find_words[..2], [0x51, 0x52]);
        assert!(outcome.tail_emitted, "healthy Find twin emits its tail");
        // Every refusal: the count word itself is unread.
        for (name, entry, ret) in refused_stamp_pairs() {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            program_find(&target);
            let outcome = run_emission_mirror(
                &target,
                layout,
                [false, false],
                [false, false],
                [0x20000, 0],
                adapter::rv_ok(),
                entry,
                ret,
                Some((0x20000, 8, 0x21000)),
            );
            adapter::assert_no_target_reads(&target, &format!("{layout:?} Find reads on {name}"));
            assert!(
                !outcome.find.valid,
                "{layout:?} {name}: refused continuity validates no Find batch"
            );
            assert!(
                !outcome.tail_emitted,
                "{layout:?} {name}: refused continuity emits no object tail"
            );
            assert!(
                outcome.fault_required,
                "{layout:?} {name}: refused continuity faults visibly"
            );
        }
    }
    pin_continuity_gate_precedes_fills();
}

/// H7-E4 BPF attribute-path mirror. The CURRENT BPF adapters inspect no
/// template (entry) and run no Get protocol (return): present pairs stay
/// zero and `object_tail_fill` marks them UNINSPECTED (see
/// `object_producer_uninspected_lists_carry_marker`, which pins that
/// marking). This mirror reproduces that observable wire behavior; the
/// tests below run the REAL shared protocol on the same vectors as the
/// oracle and require the adapter path to match it cell for cell. RED
/// while the adapters emit UNINSPECTED-only transport.
fn run_bpf_attributes_mirror() -> p11scope_ebpf_common::object_capture::AttributeListOutcome {
    use p11scope_ebpf_common::object_capture::{AttrCell, AttributeListOutcome, attr_list_flag};
    AttributeListOutcome {
        cells: [AttrCell {
            kind: 0,
            status: 0,
            value: 0,
        }; 8],
        inspected: 0,
        flags: attr_list_flag::UNINSPECTED,
        object_flags: 0,
    }
}

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

/// G05/E4: the real adapter path captures all six attribute fields, not
/// UNINSPECTED-only transport. Creation-request and GetAttributeValue
/// vectors on LP64/ia32 must yield nonempty finite cells for class, key
/// type, token, value length, modulus bits and all three curves, with
/// distinct pair templates and no promotion of requests to established
/// results.
#[test]
#[ignore = "RED: H7-E4 budgeted attribute capture pending"]
fn object_attributes_real_adapter_six_fields() {
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::{
        GetEntryState, attr_kind, attr_list_flag, attr_status, capture_get_entry,
        capture_get_return, inspect_request_template,
    };
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // Creation request: the oracle proves the vectors valid, then the
        // adapter path must match the oracle cell for cell.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&target, 0x40000, 0x50000, w);
        let (reader, bytes) = adapter::readers(&target);
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
        let actual = run_bpf_attributes_mirror();
        assert_eq!(
            actual.cells, expected.cells,
            "{layout:?} the entry adapter path must capture the six fields, not UNINSPECTED"
        );
        assert_eq!(
            actual.inspected, expected.inspected,
            "{layout:?} the entry adapter path must report its inspection"
        );
        // GetAttributeValue return: entry retains headers, return
        // establishes the same six fields.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&target, 0x40000, 0x50000, w);
        let mut state = GetEntryState::default();
        let (reader, _) = adapter::readers(&target);
        let entry = capture_get_entry(0x40000, 8, layout, &mut state, reader);
        assert_eq!(entry.inspected, 8, "{layout:?} Get entry inspects eight");
        assert_eq!(entry.slot_count, 8, "{layout:?} Get entry retains eight");
        let (reader, bytes) = adapter::readers(&target);
        let expected = capture_get_return(
            &state,
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
        let actual = run_bpf_attributes_mirror();
        assert_eq!(
            actual.cells, expected.cells,
            "{layout:?} the Get return adapter path must establish the six fields"
        );
        // Pair separation: a second template keeps its own cells while
        // the peer's headers (not values) are re-read for alias checks.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_six_field_template(&target, 0x40000, 0x50000, w);
        program_attr_slot(&target, 0x60000, 0, w, 0x0000, 0x70000, w);
        target.borrow_mut().set_word(0x70000, 2);
        let before = target.borrow().log().len();
        let (reader, bytes) = adapter::readers(&target);
        let pair = inspect_request_template(0x60000, 1, Some((0x40000, 8)), layout, reader, bytes);
        assert_eq!(pair.cells[0].kind, attr_kind::CLASS);
        assert_eq!(pair.cells[0].status, attr_status::VALUE);
        assert_eq!(pair.cells[0].value, 2);
        assert!(
            target.borrow().log()[before..]
                .iter()
                .any(|(_, addr, _)| *addr == 0x40000),
            "{layout:?} pair inspection re-reads peer headers"
        );
        assert_eq!(
            target.borrow().reads_of(0x50000),
            0,
            "{layout:?} pair inspection reads no peer value"
        );
        // No promotion: a fresh Get call without entry state establishes
        // nothing, however valid the creation request was.
        let fresh = GetEntryState::default();
        let (reader, bytes) = adapter::readers(&target);
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

/// G05/E4: the real adapter path refuses before unsafe reads. Unknown
/// and excluded selectors authorize no pointer/length reads; rejected
/// cells carry finite status while usable disjoint neighbors survive;
/// SetAttributeValue authorizes zero template reads under the approved
/// policy.
#[test]
#[ignore = "RED: H7-E4 budgeted attribute capture pending"]
fn object_attributes_refuse_before_unsafe_read() {
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_capture::{
        DeriveEntry, attr_kind, attr_status, authorize_entry_templates, inspect_request_template,
    };
    let set_fn: u32 = pkcs11_module::FUNCTION_NAMES
        .iter()
        .position(|name| *name == "C_SetAttributeValue")
        .expect("C_SetAttributeValue exists") as u32;
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // Unknown and excluded selectors: no pointer/length reads, the
        // secret sentinel behind them unread, all-zero cells.
        for (name, selector) in [
            ("unknown selector", 0xdead_beefu64),
            ("excluded CKA_ID", 0x0102u64),
            ("full-width contamination", 0x1_0000_0000u64),
        ] {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            program_attr_slot(&target, 0x40000, 0, w, selector, 0x50000, w);
            target.borrow_mut().set_word(0x50000, 0x5ec4e7);
            let slot = 0x40000;
            let (reader, bytes) = adapter::readers(&target);
            let outcome = inspect_request_template(0x40000, 1, None, layout, reader, bytes);
            assert_eq!(
                (
                    outcome.cells[0].kind,
                    outcome.cells[0].status,
                    outcome.cells[0].value
                ),
                (0, 0, 0),
                "{layout:?} {name} leaves an all-zero cell"
            );
            assert_eq!(
                target.borrow().reads_of(slot + w),
                0,
                "{layout:?} {name} reads no pointer field"
            );
            assert_eq!(
                target.borrow().reads_of(slot + 2 * w),
                0,
                "{layout:?} {name} reads no length field"
            );
            assert_eq!(
                target.borrow().reads_of(0x50000),
                0,
                "{layout:?} {name} reads no secret value"
            );
        }
        // A rejected cell carries finite status while its usable
        // disjoint neighbor survives as VALUE.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        program_attr_slot(&target, 0x40000, 0, w, 0x0001, 0x50000, 2);
        target.borrow_mut().set_bytes(0x50000, &[1, 0]);
        program_attr_slot(&target, 0x40000, 1, w, 0x0000, 0x50010, w);
        target.borrow_mut().set_word(0x50010, 4);
        let (reader, bytes) = adapter::readers(&target);
        let expected = inspect_request_template(0x40000, 2, None, layout, reader, bytes);
        assert_eq!(expected.cells[0].kind, attr_kind::TOKEN);
        assert_eq!(expected.cells[0].status, attr_status::INVALID_LENGTH);
        assert_eq!(expected.cells[1].status, attr_status::VALUE);
        assert_eq!(expected.cells[1].value, 4);
        let actual = run_bpf_attributes_mirror();
        assert_eq!(
            actual.cells[1], expected.cells[1],
            "{layout:?} the adapter path must keep the usable neighbor"
        );
        assert_eq!(
            actual.cells[0], expected.cells[0],
            "{layout:?} the adapter path must carry the finite rejection"
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
