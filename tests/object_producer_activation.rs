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
