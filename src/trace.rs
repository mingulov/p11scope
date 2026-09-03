//! `trace` renderer: one line per completed call, in arrival order — the
//! per-investigation counterpart to `profile`'s aggregate report
//! (`docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md`, "Trace
//! mode"). Reuses `render::param_combo_json` for parameter decoding so
//! the same privacy allowlist governs both renderers by construction,
//! not by two independently-maintained implementations, and reuses
//! `semantics::State`'s session-pseudonym machinery so a raw handle is
//! never rendered.

use crate::attach::CapturePolicy;
use crate::plan::AttachPlan;
use crate::render;
use crate::semantics::ProcessKey;
use crate::semantics::State;
use p11scope_ebpf_common::{Event, SESSION_NONE, capture, shape};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// `pid_tgid` (`bpf_get_current_pid_tgid()`) -> (pid, tid): tgid (process
/// id) in the high 32 bits, thread id in the low 32.
fn pid_tid(pid_tgid: u64) -> (u32, u32) {
    ((pid_tgid >> 32) as u32, pid_tgid as u32)
}

/// Function name(s) at a slot, from the current plan snapshot — the same
/// grouping `render::label` uses for aliased slots, joined the same way.
fn function_name(slots: &[Option<TraceSlot>], slot: u32) -> String {
    slots
        .get(slot as usize)
        .and_then(Option::as_ref)
        .map(|slot| slot.names.join("|"))
        .unwrap_or_else(|| format!("slot#{slot}"))
}

/// A small, honest name table for the two mechanism ids this capture
/// also decodes parameters for (`render::param_combo_json`'s
/// `rsa_pkcs_pss`/`gcm` shapes) — sourced from the same
/// `pkcs11-proxy-ng-types` crate the rest of this codebase already
/// depends on, not a re-derived literal. No general CKM_* id -> name
/// registry exists anywhere in this codebase or its dependencies to
/// reuse (verified: `pkcs11_proxy_ng_types::mechanism_registry` maps ids
/// to *shape* names like `"gcm"`, never to `CKM_*` display names).
/// Every other mechanism, known or vendor, renders verbatim as `0x…`,
/// same as the "unknown mechanism" case — honest rather than guessed.
/// ponytail: bounded to the two decoded shapes; add a full CKM_* name
/// table if trace readability for non-decoded, non-PSS/GCM mechanisms
/// ever becomes a real ask.
fn mechanism_name(id: u64) -> Option<&'static str> {
    match id {
        _ if id == pkcs11_proxy_ng_types::CkMechanismType::RSA_PKCS_PSS.0 => {
            Some("CKM_RSA_PKCS_PSS")
        }
        _ if id == pkcs11_proxy_ng_types::CkMechanismType::AES_GCM.0 => Some("CKM_AES_GCM"),
        _ => None,
    }
}

fn mechanism_label(id: u64) -> String {
    mechanism_name(id)
        .map(str::to_string)
        .unwrap_or_else(|| format!("0x{id:x}"))
}

/// Standard PKCS#11 hash-algorithm mechanism ids that can appear as the
/// `hashAlg` field of `CK_RSA_PKCS_PSS_PARAMS`. Fixed, standardized
/// values (OASIS PKCS#11 v3.02 `pkcs11t.h`), not vendor-specific — safe
/// to hardcode. Unrecognized ids render as `0x…`, never guessed.
fn hash_alg_name(id: u64) -> String {
    match id {
        0x0000_0220 => "SHA1".into(),
        0x0000_0255 => "SHA224".into(),
        id if id == pkcs11_proxy_ng_types::CkMechanismType::SHA256.0 => "SHA256".into(),
        id if id == pkcs11_proxy_ng_types::CkMechanismType::SHA384.0 => "SHA384".into(),
        id if id == pkcs11_proxy_ng_types::CkMechanismType::SHA512.0 => "SHA512".into(),
        _ => format!("0x{id:x}"),
    }
}

/// Standard `CKG_MGF1_*` values (OASIS PKCS#11 v3.02 `pkcs11t.h`).
fn mgf_name(id: u64) -> String {
    match id {
        0x1 => "MGF1_SHA1".into(),
        0x2 => "MGF1_SHA256".into(),
        0x3 => "MGF1_SHA384".into(),
        0x4 => "MGF1_SHA512".into(),
        0x5 => "MGF1_SHA224".into(),
        _ => format!("0x{id:x}"),
    }
}

/// Mechanism + decoded parameters, e.g. `CKM_RSA_PKCS_PSS(hash=SHA256
/// mgf=MGF1_SHA256 salt=32)`. The decode itself is `render::
/// param_combo_json` — the exact function `profile`'s JSON report calls
/// — so a shape this phase does not decode (or ever stops decoding)
/// yields no parameters here either, by construction.
fn render_mechanism(ev: &Event) -> String {
    let label = mechanism_label(ev.mechanism);
    if ev.shape == shape::NONE {
        return label;
    }
    let Some(v) = render::param_combo_json(ev.shape, ev.p0, ev.p1, ev.p2, 1) else {
        return label;
    };
    let params = match v.get("shape").and_then(|s| s.as_str()) {
        Some("rsa_pkcs_pss") => {
            format!(
                "hash={} mgf={} salt={}",
                hash_alg_name(ev.p0),
                mgf_name(ev.p1),
                ev.p2
            )
        }
        Some("gcm") => format!("iv_len={} aad_len={} tag_bits={}", ev.p0, ev.p1, ev.p2),
        _ => return label,
    };
    format!("{label}({params})")
}

fn rv_name(rv: u64) -> String {
    // Reuses proxy-ng's CKR_* name table (`CkRv`'s `Display`) rather than
    // a second one; its format is "CKR_OK (0x00000000)" — only the name
    // is wanted here, the trace line carries the outcome, not the code.
    let s = pkcs11_proxy_ng_types::CkRv(rv).to_string();
    s.split(" (").next().unwrap_or(&s).to_string()
}

fn fmt_wall_time(wall_ns: u128) -> String {
    let secs_total = (wall_ns / 1_000_000_000) as u64;
    let sub_ns = (wall_ns % 1_000_000_000) as u32;
    let secs_of_day = secs_total % 86_400;
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    format!("{h:02}:{m:02}:{s:02}.{:06}", sub_ns / 1_000)
}

/// One trace line, in the design spec's shape:
/// `HH:MM:SS.ffffff pid P tid T [sess#N] FUNCTION[ MECHANISM] → CKR_x DURATION`.
/// A pure function — no I/O, no shared state — so it is directly
/// testable: given a known `Event` and its resolved wall-clock time,
/// function name, and session pseudonym, it always renders the same line.
pub fn format_line(ev: &Event, wall_ns: u128, function: &str, session: Option<u64>) -> String {
    let (pid, tid) = pid_tid(ev.pid_tgid);
    let mut line = format!("{} pid {pid} tid {tid}", fmt_wall_time(wall_ns));
    if let Some(n) = session {
        line.push_str(&format!(" sess#{n}"));
    }
    line.push_str(&format!(" {function}"));
    if ev.capture & capture::MECHANISM_MASK == capture::MECHANISM_VALUE {
        line.push(' ');
        line.push_str(&render_mechanism(ev));
    }
    line.push_str(&format!(
        " \u{2192} {} {}",
        rv_name(ev.rv),
        render::fmt_ns(Some(ev.duration_ns))
    ));
    line
}

/// `LOST n events` when the ring buffer dropped anything — mandatory
/// whenever `n > 0`; a trace that lost events must never end silently.
/// `None` when nothing was lost, so a caller can skip printing rather
/// than testing the string for a sentinel.
pub fn lost_line(n: u64) -> Option<String> {
    (n > 0).then(|| format!("LOST {n} events"))
}

pub fn truncated_line(limit: u64) -> String {
    format!("TRUNCATED at {limit} events (--max-events)")
}

pub fn capture_line(policy: CapturePolicy) -> String {
    format!("CAPTURE privacy={}", policy.privacy_mode())
}

/// Final machine-readable evidence record for a normally stopped trace.
/// Detaching perf links does not prove already-running callbacks quiesced, so
/// this record must remain PARTIAL and must not claim a proven final drain.
pub fn evidence_line(ev: &render::Evidence, policy: CapturePolicy, truncated: bool) -> String {
    let mut value = render::versioned_evidence(ev);
    let object = value
        .as_object_mut()
        .expect("Evidence serializes as an object");
    object.insert(
        "privacy_mode".into(),
        serde_json::Value::String(policy.privacy_mode().into()),
    );
    object.insert(
        "completeness".into(),
        serde_json::Value::String("PARTIAL".into()),
    );
    object.insert("capture_aborted".into(), serde_json::Value::Null);
    object.insert("final_drain".into(), serde_json::Value::Bool(false));
    object.insert("counters_available".into(), serde_json::Value::Bool(true));
    object.insert("trace_truncated".into(), serde_json::Value::Bool(truncated));
    format!("EVIDENCE {value}")
}

#[derive(Serialize)]
struct CountEvidence {
    stats_entered: u64,
    stats_returned: u64,
    raw_calls: u64,
}

/// Final aggregate count record for trace. `raw_calls` is maintained by the
/// drain before output truncation; STATS values come from the same reports as
/// terminal evidence and are summed with saturation.
pub(crate) fn count_evidence_line(
    reports: &[crate::metrics::SlotReport],
    raw_calls: u64,
) -> String {
    let (stats_returned, stats_entered) =
        reports
            .iter()
            .fold((0u64, 0u64), |(stats_returned, stats_entered), report| {
                (
                    stats_returned.saturating_add(report.calls),
                    stats_entered.saturating_add(report.calls.saturating_add(report.in_flight)),
                )
            });
    let value = CountEvidence {
        stats_entered,
        stats_returned,
        raw_calls,
    };
    format!(
        "COUNT_EVIDENCE {}",
        serde_json::to_string(&value).expect("count evidence serializes")
    )
}

/// Turns completed events into trace lines, tracking the two bits of
/// state a pure per-line formatter cannot carry itself: the wall-clock
/// anchor (kernel timestamps are boot-relative monotonic, not epoch —
/// see `p11scope_ebpf_common::Event::ts_ns`) and the session-pseudonym
/// lookup, which `semantics::State` owns.
#[derive(Clone)]
struct TraceSlot {
    names: Vec<String>,
    semantics: p11scope_ebpf_common::SlotSemantics,
    semantic_authorized: bool,
}

fn trace_slots(plan: &AttachPlan) -> Vec<Option<TraceSlot>> {
    let mut slots = Vec::new();
    for slot in &plan.slots {
        let index = slot.index as usize;
        if index >= slots.len() {
            slots.resize_with(index + 1, || None);
        }
        slots[index] = Some(TraceSlot {
            names: slot.names.clone(),
            semantics: plan.effective_semantics(slot),
            semantic_authorized: slot.semantic_authorized,
        });
    }
    slots
}

pub struct Tracer {
    slots: Vec<Option<TraceSlot>>,
    raw_calls: u64,
    /// (first observed event's kernel monotonic ts_ns, wall-clock ns at
    /// that same moment) — every later line's wall time is this anchor
    /// plus the kernel-monotonic delta, so line-to-line spacing tracks
    /// the kernel clock exactly; only the anchor itself carries the
    /// small, constant "poll processing lag" of the first event.
    anchor: Option<(u64, u128)>,
}

impl Tracer {
    pub fn new(plan: &AttachPlan) -> Self {
        Self {
            slots: trace_slots(plan),
            raw_calls: 0,
            anchor: None,
        }
    }

    /// Replaces the minimal display metadata from the same plan snapshot that
    /// updates semantic state; no immutable plan borrow survives a live sync.
    pub fn sync_plan(&mut self, plan: &AttachPlan) {
        self.slots = trace_slots(plan);
    }

    /// Counts one well-formed event consumed by trace before truncation or
    /// semantic reduction. Fork lifecycle records are transport events, not
    /// calls, and are intentionally excluded.
    pub(crate) fn count_raw_call(&mut self, ev: &Event) {
        if matches!(ev.event_type, p11scope_ebpf_common::event_type::CALL) {
            self.raw_calls = self.raw_calls.saturating_add(1);
        }
    }

    pub(crate) fn raw_calls(&self) -> u64 {
        self.raw_calls
    }

    fn wall_ns_for(&mut self, ts_ns: u64) -> u128 {
        match self.anchor {
            Some((mono0, wall0)) => wall0 + u128::from(ts_ns.saturating_sub(mono0)),
            None => {
                let wall0 = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                self.anchor = Some((ts_ns, wall0));
                wall0
            }
        }
    }

    /// Feeds one completed event through the semantic state (session
    /// pseudonym allocation, same as `profile`) and returns its rendered
    /// trace line. The session's pseudonym is resolved *before*
    /// `observe`-ing a `C_CloseSession` event — `State::observe` retires
    /// the mapping on a successful close, and the closing call's own
    /// line must still show which session closed.
    pub fn on_event(&mut self, ev: &Event, state: &mut State) -> String {
        self.on_event_process(ev, ProcessKey::from_pid(pid_tid(ev.pid_tgid).0), state)
    }

    pub fn on_event_process(
        &mut self,
        ev: &Event,
        process: ProcessKey,
        state: &mut State,
    ) -> String {
        let slot = self
            .slots
            .get(ev.slot as usize)
            .and_then(Option::as_ref)
            .cloned();
        let semantic = slot
            .as_ref()
            .is_some_and(|slot| slot.semantics != p11scope_ebpf_common::SlotSemantics::COUNT_ONLY);
        let pre = (semantic && ev.session != SESSION_NONE)
            .then(|| state.session_pseudonym_process(process, ev.slot, ev.session))
            .flatten();
        state.observe_process(process, ev);
        let session = pre.or_else(|| {
            (semantic && ev.session != SESSION_NONE)
                .then(|| state.session_pseudonym_process(process, ev.slot, ev.session))
                .flatten()
        });
        let wall_ns = self.wall_ns_for(ev.ts_ns);
        let mut function = function_name(&self.slots, ev.slot);
        if slot.as_ref().is_some_and(|slot| !slot.semantic_authorized) {
            function.push_str(" [semantics unverified]");
        }
        let mut rendered = *ev;
        if !semantic {
            rendered.capture = 0;
        }
        format_line(&rendered, wall_ns, &function, session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::{MECH_NONE, USER_TYPE_NONE, capture, shape};

    fn base_event() -> Event {
        Event {
            ts_ns: 0,
            duration_ns: 18_000,
            pid_tgid: (12345u64 << 32) | 12401,
            cgroup_id: 0,
            session: SESSION_NONE,
            mechanism: MECH_NONE,
            rv: 0,
            p0: 0,
            p1: 0,
            p2: 0,
            slot: 0,
            user_type: USER_TYPE_NONE,
            shape: shape::NONE,
            attr_types: [0; 8],
            attr_count: 0,
            attr_total: 0,
            attr_bools: 0,
            attr_bools_seen: 0,
            ..Event::default()
        }
    }

    #[test]
    fn known_event_renders_the_documented_line_shape() {
        let mut ev = base_event();
        ev.mechanism = pkcs11_proxy_ng_types::CkMechanismType::RSA_PKCS_PSS.0;
        ev.capture = capture::MECHANISM_VALUE;
        ev.shape = shape::RSA_PKCS_PSS;
        ev.p0 = 0x0000_0250; // CKM_SHA256
        ev.p1 = 0x2; // CKG_MGF1_SHA256
        ev.p2 = 32;

        // Wall time 12:00:01.123456 UTC.
        let wall_ns = 12u128 * 3_600_000_000_000 + 1_123_456_000;
        let line = format_line(&ev, wall_ns, "C_SignInit", Some(7));

        // Duration formatting is reused verbatim from `render::fmt_ns`
        // (one decimal place at µs scale) rather than a second formatter
        // — "18.0µs", not the spec prose's illustrative "18µs".
        assert_eq!(
            line,
            "12:00:01.123456 pid 12345 tid 12401 sess#7 C_SignInit \
             CKM_RSA_PKCS_PSS(hash=SHA256 mgf=MGF1_SHA256 salt=32) \u{2192} CKR_OK 18.0\u{b5}s"
        );
    }

    #[test]
    fn vendor_mechanism_renders_as_hex() {
        let mut ev = base_event();
        ev.mechanism = 0x8000_1042;
        ev.capture = capture::MECHANISM_VALUE;
        ev.shape = shape::NONE;

        let line = format_line(&ev, 0, "C_EncryptInit", None);
        assert!(line.contains("0x80001042"), "line: {line}");
        assert!(
            !line.contains("sess#"),
            "no session pseudonym must appear when none resolved"
        );
    }

    #[test]
    fn tagged_maximum_mechanism_id_renders_as_hex() {
        let ev = Event {
            mechanism: u64::MAX,
            capture: capture::MECHANISM_VALUE,
            ..base_event()
        };

        let line = format_line(&ev, 0, "C_EncryptInit", None);
        assert!(
            line.contains(" C_EncryptInit 0xffffffffffffffff \u{2192} CKR_OK"),
            "line: {line}"
        );
    }

    #[test]
    fn known_mechanism_id_with_no_decoded_shape_still_renders_by_name_only() {
        let mut ev = base_event();
        ev.mechanism = pkcs11_proxy_ng_types::CkMechanismType::AES_GCM.0;
        ev.capture = capture::MECHANISM_VALUE;
        ev.shape = shape::NONE; // e.g. decode failed this call

        let line = format_line(&ev, 0, "C_EncryptInit", None);
        assert!(line.contains("CKM_AES_GCM"), "line: {line}");
        assert!(
            !line.contains('('),
            "no parameters rendered without a decoded shape: {line}"
        );
    }

    #[test]
    fn errored_call_shows_its_ck_rv() {
        let mut ev = base_event();
        ev.rv = 0x60; // CKR_KEY_HANDLE_INVALID
        let line = format_line(&ev, 0, "C_Sign", Some(3));
        assert!(line.contains("CKR_KEY_HANDLE_INVALID"), "line: {line}");
        assert!(!line.contains("CKR_OK"));
    }

    #[test]
    fn no_session_pseudonym_omits_the_sess_token() {
        let ev = base_event(); // session == SESSION_NONE
        let line = format_line(&ev, 0, "C_Login", None);
        assert!(!line.contains("sess#"), "line: {line}");
    }

    #[test]
    fn lost_line_is_none_when_nothing_was_lost() {
        assert_eq!(lost_line(0), None);
    }

    #[test]
    fn nonzero_loss_counter_produces_the_lost_line() {
        assert_eq!(lost_line(1), Some("LOST 1 events".to_string()));
        assert_eq!(lost_line(42), Some("LOST 42 events".to_string()));
    }

    fn slot_report(calls: u64, in_flight: u64) -> crate::metrics::SlotReport {
        crate::metrics::SlotReport {
            names: vec![],
            aliased: false,
            semantic_authorized: true,
            module: None,
            module_ambiguous: false,
            module_unresolved: false,
            calls,
            errors: 0,
            in_flight,
            total_ns: 0,
            max_ns: 0,
            buckets: [0; p11scope_ebpf_common::LATENCY_BUCKETS],
            rv_counts: Default::default(),
        }
    }

    #[test]
    fn count_evidence_line_has_exact_fields_and_derives_entered_calls() {
        let line = count_evidence_line(&[slot_report(3, 2), slot_report(4, 1)], 9);
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("COUNT_EVIDENCE ").unwrap()).unwrap();

        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["stats_entered"], 10);
        assert_eq!(value["stats_returned"], 7);
        assert_eq!(value["raw_calls"], 9);
    }

    #[test]
    fn count_evidence_line_saturates_each_aggregate() {
        let line = count_evidence_line(&[slot_report(u64::MAX, 1)], u64::MAX);
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("COUNT_EVIDENCE ").unwrap()).unwrap();

        assert_eq!(value["stats_entered"], u64::MAX);
        assert_eq!(value["stats_returned"], u64::MAX);
        assert_eq!(value["raw_calls"], u64::MAX);
    }

    fn empty_evidence() -> render::Evidence {
        render::Evidence {
            discovery: render::DiscoveryEvidence::default(),
            table_entries: 0,
            slots: 0,
            attached_probes: 0,
            attach_failures: vec![],
            aliased: vec![],
            skipped: vec![],
            semantic_unverified_slots: 0,
            in_flight_at_end: 0,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
            event_loss: 0,
            start_insert_failures: 0,
            unmatched_returns: 0,
            rv_update_failures: 0,
            cgroup_scope_failures: 0,
            semantic_capture_failures: 0,
            unregistered_mechanisms: 0,
            template_tail_failures: 0,
            process_tracking_fallbacks: 0,
            process_tracking_failures: 0,
            process_tracking_evictions: 0,
            state_reconciliations: 0,
            session_cancel_ambiguities: 0,
            session_cancel_unknown_flags: 0,
            operation_state_imports: 0,
            auth_state_ambiguities: 0,
            async_target_failures: 0,
            async_orphans: 0,
            async_duplicates: 0,
            async_evictions: 0,
            fork_state_ambiguities: 0,
            semantic_state_drops: 0,
            pending_at_end: 0,
            malformed_records: 0,
            orphan_ops: 0,
            unmatched_closes: 0,
            shape_decode_failures: 0,
            shape_decode_total_failures: 0,
            templates_truncated: false,
            attach_gap_ms: None,
            pause: "none",
            pause_attempts: 0,
            pause_confirmed: 0,
            pause_partial: 0,
            child_still_running: None,
            discovery_ring_loss: 0,
            discovery_state_failures: 0,
            discovery_read_failures: 0,
            discovery_truncated: 0,
            task_uprobe_link_losses: 0,
            loader_discovery: render::LoaderDiscovery::default(),
            interface_selection: render::InterfaceSelection::default(),
            attach_mechanisms: vec![],
            pid_descendant_gaps: 0,
            multi_rebuild_gaps: 0,
            unprotected_live_windows: 0,
            module_unresolved_slots: 0,
            provider_changed: false,
            completeness: "COMPLETE",
        }
    }

    #[test]
    fn final_evidence_line_is_machine_readable_and_never_claims_a_proven_drain() {
        let evidence = empty_evidence();
        let line = evidence_line(&evidence, crate::attach::CapturePolicy::Allowlisted, false);
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
        assert_eq!(value["semantic_state_drops"], 0);
        assert_eq!(value["completeness"], "PARTIAL");
        assert_eq!(value["privacy_mode"], "allowlisted");
        assert_eq!(value["capture_aborted"], serde_json::Value::Null);
        assert_eq!(value["final_drain"], false);
        assert_eq!(value["counters_available"], true);
        // A trace's terminal record is the same evidence contract as the
        // profile document, discovery included — one flattened struct, so the
        // two can never carry different fields.
        assert_eq!(value["authority"], "hash-pinned");
        assert_eq!(value["discovery"], serde_json::json!([]));
        for counter in [
            "discovery_conflicts",
            "discovery_uncorroborated",
            "module_ambiguous",
            "scan_ms",
        ] {
            assert_eq!(value[counter], 0, "{counter}");
        }
        assert_eq!(value["modules_skipped"], serde_json::json!([]));
        assert_eq!(value["scan_unavailable"], serde_json::Value::Null);
        assert_eq!(
            value["interface_selection"]["tuples"],
            serde_json::json!([])
        );
    }

    #[test]
    fn selection_evidence_is_terminal_only() {
        for line in [
            capture_line(CapturePolicy::Allowlisted),
            lost_line(1).unwrap(),
            truncated_line(1),
        ] {
            assert!(!line.contains("interface_selection"));
            assert!(!line.contains("selection_truncated"));
        }
        assert!(
            evidence_line(&empty_evidence(), CapturePolicy::Allowlisted, false)
                .contains("\"interface_selection\"")
        );
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        let event = tracer.on_event(&open_event(100, 7), &mut state);
        assert!(!event.contains("selection"));
        assert!(!event.contains("interface"));
    }

    #[test]
    fn a_truncated_trace_says_so_in_its_terminal_record() {
        assert_eq!(truncated_line(1), "TRUNCATED at 1 events (--max-events)");
        let evidence = empty_evidence();
        let line = evidence_line(&evidence, crate::attach::CapturePolicy::Allowlisted, true);
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
        assert_eq!(value["trace_truncated"], true);
        assert_eq!(value["completeness"], "PARTIAL");
    }

    #[test]
    fn policy_output_capture_header_uses_the_selected_policy() {
        assert_eq!(
            capture_line(crate::attach::CapturePolicy::UnsafeUnvalidatedMetadata),
            "CAPTURE privacy=unsafe-unvalidated-metadata"
        );
    }

    fn test_plan() -> AttachPlan {
        let mut plan = AttachPlan::from_slots(vec![
            crate::plan::Slot {
                index: 0,
                descriptor_index: crate::kinds::function_id("C_OpenSession").unwrap() + 1,
                object: crate::plan::TEST_PINNED_OBJECT,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
                names: vec!["C_OpenSession".into()],
                aliased: false,
                semantics: crate::kinds::descriptor("C_OpenSession").unwrap(),
                semantic_authorized: true,
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![crate::plan::ModuleId(0)],
            },
            crate::plan::Slot {
                index: 1,
                descriptor_index: crate::kinds::function_id("C_CloseSession").unwrap() + 1,
                object: crate::plan::TEST_PINNED_OBJECT,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x20,
                names: vec!["C_CloseSession".into()],
                aliased: false,
                semantics: crate::kinds::descriptor("C_CloseSession").unwrap(),
                semantic_authorized: true,
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![crate::plan::ModuleId(0)],
            },
        ]);
        plan.entries_seen = 2;
        plan
    }

    fn open_event(pid: u32, session: u64) -> Event {
        let mut ev = base_event();
        ev.pid_tgid = (u64::from(pid) << 32) | 1;
        ev.session = session;
        ev.slot = 0;
        ev
    }

    fn close_event(pid: u32, session: u64) -> Event {
        let mut ev = base_event();
        ev.pid_tgid = (u64::from(pid) << 32) | 1;
        ev.session = session;
        ev.slot = 1;
        ev
    }

    #[test]
    fn tracer_resolves_session_pseudonyms_never_raw_handles() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);

        let open_line = tracer.on_event(&open_event(100, 0xDEAD_BEEF), &mut state);
        assert!(open_line.contains("sess#1"), "line: {open_line}");
        assert!(
            !open_line.contains("deadbeef"),
            "raw handle must never appear: {open_line}"
        );

        // The closing call must still show the pseudonym, even though
        // `State::observe` retires the mapping as part of processing it.
        let close_line = tracer.on_event(&close_event(100, 0xDEAD_BEEF), &mut state);
        assert!(close_line.contains("sess#1"), "line: {close_line}");
        assert!(
            state.session_pseudonym(100, 0, 0xDEAD_BEEF).is_none(),
            "mapping retired after close"
        );
    }

    #[test]
    fn unverified_slot_is_explicit_and_semantically_empty() {
        let mut plan = test_plan();
        plan.slots.truncate(1);
        plan.slots[0].semantic_authorized = false;
        plan.slots[0].semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
        plan.slots[0].descriptor_index = 0;
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        tracer.anchor = Some((0, 0));
        let mut event = open_event(100, 0xdead_beef);
        event.capture = capture::MECHANISM_VALUE;
        event.mechanism = pkcs11_proxy_ng_types::CkMechanismType::AES_GCM.0;
        event.shape = shape::GCM;
        event.p0 = 0xa11c_e000_0000_0001;
        event.p1 = 0xa11c_e000_0000_0002;
        event.p2 = 0xa11c_e000_0000_0003;
        event.user_type = 0xa11c_e004;
        event.attr_types = [0xa11c_e005; 8];
        event.attr_count = 8;
        event.attr_total = 9;
        event.attr_bools = 0xff;
        event.attr_bools_seen = 0xff;

        let line = tracer.on_event(&event, &mut state);

        assert_eq!(
            line,
            "00:00:00.000000 pid 100 tid 1 C_OpenSession [semantics unverified] → CKR_OK 18.0µs"
        );
        for forbidden in [
            "sess#",
            "CKM_",
            "deadbeef",
            "a11ce00000000001",
            "a11ce00000000002",
            "a11ce00000000003",
            "a11ce004",
            "a11ce005",
            "/opt/",
        ] {
            assert!(!line.contains(forbidden), "leaked {forbidden}: {line}");
        }
        assert!(state.mechanisms().is_empty());
        assert_eq!(state.sessions().opened, 0);
        assert!(state.logins().is_empty());
        assert!(state.templates().is_empty());
        assert_eq!(state.pending_at_end(), 0);
    }

    #[test]
    fn tracer_wall_clock_tracks_kernel_monotonic_deltas() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);

        let mut first = open_event(100, 1);
        first.ts_ns = 1_000_000_000;
        let first_line = tracer.on_event(&first, &mut state);

        let mut second = open_event(100, 2);
        second.ts_ns = first.ts_ns + 500_000_000; // 500ms later, kernel time
        let second_line = tracer.on_event(&second, &mut state);

        let first_ts = &first_line[..15];
        let second_ts = &second_line[..15];
        assert_ne!(
            first_ts, second_ts,
            "distinct kernel timestamps must render distinct wall times"
        );
    }

    #[test]
    fn sync_plan_resolves_new_slots_and_keeps_unknown_slots_count_only() {
        let mut plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        tracer.anchor = Some((0, 0));

        let mut added = plan.slots[0].clone();
        added.index = 2;
        added.names = vec!["C_Sign".into()];
        added.descriptor_index = crate::kinds::function_id("C_Sign").unwrap() + 1;
        added.semantics = crate::kinds::descriptor("C_Sign").unwrap();
        plan.slots.push(added);
        tracer.sync_plan(&plan);
        state.sync_plan(&plan);

        let mut dynamic = open_event(100, 7);
        dynamic.slot = 2;
        dynamic.capture = capture::MECHANISM_VALUE;
        dynamic.mechanism = pkcs11_proxy_ng_types::CkMechanismType::AES_GCM.0;
        let dynamic_line = tracer.on_event(&dynamic, &mut state);
        assert!(
            dynamic_line.contains(" C_Sign CKM_AES_GCM"),
            "{dynamic_line}"
        );

        let mut unknown = dynamic;
        unknown.slot = 99;
        let unknown_line = tracer.on_event(&unknown, &mut state);
        assert!(unknown_line.contains(" slot#99 →"), "{unknown_line}");
        assert!(!unknown_line.contains("CKM_"), "{unknown_line}");
    }

    #[test]
    fn sync_plan_keeps_frozen_decode_metadata_for_a_retired_slot() {
        let mut plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        tracer.anchor = Some((0, 0));

        plan.deactivate(0);
        state.sync_plan(&plan);
        tracer.sync_plan(&plan);

        let line = tracer.on_event(&open_event(100, 0xdead_beef), &mut state);

        assert!(line.contains(" sess#1 C_OpenSession "), "{line}");
        assert!(!line.contains("slot#0"), "{line}");
        assert_eq!(state.sessions().opened, 1);
        assert_eq!(state.semantic_evidence().state_reconciliations, 0);
    }

    #[test]
    fn sync_plan_treats_sticky_module_ambiguity_as_count_only() {
        let mut plan = test_plan();
        let descriptor = plan.slots[0].descriptor_index;
        let mut tracer = Tracer::new(&plan);
        let mut state = State::new(&plan);
        tracer.anchor = Some((0, 0));

        let mut shared = plan.slots.clone();
        shared[0].module_ids.push(crate::plan::ModuleId(1));
        let candidate = AttachPlan::from_slots(shared);
        assert!(plan.latch_ambiguity_from(&candidate));
        tracer.sync_plan(&plan);
        state.sync_plan(&plan);

        let line = tracer.on_event(&open_event(100, 0xdead_beef), &mut state);
        assert_eq!(plan.slots[0].descriptor_index, descriptor);
        assert_eq!(
            tracer.slots[0].as_ref().unwrap().semantics,
            p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        );
        assert!(!line.contains("sess#"), "{line}");
        assert!(!state.pid_has_process_state(100));
    }
}
