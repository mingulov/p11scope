//! Rendering. Both renderers state the capture's completeness; a report
//! that lost information never reads as complete.

use crate::metrics::{SlotReport, percentile_ns};
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Evidence {
    /// Function records present in the manifest across walked surfaces.
    pub table_entries: usize,
    /// Unique {object, file_offset} targets planned.
    pub slots: usize,
    /// Probes successfully attached (2 per fully-attached slot).
    pub attached_probes: usize,
    pub attach_failures: Vec<String>,
    /// Slots whose counts belong to a name group, not a single name.
    pub aliased: Vec<Vec<String>>,
    /// Manifest entries with no attachable target, and why.
    pub skipped: Vec<SkippedOut>,
    pub in_flight_at_end: u64,
    /// Per-surface discovery provenance (walk outcome, acquisition status).
    /// A surface that was not fully walked or failed to acquire means
    /// functions the manifest declares may never have been probed, even
    /// when `skipped`/`aliased` are empty.
    pub surfaces: Vec<crate::plan::SurfaceSummary>,
    /// Present-but-undecoded vendor interfaces (never walked).
    pub vendor_interfaces: usize,
    /// Outcome of the manifest-level C_GetInterfaceList enumeration.
    pub interface_list: String,
    /// Ring-buffer events the kernel side could not reserve space for
    /// (`metrics::lost_events`). Zero in `--mode metrics`, which never
    /// drains the ring buffer.
    pub event_loss: u64,
    /// Ring-buffer records rejected by the size check (`events::Drain`).
    /// A nonzero count means the writer/reader layout drifted mid-capture.
    pub malformed_records: u64,
    /// Operational calls (`C_Sign`, `C_Encrypt`, ...) observed with no
    /// active `*Init` on their session — expected when capture attaches
    /// mid-operation; informational, does not affect `completeness`.
    pub orphan_ops: u64,
    /// `C_CloseSession` calls observed with no matching open — likewise
    /// informational, does not affect `completeness`.
    pub unmatched_closes: u64,
    pub completeness: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SkippedOut {
    pub name: String,
    pub reason: String,
}

impl Evidence {
    /// COMPLETE only when nothing was lost: every planned probe attached,
    /// nothing was skipped, no aliasing ambiguity, no call left in flight,
    /// every surface was fully walked with a successful acquisition, no
    /// vendor interfaces were left undecoded, and (profile mode) the ring
    /// buffer neither dropped nor emitted a malformed record.
    pub fn verdict(&mut self) {
        let surfaces_complete =
            self.surfaces.iter().all(|s| s.walk == "full" && s.acquisition == "ok");
        self.completeness = if self.attach_failures.is_empty()
            && self.skipped.is_empty()
            && self.aliased.is_empty()
            && self.in_flight_at_end == 0
            && surfaces_complete
            && self.vendor_interfaces == 0
            && self.event_loss == 0
            && self.malformed_records == 0
        {
            "COMPLETE"
        } else {
            "PARTIAL"
        };
    }
}

fn label(r: &SlotReport) -> String {
    if r.aliased { format!("{} (aliased)", r.names.join("|")) } else { r.names.join("|") }
}

fn fmt_ns(ns: Option<u64>) -> String {
    match ns {
        None => "—".into(),
        Some(v) if v < 1_000 => format!("{v}ns"),
        Some(v) if v < 1_000_000 => format!("{:.1}µs", v as f64 / 1e3),
        Some(v) if v < 1_000_000_000 => format!("{:.1}ms", v as f64 / 1e6),
        Some(v) => format!("{:.2}s", v as f64 / 1e9),
    }
}

/// One refreshing screen. Rows with no activity are omitted; the evidence
/// line is always present.
pub fn live(reports: &[SlotReport], ev: &Evidence, elapsed: Duration, module: &str, mode: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "p11scope — {module} — up {:02}:{:02}:{:02} — mode {mode}\n",
        elapsed.as_secs() / 3600,
        (elapsed.as_secs() % 3600) / 60,
        elapsed.as_secs() % 60
    ));
    s.push_str(&format!(
        "{:<28} {:>8} {:>6} {:>9} {:>9} {:>9} {:>9}\n",
        "FUNCTION", "CALLS", "ERR", "p50~", "p95~", "p99~", "IN-FLIGHT"
    ));
    let mut rows: Vec<&SlotReport> =
        reports.iter().filter(|r| r.calls > 0 || r.in_flight > 0).collect();
    rows.sort_by(|a, b| b.calls.cmp(&a.calls).then(a.names.cmp(&b.names)));
    for r in rows {
        s.push_str(&format!(
            "{:<28} {:>8} {:>6} {:>9} {:>9} {:>9} {:>9}\n",
            label(r),
            r.calls,
            r.errors,
            fmt_ns(percentile_ns(&r.buckets, 0.50)),
            fmt_ns(percentile_ns(&r.buckets, 0.95)),
            fmt_ns(percentile_ns(&r.buckets, 0.99)),
            r.in_flight
        ));
    }
    s.push_str("(~ = log2-bucket approximation, lower bound)\n");
    let surface_gaps =
        ev.surfaces.iter().filter(|s| s.walk != "full" || s.acquisition != "ok").count();
    let mut evidence_line = format!(
        "Evidence: {}/{} probes attached · {} slots · {} aliased · {} skipped · {} in-flight",
        ev.attached_probes,
        ev.slots * 2,
        ev.slots,
        ev.aliased.len(),
        ev.skipped.len(),
        ev.in_flight_at_end,
    );
    if surface_gaps > 0 || ev.vendor_interfaces > 0 {
        evidence_line.push_str(&format!(
            " · {surface_gaps} surface gaps · {} vendor interfaces",
            ev.vendor_interfaces
        ));
    }
    evidence_line.push_str(&format!(" → {}\n", ev.completeness));
    s.push_str(&evidence_line);
    s
}

#[derive(Serialize)]
struct FunctionOut {
    names: Vec<String>,
    aliased: bool,
    calls: u64,
    errors: u64,
    in_flight: u64,
    latency_ns: LatencyOut,
    rv_counts: std::collections::BTreeMap<String, u64>,
}

#[derive(Serialize)]
struct LatencyOut {
    /// Bucket-approximated; exact values are total/max.
    approximate: bool,
    p50: Option<u64>,
    p95: Option<u64>,
    p99: Option<u64>,
    total: u64,
    max: u64,
}

fn latency_out(buckets: &[u64; p11scope_ebpf_common::LATENCY_BUCKETS], total: u64, max: u64) -> LatencyOut {
    LatencyOut {
        approximate: true,
        p50: percentile_ns(buckets, 0.50),
        p95: percentile_ns(buckets, 0.95),
        p99: percentile_ns(buckets, 0.99),
        total,
        max,
    }
}

/// Per-name call/error/latency counts from the **aggregate BPF maps** —
/// the count authority in every mode (see module docs on `functions`
/// sourcing in both renderers).
fn functions_out(reports: &[SlotReport]) -> Vec<FunctionOut> {
    reports
        .iter()
        .map(|r| FunctionOut {
            names: r.names.clone(),
            aliased: r.aliased,
            calls: r.calls,
            errors: r.errors,
            in_flight: r.in_flight,
            latency_ns: latency_out(&r.buckets, r.total_ns, r.max_ns),
            rv_counts: r
                .rv_counts
                .iter()
                .map(|(rv, n)| (format!("0x{rv:08x}"), *n))
                .collect(),
        })
        .collect()
}

pub fn json(
    reports: &[SlotReport],
    ev: &Evidence,
    module: &str,
    started: &str,
    ended: &str,
    kernel: &str,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "pkcs11-scope/observed-profile/v0-metrics",
        "capture": { "start": started, "end": ended, "mode": "metrics",
                     "kernel": kernel, "module": module },
        "evidence": ev,
        "functions": functions_out(reports),
    })
}

/// One mechanism id's aggregate stats, event-derived (see module docs):
/// the aggregate maps have no per-mechanism breakdown, only the ring
/// buffer / semantic state machine does.
#[derive(Serialize)]
struct MechanismOut {
    /// Verbatim id — vendor ids survive unchanged, never renamed or dropped.
    mechanism: u64,
    mechanism_hex: String,
    /// Operation categories (`"sign"`, `"encrypt"`, ...) this id was seen
    /// initializing. Empty when only ever seen as an orphan operational
    /// call (no `*Init` observed in this capture).
    ops: Vec<String>,
    calls: u64,
    errors: u64,
    latency_ns: LatencyOut,
    /// Parameter decoding is Phase 3 — never a partial decode. Always
    /// `null` today; typed as `Value` so a Phase 3 decoder can populate
    /// it without a schema-breaking type change.
    params: serde_json::Value,
    note: &'static str,
}

#[derive(Serialize)]
struct SessionsOut {
    opened: u64,
    closed: u64,
    peak_concurrent: u64,
    /// `opened - closed`: sessions still open (or leaked) at capture end.
    balance: u64,
}

/// `capture` section fields that aren't derived from `reports`/`ev`/`state`.
pub struct CaptureMeta<'a> {
    pub module: &'a str,
    /// From the manifest's object identity; `None` when unavailable.
    pub build_id: Option<&'a str>,
    pub started: &'a str,
    pub ended: &'a str,
    pub kernel: &'a str,
}

/// The v1 `observed-profile.json` document. `functions` comes from the
/// aggregate maps (count authority); `mechanisms`/`sessions`/`logins`
/// come from the semantic state machine, the only place that
/// reconstructs mechanism/session/login context from the event stream.
pub fn profile_json(
    reports: &[SlotReport],
    ev: &Evidence,
    state: &crate::semantics::State,
    capture: &CaptureMeta,
) -> serde_json::Value {
    let mechanisms: Vec<MechanismOut> = state
        .mechanisms()
        .iter()
        .map(|(id, m)| MechanismOut {
            mechanism: *id,
            mechanism_hex: format!("0x{id:x}"),
            ops: m.ops.iter().cloned().collect(),
            calls: m.calls,
            errors: m.errors,
            latency_ns: latency_out(&m.buckets, m.total_ns, m.max_ns),
            params: serde_json::Value::Null,
            note: "parameter decoding is Phase 3; not attempted here, never a partial decode",
        })
        .collect();
    let sessions = state.sessions();
    let sessions_out = SessionsOut {
        opened: sessions.opened,
        closed: sessions.closed,
        peak_concurrent: sessions.peak_concurrent,
        balance: sessions.opened.saturating_sub(sessions.closed),
    };
    let logins: std::collections::BTreeMap<String, u64> =
        state.logins().iter().map(|(user_type, n)| (user_type.to_string(), *n)).collect();

    serde_json::json!({
        "schema": "pkcs11-scope/observed-profile/v1",
        "capture": {
            "start": capture.started, "end": capture.ended, "mode": "profile",
            "kernel": capture.kernel,
            "module": { "path": capture.module, "build_id": capture.build_id },
        },
        "evidence": ev,
        "functions": functions_out(reports),
        "mechanisms": mechanisms,
        "sessions": sessions_out,
        "logins": logins,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::LATENCY_BUCKETS;

    fn report(name: &str, calls: u64, in_flight: u64, aliased: bool) -> SlotReport {
        SlotReport {
            names: vec![name.into()],
            aliased,
            calls,
            errors: 0,
            in_flight,
            total_ns: 0,
            max_ns: 0,
            buckets: [0; LATENCY_BUCKETS],
            rv_counts: Default::default(),
        }
    }

    fn ok_surface() -> crate::plan::SurfaceSummary {
        crate::plan::SurfaceSummary {
            source: "legacy_function_list".into(),
            walk: "full".into(),
            acquisition: "ok".into(),
            functions: 68,
        }
    }

    fn evidence() -> Evidence {
        Evidence {
            table_entries: 68,
            slots: 68,
            attached_probes: 136,
            attach_failures: vec![],
            aliased: vec![],
            skipped: vec![],
            in_flight_at_end: 0,
            surfaces: vec![ok_surface()],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
            event_loss: 0,
            malformed_records: 0,
            orphan_ops: 0,
            unmatched_closes: 0,
            completeness: "UNKNOWN",
        }
    }

    #[test]
    fn clean_capture_is_complete() {
        let mut ev = evidence();
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
    }

    #[test]
    fn any_gap_forces_partial() {
        for mutate in [
            (|e: &mut Evidence| e.attach_failures.push("boom".into())) as fn(&mut Evidence),
            |e: &mut Evidence| e.skipped.push(SkippedOut { name: "C_X".into(), reason: "null pointer".into() }),
            |e: &mut Evidence| e.aliased.push(vec!["C_A".into(), "C_B".into()]),
            |e: &mut Evidence| e.in_flight_at_end = 1,
            |e: &mut Evidence| e.surfaces[0].walk = "known_prefix".into(),
            |e: &mut Evidence| e.surfaces[0].acquisition = "error: boom".into(),
            |e: &mut Evidence| e.vendor_interfaces = 1,
            |e: &mut Evidence| e.event_loss = 1,
            |e: &mut Evidence| e.malformed_records = 1,
        ] {
            let mut ev = evidence();
            mutate(&mut ev);
            ev.verdict();
            assert_eq!(ev.completeness, "PARTIAL", "a gap must never read as COMPLETE");
        }
    }

    #[test]
    fn orphan_ops_and_unmatched_closes_do_not_affect_completeness() {
        // Informational evidence fields, not attach/loss gaps: a capture
        // that started mid-operation is still COMPLETE for what it saw.
        let mut ev = evidence();
        ev.orphan_ops = 3;
        ev.unmatched_closes = 2;
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
    }

    #[test]
    fn live_view_shows_inflight_rows_and_marks_aliases() {
        let mut ev = evidence();
        ev.verdict();
        let out = live(
            &[report("C_Sign", 10, 0, false), report("C_WaitForSlotEvent", 0, 1, true)],
            &ev,
            Duration::from_secs(65),
            "/opt/p11.so",
            "profile",
        );
        assert!(out.contains("C_Sign"));
        // Zero-call rows still appear when a call is in flight.
        assert!(out.contains("C_WaitForSlotEvent (aliased)"));
        assert!(out.contains("up 00:01:05"));
        assert!(out.contains("mode profile"));
        assert!(out.contains("approximation"));
    }

    #[test]
    fn json_marks_latency_approximate_and_hex_rvs() {
        let mut ev = evidence();
        ev.verdict();
        let mut r = report("C_Sign", 1, 0, false);
        r.rv_counts.insert(0, 1);
        let v = json(&[r], &ev, "/opt/p11.so", "t0", "t1", "6.8.0");
        assert_eq!(v["functions"][0]["latency_ns"]["approximate"], true);
        assert_eq!(v["functions"][0]["rv_counts"]["0x00000000"], 1);
        assert_eq!(v["evidence"]["completeness"], "COMPLETE");
    }

    fn empty_plan() -> crate::plan::AttachPlan {
        crate::plan::AttachPlan {
            slots: vec![],
            skipped: vec![],
            entries_seen: 0,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
        }
    }

    #[test]
    fn profile_json_has_every_required_top_level_section() {
        let mut ev = evidence();
        ev.verdict();
        let state = crate::semantics::State::new(&empty_plan());
        let capture = CaptureMeta {
            module: "/opt/p11.so",
            build_id: Some("aabb"),
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
        };
        let v = profile_json(&[], &ev, &state, &capture);

        assert_eq!(v["schema"], "pkcs11-scope/observed-profile/v1");
        for section in
            ["capture", "evidence", "functions", "mechanisms", "sessions", "logins"]
        {
            assert!(v.get(section).is_some(), "v1 document missing required section {section}");
        }
        assert_eq!(v["capture"]["mode"], "profile");
        assert_eq!(v["capture"]["module"]["path"], "/opt/p11.so");
        assert_eq!(v["capture"]["module"]["build_id"], "aabb");
    }

    #[test]
    fn profile_json_mechanisms_carry_verbatim_id_hex_ops_and_null_params() {
        use p11scope_ebpf_common::{Event, USER_TYPE_NONE, fnkind};

        let plan = crate::plan::AttachPlan {
            slots: vec![crate::plan::Slot {
                index: 0,
                object: "/opt/p11.so".into(),
                file_offset: 0x10,
                names: vec!["C_SignInit".into()],
                aliased: false,
                kind: fnkind::INIT_WITH_MECH,
            }],
            ..empty_plan()
        };
        let mut state = crate::semantics::State::new(&plan);
        let vendor_id: u64 = 0x8000_1042;
        state.observe(&Event {
            ts_ns: 0,
            duration_ns: 1_000,
            pid_tgid: (100u64 << 32) | 1,
            cgroup_id: 0,
            session: 7,
            mechanism: vendor_id,
            rv: 0,
            slot: 0,
            kind: fnkind::INIT_WITH_MECH,
            user_type: USER_TYPE_NONE,
            _pad: 0,
        });

        let mut ev = evidence();
        ev.verdict();
        let capture = CaptureMeta {
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
        };
        let v = profile_json(&[], &ev, &state, &capture);

        let mech = &v["mechanisms"][0];
        assert_eq!(mech["mechanism"], vendor_id);
        assert_eq!(mech["mechanism_hex"], "0x80001042");
        assert_eq!(mech["ops"], serde_json::json!(["sign"]));
        assert_eq!(mech["params"], serde_json::Value::Null);
        assert_eq!(mech["calls"], 1);
        assert_eq!(v["capture"]["module"]["build_id"], serde_json::Value::Null);
    }
}
