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
    /// every surface was fully walked with a successful acquisition, and
    /// no vendor interfaces were left undecoded.
    pub fn verdict(&mut self) {
        let surfaces_complete =
            self.surfaces.iter().all(|s| s.walk == "full" && s.acquisition == "ok");
        self.completeness = if self.attach_failures.is_empty()
            && self.skipped.is_empty()
            && self.aliased.is_empty()
            && self.in_flight_at_end == 0
            && surfaces_complete
            && self.vendor_interfaces == 0
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
pub fn live(reports: &[SlotReport], ev: &Evidence, elapsed: Duration, module: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "p11scope — {module} — up {:02}:{:02}:{:02} — mode metrics\n",
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

pub fn json(
    reports: &[SlotReport],
    ev: &Evidence,
    module: &str,
    started: &str,
    ended: &str,
    kernel: &str,
) -> serde_json::Value {
    let functions: Vec<FunctionOut> = reports
        .iter()
        .map(|r| FunctionOut {
            names: r.names.clone(),
            aliased: r.aliased,
            calls: r.calls,
            errors: r.errors,
            in_flight: r.in_flight,
            latency_ns: LatencyOut {
                approximate: true,
                p50: percentile_ns(&r.buckets, 0.50),
                p95: percentile_ns(&r.buckets, 0.95),
                p99: percentile_ns(&r.buckets, 0.99),
                total: r.total_ns,
                max: r.max_ns,
            },
            rv_counts: r
                .rv_counts
                .iter()
                .map(|(rv, n)| (format!("0x{rv:08x}"), *n))
                .collect(),
        })
        .collect();
    serde_json::json!({
        "schema": "pkcs11-scope/observed-profile/v0-metrics",
        "capture": { "start": started, "end": ended, "mode": "metrics",
                     "kernel": kernel, "module": module },
        "evidence": ev,
        "functions": functions,
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
        ] {
            let mut ev = evidence();
            mutate(&mut ev);
            ev.verdict();
            assert_eq!(ev.completeness, "PARTIAL", "a gap must never read as COMPLETE");
        }
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
        );
        assert!(out.contains("C_Sign"));
        // Zero-call rows still appear when a call is in flight.
        assert!(out.contains("C_WaitForSlotEvent (aliased)"));
        assert!(out.contains("up 00:01:05"));
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
}
