// SPDX-License-Identifier: GPL-3.0-or-later
//! Deterministic public renderer/trace consumers; these fixtures are not live captures.
use p11scope::attach::CapturePolicy;
use p11scope::metrics::SlotReport;
use p11scope::render::{
    self, CaptureMeta, DiscoveryEvidence, Evidence, GapClasses, InterfaceSelection,
    LoaderDiscovery, SchedulingEvidence,
};
use p11scope::trace;
use p11scope_ebpf_common::{Event, LATENCY_BUCKETS};
use std::time::Duration;

fn evidence() -> Evidence {
    Evidence {
        table_entries: 68,
        slots: 68,
        active_slots: 68,
        attached_probes: 136,
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
        abi_refusals: 0,
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
        semantic_history_drops: 0,
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
        kernel_control: Default::default(),
        loader_discovery: LoaderDiscovery::default(),
        interface_selection: InterfaceSelection::default(),
        attach_mechanisms: vec![],
        attach_backend: Default::default(),
        pid_descendant_gaps: 0,
        multi_rebuild_gaps: 0,
        unprotected_live_windows: 0,
        module_unresolved_slots: 0,
        provider_changed: false,
        discovery: DiscoveryEvidence {
            modules: vec![],
            ..DiscoveryEvidence::default()
        },
        scheduling: SchedulingEvidence::default(),
        stop_quiescence: Default::default(),
        drain_proven: false,
        verdict_detail: render::VERDICT_CONCRETE_GAP,
        gap_classes: GapClasses::default(),
        stdout_data_sink: false,
        trace_truncated: false,
        uretprobe_override: None,
        handoff_child_pid: None,
        pid_namespace: p11scope::pidns::PidNamespaceEvidence::of(
            &p11scope::pidns::PidNumbering::agreeing(),
        ),
        p11scope_env: vec![],
        completeness: "UNKNOWN",
    }
}

fn report(calls: u64, errors: u64, in_flight: u64) -> SlotReport {
    SlotReport {
        names: vec!["C_Sign".into()],
        aliased: false,
        semantic_authorized: false,
        module: None,
        module_ambiguous: false,
        module_unresolved: true,
        calls,
        errors,
        in_flight,
        total_ns: 0,
        max_ns: 0,
        buckets: [0; LATENCY_BUCKETS],
        rv_counts: Default::default(),
        file_offset: 0,
        target_object: None,
        ordinals: vec![],
    }
}

fn capture(scope: &'static str) -> CaptureMeta<'static> {
    CaptureMeta {
        started: "fixture-start",
        ended: "fixture-end",
        kernel: "fixture-kernel",
        policy: CapturePolicy::Allowlisted,
        scope,
        ring_bytes: 4096,
        drain_interval_ms: 100,
    }
}

fn human(reports: &[SlotReport], ev: &Evidence) -> String {
    render::live(
        reports,
        ev,
        Duration::from_secs(30),
        "/opt/provider.so",
        "profile",
        CapturePolicy::Allowlisted,
    )
}

// Catch application allocation claims in an aggregate-only mode, and ensure
// ambiguous and unowned targets retain real counters without invented owners.
#[test]
fn aggregate_scope_has_no_application_allocation() {
    let mut alias = report(7, 2, 1);
    alias.names.push("C_Encrypt".into());
    alias.aliased = true;
    alias.module_ambiguous = true;
    alias.module_unresolved = false;
    let reports = [alias, report(5, 0, 0)];
    let mut ev = evidence();
    ev.module_unresolved_slots = 1;
    ev.in_flight_at_end = 1;
    ev.verdict();
    let json = render::json(&reports, &ev, &capture("system"));
    assert_eq!(json["functions"][0]["calls"], 7);
    assert_eq!(json["functions"][0]["module_ambiguous"], true);
    assert_eq!(json["functions"][1]["module_unresolved"], true);
    for row in json["functions"].as_array().unwrap() {
        assert!(row["module"].is_null());
        assert!(row.get("application").is_none());
        assert!(row.get("pid").is_none());
    }
    let text = human(&reports, &ev);
    assert!(
        text.contains("Aggregate across the selected scope; counts are not per application"),
        "{text}"
    );
    assert!(
        text.contains("7 completed calls have ambiguous module ownership"),
        "{text}"
    );
    assert!(
        text.contains("5 completed calls have unresolved module ownership"),
        "{text}"
    );
}

// Catch using discovery table entries or entered+returned as completed calls.
#[test]
fn completed_entries_and_returns_are_distinct() {
    let reports = [report(24, 2, 1), report(0, 0, 2)];
    let mut ev = evidence();
    ev.in_flight_at_end = 3;
    ev.verdict();
    let json = render::json(&reports, &ev, &capture("pid"));
    assert_eq!(json["functions"][0]["calls"], 24);
    assert_eq!(json["functions"][0]["errors"], 2);
    assert_eq!(json["functions"][1]["in_flight"], 2);
    assert_eq!(json["evidence"]["table_entries"], 68);
    let state = p11scope::semantics::State::new(&p11scope::plan::AttachPlan::from_slots(vec![]));
    let profile = render::profile_json(
        &reports,
        render::VersionedEvidence::wrap(&ev),
        &state,
        &capture("pid"),
    );
    assert_eq!(profile["functions"], json["functions"]);
    let text = human(&reports, &ev);
    assert!(
        text.contains(
            "24 completed calls; 2 returned errors; 3 entries without an observed return"
        ),
        "{text}"
    );
    assert!(text.contains("CALLS = completed calls"), "{text}");
    assert!(text.contains("ns/us/ms/s"), "{text}");
}

// Catch treating ring-buffer loss as erased or allocated map counts.
#[test]
fn loss_does_not_erase_map_counts() {
    let reports = [report(12, 1, 0)];
    let mut ev = evidence();
    ev.event_loss = 4;
    ev.verdict();
    let metrics = render::json(&reports, &ev, &capture("system"));
    assert_eq!(metrics["functions"][0]["calls"], 12);
    assert_eq!(metrics["evidence"]["event_loss"], 4);
    let line = trace::evidence_line(&ev, CapturePolicy::Allowlisted);
    let terminal: serde_json::Value =
        serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
    assert_eq!(terminal["event_loss"], 4);
    assert_eq!(terminal["completeness"], "PARTIAL");
    assert_eq!(trace::lost_line(4).as_deref(), Some("LOST 4 events"));
    let text = human(&reports, &ev);
    assert!(text.contains("12 completed calls"), "{text}");
    assert!(text.contains("event detail was lost"), "{text}");
    assert!(
        text.contains("Aggregate counts use the counter maps"),
        "{text}"
    );
}

// Catch PID-based naming or omission of the missing executable binding.
#[test]
fn trace_unknown_never_resolves_current_pid() {
    // A live, readable PID and a vanished/reused-number fixture must both stay
    // unknown: this consumer has deliberately received no executable binding.
    for pid in [std::process::id(), 4242, u32::MAX] {
        let event = Event {
            pid_tgid: (u64::from(pid) << 32) | 4243,
            duration_ns: 12000,
            ..Event::default()
        };
        let text = trace::format_line(&event, 0, "C_Sign", None);
        assert!(
            text.contains(&format!("Unknown executable (PID {pid}, TID 4243)")),
            "{text}"
        );
        assert!(text.contains("C_Sign"), "{text}");
        assert!(text.contains("CKR_OK"), "{text}");
    }
}

// Catch an unused/no-activity conclusion that hides missing capture coverage.
#[test]
fn zero_completed_calls_keep_open_work_and_incomplete_coverage_visible() {
    let reports = [report(0, 0, 3)];
    let mut ev = evidence();
    ev.in_flight_at_end = 3;
    ev.verdict();
    let text = human(&reports, &ev);
    assert!(
        text.contains("No completed calls observed; coverage incomplete"),
        "{text}"
    );
    assert!(
        text.contains("3 entries without an observed return"),
        "{text}"
    );
    assert!(!text.contains("unused"), "{text}");
}

// Catch terminal injection through external labels while preserving JSON facts.
#[test]
fn capture_labels_escape_controls_and_preserve_long_provider_text() {
    let label = "C_Sign\n\u{1b}[2J\u{9b}";
    let mut row = report(1, 0, 0);
    row.names = vec![label.into()];
    let mut ev = evidence();
    ev.verdict();
    let provider = format!("/opt/{}/provider\r.so", "long".repeat(1024));
    let text = render::live(
        std::slice::from_ref(&row),
        &ev,
        Duration::from_secs(30),
        &provider,
        "profile",
        CapturePolicy::Allowlisted,
    );
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{9b}') && !text.contains('\r'),
        "{text:?}"
    );
    assert!(text.contains(r"C_Sign\n\u{1b}[2J\u{9b}"), "{text:?}");
    assert!(
        text.contains(&"long".repeat(1024)),
        "provider label silently shortened"
    );
    let json = render::json(&[row], &ev, &capture("system"));
    assert_eq!(json["functions"][0]["names"][0], label);
    let trace = trace::format_line(&Event::default(), 0, label, None);
    assert!(
        !trace.contains('\u{1b}') && !trace.contains('\u{9b}'),
        "{trace:?}"
    );
}

// Catch dropping the validated Scope::kind() at the production-facing render
// seam, or publishing a PID/path accidentally supplied in place of a kind.
#[test]
fn scoped_renderer_uses_only_scope_kinds_and_keeps_legacy_consumer_valid() {
    let reports = [report(4, 1, 0)];
    let mut ev = evidence();
    ev.verdict();
    for (kind, label) in [("pid", "PID"), ("cgroup", "cgroup"), ("system", "system")] {
        let text = render::live_scoped(
            &reports,
            &ev,
            Duration::from_secs(30),
            "/opt/provider.so",
            "profile",
            CapturePolicy::Allowlisted,
            kind,
        );
        let header = text.lines().next().unwrap();
        let scope = header.find(&format!("{label} scope")).unwrap();
        let duration = header.find("up 00:00:30").unwrap();
        let counts = text.find("4 completed calls; 1 returned errors").unwrap();
        let table = text.find("FUNCTION").unwrap();
        assert!(
            scope < duration && duration < counts && counts < table,
            "{text}"
        );
        assert!(text.contains(&format!("Scope: {label} scope")), "{text}");
        assert_eq!(
            render::json(&reports, &ev, &capture(kind))["capture"]["scope"],
            kind
        );
    }
    let legacy = human(&reports, &ev);
    assert!(legacy.contains("selected scope"), "{legacy}");
    for invalid in ["/proc/4242", "4242", "system\n\u{1b}[2J"] {
        let summary = render::scope_summary(invalid, &reports, &ev);
        assert!(summary.starts_with("Scope: selected scope\n"), "{summary}");
        assert!(!summary.contains(invalid), "{summary}");
    }
    assert!(trace::identity_note().contains("completed call events in arrival order"));
    assert!(trace::identity_note().contains("PID/TID remain diagnostic identifiers"));
}

// Feed the actual production formatter to the real qualification privacy
// consumer, rather than a test-local trace parser or a copied output fixture.
#[test]
fn actual_trace_formatter_is_accepted_by_canary_privacy_consumer() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let event = Event {
        pid_tgid: (111u64 << 32) | 112,
        duration_ns: 12000,
        ..Event::default()
    };
    let line = trace::format_line(&event, 0, "C_Sign", None);
    let text = format!(
        "{}\n{}\n{line}\n",
        trace::capture_line(CapturePolicy::Allowlisted),
        trace::identity_note()
    );
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-canary-evidence.py");
    let mut child = Command::new("python3").args(["-I", "-c",
        "import runpy,sys; n=runpy.run_path(sys.argv[1]); rest=n['trace_scannable']('renderer',sys.stdin.read()); n['assert_no_loader_pause_identity']('renderer',rest)"])
        .arg(script).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
