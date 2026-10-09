//! SPDX-License-Identifier: GPL-3.0-or-later
//! Final-sink orchestration tests; these never initialize BPF.

use super::*;
use crate::inventory_diagnostics::{CaptureOutcome, CaptureSettlement, DiagnosticOutcome};
use std::cell::Cell;

fn private_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    dir
}

fn fixture_diagnostic_path(directory: &Path) -> PathBuf {
    // The existing retained-dir AtomicFile fixture holds one temp file per
    // directory. Independent primary and diagnostic sinks need two directories.
    let directory = directory.join("diagnostic-output");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(
        &directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    directory.join("diagnostics.jsonl")
}

fn fixture_diagnostics(
    path: &Path,
    report: Option<&Path>,
    event_log: Option<&Path>,
) -> DiagnosticsState {
    DiagnosticsState {
        path: path.to_path_buf(),
        destination: Some(crate::inventory_diagnostics_output::fixture_destination(
            path, report, event_log,
        )),
        failed: false,
    }
}

fn records(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn coordinator() -> InventoryCoordinator<OsProcessSource> {
    InventoryCoordinator::new(
        Scope::Pid(std::process::id()),
        HookRegistry::builtin(),
        Vec::new(),
        OsProcessSource,
        RegistryLimits::default_limits(),
    )
    .unwrap()
}

fn completed() -> DiagnosticOutcome {
    DiagnosticOutcome {
        capture_outcome: CaptureOutcome::Completed,
        capture_settlement: CaptureSettlement::Unsettled,
    }
}

#[test]
fn diagnostics_notice_bounds_control_characters_and_unicode() {
    let input = format!("{}{}", "\u{1b}".repeat(511), "🛑".repeat(100));
    let mut notices = Vec::new();
    diagnostics_notice(&input, &mut |line| notices.push(line.to_string()));
    assert_eq!(notices.len(), 1);
    assert!(notices[0].ends_with(" [truncated]"));
    assert!(notices[0].len() < 4096);
    assert!(!notices[0].chars().any(char::is_control));
}

// Removing the diagnostic attempt after finish_output must fail this test.
#[test]
fn primary_stdout_failure_still_delivers_diagnostics_after_report() {
    struct FailedStdout<'a> {
        report: &'a Path,
        diagnostics: &'a Path,
    }
    impl FinalStdout for FailedStdout<'_> {
        fn begin_finalization(&mut self) {}
        fn write_document(&mut self, bytes: &[u8]) -> StdoutResult {
            assert!(
                self.report.exists(),
                "primary report must be attempted first"
            );
            assert!(
                !self.diagnostics.exists(),
                "diagnostics follow primary output"
            );
            Err(crate::inventory_output::StdoutFailure {
                accepted: 0,
                total: bytes.len(),
                reason: StdoutFailureReason::Io(std::io::Error::other("stdout refused")),
            })
        }
    }
    let dir = private_tempdir();
    let report = dir.path().join("report.json");
    let diagnostics = fixture_diagnostic_path(dir.path());
    let mut coordinator = coordinator();
    let mut diagnostic = fixture_diagnostics(&diagnostics, Some(&report), None);
    diagnostic.enable(
        &mut coordinator,
        CaptureMode::Native,
        InspectScope::System,
        None,
    );
    let presentation = Presentation::capture(&coordinator, "system", 1, 2, 0);
    let mut notices = Vec::new();
    let result = finish_runtime_output(
        Some(crate::output::atomic_file_test_fixture(&report)),
        &mut EventLogState::new(None),
        &mut StreamState::new(),
        &presentation,
        true,
        false,
        &mut FailedStdout {
            report: &report,
            diagnostics: &diagnostics,
        },
        None,
        &mut coordinator,
        Some(diagnostic),
        completed(),
        &|| false,
        &mut |line| notices.push(line.to_string()),
    );
    assert_eq!(result.exit_code(), 1);
    assert_eq!(
        records(&diagnostics).last().unwrap()["capture_outcome"],
        "completed"
    );
    assert_eq!(
        notices
            .iter()
            .filter(|line| line.starts_with("Diagnostics:"))
            .count(),
        1
    );
}

#[test]
fn primary_report_commit_failure_still_delivers_diagnostics_and_stdout() {
    let dir = private_tempdir();
    let report = dir.path().join("report.json");
    let prior_report = dir.path().join("prior.json");
    let diagnostics = fixture_diagnostic_path(dir.path());
    std::fs::write(&prior_report, b"prior report\n").unwrap();
    let mut coordinator = coordinator();
    let mut diagnostic = fixture_diagnostics(&diagnostics, Some(&report), None);
    diagnostic.enable(
        &mut coordinator,
        CaptureMode::Native,
        InspectScope::System,
        None,
    );
    let sink = crate::output::atomic_file_test_fixture(&report);
    std::os::unix::fs::symlink(&prior_report, &report).unwrap();
    let presentation = Presentation::capture(&coordinator, "system", 1, 2, 0);
    let mut stdout = Vec::new();
    let result = finish_runtime_output(
        Some(sink),
        &mut EventLogState::new(None),
        &mut StreamState::new(),
        &presentation,
        true,
        false,
        &mut WriterStdout(&mut stdout),
        None,
        &mut coordinator,
        Some(diagnostic),
        completed(),
        &|| false,
        &mut |_| {},
    );
    assert_eq!(result.exit_code(), 1);
    assert_eq!(result.report_committed, Some(false));
    assert_eq!(std::fs::read(prior_report).unwrap(), b"prior report\n");
    let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(document["schema"], DOC_ID);
    assert_eq!(
        records(&diagnostics).last().unwrap()["capture_outcome"],
        "completed"
    );
}

// Ignoring the explicit second-signal callback must fail this test.
#[test]
fn diagnostic_cancellation_preserves_destination_and_normal_report() {
    let dir = private_tempdir();
    let report = dir.path().join("report.json");
    let diagnostics = fixture_diagnostic_path(dir.path());
    std::fs::write(&diagnostics, b"previous diagnostics\n").unwrap();
    let mut coordinator = coordinator();
    let mut diagnostic = fixture_diagnostics(&diagnostics, Some(&report), None);
    diagnostic.enable(
        &mut coordinator,
        CaptureMode::Native,
        InspectScope::System,
        None,
    );
    let presentation = Presentation::capture(&coordinator, "system", 1, 2, 0);
    let mut stdout = Vec::new();
    let result = finish_runtime_output(
        Some(crate::output::atomic_file_test_fixture(&report)),
        &mut EventLogState::new(None),
        &mut StreamState::new(),
        &presentation,
        true,
        false,
        &mut WriterStdout(&mut stdout),
        None,
        &mut coordinator,
        Some(diagnostic),
        completed(),
        &|| true,
        &mut |_| {},
    );
    assert_eq!(result.exit_code(), 1);
    assert_eq!(std::fs::read(report).unwrap(), stdout);
    assert_eq!(
        std::fs::read(diagnostics).unwrap(),
        b"previous diagnostics\n"
    );
}

#[test]
fn unavailable_diagnostics_setup_still_commits_normal_report_and_returns_failure() {
    let dir = private_tempdir();
    let report = dir.path().join("report.json");
    let diagnostics = dir.path().join("missing-parent/diagnostics.jsonl");
    let mut coordinator = coordinator();
    let mut diagnostic = DiagnosticsState::prepare(&diagnostics, Some(&report), None).unwrap();
    diagnostic.enable(
        &mut coordinator,
        CaptureMode::Native,
        InspectScope::System,
        None,
    );
    let presentation = Presentation::capture(&coordinator, "system", 1, 2, 0);
    let mut stdout = Vec::new();
    let mut notices = Vec::new();
    let result = finish_runtime_output(
        Some(crate::output::atomic_file_test_fixture(&report)),
        &mut EventLogState::new(None),
        &mut StreamState::new(),
        &presentation,
        true,
        false,
        &mut WriterStdout(&mut stdout),
        None,
        &mut coordinator,
        Some(diagnostic),
        completed(),
        &|| false,
        &mut |line| notices.push(line.to_string()),
    );
    assert_eq!(result.exit_code(), 1);
    assert_eq!(std::fs::read(report).unwrap(), stdout);
    assert!(!diagnostics.exists());
    assert!(
        notices.is_empty(),
        "setup warning must not be repeated at finalization"
    );
}

#[test]
fn normal_signal_stop_delivers_an_unsettled_footer() {
    let dir = private_tempdir();
    let diagnostics = fixture_diagnostic_path(dir.path());
    let mut coordinator = coordinator();
    let mut diagnostic = fixture_diagnostics(&diagnostics, None, None);
    diagnostic.enable(
        &mut coordinator,
        CaptureMode::Native,
        InspectScope::System,
        None,
    );
    let presentation = Presentation::capture(&coordinator, "system", 1, 2, 0);
    let result = finish_runtime_output(
        None,
        &mut EventLogState::new(None),
        &mut StreamState::new(),
        &presentation,
        true,
        false,
        &mut WriterStdout(&mut Vec::new()),
        None,
        &mut coordinator,
        Some(diagnostic),
        diagnostic_outcome(true, false, true),
        &|| false,
        &mut |_| {},
    );
    assert_eq!(result.exit_code(), 0);
    let lines = records(&diagnostics);
    let footer = lines.last().unwrap();
    assert_eq!(footer["capture_outcome"], "stopped");
    assert_eq!(footer["capture_settlement"], "unsettled");
}

#[test]
fn auto_fallback_exports_only_envelopes_with_native_unavailable() {
    let dir = private_tempdir();
    let diagnostics = fixture_diagnostic_path(dir.path());
    let mut coordinator = coordinator();
    let mut diagnostic = fixture_diagnostics(&diagnostics, None, None);
    diagnostic.enable(
        &mut coordinator,
        CaptureMode::Auto,
        InspectScope::System,
        None,
    );
    let presentation = Presentation::capture(&coordinator, "system", 1, 2, 0);
    let result = finish_runtime_output(
        None,
        &mut EventLogState::new(None),
        &mut StreamState::new(),
        &presentation,
        true,
        false,
        &mut WriterStdout(&mut Vec::new()),
        None,
        &mut coordinator,
        Some(diagnostic),
        diagnostic_outcome(false, false, false),
        &|| false,
        &mut |_| {},
    );
    assert_eq!(result.exit_code(), 0);
    let lines = records(&diagnostics);
    assert_eq!(lines.len(), 2, "fallback invents no native decisions");
    assert_eq!(
        lines.last().unwrap()["capture_outcome"],
        "native_unavailable"
    );
    assert_eq!(lines.last().unwrap()["capture_settlement"], "unavailable");
}

// Preparing diagnostics after EventWriter creation would truncate this file.
#[test]
fn diagnostic_alias_is_refused_before_event_log_truncation() {
    let dir = private_tempdir();
    let events = dir.path().join("events.jsonl");
    let diagnostics = dir.path().join("diagnostics.jsonl");
    std::fs::write(&events, b"existing event log\n").unwrap();
    std::fs::hard_link(&events, &diagnostics).unwrap();
    let mut stdout = Vec::new();
    let result =
        crate::pidns::test_seam::with_numbering(crate::pidns::PidNumbering::agreeing(), || {
            run_with_terminal_diagnostics(
                InspectScope::Pid(u32::MAX),
                &[],
                &HookRegistry::builtin(),
                true,
                None,
                None,
                None,
                None,
                false,
                Some(&events),
                None,
                None,
                CaptureMode::Native,
                crate::attach::BackendSelection::Auto,
                &|| false,
                &|| {},
                false,
                &mut WriterStdout(&mut stdout),
                &DashboardIo::stdio(),
                DiagnosticRequest {
                    path: Some(&diagnostics),
                    pid_filter: None,
                    second_signal: &|| false,
                },
                None,
            )
        });
    assert!(result.unwrap_err().to_string().contains("aliases"));
    assert_eq!(std::fs::read(events).unwrap(), b"existing event log\n");
    assert!(stdout.is_empty());
}

// Returning open_native_lane's error early would skip this failed footer.
#[test]
fn native_startup_error_exports_failed_footer_and_keeps_primary_error() {
    let dir = private_tempdir();
    let diagnostics = dir.path().join("diagnostics.jsonl");
    let events = dir.path().join("events.jsonl");
    let finalized = Cell::new(false);
    let mut stdout = Vec::new();
    let error =
        crate::pidns::test_seam::with_numbering(crate::pidns::PidNumbering::agreeing(), || {
            run_with_terminal_diagnostics(
                InspectScope::Pid(u32::MAX),
                &[],
                &HookRegistry::builtin(),
                true,
                None,
                None,
                None,
                None,
                false,
                Some(&events),
                None,
                None,
                CaptureMode::Native,
                crate::attach::BackendSelection::Auto,
                &|| false,
                &|| finalized.set(true),
                false,
                &mut WriterStdout(&mut stdout),
                &DashboardIo::stdio(),
                DiagnosticRequest {
                    path: Some(&diagnostics),
                    pid_filter: Some(u32::MAX),
                    second_signal: &|| false,
                },
                None,
            )
        })
        .unwrap_err();
    assert!(error.to_string().contains("--capture native"), "{error:#}");
    assert!(finalized.get());
    assert!(
        std::fs::read(&events).unwrap().is_empty(),
        "capture never started: no successful ended marker"
    );
    let records = records(&diagnostics);
    let footer = records.last().unwrap();
    assert_eq!(footer["capture_outcome"], "failed");
    assert_eq!(footer["capture_settlement"], "unavailable");
    assert!(
        records.iter().all(|record| !matches!(
            record["kind"].as_str(),
            Some("count_observation" | "count_decision" | "ownership_transition")
        )),
        "startup failure invents no native decisions"
    );
}

#[test]
fn failed_started_record_retires_event_log_before_classic_or_dashboard_finalization() {
    use std::os::fd::{AsRawFd, FromRawFd};
    for dashboard in [false, true] {
        let dir = private_tempdir();
        let diagnostics = dir.path().join("diagnostics.jsonl");
        let events = dir.path().join("events.jsonl");
        let report = dir.path().join("report.json");
        let fault = crate::inventory_events::EventFault {
            kind: "started",
            final_pass_only: false,
            after_ended: false,
            attempts: Default::default(),
        };
        let attempts = fault.attempts.clone();
        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let _master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let notices = std::fs::File::create(dir.path().join("notices")).unwrap();
        let terminal = DashboardIo {
            output: slave.as_raw_fd(),
            input: None,
            account: None,
            stderr_fd: notices.as_raw_fd(),
            stderr: StderrRoute::Leave,
        };
        let finalized = Cell::new(false);
        let mut stdout = Vec::new();
        let error =
            crate::pidns::test_seam::with_numbering(crate::pidns::PidNumbering::agreeing(), || {
                run_with_terminal_diagnostics(
                    InspectScope::Pid(u32::MAX),
                    &[],
                    &HookRegistry::builtin(),
                    true,
                    None,
                    None,
                    None,
                    Some(&report),
                    dashboard,
                    Some(&events),
                    None,
                    None,
                    CaptureMode::Auto,
                    crate::attach::BackendSelection::Auto,
                    &|| false,
                    &|| finalized.set(true),
                    dashboard,
                    &mut WriterStdout(&mut stdout),
                    &terminal,
                    DiagnosticRequest {
                        path: Some(&diagnostics),
                        pid_filter: None,
                        second_signal: &|| false,
                    },
                    Some(fault),
                )
            })
            .unwrap_err();
        assert!(
            error.to_string().contains("started append failure"),
            "{error:#}"
        );
        assert_eq!(
            *attempts.borrow(),
            ["started"],
            "retired event writer must not append ended"
        );
        assert!(finalized.get());
        assert!(std::fs::read(&events).unwrap().is_empty());
        assert_eq!(std::fs::read(&report).unwrap(), stdout);
        assert_eq!(
            records(&diagnostics).last().unwrap()["capture_outcome"],
            "failed"
        );
    }
}

#[test]
fn failed_prologue_writer_cannot_resume_during_final_sinks() {
    let dir = private_tempdir();
    let report = dir.path().join("report.json");
    let diagnostics = fixture_diagnostic_path(dir.path());
    let events = dir.path().join("events.jsonl");
    let mut writer = EventWriter::anonymous_test_sink(std::fs::File::create(&events).unwrap());
    let fault = crate::inventory_events::EventFault {
        kind: "started",
        final_pass_only: false,
        after_ended: false,
        attempts: Default::default(),
    };
    let attempts = fault.attempts.clone();
    writer.fault = Some(fault);
    let mut stream = EventLogState::new(Some(writer));
    let mut coordinator = coordinator();
    let mut diagnostics_state = fixture_diagnostics(&diagnostics, Some(&report), None);
    diagnostics_state.enable(
        &mut coordinator,
        CaptureMode::Auto,
        InspectScope::System,
        None,
    );
    let error = start_event_log(&mut stream, &coordinator, "system", 1).unwrap();
    assert!(error.to_string().contains("started append failure"));
    let presentation = Presentation::capture(&coordinator, "system", 1, 2, 0);
    let mut stdout = Vec::new();
    let outcome = finish_runtime_output(
        Some(crate::output::atomic_file_test_fixture(&report)),
        &mut stream,
        &mut StreamState::new(),
        &presentation,
        true,
        false,
        &mut WriterStdout(&mut stdout),
        None,
        &mut coordinator,
        Some(diagnostics_state),
        diagnostic_outcome(false, true, false),
        &|| false,
        &mut |_| {},
    );
    assert_eq!(
        *attempts.borrow(),
        ["started"],
        "a failed prologue must retire its writer"
    );
    assert_eq!(outcome.event_log_confirmed, Some(false));
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(std::fs::read(report).unwrap(), stdout);
    assert_eq!(
        records(&diagnostics).last().unwrap()["capture_outcome"],
        "failed"
    );
}

#[test]
fn failed_native_startup_cannot_complete_event_stream() {
    let dir = private_tempdir();
    let report = dir.path().join("report.json");
    let diagnostics = fixture_diagnostic_path(dir.path());
    let events = dir.path().join("events.jsonl");
    let writer = EventWriter::anonymous_test_sink(std::fs::File::create(&events).unwrap());
    let mut stream = EventLogState::new(Some(writer));
    let mut coordinator = coordinator();
    let mut diagnostics_state = fixture_diagnostics(&diagnostics, Some(&report), None);
    diagnostics_state.enable(
        &mut coordinator,
        CaptureMode::Native,
        InspectScope::Pid(u32::MAX),
        None,
    );
    let error = open_native_lane(
        CaptureMode::Native,
        crate::attach::BackendSelection::Auto,
        InspectScope::Pid(u32::MAX),
        &mut coordinator,
    )
    .err()
    .unwrap();
    let mut stdout = Vec::new();
    let finalized = Cell::new(false);
    let outcome = finish_failed_startup(
        &mut coordinator,
        "pid:4294967295",
        1,
        Some(crate::output::atomic_file_test_fixture(&report)),
        &mut stream,
        Some(diagnostics_state),
        true,
        &mut WriterStdout(&mut stdout),
        &error,
        &|| false,
        &|| finalized.set(true),
    );
    assert_eq!(outcome.event_log_confirmed, Some(false));
    assert!(
        std::fs::read(events).unwrap().is_empty(),
        "no event observation started"
    );
    assert_eq!(std::fs::read(report).unwrap(), stdout);
    assert!(finalized.get());
    assert_eq!(
        records(&diagnostics).last().unwrap()["capture_outcome"],
        "failed"
    );
}
