//! SPDX-License-Identifier: GPL-3.0-or-later
//! Independent, atomic delivery of the completed inventory diagnostics.

use crate::inventory_diagnostics::{DiagnosticSummary, FinishedDiagnostics, RetainedIdentityView};
use crate::output::AtomicFile;
use std::ffi::OsStr;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

// A diagnostics-only validation must not add an unbounded directory walk.
const MAX_DIRECTORY_VISITS: usize = 4096;

#[derive(Debug)]
pub(crate) enum PrepareError {
    Conflict(String),
    Unavailable(String),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict(message) | Self::Unavailable(message) => formatter.write_str(message),
        }
    }
}
impl std::error::Error for PrepareError {}

pub(crate) struct DiagnosticsDestination {
    path: PathBuf,
    report: Option<PathBuf>,
    event_log: Option<PathBuf>,
    output: AtomicFile,
}

impl DiagnosticsDestination {
    /// Must run before creating the event stream, whose open can truncate.
    /// Existing-rotation identity validation visits at most 4,096 directory
    /// entries. An incomplete check is Unavailable, never proof of safety.
    pub(crate) fn prepare(
        path: &Path,
        report: Option<&Path>,
        event_log: Option<&Path>,
    ) -> Result<Self, PrepareError> {
        validate_aliases(path, report, event_log)?;
        let normalized = normalize(path)?;
        let output = AtomicFile::create(path).map_err(PrepareError::Unavailable)?;
        Ok(Self {
            path: normalized,
            report: report.map(normalize).transpose()?,
            event_log: event_log.map(normalize).transpose()?,
            output,
        })
    }

    /// Called after primary report attempts. Cancellation is the second signal.
    pub(crate) fn deliver(
        mut self,
        finished: FinishedDiagnostics,
        view: &impl RetainedIdentityView,
        mut second_signal: impl FnMut() -> bool,
    ) -> Result<DiagnosticSummary, String> {
        let summary = finished
            .write_jsonl(self.output.file(), view, &mut second_signal)
            .map_err(|error| {
                format!(
                    "writing diagnostics {} failed: {error}",
                    self.path.display()
                )
            })?;
        if second_signal() {
            return Err(format!(
                "diagnostics export cancelled: {}",
                self.path.display()
            ));
        }
        validate_aliases_with_identity(
            &self.path,
            || {
                self.output
                    .destination_identity()
                    .map_err(PrepareError::Unavailable)
            },
            self.report.as_deref(),
            self.event_log.as_deref(),
        )
        .map_err(|error| {
            format!(
                "checking diagnostics {} aliases before publication failed: {error}",
                self.path.display()
            )
        })?;
        if second_signal() {
            return Err(format!(
                "diagnostics export cancelled: {}",
                self.path.display()
            ));
        }
        self.output.commit().map_err(|error| {
            format!(
                "publishing diagnostics {} failed: {error}",
                self.path.display()
            )
        })?;
        Ok(summary)
    }
}

fn validate_aliases(
    path: &Path,
    report: Option<&Path>,
    event_log: Option<&Path>,
) -> Result<(), PrepareError> {
    validate_aliases_with_identity(path, || existing_identity(path), report, event_log)
}

fn validate_aliases_with_identity(
    path: &Path,
    identity: impl FnOnce() -> Result<Option<(u64, u64)>, PrepareError>,
    report: Option<&Path>,
    event_log: Option<&Path>,
) -> Result<(), PrepareError> {
    // Independent known aliases take precedence over an unavailable check.
    // Start with lexical equality before touching any filesystem path.
    for (kind, other) in [("report", report), ("event-log", event_log)] {
        if let Some(other) = other
            && path == other
        {
            return Err(conflict(path, kind, other));
        }
    }
    let mut unavailable = None;
    let normalized = available(normalize(path), &mut unavailable);
    let normalized_report = report.and_then(|path| available(normalize(path), &mut unavailable));
    let live = event_log.and_then(|path| available(normalize(path), &mut unavailable));
    for (kind, other) in [
        ("report", normalized_report.as_deref()),
        ("event-log", live.as_deref()),
    ] {
        if let (Some(normalized), Some(other)) = (normalized.as_deref(), other)
            && normalized == other
        {
            return Err(conflict(path, kind, other));
        }
    }
    // rotated_path spells the basename through to_string_lossy, then adds
    // the canonical decimal u64 sequence. Preserve that exact namespace.
    let prefix = live
        .as_ref()
        .map(|live| format!("{}.", live.file_name().unwrap().to_string_lossy()));
    if let (Some(normalized), Some(live), Some(prefix)) =
        (normalized.as_deref(), live.as_deref(), prefix.as_deref())
        && normalized.parent() == live.parent()
        && rotation_name(normalized.file_name().unwrap(), prefix)
    {
        return Err(conflict(path, "event-log rotation", live));
    }
    // Also check identities for spellings AtomicFile will later refuse, and
    // continue other identity/rotation checks if one destination is unreadable.
    let identity = available(identity(), &mut unavailable).flatten();
    if let Some(identity) = identity {
        for (kind, other) in [("report", report), ("event-log", event_log)] {
            if let Some(other) = other
                && available(existing_identity(other), &mut unavailable).flatten() == Some(identity)
            {
                return Err(conflict(path, kind, other));
            }
        }
        if let (Some(live), Some(prefix)) = (live.as_deref(), prefix.as_deref()) {
            let parent = live.parent().unwrap();
            if let Some(mut entries) = available(
                std::fs::read_dir(parent).map_err(|error| unavailable_at(parent, error)),
                &mut unavailable,
            ) {
                let mut complete = false;
                for _ in 0..MAX_DIRECTORY_VISITS {
                    let Some(entry) = entries.next() else {
                        complete = true;
                        break;
                    };
                    let Some(entry) = available(
                        entry.map_err(|error| unavailable_at(parent, error)),
                        &mut unavailable,
                    ) else {
                        continue;
                    };
                    if rotation_name(&entry.file_name(), prefix)
                        && available(existing_identity(&entry.path()), &mut unavailable).flatten()
                            == Some(identity)
                    {
                        return Err(conflict(path, "event-log rotation", &entry.path()));
                    }
                }
                if !complete {
                    unavailable.get_or_insert_with(|| PrepareError::Unavailable(format!(
                        "diagnostics alias validation in {} could not complete within {MAX_DIRECTORY_VISITS} directory visits",
                        parent.display()
                    )));
                }
            }
        }
    }
    unavailable.map_or(Ok(()), Err)
}

fn available<T>(result: Result<T, PrepareError>, error: &mut Option<PrepareError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(unavailable) => {
            error.get_or_insert(unavailable);
            None
        }
    }
}

fn rotation_name(name: &OsStr, prefix: &str) -> bool {
    let Some(number) = name.to_str().and_then(|name| name.strip_prefix(prefix)) else {
        return false;
    };
    number
        .parse::<u64>()
        .is_ok_and(|sequence| sequence.to_string() == number)
}

fn normalize(path: &Path) -> Result<PathBuf, PrepareError> {
    crate::output::normalize_output_path(path.to_path_buf()).map_err(PrepareError::Unavailable)
}

fn existing_identity(path: &Path) -> Result<Option<(u64, u64)>, PrepareError> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some((metadata.dev(), metadata.ino()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(unavailable_at(path, error)),
    }
}

fn unavailable_at(path: &Path, error: io::Error) -> PrepareError {
    PrepareError::Unavailable(format!(
        "checking diagnostics destination aliases at {} failed: {error}",
        path.display()
    ))
}

fn conflict(path: &Path, kind: &str, other: &Path) -> PrepareError {
    PrepareError::Conflict(format!(
        "diagnostics {} aliases {kind} destination {}",
        path.display(),
        other.display()
    ))
}

#[cfg(test)]
pub(crate) use tests::fixture_destination;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory_diagnostics::{
        CaptureOutcome, CaptureSettlement, DiagnosticConfig, DiagnosticKind, DiagnosticOutcome,
        DiagnosticRecord, Recorder,
    };
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

    struct NoLabels;
    impl RetainedIdentityView for NoLabels {
        fn application(&self, _: u32) -> Option<&str> {
            None
        }
        fn module(&self, _: u32) -> Option<&str> {
            None
        }
    }

    fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn finished(outcome: CaptureOutcome) -> FinishedDiagnostics {
        let mut recorder = Recorder::try_new(DiagnosticConfig {
            ordinary_capacity: 2,
            exceptional_capacity: 2,
            ..DiagnosticConfig::default()
        })
        .unwrap();
        recorder.record(DiagnosticRecord::new(DiagnosticKind::CountObservation));
        recorder.finish(DiagnosticOutcome {
            capture_outcome: outcome,
            capture_settlement: CaptureSettlement::Settled,
        })
    }

    // This fixture retains a trusted private directory directly, without
    // changing the production ancestor walk. The real-path test below still
    // exercises prepare and the full trust policy on ordinary hosts.
    pub(crate) fn fixture_destination(
        path: &Path,
        report: Option<&Path>,
        event_log: Option<&Path>,
    ) -> DiagnosticsDestination {
        DiagnosticsDestination {
            path: path.to_path_buf(),
            report: report.map(Path::to_path_buf),
            event_log: event_log.map(Path::to_path_buf),
            output: crate::output::atomic_file_test_fixture(path),
        }
    }

    fn assert_no_temporary_files(directory: &Path) {
        for entry in std::fs::read_dir(directory).unwrap() {
            assert!(
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".p11scope.")
            );
        }
    }

    #[test]
    fn aliases_are_refused_before_event_stream_can_truncate() {
        let directory = private_directory();
        let live = directory.path().join("events.jsonl");
        std::fs::write(&live, b"previous events").unwrap();
        let error = DiagnosticsDestination::prepare(
            &directory.path().join("./events.jsonl"),
            None,
            Some(&live),
        )
        .err()
        .expect("an event destination alias must be invalid");
        assert!(matches!(error, PrepareError::Conflict(_)));
        assert_eq!(std::fs::read(&live).unwrap(), b"previous events");
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn known_event_alias_is_not_masked_by_an_unavailable_report_path() {
        for invalid_syntax in [false, true] {
            let directory = private_directory();
            let events = directory.path().join("events.jsonl");
            let report = if invalid_syntax {
                // No existing event inode: lexical equality must win even
                // when another destination cannot be normalized.
                directory.path().join("missing/../report.json")
            } else {
                std::fs::write(&events, b"previous events").unwrap();
                let loop_path = directory.path().join("report-loop");
                std::os::unix::fs::symlink("report-loop", &loop_path).unwrap();
                loop_path
            };
            let error = DiagnosticsDestination::prepare(
                &directory.path().join("./events.jsonl"),
                Some(&report),
                Some(&events),
            )
            .err()
            .expect("the known event destination alias must be refused");
            assert!(matches!(error, PrepareError::Conflict(_)), "{error}");
            if !invalid_syntax {
                assert_eq!(std::fs::read(&events).unwrap(), b"previous events");
            }
            assert_no_temporary_files(directory.path());
        }
    }

    #[test]
    fn known_event_alias_hardlinks_are_not_masked_by_an_unreadable_report() {
        for target_name in ["events.jsonl", "events.jsonl.73"] {
            let directory = private_directory();
            let target = directory.path().join(target_name);
            let diagnostics = directory.path().join("diagnostics.jsonl");
            let report = directory.path().join("report-loop");
            let events = directory.path().join("events.jsonl");
            std::fs::write(&target, b"previous events").unwrap();
            std::fs::hard_link(&target, &diagnostics).unwrap();
            std::os::unix::fs::symlink("report-loop", &report).unwrap();
            let error = DiagnosticsDestination::prepare(&diagnostics, Some(&report), Some(&events))
                .err()
                .expect("an existing event identity alias must be refused");
            assert!(matches!(error, PrepareError::Conflict(_)), "{error}");
            assert_eq!(std::fs::read(&target).unwrap(), b"previous events");
            assert_no_temporary_files(directory.path());
        }
    }

    #[test]
    fn relative_and_absolute_report_aliases_are_invalid() {
        let relative = Path::new("diagnostics-report-alias.json");
        let absolute = std::env::current_dir().unwrap().join(relative);
        assert!(matches!(
            validate_aliases(relative, Some(&absolute), None),
            Err(PrepareError::Conflict(_))
        ));
    }

    #[test]
    fn existing_hardlinks_to_report_live_and_rotated_event_files_are_invalid() {
        for target in ["report.json", "events.jsonl", "events.jsonl.73"] {
            let directory = private_directory();
            let source = directory.path().join(target);
            let diagnostics = directory.path().join("diagnostics.jsonl");
            std::fs::write(&source, b"prior destination").unwrap();
            std::fs::hard_link(&source, &diagnostics).unwrap();
            let report = directory.path().join("report.json");
            let events = directory.path().join("events.jsonl");
            assert!(
                matches!(
                    validate_aliases(&diagnostics, Some(&report), Some(&events)),
                    Err(PrepareError::Conflict(_))
                ),
                "hardlink to {target}"
            );
            assert_eq!(std::fs::read(&source).unwrap(), b"prior destination");
        }
    }

    #[test]
    fn future_rotation_namespace_matches_actual_lossy_utf8_spelling() {
        let directory = private_directory();
        let live = directory
            .path()
            .join(std::ffi::OsStr::from_bytes(b"events\xff"));
        for name in ["events\u{fffd}.1", "events\u{fffd}.18446744073709551615"] {
            assert!(
                matches!(
                    validate_aliases(&directory.path().join(name), None, Some(&live)),
                    Err(PrepareError::Conflict(_))
                ),
                "future rotation {name}"
            );
        }
        for name in [
            "events\u{fffd}.01",
            "events\u{fffd}.notes",
            "events\u{fffd}.18446744073709551616",
        ] {
            validate_aliases(&directory.path().join(name), None, Some(&live)).unwrap();
        }
    }

    #[test]
    fn unrelated_destinations_do_not_create_any_file_at_validation() {
        let directory = private_directory();
        validate_aliases(
            &directory.path().join("diagnostics.jsonl"),
            Some(&directory.path().join("report.json")),
            Some(&directory.path().join("events.jsonl")),
        )
        .unwrap();
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn incomplete_rotation_identity_scan_disables_diagnostics_without_claiming_safety() {
        let directory = private_directory();
        let diagnostics = directory.path().join("diagnostics.jsonl");
        std::fs::write(&diagnostics, b"old diagnostics").unwrap();
        for index in 0..4097 {
            std::fs::write(directory.path().join(format!("unrelated-{index}")), b"").unwrap();
        }
        let error = validate_aliases(
            &diagnostics,
            None,
            Some(&directory.path().join("events.jsonl")),
        )
        .unwrap_err();
        assert!(matches!(error, PrepareError::Unavailable(_)));
        assert_eq!(std::fs::read(diagnostics).unwrap(), b"old diagnostics");
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn missing_parent_is_a_diagnostics_only_open_failure() {
        let directory = private_directory();
        let error = DiagnosticsDestination::prepare(
            &directory.path().join("missing/diagnostics.jsonl"),
            None,
            None,
        )
        .err()
        .expect("missing parent cannot open");
        assert!(matches!(error, PrepareError::Unavailable(_)));
    }

    #[test]
    fn unsafe_diagnostics_targets_are_refused_without_touching_old_data() {
        let directory = private_directory();
        let target = directory.path().join("target");
        std::fs::write(&target, b"keep old data").unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let fifo = directory.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        for path in [&link, &fifo] {
            assert!(matches!(
                DiagnosticsDestination::prepare(path, None, None),
                Err(PrepareError::Unavailable(_))
            ));
        }
        assert_eq!(std::fs::read(target).unwrap(), b"keep old data");
        assert!(
            std::fs::symlink_metadata(link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            std::fs::symlink_metadata(fifo)
                .unwrap()
                .file_type()
                .is_fifo()
        );
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn real_preflight_and_delivery_publish_private_complete_jsonl() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        let destination = DiagnosticsDestination::prepare(&path, None, None).unwrap();
        destination
            .deliver(finished(CaptureOutcome::Completed), &NoLabels, || false)
            .unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let data = std::fs::read_to_string(&path).unwrap();
        let last: serde_json::Value = serde_json::from_str(data.lines().last().unwrap()).unwrap();
        assert_eq!(last["kind"], "footer");
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn normal_stop_exports_footer_without_cancelling_delivery() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        std::fs::write(&path, b"old diagnostics").unwrap();
        let destination = fixture_destination(&path, None, None);
        let summary = destination
            .deliver(finished(CaptureOutcome::Stopped), &NoLabels, || false)
            .unwrap();
        assert_eq!(summary.records_written, 1);
        let data = std::fs::read_to_string(&path).unwrap();
        let footer: serde_json::Value = serde_json::from_str(data.lines().last().unwrap()).unwrap();
        assert_eq!(footer["kind"], "footer");
        assert_eq!(footer["capture_outcome"], "stopped");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn second_signal_during_export_preserves_existing_destination() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        std::fs::write(&path, b"old diagnostics").unwrap();
        let destination = fixture_destination(&path, None, None);
        let mut checks = 0;
        let error = destination
            .deliver(finished(CaptureOutcome::Stopped), &NoLabels, || {
                checks += 1;
                checks >= 2
            })
            .unwrap_err();
        assert!(error.contains("cancelled"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), b"old diagnostics");
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn second_signal_after_footer_prevents_publication() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        std::fs::write(&path, b"old diagnostics").unwrap();
        let destination = fixture_destination(&path, None, None);
        let error = destination
            .deliver(finished(CaptureOutcome::Stopped), &NoLabels, || {
                let temporary = std::fs::read_dir(directory.path())
                    .unwrap()
                    .find_map(|entry| {
                        let entry = entry.unwrap();
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".p11scope.")
                            .then(|| entry.path())
                    })
                    .unwrap();
                std::fs::read_to_string(temporary)
                    .unwrap()
                    .lines()
                    .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .any(|line| line["kind"] == "footer")
            })
            .unwrap_err();
        assert!(error.contains("cancelled"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), b"old diagnostics");
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn alias_introduced_during_export_is_rechecked_before_commit() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        let report = directory.path().join("report.json");
        std::fs::write(&path, b"old diagnostics").unwrap();
        std::fs::write(&report, b"primary report").unwrap();
        let destination = fixture_destination(&path, Some(&report), None);
        let mut swapped = false;
        let error = destination
            .deliver(finished(CaptureOutcome::Completed), &NoLabels, || {
                if !swapped {
                    std::fs::remove_file(&path).unwrap();
                    std::fs::hard_link(&report, &path).unwrap();
                    swapped = true;
                }
                false
            })
            .unwrap_err();
        assert!(error.contains("alias"), "{error}");
        assert_eq!(std::fs::read(&report).unwrap(), b"primary report");
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            std::fs::metadata(&report).unwrap().ino()
        );
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn revalidation_uses_retained_destination_when_its_parent_is_renamed() {
        let directory = private_directory();
        let capture_directory = directory.path().join("capture");
        std::fs::create_dir(&capture_directory).unwrap();
        std::fs::set_permissions(&capture_directory, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let path = capture_directory.join("diagnostics.jsonl");
        let report = directory.path().join("report.json");
        let moved_directory = directory.path().join("moved");
        std::fs::write(&path, b"old diagnostics").unwrap();
        std::fs::write(&report, b"primary report").unwrap();
        let destination = fixture_destination(&path, Some(&report), None);
        let mut moved = false;
        let error = destination
            .deliver(finished(CaptureOutcome::Completed), &NoLabels, || {
                if !moved {
                    std::fs::remove_file(&report).unwrap();
                    std::fs::hard_link(&path, &report).unwrap();
                    std::fs::rename(&capture_directory, &moved_directory).unwrap();
                    moved = true;
                }
                false
            })
            .unwrap_err();
        assert!(error.contains("alias"), "{error}");
        assert_eq!(std::fs::read(&report).unwrap(), b"old diagnostics");
        assert_eq!(
            std::fs::read(moved_directory.join("diagnostics.jsonl")).unwrap(),
            b"old diagnostics"
        );
        assert_no_temporary_files(&moved_directory);
    }

    #[test]
    fn damaged_temporary_file_fails_delivery_and_preserves_old_destination() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        std::fs::write(&path, b"old diagnostics").unwrap();
        let destination = fixture_destination(&path, None, None);
        let mut damaged = false;
        let result = destination.deliver(finished(CaptureOutcome::Completed), &NoLabels, || {
            if !damaged {
                let temporary = std::fs::read_dir(directory.path())
                    .unwrap()
                    .find_map(|entry| {
                        let entry = entry.unwrap();
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".p11scope.")
                            .then(|| entry.path())
                    })
                    .unwrap();
                std::fs::remove_file(temporary).unwrap();
                damaged = true;
            }
            false
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"old diagnostics");
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn actual_write_failure_preserves_existing_destination_and_cleans_temporary_file() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        std::fs::write(&path, b"old diagnostics").unwrap();
        let mut destination = fixture_destination(&path, None, None);
        crate::output::atomic_file_test_fixture_read_only(&mut destination.output);
        assert!(
            destination
                .deliver(finished(CaptureOutcome::Completed), &NoLabels, || false)
                .is_err()
        );
        assert_eq!(std::fs::read(path).unwrap(), b"old diagnostics");
        assert_no_temporary_files(directory.path());
    }
}
