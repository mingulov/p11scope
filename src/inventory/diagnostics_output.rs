//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Independent, atomic delivery of the completed inventory diagnostics.

use crate::inventory_diagnostics::{
    DiagnosticSummary, ExportError, FinishedDiagnostics, RetainedIdentityView,
};
use crate::output::AtomicFile;
use std::cell::RefCell;
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
    ///
    /// The export streams each line (fixed 8 KiB scratch, cancellation
    /// checked between records) to the `-o` temp, with bounded heap:
    /// no in-memory copy of the complete file while the rings and
    /// export indexes are live. The primary keeps priority: no
    /// recovery file or dir is created while it stays healthy, so a
    /// staging cannot consume the space the primary needs. On the
    /// first primary write error the export checks cancellation, then
    /// lazily opens a private disk-backed recovery staging and replays
    /// the confirmed prefix (tracked before each attempted record, so
    /// a partial write cannot duplicate) from the held readable
    /// primary FD with bounded scratch and cancellation checks; the
    /// failing record and the tail then continue there. A short `-o`
    /// write finishes the staging instead of dropping the export.
    /// Cancellation is checked before starting recovery; a cancelled
    /// export aborts its staging and leaves the old destination
    /// intact.
    pub(crate) fn deliver(
        mut self,
        finished: FinishedDiagnostics,
        view: &impl RetainedIdentityView,
        mut second_signal: impl FnMut() -> bool,
    ) -> Result<DiagnosticSummary, String> {
        let base = crate::output::recovered_base_dir();
        // Stream the export through the lazy writer; it borrows the
        // `-o` temp only for this block, so the tail below reclaims
        // it. The writer and `write_jsonl` share the cancellation
        // closure through the cell (never called reentrantly: record
        // writes and record-boundary polls strictly alternate).
        let (export, primary_failed, primary_error, staging, creation_error, staging_error) = {
            let cancel: RefCell<&mut dyn FnMut() -> bool> = RefCell::new(&mut second_signal);
            let mut writer = LazyRecoveryWriter {
                output: &mut self.output,
                dest: self.path.clone(),
                base: base.clone(),
                confirmed: 0,
                primary_failed: false,
                primary_error: None,
                staging: None,
                creation_error: None,
                staging_error: None,
                cancel: &cancel,
            };
            let export = finished.write_jsonl(&mut writer, view, || (*cancel.borrow_mut())());
            (
                export,
                writer.primary_failed,
                writer.primary_error,
                writer.staging.take(),
                writer.creation_error,
                writer.staging_error,
            )
        };
        // From here the writer is gone; `second_signal`,
        // `self.output` and `staging` are usable again.
        match export {
            Ok(summary) => {
                if primary_failed {
                    let Some(staging) = staging else {
                        // Primary failed with no surviving staging
                        // (creation failed, or a staging write failed
                        // mid-export but the export still returned
                        // success, which the lazy writer never does):
                        // both errors, as lost.
                        if second_signal() {
                            return Err(format!(
                                "diagnostics export cancelled: {}",
                                self.path.display()
                            ));
                        }
                        let second = creation_error
                            .or(staging_error)
                            .unwrap_or_else(|| "unknown error".to_string());
                        return Err(format!(
                            "writing diagnostics {} failed: {}; saving to {} also failed: {second}; capture lost",
                            self.path.display(),
                            primary_error.unwrap_or_else(|| "unknown error".to_string()),
                            base.display(),
                        ));
                    };
                    // The `-o` temp holds at most a partial write; the
                    // staging holds the complete export. Check
                    // cancellation before starting recovery.
                    if second_signal() {
                        staging.abort();
                        return Err(format!(
                            "diagnostics export cancelled: {}",
                            self.path.display()
                        ));
                    }
                    let failure = self.output.fail_streaming_write_with_recovery(
                        staging,
                        format!(
                            "writing diagnostics {} failed: {}",
                            self.path.display(),
                            primary_error.unwrap_or_else(|| "unknown error".to_string()),
                        ),
                    );
                    return Err(failure.into_message());
                }
                // Primary holds the complete export; no staging was
                // created. Dropping the (absent) staging is a no-op.
                drop(staging);
                // Fall through with `summary` to the publication tail.
                Self::publish_tail(self, summary, &mut second_signal)
            }
            Err(error) => {
                // The lazy writer failed both sinks (the primary, then
                // the recovery setup or write), or the export was
                // cancelled, or a line could not serialize. Abort any
                // partial staging and leave the old destination intact.
                drop(staging);
                if second_signal() {
                    return Err(format!(
                        "diagnostics export cancelled: {}",
                        self.path.display()
                    ));
                }
                // A primary I/O failure plus a failed recovery setup or
                // write reports both causes with the loss outcome, as
                // the buffered sites do. Cancellation and serialization
                // stay distinct.
                if primary_failed && matches!(error, ExportError::Io(_)) {
                    let second = creation_error
                        .or(staging_error)
                        .unwrap_or_else(|| "unknown error".to_string());
                    return Err(format!(
                        "writing diagnostics {} failed: {}; saving to {} also failed: {second}; capture lost",
                        self.path.display(),
                        primary_error.unwrap_or_else(|| "unknown error".to_string()),
                        base.display(),
                    ));
                }
                Err(format!(
                    "writing diagnostics {} failed: {error}",
                    self.path.display()
                ))
            }
        }
    }

    /// The post-export publication tail: cancellation, alias
    /// revalidation, cancellation, commit. Split so the streaming head
    /// above returns early on write failure without duplicating it.
    fn publish_tail(
        destination: DiagnosticsDestination,
        summary: DiagnosticSummary,
        second_signal: &mut impl FnMut() -> bool,
    ) -> Result<DiagnosticSummary, String> {
        if second_signal() {
            return Err(format!(
                "diagnostics export cancelled: {}",
                destination.path.display()
            ));
        }
        validate_aliases_with_identity(
            &destination.path,
            || {
                destination
                    .output
                    .destination_identity()
                    .map_err(PrepareError::Unavailable)
            },
            destination.report.as_deref(),
            destination.event_log.as_deref(),
        )
        .map_err(|error| {
            format!(
                "checking diagnostics {} aliases before publication failed: {error}",
                destination.path.display()
            )
        })?;
        if second_signal() {
            return Err(format!(
                "diagnostics export cancelled: {}",
                destination.path.display()
            ));
        }
        destination.output.commit().map_err(|error| {
            format!(
                "publishing diagnostics {} failed: {error}",
                destination.path.display()
            )
        })?;
        Ok(summary)
    }
}

/// Streams each export line to the `-o` temp with bounded heap.
/// The primary keeps priority: no recovery file or dir exists while
/// it stays healthy. On the first primary write error the writer
/// checks cancellation, lazily opens a recovery staging, replays the
/// confirmed prefix from the held readable primary FD, and continues
/// the failing record plus the tail there. The confirmed prefix is
/// tracked before each attempted record, so a partial primary write
/// cannot duplicate. Both sinks failed is an I/O error carrying the
/// primary cause; the recovery cause travels in `creation_error` or
/// `staging_error` for the delivery boundary to report both as lost.
struct LazyRecoveryWriter<'cell, 'signal> {
    output: &'cell mut AtomicFile,
    dest: PathBuf,
    base: PathBuf,
    confirmed: u64,
    primary_failed: bool,
    primary_error: Option<String>,
    staging: Option<crate::output::RecoveryStaging>,
    creation_error: Option<String>,
    staging_error: Option<String>,
    cancel: &'cell RefCell<&'signal mut dyn FnMut() -> bool>,
}

/// Why a confirmed-prefix replay failed: cancellation (the delivery
/// boundary reports `cancelled`) or an I/O cause (reported as the
/// recovery side of a double failure).
enum ReplayOutcome {
    Cancelled,
    Failed(String),
}

impl LazyRecoveryWriter<'_, '_> {
    /// Fails over to recovery after a primary write error: checks
    /// cancellation, lazily opens the staging, replays the confirmed
    /// prefix, and writes the failing record's bytes there. Returns
    /// the full length on success; on any failure records the cause
    /// and returns the primary error for the export to abort with.
    fn fail_over(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if (*self.cancel.borrow_mut())() {
            return Err(self.primary_io_error());
        }
        match crate::output::RecoveryStaging::create(&self.dest, &self.base) {
            Ok(staging) => {
                self.staging = Some(staging);
            }
            Err(error) => {
                self.creation_error = Some(error);
                return Err(self.primary_io_error());
            }
        }
        match self.replay_prefix() {
            Ok(()) => {}
            Err(ReplayOutcome::Cancelled) => {
                return Err(self.primary_io_error());
            }
            Err(ReplayOutcome::Failed(error)) => {
                self.staging_error = Some(error);
                self.staging = None;
                return Err(self.primary_io_error());
            }
        }
        let write_result = match self.staging.as_mut() {
            Some(staging) => std::io::Write::write_all(staging, bytes),
            None => unreachable!("a replayed staging accepts the failing record"),
        };
        match write_result {
            Ok(()) => Ok(bytes.len()),
            Err(error) => {
                self.staging_error = Some(error.to_string());
                self.staging = None;
                Err(self.primary_io_error())
            }
        }
    }

    /// Replays the confirmed prefix from the held readable primary FD
    /// into the staging with fixed 8 KiB scratch, checking
    /// cancellation between chunks. The primary is abandoned after
    /// failover, so moving its shared offset is harmless.
    fn replay_prefix(&mut self) -> Result<(), ReplayOutcome> {
        let Some(staging) = self.staging.as_mut() else {
            return Err(ReplayOutcome::Failed(
                "recovery staging is gone".to_string(),
            ));
        };
        let mut src = self.output.file().try_clone().map_err(|error| {
            ReplayOutcome::Failed(format!(
                "reading confirmed prefix for recovery failed: {error}"
            ))
        })?;
        use std::io::{Read as _, Seek as _, SeekFrom};
        src.seek(SeekFrom::Start(0)).map_err(|error| {
            ReplayOutcome::Failed(format!(
                "reading confirmed prefix for recovery failed: {error}"
            ))
        })?;
        let mut remaining = self.confirmed;
        let mut scratch = [0u8; 8 * 1024];
        while remaining > 0 {
            if (*self.cancel.borrow_mut())() {
                return Err(ReplayOutcome::Cancelled);
            }
            let want = std::cmp::min(remaining, scratch.len() as u64) as usize;
            let got = src.read(&mut scratch[..want]).map_err(|error| {
                ReplayOutcome::Failed(format!(
                    "reading confirmed prefix for recovery failed: {error}"
                ))
            })?;
            if got == 0 {
                return Err(ReplayOutcome::Failed(
                    "reading confirmed prefix for recovery failed: unexpected end of file"
                        .to_string(),
                ));
            }
            std::io::Write::write_all(staging, &scratch[..got])
                .map_err(|error| ReplayOutcome::Failed(error.to_string()))?;
            remaining -= got as u64;
        }
        Ok(())
    }

    /// Writes directly to the surviving staging after failover. A
    /// staging failure drops it (unlinking the partial file) and
    /// aborts the export with the primary cause; the recovery cause
    /// stays in `staging_error` for the double-failure line.
    fn write_to_staging(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let write_result = match self.staging.as_mut() {
            Some(staging) => std::io::Write::write_all(staging, bytes),
            None => return Err(self.primary_io_error()),
        };
        match write_result {
            Ok(()) => Ok(bytes.len()),
            Err(error) => {
                self.staging_error = Some(error.to_string());
                self.staging = None;
                Err(self.primary_io_error())
            }
        }
    }

    fn primary_io_error(&self) -> std::io::Error {
        std::io::Error::other(
            self.primary_error
                .clone()
                .unwrap_or_else(|| "diagnostics write failed".to_string()),
        )
    }
}

impl std::io::Write for LazyRecoveryWriter<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.primary_failed {
            return self.write_to_staging(bytes);
        }
        match self.output.write_document(bytes) {
            Ok(()) => {
                self.confirmed += bytes.len() as u64;
                Ok(bytes.len())
            }
            Err(error) => {
                self.primary_failed = true;
                self.primary_error = Some(error.to_string());
                self.fail_over(bytes)
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
        // The streaming export stages to the recovery dir: hold the
        // override so the staging lands in this test's own dir.
        let recovered_base = directory.path().join("p11scope-recovered");
        let _override = crate::output::hold_recovered_override(&recovered_base);
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
        let recovered_base = directory.path().join("p11scope-recovered");
        let _override = crate::output::hold_recovered_override(&recovered_base);
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

    /// A diagnostics `-o` write failure (ENOSPC here) saves the
    /// finished export to the recovery dir instead of dropping it:
    /// the error names the fallback, the saved file is the complete
    /// JSONL export (header through footer), the destination keeps
    /// its old bytes, and no temp litters the directory.
    #[test]
    fn diagnostics_write_failure_saves_the_export_to_recovery() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        std::fs::write(&path, b"old diagnostics").unwrap();
        let recovered_base = directory.path().join("p11scope-recovered");
        let mut destination = fixture_destination(&path, None, None);
        destination.output.set_fail_write_with(libc::ENOSPC);
        let _override = crate::output::hold_recovered_override(&recovered_base);
        let error = destination
            .deliver(finished(CaptureOutcome::Completed), &NoLabels, || false)
            .unwrap_err();
        assert!(
            error.contains("capture saved to"),
            "the error names the fallback, got: {error}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"old diagnostics",
            "the destination keeps its old bytes"
        );
        let saved: Vec<std::path::PathBuf> = std::fs::read_dir(&recovered_base)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(saved.len(), 1, "one fallback file: {saved:?}");
        assert!(
            error.contains(&saved[0].display().to_string()),
            "the error names the fallback path, got: {error}"
        );
        let data = std::fs::read_to_string(&saved[0]).unwrap();
        let lines: Vec<serde_json::Value> = data
            .lines()
            .map(|line| serde_json::from_str(line).expect("export line parses"))
            .collect();
        assert!(lines.len() >= 2, "header through footer: {data}");
        assert_eq!(lines.first().unwrap()["kind"], "header");
        assert_eq!(lines.last().unwrap()["kind"], "footer");
        assert_eq!(lines.last().unwrap()["capture_outcome"], "completed");
        assert_no_temporary_files(directory.path());
    }

    /// A diagnostics `-o` write failure (ENOSPC here) plus a second
    /// signal reports cancellation without a recovery save: the
    /// export checks cancellation before starting recovery, the old
    /// destination keeps its bytes, no fallback file remains, and no
    /// temp litters the directory.
    #[test]
    fn diagnostics_write_failure_plus_cancellation_reports_cancelled_without_recovery() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        std::fs::write(&path, b"old diagnostics").unwrap();
        let recovered_base = directory.path().join("p11scope-recovered");
        let mut destination = fixture_destination(&path, None, None);
        destination.output.set_fail_write_with(libc::ENOSPC);
        let _override = crate::output::hold_recovered_override(&recovered_base);
        let error = destination
            .deliver(finished(CaptureOutcome::Completed), &NoLabels, || {
                // Cancel once the recovery staging holds a footer:
                // the export is complete there, but promotion must
                // still check cancellation first.
                let Ok(entries) = std::fs::read_dir(&recovered_base) else {
                    return false;
                };
                entries.filter_map(|entry| entry.ok()).any(|entry| {
                    std::fs::read_to_string(entry.path())
                        .map(|data| {
                            data.lines()
                                .filter_map(|line| {
                                    serde_json::from_str::<serde_json::Value>(line).ok()
                                })
                                .any(|line| line["kind"] == "footer")
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_err();
        assert!(
            error.contains("cancelled"),
            "cancellation wins over recovery, got: {error}"
        );
        assert!(
            !error.contains("capture saved to"),
            "no recovery save when cancelled, got: {error}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"old diagnostics",
            "the destination keeps its old bytes"
        );
        let saved: Vec<std::path::PathBuf> = std::fs::read_dir(&recovered_base)
            .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
            .unwrap_or_default();
        assert!(
            saved.is_empty(),
            "no fallback file remains when cancelled: {saved:?}"
        );
        assert_no_temporary_files(directory.path());
    }

    #[test]
    fn second_signal_during_export_preserves_existing_destination() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        std::fs::write(&path, b"old diagnostics").unwrap();
        let recovered_base = directory.path().join("p11scope-recovered");
        let _override = crate::output::hold_recovered_override(&recovered_base);
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
        let recovered_base = directory.path().join("p11scope-recovered");
        let _override = crate::output::hold_recovered_override(&recovered_base);
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
        let recovered_base = directory.path().join("p11scope-recovered");
        let _override = crate::output::hold_recovered_override(&recovered_base);
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
        let recovered_base = directory.path().join("p11scope-recovered");
        let _override = crate::output::hold_recovered_override(&recovered_base);
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
        let recovered_base = directory.path().join("p11scope-recovered");
        let _override = crate::output::hold_recovered_override(&recovered_base);
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
        // The failed write saves to the recovery dir: hold the
        // override so the fallback lands in this test's own dir,
        // never a concurrent twin's.
        let recovered_base = directory.path().join("p11scope-recovered");
        let _override = crate::output::hold_recovered_override(&recovered_base);
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

    /// The healthy export for byte-for-byte comparisons: deterministic
    /// (no timestamps in header/footer), so two runs with the same
    /// outcome produce identical bytes. Runs without a budget or
    /// fault, in its own dir, returning the published file's bytes.
    fn healthy_export_bytes() -> Vec<u8> {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        let recovered_base = directory.path().join("p11scope-recovered");
        let _override = crate::output::hold_recovered_override(&recovered_base);
        let destination = fixture_destination(&path, None, None);
        destination
            .deliver(finished(CaptureOutcome::Completed), &NoLabels, || false)
            .unwrap();
        std::fs::read(&path).unwrap()
    }

    /// A single-copy budget (exactly the healthy export's length,
    /// shared by the primary and any recovery staging) must still
    /// publish the complete export byte-for-byte: the healthy write
    /// stays on the primary, and no recovery dir is created. An eager
    /// second file would exhaust the budget and fail.
    #[test]
    fn healthy_export_with_single_copy_budget_succeeds_without_recovery() {
        let expected = healthy_export_bytes();
        assert!(!expected.is_empty(), "the healthy export is non-empty");
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        let recovered_base = directory.path().join("p11scope-recovered");
        let _override = crate::output::hold_recovered_override(&recovered_base);
        let _budget = crate::output::hold_write_budget(expected.len() as u64);
        let destination = fixture_destination(&path, None, None);
        let summary = destination
            .deliver(finished(CaptureOutcome::Completed), &NoLabels, || false)
            .unwrap();
        assert_eq!(summary.records_written, 1);
        let data = std::fs::read(&path).unwrap();
        assert_eq!(
            data, expected,
            "a single-copy budget must yield the complete export byte-for-byte"
        );
        assert!(
            !recovered_base.exists(),
            "a healthy export must not create a recovery dir"
        );
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_no_temporary_files(directory.path());
    }

    /// A mid-stream primary short write (ENOSPC after the header)
    /// saves the complete export to recovery byte-for-byte equal to
    /// the healthy export: the confirmed prefix is replayed once, the
    /// failing record and the tail continue there, and no recovery
    /// file exists before the failure. The destination keeps its old
    /// bytes, and no temp litters the directory.
    #[test]
    fn mid_stream_short_write_replays_prefix_without_duplication() {
        let expected = healthy_export_bytes();
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        std::fs::write(&path, b"old diagnostics").unwrap();
        let recovered_base = directory.path().join("p11scope-recovered");
        let _override = crate::output::hold_recovered_override(&recovered_base);
        let mut destination = fixture_destination(&path, None, None);
        destination.output.set_fail_write_after(1, libc::ENOSPC);
        let mut calls = 0;
        let mut early_staging = false;
        let error = destination
            .deliver(finished(CaptureOutcome::Completed), &NoLabels, || {
                calls += 1;
                // The first two cancellation polls run before the
                // mid-stream failure (before the header, then after
                // the header but before the failing record): no
                // recovery file or dir may exist yet.
                if calls <= 2 {
                    if recovered_base.exists() {
                        early_staging = true;
                    }
                    if let Ok(entries) = std::fs::read_dir(&recovered_base)
                        && entries.filter_map(|entry| entry.ok()).next().is_some()
                    {
                        early_staging = true;
                    }
                }
                false
            })
            .unwrap_err();
        assert!(
            !early_staging,
            "recovery must stay lazy until the primary fails"
        );
        assert!(
            error.contains("capture saved to"),
            "the error names the fallback, got: {error}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"old diagnostics",
            "the destination keeps its old bytes"
        );
        let saved: Vec<std::path::PathBuf> = std::fs::read_dir(&recovered_base)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(saved.len(), 1, "one fallback file: {saved:?}");
        let data = std::fs::read(&saved[0]).unwrap();
        assert_eq!(
            data, expected,
            "the recovery save must equal the healthy export byte-for-byte"
        );
        assert_no_temporary_files(directory.path());
    }

    /// A primary write failure plus a refused recovery setup (a
    /// planted symlink here) reports both errors with `capture lost`:
    /// the operator sees the primary cause and the recovery refusal,
    /// the destination keeps its old bytes, and nothing is written
    /// through the refused base.
    #[test]
    fn diagnostics_write_failure_with_refused_recovery_reports_both_errors_as_lost() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        std::fs::write(&path, b"old diagnostics").unwrap();
        let plant = private_directory();
        let target = plant.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = plant.path().join("p11scope-recovered");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut destination = fixture_destination(&path, None, None);
        destination.output.set_fail_write_with(libc::ENOSPC);
        let _override = crate::output::hold_recovered_override(&link);
        let error = destination
            .deliver(finished(CaptureOutcome::Completed), &NoLabels, || false)
            .unwrap_err();
        let primary = std::io::Error::from_raw_os_error(libc::ENOSPC).to_string();
        assert!(
            error.contains(&primary),
            "the error carries the primary cause, got: {error}"
        );
        assert!(
            error.contains("also failed"),
            "the error names the recovery failure, got: {error}"
        );
        assert!(error.contains("capture lost"), "got: {error}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"old diagnostics",
            "the destination keeps its old bytes"
        );
        let target_files: Vec<std::path::PathBuf> = std::fs::read_dir(&target)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert!(
            target_files.is_empty(),
            "nothing is written through the refused link: {target_files:?}"
        );
        assert_no_temporary_files(directory.path());
    }

    /// A primary write failure plus a failed recovery write (EDQUOT
    /// here) reports both errors with `capture lost`: the operator
    /// sees both causes, the destination keeps its old bytes, and no
    /// partial fallback file remains.
    #[test]
    fn diagnostics_write_failure_with_failed_recovery_write_reports_both_errors_as_lost() {
        let directory = private_directory();
        let path = directory.path().join("diagnostics.jsonl");
        std::fs::write(&path, b"old diagnostics").unwrap();
        let recovered_base = directory.path().join("p11scope-recovered");
        let mut destination = fixture_destination(&path, None, None);
        destination.output.set_fail_write_with(libc::ENOSPC);
        let _override = crate::output::hold_recovered_override(&recovered_base);
        let _staging_fail = crate::output::hold_staging_fail_write(libc::EDQUOT);
        let error = destination
            .deliver(finished(CaptureOutcome::Completed), &NoLabels, || false)
            .unwrap_err();
        let primary = std::io::Error::from_raw_os_error(libc::ENOSPC).to_string();
        let recovery = std::io::Error::from_raw_os_error(libc::EDQUOT).to_string();
        assert!(
            error.contains(&primary),
            "the error carries the primary cause, got: {error}"
        );
        assert!(
            error.contains(&recovery),
            "the error carries the recovery cause, got: {error}"
        );
        assert!(
            error.contains("also failed"),
            "the error names the recovery failure, got: {error}"
        );
        assert!(error.contains("capture lost"), "got: {error}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"old diagnostics",
            "the destination keeps its old bytes"
        );
        let saved: Vec<std::path::PathBuf> = std::fs::read_dir(&recovered_base)
            .map(|entries| entries.map(|entry| entry.unwrap().path()).collect())
            .unwrap_or_default();
        assert!(
            saved.is_empty(),
            "no partial fallback file remains on a double failure: {saved:?}"
        );
        assert_no_temporary_files(directory.path());
    }
}
