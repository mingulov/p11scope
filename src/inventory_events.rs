//! SPDX-License-Identifier: GPL-3.0-or-later
//! U0/D JSONL observation-event stream (amendment A1).
//!
//! Alongside the versioned snapshot JSON, an appendable JSONL stream
//! carries observation events for external observability/monitoring:
//! one JSON object per line, versioned as
//! `p11scope/inventory-events/v1` (see
//! `docs/schema/inventory-events-v1.md`). File transport with
//! size-based rotation and bounded retention; rotation and eviction
//! are explicit events, never silent loss.
//!
//! Privacy bounds and loss accounting apply EXACTLY as to snapshots:
//! events carry the same caller/module/edge/gap shapes the snapshot
//! document carries (plus derived presentation states, never new
//! capture), and every dropped/rotated/evicted event is accounted in
//! a retained event.

use crate::discovery::caller_registry::CallerEvent;
use crate::discovery::engine::inventory_coordinator::PassReport;
use crate::inventory::render_json_from_presentation;
use crate::inventory_present::GapView;
use crate::inventory_present::Presentation;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The versioned event-stream schema id. Consumers dispatch on this
/// exact string; a new id means a new contract.
pub(crate) const EVENT_SCHEMA: &str = "p11scope/inventory-events/v1";

/// Default rotation threshold: start a new file once the current one
/// would exceed this many bytes.
pub(crate) const DEFAULT_ROTATE_BYTES: u64 = 1_048_576;
/// Default retention: the live file plus this many rotated files.
pub(crate) const DEFAULT_MAX_FILES: usize = 5;

/// One retained rotated file: its rotation sequence, the event and
/// byte counts it carries, plus the transitively covered loss — the
/// evicted totals recorded by `retention_evicted` lines INSIDE this
/// file. Evicting a file whose records covered earlier evictions must
/// re-cover those counts, or the chain loses them silently.
#[derive(Debug, Clone)]
struct RetainedFile {
    seq: u64,
    events: u64,
    bytes: u64,
    covered_events: u64,
    covered_bytes: u64,
}

/// Appendable JSONL event writer with rotation + bounded retention.
/// All writes go through [`EventWriter::append`]; rotation checks run
/// before every line, so no single event is ever split or silently
/// dropped. Flushed per event (SIGKILL-safe); synced on rotation and
/// finish.
pub(crate) struct EventWriter {
    path: PathBuf,
    file: File,
    current_bytes: u64,
    events_in_file: u64,
    max_bytes: u64,
    max_files: usize,
    rotation_seq: u64,
    next_seq: u64,
    retained: VecDeque<RetainedFile>,
    rotations: u64,
    evicted_events: u64,
    evicted_bytes: u64,
    live_covered_events: u64,
    live_covered_bytes: u64,
}

impl EventWriter {
    /// Open (or truncate) the live stream file. `max_bytes` must be
    /// non-zero; `max_files` counts the live file plus retained
    /// rotations (minimum 1). Pre-existing `<path>.<N>` rotations are
    /// inventoried so this run's sequence never collides with a prior
    /// run's; prior files are never deleted here — only this run's
    /// retention enforcement evicts, and every eviction is an event.
    pub(crate) fn create(path: &Path, max_bytes: u64, max_files: usize) -> Result<Self, String> {
        if max_bytes == 0 {
            return Err("event rotation threshold must be greater than zero".into());
        }
        let max_files = max_files.max(1);
        let rotation_seq = next_rotation_seq(path);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|error| format!("opening event stream {} failed: {error}", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            current_bytes: 0,
            events_in_file: 0,
            max_bytes,
            max_files,
            rotation_seq,
            next_seq: 0,
            retained: VecDeque::new(),
            rotations: 0,
            evicted_events: 0,
            evicted_bytes: 0,
            live_covered_events: 0,
            live_covered_bytes: 0,
        })
    }

    /// Append one event line: `{"schema","seq","at_ns","kind","event"}`.
    pub(crate) fn append(
        &mut self,
        kind: &str,
        payload: serde_json::Value,
        at_ns: u64,
    ) -> Result<(), String> {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let line = serde_json::json!({
            "schema": EVENT_SCHEMA,
            "seq": seq,
            "at_ns": at_ns,
            "kind": kind,
            "event": payload,
        });
        let mut bytes = serde_json::to_vec(&line)
            .map_err(|error| format!("encoding {kind} event failed: {error}"))?;
        bytes.push(b'\n');
        self.rotate_if_needed(bytes.len() as u64)?;
        self.file
            .write_all(&bytes)
            .map_err(|error| format!("writing {kind} event failed: {error}"))?;
        self.file
            .flush()
            .map_err(|error| format!("flushing {kind} event failed: {error}"))?;
        self.current_bytes = self.current_bytes.saturating_add(bytes.len() as u64);
        self.events_in_file = self.events_in_file.saturating_add(1);
        Ok(())
    }

    /// Write the terminal `ended` event, flush, and sync the live file.
    pub(crate) fn finish(&mut self, payload: serde_json::Value, at_ns: u64) -> Result<(), String> {
        self.append("ended", payload, at_ns)?;
        self.file.sync_all().map_err(|error| {
            format!(
                "syncing event stream {} failed: {error}",
                self.path.display()
            )
        })
    }

    /// Rotation + retention state for tests and the `ended` payload.
    pub(crate) fn rotations(&self) -> u64 {
        self.rotations
    }

    pub(crate) fn evicted_events(&self) -> u64 {
        self.evicted_events
    }

    pub(crate) fn evicted_bytes(&self) -> u64 {
        self.evicted_bytes
    }

    /// Events in the live file (tests assert rotation boundaries).
    #[cfg(test)]
    pub(crate) fn live_events(&self) -> u64 {
        self.events_in_file
    }

    fn rotate_if_needed(&mut self, incoming_len: u64) -> Result<(), String> {
        if self.events_in_file > 0
            && self.current_bytes.saturating_add(incoming_len) > self.max_bytes
        {
            self.rotate()?;
        }
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), String> {
        self.file
            .flush()
            .map_err(|error| format!("flushing event stream before rotation failed: {error}"))?;
        self.file
            .sync_all()
            .map_err(|error| format!("syncing event stream before rotation failed: {error}"))?;
        let seq = self.rotation_seq;
        self.rotation_seq = self.rotation_seq.saturating_add(1);
        let rotated_name = rotated_path(&self.path, seq);
        std::fs::rename(&self.path, &rotated_name).map_err(|error| {
            format!(
                "rotating event stream {} to {} failed: {error}",
                self.path.display(),
                rotated_name.display()
            )
        })?;
        self.retained.push_back(RetainedFile {
            seq,
            events: self.events_in_file,
            bytes: self.current_bytes,
            covered_events: self.live_covered_events,
            covered_bytes: self.live_covered_bytes,
        });
        self.live_covered_events = 0;
        self.live_covered_bytes = 0;
        self.rotations = self.rotations.saturating_add(1);
        self.file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|error| {
                format!(
                    "opening rotated event stream {} failed: {error}",
                    self.path.display()
                )
            })?;
        self.current_bytes = 0;
        self.events_in_file = 0;
        // The rotation marker is the new file's first line: the
        // boundary is explicit, never silent.
        let marker = serde_json::json!({
            "prior_file": rotated_name
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            "prior_events": self.retained.back().map(|file| file.events).unwrap_or(0),
            "prior_bytes": self.retained.back().map(|file| file.bytes).unwrap_or(0),
            "rotation_seq": seq,
        });
        // The marker is small; a degenerate `max_bytes` below one line
        // still fits exactly one event per file (the `events_in_file >
        // 0` guard above prevents a rotate loop).
        let line = serde_json::json!({
            "schema": EVENT_SCHEMA,
            "seq": self.next_seq,
            "at_ns": crate::discovery::caller_registry::now_ns(),
            "kind": "rotated",
            "event": marker,
        });
        self.next_seq = self.next_seq.saturating_add(1);
        let mut bytes = serde_json::to_vec(&line)
            .map_err(|error| format!("encoding rotation marker failed: {error}"))?;
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .map_err(|error| format!("writing rotation marker failed: {error}"))?;
        self.file
            .flush()
            .map_err(|error| format!("flushing rotation marker failed: {error}"))?;
        self.current_bytes = self.current_bytes.saturating_add(bytes.len() as u64);
        self.events_in_file = self.events_in_file.saturating_add(1);
        self.enforce_retention()
    }

    /// Delete oldest rotations past the bound, accounting every
    /// evicted event in a retained `retention_evicted` event. The
    /// record covers the deleted file's own lines PLUS the earlier
    /// evictions its inner records had covered — the chain re-covers
    /// transitively, so no loss drops silently however deep it runs.
    fn enforce_retention(&mut self) -> Result<(), String> {
        while self.retained.len() + 1 > self.max_files {
            let Some(oldest) = self.retained.pop_front() else {
                break;
            };
            let victim = rotated_path(&self.path, oldest.seq);
            match std::fs::remove_file(&victim) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "evicting retained event file {} failed: {error}",
                        victim.display()
                    ));
                }
            }
            let total_events = oldest.events.saturating_add(oldest.covered_events);
            let total_bytes = oldest.bytes.saturating_add(oldest.covered_bytes);
            self.evicted_events = self.evicted_events.saturating_add(total_events);
            self.evicted_bytes = self.evicted_bytes.saturating_add(total_bytes);
            self.live_covered_events = self.live_covered_events.saturating_add(total_events);
            self.live_covered_bytes = self.live_covered_bytes.saturating_add(total_bytes);
            let payload = serde_json::json!({
                "evicted_file": victim
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                "evicted_events": oldest.events,
                "evicted_bytes": oldest.bytes,
                "covered_events": oldest.covered_events,
                "covered_bytes": oldest.covered_bytes,
                "reason": format!(
                    "retention keeps at most {} files; the oldest rotation was deleted and its events (plus the earlier evictions its records covered) are accounted here, not silently lost",
                    self.max_files,
                ),
            });
            let line = serde_json::json!({
                "schema": EVENT_SCHEMA,
                "seq": self.next_seq,
                "at_ns": crate::discovery::caller_registry::now_ns(),
                "kind": "retention_evicted",
                "event": payload,
            });
            self.next_seq = self.next_seq.saturating_add(1);
            let mut bytes = serde_json::to_vec(&line)
                .map_err(|error| format!("encoding retention event failed: {error}"))?;
            bytes.push(b'\n');
            self.file
                .write_all(&bytes)
                .map_err(|error| format!("writing retention event failed: {error}"))?;
            self.file
                .flush()
                .map_err(|error| format!("flushing retention event failed: {error}"))?;
            self.current_bytes = self.current_bytes.saturating_add(bytes.len() as u64);
            self.events_in_file = self.events_in_file.saturating_add(1);
        }
        Ok(())
    }
}

fn rotated_path(live: &Path, seq: u64) -> PathBuf {
    let mut name = live
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "events.jsonl".to_string());
    name.push('.');
    name.push_str(&seq.to_string());
    live.with_file_name(name)
}

/// Continue the rotation sequence past any prior run's files so two
/// runs sharing one directory never collide on a rotated name.
fn next_rotation_seq(live: &Path) -> u64 {
    let parent = live.parent().unwrap_or_else(|| Path::new("."));
    let prefix = live
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut max: Option<u64> = None;
    let Ok(entries) = std::fs::read_dir(parent) else {
        return 1;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(suffix) = name.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let Some(number) = suffix.strip_prefix('.') else {
            continue;
        };
        if let Ok(seq) = number.parse::<u64>() {
            max = Some(max.map_or(seq, |best| best.max(seq)));
        }
    }
    max.map_or(1, |best| best.saturating_add(1))
}

/// The `started` payload: scope, clock, and enforced limits.
pub(crate) fn started_payload(
    scope_label: &str,
    started_ns: u64,
    presentation: &Presentation,
) -> serde_json::Value {
    serde_json::json!({
        "scope": scope_label,
        "clock": {
            "basis": crate::discovery::caller_registry::CLOCK_BASIS,
            "unit": crate::discovery::caller_registry::CLOCK_UNIT,
        },
        "started_ns": started_ns,
        "limits": {
            "callers": presentation.budgets.callers_limit,
            "modules": presentation.budgets.modules_limit,
            "edges": presentation.budgets.edges_limit,
            "endpoints": presentation.budgets.endpoints_limit,
            "inventory_endpoints": presentation.budgets.inventory_endpoints_limit,
            "inventory_attach_modules": presentation.budgets.inventory_modules_limit,
            "semantic_state": presentation.budgets.semantic_limit,
            "retained_history": presentation.budgets.retained_limit,
        },
    })
}

/// One [`CallerEvent`] as a stream payload: admissions, retirements,
/// and failures with the same budget shape snapshot gaps carry.
pub(crate) fn caller_event_payload(event: &CallerEvent) -> serde_json::Value {
    match event {
        CallerEvent::Admitted { id } => serde_json::json!({
            "event": "admitted",
            "caller": id.label(),
        }),
        CallerEvent::Exited { id, reason } => serde_json::json!({
            "event": "exited",
            "caller": id.label(),
            "reason": reason,
        }),
        CallerEvent::ExecRetired { old, new } => serde_json::json!({
            "event": "exec_retired",
            "old": old.label(),
            "new": new.label(),
        }),
        CallerEvent::Reused { old, new } => serde_json::json!({
            "event": "reused",
            "old": old.label(),
            "new": new.label(),
        }),
        CallerEvent::AdmitFailed {
            pid,
            reason,
            budget,
        } => serde_json::json!({
            "event": "admit_failed",
            "pid": pid,
            "reason": reason,
            "budget": budget.map(|refusal| serde_json::json!({
                "resource": refusal.resource,
                "limit": refusal.limit,
                "requested": refusal.requested,
            })).unwrap_or(serde_json::Value::Null),
        }),
    }
}

/// Emit one full presentation as snapshot-equivalent events: every
/// caller, module, edge (with its presentation states), and gap, in
/// document order. Gap events carry the IDENTICAL subject/reason/
/// budget the snapshot gaps carry — a refused capture produces stream
/// gaps identical in meaning to snapshot gaps. Test-gated: production
/// emits incrementally per pass; tests replay whole snapshots through
/// here for equivalence and rotation accounting.
#[cfg(test)]
pub(crate) fn emit_snapshot_as_events(
    writer: &mut EventWriter,
    presentation: &Presentation,
    at_ns: u64,
) -> Result<(), String> {
    let document = render_json_from_presentation(presentation);
    for caller in document["callers"].as_array().expect("callers array") {
        writer.append("caller_observed", caller.clone(), at_ns)?;
    }
    for module in document["modules"].as_array().expect("modules array") {
        writer.append("module_observed", module.clone(), at_ns)?;
    }
    let edges = document["edges"].as_array().expect("edges array");
    for (edge_json, edge_view) in edges.iter().zip(presentation.edges.iter()) {
        let mut enriched = edge_json.clone();
        enriched["presence"] = serde_json::Value::from(edge_view.presence.label());
        enriched["capture"] = serde_json::Value::from(edge_view.capture.label());
        enriched["activity"] = serde_json::Value::from(edge_view.activity.label());
        writer.append("edge_observed", enriched, at_ns)?;
    }
    for gap in document["gaps"].as_array().expect("gaps array") {
        writer.append("gap_recorded", gap.clone(), at_ns)?;
    }
    writer.append(
        "snapshot",
        serde_json::json!({
            "scope": presentation.scope_label,
            "passes": presentation.passes,
            "budgets": document["budgets"].clone(),
            "gaps_suppressed": presentation.gaps_suppressed,
        }),
        at_ns,
    )
}

/// One gap as a `gap_recorded` payload: the IDENTICAL caller/module/
/// pid/subject/reason/budget shape snapshot gaps carry.
pub(crate) fn gap_payload(gap: &GapView) -> serde_json::Value {
    serde_json::json!({
        "caller": gap.caller.map(|caller| caller.label()),
        "module": gap.module.map(|module| module.label()),
        "pid": gap.pid,
        "subject": gap.subject,
        "reason": gap.reason,
        "budget": gap.budget.map(|refusal| serde_json::json!({
            "resource": refusal.resource,
            "limit": refusal.limit,
            "requested": refusal.requested,
        })).unwrap_or(serde_json::Value::Null),
    })
}

/// One committed pass as a `pass_committed` payload: what the pass
/// scanned, the resulting totals, and this pass's loss accounting.
pub(crate) fn pass_payload(
    report: &PassReport,
    presentation: &Presentation,
    new_gaps: usize,
    suppressed_delta: u64,
) -> serde_json::Value {
    serde_json::json!({
        "pass": report.pass,
        "scanned": report.scanned,
        "native_callers": report.native_callers,
        "scan_callers": report.scan_callers,
        "totals": {
            "callers": presentation.callers.len(),
            "modules": presentation.modules.len(),
            "edges": presentation.edges.len(),
        },
        "new_gaps": new_gaps,
        "suppressed_delta": suppressed_delta,
        "gaps_suppressed": presentation.gaps_suppressed,
    })
}

/// The terminal `ended` payload: final budgets plus stream accounting.
pub(crate) fn ended_payload(
    presentation: &Presentation,
    ended_ns: u64,
    writer: &EventWriter,
) -> serde_json::Value {
    let document = render_json_from_presentation(presentation);
    serde_json::json!({
        "ended_ns": ended_ns,
        "passes": presentation.passes,
        "budgets": document["budgets"].clone(),
        "gaps_suppressed": presentation.gaps_suppressed,
        "stream": {
            "rotations": writer.rotations(),
            "evicted_events": writer.evicted_events(),
            "evicted_bytes": writer.evicted_bytes(),
        },
    })
}

#[cfg(test)]
#[path = "inventory_events_tests.rs"]
mod tests;
