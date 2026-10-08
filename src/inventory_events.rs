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
//! a retained event. Edge records are change-driven and capped per
//! pass ([`EdgeEmitter`]); deferred ones are counted, never dropped.

use crate::discovery::caller_registry::{CallerEvent, CallerId, ModuleId, UseCoverage};
use crate::discovery::engine::inventory_coordinator::PassReport;
use crate::inventory::{edge_json, render_json_from_presentation};
use crate::inventory_present::GapView;
use crate::inventory_present::{Activity, Capture, EdgeView, Presence, Presentation};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::hash::BuildHasher as _;
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

/// Upper bound on the non-payload lines one rotation adds to a file: its
/// `rotated` marker and at most one `retention_evicted` record (file names
/// are at most 255 bytes, the rest is fixed text).
const ROTATION_OVERHEAD: u64 = 2048;

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
    #[cfg(test)]
    pub(crate) fault: Option<EventFault>,
}

/// Failure injection belongs to one writer, never another parallel run.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct EventFault {
    pub(crate) kind: &'static str,
    pub(crate) final_pass_only: bool,
    pub(crate) after_ended: bool,
    pub(crate) attempts: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
}

impl EventWriter {
    /// Open (or truncate) the live stream file. `max_bytes` must be
    /// non-zero; `max_files` counts the live file plus retained
    /// rotations (minimum 1). Pre-existing `<path>.<N>` rotations are
    /// inventoried so this run's sequence never collides with a prior
    /// run's; prior files are never deleted here — only this run's
    /// retention enforcement evicts, and every eviction is an event.
    ///
    /// Hardening (B1): the live file opens with the `-o` policy
    /// ([`crate::output::create_private_stream`] + `begin`): the parent
    /// is retained without following a symlink, the final component is
    /// opened `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, a new file is `0600`, an
    /// existing target must be a regular file owned by the caller and is
    /// truncated and made `0600`. A symlink, FIFO, device, socket or
    /// directory at the name is refused with a clear error and left
    /// untouched. Difference from `-o` trace: the truncate happens here,
    /// at stream creation, because the event stream writes synchronously
    /// from the first `started` event (there is no attach-then-begin
    /// split); a stream that is created and never appended to still
    /// truncates. Rotation reopen uses the same helper; rotation renames
    /// and retention removals use the no-follow/no-clobber helpers below.
    pub(crate) fn create(path: &Path, max_bytes: u64, max_files: usize) -> Result<Self, String> {
        if max_bytes == 0 {
            return Err("event rotation threshold must be greater than zero".into());
        }
        let max_files = max_files.max(1);
        let rotation_seq = next_rotation_seq(path);
        let file = open_event_live_file(path)?;
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
            #[cfg(test)]
            fault: None,
        })
    }

    /// Append one event line: `{"schema","seq","at_ns","kind","event"}`.
    pub(crate) fn append(
        &mut self,
        kind: &str,
        payload: serde_json::Value,
        at_ns: u64,
    ) -> Result<(), String> {
        self.append_sized(kind, payload, at_ns).map(|_| ())
    }

    /// [`EventWriter::append`], returning the line's length in bytes. The
    /// line lands in the live file, generation [`EventWriter::generation`].
    pub(crate) fn append_sized(
        &mut self,
        kind: &str,
        payload: serde_json::Value,
        at_ns: u64,
    ) -> Result<u64, String> {
        #[cfg(test)]
        if let Some(fault) = &self.fault {
            fault.attempts.borrow_mut().push(kind.to_string());
            if !fault.after_ended
                && fault.kind == kind
                && (!fault.final_pass_only || payload["final"] == true)
            {
                return Err(format!("injected {kind} append failure"));
            }
        }
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
        Ok(bytes.len() as u64)
    }

    /// The exact length of the line [`EventWriter::append`] would write
    /// next for this event (seq, envelope and trailing newline included).
    pub(crate) fn line_len(&self, kind: &str, payload: &serde_json::Value, at_ns: u64) -> u64 {
        let line = serde_json::json!({
            "schema": EVENT_SCHEMA,
            "seq": self.next_seq,
            "at_ns": at_ns,
            "kind": kind,
            "event": payload,
        });
        line.to_string().len() as u64 + 1
    }

    /// The live file's generation: how many times this run's stream
    /// rotated. A line appended now belongs to this generation.
    pub(crate) fn generation(&self) -> u64 {
        self.rotations
    }

    /// The oldest generation still retained on disk: a line of an older
    /// generation was evicted (and accounted in `retention_evicted`).
    pub(crate) fn oldest_generation(&self) -> u64 {
        self.rotations.saturating_sub(self.retained.len() as u64)
    }

    /// Rotate now if a tail of `bytes` would not fit the live file, so
    /// that tail (`ended`) can no longer rotate (unless `bytes` exceeds
    /// what a fresh file holds); see [`EventWriter::oldest_generation_after`].
    pub(crate) fn reserve(&mut self, bytes: u64) -> Result<(), String> {
        self.rotate_if_needed(bytes)
    }

    /// The oldest generation still retained once a line of `incoming` bytes
    /// is appended: one generation later when that line would rotate a full
    /// retained set.
    pub(crate) fn oldest_generation_after(&self, incoming: u64) -> u64 {
        if self.events_in_file > 0 && self.current_bytes.saturating_add(incoming) > self.max_bytes {
            let retained = (self.retained.len() + 1).min(self.max_files - 1) as u64;
            self.rotations.saturating_add(1).saturating_sub(retained)
        } else {
            self.oldest_generation()
        }
    }

    /// Bytes of one contiguous run of lines that retention is guaranteed
    /// to keep, whatever the live file holds when the run starts: the
    /// `max_files - 1` files the run can fill after its first one, each
    /// holding at least `max_bytes - largest_line - ROTATION_OVERHEAD`
    /// bytes of it (a file rotates only when the next line does not fit;
    /// its rotation marker and eviction record take the rest). Zero when
    /// only the live file is kept.
    pub(crate) fn contiguous_capacity(&self, largest_line: u64) -> u64 {
        let per_file = self
            .max_bytes
            .saturating_sub(largest_line.saturating_add(ROTATION_OVERHEAD));
        (self.max_files as u64 - 1).saturating_mul(per_file)
    }

    /// Write the terminal `ended` event, flush, and sync the live file.
    pub(crate) fn finish(&mut self, payload: serde_json::Value, at_ns: u64) -> Result<(), String> {
        self.append("ended", payload, at_ns)?;
        #[cfg(test)]
        if let Some(fault) = &self.fault
            && fault.after_ended
        {
            return Err("injected event stream sync failure".into());
        }
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

    /// Bytes in the live file (tests fill it to a boundary).
    #[cfg(test)]
    pub(crate) fn live_bytes(&self) -> u64 {
        self.current_bytes
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
        rename_live_to_rotated(&self.path, &rotated_name)?;
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
        self.file = open_event_live_file(&self.path).map_err(|error| {
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
            remove_retained_file(&victim)?;
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

/// Open (or truncate) the live event file with the `-o` hardening. See
/// [`EventWriter::create`] for the policy and its one documented
/// difference (immediate truncate).
fn open_event_live_file(path: &Path) -> Result<File, String> {
    let stream =
        crate::output::create_private_stream(path).map_err(|error| open_failed(path, error))?;
    stream.begin().map_err(|error| open_failed(path, error))
}

/// The refusal for a failed event-stream open. When the name holds a
/// target the stream must never touch, the kind is named explicitly —
/// a symlink, FIFO, socket, device or directory — instead of surfacing
/// the bare errno (`ELOOP`, `ENXIO`) the hardened open failed with.
/// Advisory only: the open itself is the enforcement, so a name that
/// raced past this check is still refused by `O_NOFOLLOW`/ownership.
fn open_failed(path: &Path, error: String) -> String {
    if let Some(kind) = existing_target_kind(path) {
        format!(
            "refusing to open event stream {}: it is {kind}; leaving it as it was ({error})",
            path.display()
        )
    } else {
        format!("opening event stream {} failed: {error}", path.display())
    }
}

/// What the failed open found at the name, when it found a target the
/// stream must never touch. Kind names match `-o`
/// (`output::check_final_name`).
fn existing_target_kind(path: &Path) -> Option<&'static str> {
    use std::os::unix::fs::FileTypeExt as _;
    let kind = std::fs::symlink_metadata(path).ok()?.file_type();
    if kind.is_symlink() {
        Some("a symbolic link")
    } else if kind.is_fifo() {
        Some("a FIFO")
    } else if kind.is_socket() {
        Some("a socket")
    } else if kind.is_char_device() {
        Some("a character device")
    } else if kind.is_block_device() {
        Some("a block device")
    } else if kind.is_dir() {
        Some("a directory")
    } else {
        None
    }
}

/// Rename the live file to its rotated name without following or
/// clobbering a planted entry. The sequence is fresh
/// ([`next_rotation_seq`] skips prior files), so anything at the target
/// is a race or an attack: refuse it. The rename itself uses
/// `RENAME_NOREPLACE` so a name that appears between the check and the
/// rename is not replaced either.
fn rename_live_to_rotated(live: &Path, rotated: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(rotated) {
        Ok(_) => {
            return Err(format!(
                "rotating event stream {} to {} failed: target exists; refusing to replace it",
                live.display(),
                rotated.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "checking rotation target {} failed: {error}",
                rotated.display()
            ));
        }
    }
    match rename_noreplace(live, rotated) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => Err(format!(
            "rotating event stream {} to {} failed: target appeared during rotation; refusing to replace it",
            live.display(),
            rotated.display()
        )),
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
            // Filesystem without RENAME_NOREPLACE: re-check, then plain
            // rename. The remaining check-then-rename window needs write
            // access to a parent the live-file open already trusted.
            match std::fs::symlink_metadata(rotated) {
                Ok(_) => Err(format!(
                    "rotating event stream {} to {} failed: target exists; refusing to replace it",
                    live.display(),
                    rotated.display()
                )),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::rename(live, rotated).map_err(|error| {
                        format!(
                            "rotating event stream {} to {} failed: {error}",
                            live.display(),
                            rotated.display()
                        )
                    })
                }
                Err(error) => Err(format!(
                    "checking rotation target {} failed: {error}",
                    rotated.display()
                )),
            }
        }
        Err(error) => Err(format!(
            "rotating event stream {} to {} failed: {error}",
            live.display(),
            rotated.display()
        )),
    }
}

/// `renameat2(..., RENAME_NOREPLACE)` on paths, so a libc without the
/// wrapper still links. EEXIST when the new name exists; EINVAL when the
/// filesystem does not support the flag.
fn rename_noreplace(old: &Path, new: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let old = std::ffi::CString::new(old.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL byte")
    })?;
    let new = std::ffi::CString::new(new.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL byte")
    })?;
    // SAFETY: both names are NUL-terminated C strings that outlive the call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            old.as_ptr(),
            libc::AT_FDCWD,
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Remove one retention victim without following a symlink. The victim
/// must be a regular file owned by the caller — anything this run
/// rotated there was — otherwise it is refused and left as it was. A
/// missing file is already evicted.
fn remove_retained_file(victim: &Path) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(victim) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "evicting retained event file {} failed: {error}",
                victim.display()
            ));
        }
    };
    if !metadata.is_file() {
        return Err(format!(
            "refusing to evict retained event file {}: not a regular file; refusing to remove it",
            victim.display()
        ));
    }
    {
        use std::os::unix::fs::MetadataExt as _;
        let owner = metadata.uid();
        let current = unsafe { libc::geteuid() } as u32;
        if owner != current {
            return Err(format!(
                "refusing to evict retained event file {}: owned by uid {owner}; refusing to remove it",
                victim.display()
            ));
        }
    }
    match std::fs::remove_file(victim) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "evicting retained event file {} failed: {error}",
            victim.display()
        )),
    }
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
/// here for equivalence and rotation accounting. Edges and gaps go
/// through the production emitters ([`EdgeEmitter`], [`GapEmitter`]).
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
    EdgeEmitter::new().sweep(
        writer,
        &presentation.edges,
        presentation.budgets.edges_limit,
        at_ns,
        0,
    )?;
    GapEmitter::new().emit(writer, &presentation.gaps, true, at_ns)?;
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

/// One edge as an `edge_observed` payload: the snapshot `edges[]` entry
/// verbatim plus ONLY the three derived presentation states the
/// dashboard renders from the same view (`presence`, `capture`,
/// `activity`) — never new capture.
pub(crate) fn edge_payload(edge: &EdgeView) -> serde_json::Value {
    let mut payload = edge_json(edge);
    payload["presence"] = serde_json::Value::from(edge.presence.label());
    payload["capture"] = serde_json::Value::from(edge.capture.label());
    payload["activity"] = serde_json::Value::from(edge.activity.label());
    payload
}

/// The most `edge_observed` records one pass (or the native stop's
/// commit) writes; the rest wait, counted in `edge_events_deferred`.
pub(crate) const EDGE_EVENTS_PER_PASS: usize = 4096;

/// How often a count change that is not a class change may emit per
/// edge (C7 C4, D-C7-5): at most one record per edge per 10 s, with
/// the latest count. Class changes (including bucket jumps) still go
/// out at once; the final sweep stays exact.
pub(crate) const EDGE_COUNT_EMIT_INTERVAL_NS: u64 = 10_000_000_000;

/// Bytes the mid-run refresh condition reserves for the lines that end a
/// stream after a contiguous copy of every edge (the sweep itself uses the
/// measured `ended` size).
pub(crate) const DUMP_TAIL_RESERVE: u64 = 8192;

/// Slack added to the `ended` line's measured size when reserving its
/// room: its envelope plus digits that may still grow (counts, `seq`).
pub(crate) const ENDED_TAIL_SLACK: u64 = 256;

/// Per-edge slack on a dump's size estimate: a record's `seq` and `at_ns`
/// digits may grow between its last write and the dump.
const DUMP_LINE_SLACK: u64 = 32;

type EdgeKey = (CallerId, ModuleId);

/// The classes whose change makes an edge due mid-run: its entries
/// (count by power-of-two bucket, so a busy counter costs O(log calls)
/// records, plus saturation, in-flight and the observation label), its
/// full usage coverage, and the presence, capture and activity states.
/// Activity is read from the presentation the stream is given, which must
/// be the classic whole-run-window one (the dashboard display's trailing
/// window is for frames only). Anything else (mapping instants,
/// semantics) reaches the stream with the next record or the exact sweep
/// before `ended`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EdgeClass {
    entries_bucket: u32,
    entries_saturated: bool,
    entries_in_flight: bool,
    entries_observation: &'static str,
    coverage: UseCoverage,
    presence: Presence,
    capture: Capture,
    activity: Activity,
}

impl EdgeClass {
    fn of(edge: &EdgeView) -> Self {
        Self {
            entries_bucket: edge.entry_count.checked_ilog2().map_or(0, |log| log + 1),
            entries_saturated: edge.entry_saturated,
            entries_in_flight: edge.entry_in_flight,
            entries_observation: edge.entry_observation,
            coverage: edge.coverage.clone(),
            presence: edge.presence,
            capture: edge.capture,
            activity: edge.activity,
        }
    }
}

/// What the stream last carried for one edge: its class, a 128-bit keyed
/// digest of the exact payload (the sweep's comparison), where and
/// how large that record is (the retention checks), and the count and
/// instant it carried (the 10 s count cadence: every record carries
/// the latest count, so every record resets it).
#[derive(Debug)]
struct EdgeDigest {
    class: EdgeClass,
    exact: (u64, u64),
    generation: u64,
    bytes: u64,
    emitted_count: u64,
    emitted_ns: u64,
}

/// One pass's edge output: records written and records still waiting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EdgeEmission {
    pub emitted: usize,
    pub deferred: usize,
}

/// The final sweep's output: records written, and edges whose last record
/// is no longer retained on disk (0 unless retention could not hold them).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EdgeSweep {
    pub emitted: usize,
    /// An upper bound, taken for a tail of the reserved size; the exact
    /// count for the real `ended` line is [`EdgeEmitter::settle_ended`]'s.
    pub unretained: usize,
    /// Whether the sweep wrote a contiguous copy of every edge.
    pub dumped: bool,
}

/// The single place `edge_observed` records are written (DR-C5-EDGE).
/// **Every emitter that appends edge records (the per-pass emitter, the
/// stop-time emitter, the final sweep before `ended`, the snapshot sync
/// emitter) must call [`EdgeEmitter`]; never append `edge_observed`
/// directly**, or the replayed stream diverges from the snapshot.
///
/// Per pass ([`EdgeEmitter::emit`]) an edge is due when it is new, when
/// its [`EdgeClass`] differs from the one the stream last carried, when
/// its count drifted past the last carried count and the 10 s count
/// cadence expired ([`EDGE_COUNT_EMIT_INTERVAL_NS`]), or when retention
/// evicted its last record while the edges' records fit the retention
/// ([`EdgeEmitter::fits`]). Due edges queue in arrival order; at most
/// `EDGE_EVENTS_PER_PASS` records go out per pass, each with the edge's
/// current payload, and the rest stay queued (FIFO, so a deferred edge
/// is never starved) and are counted as deferred.
///
/// The sweep ([`EdgeEmitter::sweep`]), made once before `ended` on every
/// clean termination, writes every edge whose exact payload differs from
/// its last record, or whose last record was evicted, uncapped (bounded by
/// the edge limit). If its own lines rotated a needed record out, it
/// writes one contiguous dump of every edge when that provably fits the
/// retention, and reports any edge still without a retained record. So the
/// last retained record per (caller, module) equals the snapshot's
/// `edges[]` entry plus its three derived states whenever the sweep reports
/// none unretained. A stream that was cut short has no `ended`; its last
/// records may lag the run's end.
///
/// Memory: one digest per edge, bounded by the registry's edge limit
/// (32,768 by default). An edge past that bound (unreachable while the
/// registry enforces the same limit) keeps no digest and is treated as
/// always changed: it over-emits, never under-emits.
#[derive(Debug)]
pub(crate) struct EdgeEmitter {
    digests: HashMap<EdgeKey, EdgeDigest>,
    queue: VecDeque<EdgeKey>,
    queued: HashSet<EdgeKey>,
    per_pass: usize,
    /// Sum of `bytes` over `digests`: the size of one copy of every
    /// tracked edge's last record.
    carried_bytes: u64,
    /// The largest edge record line written so far.
    largest_line: u64,
    keys: (std::hash::RandomState, std::hash::RandomState),
}

impl Default for EdgeEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl EdgeEmitter {
    pub(crate) fn new() -> Self {
        Self::with_cap(EDGE_EVENTS_PER_PASS)
    }

    /// An emitter with its own per-pass record cap (tests).
    pub(crate) fn with_cap(per_pass: usize) -> Self {
        Self {
            digests: HashMap::new(),
            queue: VecDeque::new(),
            queued: HashSet::new(),
            per_pass,
            carried_bytes: 0,
            largest_line: 0,
            keys: (std::hash::RandomState::new(), std::hash::RandomState::new()),
        }
    }

    /// Edges holding a digest (at most the edge limit).
    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.digests.len()
    }

    fn digest(&self, payload: &serde_json::Value) -> (u64, u64) {
        let bytes = payload.to_string();
        (
            self.keys.0.hash_one(bytes.as_bytes()),
            self.keys.1.hash_one(bytes.as_bytes()),
        )
    }

    /// Whether one contiguous copy of every tracked edge's record, plus
    /// a tail of at most [`DUMP_TAIL_RESERVE`] bytes, is guaranteed to
    /// survive retention (the mid-run refresh condition).
    fn fits(&self, writer: &EventWriter) -> bool {
        self.fits_with_tail(writer, DUMP_TAIL_RESERVE)
    }

    /// [`EdgeEmitter::fits`] for a known tail of `tail` bytes (the sweep's
    /// dump, followed by `reserve(tail)` and then only that tail).
    fn fits_with_tail(&self, writer: &EventWriter, tail: u64) -> bool {
        let slack = DUMP_LINE_SLACK.saturating_mul(self.digests.len() as u64);
        let dump = self
            .carried_bytes
            .saturating_add(slack)
            .saturating_add(tail);
        dump <= writer.contiguous_capacity(self.largest_line.saturating_add(DUMP_LINE_SLACK))
    }

    /// Whether `key`'s last record is gone from disk.
    fn evicted(&self, key: &EdgeKey, writer: &EventWriter) -> bool {
        self.evicted_before(key, writer.oldest_generation())
    }

    /// Whether `key`'s last record is older than generation `oldest`.
    fn evicted_before(&self, key: &EdgeKey, oldest: u64) -> bool {
        self.digests
            .get(key)
            .is_some_and(|digest| digest.generation < oldest)
    }

    /// Whether the edge's count drifted past its last carried count and
    /// the 10 s cadence expired: due with the latest count. Counts only
    /// move up, so drift is one-sided; a record older than `at_ns`
    /// (scripted time running backwards) never qualifies.
    fn count_due(digest: &EdgeDigest, edge: &EdgeView, at_ns: u64) -> bool {
        edge.entry_count != digest.emitted_count
            && at_ns.saturating_sub(digest.emitted_ns) >= EDGE_COUNT_EMIT_INTERVAL_NS
    }

    /// Write one record and remember it, within `limit`.
    fn write(
        &mut self,
        writer: &mut EventWriter,
        edge: &EdgeView,
        payload: serde_json::Value,
        limit: usize,
        at_ns: u64,
    ) -> Result<(), String> {
        let exact = self.digest(&payload);
        let bytes = writer.append_sized("edge_observed", payload, at_ns)?;
        self.largest_line = self.largest_line.max(bytes);
        let key = (edge.caller, edge.module);
        if !self.digests.contains_key(&key) && self.digests.len() >= limit {
            return Ok(());
        }
        let digest = EdgeDigest {
            class: EdgeClass::of(edge),
            exact,
            generation: writer.generation(),
            bytes,
            emitted_count: edge.entry_count,
            emitted_ns: at_ns,
        };
        self.carried_bytes = self.carried_bytes.saturating_add(bytes);
        if let Some(old) = self.digests.insert(key, digest) {
            self.carried_bytes = self.carried_bytes.saturating_sub(old.bytes);
        }
        Ok(())
    }

    /// One pass: queue every new, class-changed, count-due or (while
    /// the records fit the retention) evicted edge, then write up to the
    /// per-pass cap from the queue's head. `edges` is the presentation's
    /// (sorted by (caller, module)); `limit` its edge limit.
    pub(crate) fn emit(
        &mut self,
        writer: &mut EventWriter,
        edges: &[EdgeView],
        limit: usize,
        at_ns: u64,
    ) -> Result<EdgeEmission, String> {
        let refresh = self.fits(writer);
        for edge in edges {
            let key = (edge.caller, edge.module);
            if self.queued.contains(&key) {
                continue;
            }
            let due = match self.digests.get(&key) {
                None => true,
                Some(digest) => {
                    digest.class != EdgeClass::of(edge)
                        || (refresh && digest.generation < writer.oldest_generation())
                        || Self::count_due(digest, edge, at_ns)
                }
            };
            if due {
                self.queue.push_back(key);
                self.queued.insert(key);
            }
        }
        let mut emitted = 0;
        while emitted < self.per_pass {
            let Some(key) = self.queue.pop_front() else {
                break;
            };
            self.queued.remove(&key);
            let Ok(position) = edges.binary_search_by_key(&key, |edge| (edge.caller, edge.module))
            else {
                continue;
            };
            let edge = &edges[position];
            // A change that reverted while it waited is already carried,
            // unless its record has since been evicted.
            if self.digests.get(&key).is_some_and(|digest| {
                digest.class == EdgeClass::of(edge) && edge.entry_count == digest.emitted_count
            }) && !self.evicted(&key, writer)
            {
                continue;
            }
            self.write(writer, edge, edge_payload(edge), limit, at_ns)?;
            emitted += 1;
        }
        Ok(EdgeEmission {
            emitted,
            deferred: self.queue.len(),
        })
    }

    /// The exact sweep before `ended`: every edge whose payload differs
    /// from its last record, or whose last record was evicted (or that was
    /// never carried), in `edges` order, uncapped. Room for the `tail`
    /// bytes still to come (the `ended` line) is then reserved, so a
    /// rotation that tail would cause happens here, before the count. If a
    /// needed record was rotated out, one contiguous dump of every edge
    /// follows when it, plus the tail, provably fits the retention. The
    /// returned
    /// `unretained` is final for a tail of at most `tail` bytes: it counts
    /// the edges whose last record will not be retained once that tail is
    /// written. Clears the deferred queue.
    pub(crate) fn sweep(
        &mut self,
        writer: &mut EventWriter,
        edges: &[EdgeView],
        limit: usize,
        at_ns: u64,
        tail: u64,
    ) -> Result<EdgeSweep, String> {
        self.queue.clear();
        self.queued.clear();
        let mut emitted = 0;
        for edge in edges {
            let key = (edge.caller, edge.module);
            let payload = edge_payload(edge);
            let carried = self.digests.get(&key).is_some_and(|digest| {
                digest.exact == self.digest(&payload)
                    && digest.generation >= writer.oldest_generation()
            });
            if carried {
                continue;
            }
            self.write(writer, edge, payload, limit, at_ns)?;
            emitted += 1;
        }
        writer.reserve(tail)?;
        let dumped =
            self.unretained_after(writer, edges, tail) > 0 && self.fits_with_tail(writer, tail);
        if dumped {
            for edge in edges {
                self.write(writer, edge, edge_payload(edge), limit, at_ns)?;
                emitted += 1;
            }
            // No second reserve: the fit bound already holds the tail.
        }
        Ok(EdgeSweep {
            emitted,
            unretained: self.unretained_after(writer, edges, tail),
            dumped,
        })
    }

    /// Edges whose last record will not be retained once one more line of
    /// `incoming` bytes is appended.
    pub(crate) fn unretained_after(
        &self,
        writer: &EventWriter,
        edges: &[EdgeView],
        incoming: u64,
    ) -> usize {
        let oldest = writer.oldest_generation_after(incoming);
        edges
            .iter()
            .filter(|edge| self.evicted_before(&(edge.caller, edge.module), oldest))
            .count()
    }

    /// The exact `ended` payload and its `edges_unretained` (review R2-1).
    /// `ended(count)` builds the payload carrying `count`; the count is
    /// recomputed for that payload's exact line length until it is stable.
    /// Starting from the sweep's `estimate` (taken for the reserved tail,
    /// at least as long as any real `ended` line) the count can only fall,
    /// and a longer count never shortens the line, so this converges to a
    /// count that is exact for the line actually written.
    pub(crate) fn settle_ended(
        &self,
        writer: &EventWriter,
        edges: &[EdgeView],
        estimate: usize,
        at_ns: u64,
        ended: impl Fn(usize) -> serde_json::Value,
    ) -> (usize, serde_json::Value) {
        let mut count = estimate;
        for _ in 0..=edges.len() + 1 {
            let payload = ended(count);
            let exact =
                self.unretained_after(writer, edges, writer.line_len("ended", &payload, at_ns));
            if exact == count {
                return (count, payload);
            }
            count = exact;
        }
        unreachable!("the unretained count converges within edges + 1 steps")
    }
}

/// One gap as a `gap_recorded` payload: the IDENTICAL caller/module/
/// pid/subject/reason/budget shape snapshot gaps carry.
pub(crate) fn gap_payload(index: usize, gap: &GapView) -> serde_json::Value {
    serde_json::json!({
        "index": index,
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

/// A `gap_repeated` payload: gap `index` (its position in `gap_recorded`
/// order, equal to its `gaps[]` index) now stands at `repeats` recordings.
pub(crate) fn gap_repeated_payload(index: usize, repeats: u64) -> serde_json::Value {
    serde_json::json!({"index": index, "repeats": repeats})
}

/// The single place gap events are written. **Every emitter that appends
/// gap events (the per-pass emitter, the stop-time emitter, the final
/// flush before `ended`, the snapshot sync emitter) must call
/// [`GapEmitter::emit`]; never append `gap_recorded` or `gap_repeated`
/// directly**, or the replayed stream diverges from the snapshot.
///
/// `gap_recorded{index, ...identity}` goes out once per distinct gap, in
/// `gaps[]` order. `gap_repeated{index, repeats}` goes out mid-run only
/// when a gap's cumulative count crosses a power of two (live signal,
/// O(gaps * log passes) lines per run, so a steady recurring gap lets the
/// stream go quiet); values seen mid-run are lower bounds. The `flush`
/// call, made once before `ended` on every clean termination, emits the
/// exact count of every gap whose count differs from its last emitted
/// value, so the last value per index equals the snapshot. A stream that
/// was cut short has no `ended`, and its last values are lower bounds.
#[derive(Debug, Default)]
pub(crate) struct GapEmitter {
    /// Per retained gap, the `repeats` the stream last carried.
    emitted: Vec<u64>,
}

impl GapEmitter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Emit new gaps and power-of-two repeat crossings (`flush` false), or
    /// every outstanding exact count (`flush` true). Returns the number
    /// of new `gap_recorded` events.
    pub(crate) fn emit(
        &mut self,
        writer: &mut EventWriter,
        gaps: &[GapView],
        flush: bool,
        at_ns: u64,
    ) -> Result<usize, String> {
        let fresh = gaps.len().saturating_sub(self.emitted.len());
        for (index, gap) in gaps.iter().enumerate().skip(self.emitted.len()) {
            writer.append("gap_recorded", gap_payload(index, gap), at_ns)?;
            self.emitted.push(1);
        }
        for (index, gap) in gaps.iter().enumerate() {
            let last = self.emitted[index];
            let due = if flush {
                gap.repeats != last
            } else {
                gap.repeats > last && gap.repeats.ilog2() > last.ilog2()
            };
            if due {
                writer.append(
                    "gap_repeated",
                    gap_repeated_payload(index, gap.repeats),
                    at_ns,
                )?;
                self.emitted[index] = gap.repeats;
            }
        }
        Ok(fresh)
    }
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
        "maps_matched": report.maps_matched,
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
