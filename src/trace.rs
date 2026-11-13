//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! `trace` renderer: one line per completed call, in arrival order — the
//! per-investigation counterpart to `profile`'s aggregate report
//! (see `docs/usage.md` and `docs/privacy/allowlist-v1.md`).
//! Reuses `render::param_combo_json` for parameter decoding so
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
use std::collections::BTreeMap;
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
        .map(|slot| slot.label.clone())
        .unwrap_or_else(|| format!("slot#{slot}"))
}

/// A small, honest name table for the two mechanism ids this capture
/// also decodes parameters for (`render::param_combo_json`'s
/// `rsa_pkcs_pss`/`gcm` shapes) — sourced from the same
/// `pkcs11-types` crate the rest of this codebase already
/// depends on, not a re-derived literal. No general CKM_* id -> name
/// registry exists anywhere in this codebase or its dependencies to
/// reuse (verified: `pkcs11_types::mechanism_registry` maps ids
/// to *shape* names like `"gcm"`, never to `CKM_*` display names).
/// Every other mechanism, known or vendor, renders verbatim as `0x…`,
/// same as the "unknown mechanism" case — honest rather than guessed.
/// ponytail: bounded to the two decoded shapes; add a full CKM_* name
/// table if trace readability for non-decoded, non-PSS/GCM mechanisms
/// ever becomes a real ask.
fn mechanism_name(id: u64) -> Option<&'static str> {
    match id {
        _ if id == pkcs11_types::CkMechanismType::RSA_PKCS_PSS.0 => Some("CKM_RSA_PKCS_PSS"),
        _ if id == pkcs11_types::CkMechanismType::AES_GCM.0 => Some("CKM_AES_GCM"),
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
        id if id == pkcs11_types::CkMechanismType::SHA256.0 => "SHA256".into(),
        id if id == pkcs11_types::CkMechanismType::SHA384.0 => "SHA384".into(),
        id if id == pkcs11_types::CkMechanismType::SHA512.0 => "SHA512".into(),
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
    // One source of truth: the shared `CKR_*` lookup. Trace keeps its
    // historical `CKR_UNKNOWN` rendering for unregistered codes; profile
    // renders those as verbatim hex instead (see `render`).
    crate::semantics_edge::rv_name(rv).unwrap_or_else(|| "CKR_UNKNOWN".to_string())
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
/// `HH:MM:SS.ffffff Unknown executable (PID P, TID T) [sess#N] FUNCTION[ MECHANISM] → CKR_x DURATION`.
/// A pure function — no I/O, no shared state — so it is directly
/// testable: given a known `Event` and its resolved wall-clock time,
/// function name, and session pseudonym, it always renders the same line.
pub fn format_line(ev: &Event, wall_ns: u128, function: &str, session: Option<u64>) -> String {
    format_line_with_executable(
        ev,
        wall_ns,
        function,
        session,
        crate::trace_identity::TraceExecutableView::unknown(
            crate::trace_identity::TraceIdentityUnknown::NotSeeded,
        ),
    )
}

fn quote_executable(value: &str) -> String {
    // JSON Unicode escapes preserve the value while keeping splitlines-based
    // consumers on the one LF-delimited record the capture actually emitted.
    serde_json::to_string(&render::escape_controls(value))
        .expect("JSON string")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

pub(crate) fn format_line_with_executable(
    ev: &Event,
    wall_ns: u128,
    function: &str,
    session: Option<u64>,
    executable: crate::trace_identity::TraceExecutableView<'_>,
) -> String {
    let (pid, tid) = pid_tid(ev.pid_tgid);
    let mut line = if let Some(path) = executable.path() {
        let basename = path
            .rsplit('/')
            .find(|part| !part.is_empty())
            .unwrap_or(path);
        let basename = quote_executable(basename);
        let path = quote_executable(path);
        format!(
            "{} {basename} (PID {pid}, TID {tid}) exe={path}",
            fmt_wall_time(wall_ns)
        )
    } else {
        format!(
            "{} Unknown executable (PID {pid}, TID {tid})",
            fmt_wall_time(wall_ns)
        )
    };
    if let Some(n) = session {
        line.push_str(&format!(" sess#{n}"));
    }
    // The function label comes from the target's own tables, so this
    // terminal boundary escapes controls the way inspect already does.
    line.push_str(&format!(" {}", render::escape_controls(function)));
    if ev.capture & capture::MECHANISM_MASK == capture::MECHANISM_VALUE {
        line.push(' ');
        line.push_str(&render_mechanism(ev));
    }
    line.push_str(&format!(
        " -> {} {}",
        rv_name(ev.rv),
        render::fmt_ns(Some(ev.duration_ns))
    ));
    line
}

/// One trace line labeled with the owned run's command: the resolved
/// spawn path p11scope executed itself, in the same quoted shape as a
/// verified label. Used only when the identity proof has no path and
/// the event is the child's own.
fn format_line_with_owned(
    ev: &Event,
    wall_ns: u128,
    function: &str,
    session: Option<u64>,
    path: &str,
) -> String {
    let (pid, tid) = pid_tid(ev.pid_tgid);
    let basename = path
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(path);
    let mut line = format!(
        "{} {} (PID {pid}, TID {tid}) exe={}",
        fmt_wall_time(wall_ns),
        quote_executable(basename),
        quote_executable(path),
    );
    if let Some(n) = session {
        line.push_str(&format!(" sess#{n}"));
    }
    line.push_str(&format!(" {}", render::escape_controls(function)));
    if ev.capture & capture::MECHANISM_MASK == capture::MECHANISM_VALUE {
        line.push(' ');
        line.push_str(&render_mechanism(ev));
    }
    line.push_str(&format!(
        " -> {} {}",
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

/// `TRUNCATED at {limit} events`, citing the effective cap: the explicit
/// `--max-events` value when the operator passed one, the default cap
/// otherwise — never blaming a flag that was never given (SYSPLAN
/// residual F-17).
pub fn truncated_line(limit: u64, explicit: bool) -> String {
    if explicit {
        format!("TRUNCATED at {limit} events (--max-events {limit})")
    } else {
        format!("TRUNCATED at {limit} events (default cap; pass --max-events <n> to change it)")
    }
}

pub fn capture_line(policy: CapturePolicy) -> String {
    format!("CAPTURE privacy={}", policy.privacy_mode())
}

/// Context for completed event lines without a producer-backed image label.
/// This header is human text; terminal EVIDENCE and count records stay intact.
pub fn identity_note() -> &'static str {
    "Trace - completed call events in arrival order\nExecutable labels use verified observed paths; event PID/TID remain diagnostic identifiers."
}

/// The event clock, stated once: trace stamps are UTC wall time
/// anchored to the kernel monotonic clock at the first event.
pub fn zone_note() -> &'static str {
    "Trace times are UTC."
}

/// The whole trace header: the CAPTURE line, the identity note, the
/// zone note, and the unverified note when the plan watches any.
/// Oracles tolerate each context line, so this is the one assembly
/// point — never a second inline copy.
pub(crate) fn header(policy: CapturePolicy, plan: &AttachPlan) -> String {
    let mut header = format!(
        "{}\n{}\n{}",
        capture_line(policy),
        identity_note(),
        zone_note()
    );
    if watches_unverified(plan) {
        header.push('\n');
        header.push_str(unverified_note());
    }
    header
}

/// The header note printed once, instead of a per-line marker, when the
/// capture watches functions whose semantics are not authorized: those
/// calls show names without decoded parameters.
pub fn unverified_note() -> &'static str {
    "Calls on unverified functions are not decoded (names only)."
}

/// True when the trace header must say once that unverified calls are
/// not decoded: the plan watches an unauthorized function, or it is
/// still empty — an owned run discovers its provider after release,
/// and scan-found slots are never authorized, so the note errs toward
/// disclosure.
pub(crate) fn watches_unverified(plan: &AttachPlan) -> bool {
    plan.slots.is_empty() || plan.semantic_unverified_slot_count() > 0
}

/// One rendered caller identity: the process plus its verified-or-owned
/// executable path (`None` for unknown callers).
type CallerKey = (u32, Option<String>);

/// One counted line: the function label plus its return code.
type FunctionRv = (String, u64);

/// Maximum distinct failing callers retained in [`CallerReasons`]
/// (Opus residual pin 5): further callers fold into one bounded
/// "(other callers)" row per (function, rv) with a counted EVIDENCE gap,
/// so the roll-up stays proportional to retained callers, never to the
/// 10M-event trace stream.
pub(crate) const MAX_CALLER_REASONS_CALLERS: usize = 4096;

/// The roll-up cell naming the folded overflow: lines whose caller
/// arrived past [`MAX_CALLER_REASONS_CALLERS`], counted per
/// (function, rv) without retaining their caller identity.
const OTHER_CALLERS_CELL: &str = "(other callers)";

/// Per-caller CKR attribution accumulated over rendered trace lines:
/// caller → (function, rv) → count. A pure projection of the failing
/// line stream — every counted line was rendered, every rendered failing
/// line is counted (retained per caller under the cap, folded past it) —
/// so the terminal roll-up can never disagree with the lines above it.
/// Success and pending returns are never reasons and leave no entry.
/// Threads group into their process (TID stays line detail). Labels
/// rendered from these keys reuse the line quoting, so a roll-up row
/// names exactly the caller the lines named.
#[derive(Debug, Default)]
pub(crate) struct CallerReasons {
    calls: BTreeMap<CallerKey, BTreeMap<FunctionRv, u64>>,
    /// Folded (function, rv) counts for rendered failing lines whose
    /// caller arrived past [`MAX_CALLER_REASONS_CALLERS`]: bounded by
    /// distinct functions × return codes, never by caller count.
    overflow: BTreeMap<FunctionRv, u64>,
    /// Rendered failing lines folded into `overflow` (exact, saturating).
    folded_lines: u64,
}

impl CallerReasons {
    pub(crate) fn note(&mut self, pid: u32, path: Option<&str>, function: &str, rv: u64) {
        // Success and pending returns are never reasons: skip them at
        // the intake so a clean caller leaves no entry at all. The
        // roll-up drops them too, so output is unchanged either way.
        if rv == pkcs11_types::CkRv::OK.0 || rv == pkcs11_types::CkRv::PENDING.0 {
            return;
        }
        let key = (pid, path.map(str::to_string));
        if !self.calls.contains_key(&key) && self.calls.len() >= MAX_CALLER_REASONS_CALLERS {
            self.overflow
                .entry((function.to_string(), rv))
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);
            self.folded_lines = self.folded_lines.saturating_add(1);
            return;
        }
        self.calls
            .entry(key)
            .or_default()
            .entry((function.to_string(), rv))
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
    }

    /// Retained distinct failing callers (outer entries, at most the
    /// cap) — the R11 outer size for the memory-counter lane.
    #[cfg_attr(not(test), allow(dead_code))] // Staged R11 size API; the memory-counter lane consumes it.
    pub(crate) fn caller_entries(&self) -> usize {
        self.calls.len()
    }

    /// Retained (function, rv) rows across callers, folded overflow rows
    /// included — the R11 inner size for the memory-counter lane.
    #[cfg_attr(not(test), allow(dead_code))] // Staged R11 size API; the memory-counter lane consumes it.
    pub(crate) fn row_entries(&self) -> usize {
        self.calls
            .values()
            .map(BTreeMap::len)
            .sum::<usize>()
            .saturating_add(self.overflow.len())
    }

    /// True once a rendered failing line folded past the caller cap.
    pub(crate) fn overflowed(&self) -> bool {
        self.folded_lines > 0
    }

    /// Rendered failing lines folded into "(other callers)" (exact,
    /// saturating). A distinct overflow-caller count is intentionally not
    /// tracked: retaining those identities would be the unbounded
    /// structure the cap removes.
    pub(crate) fn folded_lines(&self) -> u64 {
        self.folded_lines
    }

    /// Distinct folded (function, rv) pairs — the EVIDENCE row count.
    pub(crate) fn folded_rows(&self) -> usize {
        self.overflow.len()
    }
}

/// A roll-up row's caller cell: the line's caller identity without
/// the TID (threads group into their process), quoted exactly as the
/// lines quote it — basename derivation, JSON quoting and control
/// escaping all shared, never a second spelling.
fn caller_cell(pid: u32, path: Option<&str>) -> String {
    match path {
        Some(path) => {
            let basename = path
                .rsplit('/')
                .find(|part| !part.is_empty())
                .unwrap_or(path);
            format!(
                "{} (PID {pid}) exe={}",
                quote_executable(basename),
                quote_executable(path)
            )
        }
        None => format!("Unknown executable (PID {pid})"),
    }
}

/// One (caller, function) row's sorted failure reasons plus its failure
/// total, for worst-first ordering.
struct FunctionRow {
    function: String,
    failures: u64,
    reasons: Vec<(u64, u64)>,
}

/// One caller's sorted function rows plus its failure total.
struct CallerRow<'a> {
    pid: u32,
    path: Option<&'a str>,
    total: u64,
    rows: Vec<FunctionRow>,
    /// True for the folded overflow: renders under [`OTHER_CALLERS_CELL`]
    /// after every retained caller, never among them.
    overflow: bool,
}

/// Groups one (function, rv) count map into failure-sorted function rows
/// plus the failure total, worst-first. Shared by retained callers and
/// the "(other callers)" fold so both order and bound reasons the same
/// way. Success and pending returns are never reasons.
fn function_rows(calls: &BTreeMap<FunctionRv, u64>) -> (Vec<FunctionRow>, u64) {
    let ok = pkcs11_types::CkRv::OK.0;
    let pending = pkcs11_types::CkRv::PENDING.0;
    let mut functions: Vec<FunctionRow> = Vec::new();
    for ((function, rv), count) in calls {
        if *count == 0 || *rv == ok || *rv == pending {
            continue;
        }
        match functions.iter_mut().find(|row| row.function == *function) {
            Some(row) => row.reasons.push((*rv, *count)),
            None => functions.push(FunctionRow {
                function: function.clone(),
                failures: 0,
                reasons: vec![(*rv, *count)],
            }),
        }
    }
    let mut total = 0u64;
    for row in &mut functions {
        row.reasons
            .sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        row.failures = row
            .reasons
            .iter()
            .fold(0u64, |sum, (_, count)| sum.saturating_add(*count));
        total = total.saturating_add(row.failures);
    }
    functions.sort_by(|a, b| {
        b.failures
            .cmp(&a.failures)
            .then(a.function.cmp(&b.function))
    });
    (functions, total)
}

/// Terminal `CALLER ERROR REASONS:` section over the rendered lines:
/// one row per failing (caller, function) pair with its `CKR_*` reasons
/// (concise keeps three plus an `and N more` tail, verbose lists every
/// distinct code), or a named gap when counted errors left no failure
/// reasons among the rendered lines. Empty for a clean trace, so clean
/// tails stay byte-identical. Success and pending returns are never
/// reasons; unregistered codes keep the trace `CKR_UNKNOWN` spelling,
/// matching the lines this section summarizes. Rows read worst-first:
/// callers by failure count, then pid and path; functions within a
/// caller by failure count, then name; reasons by count, then code. Past
/// the caller cap the folded lines render last as "(other callers)" rows,
/// one per function with the same reason bounding.
fn caller_reason_lines(
    reasons: &CallerReasons,
    verbose: bool,
    truncated: bool,
    errors: u64,
) -> Vec<String> {
    // Per caller: per function failure reasons, worst-first; the caller
    // totals below sort the callers the same way.
    let mut callers: Vec<CallerRow<'_>> = Vec::new();
    for ((pid, path), calls) in &reasons.calls {
        let (functions, total) = function_rows(calls);
        if functions.is_empty() {
            continue;
        }
        callers.push(CallerRow {
            pid: *pid,
            path: path.as_deref(),
            total,
            rows: functions,
            overflow: false,
        });
    }
    callers.sort_by(|a, b| {
        b.total
            .cmp(&a.total)
            .then(a.pid.cmp(&b.pid))
            .then(a.path.cmp(&b.path))
    });
    // The fold renders after every retained caller, so the overflow is
    // unmistakable and retained detail keeps its worst-first order.
    if !reasons.overflow.is_empty() {
        let (functions, total) = function_rows(&reasons.overflow);
        if !functions.is_empty() {
            callers.push(CallerRow {
                pid: 0,
                path: None,
                total,
                rows: functions,
                overflow: true,
            });
        }
    }
    let mut lines = Vec::new();
    if callers.is_empty() {
        if errors == 0 {
            return lines;
        }
        lines.push("CALLER ERROR REASONS:".to_string());
        let noun = if errors == 1 { "error" } else { "errors" };
        lines.push(format!(
            "({errors} {noun} counted; no failure reasons among rendered lines)"
        ));
    } else {
        lines.push("CALLER ERROR REASONS:".to_string());
        for caller in &callers {
            let cell = if caller.overflow {
                OTHER_CALLERS_CELL.to_string()
            } else {
                caller_cell(caller.pid, caller.path)
            };
            for row in &caller.rows {
                let shown = if verbose {
                    row.reasons.len()
                } else {
                    row.reasons
                        .len()
                        .min(crate::render::CONCISE_REASONS_PER_FUNCTION)
                };
                let mut text = format!("{cell}: {}: ", render::escape_controls(&row.function));
                for (i, &(rv, count)) in row.reasons[..shown].iter().enumerate() {
                    if i > 0 {
                        text.push_str(", ");
                    }
                    text.push_str(&format!("{} x{count}", rv_name(rv)));
                }
                if shown < row.reasons.len() {
                    text.push_str(&format!(", and {} more", row.reasons.len() - shown));
                }
                lines.push(text);
            }
        }
    }
    if truncated {
        lines.push("(caller reasons cover rendered lines only; trace truncated)".to_string());
    }
    lines
}

/// The human tail a trace ends with, after the machine-readable
/// terminal records: totals in the profile wording, one coverage
/// line, the per-caller error-reason roll-up when the rendered lines
/// hold failures, and the `-v` hint in default text only.
pub(crate) fn terminal_summary(
    calls: u64,
    errors: u64,
    open: u64,
    ev: &render::Evidence,
    verbosity: crate::cli::TextVerbosity,
    callers: &CallerReasons,
) -> Vec<String> {
    let mut lines = vec![
        render::totals_line(calls, errors, open),
        render::coverage_line(ev, verbosity == crate::cli::TextVerbosity::Verbose),
    ];
    lines.extend(caller_reason_lines(
        callers,
        verbosity == crate::cli::TextVerbosity::Verbose,
        ev.trace_truncated,
        errors,
    ));
    if verbosity == crate::cli::TextVerbosity::Concise {
        lines.push(crate::cli::VERBOSE_HINT.to_string());
    }
    lines
}

/// Final machine-readable evidence record for a normally stopped trace.
/// Detaching perf links does not prove already-running callbacks quiesced;
/// only the stop gate's proven quiescence does (`ev.drain_proven`, owner
/// ruling B). Without it this record stays PARTIAL with `final_drain: false`.
/// A truncated trace (`ev.trace_truncated`) is PARTIAL even behind a proven
/// drain: its line stream is short (DR-RETRO-C6-1).
pub fn evidence_line(ev: &render::Evidence, policy: CapturePolicy) -> String {
    evidence_line_inner(ev, policy, None)
}

/// Trace terminal record with the caller-reasons overflow gap: past the
/// caller cap the record carries a counted `caller_reasons_overflow`
/// object (`folded_lines`, `folded_rows`); under the cap the field is
/// absent and the record matches [`evidence_line`] exactly.
pub(crate) fn evidence_line_with_caller_overflow(
    ev: &render::Evidence,
    policy: CapturePolicy,
    callers: &CallerReasons,
) -> String {
    let overflow = callers.overflowed().then(|| {
        serde_json::json!({
            "folded_lines": callers.folded_lines(),
            "folded_rows": callers.folded_rows(),
        })
    });
    evidence_line_inner(ev, policy, overflow)
}

fn evidence_line_inner(
    ev: &render::Evidence,
    policy: CapturePolicy,
    caller_reasons_overflow: Option<serde_json::Value>,
) -> String {
    let mut value = render::versioned_evidence(ev);
    let object = value
        .as_object_mut()
        .expect("Evidence serializes as an object");
    object.insert(
        "privacy_mode".into(),
        serde_json::Value::String(policy.privacy_mode().into()),
    );
    // The sealed verdict, re-gated on the latch and on truncation so an
    // unsealed snapshot can never publish COMPLETE: only a proven stop-gate
    // drain (owner ruling B) makes the final drain true, and only an
    // untruncated one may with it be COMPLETE.
    let complete = ev.drain_proven && !ev.trace_truncated && ev.completeness == "COMPLETE";
    object.insert(
        "completeness".into(),
        serde_json::Value::String(if complete { "COMPLETE" } else { "PARTIAL" }.into()),
    );
    object.insert("capture_aborted".into(), serde_json::Value::Null);
    object.insert(
        "final_drain".into(),
        serde_json::Value::Bool(ev.drain_proven),
    );
    object.insert("counters_available".into(), serde_json::Value::Bool(true));
    object.insert(
        "trace_truncated".into(),
        serde_json::Value::Bool(ev.trace_truncated),
    );
    if let Some(overflow) = caller_reasons_overflow {
        object.insert("caller_reasons_overflow".into(), overflow);
    }
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
    /// `plan::presented_label`: names, or `function #<ordinal> (unnamed)` when unnamed.
    label: String,
    semantics: p11scope_ebpf_common::SlotSemantics,
    standard_layout: bool,
}

fn trace_slots(plan: &AttachPlan) -> Vec<Option<TraceSlot>> {
    let mut slots = Vec::new();
    for slot in &plan.slots {
        let index = slot.index as usize;
        if index >= slots.len() {
            slots.resize_with(index + 1, || None);
        }
        slots[index] = Some(TraceSlot {
            label: plan.label_of(slot),
            semantics: plan.effective_semantics(slot),
            standard_layout: plan.is_standard_layout_slot(slot.index),
        });
    }
    slots
}

pub struct Tracer {
    slots: Vec<Option<TraceSlot>>,
    raw_calls: u64,
    caller_reasons: CallerReasons,
    /// (first observed event's kernel monotonic ts_ns, wall-clock ns at
    /// that same moment) — every later line's wall time is this anchor
    /// plus the kernel-monotonic delta, so line-to-line spacing tracks
    /// the kernel clock exactly; only the anchor itself carries the
    /// small, constant "poll processing lag" of the first event.
    anchor: Option<(u64, u128)>,
    /// The owned run's child pid and resolved spawn path, naming lines
    /// the identity proof cannot resolve. Set for owned runs only, and
    /// applied to the child's own pid only — never to another process.
    owned: Option<(u32, String)>,
}

impl Tracer {
    pub fn new(plan: &AttachPlan) -> Self {
        Self {
            slots: trace_slots(plan),
            raw_calls: 0,
            caller_reasons: CallerReasons::default(),
            anchor: None,
            owned: None,
        }
    }

    /// Names the owned run's command on lines the identity proof
    /// cannot resolve. `path` is the canonical spawn path p11scope
    /// resolved and executed itself — first-hand, never observed —
    /// and only the child's own pid is labeled with it.
    pub fn set_owned_command(&mut self, pid: u32, path: String) {
        self.owned = Some((pid, path));
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

    /// The per-caller return-code roll-up over the lines this tracer
    /// rendered, for the terminal summary. Projection only: no event
    /// the stream did not render is counted.
    pub(crate) fn caller_reasons(&self) -> &CallerReasons {
        &self.caller_reasons
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

    pub(crate) fn on_rejected_history(&mut self, ev: &Event) -> String {
        let mut raw = *ev;
        raw.capture = 0;
        let wall = self.wall_ns_for(ev.ts_ns);
        let function = self.qualified_function(ev.slot);
        let (pid, _) = pid_tid(ev.pid_tgid);
        let owned = self.owned_label(ev).map(str::to_string);
        self.caller_reasons
            .note(pid, owned.as_deref(), &function, ev.rv);
        if let Some(path) = self.owned_label(ev) {
            return format_line_with_owned(&raw, wall, &function, None, path);
        }
        format_line(&raw, wall, &function, None)
    }

    fn qualified_function(&self, index: u32) -> String {
        // No per-line marker: the header note says once that unverified
        // calls are not decoded, and the terminal evidence counts them.
        function_name(&self.slots, index)
    }

    /// The owned command's spawn path for this event, when the run is
    /// owned and the event is the child's own — otherwise `None`, and
    /// the line stays unknown rather than mislabeled.
    fn owned_label(&self, ev: &Event) -> Option<&str> {
        let (pid, _) = pid_tid(ev.pid_tgid);
        self.owned
            .as_ref()
            .filter(|(owned_pid, _)| *owned_pid == pid)
            .map(|(_, path)| path.as_str())
    }

    pub fn on_event_process(
        &mut self,
        ev: &Event,
        process: ProcessKey,
        state: &mut State,
    ) -> String {
        self.on_event_process_with_executable(
            ev,
            process,
            state,
            crate::trace_identity::TraceExecutableView::unknown(
                crate::trace_identity::TraceIdentityUnknown::NotSeeded,
            ),
        )
    }

    pub(crate) fn on_event_process_with_executable(
        &mut self,
        ev: &Event,
        process: ProcessKey,
        state: &mut State,
        executable: crate::trace_identity::TraceExecutableView<'_>,
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
        let function = self.qualified_function(ev.slot);
        let mut rendered = *ev;
        if !semantic {
            rendered.capture = 0;
        }
        // Membership gate (ruling 2026-11-11 clause 2): a mechanism
        // value outside the registered CKM_* registry read through a
        // standard-layout-only slot never prints as a number.
        if slot.as_ref().is_some_and(|slot| slot.standard_layout)
            && rendered.capture & capture::MECHANISM_MASK == capture::MECHANISM_VALUE
            && crate::mechanism_names::mechanism_name(rendered.mechanism).is_none()
        {
            rendered.capture =
                (rendered.capture & !capture::MECHANISM_MASK) | capture::MECHANISM_NONE;
        }
        // The roll-up counts exactly this line, under exactly the caller
        // identity the line shows: the verified path when present, else
        // the owned command's spawn path for the child's own pid, else
        // unknown — the same precedence as the branch below.
        let (pid, _) = pid_tid(ev.pid_tgid);
        match executable.path() {
            Some(path) => self.caller_reasons.note(pid, Some(path), &function, ev.rv),
            None => {
                let owned = self.owned_label(ev).map(str::to_string);
                self.caller_reasons
                    .note(pid, owned.as_deref(), &function, ev.rv);
            }
        }
        if executable.path().is_none()
            && let Some(path) = self.owned_label(ev)
        {
            return format_line_with_owned(&rendered, wall_ns, &function, session, path);
        }
        format_line_with_executable(&rendered, wall_ns, &function, session, executable)
    }
}

#[cfg(test)]
mod trace_identity_renderer_tests {
    use super::*;
    use crate::discovery::engine::tests::detailed_proof_driver::verified_fixture_with_link;
    use crate::fixture_guard::DieWithParent as _;
    use crate::trace_identity::TraceIdentityStore;

    fn event(key: ProcessKey, ts_ns: u64) -> Event {
        Event {
            pid_tgid: (u64::from(key.pid) << 32) | 8,
            ts_ns,
            duration_ns: 3_000,
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: key.generation,
                exec_id: key.exec_id,
            },
            ..Event::default()
        }
    }

    #[test]
    fn trace_identity_renderer_event_time_boundary() {
        let (proof, receipt) = verified_fixture_with_link(b"/owned/fixture");
        let key = receipt.key();
        let mut store = TraceIdentityStore::new(proof);
        store.admit(receipt).unwrap();
        for ts in [0, 5, 10, 20, 21, u64::MAX] {
            let ev = event(key, ts);
            let line =
                format_line_with_executable(&ev, 0, "C_GetInfo", None, store.lookup(key, ts));
            if [20, 21].contains(&ts) {
                assert!(line.contains("\"fixture\" (PID "), "t={ts}: {line}");
                assert!(
                    line.contains("exe=\"/owned/fixture\" C_GetInfo"),
                    "t={ts}: {line}"
                );
            } else {
                assert_eq!(line, format_line(&ev, 0, "C_GetInfo", None), "t={ts}");
                assert!(line.contains("Unknown executable"));
            }
        }
    }

    #[test]
    fn trace_identity_renderer_quotes_controls_deleted_and_basename_collisions() {
        // These paths pass the actual sampler/producer before reaching the
        // private view. No renderer test can construct a positive view.
        for (path, basename, escaped_path) in [
            ("/first/duplicate", "duplicate", "/first/duplicate"),
            ("/second/duplicate", "duplicate", "/second/duplicate"),
            (
                "/owned/with spaces (deleted)",
                "with spaces (deleted)",
                "/owned/with spaces (deleted)",
            ),
            (
                "/owned/q\"u\\ote\n\u{85}",
                "q\"u\\ote\\n\\u{85}",
                "/owned/q\"u\\ote\\n\\u{85}",
            ),
            (
                "/owned/(PID 9, TID 8) exe=\"fake\" sess#4",
                "(PID 9, TID 8) exe=\"fake\" sess#4",
                "/owned/(PID 9, TID 8) exe=\"fake\" sess#4",
            ),
        ] {
            let (proof, receipt) = verified_fixture_with_link(path.as_bytes());
            let key = receipt.key();
            let mut store = TraceIdentityStore::new(proof);
            store.admit(receipt).unwrap();
            let line = format_line_with_executable(
                &event(key, 20),
                0,
                "C_GetInfo",
                Some(7),
                store.lookup(key, 20),
            );
            assert!(!line.chars().any(char::is_control), "{line:?}");
            let rest = line.strip_prefix("00:00:00.000000 ").unwrap();
            let mut atoms = serde_json::Deserializer::from_str(rest).into_iter::<String>();
            assert_eq!(atoms.next().unwrap().unwrap(), basename);
            let rest = &rest[atoms.byte_offset()..];
            let marker = format!(" (PID {}, TID 8) exe=", key.pid);
            let rest = rest.strip_prefix(&marker).unwrap();
            let mut atoms = serde_json::Deserializer::from_str(rest).into_iter::<String>();
            assert_eq!(atoms.next().unwrap().unwrap(), escaped_path);
            assert_eq!(
                &rest[atoms.byte_offset()..],
                " sess#7 C_GetInfo -> CKR_OK 3.0us"
            );
        }
    }

    #[test]
    fn trace_identity_renderer_context_and_public_unknown_wrapper() {
        assert_eq!(
            identity_note(),
            "Trace - completed call events in arrival order\nExecutable labels use verified observed paths; event PID/TID remain diagnostic identifiers."
        );
        let ev = Event {
            pid_tgid: (123u64 << 32) | 456,
            duration_ns: 3_000,
            ..Event::default()
        };
        assert_eq!(
            format_line(&ev, 0, "C_GetInfo", None),
            "00:00:00.000000 Unknown executable (PID 123, TID 456) C_GetInfo -> CKR_OK 3.0us"
        );
    }

    #[test]
    fn trace_identity_renderer_to_actual_python_consumers() {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let (proof, receipt) = verified_fixture_with_link(
            "/owned/q\"u\\ote (PID 9, TID 8) sess#4\u{2028}\u{2029} (deleted)".as_bytes(),
        );
        let key = receipt.key();
        let mut store = TraceIdentityStore::new(proof);
        store.admit(receipt).unwrap();
        let ev = event(key, 20);
        let lines = [
            "C_GenerateRandom",
            "C_DigestInit",
            "C_Digest",
            "C_FindObjectsInit",
            "C_FindObjects",
            "C_FindObjectsFinal",
        ]
        .map(|function| {
            format_line_with_executable(&ev, 0, function, Some(7), store.lookup(key, 20))
        });
        assert!(lines.iter().all(|line| line.contains(" exe=")), "{lines:?}");
        let text = format!(
            "{}\n{}\n{}\nCOUNT_EVIDENCE {}\nEVIDENCE {}\n",
            capture_line(CapturePolicy::Allowlisted),
            identity_note(),
            lines.join("\n"),
            serde_json::json!({"stats_entered":6, "stats_returned":6, "raw_calls":6}),
            serde_json::json!({"event_loss":0, "verdict_detail":"attribution_only",
                "pid_namespace":{"observer":"initial", "kernel_pids":"initial", "proc_pids":"observer"},
                "gap_classes":{"observation":{"causes":[], "status":"exact"}}})
        );
        let program = r#"
import contextlib,io,json,pathlib,runpy,sys,tempfile
root=pathlib.Path(sys.argv[1]); pid=int(sys.argv[2]); text=sys.stdin.read()
measure=runpy.run_path(str(root/'scripts/system-scope-measure.py'))
assert measure['parse_trace_stream'](text.splitlines())['call_lines_total']==6
checker=runpy.run_path(str(root/'scripts/check-canary-evidence.py'))
rest=checker['trace_scannable']('actual renderer',text)
checker['assert_no_loader_pause_identity']('actual renderer',rest)
assert '/owned/q"u\\ote (PID 9, TID 8) sess#4\u2028\u2029 (deleted)' in rest
arguments=sys.argv; sys.argv=['kind-e2e-oracle.py','--self-test']
kind=runpy.run_path(str(root/'scripts/kind-e2e-oracle.py')); sys.argv=arguments
assert kind['trace_exact'](text,1)['trace_pids']==[pid]
source=(root/'scripts/matrix/verify-pidns.sh').read_text()
block=source.split('  d=$(python3 - "$OUT" "$ITERS" <<\'PY\'\n',1)[1].split('\nPY\n',1)[0]
with tempfile.TemporaryDirectory() as raw:
    out=pathlib.Path(raw)
    (out/'nested-trace.txt').write_text(text)
    (out/'nested-trace.wl').write_text('READY pid=7\n')
    (out/'nested-trace.rc').write_text('0\n')
    sys.argv=['actual-renderer',raw,'1']; output=io.StringIO()
    with contextlib.redirect_stdout(output): exec(compile(block,str(root/'scripts/matrix/verify-pidns.sh'),'exec'),{})
    result=json.loads(output.getvalue())
    assert result['printed_pids']==[pid] and result['call_lines']==6
"#;
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            Command::new("python3")
                .args(["-I", "-c", program])
                .arg(env!("CARGO_MANIFEST_DIR"))
                .arg(key.pid.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .die_with_parent()
                .spawn()
                .unwrap(),
        );
        child
            .0
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "actual Python consumer exceeded its owned deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        let mut stderr = String::new();
        child
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(status.success(), "{stderr}");
    }
}

/// A fixed original wall/monotonic anchor for output-only test fixtures.
/// Production tracers keep deriving their first anchor from `SystemTime`.
#[cfg(test)]
pub(crate) fn tracer_with_test_wall_anchor(
    plan: &AttachPlan,
    mono_ns: u64,
    wall_ns: u128,
) -> Tracer {
    let mut tracer = Tracer::new(plan);
    tracer.anchor = Some((mono_ns, wall_ns));
    tracer
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
        ev.mechanism = pkcs11_types::CkMechanismType::RSA_PKCS_PSS.0;
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
            "12:00:01.123456 Unknown executable (PID 12345, TID 12401) sess#7 C_SignInit \
             CKM_RSA_PKCS_PSS(hash=SHA256 mgf=MGF1_SHA256 salt=32) -> CKR_OK 18.0us"
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
            line.contains(" C_EncryptInit 0xffffffffffffffff -> CKR_OK"),
            "line: {line}"
        );
    }

    #[test]
    fn known_mechanism_id_with_no_decoded_shape_still_renders_by_name_only() {
        let mut ev = base_event();
        ev.mechanism = pkcs11_types::CkMechanismType::AES_GCM.0;
        ev.capture = capture::MECHANISM_VALUE;
        ev.shape = shape::NONE; // e.g. decode failed this call

        let line = format_line(&ev, 0, "C_EncryptInit", None);
        assert!(line.contains("CKM_AES_GCM"), "line: {line}");
        assert!(
            !line.contains("CKM_AES_GCM("),
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

    /// v070-ckr-reasons: a vendor return code keeps its current trace
    /// rendering while the name lookup moves to the shared helper.
    #[test]
    fn vendor_call_keeps_its_current_trace_rendering() {
        let mut ev = base_event();
        ev.rv = 0x8000_0001; // CKR_VENDOR_DEFINED + 1, unregistered
        let line = format_line(&ev, 0, "C_Sign", Some(3));
        assert!(line.contains("CKR_UNKNOWN"), "line: {line}");
    }

    #[test]
    fn target_controlled_function_name_controls_are_escaped_like_inspect() {
        // Slot labels come from the target's own tables: a hostile name
        // must not reach the terminal raw.
        let ev = base_event();
        let line = format_line(&ev, 0, "C_Sign\x1b[2J\n evil", None);
        assert!(!line.contains('\x1b'), "raw escape: {line:?}");
        assert!(!line.contains('\n'), "raw newline: {line:?}");
        assert!(line.contains(r"C_Sign\u{1b}[2J\n evil"), "line: {line:?}");
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
            file_offset: 0,
            target_object: None,
            ordinals: Vec::new(),
            names: vec![],
            aliased: false,
            semantic_authorized: true,
            module: None,
            module_ambiguous: false,
            module_unresolved: false,
            mode: p11scope_ebpf_common::CounterMode::Latency,
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

    /// The terminal EVIDENCE record names every refused or partially covered
    /// module with its reason.
    #[test]
    fn evidence_line_names_refused_and_partially_covered_modules() {
        let mut ev = empty_evidence();
        ev.discovery.modules_skipped = vec![
            render::SkippedOut {
                name: "/opt/p11-kit-trust.so".into(),
                reason: "module needs 68 more; only 512 attach slots are available".into(),
            },
            render::SkippedOut {
                name: "/opt/libp11-kit.so".into(),
                reason: "admitted module needs 6120 more; only 512 attach slots are available"
                    .into(),
            },
        ];
        let line = evidence_line(&ev, crate::attach::CapturePolicy::Allowlisted);
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
        assert_eq!(value["modules_skipped"][0]["name"], "/opt/p11-kit-trust.so");
        assert!(
            value["modules_skipped"][0]["reason"]
                .as_str()
                .unwrap()
                .contains("module needs 68 more"),
            "{value}"
        );
        assert_eq!(value["modules_skipped"][1]["name"], "/opt/libp11-kit.so");
        assert!(
            value["modules_skipped"][1]["reason"]
                .as_str()
                .unwrap()
                .contains("admitted module needs 6120 more"),
            "{value}"
        );
    }

    fn empty_evidence() -> render::Evidence {
        render::Evidence {
            discovery: render::DiscoveryEvidence::default(),
            table_entries: 0,
            slots: 0,
            active_slots: 0,
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
            abi_refusals: 0,
            semantic_capture_failures: 0,
            unregistered_mechanisms: 0,
            unpublished_mechanisms: 0,
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
            semantic_key_budget: crate::semantics::MAX_STATE_KEYS,
            semantic_state_drops: 0,
            mechanism_id_overflow: 0,
            unregistered_standard_layout_mechanisms: 0,
            standard_layout_slots: 0,
            standard_layout_evidence: Vec::new(),
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
            pause_unavailable: 0,
            pause_engine_incomplete_retirements: 0,
            pause_refused: None,
            snapshot_failure: None,
            child_still_running: None,
            run_tree_handed_back: None,
            ring_accounting: render::RingAccountingEvidence::unknown(),
            discovery_ring_loss: 0,
            discovery_state_failures: 0,
            discovery_read_failures: 0,
            discovery_truncated: 0,
            task_uprobe_link_losses: 0,
            kernel_control: Default::default(),
            loader_discovery: render::LoaderDiscovery::default(),
            interface_selection: render::InterfaceSelection::default(),
            attach_mechanisms: vec![],
            attach_backend: Default::default(),
            object_capture: render::ObjectCaptureEvidence::for_build(false),
            pid_descendant_gaps: 0,
            multi_rebuild_gaps: 0,
            learned_staged_files: 0,
            learned_event_loss: 0,
            learned_cap_skipped: 0,
            gap_exe_hints: None,
            target_exec_hints: None,
            instance_reload_not_excluded: None,
            unprotected_live_windows: 0,
            module_unresolved_slots: 0,
            provider_changed: false,
            scheduling: render::SchedulingEvidence::default(),
            stop_quiescence: Default::default(),
            drain_proven: false,
            verdict_detail: render::VERDICT_CONCRETE_GAP,
            gap_classes: render::GapClasses::default(),
            stdout_data_sink: false,
            trace_truncated: false,
            uretprobe_override: None,
            handoff_child_pid: None,
            pid_namespace: crate::pidns::PidNamespaceEvidence::of(
                &crate::pidns::PidNumbering::agreeing(),
            ),
            container_only_view: false,
            p11scope_env: vec![],
            completeness: "COMPLETE",
        }
    }

    #[test]
    fn final_evidence_line_is_machine_readable_and_never_claims_a_proven_drain() {
        let evidence = empty_evidence();
        let line = evidence_line(&evidence, crate::attach::CapturePolicy::Allowlisted);
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

    // SG-T7B (owner ruling B): the trace terminal record carries the sealed
    // verdict. A proven stop-gate drain is COMPLETE with `final_drain:
    // true`; anything less stays PARTIAL with `final_drain: false`.
    #[test]
    #[cfg(target_arch = "x86_64")] // the drain proof applies on x86_64 only
    fn final_evidence_line_carries_a_proven_drain_and_its_sealed_verdict() {
        use crate::render::{QuiescenceState, StopQuiescence};
        let line_for = |stop: StopQuiescence| {
            let mut evidence = crate::render::tests::evidence();
            evidence.apply_stop_quiescence(stop);
            evidence.settle_terminal(true);
            let line = evidence_line(&evidence, CapturePolicy::Allowlisted);
            serde_json::from_str::<serde_json::Value>(line.strip_prefix("EVIDENCE ").unwrap())
                .unwrap()
        };
        let proven = line_for(StopQuiescence {
            state: QuiescenceState::Proven,
            ..Default::default()
        });
        assert_eq!(proven["completeness"], "COMPLETE");
        assert_eq!(proven["final_drain"], true);
        assert_eq!(proven["drain_proven"], true);
        assert_eq!(proven["verdict_detail"], "clean_proven");
        assert_eq!(proven["stop_quiescence"]["state"], "proven");
        let post_q = line_for(StopQuiescence {
            state: QuiescenceState::Proven,
            post_q_events: true,
            post_q_discovery: false,
        });
        assert_eq!(post_q["completeness"], "PARTIAL");
        assert_eq!(post_q["final_drain"], false);
        assert_eq!(post_q["verdict_detail"], "clean_but_unproven");
        assert_eq!(post_q["stop_quiescence"]["post_q_events"], true);
    }

    // DR-RETRO-C6-1: truncation forces PARTIAL even behind a proven drain
    // (observed-profile-v3, "Any truncation … forces PARTIAL"). The
    // unproven fixture above cannot show this: it is PARTIAL anyway. The
    // cause is in the sealed classes too, so `verdict_detail` agrees with
    // `completeness` and a consumer of either sees the gap.
    #[test]
    #[cfg(target_arch = "x86_64")] // the drain proof applies on x86_64 only
    fn a_truncated_trace_with_a_proven_drain_is_partial() {
        use crate::render::{QuiescenceState, StopQuiescence};
        let mut evidence = crate::render::tests::evidence();
        evidence.trace_truncated = true;
        evidence.apply_stop_quiescence(StopQuiescence {
            state: QuiescenceState::Proven,
            ..Default::default()
        });
        evidence.settle_terminal(true);
        let line = evidence_line(&evidence, CapturePolicy::Allowlisted);
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
        assert_eq!(value["trace_truncated"], true);
        assert_eq!(value["final_drain"], true);
        assert_eq!(value["drain_proven"], true);
        assert_eq!(value["completeness"], "PARTIAL");
        assert_eq!(value["verdict_detail"], "concrete_gap");
        assert_eq!(
            value["gap_classes"]["observation"],
            serde_json::json!({"status": "lossy", "causes": ["trace_truncated"]})
        );
        assert_eq!(evidence.completeness, "PARTIAL");
    }

    // The record re-gates on truncation itself, like it re-gates on the
    // latch: an unsealed snapshot that still reads COMPLETE never prints it.
    #[test]
    fn an_unsealed_truncated_snapshot_never_prints_complete() {
        let mut evidence = empty_evidence();
        evidence.drain_proven = true;
        evidence.completeness = "COMPLETE";
        evidence.trace_truncated = true;
        let line = evidence_line(&evidence, CapturePolicy::Allowlisted);
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
        assert_eq!(value["completeness"], "PARTIAL");
        evidence.trace_truncated = false;
        let line = evidence_line(&evidence, CapturePolicy::Allowlisted);
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
        assert_eq!(value["completeness"], "COMPLETE", "the control");
        assert_eq!(value["trace_truncated"], false);
    }

    #[test]
    fn selection_evidence_is_terminal_only() {
        for line in [
            capture_line(CapturePolicy::Allowlisted),
            lost_line(1).unwrap(),
            truncated_line(1, true),
        ] {
            assert!(!line.contains("interface_selection"));
            assert!(!line.contains("selection_truncated"));
        }
        assert!(
            evidence_line(&empty_evidence(), CapturePolicy::Allowlisted)
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
        assert_eq!(
            truncated_line(1, true),
            "TRUNCATED at 1 events (--max-events 1)"
        );
        assert_eq!(
            truncated_line(1, false),
            "TRUNCATED at 1 events (default cap; pass --max-events <n> to change it)"
        );
        let mut evidence = empty_evidence();
        evidence.trace_truncated = true;
        evidence.settle_terminal(true);
        let line = evidence_line(&evidence, crate::attach::CapturePolicy::Allowlisted);
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
        assert_eq!(value["trace_truncated"], true);
        assert_eq!(value["completeness"], "PARTIAL");
        assert!(
            value["gap_classes"]["observation"]["causes"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("trace_truncated"))
        );
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

    fn call_event(pid: u32, slot: u32, rv: u64) -> Event {
        let mut ev = base_event();
        ev.pid_tgid = (u64::from(pid) << 32) | 1;
        ev.slot = slot;
        ev.rv = rv;
        ev
    }

    fn complete_evidence() -> render::Evidence {
        let mut ev = crate::render::tests::evidence();
        ev.completeness = "COMPLETE";
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
        event.mechanism = pkcs11_types::CkMechanismType::AES_GCM.0;
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
            "00:00:00.000000 Unknown executable (PID 100, TID 1) C_OpenSession -> CKR_OK 18.0us"
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
        dynamic.mechanism = pkcs11_types::CkMechanismType::AES_GCM.0;
        let dynamic_line = tracer.on_event(&dynamic, &mut state);
        assert!(
            dynamic_line.contains(" C_Sign CKM_AES_GCM"),
            "{dynamic_line}"
        );

        let mut unknown = dynamic;
        unknown.slot = 99;
        let unknown_line = tracer.on_event(&unknown, &mut state);
        assert!(unknown_line.contains(" slot#99 ->"), "{unknown_line}");
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

    // SYSPLAN residual F-17 (GREEN): the TRUNCATED message cites the effective
    // cap instead of blaming a flag the operator never passed.
    #[test]
    fn truncated_message_cites_effective_default_cap() {
        let msg = truncated_line(10_000_000, false);
        assert!(
            msg.contains("default"),
            "default-cap truncation must say so: {msg:?}"
        );
        assert!(
            !msg.contains("--max-events 10000000"),
            "must not blame an unpassed flag value: {msg:?}"
        );
        let explicit = truncated_line(5, true);
        assert!(
            explicit.contains("--max-events 5"),
            "explicit cap must cite the flag: {explicit:?}"
        );
    }

    /// CLI text: an owned run names its command on lines the identity
    /// proof cannot resolve, with the resolved spawn path; any other
    /// process stays unknown rather than mislabeled.
    #[test]
    fn owned_command_names_unknown_executable_lines() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        tracer.anchor = Some((0, 0));
        tracer.set_owned_command(100, "/usr/bin/pkcs11-tool".to_string());
        let line = tracer.on_event(&open_event(100, 0xdead_beef), &mut state);
        assert!(
            line.contains("\"pkcs11-tool\" (PID 100, TID 1) exe=\"/usr/bin/pkcs11-tool\""),
            "{line}"
        );
        assert!(!line.contains("Unknown executable"), "{line}");
        let foreign = tracer.on_event(&open_event(200, 0xdead_beef), &mut state);
        assert!(foreign.contains("Unknown executable"), "{foreign}");
    }

    /// CLI text: no per-line semantics marker; the header note says
    /// once that unverified calls are not decoded.
    #[test]
    fn trace_lines_carry_no_per_line_semantics_marker() {
        let mut plan = test_plan();
        plan.slots[0].semantic_authorized = false;
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        tracer.anchor = Some((0, 0));
        let line = tracer.on_event(&open_event(100, 0xdead_beef), &mut state);
        assert!(line.contains("C_OpenSession"), "{line}");
        assert!(!line.contains("[semantics unverified]"), "{line}");
        assert!(
            unverified_note().contains("not decoded"),
            "{}",
            unverified_note()
        );
        assert!(watches_unverified(&plan));
        assert!(!watches_unverified(&test_plan()));
        assert!(watches_unverified(&AttachPlan::from_slots(vec![])));
    }

    /// CLI text: the trace tail reports totals, one coverage line, and
    /// the `-v` hint in default text; verbose pairs machine names and
    /// drops the hint, quiet drops the hint.
    #[test]
    fn terminal_summary_reports_totals_coverage_and_hint() {
        let mut ev = crate::render::tests::evidence();
        ev.event_loss = 1;
        ev.verdict();
        let callers = CallerReasons::default();
        let concise = terminal_summary(19, 0, 0, &ev, crate::cli::TextVerbosity::Concise, &callers);
        assert_eq!(
            concise,
            vec![
                "19 completed calls; 0 returned errors; 0 entries without an observed return."
                    .to_string(),
                "coverage: partial - calls may be missing (1 call record lost)".to_string(),
                crate::cli::VERBOSE_HINT.to_string(),
            ]
        );
        let verbose = terminal_summary(19, 0, 0, &ev, crate::cli::TextVerbosity::Verbose, &callers);
        assert_eq!(verbose.len(), 2);
        assert!(verbose[1].contains("(event_loss)"), "{verbose:?}");
        assert!(
            !verbose.iter().any(|line| line.contains("-v")),
            "{verbose:?}"
        );
        let quiet = terminal_summary(19, 0, 0, &ev, crate::cli::TextVerbosity::Quiet, &callers);
        assert_eq!(quiet.len(), 2);
        assert!(!quiet[1].contains("event_loss"), "{quiet:?}");
    }

    /// CLI text: the trace header labels the event clock. Trace
    /// stamps are UTC wall time anchored to the kernel monotonic
    /// clock, so the header says so once, after the identity note and
    /// before the unverified note.
    #[test]
    fn trace_header_labels_utc_after_identity() {
        let plan = test_plan();
        assert_eq!(
            header(CapturePolicy::Allowlisted, &plan),
            "CAPTURE privacy=allowlisted\nTrace - completed call events in arrival order\nExecutable \
             labels use verified observed paths; event PID/TID remain diagnostic \
             identifiers.\nTrace times are UTC."
        );
        let unwatched = AttachPlan::from_slots(vec![]);
        assert!(
            header(CapturePolicy::Allowlisted, &unwatched).ends_with(
                "\nTrace times are UTC.\nCalls on unverified functions are not decoded (names only)."
            ),
            "the zone note precedes the unverified note"
        );
    }

    /// The trace tail attributes failures per caller: one row per failing
    /// (caller, function) pair with its `CKR_*` reasons, named callers under
    /// their owned-or-verified label, the rest under `Unknown executable`.
    #[test]
    fn caller_reasons_roll_up_per_caller_function_and_rv() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        tracer.set_owned_command(100, "/usr/bin/firefox".to_string());
        let pin = pkcs11_types::CkRv::PIN_INCORRECT.0;
        let general = pkcs11_types::CkRv::GENERAL_ERROR.0;
        let device = pkcs11_types::CkRv::DEVICE_ERROR.0;
        tracer.on_event(&call_event(100, 0, pin), &mut state);
        tracer.on_event(&call_event(100, 0, pin), &mut state);
        tracer.on_event(&call_event(100, 0, pkcs11_types::CkRv::OK.0), &mut state);
        tracer.on_event(&call_event(100, 1, general), &mut state);
        tracer.on_event(&call_event(200, 0, device), &mut state);
        let ev = complete_evidence();
        let tail = terminal_summary(
            5,
            4,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            tracer.caller_reasons(),
        );
        assert_eq!(
            tail,
            vec![
                "5 completed calls; 4 returned errors; 0 entries without an observed return."
                    .to_string(),
                "coverage: complete".to_string(),
                "CALLER ERROR REASONS:".to_string(),
                "\"firefox\" (PID 100) exe=\"/usr/bin/firefox\": C_OpenSession: CKR_PIN_INCORRECT x2"
                    .to_string(),
                "\"firefox\" (PID 100) exe=\"/usr/bin/firefox\": C_CloseSession: CKR_GENERAL_ERROR x1"
                    .to_string(),
                "Unknown executable (PID 200): C_OpenSession: CKR_DEVICE_ERROR x1".to_string(),
                crate::cli::VERBOSE_HINT.to_string(),
            ]
        );
        let verbose = terminal_summary(
            5,
            4,
            0,
            &ev,
            crate::cli::TextVerbosity::Verbose,
            tracer.caller_reasons(),
        );
        assert_eq!(verbose.len(), 6);
        assert_eq!(&verbose[2..6], &tail[2..6]);
    }

    /// One row's reason list is bounded in concise text (top three plus an
    /// `and N more` tail) and complete under `-v`, like the profile view.
    #[test]
    fn caller_reasons_concise_bounds_reasons_and_verbose_lists_all() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        for (rv, n) in [
            (pkcs11_types::CkRv::GENERAL_ERROR.0, 5),
            (pkcs11_types::CkRv::DEVICE_ERROR.0, 4),
            (pkcs11_types::CkRv::PIN_INCORRECT.0, 3),
            (pkcs11_types::CkRv::CANCEL.0, 2),
            (pkcs11_types::CkRv::BUFFER_TOO_SMALL.0, 1),
        ] {
            for _ in 0..n {
                tracer.on_event(&call_event(50, 0, rv), &mut state);
            }
        }
        let ev = complete_evidence();
        let concise = terminal_summary(
            15,
            15,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            tracer.caller_reasons(),
        );
        assert_eq!(
            concise[3],
            "Unknown executable (PID 50): C_OpenSession: CKR_GENERAL_ERROR x5, \
             CKR_DEVICE_ERROR x4, CKR_PIN_INCORRECT x3, and 2 more"
        );
        let verbose = terminal_summary(
            15,
            15,
            0,
            &ev,
            crate::cli::TextVerbosity::Verbose,
            tracer.caller_reasons(),
        );
        assert_eq!(
            verbose[3],
            "Unknown executable (PID 50): C_OpenSession: CKR_GENERAL_ERROR x5, \
             CKR_DEVICE_ERROR x4, CKR_PIN_INCORRECT x3, CKR_CANCEL x2, \
             CKR_BUFFER_TOO_SMALL x1"
        );
    }

    /// Success and pending returns are never reasons, and a trace whose
    /// rendered lines hold no failures carries no section at any level.
    #[test]
    fn caller_reasons_exclude_ok_and_pending_and_clean_traces_have_no_section() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        let ok = pkcs11_types::CkRv::OK.0;
        tracer.on_event(&call_event(60, 0, ok), &mut state);
        tracer.on_event(&call_event(60, 0, ok), &mut state);
        tracer.on_event(
            &call_event(60, 0, pkcs11_types::CkRv::PENDING.0),
            &mut state,
        );
        tracer.on_event(
            &call_event(60, 0, pkcs11_types::CkRv::DEVICE_ERROR.0),
            &mut state,
        );
        let ev = complete_evidence();
        let tail = terminal_summary(
            4,
            1,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            tracer.caller_reasons(),
        );
        assert_eq!(
            tail[3],
            "Unknown executable (PID 60): C_OpenSession: CKR_DEVICE_ERROR x1"
        );

        let mut clean_state = State::new(&plan);
        let mut clean = Tracer::new(&plan);
        clean.on_event(&call_event(60, 0, ok), &mut clean_state);
        for verbosity in [
            crate::cli::TextVerbosity::Concise,
            crate::cli::TextVerbosity::Verbose,
            crate::cli::TextVerbosity::Quiet,
        ] {
            let tail = terminal_summary(1, 0, 0, &ev, verbosity, clean.caller_reasons());
            assert!(
                !tail
                    .iter()
                    .any(|line| line.contains("CALLER ERROR REASONS")),
                "{tail:?}"
            );
            assert!(!tail.iter().any(|line| line.contains("PID 60")), "{tail:?}");
        }
        assert_eq!(
            terminal_summary(
                1,
                0,
                0,
                &ev,
                crate::cli::TextVerbosity::Concise,
                clean.caller_reasons()
            )
            .len(),
            3
        );
    }

    /// Counted errors with no failure reasons among the rendered lines —
    /// the failures never reached the stream — name that gap instead of
    /// printing an empty section.
    #[test]
    fn caller_reasons_name_the_gap_when_errors_leave_no_rendered_failures() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        tracer.on_event(&call_event(60, 0, pkcs11_types::CkRv::OK.0), &mut state);
        let ev = complete_evidence();
        let tail = terminal_summary(
            4,
            3,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            tracer.caller_reasons(),
        );
        assert_eq!(tail[2], "CALLER ERROR REASONS:");
        assert_eq!(
            tail[3],
            "(3 errors counted; no failure reasons among rendered lines)"
        );
        let one = terminal_summary(
            2,
            1,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            tracer.caller_reasons(),
        );
        assert_eq!(
            one[3],
            "(1 error counted; no failure reasons among rendered lines)"
        );
    }

    /// A truncated stream's roll-up covers the rendered lines only, and
    /// says so; an untruncated one carries no such note.
    #[test]
    fn caller_reasons_cover_rendered_lines_only_when_truncated() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        tracer.on_event(
            &call_event(70, 0, pkcs11_types::CkRv::DEVICE_ERROR.0),
            &mut state,
        );
        let mut ev = complete_evidence();
        ev.trace_truncated = true;
        let tail = terminal_summary(
            1,
            1,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            tracer.caller_reasons(),
        );
        assert_eq!(
            tail[tail.len() - 2],
            "(caller reasons cover rendered lines only; trace truncated)"
        );
        ev.trace_truncated = false;
        let whole = terminal_summary(
            1,
            1,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            tracer.caller_reasons(),
        );
        assert!(
            !whole
                .iter()
                .any(|line| line.contains("rendered lines only")),
            "{whole:?}"
        );
    }

    /// A roll-up row names its caller exactly as the lines do, hostile
    /// bytes quoted the same way — never a second spelling.
    #[test]
    fn caller_reasons_quote_hostile_caller_names_like_lines() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        tracer.set_owned_command(100, "/x/a\"b".to_string());
        let line = tracer.on_event(
            &call_event(100, 0, pkcs11_types::CkRv::DEVICE_ERROR.0),
            &mut state,
        );
        assert!(
            line.contains("\"a\\\"b\" (PID 100, TID 1) exe=\"/x/a\\\"b\""),
            "{line}"
        );
        let ev = complete_evidence();
        let tail = terminal_summary(
            1,
            1,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            tracer.caller_reasons(),
        );
        assert_eq!(
            tail[3],
            "\"a\\\"b\" (PID 100) exe=\"/x/a\\\"b\": C_OpenSession: CKR_DEVICE_ERROR x1"
        );
    }

    /// Rows read worst-first: callers by failure count, then pid; functions
    /// within a caller by failure count, then name.
    #[test]
    fn caller_reasons_sort_by_failures_then_identity() {
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        tracer.on_event(
            &call_event(300, 0, pkcs11_types::CkRv::DEVICE_ERROR.0),
            &mut state,
        );
        tracer.on_event(
            &call_event(100, 0, pkcs11_types::CkRv::PIN_INCORRECT.0),
            &mut state,
        );
        tracer.on_event(
            &call_event(100, 1, pkcs11_types::CkRv::GENERAL_ERROR.0),
            &mut state,
        );
        tracer.on_event(
            &call_event(200, 0, pkcs11_types::CkRv::CANCEL.0),
            &mut state,
        );
        tracer.on_event(
            &call_event(200, 0, pkcs11_types::CkRv::CANCEL.0),
            &mut state,
        );
        let ev = complete_evidence();
        let tail = terminal_summary(
            5,
            5,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            tracer.caller_reasons(),
        );
        assert_eq!(
            &tail[2..7],
            &[
                "CALLER ERROR REASONS:".to_string(),
                "Unknown executable (PID 100): C_CloseSession: CKR_GENERAL_ERROR x1".to_string(),
                "Unknown executable (PID 100): C_OpenSession: CKR_PIN_INCORRECT x1".to_string(),
                "Unknown executable (PID 200): C_OpenSession: CKR_CANCEL x2".to_string(),
                "Unknown executable (PID 300): C_OpenSession: CKR_DEVICE_ERROR x1".to_string(),
            ]
        );
    }

    /// The verified executable label wins over the owned command's spawn
    /// path in the roll-up, exactly as on the line itself.
    #[test]
    fn caller_reasons_use_the_verified_executable_label() {
        use crate::discovery::engine::tests::detailed_proof_driver::verified_fixture_with_link;
        use crate::trace_identity::TraceIdentityStore;
        let (proof, receipt) = verified_fixture_with_link(b"/usr/bin/firefox");
        let key = receipt.key();
        let mut store = TraceIdentityStore::new(proof);
        store.admit(receipt).unwrap();
        let plan = test_plan();
        let mut state = State::new(&plan);
        let mut tracer = Tracer::new(&plan);
        tracer.set_owned_command(key.pid, "/other/binary".to_string());
        let mut ev = call_event(key.pid, 0, pkcs11_types::CkRv::DEVICE_ERROR.0);
        ev.ts_ns = 20;
        let line =
            tracer.on_event_process_with_executable(&ev, key, &mut state, store.lookup(key, 20));
        assert!(line.contains("exe=\"/usr/bin/firefox\""), "{line}");
        assert!(!line.contains("other"), "{line}");
        let evidence = complete_evidence();
        let tail = terminal_summary(
            1,
            1,
            0,
            &evidence,
            crate::cli::TextVerbosity::Concise,
            tracer.caller_reasons(),
        );
        assert_eq!(
            tail[3],
            format!(
                "\"firefox\" (PID {}) exe=\"/usr/bin/firefox\": C_OpenSession: CKR_DEVICE_ERROR x1",
                key.pid
            )
        );
    }

    /// Lines rendered without admitted history still join the roll-up
    /// under the caller identity they show.
    #[test]
    fn rejected_history_lines_join_the_caller_rollup() {
        let plan = test_plan();
        let mut tracer = Tracer::new(&plan);
        let bad = pkcs11_types::CkRv::SESSION_HANDLE_INVALID.0;
        tracer.on_rejected_history(&call_event(400, 1, bad));
        let ev = complete_evidence();
        let tail = terminal_summary(
            1,
            1,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            tracer.caller_reasons(),
        );
        assert_eq!(
            tail[3],
            "Unknown executable (PID 400): C_CloseSession: CKR_SESSION_HANDLE_INVALID x1"
        );

        let mut owned = Tracer::new(&plan);
        owned.set_owned_command(400, "/sbin/cryptsetup".to_string());
        owned.on_rejected_history(&call_event(400, 1, bad));
        let tail = terminal_summary(
            1,
            1,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            owned.caller_reasons(),
        );
        assert_eq!(
            tail[3],
            "\"cryptsetup\" (PID 400) exe=\"/sbin/cryptsetup\": C_CloseSession: \
             CKR_SESSION_HANDLE_INVALID x1"
        );
    }

    /// B0 sizes: `note()` records failing lines only — OK/PENDING never
    /// occupy the roll-up, so a clean caller leaves no entry at all.
    #[test]
    fn caller_reasons_note_skips_ok_and_pending() {
        let ok = pkcs11_types::CkRv::OK.0;
        let pending = pkcs11_types::CkRv::PENDING.0;
        let device = pkcs11_types::CkRv::DEVICE_ERROR.0;
        let mut reasons = CallerReasons::default();
        for _ in 0..3 {
            reasons.note(60, None, "C_OpenSession", ok);
        }
        for _ in 0..2 {
            reasons.note(60, None, "C_OpenSession", pending);
        }
        assert_eq!(reasons.caller_entries(), 0);
        assert_eq!(reasons.row_entries(), 0);
        assert!(!reasons.overflowed());
        assert_eq!(reasons.folded_lines(), 0);
        reasons.note(60, None, "C_OpenSession", device);
        assert_eq!(reasons.caller_entries(), 1);
        assert_eq!(reasons.row_entries(), 1);
    }

    /// B0 cap: the roll-up retains at most 4096 failing callers; further
    /// distinct callers fold into one bounded "(other callers)" row per
    /// (function, rv), rendered after the retained callers.
    #[test]
    fn caller_reasons_fold_overflow_callers_past_4096() {
        let device = pkcs11_types::CkRv::DEVICE_ERROR.0;
        let mut reasons = CallerReasons::default();
        for pid in 0..4096u32 {
            reasons.note(pid, None, "C_OpenSession", device);
        }
        assert_eq!(reasons.caller_entries(), MAX_CALLER_REASONS_CALLERS);
        assert!(!reasons.overflowed());
        for pid in 4096..4099u32 {
            reasons.note(pid, None, "C_OpenSession", device);
        }
        assert_eq!(reasons.caller_entries(), MAX_CALLER_REASONS_CALLERS);
        assert!(reasons.overflowed());
        assert_eq!(reasons.folded_lines(), 3);
        // A retained caller still counts exactly past the cap.
        reasons.note(7, None, "C_OpenSession", device);
        assert_eq!(reasons.folded_lines(), 3);
        assert_eq!(reasons.caller_entries(), MAX_CALLER_REASONS_CALLERS);
        let ev = complete_evidence();
        let tail = terminal_summary(
            4100,
            4100,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            &reasons,
        );
        let folded = tail
            .iter()
            .rposition(|line| line.contains("(other callers)"))
            .expect("the fold renders plainly");
        assert_eq!(
            tail[folded],
            "(other callers): C_OpenSession: CKR_DEVICE_ERROR x3"
        );
        assert!(
            tail[..folded]
                .iter()
                .all(|line| !line.contains("(other callers)")),
            "the fold renders after every retained caller"
        );
        assert!(
            tail[..folded]
                .iter()
                .any(|line| line.contains("PID 7") && line.contains("CKR_DEVICE_ERROR x2")),
            "retained callers keep exact counts past the cap"
        );
    }

    /// B0 EVIDENCE: `caller_reasons_overflow` is absent under the cap and
    /// a counted gap past it.
    #[test]
    fn caller_reasons_overflow_evidence_field_counts_the_fold() {
        let device = pkcs11_types::CkRv::DEVICE_ERROR.0;
        let ev = empty_evidence();
        let mut under = CallerReasons::default();
        under.note(1, None, "C_OpenSession", device);
        let line = evidence_line_with_caller_overflow(
            &ev,
            crate::attach::CapturePolicy::Allowlisted,
            &under,
        );
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
        assert!(value.get("caller_reasons_overflow").is_none(), "{value}");
        let mut over = CallerReasons::default();
        for pid in 0..4097u32 {
            over.note(pid, None, "C_OpenSession", device);
        }
        let line = evidence_line_with_caller_overflow(
            &ev,
            crate::attach::CapturePolicy::Allowlisted,
            &over,
        );
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
        assert_eq!(
            value["caller_reasons_overflow"],
            serde_json::json!({"folded_lines": 1, "folded_rows": 1})
        );
        // The legacy entry point never carries the field.
        let legacy = evidence_line(&ev, crate::attach::CapturePolicy::Allowlisted);
        let legacy_value: serde_json::Value =
            serde_json::from_str(legacy.strip_prefix("EVIDENCE ").unwrap()).unwrap();
        assert!(legacy_value.get("caller_reasons_overflow").is_none());
    }

    /// B0 fold shape: overflow groups by function, not by pair — one
    /// rendered line per function with worst-first reasons — while
    /// `folded_rows` counts the folded (function, rv) pairs.
    #[test]
    fn caller_reasons_fold_groups_overflow_by_function_worst_first() {
        let device = pkcs11_types::CkRv::DEVICE_ERROR.0;
        let general = pkcs11_types::CkRv::GENERAL_ERROR.0;
        let mut reasons = CallerReasons::default();
        for pid in 0..4096u32 {
            reasons.note(pid, None, "C_OpenSession", device);
        }
        assert!(!reasons.overflowed());
        let mut pid = 4096u32;
        for (function, rv, n) in [
            ("C_Login", device, 5),
            ("C_Login", general, 3),
            ("C_OpenSession", general, 2),
        ] {
            for _ in 0..n {
                reasons.note(pid, None, function, rv);
                pid += 1;
            }
        }
        assert!(reasons.overflowed());
        assert_eq!(reasons.folded_lines(), 10);
        assert_eq!(reasons.folded_rows(), 3);
        let ev = complete_evidence();
        let tail = terminal_summary(
            4106,
            4106,
            0,
            &ev,
            crate::cli::TextVerbosity::Concise,
            &reasons,
        );
        let folded: Vec<&str> = tail
            .iter()
            .filter(|line| line.contains("(other callers)"))
            .map(String::as_str)
            .collect();
        assert_eq!(
            folded,
            [
                "(other callers): C_Login: CKR_DEVICE_ERROR x5, CKR_GENERAL_ERROR x3",
                "(other callers): C_OpenSession: CKR_GENERAL_ERROR x2",
            ]
        );
        // The verbose fold shows the same grouped lines: two reasons need
        // no concise bounding, so both views agree exactly.
        let verbose = terminal_summary(
            4106,
            4106,
            0,
            &ev,
            crate::cli::TextVerbosity::Verbose,
            &reasons,
        );
        let folded_verbose: Vec<&str> = verbose
            .iter()
            .filter(|line| line.contains("(other callers)"))
            .map(String::as_str)
            .collect();
        assert_eq!(folded_verbose, folded);
        // The EVIDENCE gap conserves the fold: ten folded lines over three
        // folded pairs, matching the rendered rows above.
        let line = evidence_line_with_caller_overflow(
            &empty_evidence(),
            crate::attach::CapturePolicy::Allowlisted,
            &reasons,
        );
        let value: serde_json::Value =
            serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
        assert_eq!(
            value["caller_reasons_overflow"],
            serde_json::json!({"folded_lines": 10, "folded_rows": 3})
        );
    }
}
