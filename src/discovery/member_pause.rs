<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
//! Run-tree member load pauses (FIRST-CHILD-WINDOW).
//!
//! `p11scope run` pauses its direct child's loads through the owned
//! pause chain. Descendants used to run unpaused: the first process
//! that cold-loads a provider file taught the run its file, but its own
//! calls before the attach stayed missing. This module closes that
//! window for run-tree members on the run cgroup scope:
//!
//! * the kernel stops a rowless member's first exec (the
//!   `member_exec_pause_due` rule), so the controller can admit the
//!   member and arm its own authorization before it runs any
//!   userspace;
//! * arming a member's loader context also publishes the member's
//!   `PID_FILTER`/`PAUSE_PIDS` rows, so every later loader or
//!   export-discovery event of that member stops it exactly like the
//!   owned chain's;
//! * [`Engine::service_member_pauses`] confirms each stop, holds the
//!   member through its scan and any provider publication, re-arms the
//!   row and resumes it — the resume happens only once the probes on
//!   every file the member proved are attached.
//!
//! Every bound is finite: the row set (64), the stop confirmation
//! (20 ms of settle samples) and the publication hold (500 ms, the
//! owned chain's cycle bound). A cycle that cannot confirm or a hold
//! that outlives its bound resumes the member and counts a partial
//! attempt; a member whose rows cannot be published stays unprotected
//! and keeps the honest learned-after-first-use accounting.

use std::collections::BTreeMap;

use p11scope_ebpf_common::{
    COALESCED_NO_HELPER_RC, DISCOVERY_STATUS_COALESCED_NO_HELPER,
    DISCOVERY_STATUS_LOADER_CONTEXT_INVALID, MEMBER_PAUSE_ROWS, PAUSE_REQUESTED,
};

use super::Engine;
use crate::discovery::EngineSession;
use crate::process::ProcessViewId;

/// How long a member stop may take to settle every task into `T`
/// before the cycle counts partial: 20 settle samples of 1 ms.
const MEMBER_PAUSE_SETTLE_SAMPLES: u32 = 20;
/// How long a stop-held member may wait for its admission, scan or
/// provider publication before the service resumes it unprotected.
/// Mirrors the owned chain's cycle bound (`pause::CYCLE_NS`).
const MEMBER_PAUSE_HOLD_NS: u64 = 500_000_000;
/// Member pause tokens start with the sign bit set: they can never
/// collide with the owned chain's small generation counter.
const MEMBER_TOKEN_BASE: u64 = 1 << 63;

/// One armed member row: the published authorization plus this stop
/// cycle's bookkeeping.
pub(super) struct MemberRow {
    token: u64,
    view: ProcessViewId,
    /// When the current stop cycle opened (`None` while ARMED).
    stop_since_ns: Option<u64>,
}

/// The engine-side state of the member load-pause machinery.
#[derive(Default)]
pub(super) struct MemberPauses {
    /// Enabled only for owned runs on their cgroup scope whose pause
    /// policy is not `never`.
    pub(super) enabled: bool,
    pub(super) rows: BTreeMap<u32, MemberRow>,
    next_token: u64,
    /// Rowless members the kernel stopped at their first exec, waiting
    /// for admission, arming and their first resume.
    pub(super) pending_exec: BTreeMap<u32, u64>,
    /// Files proven by a member while its stop held, keyed by the file
    /// identity: staging owes these members its attach-before-resume
    /// hold, and the first-use gap row stays silent only while the
    /// protection is real.
    pub(super) proven_protected: BTreeMap<(u64, u64), u32>,
    pub(super) attempts: u64,
    pub(super) confirmed: u64,
    pub(super) partial: u64,
    /// Rows refused by the bounded capacity (disclosed once).
    pub(super) refused: u64,
    /// Rows a session without member pause support could not publish.
    pub(super) unavailable: u64,
}

impl MemberPauses {
    fn next_member_token(&mut self) -> Option<u64> {
        let candidate = MEMBER_TOKEN_BASE | self.next_token;
        self.next_token = self.next_token.checked_add(1)?;
        // The low half holds at most MEMBER_PAUSE_ROWS live values per
        // capture; the wrap check stays for honesty.
        Some(candidate).filter(|token| *token != 0)
    }
}

/// Whether a discovery record of an armed member proves the kernel
/// requested its stop: the pause-eligible paths write the signal
/// result, and only the invalid-context loader record carries `0`
/// without any request.
pub(super) fn record_stop_requested(status_flags: u8, send_signal_rc: i64) -> bool {
    if status_flags & DISCOVERY_STATUS_LOADER_CONTEXT_INVALID != 0 {
        return false;
    }
    send_signal_rc == 0 || status_flags & DISCOVERY_STATUS_COALESCED_NO_HELPER != 0
}

impl Engine {
    /// Enables (or disables) the member load-pause machinery. Run
    /// sessions enable it once the pause policy is known; every other
    /// capture keeps it off.
    pub(crate) fn set_member_pause_enabled(&mut self, enabled: bool) {
        self.member_pauses.enabled = enabled;
    }

    /// Whether this engine currently arms member rows: an owned run on
    /// its cgroup scope with the pause machinery active.
    fn member_pause_armed(&self) -> bool {
        self.member_pauses.enabled
            && self.owned_run_pid.is_some()
            && matches!(self.scope, crate::scope::Scope::Cgroup { .. })
    }

    /// Notes an EXEC record of a member that carries no authorization
    /// row: the kernel's member-exec rule stopped the process before
    /// its first userspace instruction, so the engine owes it an
    /// admission, an arming and a resume.
    pub(super) fn note_member_exec_stop(&mut self, pid: u32, now_ns: Option<u64>) {
        if !self.member_pause_armed() || self.owned_run_pid == Some(pid) {
            return;
        }
        if self.member_pauses.rows.contains_key(&pid) {
            // An armed member's exec stopped through its own row; the
            // row service owns the cycle.
            return;
        }
        let now_ns = now_ns.or_else(crate::attach::monotonic_ns).unwrap_or(0);
        self.member_pauses
            .pending_exec
            .entry(pid)
            .or_insert(now_ns);
        self.member_pause_frame_owed = true;
    }

    /// Publishes one member's pause rows beside its freshly attached
    /// loader context. The loader arm is the arming point: the member's
    /// next loader or export-discovery event stops it exactly like the
    /// owned chain's. Capacity refusals disclose one bounded gap; a
    /// session without the support skips silently (the exploration
    /// envelope, like the gated loader arming) and counts.
    pub(super) fn arm_member_pause_after_loader(
        &mut self,
        session: &mut dyn EngineSession,
        view: ProcessViewId,
        pid: u32,
    ) {
        if !self.member_pause_armed() || self.owned_run_pid == Some(pid) {
            return;
        }
        if self.member_pauses.rows.contains_key(&pid) {
            let entry = self.member_pauses.rows.get_mut(&pid).expect("checked");
            entry.view = view;
            return;
        }
        if self.member_pauses.rows.len() >= MEMBER_PAUSE_ROWS {
            if self.member_pauses.refused == 0 {
                self.mark_partial(
                    "member load pause",
                    "the member pause rows were full; later members of this run loaded without \
                     stop protection",
                );
            }
            self.member_pauses.refused = self.member_pauses.refused.saturating_add(1);
            return;
        }
        let Some(token) = self.member_pauses.next_member_token() else {
            if self.member_pauses.refused == 0 {
                self.mark_partial(
                    "member load pause",
                    "the member pause token space was exhausted; members loaded without stop \
                     protection",
                );
            }
            self.member_pauses.refused = self.member_pauses.refused.saturating_add(1);
            return;
        };
        match session.member_pause_publish(pid, token) {
            Ok(()) => {
                self.member_pauses.rows.insert(
                    pid,
                    MemberRow {
                        token,
                        view,
                        stop_since_ns: None,
                    },
                );
            }
            Err(_) => {
                // A session without member pause support (or a refused
                // map write): the member keeps today's unprotected
                // behavior and the honest learned-after-first-use gap.
                self.member_pauses.unavailable = self.member_pauses.unavailable.saturating_add(1);
            }
        }
    }

    /// Whether any member stop owes service: a rowless exec stop
    /// waiting for admission, a REQUESTED row, or a member still
    /// holding through a publication.
    pub(crate) fn member_pause_pending(&mut self, session: &mut dyn EngineSession) -> bool {
        if !self.member_pause_armed() {
            return false;
        }
        if !self.member_pauses.pending_exec.is_empty() {
            return true;
        }
        let rows: Vec<(u32, u64)> = self
            .member_pauses
            .rows
            .iter()
            .map(|(pid, row)| (*pid, row.token))
            .collect();
        rows.iter().any(|(pid, token)| {
            matches!(
                session.member_pause_state(*pid, *token),
                Ok(Some(PAUSE_REQUESTED))
            )
        }) || self.member_pauses.rows.values().any(|row| {
            row.stop_since_ns.is_some_and(|since| {
                crate::attach::monotonic_ns()
                    .is_some_and(|now| now.saturating_sub(since) < MEMBER_PAUSE_HOLD_NS)
            })
        })
    }

    /// Consume the member-pause expedited-frame hint (scheduling only,
    /// never admission authority).
    pub(crate) fn take_member_pause_frame(&mut self) -> bool {
        std::mem::take(&mut self.member_pause_frame_owed)
    }

    /// One bounded sample of the member's task states: `Some(true)`
    /// when every task sits in group stop, `Some(false)` when a task
    /// provably did not (or the process is gone), `None` while the
    /// states are unreadable (not judged).
    fn member_stop_confirmed(pid: u32) -> Option<bool> {
        let states = crate::discovery::pause::read_task_states(pid).ok()?;
        Some(
            !states.is_empty() && states.values().all(|state| *state == b'T'),
        )
    }

    /// Best-effort resume: the view's pidfd when the retained pin has
    /// signal authority, else a plain signal to the pid (a SIGCONT to a
    /// running process is a no-op, so a raced pid reuse is harmless).
    fn member_pause_resume(&self, pid: u32) {
        if let Some(view) = self.views.iter().find(|view| view.pid() == pid) {
            if view.send_signal(libc::SIGCONT).is_ok() {
                return;
            }
        }
        // SAFETY: `kill` takes the plain pid scalar.
        unsafe { libc::kill(pid as i32, libc::SIGCONT) };
    }

    /// Whether a stop-held member must stay held: a scan or publication
    /// of its own provider is still pending, or its admission refresh
    /// has not completed.
    fn member_publication_pending(&self, pid: u32) -> bool {
        if self.owned_publication_pending(pid) || self.refresh_requested.contains_key(&pid) {
            return true;
        }
        self.pending_learned
            .iter()
            .any(|candidate| self.member_pauses.proven_protected.get(&(candidate.dev, candidate.ino)) == Some(&pid))
    }

    /// Services every pending member stop. Runs after each discovery
    /// pass: confirms the stop, holds through publications, re-arms,
    /// resumes. Every cycle is bounded by [`MEMBER_PAUSE_HOLD_NS`]; a
    /// member that cannot be serviced in the bound resumes unprotected
    /// and its attempt counts partial.
    pub(crate) fn service_member_pauses(&mut self, session: &mut dyn EngineSession) {
        if !self.member_pause_armed() {
            return;
        }
        let now = crate::attach::monotonic_ns().unwrap_or(0);
        // Rowless exec stops: admission owns the hold; once the member
        // is armed its cycles run through the row service below.
        let pending: Vec<u32> = self.member_pauses.pending_exec.keys().copied().collect();
        for pid in pending {
            if self.member_pauses.rows.contains_key(&pid) {
                self.member_pauses.pending_exec.remove(&pid);
                continue;
            }
            let first = *self
                .member_pauses
                .pending_exec
                .get(&pid)
                .copied()
                .unwrap_or(now);
            let admission_pending = self.refresh_requested.contains_key(&pid)
                || self.views.iter().any(|view| view.pid() == pid);
            if admission_pending && now.saturating_sub(first) < MEMBER_PAUSE_HOLD_NS {
                self.member_pause_frame_owed = true;
                continue;
            }
            // Admission never completed inside the bound (or the member
            // left): resume it and count the refused attempt.
            self.member_pause_resume(pid);
            self.member_pauses.pending_exec.remove(&pid);
            self.member_pauses.attempts = self.member_pauses.attempts.saturating_add(1);
            self.member_pauses.partial = self.member_pauses.partial.saturating_add(1);
            if admission_pending {
                self.mark_partial(
                    "member load pause",
                    "a member's exec stop outlived its admission bound; its loads ran without \
                     stop protection",
                );
            }
        }
        // Armed rows.
        let rows: Vec<(u32, u64)> = self
            .member_pauses
            .rows
            .iter()
            .map(|(pid, row)| (*pid, row.token))
            .collect();
        for (pid, token) in rows {
            let state = match session.member_pause_state(pid, token) {
                Ok(state) => state,
                Err(_) => None,
            };
            match state {
                Some(PAUSE_REQUESTED) => {
                    self.member_pauses.attempts = self.member_pauses.attempts.saturating_add(1);
                    let since = self
                        .member_pauses
                        .rows
                        .get_mut(&pid)
                        .expect("row collected from the map")
                        .stop_since_ns
                        .get_or_insert(now);
                    let held_for = now.saturating_sub(*since);
                    let confirmed = Self::member_stop_confirmed(pid);
                    let publication_pending = self.member_publication_pending(pid);
                    match (confirmed, publication_pending, held_for < MEMBER_PAUSE_HOLD_NS) {
                        (Some(true), false, _) => {
                            self.member_pauses.confirmed =
                                self.member_pauses.confirmed.saturating_add(1);
                            if session.member_pause_rearm(pid, token).is_err() {
                                self.member_pauses.partial =
                                    self.member_pauses.partial.saturating_add(1);
                                self.note_unprotected_owned(pid);
                            }
                            self.member_pause_resume(pid);
                            if let Some(row) = self.member_pauses.rows.get_mut(&pid) {
                                row.stop_since_ns = None;
                            }
                        }
                        (Some(true), true, true) => {
                            // Hold through the publication; the next
                            // pass re-checks inside the bound.
                            self.member_pause_frame_owed = true;
                        }
                        (Some(false) | None, _, true) => {
                            // Still settling (or unreadable): hold the
                            // cycle open inside the bound.
                            self.member_pause_frame_owed = true;
                        }
                        (_, _, false) => {
                            // The bound expired: resume unprotected,
                            // count partial, and withdraw any protection
                            // claim this member's proofs still carry.
                            self.member_pauses.partial =
                                self.member_pauses.partial.saturating_add(1);
                            self.note_unprotected_owned(pid);
                            self.member_pauses
                                .proven_protected
                                .retain(|_, prover| *prover != pid);
                            let _ = session.member_pause_rearm(pid, token);
                            self.member_pause_resume(pid);
                            if let Some(row) = self.member_pauses.rows.get_mut(&pid) {
                                row.stop_since_ns = None;
                            }
                        }
                    }
                }
                Some(_) => {
                    if let Some(row) = self.member_pauses.rows.get_mut(&pid) {
                        row.stop_since_ns = None;
                    }
                }
                None => {
                    // The row vanished underneath the engine (map
                    // removal outside the service): drop the tracking;
                    // the member runs like an unarmed one.
                    let _ = session.member_pause_remove(pid, token);
                    self.member_pauses.rows.remove(&pid);
                }
            }
        }
        // Departed members release their rows; a still-live pid keeps
        // its authorization across view churn (its exec re-arms it).
        let departed: Vec<u32> = self
            .member_pauses
            .rows
            .keys()
            .copied()
            .filter(|pid| {
                !self.views.iter().any(|view| view.pid() == *pid)
                    && !std::path::Path::new(&format!("/proc/{pid}")).exists()
            })
            .collect();
        for pid in departed {
            self.member_pause_resume(pid);
            if let Some(row) = self.member_pauses.rows.remove(&pid) {
                let _ = session.member_pause_remove(pid, row.token);
            }
            self.member_pauses.pending_exec.remove(&pid);
            self.member_pauses
                .proven_protected
                .retain(|_, prover| *prover != pid);
        }
        if !self.member_pauses.pending_exec.is_empty() {
            self.member_pause_frame_owed = true;
        }
    }

    /// Final cleanup: every armed row and every pending exec stop is
    /// released and its member resumed. Runs on every capture end
    /// path, before probe teardown, so no member the observer stopped
    /// can outlive the capture frozen.
    pub(crate) fn release_member_pauses(&mut self, session: &mut dyn EngineSession) {
        let rows: Vec<(u32, u64)> = self
            .member_pauses
            .rows
            .iter()
            .map(|(pid, row)| (*pid, row.token))
            .collect();
        for (pid, token) in rows {
            self.member_pause_resume(pid);
            let _ = session.member_pause_remove(pid, token);
        }
        for pid in self.member_pauses.pending_exec.keys().copied().collect::<Vec<_>>() {
            self.member_pause_resume(pid);
        }
        self.member_pauses.rows.clear();
        self.member_pauses.pending_exec.clear();
        self.member_pauses.proven_protected.clear();
    }

    /// The member stop-cycle counters for the shared pause evidence.
    pub(crate) fn member_pause_counters(&self) -> (u64, u64, u64) {
        (
            self.member_pauses.attempts,
            self.member_pauses.confirmed,
            self.member_pauses.partial,
        )
    }

    /// Whether a discovery record of an armed member was held by its
    /// stop: the pause-eligible kernel paths request the stop before
    /// they submit the record, so the record itself is the receipt.
    pub(super) fn member_record_stop_held(&self, pid: u32, status_flags: u8, send_signal_rc: i64) -> bool {
        record_stop_requested(status_flags, send_signal_rc)
            && self.member_pauses.rows.contains_key(&pid)
    }
}
