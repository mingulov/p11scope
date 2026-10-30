//! SPDX-License-Identifier: GPL-3.0-or-later
//! Packet 6.13 — pre-armed named providers (B19) and explicit watch
//! intervals (B18): the `--prearm-module` input route, watch state machine,
//! and evidence-assembly interval output.
//!
//! # Contract (merged D1 verdict R2-D1-1…11; replaces both round-1 lists)
//!
//! * **R2-D1-1 Input.** Separate repeatable `--prearm-module <provider.so>`
//!   (name frozen; never `--module`/`--manifest`) on profile/trace, `run`
//!   and `inventory`; refused by name under `inventory --capture scan`. The
//!   flag selects a physical file and inherits the command's scope: it
//!   never populates `modules`/hint matching and never manufactures
//!   manifest function claims. Value resolution is manifest-*locator*
//!   resolution through retained views (retained view's root for `--pid`,
//!   observer root otherwise) — never bounded-JSON `read_manifest`, never
//!   a pathname at attach. One pinned object however many of
//!   pre-arm/manifest/scan name it; `sources` gains the one new label
//!   `"prearm"`; pre-arm-only reads `Uncorroborated` and forces `PARTIAL`;
//!   duplicates dedupe by pinned identity; `--module` filtering never
//!   drops a pre-armed record nor disturbs its corroboration standing;
//!   one bad path fails startup `Fatal`.
//! * **R2-D1-2 Offset provenance.** Pre-mapping attach only for offsets
//!   proved by (a) an accompanying `--manifest` claim for the same pinned
//!   object, or (b) defined ELF exports of the held file proved executable
//!   in held bytes — the pin's standard-name export witness; heuristic
//!   held-file table entries are never attached pre-mapping (no held-file
//!   table decoder exists; the offline discoverer executes provider code,
//!   which is forbidden). Unproved functions attach only after ordinary
//!   scan corroboration, with the gap disclosed. No provider execution.
//! * **R2-D1-3 Custody.** Pin once through the existing worker (open-first,
//!   `(ino, size, ctime)` bracket, shared 512-object/512-MiB accounting
//!   across manifest+pre-arm, all-or-nothing `Fatal`); retain the
//!   descriptor through attachment and joined cleanup; attach exclusively
//!   via the capture-local pinned identity (`/proc/self/fd/N`, no by-path
//!   fallback). Plan admission caps unchanged. No new knobs.
//! * **R2-D1-4 Armed semantics.** Finite `watch.state`: `pinned_unarmed`
//!   (pinned; required links/scope/feed not yet ready), `armed` (links
//!   installed on the declared endpoint set; mapping not required),
//!   `armed_idle` (armed + clean observation health + no observed use over
//!   the stated interval — the declared proved set only), `unavailable`
//!   (no proved offset / attach or scope failure), `ended`. Zero proved
//!   endpoints ⇒ never `armed*`. `watch.since_ns` is the arm instant
//!   (declared set's links ready), not pin time. Stdout/docs wording for
//!   pre-mapping states is "armed (not yet mapped)" once armed, never
//!   "watched/observed" for `pinned_unarmed`. Mapped-but-unattached
//!   endpoints are outside the declared set and surface as windows with
//!   reason `mapped_unattached`.
//! * **R2-D1-5 Output keys (additive; existing keys untouched).**
//!   `attached_at_ns`: nullable, `CLOCK_MONOTONIC`, per-module max over the
//!   declared set's real attach-complete stamps (the once-only session
//!   stamp is never per-provider evidence). `unobserved_windows`:
//!   `[{start_ns, end_ns, reason}]` with finite `reason`, conservative
//!   outer bounds; one `[scope_start_ns, attached_at_ns]` window for any
//!   mapped/attached module without R2-D1-6 proof; absent for never-mapped
//!   pre-arm (its `watch` speaks); key presence never proves exactness.
//!   `watch`: `{since_ns, state, until_ns?, ended_by?, changed?}`. Stage
//!   rule: discovery emits only `watch`; attach keys merge from real
//!   Session/coordinator stamps at evidence assembly (producer: the
//!   capture-end assembly in `run.rs` via `PrearmState::assemble`). No
//!   missed-call estimate is ever emitted; unknown association preserves
//!   physical counts.
//! * **R2-D1-6 Exactness.** `unobserved_windows: []` is allowed only with
//!   the interval explicitly identified *and* one of two proof sources:
//!   (i) the `run` child held by pause/loader gate across the load, or
//!   (ii) capture-held ordering evidence of attach-complete strictly before
//!   first mapping of that inode in every scope member. A scan that saw no
//!   mapping before attach is not proof. Installed first-burst exactness
//!   still requires the independent workload ledger + probes-before-use
//!   positive at C6-D; fixture labels/stage-count tests are not evidence.
//! * **R2-D1-7 End/cancel.** `ended_by` ∈ `{attached, scope_end, stop,
//!   object_changed, health_loss, scope_uncertain}`, set only when the end
//!   actually happens (a static `cancel` datum is rejected). `until_ns` is
//!   set exactly once — at scope end, stop, or truncation, whichever
//!   first; no probe for that module attaches after it in this capture.
//!   (Resolution note: the "first declared-set attach" until-trigger in the
//!   WF text is incoherent with the conceded Codex rule that a watch must
//!   not end on attachment — partial attachment remains unarmed — so this
//!   implementation ends coverage only at scope end, stop or a terminating
//!   failure. `ended_by: attached` is reserved for the unarmed wait the
//!   full attach discharged without opening a claimable armed interval.)
//!   On health loss/scope uncertainty the idle interval ends at its last
//!   proven-clean bound; it never survives as an ongoing clean watch.
//! * **R2-D1-8 Object change.** No point `replaced.at_ns`. Publish
//!   `changed: {last_ok_ns, detected_ns, previous_ino}` — the uncertainty
//!   bracket — under the name `pinned_object_changed` in prose, from
//!   per-object checks on the retained target; the all-objects sticky bool
//!   alone cannot attribute a per-module window. The held descriptor is
//!   never retargeted. Changed-byte refusal keeps precedence: a change
//!   detected before attach refuses that attach exactly as today;
//!   already-attached probes continue and the capture is `PARTIAL` (the
//!   global `provider_changed` verdict cause already exists; the per-module
//!   bracket adds which/when). Same-ctime-granularity in-place rewrite
//!   undetectable by this seam is named residual (heavier proof is 6.12's).
//!   Fresh-capture-after-change is a new pin / manifest mismatch as today,
//!   never a `watch` window.
//! * **R2-D1-9 REDs.** RED-0 (bare pre-arm, no manifest) plus reworked
//!   RED-1…4 with value assertions, real states/bounds, real cancellation
//!   behavior and same-retained-owner replacement, in
//!   `tests/prearm_watch_intervals.rs`.
//! * **R2-D1-10 Scope guards.** Drain cadence is never a coverage bound;
//!   watch never resurrects after first attach (ordinary coverage owns
//!   reloads; same-inode remap reuses probes, different inode is R2-D1-8);
//!   `attach_gap_ms`/`unprotected_live_windows` semantics untouched.
//! * **R2-D1-11 Same-patch surface.** Schema addition (three keys +
//!   `"prearm"` source), help text, known-limitations generic disclosure
//!   retained; key names above are the frozen 6.14-facing surface.
//!
//! # What stays out (owner-ratified or later packets)
//!
//! O4 allowlist row: the needed amendment is noted in the packet report;
//! this patch never writes `docs/privacy/allowlist-v1.md`. Fresh-file
//! attribution stays 6.12's. Installed exactness positives stay C6-D. The
//! inventory Detailed-subset work follows the input surface in a later
//! packet: until its startup pin/custody path exists, inventory refuses
//! `--prearm-module` inputs by name before side effects under every
//! capture mode — a pending-activation gap is not an implementation.

use std::collections::{BTreeMap, BTreeSet};

use crate::discovery::identity::PinnedObjectId;
use crate::plan::AttachKey;
use crate::render::{
    PrearmObjectChange, PrearmWatch as RenderWatch, PrearmWatchEnd, PrearmWatchState,
    UnobservedReason, UnobservedWindow,
};

/// Engine-side pre-arm watch for one pinned object: the frozen declared
/// endpoint set plus the interval state rendered as [`RenderWatch`].
/// Keyed by pinned object (stable across plan rebuilds), not by plan-local
/// module id. `ended` is terminal: a watch never resurrects (R2-D1-10).
#[derive(Debug, Clone)]
pub(crate) struct PrearmWatch {
    /// Frozen nonempty-except-`unavailable` declared endpoint set: the
    /// operator-declared (manifest-claimed + export-proved) attach keys.
    declared: BTreeSet<AttachKey>,
    state: PrearmWatchState,
    since_ns: Option<u64>,
    until_ns: Option<u64>,
    ended_by: Option<PrearmWatchEnd>,
    changed: Option<PrearmObjectChange>,
    /// Last instant the full declared set was verified linked. Bounds the
    /// `health_loss`/`scope_uncertain` truncation conservatively.
    last_verified_ns: Option<u64>,
}

impl PrearmWatch {
    /// A fresh watch over a frozen declared set. An empty set can never
    /// arm: it reads `unavailable`, never `pinned_unarmed`-forever.
    pub(crate) fn new(declared: BTreeSet<AttachKey>) -> Self {
        let state = if declared.is_empty() {
            PrearmWatchState::Unavailable
        } else {
            PrearmWatchState::PinnedUnarmed
        };
        Self {
            declared,
            state,
            since_ns: None,
            until_ns: None,
            ended_by: None,
            changed: None,
            last_verified_ns: None,
        }
    }

    pub(crate) fn declared(&self) -> &BTreeSet<AttachKey> {
        &self.declared
    }

    pub(crate) fn ended_by(&self) -> Option<PrearmWatchEnd> {
        self.ended_by
    }

    /// Whether this watch's tracking already ended (the exactly-once latch
    /// for `until_ns`: latched by `ended_by`, so even a clock-unknown end
    /// cannot be re-ended).
    pub(crate) fn is_ended(&self) -> bool {
        self.ended_by.is_some()
    }

    /// Arm evaluation against current link facts, one entry per declared
    /// key: partial attachment remains unarmed for the declared set, and
    /// readiness never precedes the last member's real attach stamp. Every
    /// required member needs its own real timestamp before the watch claims
    /// an arm instant — one known stamp is not the known maximum of the
    /// declared set — so any missing stamp discharges the unarmed wait as
    /// `ended_by: attached` instead of arming.
    pub(crate) fn evaluate_arm(&mut self, links: &[DeclaredLink]) {
        if self.state != PrearmWatchState::PinnedUnarmed {
            return;
        }
        if self.declared.is_empty() {
            self.state = PrearmWatchState::Unavailable;
            return;
        }
        let all_linked = self
            .declared
            .iter()
            .all(|key| links.iter().any(|link| link.key == *key && link.linked));
        if !all_linked {
            return;
        }
        let mut latest: Option<u64> = None;
        for key in &self.declared {
            let Some(stamped_at) = links
                .iter()
                .find(|link| link.key == *key)
                .and_then(|link| link.stamped_at)
            else {
                // Fully linked but the arm instant is unknown: no armed
                // interval is claimable, so the unarmed wait ends here.
                self.state = PrearmWatchState::Ended;
                self.ended_by = Some(PrearmWatchEnd::Attached);
                return;
            };
            latest = Some(latest.map_or(stamped_at, |known| known.max(stamped_at)));
        }
        match latest {
            Some(since) => {
                self.state = PrearmWatchState::Armed;
                self.since_ns = Some(since);
                self.last_verified_ns = Some(since);
            }
            None => {
                self.state = PrearmWatchState::Ended;
                self.ended_by = Some(PrearmWatchEnd::Attached);
            }
        }
    }

    /// Idle qualification over an armed interval: armed plus clean health
    /// plus no observed use. Use observed or health regressed leaves the
    /// watch armed (no quiet claim); only the qualified interval reads
    /// `armed_idle`.
    pub(crate) fn evaluate_idle(&mut self, use_observed: bool, health_clean: bool) {
        if self.state != PrearmWatchState::Armed {
            return;
        }
        if !use_observed && health_clean {
            self.state = PrearmWatchState::ArmedIdle;
        }
    }

    /// Declared-link liveness for an armed watch: while every declared key
    /// stays linked the verification bound advances; a lost link voids the
    /// standing claim at the last verified instant (reported as
    /// `health_loss`: the observation feed for that endpoint is gone).
    pub(crate) fn verify_links(&mut self, links: &[DeclaredLink], now: Option<u64>) {
        if !matches!(
            self.state,
            PrearmWatchState::Armed | PrearmWatchState::ArmedIdle
        ) {
            return;
        }
        let all_linked = self
            .declared
            .iter()
            .all(|key| links.iter().any(|link| link.key == *key && link.linked));
        if all_linked {
            if now.is_some() {
                self.last_verified_ns = now;
            }
            return;
        }
        self.until_ns = self.last_verified_ns;
        self.ended_by = Some(PrearmWatchEnd::HealthLoss);
        self.state = PrearmWatchState::Ended;
    }

    /// Ends the watch's tracking at `now` for `cause`, exactly once. A
    /// natural close (`scope_end`/`stop`) preserves an earned `armed_idle`
    /// claim with its closed bounds; every other end voids the standing
    /// state into `ended`.
    pub(crate) fn end(&mut self, cause: PrearmWatchEnd, now: Option<u64>) {
        if self.is_ended() {
            return;
        }
        // Truncation causes close at the last proven-clean bound, never at
        // the detection instant: the claim cannot ride past its proof.
        self.until_ns = match cause {
            PrearmWatchEnd::HealthLoss | PrearmWatchEnd::ScopeUncertain => self.last_verified_ns,
            _ => now,
        };
        self.ended_by = Some(cause);
        let natural_close = matches!(cause, PrearmWatchEnd::ScopeEnd | PrearmWatchEnd::Stop);
        if !(natural_close && self.state == PrearmWatchState::ArmedIdle) {
            self.state = PrearmWatchState::Ended;
        }
    }

    /// Records a `pinned_object_changed` bracket against the watch. A change
    /// that lands after the watch already ended is irrelevant to the closed
    /// interval and leaves the first end standing.
    pub(crate) fn note_object_changed(&mut self, bracket: PrearmObjectChange) {
        if self.is_ended() {
            return;
        }
        self.changed = Some(bracket);
        self.until_ns = Some(bracket.detected_ns);
        self.ended_by = Some(PrearmWatchEnd::ObjectChanged);
        self.state = PrearmWatchState::Ended;
    }

    /// Renders the serializable interval. Discovery calls this; attach keys
    /// merge separately at evidence assembly (stage rule, R2-D1-5).
    pub(crate) fn render(&self) -> RenderWatch {
        RenderWatch {
            since_ns: self.since_ns,
            state: self.state,
            until_ns: self.until_ns,
            ended_by: self.ended_by,
            changed: self.changed,
        }
    }
}

/// Current link facts for one declared endpoint, resolved by the engine
/// from the plan (slot membership) and the session (links + stamps).
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeclaredLink {
    pub(crate) key: AttachKey,
    /// A live session link covers this endpoint right now.
    pub(crate) linked: bool,
    /// Its attach-complete stamp, if the session recorded one.
    pub(crate) stamped_at: Option<u64>,
}

/// R2-D1-6 proof behind an explicitly empty `unobserved_windows`: the
/// identified interval plus which of the two proof sources backs it. An
/// empty list is emitted only when the identified interval exactly equals
/// the would-be `[scope_start_ns, attached_at_ns]` window — a mismatched
/// proof fails closed to the window. No producer ships in this packet
/// (first producers land with C6-D installed proof); the gate and its
/// fail-closed rule are unit-tested here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExactnessProof {
    pub(crate) interval_start_ns: u64,
    pub(crate) interval_end_ns: u64,
    pub(crate) kind: ExactnessProofKind,
}

/// The two R2-D1-6 proof sources. Nothing constructs these outside tests
/// until C6-D wires the first installed producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum ExactnessProofKind {
    /// The `run` child held by pause/loader gate across the load.
    PauseGateHeld,
    /// Capture-held ordering evidence: attach-complete strictly before
    /// first mapping of that inode in every scope member.
    OrderingEvidence,
}

/// Terminal observation/scope/link health for idle qualification
/// (packet 6.13 residual, R2-D1-4): the same counters the capture verdict
/// reads, scoped to what a quiet claim needs. Discovery transport loss,
/// call-event loss, scope/identity refusals, malformed feeds, link gaps
/// and the module's own attach failures all void `armed_idle`. A sibling
/// object's change does not void this module's quiet: per-object change
/// evidence ends that object's watch, not this one's interval.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PrearmHealth {
    pub discovery_ring_loss: u64,
    pub discovery_state_failures: u64,
    pub discovery_read_failures: u64,
    pub discovery_truncated: u64,
    pub malformed_discovery: u64,
    pub discovery_abi_refusals: u64,
    pub kernel: crate::metrics::KernelEvidence,
    pub malformed_records: u64,
    pub link_gap: bool,
    pub own_attach_failures: bool,
}

/// Whether one module's observation health is clean enough to qualify an
/// `armed_idle` interval: every loss/scope/identity/link counter quiet —
/// discovery transport, call-event loss, scope/identity refusals, the
/// malformed call feed, recorded link gaps and the module's own attach
/// failures. A final live-link snapshot alone authorizes nothing.
pub(crate) fn idle_health_clean(health: &PrearmHealth) -> bool {
    health.discovery_ring_loss == 0
        && health.discovery_state_failures == 0
        && health.discovery_read_failures == 0
        && health.discovery_truncated == 0
        && health.malformed_discovery == 0
        && health.discovery_abi_refusals == 0
        && health.kernel.ring_loss == 0
        && health.kernel.start_insert_failures == 0
        && health.kernel.unmatched_returns == 0
        && health.kernel.rv_update_failures == 0
        && health.kernel.cgroup_scope_failures == 0
        && health.kernel.semantic_capture_failures == 0
        && health.kernel.template_tail_failures == 0
        && health.kernel.unregistered_mechanisms == 0
        && health.kernel.abi_refusals == 0
        && health.kernel.control.evidence().complete()
        && health.malformed_records == 0
        && !health.link_gap
        && !health.own_attach_failures
}

/// Loss cause for a health-dirty armed watch: scope/identity uncertainty
/// truncates as `scope_uncertain`, other loss as `health_loss`. Both close
/// at the last proven-clean bound, never at the detection instant.
pub(crate) fn prearm_loss_cause(health: &PrearmHealth) -> PrearmWatchEnd {
    if health.kernel.cgroup_scope_failures > 0
        || health.kernel.abi_refusals > 0
        || health.discovery_abi_refusals > 0
        || !health.kernel.control.evidence().complete()
    {
        PrearmWatchEnd::ScopeUncertain
    } else {
        PrearmWatchEnd::HealthLoss
    }
}

/// Capture-lifetime pre-arm state, owned by the engine: one watch per
/// pre-armed object, the capture's scope start, and the initial module set
/// (which tells late discovery from attach lag at assembly).
#[derive(Debug, Clone, Default)]
pub(crate) struct PrearmState {
    watches: BTreeMap<PinnedObjectId, PrearmWatch>,
    scope_start_ns: Option<u64>,
    initial_module_objects: BTreeSet<PinnedObjectId>,
}

impl PrearmState {
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.watches.is_empty()
    }

    pub(crate) fn watches(&self) -> &BTreeMap<PinnedObjectId, PrearmWatch> {
        &self.watches
    }

    pub(crate) fn get(&self, id: PinnedObjectId) -> Option<&PrearmWatch> {
        self.watches.get(&id)
    }

    pub(crate) fn get_mut(&mut self, id: PinnedObjectId) -> Option<&mut PrearmWatch> {
        self.watches.get_mut(&id)
    }

    /// Records the capture's scope start (discover entry; the `run` path
    /// overrides with its pre-spawn instant so the window's outer bound
    /// cannot understate the gap).
    pub(crate) fn set_scope_start_ns(&mut self, scope_start_ns: Option<u64>) {
        self.scope_start_ns = scope_start_ns;
    }

    /// Records the initial build's module objects. A module absent here at
    /// assembly was discovered late.
    pub(crate) fn record_initial_modules(
        &mut self,
        objects: impl IntoIterator<Item = PinnedObjectId>,
    ) {
        self.initial_module_objects.extend(objects);
    }

    /// Creates watches for every pre-armed plan module, freezing each
    /// watch's declared endpoint set from the operator-declared keys.
    /// Existing watches are never reset: rebuilds keep live interval
    /// state, and only newly appeared pre-arm modules gain a watch.
    pub(crate) fn create_watches(
        &mut self,
        modules: &[crate::plan::ModuleSummary],
        declared: &BTreeMap<PinnedObjectId, BTreeSet<AttachKey>>,
        pinned: &crate::discovery::identity::PinnedObjects,
    ) {
        for module in modules {
            if !pinned.has_prearm(module.object) {
                continue;
            }
            self.watches.entry(module.object).or_insert_with(|| {
                PrearmWatch::new(declared.get(&module.object).cloned().unwrap_or_default())
            });
        }
    }

    /// Ends every watch's tracking exactly once (scope end / stop driver).
    pub(crate) fn end_all(&mut self, cause: PrearmWatchEnd, now: Option<u64>) {
        for watch in self.watches.values_mut() {
            watch.end(cause, now);
        }
    }

    /// Declared keys of ended watches: no probe for these attaches after
    /// their `until_ns` in this capture (R2-D1-7). The attach path refuses
    /// them; the engine also retires their slots so ordinary retirement
    /// machinery agrees.
    pub(crate) fn ended_declared_keys(&self) -> BTreeSet<AttachKey> {
        self.watches
            .values()
            .filter(|watch| watch.is_ended())
            .flat_map(|watch| watch.declared.iter().copied())
            .collect()
    }

    /// Evidence-assembly merge (R2-D1-5 stage rule): attaches
    /// `attached_at_ns` and `unobserved_windows` onto module records from
    /// real attach-complete stamps. Pure over its inputs; the run/session
    /// path supplies the stamps at capture end.
    ///
    /// * `attached_at_ns` is always set post-assembly: for watched
    ///   modules the max over the declared set's real stamps, and only when
    ///   every required member carries one (any missing stamp leaves the
    ///   instant unknown); over the module's attached slots otherwise; null
    ///   when nothing attached.
    /// * The base `[scope_start_ns, attached_at_ns]` window emits for every
    ///   attached module without an R2-D1-6 proof, except never-mapped
    ///   pre-arm (its watch speaks). Reason is `pre_attach`, or
    ///   `late_discovery` when the module missed the initial build.
    /// * Watched modules additionally disclose attached endpoints outside
    ///   the declared set as one `mapped_unattached` window to their max
    ///   attach instant (R2-D1-2: unproved functions attach only after
    ///   scan corroboration, with the gap disclosed).
    /// * A matching exactness proof replaces the base window with an
    ///   explicitly empty list; it never covers `mapped_unattached`
    ///   endpoints outside the proved interval.
    /// * Anything unboundable (no stamps, no scope start) stays undisclosed:
    ///   absence claims nothing.
    pub(crate) fn assemble(
        &self,
        records: &mut [crate::render::DiscoveredModule],
        plan: &crate::plan::AttachPlan,
        attached: &BTreeMap<u32, u64>,
        proofs: &BTreeMap<PinnedObjectId, ExactnessProof>,
    ) {
        let objects: BTreeMap<crate::plan::ModuleId, PinnedObjectId> = plan
            .modules
            .iter()
            .map(|module| (module.id, module.object))
            .collect();
        for record in records {
            let object = objects.get(&record.id).copied();
            let watch = object.and_then(|object| self.watches.get(&object));
            let attached_at = match watch {
                // The declared set's maximum needs every member's real
                // stamp: a subset maximum is not declared-set readiness.
                Some(watch) => {
                    let mut latest: Option<u64> = None;
                    for key in watch.declared.iter() {
                        let Some(stamped_at) = plan
                            .slot_index_for_key(*key)
                            .and_then(|index| attached.get(&index).copied())
                        else {
                            latest = None;
                            break;
                        };
                        latest = Some(latest.map_or(stamped_at, |known| known.max(stamped_at)));
                    }
                    latest
                }
                None => plan
                    .slots
                    .iter()
                    .filter(|slot| slot.module_ids.contains(&record.id))
                    .filter_map(|slot| attached.get(&slot.index).copied())
                    .max(),
            };
            record.attached_at_ns = Some(attached_at);
            let Some(attached_at) = attached_at else {
                continue;
            };
            let mapped = record.sources.contains(&"scan");
            let never_mapped_prearm = watch.is_some() && !mapped;
            let mut windows = Vec::new();
            let proof_matches = object.is_some_and(|object| {
                proofs.get(&object).is_some_and(|proof| {
                    self.scope_start_ns.is_some_and(|start| {
                        proof.interval_start_ns == start && proof.interval_end_ns == attached_at
                    })
                })
            });
            if !never_mapped_prearm
                && !proof_matches
                && let Some(start) = self.scope_start_ns
            {
                let reason =
                    if object.is_some_and(|object| self.initial_module_objects.contains(&object)) {
                        UnobservedReason::PreAttach
                    } else {
                        UnobservedReason::LateDiscovery
                    };
                windows.push(UnobservedWindow {
                    start_ns: start,
                    end_ns: attached_at,
                    reason,
                });
            }
            if let (Some(watch), Some(start)) = (watch, self.scope_start_ns) {
                let undeclared_max = plan
                    .slots
                    .iter()
                    .filter(|slot| slot.module_ids.contains(&record.id))
                    .filter(|slot| {
                        !watch.declared.contains(&AttachKey {
                            object: slot.object,
                            file_offset: slot.file_offset,
                        })
                    })
                    .filter_map(|slot| attached.get(&slot.index).copied())
                    .max();
                if let Some(end) = undeclared_max {
                    windows.push(UnobservedWindow {
                        start_ns: start,
                        end_ns: end,
                        reason: UnobservedReason::MappedUnattached,
                    });
                }
            }
            if proof_matches || !windows.is_empty() {
                record.unobserved_windows = Some(windows);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{ModuleId, ModuleSummary, Slot};

    fn key(object: u32, file_offset: u64) -> AttachKey {
        AttachKey {
            object: PinnedObjectId(object),
            file_offset,
        }
    }

    fn link(key: AttachKey, linked: bool, stamped_at: Option<u64>) -> DeclaredLink {
        DeclaredLink {
            key,
            linked,
            stamped_at,
        }
    }

    fn watched(declared: BTreeSet<AttachKey>) -> PrearmWatch {
        PrearmWatch::new(declared)
    }

    #[test]
    fn empty_declared_set_never_arms() {
        let mut watch = watched(BTreeSet::new());
        assert_eq!(watch.render().state, PrearmWatchState::Unavailable);
        watch.evaluate_arm(&[]);
        assert_eq!(watch.render().state, PrearmWatchState::Unavailable);
        assert_eq!(watch.render().since_ns, None);
        assert_eq!(watch.render().until_ns, None);
    }

    #[test]
    fn arm_requires_full_declared_set_and_real_stamps() {
        let a = key(1, 0x1000);
        let b = key(1, 0x2000);
        // Partial attachment stays unarmed for the declared set.
        let mut watch = watched(BTreeSet::from([a, b]));
        watch.evaluate_arm(&[link(a, true, Some(100)), link(b, false, None)]);
        assert_eq!(watch.render().state, PrearmWatchState::PinnedUnarmed);
        assert_eq!(watch.render().since_ns, None);
        // Fully linked but unstamped: no armed interval is claimable, so the
        // unarmed wait discharges instead of arming.
        watch.evaluate_arm(&[link(a, true, None), link(b, true, None)]);
        assert_eq!(watch.render().state, PrearmWatchState::Ended);
        assert_eq!(watch.ended_by(), Some(PrearmWatchEnd::Attached));
        assert_eq!(watch.render().until_ns, None);
        // Stamped: readiness never precedes the last member's stamp.
        let mut watch = watched(BTreeSet::from([a, b]));
        watch.evaluate_arm(&[link(a, true, Some(100)), link(b, true, Some(140))]);
        assert_eq!(watch.render().state, PrearmWatchState::Armed);
        assert_eq!(watch.render().since_ns, Some(140));
    }

    #[test]
    fn mixed_known_unknown_stamps_never_arm() {
        let a = key(1, 0x1000);
        let b = key(1, 0x2000);
        // One known stamp is not the known maximum of the declared set: a
        // missing required stamp fails closed to unknown readiness, in both
        // link orderings.
        for links in [
            vec![link(a, true, Some(100)), link(b, true, None)],
            vec![link(a, true, None), link(b, true, Some(100))],
        ] {
            let mut watch = watched(BTreeSet::from([a, b]));
            watch.evaluate_arm(&links);
            assert_eq!(watch.render().state, PrearmWatchState::Ended);
            assert_eq!(watch.ended_by(), Some(PrearmWatchEnd::Attached));
            assert_eq!(watch.render().since_ns, None);
        }
    }

    #[test]
    fn idle_qualifies_only_when_unused_and_clean() {
        let a = key(1, 0x1000);
        let mut watch = watched(BTreeSet::from([a]));
        // Idle evaluation before arming is a no-op.
        watch.evaluate_idle(false, true);
        assert_eq!(watch.render().state, PrearmWatchState::PinnedUnarmed);
        watch.evaluate_arm(&[link(a, true, Some(100))]);
        watch.evaluate_idle(true, true);
        assert_eq!(watch.render().state, PrearmWatchState::Armed);
        watch.evaluate_idle(false, false);
        assert_eq!(watch.render().state, PrearmWatchState::Armed);
        watch.evaluate_idle(false, true);
        assert_eq!(watch.render().state, PrearmWatchState::ArmedIdle);
    }

    #[test]
    fn lost_link_truncates_at_last_verified_bound() {
        let a = key(1, 0x1000);
        let b = key(1, 0x2000);
        let mut watch = watched(BTreeSet::from([a, b]));
        watch.evaluate_arm(&[link(a, true, Some(100)), link(b, true, Some(100))]);
        watch.verify_links(
            &[link(a, true, Some(100)), link(b, true, Some(100))],
            Some(200),
        );
        assert_eq!(watch.render().state, PrearmWatchState::Armed);
        watch.verify_links(&[link(a, true, Some(100)), link(b, false, None)], Some(300));
        assert_eq!(watch.render().state, PrearmWatchState::Ended);
        assert_eq!(watch.ended_by(), Some(PrearmWatchEnd::HealthLoss));
        // The claim cannot ride past its proof: it ends at the last
        // verified instant, not at detection time.
        assert_eq!(watch.render().until_ns, Some(200));
    }

    #[test]
    fn end_latches_exactly_once_and_preserves_earned_idle() {
        let a = key(1, 0x1000);
        let mut watch = watched(BTreeSet::from([a]));
        watch.evaluate_arm(&[link(a, true, Some(100))]);
        watch.evaluate_idle(false, true);
        watch.end(PrearmWatchEnd::ScopeEnd, Some(300));
        assert_eq!(watch.render().state, PrearmWatchState::ArmedIdle);
        assert_eq!(watch.render().until_ns, Some(300));
        assert_eq!(watch.ended_by(), Some(PrearmWatchEnd::ScopeEnd));
        // A second end cannot move the latched bound.
        watch.end(PrearmWatchEnd::Stop, Some(400));
        assert_eq!(watch.render().until_ns, Some(300));
        assert_eq!(watch.ended_by(), Some(PrearmWatchEnd::ScopeEnd));
    }

    #[test]
    fn truncation_end_closes_at_proven_bound_not_now() {
        let a = key(1, 0x1000);
        let mut watch = watched(BTreeSet::from([a]));
        watch.evaluate_arm(&[link(a, true, Some(100))]);
        watch.end(PrearmWatchEnd::HealthLoss, Some(500));
        assert_eq!(watch.render().state, PrearmWatchState::Ended);
        assert_eq!(watch.render().until_ns, Some(100));
    }

    fn quiet_health() -> PrearmHealth {
        PrearmHealth {
            discovery_ring_loss: 0,
            discovery_state_failures: 0,
            discovery_read_failures: 0,
            discovery_truncated: 0,
            malformed_discovery: 0,
            discovery_abi_refusals: 0,
            kernel: crate::metrics::KernelEvidence::default(),
            malformed_records: 0,
            link_gap: false,
            own_attach_failures: false,
        }
    }

    #[test]
    fn idle_health_clean_requires_all_quiet() {
        assert!(idle_health_clean(&quiet_health()));
        let mut dirty = quiet_health();
        dirty.discovery_ring_loss = 1;
        assert!(!idle_health_clean(&dirty));
        let mut dirty = quiet_health();
        dirty.discovery_state_failures = 1;
        assert!(!idle_health_clean(&dirty));
        let mut dirty = quiet_health();
        dirty.discovery_read_failures = 1;
        assert!(!idle_health_clean(&dirty));
        let mut dirty = quiet_health();
        dirty.discovery_truncated = 1;
        assert!(!idle_health_clean(&dirty));
        let mut dirty = quiet_health();
        dirty.malformed_discovery = 1;
        assert!(!idle_health_clean(&dirty));
        let mut dirty = quiet_health();
        dirty.own_attach_failures = true;
        assert!(!idle_health_clean(&dirty));
    }

    #[test]
    fn idle_health_clean_feeds_call_scope_and_link_health() {
        // Every terminal loss/scope/link input voids the quiet claim, even
        // with zero observed use and a clean discovery ring.
        let mut dirty = quiet_health();
        dirty.kernel.ring_loss = 1;
        assert!(!idle_health_clean(&dirty));
        let mut dirty = quiet_health();
        dirty.kernel.cgroup_scope_failures = 1;
        assert!(!idle_health_clean(&dirty));
        let mut dirty = quiet_health();
        dirty.kernel.abi_refusals = 1;
        assert!(!idle_health_clean(&dirty));
        let mut dirty = quiet_health();
        dirty.discovery_abi_refusals = 1;
        assert!(!idle_health_clean(&dirty));
        let mut dirty = quiet_health();
        dirty.kernel.control.identity_unavailable = 1;
        assert!(!idle_health_clean(&dirty));
        let mut dirty = quiet_health();
        dirty.malformed_records = 1;
        assert!(!idle_health_clean(&dirty));
        let mut dirty = quiet_health();
        dirty.link_gap = true;
        assert!(!idle_health_clean(&dirty));
    }

    #[test]
    fn loss_cause_separates_scope_uncertainty_from_health_loss() {
        let mut scope = quiet_health();
        scope.kernel.cgroup_scope_failures = 1;
        assert_eq!(prearm_loss_cause(&scope), PrearmWatchEnd::ScopeUncertain);
        let mut scope = quiet_health();
        scope.kernel.control.identity_unavailable = 1;
        assert_eq!(prearm_loss_cause(&scope), PrearmWatchEnd::ScopeUncertain);
        let mut loss = quiet_health();
        loss.kernel.ring_loss = 1;
        assert_eq!(prearm_loss_cause(&loss), PrearmWatchEnd::HealthLoss);
        let mut loss = quiet_health();
        loss.malformed_records = 1;
        assert_eq!(prearm_loss_cause(&loss), PrearmWatchEnd::HealthLoss);
    }

    fn slot(index: u32, object: u32, file_offset: u64, module: u32) -> Slot {
        Slot {
            index,
            descriptor_index: 1,
            object: PinnedObjectId(object),
            object_path: format!("/proc/self/fd/{object}"),
            file_offset,
            names: vec!["C_Sign".into()],
            aliased: false,
            semantics: crate::kinds::DESCRIPTORS[1],
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![ModuleId(module)],
        }
    }

    fn module(id: u32, object: u32) -> ModuleSummary {
        ModuleSummary {
            id: ModuleId(id),
            object: PinnedObjectId(object),
            key: crate::plan::TEST_OBJECT,
            path: format!("/prearm/{id}.so"),
            tables: Vec::new(),
            interfaces: 0,
            source: "prearm",
            corroborated: false,
            skipped: Vec::new(),
        }
    }

    fn record(id: u32, sources: Vec<&'static str>) -> crate::render::DiscoveredModule {
        crate::render::DiscoveredModule {
            id: ModuleId(id),
            dev: (8, 1),
            ino: 42,
            sha256: None,
            path: format!("/prearm/{id}.so"),
            build_id: None,
            objects: Vec::new(),
            sources,
            corroborated: false,
            corroboration: Vec::new(),
            tables: Vec::new(),
            interfaces: 0,
            skipped: Vec::new(),
            watch: None,
            attached_at_ns: None,
            unobserved_windows: None,
        }
    }

    #[test]
    fn assembly_emits_pre_attach_window_for_attached_module() {
        let mut plan = crate::plan::AttachPlan::from_slots(vec![slot(0, 7, 0x1000, 3)]);
        plan.modules = vec![module(3, 7)];
        let mut state = PrearmState::empty();
        state.set_scope_start_ns(Some(50));
        state.record_initial_modules([PinnedObjectId(7)]);
        let mut records = vec![record(3, vec!["scan"])];
        state.assemble(
            &mut records,
            &plan,
            &BTreeMap::from([(0, 900)]),
            &BTreeMap::new(),
        );
        assert_eq!(records[0].attached_at_ns, Some(Some(900)));
        assert_eq!(
            records[0].unobserved_windows,
            Some(vec![UnobservedWindow {
                start_ns: 50,
                end_ns: 900,
                reason: UnobservedReason::PreAttach,
            }]),
        );
    }

    #[test]
    fn assembly_marks_late_module_late_discovery() {
        let mut plan = crate::plan::AttachPlan::from_slots(vec![slot(0, 7, 0x1000, 3)]);
        plan.modules = vec![module(3, 7)];
        let mut state = PrearmState::empty();
        state.set_scope_start_ns(Some(50));
        // Object 7 missed the initial build: discovered late.
        let mut records = vec![record(3, vec!["scan"])];
        state.assemble(
            &mut records,
            &plan,
            &BTreeMap::from([(0, 900)]),
            &BTreeMap::new(),
        );
        assert_eq!(
            records[0].unobserved_windows,
            Some(vec![UnobservedWindow {
                start_ns: 50,
                end_ns: 900,
                reason: UnobservedReason::LateDiscovery,
            }]),
        );
    }

    #[test]
    fn assembly_matching_proof_empties_windows() {
        let mut plan = crate::plan::AttachPlan::from_slots(vec![slot(0, 7, 0x1000, 3)]);
        plan.modules = vec![module(3, 7)];
        let mut state = PrearmState::empty();
        state.set_scope_start_ns(Some(50));
        state.record_initial_modules([PinnedObjectId(7)]);
        let proofs = BTreeMap::from([(
            PinnedObjectId(7),
            ExactnessProof {
                interval_start_ns: 50,
                interval_end_ns: 900,
                kind: ExactnessProofKind::OrderingEvidence,
            },
        )]);
        let mut records = vec![record(3, vec!["scan"])];
        state.assemble(&mut records, &plan, &BTreeMap::from([(0, 900)]), &proofs);
        assert_eq!(records[0].attached_at_ns, Some(Some(900)));
        assert_eq!(records[0].unobserved_windows, Some(Vec::new()));
    }

    #[test]
    fn assembly_mismatched_proof_fails_closed_to_window() {
        let mut plan = crate::plan::AttachPlan::from_slots(vec![slot(0, 7, 0x1000, 3)]);
        plan.modules = vec![module(3, 7)];
        let mut state = PrearmState::empty();
        state.set_scope_start_ns(Some(50));
        state.record_initial_modules([PinnedObjectId(7)]);
        // The proof names a different interval than the would-be window.
        let proofs = BTreeMap::from([(
            PinnedObjectId(7),
            ExactnessProof {
                interval_start_ns: 60,
                interval_end_ns: 900,
                kind: ExactnessProofKind::PauseGateHeld,
            },
        )]);
        let mut records = vec![record(3, vec!["scan"])];
        state.assemble(&mut records, &plan, &BTreeMap::from([(0, 900)]), &proofs);
        assert!(records[0].unobserved_windows.as_ref().is_some_and(
            |windows| windows.len() == 1 && windows[0].reason == UnobservedReason::PreAttach
        ),);
    }

    #[test]
    fn assembly_watched_module_reports_declared_and_undeclared() {
        let declared = key(7, 0x1000);
        let mut plan =
            crate::plan::AttachPlan::from_slots(vec![slot(0, 7, 0x1000, 3), slot(1, 7, 0x5000, 3)]);
        plan.modules = vec![module(3, 7)];
        let mut state = PrearmState::empty();
        state.set_scope_start_ns(Some(50));
        state.record_initial_modules([PinnedObjectId(7)]);
        state
            .watches
            .insert(PinnedObjectId(7), watched(BTreeSet::from([declared])));
        // Mapped (scan source) so the base window applies, with one attached
        // endpoint outside the declared set.
        let mut records = vec![record(3, vec!["scan", "prearm"])];
        state.assemble(
            &mut records,
            &plan,
            &BTreeMap::from([(0, 900), (1, 1200)]),
            &BTreeMap::new(),
        );
        // Declared-set max only: the undeclared attach is disclosed, never
        // folded into the provider's attach instant.
        assert_eq!(records[0].attached_at_ns, Some(Some(900)));
        assert_eq!(
            records[0].unobserved_windows,
            Some(vec![
                UnobservedWindow {
                    start_ns: 50,
                    end_ns: 900,
                    reason: UnobservedReason::PreAttach,
                },
                UnobservedWindow {
                    start_ns: 50,
                    end_ns: 1200,
                    reason: UnobservedReason::MappedUnattached,
                },
            ]),
        );
    }

    #[test]
    fn assembly_requires_every_declared_stamp_for_attached_at() {
        let a = key(7, 0x1000);
        let b = key(7, 0x2000);
        // A subset maximum is not declared-set readiness: whichever member
        // lacks a stamp, the attach instant stays unknown and undisclosed.
        for attached in [BTreeMap::from([(0, 900)]), BTreeMap::from([(1, 1200)])] {
            let mut plan = crate::plan::AttachPlan::from_slots(vec![
                slot(0, 7, 0x1000, 3),
                slot(1, 7, 0x2000, 3),
            ]);
            plan.modules = vec![module(3, 7)];
            let mut state = PrearmState::empty();
            state.set_scope_start_ns(Some(50));
            state.record_initial_modules([PinnedObjectId(7)]);
            state
                .watches
                .insert(PinnedObjectId(7), watched(BTreeSet::from([a, b])));
            let mut records = vec![record(3, vec!["scan", "prearm"])];
            state.assemble(&mut records, &plan, &attached, &BTreeMap::new());
            assert_eq!(records[0].attached_at_ns, Some(None));
            assert_eq!(records[0].unobserved_windows, None);
        }
    }

    #[test]
    fn assembly_never_mapped_watch_skips_base_window() {
        let declared = key(7, 0x1000);
        let mut plan = crate::plan::AttachPlan::from_slots(vec![slot(0, 7, 0x1000, 3)]);
        plan.modules = vec![module(3, 7)];
        let mut state = PrearmState::empty();
        state.set_scope_start_ns(Some(50));
        state.record_initial_modules([PinnedObjectId(7)]);
        state
            .watches
            .insert(PinnedObjectId(7), watched(BTreeSet::from([declared])));
        // Pre-arm-only record: no scan source, so the watch speaks and no
        // base window emits.
        let mut records = vec![record(3, vec!["prearm"])];
        state.assemble(
            &mut records,
            &plan,
            &BTreeMap::from([(0, 900)]),
            &BTreeMap::new(),
        );
        assert_eq!(records[0].attached_at_ns, Some(Some(900)));
        assert_eq!(records[0].unobserved_windows, None);
    }
}
