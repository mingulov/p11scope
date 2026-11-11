//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Rendering. Both renderers state the capture's completeness; a report
//! that lost information never reads as complete.

use crate::attach::CapturePolicy;
use crate::discovery::elf_needed::{
    GapExeHints, STATIC_HINT_LABEL, STATIC_HINT_SCOPE_D_TRANSITIVE,
};
use crate::discovery::scan::{ExcludedRecord, Skipped};
use crate::kinds;
use crate::mechanism_names::{mechanism_label, mechanism_name};
use crate::metrics::{SlotReport, percentile_ns};
use crate::plan::{ModuleId, TableSummary};
use crate::semantic_capture::InstanceReloadNotExcluded;
use crate::semantics::MechStat;
use p11scope_ebpf_common::{CounterMode, IMAGE_IDENTITY_TICKET_LIMIT};
use p11scope_manifest::manifest::{SelectionAuthority, SelectionRequest};
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;

/// Target-controlled bytes reach a terminal here. Only control characters —
/// C0, DEL, C1 (including CSI U+009B) — are rewritten; legitimate non-ASCII
/// pathnames still render as themselves. JSON is unaffected.
pub(crate) fn escape_controls(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Which live-discovery strategy each exact bound context used (design §9.2).
/// Only `debug_state_every_hit` leaves no completeness gap.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct LoaderStrategies {
    pub debug_state_every_hit: u64,
    pub dlopen_return: u64,
    pub unavailable: u64,
}

/// One load kind's timing classification, per exact bound context (design
/// §9.2). With the empty compiled-in catalog (D3 amendment §3) the catalog
/// classes are never reachable: a context is `unproven` or `none`, both
/// gaps, unless an owned `run`'s pause held every one of its loader hits and
/// table publications until the probes were attached — `pause_protected`,
/// which needs no catalog and is not a gap.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct LoaderTiming {
    pub qualified_pre_constructor: u64,
    pub known_pre_relocation: u64,
    pub unproven: u64,
    pub none: u64,
    pub pause_protected: u64,
}

impl LoaderTiming {
    /// Every classification except `qualified_pre_constructor` and
    /// `pause_protected` is a gap.
    fn gaps(&self) -> u64 {
        self.known_pre_relocation
            .saturating_add(self.unproven)
            .saturating_add(self.none)
    }
}

/// Whether an owned `run` could capture the child's initial provider set
/// before its first constructor ran (design §9.2).
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct InitialSetCapture {
    pub eligible: u64,
    pub none: u64,
    /// The owned child's initial set was held by its pause (see
    /// `LoaderTiming::pause_protected`); not a gap.
    pub pause_protected: u64,
}

/// The whole public live-loader surface: finite aggregate counts, never a
/// loader list, proof id, address, cookie, or process identity (design §9.2).
/// Always present in a Slice 1b-2 document, all-zero when nothing live ran.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct LoaderDiscovery {
    pub strategies: LoaderStrategies,
    pub dlopen_timing: LoaderTiming,
    pub initial_set_timing: LoaderTiming,
    pub initial_set_capture: InitialSetCapture,
    /// Scoped BPF debug-state hit counter, incremented before ring
    /// reservation. Never derived from received-record counts.
    pub hits: u64,
    /// Loader hits whose records resolved benignly: accepted, scan
    /// complete, no new provider module, no suspicious close — or
    /// pause-protected (the pause, not the scan, is the proof). A hit
    /// is exonerated only when its record is fully accounted; see
    /// `complete`. Never above `hits`: the checker refuses the report
    /// when it is.
    pub benign_hits: u64,
    /// The separate BPF counter for `_r_debug.r_state` reads. There is no
    /// second public copy of it.
    pub state_read_failures: u64,
}

impl LoaderDiscovery {
    /// True when nothing live discovery did leaves a completeness gap:
    /// only `debug_state_every_hit`, `qualified_pre_constructor`,
    /// `pause_protected`, and `initial_set_capture.eligible` /
    /// `.pause_protected` are neutral (design §9.2).
    ///
    /// A dlopen timing class is a gap only while a hit is unaccounted.
    /// Every hit of a bound context is counted before its record is
    /// reserved, so zero `hits` proves no load occurred during the
    /// capture: an armed loader that never fired cannot have missed a
    /// late provider's first call. A hit whose record resolved benignly
    /// (accepted, scan complete, no new provider, no suspicious close)
    /// loaded nothing the capture could have missed calls through, so
    /// fully benign hits do not gate exactness even with unproven
    /// timing. An unbound context counts nothing, so `unavailable`
    /// stays a gap on its own.
    fn complete(&self) -> bool {
        self.strategies.dlopen_return == 0
            && self.strategies.unavailable == 0
            && (self.benign_hits == self.hits || self.dlopen_timing.gaps() == 0)
            && self.initial_set_timing.gaps() == 0
            && self.initial_set_capture.none == 0
            && self.state_read_failures == 0
    }
}

/// Terminal verdict detail (SYSPLAN residual F-02): `completeness` alone can
/// no longer distinguish a clean-but-unproven drain from a concrete gap.
pub const VERDICT_CLEAN_PROVEN: &str = "clean_proven";
pub const VERDICT_CLEAN_BUT_UNPROVEN: &str = "clean_but_unproven";
pub const VERDICT_CONCRETE_GAP: &str = "concrete_gap";
/// No observation loss and no semantic degradation: the counts are exact,
/// only a name, owner, mechanism, or semantic interpretation is withheld
/// (review answer (a)). Still `PARTIAL`.
pub const VERDICT_ATTRIBUTION_ONLY: &str = "attribution_only";

/// How the terminal stop gate ended (owner ruling B, 2026-09-25).
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuiescenceState {
    /// No terminal stop gate ran: a live snapshot, or a path that never
    /// reached the terminal drain.
    #[default]
    NotReached,
    /// The stop gate observed quiescence (Q): no admitted BPF body was
    /// still running, and both terminal drains ran to the positions read
    /// at Q.
    Proven,
    /// The owner budget expired without Q (`QuiescenceUnproven`).
    Unproven,
}

/// Terminal stop-gate evidence: the quiescence outcome and the two post-Q
/// invariant flags (a record past the Q position on either ring means an
/// ungated writer). Published so the reason a drain stayed unproven is in
/// the document, not only on stderr.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct StopQuiescence {
    pub state: QuiescenceState,
    pub post_q_events: bool,
    pub post_q_discovery: bool,
}

impl StopQuiescence {
    /// Owner ruling B: a proven Q plus a drain to the Q positions proves
    /// the terminal drain, on x86_64 only. Either post-Q flag, an unproven
    /// or missing Q, or another architecture keeps it unproven.
    pub fn proves_drain(&self) -> bool {
        self.proves_drain_on(DRAIN_PROOF_ARCH)
    }

    /// The ruling with the architecture decision injected, so the arm64
    /// cell is testable on an x86_64 host.
    pub(crate) fn proves_drain_on(&self, arch_proves: bool) -> bool {
        arch_proves
            && self.state == QuiescenceState::Proven
            && !self.post_q_events
            && !self.post_q_discovery
    }
}

/// Whether this build's architecture carries the quiescence proof. The
/// argument rests on x86's lock-prefixed add being a full barrier; arm64
/// JITs the non-fetch add without barriers, so it stays unproven there.
pub(crate) const DRAIN_PROOF_ARCH: bool = cfg!(target_arch = "x86_64");

/// The skip reason of a NULL function-table entry. A NULL pointer can never
/// be called, so no call can be missed through it: it is a published fact,
/// never an observation gap.
pub(crate) const NULL_POINTER_REASON: &str = "null pointer";

/// One closed gap class: its status and the evidence fields that put it
/// there, in the fixed order `Evidence::gap_classes` checks them.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GapClass {
    pub status: &'static str,
    pub causes: Vec<&'static str>,
}

/// The verdict's inputs split into what they mean (review answer (a)):
/// `observation` — could a call or record be missing, or a count be wrong
/// (`exact` | `lossy`); `attribution` — is a name, owner, mechanism, or
/// semantic interpretation withheld while counts stay exact (`attested` |
/// `withheld`); `semantics` — are the event-derived sections degraded
/// (`complete` | `degraded` | `not_applicable` when no slot carries
/// semantics); `open_calls` — calls entered but not returned at the snapshot;
/// `settlement` — whether the terminal drain is proven (`proven` |
/// `unproven`); `stdout_data_sink` — whether stdout carried the capture's
/// data, the only case in which slow-sink drops are an observation loss.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GapClasses {
    pub observation: GapClass,
    pub attribution: GapClass,
    pub semantics: GapClass,
    pub open_calls: u64,
    pub settlement: &'static str,
    pub stdout_data_sink: bool,
}

impl Default for GapClasses {
    fn default() -> Self {
        Self {
            observation: GapClass {
                status: "exact",
                causes: Vec::new(),
            },
            attribution: GapClass {
                status: "attested",
                causes: Vec::new(),
            },
            semantics: GapClass {
                status: "complete",
                causes: Vec::new(),
            },
            open_calls: 0,
            settlement: "unproven",
            stdout_data_sink: false,
        }
    }
}

/// Every `P11SCOPE_*` switch that can change capture behavior, with its
/// effect. `--help` and `docs/usage.md` list exactly these (plus the
/// build/lane inputs usage.md owns); capture evidence records the active
/// value of each (SYSPLAN residual F-26). Test-only re-exec markers and
/// lane-internal plumbing are not operator switches and stay out.
pub const P11SCOPE_ENV_VARS: &[(&str, &str)] = &[
    (
        "P11SCOPE_BROAD_ADMIT",
        "experiment-only broad provider admission; anything but exactly \
         \"1\" keeps the narrow default",
    ),
    (
        "P11SCOPE_LOADER_ENV_SANITIZED",
        "p11scope-discover loader-environment marker; a forged value is \
         rejected, never trusted",
    ),
    (
        "P11SCOPE_DISABLE_FILE_LEARNING",
        "disables kernel file-open learning under --system; exactly \"1\" \
         disables it, anything else keeps learning on",
    ),
];

/// One capture-visible environment switch and its active value: `None`
/// when unset (SYSPLAN residual F-26).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EnvEvidence {
    pub name: &'static str,
    pub effect: &'static str,
    pub value: Option<String>,
}

/// Snapshots [`P11SCOPE_ENV_VARS`] through `get`, so tests inject a fake
/// environment instead of mutating the process's.
pub fn snapshot_env(get: impl Fn(&str) -> Option<String>) -> Vec<EnvEvidence> {
    P11SCOPE_ENV_VARS
        .iter()
        .map(|(name, effect)| EnvEvidence {
            name,
            effect,
            value: get(name),
        })
        .collect()
}

/// Snapshots [`P11SCOPE_ENV_VARS`] from the process environment.
pub fn snapshot_process_env() -> Vec<EnvEvidence> {
    snapshot_env(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

/// A `--allow-uretprobe-on-confined-target` override, recorded durably
/// (SYSPLAN residual F-01): the flag that accepted the risk plus the
/// hazard preflight's reason for requiring it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct UretprobeOverride {
    pub flag: &'static str,
    pub reason: String,
}

/// The render-ready facts the binary may see: everything the headings, the
/// final frame, and the JSON document are built from. Sanitized by
/// construction — no pins, process views, open files, timing keys, or
/// loader/pause identities cross this boundary (plan Task 8 Step 2). Most
/// fields are capture-lifetime history and never shrink once accepted;
/// `active_slots` is the one exception (owner decision U-14, 2026-09-23) —
/// see its own doc below.
#[derive(Debug, Clone, Default)]
pub struct CaptureFacts {
    pub(crate) discovery: DiscoveryEvidence,
    pub(crate) table_entries: usize,
    pub(crate) slots: usize,
    /// The plan's active-slot count right now, not capture-lifetime history:
    /// it reaches 0 for a scan-only `--pid` capture once the target has
    /// exited, and shrinks independently on a failed live attach or
    /// replacement, or a lost process generation. A manifest-attested object
    /// stays planned and active independently of any one process view, so a
    /// manifest-backed capture's exit does not drive it to 0. See
    /// `AttachPlan::active_slot_count`.
    pub(crate) active_slots: usize,
    pub(crate) attach_gap_ms: Option<u64>,
    pub(crate) loader_discovery: LoaderDiscovery,
    pub(crate) discovery_ring_loss: u64,
    pub(crate) discovery_state_failures: u64,
    pub(crate) discovery_read_failures: u64,
    pub(crate) discovery_truncated: u64,
    /// Raw per-ring cross-check inputs (kernel produced/dropped plus
    /// userspace consumed/queued). The report computes the accounts.
    pub(crate) ring_readings: crate::ring_accounting::RingReadings,
    /// The exit-ended subset of `discovery_truncated`: loader scans
    /// and loader rejects settled at a proven process exit. Not a
    /// fifth loss lane — K0 subtracts it from the total when it
    /// compares its window snapshots. In cgroup and system scopes a
    /// scope departure settles here too, but K0 refuses those scopes
    /// by name, so no consumer reads it there.
    pub(crate) exit_ended_truncations: u64,
    /// The exit-only total above, split by route for the K0 debug
    /// line: [deferred-scan ends, loader rejects, zero-state ends].
    /// Not serialized; the live cells parse it off stderr.
    pub(crate) exit_ended_by_route: [u64; 3],
    pub(crate) task_uprobe_link_losses: u64,
}

impl CaptureFacts {
    /// Everything discovery accepted over the whole capture, already sanitized.
    pub fn discovery(&self) -> &DiscoveryEvidence {
        &self.discovery
    }

    /// Function records decoded across every walked surface this capture saw.
    pub fn table_entries(&self) -> usize {
        self.table_entries
    }

    /// Attach slots allocated over the whole capture. Capture-lifetime
    /// history: it never shrinks, even once a target exits, an attach fails,
    /// or a generation is lost. See `active_slots` for what is active in the
    /// plan.
    pub fn slots(&self) -> usize {
        self.slots
    }

    /// The plan's active-slot count when this report is written (owner
    /// decision U-14) — not capture-lifetime history, and not a churn count.
    /// `slots - active_slots` mixes several causes (an ordinary target exit,
    /// a failed live attach or replacement, a lost generation) and must not
    /// be read as "N restarts". A scan-only `--pid` capture reports 0 once
    /// its target has exited; a manifest-attested object can stay planned
    /// and active independently of any one process view.
    pub fn active_slots(&self) -> usize {
        self.active_slots
    }

    pub fn attach_gap_ms(&self) -> Option<u64> {
        self.attach_gap_ms
    }

    pub fn loader_discovery(&self) -> LoaderDiscovery {
        self.loader_discovery
    }

    /// The four §9.1 discovery loss counters, in schema order.
    pub fn discovery_losses(&self) -> [u64; 4] {
        [
            self.discovery_ring_loss,
            self.discovery_state_failures,
            self.discovery_read_failures,
            self.discovery_truncated,
        ]
    }

    /// Raw per-ring cross-check inputs for the report's accounts.
    pub(crate) fn ring_readings(&self) -> crate::ring_accounting::RingReadings {
        self.ring_readings
    }

    /// Loader scans and loader rejects settled at a proven process
    /// exit: the exit-only subset of the truncation total. K0's
    /// window rule compares the total minus this count. In cgroup and
    /// system scopes a scope departure settles here too, but K0
    /// refuses those scopes by name, so no consumer reads it there.
    pub fn exit_ended_truncations(&self) -> u64 {
        self.exit_ended_truncations
    }

    /// The exit-only total above, split by route for the K0 debug
    /// line: [deferred-scan ends, loader rejects, zero-state ends].
    pub fn exit_ended_by_route(&self) -> [u64; 3] {
        self.exit_ended_by_route
    }

    /// Task-uprobe links that disappeared while their retained process group
    /// still had a live member, counted once per affected process view.
    pub fn task_uprobe_link_losses(&self) -> u64 {
        self.task_uprobe_link_losses
    }

    /// The one live-heading policy: every ordinary heading names the providers
    /// this capture accepted over its lifetime, never the currently active
    /// topology. A target that exited keeps its provider in the heading, so
    /// "no modules discovered" can never print beside retained historical
    /// calls; only a capture that never accepted a provider says it — and
    /// when refused providers were found, the heading says none attached
    /// with the found count instead of contradicting the refusal line.
    /// The found count shares the stderr hint's classifier: a proxy
    /// closure still awaiting publication reads like nothing mapped
    /// yet, never as a found provider.
    pub fn heading(&self) -> String {
        let found = self
            .discovery
            .modules_skipped
            .iter()
            .filter(|skipped| crate::plan::skip_is_found_provider(&skipped.reason))
            .count();
        match self.discovery.modules.as_slice() {
            [] if found == 0 => "no modules discovered".to_string(),
            [] => format!("none attached ({found} found, refused)"),
            [only] => escape_controls(&only.path).into_owned(),
            [first, rest @ ..] => {
                format!("{} (+{} more)", escape_controls(&first.path), rest.len())
            }
        }
    }
}

/// How the classic session attached its static probes (DR-CLASSIC-PID0),
/// as the native inventory lane's `observation.attach` spells it.
/// Profile and metrics lanes (`evidence.attach_backend`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AttachBackendEvidence {
    /// The operator's `--attach-backend`: `auto`, `multi` or `singles`.
    pub selection: &'static str,
    /// Why `auto` runs per-offset links (a failed functional probe, or a
    /// uprobe-multi attach the kernel refused), else `None`.
    pub fallback: Option<String>,
    /// Under `--pid`, what keeps other processes out of the static probes
    /// besides the in-BPF PID guard: `kernel-pid+bpf` (uprobe-multi links
    /// name the target; the kernel pid filter was proven) or
    /// `perf-task+bpf` (per-offset links bound to the target's task);
    /// `None` under cgroup and system scope.
    pub scope_filter: Option<&'static str>,
}

impl Default for AttachBackendEvidence {
    fn default() -> Self {
        Self {
            selection: "auto",
            fallback: None,
            scope_filter: None,
        }
    }
}

/// Object-attribute capture availability: build scope, identical for
/// every capture of this binary. Stubbed (P0)
/// builds report `available: false` with the finite `not_enabled`
/// reason; FULL builds report `available: true`. Never gates the
/// verdict — P0 scope is complete when P0 facts are complete; this
/// disclaims attribute coverage instead of claiming it.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct ObjectCaptureEvidence {
    /// Whether this build captures object attributes.
    pub available: bool,
    /// Finite machine reason when unavailable, else `None`.
    pub reason: Option<&'static str>,
}

impl ObjectCaptureEvidence {
    /// The one P0 unavailability reason: the stub feature compiled
    /// attribute capture out.
    pub const NOT_ENABLED: &'static str = "not_enabled";

    /// Structured status for a build flavor: `stubbed` names the probed
    /// byte state, true when the embedded object's attribute capture is stubbed.
    pub const fn for_build(stubbed: bool) -> Self {
        if stubbed {
            Self {
                available: false,
                reason: Some(Self::NOT_ENABLED),
            }
        } else {
            Self {
                available: true,
                reason: None,
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct InterfaceSelection {
    pub providers: Vec<SelectionProvider>,
    pub standard_exports: Vec<StandardExport>,
    pub inventory_surfaces: Vec<SelectionSurface>,
    pub tuples: Vec<SelectionTuple>,
    pub selection_truncated: bool,
}

impl InterfaceSelection {
    pub(crate) fn mark_descendant_gap(&mut self) {
        for provider in &mut self.providers {
            provider.coverage = match provider.coverage {
                "observed" => "observed_uncovered",
                "absent_covered" => "absent_uncovered",
                coverage => coverage,
            };
        }
    }

    /// Every selection fact that bounds what was observed: nothing
    /// truncated, every provider covered, every standard export resolved,
    /// and no successful selection of a table the inventory does not hold.
    fn observation_complete(&self) -> bool {
        !self.selection_truncated
            && self
                .providers
                .iter()
                .all(|provider| matches!(provider.coverage, "observed" | "absent_covered"))
            && self.standard_exports.iter().all(|export| {
                matches!(
                    export.status,
                    "present" | "legacy_absent" | "required_absent"
                )
            })
            && self.tuples.iter().all(|tuple| {
                !(tuple.rv == 0
                    && tuple.result.is_some()
                    && tuple.inventory_matches.is_empty()
                    && tuple.authority == SelectionAuthority::None)
            })
    }

    /// A selection-only table was counted without inventory authority: its
    /// counts are exact, its semantic attribution is withheld.
    fn has_count_only_authority(&self) -> bool {
        self.tuples
            .iter()
            .any(|tuple| tuple.authority == SelectionAuthority::SelectionCountOnly)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SelectionProvider {
    pub module: u32,
    pub coverage: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StandardExport {
    pub module: u32,
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SelectionSurface {
    pub module: u32,
    pub ordinal: u16,
    pub kind: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SelectionMatch {
    pub surface: u16,
    pub name_agrees: bool,
    pub version_agrees: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SelectionTuple {
    pub module: u32,
    pub request: SelectionRequest,
    pub rv: u64,
    /// Result `flags` publish only as a finite class (see
    /// [`selection_result_flags_class`]); request flags are a scalar argument.
    #[serde(serialize_with = "serialize_selection_result")]
    pub result: Option<SelectionRequest>,
    pub table_match: bool,
    pub inventory_matches: Vec<SelectionMatch>,
    pub authority: SelectionAuthority,
    pub count: u64,
}

/// The finite class of a returned interface flags word: `zero`,
/// `fork_safe` (exactly `CKF_INTERFACE_FORK_SAFE`), or `other`. The kernel
/// already reduces live results to this domain; the class is applied again
/// here so no path (live, offline helper, stale object) publishes the word.
pub fn selection_result_flags_class(flags: u64) -> &'static str {
    match flags {
        0 => "zero",
        cryptoki_sys::CKF_INTERFACE_FORK_SAFE => "fork_safe",
        _ => "other",
    }
}

fn serialize_selection_result<S: serde::Serializer>(
    result: &Option<SelectionRequest>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct PublishedResult {
        name: p11scope_manifest::manifest::SelectionNameClass,
        version: p11scope_manifest::manifest::SelectionVersionClass,
        flags: &'static str,
    }
    result
        .as_ref()
        .map(|result| PublishedResult {
            name: result.name,
            version: result.version,
            flags: selection_result_flags_class(result.flags),
        })
        .serialize(serializer)
}

/// What discovery learned, carried into evidence (spec §4.8). Flattened into
/// `evidence`, so a consumer reads `evidence.authority`, `evidence.discovery[]`
/// and the counters as siblings of every other evidence field.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DiscoveryEvidence {
    /// How the objects behind every probe were authorized. `"hash-pinned"` is
    /// the only value this slice emits: pinned by fd, hashed once with SHA-256,
    /// and re-checked by `fstat` `(ino, size, ctime)` during the capture.
    pub authority: &'static str,
    #[serde(rename = "discovery")]
    pub modules: Vec<DiscoveredModule>,
    /// Manifests whose recorded targets differ from the ones the scan decoded
    /// in the same object; the union is attached (spec §4.12).
    #[serde(rename = "discovery_conflicts")]
    pub conflicts: u64,
    /// Manifest modules nothing corroborated: not mapped in scope, the scan
    /// could not run, or the scan decoded no table in them.
    #[serde(rename = "discovery_uncorroborated")]
    pub uncorroborated: u64,
    /// Heuristic tables decoded but not admitted: past the per-object
    /// evidence-ordered cap or past the remaining global budget. Informational
    /// — spilling lookalikes is correct admission, not a coverage gap — so it
    /// does not affect `completeness` on its own. Capture-lifetime evidence:
    /// the high-water mark across publications, so a spill a later live merge
    /// resolves stays reported (the plan's own counter is the current-state
    /// one that resolves).
    #[serde(rename = "discovery_uncorroborated_candidates")]
    pub uncorroborated_candidates: u64,
    /// Attach slots two modules both publish: counted, never attributed.
    pub module_ambiguous: u64,
    /// Modules the slot ceiling cut short, one record per module. A module
    /// new to the capture, or an attached one whose sources list none of its
    /// endpoints any more, is refused whole, never attached in part; one
    /// already attached whose growth did not fit keeps its endpoints and is
    /// listed as partially covered, its reason opening with `admitted module
    /// needs` (G-03) and stating the largest omission the capture saw for it,
    /// a lower bound that a later whole refusal supersedes.
    pub modules_skipped: Vec<SkippedOut>,
    /// Optional-manifest objects ignored only because one exact scan-opened
    /// replacement table covered every dropped claim. Numeric manifest/object
    /// ordinals and replacement identity are bounded and path/PID-free.
    pub manifest_object_fallbacks: Vec<ManifestObjectFallback>,
    /// `Some("ptrace")` when the memory scan could not run.
    pub scan_unavailable: Option<String>,
    pub scan_ms: u64,
    /// Files skipped by `--exclude-module`, one record per distinct file
    /// (device + inode) with the number of in-scope processes that mapped
    /// it. A declared operator choice, never a loss: excluded files get no
    /// probes and use no slots, and the rest of the capture can still be
    /// `exact`. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_modules: Vec<ExcludedOut>,
    /// `--exclude-module` inputs that matched no mapped file. Omitted when
    /// empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmatched_excludes: Vec<String>,
    /// Modules the operator declared as forwarding layers with
    /// `--forwarding-module`, matched to mapped files at evidence assembly.
    /// Renderer metadata like `admission_class`: absent from the schema;
    /// the JSON layer split travels in `functions[]` and `layer_totals`.
    #[serde(skip)]
    pub forwarding_declared: Vec<ModuleId>,
    /// `--forwarding-module` inputs that matched no mapped file, in
    /// operator order. Omitted when empty. A declared input that matched
    /// nothing must never silently do nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmatched_forwarding: Vec<String>,
    /// 6.14 Option A exit-time mapping split, `None` unless extensive
    /// mode armed. Serde-skipped carrier: the profile lane and the
    /// terminal trace `EVIDENCE` hoist it to the top-level
    /// `gap_exit_mappings` key in `versioned_evidence`; the metrics
    /// lane hoists the hint splits but this split never arms there
    /// (no instance hooks), so the key stays absent. Stamped from
    /// live engine state on every `capture_facts()`.
    #[serde(skip)]
    pub gap_exit_mappings: Option<GapExitMappings>,
    /// Host-sized Detailed attach-slot ceiling, present only when the
    /// host-scaled STATS budget trimmed the compiled ceiling. Absent,
    /// never null, when the default loaded unchanged. Stamped from
    /// live engine state on every `capture_facts()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_sizing: Option<crate::capacity::SlotSizing>,
}

/// 6.14 Option A exit-time split of the novel unmatched-exit
/// subpopulation: leaders for which the kernel recorded a localized
/// mapping of a watched provider file at some point while watched
/// (`mapped`; the cells persist across unmap and exec, so this never
/// means the file was still mapped at the exit instant) vs every
/// other shape (`unknown`). Nominally `pub` for the
/// `DiscoveryEvidence` carrier; only the two counts render.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GapExitMappings {
    pub mapped: u64,
    pub unknown: u64,
}

/// One `--exclude-module` hit for the report: the file's target-view path,
/// its fstat identity, and how many in-scope processes mapped it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExcludedOut {
    pub path: String,
    pub dev: u64,
    pub ino: u64,
    pub processes: usize,
}

/// Aggregate per-(pid, file) exclusion records into per-file report rows
/// plus the inputs that matched nothing. Files group by (device, inode);
/// processes counts distinct pids; rows sort by path for stable output.
/// Unmatched inputs keep operator order.
pub(crate) fn aggregate_excluded(
    records: &[ExcludedRecord],
    excludes: &[std::path::PathBuf],
) -> (Vec<ExcludedOut>, Vec<String>) {
    use std::collections::{BTreeMap, BTreeSet};
    let mut by_file: BTreeMap<(u64, u64), (String, BTreeSet<u32>)> = BTreeMap::new();
    let mut matched: BTreeSet<&std::path::PathBuf> = BTreeSet::new();
    for record in records {
        matched.insert(&record.via);
        by_file
            .entry((record.dev, record.ino))
            .and_modify(|(_, pids)| {
                pids.insert(record.pid);
            })
            .or_insert_with(|| {
                let mut pids = BTreeSet::new();
                pids.insert(record.pid);
                (record.path.clone(), pids)
            });
    }
    let mut excluded: Vec<ExcludedOut> = by_file
        .into_iter()
        .map(|((dev, ino), (path, pids))| ExcludedOut {
            path,
            dev,
            ino,
            processes: pids.len(),
        })
        .collect();
    excluded.sort_by(|a, b| a.path.cmp(&b.path));
    let unmatched: Vec<String> = excludes
        .iter()
        .filter(|input| !matched.contains(*input))
        .map(|input| input.display().to_string())
        .collect();
    (excluded, unmatched)
}

/// Match `--forwarding-module` inputs against mapped modules at evidence
/// assembly. Each module is `(id, path, dev, ino)` with `dev` as
/// `(major, minor)`; `dev` is carried for shape stability and never
/// compared. A full path (contains `/`) matches the discovered
/// target-view path, corroborated by inode — fail closed, so an input
/// that no longer resolves matches nothing; a bare name matches every
/// file with that basename. Returns matched module ids (deduped, in
/// module order) plus the inputs that matched nothing. Bare names never
/// match by ELF soname here — the scan-time exclusion matcher owns
/// that; an unmatched soname is reported, not guessed. Generic over the
/// module-id type: the render lane keys by [`ModuleId`](crate::plan::ModuleId),
/// inventory by the caller registry's own id.
pub(crate) fn match_forwarding_inputs<Id: Copy + Ord>(
    declared: &[std::path::PathBuf],
    modules: &[(Id, String, (u64, u64), u64)],
) -> (Vec<Id>, Vec<String>) {
    use std::collections::BTreeSet;
    use std::os::unix::ffi::OsStrExt as _;
    let mut matched: BTreeSet<Id> = BTreeSet::new();
    let mut unmatched: Vec<String> = Vec::new();
    for input in declared {
        let text = input.as_os_str().as_bytes();
        let is_path = text.contains(&b'/');
        let mut hit = false;
        // A full path matches the discovered target-view path (mirroring
        // the scan-time --module hint gate, whose verbatim path match is
        // sufficient even for an unopenable hint), corroborated by inode,
        // and fails closed: a deletion or rotation between startup
        // validation and report time breaks the inode link and leaves the
        // declaration unmatched (named, never applied to the new file).
        // Device numbers are never compared: the module side renders a
        // maps/mountinfo device while the input side is an observer
        // fstat, and the two disagree for the same file (btrfs host:
        // st_dev 37 vs mount 0:35).
        let inode = if is_path {
            std::fs::metadata(input).ok().map(|meta| {
                use std::os::unix::fs::MetadataExt as _;
                meta.ino()
            })
        } else {
            None
        };
        let input_string = input.display().to_string();
        for (id, path, _dev, ino) in modules {
            let same = if is_path {
                crate::discovery::identity::target_paths_equal(&input_string, path)
                    && inode.is_some_and(|file_ino| *ino == file_ino)
            } else {
                std::path::Path::new(path)
                    .file_name()
                    .is_some_and(|base| base == input.as_os_str())
            };
            if same {
                matched.insert(*id);
                hit = true;
            }
        }
        if !hit {
            unmatched.push(input_string);
        }
    }
    let mut ordered: Vec<Id> = modules
        .iter()
        .map(|(id, _, _, _)| *id)
        .filter(|id| matched.contains(id))
        .collect();
    ordered.dedup();
    (ordered, unmatched)
}

impl Default for DiscoveryEvidence {
    fn default() -> Self {
        Self {
            authority: "hash-pinned",
            modules: Vec::new(),
            conflicts: 0,
            uncorroborated: 0,
            uncorroborated_candidates: 0,
            module_ambiguous: 0,
            modules_skipped: Vec::new(),
            manifest_object_fallbacks: Vec::new(),
            scan_unavailable: None,
            scan_ms: 0,
            excluded_modules: Vec::new(),
            unmatched_excludes: Vec::new(),
            forwarding_declared: Vec::new(),
            unmatched_forwarding: Vec::new(),
            gap_exit_mappings: None,
            slot_sizing: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ManifestObjectFallback {
    pub manifest: u32,
    pub object: u32,
    pub reason: &'static str,
    pub replacement: ManifestReplacement,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ManifestReplacement {
    pub dev: (u64, u64),
    pub ino: u64,
    pub sha256: String,
}

/// One object this capture pinned. `path` is the pathname the source that found
/// it saw: for anything the memory scan found that is a path in the **target's**
/// mount namespace, which the observer may be unable to open and which may name
/// a different file — or none — on the host. The identity is `{dev, ino, sha256}`;
/// the path is a label.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ObjectSummary {
    pub dev: (u64, u64),
    pub ino: u64,
    /// `None` when nothing pinned this object, so no digest was ever taken —
    /// an absence, never an empty digest.
    pub sha256: Option<String>,
    pub path: String,
    pub build_id: Option<String>,
    /// `"mountinfo"` when the whole `{dev, ino}` was comparable against the
    /// mapping, `"stat"` when only the inode was, `"unpinned"` when this
    /// capture never pinned the object and compared nothing.
    pub identity_source: &'static str,
    /// Why `identity_source` is `"stat"` rather than `"mountinfo"`.
    pub note: Option<String>,
    /// Exact canonical ownership: `scan`, `manifest`, or both.
    pub sources: Vec<&'static str>,
}

/// Pre-arm watch state for one `--prearm-module` object (packet 6.13, merged
/// D1 contract R2-D1-4). Finite vocabulary, serialized snake_case; stdout and
/// docs say "armed (not yet mapped)" once armed, never "watched/observed"
/// for `pinned_unarmed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrearmWatchState {
    /// Pinned; required links, scope or feed not yet ready. A pin is custody,
    /// never coverage: absence of a mapping proves nothing about links.
    PinnedUnarmed,
    /// Links installed on the whole declared endpoint set; mapping not
    /// required. Partial attachment stays unarmed for the declared set.
    Armed,
    /// Armed, plus clean observation health and no observed use over the
    /// stated interval — over the declared proved set only.
    ArmedIdle,
    /// No proved offset, or attach/scope failure: arming is impossible.
    Unavailable,
    /// The watch ended; `until_ns`/`ended_by` say when and why.
    Ended,
}

/// Why a pre-arm watch ended (R2-D1-7). Set only when the end actually
/// happened — never a static policy datum — and set exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrearmWatchEnd {
    /// The unarmed wait discharged: the declared set fully attached, but no
    /// armed interval is claimable (the arm instant is unknown).
    Attached,
    /// The capture scope ended; the watch is cancelled with it.
    ScopeEnd,
    /// The operator stopped the capture.
    Stop,
    /// The retained object changed under its pin (see `changed`).
    ObjectChanged,
    /// Observation health regressed; the clean claim truncates at its last
    /// proven-clean bound.
    HealthLoss,
    /// Scope membership went uncertain; same truncation as health loss.
    ScopeUncertain,
}

/// The uncertainty bracket of a retained-object change (R2-D1-8,
/// `pinned_object_changed` in prose): the change landed after `last_ok_ns`
/// and at or before `detected_ns`. A bracket, never a point instant, from
/// per-object held-fd `(ino, size, ctime)` checks — never retargeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PrearmObjectChange {
    pub last_ok_ns: u64,
    pub detected_ns: u64,
    pub previous_ino: u64,
}

/// The pre-arm watch interval on one discovery module record (R2-D1-4/5/7/8).
/// Discovery emits only this; `attached_at_ns`/`unobserved_windows` merge
/// later from real attach stamps at evidence assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PrearmWatch {
    /// The arm instant (declared set's links ready), `CLOCK_MONOTONIC`.
    /// Always emitted: null until armed. Never pin time.
    pub since_ns: Option<u64>,
    pub state: PrearmWatchState,
    /// Coverage-claim end, set exactly once at the first of scope end, stop,
    /// or truncation. No probe for this module attaches after it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_by: Option<PrearmWatchEnd>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<PrearmObjectChange>,
}

/// Why one interval went unobserved (R2-D1-5). Finite; every window carries
/// conservative outer bounds, never a missed-call estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnobservedReason {
    /// Before this module's probes attached: `[scope_start_ns, attached_at_ns]`.
    PreAttach,
    /// Generic provider discovered after scope start (outer bound starts at
    /// scope start: it may have existed and been called before discovery).
    LateDiscovery,
    /// Mapped but unattached endpoints outside the declared set.
    MappedUnattached,
    /// Observation health regressed over the tail interval.
    HealthLoss,
    /// Scope membership was uncertain over the tail interval.
    ScopeUncertain,
}

/// One explicitly unobserved interval on a discovery module record. Key
/// presence never proves exactness; only an explicitly empty list with an
/// R2-D1-6 proof behind it reads as exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UnobservedWindow {
    pub start_ns: u64,
    pub end_ns: u64,
    pub reason: UnobservedReason,
}

/// Which side of a witness-proven copy-up pair a module row describes.
/// Absent (`None`) is the ordinary case: the row describes the mapped
/// file itself. Finite vocabulary, serialized snake_case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleLayer {
    /// The lower file's row: the merge path, the shared merge-view
    /// key, the lower file's own digest, and the stale-mapping calls.
    /// JSON `"layer": "pre_copy_up"`.
    PreCopyUp,
}

/// Who first loaded a learned provider file: the drain's reuse-immune
/// `/proc/<loader>/exe` read at first sight, or the finite reason it
/// could not be read, plus how many distinct loader processes were
/// observed opening the file before it staged. Exactly one of `exe` /
/// `exe_unknown_reason` is non-null. Learned modules only; absent on
/// the wire for every ordinary module. No PID number is carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirstLoadedBy {
    /// Loading program's executable path, lossy UTF-8 from the exe link.
    pub exe: Option<String>,
    /// Finite reason when `exe` is `None`, else `None`.
    pub exe_unknown_reason: Option<&'static str>,
    /// Distinct loader processes observed opening this file before it
    /// was staged for attach (saturating). Loads between staging and
    /// attach are covered by the unobserved window, not this count;
    /// the count is not a bound on missed calls.
    pub pre_attach_loads: u64,
}

/// One module discovery found, with everything known about how it was found.
/// Same path caveat as `ObjectSummary`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DiscoveredModule {
    /// Capture-local stable ownership ID. It is renderer metadata only and is
    /// deliberately absent from the public report schema.
    #[serde(skip)]
    pub id: ModuleId,
    /// The deciding admission class label, renderer metadata like `id`:
    /// `closure_array` marks a forwarding-layer candidate even when it was
    /// admitted whole with no gap (counter/broad policies); the split
    /// additionally needs an active attributed row and no refused backend.
    /// Absent from the schema; the JSON layer split travels in `functions[]`
    /// and `layer_totals` instead.
    #[serde(skip)]
    pub admission_class: Option<&'static str>,
    pub dev: (u64, u64),
    pub ino: u64,
    /// `None` when nothing pinned the module object itself.
    pub sha256: Option<String>,
    pub path: String,
    pub build_id: Option<String>,
    /// `Some` only for the witness-proven pre-copy-up lower file's row;
    /// absent on the wire for every ordinary module.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<ModuleLayer>,
    /// Every object this module's **planned slots** attach into — a forwarded
    /// entry lands in a dependency, not in the module that published it. An
    /// entry that never became a slot is in `skipped`, not here.
    pub objects: Vec<ObjectSummary>,
    /// `"scan"`, `"manifest"`, `"prearm"`, or a `+`-joined combination.
    pub sources: Vec<&'static str>,
    /// A second source described the same targets (spec §4.12).
    pub corroborated: bool,
    /// Which §4.12 outcome each source pairing produced, so an agreement and a
    /// conflict are never indistinguishable in the record. One entry per
    /// `--manifest` that named this object, so two manifests naming one object
    /// show both outcomes rather than the first hiding the second:
    /// `single_source` (nothing to corroborate against), `agreed`, `conflict`
    /// (both sources decoded targets and they differ), `scan_empty` (the scan
    /// pinned this object but decoded no table in it — the documented use of
    /// `--manifest`), `uncorroborated` (not mapped in scope, or no scan),
    /// `identity_mismatch` (a manifest naming this object was ignored: the
    /// mapped bytes are not the ones it records).
    pub corroboration: Vec<&'static str>,
    pub tables: Vec<TableSummary>,
    /// How many interfaces were seen — the most any one source saw, never the
    /// sum across sources. Never their names: those are bytes read out of the
    /// target and stay in `inspect` (spec §4.3, allowlist v1).
    pub interfaces: usize,
    /// This module's own unattachable entries, and why.
    pub skipped: Vec<SkippedOut>,
    /// Pre-arm watch interval (packet 6.13). `None` — and absent on the wire —
    /// for every module no `--prearm-module` named. Discovery emits only this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watch: Option<PrearmWatch>,
    /// Per-module attach instant, `CLOCK_MONOTONIC`, merged at evidence
    /// assembly from real attach-complete stamps (never the once-only session
    /// stamp). Triple-state: absent before assembly, null when assembled
    /// with nothing attached, otherwise the max over the declared set's
    /// real stamps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attached_at_ns: Option<Option<u64>>,
    /// Explicit unobserved intervals, merged at evidence assembly. Absent
    /// means undisclosed (never-mapped pre-arm, unattached modules); an
    /// explicitly empty list reads as exact only with an R2-D1-6 proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unobserved_windows: Option<Vec<UnobservedWindow>>,
    /// Who first loaded this file, learned modules only. `None` — and
    /// absent on the wire — for every module no learn event staged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_loaded_by: Option<FirstLoadedBy>,
}

/// One ring's cross-check account: the kernel's submitted (`produced`)
/// and refused (`dropped`) totals against userspace's drained (`consumed`)
/// total and the queued remainder. `still_queued`/`unexplained` are absent
/// exactly when the remainder is structurally unknowable (a live EVENTS
/// ring); a measured nonzero `unexplained` is loss the reserve-failure
/// counter never saw, reported as a named gap.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RingAccountEvidence {
    pub produced: u64,
    pub consumed: u64,
    pub dropped: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub still_queued: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unexplained: Option<u64>,
}

/// Both rings' cross-check accounts. A ring is absent when it has no
/// counters in this build or mode (EVENTS under inventory or metrics,
/// which never drain it): unknown, never zero.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RingAccountingEvidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery: Option<RingAccountEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<RingAccountEvidence>,
}

impl RingAccountingEvidence {
    /// No ring has counters: the unknown account, for modes that drain
    /// no ring.
    pub fn unknown() -> Self {
        Self {
            discovery: None,
            events: None,
        }
    }

    /// Computes both rings' accounts from the facts' raw readings. The
    /// EVENTS reserve-failure total rides kernel evidence (the engine
    /// never sees that map), so the caller merges it here; every other
    /// input comes from the facts.
    pub(crate) fn from_readings(
        readings: &crate::ring_accounting::RingReadings,
        events_dropped: u64,
    ) -> Self {
        let mut readings = *readings;
        readings.events.dropped = events_dropped;
        let accounts = readings.accounts();
        let convert = |account: crate::ring_accounting::RingAccount| RingAccountEvidence {
            produced: account.produced,
            consumed: account.consumed,
            dropped: account.dropped,
            still_queued: account.still_queued,
            unexplained: account.unexplained,
        };
        Self {
            discovery: accounts.discovery.map(convert),
            events: accounts.events.map(convert),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Evidence {
    /// Function records discovery decoded across every walked surface, whether
    /// or not they became attachable — a NULL slot and an entry whose object
    /// could not be pinned are both counted here and listed in `skipped`, so
    /// this reads as "seen" against `slots`' "attached".
    pub table_entries: usize,
    /// Unique {object, file_offset} targets planned, allocated over the
    /// whole capture. The plan is append-only: a slot is never reused within
    /// a capture, so a retired target still counts here — this number never
    /// shrinks. See `active_slots` for what is active in the plan.
    pub slots: usize,
    /// The plan's active-slot count when this report was written (owner
    /// decision U-14, 2026-09-23): mirrors `plan.is_active`, not a count of
    /// kernel links, and not capture-lifetime history like `slots`. It is 0
    /// after an ordinary exit of a scan-only `--pid` target (a manifest-
    /// attested object can stay planned and active on its own), and shrinks
    /// independently on a failed live attach or replacement, or a lost
    /// process generation. `slots - active_slots` is not a churn count: it
    /// mixes all of those causes.
    pub active_slots: usize,
    /// Probes successfully attached (2 per fully-attached slot).
    pub attached_probes: usize,
    pub attach_failures: Vec<String>,
    /// Slots whose counts belong to a name group, not a single name.
    pub aliased: Vec<Vec<String>>,
    /// Discovered entries with no attachable target, and why. Also published
    /// per module in `discovery[].skipped`.
    pub skipped: Vec<SkippedOut>,
    /// Planned slots whose names are not authorized for semantic
    /// interpretation (every scan-found slot, whatever its linkage). Counts
    /// through them are exact; only their semantics are withheld, so this is
    /// an attribution gate, never an observation loss.
    pub semantic_unverified_slots: usize,
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
    /// Ring-buffer events the kernel side could not reserve space for
    /// (`metrics::lost_events`). Zero in `--mode metrics`, which never
    /// drains the ring buffer.
    pub event_loss: u64,
    pub start_insert_failures: u64,
    pub unmatched_returns: u64,
    pub rv_update_failures: u64,
    pub cgroup_scope_failures: u64,
    /// Scoped probe hits whose exact x86 execution-mode selector was neither
    /// conventional LP64 nor ia32. No ABI-dependent read was attempted.
    pub abi_refusals: u64,
    pub semantic_capture_failures: u64,
    pub unregistered_mechanisms: u64,
    /// Approved mechanism ids the `MECH_SHAPE` publication could not fit
    /// (ruling JK-22a): the official-first subset published instead of
    /// refusing the session, and these stayed unpublished, counting
    /// through the unregistered path. Zero unless the approval union
    /// exceeded the map.
    pub unpublished_mechanisms: u64,
    pub template_tail_failures: u64,
    pub process_tracking_fallbacks: u64,
    pub process_tracking_failures: u64,
    pub process_tracking_evictions: u64,
    pub state_reconciliations: u64,
    pub session_cancel_ambiguities: u64,
    pub session_cancel_unknown_flags: u64,
    pub operation_state_imports: u64,
    pub auth_state_ambiguities: u64,
    pub async_target_failures: u64,
    pub async_orphans: u64,
    pub async_duplicates: u64,
    pub async_evictions: u64,
    pub fork_state_ambiguities: u64,
    /// The enforced per-capture semantic-state key budget: at most this
    /// many keys are ever admitted, and every refused admission counts
    /// in `semantic_state_drops` below. Always present, so a report
    /// states its own budget; never feeds shares, verdicts, or
    /// completeness.
    pub semantic_key_budget: usize,
    pub semantic_state_drops: u64,
    /// Mechanism observations shed because the per-id table already held
    /// 256 distinct ids (`semantics::SemanticEvidence::mechanism_id_overflow`):
    /// one count per shed observation. The shed ids keep no row anywhere.
    /// Shed observations bypass the shared budget; row calls plus this
    /// count account for every mechanism-bearing observation except those
    /// refused by the shared budget (counted in `semantic_state_drops`).
    /// Forces `PARTIAL`, like every other shed observation.
    pub mechanism_id_overflow: u64,
    /// Mechanism observations through standard-layout-only slots whose
    /// value is outside the registered CKM_* registry: counted only,
    /// the number is never published (ruling 2026-11-11 clause 2).
    pub unregistered_standard_layout_mechanisms: u64,
    /// Planned slots whose semantic authority is standard-layout scan
    /// evidence only. Renderer metadata for the coverage note.
    #[serde(skip)]
    pub standard_layout_slots: u64,
    /// Layout-evidence labels behind those slots, for the note.
    #[serde(skip)]
    pub standard_layout_evidence: Vec<String>,
    pub semantic_history_drops: u64,
    pub pending_at_end: u64,
    /// Ring-buffer records rejected by the size check (`events::OwnedDrain`/`EventDrain`).
    /// A nonzero count means the writer/reader layout drifted mid-capture.
    pub malformed_records: u64,
    /// Operational calls (`C_Sign`, `C_Encrypt`, ...) observed with no
    /// active `*Init` on their session — expected when capture attaches
    /// mid-operation; informational, does not affect `completeness`.
    pub orphan_ops: u64,
    /// `C_CloseSession` calls observed with no matching open — likewise
    /// informational, does not affect `completeness`.
    pub unmatched_closes: u64,
    /// `*Init` calls whose unsafe parameter decode did not apply for a mechanism
    /// id known to have a diagnostic shape this capture
    /// (`semantics::State::shape_decode_failures`) — an inconsistent- or
    /// total-decode-failure signal, by call count. Informational: does not
    /// affect `completeness` on its own, since an inconsistent decode may
    /// reflect provider-side parameter validation rather than a capture
    /// defect. See `shape_decode_total_failures` for the subset (whole
    /// mechanisms, never once decoded) that does gate `completeness`.
    pub shape_decode_failures: u64,
    /// Mechanism ids with a published shape whose decode never once
    /// succeeded this capture (`semantics::State::total_shape_decode_failures`)
    /// — a real decode regression (wrong offsets, too-short
    /// `ulParameterLen`, an unfaulted page, every single call), not
    /// ordinary provider-side rejection variance. Unlike
    /// `shape_decode_failures`, this **does** gate `completeness`: a
    /// mechanism in this state renders `params: null` but is not the
    /// benign "no diagnostic shape" case — see `mechanisms[].note`.
    pub shape_decode_total_failures: u64,
    /// True when any `templates[].operations[]` entry observed
    /// `attr_total > attr_count` — a template longer than the capture's
    /// per-event cap, or a read failure mid-walk. Unlike the informational
    /// counters above, this DOES gate `completeness`: truncation is lost
    /// evidence.
    pub templates_truncated: bool,
    /// A pinned provider object changed (ino, size or ctime) after attach;
    /// probes may no longer describe the mapped bytes.
    pub provider_changed: bool,
    /// Maximum of the defined per-module earliest-causal-event-to-last-
    /// required-attach gaps (design §5.5). `null` — never an invented zero —
    /// when no module has a defined gap.
    pub attach_gap_ms: Option<u64>,
    /// Exactly `none`, `sigstop`, or `partial`, derived only from the three
    /// counters below by the design §5.6 lattice.
    pub pause: &'static str,
    pub pause_attempts: u64,
    pub pause_confirmed: u64,
    pub pause_partial: u64,
    /// `--pause always` degrades that collected unpaused instead of
    /// aborting (never-stop). Each forces `PARTIAL`.
    pub pause_unavailable: u64,
    /// Engine-incomplete cap retirements: `--pause auto` chains that
    /// ended after four straight incomplete cycles. Each is already one
    /// counted `pause_partial`; this count is a subset annotation, not
    /// a lattice member.
    pub pause_engine_incomplete_retirements: u64,
    /// Why the pause did not hold, when a lifecycle failure ended the
    /// run. Absent, never null, otherwise. Annotation beside the pause
    /// lattice, never a member of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pause_refused: Option<&'static str>,
    /// The aggregate read that never landed, when the terminal published
    /// without any snapshot. Absent, never null, otherwise; aggregate
    /// zeros are unknown, not measured, whenever it is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_failure: Option<&'static str>,
    /// Present only for `run`: true only when capture ended while the owned
    /// child was still alive. Absent from every `--pid`/`--cgroup` document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_still_running: Option<bool>,
    /// Present only for `run`: tree members handed back alive at run end
    /// (measured zero when the tree retired cleanly). Annotation beside
    /// the paired `run process tree` skip, which carries the verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_tree_handed_back: Option<u64>,
    /// Per-ring cross-check accounts (kernel produced/dropped against
    /// userspace consumed plus the queued remainder). A ring is absent
    /// when it has no counters in this build or mode.
    pub ring_accounting: RingAccountingEvidence,
    /// Failed `DISCOVERY` ring reservations across loader, exec, and export
    /// records — from the BPF counter, never derived from received records.
    pub discovery_ring_loss: u64,
    /// Export entry-state no-overwrite/cleanup failures (BPF counter).
    pub discovery_state_failures: u64,
    /// Export table/interface bounded user-read failures only (BPF counter);
    /// loader-state reads are excluded and live in `loader_discovery`.
    pub discovery_read_failures: u64,
    /// One discovery-engine accumulator: source-declared record truncations,
    /// userspace decode failures, and every refused/invalid/stale loader
    /// context, each fed exactly once.
    pub discovery_truncated: u64,
    /// Matched leader exits whose retained process generation stayed live,
    /// proving task-uprobe link loss; counted once per process view.
    pub task_uprobe_link_losses: u64,
    /// Native kernel control state (owner poison, identity and root-affiliation
    /// refusals), read at every snapshot. A halt or any loss forces PARTIAL.
    pub kernel_control: crate::metrics::KernelControlEvidence,
    /// The always-present finite live-loader aggregate (design §9.2).
    pub loader_discovery: LoaderDiscovery,
    #[serde(skip)]
    pub interface_selection: InterfaceSelection,
    #[serde(skip)]
    pub attach_mechanisms: Vec<&'static str>,
    pub attach_backend: AttachBackendEvidence,
    /// Object-attribute capture availability in this build (P0-only ship
    /// vehicle): always present, queryable, never inferred from absence.
    pub object_capture: ObjectCaptureEvidence,
    #[serde(skip)]
    pub pid_descendant_gaps: u64,
    #[serde(skip)]
    pub multi_rebuild_gaps: u64,
    /// Provider files the fanotify drain staged (informational: the
    /// learned first-run row carries the verdict, never this count).
    #[serde(skip)]
    pub learned_staged_files: u64,
    /// Learning loss: queue overflows, lost drain tails, drain deaths.
    #[serde(skip)]
    pub learned_event_loss: u64,
    /// Learned candidates refused by the per-capture file cap.
    #[serde(skip)]
    pub learned_cap_skipped: u64,
    /// 6.14 Option B extensive-mode split of the novel unmatched-exit
    /// subpopulation, `None` unless armed. Manually serialized beside
    /// the gap counts; never part of shares or verdicts.
    #[serde(skip)]
    pub gap_exe_hints: Option<GapExeHints>,
    /// 7.10b extensive-mode split of the validated-target-exec
    /// subpopulation under exact-`--pid` scope, `None` unless the PID
    /// consumer armed. Manually serialized beside the gap counts;
    /// never part of shares or verdicts.
    #[serde(skip)]
    pub target_exec_hints: Option<GapExeHints>,
    /// B17 W2 per-identity reload disclosure, `None` without a
    /// producer. Manually serialized beside the gap counts into the
    /// profile lane only; never part of shares or verdicts.
    #[serde(skip)]
    pub instance_reload_not_excluded: Option<InstanceReloadNotExcluded>,
    /// Whether a live window (design §5.7: a first required attach key learned
    /// from a live loader or export event) went unprotected by a confirmed
    /// pause owner: 0 or 1, inferred as `loader_discovery.hits > 0` and
    /// `pause != "sigstop"`. Published so a `PARTIAL` behind it is visible;
    /// §5.7 kept it unpublished only because the inference is inexact, never
    /// for privacy — both inputs are already public.
    pub unprotected_live_windows: usize,
    /// Allocated aggregate cells with no accepted sole owner — the count of
    /// `functions[].module_unresolved` rows. An attribution gate.
    pub module_unresolved_slots: usize,
    /// Everything discovery learned, flattened into this object.
    #[serde(flatten)]
    pub discovery: DiscoveryEvidence,
    /// Consumer-scheduling evidence: which bound broke, and phase timings.
    pub scheduling: SchedulingEvidence,
    /// The terminal stop gate's outcome and post-Q flags (owner ruling B).
    pub stop_quiescence: StopQuiescence,
    /// Terminal drain settlement latch (SYSPLAN residual F-02). Set only by
    /// [`Evidence::apply_stop_quiescence`] from a proven stop-gate Q with
    /// both drains run to the Q positions and no post-Q record, on x86_64
    /// (owner ruling B). The terminal seal forces PARTIAL while false, so a
    /// COMPLETE requires this latch — never call-site discipline.
    pub drain_proven: bool,
    /// Which terminal story `completeness` tells: [`VERDICT_CLEAN_PROVEN`],
    /// [`VERDICT_CLEAN_BUT_UNPROVEN`], [`VERDICT_ATTRIBUTION_ONLY`], or
    /// [`VERDICT_CONCRETE_GAP`] — derived from `gap_classes` alone.
    pub verdict_detail: &'static str,
    /// The closed classes behind `completeness` and `verdict_detail`, with
    /// the evidence fields that put each class where it is.
    pub gap_classes: GapClasses,
    /// Whether stdout carried the capture's data (trace without `-o`). Only
    /// then are slow-sink drops an observation loss; a profile, metrics, or
    /// `-o` capture's stdout carries display frames only.
    #[serde(skip)]
    pub stdout_data_sink: bool,
    /// Whether a trace stopped at its event cap (`--max-events` or the
    /// default cap) and printed no line for the events drained after it.
    /// An observation cause on its own (DR-RETRO-C6-1): the line stream is
    /// short even behind a proven drain, so truncation always forces
    /// `PARTIAL`. Only the trace lane sets it; the trace terminal record
    /// publishes it as `trace_truncated`, so it is not a profile field.
    #[serde(skip)]
    pub trace_truncated: bool,
    /// The uretprobe/hazard override behind this capture, if any (SYSPLAN
    /// residual F-01). `None` exactly when the preflight proceeded clean.
    pub uretprobe_override: Option<UretprobeOverride>,
    /// The PID handed back alive at duration expiry, if any (SYSPLAN
    /// residual F-15). `Some` exactly when the `run` lane left its owned
    /// child running — the operator's own child, nameable, exit still 0.
    pub handoff_child_pid: Option<u32>,
    /// Which PID namespace numbers which PIDs (DR-K8S-1/2): the observer's
    /// own (`initial`, `nested`, `unknown`), kernel-reported PIDs (always
    /// `initial`), and `/proc`-read PIDs (`observer` when the mounted `/proc`
    /// is the observer's own, `foreign` otherwise). Anything but an
    /// `initial` observer is the observation gap `pid_namespace`, and a
    /// `foreign` `/proc` is `proc_namespace_mismatch`: live discovery keys
    /// on kernel PIDs this observer cannot resolve through `/proc`.
    pub pid_namespace: crate::pidns::PidNamespaceEvidence,
    /// A nested observer whose `/proc` showed nothing beyond its own
    /// container when this evidence was built (`docker run` without
    /// `--pid=host`): the `pid_namespace` gap text then names the
    /// container-only view and its remedy. Render-only, never
    /// serialized: the published `pid_namespace` evidence and the
    /// `pid_namespace` cause already carry the machine-readable fact.
    #[serde(skip)]
    pub container_only_view: bool,
    /// Active values of every capture-visible `P11SCOPE_*` switch
    /// ([`P11SCOPE_ENV_VARS`]), so the document says which behavior
    /// switches were live (SYSPLAN residual F-26).
    pub p11scope_env: Vec<EnvEvidence>,
    pub completeness: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SkippedOut {
    pub name: String,
    pub reason: String,
}

/// The declared slow-sink policy: a stalled stdout flush waits at most the
/// per-tick budget, then its pending bytes are dropped with counters, never
/// held unboundedly. The capture continues; the evidence says what left
/// through the sink and what did not.
pub const SINK_POLICY_BOUNDED_WAIT_DROP: &str = "bounded-wait-drop";

/// Why the capture loop ended, as published in [`PhaseMonoNs`]. Closed
/// set, pinned by the capture-evidence oracle.
pub const LOOP_END_EXPIRY: &str = "expiry";
pub const LOOP_END_OPERATOR_STOP: &str = "operator_stop";
pub const LOOP_END_TARGET_EXIT: &str = "target_exit";
pub const LOOP_END_LIMIT_REACHED: &str = "limit_reached";
pub const LOOP_END_ERROR: &str = "error";
/// The loop had not ended when snapshotted — mid-loop frames, or a capture
/// that never reached its loop.
pub const LOOP_END_UNSTARTED: &str = "unstarted";

/// Authoritative observer phase timestamps (T2, G-14): CLOCK_MONOTONIC
/// readings the observer takes itself at attach completion, capture-loop
/// start, and capture-loop end. `None` (JSON null) when the phase was never
/// reached — never 0, never an FD estimate. Measurement scripts prefer these
/// over retrospective FD estimates whenever present.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct PhaseMonoNs {
    pub attach_mono_ns: Option<u64>,
    pub loop_start_mono_ns: Option<u64>,
    pub loop_end_mono_ns: Option<u64>,
    /// One of the `LOOP_END_*` labels.
    pub loop_end_reason: &'static str,
}

impl Default for PhaseMonoNs {
    fn default() -> Self {
        Self {
            attach_mono_ns: None,
            loop_start_mono_ns: None,
            loop_end_mono_ns: None,
            loop_end_reason: LOOP_END_UNSTARTED,
        }
    }
}

/// In-observer per-phase wall time in milliseconds, cumulative over the
/// capture. Discovery is measured directly here (Task 3.1 G-discovery-
/// tick-slice), not as a residual of totals; `discovery` covers every
/// discovery drain (tick + terminal), while `discovery_terminal` covers
/// only the pre-detach terminal drain, so the per-frame tick slice is
/// `discovery - discovery_terminal`.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct SchedulingPhaseMs {
    pub discovery: u64,
    pub discovery_terminal: u64,
    pub drain: u64,
    pub maps: u64,
    pub render: u64,
    /// Producer-detach phase wall time within the published window.
    /// The terminal callback publishes before the producers detach
    /// (quiesce-then-publish), so post-stop-gate reads are 0 by
    /// design: the teardown rides the worker final line plus the
    /// `STOPGATE_TIMING` `cleanup_ms` evidence instead.
    pub detach: u64,
}

/// Per-stage wall time in milliseconds, cumulative over the capture, in
/// [`crate::timing::StageKind::ALL`] order. Each total is the saturating sum
/// of that stage's recorded leaf spans only; spans whose clock read failed
/// contribute nothing (see `stage_unknown_clock`). Independent measurements
/// from `phase_ms` (different clocks, leaf spans vs wall brackets): they do
/// not sum to any phase and no identity is asserted between them.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct StageMs {
    pub scan: u64,
    pub pin: u64,
    pub bind: u64,
    pub plan: u64,
    pub merge: u64,
    pub projection: u64,
    pub attach: u64,
    pub drain: u64,
    pub cleanup: u64,
}

/// Per-stage recorded span counts, same keys as [`StageMs`]. A stage that
/// never ran publishes total `0` with `0` invocations (an exact empty sum,
/// not a missing sample).
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct StageInvocations {
    pub scan: u64,
    pub pin: u64,
    pub bind: u64,
    pub plan: u64,
    pub merge: u64,
    pub projection: u64,
    pub attach: u64,
    pub drain: u64,
    pub cleanup: u64,
}

/// The capture's longest single recorded span: its longest indivisible
/// operation. All three fields are `null` when no span was recorded —
/// a missing sample, never an invented zero.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct LongestOpEvidence {
    /// The stage key (`scan`, `pin`, `bind`, `plan`, `merge`,
    /// `projection`, `attach`, `drain`, `cleanup`), or `null`.
    pub stage: Option<&'static str>,
    /// The leaf operation label (e.g. `"attach_targets"`), or `null`.
    pub op: Option<&'static str>,
    /// Whole milliseconds (floor), or `null`.
    pub duration_ms: Option<u64>,
}

/// The bounded inter-drain gap distribution. Quantiles are bucket
/// upper-bound estimates in milliseconds (see
/// [`crate::timing::GAP_BUCKET_BOUNDS_MS`]); a quantile above the bucketed
/// range, or with no samples at all, publishes `null` — missing, never
/// zero. The maximum is exact and agrees with `max_inter_drain_gap_ms`
/// whenever samples exist.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct InterDrainGapEvidence {
    /// Gaps sampled (drains minus one; the first drain samples no gap).
    pub samples: u64,
    pub p50_ms: Option<u64>,
    pub p99_ms: Option<u64>,
    pub max_ms: Option<u64>,
}

/// Newcomer/refresh queue-age evidence in whole milliseconds. Ages run from
/// first-seen (arrival mark) to first-observed-ready (admission) or to the
/// drop tick. Clock-unknown samples count in the `*_unknown` counters and
/// never enter a mean or maximum.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct NewcomerQueueEvidence {
    /// Admissions with a known first-seen mark.
    pub admitted: u64,
    /// Admissions without one (clock unavailable or mark dropped).
    pub admitted_unknown: u64,
    /// Maximum known admission age, or `null` when none was sampled.
    pub max_admitted_age_ms: Option<u64>,
    /// Mean known admission age (floor), or `null` when none was sampled.
    pub mean_admitted_age_ms: Option<u64>,
    /// Pids still waiting at the snapshot (the union of the pending
    /// refresh queue and the deferred diff-discovered newcomers).
    pub pending: u64,
    /// Oldest known pending age at the snapshot, or `null` when no
    /// pending pid has a known mark.
    pub oldest_pending_age_ms: Option<u64>,
    /// Queue-cap drops with a known age (loss markers kept alongside).
    pub dropped: u64,
    /// Queue-cap drops without one.
    pub dropped_unknown: u64,
    /// Maximum known drop age, or `null` when none was sampled.
    pub max_dropped_age_ms: Option<u64>,
    /// Arrival marks dropped past the mark cap (bounded memory).
    pub marks_dropped: u64,
}

/// One capture-process resource sample. Every field is `null` when its
/// read or parse failed — a missing sample, never a zero.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct ResourceSampleEvidence {
    pub rss_kb: Option<u64>,
    pub utime_ms: Option<u64>,
    pub stime_ms: Option<u64>,
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
}

/// The capture's resource timeline: `/proc/self` samples at capture start,
/// attach readiness, and loop end, plus the bounded periodic summary (one
/// sample every [`crate::timing::RESOURCE_SAMPLE_EVERY_N_TICKS`] ticks;
/// only the count and latest sample publish) and the process peak RSS.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct ResourceEvidence {
    /// Periodic samples taken.
    pub samples: u64,
    /// Process peak RSS: the kernel high-water mark (`VmHWM`), or the
    /// periodic-sample maximum when the peak read failed, or `null`
    /// when neither read RSS. It includes the EVENTS ring's double user
    /// mapping (about twice the ring size), which is not extra memory:
    /// the ring is charged once.
    pub max_rss_kb: Option<u64>,
    pub start: ResourceSampleEvidence,
    pub readiness: ResourceSampleEvidence,
    pub end: ResourceSampleEvidence,
    /// The latest periodic sample (all `null` when none was taken).
    pub last_periodic: ResourceSampleEvidence,
}

/// Consumer-scheduling evidence (Task 3.1 repair): which bound broke when
/// the event path lost data, and how the capture loop spent its time.
/// The loss splits are identities, not estimates: capture + detach shares
/// always sum to the published loss counter.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SchedulingEvidence {
    /// Extra event-ring polls after a quantum stopped with backlog queued.
    pub drain_repolls: u64,
    /// Ticks that stopped draining with backlog left under the per-tick
    /// record/wall budget.
    pub drain_budget_exhaustions: u64,
    /// Ring loss sampled at capture-loop end, before producer detach.
    pub capture_event_loss: u64,
    /// Ring loss accrued after the capture loop ended through the
    /// terminal snapshot (the quiesce + terminal-drain window): the
    /// terminal reading minus the loop-end reading. Excludes anything
    /// lost during or after the post-publication producer detach.
    pub detach_event_loss: u64,
    /// Discovery-ring loss at capture-loop end, before producer detach.
    pub capture_discovery_loss: u64,
    /// Discovery-ring loss accrued after the capture loop ended through
    /// the terminal snapshot (the quiesce + terminal-drain window): the
    /// terminal reading minus the loop-end reading. Excludes anything
    /// lost during or after the post-publication producer detach.
    pub detach_discovery_loss: u64,
    /// Explicit record bound of the post-detach terminal event drain.
    pub terminal_drain_bound: u64,
    /// The terminal drain stopped at its bound with backlog still queued.
    pub terminal_drain_truncated: bool,
    /// Declared slow-sink policy; always [`SINK_POLICY_BOUNDED_WAIT_DROP`].
    pub sink_policy: &'static str,
    /// Total milliseconds stdout flushes stalled under backpressure.
    pub sink_stall_ms: u64,
    /// Flushes that exceeded the per-tick stall budget and dropped bytes.
    pub sink_timeouts: u64,
    /// Stdout bytes discarded by the slow-sink policy.
    pub sink_dropped_bytes: u64,
    /// Cumulative per-phase wall time.
    pub phase_ms: SchedulingPhaseMs,
    /// Authoritative observer phase timestamps (T2, G-14).
    pub phase_mono_ns: PhaseMonoNs,
    /// Largest gap between consecutive event drains during the capture
    /// loop. The undrained detach window and terminal drain never extend
    /// it (frozen at loop end): the detach window is separately counted
    /// (capture/detach split) and timed (detach phase).
    pub max_inter_drain_gap_ms: u64,
    /// Live discovery frames that spent their work budget and deferred the
    /// rest of their discovery work, in order, to the next frame (H-1). A
    /// scheduling fact, never a loss: work still undone after the terminal
    /// drain is published as a loss instead.
    pub discovery_deferrals: u64,
    /// Per-stage wall time (Phase 2): the discovery batch split into
    /// scan/pin/bind/plan/merge/projection/attach plus drain and cleanup.
    pub stage_ms: StageMs,
    /// Per-stage recorded span counts.
    pub stage_invocations: StageInvocations,
    /// Stage spans dropped for a failed clock read (in no total).
    pub stage_unknown_clock: u64,
    /// The longest single recorded span.
    pub longest_op: LongestOpEvidence,
    /// The inter-drain gap distribution (bounded histogram).
    pub inter_drain_gap: InterDrainGapEvidence,
    /// Newcomer/refresh queue ages.
    pub newcomer_queue: NewcomerQueueEvidence,
    /// Capture-process resource timeline.
    pub resource: ResourceEvidence,
    /// Batch-tail publications executed.
    pub tail_publishes: u64,
    /// Batch-tail publications skipped as provably redundant (B1).
    pub tail_skips: u64,
}

impl Default for SchedulingEvidence {
    fn default() -> Self {
        Self {
            drain_repolls: 0,
            drain_budget_exhaustions: 0,
            capture_event_loss: 0,
            detach_event_loss: 0,
            capture_discovery_loss: 0,
            detach_discovery_loss: 0,
            terminal_drain_bound: 0,
            terminal_drain_truncated: false,
            sink_policy: SINK_POLICY_BOUNDED_WAIT_DROP,
            sink_stall_ms: 0,
            sink_timeouts: 0,
            sink_dropped_bytes: 0,
            phase_ms: SchedulingPhaseMs::default(),
            phase_mono_ns: PhaseMonoNs::default(),
            max_inter_drain_gap_ms: 0,
            discovery_deferrals: 0,
            stage_ms: StageMs::default(),
            stage_invocations: StageInvocations::default(),
            stage_unknown_clock: 0,
            longest_op: LongestOpEvidence::default(),
            inter_drain_gap: InterDrainGapEvidence::default(),
            newcomer_queue: NewcomerQueueEvidence::default(),
            resource: ResourceEvidence::default(),
            tail_publishes: 0,
            tail_skips: 0,
        }
    }
}

const DISCOVERY_SUBJECT: &str = "discovery subject";
/// Run-tree scope gaps file under this subject with finite reasons
/// (schema v3): the survivor count rides in
/// `evidence.run_tree_handed_back`, never in the reason.
pub(crate) const RUN_TREE_SUBJECT: &str = "run process tree";
pub(crate) const RUN_TREE_SURVIVORS: &str = "process-tree members were still present when the command exited; their calls after the run end are out of scope";
pub(crate) const RUN_TREE_DEGRADED: &str = "only the started command is observed";
pub(crate) const RUN_TREE_MEMBERSHIP_UNKNOWN: &str = "handed-back descendants are unknown";
/// Learned-file gaps file under this subject with seven finite reasons
/// (schema v3): the staged-file count rides in
/// `evidence.learned_staged_files`, the loss in
/// `evidence.learned_event_loss`, the cap excess in
/// `evidence.learned_cap_skipped`, never in the reason.
pub(crate) const LEARNED_SKIP_SUBJECT: &str = "learned provider file";
pub(crate) const LEARNED_FIRST_RUN_REASON: &str =
    "a provider file was learned after its first use; its earlier calls were not observed";
pub(crate) const LEARNED_OVERFLOW_REASON: &str =
    "file-learning events were lost; some provider files may not have been learned";
pub(crate) const LEARNED_CAP_REASON: &str =
    "file learning reached its 32-file per-capture cap; further provider files were not learned";
pub(crate) const LEARNED_UNAVAILABLE_REASON: &str =
    "file learning was unavailable; short-lived first loads of new provider files were not learned";
pub(crate) const LEARNED_REPLACED_DELETED_REASON: &str =
    "a provider file was replaced or deleted before staging; it was not learned";
pub(crate) const LEARNED_DISABLED_REASON: &str = "file learning was disabled by the operator; short-lived first loads of new provider files were not learned";
pub(crate) const LEARNED_MOUNT_NAMESPACE_REASON: &str = "file learning cannot see filesystems outside the observer's mount namespace; provider files opened only there were not learned";
const DISCOVERY_UNAVAILABLE: &str = "discovery unavailable";
const ENTRY_UNAVAILABLE: &str = "function entry unavailable";
const TABLE_UNAVAILABLE: &str = "function table unavailable in file-backed data";
const SHARED_OVERLAY_UNCERTAINTY: &str = "shared-overlay physical identity is uncertain; a distinct byte-identical instance may be unobserved";
const PHYSICAL_IDENTITY_AMBIGUITY: &str =
    "physical identity is ambiguous; the collision group was not attached";
const UNSUPPORTED_TABLE_VERSION: &str =
    "unsupported function-table version; the scanner does not walk this layout";
const STATIC_GAP_INCOMPLETE: &str = "static probe coverage gap incomplete";
const STATIC_GAP_RECOVERED: &str = "static probes detached and exact pairs reattached";
const PROCESS_VIEW_CAPACITY_EXHAUSTED: &str =
    "capture process-view capacity was exhausted; remaining generations were not scanned";
const LOADER_CONTEXT_CAPACITY_EXHAUSTED: &str = "loader context capacity 256 is exhausted";
const LOADER_SCAN_LEDGER_EXCEEDED: &str =
    "a deferred loader memory scan exceeded the bounded loader-context ledger";
const LOADER_ARM_LEDGER_FULL: &str = "the bounded loader-arm catch-up ledger was full";
const MANIFEST_OBJECT_UNAVAILABLE: &str = "manifest object unavailable";
const PREARM_OBJECT_UNAVAILABLE: &str = "prearm object unavailable";
const DISCOVERY_TRANSPORT_UNAVAILABLE: &str = "discovery transport unavailable";

/// The engine's view-capacity sentence with its configured limit value
/// still in place: exact prefix, ASCII digits, exact suffix, whole string
/// consumed. Anything appended, prepended or non-numeric fails — a path
/// can never satisfy this, so the value that normalizes out is the
/// product limit alone, never target data.
fn is_view_capacity_exhaustion(reason: &str) -> bool {
    const PREFIX: &str = "capture process-view capacity ";
    const SUFFIX: &str = " was exhausted; remaining generations were not scanned";
    let Some(rest) = reason.strip_prefix(PREFIX) else {
        return false;
    };
    let Some(value) = rest.strip_suffix(SUFFIX) else {
        return false;
    };
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Closed allowlist of fixed product-limit skips (OD34/E1): the user must
/// read WHICH limit was hit. Each entry matches an exact internal
/// (subject, reason) pair whose text is fixed product wording with no
/// target-derived data (no path, pid, name or bytes) and maps it to its
/// finite public reason. Everything else keeps today's redaction.
fn limit_skip_reason(subject: &str, reason: &str) -> Option<&'static str> {
    if subject == "process view" && is_view_capacity_exhaustion(reason) {
        return Some(PROCESS_VIEW_CAPACITY_EXHAUSTED);
    }
    if (subject == "live loader arming" || subject == "owned initial-set discovery")
        && reason == LOADER_CONTEXT_CAPACITY_EXHAUSTED
    {
        return Some(LOADER_CONTEXT_CAPACITY_EXHAUSTED);
    }
    if subject == "live loader memory discovery" && reason == LOADER_SCAN_LEDGER_EXCEEDED {
        return Some(LOADER_SCAN_LEDGER_EXCEEDED);
    }
    if subject == "post-arm provider discovery" && reason == LOADER_ARM_LEDGER_FULL {
        return Some(LOADER_ARM_LEDGER_FULL);
    }
    None
}

/// Convert an untyped internal discovery loss into the finite public capture
/// record. Detailed paths, process identities, and error chains remain in
/// diagnostics; capture output keeps only the categorical loss needed to make
/// completeness honest.
pub fn capture_skipped_out(s: &Skipped) -> SkippedOut {
    // Fixed product-limit skips name their limit; the allowlist holds
    // exact pairs only, disjoint from function subjects and the gated null.
    if let Some(reason) = limit_skip_reason(&s.subject, &s.reason) {
        return SkippedOut {
            name: DISCOVERY_SUBJECT.into(),
            reason: reason.into(),
        };
    }
    // Run-tree gaps keep their subject and their finite reason; the
    // survivor count rides in `evidence.run_tree_handed_back`, never in
    // the reason. Anything else under the subject falls through to the
    // fail-closed generic below instead of breaking the closed vocabulary.
    if s.subject == RUN_TREE_SUBJECT
        && matches!(
            s.reason.as_str(),
            RUN_TREE_SURVIVORS | RUN_TREE_DEGRADED | RUN_TREE_MEMBERSHIP_UNKNOWN
        )
    {
        return SkippedOut {
            name: s.subject.clone(),
            reason: s.reason.clone(),
        };
    }
    // Learned-file gaps keep their subject and their seven finite
    // reasons; the counts ride in the `evidence.learned_*` keys.
    // Anything else under the subject falls through to the fail-closed
    // generic below instead of breaking the closed vocabulary.
    if s.subject == LEARNED_SKIP_SUBJECT
        && matches!(
            s.reason.as_str(),
            LEARNED_FIRST_RUN_REASON
                | LEARNED_OVERFLOW_REASON
                | LEARNED_CAP_REASON
                | LEARNED_UNAVAILABLE_REASON
                | LEARNED_REPLACED_DELETED_REASON
                | LEARNED_DISABLED_REASON
                | LEARNED_MOUNT_NAMESPACE_REASON
        )
    {
        return SkippedOut {
            name: s.subject.clone(),
            reason: s.reason.clone(),
        };
    }
    let function = kinds::function_id(&s.subject).is_some();
    // A gated null fact: the mislabel guard renamed an unlinked table's null
    // slot to `unknown`, and the nullness itself is still evidence worth
    // keeping — without claiming which function was null.
    let gated_null = s.subject == crate::plan::UNKNOWN_FUNCTION_NAME && s.reason == "null pointer";
    let reason = if s.subject == "live inventory pass" || s.subject == "live process admission" {
        // Dropped inventory passes and held-back processes (one producer
        // each) publish the generic discovery reason the schema and the
        // evidence checker accept, decided by subject before any
        // reason-text match: the error chain may quote another
        // category's text. The chain itself stays in diagnostics.
        DISCOVERY_UNAVAILABLE
    } else if function {
        if s.reason == "null pointer" {
            "null pointer"
        } else {
            ENTRY_UNAVAILABLE
        }
    } else if gated_null {
        "null pointer"
    } else if s.subject == "physical static probe gap"
        && s.reason
            == "an actual static detach opened a physical coverage interval whose final exact pairs or clock remain incomplete"
    {
        STATIC_GAP_INCOMPLETE
    } else if s.subject == "physical static probe gap"
        && s.reason
            == "static probes detached and final exact pairs reattached; the physical coverage interval remains in history"
    {
        STATIC_GAP_RECOVERED
    } else if s
        .reason
        .contains("cannot prove physical identity across overlay instances")
    {
        SHARED_OVERLAY_UNCERTAINTY
    } else if s.reason.contains("physical identity is ambiguous") {
        PHYSICAL_IDENTITY_AMBIGUITY
    } else if s.reason.contains("unsupported function-table version") {
        UNSUPPORTED_TABLE_VERSION
    } else if s
        .reason
        .contains("table header extends past the object's file-backed data")
        || s.reason
            .contains("no function table was found in its file-backed data")
    {
        TABLE_UNAVAILABLE
    } else if s.reason.starts_with("manifest object unavailable") {
        MANIFEST_OBJECT_UNAVAILABLE
    } else if s.reason.starts_with("prearm object unavailable") {
        PREARM_OBJECT_UNAVAILABLE
    } else if s.reason.starts_with("discovery transport unavailable")
        || (s.subject == "live discovery transport" && s.reason.contains("transport failure"))
    {
        DISCOVERY_TRANSPORT_UNAVAILABLE
    } else {
        DISCOVERY_UNAVAILABLE
    };
    SkippedOut {
        name: if function || gated_null {
            s.subject.clone()
        } else {
            DISCOVERY_SUBJECT.into()
        },
        reason: reason.into(),
    }
}

#[cfg(test)]
#[test]
fn physical_gap_category_requires_exact_internal_subject_and_description() {
    for description in [
        "an actual static detach opened a physical coverage interval whose final exact pairs or clock remain incomplete",
        "static probes detached and final exact pairs reattached; the physical coverage interval remains in history",
    ] {
        for (subject, reason) in [
            ("discovery subject".to_string(), description.to_string()),
            (
                "physical static probe gap PRIVATE_SUBJECT_SENTINEL".to_string(),
                description.to_string(),
            ),
            (
                "physical static probe gap".to_string(),
                format!("{description} PRIVATE_REASON_SENTINEL"),
            ),
            (
                "physical static probe gap".to_string(),
                description.to_uppercase(),
            ),
            (
                "physical static probe gap".to_string(),
                format!(" {description}"),
            ),
            (
                "physical static probe gap".to_string(),
                "static probes detached and exact pairs reattached".to_string(),
            ),
        ] {
            let projected = capture_skipped_out(&Skipped { subject, reason });
            assert_eq!(projected.name, "discovery subject");
            assert_eq!(projected.reason, "discovery unavailable");
            assert!(
                !serde_json::to_string(&projected)
                    .unwrap()
                    .contains("PRIVATE_")
            );
        }
    }
}

/// Run-tree gaps project under their own subject with their finite
/// reason intact; anything else under the subject fails closed to the
/// generic discovery skip instead of breaking the closed vocabulary.
#[cfg(test)]
#[test]
fn run_tree_gaps_project_under_their_own_subject_with_finite_reasons() {
    for reason in [
        RUN_TREE_SURVIVORS,
        RUN_TREE_DEGRADED,
        RUN_TREE_MEMBERSHIP_UNKNOWN,
    ] {
        let projected = capture_skipped_out(&Skipped {
            subject: "run process tree".into(),
            reason: reason.into(),
        });
        assert_eq!(projected.name, "run process tree");
        assert_eq!(projected.reason, reason);
        let json = serde_json::to_string(&projected).unwrap();
        assert!(!json.contains("discovery unavailable"), "{json}");
    }
    for reason in [
        "1 process-tree member was still present",
        "the run cgroup could not be created (permission denied)",
        "anything else under this subject",
    ] {
        let projected = capture_skipped_out(&Skipped {
            subject: "run process tree".into(),
            reason: reason.into(),
        });
        assert_eq!(projected.name, "discovery subject", "{reason}");
        assert_eq!(projected.reason, DISCOVERY_UNAVAILABLE, "{reason}");
        let json = serde_json::to_string(&projected).unwrap();
        assert!(!json.contains("permission denied"), "{json}");
    }
}

#[cfg(test)]
#[test]
fn never_stop_gaps_project_to_finite_reasons_without_paths() {
    for (subject, reason, expected) in [
        (
            "/opt/secret/provider.so",
            "manifest object unavailable: cannot open the file now (os error 13)",
            "manifest object unavailable",
        ),
        (
            "/opt/secret/prearm.so",
            "prearm object unavailable: the pre-arm file locator no longer resolves",
            "prearm object unavailable",
        ),
        (
            "live discovery transport",
            "discovery transport unavailable: dequeue failed after 2 records",
            "discovery transport unavailable",
        ),
    ] {
        let projected = capture_skipped_out(&Skipped {
            subject: subject.into(),
            reason: reason.into(),
        });
        assert_eq!(projected.name, "discovery subject");
        assert_eq!(projected.reason, expected);
        let json = serde_json::to_string(&projected).unwrap();
        assert!(!json.contains("/opt/secret"), "{json}");
        assert!(!json.contains("os error"), "{json}");
    }
}

/// Every `reason` enum the published v3 schema allows for a capture's
/// `evidence.skipped` entries.
#[cfg(test)]
fn schema_skip_reason_enums() -> Vec<Vec<String>> {
    fn walk(value: &serde_json::Value, out: &mut Vec<Vec<String>>) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(reasons) = map
                    .get("skipped")
                    .and_then(|skipped| skipped.pointer("/items/properties/reason/enum"))
                    .and_then(serde_json::Value::as_array)
                {
                    out.push(
                        reasons
                            .iter()
                            .filter_map(|reason| reason.as_str().map(str::to_owned))
                            .collect(),
                    );
                }
                map.values().for_each(|child| walk(child, out));
            }
            serde_json::Value::Array(items) => items.iter().for_each(|child| walk(child, out)),
            _ => {}
        }
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/schema/observed-profile-v3.schema.json"
    );
    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut out = Vec::new();
    walk(&schema, &mut out);
    out
}

/// Dropped inventory passes project to a reason the published schema
/// and the release evidence checker accept (`discovery unavailable`),
/// decided by the subject before any reason-text match, so an error
/// chain that happens to quote another category is not mislabelled.
#[cfg(test)]
#[test]
fn dropped_pass_gaps_project_to_a_schema_reason() {
    let enums = schema_skip_reason_enums();
    assert!(!enums.is_empty(), "the schema names its skip reasons");
    for reason in [
        "pass 2 dropped: test-forced apply failure",
        "pass 7 dropped: provider object 3 has no exact opened identity",
        "pass 4 dropped: physical identity is ambiguous for object 9",
        "pass 5 dropped: no function table was found in its file-backed data",
    ]
    .into_iter()
    .map(|reason| ("live inventory pass", reason))
    .chain([(
        "live process admission",
        "a process whose data broke the inventory pass is held back from admission and retried later",
    )]) {
        let (subject, reason) = reason;
        let projected = capture_skipped_out(&Skipped {
            subject: subject.into(),
            reason: reason.into(),
        });
        assert_eq!(projected.name, "discovery subject", "{reason}");
        assert_eq!(projected.reason, DISCOVERY_UNAVAILABLE, "{reason}");
        for allowed in &enums {
            assert!(
                allowed.contains(&projected.reason),
                "{:?} is not a schema skip reason",
                projected.reason
            );
        }
        let json = serde_json::to_string(&projected).unwrap();
        assert!(!json.contains("test-forced"), "{json}");
        assert!(!json.contains("object"), "{json}");
    }
}

impl Evidence {
    /// COMPLETE only when nothing was lost: every planned probe attached,
    /// nothing was skipped, no aliasing ambiguity, no call left in flight,
    /// every surface was fully walked with a successful acquisition, no
    /// vendor interfaces were left undecoded, (profile mode) the ring
    /// buffer neither dropped nor emitted a malformed record, no template
    /// was truncated, no mechanism's parameter decode failed on every
    /// single observed call, and no pinned provider object changed.
    ///
    /// Discovery gates it too, and three of those conditions are the ones a
    /// gap-counting verdict gets wrong on its own: a capture that discovered no
    /// module, one that discovered a module but planned no slot in it (every
    /// ptrace-refused capture: `ScanOutcome::Unavailable` still names the
    /// objects, with no tables), and one whose scan could not read a target at
    /// all. Each has nothing to fail — no attach was attempted, no entry was
    /// skipped — and would otherwise report COMPLETE having observed nothing.
    /// `scan_unavailable` is only transitively covered by `slots` for `--pid`;
    /// a cgroup with one readable and one unreadable process needs its own.
    pub fn verdict(&mut self) {
        self.verdict_with_selection(true);
    }

    pub(crate) fn verdict_with_selection(&mut self, include_selection: bool) {
        let classes = self.gap_classes(include_selection);
        let clean = classes.observation.causes.is_empty()
            && classes.attribution.causes.is_empty()
            && classes.semantics.causes.is_empty();
        self.completeness = if clean { "COMPLETE" } else { "PARTIAL" };
        self.verdict_detail =
            if !classes.observation.causes.is_empty() || !classes.semantics.causes.is_empty() {
                VERDICT_CONCRETE_GAP
            } else if !classes.attribution.causes.is_empty() {
                VERDICT_ATTRIBUTION_ONLY
            } else if self.drain_proven {
                VERDICT_CLEAN_PROVEN
            } else {
                VERDICT_CLEAN_BUT_UNPROVEN
            };
        self.gap_classes = classes;
    }

    /// Every verdict gate, each in exactly one class (review answer (a)).
    /// `completeness` is `COMPLETE` only when all three cause lists are
    /// empty, so the gate stays exactly as strict as the single conjunction
    /// it replaces — except that a NULL-pointer skip is no longer a gate (a
    /// NULL entry cannot be called, so nothing is missed through it) and
    /// slow-sink drops gate only when stdout carried the data.
    ///
    /// Classes are sticky exactly like their counters: the pipeline never
    /// resets one, so a later clean tick cannot subtract a loss.
    pub(crate) fn gap_classes(&self, include_selection: bool) -> GapClasses {
        fn cause(causes: &mut Vec<&'static str>, name: &'static str, hit: bool) {
            if hit {
                causes.push(name);
            }
        }
        let mut observation = Vec::new();
        let o = &mut observation;
        cause(o, "discovery", self.discovery.modules.is_empty());
        cause(o, "slots", self.slots == 0);
        cause(
            o,
            "scan_unavailable",
            self.discovery.scan_unavailable.is_some(),
        );
        cause(
            o,
            "modules_skipped",
            !self.discovery.modules_skipped.is_empty(),
        );
        cause(o, "attach_failures", !self.attach_failures.is_empty());
        cause(
            o,
            "skipped",
            self.skipped
                .iter()
                .any(|skip| skip.reason != NULL_POINTER_REASON),
        );
        // F-9: an entry without its return cannot yet be told apart from a
        // lost return, so open calls stay an observation gap for now.
        cause(o, "in_flight_at_end", self.in_flight_at_end > 0);
        cause(
            o,
            "surfaces",
            self.surfaces
                .iter()
                .any(|s| s.walk != "full" || s.acquisition != "ok"),
        );
        cause(o, "vendor_interfaces", self.vendor_interfaces > 0);
        cause(
            o,
            "interface_list",
            self.interface_list.starts_with("error:"),
        );
        cause(o, "event_loss", self.event_loss > 0);
        cause(o, "start_insert_failures", self.start_insert_failures > 0);
        cause(o, "unmatched_returns", self.unmatched_returns > 0);
        cause(o, "rv_update_failures", self.rv_update_failures > 0);
        cause(o, "cgroup_scope_failures", self.cgroup_scope_failures > 0);
        cause(o, "abi_refusals", self.abi_refusals > 0);
        cause(o, "malformed_records", self.malformed_records > 0);
        cause(o, "provider_changed", self.provider_changed);
        // D1: a poisoned owner or refused identity/root accounting halts or
        // thins capture in the kernel; it is loss, never attribution.
        cause(o, "kernel_control", !self.kernel_control.complete());
        // DR-K8S-1/2: outside the initial PID namespace the kernel's PIDs
        // cannot be resolved through this observer's /proc, so every live
        // discovery keyed on them is unproven.
        cause(
            o,
            "pid_namespace",
            !self.pid_namespace.observer_is_initial(),
        );
        // M1: an initial observer reading another namespace's /proc
        // (`nsenter -m` without `-p`) resolves kernel PIDs no better.
        cause(
            o,
            "proc_namespace_mismatch",
            !self.pid_namespace.proc_is_own(),
        );
        // Live discovery (design §5.7, §9.1, §9.2).
        cause(
            o,
            "unprotected_live_windows",
            self.unprotected_live_windows > 0,
        );
        cause(o, "discovery_ring_loss", self.discovery_ring_loss > 0);
        cause(
            o,
            "discovery_ring_unexplained",
            ring_unexplained(&self.ring_accounting.discovery) > 0,
        );
        cause(
            o,
            "events_ring_unexplained",
            ring_unexplained(&self.ring_accounting.events) > 0,
        );
        cause(
            o,
            "discovery_state_failures",
            self.discovery_state_failures > 0,
        );
        cause(
            o,
            "discovery_read_failures",
            self.discovery_read_failures > 0,
        );
        cause(o, "discovery_truncated", self.discovery_truncated > 0);
        cause(
            o,
            "task_uprobe_link_losses",
            self.task_uprobe_link_losses > 0,
        );
        cause(o, "pause_partial", self.pause_partial > 0);
        cause(o, "pause_unavailable", self.pause_unavailable > 0);
        cause(o, "loader_discovery", !self.loader_discovery.complete());
        cause(
            o,
            "scheduling.terminal_drain_truncated",
            self.scheduling.terminal_drain_truncated,
        );
        cause(
            o,
            "scheduling.sink_dropped_bytes",
            self.stdout_data_sink && self.scheduling.sink_dropped_bytes > 0,
        );
        cause(o, "trace_truncated", self.trace_truncated);
        if include_selection {
            cause(
                o,
                "interface_selection",
                !self.interface_selection.observation_complete(),
            );
            cause(o, "pid_descendant_gaps", self.pid_descendant_gaps > 0);
            cause(o, "multi_rebuild_gaps", self.multi_rebuild_gaps > 0);
        }

        let mut attribution = Vec::new();
        let a = &mut attribution;
        cause(
            a,
            "semantic_unverified_slots",
            self.semantic_unverified_slots > 0,
        );
        cause(a, "aliased", !self.aliased.is_empty());
        cause(a, "module_ambiguous", self.discovery.module_ambiguous > 0);
        cause(
            a,
            "module_unresolved_slots",
            self.module_unresolved_slots > 0,
        );
        cause(
            a,
            "unregistered_mechanisms",
            self.unregistered_mechanisms > 0,
        );
        cause(a, "unpublished_mechanisms", self.unpublished_mechanisms > 0);
        cause(a, "discovery_conflicts", self.discovery.conflicts > 0);
        cause(
            a,
            "discovery_uncorroborated",
            self.discovery.uncorroborated > 0,
        );
        if include_selection {
            cause(
                a,
                "interface_selection.selection_count_only",
                self.interface_selection.has_count_only_authority(),
            );
        }

        let mut semantics = Vec::new();
        let s = &mut semantics;
        cause(
            s,
            "semantic_capture_failures",
            self.semantic_capture_failures > 0,
        );
        cause(s, "template_tail_failures", self.template_tail_failures > 0);
        cause(
            s,
            "process_tracking_failures",
            self.process_tracking_failures > 0,
        );
        cause(
            s,
            "process_tracking_evictions",
            self.process_tracking_evictions > 0,
        );
        cause(s, "state_reconciliations", self.state_reconciliations > 0);
        cause(
            s,
            "session_cancel_ambiguities",
            self.session_cancel_ambiguities > 0,
        );
        cause(
            s,
            "session_cancel_unknown_flags",
            self.session_cancel_unknown_flags > 0,
        );
        cause(
            s,
            "operation_state_imports",
            self.operation_state_imports > 0,
        );
        cause(s, "auth_state_ambiguities", self.auth_state_ambiguities > 0);
        cause(s, "async_target_failures", self.async_target_failures > 0);
        cause(s, "async_orphans", self.async_orphans > 0);
        cause(s, "async_duplicates", self.async_duplicates > 0);
        cause(s, "async_evictions", self.async_evictions > 0);
        cause(s, "fork_state_ambiguities", self.fork_state_ambiguities > 0);
        cause(s, "semantic_state_drops", self.semantic_state_drops > 0);
        cause(s, "mechanism_id_overflow", self.mechanism_id_overflow > 0);
        cause(s, "semantic_history_drops", self.semantic_history_drops > 0);
        cause(s, "pending_at_end", self.pending_at_end > 0);
        cause(s, "templates_truncated", self.templates_truncated);
        cause(
            s,
            "shape_decode_total_failures",
            self.shape_decode_total_failures > 0,
        );

        let semantics_status = if !semantics.is_empty() {
            "degraded"
        } else if self.slots == 0 || self.semantic_unverified_slots >= self.slots {
            "not_applicable"
        } else {
            "complete"
        };
        GapClasses {
            observation: GapClass {
                status: if observation.is_empty() {
                    "exact"
                } else {
                    "lossy"
                },
                causes: observation,
            },
            attribution: GapClass {
                status: if attribution.is_empty() {
                    "attested"
                } else {
                    "withheld"
                },
                causes: attribution,
            },
            semantics: GapClass {
                status: semantics_status,
                causes: semantics,
            },
            open_calls: self.in_flight_at_end,
            settlement: if self.drain_proven {
                "proven"
            } else {
                "unproven"
            },
            stdout_data_sink: self.stdout_data_sink,
        }
    }

    /// Terminal settlement after the last accounting has landed (F-4):
    /// recompute from every final counter, then seal. Callers run it after
    /// the final scheduling snapshot, never before.
    pub(crate) fn settle_terminal(&mut self, include_selection: bool) {
        self.verdict_with_selection(include_selection);
        self.mark_terminal_drain_unproven();
    }

    /// Records the terminal stop gate's outcome and derives the
    /// `drain_proven` latch from it — the latch's only setter. Run before
    /// the terminal seal: a post-Q flag or an unproven Q leaves the latch
    /// false, so the seal keeps PARTIAL.
    pub(crate) fn apply_stop_quiescence(&mut self, stop: StopQuiescence) {
        self.stop_quiescence = stop;
        self.drain_proven = stop.proves_drain();
    }

    /// A detached perf link stops new invocations but does not wait for BPF
    /// callbacks already executing on another CPU. Only the stop gate's
    /// proven quiescence closes that window, and that proof reaches the
    /// verdict as the `drain_proven` latch, never as this function's
    /// unconditional assignment: [`Evidence::apply_stop_quiescence`] sets
    /// the latch, and only then may a terminal COMPLETE survive the seal.
    /// Without it every terminal document stays PARTIAL, and clean-but-
    /// unproven and concrete-gap runs say which they are (SYSPLAN residual
    /// F-02). PARTIAL is split, never deleted.
    pub fn mark_terminal_drain_unproven(&mut self) {
        if self.drain_proven {
            return;
        }
        // A gap already names its story (`concrete_gap` or
        // `attribution_only`); only a clean run needs the unproven one.
        if self.completeness == "COMPLETE" {
            self.verdict_detail = VERDICT_CLEAN_BUT_UNPROVEN;
        }
        self.completeness = "PARTIAL";
    }
}

fn label(r: &SlotReport) -> String {
    let names = crate::plan::presented_label(&r.names, &r.ordinals, r.file_offset);
    if r.aliased {
        format!("{names} (aliased)")
    } else {
        names
    }
}

/// The function table's provider cell: the owning module's file name,
/// `two providers` when two files claim the row, or `unknown` when no
/// file is proven. Escaped and truncated to the column width, so long
/// paths never break the table's alignment.
/// Whether a function row's attributed module is the witness-proven
/// pre-copy-up lower file's row: verbose text marks those rows so two
/// rows sharing one merge path stay distinguishable.
fn row_module_is_pre_copy_up(row: &SlotReport, modules: &[DiscoveredModule]) -> bool {
    row.module.is_some_and(|id| {
        modules
            .iter()
            .any(|module| module.id == id && module.layer == Some(ModuleLayer::PreCopyUp))
    })
}

fn provider_cell(row: &SlotReport, modules: &[DiscoveredModule]) -> String {
    const WIDTH: usize = 16;
    let cell = if row.module_ambiguous {
        "two providers".to_string()
    } else if let Some(id) = row.module {
        modules
            .iter()
            .find(|module| module.id == id)
            .map(|module| {
                module
                    .path
                    .rsplit('/')
                    .find(|part| !part.is_empty())
                    .unwrap_or(&module.path)
                    .to_string()
            })
            .unwrap_or_else(|| "unknown".to_string())
    } else {
        "unknown".to_string()
    };
    let escaped = escape_controls(&cell);
    if escaped.chars().count() <= WIDTH {
        escaped.into_owned()
    } else {
        let mut short: String = escaped.chars().take(WIDTH - 1).collect();
        short.push('…');
        short
    }
}

pub(crate) fn fmt_ns(ns: Option<u64>) -> String {
    match ns {
        None => "—".into(),
        Some(v) if v < 1_000 => format!("{v}ns"),
        Some(v) if v < 1_000_000 => format!("{:.1}µs", v as f64 / 1e3),
        Some(v) if v < 1_000_000_000 => format!("{:.1}ms", v as f64 / 1e6),
        Some(v) => format!("{:.2}s", v as f64 / 1e9),
    }
}

fn scope_label(scope: &str) -> &'static str {
    match scope {
        "pid" => "PID",
        "cgroup" => "cgroup",
        "system" => "system",
        _ => "selected",
    }
}

/// Named module gaps shown in the terminal summary: at most this many
/// `modules_skipped` lines plus an "and K more" line.
pub(crate) const MODULE_GAPS_SHOWN: usize = 5;

/// Attached providers named inside one closure-array gap line: the top
/// three by counted calls plus an "and K more" suffix.
const GAP_PROVIDERS_SHOWN: usize = 3;

/// Concise module gaps shown in default text: at most this many
/// `modules_skipped` lines plus an "and K more" line. Verbose shows
/// up to `MODULE_GAPS_SHOWN`; quiet shows none.
pub(crate) const CONCISE_MODULE_GAPS_SHOWN: usize = 2;

/// Display severity of one `modules_skipped` row, most
/// decision-relevant first: a whole-refused provider (no calls counted
/// at all) reads before a partially covered one (some endpoints still
/// watched), which reads before a refused proxy closure (its forwarded
/// calls are counted at the attached providers below it).
fn skipped_severity_rank(reason: &str) -> u8 {
    if crate::plan::is_partial_coverage(reason) {
        1
    } else if crate::plan::is_closure_array_refusal(reason) {
        2
    } else {
        0
    }
}

/// `modules_skipped` in display order: severity rank first, plan order
/// within a rank (the sort is stable, so ties keep their plan order).
fn ordered_module_gaps(skipped: &[SkippedOut]) -> Vec<&SkippedOut> {
    let mut ordered: Vec<&SkippedOut> = skipped.iter().collect();
    ordered.sort_by_key(|row| skipped_severity_rank(&row.reason));
    ordered
}

/// Display rows for the module gap lists: severity order, with a
/// same-path occurrence marker (`same-path file i of n`, in display
/// order) whenever a path repeats in the full list. Numbering counts
/// every row, so a shown subset still reads "1 of 3" beside
/// "and 1 more". Unique paths print bare. The capture records no
/// per-skipped file identity, so the marker distinguishes the rows,
/// not the underlying files.
fn display_module_gaps(skipped: &[SkippedOut]) -> Vec<(String, &SkippedOut)> {
    let ordered = ordered_module_gaps(skipped);
    let mut totals = std::collections::BTreeMap::<&str, usize>::new();
    for row in &ordered {
        *totals.entry(row.name.as_str()).or_insert(0) += 1;
    }
    let mut seen = std::collections::BTreeMap::<&str, usize>::new();
    ordered
        .into_iter()
        .map(|row| {
            let occurrence = seen.entry(row.name.as_str()).or_insert(0);
            *occurrence += 1;
            let total = totals.get(row.name.as_str()).copied().unwrap_or(1);
            let name = if total > 1 {
                format!("{} (same-path file {occurrence} of {total})", row.name)
            } else {
                row.name.clone()
            };
            (name, row)
        })
        .collect()
}

/// The concise twin of [`module_gap_lines`]: the most decision-relevant
/// one or two refused or partially covered providers with file, plain
/// status and the `--module` remedy, so a concise PARTIAL names its
/// target without requiring `-v`. Empty when nothing was refused.
fn concise_module_gap_lines(ev: &Evidence, reports: &[SlotReport]) -> String {
    let total = ev.discovery.modules_skipped.len();
    if total == 0 {
        return String::new();
    }
    let shown = total.min(CONCISE_MODULE_GAPS_SHOWN);
    let mut out = format!("Module gaps (showing {shown} of {total}):\n");
    for (name, skipped) in display_module_gaps(&ev.discovery.modules_skipped)
        .into_iter()
        .take(shown)
    {
        out.push_str(&format!(
            "  {}: {}\n",
            escape_controls(&name),
            gap_line_body(ev, reports, skipped)
        ));
    }
    if total > shown {
        out.push_str(&format!("  and {} more\n", total - shown));
    }
    out
}

/// The named module gaps behind a PARTIAL verdict: every refused or
/// partially covered module with its reason in plain words, what is still
/// counted, and the hint. Empty when nothing was refused. Paths and reasons
/// come from target-namespace labels, so every one is control-escaped.
fn module_gap_lines(ev: &Evidence, reports: &[SlotReport]) -> String {
    let total = ev.discovery.modules_skipped.len();
    if total == 0 {
        return String::new();
    }
    let shown = total.min(MODULE_GAPS_SHOWN);
    let mut out = format!("Module gaps (showing {shown} of {total}):\n");
    for (name, skipped) in display_module_gaps(&ev.discovery.modules_skipped)
        .into_iter()
        .take(shown)
    {
        out.push_str(&format!(
            "  {}: {}\n",
            escape_controls(&name),
            gap_line_body(ev, reports, skipped)
        ));
    }
    if total > shown {
        out.push_str(&format!("  and {} more\n", total - shown));
    }
    out
}

/// Files the operator excluded with `--exclude-module`, never silent: each
/// with its path, identity, and mapping process count, plus any inputs that
/// matched nothing. A declared choice, not a loss — calls into excluded
/// files were not observed, and the rest of the capture can still be exact.
fn excluded_lines(ev: &Evidence) -> String {
    let mut out = String::new();
    let total = ev.discovery.excluded_modules.len();
    if total > 0 {
        out.push_str(&format!("Excluded by you ({total} files):\n"));
        for excluded in &ev.discovery.excluded_modules {
            let processes = if excluded.processes == 1 {
                "1 process mapped it".to_string()
            } else {
                format!("{} processes mapped it", excluded.processes)
            };
            out.push_str(&format!(
                "  {}: excluded by you (device {} inode {}, {processes}); calls into this file were not observed\n",
                escape_controls(&excluded.path),
                excluded.dev,
                excluded.ino,
            ));
        }
    }
    if !ev.discovery.unmatched_excludes.is_empty() {
        out.push_str(&format!(
            "Unmatched exclusions ({}): {}\n",
            ev.discovery.unmatched_excludes.len(),
            ev.discovery
                .unmatched_excludes
                .iter()
                .map(|input| escape_controls(input))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    out
}

/// One named gap line's body: the status, the planner's reason, and the
/// hint. A forwarding (proxy closure) layer points at the attached providers
/// that count its forwarded calls and states plainly that calls the layer
/// answers itself are not counted (through a template that was not attached,
/// for a prefix); a refused provider points at `--module`
/// (unless the reason already carries that hint, as shared-scope refusals do).
fn gap_line_body(ev: &Evidence, reports: &[SlotReport], skipped: &SkippedOut) -> String {
    let status = if crate::plan::is_partial_coverage(&skipped.reason) {
        "partially covered"
    } else {
        "not attached"
    };
    let mut body = format!("{status} — {}", escape_controls(&skipped.reason));
    if crate::plan::is_closure_array_refusal(&skipped.reason) {
        body.push_str(&closure_forwarding_hint(ev, reports, &skipped.name));
        body.push_str(". Calls the forwarding layer answers itself are not counted.");
    } else if crate::plan::is_closure_array_prefix(&skipped.reason) {
        body.push_str(&closure_forwarding_hint(ev, reports, &skipped.name));
        body.push_str(
            ". Calls the forwarding layer answers itself through a template \
             that was not attached are not counted.",
        );
    } else if !skipped.reason.contains("--module") {
        body.push_str(&format!(
            "; capture it alone with --module {}",
            escape_controls(&skipped.name)
        ));
    }
    body
}

/// Where a refused proxy layer's forwarded calls are counted: the attached
/// providers with their completed calls, top three plus "and K more" — or,
/// when nothing below it counted, an explicit statement to that effect.
/// The skipped layer itself is never listed: a prefix-admitted layer's own
/// stub slots count under its own module id, and naming it as a provider
/// below itself would be circular. A refused layer holds no slots, so the
/// exclusion is a no-op there.
fn closure_forwarding_hint(ev: &Evidence, reports: &[SlotReport], skipped_name: &str) -> String {
    let skipped_id = ev
        .discovery
        .modules
        .iter()
        .find(|module| module.path == skipped_name)
        .map(|module| module.id);
    let mut calls = std::collections::BTreeMap::<ModuleId, u64>::new();
    for report in reports {
        if let Some(module) = report.module {
            if Some(module) == skipped_id {
                continue;
            }
            let total = calls
                .get(&module)
                .copied()
                .unwrap_or(0)
                .saturating_add(report.calls);
            calls.insert(module, total);
        }
    }
    let mut providers: Vec<(&str, u64)> = calls
        .iter()
        .filter(|(_, calls)| **calls > 0)
        .filter_map(|(id, calls)| {
            ev.discovery
                .modules
                .iter()
                .find(|module| module.id == *id)
                .map(|module| (module.path.as_str(), *calls))
        })
        .collect();
    providers.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    if providers.is_empty() {
        if ev.discovery.modules.is_empty() {
            return "; no provider below it was captured".into();
        }
        return "; no other attached provider counted calls; the layer's own calls stay in the totals"
            .into();
    }
    let mut list: Vec<String> = providers
        .iter()
        .take(GAP_PROVIDERS_SHOWN)
        .map(|(path, calls)| {
            format!(
                "{}: {calls} call{}",
                escape_controls(path),
                if *calls == 1 { "" } else { "s" }
            )
        })
        .collect();
    let more = providers.len().saturating_sub(GAP_PROVIDERS_SHOWN);
    if more > 0 {
        list.push(format!("and {more} more"));
    }
    format!(
        "; calls it forwards are counted at the attached provider files ({})",
        list.join(", ")
    )
}

/// Modules whose attached counts are forwarding-layer observations, never
/// logical calls: closure-array layers admitted beside watched providers.
/// Identified structurally — never by path, name or vendor — from the
/// deciding admission class first (this also catches whole-admitted
/// closures under counter/broad policies, which carry no gap) and from
/// the planner's closure gaps beside it. The split additionally needs any
/// watched, attributed, active non-layer row in the same capture — not
/// necessarily the provider below the layer, any active non-layer module
/// flips the gate — and no refused (whole, non-closure) provider gap: a
/// refused backend keeps the layer logical, since a disclosed overcount
/// beats hiding the application's calls. Without an active attributed row
/// (a lone remote client, a quiet provider, or backend rows observed only
/// through unattributed rows) the layer's calls are the only attributed
/// observation and stay logical, so the set is empty. Render rows carry no
/// caller in any scope, so the gate applies capture-wide. Modules the
/// operator declared with `--forwarding-module` join the same candidate
/// set under the same gate: a single-table shim (pkcs11-spy shape) splits
/// exactly like a closure array once declared, and never without it.
fn forwarding_module_ids(
    ev: &Evidence,
    reports: &[SlotReport],
) -> std::collections::BTreeSet<ModuleId> {
    let mut names = std::collections::BTreeSet::new();
    for skipped in &ev.discovery.modules_skipped {
        if crate::plan::is_closure_array_prefix(&skipped.reason)
            || crate::plan::is_closure_array_refusal(&skipped.reason)
        {
            names.insert(skipped.name.as_str());
        }
    }
    let mut candidates: std::collections::BTreeSet<ModuleId> = ev
        .discovery
        .modules
        .iter()
        .filter(|module| {
            module.admission_class == Some("closure_array") || names.contains(module.path.as_str())
        })
        .map(|module| module.id)
        .collect();
    for id in &ev.discovery.forwarding_declared {
        candidates.insert(*id);
    }
    let backend_refused = ev.discovery.modules_skipped.iter().any(|skipped| {
        !crate::plan::is_partial_coverage(&skipped.reason)
            && !crate::plan::is_closure_array_refusal(&skipped.reason)
    });
    if backend_refused {
        return std::collections::BTreeSet::new();
    }
    let provider_active = reports.iter().any(|row| {
        row.module.is_some_and(|id| !candidates.contains(&id))
            && (row.calls > 0 || row.errors > 0 || row.in_flight > 0)
    });
    if !provider_active {
        return std::collections::BTreeSet::new();
    }
    candidates
}

/// True when a slot row counts calls at a forwarding layer. Attributed
/// rows match by module id; unattributed rows (ambiguous or unresolved
/// ownership) match by the attach target's file identity, since the
/// counts are real even when the owner was not proven.
fn row_is_forwarding(
    report: &SlotReport,
    forwarding: &std::collections::BTreeSet<ModuleId>,
    modules: &[DiscoveredModule],
) -> bool {
    if forwarding.is_empty() {
        return false;
    }
    if let Some(id) = report.module {
        return forwarding.contains(&id);
    }
    if let Some(target) = &report.target_object {
        return modules.iter().any(|module| {
            forwarding.contains(&module.id) && module.dev == target.dev && module.ino == target.ino
        });
    }
    false
}

/// Advisory hint when two attached non-layer modules show coincident call
/// vectors: every per-function count of one is exactly contained in the
/// other (the undeclared-shim shape — every shim call re-observed at the
/// backend). The observer never splits on coincidence (a real provider
/// pair can coincide); it names both modules and the `--forwarding-module`
/// remedy instead. Text-only, like the `--manifest` hints; JSON stays
/// complete on the per-layer facts and this changes no count. The
/// contained side needs at least three calls across at least two
/// functions, so a lone shared probe (init/finalize on two providers)
/// stays silent. Declared and closure layers never suggest.
fn forwarding_suggestion(
    reports: &[SlotReport],
    modules: &[DiscoveredModule],
    forwarding: &std::collections::BTreeSet<ModuleId>,
) -> Option<String> {
    use std::collections::BTreeMap;
    let mut vectors: BTreeMap<ModuleId, BTreeMap<String, u64>> = BTreeMap::new();
    for row in reports {
        let Some(id) = row.module else {
            continue;
        };
        if forwarding.contains(&id) || row.calls == 0 {
            continue;
        }
        let mut names = row.names.clone();
        names.sort();
        *vectors
            .entry(id)
            .or_default()
            .entry(names.join(" + "))
            .or_default() += row.calls;
    }
    let ids: Vec<ModuleId> = vectors.keys().copied().collect();
    let mut pairs: Vec<(ModuleId, ModuleId)> = Vec::new();
    for (i, left) in ids.iter().enumerate() {
        for right in &ids[i + 1..] {
            let inner = &vectors[left];
            let outer = &vectors[right];
            let contained = |inner: &BTreeMap<String, u64>, outer: &BTreeMap<String, u64>| {
                inner.len() >= 2
                    && inner.values().sum::<u64>() >= 3
                    && inner
                        .iter()
                        .all(|(name, calls)| outer.get(name).unwrap_or(&0) >= calls)
            };
            if contained(inner, outer) || contained(outer, inner) {
                pairs.push((*left, *right));
            }
        }
    }
    let (first, second) = *pairs.first()?;
    let path = |id: ModuleId| {
        modules
            .iter()
            .find(|module| module.id == id)
            .map(|module| module.path.as_str())
            .unwrap_or("?")
    };
    let mut hint = format!(
        "Possible forwarding: calls at {} coincide with calls at {}; if one forwards to the other, declare it with --forwarding-module <path-or-name> so headline totals count each application call once.",
        path(first),
        path(second)
    );
    if pairs.len() > 1 {
        hint.push_str(&format!(
            " ({} more module pair{} coincide)",
            pairs.len() - 1,
            if pairs.len() == 2 { "" } else { "s" }
        ));
    }
    Some(hint)
}

/// Declared-but-unmatched forwarding inputs, echoed whenever present: a
/// `--forwarding-module` input that matched no mapped file must never
/// silently do nothing. The JSON twin is the `unmatched_forwarding` key;
/// never a coverage gap, so it never forces `PARTIAL`.
fn unmatched_forwarding_lines(ev: &Evidence) -> String {
    if ev.discovery.unmatched_forwarding.is_empty() {
        return String::new();
    }
    format!(
        "Unmatched forwarding declarations ({}): {}\n",
        ev.discovery.unmatched_forwarding.len(),
        ev.discovery.unmatched_forwarding.join(", ")
    )
}

/// Ownership-gap rows behind the headline: logical rows only, since
/// the gap lines explain headline attribution. Forwarding rows are
/// stated in the forwarding line, never summed here.
fn owner_gap_total(
    reports: &[SlotReport],
    forwarding: &std::collections::BTreeSet<ModuleId>,
    modules: &[DiscoveredModule],
    gap: fn(&SlotReport) -> bool,
) -> (bool, u64) {
    let mut any = false;
    let mut total = 0u64;
    for row in reports {
        if gap(row) && !row_is_forwarding(row, forwarding, modules) {
            any = true;
            total = total.saturating_add(row.calls);
        }
    }
    (any, total)
}

/// Per-layer completed/error/in-flight totals over slot rows: logical
/// (provider) calls first, forwarding-layer calls second. One logical
/// call observed at both layers counts once, in the logical total.
fn layer_call_totals(
    reports: &[SlotReport],
    forwarding: &std::collections::BTreeSet<ModuleId>,
    modules: &[DiscoveredModule],
) -> [(u64, u64, u64); 2] {
    let mut totals = [(0u64, 0u64, 0u64); 2];
    for report in reports {
        let slot = if row_is_forwarding(report, forwarding, modules) {
            &mut totals[1]
        } else {
            &mut totals[0]
        };
        slot.0 = slot.0.saturating_add(report.calls);
        slot.1 = slot.1.saturating_add(report.errors);
        slot.2 = slot.2.saturating_add(report.in_flight);
    }
    totals
}

/// True when at least one mapped provider has no manifest source at all.
fn has_unattested_provider(ev: &Evidence) -> bool {
    !ev.discovery.modules.is_empty()
        && ev
            .discovery
            .modules
            .iter()
            .any(|module| !module.sources.contains(&"manifest"))
}

/// Plain-words companion to the `semantic_unverified_slots` verdict
/// fragment: how many mapped providers have no manifest at all, by name.
/// Prints only when unverified slots remain and at least one mapped
/// provider lacks any manifest source; partial manifest coverage keeps
/// the machine fragment alone. Human text only; the JSON is unchanged.
/// Concise states the fact; the `--manifest` remedy lives once in the
/// coverage line, with verbose repeating it here.
fn unattributed_provider_line(ev: &Evidence, verbose: bool) -> String {
    if ev.semantic_unverified_slots == 0 || !has_unattested_provider(ev) {
        return String::new();
    }
    let modules = &ev.discovery.modules;
    let mut unattested: Vec<String> = modules
        .iter()
        .filter(|module| !module.sources.contains(&"manifest"))
        .map(|module| {
            std::path::Path::new(&module.path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| module.path.clone())
        })
        .collect();
    if unattested.is_empty() {
        return String::new();
    }
    unattested.sort();
    let shown: Vec<&str> = unattested.iter().take(3).map(String::as_str).collect();
    let names = if unattested.len() > 3 {
        format!("{}, and {} more", shown.join(", "), unattested.len() - 3)
    } else {
        shown.join(", ")
    };
    let remedy = if verbose {
        " — rerun with --manifest for provider files with unverified tables (see Coverage) to confirm their layouts for mechanism decoding"
    } else {
        ""
    };
    format!(
        "Attribution: {} of {} mapped provider file{} {} no manifest ({}); counts are exact, \
         names are unconfirmed{remedy}.\n",
        unattested.len(),
        modules.len(),
        if modules.len() == 1 { "" } else { "s" },
        if unattested.len() == 1 { "has" } else { "have" },
        escape_controls(&names),
    )
}

/// Plain-words per-layer split for forwarding-layer activity: each
/// forwarding layer with its own completed calls, stated separately from
/// — never summed into — the logical headline above it. Empty when no
/// forwarding layer recorded activity, so single-layer captures read
/// exactly as before.
fn forwarding_layer_lines(
    reports: &[SlotReport],
    ev: &Evidence,
    forwarding: &std::collections::BTreeSet<ModuleId>,
    (fwd_calls, fwd_errors, fwd_open): (u64, u64, u64),
) -> String {
    if fwd_calls == 0 && fwd_errors == 0 && fwd_open == 0 {
        return String::new();
    }
    let mut per_layer = std::collections::BTreeMap::<ModuleId, (u64, u64, u64)>::new();
    for report in reports {
        if !row_is_forwarding(report, forwarding, &ev.discovery.modules) {
            continue;
        }
        // Attributed rows group under their module; unattributed rows
        // group under the forwarding layer their attach target
        // identifies (the same file-identity match as
        // `row_is_forwarding`), so the per-layer line names the
        // matched layer.
        let key = report
            .module
            .or_else(|| {
                report.target_object.as_ref().and_then(|target| {
                    ev.discovery
                        .modules
                        .iter()
                        .filter(|module| {
                            forwarding.contains(&module.id)
                                && module.dev == target.dev
                                && module.ino == target.ino
                        })
                        .map(|module| module.id)
                        .next()
                })
            })
            .unwrap_or(ModuleId(u32::MAX));
        let slot = per_layer.entry(key).or_insert((0, 0, 0));
        slot.0 = slot.0.saturating_add(report.calls);
        slot.1 = slot.1.saturating_add(report.errors);
        slot.2 = slot.2.saturating_add(report.in_flight);
    }
    let mut layers: Vec<String> = per_layer
        .iter()
        .filter(|(_, (calls, errors, open))| *calls > 0 || *errors > 0 || *open > 0)
        .map(|(id, (calls, errors, open))| {
            let path = ev
                .discovery
                .modules
                .iter()
                .find(|module| module.id == *id)
                .map(|module| escape_controls(&module.path).into_owned())
                .unwrap_or_else(|| "an unattributed forwarding target".into());
            let mut detail = format!("{path} recorded {calls} completed forwarding-layer calls");
            if *errors > 0 {
                detail.push_str(&format!(", {errors} returned errors"));
            }
            if *open > 0 {
                detail.push_str(&format!(", {open} entries without an observed return"));
            }
            detail
        })
        .collect();
    layers.sort();
    if layers.is_empty() {
        return String::new();
    }
    format!(
        "Forwarding layers counted separately (not in the totals above): {}.\n\
         The totals above count calls at the attached providers; \
         calls a layer answered itself or forwarded to a provider that was not attached, \
         including its errors, appear only here, \
         and a layer call that reaches several providers counts at each.\n",
        layers.join("; ")
    )
}

/// Human context from aggregate map rows and the existing evidence verdict.
/// Scope is a kind, never a target PID, path or application identity.
/// Renders at the run-scoped verbosity; see [`scope_summary_with_verbosity`].
pub fn scope_summary(scope: &str, reports: &[SlotReport], ev: &Evidence) -> String {
    scope_summary_with_verbosity(scope, reports, ev, crate::cli::text_verbosity())
}

/// [`scope_summary`] at an explicit verbosity: the tests' race-free
/// handle. Concise keeps totals, plain coverage reasons, the
/// attribution hint and the first module gaps; verbose adds every
/// module gap and owner-gap lines; quiet keeps totals and coverage
/// only.
pub fn scope_summary_with_verbosity(
    scope: &str,
    reports: &[SlotReport],
    ev: &Evidence,
    verbosity: crate::cli::TextVerbosity,
) -> String {
    use crate::cli::TextVerbosity;
    let verbose = verbosity == TextVerbosity::Verbose;
    // Headline totals count logical calls once: a call observed at both
    // a forwarding layer and the provider it forwards into counts in the
    // provider (logical) total only. Forwarding-layer calls are stated
    // separately below, never summed in.
    let forwarding = forwarding_module_ids(ev, reports);
    let [(calls, errors, open), (fwd_calls, fwd_errors, fwd_open)] =
        layer_call_totals(reports, &forwarding, &ev.discovery.modules);
    let mut text = String::new();
    if verbosity != TextVerbosity::Quiet {
        if scope != "pid" {
            text.push_str("Aggregate across the selected scope; counts are not per application.\n");
        }
        if calls == 0 && fwd_calls == 0 {
            // One coverage statement: counts-complete windows (COMPLETE
            // or attribution-only PARTIAL) read as a quiet result here,
            // with the coverage line below carrying the verdict. Only
            // observation/semantics gaps claim "coverage incomplete".
            let counts_complete =
                ev.completeness == "COMPLETE" || ev.verdict_detail == VERDICT_ATTRIBUTION_ONLY;
            text.push_str(if counts_complete {
                "No completed calls observed during this window.\n"
            } else {
                "No completed calls observed; coverage incomplete.\n"
            });
            // A quiet window over mapped providers is usually correct —
            // the target simply made no PKCS#11 calls — but it reads as a
            // failure. Say when providers are typically called and name
            // the wider target a narrower scope should try. Only when
            // coverage is COMPLETE: under PARTIAL the assertion would
            // overclaim calls explicitly not counted.
            if ev.completeness == "COMPLETE" && !ev.discovery.modules.is_empty() {
                text.push_str(
                    "No PKCS#11 calls were made in this window; providers are often called only at startup. ",
                );
                if scope == "system" {
                    text.push_str("Attach before the targets start.\n");
                } else {
                    text.push_str(
                        "Attach before the target starts, or use --system when a related process may call them.\n",
                    );
                }
            }
        }
    }
    text.push_str(&totals_line(calls, errors, open));
    text.push('\n');
    text.push_str(&forwarding_layer_lines(
        reports,
        ev,
        &forwarding,
        (fwd_calls, fwd_errors, fwd_open),
    ));
    text.push_str(&coverage_line(ev, verbose));
    text.push('\n');
    if verbosity != TextVerbosity::Quiet {
        text.push_str(&unattributed_provider_line(ev, verbose));
        if let Some(hint) = forwarding_suggestion(reports, &ev.discovery.modules, &forwarding) {
            text.push_str(&hint);
            text.push('\n');
        }
    }
    if verbose {
        text.push_str(&module_gap_lines(ev, reports));
    } else if verbosity == TextVerbosity::Concise {
        text.push_str(&concise_module_gap_lines(ev, reports));
    }
    text.push_str(&excluded_lines(ev));
    text.push_str(&unmatched_forwarding_lines(ev));
    if verbose {
        for ((has_owner_gap, total), description) in [
            (
                owner_gap_total(reports, &forwarding, &ev.discovery.modules, |row| {
                    row.module_ambiguous
                }),
                "ambiguous",
            ),
            (
                owner_gap_total(reports, &forwarding, &ev.discovery.modules, |row| {
                    row.module_unresolved
                }),
                "unresolved",
            ),
        ] {
            if has_owner_gap {
                text.push_str(&format!(
                    "{total} completed calls have {description} module ownership.\n"
                ));
            }
        }
    }
    text
}

/// Concise text shows at most this many failure reasons per function;
/// verbose lists every distinct code. Shared with the trace tail's
/// per-caller roll-up, so both views bound concise reasons the same way.
pub(crate) const CONCISE_REASONS_PER_FUNCTION: usize = 3;

/// One `TABLE-NAME: reason xN, …` line per function row with errors, in
/// table order. Verbose lists every distinct failure code; concise
/// keeps the top three by count plus an `and N more` tail. Success
/// (`CKR_OK`) and pending returns are never reasons. Names come from
/// the shared `CKR_*` lookup; unregistered (vendor) codes render as
/// verbatim hex, never guessed. A row with errors but no error
/// breakdown in `rv_counts` — the return-value table read failed —
/// names that gap instead of stopping the view.
fn error_reason_lines(rendered: &[(String, &SlotReport)], verbose: bool) -> Vec<String> {
    let mut lines = Vec::new();
    for (name, r) in rendered {
        if r.errors == 0 {
            continue;
        }
        let mut reasons: Vec<(u64, u64)> = r
            .rv_counts
            .iter()
            .filter_map(|(&rv, &count)| {
                (count > 0 && rv != pkcs11_types::CkRv::OK.0 && rv != pkcs11_types::CkRv::PENDING.0)
                    .then_some((rv, count))
            })
            .collect();
        // Count descending, then code ascending: the concise top-N is
        // deterministic, and ties read in numeric order.
        reasons.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        if reasons.is_empty() {
            let noun = if r.errors == 1 { "error" } else { "errors" };
            lines.push(format!(
                "{name}: {} {noun} (return-code breakdown unavailable)",
                r.errors
            ));
            continue;
        }
        let shown = if verbose {
            reasons.len()
        } else {
            reasons.len().min(CONCISE_REASONS_PER_FUNCTION)
        };
        let mut line = format!("{name}: ");
        for (i, &(rv, count)) in reasons[..shown].iter().enumerate() {
            if i > 0 {
                line.push_str(", ");
            }
            let reason = crate::semantics_edge::rv_name(rv).unwrap_or_else(|| format!("0x{rv:x}"));
            line.push_str(&format!("{reason} x{count}"));
        }
        if shown < reasons.len() {
            line.push_str(&format!(", and {} more", reasons.len() - shown));
        }
        lines.push(line);
    }
    lines
}

/// One refreshing screen for consumers without a retained scope kind.
/// Rows with no activity are omitted; the evidence line renders under
/// `-v` only. Mechanism rows are never shown here; `live_scoped`
/// renders them.
pub fn live(
    reports: &[SlotReport],
    ev: &Evidence,
    elapsed: Duration,
    module: &str,
    mode: &str,
    policy: CapturePolicy,
) -> String {
    live_scoped(
        reports,
        ev,
        elapsed,
        module,
        mode,
        policy,
        "selected",
        &BTreeMap::new(),
    )
}

/// Derive the extra observation gap from the protected snapshot. This is
/// reapplied after terminal verdict recomputation, without changing the
/// existing Evidence layout or the legacy cause/class accounting.
pub(crate) fn apply_counter_snapshot(
    ev: &mut Evidence,
    snapshot: &crate::metrics::CaptureSnapshot,
) {
    if snapshot.has_counter_gap() {
        let observation = &mut ev.gap_classes.observation;
        if !observation.causes.contains(&"counter_collection") {
            observation.causes.push("counter_collection");
        }
        observation.status = "lossy";
        ev.completeness = "PARTIAL";
        ev.verdict_detail = VERDICT_CONCRETE_GAP;
    }
}

/// Derive the legacy read gap from the protected snapshot, mirroring the
/// counter gap above. A legacy slot or evidence read failure never blanks
/// the capture; it reports zeros as unknown with this named gap.
pub(crate) fn apply_legacy_gaps(ev: &mut Evidence, snapshot: &crate::metrics::CaptureSnapshot) {
    if snapshot.has_legacy_gap() {
        let observation = &mut ev.gap_classes.observation;
        if !observation.causes.contains(&"legacy_collection") {
            observation.causes.push("legacy_collection");
        }
        observation.status = "lossy";
        ev.completeness = "PARTIAL";
        ev.verdict_detail = VERDICT_CONCRETE_GAP;
    }
}

/// Derive the zero-snapshot terminal gap from the degraded snapshot,
/// mirroring the collection gap above. A terminal read failure with no
/// snapshot behind it still seals the report: no aggregate rows, the
/// failed read's finite name, PARTIAL with a concrete gap.
pub(crate) fn apply_snapshot_failure(
    ev: &mut Evidence,
    snapshot: &crate::metrics::CaptureSnapshot,
) {
    if let Some(failure) = snapshot.snapshot_failure() {
        ev.snapshot_failure = Some(failure);
        let observation = &mut ev.gap_classes.observation;
        if !observation.causes.contains(&"snapshot_failure") {
            observation.causes.push("snapshot_failure");
        }
        observation.status = "lossy";
        ev.completeness = "PARTIAL";
        ev.verdict_detail = VERDICT_CONCRETE_GAP;
    }
}

/// Snapshot frame plus the pid-scope caller line, so profile stdout
/// names the caller program. `None` caller renders no line. Carries
/// capture-wide session/login counts; see
/// [`live_scoped_with_verbosity_and_sessions`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn live_snapshot_scoped(
    snapshot: &crate::metrics::CaptureSnapshot,
    ev: &Evidence,
    elapsed: Duration,
    module: &str,
    mode: &str,
    policy: CapturePolicy,
    scope: &str,
    mechanisms: &BTreeMap<u64, MechStat>,
    caller: Option<&CaptureCaller>,
    sessions: &crate::semantics::SessionStats,
    logins: &BTreeMap<u32, u64>,
) -> String {
    let mut frame = live_scoped_with_caller(
        snapshot.reports(),
        ev,
        elapsed,
        module,
        mode,
        policy,
        scope,
        mechanisms,
        caller,
        crate::cli::text_verbosity(),
        sessions,
        logins,
    );
    if let Some(summary) = snapshot.counter_summary() {
        // Concise frames end with the `-v` hint: the counter block reads
        // before it so the hint stays the frame's last line (and a
        // `--select-endpoint` report line inserted before the hint lands
        // after this block). Verbose and quiet frames carry no trailing
        // hint, so they keep the plain append.
        let hint = format!("{}\n", crate::cli::VERBOSE_HINT);
        if let Some(body) = frame.strip_suffix(hint.as_str()) {
            frame = format!("{body}{summary}{hint}");
        } else {
            frame.push_str(&summary);
        }
    }
    frame
}

/// The capture renderer receives only the validated scope kind.
/// `mechanisms` is the same per-id map the JSON `mechanisms[]` carries
/// (`State::mechanisms`): a nonempty map renders a compact name/calls/errors
/// table under the function table, while an empty map with observed calls
/// renders one plain line saying why no mechanisms are named. No parameters
/// are shown, so no decoder policy applies here.
#[allow(clippy::too_many_arguments)]
pub fn live_scoped(
    reports: &[SlotReport],
    ev: &Evidence,
    elapsed: Duration,
    module: &str,
    mode: &str,
    policy: CapturePolicy,
    scope: &str,
    mechanisms: &BTreeMap<u64, MechStat>,
) -> String {
    live_scoped_with_verbosity(
        reports,
        ev,
        elapsed,
        module,
        mode,
        policy,
        scope,
        mechanisms,
        crate::cli::text_verbosity(),
    )
}

/// The pid-scope caller line for profile stdout, without the PID number
/// (allowlist v1: the pid is a stderr diagnostic only). `None` for
/// aggregate scopes, which name no single caller. The exe is
/// target-controlled, so it is control-escaped at this boundary, like
/// the stderr target line.
pub fn caller_text_line(caller: Option<&CaptureCaller>) -> Option<String> {
    let caller = caller?;
    match (&caller.exe, caller.exe_unknown_reason) {
        (Some(exe), _) => Some(format!("caller: {}", escape_controls(exe))),
        (None, Some(reason)) => Some(format!("caller unknown: {reason}")),
        (None, None) => Some("caller unknown: caller unresolved".to_string()),
    }
}

/// [`live_scoped_with_verbosity_and_sessions`] plus the pid-scope caller
/// line after the header, so profile stdout names the caller program
/// like JSON `capture.caller` does. `None` caller renders no line.
#[allow(clippy::too_many_arguments)]
pub fn live_scoped_with_caller(
    reports: &[SlotReport],
    ev: &Evidence,
    elapsed: Duration,
    module: &str,
    mode: &str,
    policy: CapturePolicy,
    scope: &str,
    mechanisms: &BTreeMap<u64, MechStat>,
    caller: Option<&CaptureCaller>,
    verbosity: crate::cli::TextVerbosity,
    sessions: &crate::semantics::SessionStats,
    logins: &BTreeMap<u32, u64>,
) -> String {
    let frame = live_scoped_with_verbosity_and_sessions(
        reports, ev, elapsed, module, mode, policy, scope, mechanisms, verbosity, sessions, logins,
    );
    let Some(line) = caller_text_line(caller) else {
        return frame;
    };
    // After the header so the header stays first and the caller answers
    // the demo question next, at every verbosity (quiet included).
    if let Some((header, rest)) = frame.split_once('\n') {
        format!("{header}\n{line}\n{rest}")
    } else {
        format!("{frame}{line}\n")
    }
}

/// One plain line naming a refused pause and why. `None` unless a
/// lifecycle failure ended the run; an unrecognized reason still
/// surfaces verbatim rather than vanishing.
fn pause_refusal_line(ev: &Evidence) -> Option<String> {
    ev.pause_refused.map(|reason| match reason {
        "interrupted" => "pause refused: interrupted by operator stop".to_string(),
        "refused" => "pause refused: protection could not be completed".to_string(),
        other => format!("pause refused: {other}"),
    })
}

/// [`live_scoped`] at an explicit verbosity: the tests' race-free
/// handle. Concise keeps the header, totals, plain coverage reasons
/// and the function/mechanism tables plus the `-v` hint; verbose is
/// the full frame with Evidence and machine reason names; quiet keeps
/// the header, totals and coverage only. The function table renders
/// only when some row has activity; the header carries the privacy
/// mode under verbose only. Sessions/logins render empty here; the
/// profile lane passes real counts through
/// [`live_scoped_with_verbosity_and_sessions`].
#[allow(clippy::too_many_arguments)]
pub fn live_scoped_with_verbosity(
    reports: &[SlotReport],
    ev: &Evidence,
    elapsed: Duration,
    module: &str,
    mode: &str,
    policy: CapturePolicy,
    scope: &str,
    mechanisms: &BTreeMap<u64, MechStat>,
    verbosity: crate::cli::TextVerbosity,
) -> String {
    live_scoped_with_verbosity_and_sessions(
        reports,
        ev,
        elapsed,
        module,
        mode,
        policy,
        scope,
        mechanisms,
        verbosity,
        &crate::semantics::SessionStats::default(),
        &BTreeMap::new(),
    )
}

/// The `C_Login` user-type number as a plain word: PKCS#11
/// CKU_SO/CKU_USER/CKU_CONTEXT_SPECIFIC. A vendor-extended type
/// renders numerically, never guessed.
fn login_user_type_name(user_type: u32) -> String {
    match user_type {
        0 => "SO".to_string(),
        1 => "user".to_string(),
        2 => "context-specific".to_string(),
        other => format!("type {other}"),
    }
}

/// The capture-wide sessions/logins line for the profile text, from
/// the reducer state the JSON `sessions`/`logins` already carry — no
/// new capture, no schema change. `None` when no session was opened
/// or inherited and no login was seen. The counts are event-derived;
/// under a PARTIAL verdict the coverage line governs them, which is
/// why this rides beside the mechanism section rather than the
/// header totals. Verbose adds the inherited/closed accounting.
fn session_login_line(
    sessions: &crate::semantics::SessionStats,
    logins: &BTreeMap<u32, u64>,
    verbose: bool,
) -> Option<String> {
    if sessions.opened == 0 && sessions.inherited == 0 && logins.is_empty() {
        return None;
    }
    let balance = sessions
        .opened
        .saturating_add(sessions.inherited)
        .saturating_sub(sessions.closed);
    let mut line = if sessions.opened > 0 {
        let mut head = format!("sessions: {} opened", sessions.opened);
        if verbose && sessions.async_opened > 0 {
            head.push_str(&format!(" ({} async)", sessions.async_opened));
        }
        if verbose {
            head.push_str(&format!(
                ", {} inherited, {} closed",
                sessions.inherited, sessions.closed
            ));
        }
        head.push_str(&format!(
            ", peak {} at once, {balance} still open",
            sessions.peak_concurrent
        ));
        head
    } else if sessions.inherited > 0 {
        let mut head = format!("sessions: {} inherited", sessions.inherited);
        if verbose {
            head.push_str(&format!(", {} closed", sessions.closed));
        }
        head.push_str(&format!(
            ", peak {} at once, {balance} still open",
            sessions.peak_concurrent
        ));
        head
    } else {
        "sessions: none opened".to_string()
    };
    if !logins.is_empty() {
        let parts: Vec<String> = logins
            .iter()
            .map(|(user_type, n)| format!("{} ×{n}", login_user_type_name(*user_type)))
            .collect();
        line.push_str(&format!("; logins: {}", parts.join(", ")));
    }
    Some(line)
}

/// [`live_scoped_with_verbosity`] with capture-wide session/login
/// counts for the profile text. See [`session_login_line`].
#[allow(clippy::too_many_arguments)]
pub fn live_scoped_with_verbosity_and_sessions(
    reports: &[SlotReport],
    ev: &Evidence,
    elapsed: Duration,
    module: &str,
    mode: &str,
    policy: CapturePolicy,
    scope: &str,
    mechanisms: &BTreeMap<u64, MechStat>,
    verbosity: crate::cli::TextVerbosity,
    sessions: &crate::semantics::SessionStats,
    logins: &BTreeMap<u32, u64>,
) -> String {
    let mut s = String::new();
    // Concise states the scope once, in the header; the privacy mode
    // is verbose detail.
    let privacy = if verbosity == crate::cli::TextVerbosity::Verbose {
        format!(" — privacy={}", policy.privacy_mode())
    } else {
        String::new()
    };
    s.push_str(&format!(
        "p11scope — {} scope — up {:02}:{:02}:{:02} — mode {}{} — {}\n",
        scope_label(scope),
        elapsed.as_secs() / 3600,
        (elapsed.as_secs() % 3600) / 60,
        elapsed.as_secs() % 60,
        escape_controls(mode),
        privacy,
        escape_controls(module),
    ));
    s.push_str(&scope_summary_with_verbosity(scope, reports, ev, verbosity));
    if let Some(refusal) = pause_refusal_line(ev) {
        s.push_str(&refusal);
        s.push('\n');
    }
    if verbosity == crate::cli::TextVerbosity::Quiet {
        return s;
    }
    let mut rows: Vec<&SlotReport> = reports
        .iter()
        .filter(|r| r.calls > 0 || r.in_flight > 0)
        .collect();
    rows.sort_by(|a, b| b.calls.cmp(&a.calls).then(a.names.cmp(&b.names)));
    // No table at all when nothing was called — neither legends nor
    // header. One latency legend otherwise, above the table.
    if !rows.is_empty() {
        s.push_str("CALLS = completed calls; ERR = returned errors; IN-FLIGHT = entries without an observed return.\n");
        s.push_str("Latency units: ns/us/ms/s (us displayed as µs); ~ = log2-bucket approximation, lower bound.\n");
        let forwarding = forwarding_module_ids(ev, reports);
        // The name field fits the longest rendered name in this frame (min 28),
        // so marked rows keep the columns aligned without fixed padding.
        let mut rendered: Vec<(String, &SlotReport)> = Vec::with_capacity(rows.len());
        for r in rows {
            let mut name = label(r);
            if let Some(init) = initialization_out(&r.names, &r.rv_counts) {
                name.push_str(init.text_suffix());
            }
            if row_is_forwarding(r, &forwarding, &ev.discovery.modules) {
                name.push_str(" (forwarding layer)");
            }
            if verbosity == crate::cli::TextVerbosity::Verbose
                && row_module_is_pre_copy_up(r, &ev.discovery.modules)
            {
                name.push_str(" (file before copy-up)");
            }
            rendered.push((escape_controls(&name).into_owned(), r));
        }
        let width = rendered
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(0)
            .max(28);
        s.push_str(&format!(
            "{:<w$} {:<16} {:>8} {:>6} {:>9} {:>9} {:>9} {:>9}\n",
            "FUNCTION",
            "PROVIDER",
            "CALLS",
            "ERR",
            "p50~",
            "p95~",
            "p99~",
            "IN-FLIGHT",
            w = width
        ));
        for (name, r) in &rendered {
            let percentiles = if r.mode.has_histogram() {
                [
                    percentile_ns(&r.buckets, 0.50),
                    percentile_ns(&r.buckets, 0.95),
                    percentile_ns(&r.buckets, 0.99),
                ]
            } else {
                [None; 3]
            };
            s.push_str(&format!(
                "{:<w$} {:<16} {:>8} {:>6} {:>9} {:>9} {:>9} {:>9}\n",
                name,
                provider_cell(r, &ev.discovery.modules),
                r.calls,
                r.errors,
                fmt_ns(percentiles[0]),
                fmt_ns(percentiles[1]),
                fmt_ns(percentiles[2]),
                r.in_flight,
                w = width
            ));
        }
        // Why the calls failed, per function: the `CKR_*` breakdown
        // behind each row's ERR count. Absent without failures.
        let reason_lines =
            error_reason_lines(&rendered, verbosity == crate::cli::TextVerbosity::Verbose);
        if !reason_lines.is_empty() {
            s.push_str("ERROR REASONS:\n");
            for line in reason_lines {
                s.push_str(&line);
                s.push('\n');
            }
        }
    }
    if !mechanisms.is_empty() {
        s.push_str(&format!(
            "{:<28} {:>8} {:>6}\n",
            "MECHANISM", "CALLS", "ERR"
        ));
        let mut rows: Vec<(&u64, &MechStat)> = mechanisms.iter().collect();
        rows.sort_by(|(a_id, a), (b_id, b)| b.calls.cmp(&a.calls).then(a_id.cmp(b_id)));
        for (id, stat) in rows {
            let name = mechanism_label(*id);
            s.push_str(&format!(
                "{:<28} {:>8} {:>6}\n",
                escape_controls(&name),
                stat.calls,
                stat.errors
            ));
        }
        if ev.mechanism_id_overflow > 0 {
            s.push_str(&format!(
                "plus {} further mechanism observation{} beyond the 256-id table (see Coverage).\n",
                ev.mechanism_id_overflow,
                if ev.mechanism_id_overflow == 1 {
                    ""
                } else {
                    "s"
                },
            ));
        }
        if ev.unregistered_standard_layout_mechanisms > 0 {
            s.push_str(&format!(
                "mechanism value not in the registry (names unconfirmed): {}\n",
                ev.unregistered_standard_layout_mechanisms,
            ));
        }
        if ev.standard_layout_slots > 0 {
            let evidence = if ev.standard_layout_evidence.is_empty() {
                "standard layout".to_string()
            } else {
                ev.standard_layout_evidence.join(", ")
            };
            s.push_str(&format!(
                "mechanism names from the standard table (layout evidence: {evidence})\n"
            ));
        }
    } else if reports.iter().any(|r| r.calls > 0 || r.in_flight > 0) {
        // No attributed mechanisms despite observed calls: name the gap in
        // one plain line instead of omitting the section. Count-only slots
        // never carry mechanism attribution; anything else simply records
        // none for the observed calls. The manifest remedy prints only
        // while a mapped provider actually lacks one.
        if ev.semantic_unverified_slots > 0 && has_unattested_provider(ev) {
            // Concise points at Coverage for the one remedy; verbose
            // repeats the remedy here beside the fact.
            let remedy = if verbosity == crate::cli::TextVerbosity::Verbose {
                "; add --manifest for provider files with unverified tables to confirm their layouts"
            } else {
                ""
            };
            s.push_str(&format!(
                "Mechanisms: none attributed — {} function{} named from the standard table, \
                 unconfirmed{remedy} (see Coverage).\n",
                ev.semantic_unverified_slots,
                if ev.semantic_unverified_slots == 1 {
                    ""
                } else {
                    "s"
                },
            ));
        } else {
            s.push_str("Mechanisms: none recorded for the observed calls.\n");
        }
        if ev.unregistered_standard_layout_mechanisms > 0 {
            s.push_str(&format!(
                "mechanism value not in the registry (names unconfirmed): {}\n",
                ev.unregistered_standard_layout_mechanisms,
            ));
        }
    }
    // Capture-wide sessions/logins beside the mechanism section, in
    // concise and verbose (quiet returned above with the header,
    // totals and coverage only). Absent without sessions or logins.
    if let Some(line) = session_login_line(
        sessions,
        logins,
        verbosity == crate::cli::TextVerbosity::Verbose,
    ) {
        s.push_str(&line);
        s.push('\n');
    }
    if verbosity == crate::cli::TextVerbosity::Verbose {
        let mut evidence_line = format!(
            "Evidence: {}/{} probes attached · {} slots ({} active) · {} aliased · {} skipped · {} in-flight",
            ev.attached_probes,
            ev.slots * 2,
            ev.slots,
            ev.active_slots,
            ev.aliased.len(),
            ev.skipped.len(),
            ev.in_flight_at_end,
        );
        if ev.semantic_history_drops > 0 {
            evidence_line.push_str(&format!(
                " · semantic_history_drops={}",
                ev.semantic_history_drops
            ));
        }
        let mut info_fragments: Vec<String> = Vec::new();
        for (label, count) in [
            ("orphan ops", ev.orphan_ops),
            ("unmatched closes", ev.unmatched_closes),
            ("shape decode gaps", ev.shape_decode_failures),
            (
                "process trackers using /proc",
                ev.process_tracking_fallbacks,
            ),
        ] {
            if count > 0 {
                info_fragments.push(format!("ℹ {count} {label}"));
            }
        }
        if !info_fragments.is_empty() {
            evidence_line.push_str(" · ");
            evidence_line.push_str(&info_fragments.join(" "));
        }
        // F-13: why the verdict is what it is, from the classes the verdict used,
        // so a gate can never force PARTIAL without being named here.
        evidence_line.push_str(&format!(
            " → {}{}\n",
            ev.completeness,
            verdict_reasons(ev, true)
        ));
        s.push_str(&escape_controls(evidence_line.trim_end()));
        s.push('\n');
    } else {
        s.push_str(crate::cli::VERBOSE_HINT);
        s.push('\n');
    }
    s
}

/// `" — calls may be missing (12 call records lost); names unconfirmed
/// (…)"` — one group per class with a cause, from `ev.gap_classes` —
/// or the unproven-drain sentence when the terminal seal is the only
/// reason. Empty when `COMPLETE`. Concise text is plain words only;
/// verbose pairs each machine name beside its plain words.
fn verdict_reasons(ev: &Evidence, verbose: bool) -> String {
    verdict_reason_body(ev, verbose).map_or_else(String::new, |body| format!(" — {body}"))
}

/// The [`verdict_reasons`] groups without the leading separator, so
/// the coverage line can reuse or replace them. `None` when `COMPLETE`
/// or when no reason renders at all.
fn verdict_reason_body(ev: &Evidence, verbose: bool) -> Option<String> {
    if ev.completeness == "COMPLETE" {
        return None;
    }
    let classes = &ev.gap_classes;
    let mut groups: Vec<String> = [
        ("observation", &classes.observation),
        ("attribution", &classes.attribution),
        ("semantics", &classes.semantics),
    ]
    .into_iter()
    .filter_map(|(label, class)| {
        let fragments = cause_fragments(ev, &class.causes, verbose);
        (!fragments.is_empty()).then(|| {
            format!(
                "{} ({})",
                verdict_group_label(label, class.status, verbose),
                fragments.join(", ")
            )
        })
    })
    .collect();
    if groups.is_empty() && !ev.drain_proven {
        groups.push(if verbose {
            "end of capture not fully confirmed — last calls may be missing \
             (terminal drain unproven)"
                .into()
        } else {
            "end of capture not fully confirmed (last calls may be missing)".into()
        });
    }
    if groups.is_empty() {
        None
    } else {
        Some(groups.join("; "))
    }
}

/// One verdict group's plain label: what the class means for the
/// counts. An unexpected label/status pair renders verbatim so it
/// always surfaces.
fn verdict_group_label(label: &str, status: &str, verbose: bool) -> String {
    let plain = match (label, status) {
        ("observation", "lossy") => "calls may be missing",
        ("attribution", "withheld") => "names unconfirmed",
        ("semantics", "degraded") => "call details degraded",
        _ => return format!("{label} {status}"),
    };
    if verbose {
        format!("{plain} ({label} {status})")
    } else {
        plain.to_string()
    }
}

/// The reducer-state counters the live line aggregates into one
/// "semantic state gaps" fragment.
fn semantic_state_counter(ev: &Evidence, cause: &str) -> Option<u64> {
    Some(match cause {
        "process_tracking_failures" => ev.process_tracking_failures,
        "process_tracking_evictions" => ev.process_tracking_evictions,
        "state_reconciliations" => ev.state_reconciliations,
        "session_cancel_ambiguities" => ev.session_cancel_ambiguities,
        "session_cancel_unknown_flags" => ev.session_cancel_unknown_flags,
        "operation_state_imports" => ev.operation_state_imports,
        "auth_state_ambiguities" => ev.auth_state_ambiguities,
        "async_target_failures" => ev.async_target_failures,
        "async_orphans" => ev.async_orphans,
        "async_duplicates" => ev.async_duplicates,
        "async_evictions" => ev.async_evictions,
        "fork_state_ambiguities" => ev.fork_state_ambiguities,
        "semantic_state_drops" => ev.semantic_state_drops,
        "pending_at_end" => ev.pending_at_end,
        _ => return None,
    })
}

/// The concise identity-refusal fragment: the counter counts refusal
/// attempts — including repeats for one leader — not distinct
/// processes. Shared by the kernel-control cause and the
/// missed-provider-load shortcut, so the shortcut never hides a spent
/// budget behind the pause remedy. `None` while nothing was refused.
fn identity_refusal_fragment(control: &crate::metrics::KernelControlEvidence) -> Option<String> {
    if control.identity_unavailable == 0 {
        return None;
    }
    let plain = format!(
        "{} {}",
        control.identity_unavailable,
        if control.identity_unavailable == 1 {
            "process identity refusal"
        } else {
            "process identity refusals"
        }
    );
    Some(if control.identity_budget_exhausted {
        format!("{plain} (lifetime budget of {IMAGE_IDENTITY_TICKET_LIMIT} identities spent)")
    } else {
        plain
    })
}

/// One ring's measured unexplained remainder: records the kernel
/// submitted that userspace neither consumed nor finds queued. Zero
/// when the ring has no account or the remainder is unmeasured: an
/// unknown remainder is unknown, never a gap.
fn ring_unexplained(account: &Option<RingAccountEvidence>) -> u64 {
    account
        .as_ref()
        .and_then(|account| account.unexplained)
        .unwrap_or(0)
}

/// One human fragment per verdict cause, stating the count behind it.
/// Concise text is plain words only; verbose pairs the machine cause
/// name beside each plain fragment. A cause without a phrase folds
/// into "other gaps" in concise text and renders as its own field name
/// in verbose, so a new gate always surfaces.
fn cause_fragments(ev: &Evidence, causes: &[&'static str], verbose: bool) -> Vec<String> {
    let count = |n: u64, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    let mut fragments = Vec::new();
    let mut state_gaps = 0u64;
    let mut state_causes: Vec<&str> = Vec::new();
    let mut unknown = 0u64;
    for &cause in causes {
        if let Some(value) = semantic_state_counter(ev, cause) {
            state_gaps = state_gaps.saturating_add(value);
            if value > 0 {
                state_causes.push(cause);
            }
            continue;
        }
        // Pairs the machine cause name beside its plain fragment.
        let tag = |plain: String| {
            if verbose {
                format!("{plain} ({cause})")
            } else {
                plain
            }
        };
        let fragment = match cause {
            "discovery" => "no provider files found".to_string(),
            "slots" => "no functions watched".to_string(),
            "scan_unavailable" => format!(
                "memory scan unavailable ({})",
                ev.discovery
                    .scan_unavailable
                    .as_deref()
                    .unwrap_or("unknown")
            ),
            "modules_skipped" => {
                // A module still attached on the endpoints it had when its
                // growth did not fit is partially covered, not refused (G-03).
                // A Part 0 prefix-admitted closure array is likewise partial.
                let partially_covered = ev
                    .discovery
                    .modules_skipped
                    .iter()
                    .filter(|module| crate::plan::is_partial_coverage(&module.reason))
                    .count() as u64;
                let refused = ev.discovery.modules_skipped.len() as u64 - partially_covered;
                for (n, one, many) in [
                    (
                        refused,
                        "provider file not watched",
                        "provider files not watched",
                    ),
                    (
                        partially_covered,
                        "provider file partially covered",
                        "provider files partially covered",
                    ),
                ] {
                    if n > 0 {
                        fragments.push(tag(count(n, one, many)));
                    }
                }
                continue;
            }
            "attach_failures" => count(
                ev.attach_failures.len() as u64,
                "function could not be watched",
                "functions could not be watched",
            ),
            "skipped" => {
                // Discovery-subject entries are unavailable discovery
                // steps, not skipped functions; only named function
                // entries keep the "skipped" wording.
                let mut subjects = 0u64;
                let mut functions = 0u64;
                for skip in ev
                    .skipped
                    .iter()
                    .filter(|skip| skip.reason != NULL_POINTER_REASON)
                {
                    if skip.name == DISCOVERY_SUBJECT {
                        subjects += 1;
                    } else if skip.name == LEARNED_SKIP_SUBJECT {
                        // Named by the histogram below with its count,
                        // not as a skipped function.
                    } else {
                        functions += 1;
                    }
                }
                if subjects > 0 {
                    fragments.push(tag(count(
                        subjects,
                        "discovery step unavailable",
                        "discovery steps unavailable",
                    )));
                }
                if functions > 0 {
                    fragments.push(tag(count(
                        functions,
                        "function skipped",
                        "functions skipped",
                    )));
                }
                // One histogram line per named limit present, in canonical
                // order; the labels are the finite public reasons, never
                // raw skip text, so no target data can reach this line.
                for reason in [
                    PROCESS_VIEW_CAPACITY_EXHAUSTED,
                    LOADER_CONTEXT_CAPACITY_EXHAUSTED,
                    LOADER_SCAN_LEDGER_EXCEEDED,
                    LOADER_ARM_LEDGER_FULL,
                    LEARNED_FIRST_RUN_REASON,
                    LEARNED_OVERFLOW_REASON,
                    LEARNED_CAP_REASON,
                    LEARNED_UNAVAILABLE_REASON,
                    LEARNED_REPLACED_DELETED_REASON,
                    LEARNED_DISABLED_REASON,
                    LEARNED_MOUNT_NAMESPACE_REASON,
                ] {
                    let hits = ev
                        .skipped
                        .iter()
                        .filter(|skip| skip.reason == reason)
                        .count() as u64;
                    if hits > 0 {
                        fragments.push(tag(format!("{reason}: {hits}")));
                    }
                }
                if verbose {
                    let items = skipped_item_list(ev);
                    if !items.is_empty() {
                        fragments.push(format!("skipped: {}", items.join(", ")));
                    }
                }
                continue;
            }
            "in_flight_at_end" => count(
                ev.in_flight_at_end,
                "call still running at capture end",
                "calls still running at capture end",
            ),
            "surfaces" => count(
                ev.surfaces
                    .iter()
                    .filter(|s| s.walk != "full" || s.acquisition != "ok")
                    .count() as u64,
                "provider table incompletely read",
                "provider tables incompletely read",
            ),
            "vendor_interfaces" => count(
                ev.vendor_interfaces as u64,
                "vendor-specific interface not decoded",
                "vendor-specific interfaces not decoded",
            ),
            "interface_list" => "could not list interfaces".to_string(),
            "event_loss" => count(ev.event_loss, "call record lost", "call records lost"),
            "start_insert_failures" => count(
                ev.start_insert_failures,
                "call start not recorded",
                "call starts not recorded",
            ),
            "unmatched_returns" => count(
                ev.unmatched_returns,
                "return without a recorded start",
                "returns without a recorded start",
            ),
            "rv_update_failures" => count(
                ev.rv_update_failures,
                "return value not recorded",
                "return values not recorded",
            ),
            "cgroup_scope_failures" => count(
                ev.cgroup_scope_failures,
                "cgroup membership check failed",
                "cgroup membership checks failed",
            ),
            "abi_refusals" => count(
                ev.abi_refusals,
                "unexpected probe hit refused",
                "unexpected probe hits refused",
            ),
            "malformed_records" => count(
                ev.malformed_records,
                "unreadable kernel record",
                "unreadable kernel records",
            ),
            "provider_changed" => "provider file changed during capture".to_string(),
            "trace_truncated" => "trace truncated at its event cap".to_string(),
            "counter_collection" => "final counter read incomplete".to_string(),
            "legacy_collection" => "legacy collection incomplete".to_string(),
            "snapshot_failure" => format!(
                "aggregate snapshot unavailable ({}): function counts unknown",
                ev.snapshot_failure.unwrap_or("unavailable")
            ),
            "proc_namespace_mismatch" => {
                "process numbering is foreign: kernel PIDs unresolvable".to_string()
            }
            "pid_namespace" => {
                let base = format!(
                    "observer PID namespace {}: kernel PIDs unresolvable",
                    ev.pid_namespace.observer
                );
                // `docker run` without `--pid=host`: the evidence saw
                // only this container, so the gap names it and its
                // remedy in the same plain words as the start warning.
                if ev.container_only_view {
                    format!(
                        "{base}; only this container is visible; run with --pid=host to see the host"
                    )
                } else {
                    base
                }
            }
            "unprotected_live_windows" => {
                "calls made while probes were being attached may be missing".to_string()
            }
            "discovery_ring_loss" => count(
                ev.discovery_ring_loss,
                "discovery record lost",
                "discovery records lost",
            ),
            "discovery_state_failures" => count(
                ev.discovery_state_failures,
                "discovery update failed",
                "discovery updates failed",
            ),
            "discovery_read_failures" => count(
                ev.discovery_read_failures,
                "discovery read failed",
                "discovery reads failed",
            ),
            "discovery_truncated" => count(
                ev.discovery_truncated,
                "discovery record truncated",
                "discovery records truncated",
            ),
            "discovery_ring_unexplained" => count(
                ring_unexplained(&ev.ring_accounting.discovery),
                "submitted discovery record unaccounted for",
                "submitted discovery records unaccounted for",
            ),
            "events_ring_unexplained" => count(
                ring_unexplained(&ev.ring_accounting.events),
                "submitted call record unaccounted for",
                "submitted call records unaccounted for",
            ),
            "task_uprobe_link_losses" => count(
                ev.task_uprobe_link_losses,
                "probe link lost",
                "probe links lost",
            ),
            "pause_partial" => count(
                ev.pause_partial,
                "load only partly paused",
                "loads only partly paused",
            ),
            "pause_unavailable" => count(
                ev.pause_unavailable,
                "load could not be paused (collected unpaused)",
                "loads could not be paused (collected unpaused)",
            ),
            "loader_discovery" => {
                let loader = &ev.loader_discovery;
                if loader.hits == 0 && loader.strategies.debug_state_every_hit == 1 {
                    "library-load tracking received nothing from the kernel \
                     (loads may be missing)"
                        .to_string()
                } else if loader.hits == 0 && loader.strategies.debug_state_every_hit >= 2 {
                    "library-load tracking missed loads it should have seen".to_string()
                } else {
                    "library-load tracking could not be confirmed".to_string()
                }
            }
            "scheduling.terminal_drain_truncated" => {
                "final drain cut short (last calls may be missing)".to_string()
            }
            "scheduling.sink_dropped_bytes" => count(
                ev.scheduling.sink_dropped_bytes,
                "output byte dropped",
                "output bytes dropped",
            ),
            "interface_selection" => "function list not fully identified".to_string(),
            "pid_descendant_gaps" => count(
                ev.pid_descendant_gaps,
                "short-lived process gap",
                "short-lived process gaps",
            ),
            "multi_rebuild_gaps" => count(
                ev.multi_rebuild_gaps,
                "probe re-attach gap",
                "probe re-attach gaps",
            ),
            "semantic_unverified_slots" => {
                // The names render from the standard table by position, but
                // the layout was not verified from scan (unknown, vendor or
                // ambiguous tables stay count-only); a manifest confirms the
                // positions for mechanism decoding. Verbose keeps the slot
                // count with the machine cause name. Standard-layout tables
                // (interface-linked, sole-complete) verify without a manifest
                // and never reach this hint.
                const PLAIN: &str = "function names follow the standard PKCS#11 table but their \
                     layout was not verified from scan (add --manifest to confirm positions for mechanism decoding)";
                if verbose {
                    fragments.push(format!(
                        "{PLAIN} ({} slots; {cause})",
                        ev.semantic_unverified_slots
                    ));
                } else {
                    fragments.push(PLAIN.to_string());
                }
                continue;
            }
            "aliased" => count(
                ev.aliased.len() as u64,
                "function sharing an address",
                "functions sharing an address",
            ),
            "module_ambiguous" => count(
                ev.discovery.module_ambiguous,
                "function claimed by two provider files",
                "functions claimed by two provider files",
            ),
            "module_unresolved_slots" => count(
                ev.module_unresolved_slots as u64,
                "function with no proven provider file",
                "functions with no proven provider file",
            ),
            "unregistered_mechanisms" => count(
                ev.unregistered_mechanisms,
                "unregistered mechanism",
                "unregistered mechanisms",
            ),
            "unpublished_mechanisms" => count(
                ev.unpublished_mechanisms,
                "vendor mechanism not listed by name",
                "vendor mechanisms not listed by name",
            ),
            "discovery_conflicts" => format!(
                "manifest and scan disagree on {} provider file{}",
                ev.discovery.conflicts,
                if ev.discovery.conflicts == 1 { "" } else { "s" }
            ),
            "discovery_uncorroborated" => count(
                ev.discovery.uncorroborated,
                "provider file not confirmed from a second source",
                "provider files not confirmed from a second source",
            ),
            "interface_selection.selection_count_only" => {
                "function list counted without names".to_string()
            }
            "semantic_capture_failures" => count(
                ev.semantic_capture_failures,
                "mechanism detail not recorded",
                "mechanism details not recorded",
            ),
            "template_tail_failures" => count(
                ev.template_tail_failures,
                "attribute-list read not recorded",
                "attribute-list reads not recorded",
            ),
            "mechanism_id_overflow" => count(
                ev.mechanism_id_overflow,
                "mechanism observation beyond the 256-id table",
                "mechanism observations beyond the 256-id table",
            ),
            "semantic_history_drops" => count(
                ev.semantic_history_drops,
                "mechanism history dropped",
                "mechanism histories dropped",
            ),
            "templates_truncated" => "attribute lists cut short".to_string(),
            "shape_decode_total_failures" => count(
                ev.shape_decode_total_failures,
                "mechanism never decoded",
                "mechanisms never decoded",
            ),
            "kernel_control" => {
                // One fragment per active kernel-control part, so the
                // cause never folds into "other gaps": identity
                // refusals with the spent budget, a halted kernel with
                // its poison names, refused ownership admissions and
                // root-affiliation failures. The verdict fires this
                // cause exactly when one part is active, so at least
                // one fragment always lands. A spent budget with zero
                // refusals stays COMPLETE and is named on the longrun
                // line instead (spark rv-v070-identity-reuse F1).
                let control = &ev.kernel_control;
                if control.capture_halted {
                    fragments.push(tag(if control.owner_poison.is_empty() {
                        "kernel capture halted".to_string()
                    } else {
                        format!(
                            "kernel capture halted ({})",
                            control.owner_poison.join(", ")
                        )
                    }));
                } else {
                    for reason in &control.owner_poison {
                        fragments.push(tag(format!("kernel owner refusal: {reason}")));
                    }
                }
                if control.owner_admission_failures > 0 {
                    fragments.push(tag(count(
                        control.owner_admission_failures,
                        "kernel ownership admission refused",
                        "kernel ownership admissions refused",
                    )));
                }
                if let Some(fragment) = identity_refusal_fragment(control) {
                    fragments.push(tag(fragment));
                }
                for reason in &control.root_affiliation_failures {
                    fragments.push(tag(format!("kernel root affiliation failure: {reason}")));
                }
                continue;
            }
            other => {
                if verbose {
                    fragments.push(other.to_string());
                } else {
                    unknown += 1;
                }
                continue;
            }
        };
        fragments.push(tag(fragment));
    }
    if state_gaps > 0 {
        let plain = count(state_gaps, "session-tracking gap", "session-tracking gaps");
        fragments.push(if verbose && !state_causes.is_empty() {
            let mut detail = state_causes.join(", ");
            // Drops exist only once the monotonic budget is spent, so a
            // nonzero count names the spent budget beside the causes.
            if ev.semantic_state_drops > 0 {
                detail.push_str(&format!(
                    "; key budget of {} spent",
                    crate::semantics::MAX_STATE_KEYS
                ));
            }
            format!("{plain} ({detail})")
        } else {
            plain
        });
    }
    if unknown > 0 {
        fragments.push(format!(
            "{} other gap{} (see --json evidence)",
            unknown,
            if unknown == 1 { "" } else { "s" }
        ));
    }
    fragments
}

/// Verbose `-v` listing of the skipped entries behind the `skipped`
/// cause: each distinct `{name} ({reason})` in first-seen order with
/// a repeat count, capped like the module gaps. The coverage line
/// already escapes the whole reasons string, so categorical names and
/// reasons render as-is.
fn skipped_item_list(ev: &Evidence) -> Vec<String> {
    const SHOWN: usize = 5;
    let mut distinct: Vec<(&str, &str, u64)> = Vec::new();
    for skip in ev
        .skipped
        .iter()
        .filter(|skip| skip.reason != NULL_POINTER_REASON)
    {
        if let Some(entry) = distinct
            .iter_mut()
            .find(|(name, reason, _)| *name == skip.name && *reason == skip.reason)
        {
            entry.2 += 1;
        } else {
            distinct.push((skip.name.as_str(), skip.reason.as_str(), 1));
        }
    }
    let mut items: Vec<String> = distinct
        .iter()
        .take(SHOWN)
        .map(|(name, reason, n)| {
            if *n > 1 {
                format!("{name} ({reason}) ×{n}")
            } else {
                format!("{name} ({reason})")
            }
        })
        .collect();
    if distinct.len() > SHOWN {
        items.push(format!("and {} more", distinct.len() - SHOWN));
    }
    items
}

/// True for an owned run that never paused while its command ran
/// ahead of probe attachment: nothing was watched, a live load went
/// unpaused, and a refused loader context or repeated discovery
/// misses corroborate the missed provider. A bare command with no
/// missed load (one subject skip, no refused context) stays generic.
fn missed_provider_load(ev: &Evidence) -> bool {
    ev.child_still_running.is_some()
        && ev.pause == "none"
        && ev.pause_attempts == 0
        && ev.unprotected_live_windows > 0
        && ev.slots == 0
        && (ev.discovery_truncated > 0
            || ev
                .skipped
                .iter()
                .filter(|skip| skip.name == DISCOVERY_SUBJECT)
                .count()
                > 1)
}

/// The totals line shared by the profile summary and the trace tail.
pub(crate) fn totals_line(calls: u64, errors: u64, open: u64) -> String {
    let call_noun = if calls == 1 { "call" } else { "calls" };
    let error_noun = if errors == 1 { "error" } else { "errors" };
    let entry_noun = if open == 1 { "entry" } else { "entries" };
    format!(
        "{calls} completed {call_noun}; {errors} returned {error_noun}; {open} {entry_noun} \
         without an observed return."
    )
}

/// The one coverage line shared by the profile summary and the trace
/// tail: `coverage: complete`; `coverage: partial — counts complete; …`
/// when names are the only gap (the text states the same PARTIAL verdict
/// as JSON, with counts complete in plain words); the owned-run
/// missed-load remedy, with an active identity-refusal fragment
/// appended at default verbosity; or `coverage: partial — <reasons>`.
/// Verbose keeps the full grouped reasons beside the special cases.
pub(crate) fn coverage_line(ev: &Evidence, verbose: bool) -> String {
    if ev.completeness == "COMPLETE" {
        return "coverage: complete".to_string();
    }
    if missed_provider_load(ev) {
        let mut line = "coverage: partial — the command loaded its provider before probes \
             attached; rerun with --pause auto"
            .to_string();
        if verbose {
            if let Some(reasons) = verdict_reason_body(ev, true) {
                line.push_str("; ");
                line.push_str(&escape_controls(&reasons));
            }
        } else if let Some(fragment) = identity_refusal_fragment(&ev.kernel_control) {
            line.push_str("; ");
            line.push_str(&escape_controls(&fragment));
        }
        return line;
    }
    let classes = &ev.gap_classes;
    if classes.observation.causes.is_empty()
        && classes.semantics.causes.is_empty()
        && !classes.attribution.causes.is_empty()
    {
        let fragments = cause_fragments(ev, &classes.attribution.causes, verbose);
        if fragments.is_empty() {
            return "coverage: partial — counts complete".to_string();
        }
        return format!(
            "coverage: partial — counts complete; {}",
            escape_controls(&fragments.join("; "))
        );
    }
    match verdict_reason_body(ev, verbose) {
        Some(body) => format!("coverage: partial — {}", escape_controls(&body)),
        None => "coverage: partial".to_string(),
    }
}

/// The module a slot's counts belong to, as `functions[]` renders it.
#[derive(Serialize)]
struct ModuleRef {
    dev: (u64, u64),
    ino: u64,
    sha256: Option<String>,
}

/// A row's exact attach target: the stable key of `functions[]`.
#[derive(Serialize)]
struct TargetOut {
    /// The pinned object, identified as `discovery[].objects[]` does;
    /// `null` only when no pin identity was recorded for it.
    object: Option<crate::plan::TargetObject>,
    /// Offset of the probed function inside that object's file.
    file_offset: u64,
}

#[derive(Serialize)]
struct FunctionOut {
    names: Vec<String>,
    aliased: bool,
    /// Which exact function this row counts — distinct for every row, named
    /// or not (review answer (c)).
    target: TargetOut,
    /// Every table ordinal reaching `target`. A position, never a name: an
    /// unnamed row stays `["unknown"]`; two or more entries disclose that
    /// several ordinals share this target.
    ordinals: Vec<crate::plan::SlotOrdinal>,
    /// `null` when two modules publish this target: the counts are real, the
    /// owner is not knowable, and guessing one would credit a provider's calls
    /// to another.
    module: Option<ModuleRef>,
    /// True exactly when `module` is null because two modules claim the slot.
    module_ambiguous: bool,
    /// True exactly when `module` is null because this allocated aggregate
    /// cell has no accepted sole owner at all — an unowned endpoint, never
    /// relabelled as two-module ambiguity. The three fields are an exact
    /// exclusive relation: nonnull/false/false, null/true/false, null/false/true.
    module_unresolved: bool,
    /// True when this row counts calls at a forwarding layer (a closure
    /// array admitted beside watched providers): the logical call is the
    /// provider row it contains, counted once in `layer_totals.logical`.
    /// Additive within v3: consumers that sum `calls` across rows must
    /// skip `forwarding_layer` rows to count logical calls once.
    forwarding_layer: bool,
    calls: u64,
    errors: u64,
    pending_returns: u64,
    in_flight: u64,
    latency_ns: Option<LatencyOut>,
    rv_counts: std::collections::BTreeMap<String, u64>,
    /// `CKR_*` names for the `rv_counts` keys that have a registered
    /// name, keyed by the same 16-digit hex strings. Unregistered
    /// (vendor) codes are absent — their hex key is the verbatim
    /// rendering. Render-time presentation of already-captured values
    /// through the shared lookup; no new capture.
    rv_names: std::collections::BTreeMap<String, String>,
    /// The Initialize claim, present only on rows that name `C_Initialize`
    /// with at least one positively counted return; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    initialization: Option<InitializationOut>,
}

#[derive(Serialize)]
struct LatencyOut {
    /// Whether percentiles are bucket-approximated. Total/max retain their
    /// source's measurement and loss limits.
    approximate: bool,
    p50: Option<u64>,
    p95: Option<u64>,
    p99: Option<u64>,
    total: u64,
    max: u64,
}

fn latency_out(
    buckets: &[u64; p11scope_ebpf_common::LATENCY_BUCKETS],
    total: u64,
    max: u64,
) -> LatencyOut {
    LatencyOut {
        approximate: true,
        p50: percentile_ns(buckets, 0.50),
        p95: percentile_ns(buckets, 0.95),
        p99: percentile_ns(buckets, 0.99),
        total,
        max,
    }
}

/// Availability follows the actual row's counter capability, never its values.
fn latency_out_for_mode(report: &SlotReport) -> Option<LatencyOut> {
    match report.mode {
        CounterMode::Counts => None,
        CounterMode::Timestamps => Some(LatencyOut {
            approximate: false,
            p50: None,
            p95: None,
            p99: None,
            total: report.total_ns,
            max: report.max_ns,
        }),
        CounterMode::Latency => Some(latency_out(&report.buckets, report.total_ns, report.max_ns)),
    }
}

/// The per-row Initialize claim: the outcome class over the row's own
/// completed calls plus the potential-provider likelihood. Render-time
/// only, from `rv_counts` already on the row — no new read, no new
/// retention. Absent (never null or false) unless the row names
/// `C_Initialize` with at least one positively counted return.
#[derive(Serialize)]
struct InitializationOut {
    /// `ok`, `already_initialized`, `error`, or `mixed` (more than one
    /// class over the row's completed calls).
    outcome: InitializationOutcome,
    /// Present and true exactly when at least one completed call returned
    /// CKR_OK or CKR_CRYPTOKI_ALREADY_INITIALIZED: a likelihood that the
    /// row's module behaves as a Cryptoki provider, never proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    potential_provider: Option<bool>,
}

/// The closed outcome vocabulary, shared by the JSON row and the live
/// marker so both stay exhaustive.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum InitializationOutcome {
    Ok,
    AlreadyInitialized,
    Error,
    Mixed,
}

impl InitializationOut {
    /// The live-table marker reports the outcome only; the provider
    /// column beside it names the file.
    fn text_suffix(&self) -> &'static str {
        match self.outcome {
            InitializationOutcome::Ok => " [init: ok]",
            InitializationOutcome::AlreadyInitialized => " [init: already_initialized]",
            InitializationOutcome::Mixed => " [init: mixed]",
            InitializationOutcome::Error => " [init: error]",
        }
    }
}

/// Derives the Initialize claim from the row's own `rv_counts` alone.
/// Every positively counted return maps to exactly one class: CKR_OK is
/// `ok`, CKR_CRYPTOKI_ALREADY_INITIALIZED is `already_initialized`, and
/// anything else — including CKR_PENDING, for which the outcome
/// vocabulary has no word — is `error`. Zero counts assert nothing and
/// are ignored.
fn initialization_out(
    names: &[String],
    rv_counts: &std::collections::BTreeMap<u64, u64>,
) -> Option<InitializationOut> {
    if !names.iter().any(|name| name == "C_Initialize") {
        return None;
    }
    let mut ok = false;
    let mut already = false;
    let mut error = false;
    for (&rv, &count) in rv_counts {
        if count == 0 {
            continue;
        }
        if rv == pkcs11_types::CkRv::OK.0 {
            ok = true;
        } else if rv == pkcs11_types::CkRv::CRYPTOKI_ALREADY_INITIALIZED.0 {
            already = true;
        } else {
            error = true;
        }
    }
    let classes = [ok, already, error].into_iter().filter(|&b| b).count();
    if classes == 0 {
        return None;
    }
    let outcome = if classes > 1 {
        InitializationOutcome::Mixed
    } else if ok {
        InitializationOutcome::Ok
    } else if already {
        InitializationOutcome::AlreadyInitialized
    } else {
        InitializationOutcome::Error
    };
    Some(InitializationOut {
        outcome,
        potential_provider: (ok || already).then_some(true),
    })
}

/// Per-name call/error/latency counts from the **aggregate BPF maps** —
/// the count authority in every mode (see module docs on `functions`
/// sourcing in both renderers). `modules` is the current compact
/// `evidence.discovery[]` snapshot, so stable `ModuleId`s are matched rather
/// than treated as vector offsets.
fn functions_out(
    reports: &[SlotReport],
    modules: &[DiscoveredModule],
    forwarding: &std::collections::BTreeSet<ModuleId>,
) -> Vec<FunctionOut> {
    reports
        .iter()
        .map(|r| FunctionOut {
            names: r.names.clone(),
            aliased: r.aliased,
            target: TargetOut {
                object: r.target_object.clone(),
                file_offset: r.file_offset,
            },
            ordinals: r.ordinals.clone(),
            module: r
                .module
                .and_then(|id| modules.iter().find(|module| module.id == id))
                .map(|m| ModuleRef {
                    dev: m.dev,
                    ino: m.ino,
                    sha256: m.sha256.clone(),
                }),
            // Kept next to `module` on purpose: a reader that only checks for a
            // null module must not have to know why it is null.
            module_ambiguous: r.module_ambiguous,
            module_unresolved: r.module_unresolved,
            forwarding_layer: row_is_forwarding(r, forwarding, modules),
            calls: r.calls,
            errors: r.errors,
            pending_returns: r
                .rv_counts
                .get(&pkcs11_types::CkRv::PENDING.0)
                .copied()
                .unwrap_or(0),
            in_flight: r.in_flight,
            latency_ns: latency_out_for_mode(r),
            rv_counts: r
                .rv_counts
                .iter()
                .map(|(rv, n)| (format!("0x{rv:016x}"), *n))
                .collect(),
            rv_names: r
                .rv_counts
                .keys()
                .filter_map(|rv| {
                    crate::semantics_edge::rv_name(*rv).map(|name| (format!("0x{rv:016x}"), name))
                })
                .collect(),
            initialization: initialization_out(&r.names, &r.rv_counts),
        })
        .collect()
}

/// `capture.modules[]`: the identity of every currently discovered module. A
/// projection of `evidence.discovery[]` rather than a second list, so the two
/// can never disagree about what this capture observed.
fn capture_modules(ev: &Evidence) -> Vec<serde_json::Value> {
    ev.discovery
        .modules
        .iter()
        .map(|m| {
            serde_json::json!({
                "path": m.path,
                "dev": m.dev,
                "ino": m.ino,
                "sha256": m.sha256,
                "build_id": m.build_id,
            })
        })
        .collect()
}

/// Additive v3 `layer_totals`: logical (provider) calls count once no
/// matter how many layers observed them; forwarding-layer calls stay
/// explicit beside them. Both layers keep their `functions[]` rows with
/// `forwarding_layer` labels, so the split is reproducible per row.
fn layer_totals_json(
    reports: &[SlotReport],
    forwarding: &std::collections::BTreeSet<ModuleId>,
    modules: &[DiscoveredModule],
) -> serde_json::Value {
    let [
        (logical_calls, logical_errors, logical_open),
        (fwd_calls, fwd_errors, fwd_open),
    ] = layer_call_totals(reports, forwarding, modules);
    serde_json::json!({
        "logical": {"calls": logical_calls, "errors": logical_errors, "in_flight": logical_open},
        "forwarding": {"calls": fwd_calls, "errors": fwd_errors, "in_flight": fwd_open},
    })
}

pub fn json(reports: &[SlotReport], ev: &Evidence, capture: &CaptureMeta<'_>) -> serde_json::Value {
    let forwarding = forwarding_module_ids(ev, reports);
    let mut document = serde_json::json!({
        "schema": "p11scope/observed-profile/v3-metrics",
        // Machine-readable lane discriminator (SYSPLAN residual F-12): the
        // metrics lane embeds `Evidence` directly (the four profile-only
        // fields are absent) with a selection-blind verdict.
        "lane": "metrics",
        "capture": { "start": capture.started, "end": capture.ended, "mode": "metrics",
                     "privacy_mode": capture.policy.privacy_mode(),
                     "scope": capture.scope,
                     "kernel": capture.kernel,
                     "ring_bytes": capture.ring_bytes,
                     "drain_interval_ms": capture.drain_interval_ms,
                     "modules": capture_modules(ev) },
        "evidence": ev,
        "functions": functions_out(reports, &ev.discovery.modules, &forwarding),
        "layer_totals": layer_totals_json(reports, &forwarding, &ev.discovery.modules),
    });
    if let Some(caller) = caller_out(capture.scope, capture.caller.as_ref()) {
        document["capture"]["caller"] = caller;
    }
    // 7.10b: the metrics lane embeds `Evidence` directly, so the
    // skipped armed-only splits are hoisted here with the same closed
    // shapes the profile lane publishes. Present if and only if
    // armed; absent, never null, otherwise.
    {
        let evidence = document["evidence"]
            .as_object_mut()
            .expect("metrics renderer emits an evidence object");
        if let Some(hints) = ev.gap_exe_hints {
            evidence.insert("gap_exe_hints".into(), static_hint_split_json(&hints));
        }
        if let Some(split) = ev.discovery.gap_exit_mappings {
            evidence.insert("gap_exit_mappings".into(), exit_mappings_split_json(&split));
        }
        if let Some(hints) = ev.target_exec_hints {
            evidence.insert("target_exec_hints".into(), static_hint_split_json(&hints));
        }
    }
    document
}

/// Only a protected accepted snapshot can supply this optional derived data.
/// Ordinary capture/trace evidence and all existing initializers stay intact.
pub(crate) fn with_counter_snapshot(
    mut document: serde_json::Value,
    snapshot: &crate::metrics::CaptureSnapshot,
) -> serde_json::Value {
    if let Some(collection) = snapshot.counter_collection() {
        document["evidence"]
            .as_object_mut()
            .expect("capture renderer emits an evidence object")
            .insert("counter_collection".into(), collection);
    }
    document
}

/// Optional legacy gap object, omitted when the legacy read was exact.
/// Counts and finite reason names only; zeros in the rows are unknown, not
/// exact, whenever this object is present.
pub(crate) fn with_legacy_snapshot(
    mut document: serde_json::Value,
    snapshot: &crate::metrics::CaptureSnapshot,
) -> serde_json::Value {
    if let Some(collection) = snapshot.legacy_collection() {
        document["evidence"]
            .as_object_mut()
            .expect("capture renderer emits an evidence object")
            .insert("legacy_collection".into(), collection);
    }
    document
}

/// Type-enforced versioned evidence (SYSPLAN residual F-08): the only input
/// `profile_json` accepts, so the profile lane can never silently regress
/// to embedding a raw `Evidence` by call-site discipline. The Python oracle
/// stays a second reader of the emitted shape.
pub struct VersionedEvidence<'a> {
    ev: &'a Evidence,
    value: serde_json::Value,
}

impl<'a> VersionedEvidence<'a> {
    pub fn wrap(ev: &'a Evidence) -> Self {
        Self {
            ev,
            value: versioned_evidence(ev),
        }
    }

    pub fn evidence(&self) -> &'a Evidence {
        self.ev
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }
}

/// 7.10b: the closed STATIC HINT split shape, shared by the
/// profile, metrics and trace lanes so the three can never drift
/// apart. Both the gap split and the PID target-exec split use it.
fn static_hint_split_json(hints: &GapExeHints) -> serde_json::Value {
    serde_json::json!({
        "label": STATIC_HINT_LABEL,
        "scope": STATIC_HINT_SCOPE_D_TRANSITIVE,
        "links_provider": hints.links_provider,
        "links_pkcs11_loader": hints.links_pkcs11_loader,
        "no_static_link_within_scope": hints.no_static_link_within_scope,
        "unknown": hints.unknown,
    })
}

/// 7.10b: the closed exit-mapping split shape, shared like the hint
/// shape above.
fn exit_mappings_split_json(split: &GapExitMappings) -> serde_json::Value {
    serde_json::json!({
        "mapped": split.mapped,
        "unknown": split.unknown,
    })
}

pub(crate) fn versioned_evidence(ev: &Evidence) -> serde_json::Value {
    let mut evidence = serde_json::to_value(ev).expect("Evidence serializes");
    let object = evidence.as_object_mut().expect("Evidence is an object");
    object.insert(
        "interface_selection".into(),
        serde_json::to_value(&ev.interface_selection).expect("selection evidence serializes"),
    );
    object.insert(
        "attach_mechanisms".into(),
        serde_json::json!(ev.attach_mechanisms),
    );
    object.insert(
        "attach_backend".into(),
        serde_json::to_value(&ev.attach_backend).expect("attach backend evidence serializes"),
    );
    object.insert("pid_descendant_gaps".into(), ev.pid_descendant_gaps.into());
    object.insert("multi_rebuild_gaps".into(), ev.multi_rebuild_gaps.into());
    object.insert(
        "learned_staged_files".into(),
        ev.learned_staged_files.into(),
    );
    object.insert("learned_event_loss".into(), ev.learned_event_loss.into());
    object.insert("learned_cap_skipped".into(), ev.learned_cap_skipped.into());
    // 6.14 Option B: present if and only if extensive mode armed. The
    // label and scope ride every publication (Row C); the counts never
    // feed shares, verdicts, or completeness.
    if let Some(hints) = ev.gap_exe_hints {
        object.insert("gap_exe_hints".into(), static_hint_split_json(&hints));
    }
    // 7.10b: the PID target-exec split rides the same shape. Present
    // if and only if the PID consumer armed; absent, never null,
    // otherwise. The counts never feed shares, verdicts, or
    // completeness.
    if let Some(hints) = ev.target_exec_hints {
        object.insert("target_exec_hints".into(), static_hint_split_json(&hints));
    }
    // 6.14 Option A: present if and only if extensive mode armed. A
    // kernel exit-time observation, not a hint: no label or scope
    // rides it, only the two counts, which never feed shares,
    // verdicts, or completeness.
    if let Some(split) = ev.discovery.gap_exit_mappings {
        object.insert("gap_exit_mappings".into(), exit_mappings_split_json(&split));
    }
    // B17 W2: present whenever the capture produced reload evidence:
    // a disclosed tainted identity, or nonzero count snapshots with
    // an empty identities list (mint exhaustion). Per-identity
    // entries plus the capture counts; the private image key never
    // renders, and the key never feeds shares, verdicts, or
    // completeness.
    if let Some(reload) = ev.instance_reload_not_excluded.as_ref() {
        let identities: Vec<serde_json::Value> = reload
            .identities
            .iter()
            .map(|entry| serde_json::json!({"file_slot": entry.file_slot, "ids": entry.ids}))
            .collect();
        object.insert(
            "instance_reload_not_excluded".into(),
            serde_json::json!({
                "continued_across_global": reload.continued_across_global,
                "joined_across_global": reload.joined_across_global,
                "identities": identities,
            }),
        );
    }
    evidence
}

/// One mechanism id's aggregate stats, event-derived (see module docs):
/// the aggregate maps have no per-mechanism breakdown, only the ring
/// buffer / semantic state machine does.
#[derive(Serialize)]
struct MechanismOut {
    /// Verbatim id — vendor ids survive unchanged, never renamed or dropped.
    mechanism: u64,
    mechanism_hex: String,
    /// The `CKM_*` name when the id is a known standard or listed
    /// vendor mechanism, else null — never guessed. Display only:
    /// naming never affects counts, publication or row presence, so a
    /// named vendor id still carries its number above.
    name: Option<&'static str>,
    /// The BPF return path found this id in `MECH_SHAPE` (registry
    /// membership, parameter shape published). `false` marks an
    /// unregistered publication: numeric id plus call/error counts
    /// only, never decoded; the name above is display-only and
    /// independent of this flag.
    registered: bool,
    /// Attribution basis for this row (ruling 2026-11-11 clause 3):
    /// `"standard_layout"` when every observation came through a
    /// slot authorized by standard-layout scan evidence only,
    /// `"manifest"` when a manifest/confirmed slot contributed.
    attribution_basis: &'static str,
    /// Operation categories (`"sign"`, `"encrypt"`, ...) this id was seen
    /// initializing. Empty when only ever seen as an orphan operational
    /// call (no `*Init` observed in this capture).
    ops: Vec<String>,
    calls: u64,
    errors: u64,
    latency_ns: LatencyOut,
    /// `null` when no diagnostic parameter shape ever decoded for this
    /// mechanism id in this capture (unrecognized/absent shape, or every
    /// decode attempt failed) — unchanged from v1. Otherwise an array of
    /// shape-tagged parameter-combination objects, one per **distinct**
    /// combination of decoded scalar values observed, each carrying its
    /// own `count` — never an average or a "latest wins" value, since
    /// migration assessment needs the actual combos a mechanism was
    /// driven with. See `docs/schema/observed-profile-v2.md` for the
    /// per-shape field layout.
    params: serde_json::Value,
    /// Why `params` is `null` (F-21), absent when it is an array:
    /// `policy` — the allowlisted capture policy disables parameter
    /// decoding; `no_shape` — no diagnostic shape is published for this id,
    /// so decoding was not attempted; `decode_failed` — a shape exists but
    /// every decode attempt failed. Never "nothing was passed".
    #[serde(skip_serializing_if = "Option::is_none")]
    params_omitted: Option<&'static str>,
    note: &'static str,
    /// Per-provider partition of `calls`/`errors`, in module-id order.
    /// Empty when no observation carried an attributable sole-owner
    /// module the document's discovery list names.
    by_module: Vec<ByModuleOut>,
}

/// One provider's share of a mechanism row: the same `{dev, ino,
/// sha256}` module reference `functions[].module` uses, with that
/// provider's calls/errors for this id. Entries cover the attributed
/// subset of the row — observations on slots with no sole owner, or
/// whose owner the discovery list does not name, count in the row
/// totals but in no entry — so entry sums never exceed the row.
#[derive(Serialize)]
struct ByModuleOut {
    module: ModuleRef,
    calls: u64,
    errors: u64,
}

/// One decoded parameter combination, tagged by shape, with its
/// occurrence count. `None` for a shape code this phase does not decode
/// (should not occur: `param_combos` only ever stores shapes the BPF side
/// actually decoded) — filtered out by the caller, never emitted as a
/// guess.
pub(crate) fn param_combo_json(
    shape_code: u32,
    p0: u64,
    p1: u64,
    p2: u64,
    count: u64,
) -> Option<serde_json::Value> {
    match shape_code {
        p11scope_ebpf_common::shape::RSA_PKCS_PSS => Some(serde_json::json!({
            "shape": "rsa_pkcs_pss",
            "hash_alg": p0,
            "hash_alg_hex": format!("0x{p0:x}"),
            "mgf": p1,
            "salt_len": p2,
            "count": count,
        })),
        p11scope_ebpf_common::shape::GCM_V220 => Some(serde_json::json!({
            "shape": "gcm",
            "layout": "v2.20",
            "iv_len": p0,
            "aad_len": p1,
            "tag_bits": p2,
            "count": count,
        })),
        p11scope_ebpf_common::shape::GCM_V240 => Some(serde_json::json!({
            "shape": "gcm",
            "layout": "v2.40",
            "iv_len": p0,
            "aad_len": p1,
            "tag_bits": p2,
            "count": count,
        })),
        _ => None,
    }
}

/// Bit position (`attr_bool` module) -> the `CKA_*` name it stands for, in
/// the same order `crates/ebpf-common::attr_bool` declares them.
const POLICY_BOOL_NAMES: &[(u32, &str)] = &[
    (p11scope_ebpf_common::attr_bool::TOKEN, "CKA_TOKEN"),
    (p11scope_ebpf_common::attr_bool::PRIVATE, "CKA_PRIVATE"),
    (p11scope_ebpf_common::attr_bool::SENSITIVE, "CKA_SENSITIVE"),
    (p11scope_ebpf_common::attr_bool::ENCRYPT, "CKA_ENCRYPT"),
    (p11scope_ebpf_common::attr_bool::DECRYPT, "CKA_DECRYPT"),
    (p11scope_ebpf_common::attr_bool::WRAP, "CKA_WRAP"),
    (p11scope_ebpf_common::attr_bool::UNWRAP, "CKA_UNWRAP"),
    (p11scope_ebpf_common::attr_bool::SIGN, "CKA_SIGN"),
    (p11scope_ebpf_common::attr_bool::VERIFY, "CKA_VERIFY"),
    (p11scope_ebpf_common::attr_bool::DERIVE, "CKA_DERIVE"),
    (
        p11scope_ebpf_common::attr_bool::EXTRACTABLE,
        "CKA_EXTRACTABLE",
    ),
];

#[derive(Serialize)]
struct AttrTypeOut {
    attr_type: u64,
    attr_type_hex: String,
}

#[derive(Serialize)]
struct PolicyBooleansOut {
    /// Policy-boolean attributes (`CKA_*` names) observed present-and-true
    /// on at least one call.
    observed_true: Vec<&'static str>,
    /// Observed present-and-false on at least one call. Independent of
    /// `observed_true` — a name can legitimately appear in both when
    /// different calls asked for different values. A name absent from
    /// both lists was never present in a requested template at all in
    /// this capture — a real three-state, not a boolean default.
    observed_false: Vec<&'static str>,
}

/// One template-bearing operation (`C_FindObjectsInit`, `C_CreateObject`,
/// `C_GenerateKey`, ...). Every field here is what the application
/// **requested** via its `CK_ATTRIBUTE` template — never the key's
/// effective policy, which the provider may reject, ignore, or override.
/// See `templates.note` in the top-level document and
/// `docs/schema/observed-profile-v2.md`.
#[derive(Serialize)]
struct TemplateOut {
    names: Vec<String>,
    aliased: bool,
    role: Option<&'static str>,
    /// Always `true`: an explicit, unambiguous marker (not just prose)
    /// that every field below is a request, never an effective policy.
    requested: bool,
    /// Union of attribute *types* requested across every observed call
    /// for this operation — never a value, except the policy booleans
    /// below.
    attr_types: Vec<AttrTypeOut>,
    policy_booleans: PolicyBooleansOut,
    /// True when any observed call had `attr_total > attr_count` — a
    /// template longer than the capture's per-event cap. Also forces
    /// `evidence.templates_truncated` and `completeness: PARTIAL`.
    truncated: bool,
}

fn templates_out(state: &crate::semantics::State) -> Vec<TemplateOut> {
    state
        .templates()
        .values()
        .map(|t| TemplateOut {
            names: t.names.clone(),
            aliased: t.aliased,
            role: t.role,
            requested: true,
            attr_types: t
                .attr_types
                .iter()
                .map(|&ty| AttrTypeOut {
                    attr_type: ty,
                    attr_type_hex: format!("0x{ty:x}"),
                })
                .collect(),
            policy_booleans: PolicyBooleansOut {
                observed_true: POLICY_BOOL_NAMES
                    .iter()
                    .filter(|(bit, _)| t.bools_true & bit != 0)
                    .map(|(_, name)| *name)
                    .collect(),
                observed_false: POLICY_BOOL_NAMES
                    .iter()
                    .filter(|(bit, _)| t.bools_false & bit != 0)
                    .map(|(_, name)| *name)
                    .collect(),
            },
            truncated: t.truncated,
        })
        .collect()
}

#[derive(Serialize)]
struct SessionsOut {
    opened: u64,
    inherited: u64,
    closed: u64,
    async_opened: u64,
    peak_concurrent: u64,
    /// `opened + inherited - closed`: tracked arithmetic balance at capture end.
    balance: u64,
}

/// One mechanism id's calls/errors, scoped to one cgroup —
/// `semantics::MechCallStat` rendered.
#[derive(Serialize)]
struct CgroupMechOut {
    mechanism: u64,
    mechanism_hex: String,
    /// The `CKM_*` name when the id is a known standard or listed
    /// vendor mechanism, else null — never guessed. Same meaning as
    /// the top-level rows' `name`.
    name: Option<&'static str>,
    /// The BPF return path found this id in `MECH_SHAPE` (registry
    /// membership). `false` marks an unregistered publication:
    /// numeric id plus call/error counts only, never decoded — the
    /// same flag as the top-level `mechanisms[]` rows, independent of
    /// the display-only name above.
    registered: bool,
    calls: u64,
    errors: u64,
}

/// One `cgroup_id`'s breakdown — `semantics::CgroupStat` rendered. Exists
/// so one node-wide attach over a cgroup shared by several containers/pods
/// (e.g. two sharing one overlay2 image layer, hence one inode) can still
/// be split back out per container: see `docs/schema/observed-profile-v2.md`
/// and `docs/privacy/allowlist-v1.md`'s `cgroup_id` entry.
#[derive(Serialize)]
struct CgroupOut {
    /// The raw kernel cgroup id — a directory inode number, not a
    /// sensitive value (see the allowlist doc). Verbatim, so a consumer
    /// can cross-reference it against its own container/pod inventory.
    cgroup_id: u64,
    /// Best-effort label resolved by matching `cgroup_id` against
    /// `/sys/fs/cgroup` directory inodes at report time (`scope::label`).
    /// `null` when it cannot be resolved — e.g. the cgroup was already
    /// removed by report time (container exited mid-capture). Absent is
    /// fine; this never guesses, so a present label is always trustworthy.
    label: Option<String>,
    /// Plain workload label parsed from the resolved path
    /// ([`crate::caller_metadata::workload_label_for_cgroup_path`]):
    /// pod UID + container id, lone container id, systemd unit, or the
    /// raw path for unknown shapes. `null` exactly when `label` is.
    workload: Option<String>,
    /// Every event observed with this `cgroup_id`, regardless of kind.
    calls: u64,
    errors: u64,
    /// Calls counted for events whose process missed admission (including
    /// a zero identity cookie, a zero pid, a stale exec generation, a full
    /// history registry, or a closed generation): a subset of `calls`
    /// above, grouped per pod/unit in `-v` text.
    unadmitted: u64,
    /// The subset of `calls` a mechanism could be attributed to.
    mechanisms: Vec<CgroupMechOut>,
}

fn cgroups_out(state: &crate::semantics::State) -> Vec<CgroupOut> {
    cgroups_out_with_live_root(state, std::path::Path::new("/sys/fs/cgroup"))
}

/// [`cgroups_out`] against an explicit live root: the test seam. The
/// live walk runs under `live_root`, so fixture cgroups resolve
/// without touching the host's `/sys/fs/cgroup`.
fn cgroups_out_with_live_root(
    state: &crate::semantics::State,
    live_root: &std::path::Path,
) -> Vec<CgroupOut> {
    state
        .cgroups()
        .iter()
        .map(|(&cgroup_id, c)| {
            // Live first (current truth), retained fallback (exited
            // pods under churn); never a guess either way.
            let label = crate::scope::label(live_root, cgroup_id)
                .or_else(|| state.retained_cgroup_path(cgroup_id));
            let workload = label
                .as_deref()
                .map(crate::caller_metadata::workload_label_for_cgroup_path);
            CgroupOut {
                cgroup_id,
                label,
                workload,
                calls: c.calls,
                errors: c.errors,
                unadmitted: c.unadmitted,
                mechanisms: c
                    .mechanisms
                    .iter()
                    .map(|(&mechanism, m)| CgroupMechOut {
                        mechanism,
                        mechanism_hex: format!("0x{mechanism:x}"),
                        name: mechanism_name(mechanism),
                        registered: !m.unregistered,
                        calls: m.calls,
                        errors: m.errors,
                    })
                    .collect(),
            }
        })
        .collect()
}

/// `-v` per-cgroup section for the final profile frame: one row per
/// cgroup with its workload label and counts, unknown paths degraded
/// to their numeric id, and kernel-dropped completions named as
/// unattributable. Empty when the state holds no cgroup rows.
/// Renders from the same rows the JSON report carries, so text and
/// JSON cannot drift.
pub(crate) fn cgroup_verbose_section(state: &crate::semantics::State, ev: &Evidence) -> String {
    cgroup_verbose_section_with_live_root(state, ev, std::path::Path::new("/sys/fs/cgroup"))
}

/// [`cgroup_verbose_section`] against an explicit live root: the test
/// seam. Fixture cgroups resolve without touching the host's
/// `/sys/fs/cgroup`, so a fixture inode can never collide with a live
/// host cgroup id.
fn cgroup_verbose_section_with_live_root(
    state: &crate::semantics::State,
    ev: &Evidence,
    live_root: &std::path::Path,
) -> String {
    let rows = cgroups_out_with_live_root(state, live_root);
    if rows.is_empty() {
        return String::new();
    }
    let mut out = format!("Cgroups ({}):\n", rows.len());
    let mut missed = 0u64;
    for row in rows {
        missed = missed.saturating_add(row.unadmitted);
        let name = row
            .workload
            .unwrap_or_else(|| format!("cgroup {} (unknown)", row.cgroup_id));
        let mut line = format!(
            "  {}: {} calls, {} errors",
            escape_controls(&name),
            row.calls,
            row.errors
        );
        if row.unadmitted > 0 {
            line.push_str(&format!(", {} unadmitted", row.unadmitted));
        }
        out.push_str(&line);
        out.push('\n');
    }
    if missed > 0 || ev.semantic_capture_failures > 0 || ev.kernel_control.identity_unavailable > 0
    {
        out.push_str(&format!(
            "  ({} calls above missed process admission; {} semantic capture failures, {} kernel identity refusals; dropped calls carry no per-pod data)\n",
            missed, ev.semantic_capture_failures, ev.kernel_control.identity_unavailable
        ));
    }
    out
}

/// `capture` section fields that aren't derived from `reports`/`ev`/`state`.
/// The discovered modules are not among them: they come from `ev.discovery`.
pub struct CaptureMeta<'a> {
    pub started: &'a str,
    pub ended: &'a str,
    pub kernel: &'a str,
    pub policy: CapturePolicy,
    /// Capture scope kind: `pid`, `cgroup`, or `system` (`Scope::kind`).
    pub scope: &'static str,
    /// The pid-scope target's caller identity, resolved at attach time.
    /// `None` for aggregate scopes (cgroup/system), which name no single
    /// caller by design. The renderer emits `capture.caller` only for
    /// pid scope with `Some`, so a stray `Some` can never leak a caller
    /// into an aggregate document.
    pub caller: Option<CaptureCaller>,
    /// Effective EVENTS ringbuf size in bytes (`--ring-bytes` or default).
    pub ring_bytes: u32,
    /// Effective capture-loop tick in ms (`--drain-interval-ms` or default).
    pub drain_interval_ms: u64,
}

/// The pid-scope target's caller identity: the `/proc/<pid>/exe` link
/// text read at attach time, or the finite reason it could not be read.
/// Exactly one of the two is `Some`. No PID number is carried: profile
/// and metrics reports do not publish raw PID/TID (allowlist v1); the
/// operator's own target pid is named on stderr diagnostics only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureCaller {
    /// Target executable path, lossy UTF-8 from the exe link.
    pub exe: Option<String>,
    /// Finite reason when `exe` is `None`, else `None`.
    pub exe_unknown_reason: Option<&'static str>,
}

/// `capture.caller`, present if and only if this is a pid-scope capture
/// with resolved caller identity: `{exe, exe_unknown_reason}` with
/// exactly one non-null. Aggregate scopes emit no key — absent, never
/// null — and neither does a pid scope that resolved nothing.
fn caller_out(scope: &str, caller: Option<&CaptureCaller>) -> Option<serde_json::Value> {
    if scope != "pid" {
        return None;
    }
    let caller = caller?;
    Some(serde_json::json!({
        "exe": caller.exe.as_deref(),
        "exe_unknown_reason": caller.exe_unknown_reason,
    }))
}

/// The v2 `observed-profile.json` document. `functions` comes from the
/// aggregate maps (count authority); `mechanisms`/`sessions`/`logins`/
/// `cgroups` come from the semantic state machine, the only place that
/// reconstructs mechanism/session/login/cgroup context from the event
/// stream.
pub fn profile_json(
    reports: &[SlotReport],
    versioned: VersionedEvidence<'_>,
    state: &crate::semantics::State,
    capture: &CaptureMeta,
) -> serde_json::Value {
    let ev = versioned.evidence();
    let forwarding = forwarding_module_ids(ev, reports);
    let mechanisms: Vec<MechanismOut> = state
        .mechanisms()
        .iter()
        .map(|(id, m)| {
            let combos: Vec<serde_json::Value> = m
                .param_combos
                .iter()
                .filter_map(|(&(sh, p0, p1, p2), &count)| param_combo_json(sh, p0, p1, p2, count))
                .collect();
            let (params, params_omitted, note) = if !capture.policy.uses_unsafe_decoders() {
                (
                    serde_json::Value::Null,
                    Some("policy"),
                    "parameter decoding was disabled by allowlisted capture policy",
                )
            } else if combos.is_empty() {
                if state.mech_shapes().contains_key(id) {
                    // A published shape exists for this id, but not one
                    // observed call decoded successfully — a total decode
                    // failure, never "not attempted" (see
                    // evidence.shape_decode_total_failures, which this
                    // mechanism forces nonzero).
                    (
                        serde_json::Value::Null,
                        Some("decode_failed"),
                        "this mechanism has a diagnostic parameter shape, but every decode \
                         attempt failed in this capture (see \
                         evidence.shape_decode_total_failures and \
                         evidence.shape_decode_failures); any successfully decoded values would \
                         be unvalidated pointer-derived metadata — never a partial decode",
                    )
                } else {
                    (
                        serde_json::Value::Null,
                        Some("no_shape"),
                        "this mechanism has no published diagnostic parameter shape; \
                         unvalidated pointer-derived decoding was not attempted, never a \
                         partial decode",
                    )
                }
            } else {
                (
                    serde_json::Value::Array(combos),
                    None,
                    "unvalidated pointer-derived metadata (RSA-PSS hash/MGF/salt, GCM \
                     IV/AAD/tag length); requested values as passed to the operation, never a \
                     partial decode",
                )
            };
            // Per-provider partition, resolved through the discovery
            // list exactly like `functions[].module`: an entry whose
            // module the document does not name is skipped, never
            // fabricated, so the row totals stay authoritative.
            let by_module: Vec<ByModuleOut> = m
                .by_module
                .iter()
                .filter_map(|(id, cell)| {
                    ev.discovery
                        .modules
                        .iter()
                        .find(|module| module.id == *id)
                        .map(|found| ByModuleOut {
                            module: ModuleRef {
                                dev: found.dev,
                                ino: found.ino,
                                sha256: found.sha256.clone(),
                            },
                            calls: cell.calls,
                            errors: cell.errors,
                        })
                })
                .collect();
            MechanismOut {
                mechanism: *id,
                mechanism_hex: format!("0x{id:x}"),
                name: mechanism_name(*id),
                registered: !m.unregistered,
                attribution_basis: if m.attributed_standard_layout && !m.attributed_confirmed {
                    "standard_layout"
                } else {
                    "manifest"
                },
                ops: m.ops.iter().cloned().collect(),
                calls: m.calls,
                errors: m.errors,
                latency_ns: latency_out(&m.buckets, m.total_ns, m.max_ns),
                params,
                params_omitted,
                note,
                by_module,
            }
        })
        .collect();
    let sessions = state.sessions();
    let sessions_out = SessionsOut {
        opened: sessions.opened,
        inherited: sessions.inherited,
        closed: sessions.closed,
        async_opened: sessions.async_opened,
        peak_concurrent: sessions.peak_concurrent,
        balance: sessions
            .opened
            .saturating_add(sessions.inherited)
            .saturating_sub(sessions.closed),
    };
    let logins: std::collections::BTreeMap<String, u64> = state
        .logins()
        .iter()
        .map(|(user_type, n)| (user_type.to_string(), *n))
        .collect();
    let templates = if capture.policy.uses_unsafe_decoders() {
        templates_out(state)
    } else {
        Vec::new()
    };

    let mut document = serde_json::json!({
        "schema": "p11scope/observed-profile/v3",
        // Machine-readable lane discriminator (SYSPLAN residual F-12): the
        // profile lane carries the four versioned-only evidence fields with
        // a selection-aware verdict.
        "lane": "profile",
        "capture": {
            "start": capture.started, "end": capture.ended, "mode": "profile",
            "privacy_mode": capture.policy.privacy_mode(),
            "scope": capture.scope,
            "kernel": capture.kernel,
            "ring_bytes": capture.ring_bytes,
            "drain_interval_ms": capture.drain_interval_ms,
            "modules": capture_modules(ev),
        },
        "evidence": versioned.value().clone(),
        "functions": functions_out(reports, &ev.discovery.modules, &forwarding),
        "layer_totals": layer_totals_json(reports, &forwarding, &ev.discovery.modules),
        "mechanisms": mechanisms,
        "sessions": sessions_out,
        "logins": logins,
        "templates": {
            "note": if capture.policy.uses_unsafe_decoders() {
                "unvalidated pointer-derived metadata: every field here is what the application \
                 asked for via a CK_ATTRIBUTE template — never asserted as the key's effective \
                 policy; the provider may reject, ignore, or override any of it (see the \
                 `requested` marker on each operation)"
            } else {
                "template capture was disabled by allowlisted capture policy; an empty operation \
                 list is not evidence that no template was used"
            },
            "operations": templates,
        },
        "cgroups": cgroups_out(state),
    });
    if let Some(caller) = caller_out(capture.scope, capture.caller.as_ref()) {
        document["capture"]["caller"] = caller;
    }
    document
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p11scope_ebpf_common::{CounterMode, LATENCY_BUCKETS, shape};

    /// One evidence mutation for the table-driven gate pins below.
    type EvidenceMutation = fn(&mut Evidence);

    /// Task 11 fix round 2 (csf_b8067e3 sibling): the C1 range — the raw 8-bit
    /// CSI U+009B above all — is escaped exactly like C0 and DEL, and legitimate
    /// non-ASCII pathnames pass through untouched. Pinned so an ASCII-only
    /// control check cannot silently re-open raw 8-bit CSI.
    #[test]
    fn escape_controls_rewrites_c0_del_and_c1_only() {
        assert_eq!(
            escape_controls("a\u{9b}b\u{85}c\u{7f}d\u{1}e\u{1b}[2Jf\rg"),
            r"a\u{9b}b\u{85}c\u{7f}d\u{1}e\u{1b}[2Jf\rg"
        );
        assert!(matches!(
            escape_controls("/opt/p11-ключ-é.so"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    fn report(name: &str, calls: u64, in_flight: u64, aliased: bool) -> SlotReport {
        SlotReport {
            file_offset: 0,
            target_object: None,
            ordinals: Vec::new(),
            names: vec![name.into()],
            aliased,
            semantic_authorized: true,
            module: None,
            module_ambiguous: false,
            module_unresolved: false,
            mode: CounterMode::Latency,
            calls,
            errors: 0,
            in_flight,
            total_ns: 0,
            max_ns: 0,
            buckets: [0; LATENCY_BUCKETS],
            rv_counts: Default::default(),
        }
    }

    #[test]
    fn counter_modes_render_their_timing_availability() {
        use p11scope_ebpf_common::bucket_of;
        let capture = CaptureMeta {
            policy: CapturePolicy::AggregateOnly,
            ..capture_fixture()
        };
        for (mode, latency) in [
            (CounterMode::Counts, serde_json::Value::Null),
            (
                CounterMode::Timestamps,
                serde_json::json!({
                    "approximate": false, "p50": null, "p95": null, "p99": null,
                    "total": 2_500, "max": 100,
                }),
            ),
            (
                CounterMode::Latency,
                serde_json::json!({
                    "approximate": true, "p50": 64, "p95": 64, "p99": 64,
                    "total": 2_500, "max": 100,
                }),
            ),
        ] {
            let mut row = report("C_Sign", 25, 2, false);
            row.mode = mode;
            row.errors = 3;
            row.total_ns = 2_500;
            row.max_ns = 100;
            row.buckets[bucket_of(100) as usize] = 25;
            row.rv_counts.insert(0, 22);
            row.rv_counts.insert(5, 3);
            let output = json(&[row], &evidence(), &capture);
            let functions = output["functions"].as_array().unwrap();
            assert_eq!(functions.len(), 1);
            assert_eq!(functions[0]["latency_ns"], latency, "{mode:?}");
            assert_eq!(functions[0]["calls"], 25);
            assert_eq!(functions[0]["errors"], 3);
            assert_eq!(functions[0]["in_flight"], 2);
            assert_eq!(
                functions[0]["rv_counts"],
                serde_json::json!({"0x0000000000000000": 22, "0x0000000000000005": 3})
            );
        }
    }

    #[test]
    fn counter_timing_ignores_unavailable_fields_and_preserves_measured_zero() {
        use p11scope_ebpf_common::bucket_of;
        let capture = CaptureMeta {
            policy: CapturePolicy::AggregateOnly,
            ..capture_fixture()
        };
        let mut row = report("C_Sign", 25, 0, false);
        row.mode = CounterMode::Counts;
        row.total_ns = u64::MAX;
        row.max_ns = u64::MAX;
        row.buckets[bucket_of(100) as usize] = 25;
        assert!(
            json(&[row.clone()], &evidence(), &capture)["functions"][0]["latency_ns"].is_null()
        );

        row.mode = CounterMode::Timestamps;
        row.total_ns = 0;
        row.max_ns = 0;
        assert_eq!(
            json(&[row.clone()], &evidence(), &capture)["functions"][0]["latency_ns"],
            serde_json::json!({
                "approximate": false, "p50": null, "p95": null, "p99": null,
                "total": 0, "max": 0,
            })
        );

        row.mode = CounterMode::Latency;
        row.buckets = [0; LATENCY_BUCKETS];
        row.buckets[0] = 25;
        assert_eq!(
            json(&[row], &evidence(), &capture)["functions"][0]["latency_ns"],
            serde_json::json!({
                "approximate": true, "p50": 0, "p95": 0, "p99": 0,
                "total": 0, "max": 0,
            })
        );
    }

    #[test]
    fn human_counter_percentiles_follow_capability_with_poisoned_buckets() {
        use p11scope_ebpf_common::bucket_of;
        for (mode, expected) in [
            (CounterMode::Counts, "—"),
            (CounterMode::Timestamps, "—"),
            (CounterMode::Latency, "64ns"),
        ] {
            let mut row = report("C_Sign", 25, 2, false);
            row.mode = mode;
            row.errors = 3;
            row.buckets[bucket_of(100) as usize] = 25;
            let output = live(
                &[row],
                &evidence(),
                Duration::from_secs(1),
                "/owned/provider.so",
                "metrics",
                CapturePolicy::AggregateOnly,
            );
            let fields: Vec<_> = output
                .lines()
                .find(|line| line.starts_with("C_Sign "))
                .unwrap()
                .split_whitespace()
                .collect();
            assert_eq!(
                fields,
                [
                    "C_Sign", "unknown", "25", "3", expected, expected, expected, "2"
                ],
                "{mode:?}"
            );
        }
    }

    #[test]
    fn protected_counter_snapshot_adapters_preserve_legacy_outputs() {
        for profile in [false, true] {
            let snapshot = crate::metrics::ConsumerFixture::ordinary_snapshot(profile);
            let mut ev = evidence();
            ev.verdict_with_selection(profile);
            let before = serde_json::to_value(&ev).unwrap();
            apply_counter_snapshot(&mut ev, &snapshot);
            assert_eq!(serde_json::to_value(&ev).unwrap(), before);
            let capture = capture_fixture();
            let document = if profile {
                profile_json(
                    snapshot.reports(),
                    VersionedEvidence::wrap(&ev),
                    &state_fixture(),
                    &capture,
                )
            } else {
                json(snapshot.reports(), &ev, &capture)
            };
            assert_eq!(with_counter_snapshot(document.clone(), &snapshot), document);
            assert_eq!(
                live_snapshot_scoped(
                    &snapshot,
                    &ev,
                    Duration::ZERO,
                    "owned",
                    "profile",
                    capture.policy,
                    "pid",
                    &BTreeMap::new(),
                    None,
                    &crate::semantics::SessionStats::default(),
                    &BTreeMap::new()
                ),
                live_scoped(
                    snapshot.reports(),
                    &ev,
                    Duration::ZERO,
                    "owned",
                    "profile",
                    capture.policy,
                    "pid",
                    &BTreeMap::new()
                ),
            );
            assert!(
                !versioned_evidence(&ev)
                    .as_object()
                    .unwrap()
                    .contains_key("counter_collection")
            );
        }
    }

    #[test]
    fn protected_counter_snapshot_metadata_uses_actual_modes_and_aggregate_totals() {
        let mut detail =
            crate::semantics::State::with_policy(&init_plan(), CapturePolicy::Allowlisted);
        let mut event = init_event(0, 0x0D, shape::NONE, 0, 0, 0);
        event.cgroup_id = 111;
        detail.observe(&event);
        detail.observe(&event);
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let mut fixture = crate::metrics::ConsumerFixture::new();
            let snapshot = fixture.fresh(mode, 1, 5, None).unwrap();
            let mut ev = evidence();
            ev.verdict_with_selection(false);
            let before = serde_json::to_value(&ev).unwrap();
            apply_counter_snapshot(&mut ev, &snapshot);
            assert_eq!(serde_json::to_value(&ev).unwrap(), before);
            for profile in [false, true] {
                let capture = capture_fixture();
                let document = if profile {
                    profile_json(
                        snapshot.reports(),
                        VersionedEvidence::wrap(&ev),
                        &detail,
                        &capture,
                    )
                } else {
                    json(snapshot.reports(), &ev, &capture)
                };
                let document = with_counter_snapshot(document, &snapshot);
                assert_eq!(
                    document["evidence"]["counter_collection"],
                    snapshot.counter_collection().unwrap()
                );
                assert_eq!(
                    document["evidence"]["counter_collection"]["mode"],
                    mode.name()
                );
                assert_eq!(document["functions"][0]["calls"], 5);
                if profile {
                    assert_eq!(
                        document["cgroups"][0]["calls"], 2,
                        "selected detail is nonempty"
                    );
                }
                let timing = &document["functions"][0]["latency_ns"];
                if mode == CounterMode::Counts {
                    assert!(timing.is_null());
                } else if mode == CounterMode::Timestamps {
                    assert_eq!(timing["total"], 500);
                    assert!(timing["p50"].is_null());
                } else {
                    assert_eq!(timing["total"], 500);
                    assert!(!timing["p50"].is_null());
                }
            }
        }
    }

    #[test]
    fn protected_counter_failures_and_discontinuity_cannot_render_complete() {
        for fault in [
            crate::metrics::ConsumerFault::Saturated,
            crate::metrics::ConsumerFault::Contended,
        ] {
            let mut fixture = crate::metrics::ConsumerFixture::new();
            fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
            let stale = fixture
                .fresh(CounterMode::Counts, 1, 8, Some(fault))
                .unwrap();
            let mut ev = evidence();
            ev.verdict_with_selection(false);
            let attribution = ev.gap_classes.attribution.clone();
            let semantics = ev.gap_classes.semantics.clone();
            apply_counter_snapshot(&mut ev, &stale);
            apply_counter_snapshot(&mut ev, &stale);
            assert_eq!(ev.completeness, "PARTIAL");
            assert_eq!(ev.verdict_detail, VERDICT_CONCRETE_GAP);
            assert_eq!(
                ev.gap_classes
                    .observation
                    .causes
                    .iter()
                    .filter(|&&cause| cause == "counter_collection")
                    .count(),
                1
            );
            assert_eq!(ev.gap_classes.attribution, attribution);
            assert_eq!(ev.gap_classes.semantics, semantics);
            let frame = live_snapshot_scoped(
                &stale,
                &ev,
                Duration::ZERO,
                "owned",
                "metrics",
                CapturePolicy::AggregateOnly,
                "pid",
                &BTreeMap::new(),
                None,
                &crate::semantics::SessionStats::default(),
                &BTreeMap::new(),
            );
            assert!(frame.contains("last read stale"), "{frame}");
            assert!(frame.contains("coverage: partial"), "{frame}");
            let document =
                with_counter_snapshot(json(stale.reports(), &ev, &capture_fixture()), &stale);
            assert!(document["evidence"]["counter_collection"]["health"].is_null());
            assert_eq!(document["functions"][0]["calls"], 5);
        }
        let mut fixture = crate::metrics::ConsumerFixture::new();
        fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
        let changed = fixture.terminal(CounterMode::Counts, 2, 8, None).unwrap();
        let mut ev = evidence();
        ev.settle_terminal(false);
        apply_counter_snapshot(&mut ev, &changed);
        assert_eq!(ev.completeness, "PARTIAL");
        assert_eq!(ev.verdict_detail, VERDICT_CONCRETE_GAP);
        assert_eq!(changed.counter_collection().unwrap()["status"], "fresh");
        assert_eq!(changed.counter_collection().unwrap()["discontinuity"], true);
    }

    fn ok_surface() -> crate::plan::SurfaceSummary {
        crate::plan::SurfaceSummary {
            source: "legacy_function_list".into(),
            walk: "full".into(),
            acquisition: "ok".into(),
            functions: 68,
        }
    }

    pub(crate) fn evidence() -> Evidence {
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
            surfaces: vec![ok_surface()],
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
            ring_accounting: RingAccountingEvidence::unknown(),
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
            object_capture: ObjectCaptureEvidence::for_build(false),
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
            discovery: DiscoveryEvidence {
                modules: vec![discovered_fixture()],
                ..DiscoveryEvidence::default()
            },
            scheduling: SchedulingEvidence::default(),
            stop_quiescence: Default::default(),
            drain_proven: false,
            verdict_detail: VERDICT_CONCRETE_GAP,
            gap_classes: GapClasses::default(),
            stdout_data_sink: false,
            trace_truncated: false,
            uretprobe_override: None,
            handoff_child_pid: None,
            pid_namespace: crate::pidns::PidNamespaceEvidence::of(
                &crate::pidns::PidNumbering::agreeing(),
            ),
            container_only_view: false,
            p11scope_env: vec![],
            completeness: "UNKNOWN",
        }
    }

    fn selection_tuple(rv: u64, result: bool, authority: SelectionAuthority) -> SelectionTuple {
        let request = SelectionRequest {
            name: p11scope_manifest::manifest::SelectionNameClass::ExactStandard,
            version: p11scope_manifest::manifest::SelectionVersionClass::V3_0,
            flags: 0,
        };
        SelectionTuple {
            module: 0,
            request,
            rv,
            result: result.then_some(request),
            table_match: false,
            inventory_matches: vec![],
            authority,
            count: 1,
        }
    }

    #[test]
    fn profile_v3_selection_contract_is_exact() {
        let ev = evidence();
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );

        assert_eq!(profile["schema"], "p11scope/observed-profile/v3");
        assert_eq!(
            profile["evidence"]["interface_selection"],
            serde_json::json!({
                "providers": [],
                "standard_exports": [],
                "inventory_surfaces": [],
                "tuples": [],
                "selection_truncated": false,
            })
        );
        assert_eq!(
            profile["evidence"]["attach_mechanisms"],
            serde_json::json!([])
        );
        assert_eq!(
            profile["evidence"]["attach_backend"],
            serde_json::json!({"selection": "auto", "fallback": null, "scope_filter": null})
        );
        assert_eq!(profile["evidence"]["pid_descendant_gaps"], 0);
        assert_eq!(profile["evidence"]["multi_rebuild_gaps"], 0);
        // Disarmed: the split key is absent, never null.
        assert!(profile["evidence"].get("gap_exe_hints").is_none());

        let metrics = json(&reports_fixture(), &ev, &capture_fixture());
        assert_eq!(metrics["schema"], "p11scope/observed-profile/v3-metrics");
        assert_eq!(
            metrics["evidence"]["attach_backend"],
            profile["evidence"]["attach_backend"]
        );
        for field in [
            "interface_selection",
            "attach_mechanisms",
            "pid_descendant_gaps",
            "multi_rebuild_gaps",
        ] {
            assert!(metrics["evidence"].get(field).is_none(), "{field}");
        }
    }

    #[test]
    fn profile_v3_gap_exe_hints_split_is_exact_when_armed() {
        let mut ev = evidence();
        ev.gap_exe_hints = Some(GapExeHints {
            links_provider: 2,
            links_pkcs11_loader: 1,
            no_static_link_within_scope: 4,
            unknown: 3,
        });
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        assert_eq!(
            profile["evidence"]["gap_exe_hints"],
            serde_json::json!({
                "label": "STATIC HINT",
                "scope": STATIC_HINT_SCOPE_D_TRANSITIVE,
                "links_provider": 2,
                "links_pkcs11_loader": 1,
                "no_static_link_within_scope": 4,
                "unknown": 3,
            })
        );
        // 7.10b: the metrics lane hoists the armed split with the
        // same closed shape the profile lane publishes.
        let metrics = json(&reports_fixture(), &ev, &capture_fixture());
        assert_eq!(
            metrics["evidence"]["gap_exe_hints"],
            profile["evidence"]["gap_exe_hints"]
        );
    }

    // 614b P2#5: the shares-unchanged twin over a nonzero observed
    // call/attribution surface. Both sides observe the same calls
    // through the semantic state machine and render the same slot
    // aggregates; only the hint evidence differs, so every rendered
    // call, mechanism, cgroup-attribution, verdict and completeness
    // surface must be identical.
    #[test]
    fn profile_v3_gap_exe_hints_do_not_move_call_or_attribution_surfaces() {
        use p11scope_ebpf_common::shape;

        let observed_state = || {
            let mut state =
                crate::semantics::State::with_policy(&init_plan(), CapturePolicy::Allowlisted);
            let mut event = init_event(0, 0x0D, shape::NONE, 0, 0, 0);
            event.cgroup_id = 111;
            state.observe(&event);
            state.observe(&event);
            state.observe(&event);
            state
        };
        let reports = || {
            let mut sign = report("C_Sign", 25, 2, false);
            sign.module = Some(crate::plan::ModuleId(0));
            sign.errors = 3;
            sign.total_ns = 2_500;
            sign.max_ns = 100;
            sign.rv_counts.insert(0, 22);
            sign.rv_counts.insert(5, 3);
            let mut encrypt = report("C_Encrypt", 7, 0, false);
            encrypt.module = Some(crate::plan::ModuleId(0));
            encrypt.rv_counts.insert(0, 7);
            vec![sign, encrypt]
        };
        let mut plain_ev = evidence();
        plain_ev.pid_descendant_gaps = 2;
        let mut armed_ev = evidence();
        armed_ev.pid_descendant_gaps = 2;
        armed_ev.gap_exe_hints = Some(GapExeHints {
            links_provider: 1,
            links_pkcs11_loader: 0,
            no_static_link_within_scope: 0,
            unknown: 1,
        });

        let plain = profile_json(
            &reports(),
            VersionedEvidence::wrap(&plain_ev),
            &observed_state(),
            &capture_fixture(),
        );
        let mut armed = profile_json(
            &reports(),
            VersionedEvidence::wrap(&armed_ev),
            &observed_state(),
            &capture_fixture(),
        );

        // Both controls really carry calls and attribution, and only
        // the armed side carries a nonzero hint split.
        let total_calls: u64 = plain["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|function| function["calls"].as_u64().unwrap())
            .sum();
        assert_eq!(total_calls, 32, "twin must observe nonzero calls");
        assert_eq!(plain["mechanisms"][0]["calls"], 3);
        assert_eq!(plain["cgroups"][0]["calls"], 3);
        assert_eq!(plain["cgroups"][0]["mechanisms"][0]["calls"], 3);
        assert!(plain["evidence"].get("gap_exe_hints").is_none());
        assert_eq!(armed["evidence"]["gap_exe_hints"]["links_provider"], 1);
        assert_eq!(armed["evidence"]["gap_exe_hints"]["unknown"], 1);

        // Call/attribution surfaces match exactly, field by field.
        for surface in ["functions", "mechanisms", "sessions", "logins", "cgroups"] {
            assert_eq!(armed[surface], plain[surface], "{surface} must not move");
        }
        assert_eq!(
            armed["evidence"]["completeness"], plain["evidence"]["completeness"],
            "completeness must not move"
        );
        assert_eq!(
            armed["evidence"]["verdict_detail"], plain["evidence"]["verdict_detail"],
            "verdict must not move"
        );
        assert_eq!(
            armed["evidence"]["pid_descendant_gaps"],
            plain["evidence"]["pid_descendant_gaps"]
        );

        // With the hint split removed, the whole documents are equal:
        // the hint evidence is the only difference anywhere.
        armed["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("gap_exe_hints");
        assert_eq!(armed, plain);
    }

    #[test]
    fn profile_v3_gap_exit_mappings_split_is_exact_when_armed() {
        let mut ev = evidence();
        ev.discovery.gap_exit_mappings = Some(GapExitMappings {
            mapped: 2,
            unknown: 3,
        });
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        assert_eq!(
            profile["evidence"]["gap_exit_mappings"],
            serde_json::json!({"mapped": 2, "unknown": 3})
        );
        // 7.10b: the metrics lane hoists the armed split with the
        // same closed shape the profile lane publishes.
        let metrics = json(&reports_fixture(), &ev, &capture_fixture());
        assert_eq!(
            metrics["evidence"]["gap_exit_mappings"],
            profile["evidence"]["gap_exit_mappings"]
        );
    }

    #[test]
    fn profile_v3_gap_exit_mappings_absent_unless_armed() {
        let ev = evidence();
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        assert!(profile["evidence"].get("gap_exit_mappings").is_none());
    }

    // The trace lane renders through the shared `versioned_evidence`
    // hoist, so an armed `Evidence` publishes the split key in a
    // trace terminal record too; 7.10b arms trace captures, so real
    // armed traces carry it.
    #[test]
    fn trace_evidence_line_hoists_armed_gap_exit_mappings() {
        let line_for = |ev: &Evidence| {
            let line = crate::trace::evidence_line(ev, crate::attach::CapturePolicy::Allowlisted);
            serde_json::from_str::<serde_json::Value>(line.strip_prefix("EVIDENCE ").unwrap())
                .unwrap()
        };
        let mut armed = evidence();
        armed.discovery.gap_exit_mappings = Some(GapExitMappings {
            mapped: 1,
            unknown: 2,
        });
        assert_eq!(
            line_for(&armed)["gap_exit_mappings"],
            serde_json::json!({"mapped": 1, "unknown": 2})
        );
        assert!(
            line_for(&evidence()).get("gap_exit_mappings").is_none(),
            "unarmed evidence omits the key in trace too"
        );
    }

    // The exit-mapping split is informational, never a call, share,
    // verdict, or completeness input: armed and plain renders of one
    // observed surface differ only in the split key itself.
    #[test]
    fn profile_v3_gap_exit_mappings_do_not_move_call_or_attribution_surfaces() {
        use p11scope_ebpf_common::shape;

        let observed_state = || {
            let mut state =
                crate::semantics::State::with_policy(&init_plan(), CapturePolicy::Allowlisted);
            let mut event = init_event(0, 0x0D, shape::NONE, 0, 0, 0);
            event.cgroup_id = 111;
            state.observe(&event);
            state.observe(&event);
            state.observe(&event);
            state
        };
        let reports = || {
            let mut sign = report("C_Sign", 25, 2, false);
            sign.module = Some(crate::plan::ModuleId(0));
            sign.errors = 3;
            sign.total_ns = 2_500;
            sign.max_ns = 100;
            sign.rv_counts.insert(0, 22);
            sign.rv_counts.insert(5, 3);
            let mut encrypt = report("C_Encrypt", 7, 0, false);
            encrypt.module = Some(crate::plan::ModuleId(0));
            encrypt.rv_counts.insert(0, 7);
            vec![sign, encrypt]
        };
        let mut plain_ev = evidence();
        plain_ev.pid_descendant_gaps = 2;
        let mut armed_ev = evidence();
        armed_ev.pid_descendant_gaps = 2;
        armed_ev.discovery.gap_exit_mappings = Some(GapExitMappings {
            mapped: 1,
            unknown: 1,
        });

        let plain = profile_json(
            &reports(),
            VersionedEvidence::wrap(&plain_ev),
            &observed_state(),
            &capture_fixture(),
        );
        let mut armed = profile_json(
            &reports(),
            VersionedEvidence::wrap(&armed_ev),
            &observed_state(),
            &capture_fixture(),
        );

        let total_calls: u64 = plain["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|function| function["calls"].as_u64().unwrap())
            .sum();
        assert_eq!(total_calls, 32, "twin must observe nonzero calls");
        assert!(plain["evidence"].get("gap_exit_mappings").is_none());
        assert_eq!(armed["evidence"]["gap_exit_mappings"]["mapped"], 1);
        assert_eq!(armed["evidence"]["gap_exit_mappings"]["unknown"], 1);

        for surface in ["functions", "mechanisms", "sessions", "logins", "cgroups"] {
            assert_eq!(armed[surface], plain[surface], "{surface} must not move");
        }
        assert_eq!(
            armed["evidence"]["completeness"], plain["evidence"]["completeness"],
            "completeness must not move"
        );
        assert_eq!(
            armed["evidence"]["verdict_detail"], plain["evidence"]["verdict_detail"],
            "verdict must not move"
        );
        assert_eq!(
            armed["evidence"]["pid_descendant_gaps"],
            plain["evidence"]["pid_descendant_gaps"]
        );

        armed["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("gap_exit_mappings");
        assert_eq!(armed, plain);
    }

    // 7.10b: the metrics lane carries both armed gap splits in its
    // evidence object, with the same closed shapes the profile lane
    // publishes.
    #[test]
    fn metrics_json_carries_armed_gap_splits() {
        let mut ev = evidence();
        ev.gap_exe_hints = Some(GapExeHints {
            links_provider: 2,
            links_pkcs11_loader: 1,
            no_static_link_within_scope: 4,
            unknown: 3,
        });
        ev.discovery.gap_exit_mappings = Some(GapExitMappings {
            mapped: 5,
            unknown: 6,
        });
        let metrics = json(&reports_fixture(), &ev, &capture_fixture());
        assert_eq!(
            metrics["evidence"]["gap_exe_hints"],
            serde_json::json!({
                "label": "STATIC HINT",
                "scope": STATIC_HINT_SCOPE_D_TRANSITIVE,
                "links_provider": 2,
                "links_pkcs11_loader": 1,
                "no_static_link_within_scope": 4,
                "unknown": 3,
            })
        );
        assert_eq!(
            metrics["evidence"]["gap_exit_mappings"],
            serde_json::json!({"mapped": 5, "unknown": 6})
        );
        // Disarmed: both keys absent, never null.
        let plain = json(&reports_fixture(), &evidence(), &capture_fixture());
        assert!(plain["evidence"].get("gap_exe_hints").is_none());
        assert!(plain["evidence"].get("gap_exit_mappings").is_none());
    }

    // 7.10b: the profile lane carries the armed target-exec split
    // with the same STATIC HINT shape as the gap split.
    #[test]
    fn profile_json_carries_armed_target_exec_hints() {
        let mut ev = evidence();
        ev.target_exec_hints = Some(GapExeHints {
            links_provider: 1,
            links_pkcs11_loader: 0,
            no_static_link_within_scope: 2,
            unknown: 0,
        });
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        assert_eq!(
            profile["evidence"]["target_exec_hints"],
            serde_json::json!({
                "label": "STATIC HINT",
                "scope": STATIC_HINT_SCOPE_D_TRANSITIVE,
                "links_provider": 1,
                "links_pkcs11_loader": 0,
                "no_static_link_within_scope": 2,
                "unknown": 0,
            })
        );
        // The gap keys stay independent: arming the PID consumer
        // publishes no gap split.
        assert!(profile["evidence"].get("gap_exe_hints").is_none());
        assert!(profile["evidence"].get("gap_exit_mappings").is_none());
        // Disarmed: the key absent, never null.
        let plain = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&evidence()),
            &state_fixture(),
            &capture_fixture(),
        );
        assert!(plain["evidence"].get("target_exec_hints").is_none());
    }

    // 7.10b: the metrics lane carries the armed target-exec split,
    // with the same closed shape as the profile lane.
    #[test]
    fn metrics_json_carries_armed_target_exec_hints() {
        let mut ev = evidence();
        ev.target_exec_hints = Some(GapExeHints {
            links_provider: 0,
            links_pkcs11_loader: 1,
            no_static_link_within_scope: 0,
            unknown: 2,
        });
        let metrics = json(&reports_fixture(), &ev, &capture_fixture());
        assert_eq!(
            metrics["evidence"]["target_exec_hints"],
            serde_json::json!({
                "label": "STATIC HINT",
                "scope": STATIC_HINT_SCOPE_D_TRANSITIVE,
                "links_provider": 0,
                "links_pkcs11_loader": 1,
                "no_static_link_within_scope": 0,
                "unknown": 2,
            })
        );
        let plain = json(&reports_fixture(), &evidence(), &capture_fixture());
        assert!(plain["evidence"].get("target_exec_hints").is_none());
    }

    // 7.10b: the trace lane renders through the shared
    // `versioned_evidence` hoist, so an armed `Evidence` publishes
    // the target key in a trace terminal record too.
    #[test]
    fn trace_evidence_line_hoists_armed_target_exec_hints() {
        let line_for = |ev: &Evidence| {
            let line = crate::trace::evidence_line(ev, crate::attach::CapturePolicy::Allowlisted);
            serde_json::from_str::<serde_json::Value>(line.strip_prefix("EVIDENCE ").unwrap())
                .unwrap()
        };
        let mut armed = evidence();
        armed.target_exec_hints = Some(GapExeHints {
            links_provider: 1,
            links_pkcs11_loader: 1,
            no_static_link_within_scope: 1,
            unknown: 1,
        });
        assert_eq!(
            line_for(&armed)["target_exec_hints"],
            serde_json::json!({
                "label": "STATIC HINT",
                "scope": STATIC_HINT_SCOPE_D_TRANSITIVE,
                "links_provider": 1,
                "links_pkcs11_loader": 1,
                "no_static_link_within_scope": 1,
                "unknown": 1,
            })
        );
        assert!(
            line_for(&evidence()).get("target_exec_hints").is_none(),
            "unarmed evidence omits the key in trace too"
        );
    }

    // 7.10b twin: arming the gap splits in metrics never moves the
    // call or layer surfaces. The armed side must carry the keys
    // first (otherwise this passes by missing the feature), then
    // every other surface must match the plain twin exactly.
    #[test]
    fn metrics_armed_gap_splits_do_not_move_call_or_layer_surfaces() {
        let reports = || {
            let mut sign = report("C_Sign", 25, 2, false);
            sign.module = Some(crate::plan::ModuleId(0));
            sign.errors = 3;
            sign.total_ns = 2_500;
            sign.max_ns = 100;
            sign.rv_counts.insert(0, 22);
            sign.rv_counts.insert(5, 3);
            vec![sign]
        };
        let mut plain_ev = evidence();
        plain_ev.pid_descendant_gaps = 2;
        let mut armed_ev = evidence();
        armed_ev.pid_descendant_gaps = 2;
        armed_ev.gap_exe_hints = Some(GapExeHints {
            links_provider: 1,
            links_pkcs11_loader: 0,
            no_static_link_within_scope: 0,
            unknown: 1,
        });
        armed_ev.discovery.gap_exit_mappings = Some(GapExitMappings {
            mapped: 1,
            unknown: 1,
        });
        let plain = json(&reports(), &plain_ev, &capture_fixture());
        let mut armed = json(&reports(), &armed_ev, &capture_fixture());
        // Both controls carry calls, and only the armed side carries
        // the splits.
        assert_eq!(plain["functions"][0]["calls"], 25);
        assert_eq!(armed["evidence"]["gap_exe_hints"]["links_provider"], 1);
        assert_eq!(armed["evidence"]["gap_exit_mappings"]["mapped"], 1);
        assert!(plain["evidence"].get("gap_exe_hints").is_none());
        assert!(plain["evidence"].get("gap_exit_mappings").is_none());
        for surface in ["functions", "layer_totals"] {
            assert_eq!(armed[surface], plain[surface], "{surface} must not move");
        }
        assert_eq!(
            armed["evidence"]["completeness"], plain["evidence"]["completeness"],
            "completeness must not move"
        );
        armed["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("gap_exe_hints");
        armed["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("gap_exit_mappings");
        assert_eq!(armed, plain);
    }

    // 7.10b twin: arming the target-exec split in profile never moves
    // the call or attribution surfaces. The armed side must carry the
    // key first, then every other surface must match exactly.
    #[test]
    fn profile_target_exec_hints_do_not_move_call_or_attribution_surfaces() {
        use p11scope_ebpf_common::shape;

        let observed_state = || {
            let mut state =
                crate::semantics::State::with_policy(&init_plan(), CapturePolicy::Allowlisted);
            let mut event = init_event(0, 0x0D, shape::NONE, 0, 0, 0);
            event.cgroup_id = 111;
            state.observe(&event);
            state.observe(&event);
            state.observe(&event);
            state
        };
        let reports = || {
            let mut sign = report("C_Sign", 25, 2, false);
            sign.module = Some(crate::plan::ModuleId(0));
            sign.errors = 3;
            sign.total_ns = 2_500;
            sign.max_ns = 100;
            sign.rv_counts.insert(0, 22);
            sign.rv_counts.insert(5, 3);
            vec![sign]
        };
        let plain_ev = evidence();
        let mut armed_ev = evidence();
        armed_ev.target_exec_hints = Some(GapExeHints {
            links_provider: 1,
            links_pkcs11_loader: 0,
            no_static_link_within_scope: 0,
            unknown: 0,
        });
        let plain = profile_json(
            &reports(),
            VersionedEvidence::wrap(&plain_ev),
            &observed_state(),
            &capture_fixture(),
        );
        let mut armed = profile_json(
            &reports(),
            VersionedEvidence::wrap(&armed_ev),
            &observed_state(),
            &capture_fixture(),
        );
        assert_eq!(plain["functions"][0]["calls"], 25);
        assert_eq!(armed["evidence"]["target_exec_hints"]["links_provider"], 1);
        assert!(plain["evidence"].get("target_exec_hints").is_none());
        for surface in ["functions", "mechanisms", "sessions", "logins", "cgroups"] {
            assert_eq!(armed[surface], plain[surface], "{surface} must not move");
        }
        assert_eq!(
            armed["evidence"]["completeness"], plain["evidence"]["completeness"],
            "completeness must not move"
        );
        assert_eq!(
            armed["evidence"]["verdict_detail"], plain["evidence"]["verdict_detail"],
            "verdict must not move"
        );
        armed["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("target_exec_hints");
        assert_eq!(armed, plain);
    }

    // B17 W2 RED: the v3 profile lane renders the ruled per-identity
    // disclosure key with the exact closed shape, without moving the
    // verdict: the disclosure is informational, never a PARTIAL cause.
    // The metrics lane stays blind to it (profile-only, like the hint
    // split above).
    #[test]
    fn profile_v3_reload_disclosure_renders_exact_shape_and_holds_complete() {
        use crate::semantic_capture::ReloadNotExcludedIdentity;

        let mut ev = evidence();
        ev.drain_proven = true;
        ev.instance_reload_not_excluded = Some(InstanceReloadNotExcluded {
            continued_across_global: 1,
            joined_across_global: 1,
            identities: vec![ReloadNotExcludedIdentity {
                file_slot: 0,
                ids: vec![1],
            }],
        });
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
        assert_eq!(ev.verdict_detail, VERDICT_CLEAN_PROVEN);
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        assert_eq!(
            profile["evidence"]["instance_reload_not_excluded"],
            serde_json::json!({
                "continued_across_global": 1,
                "joined_across_global": 1,
                "identities": [{"file_slot": 0, "ids": [1]}],
            })
        );
        assert_eq!(profile["evidence"]["completeness"], "COMPLETE");
        assert_eq!(profile["evidence"]["verdict_detail"], "clean_proven");
        let metrics = json(&reports_fixture(), &ev, &capture_fixture());
        assert!(
            metrics["evidence"]
                .get("instance_reload_not_excluded")
                .is_none()
        );
    }

    // B17 W2 control twin: without a producer the key is absent, never
    // zero or null.
    #[test]
    fn profile_v3_reload_disclosure_absent_without_producer() {
        let ev = evidence();
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        assert!(
            profile["evidence"]
                .get("instance_reload_not_excluded")
                .is_none()
        );
    }

    #[test]
    fn metrics_serializes_actual_attach_backend_metadata() {
        let pid_fallback = crate::attach::select_session_backend(
            crate::attach::BackendSelection::Auto,
            true,
            || panic!("PID scope must use the PID-filter probe"),
            || Err("not supported".to_owned()),
        )
        .unwrap();
        assert_eq!(pid_fallback.backend, crate::attach::AttachBackend::Singles);
        for (scope, selection, fallback, scope_filter, expected) in [
            (
                "pid",
                "singles",
                None,
                Some("perf-task+bpf"),
                serde_json::json!({"selection": "singles", "fallback": null, "scope_filter": "perf-task+bpf"}),
            ),
            (
                "pid",
                "multi",
                None,
                Some("kernel-pid+bpf"),
                serde_json::json!({"selection": "multi", "fallback": null, "scope_filter": "kernel-pid+bpf"}),
            ),
            (
                "pid",
                "auto",
                pid_fallback.fallback.as_deref(),
                Some("perf-task+bpf"),
                serde_json::json!({"selection": "auto", "fallback": "uprobe-multi under --pid needs a proven kernel pid filter: not supported", "scope_filter": "perf-task+bpf"}),
            ),
            (
                "system",
                "multi",
                None,
                None,
                serde_json::json!({"selection": "multi", "fallback": null, "scope_filter": null}),
            ),
            (
                "cgroup",
                "singles",
                None,
                None,
                serde_json::json!({"selection": "singles", "fallback": null, "scope_filter": null}),
            ),
        ] {
            let mut ev = evidence();
            ev.attach_backend = AttachBackendEvidence {
                selection,
                fallback: fallback.map(str::to_owned),
                scope_filter,
            };
            let capture = CaptureMeta {
                scope,
                caller: None,
                ..capture_fixture()
            };
            let document = json(&reports_fixture(), &ev, &capture);
            assert_eq!(document["evidence"]["attach_backend"], expected);
        }
    }

    /// P0-only ship vehicle: the build flavor maps to a structured
    /// availability status, both directions. Stubbed builds disclaim
    /// attribute coverage with the finite `not_enabled` reason; FULL
    /// builds report available with no reason.
    #[test]
    fn object_capture_status_for_build_both_directions() {
        let stubbed = ObjectCaptureEvidence::for_build(true);
        assert!(!stubbed.available);
        assert_eq!(stubbed.reason, Some("not_enabled"));
        let wired = ObjectCaptureEvidence::for_build(false);
        assert!(wired.available);
        assert_eq!(wired.reason, None);
    }

    /// The profile document carries object-capture status as structured
    /// evidence, both directions; the production builder wires the
    /// session source (pinned alongside, since fixtures pin FULL).
    #[test]
    fn profile_carries_object_capture_status() {
        for stubbed in [false, true] {
            let mut ev = evidence();
            ev.object_capture = ObjectCaptureEvidence::for_build(stubbed);
            let document = json(&reports_fixture(), &ev, &capture_fixture());
            let expected = if stubbed {
                serde_json::json!({"available": false, "reason": "not_enabled"})
            } else {
                serde_json::json!({"available": true, "reason": null})
            };
            assert_eq!(document["evidence"]["object_capture"], expected);
        }
        let source = include_str!("run.rs");
        assert!(
            source.contains("session.object_capture_evidence()"),
            "evidence_for must wire the session status"
        );
        assert!(
            source.contains("context.1.object_capture_evidence()"),
            "evidence_for must wire the session status"
        );
        assert!(
            !source.contains("Session::object_capture_evidence()"),
            "output evidence never re-reads the global cache"
        );
        let fence = include_str!("run/root_fence_runtime.rs");
        assert!(
            fence.contains("session.object_capture_evidence()"),
            "evidence_for must wire the session status"
        );
        assert!(
            !fence.contains("Session::object_capture_evidence()"),
            "output evidence never re-reads the global cache"
        );
    }

    #[test]
    fn profile_v3_selection_variants_have_exact_inner_shapes() {
        use p11scope_manifest::manifest::{
            SelectionNameClass as Name, SelectionVersionClass as Version,
        };
        use std::collections::BTreeSet;

        let names = [
            Name::Null,
            Name::ExactStandard,
            Name::Other,
            Name::Unreadable,
        ];
        let versions = [
            Version::Null,
            Version::Unreadable,
            Version::V2_40,
            Version::V3_0,
            Version::V3_1,
            Version::V3_2,
            Version::Other,
        ];
        let mut ev = evidence();
        ev.interface_selection.providers = [
            "observed",
            "observed_uncovered",
            "absent_covered",
            "absent_uncovered",
        ]
        .into_iter()
        .enumerate()
        .map(|(module, coverage)| SelectionProvider {
            module: module as u32,
            coverage,
        })
        .collect();
        ev.interface_selection.standard_exports = [
            "present",
            "legacy_absent",
            "required_absent",
            "outside_module",
            "unresolved",
        ]
        .into_iter()
        .enumerate()
        .map(|(module, status)| StandardExport {
            module: module as u32,
            status,
        })
        .collect();
        ev.interface_selection.inventory_surfaces = vec![
            SelectionSurface {
                module: 0,
                ordinal: 0,
                kind: "legacy",
            },
            SelectionSurface {
                module: 0,
                ordinal: 1,
                kind: "interface",
            },
        ];
        ev.interface_selection.tuples = versions
            .into_iter()
            .enumerate()
            .map(|(index, version)| {
                let request = SelectionRequest {
                    name: names[index.min(names.len() - 1)],
                    version,
                    flags: index as u64,
                };
                SelectionTuple {
                    module: 0,
                    request,
                    rv: if index == 2 { 1 } else { 0 },
                    result: (index != 2).then_some(request),
                    table_match: false,
                    inventory_matches: vec![],
                    authority: SelectionAuthority::None,
                    count: u64::MAX,
                }
            })
            .collect();
        let exact = SelectionRequest {
            name: Name::ExactStandard,
            version: Version::V3_0,
            flags: 0,
        };
        ev.interface_selection.tuples.extend([
            SelectionTuple {
                module: 0,
                request: exact,
                rv: 0,
                result: Some(exact),
                table_match: true,
                inventory_matches: vec![SelectionMatch {
                    surface: 0,
                    name_agrees: true,
                    version_agrees: true,
                }],
                authority: SelectionAuthority::Inventory,
                count: u64::MAX,
            },
            SelectionTuple {
                module: 0,
                request: exact,
                rv: 0,
                result: Some(exact),
                table_match: false,
                inventory_matches: vec![],
                authority: SelectionAuthority::SelectionCountOnly,
                count: u64::MAX,
            },
        ]);

        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        let selection = &profile["evidence"]["interface_selection"];
        fn keys(value: &serde_json::Value) -> BTreeSet<&str> {
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        }
        assert_eq!(
            keys(selection),
            BTreeSet::from([
                "inventory_surfaces",
                "providers",
                "selection_truncated",
                "standard_exports",
                "tuples"
            ])
        );
        for provider in selection["providers"].as_array().unwrap() {
            assert_eq!(keys(provider), BTreeSet::from(["coverage", "module"]));
        }
        for export in selection["standard_exports"].as_array().unwrap() {
            assert_eq!(keys(export), BTreeSet::from(["module", "status"]));
        }
        for surface in selection["inventory_surfaces"].as_array().unwrap() {
            assert_eq!(keys(surface), BTreeSet::from(["kind", "module", "ordinal"]));
        }
        for tuple in selection["tuples"].as_array().unwrap() {
            assert_eq!(
                keys(tuple),
                BTreeSet::from([
                    "authority",
                    "count",
                    "inventory_matches",
                    "module",
                    "request",
                    "result",
                    "rv",
                    "table_match"
                ])
            );
            assert_eq!(
                keys(&tuple["request"]),
                BTreeSet::from(["flags", "name", "version"])
            );
            if !tuple["result"].is_null() {
                assert_eq!(
                    keys(&tuple["result"]),
                    BTreeSet::from(["flags", "name", "version"])
                );
            }
            let matches = tuple["inventory_matches"].as_array().unwrap();
            assert_eq!(tuple["table_match"], !matches.is_empty());
            assert!(tuple["count"].as_u64().unwrap() >= 1);
            for matched in matches {
                let surface = matched["surface"].as_u64().unwrap() as usize;
                assert!(surface < selection["inventory_surfaces"].as_array().unwrap().len());
                assert_eq!(
                    selection["inventory_surfaces"][surface]["module"],
                    tuple["module"]
                );
            }
        }
        assert_eq!(
            keys(&selection["tuples"][7]["inventory_matches"][0]),
            BTreeSet::from(["name_agrees", "surface", "version_agrees"])
        );
        assert_eq!(
            selection["providers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["coverage"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "observed",
                "observed_uncovered",
                "absent_covered",
                "absent_uncovered"
            ]
        );
        assert_eq!(
            selection["standard_exports"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["status"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "present",
                "legacy_absent",
                "required_absent",
                "outside_module",
                "unresolved"
            ]
        );
        assert_eq!(
            selection["inventory_surfaces"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["kind"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["legacy", "interface"]
        );
        assert_eq!(
            selection["tuples"].as_array().unwrap()[..4]
                .iter()
                .map(|row| row["request"]["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["null", "exact_standard", "other", "unreadable"]
        );
        assert_eq!(
            selection["tuples"].as_array().unwrap()[..7]
                .iter()
                .map(|row| row["request"]["version"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "null",
                "unreadable",
                "v2_40",
                "v3_0",
                "v3_1",
                "v3_2",
                "other"
            ]
        );
        assert_eq!(selection["tuples"][7]["authority"], "inventory");
        assert_eq!(selection["tuples"][8]["authority"], "selection_count_only");
        assert_eq!(selection["tuples"][2]["result"], serde_json::Value::Null);
        assert_eq!(selection["tuples"][2]["authority"], "none");
        for (index, tuple) in selection["tuples"].as_array().unwrap().iter().enumerate() {
            assert_eq!(tuple["result"].is_null(), tuple["rv"] != 0, "tuple {index}");
        }
        assert_eq!(selection["tuples"][0]["count"], u64::MAX);
        assert_eq!(
            selection,
            &trace_evidence_object(&ev)["interface_selection"],
            "profile and terminal trace must serialize identical selection evidence"
        );
    }

    #[test]
    fn metrics_completeness_ignores_hidden_selection_state() {
        let mut baseline = evidence();
        baseline.verdict_with_selection(false);
        let expected = baseline.completeness;
        let expected_json = json(&reports_fixture(), &baseline, &capture_fixture());

        baseline.interface_selection.selection_truncated = true;
        baseline
            .interface_selection
            .providers
            .push(SelectionProvider {
                module: 0,
                coverage: "absent_uncovered",
            });
        baseline.verdict_with_selection(false);
        assert_eq!(baseline.completeness, expected);
        assert_eq!(
            json(&reports_fixture(), &baseline, &capture_fixture()),
            expected_json,
            "selection-only state must not change metrics output or verdict"
        );
        assert!(
            json(&reports_fixture(), &baseline, &capture_fixture())["evidence"]
                .get("interface_selection")
                .is_none()
        );

        baseline.verdict_with_selection(true);
        assert_eq!(baseline.completeness, "PARTIAL");
    }

    fn discovered_fixture() -> DiscoveredModule {
        let sha = "11".repeat(32);
        DiscoveredModule {
            id: ModuleId(0),
            admission_class: None,
            dev: (8, 1),
            ino: 11,
            sha256: Some(sha.clone()),
            path: "/opt/p11.so".into(),
            build_id: Some("aabb".into()),
            layer: None,
            objects: vec![ObjectSummary {
                dev: (8, 1),
                ino: 11,
                sha256: Some(sha),
                path: "/opt/p11.so".into(),
                build_id: Some("aabb".into()),
                identity_source: "mountinfo",
                note: None,
                sources: vec!["scan"],
            }],
            sources: vec!["scan"],
            corroborated: false,
            corroboration: vec!["single_source"],
            watch: None,
            attached_at_ns: None,
            unobserved_windows: None,
            first_loaded_by: None,
            tables: vec![crate::plan::TableSummary {
                version: (2, 40),
                entries: 68,
                source: "scan",
                file_offset: None,
                linkage: "heuristic",
                exports_agreeing: Some(0),
            }],
            interfaces: 1,
            skipped: vec![],
        }
    }

    /// A learned module carries who loaded it first and how many loads ran
    /// before staging: exe path plus the missed-load count, no pid, no
    /// address, no file bytes.
    #[test]
    fn learned_module_carries_first_loader_without_addresses() {
        let mut module = discovered_fixture();
        module.first_loaded_by = Some(FirstLoadedBy {
            exe: Some("/usr/bin/pkcs11-tool".to_string()),
            exe_unknown_reason: None,
            pre_attach_loads: 1,
        });
        let json = serde_json::to_value(&module).unwrap();
        assert_eq!(
            json["first_loaded_by"]["exe"],
            serde_json::json!("/usr/bin/pkcs11-tool")
        );
        assert_eq!(
            json["first_loaded_by"]["pre_attach_loads"],
            serde_json::json!(1)
        );
        assert!(json["first_loaded_by"]["exe_unknown_reason"].is_null());
        let text = serde_json::to_string(&json["first_loaded_by"]).unwrap();
        assert!(!text.contains("pid"), "{text}");
        assert!(!text.contains("0x"), "{text}");
        let mut unknown = discovered_fixture();
        unknown.first_loaded_by = Some(FirstLoadedBy {
            exe: None,
            exe_unknown_reason: Some("loader exe link unreadable"),
            pre_attach_loads: 2,
        });
        let json = serde_json::to_value(&unknown).unwrap();
        assert!(json["first_loaded_by"]["exe"].is_null());
        assert_eq!(
            json["first_loaded_by"]["exe_unknown_reason"],
            serde_json::json!("loader exe link unreadable")
        );
        let plain = discovered_fixture();
        assert!(
            serde_json::to_value(&plain)
                .unwrap()
                .get("first_loaded_by")
                .is_none(),
            "ordinary modules carry no key"
        );
    }

    /// Learned gaps project under their own subject with their seven
    /// finite reasons; anything else under the subject still redacts to
    /// the generic discovery pair, and no path, pid, or executable ever
    /// reaches output through the row.
    #[test]
    fn learned_gaps_project_named_without_target_data() {
        for reason in [
            LEARNED_FIRST_RUN_REASON,
            LEARNED_OVERFLOW_REASON,
            LEARNED_CAP_REASON,
            LEARNED_UNAVAILABLE_REASON,
            LEARNED_REPLACED_DELETED_REASON,
            LEARNED_DISABLED_REASON,
            LEARNED_MOUNT_NAMESPACE_REASON,
        ] {
            let projected = capture_skipped_out(&Skipped {
                subject: LEARNED_SKIP_SUBJECT.into(),
                reason: (*reason).into(),
            });
            assert_eq!(projected.name, LEARNED_SKIP_SUBJECT);
            assert_eq!(projected.reason, *reason);
        }
        assert!(
            LEARNED_CAP_REASON.contains("32"),
            "the cap names which limit was hit: {LEARNED_CAP_REASON}"
        );
        for reason in [
            "provider /opt/vendor/libx.so was first seen loaded by /usr/bin/pkcs11-tool; its earlier calls were not observed",
            "file learning is unavailable: fanotify_init failed (os error 1)",
        ] {
            let projected = capture_skipped_out(&Skipped {
                subject: LEARNED_SKIP_SUBJECT.into(),
                reason: reason.into(),
            });
            assert_eq!(projected.name, "discovery subject", "{reason}");
            assert_eq!(projected.reason, DISCOVERY_UNAVAILABLE, "{reason}");
            let json = serde_json::to_string(&projected).unwrap();
            assert!(!json.contains("/opt/vendor/libx.so"), "{json}");
            assert!(!json.contains("pkcs11-tool"), "{json}");
            assert!(!json.contains("os error"), "{json}");
        }
    }

    fn reports_fixture() -> Vec<SlotReport> {
        let mut r = report("C_Sign", 1, 0, false);
        r.module = Some(crate::plan::ModuleId(0));
        vec![r]
    }

    #[test]
    fn functions_out_attributes_a_holey_stable_module_id_to_its_module() {
        let mut b = discovered_fixture();
        b.id = ModuleId(1);
        b.ino = 22;
        b.path = "/opt/b.so".into();
        let mut c = discovered_fixture();
        c.id = ModuleId(2);
        c.ino = 33;
        c.path = "/opt/c.so".into();
        let mut report = report("C_Sign", 1, 0, false);
        report.module = Some(crate::plan::ModuleId(1));

        let out = functions_out(&[report], &[b, c], &std::collections::BTreeSet::new());

        assert_eq!(out[0].module.as_ref().unwrap().ino, 22);
    }

    /// WU-15 round 2: an Initialize row whose completed calls all returned
    /// CKR_OK reports `ok` with the potential-provider likelihood.
    #[test]
    fn initialize_row_with_ok_returns_reports_ok_and_potential_provider() {
        let mut row = report("C_Initialize", 3, 0, false);
        row.rv_counts.insert(pkcs11_types::CkRv::OK.0, 3);
        let ev = evidence();
        let state = state_fixture();
        let profile = profile_json(
            &[row],
            VersionedEvidence::wrap(&ev),
            &state,
            &capture_fixture(),
        );
        assert_eq!(
            profile["functions"][0]["initialization"],
            serde_json::json!({"outcome": "ok", "potential_provider": true})
        );
    }

    /// The ALREADY class is its own outcome, and it still evidences a
    /// responding Cryptoki: the likelihood is present.
    #[test]
    fn initialize_row_with_already_returns_reports_already_and_potential_provider() {
        let mut row = report("C_Initialize", 2, 0, false);
        row.rv_counts
            .insert(pkcs11_types::CkRv::CRYPTOKI_ALREADY_INITIALIZED.0, 2);
        let ev = evidence();
        let state = state_fixture();
        let profile = profile_json(
            &[row],
            VersionedEvidence::wrap(&ev),
            &state,
            &capture_fixture(),
        );
        assert_eq!(
            profile["functions"][0]["initialization"],
            serde_json::json!({"outcome": "already_initialized", "potential_provider": true})
        );
    }

    /// Error-only rows report `error` with no likelihood key: one error RV,
    /// two distinct error RVs (still one class, never `mixed`), and a
    /// PENDING-only row (a non-success return for a synchronous lifecycle
    /// call; the outcome vocabulary has no pending word, and the row
    /// evidenced no successful initialization).
    #[test]
    fn initialize_row_with_errors_only_reports_error_without_potential() {
        use pkcs11_types::CkRv;
        for rvs in [
            vec![(CkRv::GENERAL_ERROR.0, 4)],
            vec![(CkRv::GENERAL_ERROR.0, 2), (CkRv::DEVICE_ERROR.0, 1)],
            vec![(CkRv::PENDING.0, 2)],
        ] {
            let mut row = report("C_Initialize", 4, 0, false);
            row.rv_counts = rvs.into_iter().collect();
            let ev = evidence();
            let state = state_fixture();
            let profile = profile_json(
                &[row],
                VersionedEvidence::wrap(&ev),
                &state,
                &capture_fixture(),
            );
            assert_eq!(
                profile["functions"][0]["initialization"],
                serde_json::json!({"outcome": "error"}),
            );
        }
    }

    /// More than one outcome class over the row's completed calls is
    /// `mixed`. Every mixed pair contains `ok` or `already_initialized`
    /// (a lone `error` class cannot mix with itself), so the likelihood
    /// is always present.
    #[test]
    fn initialize_row_with_mixed_classes_reports_mixed() {
        use pkcs11_types::CkRv;
        for rvs in [
            vec![(CkRv::OK.0, 1), (CkRv::GENERAL_ERROR.0, 1)],
            vec![
                (CkRv::CRYPTOKI_ALREADY_INITIALIZED.0, 2),
                (CkRv::GENERAL_ERROR.0, 1),
            ],
            vec![(CkRv::OK.0, 1), (CkRv::CRYPTOKI_ALREADY_INITIALIZED.0, 1)],
        ] {
            let mut row = report("C_Initialize", 2, 0, false);
            row.rv_counts = rvs.into_iter().collect();
            let ev = evidence();
            let state = state_fixture();
            let profile = profile_json(
                &[row],
                VersionedEvidence::wrap(&ev),
                &state,
                &capture_fixture(),
            );
            assert_eq!(
                profile["functions"][0]["initialization"],
                serde_json::json!({"outcome": "mixed", "potential_provider": true}),
            );
        }
    }

    /// No completed-call evidence, no claim: an idle row, a row whose only
    /// RV entry carries a zero count, and a row with lost RV detail
    /// (`calls > 0` but empty `rv_counts`) all omit the object. The claim
    /// derives only from `rv_counts`, never from `calls`.
    #[test]
    fn initialize_row_without_completed_calls_omits_initialization() {
        let ev = evidence();
        let state = state_fixture();
        let idle = report("C_Initialize", 0, 0, false);
        let profile = profile_json(
            std::slice::from_ref(&idle),
            VersionedEvidence::wrap(&ev),
            &state,
            &capture_fixture(),
        );
        assert!(
            profile["functions"][0].get("initialization").is_none(),
            "idle row must omit the claim: {}",
            profile["functions"][0]
        );

        let mut zeroed = report("C_Initialize", 0, 0, false);
        zeroed.rv_counts.insert(pkcs11_types::CkRv::OK.0, 0);
        let metrics = json(std::slice::from_ref(&zeroed), &ev, &capture_fixture());
        assert!(
            metrics["functions"][0].get("initialization").is_none(),
            "zero-count RVs assert nothing observed: {}",
            metrics["functions"][0]
        );

        let lost = report("C_Initialize", 3, 0, false);
        let metrics = json(std::slice::from_ref(&lost), &ev, &capture_fixture());
        assert!(
            metrics["functions"][0].get("initialization").is_none(),
            "calls without RV detail stay unknown: {}",
            metrics["functions"][0]
        );
    }

    /// Only rows that name exactly `C_Initialize` carry the claim, however
    /// successful their own calls were.
    #[test]
    fn non_initialize_row_omits_initialization() {
        let ev = evidence();
        let state = state_fixture();
        for name in ["C_Sign", "unknown", "c_initialize"] {
            let mut row = report(name, 5, 0, false);
            row.rv_counts.insert(pkcs11_types::CkRv::OK.0, 5);
            let profile = profile_json(
                std::slice::from_ref(&row),
                VersionedEvidence::wrap(&ev),
                &state,
                &capture_fixture(),
            );
            assert!(
                profile["functions"][0].get("initialization").is_none(),
                "{name} must omit the claim: {}",
                profile["functions"][0]
            );
        }
    }

    /// The claim renders identically in the metrics lane and under every
    /// counter mode: one shared row builder feeds both lanes, and the
    /// counter mode only selects the timing shape beside it.
    #[test]
    fn initialization_claim_renders_in_metrics_lane_and_all_counter_modes() {
        let ev = evidence();
        let state = state_fixture();
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let mut row = report("C_Initialize", 2, 0, false);
            row.mode = mode;
            row.rv_counts.insert(pkcs11_types::CkRv::OK.0, 2);
            let wanted = serde_json::json!({"outcome": "ok", "potential_provider": true});
            let metrics = json(std::slice::from_ref(&row), &ev, &capture_fixture());
            assert_eq!(
                metrics["functions"][0]["initialization"], wanted,
                "{mode:?}"
            );
            let profile = profile_json(
                std::slice::from_ref(&row),
                VersionedEvidence::wrap(&ev),
                &state,
                &capture_fixture(),
            );
            assert_eq!(
                profile["functions"][0]["initialization"], wanted,
                "{mode:?}"
            );
        }
    }

    /// The claim is row-scoped: an aliased row that names `C_Initialize`
    /// among its names reports the row's own outcomes (aliased counts are
    /// never split into guessed per-name shares).
    #[test]
    fn initialize_claim_covers_aliased_rows_by_row_outcomes() {
        let mut row = report("C_Initialize", 2, 0, true);
        row.names.push("C_GetFunctionList".into());
        row.rv_counts.insert(pkcs11_types::CkRv::OK.0, 2);
        let ev = evidence();
        let state = state_fixture();
        let profile = profile_json(
            &[row],
            VersionedEvidence::wrap(&ev),
            &state,
            &capture_fixture(),
        );
        assert_eq!(
            profile["functions"][0]["initialization"],
            serde_json::json!({"outcome": "ok", "potential_provider": true})
        );
    }

    /// The live function table marks qualifying Initialize rows with the
    /// same outcome and likelihood words the JSON row carries; other rows
    /// and rows without completed calls carry no marker.
    #[test]
    fn live_view_marks_initialize_rows_with_outcome_and_potential() {
        use pkcs11_types::CkRv;
        let mut ok = report("C_Initialize", 2, 0, false);
        ok.rv_counts.insert(CkRv::OK.0, 2);
        let mut already = report("C_Initialize", 1, 0, false);
        already
            .rv_counts
            .insert(CkRv::CRYPTOKI_ALREADY_INITIALIZED.0, 1);
        let mut error = report("C_Initialize", 1, 0, false);
        error.rv_counts.insert(CkRv::GENERAL_ERROR.0, 1);
        let mut mixed = report("C_Initialize", 2, 0, false);
        mixed.rv_counts.insert(CkRv::OK.0, 1);
        mixed.rv_counts.insert(CkRv::GENERAL_ERROR.0, 1);
        let mut other = report("C_Sign", 5, 0, false);
        other.rv_counts.insert(CkRv::OK.0, 5);
        let uncompleted = report("C_Initialize", 0, 1, false);
        let mut ev = evidence();
        ev.verdict();
        let out = live(
            &[ok, already, error, mixed, other, uncompleted],
            &ev,
            Duration::from_secs(65),
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
        );
        let init_lines: Vec<&str> = out
            .lines()
            .filter(|line| line.contains("C_Initialize"))
            .collect();
        assert_eq!(init_lines.len(), 5, "{out}");
        for marker in ["[init: ok]", "[init: already_initialized]", "[init: mixed]"] {
            assert!(
                init_lines.iter().any(|line| line.contains(marker)),
                "missing {marker} in:\n{out}"
            );
        }
        assert!(
            !out.contains("potential provider"),
            "no row claims a provider: {out}"
        );
        let error_line = init_lines
            .iter()
            .find(|line| line.contains("[init: error]"))
            .expect("error row carries [init: error]");
        assert!(
            !error_line.contains("potential provider"),
            "error row must not claim the likelihood: {error_line}"
        );
        let sign_line = out
            .lines()
            .find(|line| line.contains("C_Sign"))
            .expect("C_Sign row renders");
        assert!(
            !sign_line.contains("[init:"),
            "non-Initialize row must carry no marker: {sign_line}"
        );
        let unmarked = init_lines
            .iter()
            .filter(|line| !line.contains("[init:"))
            .count();
        assert_eq!(unmarked, 1, "only the in-flight row lacks a marker:\n{out}");
    }

    fn state_fixture() -> crate::semantics::State {
        crate::semantics::State::with_policy(&empty_plan(), CapturePolicy::Allowlisted)
    }

    fn capture_fixture() -> CaptureMeta<'static> {
        CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::Allowlisted,
            scope: "pid",
            caller: Some(CaptureCaller {
                exe: Some("/opt/target/harness".to_string()),
                exe_unknown_reason: None,
            }),
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        }
    }

    #[test]
    fn capture_skip_records_exclude_private_subjects_and_reasons_from_profile_and_metrics() {
        use crate::discovery::scan::Skipped;

        let skips = [
            Skipped {
                subject: "/private/SUBJECT_PATH_SENTINEL".into(),
                reason: "mapped /private/REASON_PATH_SENTINEL could not be read".into(),
            },
            Skipped {
                subject: "pid 424242991".into(),
                reason: "scanning pid 424242992: /proc/424242992/maps: ERROR_CHAIN_SENTINEL"
                    .into(),
            },
            Skipped {
                subject: "/sys/fs/cgroup/CGROUP_SUBJECT_SENTINEL.scope".into(),
                reason: "cgroup /sys/fs/cgroup/CGROUP_REASON_SENTINEL.scope failed".into(),
            },
            Skipped {
                subject: "C_Sign".into(),
                reason: "/private/ENTRY_REASON_SENTINEL.so was not pinned".into(),
            },
            Skipped {
                subject: "/private/OVERLAY_SUBJECT_SENTINEL.so".into(),
                reason: "mapping OVERLAY_KEY_SENTINEL was collapsed by the overlayfs + inode metadata + SHA-256 heuristic, which cannot prove physical identity across overlay instances; /private/OVERLAY_REASON_SENTINEL.so would not be probed".into(),
            },
            Skipped {
                subject: "discovery subject".into(),
                reason: crate::discovery::identity::AMBIGUOUS_REASON.into(),
            },
        ];
        let mut ev = evidence();
        ev.skipped = skips.iter().map(capture_skipped_out).collect();
        ev.verdict();

        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        let metrics = json(&reports_fixture(), &ev, &capture_fixture());
        let expected = [
            ("discovery subject", "discovery unavailable"),
            ("discovery subject", "discovery unavailable"),
            ("discovery subject", "discovery unavailable"),
            ("C_Sign", "function entry unavailable"),
            (
                "discovery subject",
                "shared-overlay physical identity is uncertain; a distinct byte-identical instance may be unobserved",
            ),
            (
                "discovery subject",
                "physical identity is ambiguous; the collision group was not attached",
            ),
        ];

        for document in [profile, metrics] {
            let records = document["evidence"]["skipped"].as_array().unwrap();
            let actual: Vec<(&str, &str)> = records
                .iter()
                .map(|item| {
                    (
                        item["name"].as_str().unwrap(),
                        item["reason"].as_str().unwrap(),
                    )
                })
                .collect();
            assert_eq!(actual, expected);
            let rendered = serde_json::to_string(&document).unwrap();
            for sentinel in [
                "SUBJECT_PATH_SENTINEL",
                "REASON_PATH_SENTINEL",
                "424242991",
                "424242992",
                "ERROR_CHAIN_SENTINEL",
                "CGROUP_SUBJECT_SENTINEL",
                "CGROUP_REASON_SENTINEL",
                "ENTRY_REASON_SENTINEL",
                "OVERLAY_KEY_SENTINEL",
                "OVERLAY_SUBJECT_SENTINEL",
                "OVERLAY_REASON_SENTINEL",
            ] {
                assert!(
                    !rendered.contains(sentinel),
                    "leaked {sentinel}: {rendered}"
                );
            }
        }
    }

    #[test]
    fn clean_capture_is_complete() {
        let mut ev = evidence();
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
    }

    /// Review answer (a) / F-1: a capture whose only gate is withheld
    /// names/semantics is `attribution_only`, never `concrete_gap`; any
    /// observation loss is `concrete_gap`; `completeness` stays PARTIAL for
    /// both. The inputs that drive it are published.
    #[test]
    fn withheld_attribution_alone_is_not_a_concrete_gap() {
        for (label, mutate) in [
            (
                "semantic_unverified_slots",
                (|ev: &mut Evidence| ev.semantic_unverified_slots = 68) as fn(&mut Evidence),
            ),
            ("aliased", |ev| {
                ev.aliased = vec![vec!["C_A".into(), "C_B".into()]]
            }),
            ("module_unresolved_slots", |ev| {
                ev.module_unresolved_slots = 1
            }),
            ("unregistered_mechanisms", |ev| {
                ev.unregistered_mechanisms = 1
            }),
            ("unpublished_mechanisms", |ev| ev.unpublished_mechanisms = 1),
        ] {
            let mut ev = evidence();
            mutate(&mut ev);
            ev.verdict();
            assert_eq!(ev.completeness, "PARTIAL", "{label}");
            assert_eq!(ev.verdict_detail, "attribution_only", "{label}");
            ev.mark_terminal_drain_unproven();
            assert_eq!(
                ev.verdict_detail, "attribution_only",
                "{label} after the seal"
            );
        }
        for (label, mutate) in [
            (
                "event_loss",
                (|ev: &mut Evidence| ev.event_loss = 1) as fn(&mut Evidence),
            ),
            ("in_flight_at_end", |ev| ev.in_flight_at_end = 1),
            ("unprotected_live_windows", |ev| {
                ev.unprotected_live_windows = 1
            }),
            ("pending_at_end", |ev| ev.pending_at_end = 1),
        ] {
            let mut ev = evidence();
            ev.semantic_unverified_slots = 68;
            mutate(&mut ev);
            ev.verdict();
            assert_eq!(ev.verdict_detail, "concrete_gap", "{label}");
        }
        let mut ev = evidence();
        ev.semantic_unverified_slots = 68;
        ev.unprotected_live_windows = 1;
        ev.module_unresolved_slots = 2;
        ev.verdict();
        let value = serde_json::to_value(&ev).unwrap();
        assert_eq!(value["semantic_unverified_slots"], 68);
        assert_eq!(value["unprotected_live_windows"], 1);
        assert_eq!(value["module_unresolved_slots"], 2);
    }

    /// `gap_classes` names every contributing counter in its one class.
    #[test]
    fn gap_classes_name_every_contributing_counter() {
        let mut ev = evidence();
        ev.semantic_unverified_slots = 68;
        ev.event_loss = 2;
        ev.state_reconciliations = 1;
        ev.in_flight_at_end = 3;
        ev.verdict();
        assert_eq!(
            serde_json::to_value(&ev).unwrap()["gap_classes"],
            serde_json::json!({
                "observation": {"status": "lossy", "causes": ["in_flight_at_end", "event_loss"]},
                "attribution": {"status": "withheld", "causes": ["semantic_unverified_slots"]},
                "semantics": {"status": "degraded", "causes": ["state_reconciliations"]},
                "open_calls": 3,
                "settlement": "unproven",
                "stdout_data_sink": false,
            })
        );
        // Every slot count-only and nothing degraded: semantics do not apply.
        let mut ev = evidence();
        ev.semantic_unverified_slots = ev.slots;
        ev.verdict();
        assert_eq!(ev.gap_classes.semantics.status, "not_applicable");
        assert_eq!(ev.verdict_detail, VERDICT_ATTRIBUTION_ONLY);
    }

    /// DR-K8S-1/2: an observer outside the initial PID namespace cannot
    /// resolve the kernel's PIDs, so its live discovery is unproven and the
    /// observation is never exact — the cause names it, the line says why,
    /// and the evidence names both numberings.
    #[test]
    fn an_observer_outside_the_initial_pid_namespace_is_never_exact() {
        use crate::pidns::{ObserverPidNs, PidNamespaceEvidence, PidNumbering, ProcView};
        let mut clean = evidence();
        clean.verdict();
        assert!(clean.gap_classes.observation.causes.is_empty());
        assert_eq!(
            serde_json::to_value(&clean).unwrap()["pid_namespace"],
            serde_json::json!({"observer": "initial", "kernel_pids": "initial", "proc_pids": "observer"})
        );
        for observer in [ObserverPidNs::Nested, ObserverPidNs::Unknown("x".into())] {
            let mut ev = evidence();
            ev.pid_namespace = PidNamespaceEvidence::of(&PidNumbering {
                observer: observer.clone(),
                proc_view: ProcView::Own,
            });
            ev.verdict();
            assert_eq!(ev.gap_classes.observation.status, "lossy", "{observer:?}");
            assert_eq!(ev.gap_classes.observation.causes, ["pid_namespace"]);
            assert_eq!(ev.completeness, "PARTIAL");
            assert_eq!(ev.verdict_detail, VERDICT_CONCRETE_GAP);
            assert_eq!(
                serde_json::to_value(&ev).unwrap()["pid_namespace"]["observer"],
                observer.label()
            );
            let reasons = verdict_reasons(&ev, false);
            assert!(
                reasons.contains(&format!(
                    "calls may be missing (observer PID namespace {}",
                    observer.label()
                )),
                "{reasons}"
            );
        }
    }

    /// `docker run` without `--pid=host`: when the evidence says the
    /// observer saw only its own container, the `pid_namespace` gap in
    /// the report names the container-only view and its remedy — the
    /// same plain words as the start warning. Without the flag the
    /// gap text stays exactly what it was.
    #[test]
    fn a_container_only_view_is_named_in_the_report_gap() {
        use crate::pidns::{PidNamespaceEvidence, PidNumbering};
        let mut ev = evidence();
        ev.pid_namespace = PidNamespaceEvidence::of(&PidNumbering {
            observer: crate::pidns::ObserverPidNs::Nested,
            proc_view: crate::pidns::ProcView::Own,
        });
        ev.container_only_view = true;
        ev.verdict();
        assert_eq!(ev.gap_classes.observation.causes, ["pid_namespace"]);
        let reasons = verdict_reasons(&ev, false);
        assert!(
            reasons.contains("only this container is visible"),
            "{reasons}"
        );
        assert!(reasons.contains("--pid=host"), "{reasons}");
        // The flag is render-only: never serialized, never a new cause.
        let value = serde_json::to_value(&ev).unwrap();
        assert!(value.get("container_only_view").is_none(), "{value}");
        let mut plain = evidence();
        plain.pid_namespace = ev.pid_namespace;
        plain.verdict();
        let reasons = verdict_reasons(&plain, false);
        assert!(!reasons.contains("only this container"), "{reasons}");
    }

    /// M1 (review): an initial observer reading another namespace's /proc
    /// (`nsenter -m` without `-p`) is the cause `proc_namespace_mismatch`;
    /// a nested observer on a stale host /proc carries both causes.
    #[test]
    fn a_foreign_proc_is_never_exact_either() {
        use crate::pidns::{ObserverPidNs, PidNamespaceEvidence, PidNumbering, ProcView};
        for (observer, causes) in [
            (ObserverPidNs::Initial, vec!["proc_namespace_mismatch"]),
            (
                ObserverPidNs::Nested,
                vec!["pid_namespace", "proc_namespace_mismatch"],
            ),
        ] {
            let mut ev = evidence();
            ev.pid_namespace = PidNamespaceEvidence::of(&PidNumbering {
                observer,
                proc_view: ProcView::Foreign("/proc/self: gone".into()),
            });
            ev.verdict();
            assert_eq!(ev.gap_classes.observation.status, "lossy");
            assert_eq!(ev.gap_classes.observation.causes, causes);
            assert_eq!(ev.verdict_detail, VERDICT_CONCRETE_GAP);
            assert_eq!(
                serde_json::to_value(&ev).unwrap()["pid_namespace"]["proc_pids"],
                "foreign"
            );
            assert!(verdict_reasons(&ev, false).contains("process numbering is foreign"));
        }
    }

    /// A NULL function-table entry cannot be called, so no call is missed
    /// through it: the published skip is a fact, not an observation gap.
    #[test]
    fn a_null_table_entry_is_not_an_observation_loss() {
        let mut ev = evidence();
        ev.skipped = vec![SkippedOut {
            name: "C_GetFunctionStatus".into(),
            reason: "null pointer".into(),
        }];
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
        ev.mark_terminal_drain_unproven();
        assert_eq!(ev.verdict_detail, "clean_but_unproven");

        let mut ev = evidence();
        ev.skipped = vec![SkippedOut {
            name: "C_Sign".into(),
            reason: ENTRY_UNAVAILABLE.into(),
        }];
        ev.verdict();
        assert_eq!(ev.verdict_detail, "concrete_gap");
    }

    #[test]
    fn unverified_semantic_authority_alone_forces_partial() {
        let mut ev = evidence();
        ev.semantic_unverified_slots = 1;
        ev.verdict();

        assert_eq!(ev.completeness, "PARTIAL");
        let output = live(
            &reports_fixture(),
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
        );
        assert!(
            output.contains(
                "coverage: partial — counts complete; function names follow the standard PKCS#11 table"
            ),
            "{output}"
        );
    }

    /// Task 1.3 mislabel guard: an admitted scan table carries (file_offset,
    /// entry count, linkage kind) from plan into evidence, and a heuristic
    /// table with no linkage is named `unknown` — never the PKCS#11 label its
    /// ordinals suggest. Only a linkage-or-manifest-authorized table keeps
    /// `function_name` names.
    #[test]
    fn admitted_tables_carry_provenance_and_unlinked_tables_are_unknown() {
        use crate::discovery::identity::ReconciledModule;
        use crate::discovery::scan::{ScannedEntry, ScannedInterface, ScannedModule, ScannedTable};
        use crate::process::{MountNamespaceId, ProcessViewId};
        use p11scope_manifest::maps::{Device, ObjectKey};

        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 42,
        };
        let entry = |name: &'static str, file_offset: u64| ScannedEntry {
            name,
            object: key,
            object_path: "/opt/p11.so".into(),
            file_offset,
        };
        let object = crate::plan::TEST_PINNED_OBJECT;
        let plan = crate::plan::build_from_reconciled_modules(&[ReconciledModule {
            exports: Default::default(),
            getter_present: false,
            witness_fault: false,
            object,
            entry_objects: vec![vec![object, object], vec![object]],
            scanned: ScannedModule {
                module_hint: None,
                mapped_identity: None,
                double_loaded: false,
                same_file_loads: 1,
                pre_copy_up: None,
                view: ProcessViewId(0),
                mount_namespace: MountNamespaceId {
                    device: 1,
                    inode: 1,
                },
                key,
                path: "/opt/p11.so".into(),
                tables_scan_finished: false,
                decoder_abi: Some(p11scope_manifest::elf::ElfAbi::Lp64),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![
                    ScannedTable {
                        version: (2, 40),
                        walk: "full",
                        entries: vec![entry("C_Sign", 0x10), entry("C_Verify", 0x18)],
                        null_entries: vec!["C_GetFunctionStatus"],
                        unpinned: vec![],
                        address: 0x7000,
                        file_offset: Some(0x100),
                        live_return: false,
                        manifest_supported: false,
                        extension_impossible: false,
                    },
                    ScannedTable {
                        version: (2, 40),
                        walk: "full",
                        entries: vec![entry("C_Encrypt", 0x20)],
                        null_entries: vec![],
                        unpinned: vec![],
                        address: 0x8000,
                        file_offset: Some(0x200),
                        live_return: false,
                        manifest_supported: false,
                        extension_impossible: false,
                    },
                ],
                interfaces: vec![ScannedInterface {
                    index: 0,
                    name_class: "exact_standard",
                    name_lossy: None,
                    name_private: Some(b"PKCS 11".to_vec()),
                    flags: 0,
                    table: Some(1),
                }],
            },
        }]);

        assert_eq!(plan.slots.len(), 3);
        let names_of = |offset: u64| {
            plan.slots
                .iter()
                .find(|slot| slot.file_offset == offset)
                .unwrap()
                .names
                .clone()
        };
        assert_eq!(names_of(0x10), ["unknown"]);
        assert_eq!(names_of(0x18), ["unknown"]);
        assert_eq!(names_of(0x20), ["C_Encrypt"]);

        let tables = &plan.modules[0].tables;
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0].file_offset, Some(0x100));
        assert_eq!(tables[0].entries, 2);
        assert_eq!(tables[0].linkage, "heuristic");
        assert_eq!(tables[1].file_offset, Some(0x200));
        assert_eq!(tables[1].entries, 1);
        assert_eq!(tables[1].linkage, "interface");

        // The null slot of the unlinked table stays a null fact without
        // claiming which function was null.
        assert!(
            plan.skipped
                .iter()
                .any(|skip| skip.subject == "unknown" && skip.reason == "null pointer"),
            "{:?}",
            plan.skipped
        );

        // Provenance reaches rendered evidence as JSON keys, not comments.
        let mut discovered = discovered_fixture();
        discovered.tables = tables.clone();
        let value = serde_json::to_value(&discovered).unwrap();
        assert_eq!(value["tables"][0]["file_offset"], 0x100);
        assert_eq!(value["tables"][0]["entries"], 2);
        assert_eq!(value["tables"][0]["linkage"], "heuristic");
        assert_eq!(value["tables"][1]["file_offset"], 0x200);
        assert_eq!(value["tables"][1]["linkage"], "interface");
    }

    #[test]
    fn scan_only_count_only_event_keeps_aggregate_output_and_no_semantic_payload() {
        use crate::discovery::identity::ReconciledModule;
        use crate::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
        use crate::process::{MountNamespaceId, ProcessViewId};
        use p11scope_ebpf_common::{Event, SlotSemantics, bucket_of, capture};
        use p11scope_manifest::maps::{Device, ObjectKey};

        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 42,
        };
        let plan = crate::plan::build_from_reconciled_modules(&[ReconciledModule {
            exports: Default::default(),
            getter_present: false,
            witness_fault: false,
            object: crate::plan::TEST_PINNED_OBJECT,
            entry_objects: vec![vec![crate::plan::TEST_PINNED_OBJECT]],
            scanned: ScannedModule {
                module_hint: None,
                mapped_identity: None,
                double_loaded: false,
                same_file_loads: 1,
                pre_copy_up: None,
                view: ProcessViewId(0),
                mount_namespace: MountNamespaceId {
                    device: 1,
                    inode: 1,
                },
                key,
                path: "/opt/p11.so".into(),
                tables_scan_finished: false,
                decoder_abi: Some(p11scope_manifest::elf::ElfAbi::Lp64),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries: vec![ScannedEntry {
                        name: "C_OpenSession",
                        object: key,
                        object_path: "/opt/p11.so".into(),
                        file_offset: 0x10,
                    }],
                    null_entries: vec![],
                    unpinned: vec![],
                    address: 0x7000,
                    file_offset: Some(0),
                    live_return: false,
                    manifest_supported: false,
                    extension_impossible: false,
                }],
                interfaces: vec![],
            },
        }]);
        assert_eq!(plan.entries_seen, 1);
        assert_eq!(plan.slots.len(), 1);
        assert_eq!(plan.slots[0].semantics, SlotSemantics::COUNT_ONLY);
        assert!(!plan.slots[0].semantic_authorized);
        let mut state = crate::semantics::State::with_policy(&plan, CapturePolicy::Allowlisted);
        let hostile = |index, rv| Event {
            ts_ns: index * 1_000,
            duration_ns: 100,
            pid_tgid: (100u64 << 32) | 1,
            cgroup_id: 7,
            session: 0xdead_beef,
            mechanism: 0xa11c_e000_0000_0000,
            capture: capture::MECHANISM_VALUE,
            rv,
            p0: 0xa11c_e000_0000_0001,
            p1: 0xa11c_e000_0000_0002,
            p2: 0xa11c_e000_0000_0003,
            slot: 0,
            user_type: 0xa11c_e004,
            shape: shape::GCM,
            attr_types: [0xa11c_e005; 8],
            attr_count: 8,
            attr_total: 9,
            attr_bools: 0xff,
            attr_bools_seen: 0xff,
            ..Event::default()
        };
        let events: Vec<_> = (0..25u64)
            .map(|index| {
                hostile(
                    index,
                    if index < 17 {
                        0
                    } else if index < 20 {
                        pkcs11_types::CkRv::GENERAL_ERROR.0
                    } else {
                        pkcs11_types::CkRv::PENDING.0
                    },
                )
            })
            .collect();
        let mut tracer = crate::trace::Tracer::new(&plan);
        let lines: Vec<_> = events
            .iter()
            .map(|event| tracer.on_event(event, &mut state))
            .collect();

        let mut report = report("C_OpenSession", 25, 0, false);
        report.semantic_authorized = false;
        report.module = Some(crate::plan::ModuleId(0));
        report.errors = 3;
        report.total_ns = 2_500;
        report.max_ns = 100;
        report.buckets[bucket_of(100) as usize] = 25;
        report.rv_counts.insert(0, 17);
        report
            .rv_counts
            .insert(pkcs11_types::CkRv::GENERAL_ERROR.0, 3);
        report.rv_counts.insert(pkcs11_types::CkRv::PENDING.0, 5);
        let observed_rvs =
            events
                .iter()
                .fold(std::collections::BTreeMap::new(), |mut counts, event| {
                    counts
                        .entry(event.rv)
                        .and_modify(|count: &mut u64| *count = count.saturating_add(1))
                        .or_insert(1);
                    counts
                });
        assert_eq!(report.rv_counts, observed_rvs);
        assert_eq!(
            report.errors,
            events
                .iter()
                .filter(|event| { event.rv != 0 && event.rv != pkcs11_types::CkRv::PENDING.0 })
                .count() as u64
        );
        assert_eq!(
            report.total_ns,
            events.iter().map(|event| event.duration_ns).sum::<u64>()
        );
        assert_eq!(
            report.max_ns,
            events.iter().map(|event| event.duration_ns).max().unwrap()
        );

        let mut ev = evidence();
        ev.table_entries = plan.entries_seen;
        ev.slots = plan.slots.len();
        ev.active_slots = ev.slots;
        ev.attached_probes = 2;
        ev.semantic_unverified_slots = 1;
        ev.surfaces = plan.surfaces.clone();
        let discovered = &mut ev.discovery.modules[0];
        discovered.dev = (key.device.major, key.device.minor);
        discovered.ino = key.inode;
        discovered.path = plan.modules[0].path.clone();
        discovered.objects[0].dev = discovered.dev;
        discovered.objects[0].ino = discovered.ino;
        discovered.objects[0].path = discovered.path.clone();
        discovered.tables = plan.modules[0].tables.clone();
        discovered.interfaces = plan.modules[0].interfaces;
        ev.verdict();

        assert_eq!(
            state.cgroups()[&7].calls,
            report.calls,
            "the fixture must send every aggregate call through State"
        );
        assert_eq!(state.cgroups()[&7].errors, report.errors);
        assert!(state.mechanisms().is_empty());
        assert_eq!(state.sessions(), crate::semantics::SessionStats::default());
        assert!(state.logins().is_empty());
        assert!(state.templates().is_empty());
        assert_eq!(
            ev.surfaces[0].functions, ev.table_entries,
            "the scan table, surface, and public table-entry count must agree"
        );
        assert_eq!(ev.discovery.modules[0].tables, plan.modules[0].tables);
        assert_eq!(lines.len(), report.calls as usize);
        for (event, line) in events.iter().zip(&lines) {
            let rv = match event.rv {
                0 => "CKR_OK",
                value if value == pkcs11_types::CkRv::GENERAL_ERROR.0 => "CKR_GENERAL_ERROR",
                value if value == pkcs11_types::CkRv::PENDING.0 => "CKR_PENDING",
                value => unreachable!("unexpected fixture RV {value:#x}"),
            };
            // Task 1.3: the scan-only table is unlinked, so the trace never
            // names the slot — it shows the ordinal that reached it as a
            // numbered unnamed function (review answer (c)); the counts
            // and RVs are retained unchanged, with no per-line marker
            // (the header says once that unverified calls are not
            // decoded).
            let ordinal = crate::discovery::scan::standard_ordinal("C_OpenSession").unwrap();
            assert_eq!(
                &line[15..],
                format!(
                    " Unknown executable (PID 100, TID 1) function #{ordinal} (unnamed) → {rv} 100ns"
                ),
                "the generated trace must retain every aggregate RV without semantic payload"
            );
        }
        let profile = profile_json(
            &[report],
            VersionedEvidence::wrap(&ev),
            &state,
            &capture_fixture(),
        );

        assert_eq!(profile["evidence"]["completeness"], "PARTIAL");
        assert_eq!(
            profile["evidence"]["discovery"][0]["sources"],
            serde_json::json!(["scan"])
        );
        let function = &profile["functions"][0];
        assert_eq!(function["calls"], 25);
        assert_eq!(function["errors"], 3);
        assert_eq!(function["pending_returns"], 5);
        assert_eq!(
            function["rv_counts"],
            serde_json::json!({
                "0x0000000000000000": 17,
                "0x0000000000000005": 3,
                "0x0000000000000204": 5,
            })
        );
        assert_eq!(
            function["latency_ns"],
            serde_json::json!({
                "approximate": true,
                "p50": 64,
                "p95": 64,
                "p99": 64,
                "total": 2_500,
                "max": 100,
            })
        );
        assert_eq!(profile["mechanisms"], serde_json::json!([]));
        assert_eq!(
            profile["sessions"],
            serde_json::json!({
                "opened": 0,
                "inherited": 0,
                "closed": 0,
                "async_opened": 0,
                "peak_concurrent": 0,
                "balance": 0,
            })
        );
        assert_eq!(profile["logins"], serde_json::json!({}));
        assert_eq!(profile["templates"]["operations"], serde_json::json!([]));
        assert_eq!(profile["cgroups"][0]["calls"], 25);
        assert_eq!(profile["cgroups"][0]["errors"], 3);
        assert_eq!(profile["cgroups"][0]["mechanisms"], serde_json::json!([]));

        let rendered = format!("{profile}\n{}", lines.join("\n"));
        for value in [
            events[0].session,
            events[0].mechanism,
            events[0].p0,
            events[0].p1,
            events[0].p2,
            u64::from(events[0].user_type),
            events[0].attr_types[0],
        ] {
            for spelling in [
                value.to_string(),
                format!("0x{value:x}"),
                format!("0x{value:016x}"),
            ] {
                assert!(
                    !rendered.contains(&spelling),
                    "scan-only semantic payload leaked: {spelling} in {rendered}"
                );
            }
        }
    }

    #[test]
    fn a_capture_that_discovered_nothing_is_never_complete() {
        let mut ev = evidence();
        ev.discovery.modules.clear();
        ev.verdict();
        assert_eq!(
            ev.completeness, "PARTIAL",
            "no modules ⇒ nothing was observed"
        );
    }

    /// The sibling of the rule above: a module was discovered, but nothing in it
    /// could be attached. No attach failed (none was attempted) and a scan that
    /// decoded no table produces no skips either.
    #[test]
    fn a_capture_that_attached_nothing_is_never_complete() {
        let mut ev = evidence();
        ev.slots = 0;
        ev.active_slots = 0;
        ev.attached_probes = 0;
        ev.verdict();
        assert_eq!(
            ev.completeness, "PARTIAL",
            "no slots ⇒ nothing was observed"
        );
    }

    #[test]
    fn discovery_gaps_each_force_partial() {
        for mutate in [
            (|e: &mut Evidence| e.discovery.conflicts = 1) as fn(&mut Evidence),
            |e: &mut Evidence| e.discovery.uncorroborated = 1,
            |e: &mut Evidence| e.discovery.module_ambiguous = 1,
            |e: &mut Evidence| {
                e.discovery.modules_skipped.push(SkippedOut {
                    name: "/opt/x.so".into(),
                    reason: "capacity".into(),
                })
            },
            // An admitted provider whose growth did not fit stays attached
            // but is only partially covered (G-03).
            |e: &mut Evidence| {
                e.discovery.modules_skipped.push(SkippedOut {
                    name: "/opt/grown.so".into(),
                    reason: GROWTH_OMISSION_RECORD.into(),
                })
            },
            // Only `--pid` gets this transitively from `slots == 0`: a cgroup
            // with one readable and one unreadable process still plans slots.
            |e: &mut Evidence| e.discovery.scan_unavailable = Some("ptrace".into()),
        ] {
            let mut ev = evidence();
            mutate(&mut ev);
            ev.verdict();
            assert_eq!(ev.completeness, "PARTIAL");
        }
    }

    #[test]
    fn manifest_object_fallback_renders_exact_bounded_path_free_partial_evidence() {
        let mut ev = evidence();
        ev.discovery.uncorroborated = 1;
        ev.discovery.manifest_object_fallbacks = vec![ManifestObjectFallback {
            manifest: 2,
            object: 7,
            reason: "identity_mismatch",
            replacement: ManifestReplacement {
                dev: (8, 1),
                ino: 19,
                sha256: "ab".repeat(32),
            },
        }];
        ev.verdict();

        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        assert_eq!(profile["evidence"]["completeness"], "PARTIAL");
        assert_eq!(
            profile["evidence"]["manifest_object_fallbacks"],
            serde_json::json!([{
                "manifest": 2,
                "object": 7,
                "reason": "identity_mismatch",
                "replacement": {
                    "dev": [8, 1],
                    "ino": 19,
                    "sha256": "ab".repeat(32),
                },
            }])
        );
        let rendered = profile.to_string();
        assert!(!rendered.contains("/private/"));
        assert!(!rendered.contains("\"pid\":"));
    }

    #[test]
    fn p2_bracket_refusals_remain_distinct_finite_partial_evidence() {
        let mut ev = evidence();
        let reasons = [
            crate::discovery::scan::MAPPING_CHANGED_REASON,
            "memory scan refused: final mapping validation unavailable: PRIVATE_DETAIL",
        ];
        ev.skipped = reasons
            .iter()
            .map(|reason| {
                capture_skipped_out(&crate::discovery::scan::Skipped {
                    subject: "/PRIVATE_PROVIDER_PATH".into(),
                    reason: (*reason).into(),
                })
            })
            .collect();
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        for document in [
            profile_json(
                &reports_fixture(),
                VersionedEvidence::wrap(&ev),
                &state_fixture(),
                &capture_fixture(),
            ),
            json(&reports_fixture(), &ev, &capture_fixture()),
        ] {
            assert_eq!(document["evidence"]["completeness"], "PARTIAL");
            assert_eq!(
                document["evidence"]["skipped"],
                serde_json::json!([
                    {"name":"discovery subject","reason":"discovery unavailable"},
                    {"name":"discovery subject","reason":"discovery unavailable"}
                ])
            );
            assert!(!document.to_string().contains("PRIVATE_"));
        }
    }

    #[test]
    fn bounded_decode_omissions_render_finite_partial_evidence() {
        use crate::discovery::scan::{Skipped, WORK_CEILING_REASON};

        let mut reasons = vec![
            "capture table decode ceiling reached (512 candidates, 53248 entries); remaining \
             table data was not decoded",
            "capture interface decode ceiling reached (512 records); remaining interface data \
             was not decoded",
        ];
        reasons.push(WORK_CEILING_REASON);
        for reason in reasons {
            let mut ev = evidence();
            ev.skipped = vec![capture_skipped_out(&Skipped {
                subject: "/private/provider.so".into(),
                reason: reason.into(),
            })];
            ev.verdict();
            assert_eq!(ev.completeness, "PARTIAL");
            let profile = profile_json(
                &reports_fixture(),
                VersionedEvidence::wrap(&ev),
                &state_fixture(),
                &capture_fixture(),
            );
            assert_eq!(profile["evidence"]["completeness"], "PARTIAL");
            assert_eq!(
                profile["evidence"]["skipped"][0],
                serde_json::json!({
                    "name": "discovery subject",
                    "reason": "discovery unavailable",
                })
            );
            assert!(!profile.to_string().contains("/private/provider.so"));
        }
    }

    #[test]
    fn v3_json_publishes_modules_and_per_function_module_identity() {
        let v = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&evidence()),
            &state_fixture(),
            &capture_fixture(),
        );
        assert_eq!(v["schema"], "p11scope/observed-profile/v3");
        assert_eq!(v["capture"]["modules"][0]["path"], "/opt/p11.so");
        assert_eq!(
            v["capture"]["modules"][0]["sha256"].as_str().unwrap().len(),
            64
        );
        assert!(
            v["capture"]["module"].is_null(),
            "v1's singular field is gone"
        );
        assert_eq!(v["evidence"]["authority"], "hash-pinned");
        assert_eq!(v["evidence"]["discovery"][0]["sources"][0], "scan");
        assert_eq!(v["functions"][0]["module"]["ino"], 11);
        assert_eq!(
            v["functions"][0]["module"]["dev"],
            serde_json::json!([8, 1])
        );
        assert_eq!(v["functions"][0]["module_ambiguous"], false);
    }

    /// A target two modules both hand out is counted, never attributed: guessing
    /// an owner would attribute one provider's calls to another.
    #[test]
    fn an_ambiguous_slot_is_counted_but_never_attributed_to_a_module() {
        let mut report = report("C_Sign", 3, 0, false);
        report.module = None;
        report.module_ambiguous = true;
        let mut ev = evidence();
        ev.discovery.module_ambiguous = 1;
        ev.verdict();
        let v = profile_json(
            &[report],
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        assert_eq!(v["functions"][0]["module"], serde_json::Value::Null);
        assert_eq!(v["functions"][0]["module_ambiguous"], true);
        assert_eq!(v["functions"][0]["calls"], 3);
        assert_eq!(v["evidence"]["module_ambiguous"], 1);
        assert_eq!(v["evidence"]["completeness"], "PARTIAL");
    }

    #[test]
    fn interface_name_bytes_never_reach_capture_output() {
        // inspect may show names; capture output may not (spec §4.3, allowlist v1).
        // The count is the evidence; the bytes came out of a provider's memory.
        // Both places a name could reach the document are exercised: the
        // per-module discovery record, and the surface label a `--manifest`
        // interface produces — built here by the real labelling function, so
        // this fails if either starts carrying the recorded name.
        let mut ev = evidence();
        ev.discovery.modules[0].interfaces = 3;
        ev.surfaces.push(crate::plan::SurfaceSummary {
            source: crate::plan::source_label(
                &p11scope_manifest::manifest::SurfaceSource::Interface {
                    index: 0,
                    raw_name_hex: Some("504b4353203131".into()),
                    name_lossy: Some("PKCS 11".into()),
                    name_error: None,
                    flags: 1,
                    classification:
                        p11scope_manifest::manifest::InterfaceClassification::ExactStandard,
                },
            ),
            walk: "full".into(),
            acquisition: "ok".into(),
            functions: 92,
        });
        ev.verdict();
        let v = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        let text = serde_json::to_string(&v).unwrap();
        assert!(
            !text.contains("PKCS 11"),
            "interface names must not be rendered in capture output: {text}"
        );
        assert_eq!(v["evidence"]["discovery"][0]["interfaces"], 3);
    }

    /// The copy-up layer marker travels only on the lower file's module
    /// row: ordinary rows keep their exact key set, and the marked row
    /// carries the finite `pre_copy_up` value.
    #[test]
    fn module_layer_serializes_only_on_pre_copy_up_rows() {
        let plain = discovered_fixture();
        let value = serde_json::to_value(&plain).unwrap();
        assert!(
            value.get("layer").is_none(),
            "ordinary rows carry no layer key: {value}"
        );
        let mut marked = plain;
        marked.layer = Some(ModuleLayer::PreCopyUp);
        let value = serde_json::to_value(&marked).unwrap();
        assert_eq!(value["layer"], "pre_copy_up", "{value}");
    }

    /// Under `-v`, function rows attributed to the lower file's module
    /// carry "(file before copy-up)" so two rows sharing one merge path
    /// stay distinguishable; concise shows the same counts unmarked.
    #[test]
    fn verbose_frame_marks_file_before_copy_up_rows() {
        let mut upper = discovered_fixture();
        upper.id = ModuleId(0);
        let mut lower = discovered_fixture();
        lower.id = ModuleId(1);
        lower.layer = Some(ModuleLayer::PreCopyUp);
        lower.sha256 = Some("22".repeat(32));
        let mut ev = evidence();
        ev.discovery.modules = vec![upper, lower];
        let mut fresh = report("C_Sign", 25, 0, false);
        fresh.module = Some(ModuleId(0));
        let mut stale = report("C_Sign", 7, 0, false);
        stale.module = Some(ModuleId(1));
        let frame = |verbosity| {
            live_scoped_with_verbosity(
                &[fresh.clone(), stale.clone()],
                &ev,
                Duration::ZERO,
                "/opt/p11.so (+1 more)",
                "profile",
                CapturePolicy::Allowlisted,
                "selected",
                &BTreeMap::new(),
                verbosity,
            )
        };
        let verbose = frame(crate::cli::TextVerbosity::Verbose);
        assert_eq!(
            verbose.matches("(file before copy-up)").count(),
            1,
            "{verbose}"
        );
        assert!(
            verbose.contains("C_Sign (file before copy-up)"),
            "{verbose}"
        );
        let concise = frame(crate::cli::TextVerbosity::Concise);
        assert!(
            !concise.contains("file before copy-up"),
            "concise stays unmarked: {concise}"
        );
        assert_eq!(
            concise.matches("C_Sign").count(),
            2,
            "concise keeps both rows: {concise}"
        );
        assert!(
            concise.contains("25") && concise.contains('7'),
            "concise keeps both counts: {concise}"
        );
    }

    /// F-13: the evidence line names why a verdict is PARTIAL, from the
    /// same classes the verdict uses — including gates that used to have no
    /// fragment (an unprotected live window) and the terminal seal alone.
    /// The default profile text names capture-wide sessions and
    /// logins from the reducer state the JSON already carries (no new
    /// capture): one concise line beside the mechanisms section, fuller
    /// accounting under `-v`, nothing when no session was opened,
    /// inherited, or logged in.
    #[test]
    fn profile_text_names_sessions_and_logins() {
        use crate::semantics::SessionStats;
        let sessions = SessionStats {
            opened: 3,
            inherited: 0,
            closed: 1,
            async_opened: 0,
            peak_concurrent: 2,
        };
        let logins = BTreeMap::from([(1u32, 1u64)]);
        let frame = |verbosity| {
            live_scoped_with_verbosity_and_sessions(
                &[],
                &evidence(),
                Duration::ZERO,
                "/opt/p11.so",
                "profile",
                CapturePolicy::Allowlisted,
                "selected",
                &BTreeMap::new(),
                verbosity,
                &sessions,
                &logins,
            )
        };
        let concise = frame(crate::cli::TextVerbosity::Concise);
        assert!(
            concise.contains("sessions: 3 opened, peak 2 at once, 2 still open; logins: user ×1"),
            "{concise}"
        );
        let verbose = frame(crate::cli::TextVerbosity::Verbose);
        assert!(
            verbose.contains(
                "sessions: 3 opened, 0 inherited, 1 closed, peak 2 at once, 2 still open; \
                 logins: user ×1"
            ),
            "{verbose}"
        );
        // Control: no sessions, no logins — no line.
        let quiet = live_scoped_with_verbosity_and_sessions(
            &[],
            &evidence(),
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "selected",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Concise,
            &SessionStats::default(),
            &BTreeMap::new(),
        );
        assert!(!quiet.contains("sessions:"), "{quiet}");
    }

    #[test]
    fn live_view_names_why_the_verdict_is_partial() {
        let frame = |mutate: fn(&mut Evidence), seal: bool| {
            let mut ev = evidence();
            mutate(&mut ev);
            ev.verdict();
            if seal {
                ev.mark_terminal_drain_unproven();
            }
            live_scoped_with_verbosity(
                &[],
                &ev,
                Duration::ZERO,
                "/opt/p11.so",
                "profile",
                CapturePolicy::Allowlisted,
                "selected",
                &BTreeMap::new(),
                crate::cli::TextVerbosity::Verbose,
            )
        };
        let out = frame(|ev| ev.event_loss = 12, false);
        assert!(
            out.contains(
                "→ PARTIAL — calls may be missing (observation lossy) \
                 (12 call records lost (event_loss))"
            ),
            "{out}"
        );
        let out = frame(|ev| ev.semantic_unverified_slots = 68, true);
        assert!(
            out.contains(
                "→ PARTIAL — names unconfirmed (attribution withheld) \
                 (function names follow the standard PKCS#11 table but their layout was not verified \
                 from scan (add --manifest to confirm positions for mechanism decoding) (68 slots; semantic_unverified_slots))"
            ),
            "{out}"
        );
        let out = frame(|ev| ev.unprotected_live_windows = 1, false);
        assert!(
            out.contains(
                "calls made while probes were being attached may be missing \
                 (unprotected_live_windows)"
            ),
            "{out}"
        );
        let out = frame(|ev| ev.pending_at_end = 2, false);
        assert!(
            out.contains("2 session-tracking gaps (pending_at_end)"),
            "{out}"
        );
        let out = frame(|_| {}, true);
        assert!(out.contains("end of capture not fully confirmed"), "{out}");
        let out = frame(|_| {}, false);
        assert!(out.trim_end().ends_with("→ COMPLETE"), "{out}");
    }

    fn ring_unexplained_fixture() -> (Evidence, Evidence) {
        let mut discovery = evidence();
        discovery.ring_accounting.discovery = Some(RingAccountEvidence {
            produced: 100,
            consumed: 80,
            dropped: 3,
            still_queued: Some(10),
            unexplained: Some(7),
        });
        let mut events = evidence();
        events.ring_accounting.events = Some(RingAccountEvidence {
            produced: 200,
            consumed: 190,
            dropped: 0,
            still_queued: Some(0),
            unexplained: Some(10),
        });
        (discovery, events)
    }

    /// RED twin: a measured nonzero unexplained remainder is a named
    /// observation gap on its ring and forces PARTIAL, like any loss.
    #[test]
    fn unexplained_ring_remainder_is_a_named_gap() {
        let (mut discovery, mut events) = ring_unexplained_fixture();
        discovery.verdict();
        assert_eq!(discovery.completeness, "PARTIAL");
        assert!(
            discovery
                .gap_classes
                .observation
                .causes
                .contains(&"discovery_ring_unexplained"),
            "{:?}",
            discovery.gap_classes.observation.causes
        );
        events.verdict();
        assert_eq!(events.completeness, "PARTIAL");
        assert!(
            events
                .gap_classes
                .observation
                .causes
                .contains(&"events_ring_unexplained"),
            "{:?}",
            events.gap_classes.observation.causes
        );
        // Control: a balanced account gaps nothing.
        let mut clean = evidence();
        clean.ring_accounting.discovery = Some(RingAccountEvidence {
            produced: 100,
            consumed: 90,
            dropped: 0,
            still_queued: Some(10),
            unexplained: Some(0),
        });
        clean.ring_accounting.events = Some(RingAccountEvidence {
            produced: 50,
            consumed: 50,
            dropped: 0,
            still_queued: Some(0),
            unexplained: Some(0),
        });
        clean.verdict();
        assert_eq!(clean.completeness, "COMPLETE");
    }

    /// RED twin: -v names each ring's unexplained remainder with its
    /// cause, so the loss is found without opening the JSON.
    #[test]
    fn verbose_view_names_each_rings_unexplained_remainder() {
        let (discovery, events) = ring_unexplained_fixture();
        for (mut ev, cause) in [
            (discovery, "discovery_ring_unexplained"),
            (events, "events_ring_unexplained"),
        ] {
            ev.verdict();
            let out = live_scoped_with_verbosity(
                &[],
                &ev,
                Duration::ZERO,
                "/opt/p11.so",
                "profile",
                CapturePolicy::Allowlisted,
                "selected",
                &BTreeMap::new(),
                crate::cli::TextVerbosity::Verbose,
            );
            assert!(out.contains(cause), "{out}");
            assert!(out.contains("unexplained"), "{out}");
        }
    }

    #[test]
    fn live_view_shows_every_discovery_gap_behind_a_partial_verdict() {
        let mut ev = evidence();
        ev.discovery.conflicts = 1;
        ev.discovery.uncorroborated = 2;
        ev.discovery.module_ambiguous = 3;
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/x.so".into(),
            reason: "capacity".into(),
        });
        ev.discovery.scan_unavailable = Some("ptrace".into());
        ev.verdict();
        let out = live(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
        );
        assert!(
            out.contains("manifest and scan disagree on 1 provider file"),
            "{out}"
        );
        assert!(
            out.contains("2 provider files not confirmed from a second source"),
            "{out}"
        );
        assert!(
            out.contains("3 functions claimed by two provider files"),
            "{out}"
        );
        assert!(out.contains("1 provider file not watched"), "{out}");
        assert!(out.contains("memory scan unavailable (ptrace)"), "{out}");
        assert!(out.contains("coverage: partial"), "{out}");
    }

    /// CLI-1/F2: the concise profile summary keeps totals with plain
    /// coverage reasons and no machine names, plus the first module
    /// gaps (file + remedy) so a refused provider is actionable.
    #[test]
    fn concise_profile_summary_keeps_plain_reasons_without_machine_names() {
        let mut ev = evidence();
        ev.event_loss = 12;
        ev.semantic_unverified_slots = 68;
        ev.discovery.conflicts = 1;
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/x.so".into(),
            reason: "capacity".into(),
        });
        ev.verdict();
        let out = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("coverage: partial"), "{out}");
        assert!(out.contains("calls may be missing"), "{out}");
        assert!(out.contains("12 call records lost"), "{out}");
        assert!(out.contains("names unconfirmed"), "{out}");
        assert!(
            out.contains(
                "function names follow the standard PKCS#11 table but their layout was not verified \
                 from scan (add --manifest to confirm positions for mechanism decoding)"
            ),
            "{out}"
        );
        assert!(
            out.contains("manifest and scan disagree on 1 provider file"),
            "{out}"
        );
        for machine in [
            "observation lossy",
            "attribution withheld",
            "semantics-unverified",
            "discovery conflicts",
            "event_loss",
        ] {
            assert!(!out.contains(machine), "{machine} leaked: {out}");
        }
        // F2: concise names the refused file with its remedy.
        assert!(out.contains("Module gaps (showing 1 of 1):"), "{out}");
        assert!(out.contains("/opt/x.so"), "{out}");
        assert!(
            out.contains("capture it alone with --module /opt/x.so"),
            "{out}"
        );
    }

    /// Concise default output names whole capacity refusals before proxy
    /// awaiting-publication lines: with two proxy gaps first, the trust
    /// and snap softokn capacity refusals take the two shown lines, so
    /// the reader sees the real gaps without `-v`. Reasons are verbatim
    /// rc16 report text.
    #[test]
    fn concise_gaps_name_capacity_refusals_before_proxy_lines() {
        const PROXY_AWAITING: &str = "a proxy closure array in a detailed capture attaches only its published tables, and none of its 67 lookalike function tables is published yet, so calls through it are not counted (a proxy closure array is admitted whole, as a prefix when named by the operator, or as published tables; an unnamed layer in a detailed capture attaches only its published tables); the providers it forwards to attach when they load";
        const TRUST_CAPACITY: &str = "module needs 68 more; only 512 attach slots are available; 317 are in use (317 active, 0 retired; held by /usr/lib/x86_64-linux-gnu/libsoftokn3.so 212, /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so 105); 128 are reserved for providers with a corroborated function table — refusing to attach a prefix; to capture one provider, name it with --module <path>; to free slots, exclude an unneeded module with --exclude-module <name>";
        const SNAP_CAPACITY: &str = "module needs 212 more; only 512 attach slots are available; 317 are in use (317 active, 0 retired; held by /usr/lib/x86_64-linux-gnu/libsoftokn3.so 212, /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so 105) — refusing to attach a prefix; to capture one provider, name it with --module <path>; to free slots, exclude an unneeded module with --exclude-module <name>";
        let mut ev = evidence();
        for name in [
            "/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.4.8",
            "/snap/snapd-desktop-integration/391/gnome-platform/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.4.5",
        ] {
            ev.discovery.modules_skipped.push(SkippedOut {
                name: name.into(),
                reason: PROXY_AWAITING.into(),
            });
        }
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so".into(),
            reason: TRUST_CAPACITY.into(),
        });
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/snap/firefox/9057/usr/lib/firefox/libsoftokn3.so".into(),
            reason: SNAP_CAPACITY.into(),
        });
        let out = concise_module_gap_lines(&ev, &reports_fixture());
        assert!(out.contains("Module gaps (showing 2 of 4):"), "{out}");
        assert!(out.contains("p11-kit-trust.so"), "{out}");
        assert!(
            out.contains("snap/firefox/9057/usr/lib/firefox/libsoftokn3.so"),
            "{out}"
        );
        assert!(
            !out.contains("libp11-kit.so"),
            "proxy lines rank below capacity refusals: {out}"
        );
    }

    /// F2: the concise profile summary names a refused provider with
    /// its file and the `--module` remedy (not just the aggregate
    /// "1 provider file not watched" fragment).
    #[test]
    fn concise_profile_summary_names_refused_provider_with_remedy() {
        let mut ev = evidence();
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/refused.so".into(),
            reason: "capacity".into(),
        });
        ev.verdict();
        let out = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("1 provider file not watched"), "{out}");
        assert!(out.contains("/opt/refused.so"), "{out}");
        assert!(
            out.contains("capture it alone with --module /opt/refused.so"),
            "{out}"
        );
    }

    /// CLI text: one coverage format in capture text — `coverage: partial —
    /// <reasons>` and `coverage: complete` — in every verbosity.
    #[test]
    fn coverage_line_uses_one_lowercase_format() {
        let mut partial = evidence();
        partial.event_loss = 12;
        partial.verdict();
        assert_eq!(partial.completeness, "PARTIAL");
        for verbosity in [
            crate::cli::TextVerbosity::Concise,
            crate::cli::TextVerbosity::Verbose,
            crate::cli::TextVerbosity::Quiet,
        ] {
            let out = scope_summary_with_verbosity("pid", &reports_fixture(), &partial, verbosity);
            assert!(out.contains("coverage: partial — "), "{verbosity:?}: {out}");
            assert!(!out.contains("Coverage PARTIAL"), "{verbosity:?}: {out}");
            assert!(!out.contains("Coverage COMPLETE"), "{verbosity:?}: {out}");
        }
        let mut complete = evidence();
        complete.verdict();
        assert_eq!(complete.completeness, "COMPLETE");
        for verbosity in [
            crate::cli::TextVerbosity::Concise,
            crate::cli::TextVerbosity::Verbose,
            crate::cli::TextVerbosity::Quiet,
        ] {
            let out = scope_summary_with_verbosity("pid", &reports_fixture(), &complete, verbosity);
            assert!(out.contains("coverage: complete"), "{verbosity:?}: {out}");
            assert!(!out.contains("Coverage COMPLETE"), "{verbosity:?}: {out}");
        }
    }

    /// CLI text: every counted coverage fragment uses the singular for
    /// one and the plural otherwise.
    #[test]
    fn coverage_counts_use_singular_for_one() {
        fn summary(mutated: fn(&mut Evidence)) -> String {
            let mut ev = evidence();
            // The loader aggregate is complete by default; keep every
            // other gate clean so each arm below pins only its fragment.
            mutated(&mut ev);
            ev.verdict();
            scope_summary_with_verbosity(
                "pid",
                &reports_fixture(),
                &ev,
                crate::cli::TextVerbosity::Concise,
            )
        }
        fn bad_surface() -> crate::plan::SurfaceSummary {
            crate::plan::SurfaceSummary {
                source: "legacy_function_list".into(),
                walk: "partial".into(),
                acquisition: "ok".into(),
                functions: 68,
            }
        }
        fn refused(module: &str, reason: &str) -> SkippedOut {
            SkippedOut {
                name: module.into(),
                reason: reason.into(),
            }
        }
        // (mutation for one, mutation for two, singular, plural)
        type CountArm = (
            fn(&mut Evidence),
            fn(&mut Evidence),
            &'static str,
            &'static str,
        );
        let arms: Vec<CountArm> = vec![
            (
                |ev| ev.attach_failures.push("slot 3: EPERM".into()),
                |ev| {
                    ev.attach_failures.push("slot 3: EPERM".into());
                    ev.attach_failures.push("slot 4: EPERM".into());
                },
                "1 function could not be watched",
                "2 functions could not be watched",
            ),
            (
                |ev| ev.in_flight_at_end = 1,
                |ev| ev.in_flight_at_end = 2,
                "1 call still running at capture end",
                "2 calls still running at capture end",
            ),
            (
                |ev| ev.surfaces = vec![ok_surface(), bad_surface()],
                |ev| ev.surfaces = vec![bad_surface(), bad_surface()],
                "1 provider table incompletely read",
                "2 provider tables incompletely read",
            ),
            (
                |ev| ev.vendor_interfaces = 1,
                |ev| ev.vendor_interfaces = 2,
                "1 vendor-specific interface not decoded",
                "2 vendor-specific interfaces not decoded",
            ),
            (
                |ev| ev.event_loss = 1,
                |ev| ev.event_loss = 2,
                "1 call record lost",
                "2 call records lost",
            ),
            (
                |ev| ev.start_insert_failures = 1,
                |ev| ev.start_insert_failures = 2,
                "1 call start not recorded",
                "2 call starts not recorded",
            ),
            (
                |ev| ev.unmatched_returns = 1,
                |ev| ev.unmatched_returns = 2,
                "1 return without a recorded start",
                "2 returns without a recorded start",
            ),
            (
                |ev| ev.rv_update_failures = 1,
                |ev| ev.rv_update_failures = 2,
                "1 return value not recorded",
                "2 return values not recorded",
            ),
            (
                |ev| ev.cgroup_scope_failures = 1,
                |ev| ev.cgroup_scope_failures = 2,
                "1 cgroup membership check failed",
                "2 cgroup membership checks failed",
            ),
            (
                |ev| ev.abi_refusals = 1,
                |ev| ev.abi_refusals = 2,
                "1 unexpected probe hit refused",
                "2 unexpected probe hits refused",
            ),
            (
                |ev| ev.malformed_records = 1,
                |ev| ev.malformed_records = 2,
                "1 unreadable kernel record",
                "2 unreadable kernel records",
            ),
            (
                |ev| ev.discovery_ring_loss = 1,
                |ev| ev.discovery_ring_loss = 2,
                "1 discovery record lost",
                "2 discovery records lost",
            ),
            (
                |ev| ev.discovery_state_failures = 1,
                |ev| ev.discovery_state_failures = 2,
                "1 discovery update failed",
                "2 discovery updates failed",
            ),
            (
                |ev| ev.discovery_read_failures = 1,
                |ev| ev.discovery_read_failures = 2,
                "1 discovery read failed",
                "2 discovery reads failed",
            ),
            (
                |ev| ev.discovery_truncated = 1,
                |ev| ev.discovery_truncated = 2,
                "1 discovery record truncated",
                "2 discovery records truncated",
            ),
            (
                |ev| ev.task_uprobe_link_losses = 1,
                |ev| ev.task_uprobe_link_losses = 2,
                "1 probe link lost",
                "2 probe links lost",
            ),
            (
                |ev| ev.pause_partial = 1,
                |ev| ev.pause_partial = 2,
                "1 load only partly paused",
                "2 loads only partly paused",
            ),
            (
                |ev| ev.pause_unavailable = 1,
                |ev| ev.pause_unavailable = 2,
                "1 load could not be paused (collected unpaused)",
                "2 loads could not be paused (collected unpaused)",
            ),
            (
                |ev| ev.multi_rebuild_gaps = 1,
                |ev| ev.multi_rebuild_gaps = 2,
                "1 probe re-attach gap",
                "2 probe re-attach gaps",
            ),
            (
                |ev| ev.aliased = vec![vec!["C_Sign".into(), "C_Encrypt".into()]],
                |ev| {
                    ev.aliased = vec![
                        vec!["C_Sign".into(), "C_Encrypt".into()],
                        vec!["C_Digest".into(), "C_DigestUpdate".into()],
                    ];
                },
                "1 function sharing an address",
                "2 functions sharing an address",
            ),
            (
                |ev| ev.discovery.module_ambiguous = 1,
                |ev| ev.discovery.module_ambiguous = 2,
                "1 function claimed by two provider files",
                "2 functions claimed by two provider files",
            ),
            (
                |ev| ev.module_unresolved_slots = 1,
                |ev| ev.module_unresolved_slots = 2,
                "1 function with no proven provider file",
                "2 functions with no proven provider file",
            ),
            (
                |ev| ev.unregistered_mechanisms = 1,
                |ev| ev.unregistered_mechanisms = 2,
                "1 unregistered mechanism",
                "2 unregistered mechanisms",
            ),
            (
                |ev| ev.unpublished_mechanisms = 1,
                |ev| ev.unpublished_mechanisms = 2,
                "1 vendor mechanism not listed by name",
                "2 vendor mechanisms not listed by name",
            ),
            (
                |ev| ev.discovery.uncorroborated = 1,
                |ev| ev.discovery.uncorroborated = 2,
                "1 provider file not confirmed from a second source",
                "2 provider files not confirmed from a second source",
            ),
            (
                |ev| ev.semantic_capture_failures = 1,
                |ev| ev.semantic_capture_failures = 2,
                "1 mechanism detail not recorded",
                "2 mechanism details not recorded",
            ),
            (
                |ev| ev.template_tail_failures = 1,
                |ev| ev.template_tail_failures = 2,
                "1 attribute-list read not recorded",
                "2 attribute-list reads not recorded",
            ),
            (
                |ev| ev.semantic_history_drops = 1,
                |ev| ev.semantic_history_drops = 2,
                "1 mechanism history dropped",
                "2 mechanism histories dropped",
            ),
            (
                |ev| ev.shape_decode_total_failures = 1,
                |ev| ev.shape_decode_total_failures = 2,
                "1 mechanism never decoded",
                "2 mechanisms never decoded",
            ),
            (
                |ev| ev.pending_at_end = 1,
                |ev| ev.pending_at_end = 2,
                "1 session-tracking gap",
                "2 session-tracking gaps",
            ),
            (
                |ev| ev.pid_descendant_gaps = 1,
                |ev| ev.pid_descendant_gaps = 2,
                "1 short-lived process gap",
                "2 short-lived process gaps",
            ),
            (
                |ev| {
                    ev.stdout_data_sink = true;
                    ev.scheduling.sink_dropped_bytes = 1;
                },
                |ev| {
                    ev.stdout_data_sink = true;
                    ev.scheduling.sink_dropped_bytes = 2;
                },
                "1 output byte dropped",
                "2 output bytes dropped",
            ),
            (
                |ev| ev.discovery.modules_skipped = vec![refused("/opt/a.so", "capacity")],
                |ev| {
                    ev.discovery.modules_skipped = vec![
                        refused("/opt/a.so", "capacity"),
                        refused("/opt/b.so", "capacity"),
                    ];
                },
                "1 provider file not watched",
                "2 provider files not watched",
            ),
            (
                |ev| {
                    ev.discovery.modules_skipped =
                        vec![refused("/opt/a.so", "admitted module needs 5 more slots")];
                },
                |ev| {
                    ev.discovery.modules_skipped = vec![
                        refused("/opt/a.so", "admitted module needs 5 more slots"),
                        refused("/opt/b.so", "admitted module needs 5 more slots"),
                    ];
                },
                "1 provider file partially covered",
                "2 provider files partially covered",
            ),
        ];
        for (one, two, singular, plural) in arms {
            let out = summary(one);
            assert!(out.contains(singular), "missing {singular:?}: {out}");
            let out = summary(two);
            assert!(out.contains(plural), "missing {plural:?}: {out}");
        }
    }

    /// CLI text: discovery-subject skips are unavailable discovery
    /// steps, not skipped functions; verbose lists each item with its
    /// reason.
    #[test]
    fn skipped_discovery_subjects_render_as_unavailable_steps() {
        let subject = || SkippedOut {
            name: "discovery subject".into(),
            reason: "discovery unavailable".into(),
        };
        let function = || SkippedOut {
            name: "C_Sign".into(),
            reason: "function entry unavailable".into(),
        };
        // Subjects alone: no "functions skipped" at all.
        let mut ev = evidence();
        ev.skipped = vec![subject()];
        ev.verdict();
        let out = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("1 discovery step unavailable"), "{out}");
        assert!(!out.contains("functions skipped"), "{out}");
        assert!(!out.contains("function skipped"), "{out}");
        // Mixed: both fragments, each counted.
        let mut ev = evidence();
        ev.skipped = vec![subject(), subject(), function()];
        ev.verdict();
        let out = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("2 discovery steps unavailable"), "{out}");
        assert!(out.contains("1 function skipped"), "{out}");
        // Verbose lists the items with their reasons.
        let out = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(out.contains("C_Sign (function entry unavailable)"), "{out}");
        assert!(
            out.contains("discovery subject (discovery unavailable)"),
            "{out}"
        );
    }

    /// CLI text: loader and live-window gaps read as plain words,
    /// never as internal mechanism names.
    #[test]
    fn loader_gaps_use_plain_words() {
        let summary = |mutated: fn(&mut Evidence)| {
            let mut ev = evidence();
            mutated(&mut ev);
            ev.verdict();
            scope_summary_with_verbosity(
                "pid",
                &reports_fixture(),
                &ev,
                crate::cli::TextVerbosity::Concise,
            )
        };
        let out = summary(|ev| ev.unprotected_live_windows = 1);
        assert!(
            out.contains("calls made while probes were being attached may be missing"),
            "{out}"
        );
        assert!(!out.contains("unguarded live capture window"), "{out}");
        let out = summary(|ev| ev.loader_discovery.initial_set_capture.none = 1);
        assert!(
            out.contains("library-load tracking could not be confirmed"),
            "{out}"
        );
        assert!(!out.contains("live loader timing unproven"), "{out}");
        let out = summary(|ev| {
            ev.loader_discovery.initial_set_capture.none = 1;
            ev.loader_discovery.strategies.debug_state_every_hit = 2;
        });
        assert!(
            out.contains("library-load tracking missed loads it should have seen"),
            "{out}"
        );
        assert!(!out.contains("uprobe miss suspected"), "{out}");
        let out = summary(|ev| {
            ev.loader_discovery.initial_set_capture.none = 1;
            ev.loader_discovery.strategies.debug_state_every_hit = 1;
        });
        assert!(
            out.contains("library-load tracking received nothing from the kernel"),
            "{out}"
        );
        assert!(!out.contains("delivery failure suspected"), "{out}");
    }

    /// CLI text: when names are the only gap, counts are complete and
    /// the names follow the standard table unconfirmed — never
    /// "withheld" above a table that names them.
    #[test]
    fn attribution_only_coverage_names_unconfirmed_standard_names() {
        let mut ev = evidence();
        ev.semantic_unverified_slots = 68;
        ev.verdict();
        assert_eq!(ev.verdict_detail, VERDICT_ATTRIBUTION_ONLY);
        let out = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Concise,
        );
        assert!(
            out.contains(
                "coverage: partial — counts complete; function names follow the standard PKCS#11 table \
                 but their layout was not verified from scan (add --manifest to confirm positions for mechanism decoding)"
            ),
            "{out}"
        );
        assert!(!out.contains("names withheld"), "{out}");
        assert!(!out.contains("counted but not named"), "{out}");
        let out = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(out.contains("coverage: partial — counts complete"), "{out}");
        assert!(out.contains("semantic_unverified_slots"), "{out}");
        assert!(out.contains("68"), "{out}");
        // Beside a concrete gap the group keeps its label, reworded.
        let mut ev = evidence();
        ev.event_loss = 12;
        ev.semantic_unverified_slots = 68;
        ev.verdict();
        let out = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("names unconfirmed"), "{out}");
        assert!(!out.contains("names withheld"), "{out}");
    }

    /// F2: attribution-only text must state the same PARTIAL verdict as
    /// JSON (`evidence.completeness: PARTIAL`, `attribution_only`), in
    /// plain words: partial, with counts complete and names unconfirmed.
    /// Never `coverage: counts complete` without the partial verdict.
    #[test]
    fn attribution_only_coverage_states_partial_with_counts_complete() {
        let mut ev = evidence();
        ev.semantic_unverified_slots = 68;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        assert_eq!(ev.verdict_detail, VERDICT_ATTRIBUTION_ONLY);
        for verbosity in [
            crate::cli::TextVerbosity::Concise,
            crate::cli::TextVerbosity::Verbose,
        ] {
            let out = scope_summary_with_verbosity("pid", &reports_fixture(), &ev, verbosity);
            assert!(
                out.contains("coverage: partial"),
                "{verbosity:?} states partial like JSON: {out}"
            );
            assert!(
                out.contains("counts complete"),
                "{verbosity:?} keeps counts complete: {out}"
            );
            assert!(
                !out.contains("coverage: counts complete"),
                "{verbosity:?} never contradicts JSON with a complete verdict: {out}"
            );
        }
    }

    /// CLI text: the frame header states the scope once, and the
    /// privacy mode only under -v.
    #[test]
    fn frame_header_states_scope_once_without_default_privacy() {
        let mut ev = evidence();
        ev.verdict();
        let frame = |verbosity| {
            live_scoped_with_verbosity(
                &[],
                &ev,
                Duration::ZERO,
                "/opt/p11.so",
                "profile",
                CapturePolicy::Allowlisted,
                "pid",
                &BTreeMap::new(),
                verbosity,
            )
        };
        let out = frame(crate::cli::TextVerbosity::Concise);
        assert!(
            out.contains("p11scope — PID scope — up 00:00:00 — mode profile — /opt/p11.so\n"),
            "{out}"
        );
        assert!(!out.contains("privacy="), "{out}");
        assert!(!out.contains("Scope: PID scope"), "{out}");
        let out = frame(crate::cli::TextVerbosity::Verbose);
        assert!(out.contains("privacy=allowlisted"), "{out}");
        assert!(!out.contains("Scope: PID scope"), "{out}");
        let out = frame(crate::cli::TextVerbosity::Quiet);
        assert!(!out.contains("privacy="), "{out}");
    }

    /// CLI text: an owned run that never paused while its command ran
    /// ahead names the missed load and the `--pause auto` remedy; a
    /// command with no missed load keeps the generic reasons.
    #[test]
    fn owned_run_without_pause_names_the_missed_provider_load() {
        const REMEDY: &str = "the command loaded its provider before probes attached; \
                              rerun with --pause auto";
        let subject = || SkippedOut {
            name: "discovery subject".into(),
            reason: "discovery unavailable".into(),
        };
        let mut ev = evidence();
        ev.discovery.modules.clear();
        ev.slots = 0;
        ev.active_slots = 0;
        ev.child_still_running = Some(false);
        ev.unprotected_live_windows = 1;
        ev.discovery_truncated = 1;
        ev.skipped = vec![subject(), subject()];
        ev.verdict();
        for verbosity in [
            crate::cli::TextVerbosity::Concise,
            crate::cli::TextVerbosity::Quiet,
        ] {
            let out = scope_summary_with_verbosity("pid", &[], &ev, verbosity);
            assert!(
                out.contains(&format!("coverage: partial — {REMEDY}")),
                "{verbosity:?}: {out}"
            );
            assert!(
                !out.contains("no provider files found"),
                "{verbosity:?}: {out}"
            );
        }
        let out = scope_summary_with_verbosity("pid", &[], &ev, crate::cli::TextVerbosity::Verbose);
        assert!(out.contains(REMEDY), "{out}");
        assert!(out.contains("unprotected_live_windows"), "{out}");
        // No missed load: a bare command keeps the generic reasons.
        let mut ev = evidence();
        ev.discovery.modules.clear();
        ev.slots = 0;
        ev.active_slots = 0;
        ev.child_still_running = Some(false);
        ev.unprotected_live_windows = 1;
        ev.skipped = vec![subject()];
        ev.verdict();
        let out = scope_summary_with_verbosity("pid", &[], &ev, crate::cli::TextVerbosity::Concise);
        assert!(!out.contains(REMEDY), "{out}");
        assert!(out.contains("no provider files found"), "{out}");
        // Pause protection was used: no remedy either.
        let mut ev = evidence();
        ev.discovery.modules.clear();
        ev.slots = 0;
        ev.active_slots = 0;
        ev.child_still_running = Some(false);
        ev.pause = "sigstop";
        ev.pause_attempts = 1;
        ev.pause_confirmed = 1;
        ev.unprotected_live_windows = 1;
        ev.discovery_truncated = 1;
        ev.verdict();
        let out = scope_summary_with_verbosity("pid", &[], &ev, crate::cli::TextVerbosity::Concise);
        assert!(!out.contains(REMEDY), "{out}");
        // Not an owned run: no remedy.
        let mut ev = evidence();
        ev.discovery.modules.clear();
        ev.slots = 0;
        ev.active_slots = 0;
        ev.unprotected_live_windows = 1;
        ev.discovery_truncated = 1;
        ev.verdict();
        let out = scope_summary_with_verbosity("pid", &[], &ev, crate::cli::TextVerbosity::Concise);
        assert!(!out.contains(REMEDY), "{out}");
    }

    /// CLI text: one latency legend, and no function table at all
    /// when nothing was called.
    #[test]
    fn empty_capture_omits_table_and_keeps_one_legend() {
        let mut ev = evidence();
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Concise,
        );
        assert!(!out.contains("FUNCTION"), "{out}");
        assert!(!out.contains("CALLS = completed calls"), "{out}");
        assert!(!out.contains("Latency units"), "{out}");
        assert!(!out.contains("log2-bucket approximation"), "{out}");
        let out = live_scoped_with_verbosity(
            &reports_fixture(),
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("FUNCTION"), "{out}");
        assert_eq!(
            out.matches("log2-bucket approximation, lower bound")
                .count(),
            1,
            "{out}"
        );
    }

    /// CLI text: a refused pause prints one plain line saying why, at
    /// every verbosity, and nothing when the pause was not refused.
    #[test]
    fn refused_pause_prints_one_plain_line() {
        use crate::cli::TextVerbosity;
        for (refused, line) in [
            ("interrupted", "pause refused: interrupted by operator stop"),
            (
                "refused",
                "pause refused: protection could not be completed",
            ),
        ] {
            let mut ev = evidence();
            ev.pause = "partial";
            ev.pause_attempts = 1;
            ev.pause_partial = 1;
            ev.pause_refused = Some(refused);
            ev.verdict();
            for verbosity in [
                TextVerbosity::Concise,
                TextVerbosity::Verbose,
                TextVerbosity::Quiet,
            ] {
                let out = live_scoped_with_verbosity(
                    &[],
                    &ev,
                    Duration::ZERO,
                    "/opt/p11.so",
                    "profile",
                    CapturePolicy::Allowlisted,
                    "pid",
                    &BTreeMap::new(),
                    verbosity,
                );
                assert!(out.contains(line), "{out}");
                assert_eq!(
                    out.matches("pause refused:").count(),
                    1,
                    "exactly one refusal line: {out}"
                );
            }
        }
        let mut ev = evidence();
        ev.pause = "partial";
        ev.pause_attempts = 1;
        ev.pause_partial = 1;
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            TextVerbosity::Concise,
        );
        assert!(!out.contains("pause refused:"), "{out}");
    }

    /// A zero-snapshot terminal names the failed read in coverage and in
    /// JSON: PARTIAL with the `snapshot_failure` cause beside the field.
    #[test]
    fn snapshot_failure_names_the_failed_read_in_text_and_json() {
        let degraded = crate::metrics::CaptureSnapshot::degraded_counter(
            "read_rvs",
            crate::metrics::KernelEvidence::default(),
            "counter collection unavailable (read_rvs)".to_string(),
        );
        let mut ev = evidence();
        apply_snapshot_failure(&mut ev, &degraded);
        assert_eq!(ev.snapshot_failure, Some("read_rvs"));
        assert_eq!(ev.completeness, "PARTIAL");
        let out = live_scoped_with_verbosity(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Concise,
        );
        assert!(
            out.contains("aggregate snapshot unavailable (read_rvs): function counts unknown"),
            "{out}"
        );
        let document = json(&reports_fixture(), &ev, &capture_fixture());
        assert_eq!(document["evidence"]["snapshot_failure"], "read_rvs");
        let causes = document["evidence"]["gap_classes"]["observation"]["causes"]
            .as_array()
            .expect("observation causes");
        assert!(
            causes.iter().any(|cause| cause == "snapshot_failure"),
            "{causes:?}"
        );
    }

    /// CLI text: the function table names each row's provider file, so
    /// identical function names from two providers stay distinct;
    /// shared and unknown rows say so instead of guessing.
    #[test]
    fn function_table_names_each_rows_provider() {
        fn module(id: u32, path: &str) -> DiscoveredModule {
            let mut module = discovered_fixture();
            module.id = crate::plan::ModuleId(id);
            module.path = path.into();
            module
        }
        let mut ev = evidence();
        ev.discovery.modules = vec![module(0, "/opt/a.so"), module(1, "/opt/b.so")];
        ev.verdict();
        let mut first = report("C_Initialize", 188, 0, false);
        first.module = Some(crate::plan::ModuleId(0));
        let mut second = report("C_Initialize", 2, 0, false);
        second.module = Some(crate::plan::ModuleId(1));
        let mut shared = report("C_Sign", 30, 0, false);
        shared.module_ambiguous = true;
        let unknown = report("C_Digest", 4001, 0, false);
        let out = live_scoped_with_verbosity(
            &[first, second, shared, unknown],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "system",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("PROVIDER"), "{out}");
        let line_for = |text: &str| {
            out.lines()
                .find(|line| line.contains(text))
                .unwrap_or_else(|| panic!("missing {text} in:\n{out}"))
                .to_string()
        };
        assert!(line_for("188").contains("a.so"), "{out}");
        assert!(line_for("C_Sign").contains("two providers"), "{out}");
        assert!(line_for("C_Digest").contains("unknown"), "{out}");
        let twins: Vec<String> = out
            .lines()
            .filter(|line| line.contains("C_Initialize"))
            .map(str::to_string)
            .collect();
        assert_eq!(twins.len(), 2, "{out}");
        assert!(twins.iter().any(|line| line.contains("a.so")), "{out}");
        assert!(twins.iter().any(|line| line.contains("b.so")), "{out}");
    }

    /// CLI text: the Initialize marker reports the outcome only; the
    /// provider column beside it names the file.
    #[test]
    fn initialization_suffix_never_claims_a_provider() {
        let mut ok = report("C_Initialize", 2, 0, false);
        ok.rv_counts.insert(pkcs11_types::CkRv::OK.0, 2);
        let mut ev = evidence();
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[ok],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("[init: ok]"), "{out}");
        assert!(!out.contains("potential provider"), "{out}");
    }

    /// v070-ckr-reasons: concise profile text names each function's
    /// failure reasons (`CKR_*` with counts), not just error counts.
    /// Successes are never listed as reasons.
    #[test]
    fn concise_text_names_per_function_ckr_reasons() {
        let mut row = report("C_Login", 5, 0, false);
        row.errors = 4;
        row.rv_counts.insert(pkcs11_types::CkRv::OK.0, 1);
        row.rv_counts.insert(pkcs11_types::CkRv::PIN_INCORRECT.0, 3);
        row.rv_counts
            .insert(pkcs11_types::CkRv::USER_NOT_LOGGED_IN.0, 1);
        let mut ev = evidence();
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[row],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("ERROR REASONS:"), "{out}");
        assert!(
            out.contains("C_Login: CKR_PIN_INCORRECT x3, CKR_USER_NOT_LOGGED_IN x1"),
            "{out}"
        );
        assert!(!out.contains("CKR_OK"), "{out}");
    }

    /// v070-ckr-reasons: concise text bounds each function to its top
    /// three reasons plus an `and N more` tail.
    #[test]
    fn concise_text_bounds_reasons_to_top_three_with_and_more() {
        let mut row = report("C_Sign", 15, 0, false);
        row.errors = 15;
        for (rv, count) in [
            (pkcs11_types::CkRv::GENERAL_ERROR.0, 5),
            (pkcs11_types::CkRv::DEVICE_ERROR.0, 4),
            (pkcs11_types::CkRv::KEY_HANDLE_INVALID.0, 3),
            (pkcs11_types::CkRv::SESSION_HANDLE_INVALID.0, 2),
            (pkcs11_types::CkRv::OPERATION_NOT_INITIALIZED.0, 1),
        ] {
            row.rv_counts.insert(rv, count);
        }
        let mut ev = evidence();
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[row],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Concise,
        );
        assert!(
            out.contains(
                "C_Sign: CKR_GENERAL_ERROR x5, CKR_DEVICE_ERROR x4, \
                 CKR_KEY_HANDLE_INVALID x3, and 2 more"
            ),
            "{out}"
        );
        assert!(!out.contains("CKR_SESSION_HANDLE_INVALID"), "{out}");
        assert!(!out.contains("CKR_OPERATION_NOT_INITIALIZED"), "{out}");
    }

    /// v070-ckr-reasons: verbose text lists every distinct failure
    /// reason per function, with no truncation tail.
    #[test]
    fn verbose_text_lists_every_distinct_ckr_reason() {
        let mut row = report("C_Sign", 15, 0, false);
        row.errors = 15;
        for (rv, count) in [
            (pkcs11_types::CkRv::GENERAL_ERROR.0, 5),
            (pkcs11_types::CkRv::DEVICE_ERROR.0, 4),
            (pkcs11_types::CkRv::KEY_HANDLE_INVALID.0, 3),
            (pkcs11_types::CkRv::SESSION_HANDLE_INVALID.0, 2),
            (pkcs11_types::CkRv::OPERATION_NOT_INITIALIZED.0, 1),
        ] {
            row.rv_counts.insert(rv, count);
        }
        let mut ev = evidence();
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[row],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Verbose,
        );
        for name in [
            "CKR_GENERAL_ERROR x5",
            "CKR_DEVICE_ERROR x4",
            "CKR_KEY_HANDLE_INVALID x3",
            "CKR_SESSION_HANDLE_INVALID x2",
            "CKR_OPERATION_NOT_INITIALIZED x1",
        ] {
            assert!(out.contains(name), "{out}");
        }
        assert!(!out.contains("and 2 more"), "{out}");
    }

    /// v070-ckr-reasons: unregistered (vendor) return codes render as
    /// verbatim hex, never as a guessed name.
    #[test]
    fn text_reasons_render_vendor_codes_as_hex() {
        let mut row = report("C_Login", 3, 0, false);
        row.errors = 3;
        row.rv_counts.insert(0x8000_0001, 2);
        row.rv_counts.insert(pkcs11_types::CkRv::PIN_INCORRECT.0, 1);
        let mut ev = evidence();
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[row],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("0x80000001 x2"), "{out}");
        assert!(!out.contains("CKR_UNKNOWN"), "{out}");
    }

    /// v070-ckr-reasons: a function with errors but no error breakdown
    /// in `rv_counts` (the return-value table read failed) degrades to
    /// a named gap instead of stopping the view.
    #[test]
    fn text_reasons_degrade_when_the_breakdown_is_unavailable() {
        let mut row = report("C_Sign", 3, 0, false);
        row.errors = 3;
        let mut ev = evidence();
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[row],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("FUNCTION"), "{out}");
        assert!(
            out.contains("C_Sign: 3 errors (return-code breakdown unavailable)"),
            "{out}"
        );
    }

    /// v070-ckr-reasons: a clean capture renders no reasons section at
    /// all — the addition is invisible without failures.
    #[test]
    fn clean_capture_text_has_no_error_reasons_section() {
        let mut row = report("C_Sign", 3, 0, false);
        row.rv_counts.insert(pkcs11_types::CkRv::OK.0, 3);
        let mut ev = evidence();
        ev.verdict();
        for verbosity in [
            crate::cli::TextVerbosity::Concise,
            crate::cli::TextVerbosity::Verbose,
        ] {
            let out = live_scoped_with_verbosity(
                &[row.clone()],
                &ev,
                Duration::ZERO,
                "/opt/p11.so",
                "profile",
                CapturePolicy::Allowlisted,
                "pid",
                &BTreeMap::new(),
                verbosity,
            );
            assert!(!out.contains("ERROR REASONS"), "{verbosity:?}: {out}");
        }
    }

    /// v070-ckr-reasons: profile JSON carries `rv_names` beside the
    /// existing hex-keyed `rv_counts`: every registered code maps to
    /// its `CKR_*` name, unregistered codes stay hex-only.
    #[test]
    fn profile_json_carries_rv_names_next_to_rv_counts() {
        let mut row = report("C_Login", 6, 0, false);
        row.errors = 5;
        row.rv_counts.insert(pkcs11_types::CkRv::OK.0, 1);
        row.rv_counts.insert(pkcs11_types::CkRv::PIN_INCORRECT.0, 3);
        row.rv_counts.insert(0x8000_0001, 2);
        let ev = evidence();
        let state = state_fixture();
        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::Allowlisted,
            scope: "pid",
            caller: None,
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let profile = profile_json(&[row], VersionedEvidence::wrap(&ev), &state, &capture);
        let function = &profile["functions"][0];
        assert_eq!(
            function["rv_counts"],
            serde_json::json!({
                "0x0000000000000000": 1,
                "0x00000000000000a0": 3,
                "0x0000000080000001": 2,
            }),
            "{profile}"
        );
        assert_eq!(
            function["rv_names"],
            serde_json::json!({
                "0x0000000000000000": "CKR_OK",
                "0x00000000000000a0": "CKR_PIN_INCORRECT",
            }),
            "{profile}"
        );
    }

    /// v070-ckr-reasons: the metrics lane shares the same renderer, so
    /// its rows carry `rv_names` too.
    #[test]
    fn metrics_json_carries_rv_names_next_to_rv_counts() {
        let mut row = report("C_Login", 4, 0, false);
        row.errors = 3;
        row.rv_counts.insert(pkcs11_types::CkRv::OK.0, 1);
        row.rv_counts.insert(pkcs11_types::CkRv::PIN_INCORRECT.0, 3);
        let ev = evidence();
        let document = json(
            &[row],
            &ev,
            &CaptureMeta {
                started: "t0",
                ended: "t1",
                kernel: "6.8.0",
                policy: CapturePolicy::AggregateOnly,
                scope: "pid",
                caller: None,
                ring_bytes: p11scope_ebpf_common::RING_BYTES,
                drain_interval_ms: 1000,
            },
        );
        assert_eq!(
            document["functions"][0]["rv_names"],
            serde_json::json!({
                "0x0000000000000000": "CKR_OK",
                "0x00000000000000a0": "CKR_PIN_INCORRECT",
            }),
            "{document}"
        );
    }

    /// F2: with lost events, concise and verbose show coverage once —
    /// the `call records lost` fragment — without the duplicate
    /// `Coverage partial: event detail was lost` sentence.
    #[test]
    fn profile_summary_shows_coverage_once_with_event_loss() {
        let mut ev = evidence();
        ev.event_loss = 12;
        ev.verdict();
        for verbosity in [
            crate::cli::TextVerbosity::Concise,
            crate::cli::TextVerbosity::Verbose,
        ] {
            let out = scope_summary_with_verbosity("pid", &reports_fixture(), &ev, verbosity);
            assert!(out.contains("12 call records lost"), "{verbosity:?}: {out}");
            assert!(
                !out.contains("event detail was lost"),
                "{verbosity:?} duplicates coverage: {out}"
            );
            assert!(
                !out.contains("Aggregate counts use the counter maps"),
                "{verbosity:?} duplicates coverage: {out}"
            );
            // One coverage verdict, not two worded differently.
            let coverage_lines = out
                .lines()
                .filter(|line| line.to_lowercase().starts_with("coverage:"))
                .count();
            assert_eq!(coverage_lines, 1, "{verbosity:?}: {out}");
        }
    }

    /// CLI-1: the verbose profile summary pairs every machine name with
    /// its plain reason and keeps the module-gap section.
    #[test]
    fn verbose_profile_summary_pairs_machine_names_with_plain_reasons() {
        let mut ev = evidence();
        ev.event_loss = 12;
        ev.semantic_unverified_slots = 68;
        ev.discovery.conflicts = 1;
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/x.so".into(),
            reason: "capacity".into(),
        });
        ev.verdict();
        let out = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(
            out.contains("calls may be missing (observation lossy)"),
            "{out}"
        );
        assert!(out.contains("12 call records lost (event_loss)"), "{out}");
        assert!(
            out.contains("names unconfirmed (attribution withheld)"),
            "{out}"
        );
        assert!(
            out.contains(
                "function names follow the standard PKCS#11 table but their layout was not verified \
                 from scan (add --manifest to confirm positions for mechanism decoding) (68 slots; semantic_unverified_slots)"
            ),
            "{out}"
        );
        assert!(out.contains("(discovery_conflicts)"), "{out}");
        assert!(out.contains("Module gaps"), "{out}");
    }

    /// CLI-1: the quiet profile summary is totals and coverage only.
    #[test]
    fn quiet_profile_summary_keeps_totals_and_coverage_only() {
        let mut ev = evidence();
        ev.event_loss = 12;
        ev.semantic_unverified_slots = 68;
        ev.verdict();
        let out = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Quiet,
        );
        assert!(out.contains("1 completed call;"), "{out}");
        assert!(out.contains("coverage: partial"), "{out}");
        assert!(!out.contains("Attribution:"), "{out}");
        assert!(!out.contains("Module gaps"), "{out}");
    }

    /// Item 25: the shared totals line singularizes one of each count.
    #[test]
    fn totals_line_singularizes_one() {
        assert_eq!(
            totals_line(1, 1, 1),
            "1 completed call; 1 returned error; 1 entry without an observed return."
        );
        assert_eq!(
            totals_line(2, 1, 0),
            "2 completed calls; 1 returned error; 0 entries without an observed return."
        );
        assert_eq!(
            totals_line(0, 0, 0),
            "0 completed calls; 0 returned errors; 0 entries without an observed return."
        );
    }

    /// CLI-1: a COMPLETE verdict reads `coverage: complete`.
    #[test]
    fn complete_coverage_reads_complete() {
        let mut ev = evidence();
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
        for verbosity in [
            crate::cli::TextVerbosity::Concise,
            crate::cli::TextVerbosity::Verbose,
            crate::cli::TextVerbosity::Quiet,
        ] {
            let out = scope_summary_with_verbosity("pid", &reports_fixture(), &ev, verbosity);
            assert!(out.contains("coverage: complete"), "{verbosity:?}: {out}");
        }
    }

    /// CLI-1: the concise live frame keeps the tables and the `-v`
    /// hint; the Evidence line is verbose-only.
    #[test]
    fn concise_live_frame_keeps_tables_and_hint_without_evidence() {
        let mut ev = evidence();
        ev.event_loss = 12;
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> =
            [(0x250, mech_stat(8, 1))].into_iter().collect();
        let out = live_scoped_with_verbosity(
            &[report("C_Sign", 10, 0, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("FUNCTION"), "{out}");
        assert!(out.contains("C_Sign"), "{out}");
        assert!(out.contains("MECHANISM"), "{out}");
        assert!(out.contains("CKM_SHA256"), "{out}");
        assert!(out.contains("coverage: partial"), "{out}");
        assert!(!out.contains("Evidence:"), "{out}");
        assert!(out.contains(crate::cli::VERBOSE_HINT), "{out}");
    }

    /// CLI text: the concise metrics frame keeps the `-v` hint last —
    /// the counter-collection block reads before it, so a
    /// `--select-endpoint` report line inserted before the hint lands
    /// after that block instead of orphaned past the hint.
    #[test]
    fn concise_counter_frame_reads_counter_block_before_hint() {
        let mut fixture = crate::metrics::ConsumerFixture::new();
        let snapshot = fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
        let mut ev = evidence();
        ev.verdict();
        let frame = live_snapshot_scoped(
            &snapshot,
            &ev,
            Duration::ZERO,
            "owned",
            "metrics",
            CapturePolicy::AggregateOnly,
            "pid",
            &BTreeMap::new(),
            None,
            &crate::semantics::SessionStats::default(),
            &BTreeMap::new(),
        );
        let hint = crate::cli::VERBOSE_HINT;
        assert!(frame.contains("Counter collection:"), "{frame}");
        assert!(
            frame.ends_with(&format!("{hint}\n")),
            "hint stays last: {frame}"
        );
        assert!(
            frame.find("Counter collection:").unwrap() < frame.find(hint).unwrap(),
            "counter block reads before the hint: {frame}"
        );
    }

    /// CLI-1: the verbose live frame keeps Evidence and no hint.
    #[test]
    fn verbose_live_frame_keeps_evidence_without_hint() {
        let mut ev = evidence();
        ev.event_loss = 12;
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[report("C_Sign", 10, 0, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(out.contains("Evidence:"), "{out}");
        assert!(!out.contains(crate::cli::VERBOSE_HINT), "{out}");
    }

    /// CLI-1: the quiet live frame is header, totals and coverage only.
    #[test]
    fn quiet_live_frame_keeps_header_totals_coverage_only() {
        let mut ev = evidence();
        ev.event_loss = 12;
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[report("C_Sign", 10, 0, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Quiet,
        );
        assert!(out.contains("p11scope — PID scope"), "{out}");
        assert!(out.contains("10 completed calls;"), "{out}");
        assert!(out.contains("coverage: partial"), "{out}");
        assert!(!out.contains("FUNCTION"), "{out}");
        assert!(!out.contains("Evidence:"), "{out}");
        assert!(!out.contains(crate::cli::VERBOSE_HINT), "{out}");
    }

    /// The omission record the planner writes for an admitted provider whose
    /// growth did not fit (`plan::tests` pins the planner to this shape).
    const GROWTH_OMISSION_RECORD: &str = "admitted module needs 2 more; only 512 attach slots \
         are available; 511 are in use — 2 endpoints not attached; kept its 511 attached endpoints";

    /// G-03: an admitted provider whose growth did not fit is partially
    /// covered, not refused. The live view counts it apart from the modules
    /// refused whole, the verdict stays PARTIAL, and the JSON evidence
    /// carries the record verbatim.
    #[test]
    fn live_view_counts_a_partially_covered_module_apart_from_refused_ones() {
        let mut ev = evidence();
        ev.discovery.modules_skipped = vec![
            SkippedOut {
                name: "/opt/new.so".into(),
                reason: "module needs 3 more; only 512 attach slots are available; 511 are in \
                         use — refusing to attach a prefix"
                    .into(),
            },
            SkippedOut {
                name: "/opt/grown.so".into(),
                reason: GROWTH_OMISSION_RECORD.into(),
            },
        ];
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");

        let out = live(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
        );
        assert!(out.contains("1 provider file not watched"), "{out}");
        assert!(out.contains("1 provider file partially covered"), "{out}");
        assert!(!out.contains("2 provider files not watched"), "{out}");

        let value = versioned_evidence(&ev);
        assert_eq!(value["modules_skipped"][1]["name"], "/opt/grown.so");
        assert_eq!(
            value["modules_skipped"][1]["reason"],
            GROWTH_OMISSION_RECORD
        );
    }

    /// The terminal summary names a refused module with its reason in plain
    /// words and the way to capture it alone.
    #[test]
    fn scope_summary_names_a_refused_module_with_its_hint() {
        let mut ev = evidence();
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/p11-kit-trust.so".into(),
            reason: "module needs 68 more; only 512 attach slots are available; 480 are in use \
                 (480 active, 0 retired; held by /opt/other.so 480) — refusing to attach a prefix"
                .into(),
        });
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(text.contains("1 provider file not watched"), "{text}");
        assert!(text.contains("Module gaps (showing 1 of 1):"), "{text}");
        assert!(
            text.contains("/opt/p11-kit-trust.so: not attached — "),
            "{text}"
        );
        assert!(text.contains("module needs 68 more"), "{text}");
        assert!(
            text.contains("capture it alone with --module /opt/p11-kit-trust.so"),
            "{text}"
        );
    }

    /// The terminal summary explains withheld attribution in plain words:
    /// how many mapped providers have no manifest at all, naming them, so
    /// PARTIAL coverage reads as a cause rather than an alarm. Verbose
    /// repeats the remedy; concise keeps it once in Coverage.
    #[test]
    fn scope_summary_names_providers_without_manifests() {
        let mut softhsm = discovered_fixture();
        softhsm.path = "/usr/lib64/pkcs11/libsofthsm2.so".into();
        softhsm.sources = vec!["scan", "manifest"];
        let mut nss = discovered_fixture();
        nss.id = ModuleId(1);
        nss.ino = 22;
        nss.path = "/opt/firefox/libsoftokn3.so".into();
        nss.sources = vec!["scan"];
        let mut ev = evidence();
        ev.discovery.modules = vec![softhsm, nss];
        ev.semantic_unverified_slots = 212;
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(
            text.contains(
                "Attribution: 1 of 2 mapped provider files has no manifest (libsoftokn3.so); \
                 counts are exact, names are unconfirmed"
            ),
            "{text}"
        );
        assert!(
            text.contains("rerun with --manifest for provider files with unverified tables"),
            "{text}"
        );
    }

    /// Plural twin: two unattested providers read as "have", naming both.
    #[test]
    fn scope_summary_names_providers_without_manifests_plural() {
        let mut a = discovered_fixture();
        a.path = "/opt/a.so".into();
        a.sources = vec!["scan"];
        let mut b = discovered_fixture();
        b.id = ModuleId(1);
        b.ino = 22;
        b.path = "/opt/b.so".into();
        b.sources = vec!["scan", "prearm"];
        let mut c = discovered_fixture();
        c.id = ModuleId(2);
        c.ino = 33;
        c.path = "/opt/c.so".into();
        c.sources = vec!["scan", "manifest"];
        let mut ev = evidence();
        ev.discovery.modules = vec![a, b, c];
        ev.semantic_unverified_slots = 9;
        ev.verdict();
        let text = scope_summary("pid", &reports_fixture(), &ev);
        assert!(
            text.contains(
                "Attribution: 2 of 3 mapped provider files have no manifest (a.so, b.so); \
                 counts are exact, names are unconfirmed"
            ),
            "{text}"
        );
    }

    /// PID scope covers one process: the aggregate note stays silent,
    /// and the header already named the scope, so no scope line repeats it.
    #[test]
    fn scope_summary_for_pid_scope_omits_the_aggregate_note() {
        let mut ev = evidence();
        ev.verdict();
        let text = scope_summary("pid", &reports_fixture(), &ev);
        assert!(!text.contains("Scope:"), "{text}");
        assert!(!text.contains("not per application"), "{text}");
    }

    /// Wider scopes keep the aggregate note: counts are not per application.
    #[test]
    fn scope_summary_for_wider_scopes_keeps_the_aggregate_note() {
        let mut ev = evidence();
        ev.verdict();
        for scope in ["cgroup", "system", "selected"] {
            let text = scope_summary(scope, &reports_fixture(), &ev);
            assert!(
                text.contains(
                    "Aggregate across the selected scope; counts are not per application."
                ),
                "{scope}: {text}"
            );
        }
    }

    /// A quiet window over mapped providers explains itself: no
    /// PKCS#11 activity happened, providers are often called only at
    /// startup, and a narrower scope names the wider target to try.
    #[test]
    fn scope_summary_with_zero_calls_over_mapped_providers_suggests_startup_attach() {
        let mut ev = evidence();
        ev.discovery.modules = vec![discovered_fixture()];
        ev.verdict();
        for scope in ["pid", "cgroup", "selected"] {
            let text = scope_summary(scope, &[], &ev);
            assert!(
                text.contains("No completed calls observed"),
                "{scope}: {text}"
            );
            assert!(
                text.contains("No PKCS#11 calls were made in this window"),
                "{scope}: {text}"
            );
            assert!(
                text.contains("Attach before the target starts"),
                "{scope}: {text}"
            );
            assert!(text.contains("--system"), "{scope}: {text}");
        }
        let system = scope_summary("system", &[], &ev);
        assert!(
            system.contains("No PKCS#11 calls were made in this window"),
            "{system}"
        );
        assert!(
            system.contains("Attach before the targets start"),
            "{system}"
        );
        assert!(!system.contains("--system"), "{system}");
        // A window with calls, or with nothing mapped, stays silent.
        let busy = scope_summary("pid", &reports_fixture(), &ev);
        assert!(!busy.contains("were made in this window"), "{busy}");
        let mut bare = evidence();
        bare.discovery.modules = Vec::new();
        bare.verdict();
        let empty = scope_summary("pid", &[], &bare);
        assert!(!empty.contains("were made in this window"), "{empty}");
    }

    /// Under PARTIAL coverage the quiet-window startup sentence stays
    /// silent: asserting that no calls were made would overclaim when
    /// calls through unattached tables were explicitly not counted.
    #[test]
    fn scope_summary_with_zero_calls_under_partial_coverage_withholds_the_startup_hint() {
        let mut ev = evidence();
        ev.discovery.modules = vec![discovered_fixture()];
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/partial.so".into(),
            reason: "2 of 67 template tables attached; calls through the others are not counted (closure_prefix)".into(),
        });
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        let text = scope_summary("pid", &[], &ev);
        assert!(
            text.contains("No completed calls observed; coverage incomplete."),
            "{text}"
        );
        assert!(
            !text.contains("No PKCS#11 calls were made in this window"),
            "a partial window must not assert no calls happened: {text}"
        );
    }

    /// Zero calls with only attribution gaps (counts complete) must use
    /// one consistent coverage statement, not "coverage incomplete"
    /// beside "coverage: partial — counts complete".
    #[test]
    fn scope_summary_with_zero_calls_and_attribution_only_gaps_is_consistent() {
        let mut ev = evidence();
        ev.discovery.modules = vec![discovered_fixture()];
        ev.semantic_unverified_slots = 1;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        assert_eq!(ev.verdict_detail, VERDICT_ATTRIBUTION_ONLY);
        let text =
            scope_summary_with_verbosity("pid", &[], &ev, crate::cli::TextVerbosity::Concise);
        assert!(text.contains("counts complete"), "{text}");
        assert!(
            !text.contains("coverage incomplete"),
            "one consistent coverage statement: {text}"
        );
    }

    /// No unverified slots, or every mapped provider attested (partial
    /// manifest coverage): the machine fragment alone stands, with no
    /// provider-manifest note.
    #[test]
    fn scope_summary_without_unattested_providers_shows_no_attribution_note() {
        let mut attested = discovered_fixture();
        attested.sources = vec!["scan", "manifest"];
        for unverified in [0, 5] {
            let mut ev = evidence();
            ev.discovery.modules = vec![attested.clone()];
            ev.semantic_unverified_slots = unverified;
            ev.verdict();
            let text = scope_summary("pid", &reports_fixture(), &ev);
            assert!(!text.contains("has no manifest"), "{text}");
            assert!(!text.contains("have no manifest"), "{text}");
        }
    }

    /// The terminal summary names a partially covered module: kept endpoints
    /// stay counted, and the omission says what did not fit.
    #[test]
    fn scope_summary_names_a_partially_covered_module() {
        let mut ev = evidence();
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/grown.so".into(),
            reason: GROWTH_OMISSION_RECORD.into(),
        });
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(text.contains("1 provider file partially covered"), "{text}");
        assert!(
            text.contains("/opt/grown.so: partially covered — "),
            "{text}"
        );
        assert!(text.contains("kept its 511 attached endpoints"), "{text}");
        assert!(
            text.contains("capture it alone with --module /opt/grown.so"),
            "{text}"
        );
    }

    /// The terminal summary names a refused proxy closure array with its
    /// lookalike reason and where its forwarded calls are counted.
    #[test]
    fn scope_summary_names_a_refused_closure_array_with_its_counted_providers() {
        let mut trust = discovered_fixture();
        trust.id = ModuleId(1);
        trust.ino = 21;
        trust.path = "/opt/p11-kit-trust.so".into();
        let mut row = report("C_FindObjects", 744, 0, false);
        row.module = Some(ModuleId(1));
        let mut ev = evidence();
        ev.discovery.modules.push(trust);
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/libp11-kit.so".into(),
            reason: format!(
                "module needs 6530 more; only 512 attach slots are available; 68 are in use \
                 (68 active, 0 retired; held by /opt/p11-kit-trust.so 68) — refusing to attach a \
                 prefix of its 64 lookalike function tables {}",
                crate::plan::CLOSURE_ARRAY_NOTE_DETAILED
            ),
        });
        ev.verdict();
        let text =
            scope_summary_with_verbosity("pid", &[row], &ev, crate::cli::TextVerbosity::Verbose);
        assert!(
            text.contains("/opt/libp11-kit.so: not attached — "),
            "{text}"
        );
        assert!(text.contains("64 lookalike function tables"), "{text}");
        // Planner/render junction: the gap line carries the planner's own
        // note verbatim.
        assert!(
            text.contains(crate::plan::CLOSURE_ARRAY_NOTE_DETAILED),
            "{text}"
        );
        assert!(
            text.contains(
                "calls it forwards are counted at the attached provider files \
                 (/opt/p11-kit-trust.so: 744 calls)"
            ),
            "{text}"
        );
        assert!(
            text.contains("Calls the forwarding layer answers itself are not counted"),
            "{text}"
        );
    }

    /// Part 0: a prefix-admitted closure array names its covered templates
    /// as partially covered, with no `--module` hint (the prefix already
    /// counts; narrowing to it alone changes nothing).
    #[test]
    fn scope_summary_names_a_prefix_admitted_closure_array() {
        let mut ev = evidence();
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/p11-kit-client.so".into(),
            reason: "4 of 64 template tables attached; calls through the others are not counted (closure_prefix)"
                .into(),
        });
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(text.contains("1 provider file partially covered"), "{text}");
        assert!(
            text.contains("/opt/p11-kit-client.so: partially covered — "),
            "{text}"
        );
        assert!(text.contains("4 of 64 template tables attached"), "{text}");
        assert!(!text.contains("--module"), "{text}");
        assert!(
            text.contains(
                "Calls the forwarding layer answers itself through a template \
                 that was not attached are not counted"
            ),
            "{text}"
        );
        assert!(
            text.contains("calls it forwards are counted at the attached provider files"),
            "{text}"
        );
    }

    /// A prefix-admitted layer's own stub slots count under its own module
    /// id; the forwarding hint must not name the layer itself among the
    /// providers below it.
    #[test]
    fn prefix_hint_excludes_the_layer_itself() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.ino = 71;
        layer.path = "/opt/libp11-kit.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.ino = 82;
        backend.path = "/opt/p11-kit-trust.so".into();
        let mut self_row = report("C_GetSlotList", 500, 0, false);
        self_row.module = Some(ModuleId(7));
        let mut backend_row = report("C_FindObjects", 744, 0, false);
        backend_row.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/libp11-kit.so".into(),
            reason: "3 of 64 template tables attached; calls through the others are not counted (closure_prefix)"
                .into(),
        });
        ev.verdict();
        let text = scope_summary("pid", &[self_row, backend_row], &ev);
        assert!(text.contains("/opt/p11-kit-trust.so: 744 calls"), "{text}");
        assert!(
            !text.contains("/opt/libp11-kit.so: 500 calls"),
            "the layer must not list itself as a provider below it: {text}"
        );
    }

    /// Nested forwarding twin: one logical call observed twice — once at
    /// the forwarding layer's published stub (outer, same thread, containing
    /// the inner call) and once at the watched provider it forwards into.
    /// Every headline total counts the logical call once (provider layer);
    /// the forwarding layer is shown separately per layer, never summed in.
    #[test]
    fn headline_totals_count_nested_forwarding_once_with_per_layer_split() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        // Same function, nested pair: outer at the layer, inner at the
        // provider. The 500 outer calls each contain one inner call; the
        // provider also answered 244 calls directly (not through the layer).
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/libforward.so".into(),
            reason: "3 of 64 template tables attached; calls through the others are not counted (closure_prefix)"
                .into(),
        });
        ev.verdict();
        let text = scope_summary("pid", &[outer, inner], &ev);
        assert!(
            text.contains("744 completed calls;"),
            "headline counts logical calls once (provider layer): {text}"
        );
        assert!(
            !text.contains("1244 completed calls;"),
            "headline must not sum both layers: {text}"
        );
        assert!(
            text.contains("/opt/libforward.so")
                && text.contains("500")
                && text.contains("forwarding"),
            "forwarding layer shown separately per layer in plain words: {text}"
        );
    }

    /// JSON twin of the nested-forwarding headline: both layers stay
    /// present and explicitly labelled; logical totals count once.
    #[test]
    fn json_labels_both_nested_layers_and_counts_logical_once() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/libforward.so".into(),
            reason: "3 of 64 template tables attached; calls through the others are not counted (closure_prefix)"
                .into(),
        });
        ev.verdict();
        let document = json(&[outer, inner], &ev, &capture_fixture());
        let functions = document["functions"].as_array().unwrap();
        assert_eq!(functions.len(), 2, "both layers stay present");
        let outer_json = functions
            .iter()
            .find(|row| row["calls"] == 500)
            .expect("forwarding row present");
        let inner_json = functions
            .iter()
            .find(|row| row["calls"] == 744)
            .expect("provider row present");
        assert_eq!(
            outer_json["forwarding_layer"], true,
            "outer row labelled as the forwarding layer"
        );
        assert_eq!(
            inner_json["forwarding_layer"], false,
            "inner row labelled as the provider layer"
        );
        assert_eq!(
            document["layer_totals"]["logical"]["calls"], 744,
            "JSON logical totals count once"
        );
        assert_eq!(
            document["layer_totals"]["forwarding"]["calls"], 500,
            "JSON forwarding totals stay explicit"
        );
    }

    /// Unattributed twin: a whole-admitted forwarding layer (counter/broad
    /// policy: no gap at all) whose row ownership was not proven (null
    /// module) still leaves the logical total once — the deciding
    /// admission class marks the layer, and the attach target's file
    /// identity places the row at it.
    #[test]
    fn unresolved_forwarding_rows_leave_logical_totals_once() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.dev = (8, 1);
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("unknown#3", 500, 0, false);
        outer.module = None;
        outer.module_unresolved = true;
        outer.target_object = Some(crate::plan::TargetObject {
            dev: (8, 1),
            ino: 71,
            sha256: None,
        });
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        assert!(ev.discovery.modules_skipped.is_empty());
        ev.verdict();
        let text = scope_summary("pid", &[outer.clone(), inner.clone()], &ev);
        assert!(
            text.contains("744 completed calls;"),
            "unattributed forwarding rows leave the logical headline once: {text}"
        );
        assert!(
            text.contains("forwarding-layer calls"),
            "unattributed forwarding activity stays visible per layer: {text}"
        );
        let document = json(&[outer, inner], &ev, &capture_fixture());
        let functions = document["functions"].as_array().unwrap();
        let outer_json = functions
            .iter()
            .find(|row| row["calls"] == 500)
            .expect("forwarding row present");
        assert_eq!(outer_json["forwarding_layer"], true);
        assert_eq!(document["layer_totals"]["logical"]["calls"], 744);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 500);
        // Negative control: the same unattributed row aimed at another
        // file stays logical — the file-identity match decides.
        let mut elsewhere = report("unknown#3", 500, 0, false);
        elsewhere.module = None;
        elsewhere.module_unresolved = true;
        elsewhere.target_object = Some(crate::plan::TargetObject {
            dev: (8, 1),
            ino: 999,
            sha256: None,
        });
        let mut direct = report("C_Sign", 744, 0, false);
        direct.module = Some(ModuleId(8));
        let control = json(&[elsewhere, direct], &ev, &capture_fixture());
        assert_eq!(control["layer_totals"]["logical"]["calls"], 1244);
        assert_eq!(control["layer_totals"]["forwarding"]["calls"], 0);
    }

    /// Live pause/counter shape: a class-marked whole-admitted forwarding
    /// layer with attributed rows and no gap. The halves compose through
    /// `row_is_forwarding`, but the exact live shape deserves one pin.
    #[test]
    fn class_marked_attributed_rows_without_gap_count_logical_once() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        assert!(ev.discovery.modules_skipped.is_empty());
        ev.verdict();
        let text = scope_summary("pid", &[outer.clone(), inner.clone()], &ev);
        assert!(
            text.contains("744 completed calls;"),
            "class-marked attributed rows count logical once: {text}"
        );
        assert!(
            !text.contains("1244 completed calls;"),
            "headline must not sum both layers: {text}"
        );
        assert!(
            text.contains("/opt/libforward.so")
                && text.contains("500")
                && text.contains("forwarding"),
            "forwarding layer shown separately: {text}"
        );
        let document = json(&[outer, inner], &ev, &capture_fixture());
        let functions = document["functions"].as_array().unwrap();
        let outer_json = functions
            .iter()
            .find(|row| row["calls"] == 500)
            .expect("forwarding row present");
        let inner_json = functions
            .iter()
            .find(|row| row["calls"] == 744)
            .expect("provider row present");
        assert_eq!(outer_json["forwarding_layer"], true);
        assert_eq!(inner_json["forwarding_layer"], false);
        assert_eq!(document["layer_totals"]["logical"]["calls"], 744);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 500);
    }

    /// A refused closure array marks forwarding by its refusal reason alone
    /// (no class, no prefix gap): the `is_closure_array_refusal` arm of
    /// `forwarding_module_ids`. Refused modules hold no rows in production,
    /// so this is rebuild-history defense; the pin keeps the arm honest.
    #[test]
    fn refused_closure_array_marks_forwarding_by_reason_alone() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = None;
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/libforward.so".into(),
            reason: format!(
                "module needs 5966 more; only 512 attach slots are available — refusing to attach a prefix of its 67 lookalike function tables {}",
                crate::plan::CLOSURE_ARRAY_NOTE_WHOLE
            ),
        });
        ev.verdict();
        let document = json(&[outer, inner], &ev, &capture_fixture());
        assert_eq!(document["layer_totals"]["logical"]["calls"], 744);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 500);
        let functions = document["functions"].as_array().unwrap();
        let outer_json = functions
            .iter()
            .find(|row| row["calls"] == 500)
            .expect("forwarding row present");
        assert_eq!(outer_json["forwarding_layer"], true);
    }

    /// The forwarding line states the counting rule honestly: provider
    /// totals, self-answered layer calls kept in the forwarding line,
    /// and per-provider counting of multi-provider layer calls — not an
    /// exactness claim the code does not have.
    #[test]
    fn forwarding_line_states_the_counting_rule() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.verdict();
        let text = scope_summary("pid", &[outer, inner], &ev);
        assert!(
            text.contains(
                "The totals above count calls at the attached providers; \
                 calls a layer answered itself or forwarded to a provider that was not attached, \
                 including its errors, appear only here, \
                 and a layer call that reaches several providers counts at each."
            ),
            "honest counting rule stated: {text}"
        );
        assert!(
            !text
                .contains("Each forwarding-layer call is counted at the provider it forwards into"),
            "no exactness claim beyond the code: {text}"
        );
        assert!(
            !text.contains("contains one provider call on the same thread"),
            "no structural nesting claim: {text}"
        );
    }

    /// Remote-client shape: a closure-array forwarding layer is the only
    /// observation point — no watched provider below it. The split needs
    /// an active provider, so the layer's calls stay in the headline
    /// totals everywhere (text, live, metrics and profile JSON) and no
    /// forwarding line prints.
    #[test]
    fn lone_forwarding_layer_keeps_its_calls_in_the_totals() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut row = report("C_Sign", 22, 0, false);
        row.module = Some(ModuleId(7));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer];
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/libforward.so".into(),
            reason: "3 of 64 template tables attached; calls through the others are not counted (closure_prefix)"
                .into(),
        });
        ev.verdict();
        let text = scope_summary("pid", &[row.clone()], &ev);
        assert!(
            text.contains("22 completed calls;"),
            "a lone layer stays in the headline totals: {text}"
        );
        assert!(
            !text.contains("Forwarding layers counted separately"),
            "no forwarding line without an active provider: {text}"
        );
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> = BTreeMap::new();
        let out = live_scoped(
            &[row.clone()],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
        );
        assert!(
            !out.contains("(forwarding layer)"),
            "a lone layer carries no live marker: {out}"
        );
        let document = json(&[row.clone()], &ev, &capture_fixture());
        assert_eq!(document["layer_totals"]["logical"]["calls"], 22);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 0);
        let functions = document["functions"].as_array().unwrap();
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0]["forwarding_layer"], false);
        let profile = profile_json(
            &[row],
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        assert_eq!(profile["layer_totals"]["logical"]["calls"], 22);
        assert_eq!(profile["layer_totals"]["forwarding"]["calls"], 0);
        let functions = profile["functions"].as_array().unwrap();
        assert_eq!(functions[0]["forwarding_layer"], false);
    }

    /// A provider attached but quiet (no calls, errors or in-flight
    /// rows) beside an active layer: exclusion needs an *active*
    /// provider, so the layer's calls stay logical.
    #[test]
    fn quiet_provider_beside_active_layer_keeps_layer_calls_logical() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 695, 0, false);
        outer.module = Some(ModuleId(7));
        let mut quiet = report("C_Sign", 0, 0, false);
        quiet.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.verdict();
        let text = scope_summary("pid", &[outer.clone(), quiet.clone()], &ev);
        assert!(
            text.contains("695 completed calls;"),
            "a quiet provider keeps the layer logical: {text}"
        );
        assert!(
            !text.contains("Forwarding layers counted separately"),
            "no forwarding line without an active provider: {text}"
        );
        let document = json(&[outer, quiet], &ev, &capture_fixture());
        assert_eq!(document["layer_totals"]["logical"]["calls"], 695);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 0);
    }

    /// A provider row with errors but no completed calls still proves an
    /// active provider below the layer: the split stays on and the
    /// provider errors stay in the logical totals.
    #[test]
    fn provider_errors_alone_keep_the_forwarding_split() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut errored = report("C_Sign", 0, 0, false);
        errored.module = Some(ModuleId(8));
        errored.errors = 3;
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.verdict();
        let text = scope_summary("pid", &[outer.clone(), errored.clone()], &ev);
        assert!(
            text.contains("0 completed calls; 3 returned errors;"),
            "provider errors stay logical while the layer splits out: {text}"
        );
        assert!(
            text.contains("Forwarding layers counted separately"),
            "an erroring provider keeps the split: {text}"
        );
        let document = json(&[outer, errored], &ev, &capture_fixture());
        assert_eq!(document["layer_totals"]["logical"]["calls"], 0);
        assert_eq!(document["layer_totals"]["logical"]["errors"], 3);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 500);
    }

    /// A provider row with in-flight entries but no completed calls or
    /// errors still proves an active provider below the layer: the split
    /// stays on (kills M3, which drops the in-flight arm of the gate).
    #[test]
    fn provider_in_flight_alone_keeps_the_forwarding_split() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut open = report("C_Sign", 0, 2, false);
        open.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.verdict();
        let text = scope_summary("pid", &[outer.clone(), open.clone()], &ev);
        assert!(
            text.contains(
                "0 completed calls; 0 returned errors; 2 entries without an observed return."
            ),
            "provider in-flight stays logical while the layer splits out: {text}"
        );
        assert!(
            text.contains("Forwarding layers counted separately"),
            "an in-flight-only provider keeps the split: {text}"
        );
        let document = json(&[outer, open], &ev, &capture_fixture());
        assert_eq!(document["layer_totals"]["logical"]["calls"], 0);
        assert_eq!(document["layer_totals"]["logical"]["in_flight"], 2);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 500);
    }

    /// P1 shape (controller ruling): a forwarding layer beside a refused
    /// backend and an unrelated active provider. The gate sees the
    /// unrelated 2 calls, but the refused backend keeps the layer logical:
    /// a disclosed overcount (697) beats hiding the app's 695 calls.
    #[test]
    fn refused_backend_keeps_layer_calls_logical() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut unrelated = discovered_fixture();
        unrelated.id = ModuleId(9);
        unrelated.admission_class = Some("corroborated");
        unrelated.ino = 93;
        unrelated.path = "/opt/libunrelated.so".into();
        let mut outer = report("C_Sign", 695, 0, false);
        outer.module = Some(ModuleId(7));
        let mut other = report("C_Initialize", 2, 0, false);
        other.module = Some(ModuleId(9));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, unrelated];
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/libbackend.so".into(),
            reason: "module needs 100 more; only 512 attach slots are available; 412 are in use \
                 (412 active, 0 retired) — refusing to attach a prefix; to capture one provider, \
                 name it with --module <path>; to free slots, exclude an unneeded module with \
                 --exclude-module <name>"
                .into(),
        });
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        let text = scope_summary("pid", &[outer.clone(), other.clone()], &ev);
        assert!(
            text.contains("697 completed calls;"),
            "a refused backend keeps the layer logical (disclosed overcount): {text}"
        );
        assert!(
            !text.contains("Forwarding layers counted separately"),
            "no forwarding line when the backend is refused: {text}"
        );
        assert!(
            text.contains("/opt/libbackend.so: not attached — "),
            "the refused backend is still named as a gap: {text}"
        );
        let document = json(&[outer, other], &ev, &capture_fixture());
        assert_eq!(document["layer_totals"]["logical"]["calls"], 697);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 0);
        let functions = document["functions"].as_array().unwrap();
        assert!(
            functions.iter().all(|row| row["forwarding_layer"] == false),
            "no row splits when the backend is refused: {document}"
        );
    }

    /// P2 shape: an unattributed backend row does not activate the gate —
    /// the layer stays logical and the total double-counts (1000) with the
    /// ownership gap naming the 500. Disclosed, not hidden.
    #[test]
    fn unattributed_backend_rows_keep_the_layer_logical() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.dev = (8, 1);
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.dev = (8, 1);
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut stray = report("unknown#3", 500, 0, false);
        stray.module = None;
        stray.module_unresolved = true;
        stray.target_object = Some(crate::plan::TargetObject {
            dev: (8, 1),
            ino: 82,
            sha256: None,
        });
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        assert!(ev.discovery.modules_skipped.is_empty());
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
        let text = scope_summary("pid", &[outer.clone(), stray.clone()], &ev);
        assert!(
            text.contains("1000 completed calls;"),
            "an unattributed backend keeps the layer logical (disclosed double count): {text}"
        );
        assert!(
            !text.contains("Forwarding layers counted separately"),
            "no split without an attributed provider row: {text}"
        );
        // Owner-gap lines are verbose-only; concise keeps the headline above.
        let verbose_text = scope_summary_with_verbosity(
            "pid",
            &[outer.clone(), stray.clone()],
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(
            verbose_text.contains("\n500 completed calls have unresolved module ownership.\n"),
            "the ownership gap names the unattributed share: {verbose_text}"
        );
        let document = json(&[outer, stray], &ev, &capture_fixture());
        assert_eq!(document["layer_totals"]["logical"]["calls"], 1000);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 0);
    }

    /// P3 shape: a lone layer with an attributed row and an unresolved stub
    /// matched by file identity stays fully logical (44/0) — the file match
    /// never splits without an active provider.
    #[test]
    fn lone_layer_attributed_and_identity_matched_rows_stay_logical() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.dev = (8, 1);
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut named = report("C_Sign", 22, 0, false);
        named.module = Some(ModuleId(7));
        let mut stub = report("unknown#3", 22, 0, false);
        stub.module = None;
        stub.module_unresolved = true;
        stub.target_object = Some(crate::plan::TargetObject {
            dev: (8, 1),
            ino: 71,
            sha256: None,
        });
        let mut ev = evidence();
        ev.discovery.modules = vec![layer];
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/libforward.so".into(),
            reason: "3 of 64 template tables attached; calls through the others are not counted (closure_prefix)"
                .into(),
        });
        ev.verdict();
        let text = scope_summary("pid", &[named.clone(), stub.clone()], &ev);
        assert!(
            text.contains("44 completed calls;"),
            "a lone layer stays fully logical: {text}"
        );
        assert!(
            !text.contains("Forwarding layers counted separately"),
            "no forwarding line without an active provider: {text}"
        );
        let document = json(&[named, stub], &ev, &capture_fixture());
        assert_eq!(document["layer_totals"]["logical"]["calls"], 44);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 0);
        let functions = document["functions"].as_array().unwrap();
        assert!(
            functions.iter().all(|row| row["forwarding_layer"] == false),
            "no row splits without an active provider: {document}"
        );
    }

    /// Declared-forwarding twin: a single-table shim (pkcs11-spy shape —
    /// corroborated, never a closure array) the operator named with
    /// `--forwarding-module` splits exactly like a closure layer. Every
    /// headline total counts the logical call once (provider layer); the
    /// declared layer is shown separately per layer, never summed in.
    #[test]
    fn declared_forwarding_layer_splits_like_closure() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("corroborated");
        layer.ino = 71;
        layer.path = "/opt/libshim.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.discovery.forwarding_declared = vec![ModuleId(7)];
        assert!(ev.discovery.modules_skipped.is_empty());
        ev.verdict();
        let text = scope_summary("pid", &[outer.clone(), inner.clone()], &ev);
        assert!(
            text.contains("744 completed calls;"),
            "declared layer counts logical once: {text}"
        );
        assert!(
            !text.contains("1244 completed calls;"),
            "headline must not sum both layers: {text}"
        );
        assert!(
            text.contains("/opt/libshim.so") && text.contains("500") && text.contains("forwarding"),
            "declared layer shown separately: {text}"
        );
        let document = json(&[outer, inner], &ev, &capture_fixture());
        let functions = document["functions"].as_array().unwrap();
        let outer_json = functions
            .iter()
            .find(|row| row["calls"] == 500)
            .expect("forwarding row present");
        let inner_json = functions
            .iter()
            .find(|row| row["calls"] == 744)
            .expect("provider row present");
        assert_eq!(outer_json["forwarding_layer"], true);
        assert_eq!(inner_json["forwarding_layer"], false);
        assert_eq!(document["layer_totals"]["logical"]["calls"], 744);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 500);
    }

    /// Control twin: the same shim shape WITHOUT the declaration stays
    /// fully logical (1244) — the observer never guesses a forwarding
    /// role. The coincidence hint below is the only undeclared signal.
    #[test]
    fn undeclared_shim_stays_fully_logical() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("corroborated");
        layer.ino = 71;
        layer.path = "/opt/libshim.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        assert!(ev.discovery.forwarding_declared.is_empty());
        ev.verdict();
        let text = scope_summary("pid", &[outer.clone(), inner.clone()], &ev);
        assert!(
            text.contains("1244 completed calls;"),
            "undeclared layers stay logical: {text}"
        );
        let document = json(&[outer, inner], &ev, &capture_fixture());
        let functions = document["functions"].as_array().unwrap();
        assert!(
            functions.iter().all(|row| row["forwarding_layer"] == false),
            "no row splits without a declaration: {document}"
        );
    }

    /// Declared-gate twin: a declared layer beside a refused backend keeps
    /// its calls logical — a disclosed overcount beats hiding the calls —
    /// exactly like the closure gate.
    #[test]
    fn declared_layer_with_refused_backend_stays_logical() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("corroborated");
        layer.ino = 71;
        layer.path = "/opt/libshim.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.discovery.forwarding_declared = vec![ModuleId(7)];
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/libother.so".into(),
            reason: "module needs 100 more; only 512 attach slots are available; 412 are in use \
                 (412 active, 0 retired) — refusing to attach a prefix; to capture one provider, \
                 name it with --module <path>; to free slots, exclude an unneeded module with \
                 --exclude-module <name>"
                .into(),
        });
        ev.verdict();
        let text = scope_summary("pid", &[outer.clone(), inner.clone()], &ev);
        assert!(
            text.contains("1244 completed calls;"),
            "a refused backend keeps the declared layer logical: {text}"
        );
        assert!(
            !text.contains("Forwarding layers counted separately"),
            "no forwarding line when the backend is refused: {text}"
        );
        let document = json(&[outer, inner], &ev, &capture_fixture());
        assert_eq!(document["layer_totals"]["logical"]["calls"], 1244);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 0);
    }

    /// Declared-gate twin: a lone declared layer (no active provider row)
    /// keeps its calls in the totals — the declaration alone never hides
    /// the only observation.
    #[test]
    fn lone_declared_layer_keeps_calls_in_totals() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("corroborated");
        layer.ino = 71;
        layer.path = "/opt/libshim.so".into();
        let mut named = report("C_Sign", 44, 0, false);
        named.module = Some(ModuleId(7));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer];
        ev.discovery.forwarding_declared = vec![ModuleId(7)];
        ev.verdict();
        let text = scope_summary("pid", &[named.clone()], &ev);
        assert!(
            text.contains("44 completed calls;"),
            "a lone declared layer stays fully logical: {text}"
        );
        assert!(
            !text.contains("Forwarding layers counted separately"),
            "no forwarding line without an active provider: {text}"
        );
        let document = json(&[named], &ev, &capture_fixture());
        assert_eq!(document["layer_totals"]["logical"]["calls"], 44);
        assert_eq!(document["layer_totals"]["forwarding"]["calls"], 0);
    }

    /// Coincidence hint: two attached non-layer modules whose per-function
    /// vectors coincide exactly (the manifest-run spy shape: every shim
    /// call re-observed at the backend) get a text hint naming both
    /// modules and the `--forwarding-module` remedy. Advisory only —
    /// counts never change here.
    #[test]
    fn coincident_vectors_suggest_forwarding_flag() {
        let mut shim = discovered_fixture();
        shim.id = ModuleId(7);
        shim.admission_class = Some("corroborated");
        shim.ino = 71;
        shim.path = "/opt/libshim.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut rows = Vec::new();
        for (name, shim_calls, backend_calls) in [
            ("C_Initialize", 1, 1),
            ("C_GetSlotList", 2, 2),
            ("C_GetTokenInfo", 2, 2),
        ] {
            let mut outer = report(name, shim_calls, 0, false);
            outer.module = Some(ModuleId(7));
            rows.push(outer);
            let mut inner = report(name, backend_calls, 0, false);
            inner.module = Some(ModuleId(8));
            rows.push(inner);
        }
        let mut extra = report("C_GetFunctionList", 1, 0, false);
        extra.module = Some(ModuleId(8));
        rows.push(extra);
        let mut ev = evidence();
        ev.discovery.modules = vec![shim, backend];
        ev.verdict();
        let text = scope_summary("pid", &rows, &ev);
        assert!(
            text.contains("--forwarding-module"),
            "coincident vectors suggest the flag: {text}"
        );
        assert!(
            text.contains("/opt/libshim.so") && text.contains("/opt/libbackend.so"),
            "the hint names both modules: {text}"
        );
        // Advisory only: the headline still sums both layers.
        assert!(
            text.contains("11 completed calls;"),
            "the hint changes no count: {text}"
        );
    }

    /// Hint negative control: unrelated vectors (no containment either
    /// way) suggest nothing.
    #[test]
    fn unrelated_vectors_suggest_nothing() {
        let mut first = discovered_fixture();
        first.id = ModuleId(7);
        first.admission_class = Some("corroborated");
        first.ino = 71;
        first.path = "/opt/libfirst.so".into();
        let mut second = discovered_fixture();
        second.id = ModuleId(8);
        second.admission_class = Some("corroborated");
        second.ino = 82;
        second.path = "/opt/libsecond.so".into();
        let mut sign = report("C_Sign", 9, 0, false);
        sign.module = Some(ModuleId(7));
        let mut verify = report("C_Verify", 9, 0, false);
        verify.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![first, second];
        ev.verdict();
        let text = scope_summary("pid", &[sign, verify], &ev);
        assert!(
            !text.contains("--forwarding-module"),
            "unrelated vectors suggest nothing: {text}"
        );
    }

    /// Hint negative control: a declared (already split) layer suggests
    /// nothing — the operator already answered.
    #[test]
    fn declared_layer_suggests_nothing() {
        let mut shim = discovered_fixture();
        shim.id = ModuleId(7);
        shim.admission_class = Some("corroborated");
        shim.ino = 71;
        shim.path = "/opt/libshim.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut rows = Vec::new();
        for name in ["C_Sign", "C_Verify"] {
            let mut outer = report(name, 5, 0, false);
            outer.module = Some(ModuleId(7));
            rows.push(outer);
            let mut inner = report(name, 5, 0, false);
            inner.module = Some(ModuleId(8));
            rows.push(inner);
        }
        let mut ev = evidence();
        ev.discovery.modules = vec![shim, backend];
        ev.discovery.forwarding_declared = vec![ModuleId(7)];
        ev.verdict();
        let text = scope_summary("pid", &rows, &ev);
        assert!(
            !text.contains("--forwarding-module"),
            "a declared layer suggests nothing: {text}"
        );
    }

    /// A `--forwarding-module` input that matched no mapped file is named
    /// in text — a declaration that matched nothing must never silently
    /// do nothing.
    #[test]
    fn unmatched_forwarding_inputs_are_named() {
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut inner = report("C_Sign", 3, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![backend];
        ev.discovery.unmatched_forwarding = vec!["nope.so".into()];
        ev.verdict();
        let text = scope_summary("pid", &[inner], &ev);
        assert!(
            text.contains("nope.so") && text.contains("forwarding"),
            "unmatched forwarding inputs are named: {text}"
        );
    }

    /// The JSON twin of the unmatched-forwarding text line: a declaration
    /// that matched nothing is machine-readable, omitted when empty.
    #[test]
    fn unmatched_forwarding_inputs_are_serialized() {
        let mut ev = evidence();
        ev.discovery.unmatched_forwarding = vec!["nope.so".into()];
        ev.verdict();
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["unmatched_forwarding"][0], "nope.so");
        let mut empty = evidence();
        empty.verdict();
        let empty_json = serde_json::to_value(&empty).unwrap();
        assert!(
            empty_json.get("unmatched_forwarding").is_none(),
            "empty unmatched_forwarding is omitted"
        );
    }

    /// Ownership-gap lines explain headline attribution gaps, so they
    /// count logical rows only: unattributed forwarding rows are already
    /// stated in the forwarding line, never summed here.
    #[test]
    fn ownership_gap_lines_count_logical_rows_only() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.dev = (8, 1);
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.dev = (8, 1);
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("unknown#3", 500, 0, false);
        outer.module = None;
        outer.module_unresolved = true;
        outer.target_object = Some(crate::plan::TargetObject {
            dev: (8, 1),
            ino: 71,
            sha256: None,
        });
        let mut stray = report("unknown#4", 5, 0, false);
        stray.module = None;
        stray.module_unresolved = true;
        stray.target_object = Some(crate::plan::TargetObject {
            dev: (8, 1),
            ino: 82,
            sha256: None,
        });
        let mut contested = report("unknown#5", 7, 0, false);
        contested.module = None;
        contested.module_ambiguous = true;
        contested.target_object = Some(crate::plan::TargetObject {
            dev: (8, 1),
            ino: 71,
            sha256: None,
        });
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.verdict();
        let text = scope_summary(
            "pid",
            &[
                outer.clone(),
                stray.clone(),
                contested.clone(),
                inner.clone(),
            ],
            &ev,
        );
        assert!(
            text.contains("749 completed calls;"),
            "headline counts logical rows once: {text}"
        );
        // Owner-gap lines are verbose-only; concise keeps the headline above.
        let verbose_text = scope_summary_with_verbosity(
            "pid",
            &[outer, stray, contested, inner],
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(
            verbose_text.contains("\n5 completed calls have unresolved module ownership.\n"),
            "unresolved line counts the logical stray only: {verbose_text}"
        );
        assert!(
            !verbose_text.contains("505 completed calls"),
            "forwarding rows are not summed into the unresolved line: {verbose_text}"
        );
        assert!(
            !verbose_text.contains("ambiguous module ownership"),
            "a forwarding-only ambiguity prints no ownership line: {verbose_text}"
        );
    }

    /// An unattributed forwarding row matched to its layer by attach-target
    /// file identity is named in the per-layer line, not hidden behind
    /// "an unattributed forwarding target".
    #[test]
    fn unattributed_forwarding_line_names_the_identity_matched_layer() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.dev = (8, 1);
        layer.ino = 71;
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.ino = 82;
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("unknown#3", 500, 0, false);
        outer.module = None;
        outer.module_unresolved = true;
        outer.target_object = Some(crate::plan::TargetObject {
            dev: (8, 1),
            ino: 71,
            sha256: None,
        });
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.verdict();
        let text = scope_summary("pid", &[outer, inner], &ev);
        assert!(
            text.contains("/opt/libforward.so recorded 500 completed forwarding-layer calls"),
            "the identity-matched layer is named: {text}"
        );
        assert!(
            !text.contains("an unattributed forwarding target"),
            "no unattributed label for a matched layer: {text}"
        );
    }

    /// JK-22a: a prefix-admitted ordinary provider names its attached
    /// endpoints as partially covered, counted under "modules partially
    /// covered" rather than "modules refused".
    #[test]
    fn scope_summary_names_a_prefix_admitted_provider() {
        let mut ev = evidence();
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/mixed.so".into(),
            reason: "100 of 150 endpoints attached; calls through the others are not counted (provider_prefix)"
                .into(),
        });
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(text.contains("1 provider file partially covered"), "{text}");
        assert!(
            text.contains("/opt/mixed.so: partially covered — "),
            "{text}"
        );
        assert!(text.contains("100 of 150 endpoints attached"), "{text}");
    }

    /// A function-level partial-admitted provider reads the same way: its
    /// attached endpoints as partially covered, counted under "modules
    /// partially covered" rather than "modules refused".
    #[test]
    fn scope_summary_names_a_function_partial_provider() {
        let mut ev = evidence();
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/trust.so".into(),
            reason: "40 of 68 endpoints attached; calls through the others are not counted (provider_partial)"
                .into(),
        });
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(text.contains("1 provider file partially covered"), "{text}");
        assert!(
            text.contains("/opt/trust.so: partially covered — "),
            "{text}"
        );
        assert!(text.contains("40 of 68 endpoints attached"), "{text}");
    }

    /// A whole refusal whose holder path names `(provider_prefix)` still
    /// renders as refused, never as partially covered.
    #[test]
    fn scope_summary_treats_holder_path_naming_provider_prefix_as_whole_refusal() {
        let mut ev = evidence();
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/crowded.so".into(),
            reason: "module needs 150 more; only 512 attach slots are available; 400 are in use \
                 (400 active, 0 retired; held by /opt/(provider_prefix)/lib.so 400) — refusing to attach \
                 a prefix; to capture one provider, name it with --module <path>; to free slots, exclude \
                 an unneeded module with --exclude-module <name>"
                .into(),
        });
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(text.contains("1 provider file not watched"), "{text}");
        assert!(!text.contains("partially covered"), "{text}");
        assert!(text.contains("/opt/crowded.so: not attached — "), "{text}");
        assert!(!text.contains("partially covered"), "{text}");
    }

    /// `--exclude-module` files are listed as "excluded by you" with path,
    /// identity, and process count, plus unmatched inputs; a capture whose
    /// only skips are excluded stays exact.
    #[test]
    fn scope_summary_lists_excluded_modules_and_unmatched_inputs() {
        let mut ev = evidence();
        ev.discovery.excluded_modules.push(ExcludedOut {
            path: "/opt/libp11-kit.so.0.4.8".into(),
            dev: 42,
            ino: 1001,
            processes: 3,
        });
        ev.discovery.unmatched_excludes.push("nope.so".into());
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
        let text = scope_summary("pid", &reports_fixture(), &ev);
        assert!(text.contains("Excluded by you (1 files):"), "{text}");
        assert!(
            text.contains("/opt/libp11-kit.so.0.4.8: excluded by you (device 42 inode 1001, 3 processes mapped it)"),
            "{text}"
        );
        assert!(
            text.contains("calls into this file were not observed"),
            "{text}"
        );
        assert!(text.contains("Unmatched exclusions (1): nope.so"), "{text}");
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(
            json["excluded_modules"][0]["path"],
            "/opt/libp11-kit.so.0.4.8"
        );
        assert_eq!(json["excluded_modules"][0]["processes"], 3);
        assert_eq!(json["unmatched_excludes"][0], "nope.so");
    }

    #[test]
    fn slot_sizing_json_reports_the_downsize_or_stays_absent() {
        // The 512 build never downsizes, so it renders a synthetic
        // downsized sizing; wide renders the real one.
        #[cfg(feature = "wide-detailed-2112")]
        let sizing = crate::capacity::size_detailed_slots(256, 2 * 1024 * 1024 * 1024);
        #[cfg(not(feature = "wide-detailed-2112"))]
        let sizing = crate::capacity::SlotSizing {
            requested_slots: 2_112,
            effective_slots: 662,
            possible_cpus: 256,
            mem_total_bytes: 2 * 1024 * 1024 * 1024,
            budget_bytes: 64 * 1024 * 1024,
            stats_bytes: 67_072_000,
        };
        let mut sized = evidence();
        sized.discovery.slot_sizing = Some(sizing);
        let json = serde_json::to_value(&sized).unwrap();
        assert_eq!(json["slot_sizing"]["requested_slots"], 2112);
        assert_eq!(json["slot_sizing"]["effective_slots"], 662);
        assert_eq!(json["slot_sizing"]["possible_cpus"], 256);
        assert_eq!(
            json["slot_sizing"]["mem_total_bytes"],
            2u64 * 1024 * 1024 * 1024
        );
        assert_eq!(json["slot_sizing"]["budget_bytes"], 64 * 1024 * 1024);
        let mut plain = evidence();
        plain.discovery.slot_sizing = None;
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json.get("slot_sizing").is_none());
    }

    #[test]
    fn aggregate_excluded_groups_by_file_and_names_unmatched_inputs() {
        use crate::discovery::scan::ExcludedRecord;
        use std::path::PathBuf;
        let records = vec![
            ExcludedRecord {
                pid: 10,
                path: "/opt/liba.so".into(),
                dev: 7,
                ino: 100,
                via: PathBuf::from("liba.so"),
            },
            ExcludedRecord {
                pid: 11,
                path: "/opt/liba.so".into(),
                dev: 7,
                ino: 100,
                via: PathBuf::from("liba.so"),
            },
            ExcludedRecord {
                pid: 10,
                path: "/snap/liba.so".into(),
                dev: 8,
                ino: 200,
                via: PathBuf::from("liba.so"),
            },
        ];
        let excludes = vec![PathBuf::from("liba.so"), PathBuf::from("nope.so")];
        let (excluded, unmatched) = aggregate_excluded(&records, &excludes);
        assert_eq!(excluded.len(), 2);
        assert_eq!(excluded[0].path, "/opt/liba.so");
        assert_eq!(excluded[0].processes, 2);
        assert_eq!(excluded[1].path, "/snap/liba.so");
        assert_eq!(excluded[1].processes, 1);
        assert_eq!(unmatched, vec!["nope.so".to_string()]);
    }

    #[test]
    fn forwarding_match_path_matches_by_path_and_inode() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("libtarget.so.1");
        std::fs::write(&target, b"fake-a").unwrap();
        let meta = std::fs::metadata(&target).unwrap();
        let modules = vec![(
            ModuleId(3),
            target.display().to_string(),
            (
                u64::from(libc::major(meta.dev())),
                u64::from(libc::minor(meta.dev())),
            ),
            meta.ino(),
        )];
        let (matched, unmatched) = match_forwarding_inputs(&[target], &modules);
        assert_eq!(matched, vec![ModuleId(3)]);
        assert!(
            unmatched.is_empty(),
            "identity match leaves none: {unmatched:?}"
        );
        // A different file never matches by path.
        let other = dir.path().join("libother.so.1");
        std::fs::write(&other, b"fake-b").unwrap();
        let (matched, unmatched) = match_forwarding_inputs(&[other], &modules);
        assert!(matched.is_empty());
        assert_eq!(unmatched.len(), 1);
    }

    #[test]
    fn forwarding_match_path_ignores_maps_device_numbers() {
        // Regression: the module side renders a maps/mountinfo device while
        // the input side is an observer fstat, and the two disagree for
        // the same file (btrfs host: st_dev 37 vs mount 0:35), so only
        // the path and the inode corroborate the match, never the device.
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("libshim.so.1");
        std::fs::write(&target, b"fake-shim").unwrap();
        let meta = std::fs::metadata(&target).unwrap();
        let foreign = (
            u64::from(libc::major(meta.dev())),
            u64::from(libc::minor(meta.dev())).wrapping_add(1),
        );
        let modules = vec![(
            ModuleId(3),
            target.display().to_string(),
            foreign,
            meta.ino(),
        )];
        let (matched, unmatched) = match_forwarding_inputs(&[target], &modules);
        assert_eq!(matched, vec![ModuleId(3)]);
        assert!(
            unmatched.is_empty(),
            "path+inode match leaves none: {unmatched:?}"
        );
    }

    #[test]
    fn forwarding_match_path_rotation_breaks_the_inode_link() {
        // Same path spelling, but the file on disk rotated after
        // discovery: the inode no longer corroborates, so the declaration
        // stays unmatched (named, never applied to the new file).
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("libshim.so.1");
        std::fs::write(&target, b"fake-shim").unwrap();
        let meta = std::fs::metadata(&target).unwrap();
        let modules = vec![(
            ModuleId(3),
            target.display().to_string(),
            (
                u64::from(libc::major(meta.dev())),
                u64::from(libc::minor(meta.dev())),
            ),
            meta.ino().wrapping_add(1),
        )];
        let (matched, unmatched) = match_forwarding_inputs(&[target], &modules);
        assert!(matched.is_empty());
        assert_eq!(unmatched.len(), 1);
    }

    #[test]
    fn forwarding_match_deleted_input_stays_unmatched() {
        // Fail closed: a declared path that no longer resolves at report
        // time matches nothing, even when a mapped module keeps the same
        // spelling and the pre-deletion inode — path spelling alone never
        // corroborates.
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("libshim.so.1");
        std::fs::write(&target, b"fake-shim").unwrap();
        let ino = std::fs::metadata(&target).unwrap().ino();
        let spelling = target.display().to_string();
        std::fs::remove_file(&target).unwrap();
        let modules = vec![(ModuleId(3), spelling.clone(), (8, 1), ino)];
        let (matched, unmatched) = match_forwarding_inputs(&[target], &modules);
        assert!(matched.is_empty(), "deleted input matches nothing");
        assert_eq!(unmatched, vec![spelling]);
    }

    #[test]
    fn forwarding_match_bare_name_matches_every_basename() {
        use std::path::PathBuf;
        let modules = vec![
            (ModuleId(3), "/opt/liba.so".into(), (8, 1), 100),
            (ModuleId(4), "/snap/liba.so".into(), (8, 2), 200),
            (ModuleId(5), "/opt/libb.so".into(), (8, 1), 300),
        ];
        let (matched, unmatched) = match_forwarding_inputs(
            &[PathBuf::from("liba.so"), PathBuf::from("nope.so")],
            &modules,
        );
        assert_eq!(matched, vec![ModuleId(3), ModuleId(4)]);
        assert_eq!(unmatched, vec!["nope.so".to_string()]);
    }

    #[test]
    fn forwarding_match_nothing_declared_matches_nothing() {
        let modules = vec![(ModuleId(3), "/opt/liba.so".into(), (8, 1), 100)];
        let (matched, unmatched) = match_forwarding_inputs(&[], &modules);
        assert!(matched.is_empty());
        assert!(unmatched.is_empty());
    }

    /// A refused closure array with nothing captured below it says so: its
    /// calls are not counted anywhere.
    #[test]
    fn scope_summary_names_a_refused_closure_array_with_nothing_below_it() {
        let mut ev = evidence();
        ev.discovery.modules.clear();
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/libp11-kit.so".into(),
            reason: format!(
                "module needs 6530 more; only 512 attach slots are available; 0 are in use \
                 (0 active, 0 retired) — refusing to attach a prefix of its 64 lookalike function \
                 tables {}",
                crate::plan::CLOSURE_ARRAY_NOTE_DETAILED
            ),
        });
        ev.verdict();
        let text =
            scope_summary_with_verbosity("pid", &[], &ev, crate::cli::TextVerbosity::Verbose);
        assert!(
            text.contains("/opt/libp11-kit.so: not attached — "),
            "{text}"
        );
        assert!(text.contains("no provider below it was captured"), "{text}");
        assert!(
            text.contains("Calls the forwarding layer answers itself are not counted"),
            "{text}"
        );
    }

    /// A refused closure array above attached-but-quiet providers says the
    /// providers counted nothing, rather than naming a count.
    #[test]
    fn scope_summary_names_a_refused_closure_array_above_quiet_providers() {
        let mut ev = evidence();
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/libp11-kit.so".into(),
            reason: format!(
                "module needs 6530 more; only 512 attach slots are available; 68 are in use \
                 (68 active, 0 retired) — refusing to attach a prefix of its 64 lookalike function \
                 tables {}",
                crate::plan::CLOSURE_ARRAY_NOTE_DETAILED
            ),
        });
        ev.verdict();
        let text =
            scope_summary_with_verbosity("pid", &[], &ev, crate::cli::TextVerbosity::Verbose);
        assert!(!ev.discovery.modules.is_empty());
        assert!(
            text.contains(
                "no other attached provider counted calls; the layer's own calls stay in the totals"
            ),
            "{text}"
        );
        assert!(
            text.contains("Calls the forwarding layer answers itself are not counted"),
            "{text}"
        );
    }

    /// The named gap list is bounded: at most five lines plus "and K more".
    #[test]
    fn scope_summary_bounds_the_named_gap_list() {
        let mut ev = evidence();
        for index in 0..7 {
            ev.discovery.modules_skipped.push(SkippedOut {
                name: format!("/opt/refused{index}.so"),
                reason: "module needs 1 more".into(),
            });
        }
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "pid",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(text.contains("Module gaps (showing 5 of 7):"), "{text}");
        assert!(text.contains("/opt/refused0.so: not attached — "), "{text}");
        assert!(text.contains("/opt/refused4.so: not attached — "), "{text}");
        assert!(!text.contains("/opt/refused5.so"), "{text}");
        assert!(text.contains("and 2 more"), "{text}");
    }

    /// A proxy closure refusal must not push whole-refused providers out
    /// of the concise list: the plan can order proxies first while the
    /// refused files (the ones whose calls are not counted at all) hide
    /// behind "and K more". Concise names the refused providers first.
    #[test]
    fn concise_module_gaps_name_refused_providers_before_proxy_closures() {
        let mut ev = evidence();
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.4.8".into(),
            reason: format!(
                "a proxy closure array in a detailed capture attaches only its published tables, \
                 and none of its 67 lookalike function tables is published yet, so calls through \
                 it are not counted {}",
                crate::plan::CLOSURE_ARRAY_NOTE_DETAILED,
            ),
        });
        for (name, need) in [
            (
                "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so",
                "module needs 68 more; only 512 attach slots are available",
            ),
            (
                "/snap/firefox/9057/usr/lib/firefox/libsoftokn3.so",
                "module needs 212 more; only 512 attach slots are available",
            ),
        ] {
            ev.discovery.modules_skipped.push(SkippedOut {
                name: name.into(),
                reason: need.into(),
            });
        }
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "system",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Concise,
        );
        assert!(text.contains("Module gaps (showing 2 of 3):"), "{text}");
        assert!(text.contains("p11-kit-trust.so"), "{text}");
        assert!(
            text.contains("/snap/firefox/9057/usr/lib/firefox/libsoftokn3.so"),
            "{text}"
        );
        assert!(text.contains("and 1 more"), "{text}");
        assert!(
            !text.contains("/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.4.8"),
            "{text}"
        );
    }

    /// The verbose list keeps the same severity order: refused providers
    /// read before proxy closures there too.
    #[test]
    fn verbose_module_gaps_name_refused_providers_before_proxy_closures() {
        let mut ev = evidence();
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/proxy.so".into(),
            reason: format!(
                "a proxy closure array in a detailed capture attaches only its published tables, \
                 and none of its 67 lookalike function tables is published yet, so calls through \
                 it are not counted {}",
                crate::plan::CLOSURE_ARRAY_NOTE_DETAILED,
            ),
        });
        ev.discovery.modules_skipped.push(SkippedOut {
            name: "/opt/refused.so".into(),
            reason: "module needs 68 more; only 512 attach slots are available".into(),
        });
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "system",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(text.contains("Module gaps (showing 2 of 2):"), "{text}");
        let refused = text.find("/opt/refused.so").expect("refused row");
        let proxy = text.find("/opt/proxy.so").expect("proxy row");
        assert!(refused < proxy, "{text}");
    }

    /// Two physical files can share one path (two refused rows with the
    /// same name and reason): each row then names its occurrence so the
    /// reader can tell the lines apart.
    #[test]
    fn concise_module_gaps_number_same_path_files() {
        let mut ev = evidence();
        for _ in 0..2 {
            ev.discovery.modules_skipped.push(SkippedOut {
                name: "/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.4.8".into(),
                reason: format!(
                    "a proxy closure array in a detailed capture attaches only its published \
                     tables, and none of its 67 lookalike function tables is published yet, so \
                     calls through it are not counted {}",
                    crate::plan::CLOSURE_ARRAY_NOTE_DETAILED,
                ),
            });
        }
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "system",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Concise,
        );
        assert!(text.contains("Module gaps (showing 2 of 2):"), "{text}");
        assert!(
            text.contains("libp11-kit.so.0.4.8 (same-path file 1 of 2):"),
            "{text}"
        );
        assert!(
            text.contains("libp11-kit.so.0.4.8 (same-path file 2 of 2):"),
            "{text}"
        );
    }

    /// Occurrence numbers count against the full list, not the shown
    /// subset: with three same-path rows concise shows "1 of 3" and
    /// "2 of 3" plus "and 1 more".
    #[test]
    fn concise_same_path_numbers_count_every_row() {
        let mut ev = evidence();
        for _ in 0..3 {
            ev.discovery.modules_skipped.push(SkippedOut {
                name: "/opt/dup.so".into(),
                reason: "module needs 68 more; only 512 attach slots are available".into(),
            });
        }
        ev.verdict();
        let text = scope_summary_with_verbosity(
            "system",
            &reports_fixture(),
            &ev,
            crate::cli::TextVerbosity::Concise,
        );
        assert!(text.contains("Module gaps (showing 2 of 3):"), "{text}");
        assert!(
            text.contains("/opt/dup.so (same-path file 1 of 3):"),
            "{text}"
        );
        assert!(
            text.contains("/opt/dup.so (same-path file 2 of 3):"),
            "{text}"
        );
        assert!(text.contains("and 1 more"), "{text}");
    }

    #[test]
    fn provider_change_forces_partial_and_is_shown_live() {
        let mut ev = evidence();
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
        ev.provider_changed = true;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        let frame = live(
            &[],
            &ev,
            Duration::from_secs(1),
            "/x.so",
            "profile",
            CapturePolicy::Allowlisted,
        );
        assert!(
            frame.contains("provider file changed during capture"),
            "{frame}"
        );
        assert_eq!(
            serde_json::to_value(&ev).unwrap()["provider_changed"],
            serde_json::Value::Bool(true)
        );
    }

    #[test]
    fn unproven_terminal_drain_forces_partial_without_fabricating_a_gap() {
        let mut ev = evidence();
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");

        ev.mark_terminal_drain_unproven();

        assert_eq!(ev.completeness, "PARTIAL");
        assert_eq!(ev.in_flight_at_end, 0);
        assert_eq!(ev.event_loss, 0);
        assert_eq!(ev.malformed_records, 0);
        let value = serde_json::to_value(&ev).unwrap();
        assert!(value.get("terminal_drain_unproven").is_none());
    }

    /// Slow-sink drops lose data only when stdout carried the data (trace
    /// without `-o`); a profile/metrics/`-o` stdout carries display frames,
    /// so there the drops are stated but are no observation gap.
    #[test]
    fn sink_drops_force_partial_only_when_stdout_is_the_data_sink() {
        let mut ev = evidence();
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");

        ev.scheduling.sink_dropped_bytes = 1024;
        ev.scheduling.sink_timeouts = 1;
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE", "display-only drops");
        assert_eq!(ev.scheduling.sink_dropped_bytes, 1024);
        assert_eq!(ev.scheduling.sink_timeouts, 1);

        ev.stdout_data_sink = true;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        assert_eq!(ev.verdict_detail, VERDICT_CONCRETE_GAP);
        assert_eq!(
            ev.gap_classes.observation.causes,
            ["scheduling.sink_dropped_bytes"]
        );
    }

    #[test]
    fn terminal_drain_truncation_forces_partial() {
        let mut ev = evidence();
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");

        ev.scheduling.terminal_drain_truncated = true;
        ev.verdict();

        assert_eq!(ev.completeness, "PARTIAL");
    }

    /// F4: frame-budget deferrals are scheduling evidence, never an
    /// observation loss — a document with deferrals and no skips stays
    /// exact, whatever the count.
    #[test]
    fn discovery_deferrals_are_scheduling_evidence_never_a_loss() {
        let mut ev = evidence();
        ev.scheduling.discovery_deferrals = 3;
        ev.verdict();

        assert_eq!(ev.completeness, "COMPLETE");
        assert!(ev.gap_classes.observation.causes.is_empty());
        let value = serde_json::to_value(&ev).unwrap();
        assert_eq!(value["scheduling"]["discovery_deferrals"], 3);
    }

    #[test]
    fn scheduling_evidence_serializes_with_declared_policy() {
        let value = serde_json::to_value(evidence()).unwrap();
        let scheduling = value
            .get("scheduling")
            .expect("scheduling evidence is serialized");
        assert_eq!(scheduling["sink_policy"], "bounded-wait-drop");
        for key in [
            "drain_repolls",
            "drain_budget_exhaustions",
            "capture_event_loss",
            "detach_event_loss",
            "capture_discovery_loss",
            "detach_discovery_loss",
            "terminal_drain_bound",
            "terminal_drain_truncated",
            "sink_policy",
            "sink_stall_ms",
            "sink_timeouts",
            "sink_dropped_bytes",
            "phase_ms",
            "phase_mono_ns",
            "max_inter_drain_gap_ms",
            "discovery_deferrals",
            "stage_ms",
            "stage_invocations",
            "stage_unknown_clock",
            "longest_op",
            "inter_drain_gap",
            "newcomer_queue",
            "resource",
            "tail_publishes",
            "tail_skips",
        ] {
            assert!(
                scheduling.get(key).is_some(),
                "scheduling evidence lacks {key}"
            );
        }
        for key in ["discovery", "drain", "maps", "render", "detach"] {
            assert!(
                scheduling["phase_ms"].get(key).is_some(),
                "phase timers lack {key}"
            );
        }
    }

    #[test]
    fn phase_mono_ns_serializes_with_nulls_and_closed_reason() {
        let value = serde_json::to_value(evidence()).unwrap();
        let phase = &value["scheduling"]["phase_mono_ns"];
        for key in [
            "attach_mono_ns",
            "loop_start_mono_ns",
            "loop_end_mono_ns",
            "loop_end_reason",
        ] {
            assert!(phase.get(key).is_some(), "phase stamps lack {key}");
        }
        assert!(phase["attach_mono_ns"].is_null());
        assert!(phase["loop_start_mono_ns"].is_null());
        assert!(phase["loop_end_mono_ns"].is_null());
        assert_eq!(phase["loop_end_reason"], LOOP_END_UNSTARTED);

        let stamped = PhaseMonoNs {
            attach_mono_ns: Some(100),
            loop_start_mono_ns: Some(200),
            loop_end_mono_ns: Some(300),
            loop_end_reason: LOOP_END_EXPIRY,
        };
        let value = serde_json::to_value(stamped).unwrap();
        assert_eq!(value["attach_mono_ns"], 100);
        assert_eq!(value["loop_start_mono_ns"], 200);
        assert_eq!(value["loop_end_mono_ns"], 300);
        assert_eq!(value["loop_end_reason"], "expiry");
    }

    #[test]
    fn history_loss_reaches_profile_json_trace_and_stderr_with_zero_pending() {
        let mut state = crate::semantics::State::new(&init_plan());
        state.reject_history(&init_event(0, 1, 0, 0, 0, 0));
        let mut ev = evidence();
        ev.semantic_history_drops = state.semantic_evidence().semantic_history_drops;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        assert_eq!(state.pending_at_end(), 0);
        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::Allowlisted,
            scope: "pid",
            caller: None,
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let value = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);
        assert_eq!(value["evidence"]["semantic_history_drops"], 1);
        assert_eq!(value["evidence"]["completeness"], "PARTIAL");
        assert!(
            crate::trace::evidence_line(&ev, CapturePolicy::Allowlisted)
                .contains("\"semantic_history_drops\":1")
        );
        assert!(
            live_scoped_with_verbosity(
                &[],
                &ev,
                Duration::ZERO,
                "/x.so",
                "profile",
                CapturePolicy::Allowlisted,
                "selected",
                &BTreeMap::new(),
                crate::cli::TextVerbosity::Verbose,
            )
            .contains("semantic_history_drops=1")
        );
        let text = value.to_string();
        assert!(!text.contains("task_cookie"));
        assert!(!text.contains("exec_id"));
        ev.semantic_history_drops = u64::MAX;
        let _ = live(
            &[],
            &ev,
            Duration::ZERO,
            "/x.so",
            "profile",
            CapturePolicy::Allowlisted,
        );
    }

    #[test]
    fn any_gap_forces_partial() {
        for mutate in [
            (|e: &mut Evidence| e.attach_failures.push("boom".into())) as fn(&mut Evidence),
            // A NULL-pointer skip is not a gap (it cannot be called);
            // any other entry skip is.
            |e: &mut Evidence| {
                e.skipped.push(SkippedOut {
                    name: "C_X".into(),
                    reason: ENTRY_UNAVAILABLE.into(),
                })
            },
            |e: &mut Evidence| e.aliased.push(vec!["C_A".into(), "C_B".into()]),
            |e: &mut Evidence| e.in_flight_at_end = 1,
            |e: &mut Evidence| e.surfaces[0].walk = "known_prefix".into(),
            |e: &mut Evidence| e.surfaces[0].acquisition = "error: boom".into(),
            |e: &mut Evidence| e.vendor_interfaces = 1,
            |e: &mut Evidence| e.interface_list = "error: boom".into(),
            |e: &mut Evidence| e.event_loss = 1,
            |e: &mut Evidence| e.start_insert_failures = 1,
            |e: &mut Evidence| e.unmatched_returns = 1,
            |e: &mut Evidence| e.rv_update_failures = 1,
            |e: &mut Evidence| e.cgroup_scope_failures = 1,
            |e: &mut Evidence| e.abi_refusals = 1,
            |e: &mut Evidence| e.semantic_capture_failures = 1,
            |e: &mut Evidence| e.unregistered_mechanisms = 1,
            |e: &mut Evidence| e.template_tail_failures = 1,
            |e: &mut Evidence| e.process_tracking_failures = 1,
            |e: &mut Evidence| e.process_tracking_evictions = 1,
            |e: &mut Evidence| e.state_reconciliations = 1,
            |e: &mut Evidence| e.session_cancel_ambiguities = 1,
            |e: &mut Evidence| e.session_cancel_unknown_flags = 1,
            |e: &mut Evidence| e.operation_state_imports = 1,
            |e: &mut Evidence| e.auth_state_ambiguities = 1,
            |e: &mut Evidence| e.async_target_failures = 1,
            |e: &mut Evidence| e.async_orphans = 1,
            |e: &mut Evidence| e.async_duplicates = 1,
            |e: &mut Evidence| e.async_evictions = 1,
            |e: &mut Evidence| e.fork_state_ambiguities = 1,
            |e: &mut Evidence| e.semantic_state_drops = 1,
            |e: &mut Evidence| e.semantic_history_drops = 1,
            |e: &mut Evidence| e.pending_at_end = 1,
            |e: &mut Evidence| e.malformed_records = 1,
            |e: &mut Evidence| e.templates_truncated = true,
            |e: &mut Evidence| e.shape_decode_total_failures = 1,
        ] {
            let mut ev = evidence();
            mutate(&mut ev);
            ev.verdict();
            assert_eq!(
                ev.completeness, "PARTIAL",
                "a gap must never read as COMPLETE"
            );
        }
    }

    #[test]
    fn orphan_ops_and_unmatched_closes_do_not_affect_completeness() {
        // Informational evidence fields, not attach/loss gaps: a capture
        // that started mid-operation is still COMPLETE for what it saw.
        let mut ev = evidence();
        ev.orphan_ops = 3;
        ev.unmatched_closes = 2;
        ev.process_tracking_fallbacks = 4;
        ev.shape_decode_failures = 4;
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
    }

    #[test]
    fn live_view_shows_inflight_rows_and_marks_aliases() {
        let mut ev = evidence();
        ev.verdict();
        let out = live(
            &[
                report("C_Sign", 10, 0, false),
                report("C_WaitForSlotEvent", 0, 1, true),
            ],
            &ev,
            Duration::from_secs(65),
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
        );
        assert!(out.contains("C_Sign"));
        // Zero-call rows still appear when a call is in flight.
        assert!(out.contains("C_WaitForSlotEvent (aliased)"));
        assert!(out.contains("up 00:01:05"));
        assert!(out.contains("mode profile"));
        assert!(out.contains("approximation"));
    }

    fn mech_stat(calls: u64, errors: u64) -> crate::semantics::MechStat {
        crate::semantics::MechStat {
            calls,
            errors,
            ..Default::default()
        }
    }

    /// Demo journey 2: the human `profile` text names the mechanisms the
    /// capture observed, under the function table — the same ids the JSON
    /// `mechanisms[]` carries, with calls/errors and no parameters.
    #[test]
    fn live_view_lists_mechanisms_under_the_function_table() {
        let mut ev = evidence();
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> =
            [(0x250, mech_stat(8, 1)), (0x9999, mech_stat(2, 0))]
                .into_iter()
                .collect();
        let out = live_scoped_with_verbosity(
            &[report("C_Sign", 10, 0, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(out.contains("MECHANISM"), "{out}");
        assert!(out.contains("CKM_SHA256"), "{out}");
        assert!(out.contains("0x9999"), "{out}");
        let function = out.find("FUNCTION").expect("function table");
        let mechanism = out.find("MECHANISM").expect("mechanism table");
        let evidence = out.find("Evidence:").expect("evidence line");
        assert!(
            function < mechanism && mechanism < evidence,
            "mechanisms render under the function table: {out}"
        );
    }

    #[test]
    fn live_view_names_listed_vendor_id() {
        let mut ev = evidence();
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> =
            [(0xCE53_4351, mech_stat(5, 0))].into_iter().collect();
        let out = live_scoped_with_verbosity(
            &[report("C_GenerateKeyPair", 5, 0, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(out.contains("CKM_NSS_AES_KEY_WRAP"), "{out}");
    }

    #[test]
    fn live_view_shows_unnamed_vendor_id_by_number() {
        let mut ev = evidence();
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> =
            [(0xCE53_43A9, mech_stat(5, 0))].into_iter().collect();
        let out = live_scoped_with_verbosity(
            &[report("C_GenerateKeyPair", 5, 0, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(out.contains("vendor-defined 0xce5343a9"), "{out}");
    }

    #[test]
    fn live_view_shows_unknown_standard_id_by_number() {
        let mut ev = evidence();
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> =
            [(0x0000_FFFF, mech_stat(3, 1))].into_iter().collect();
        let out = live_scoped_with_verbosity(
            &[report("C_SignInit", 3, 1, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(out.contains("unknown 0xffff"), "{out}");
    }

    #[test]
    fn live_view_notes_mechanism_table_overflow() {
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> =
            [(0x250, mech_stat(8, 1))].into_iter().collect();
        let render = |overflow: u64| {
            let mut ev = evidence();
            ev.mechanism_id_overflow = overflow;
            ev.verdict();
            live_scoped_with_verbosity(
                &[report("C_Sign", 8, 1, false)],
                &ev,
                Duration::ZERO,
                "/opt/p11.so",
                "profile",
                CapturePolicy::Allowlisted,
                "pid",
                &mechanisms,
                crate::cli::TextVerbosity::Verbose,
            )
        };
        let out = render(3);
        assert!(
            out.contains("plus 3 further mechanism observations beyond the 256-id table"),
            "{out}"
        );
        let one = render(1);
        assert!(
            one.contains("plus 1 further mechanism observation beyond the 256-id table"),
            "{one}"
        );
        let clean = render(0);
        assert!(!clean.contains("beyond the 256-id table"), "{clean}");
    }

    #[test]
    fn live_view_without_mechanisms_shows_no_table() {
        let mut ev = evidence();
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> = BTreeMap::new();
        let out = live_scoped(
            &[report("C_Sign", 10, 0, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
        );
        assert!(!out.contains("MECHANISM"), "{out}");
    }

    /// Live rows at a forwarding layer carry the `(forwarding layer)`
    /// marker; provider rows do not. The table holds two `C_Sign` rows,
    /// exactly one marked.
    #[test]
    fn live_table_marks_forwarding_layer_rows() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_Sign", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> = BTreeMap::new();
        let out = live_scoped(
            &[outer, inner],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
        );
        assert!(out.contains("C_Sign (forwarding layer)"), "{out}");
        assert_eq!(out.matches("C_Sign").count(), 2, "{out}");
        assert_eq!(out.matches("(forwarding layer)").count(), 1, "{out}");
    }

    /// A marked long-name row stays inside the name field: its CALLS
    /// value aligns with the header's CALLS column instead of pushing
    /// the row's columns right.
    #[test]
    fn live_table_forwarding_marker_keeps_column_alignment() {
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.path = "/opt/libforward.so".into();
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.path = "/opt/libbackend.so".into();
        let mut outer = report("C_GetAttributeValue", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![layer, backend];
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> = BTreeMap::new();
        let out = live_scoped(
            &[outer, inner],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
        );
        let header = out
            .lines()
            .find(|line| line.starts_with("FUNCTION"))
            .expect("function table header");
        let calls_col = header.find("CALLS").expect("CALLS column");
        let marked = out
            .lines()
            .find(|line| line.contains("C_GetAttributeValue (forwarding layer)"))
            .expect("marked long-name row");
        assert_eq!(
            &marked[calls_col..calls_col + 5],
            "  500",
            "marked row CALLS aligns with the header: {out}"
        );
        let plain = out
            .lines()
            .find(|line| line.starts_with("C_Sign "))
            .expect("unmarked row");
        assert_eq!(
            &plain[calls_col..calls_col + 5],
            "  744",
            "unmarked row CALLS aligns with the header: {out}"
        );
    }

    /// The live name field sizes to the longest rendered name (min 28),
    /// not a fixed width: short frames stay compact, long marked rows expand.
    #[test]
    fn live_table_name_field_sizes_to_longest_rendered_name() {
        let mut backend = discovered_fixture();
        backend.id = ModuleId(8);
        backend.admission_class = Some("corroborated");
        backend.path = "/opt/libbackend.so".into();
        let mut row = report("C_Sign", 10, 0, false);
        row.module = Some(ModuleId(8));
        let mut ev = evidence();
        ev.discovery.modules = vec![backend];
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> = BTreeMap::new();
        let out = live_scoped(
            &[row],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
        );
        let header = out
            .lines()
            .find(|line| line.starts_with("FUNCTION"))
            .expect("function table header");
        let calls_col = header.find("CALLS").expect("CALLS column");
        // Name width + gap + PROVIDER column + gap + CALLS right-offset.
        assert_eq!(
            calls_col,
            28 + 1 + 16 + 1 + 3,
            "a short frame uses the min width 28: {out}"
        );
        let mut layer = discovered_fixture();
        layer.id = ModuleId(7);
        layer.admission_class = Some("closure_array");
        layer.path = "/opt/libforward.so".into();
        let mut backend2 = discovered_fixture();
        backend2.id = ModuleId(8);
        backend2.admission_class = Some("corroborated");
        backend2.path = "/opt/libbackend.so".into();
        let mut outer = report("C_GetAttributeValue", 500, 0, false);
        outer.module = Some(ModuleId(7));
        let mut inner = report("C_Sign", 744, 0, false);
        inner.module = Some(ModuleId(8));
        let mut ev2 = evidence();
        ev2.discovery.modules = vec![layer, backend2];
        ev2.verdict();
        let out2 = live_scoped(
            &[outer, inner],
            &ev2,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
        );
        let header2 = out2
            .lines()
            .find(|line| line.starts_with("FUNCTION"))
            .expect("function table header");
        let calls_col2 = header2.find("CALLS").expect("CALLS column");
        // Name width + gap + PROVIDER column + gap + CALLS right-offset.
        assert_eq!(
            calls_col2,
            38 + 1 + 16 + 1 + 3,
            "a long marked row expands the field to its rendered name: {out2}"
        );
    }

    /// Demo journey 2, empty side: with observed calls but no attributed
    /// mechanisms, the human view says so in one plain line naming the
    /// count-only gap and how to get mechanisms, instead of omitting the
    /// section. The line sits under the function table, above Evidence.
    #[test]
    fn live_view_without_mechanisms_names_the_attribution_gap() {
        let mut ev = evidence();
        ev.semantic_unverified_slots = 212;
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> = BTreeMap::new();
        let out = live_scoped_with_verbosity(
            &[report("C_SignInit", 2, 0, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(
            out.contains(
                "Mechanisms: none attributed — 212 functions named from the standard table, \
                 unconfirmed; add --manifest for provider files with unverified tables to confirm their layouts (see Coverage)."
            ),
            "{out}"
        );
        let function = out.find("FUNCTION").expect("function table");
        let note = out
            .find("Mechanisms: none attributed")
            .expect("mechanisms note");
        let evidence = out.find("Evidence:").expect("evidence line");
        assert!(
            function < note && note < evidence,
            "mechanisms note renders under the function table: {out}"
        );
    }

    /// Concise keeps one manifest remedy (coverage); verbose keeps every
    /// hint. Three identical nags in one concise report bury the result.
    #[test]
    fn concise_frame_mentions_manifest_once() {
        let mut unattested = discovered_fixture();
        unattested.sources = vec!["scan"];
        let mut ev = evidence();
        ev.discovery.modules = vec![unattested];
        ev.semantic_unverified_slots = 68;
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> = BTreeMap::new();
        let row = report("C_Sign", 2, 0, false);
        let concise = live_scoped_with_verbosity(
            std::slice::from_ref(&row),
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
            crate::cli::TextVerbosity::Concise,
        );
        assert_eq!(
            concise.matches("--manifest").count(),
            1,
            "concise keeps one manifest hint: {concise}"
        );
        let verbose = live_scoped_with_verbosity(
            &[row],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(
            verbose.matches("--manifest").count() >= 3,
            "verbose keeps every hint: {verbose}"
        );
    }

    /// Unverified slots with every mapped provider attested (partial
    /// manifest coverage, e.g. a manifest/scan conflict): the manifest
    /// remedy would mislead, so the note records the bare fact.
    #[test]
    fn live_view_without_mechanisms_on_partial_coverage_says_none_recorded() {
        let mut attested = discovered_fixture();
        attested.sources = vec!["scan", "manifest"];
        let mut ev = evidence();
        ev.discovery.modules = vec![attested];
        ev.semantic_unverified_slots = 106;
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> = BTreeMap::new();
        let out = live_scoped(
            &[report("C_GenerateRandom", 6, 0, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
        );
        assert!(
            out.contains("Mechanisms: none recorded for the observed calls."),
            "{out}"
        );
        // The note itself offers no manifest remedy; the coverage line
        // above it still names the unconfirmed names.
        let note = out
            .lines()
            .find(|line| line.starts_with("Mechanisms:"))
            .expect("mechanisms note: {out}");
        assert!(!note.contains("--manifest"), "{out}");
    }

    /// Empty mechanisms with fully attested slots: none of the observed
    /// calls carried an attributed mechanism, so the note says exactly
    /// that and offers no manifest remedy.
    #[test]
    fn live_view_without_mechanisms_on_verified_slots_says_none_recorded() {
        let mut ev = evidence();
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> = BTreeMap::new();
        let out = live_scoped(
            &[report("C_GetInfo", 1, 0, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
        );
        assert!(
            out.contains("Mechanisms: none recorded for the observed calls."),
            "{out}"
        );
        assert!(!out.contains("--manifest"), "{out}");
    }

    /// No completed or in-flight calls: the scope summary already says no
    /// calls were observed, so no mechanisms note is added.
    #[test]
    fn live_view_without_calls_shows_no_mechanism_note() {
        let mut ev = evidence();
        ev.semantic_unverified_slots = 212;
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> = BTreeMap::new();
        let out = live_scoped(
            &[report("C_Sign", 0, 0, false)],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &mechanisms,
        );
        assert!(!out.contains("Mechanisms:"), "{out}");
    }

    /// U-14: the live evidence line must show the plan's currently-active
    /// endpoint count next to the ever-growing allocation total, not just
    /// the allocation total alone.
    #[test]
    fn live_view_shows_active_slots_next_to_allocated_slots() {
        let mut ev = evidence();
        ev.slots = 10;
        ev.active_slots = 4;
        ev.attached_probes = 8;
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "selected",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(
            out.contains("10 slots (4 active)"),
            "must pin the exact format docs/usage.md documents: {out}"
        );
    }

    #[test]
    fn live_view_surfaces_gap_counters_when_nonzero() {
        let mut ev = evidence();
        ev.event_loss = 5;
        ev.malformed_records = 2;
        ev.verdict();
        let out = live(
            &[report("C_Sign", 10, 0, false)],
            &ev,
            Duration::from_secs(10),
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
        );
        // Coverage line shows why a PARTIAL verdict was rendered.
        assert!(
            out.contains("5 call records lost"),
            "event_loss must appear in the coverage line"
        );
        assert!(
            out.contains("2 unreadable kernel records"),
            "malformed_records must appear in the coverage line"
        );
        assert!(out.contains("coverage: partial"));
    }

    #[test]
    fn live_view_surfaces_informational_counters_when_nonzero() {
        let mut ev = evidence();
        ev.orphan_ops = 3;
        ev.unmatched_closes = 1;
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[report("C_Sign", 10, 0, false)],
            &ev,
            Duration::from_secs(10),
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "selected",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Verbose,
        );
        // Informational evidence: capture started mid-operation, still marked COMPLETE for its scope.
        assert!(
            out.contains("3 orphan ops"),
            "orphan_ops must appear in evidence line"
        );
        assert!(
            out.contains("1 unmatched closes"),
            "unmatched_closes must appear in evidence line"
        );
        assert!(out.contains("COMPLETE"));
    }

    #[test]
    fn live_view_gap_fragments_render_in_class_order() {
        // MED: the gap block is table-driven; pin the relative order, not
        // exact bytes.
        let mut ev = evidence();
        ev.discovery.conflicts = 1;
        ev.event_loss = 2;
        ev.malformed_records = 3;
        ev.provider_changed = true;
        ev.verdict();
        let out = live(
            &[],
            &ev,
            Duration::ZERO,
            "/x.so",
            "profile",
            CapturePolicy::Allowlisted,
        );
        // F-13: fragments group by class — observation, then attribution —
        // each in its gate order.
        let positions = [
            out.find("calls may be missing (").unwrap(),
            out.find("2 call records lost").unwrap(),
            out.find("3 unreadable kernel records").unwrap(),
            out.find("provider file changed during capture").unwrap(),
            out.find("names unconfirmed (").unwrap(),
            out.find("manifest and scan disagree on 1 provider file")
                .unwrap(),
        ];
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "gap fragments out of order: {out}"
        );
    }

    #[test]
    fn live_view_lone_fallback_fragment_is_single_spaced() {
        // MED: the fallbacks fragment unconditionally prefixed a space, so a
        // lone "process trackers" line rendered "·  ℹ" (double space). The
        // table joins fragments uniformly; pin the single space.
        let mut ev = evidence();
        ev.process_tracking_fallbacks = 1;
        ev.verdict();
        let out = live_scoped_with_verbosity(
            &[],
            &ev,
            Duration::ZERO,
            "/x.so",
            "profile",
            CapturePolicy::Allowlisted,
            "selected",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(
            out.contains("· ℹ 1 process trackers using /proc"),
            "lone fallback fragment must be single-spaced: {out}"
        );
    }

    #[test]
    fn every_gap_counter_opens_the_evidence_gate_alone() {
        // MED: the gate used to re-list every gap condition by hand, so a new
        // fragment without a gate term rendered nothing. The table derives
        // the gate from the same fragments; each counter alone must surface.
        let gap_cases: [(&str, EvidenceMutation); 23] = [
            ("manifest and scan disagree on 1 provider file", |e| {
                e.discovery.conflicts = 1
            }),
            ("1 provider file not confirmed from a second source", |e| {
                e.discovery.uncorroborated = 1;
            }),
            ("1 function claimed by two provider files", |e| {
                e.discovery.module_ambiguous = 1;
            }),
            ("1 provider file not watched", |e| {
                e.discovery.modules_skipped.push(SkippedOut {
                    name: "/opt/x.so".into(),
                    reason: "capacity".into(),
                });
            }),
            ("1 provider file partially covered", |e| {
                e.discovery.modules_skipped.push(SkippedOut {
                    name: "/opt/grown.so".into(),
                    reason: GROWTH_OMISSION_RECORD.into(),
                });
            }),
            ("1 provider table incompletely read", |e| {
                e.surfaces[0].walk = "known_prefix".into();
            }),
            ("1 vendor-specific interface not decoded", |e| {
                e.vendor_interfaces = 1
            }),
            ("1 call record lost", |e| e.event_loss = 1),
            ("1 call start not recorded", |e| e.start_insert_failures = 1),
            ("1 return without a recorded start", |e| {
                e.unmatched_returns = 1
            }),
            ("1 return value not recorded", |e| e.rv_update_failures = 1),
            ("1 cgroup membership check failed", |e| {
                e.cgroup_scope_failures = 1
            }),
            ("1 mechanism detail not recorded", |e| {
                e.semantic_capture_failures = 1;
            }),
            ("1 unregistered mechanism", |e| {
                e.unregistered_mechanisms = 1;
            }),
            ("1 attribute-list read not recorded", |e| {
                e.template_tail_failures = 1;
            }),
            (
                "coverage: partial — counts complete; function names follow the standard PKCS#11 table",
                |e| {
                    e.semantic_unverified_slots = 1;
                },
            ),
            (
                "coverage: partial — counts complete; function names follow the standard PKCS#11 table",
                |e| {
                    e.semantic_unverified_slots = 2;
                },
            ),
            ("1 unreadable kernel record", |e| e.malformed_records = 1),
            ("attribute lists cut short", |e| {
                e.templates_truncated = true
            }),
            ("1 mechanism never decoded", |e| {
                e.shape_decode_total_failures = 1;
            }),
            ("provider file changed during capture", |e| {
                e.provider_changed = true
            }),
            ("no provider files found", |e| e.discovery.modules.clear()),
            ("memory scan unavailable (ptrace)", |e| {
                e.discovery.scan_unavailable = Some("ptrace".into());
            }),
        ];
        // Every state_gaps summand must feed the aggregate, not just open it.
        let state_cases: [EvidenceMutation; 14] = [
            |e| e.process_tracking_failures = 1,
            |e| e.process_tracking_evictions = 1,
            |e| e.state_reconciliations = 1,
            |e| e.session_cancel_ambiguities = 1,
            |e| e.session_cancel_unknown_flags = 1,
            |e| e.operation_state_imports = 1,
            |e| e.auth_state_ambiguities = 1,
            |e| e.async_target_failures = 1,
            |e| e.async_orphans = 1,
            |e| e.async_duplicates = 1,
            |e| e.async_evictions = 1,
            |e| e.fork_state_ambiguities = 1,
            |e| e.semantic_state_drops = 1,
            |e| e.pending_at_end = 1,
        ];
        let info_cases: [(&str, EvidenceMutation); 4] = [
            ("ℹ 1 orphan ops", |e| e.orphan_ops = 1),
            ("ℹ 1 unmatched closes", |e| e.unmatched_closes = 1),
            ("ℹ 1 shape decode gaps", |e| e.shape_decode_failures = 1),
            ("ℹ 1 process trackers using /proc", |e| {
                e.process_tracking_fallbacks = 1;
            }),
        ];
        for (fragment, mutate) in gap_cases {
            let mut ev = evidence();
            mutate(&mut ev);
            ev.verdict();
            let out = live(
                &[],
                &ev,
                Duration::ZERO,
                "/x.so",
                "profile",
                CapturePolicy::Allowlisted,
            );
            assert!(out.contains(fragment), "missing {fragment:?}: {out}");
        }
        for mutate in state_cases {
            let mut ev = evidence();
            mutate(&mut ev);
            ev.verdict();
            let out = live(
                &[],
                &ev,
                Duration::ZERO,
                "/x.so",
                "profile",
                CapturePolicy::Allowlisted,
            );
            assert!(
                out.contains("1 session-tracking gap"),
                "state summand lost from the aggregate: {out}"
            );
            assert!(
                !out.contains("1 session-tracking gaps"),
                "singular count must use the singular: {out}"
            );
        }
        for (fragment, mutate) in info_cases {
            let mut ev = evidence();
            mutate(&mut ev);
            ev.verdict();
            // The ℹ fragments ride the Evidence line: verbose-only.
            let out = live_scoped_with_verbosity(
                &[],
                &ev,
                Duration::ZERO,
                "/x.so",
                "profile",
                CapturePolicy::Allowlisted,
                "selected",
                &BTreeMap::new(),
                crate::cli::TextVerbosity::Verbose,
            );
            assert!(out.contains(fragment), "missing {fragment:?}: {out}");
        }
    }

    // Owner-approved 2026-09-27: a scanned [3,9] provider yields a
    // `known_prefix` surface — the scan's own `spans_for` label flows
    // into the report — and the verdict is PARTIAL with a disclosed
    // "surface gaps" cause, never the retired version skip. What a
    // `known_prefix` surface means is unchanged; only its source grew.
    #[test]
    fn scanned_future_minor_prefix_is_a_surface_gap_not_a_version_skip() {
        let (_, spans, walk) =
            crate::discovery::scan::spans_for(0x0903).expect("[3,9] is walked by the scan");
        assert_eq!(walk, "known_prefix");
        let mut ev = evidence();
        ev.surfaces = vec![crate::plan::SurfaceSummary {
            source: "interface".into(),
            walk: walk.into(),
            acquisition: "ok".into(),
            functions: spans.iter().map(|span| span.fields().len()).sum(),
        }];
        assert_eq!(ev.surfaces[0].functions, 104);
        assert!(
            ev.skipped.is_empty(),
            "a walked prefix carries no skip: {:?}",
            ev.skipped
        );
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        let out = live(
            &[],
            &ev,
            Duration::ZERO,
            "/x.so",
            "profile",
            CapturePolicy::Allowlisted,
        );
        assert!(out.contains("1 provider table incompletely read"), "{out}");
        assert!(!out.contains("unsupported function-table"), "{out}");
    }

    fn fedora_fixture_maps() -> Vec<p11scope_manifest::maps::MapEntry> {
        p11scope_manifest::maps::parse_maps(
            b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n\
              4000-5000 rw-p 00001000 08:01 7 /lib/provider.so\n\
              7000-9000 r--p 00002000 08:01 7 /lib/provider.so\n",
        )
        .unwrap()
    }

    fn fedora_shaped_snapshot() -> Vec<u8> {
        let mut snapshot = vec![0u8; 8 + 104 * 8];
        snapshot[..8].copy_from_slice(&0x0203u64.to_le_bytes());
        for slot in 0..69 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_le_bytes());
        }
        for slot in 69..104 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x4500u64.to_le_bytes());
        }
        snapshot
    }

    fn decode_table_with_maps(
        snapshot: &[u8],
        maps: &[p11scope_manifest::maps::MapEntry],
    ) -> crate::discovery::scan::ScannedTable {
        use crate::discovery::scan::{CaptureWorkBudget, decode_exact_table};
        use p11scope_manifest::maps::MapIndex;

        let map_index = MapIndex::new(maps).unwrap();
        decode_exact_table(
            snapshot,
            0x7000,
            pkcs11_module::LinuxLayout::Lp64,
            &map_index,
            &mut CaptureWorkBudget::default(),
            None,
        )
        .expect("budget must admit the table")
        .expect("the fixture table must decode")
    }

    fn decode_fedora_table(snapshot: &[u8]) -> crate::discovery::scan::ScannedTable {
        decode_table_with_maps(snapshot, &fedora_fixture_maps())
    }

    /// The Fedora shape plus the four first-failure kinds: executable
    /// anonymous memory, an executable `(deleted)` mapping, writable
    /// anonymous data, and unmapped space (no range covers `0xdead000`).
    fn structural_failure_maps() -> Vec<p11scope_manifest::maps::MapEntry> {
        p11scope_manifest::maps::parse_maps(
            b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n\
              4000-5000 rw-p 00001000 08:01 7 /lib/provider.so\n\
              7000-9000 r--p 00002000 08:01 7 /lib/provider.so\n\
              a000-b000 r-xp 00000000 00:00 0\n\
              c000-d000 r-xp 00000000 08:01 7 /lib/provider.so (deleted)\n\
              e000-f000 rw-p 00000000 00:00 0\n",
        )
        .unwrap()
    }

    fn shaped_snapshot_with_tail(failure: u64) -> Vec<u8> {
        let mut snapshot = vec![0u8; 8 + 104 * 8];
        snapshot[..8].copy_from_slice(&0x0203u64.to_le_bytes());
        for slot in 0..69 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_le_bytes());
        }
        for slot in 69..104 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&failure.to_le_bytes());
        }
        snapshot
    }

    fn observation_for_decoded_table(
        snapshot: &[u8],
        exports: std::sync::Arc<[(String, u64)]>,
        hook_exports: Vec<String>,
        expect_walk: &str,
    ) -> GapClasses {
        let table = decode_fedora_table(snapshot);
        assert_eq!(table.decoded_slot_count(), 68);
        assert_eq!(
            table.walk, "known_prefix",
            "the scan keeps the mislabelling quirk label"
        );
        observation_for_table(table, exports, hook_exports, expect_walk, false, false)
    }

    fn observation_for_table(
        table: crate::discovery::scan::ScannedTable,
        exports: std::sync::Arc<[(String, u64)]>,
        hook_exports: Vec<String>,
        expect_walk: &str,
        getter_present: bool,
        witness_fault: bool,
    ) -> GapClasses {
        use crate::discovery::identity::{PinnedObjectId, ReconciledModule};
        use crate::discovery::scan::ScannedModule;
        use crate::plan::build_from_reconciled_modules;
        use crate::process::{MountNamespaceId, ProcessViewId};
        use p11scope_manifest::elf::ElfAbi;

        let key = table.entries[0].object;
        let object = PinnedObjectId(0);
        let entry_count = table.entries.len();
        let scanned = ScannedModule {
            module_hint: None,
            mapped_identity: None,
            view: ProcessViewId(0),
            mount_namespace: MountNamespaceId {
                device: 1,
                inode: 1,
            },
            key,
            double_loaded: false,
            same_file_loads: 1,
            pre_copy_up: None,
            path: "/lib/provider.so".into(),
            tables_scan_finished: false,
            decoder_abi: Some(ElfAbi::Lp64),
            exports: hook_exports,
            tables: vec![table],
            interfaces: vec![],
        };
        let reconciled = ReconciledModule {
            scanned,
            object,
            entry_objects: vec![vec![object; entry_count]],
            exports,
            getter_present,
            witness_fault,
        };
        let plan = build_from_reconciled_modules(std::slice::from_ref(&reconciled));
        assert_eq!(plan.surfaces.len(), 1);
        assert_eq!(plan.surfaces[0].walk, expect_walk);
        assert_eq!(plan.surfaces[0].acquisition, "ok");
        assert_eq!(plan.surfaces[0].functions, 68);
        let mut ev = evidence();
        ev.surfaces = plan.surfaces.clone();
        ev.gap_classes(true)
    }

    fn fedora_exports_without_interface_getters() -> std::sync::Arc<[(String, u64)]> {
        (0..68)
            .map(|ordinal| {
                (
                    pkcs11_module::function_name(ordinal).unwrap().to_string(),
                    0x500,
                )
            })
            .collect()
    }

    #[test]
    fn fedora_shaped_68_slot_prefix_under_32_label_is_exact() {
        let exports = fedora_exports_without_interface_getters();
        assert!(
            !exports
                .iter()
                .any(|(name, _)| name == "C_GetInterface" || name == "C_GetInterfaceList"),
            "the Fedora shape exports no 3.x interface getter"
        );
        let classes = observation_for_decoded_table(
            &fedora_shaped_snapshot(),
            exports,
            vec!["C_GetFunctionList".into()],
            "full",
        );
        assert_eq!(
            classes.observation.status, "exact",
            "a complete 68-slot prefix with an impossible extension and no \
             interface getters is the full reachable surface: {:?}",
            classes.observation.causes
        );
        assert!(
            classes.observation.causes.is_empty(),
            "no observation gap: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn fedora_shape_with_an_interface_getter_export_stays_lossy() {
        let mut names: Vec<(String, u64)> = fedora_exports_without_interface_getters().to_vec();
        names.push(("C_GetInterface".into(), 0x600));
        let classes = observation_for_decoded_table(
            &fedora_shaped_snapshot(),
            names.into(),
            vec!["C_GetFunctionList".into(), "C_GetInterface".into()],
            "known_prefix",
        );
        assert_eq!(classes.observation.status, "lossy");
        assert!(
            classes.observation.causes.contains(&"surfaces"),
            "an exported 3.x getter keeps a 3.x route reachable: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn fedora_shape_with_a_truncated_extension_stays_lossy() {
        let mut truncated = fedora_shaped_snapshot();
        truncated.truncate(8 + 68 * 8);
        let classes = observation_for_decoded_table(
            &truncated,
            fedora_exports_without_interface_getters(),
            vec!["C_GetFunctionList".into()],
            "known_prefix",
        );
        assert_eq!(classes.observation.status, "lossy");
        assert!(
            classes.observation.causes.contains(&"surfaces"),
            "an unreadable extension cannot prove completeness: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn fedora_shape_with_incomplete_export_evidence_stays_lossy() {
        let mut names: Vec<(String, u64)> = fedora_exports_without_interface_getters().to_vec();
        names.pop();
        assert_eq!(names.len(), 67);
        let classes = observation_for_decoded_table(
            &fedora_shaped_snapshot(),
            names.into(),
            vec!["C_GetFunctionList".into()],
            "known_prefix",
        );
        assert_eq!(classes.observation.status, "lossy");
        assert!(
            classes.observation.causes.contains(&"surfaces"),
            "export agreement must cover every decoded slot: {:?}",
            classes.observation.causes
        );
    }

    fn extension_failure_at_92_snapshot() -> Vec<u8> {
        let mut snapshot = vec![0u8; 8 + 104 * 8];
        snapshot[..8].copy_from_slice(&0x0203u64.to_le_bytes());
        for slot in 0..92 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_le_bytes());
        }
        for slot in 92..104 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x4500u64.to_le_bytes());
        }
        snapshot
    }

    fn extension_failure_at_68_snapshot() -> Vec<u8> {
        let mut snapshot = vec![0u8; 8 + 104 * 8];
        snapshot[..8].copy_from_slice(&0x0203u64.to_le_bytes());
        for slot in 0..68 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_le_bytes());
        }
        for slot in 68..104 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x4500u64.to_le_bytes());
        }
        snapshot
    }

    #[test]
    fn extension_failure_past_the_refutation_range_stays_lossy() {
        // Slots 68..91 are real functions, so the table may be a genuine
        // 92-wide 3.0/3.1 table mislabelled 3.2; the failure at 92 refutes
        // nothing and the 68-slot prefix stays unproven.
        let table = decode_fedora_table(&extension_failure_at_92_snapshot());
        assert_eq!(table.decoded_slot_count(), 68);
        assert_eq!(table.walk, "known_prefix");
        assert!(
            !table.extension_impossible,
            "a failure at 92 is outside 68..92 and proves nothing"
        );
        let classes = observation_for_table(
            table,
            fedora_exports_without_interface_getters(),
            vec!["C_GetFunctionList".into()],
            "known_prefix",
            false,
            false,
        );
        assert_eq!(classes.observation.status, "lossy");
        assert!(
            classes.observation.causes.contains(&"surfaces"),
            "an unrefuted 92-wide hypothesis keeps surfaces lossy: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn extension_failure_at_the_first_refutation_ordinal_is_exact() {
        // The failure at exactly 68 refutes the 92-wide hypothesis, so the
        // proven prefix reports full: the lower bound of 68..92 is inclusive.
        let table = decode_fedora_table(&extension_failure_at_68_snapshot());
        assert_eq!(table.decoded_slot_count(), 68);
        assert_eq!(table.walk, "known_prefix");
        assert!(
            table.extension_impossible,
            "a failure exactly at 68 is inside 68..92"
        );
        let classes = observation_for_table(
            table,
            fedora_exports_without_interface_getters(),
            vec!["C_GetFunctionList".into()],
            "full",
            false,
            false,
        );
        assert_eq!(
            classes.observation.status, "exact",
            "a failure at 68 proves the prefix complete: {:?}",
            classes.observation.causes
        );
        assert!(
            classes.observation.causes.is_empty(),
            "no observation gap: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn extension_failure_into_executable_anonymous_memory_stays_lossy() {
        // Executable anonymous memory (JIT, trampolines) may hold a real
        // extension the scanner cannot attach, so the failure refutes
        // nothing and the prefix stays unproven.
        let maps = structural_failure_maps();
        let table = decode_table_with_maps(&shaped_snapshot_with_tail(0xa500), &maps);
        assert_eq!(table.decoded_slot_count(), 68);
        assert_eq!(table.walk, "known_prefix");
        assert!(
            !table.extension_impossible,
            "executable anonymous memory is not a structural refutation"
        );
        let classes = observation_for_table(
            table,
            fedora_exports_without_interface_getters(),
            vec!["C_GetFunctionList".into()],
            "known_prefix",
            false,
            false,
        );
        assert_eq!(classes.observation.status, "lossy");
        assert!(
            classes.observation.causes.contains(&"surfaces"),
            "an attachable-but-unusable extension keeps surfaces lossy: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn extension_failure_into_an_executable_deleted_mapping_stays_lossy() {
        // An executable `(deleted)` mapping may hold real code reached
        // through a path the scanner cannot use, so the failure refutes
        // nothing and the prefix stays unproven.
        let maps = structural_failure_maps();
        let table = decode_table_with_maps(&shaped_snapshot_with_tail(0xc500), &maps);
        assert_eq!(table.decoded_slot_count(), 68);
        assert_eq!(table.walk, "known_prefix");
        assert!(
            !table.extension_impossible,
            "an executable unusable path is not a structural refutation"
        );
        let classes = observation_for_table(
            table,
            fedora_exports_without_interface_getters(),
            vec!["C_GetFunctionList".into()],
            "known_prefix",
            false,
            false,
        );
        assert_eq!(classes.observation.status, "lossy");
        assert!(
            classes.observation.causes.contains(&"surfaces"),
            "an attachable-but-unusable extension keeps surfaces lossy: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn extension_failure_into_writable_anonymous_data_is_exact() {
        // Anonymous memory without execute permission cannot hold the
        // extension, so the failure refutes the wider layouts.
        let maps = structural_failure_maps();
        let table = decode_table_with_maps(&shaped_snapshot_with_tail(0xe500), &maps);
        assert_eq!(table.decoded_slot_count(), 68);
        assert_eq!(table.walk, "known_prefix");
        assert!(
            table.extension_impossible,
            "non-executable anonymous memory refutes the wider layouts"
        );
        let classes = observation_for_table(
            table,
            fedora_exports_without_interface_getters(),
            vec!["C_GetFunctionList".into()],
            "full",
            false,
            false,
        );
        assert_eq!(
            classes.observation.status, "exact",
            "a structural failure proves the prefix complete: {:?}",
            classes.observation.causes
        );
        assert!(
            classes.observation.causes.is_empty(),
            "no observation gap: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn extension_failure_into_unmapped_space_is_exact() {
        // A slot pointing nowhere cannot be a function, so the failure
        // refutes the wider layouts.
        let maps = structural_failure_maps();
        let table = decode_table_with_maps(&shaped_snapshot_with_tail(0xdead000), &maps);
        assert_eq!(table.decoded_slot_count(), 68);
        assert_eq!(table.walk, "known_prefix");
        assert!(
            table.extension_impossible,
            "unmapped space refutes the wider layouts"
        );
        let classes = observation_for_table(
            table,
            fedora_exports_without_interface_getters(),
            vec!["C_GetFunctionList".into()],
            "full",
            false,
            false,
        );
        assert_eq!(
            classes.observation.status, "exact",
            "a structural failure proves the prefix complete: {:?}",
            classes.observation.causes
        );
        assert!(
            classes.observation.causes.is_empty(),
            "no observation gap: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn fedora_shape_with_an_unpinned_entry_stays_lossy() {
        use crate::discovery::scan::Skipped;

        // A stripped-provider shape: one entry could not be pinned (its
        // target lies in an object reconciliation could not open), so it
        // moved to `unpinned` under its ordinal label while the witness
        // lacks that name. Every pinned entry agrees; only the unpinned
        // record refuses the proof.
        let mut table = decode_fedora_table(&fedora_shaped_snapshot());
        let moved = table.entries.pop().expect("68 decoded entries");
        table.unpinned.push(Skipped {
            subject: moved.name.to_string(),
            reason: "/lib/dep.so could not be reconciled to a comparable pinned object; \
                     entry was not attached"
                .into(),
        });
        assert_eq!(table.decoded_slot_count(), 68);
        let mut names: Vec<(String, u64)> = fedora_exports_without_interface_getters().to_vec();
        names.retain(|(name, _)| *name != moved.name);
        assert_eq!(names.len(), 67);
        let classes = observation_for_table(
            table,
            names.into(),
            vec!["C_GetFunctionList".into()],
            "known_prefix",
            false,
            false,
        );
        assert_eq!(classes.observation.status, "lossy");
        assert!(
            classes.observation.causes.contains(&"surfaces"),
            "an unpinned entry keeps the surface unproven: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn fedora_shape_with_a_fileless_table_stays_lossy() {
        // An anonymous/heap table has no file owner, so export agreement
        // cannot authorize it: a missing file offset refuses the proof.
        let mut table = decode_fedora_table(&fedora_shaped_snapshot());
        table.file_offset = None;
        let classes = observation_for_table(
            table,
            fedora_exports_without_interface_getters(),
            vec!["C_GetFunctionList".into()],
            "known_prefix",
            false,
            false,
        );
        assert_eq!(classes.observation.status, "lossy");
        assert!(
            classes.observation.causes.contains(&"surfaces"),
            "a fileless table keeps the surface unproven: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn fedora_shape_with_an_ifunc_interface_getter_stays_lossy() {
        // The witness lists definitions only, so an IFUNC (or absolute)
        // getter is absent from `symbols`; the presence bit records it
        // anyway and refuses the proof: a 3.x route may exist.
        let exports = fedora_exports_without_interface_getters();
        assert!(
            !exports
                .iter()
                .any(|(name, _)| name == "C_GetInterface" || name == "C_GetInterfaceList"),
            "an IFUNC getter leaves no definition in the witness"
        );
        let classes = observation_for_table(
            decode_fedora_table(&fedora_shaped_snapshot()),
            exports,
            vec!["C_GetFunctionList".into()],
            "known_prefix",
            true,
            false,
        );
        assert_eq!(classes.observation.status, "lossy");
        assert!(
            classes.observation.causes.contains(&"surfaces"),
            "a getter in any symbol type keeps a 3.x route reachable: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn fedora_shape_with_a_faulted_exports_walk_stays_lossy() {
        // The exports walk skipped a symbol it could not read or
        // translate, so the witness may be incomplete: the sticky fault
        // refuses the proof.
        let classes = observation_for_table(
            decode_fedora_table(&fedora_shaped_snapshot()),
            fedora_exports_without_interface_getters(),
            vec!["C_GetFunctionList".into()],
            "known_prefix",
            false,
            true,
        );
        assert_eq!(classes.observation.status, "lossy");
        assert!(
            classes.observation.causes.contains(&"surfaces"),
            "a faulted walk cannot prove getter absence: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn genuine_104_slot_32_table_stays_full() {
        use crate::discovery::identity::{PinnedObjectId, ReconciledModule};
        use crate::discovery::scan::{CaptureWorkBudget, ScannedModule, decode_exact_table};
        use crate::plan::build_from_reconciled_modules;
        use crate::process::{MountNamespaceId, ProcessViewId};
        use p11scope_manifest::elf::ElfAbi;
        use p11scope_manifest::maps::MapIndex;

        let maps = fedora_fixture_maps();
        let map_index = MapIndex::new(&maps).unwrap();
        let mut snapshot = vec![0u8; 8 + 104 * 8];
        snapshot[..8].copy_from_slice(&0x0203u64.to_le_bytes());
        for slot in 0..104 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_le_bytes());
        }
        let table = decode_exact_table(
            &snapshot,
            0x7000,
            pkcs11_module::LinuxLayout::Lp64,
            &map_index,
            &mut CaptureWorkBudget::default(),
            None,
        )
        .expect("budget")
        .expect("a genuine 104-slot table must decode");
        assert_eq!(table.version, (3, 2));
        assert_eq!(table.walk, "full");
        assert_eq!(table.decoded_slot_count(), 104);
        let key = table.entries[0].object;
        let object = PinnedObjectId(0);
        let exports: std::sync::Arc<[(String, u64)]> = (0..104)
            .map(|ordinal| {
                (
                    pkcs11_module::function_name(ordinal).unwrap().to_string(),
                    0x500,
                )
            })
            .collect();
        let scanned = ScannedModule {
            module_hint: None,
            mapped_identity: None,
            view: ProcessViewId(0),
            mount_namespace: MountNamespaceId {
                device: 1,
                inode: 1,
            },
            key,
            double_loaded: false,
            same_file_loads: 1,
            pre_copy_up: None,
            path: "/lib/provider.so".into(),
            tables_scan_finished: false,
            decoder_abi: Some(ElfAbi::Lp64),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![table],
            interfaces: vec![],
        };
        let reconciled = ReconciledModule {
            scanned,
            object,
            entry_objects: vec![vec![object; 104]],
            exports,
            getter_present: false,
            witness_fault: false,
        };
        let plan = build_from_reconciled_modules(std::slice::from_ref(&reconciled));
        assert_eq!(plan.surfaces.len(), 1);
        assert_eq!(plan.surfaces[0].walk, "full");
        let mut ev = evidence();
        ev.surfaces = plan.surfaces.clone();
        let classes = ev.gap_classes(true);
        assert_eq!(classes.observation.status, "exact");
        assert!(
            !classes.observation.causes.contains(&"surfaces"),
            "a full walk is unchanged: {:?}",
            classes.observation.causes
        );
    }

    #[test]
    fn json_marks_latency_approximate_and_hex_rvs() {
        let mut ev = evidence();
        ev.verdict();
        let mut r = report("C_Sign", 1, 0, false);
        r.rv_counts.insert(0, 1);
        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: crate::attach::CapturePolicy::AggregateOnly,
            scope: "pid",
            caller: None,
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let v = json(&[r], &ev, &capture);
        assert_eq!(v["schema"], "p11scope/observed-profile/v3-metrics");
        assert_eq!(v["capture"]["privacy_mode"], "aggregate-only");
        assert_eq!(v["functions"][0]["latency_ns"]["approximate"], true);
        assert_eq!(v["functions"][0]["rv_counts"]["0x0000000000000000"], 1);
        assert_eq!(v["evidence"]["completeness"], "COMPLETE");
    }

    #[test]
    fn policy_output_unregistered_mechanisms_force_partial_and_render_live() {
        let mut ev = evidence();
        ev.unregistered_mechanisms = 2;
        ev.verdict();

        assert_eq!(ev.completeness, "PARTIAL");
        let out = live_scoped_with_verbosity(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            crate::attach::CapturePolicy::Allowlisted,
            "selected",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(out.contains("privacy=allowlisted"), "{out}");
        assert!(out.contains("2 unregistered mechanisms"), "{out}");
    }

    #[test]
    fn policy_output_mechanism_id_overflow_forces_partial_and_renders_live() {
        let mut ev = evidence();
        ev.mechanism_id_overflow = 2;
        ev.verdict();

        assert_eq!(ev.completeness, "PARTIAL");
        let out = live_scoped_with_verbosity(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            crate::attach::CapturePolicy::Allowlisted,
            "selected",
            &BTreeMap::new(),
            crate::cli::TextVerbosity::Verbose,
        );
        assert!(out.contains("privacy=allowlisted"), "{out}");
        assert!(
            out.contains("2 mechanism observations beyond the 256-id table"),
            "{out}"
        );
    }

    #[test]
    fn live_view_standard_layout_mechanisms_carry_the_ruling_notes() {
        // Ruling 2026-11-11 clauses 2-3: the MECHANISM table shows by
        // default for standard-layout slots, gated values count
        // without their number, and one plain note names the layout
        // evidence instead of suggesting --manifest.
        let mut ev = evidence();
        ev.standard_layout_slots = 68;
        ev.standard_layout_evidence = vec!["sole complete table".to_string()];
        ev.unregistered_standard_layout_mechanisms = 3;
        ev.verdict();
        let mechanisms: BTreeMap<u64, crate::semantics::MechStat> =
            [(0x40, mech_stat(2, 0))].into_iter().collect();
        let out = live_scoped_with_verbosity(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            crate::attach::CapturePolicy::Allowlisted,
            "selected",
            &mechanisms,
            crate::cli::TextVerbosity::Concise,
        );
        assert!(out.contains("CKM_SHA256_RSA_PKCS"), "{out}");
        assert!(
            out.contains("mechanism value not in the registry (names unconfirmed): 3"),
            "{out}"
        );
        assert!(
            out.contains(
                "mechanism names from the standard table (layout evidence: sole complete table)"
            ),
            "{out}"
        );
        assert!(!out.contains("none attributed"), "{out}");
    }

    #[test]
    fn policy_output_live_headers_use_every_selected_policy_label() {
        for (policy, label) in [
            (CapturePolicy::Allowlisted, "allowlisted"),
            (
                CapturePolicy::UnsafeUnvalidatedMetadata,
                "unsafe-unvalidated-metadata",
            ),
            (CapturePolicy::AggregateOnly, "aggregate-only"),
        ] {
            let out = live_scoped_with_verbosity(
                &[],
                &evidence(),
                Duration::ZERO,
                "/opt/p11.so",
                "test",
                policy,
                "selected",
                &BTreeMap::new(),
                crate::cli::TextVerbosity::Verbose,
            );
            assert!(out.contains(&format!("privacy={label}")), "{out}");
        }
    }

    fn empty_plan() -> crate::plan::AttachPlan {
        crate::plan::AttachPlan::from_slots(vec![])
    }

    #[test]
    fn profile_json_has_every_required_top_level_section() {
        let mut ev = evidence();
        ev.verdict();
        let state = crate::semantics::State::with_policy(
            &empty_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let capture = capture_fixture();
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        assert_eq!(v["schema"], "p11scope/observed-profile/v3");
        assert_eq!(v["capture"]["privacy_mode"], "allowlisted");
        for section in [
            "capture",
            "evidence",
            "functions",
            "mechanisms",
            "sessions",
            "logins",
            "templates",
            "cgroups",
        ] {
            assert!(
                v.get(section).is_some(),
                "v2 document missing required section {section}"
            );
        }
        assert_eq!(v["templates"]["operations"], serde_json::json!([]));
        assert!(
            v["templates"]["note"]
                .as_str()
                .unwrap()
                .contains("disabled by allowlisted")
        );
        assert_eq!(v["cgroups"], serde_json::json!([]));
        assert_eq!(v["capture"]["mode"], "profile");
        assert_eq!(v["capture"]["modules"][0]["path"], "/opt/p11.so");
        assert_eq!(v["capture"]["modules"][0]["build_id"], "aabb");
    }

    #[test]
    fn profile_json_capture_discloses_ring_bytes_and_drain_interval() {
        let mut ev = evidence();
        ev.verdict();
        let state = crate::semantics::State::with_policy(
            &empty_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: crate::attach::CapturePolicy::Allowlisted,
            scope: "pid",
            caller: None,
            ring_bytes: 4096,
            drain_interval_ms: 1000,
        };
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);
        assert_eq!(v["capture"]["ring_bytes"], 4096);
        assert_eq!(v["capture"]["drain_interval_ms"], 1000);
    }

    #[test]
    fn profile_and_metrics_json_disclose_the_scope_kind() {
        let mut ev = evidence();
        ev.verdict();
        let state = crate::semantics::State::with_policy(
            &empty_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        for scope in ["pid", "cgroup", "system"] {
            let capture = CaptureMeta {
                started: "t0",
                ended: "t1",
                kernel: "6.8.0",
                policy: crate::attach::CapturePolicy::Allowlisted,
                scope,
                caller: None,
                ring_bytes: 4096,
                drain_interval_ms: 1000,
            };
            let profile = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);
            assert_eq!(profile["capture"]["scope"], scope);
            let metrics = json(&[], &ev, &capture);
            assert_eq!(metrics["capture"]["scope"], scope);
        }
    }

    #[test]
    fn profile_and_metrics_pid_capture_name_the_caller() {
        // A pid-scope capture names its caller — the target exe — or a
        // named unknown reason. Scope-kind alone leaves the caller
        // missing: the target pid and exe appear nowhere.
        let mut ev = evidence();
        ev.verdict();
        let state = crate::semantics::State::with_policy(
            &empty_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let capture = capture_fixture();
        assert_eq!(capture.scope, "pid");
        for document in [
            profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture),
            json(&[], &ev, &capture),
        ] {
            let caller = &document["capture"]["caller"];
            let named = caller
                .get("exe")
                .and_then(|exe| exe.as_str())
                .is_some_and(|exe| !exe.is_empty());
            let unknown = caller
                .get("exe_unknown_reason")
                .and_then(|reason| reason.as_str())
                .is_some_and(|reason| !reason.is_empty());
            assert!(
                named || unknown,
                "pid-scope capture names no caller: {}",
                document["capture"]
            );
        }
    }

    /// Pid-scope profile text names the caller program like JSON
    /// `capture.caller` and the stderr target line do, so the demo
    /// question answers on stdout. Aggregate scopes name none.
    #[test]
    fn pid_profile_text_names_the_caller_program() {
        let mut ev = evidence();
        ev.verdict();
        let caller = CaptureCaller {
            exe: Some("/usr/bin/python3.14".into()),
            exe_unknown_reason: None,
        };
        for verbosity in [
            crate::cli::TextVerbosity::Concise,
            crate::cli::TextVerbosity::Verbose,
        ] {
            let out = live_scoped_with_caller(
                &[],
                &ev,
                Duration::ZERO,
                "/opt/p11.so",
                "profile",
                CapturePolicy::Allowlisted,
                "pid",
                &BTreeMap::new(),
                Some(&caller),
                verbosity,
                &crate::semantics::SessionStats::default(),
                &BTreeMap::new(),
            );
            assert!(
                out.contains("caller: /usr/bin/python3.14"),
                "{verbosity:?} names the caller program: {out}"
            );
            assert!(
                !out.contains("pid 4242"),
                "{verbosity:?} carries no PID number: {out}"
            );
        }
        // Unknown exe names its reason, never a PID.
        let unknown = CaptureCaller {
            exe: None,
            exe_unknown_reason: Some("exe_unreadable"),
        };
        let out = live_scoped_with_caller(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "pid",
            &BTreeMap::new(),
            Some(&unknown),
            crate::cli::TextVerbosity::Concise,
            &crate::semantics::SessionStats::default(),
            &BTreeMap::new(),
        );
        assert!(
            out.contains("caller unknown: exe_unreadable"),
            "unknown caller names its reason: {out}"
        );
        // No caller (aggregate scopes) renders no caller line.
        let out = live_scoped_with_caller(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
            "system",
            &BTreeMap::new(),
            None,
            crate::cli::TextVerbosity::Concise,
            &crate::semantics::SessionStats::default(),
            &BTreeMap::new(),
        );
        assert!(
            !out.contains("caller:"),
            "aggregate scopes name no caller: {out}"
        );
        assert!(
            !out.contains("caller unknown:"),
            "aggregate scopes name no caller: {out}"
        );
    }

    #[test]
    fn profile_and_metrics_non_pid_capture_name_no_single_caller() {
        // Aggregate scopes name no single caller by design: counts are
        // not per-application there, so no caller key is emitted even
        // when the fixture carries pid-scope caller identity.
        let mut ev = evidence();
        ev.verdict();
        let state = crate::semantics::State::with_policy(
            &empty_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        for scope in ["cgroup", "system"] {
            let capture = CaptureMeta {
                scope,
                ..capture_fixture()
            };
            for document in [
                profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture),
                json(&[], &ev, &capture),
            ] {
                assert!(
                    document["capture"].get("caller").is_none(),
                    "{scope} capture names a single caller: {}",
                    document["capture"]
                );
            }
        }
    }

    #[test]
    fn profile_and_metrics_pid_capture_name_unknown_caller_with_reason() {
        // An unreadable exe is a named unknown, never a silent null or
        // a missing key: exactly one of exe/exe_unknown_reason is set.
        let mut ev = evidence();
        ev.verdict();
        let state = crate::semantics::State::with_policy(
            &empty_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let capture = CaptureMeta {
            caller: Some(CaptureCaller {
                exe: None,
                exe_unknown_reason: Some("target exe link unreadable"),
            }),
            ..capture_fixture()
        };
        for document in [
            profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture),
            json(&[], &ev, &capture),
        ] {
            let caller = &document["capture"]["caller"];
            assert!(caller["exe"].is_null(), "{caller}");
            assert_eq!(caller["exe_unknown_reason"], "target exe link unreadable");
        }
    }

    #[test]
    fn profile_and_metrics_pid_capture_without_caller_omit_the_key() {
        // A pid scope that resolved nothing emits no caller key —
        // absent, never null — in both lanes.
        let mut ev = evidence();
        ev.verdict();
        let state = crate::semantics::State::with_policy(
            &empty_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let capture = CaptureMeta {
            caller: None,
            ..capture_fixture()
        };
        assert_eq!(capture.scope, "pid");
        for document in [
            profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture),
            json(&[], &ev, &capture),
        ] {
            assert!(
                document["capture"].get("caller").is_none(),
                "{}",
                document["capture"]
            );
        }
    }

    #[test]
    fn cap_skip_forces_partial_in_profile_and_metrics() {
        // A scan-cap skip alone flips a clean evidence to PARTIAL, and the
        // public record stays categorical: no pid, path, or count details.
        let mut ev = evidence();
        ev.skipped = vec![capture_skipped_out(&Skipped {
            subject: "system".into(),
            reason: "3 processes in scope; discovery selected 1 for deep scanning by provider rarity (limit 1); unselected processes may contain undiscovered providers".into(),
        })];
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        let expected = serde_json::json!({
            "name": "discovery subject",
            "reason": "discovery unavailable",
        });
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        assert_eq!(profile["evidence"]["completeness"], "PARTIAL");
        assert_eq!(profile["evidence"]["skipped"][0], expected);
        assert!(
            !profile["evidence"]["skipped"][0]
                .to_string()
                .contains("processes in scope")
        );
        let metrics = json(&[], &ev, &capture_fixture());
        assert_eq!(metrics["evidence"]["completeness"], "PARTIAL");
        assert_eq!(metrics["evidence"]["skipped"][0], expected);
    }

    #[test]
    fn metrics_json_capture_discloses_ring_bytes_and_drain_interval() {
        let mut ev = evidence();
        ev.verdict();
        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: crate::attach::CapturePolicy::AggregateOnly,
            scope: "pid",
            caller: None,
            ring_bytes: 262_144,
            drain_interval_ms: 200,
        };
        let v = json(&[], &ev, &capture);
        assert_eq!(v["capture"]["ring_bytes"], 262_144);
        assert_eq!(v["capture"]["drain_interval_ms"], 200);
    }

    #[test]
    fn policy_output_safe_params_are_disabled_and_maximum_id_renders() {
        let mut state = crate::semantics::State::with_policy(
            &init_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let mut event = init_event(0, u64::MAX, shape::NONE, 0, 0, 0);
        event.capture = p11scope_ebpf_common::capture::MECHANISM_VALUE;
        state.observe(&event);
        state.set_mech_shapes(std::collections::BTreeMap::from([(
            u64::MAX,
            shape::RSA_PKCS_PSS,
        )]));

        let mut ev = evidence();
        ev.verdict();
        let capture = capture_fixture();
        let value = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        assert_eq!(value["mechanisms"][0]["mechanism"], u64::MAX);
        assert_eq!(
            value["mechanisms"][0]["mechanism_hex"],
            "0xffffffffffffffff"
        );
        assert_eq!(value["mechanisms"][0]["params"], serde_json::Value::Null);
        // F-21: the null names its cause, so it never reads as "nothing
        // observed".
        assert_eq!(value["mechanisms"][0]["params_omitted"], "policy");
        assert!(
            value["mechanisms"][0]["note"]
                .as_str()
                .unwrap()
                .contains("disabled by allowlisted")
        );
        assert_eq!(value["evidence"]["shape_decode_total_failures"], 0);
        assert_eq!(value["evidence"]["completeness"], "COMPLETE");
    }

    /// Unassigned vendor-block gap (`0xCE53_43A9`), the codebase's
    /// unknown-vendor sentinel: exact registry membership never admits
    /// it, and the display-only vendor table lists no name for it, so
    /// it always publishes by number with a null name.
    const UNREGISTERED_SENTINEL: u64 = 0xCE53_43A9;

    fn profile_mechanisms(state: &crate::semantics::State) -> serde_json::Value {
        let mut ev = evidence();
        ev.verdict();
        let capture = capture_fixture();
        profile_json(&[], VersionedEvidence::wrap(&ev), state, &capture)["mechanisms"].clone()
    }

    #[test]
    fn profile_json_lists_unregistered_mechanism_id_with_registered_false() {
        let mut state = crate::semantics::State::with_policy(
            &init_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let mut first = init_event(0, UNREGISTERED_SENTINEL, shape::NONE, 0, 0, 0);
        first.capture |= p11scope_ebpf_common::capture::MECHANISM_UNREGISTERED;
        let mut second = first;
        second.duration_ns = 200;
        state.observe(&first);
        state.observe(&second);

        let mechanisms = profile_mechanisms(&state);
        assert_eq!(mechanisms.as_array().unwrap().len(), 1);
        let row = &mechanisms[0];
        assert_eq!(row["mechanism"], UNREGISTERED_SENTINEL);
        assert_eq!(row["mechanism_hex"], "0xce5343a9");
        assert_eq!(row["calls"], 2);
        assert_eq!(row["errors"], 0);
        assert_eq!(row["registered"], false);
    }

    #[test]
    fn profile_json_lists_registered_mechanism_id_with_registered_true() {
        let mut state = crate::semantics::State::with_policy(
            &init_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        state.observe(&init_event(0, 0x0D, shape::NONE, 0, 0, 0));

        let mechanisms = profile_mechanisms(&state);
        assert_eq!(mechanisms.as_array().unwrap().len(), 1);
        let row = &mechanisms[0];
        assert_eq!(row["mechanism"], 0x0D);
        assert_eq!(row["calls"], 1);
        assert_eq!(row["registered"], true);
    }

    #[test]
    fn profile_json_carries_numeric_id_and_name_for_every_row() {
        let mut state = crate::semantics::State::with_policy(
            &init_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        state.observe(&init_event(0, 0x1087, shape::NONE, 0, 0, 0));
        let mut vendor = init_event(0, 0xCE53_4351, shape::NONE, 0, 0, 0);
        vendor.capture |= p11scope_ebpf_common::capture::MECHANISM_UNREGISTERED;
        state.observe(&vendor);
        let mut unknown = init_event(0, 0xFFFF, shape::NONE, 0, 0, 0);
        unknown.capture |= p11scope_ebpf_common::capture::MECHANISM_UNREGISTERED;
        state.observe(&unknown);

        let mechanisms = profile_mechanisms(&state);
        let rows = mechanisms.as_array().unwrap();
        assert_eq!(rows.len(), 3);
        let by_id = |id: u64| rows.iter().find(|row| row["mechanism"] == id).unwrap();
        assert_eq!(by_id(0x1087)["mechanism"], 0x1087);
        assert_eq!(by_id(0x1087)["name"], "CKM_AES_GCM");
        // `.get`: a missing key must fail, never read as null by indexing.
        assert_eq!(by_id(0xCE53_4351)["name"], "CKM_NSS_AES_KEY_WRAP");
        assert_eq!(by_id(0xFFFF).get("name"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn profile_json_counts_and_ids_survive_name_table_removal() {
        // The vendor table is a display-only layer: the same capture
        // rendered with and without it must carry identical counts and
        // ids, differing only in the displayed name. Counts and ids
        // come from the semantic state, which never consults the table;
        // the table-free lookup resolves no name for the listed vendor
        // ids, so without the table these rows would render `name: null`
        // with the same counts and ids.
        let mut state = crate::semantics::State::with_policy(
            &init_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let flagged = |slot: u32, id: u64| {
            let mut ev = init_event(slot, id, shape::NONE, 0, 0, 0);
            ev.capture |= p11scope_ebpf_common::capture::MECHANISM_UNREGISTERED;
            ev
        };
        state.observe(&init_event(0, 0x1087, shape::NONE, 0, 0, 0));
        state.observe(&init_event(0, 0x1087, shape::NONE, 0, 0, 0));
        state.observe(&flagged(0, 0xCE53_4351));
        state.observe(&flagged(0, 0x8000_0001));
        state.observe(&flagged(0, UNREGISTERED_SENTINEL));

        let mechanisms = profile_mechanisms(&state);
        let rows = mechanisms.as_array().unwrap();
        assert_eq!(rows.len(), 4);
        let by_id = |id: u64| rows.iter().find(|row| row["mechanism"] == id).unwrap();
        // Every row's counts and ids equal the semantic state, with or
        // without names.
        for (id, calls) in [(0x1087u64, 2u64), (0xCE53_4351, 1), (0x8000_0001, 1)] {
            let row = by_id(id);
            let stat = &state.mechanisms()[&id];
            assert_eq!(row["mechanism"], id);
            assert_eq!(row["mechanism_hex"], format!("0x{id:x}"));
            assert_eq!(row["calls"], calls);
            assert_eq!(row["calls"], stat.calls);
            assert_eq!(row["errors"], stat.errors);
        }
        let sentinel_row = by_id(UNREGISTERED_SENTINEL);
        assert_eq!(sentinel_row["calls"], 1);
        // The table-free lookup names none of the vendor ids.
        for id in [0xCE53_4351, 0x8000_0001, UNREGISTERED_SENTINEL] {
            assert_eq!(
                crate::mechanism_names::official_mechanism_name(id),
                None,
                "id 0x{id:x}"
            );
        }
        // With the table, the listed ids carry names and the unlisted
        // gap stays null — counts and ids above are unchanged.
        assert_eq!(by_id(0x1087)["name"], "CKM_AES_GCM");
        assert_eq!(by_id(0xCE53_4351)["name"], "CKM_NSS_AES_KEY_WRAP");
        assert_eq!(
            by_id(0x8000_0001)["name"],
            "CKM_CLOUDHSM_SP800_108_COUNTER_KDF"
        );
        assert_eq!(
            by_id(UNREGISTERED_SENTINEL).get("name"),
            Some(&serde_json::Value::Null)
        );
    }

    /// Two slots on module 0: `C_SignInit` (index 0) binds a mechanism
    /// id, `C_Sign` (index 1) attributes to that binding.
    fn init_sign_plan() -> crate::plan::AttachPlan {
        crate::plan::AttachPlan::from_slots(vec![
            crate::plan::Slot {
                index: 0,
                descriptor_index: crate::kinds::function_id("C_SignInit").unwrap() + 1,
                object: crate::plan::TEST_PINNED_OBJECT,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
                names: vec!["C_SignInit".into()],
                aliased: false,
                semantics: crate::kinds::descriptor("C_SignInit").unwrap(),
                semantic_authorized: true,
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![crate::plan::ModuleId(0)],
            },
            crate::plan::Slot {
                index: 1,
                descriptor_index: crate::kinds::function_id("C_Sign").unwrap() + 1,
                object: crate::plan::TEST_PINNED_OBJECT,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x20,
                names: vec!["C_Sign".into()],
                aliased: false,
                semantics: crate::kinds::descriptor("C_Sign").unwrap(),
                semantic_authorized: true,
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![crate::plan::ModuleId(0)],
            },
        ])
    }

    /// An operational `C_Sign` call on slot 1 of [`init_sign_plan`]: no
    /// mechanism of its own, attributed through the session binding.
    fn sign_op_event() -> p11scope_ebpf_common::Event {
        let mut op = init_event(1, p11scope_ebpf_common::MECH_NONE, shape::NONE, 0, 0, 0);
        op.capture = p11scope_ebpf_common::capture::MECHANISM_NONE;
        op
    }

    /// Two providers sharing one process: slots 0/2 (`C_SignInit`/`C_Sign`)
    /// on module 0, slots 1/3 on module 1, each pair on its own pinned
    /// object — the seam per-provider mechanism attribution renders.
    fn two_module_sign_plan() -> crate::plan::AttachPlan {
        let slot = |index: u32, name: &str, module: u32, object: u32, file_offset: u64| {
            crate::plan::Slot {
                index,
                descriptor_index: crate::kinds::function_id(name).unwrap() + 1,
                object: crate::discovery::identity::PinnedObjectId(object),
                object_path: format!("/opt/p{module}.so"),
                file_offset,
                names: vec![name.into()],
                aliased: false,
                semantics: crate::kinds::descriptor(name).unwrap(),
                semantic_authorized: true,
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![crate::plan::ModuleId(module)],
            }
        };
        crate::plan::AttachPlan::from_slots(vec![
            slot(0, "C_SignInit", 0, 42, 0x10),
            slot(1, "C_SignInit", 1, 43, 0x10),
            slot(2, "C_Sign", 0, 42, 0x20),
            slot(3, "C_Sign", 1, 43, 0x20),
        ])
    }

    /// An operational `C_Sign` call on an explicit slot of
    /// [`two_module_sign_plan`] with an explicit return code.
    fn sign_op_event_at(slot: u32, rv: u64) -> p11scope_ebpf_common::Event {
        let mut op = init_event(
            slot,
            p11scope_ebpf_common::MECH_NONE,
            p11scope_ebpf_common::shape::NONE,
            0,
            0,
            0,
        );
        op.capture = p11scope_ebpf_common::capture::MECHANISM_NONE;
        op.rv = rv;
        op
    }

    /// Every mechanism row splits its calls/errors by provider module:
    /// one `by_module` entry per sole-owner module, each with the same
    /// `{dev, ino, sha256}` reference `functions[].module` uses. The
    /// entries partition the row: their sums equal the row totals.
    #[test]
    fn profile_json_mechanism_rows_split_calls_and_errors_by_module() {
        let mut state = crate::semantics::State::with_policy(
            &two_module_sign_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let shape_none = p11scope_ebpf_common::shape::NONE;
        // Same session handle on both providers: sessions are
        // module-scoped, so each Init binds its own provider. Every
        // single-part `C_Sign` consumes its binding, so each op gets a
        // fresh Init first.
        state.observe(&init_event(0, 0x1087, shape_none, 0, 0, 0));
        state.observe(&sign_op_event_at(2, 0));
        state.observe(&init_event(0, 0x1087, shape_none, 0, 0, 0));
        state.observe(&sign_op_event_at(2, 0x5));
        state.observe(&init_event(1, 0x1087, shape_none, 0, 0, 0));
        state.observe(&sign_op_event_at(3, 0));
        state.observe(&init_event(1, 0x1087, shape_none, 0, 0, 0));
        state.observe(&sign_op_event_at(3, 0));
        state.observe(&init_event(1, 0x1087, shape_none, 0, 0, 0));
        state.observe(&sign_op_event_at(3, 0));

        let mut mod1 = discovered_fixture();
        mod1.id = crate::plan::ModuleId(1);
        mod1.dev = (8, 2);
        mod1.ino = 22;
        mod1.sha256 = Some("22".repeat(32));
        mod1.path = "/opt/p1.so".into();
        let mut ev = evidence();
        ev.discovery.modules = vec![discovered_fixture(), mod1];
        ev.verdict();
        let capture = capture_fixture();
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        assert_eq!(v["mechanisms"].as_array().unwrap().len(), 1);
        let row = &v["mechanisms"][0];
        assert_eq!(row["mechanism"], 0x1087);
        assert_eq!(row["calls"], 10);
        assert_eq!(row["errors"], 1);
        assert_eq!(
            row["by_module"],
            serde_json::json!([
                {
                    "module": {"dev": [8, 1], "ino": 11, "sha256": "11".repeat(32)},
                    "calls": 4,
                    "errors": 1,
                },
                {
                    "module": {"dev": [8, 2], "ino": 22, "sha256": "22".repeat(32)},
                    "calls": 6,
                    "errors": 0,
                },
            ]),
            "per-provider partition of the row: {row}"
        );
    }

    /// A `by_module` entry whose module the document's discovery list
    /// does not name is skipped, never fabricated: the row totals stay
    /// authoritative and the breakdown degrades to the attributed subset.
    #[test]
    fn profile_json_by_module_skips_modules_missing_from_discovery() {
        let mut state = crate::semantics::State::with_policy(
            &two_module_sign_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let shape_none = p11scope_ebpf_common::shape::NONE;
        state.observe(&init_event(0, 0x1087, shape_none, 0, 0, 0));
        state.observe(&init_event(1, 0x1087, shape_none, 0, 0, 0));

        let mut ev = evidence();
        ev.discovery.modules = vec![discovered_fixture()];
        ev.verdict();
        let capture = capture_fixture();
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        let row = &v["mechanisms"][0];
        assert_eq!(row["calls"], 2);
        assert_eq!(
            row["by_module"].as_array().map(|rows| rows.len()),
            Some(1),
            "only the discovered module renders: {row}"
        );
        assert_eq!(row["by_module"][0]["module"]["ino"], 11);
        assert_eq!(row["by_module"][0]["calls"], 1);
    }

    #[test]
    fn profile_json_operation_attributed_call_keeps_unregistered_flag() {
        // The Init binds the unregistered id, the operational call
        // attributes to that binding. Both land on one row that stays
        // unregistered.
        let mut state = crate::semantics::State::with_policy(
            &init_sign_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let mut init = init_event(0, UNREGISTERED_SENTINEL, shape::NONE, 0, 0, 0);
        init.capture |= p11scope_ebpf_common::capture::MECHANISM_UNREGISTERED;
        state.observe(&init);
        state.observe(&sign_op_event());

        let mechanisms = profile_mechanisms(&state);
        assert_eq!(mechanisms.as_array().unwrap().len(), 1);
        assert_eq!(mechanisms[0]["mechanism"], UNREGISTERED_SENTINEL);
        assert_eq!(mechanisms[0]["calls"], 2);
        assert_eq!(mechanisms[0]["registered"], false);
    }

    #[test]
    fn profile_json_binding_recreated_row_stays_unregistered_after_purge() {
        // `purge_modules` clears mechanism rows capture-wide but keeps
        // another module's bindings: the next attributed call recreates
        // the row from the binding, which must carry the flag along.
        let mut state = crate::semantics::State::with_policy(
            &init_sign_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let mut init = init_event(0, UNREGISTERED_SENTINEL, shape::NONE, 0, 0, 0);
        init.capture |= p11scope_ebpf_common::capture::MECHANISM_UNREGISTERED;
        state.observe(&init);
        let mut modules = std::collections::BTreeSet::new();
        modules.insert(crate::plan::ModuleId(99));
        state.purge_modules(&modules);
        assert!(state.mechanisms().is_empty());
        state.observe(&sign_op_event());

        let mechanisms = profile_mechanisms(&state);
        assert_eq!(mechanisms.as_array().unwrap().len(), 1);
        assert_eq!(mechanisms[0]["mechanism"], UNREGISTERED_SENTINEL);
        assert_eq!(mechanisms[0]["calls"], 1);
        assert_eq!(mechanisms[0]["registered"], false);
    }

    #[test]
    fn profile_json_mechanisms_carry_verbatim_id_hex_ops_and_null_params() {
        use p11scope_ebpf_common::{Event, USER_TYPE_NONE};

        let plan = crate::plan::AttachPlan::from_slots(vec![crate::plan::Slot {
            index: 0,
            descriptor_index: crate::kinds::function_id("C_SignInit").unwrap() + 1,
            object: crate::plan::TEST_PINNED_OBJECT,
            object_path: "/opt/p11.so".into(),
            file_offset: 0x10,
            names: vec!["C_SignInit".into()],
            aliased: false,
            semantics: crate::kinds::descriptor("C_SignInit").unwrap(),
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![crate::plan::ModuleId(0)],
        }]);
        let mut state = crate::semantics::State::new(&plan);
        let vendor_id: u64 = 0x8000_1042;
        state.observe(&Event {
            ts_ns: 0,
            duration_ns: 1_000,
            pid_tgid: (100u64 << 32) | 1,
            cgroup_id: 0,
            session: 7,
            mechanism: vendor_id,
            capture: p11scope_ebpf_common::capture::MECHANISM_VALUE,
            rv: 0,
            p0: 0,
            p1: 0,
            p2: 0,
            slot: 0,
            user_type: USER_TYPE_NONE,
            shape: 0,
            attr_types: [0; 8],
            attr_count: 0,
            attr_total: 0,
            attr_bools: 0,
            attr_bools_seen: 0,
            ..Event::default()
        });

        let mut ev = evidence();
        ev.verdict();
        let capture = capture_fixture();
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        let mech = &v["mechanisms"][0];
        assert_eq!(mech["mechanism"], vendor_id);
        assert_eq!(mech["mechanism_hex"], "0x80001042");
        assert_eq!(mech["ops"], serde_json::json!(["sign"]));
        assert_eq!(mech["params"], serde_json::Value::Null);
        assert_eq!(mech["calls"], 1);
        // The identity of what was observed now lives in `capture.modules[]`,
        // one entry per discovered module.
        assert_eq!(v["capture"]["modules"][0]["build_id"], "aabb");
        assert_eq!(v["capture"]["modules"][0]["ino"], 11);
    }

    fn init_event(
        slot: u32,
        mechanism: u64,
        shape_code: u32,
        p0: u64,
        p1: u64,
        p2: u64,
    ) -> p11scope_ebpf_common::Event {
        use p11scope_ebpf_common::{Event, USER_TYPE_NONE};
        Event {
            ts_ns: 0,
            duration_ns: 100,
            pid_tgid: (100u64 << 32) | 1,
            cgroup_id: 0,
            session: 7,
            mechanism,
            capture: p11scope_ebpf_common::capture::MECHANISM_VALUE,
            rv: 0,
            p0,
            p1,
            p2,
            slot,
            user_type: USER_TYPE_NONE,
            shape: shape_code,
            attr_types: [0; 8],
            attr_count: 0,
            attr_total: 0,
            attr_bools: 0,
            attr_bools_seen: 0,
            ..Event::default()
        }
    }

    fn init_plan() -> crate::plan::AttachPlan {
        crate::plan::AttachPlan::from_slots(vec![crate::plan::Slot {
            index: 0,
            descriptor_index: crate::kinds::function_id("C_SignInit").unwrap() + 1,
            object: crate::plan::TEST_PINNED_OBJECT,
            object_path: "/opt/p11.so".into(),
            file_offset: 0x10,
            names: vec!["C_SignInit".into()],
            aliased: false,
            semantics: crate::kinds::descriptor("C_SignInit").unwrap(),
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![crate::plan::ModuleId(0)],
        }])
    }

    #[test]
    fn profile_json_renders_pss_params_as_a_shape_tagged_object_with_count() {
        use p11scope_ebpf_common::shape;

        let mut state = crate::semantics::State::with_policy(
            &init_plan(),
            CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        // Same mechanism, same combo, twice — must collapse into one
        // entry with count 2, not two entries.
        state.observe(&init_event(0, 0x0D, shape::RSA_PKCS_PSS, 0x270, 1, 32));
        state.observe(&init_event(0, 0x0D, shape::RSA_PKCS_PSS, 0x270, 1, 32));

        let mut ev = evidence();
        ev.verdict();
        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
            scope: "pid",
            caller: None,
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        assert_eq!(v["capture"]["privacy_mode"], "unsafe-unvalidated-metadata");
        let params = &v["mechanisms"][0]["params"];
        assert_eq!(params.as_array().unwrap().len(), 1, "one distinct combo");
        let combo = &params[0];
        assert_eq!(combo["shape"], "rsa_pkcs_pss");
        assert_eq!(combo["hash_alg"], 0x270);
        assert_eq!(combo["hash_alg_hex"], "0x270");
        assert_eq!(combo["mgf"], 1);
        assert_eq!(combo["salt_len"], 32);
        assert_eq!(combo["count"], 2);
        assert!(
            v["mechanisms"][0].get("params_omitted").is_none(),
            "decoded params carry no omission marker: {}",
            v["mechanisms"][0]
        );
    }

    #[test]
    fn profile_json_renders_gcm_params_as_a_shape_tagged_object_with_its_layout() {
        use p11scope_ebpf_common::shape;

        // Both `CK_GCM_PARAMS` layouts can appear in the same capture (a
        // provider using the legacy v2.20 struct, another using the
        // current v2.40 one) — they must render as two distinct combos,
        // each tagged with the layout that produced it, never merged and
        // never mislabeled as the other's fields.
        let mut state = crate::semantics::State::with_policy(
            &init_plan(),
            CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        state.observe(&init_event(0, 0x1087, shape::GCM_V220, 12, 0, 128));
        state.observe(&init_event(0, 0x1087, shape::GCM_V240, 12, 16, 128));

        let mut ev = evidence();
        ev.verdict();
        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
            scope: "pid",
            caller: None,
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        let combos = v["mechanisms"][0]["params"].as_array().unwrap();
        assert_eq!(combos.len(), 2, "two distinct layouts, not merged");

        let v220 = combos
            .iter()
            .find(|c| c["layout"] == "v2.20")
            .expect("v2.20 combo present");
        assert_eq!(v220["shape"], "gcm");
        assert_eq!(v220["iv_len"], 12);
        assert_eq!(v220["aad_len"], 0);
        assert_eq!(v220["tag_bits"], 128);
        assert_eq!(v220["count"], 1);

        let v240 = combos
            .iter()
            .find(|c| c["layout"] == "v2.40")
            .expect("v2.40 combo present");
        assert_eq!(v240["shape"], "gcm");
        assert_eq!(v240["iv_len"], 12);
        assert_eq!(v240["aad_len"], 16);
        assert_eq!(v240["tag_bits"], 128);
        assert_eq!(v240["count"], 1);
    }

    #[test]
    fn profile_json_multiple_distinct_combos_get_separate_entries() {
        use p11scope_ebpf_common::shape;

        let mut state = crate::semantics::State::with_policy(
            &init_plan(),
            CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        state.observe(&init_event(0, 0x0D, shape::RSA_PKCS_PSS, 0x270, 1, 32));
        state.observe(&init_event(0, 0x0D, shape::RSA_PKCS_PSS, 0x270, 1, 64));

        let mut ev = evidence();
        ev.verdict();
        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
            scope: "pid",
            caller: None,
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        assert_eq!(
            v["mechanisms"][0]["params"].as_array().unwrap().len(),
            2,
            "distinct salt lengths must not collapse into one combo"
        );
    }

    #[test]
    fn profile_json_unknown_shape_still_yields_null_params() {
        // shape::NONE — no decode ever applied for this mechanism.
        let mut state = crate::semantics::State::with_policy(
            &init_plan(),
            CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        state.observe(&init_event(0, 0x0999, 0, 0, 0, 0));

        let mut ev = evidence();
        ev.verdict();
        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
            scope: "pid",
            caller: None,
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        assert_eq!(v["mechanisms"][0]["params"], serde_json::Value::Null);
        assert_eq!(v["mechanisms"][0]["params_omitted"], "no_shape");
    }

    #[test]
    fn total_decode_failure_forces_partial_with_an_honest_note() {
        use p11scope_ebpf_common::shape;

        // Mechanism has a published GCM shape, but every observed *Init
        // fails to decode (shape::NONE on both calls).
        let mut state = crate::semantics::State::with_policy(
            &init_plan(),
            CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        state.observe(&init_event(0, 0x1087, shape::NONE, 0, 0, 0));
        state.observe(&init_event(0, 0x1087, shape::NONE, 0, 0, 0));
        state.set_mech_shapes(std::collections::BTreeMap::from([(0x1087, shape::GCM)]));

        let mut ev = evidence();
        ev.shape_decode_failures = state.shape_decode_failures();
        ev.shape_decode_total_failures = state.total_shape_decode_failures();
        ev.verdict();
        assert_eq!(ev.shape_decode_total_failures, 1);
        assert_eq!(
            ev.completeness, "PARTIAL",
            "a total decode failure must force PARTIAL"
        );

        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
            scope: "pid",
            caller: None,
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);
        assert_eq!(v["mechanisms"][0]["params"], serde_json::Value::Null);
        assert_eq!(v["mechanisms"][0]["params_omitted"], "decode_failed");
        let note = v["mechanisms"][0]["note"].as_str().unwrap();
        assert!(
            !note.contains("not attempted here"),
            "a total decode failure must never read as decoding not having been attempted: {note}"
        );
        assert!(note.contains("every decode attempt failed"), "note: {note}");
        assert_eq!(v["evidence"]["shape_decode_total_failures"], 1);
        assert_eq!(v["evidence"]["completeness"], "PARTIAL");
    }

    #[test]
    fn mechanism_with_no_published_shape_keeps_the_not_attempted_note_and_stays_complete() {
        use p11scope_ebpf_common::shape;

        let mut state = crate::semantics::State::with_policy(
            &init_plan(),
            CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        state.observe(&init_event(0, 0x0999, shape::NONE, 0, 0, 0));
        // A different mechanism id is published — 0x0999 itself is not.
        state.set_mech_shapes(std::collections::BTreeMap::from([(0x1087, shape::GCM)]));

        let mut ev = evidence();
        ev.shape_decode_failures = state.shape_decode_failures();
        ev.shape_decode_total_failures = state.total_shape_decode_failures();
        ev.verdict();
        assert_eq!(ev.shape_decode_failures, 0);
        assert_eq!(ev.shape_decode_total_failures, 0);
        assert_eq!(
            ev.completeness, "COMPLETE",
            "an ordinary id-only mechanism is not a gap"
        );

        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
            scope: "pid",
            caller: None,
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);
        assert_eq!(v["mechanisms"][0]["params"], serde_json::Value::Null);
        assert_eq!(
            v["mechanisms"][0]["note"],
            "this mechanism has no published diagnostic parameter shape; unvalidated \
             pointer-derived decoding was not attempted, never a partial decode"
        );
        assert_eq!(v["evidence"]["completeness"], "COMPLETE");
    }

    fn template_plan() -> crate::plan::AttachPlan {
        crate::plan::AttachPlan::from_slots(vec![crate::plan::Slot {
            index: 0,
            descriptor_index: crate::kinds::function_id("C_FindObjectsInit").unwrap() + 1,
            object: crate::plan::TEST_PINNED_OBJECT,
            object_path: "/opt/p11.so".into(),
            file_offset: 0x20,
            names: vec!["C_FindObjectsInit".into()],
            aliased: false,
            semantics: crate::kinds::descriptor("C_FindObjectsInit").unwrap(),
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![crate::plan::ModuleId(0)],
        }])
    }

    fn template_event(
        attr_types: &[u64],
        attr_total: u32,
        attr_bools: u32,
        attr_bools_seen: u32,
    ) -> p11scope_ebpf_common::Event {
        use p11scope_ebpf_common::{Event, USER_TYPE_NONE};
        let mut types = [0u64; 8];
        for (i, &t) in attr_types.iter().enumerate() {
            types[i] = t;
        }
        Event {
            ts_ns: 0,
            duration_ns: 10,
            pid_tgid: (100u64 << 32) | 1,
            cgroup_id: 0,
            session: 7,
            mechanism: p11scope_ebpf_common::MECH_NONE,
            rv: 0,
            p0: 0,
            p1: 0,
            p2: 0,
            slot: 0,
            user_type: USER_TYPE_NONE,
            shape: 0,
            attr_types: types,
            attr_count: attr_types.len() as u32,
            attr_total,
            attr_bools,
            attr_bools_seen,
            ..Event::default()
        }
    }

    #[test]
    fn profile_json_templates_render_requested_types_and_tristate_booleans() {
        use p11scope_ebpf_common::attr_bool;

        let mut state = crate::semantics::State::with_policy(
            &template_plan(),
            CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        // CKA_TOKEN (0x01) true, CKA_PRIVATE (0x02) present-but-false,
        // CKA_SIGN (0x108) never appears.
        state.observe(&template_event(
            &[0x01, 0x02],
            2,
            attr_bool::TOKEN,
            attr_bool::TOKEN | attr_bool::PRIVATE,
        ));

        let mut ev = evidence();
        ev.verdict();
        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
            scope: "pid",
            caller: None,
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        let op = &v["templates"]["operations"][0];
        assert_eq!(op["names"], serde_json::json!(["C_FindObjectsInit"]));
        assert_eq!(
            op["requested"], true,
            "must be an explicit, unambiguous marker"
        );
        assert_eq!(op["truncated"], false);
        let types: Vec<u64> = op["attr_types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["attr_type"].as_u64().unwrap())
            .collect();
        assert_eq!(types, vec![0x01, 0x02]);
        assert_eq!(op["attr_types"][0]["attr_type_hex"], "0x1");

        let true_names: Vec<&str> = op["policy_booleans"]["observed_true"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let false_names: Vec<&str> = op["policy_booleans"]["observed_false"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(true_names, vec!["CKA_TOKEN"]);
        assert_eq!(false_names, vec!["CKA_PRIVATE"]);
        assert!(
            !true_names.contains(&"CKA_SIGN"),
            "never present — not true"
        );
        assert!(
            !false_names.contains(&"CKA_SIGN"),
            "never present — not false either"
        );
    }

    #[test]
    fn profile_json_template_truncation_forces_partial_and_evidence_field() {
        let mut state = crate::semantics::State::with_policy(
            &template_plan(),
            CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        state.observe(&template_event(&[0x01; 8], 10, 0, 0)); // attr_total(10) > attr_count(8)

        let mut ev = evidence();
        ev.templates_truncated = state.templates_truncated();
        ev.verdict();
        assert!(
            ev.templates_truncated,
            "the aggregate accessor must see the truncation"
        );
        assert_eq!(ev.completeness, "PARTIAL");

        let capture = CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
            scope: "pid",
            caller: None,
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);
        assert_eq!(v["templates"]["operations"][0]["truncated"], true);
        assert_eq!(v["evidence"]["templates_truncated"], true);
        assert_eq!(v["evidence"]["completeness"], "PARTIAL");
    }

    #[test]
    fn profile_json_cgroups_split_one_attach_into_two_container_entries() {
        // Two containers/pods sharing one node-wide attach (Phase 4's
        // Knative row: one overlay2 inode observed by a single attach) —
        // the whole point of the breakdown is that this splits back out.
        let mut state = crate::semantics::State::new(&init_plan());
        let mut ev_a = init_event(0, 0x0D, 0, 0, 0, 0);
        ev_a.cgroup_id = 111;
        state.observe(&ev_a);
        let mut ev_b = init_event(0, 0x0D, 0, 0, 0, 0);
        ev_b.cgroup_id = 222;
        ev_b.rv = 7;
        state.observe(&ev_b);

        let mut ev = evidence();
        ev.verdict();
        let capture = capture_fixture();
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        let cgroups = v["cgroups"].as_array().unwrap();
        assert_eq!(cgroups.len(), 2, "two distinct cgroup ids, two entries");
        let cg111 = cgroups
            .iter()
            .find(|c| c["cgroup_id"] == 111)
            .expect("cgroup 111 present");
        assert_eq!(cg111["calls"], 1);
        assert_eq!(cg111["errors"], 0);
        assert_eq!(cg111["mechanisms"][0]["mechanism"], 0x0D);
        assert_eq!(cg111["mechanisms"][0]["mechanism_hex"], "0xd");
        assert_eq!(cg111["mechanisms"][0]["calls"], 1);
        assert_eq!(cg111["mechanisms"][0]["errors"], 0);
        // No real /sys/fs/cgroup directory has this synthetic inode —
        // label resolution must degrade to null, never a guess.
        assert_eq!(cg111["label"], serde_json::Value::Null);

        let cg222 = cgroups
            .iter()
            .find(|c| c["cgroup_id"] == 222)
            .expect("cgroup 222 present");
        assert_eq!(cg222["calls"], 1);
        assert_eq!(
            cg222["errors"], 1,
            "the failed call counts as an error at the cgroup level too"
        );
        assert_eq!(
            cg222["mechanisms"],
            serde_json::json!([]),
            "allowlisted capture must not attribute a rejected init as a mechanism request"
        );
    }

    #[test]
    fn profile_json_cgroup_mechanism_rows_carry_name() {
        let mut state = crate::semantics::State::new(&init_plan());
        let mut known = init_event(0, 0x0D, 0, 0, 0, 0);
        known.cgroup_id = 111;
        state.observe(&known);
        let mut vendor = init_event(0, 0xCE53_4351, 0, 0, 0, 0);
        vendor.cgroup_id = 111;
        vendor.capture |= p11scope_ebpf_common::capture::MECHANISM_UNREGISTERED;
        state.observe(&vendor);

        let mut ev = evidence();
        ev.verdict();
        let capture = capture_fixture();
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);
        let cg111 = v["cgroups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["cgroup_id"] == 111)
            .expect("cgroup 111 present");
        let rows = cg111["mechanisms"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let by_id = |id: u64| rows.iter().find(|row| row["mechanism"] == id).unwrap();
        assert_eq!(by_id(0x0D)["name"], "CKM_RSA_PKCS_PSS");
        assert_eq!(by_id(0xCE53_4351)["name"], "CKM_NSS_AES_KEY_WRAP");
    }

    #[test]
    fn profile_json_cgroup_mechanism_rows_carry_registered_flag() {
        // The cgroup breakdown names the same registry membership as
        // the top-level rows: system scope is the main surface, and an
        // unregistered id there used to render with no flag at all. A
        // later observation without the bit must not clear it —
        // membership is fixed per capture, so the flag is sticky.
        let mut state = crate::semantics::State::new(&init_plan());
        let mut flagged = init_event(0, UNREGISTERED_SENTINEL, 0, 0, 0, 0);
        flagged.cgroup_id = 111;
        flagged.capture |= p11scope_ebpf_common::capture::MECHANISM_UNREGISTERED;
        state.observe(&flagged);
        let mut plain = init_event(0, UNREGISTERED_SENTINEL, 0, 0, 0, 0);
        plain.cgroup_id = 111;
        state.observe(&plain);
        let mut registered = init_event(0, 0x0D, 0, 0, 0, 0);
        registered.cgroup_id = 111;
        state.observe(&registered);

        let mut ev = evidence();
        ev.verdict();
        let capture = capture_fixture();
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);

        let cgroups = v["cgroups"].as_array().unwrap();
        assert_eq!(cgroups.len(), 1);
        let rows = cgroups[0]["mechanisms"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let unreg = rows
            .iter()
            .find(|row| row["mechanism"] == UNREGISTERED_SENTINEL)
            .expect("unregistered cgroup row present");
        assert_eq!(unreg["mechanism_hex"], "0xce5343a9");
        assert_eq!(unreg["calls"], 2);
        assert_eq!(unreg["registered"], false);
        let reg = rows
            .iter()
            .find(|row| row["mechanism"] == 0x0D)
            .expect("registered cgroup row present");
        assert_eq!(reg["calls"], 1);
        assert_eq!(reg["registered"], true);
    }

    #[test]
    fn profile_json_cgroup_mechanism_rows_carry_attribution_basis() {
        // Per-cgroup rows disclose the same attribution basis as the
        // root rows, from that cgroup's own observations: a consumer
        // splitting by cgroup must not have to borrow the merged
        // root authority. This plan's slot is confirmed, so both
        // levels read "manifest".
        let mut state = crate::semantics::State::new(&init_plan());
        let mut event = init_event(0, 0x0D, 0, 0, 0, 0);
        event.cgroup_id = 111;
        state.observe(&event);

        let mut ev = evidence();
        ev.verdict();
        let capture = capture_fixture();
        let v = profile_json(&[], VersionedEvidence::wrap(&ev), &state, &capture);
        assert_eq!(v["mechanisms"][0]["attribution_basis"], "manifest");
        let rows = v["cgroups"][0]["mechanisms"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["attribution_basis"], "manifest");
    }

    #[test]
    fn profile_json_cgroup_rows_carry_workload_labels() {
        use std::os::unix::fs::MetadataExt as _;
        // Churn twin at the JSON seam: the pod's cgroup existed at
        // first sighting and was removed before the report; the row
        // still names the pod UID and container ID.
        let uid = "12345678-1234-abcd-9876-1234567890ab";
        let systemd_uid = uid.replace('-', "_");
        let id = "c".repeat(64);
        let root = tempfile::tempdir().unwrap();
        let dir = root
            .path()
            .join("kubepods.slice")
            .join("kubepods-burstable.slice")
            .join(format!("kubepods-burstable-pod{systemd_uid}.slice"))
            .join(format!("cri-containerd-{id}.scope"));
        std::fs::create_dir_all(&dir).unwrap();
        let cgroup = std::fs::metadata(&dir).unwrap().ino();
        let mut state =
            crate::semantics::State::with_policy(&init_plan(), CapturePolicy::Allowlisted);
        state.set_cgroup_label_root(root.path().to_path_buf());
        let mut ev = init_event(0, 0x0D, p11scope_ebpf_common::shape::NONE, 0, 0, 0);
        ev.cgroup_id = cgroup;
        state.observe(&ev);
        std::fs::remove_dir_all(root.path().join("kubepods.slice")).unwrap();
        let rows = cgroups_out_with_live_root(&state, root.path());
        assert_eq!(rows.len(), 1);
        let row = serde_json::to_value(&rows[0]).unwrap();
        assert_eq!(row["cgroup_id"], cgroup);
        assert_eq!(row["workload"], format!("pod {uid} / container {id}"));
    }

    #[test]
    fn profile_json_cgroup_rows_carry_unadmitted_counts() {
        let mut state =
            crate::semantics::State::with_policy(&init_plan(), CapturePolicy::Allowlisted);
        let mut missed = init_event(0, 0x0D, p11scope_ebpf_common::shape::NONE, 0, 0, 0);
        missed.event_type = p11scope_ebpf_common::event_type::CALL;
        missed.cgroup_id = 9911;
        state.reject_unadmitted(&missed);
        let mut found = init_event(0, 0x0D, p11scope_ebpf_common::shape::NONE, 0, 0, 0);
        found.cgroup_id = 9912;
        state.observe(&found);
        let root = tempfile::tempdir().unwrap();
        let rows = cgroups_out_with_live_root(&state, root.path());
        assert_eq!(rows.len(), 2);
        let by_id = |id: u64| {
            serde_json::to_value(rows.iter().find(|row| row.cgroup_id == id).unwrap()).unwrap()
        };
        assert_eq!(by_id(9911)["calls"], 1);
        assert_eq!(by_id(9911)["unadmitted"], 1);
        assert_eq!(by_id(9912)["calls"], 1);
        assert_eq!(by_id(9912)["unadmitted"], 0);
    }

    #[test]
    fn profile_json_cgroup_live_label_wins_over_retained() {
        use std::os::unix::fs::MetadataExt as _;
        // Rename twin: same inode, new path — the live path is
        // current truth, the retained path is fallback only.
        let root = tempfile::tempdir().unwrap();
        let old = root.path().join("system.slice").join("old.service");
        std::fs::create_dir_all(&old).unwrap();
        let cgroup = std::fs::metadata(&old).unwrap().ino();
        let mut state =
            crate::semantics::State::with_policy(&init_plan(), CapturePolicy::Allowlisted);
        state.set_cgroup_label_root(root.path().to_path_buf());
        let mut ev = init_event(0, 0x0D, p11scope_ebpf_common::shape::NONE, 0, 0, 0);
        ev.cgroup_id = cgroup;
        state.observe(&ev);
        assert_eq!(
            state.retained_cgroup_path(cgroup).as_deref(),
            Some("system.slice/old.service")
        );
        std::fs::rename(&old, root.path().join("system.slice").join("new.service")).unwrap();
        let rows = cgroups_out_with_live_root(&state, root.path());
        assert_eq!(rows.len(), 1);
        let row = serde_json::to_value(&rows[0]).unwrap();
        assert_eq!(row["label"], "system.slice/new.service");
        assert_eq!(row["workload"], "new.service");
    }

    #[test]
    fn profile_json_cgroup_purge_retires_retained_paths() {
        use std::os::unix::fs::MetadataExt as _;
        // Purge twin: rows are invalidated, the same cgroup is
        // renamed and observed fresh, then removed; the fresh
        // sighting — not the purged one — must name the row.
        let root = tempfile::tempdir().unwrap();
        let slice = root.path().join("system.slice");
        let old = slice.join("old.service");
        std::fs::create_dir_all(&old).unwrap();
        let cgroup = std::fs::metadata(&old).unwrap().ino();
        let mut state =
            crate::semantics::State::with_policy(&init_plan(), CapturePolicy::Allowlisted);
        state.set_cgroup_label_root(root.path().to_path_buf());
        let mut ev = init_event(0, 0x0D, p11scope_ebpf_common::shape::NONE, 0, 0, 0);
        ev.cgroup_id = cgroup;
        state.observe(&ev);
        assert_eq!(
            state.retained_cgroup_path(cgroup).as_deref(),
            Some("system.slice/old.service")
        );
        state.purge_modules(&std::collections::BTreeSet::from([crate::plan::ModuleId(
            0,
        )]));
        assert!(state.cgroups().is_empty());
        // The retained map must not outlive the rows it names.
        assert_eq!(state.retained_cgroup_path(cgroup), None);
        // Same cgroup, new path: renamed while unobserved, then a
        // fresh call starts a new row lifetime.
        std::fs::rename(&old, slice.join("new.service")).unwrap();
        state.observe(&ev);
        // The cgroup is removed before the report; only the fresh
        // sighting may serve as fallback.
        std::fs::remove_dir_all(&slice).unwrap();
        let rows = cgroups_out_with_live_root(&state, root.path());
        assert_eq!(rows.len(), 1);
        let row = serde_json::to_value(&rows[0]).unwrap();
        assert_eq!(row["label"], "system.slice/new.service");
        assert_eq!(row["workload"], "new.service");
        assert_eq!(row["calls"], 1);
    }

    #[test]
    fn cgroup_verbose_section_lists_labeled_rows_per_pod() {
        use std::os::unix::fs::MetadataExt as _;
        // -v text names each pod with its counts.
        let uid = "12345678-1234-abcd-9876-1234567890ab";
        let systemd_uid = uid.replace('-', "_");
        let id = "d".repeat(64);
        let root = tempfile::tempdir().unwrap();
        let dir = root
            .path()
            .join("kubepods.slice")
            .join(format!("kubepods-pod{systemd_uid}.slice"))
            .join(format!("crio-{id}.scope"));
        std::fs::create_dir_all(&dir).unwrap();
        let cgroup = std::fs::metadata(&dir).unwrap().ino();
        let mut state =
            crate::semantics::State::with_policy(&init_plan(), CapturePolicy::Allowlisted);
        state.set_cgroup_label_root(root.path().to_path_buf());
        let mut ev = init_event(0, 0x0D, p11scope_ebpf_common::shape::NONE, 0, 0, 0);
        ev.cgroup_id = cgroup;
        state.observe(&ev);
        let text = cgroup_verbose_section_with_live_root(&state, &evidence(), root.path());
        assert!(
            text.contains(&format!("pod {uid} / container {id}")),
            "{text}"
        );
        assert!(text.contains("1 calls"), "{text}");
    }

    #[test]
    fn cgroup_verbose_section_marks_unknown_paths_and_unadmitted() {
        // Unknown cgroups degrade to their numeric id, never vanish;
        // unadmitted calls show per row; kernel-dropped completions
        // are named as unattributable, never grouped. The empty
        // fixture root keeps the id unknown without touching the
        // host, where that inode might name a live cgroup.
        let mut state =
            crate::semantics::State::with_policy(&init_plan(), CapturePolicy::Allowlisted);
        let mut missed = init_event(0, 0x0D, p11scope_ebpf_common::shape::NONE, 0, 0, 0);
        missed.event_type = p11scope_ebpf_common::event_type::CALL;
        missed.cgroup_id = 555121;
        state.reject_unadmitted(&missed);
        let mut ev = evidence();
        ev.semantic_capture_failures = 862455;
        let root = tempfile::tempdir().unwrap();
        let text = cgroup_verbose_section_with_live_root(&state, &ev, root.path());
        assert!(text.contains("cgroup 555121"), "{text}");
        assert!(text.contains("unadmitted"), "{text}");
        assert!(text.contains("862455"), "{text}");
    }

    #[test]
    fn cgroup_verbose_section_empty_without_rows() {
        // Twin: no cgroup rows, no section — quiet stays quiet.
        let state = crate::semantics::State::with_policy(&init_plan(), CapturePolicy::Allowlisted);
        assert_eq!(cgroup_verbose_section(&state, &evidence()), "");
    }

    // ---- Slice 1b-2 public evidence contract (design §5.5–§5.7, §9) -------
    //
    // These freeze the exact published vocabulary. Every key below is named by
    // the approved design; nothing here may be widened, renamed, or derived a
    // second time from another counter.

    /// The fields §9.1 adds to profile, metrics, and the final trace evidence
    /// object. `child_still_running` is deliberately not here: it is the one
    /// run-only field and must be absent from an ordinary capture.
    const LIVE_EVIDENCE_FIELDS: [&str; 11] = [
        "attach_gap_ms",
        "pause",
        "pause_attempts",
        "pause_confirmed",
        "pause_partial",
        "discovery_ring_loss",
        "discovery_state_failures",
        "discovery_read_failures",
        "discovery_truncated",
        "task_uprobe_link_losses",
        "loader_discovery",
    ];

    fn trace_evidence_object(ev: &Evidence) -> serde_json::Value {
        let line = crate::trace::evidence_line(ev, CapturePolicy::Allowlisted);
        serde_json::from_str(line.strip_prefix("EVIDENCE ").expect("EVIDENCE prefix"))
            .expect("the final trace evidence record is one JSON object")
    }

    #[test]
    fn every_capture_document_publishes_the_live_discovery_evidence_fields() {
        let mut ev = evidence();
        ev.verdict();
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        let metrics = json(&reports_fixture(), &ev, &capture_fixture());
        for document in [
            &profile["evidence"],
            &metrics["evidence"],
            &trace_evidence_object(&ev),
        ] {
            for field in LIVE_EVIDENCE_FIELDS {
                assert!(document.get(field).is_some(), "{field} is missing");
            }
            // Nothing this observer did not start can be a running child.
            assert!(
                document.get("child_still_running").is_none(),
                "child_still_running is a run-only field"
            );
            // Nothing this observer did not start can hand back a tree.
            assert!(
                document.get("run_tree_handed_back").is_none(),
                "run_tree_handed_back is a run-only field"
            );
            // A gap that was never measured is null, never an invented zero.
            assert!(document["attach_gap_ms"].is_null());
            assert_eq!(document["pause"], "none");
            for counter in ["pause_attempts", "pause_confirmed", "pause_partial"] {
                assert_eq!(document[counter], 0, "{counter}");
            }
        }
        // The run-only fields appear exactly when the observer owned the child.
        ev.child_still_running = Some(true);
        ev.run_tree_handed_back = Some(2);
        let owned = json(&reports_fixture(), &ev, &capture_fixture());
        assert_eq!(owned["evidence"]["child_still_running"], true);
        assert_eq!(owned["evidence"]["run_tree_handed_back"], 2);
    }

    #[test]
    fn refused_pause_annotation_rides_all_three_document_lanes() {
        let mut ev = evidence();
        ev.pause = "partial";
        ev.pause_attempts = 1;
        ev.pause_partial = 1;
        ev.pause_refused = Some("interrupted");
        ev.verdict();
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        let metrics = json(&reports_fixture(), &ev, &capture_fixture());
        for document in [
            &profile["evidence"],
            &metrics["evidence"],
            &trace_evidence_object(&ev),
        ] {
            assert_eq!(document["pause_refused"], "interrupted");
        }
        let mut clean = evidence();
        clean.verdict();
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&clean),
            &state_fixture(),
            &capture_fixture(),
        );
        let metrics = json(&reports_fixture(), &clean, &capture_fixture());
        for document in [
            &profile["evidence"],
            &metrics["evidence"],
            &trace_evidence_object(&clean),
        ] {
            assert!(
                document.get("pause_refused").is_none(),
                "absent, never null"
            );
        }
    }

    #[test]
    fn every_loader_discovery_key_is_always_present_and_an_unsigned_count() {
        let mut ev = evidence();
        ev.verdict();
        let document = json(&reports_fixture(), &ev, &capture_fixture());
        let aggregate = &document["evidence"]["loader_discovery"];
        for (group, keys) in [
            (
                "strategies",
                vec!["debug_state_every_hit", "dlopen_return", "unavailable"],
            ),
            (
                "dlopen_timing",
                vec![
                    "qualified_pre_constructor",
                    "known_pre_relocation",
                    "unproven",
                    "none",
                    "pause_protected",
                ],
            ),
            (
                "initial_set_timing",
                vec![
                    "qualified_pre_constructor",
                    "known_pre_relocation",
                    "unproven",
                    "none",
                    "pause_protected",
                ],
            ),
            (
                "initial_set_capture",
                vec!["eligible", "none", "pause_protected"],
            ),
        ] {
            let object = aggregate[group]
                .as_object()
                .unwrap_or_else(|| panic!("{group} is missing"));
            // The plan freezes the key *set*; `serde_json` is built without
            // `preserve_order`, so its object is a `BTreeMap` and JSON key
            // order is alphabetical rather than declaration order. Compare
            // sorted: no key may go missing and no key may be added.
            let present: Vec<&str> = object.keys().map(String::as_str).collect();
            let mut wanted = keys.clone();
            wanted.sort_unstable();
            assert_eq!(present, wanted, "{group} key set drifted");
            for key in keys {
                assert!(object[key].is_u64(), "{group}.{key} is not a u64 count");
            }
        }
        for key in ["hits", "benign_hits", "state_read_failures"] {
            assert!(aggregate[key].is_u64(), "{key} is not a u64 count");
        }
        assert_eq!(
            aggregate.as_object().unwrap().len(),
            7,
            "loader_discovery grew a key: {aggregate}"
        );
        // No second public copy of an internal counter, no proof/identity, no
        // per-loader list: the aggregate is the whole public surface.
        let text = serde_json::to_string(&document).unwrap();
        for forbidden in [
            "loader_state_read_failures",
            "proof_id",
            "loader_identity",
            "r_debug",
            "hook_vaddr",
            "context_id",
            "delta",
        ] {
            assert!(
                !text.contains(forbidden),
                "{forbidden} reached public output"
            );
        }
    }

    /// `module`, `module_ambiguous`, and `module_unresolved` are exclusive:
    /// nonnull/false/false, null/true/false, or null/false/true. An unowned
    /// cell is never relabelled as two-module ambiguity.
    #[test]
    fn module_ownership_is_an_exact_exclusive_relation() {
        let owned = {
            let mut r = report("C_Sign", 1, 0, false);
            r.module = Some(crate::plan::ModuleId(0));
            r
        };
        let ambiguous = {
            let mut r = report("C_Sign", 2, 0, false);
            r.module = None;
            r.module_ambiguous = true;
            r
        };
        let unresolved = {
            let mut r = report("C_Sign", 3, 0, false);
            r.module = None;
            r.module_unresolved = true;
            r
        };
        let mut ev = evidence();
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE", "baseline must start clean");

        let out = profile_json(
            &[owned, ambiguous, unresolved],
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        let rows = out["functions"].as_array().unwrap();
        assert!(!rows[0]["module"].is_null());
        assert_eq!(rows[0]["module_ambiguous"], false);
        assert_eq!(rows[0]["module_unresolved"], false);
        assert!(rows[1]["module"].is_null());
        assert_eq!(rows[1]["module_ambiguous"], true);
        assert_eq!(rows[1]["module_unresolved"], false);
        assert!(rows[2]["module"].is_null());
        assert_eq!(
            rows[2]["module_ambiguous"], false,
            "an unowned cell is not two-module ambiguity"
        );
        assert_eq!(rows[2]["module_unresolved"], true);
        // The counts are real either way; only the owner is unknown.
        assert_eq!(rows[2]["calls"], 3);
    }

    #[test]
    fn an_unresolved_owner_forces_partial() {
        let mut ev = evidence();
        ev.module_unresolved_slots = 1;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        assert_eq!(
            ev.discovery.module_ambiguous, 0,
            "an unresolved owner must not be counted as ambiguity"
        );
    }

    /// OD34: a spent 16,384 image budget on a Detailed capture is a named,
    /// counted gap: identity refusals plus the budget-exhausted flag force
    /// PARTIAL with the `kernel_control` cause, and the JSON keeps the
    /// exact counts. The twin pins that a clean control stays silent.
    #[test]
    fn kernel_control_identity_refusals_force_partial_with_counts() {
        let mut clean = evidence();
        clean.verdict();
        assert!(clean.gap_classes.observation.causes.is_empty());
        let mut ev = evidence();
        ev.kernel_control.identity_unavailable = 7;
        ev.kernel_control.identity_budget_exhausted = true;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        assert_eq!(ev.gap_classes.observation.causes, ["kernel_control"]);
        assert_eq!(ev.verdict_detail, VERDICT_CONCRETE_GAP);
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["kernel_control"]["identity_unavailable"], 7);
        assert_eq!(json["kernel_control"]["identity_budget_exhausted"], true);
    }

    // Identity budget (RED): the concise coverage line names the
    // spent budget with the refusal count in plain words; verbose
    // pairs the machine cause name beside it.
    #[test]
    fn coverage_line_names_spent_identity_budget_with_counts() {
        let mut ev = evidence();
        ev.kernel_control.identity_unavailable = 7;
        ev.kernel_control.identity_budget_exhausted = true;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        let line = coverage_line(&ev, false);
        assert!(line.contains("7 process identity refusals"), "{line}");
        assert!(line.contains("262144"), "{line}");
        assert!(!line.contains("other gap"), "{line}");
        let verbose = coverage_line(&ev, true);
        assert!(verbose.contains("kernel_control"), "{verbose}");
        assert!(verbose.contains("262144"), "{verbose}");
    }

    // Semantic key budget (RED): verbose names the spent per-capture
    // key budget beside the refusal count; concise stays quiet.
    #[test]
    fn coverage_line_verbose_names_spent_semantic_key_budget() {
        let mut ev = evidence();
        ev.semantic_state_drops = 3;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        let verbose = coverage_line(&ev, true);
        assert!(verbose.contains("3 session-tracking gaps"), "{verbose}");
        assert!(verbose.contains("semantic_state_drops"), "{verbose}");
        assert!(verbose.contains("262144"), "{verbose}");
        let line = coverage_line(&ev, false);
        assert!(line.contains("3 session-tracking gaps"), "{line}");
        assert!(!line.contains("262144"), "{line}");
    }

    // Semantic key budget (RED): the JSON evidence names the enforced
    // per-capture key limit, so a report states its own budget.
    #[test]
    fn versioned_evidence_names_the_semantic_key_budget() {
        let mut ev = evidence();
        ev.semantic_state_drops = 3;
        ev.verdict();
        let json = versioned_evidence(&ev);
        assert_eq!(json["semantic_key_budget"], 262144);
    }

    // Identity budget (RED): refusals without a spent budget name
    // the count and stay silent about the budget.
    #[test]
    fn coverage_line_names_identity_refusals_without_spent_budget() {
        let mut ev = evidence();
        ev.kernel_control.identity_unavailable = 3;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        let line = coverage_line(&ev, false);
        assert!(line.contains("3 process identity refusals"), "{line}");
        assert!(!line.contains("262144"), "{line}");
    }

    // Identity budget (RED): a halted kernel and root-affiliation
    // failures surface by name beside the identity fragment.
    #[test]
    fn coverage_line_names_kernel_halt_and_root_failures() {
        let mut ev = evidence();
        ev.kernel_control.capture_halted = true;
        ev.kernel_control.owner_poison = vec!["bad_control"];
        ev.kernel_control.owner_admission_failures = 2;
        ev.kernel_control.root_affiliation_failures = vec!["capacity"];
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        let line = coverage_line(&ev, false);
        assert!(line.contains("halted"), "{line}");
        assert!(line.contains("bad_control"), "{line}");
        assert!(line.contains("capacity"), "{line}");
        assert!(line.contains('2'), "{line}");
    }

    // Identity budget (RED twin): a complete kernel control keeps
    // the coverage line silent about identity.
    #[test]
    fn coverage_line_kernel_control_quiet_twin() {
        let mut ev = evidence();
        ev.verdict();
        assert_eq!(coverage_line(&ev, false), "coverage: complete");
        assert!(!coverage_line(&ev, false).contains("identity"));
    }

    // Identity refusals (RED): the counter counts refusal attempts —
    // including repeats for one leader — not distinct processes, so
    // the fragment says refusals in both numbers.
    #[test]
    fn coverage_line_counts_identity_refusal_attempts() {
        let mut ev = evidence();
        ev.kernel_control.identity_unavailable = 1;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        let line = coverage_line(&ev, false);
        assert!(line.contains("1 process identity refusal"), "{line}");
        assert!(!line.contains("refusals"), "{line}");
    }

    // Identity budget (RED): the missed-provider-load shortcut keeps
    // its pause remedy but still names active identity refusals at
    // default verbosity instead of hiding the spent budget.
    #[test]
    fn identity_refusals_survive_the_missed_provider_summary() {
        let subject = || SkippedOut {
            name: "discovery subject".into(),
            reason: "discovery unavailable".into(),
        };
        let mut ev = evidence();
        ev.discovery.modules.clear();
        ev.slots = 0;
        ev.active_slots = 0;
        ev.child_still_running = Some(false);
        ev.unprotected_live_windows = 1;
        ev.discovery_truncated = 1;
        ev.skipped = vec![subject(), subject()];
        ev.kernel_control.identity_unavailable = 7;
        ev.kernel_control.identity_budget_exhausted = true;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        let line = coverage_line(&ev, false);
        assert!(line.contains("rerun with --pause auto"), "{line}");
        assert!(line.contains("7 process identity refusals"), "{line}");
        assert!(line.contains("262144"), "{line}");
    }

    /// OD34/E1: the 256 process-view limit is named in the user's report.
    /// The exact view-capacity skip projects to a finite named reason (not
    /// the redacted pair), forces PARTIAL with the `skipped` cause, and the
    /// text names the limit with its count. The twin pins that a clean
    /// control stays silent.
    #[test]
    fn view_capacity_skip_names_the_limit_in_text_and_json() {
        use crate::discovery::scan::Skipped;
        let mut clean = evidence();
        clean.verdict();
        assert!(clean.gap_classes.observation.causes.is_empty());
        let internal = Skipped {
            subject: "process view".into(),
            reason: "capture process-view capacity 256 was exhausted; remaining generations were not scanned".into(),
        };
        let mut ev = evidence();
        ev.skipped = vec![capture_skipped_out(&internal)];
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        assert_eq!(ev.gap_classes.observation.causes, ["skipped"]);
        assert_eq!(ev.verdict_detail, VERDICT_CONCRETE_GAP);
        for document in [
            profile_json(
                &reports_fixture(),
                VersionedEvidence::wrap(&ev),
                &state_fixture(),
                &capture_fixture(),
            ),
            json(&reports_fixture(), &ev, &capture_fixture()),
        ] {
            assert_eq!(document["evidence"]["completeness"], "PARTIAL");
            assert_eq!(
                document["evidence"]["skipped"],
                serde_json::json!([{
                    "name": "discovery subject",
                    "reason": "capture process-view capacity was exhausted; remaining generations were not scanned",
                }])
            );
        }
        let text = scope_summary("pid", &reports_fixture(), &ev);
        assert!(text.contains("1 discovery step unavailable"), "{text}");
        assert!(
            text.contains(
                "capture process-view capacity was exhausted; remaining generations were not scanned: 1"
            ),
            "{text}"
        );
        assert!(
            verdict_reasons(&ev, false).contains(
                "capture process-view capacity was exhausted; remaining generations were not scanned: 1"
            ),
            "{text}"
        );
    }

    /// The fixed loader-limit skips name their limit too: both 256-context
    /// arm paths share the capacity reason, and the two bounded-ledger
    /// losses keep their fixed sentences. Every pair projects to its named
    /// reason; PARTIAL with the count in text and JSON.
    #[test]
    fn loader_limit_skips_name_the_limit_for_every_arm_path() {
        use crate::discovery::scan::Skipped;
        // L1 formats the preflight refusal through `{error:#}` (the live
        // arm path); a single-message error renders verbatim.
        let live_reason = format!(
            "{:#}",
            anyhow::anyhow!("loader context capacity 256 is exhausted")
        );
        let internals: [(&str, &str, &str); 4] = [
            (
                "live loader arming",
                &live_reason,
                "loader context capacity 256 is exhausted",
            ),
            (
                "owned initial-set discovery",
                "loader context capacity 256 is exhausted",
                "loader context capacity 256 is exhausted",
            ),
            (
                "live loader memory discovery",
                "a deferred loader memory scan exceeded the bounded loader-context ledger",
                "a deferred loader memory scan exceeded the bounded loader-context ledger",
            ),
            (
                "post-arm provider discovery",
                "the bounded loader-arm catch-up ledger was full",
                "the bounded loader-arm catch-up ledger was full",
            ),
        ];
        for (subject, reason, public) in &internals {
            let projected = capture_skipped_out(&Skipped {
                subject: (*subject).into(),
                reason: (*reason).into(),
            });
            assert_eq!(projected.name, "discovery subject", "{subject} {reason}");
            assert_eq!(projected.reason, *public, "{subject} {reason}");
        }
        let mut ev = evidence();
        ev.skipped = internals
            .iter()
            .map(|(subject, reason, _)| {
                capture_skipped_out(&Skipped {
                    subject: (*subject).into(),
                    reason: (*reason).into(),
                })
            })
            .collect();
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        assert_eq!(ev.gap_classes.observation.causes, ["skipped"]);
        let document = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        assert_eq!(
            document["evidence"]["skipped"],
            serde_json::json!([
                {"name": "discovery subject", "reason": "loader context capacity 256 is exhausted"},
                {"name": "discovery subject", "reason": "loader context capacity 256 is exhausted"},
                {"name": "discovery subject", "reason": "a deferred loader memory scan exceeded the bounded loader-context ledger"},
                {"name": "discovery subject", "reason": "the bounded loader-arm catch-up ledger was full"},
            ])
        );
        let text = scope_summary("pid", &reports_fixture(), &ev);
        assert!(text.contains("4 discovery steps unavailable"), "{text}");
        for fragment in [
            "loader context capacity 256 is exhausted: 2",
            "a deferred loader memory scan exceeded the bounded loader-context ledger: 1",
            "the bounded loader-arm catch-up ledger was full: 1",
        ] {
            assert!(text.contains(fragment), "{text}");
        }
    }

    /// Twins: the same subjects with target-derived reasons stay redacted —
    /// subject-only matching would leak paths through the allowlisted names,
    /// so the allowlist matches exact (subject, reason) pairs.
    #[test]
    fn path_carrying_skip_reasons_stay_redacted() {
        use crate::discovery::scan::Skipped;
        let internals = [
            (
                "process view",
                "member /private/PATH_VIEW could not be scanned: ESRCH",
            ),
            (
                "live loader arming",
                "arm failed for /private/PATH_ARM: no such process",
            ),
            (
                "live loader memory discovery",
                "scan of /private/PATH_SCAN unresolved: /proc/9999 gone",
            ),
            (
                "owned initial-set discovery",
                "preflight refused: mapping /private/PATH_OWNED changed",
            ),
            (
                "post-arm provider discovery",
                "catch-up for /private/PATH_CATCHUP skipped: budget spent",
            ),
        ];
        for (subject, reason) in &internals {
            let projected = capture_skipped_out(&Skipped {
                subject: (*subject).into(),
                reason: (*reason).into(),
            });
            assert_eq!(projected.name, "discovery subject", "{subject} {reason}");
            assert_eq!(
                projected.reason, "discovery unavailable",
                "{subject} {reason}"
            );
        }
        let mut ev = evidence();
        ev.skipped = internals
            .iter()
            .map(|(subject, reason)| {
                capture_skipped_out(&Skipped {
                    subject: (*subject).into(),
                    reason: (*reason).into(),
                })
            })
            .collect();
        ev.verdict();
        for document in [
            profile_json(
                &reports_fixture(),
                VersionedEvidence::wrap(&ev),
                &state_fixture(),
                &capture_fixture(),
            ),
            json(&reports_fixture(), &ev, &capture_fixture()),
        ] {
            let rendered = document.to_string();
            assert!(!rendered.contains("PRIVATE_"), "{rendered}");
            assert!(!rendered.contains("/private/"), "{rendered}");
        }
        let text = scope_summary("pid", &reports_fixture(), &ev);
        assert!(!text.contains("PRIVATE_"), "{text}");
        assert!(text.contains("5 discovery steps unavailable"), "{text}");
    }

    /// Twins: reasons that merely start with an allowlisted sentence but
    /// carry more (a path, a detail suffix, wrong case or spacing) stay
    /// redacted — the allowlist is exact, never prefix or substring. The
    /// normalized view sentence without a value is not an engine form and
    /// stays redacted too.
    #[test]
    fn allowlisted_prefix_plus_detail_stays_redacted() {
        use crate::discovery::scan::Skipped;
        let internals = [
            (
                "process view",
                "capture process-view capacity 256 was exhausted; remaining generations were not scanned; extra /private/PATH_SUFFIX",
            ),
            (
                "process view",
                "capture process-view capacity 256 was exhausted",
            ),
            (
                "process view",
                "capture process-view capacity was exhausted; remaining generations were not scanned",
            ),
            (
                "process view",
                "capture process-view capacity many was exhausted; remaining generations were not scanned",
            ),
            (
                "process view",
                " capture process-view capacity 256 was exhausted; remaining generations were not scanned",
            ),
            (
                "process view",
                "Capture process-view capacity 256 was exhausted; remaining generations were not scanned",
            ),
            (
                "live loader arming",
                "loader context capacity 256 is exhausted: /private/PATH_DETAIL",
            ),
            (
                "live loader arming",
                "loader context capacity 256 is exhausted ",
            ),
            (
                "live loader memory discovery",
                "a deferred loader memory scan exceeded the bounded loader-context ledger (pid /private/X)",
            ),
            (
                "post-arm provider discovery",
                "the bounded loader-arm catch-up ledger was full; see /private/Y",
            ),
        ];
        for (subject, reason) in &internals {
            let projected = capture_skipped_out(&Skipped {
                subject: (*subject).into(),
                reason: (*reason).into(),
            });
            assert_eq!(projected.name, "discovery subject", "{subject} {reason}");
            assert_eq!(
                projected.reason, "discovery unavailable",
                "{subject} {reason}"
            );
        }
        let mut ev = evidence();
        ev.skipped = internals
            .iter()
            .map(|(subject, reason)| {
                capture_skipped_out(&Skipped {
                    subject: (*subject).into(),
                    reason: (*reason).into(),
                })
            })
            .collect();
        ev.verdict();
        let document = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        let rendered = document.to_string();
        assert!(!rendered.contains("PRIVATE_"), "{rendered}");
        assert!(!rendered.contains("/private/"), "{rendered}");
        let text = scope_summary("pid", &reports_fixture(), &ev);
        assert!(!text.contains("PRIVATE_"), "{text}");
        assert!(text.contains("10 discovery steps unavailable"), "{text}");
    }

    /// With the compiled-in timing catalog empty (D3), debug-state discovery
    /// still runs but proves nothing about timing.
    #[test]
    fn an_empty_timing_catalog_stays_unproven_eligible_zero_and_partial() {
        let mut ev = evidence();
        ev.loader_discovery.strategies.debug_state_every_hit = 1;
        ev.loader_discovery.dlopen_timing.unproven = 1;
        ev.loader_discovery.initial_set_timing.unproven = 1;
        ev.loader_discovery.initial_set_capture.none = 1;
        // A fully protected observed window does not create a timing proof.
        ev.unprotected_live_windows = 0;
        ev.pause = "sigstop";
        ev.pause_attempts = 1;
        ev.pause_confirmed = 1;
        ev.verdict();

        assert_eq!(
            ev.loader_discovery.dlopen_timing.qualified_pre_constructor,
            0
        );
        assert_eq!(ev.loader_discovery.dlopen_timing.known_pre_relocation, 0);
        assert_eq!(
            ev.loader_discovery
                .initial_set_timing
                .qualified_pre_constructor,
            0
        );
        assert_eq!(
            ev.loader_discovery.initial_set_timing.known_pre_relocation,
            0
        );
        assert_eq!(ev.loader_discovery.initial_set_capture.eligible, 0);
        assert_eq!(ev.completeness, "PARTIAL");
    }

    /// A clean `profile --pid` of an already-loaded provider arms the
    /// target's loader, which then never fires: `hits` 0, one bound context
    /// whose dlopen timing is unproven only because the timing catalog is
    /// empty. Every hit of a bound context is counted before any record is
    /// reserved, so zero hits proves no load happened during the capture and
    /// no late provider's first call can have been missed. It was classified
    /// as observation loss anyway, and the verdict read `concrete_gap`.
    /// Once a load does happen, unproven timing stays a gap (a `run` whose
    /// child dlopens its provider).
    #[test]
    fn an_armed_loader_that_never_fired_is_not_an_observation_gap() {
        let mut quiet = evidence();
        quiet.loader_discovery.strategies.debug_state_every_hit = 1;
        quiet.loader_discovery.dlopen_timing.unproven = 1;
        quiet.loader_discovery.hits = 0;
        quiet.verdict();
        assert!(
            !quiet
                .gap_classes(true)
                .observation
                .causes
                .contains(&"loader_discovery"),
            "{:?}",
            quiet.gap_classes(true)
        );

        let mut loaded = quiet.clone();
        loaded.loader_discovery.hits = 2;
        loaded.verdict();
        assert!(
            loaded
                .gap_classes(true)
                .observation
                .causes
                .contains(&"loader_discovery")
        );
        assert_eq!(loaded.completeness, "PARTIAL");

        let mut unarmed = quiet.clone();
        unarmed.loader_discovery.strategies.unavailable = 1;
        unarmed.loader_discovery.dlopen_timing.none = 1;
        unarmed.verdict();
        assert!(
            unarmed
                .gap_classes(true)
                .observation
                .causes
                .contains(&"loader_discovery"),
            "an unarmed loader counts no hits, so zero proves nothing"
        );
    }

    /// A `run` whose loader hook never fired and whose initial set was
    /// never validated either (the 0-hit ghost): zero hits prove nothing
    /// when the initial context itself is unproven, so the report names
    /// the loader gap and stays PARTIAL.
    #[test]
    fn a_never_fired_loader_with_unproven_initial_set_is_an_observation_gap() {
        let mut ghost = evidence();
        ghost.loader_discovery.strategies.debug_state_every_hit = 1;
        ghost.loader_discovery.hits = 0;
        ghost.loader_discovery.initial_set_timing.unproven = 1;
        ghost.loader_discovery.initial_set_capture.none = 1;
        ghost.pause_partial = 1;
        ghost.verdict();
        assert!(
            ghost
                .gap_classes(true)
                .observation
                .causes
                .contains(&"loader_discovery"),
            "{:?}",
            ghost.gap_classes(true)
        );
        assert_eq!(ghost.completeness, "PARTIAL");
    }

    /// The 0-hit ghost with a single initial-set context never saw its EXEC
    /// acknowledged (a second live context would exist otherwise), so the
    /// kernel delivered no loader or lifecycle records for the run. The
    /// report names that empty tracking instead of generic unproven timing.
    #[test]
    fn a_never_fired_single_context_loader_names_empty_tracking() {
        let mut ghost = evidence();
        ghost.loader_discovery.strategies.debug_state_every_hit = 1;
        ghost.loader_discovery.hits = 0;
        ghost.loader_discovery.initial_set_timing.unproven = 1;
        ghost.loader_discovery.initial_set_capture.none = 1;
        ghost.pause_partial = 1;
        ghost.verdict();
        let reasons = verdict_reasons(&ghost, false);
        assert!(
            reasons.contains("library-load tracking received nothing from the kernel"),
            "ghost names the empty tracking, got: {reasons:?}",
        );
    }

    /// Zero hits with two bound contexts means the EXEC was processed (a
    /// second live context exists via acknowledgment or immediate re-arm)
    /// but the loader tracking itself never fired: a loader-specific miss,
    /// not a silent run. The report names that.
    #[test]
    fn a_never_fired_processed_loader_names_missed_loads() {
        let mut miss = evidence();
        miss.loader_discovery.strategies.debug_state_every_hit = 2;
        miss.loader_discovery.hits = 0;
        miss.loader_discovery.dlopen_timing.unproven = 1;
        miss.loader_discovery.initial_set_timing.unproven = 1;
        miss.loader_discovery.initial_set_capture.none = 1;
        miss.pause_partial = 1;
        miss.verdict();
        assert!(
            miss.gap_classes(true)
                .observation
                .causes
                .contains(&"loader_discovery"),
            "{:?}",
            miss.gap_classes(true)
        );
        let reasons = verdict_reasons(&miss, false);
        assert!(
            reasons.contains("library-load tracking missed loads it should have seen"),
            "processed 0-hit loader names the missed loads, got: {reasons:?}",
        );
    }

    /// A loader that fired keeps the generic unconfirmed-tracking text:
    /// the empty-tracking and missed-loads arms are 0-hit only.
    #[test]
    fn a_fired_loader_keeps_generic_unproven_timing_text() {
        let mut fired = evidence();
        fired.loader_discovery.strategies.debug_state_every_hit = 2;
        fired.loader_discovery.hits = 2;
        fired.loader_discovery.dlopen_timing.unproven = 1;
        fired.loader_discovery.initial_set_timing.unproven = 1;
        fired.loader_discovery.initial_set_capture.none = 1;
        fired.pause_partial = 1;
        fired.verdict();
        assert!(
            fired
                .gap_classes(true)
                .observation
                .causes
                .contains(&"loader_discovery"),
            "{:?}",
            fired.gap_classes(true)
        );
        let reasons = verdict_reasons(&fired, false);
        assert!(
            reasons.contains("library-load tracking could not be confirmed"),
            "fired loader keeps generic text, got: {reasons:?}",
        );
        assert!(
            !reasons.contains("received nothing") && !reasons.contains("missed loads"),
            "fired loader names no 0-hit cause, got: {reasons:?}",
        );
    }

    /// An owned run whose pause held every loader hit and table publication
    /// until the probes were attached is not an observation gap for its
    /// loader timing, even with the empty catalog; the same run with one
    /// unpaused hit stays lossy.
    #[test]
    fn a_pause_protected_loader_context_is_not_an_observation_gap() {
        let mut protected = evidence();
        protected.loader_discovery.hits = 5;
        protected.loader_discovery.strategies.debug_state_every_hit = 2;
        protected.loader_discovery.dlopen_timing.pause_protected = 1;
        protected
            .loader_discovery
            .initial_set_timing
            .pause_protected = 1;
        protected
            .loader_discovery
            .initial_set_capture
            .pause_protected = 1;
        protected.verdict();
        assert!(
            !protected
                .gap_classes(true)
                .observation
                .causes
                .contains(&"loader_discovery"),
            "{:?}",
            protected.gap_classes(true)
        );

        let mut lossy = protected.clone();
        lossy.loader_discovery.dlopen_timing.pause_protected = 0;
        lossy.loader_discovery.dlopen_timing.unproven = 1;
        lossy.verdict();
        assert!(
            lossy
                .gap_classes(true)
                .observation
                .causes
                .contains(&"loader_discovery")
        );
    }

    /// A loader hit whose record resolved benignly (accepted, scan
    /// complete, no new provider, no suspicious close) loaded nothing the
    /// capture could have missed calls through — not even with unproven
    /// timing. The SoftHSM `rdrand` engine probe (a failed dlopen that
    /// fires one debug-state hit with no mapping change) is the live
    /// shape: exact counts with a lossy observation until this lands.
    #[test]
    fn benign_loader_hits_do_not_gate_exactness() {
        let mut ev = evidence();
        ev.loader_discovery.strategies.debug_state_every_hit = 1;
        ev.loader_discovery.hits = 1;
        ev.loader_discovery.benign_hits = 1;
        ev.loader_discovery.dlopen_timing.unproven = 1;
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
        assert!(
            !ev.gap_classes(true)
                .observation
                .causes
                .contains(&"loader_discovery"),
            "a fully benign loader hit must not name loader_discovery: {:?}",
            ev.gap_classes(true).observation.causes
        );
    }

    /// Benign resolution is per-hit: one unresolved hit keeps the
    /// capture lossy.
    #[test]
    fn partially_benign_loader_hits_stay_lossy() {
        let mut ev = evidence();
        ev.loader_discovery.strategies.debug_state_every_hit = 1;
        ev.loader_discovery.hits = 2;
        ev.loader_discovery.benign_hits = 1;
        ev.loader_discovery.dlopen_timing.unproven = 1;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        assert!(
            ev.gap_classes(true)
                .observation
                .causes
                .contains(&"loader_discovery")
        );
    }

    /// A benign count above the hit count is inconsistent evidence,
    /// never an exoneration: without pause proof the capture stays
    /// lossy (and the checker refuses the report outright).
    #[test]
    fn benign_hits_above_hits_stays_lossy_without_pause_proof() {
        let mut ev = evidence();
        ev.loader_discovery.strategies.debug_state_every_hit = 1;
        ev.loader_discovery.hits = 1;
        ev.loader_discovery.benign_hits = 2;
        ev.loader_discovery.dlopen_timing.unproven = 1;
        ev.verdict();
        assert_eq!(ev.completeness, "PARTIAL");
        assert!(
            ev.gap_classes(true)
                .observation
                .causes
                .contains(&"loader_discovery")
        );
    }

    /// A protected window removes exactly one gap — its own. It is not a
    /// licence to call the rest of the capture complete.
    #[test]
    fn a_protected_window_removes_only_its_corresponding_live_gap() {
        let proven = |ev: &mut Evidence| {
            ev.loader_discovery.strategies.debug_state_every_hit = 1;
            ev.loader_discovery.dlopen_timing.qualified_pre_constructor = 1;
            ev.loader_discovery
                .initial_set_timing
                .qualified_pre_constructor = 1;
            ev.loader_discovery.initial_set_capture.eligible = 1;
        };

        let mut unprotected = evidence();
        proven(&mut unprotected);
        unprotected.unprotected_live_windows = 1;
        unprotected.verdict();
        assert_eq!(unprotected.completeness, "PARTIAL");

        let mut protected = evidence();
        proven(&mut protected);
        protected.unprotected_live_windows = 0;
        protected.pause = "sigstop";
        protected.pause_attempts = 1;
        protected.pause_confirmed = 1;
        protected.verdict();
        assert_eq!(protected.completeness, "COMPLETE");

        let mut protected_but_lossy = protected.clone();
        protected_but_lossy.event_loss = 1;
        protected_but_lossy.verdict();
        assert_eq!(
            protected_but_lossy.completeness, "PARTIAL",
            "a protected window cannot erase another evidence gap"
        );
    }

    /// One named live-discovery loss, applied to an otherwise clean fixture.
    type NamedLoss = fn(&mut Evidence);

    #[test]
    fn partial_is_sticky_for_every_named_live_discovery_loss() {
        let losses: Vec<(&str, NamedLoss)> = vec![
            ("scan-only semantic authority", |ev| {
                ev.semantic_unverified_slots = 1
            }),
            ("unprotected live window", |ev| {
                ev.unprotected_live_windows = 1
            }),
            ("discovery ring loss", |ev| ev.discovery_ring_loss = 1),
            ("discovery state failure", |ev| {
                ev.discovery_state_failures = 1
            }),
            ("discovery read failure", |ev| {
                ev.discovery_read_failures = 1
            }),
            ("discovery truncation", |ev| ev.discovery_truncated = 1),
            ("task-uprobe link loss", |ev| ev.task_uprobe_link_losses = 1),
            ("loader fallback", |ev| {
                ev.loader_discovery.strategies.dlopen_return = 1
            }),
            ("loader unavailable", |ev| {
                ev.loader_discovery.strategies.unavailable = 1
            }),
            // A dlopen timing class is a gap once a load happened (hits).
            ("unproven timing", |ev| {
                ev.loader_discovery.hits = 1;
                ev.loader_discovery.dlopen_timing.unproven = 1
            }),
            ("no timing", |ev| {
                ev.loader_discovery.hits = 1;
                ev.loader_discovery.dlopen_timing.none = 1
            }),
            // Every LoaderTiming class except qualified_pre_constructor is a gap,
            // for dlopen and initial-set timing alike (audit mutants M-1/M-2).
            ("known pre-relocation timing", |ev| {
                ev.loader_discovery.hits = 1;
                ev.loader_discovery.dlopen_timing.known_pre_relocation = 1
            }),
            ("initial-set unproven timing", |ev| {
                ev.loader_discovery.initial_set_timing.unproven = 1
            }),
            ("initial-set no timing", |ev| {
                ev.loader_discovery.initial_set_timing.none = 1
            }),
            ("initial-set known pre-relocation timing", |ev| {
                ev.loader_discovery.initial_set_timing.known_pre_relocation = 1
            }),
            ("initial-set capture none", |ev| {
                ev.loader_discovery.initial_set_capture.none = 1
            }),
            ("loader state read failure", |ev| {
                ev.loader_discovery.state_read_failures = 1
            }),
            ("pause partial", |ev| {
                ev.pause = "partial";
                ev.pause_attempts = 1;
                ev.pause_partial = 1;
            }),
            ("attach failure", |ev| {
                ev.attach_failures.push("C_Sign: EPERM".into())
            }),
            ("identity ambiguity", |ev| ev.discovery.module_ambiguous = 1),
            ("unresolved owner", |ev| ev.module_unresolved_slots = 1),
            ("selection truncation", |ev| {
                ev.interface_selection.selection_truncated = true
            }),
            ("selection observed uncovered", |ev| {
                ev.interface_selection.providers.push(SelectionProvider {
                    module: 0,
                    coverage: "observed_uncovered",
                })
            }),
            ("selection absent uncovered", |ev| {
                ev.interface_selection.providers.push(SelectionProvider {
                    module: 0,
                    coverage: "absent_uncovered",
                })
            }),
            ("standard export outside module", |ev| {
                ev.interface_selection
                    .standard_exports
                    .push(StandardExport {
                        module: 0,
                        status: "outside_module",
                    })
            }),
            ("standard export unresolved", |ev| {
                ev.interface_selection
                    .standard_exports
                    .push(StandardExport {
                        module: 0,
                        status: "unresolved",
                    })
            }),
            ("selection count-only authority", |ev| {
                ev.interface_selection.tuples.push(selection_tuple(
                    0,
                    true,
                    SelectionAuthority::SelectionCountOnly,
                ))
            }),
            ("unmatched successful selection", |ev| {
                ev.interface_selection.tuples.push(selection_tuple(
                    0,
                    true,
                    SelectionAuthority::None,
                ))
            }),
            ("pid descendant gap", |ev| ev.pid_descendant_gaps = 1),
            ("multi rebuild gap", |ev| ev.multi_rebuild_gaps = 1),
            ("changed provider", |ev| ev.provider_changed = true),
            ("zero modules", |ev| ev.discovery.modules.clear()),
        ];
        for (name, apply) in losses {
            let mut ev = evidence();
            apply(&mut ev);
            ev.verdict();
            assert_eq!(ev.completeness, "PARTIAL", "{name} did not force PARTIAL");
            // Sticky: a later clean pass cannot promote it back.
            ev.verdict();
            assert_eq!(ev.completeness, "PARTIAL", "{name} was un-stuck");
        }
    }

    #[test]
    fn every_discovery_loss_serializes_nonzero_and_independently_forces_partial() {
        let losses: [(&str, NamedLoss); 5] = [
            ("discovery_ring_loss", |ev| ev.discovery_ring_loss = 7),
            ("discovery_state_failures", |ev| {
                ev.discovery_state_failures = 7
            }),
            ("discovery_read_failures", |ev| {
                ev.discovery_read_failures = 7
            }),
            ("discovery_truncated", |ev| ev.discovery_truncated = 7),
            ("task_uprobe_link_losses", |ev| {
                ev.task_uprobe_link_losses = 7
            }),
        ];
        let reports = reports_fixture();
        for (field, apply) in losses {
            let mut ev = evidence();
            apply(&mut ev);
            ev.verdict();
            assert_eq!(ev.completeness, "PARTIAL", "{field}");

            let profile = profile_json(
                &reports,
                VersionedEvidence::wrap(&ev),
                &state_fixture(),
                &capture_fixture(),
            );
            let metrics = json(&reports, &ev, &capture_fixture());
            let terminal = trace_evidence_object(&ev);
            for document in [&profile["evidence"], &metrics["evidence"], &terminal] {
                assert_eq!(document[field], 7, "{field}");
                assert_eq!(document["completeness"], "PARTIAL", "{field}");
                for (other, _) in losses {
                    assert_eq!(
                        document[other],
                        if other == field { 7 } else { 0 },
                        "{field} must not alias {other}"
                    );
                }
            }
        }
    }

    #[test]
    fn neutral_selection_states_preserve_baseline_completeness() {
        let neutral: Vec<(&str, NamedLoss)> = vec![
            ("observed", |ev| {
                ev.interface_selection.providers.push(SelectionProvider {
                    module: 0,
                    coverage: "observed",
                })
            }),
            ("absent covered", |ev| {
                ev.interface_selection.providers.push(SelectionProvider {
                    module: 0,
                    coverage: "absent_covered",
                })
            }),
            ("legacy absent", |ev| {
                ev.interface_selection
                    .standard_exports
                    .push(StandardExport {
                        module: 0,
                        status: "legacy_absent",
                    })
            }),
            ("historical required absent", |ev| {
                ev.interface_selection
                    .standard_exports
                    .push(StandardExport {
                        module: 0,
                        status: "required_absent",
                    })
            }),
            ("nonzero rv", |ev| {
                ev.interface_selection.tuples.push(selection_tuple(
                    1,
                    false,
                    SelectionAuthority::None,
                ))
            }),
        ];
        for (name, apply) in neutral {
            let mut ev = evidence();
            apply(&mut ev);
            ev.verdict();
            assert_eq!(ev.completeness, "COMPLETE", "{name}");
        }
    }

    #[test]
    fn descendant_gap_downgrades_only_covered_selection_states() {
        let mut selection = InterfaceSelection {
            providers: [
                "observed",
                "observed_uncovered",
                "absent_covered",
                "absent_uncovered",
            ]
            .into_iter()
            .enumerate()
            .map(|(module, coverage)| SelectionProvider {
                module: module as u32,
                coverage,
            })
            .collect(),
            ..Default::default()
        };

        selection.mark_descendant_gap();

        assert_eq!(
            selection
                .providers
                .iter()
                .map(|provider| provider.coverage)
                .collect::<Vec<_>>(),
            [
                "observed_uncovered",
                "observed_uncovered",
                "absent_uncovered",
                "absent_uncovered",
            ]
        );
    }

    /// The capture ended the ordinary way: the process is gone, its links and
    /// views are released, and everything the capture *did* observe is still
    /// reported. An exited target is not a discovery loss.
    #[test]
    fn an_active_to_empty_lifecycle_keeps_its_history_in_every_renderer() {
        let mut ev = evidence();
        ev.child_still_running = Some(false);
        // U-14: an ordinary exit of a scan-only target retires every key an
        // unpinned object loses, so active_slots reads 0 while `slots` keeps
        // the unchanged capture-lifetime allocation total.
        ev.active_slots = 0;
        ev.verdict();
        let reports = reports_fixture();

        let profile = profile_json(
            &reports,
            VersionedEvidence::wrap(&ev),
            &state_fixture(),
            &capture_fixture(),
        );
        let metrics = json(&reports, &ev, &capture_fixture());
        let trace = trace_evidence_object(&ev);
        for document in [&profile["evidence"], &metrics["evidence"], &trace] {
            // History: the modules, the exact table entries, the surfaces and
            // skips, the allocated slots and the successful endpoints.
            assert_eq!(document["discovery"][0]["path"], "/opt/p11.so");
            assert_eq!(document["discovery"][0]["tables"][0]["entries"], 68);
            assert_eq!(document["surfaces"][0]["walk"], "full");
            assert_eq!(document["table_entries"], 68);
            assert_eq!(document["slots"], 68);
            assert_eq!(document["active_slots"], 0);
            assert_eq!(document["attached_probes"], 136);
            // No exit-generated discovery loss and no false reconciliation.
            for counter in [
                "discovery_ring_loss",
                "discovery_state_failures",
                "discovery_read_failures",
                "discovery_truncated",
                "state_reconciliations",
            ] {
                assert_eq!(document[counter], 0, "{counter} after an ordinary exit");
            }
        }
        // Aggregate calls and the exact function-module reference survive too.
        for document in [&profile, &metrics] {
            assert_eq!(document["functions"][0]["calls"], 1);
            assert_eq!(document["functions"][0]["module"]["ino"], 11);
            assert_eq!(document["capture"]["modules"][0]["path"], "/opt/p11.so");
        }
    }

    /// A slot discovered after the capture started renders exactly like one
    /// from the initial plan, in both metrics and trace evidence — and an
    /// in-flight call at the end still costs completeness.
    #[test]
    fn metrics_and_trace_render_a_slot_that_appeared_mid_capture() {
        let mut late = report("C_Encrypt", 5, 1, false);
        late.module = Some(crate::plan::ModuleId(0));
        let mut ev = evidence();
        ev.in_flight_at_end = 1;
        ev.verdict();

        let metrics = json(&[late.clone()], &ev, &capture_fixture());
        assert_eq!(metrics["functions"][0]["names"][0], "C_Encrypt");
        assert_eq!(metrics["functions"][0]["calls"], 5);
        assert_eq!(metrics["functions"][0]["module"]["ino"], 11);
        assert_eq!(metrics["evidence"]["completeness"], "PARTIAL");
        assert_eq!(trace_evidence_object(&ev)["in_flight_at_end"], 1);
    }

    /// The one live-heading policy (plan Task 8 Step 2): every ordinary
    /// heading is built from capture-lifetime provider facts, so a target that
    /// exited — active topology empty — cannot print "no modules discovered"
    /// beside the calls it is still reporting. Only a capture that never
    /// accepted a provider says that.
    #[test]
    fn the_live_heading_names_capture_facts_never_the_active_topology() {
        let facts = CaptureFacts {
            discovery: DiscoveryEvidence {
                modules: vec![discovered_fixture()],
                ..DiscoveryEvidence::default()
            },
            ..CaptureFacts::default()
        };
        assert_eq!(facts.heading(), "/opt/p11.so");

        let mut ev = evidence();
        ev.child_still_running = Some(false);
        ev.verdict();
        let frame = live(
            &reports_fixture(),
            &ev,
            Duration::from_secs(1),
            &facts.heading(),
            "profile",
            CapturePolicy::Allowlisted,
        );
        assert!(frame.contains("/opt/p11.so"), "{frame}");
        assert!(!frame.contains("no modules discovered"), "{frame}");
        // Two providers are named as two, never as "the" module.
        let mut second = discovered_fixture();
        second.id = ModuleId(1);
        second.path = "/opt/other.so".into();
        let both = CaptureFacts {
            discovery: DiscoveryEvidence {
                modules: vec![discovered_fixture(), second],
                ..DiscoveryEvidence::default()
            },
            ..CaptureFacts::default()
        };
        assert_eq!(both.heading(), "/opt/p11.so (+1 more)");
        // And the honest empty case still says so.
        assert_eq!(CaptureFacts::default().heading(), "no modules discovered");
    }

    /// The empty heading must not contradict the refused-provider line:
    /// zero accepted modules with refused providers reads as none
    /// attached with the found count, not "no modules discovered".
    #[test]
    fn the_empty_heading_names_refused_providers_instead_of_none_found() {
        let facts = CaptureFacts {
            discovery: DiscoveryEvidence {
                modules_skipped: vec![SkippedOut {
                    name: "/opt/p11.so".into(),
                    reason: "whole refusal: needs 12 slots, 4 free".into(),
                }],
                ..DiscoveryEvidence::default()
            },
            ..CaptureFacts::default()
        };
        assert_eq!(facts.heading(), "none attached (1 found, refused)");
    }

    /// A proxy closure still awaiting publication reads like nothing
    /// mapped yet (the start gate's own rule), so the empty heading
    /// says nothing was discovered instead of counting it found.
    #[test]
    fn the_empty_heading_ignores_a_closure_awaiting_publication() {
        let reason = "(a proxy closure array is admitted whole, but no table is published yet)";
        assert!(
            crate::plan::is_closure_awaiting_publication(reason),
            "the fixture must carry the awaiting-publication marker"
        );
        let facts = CaptureFacts {
            discovery: DiscoveryEvidence {
                modules_skipped: vec![SkippedOut {
                    name: "/opt/proxy/libproxy.so".into(),
                    reason: reason.into(),
                }],
                ..DiscoveryEvidence::default()
            },
            ..CaptureFacts::default()
        };
        assert_eq!(facts.heading(), "no modules discovered");
    }

    #[test]
    fn headings_and_live_frames_escape_module_path_controls() {
        let mut facts = CaptureFacts {
            discovery: DiscoveryEvidence {
                modules: vec![discovered_fixture()],
                ..DiscoveryEvidence::default()
            },
            ..CaptureFacts::default()
        };
        facts.discovery.modules[0].path = "/opt/p\u{1b}[2Jevil\r.so".into();

        let heading = facts.heading();
        assert!(
            !heading.contains('\u{1b}') && !heading.contains('\r'),
            "{heading:?}"
        );
        assert!(heading.contains(r"\u{1b}[2Jevil\r"), "{heading:?}");

        let frame = live(
            &reports_fixture(),
            &evidence(),
            Duration::from_secs(1),
            &heading,
            "profile",
            CapturePolicy::Allowlisted,
        );
        assert!(
            !frame.contains("\u{1b}[2J"),
            "raw clear-screen sequence: {frame:?}"
        );
        assert!(frame.contains(r"\u{1b}[2Jevil\r"), "{frame:?}");
    }

    // SYSPLAN residual F-02 (RED): the terminal verdict splits clean-but-
    // unproven from concrete-gap via a machine-readable drain_proven latch
    // plus a verdict_detail enum. Terminal PARTIAL is kept, not deleted.
    // GREEN: the gate works both ways — a proven drain survives the seal.
    #[test]
    fn terminal_seal_gates_complete_on_the_drain_proven_latch() {
        let mut proven = evidence();
        proven.drain_proven = true;
        proven.verdict();
        assert_eq!(proven.completeness, "COMPLETE");
        proven.mark_terminal_drain_unproven();
        assert_eq!(proven.completeness, "COMPLETE");
        let value = versioned_evidence(&proven);
        assert_eq!(value["drain_proven"], true);
        assert_eq!(value["verdict_detail"], "clean_proven");
    }

    fn stop(state: QuiescenceState, post_q_events: bool, post_q_discovery: bool) -> StopQuiescence {
        StopQuiescence {
            state,
            post_q_events,
            post_q_discovery,
        }
    }

    // SG-T7B (owner ruling B, 2026-09-25): a proven Q plus a drain to the
    // Q positions sets the latch, so a clean Detailed x86_64 terminal
    // document is COMPLETE / clean_proven, with the stop-gate outcome
    // published beside it.
    #[test]
    #[cfg(target_arch = "x86_64")] // the drain proof applies on x86_64 only
    fn a_proven_quiescence_seals_a_clean_terminal_document_complete() {
        let mut ev = evidence();
        ev.apply_stop_quiescence(stop(QuiescenceState::Proven, false, false));
        ev.settle_terminal(true);
        // The ordinary suite runs on x86_64, the architecture the proof covers.
        assert!(ev.drain_proven);
        assert_eq!(ev.completeness, "COMPLETE");
        assert_eq!(ev.verdict_detail, VERDICT_CLEAN_PROVEN);
        let value = versioned_evidence(&ev);
        assert_eq!(value["completeness"], "COMPLETE");
        assert_eq!(value["drain_proven"], true);
        assert_eq!(value["gap_classes"]["settlement"], "proven");
        assert_eq!(
            value["stop_quiescence"],
            serde_json::json!({
                "state": "proven",
                "post_q_events": false,
                "post_q_discovery": false,
            })
        );
        assert_eq!(verdict_reasons(&ev, false), "");
    }

    // Ruling B's conditions: either post-Q flag, an unproven Q, or no
    // terminal Q forces the latch false before the seal, so a clean run
    // stays PARTIAL / clean_but_unproven and says why in the document.
    #[test]
    fn post_q_flags_and_unproven_quiescence_keep_a_clean_terminal_partial() {
        for (name, cell) in [
            ("post-Q EVENTS", stop(QuiescenceState::Proven, true, false)),
            (
                "post-Q DISCOVERY",
                stop(QuiescenceState::Proven, false, true),
            ),
            ("both post-Q", stop(QuiescenceState::Proven, true, true)),
            ("unproven Q", stop(QuiescenceState::Unproven, false, false)),
            ("no Q", stop(QuiescenceState::NotReached, false, false)),
        ] {
            let mut ev = evidence();
            ev.drain_proven = true; // a stale latch must not survive
            ev.apply_stop_quiescence(cell);
            ev.settle_terminal(true);
            assert!(!ev.drain_proven, "{name}");
            assert_eq!(ev.completeness, "PARTIAL", "{name}");
            assert_eq!(ev.verdict_detail, VERDICT_CLEAN_BUT_UNPROVEN, "{name}");
            let value = versioned_evidence(&ev);
            assert_eq!(value["gap_classes"]["settlement"], "unproven", "{name}");
            assert_eq!(
                value["stop_quiescence"]["post_q_events"], cell.post_q_events,
                "{name}"
            );
            assert_eq!(
                value["stop_quiescence"]["post_q_discovery"], cell.post_q_discovery,
                "{name}"
            );
        }
    }

    // A proven drain never hides a concrete gap: loss stays PARTIAL with
    // its own detail.
    #[test]
    fn a_proven_quiescence_keeps_a_lossy_terminal_partial() {
        let mut ev = evidence();
        ev.event_loss = 1;
        ev.apply_stop_quiescence(stop(QuiescenceState::Proven, false, false));
        ev.settle_terminal(true);
        assert_eq!(ev.drain_proven, DRAIN_PROOF_ARCH);
        assert_eq!(ev.completeness, "PARTIAL");
        assert_eq!(ev.verdict_detail, VERDICT_CONCRETE_GAP);
    }

    // arm64 keeps the unconditional PARTIAL: the architecture without the
    // barrier argument never proves the drain, whatever the gate saw.
    #[test]
    fn the_drain_proof_is_scoped_to_the_x86_64_architecture() {
        let clean = stop(QuiescenceState::Proven, false, false);
        assert!(clean.proves_drain_on(true));
        assert!(!clean.proves_drain_on(false), "arm64 keeps PARTIAL");
        assert_eq!(clean.proves_drain(), cfg!(target_arch = "x86_64"));
    }

    #[test]
    fn terminal_verdict_splits_clean_unproven_from_concrete_gap() {
        let mut clean = evidence();
        clean.verdict();
        assert_eq!(clean.completeness, "COMPLETE", "fixture must start clean");
        clean.mark_terminal_drain_unproven();
        let clean_value = versioned_evidence(&clean);
        assert_eq!(clean_value["completeness"], "PARTIAL");
        assert_eq!(clean_value["drain_proven"], false);
        assert_eq!(clean_value["verdict_detail"], "clean_but_unproven");

        let mut gappy = evidence();
        gappy.event_loss = 1;
        gappy.verdict();
        assert_eq!(gappy.completeness, "PARTIAL");
        gappy.mark_terminal_drain_unproven();
        let gappy_value = versioned_evidence(&gappy);
        assert_eq!(gappy_value["completeness"], "PARTIAL");
        assert_eq!(gappy_value["drain_proven"], false);
        assert_eq!(gappy_value["verdict_detail"], "concrete_gap");
    }

    // SYSPLAN residual F-01-partial (RED): the uretprobe/hazard override
    // flag + reason is durable report evidence, not just a stderr warning.
    #[test]
    fn durable_evidence_records_uretprobe_override() {
        let value = versioned_evidence(&evidence());
        assert!(
            value.get("uretprobe_override").is_some(),
            "missing uretprobe_override in durable evidence: {value}"
        );
    }

    // SYSPLAN residual F-01 (GREEN): the override serializes as the exact
    // flag plus the hazard reason, and the verdict ignores it (an accepted
    // risk is disclosed, not a gap).
    #[test]
    fn uretprobe_override_serializes_flag_and_reason_without_forcing_partial() {
        let mut ev = evidence();
        ev.uretprobe_override = Some(UretprobeOverride {
            flag: "--allow-uretprobe-on-confined-target",
            reason: "unproven kernel with an unreadable target".into(),
        });
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
        let value = versioned_evidence(&ev);
        assert_eq!(
            value["uretprobe_override"]["flag"],
            "--allow-uretprobe-on-confined-target"
        );
        assert_eq!(
            value["uretprobe_override"]["reason"],
            "unproven kernel with an unreadable target"
        );
    }

    // SYSPLAN residual F-08 (GREEN): `profile_json` only accepts the
    // newtype, and the newtype carries exactly `versioned_evidence`.
    #[test]
    fn versioned_evidence_newtype_carries_the_versioned_shape() {
        let ev = evidence();
        let versioned = VersionedEvidence::wrap(&ev);
        assert_eq!(versioned.value(), &versioned_evidence(&ev));
        assert!(versioned.value().get("interface_selection").is_some());
        assert!(std::ptr::eq(versioned.evidence(), &ev));
    }

    // SYSPLAN residual F-26 (GREEN): the env snapshot records every known
    // switch with its active value, without touching the process env.
    #[test]
    fn env_snapshot_records_active_values_through_an_injected_getter() {
        let snap = snapshot_env(|name| match name {
            "P11SCOPE_BROAD_ADMIT" => Some("1".into()),
            _ => None,
        });
        assert_eq!(snap.len(), P11SCOPE_ENV_VARS.len());
        assert_eq!(snap[0].name, "P11SCOPE_BROAD_ADMIT");
        assert_eq!(snap[0].value.as_deref(), Some("1"));
        assert!(snap[0].effect.contains("broad provider admission"));
        assert_eq!(snap[1].name, "P11SCOPE_LOADER_ENV_SANITIZED");
        assert_eq!(snap[1].value, None);
    }

    // SYSPLAN residual F-15 (RED): the handed-back orphan PID is named in
    // machine-readable evidence, not dropped.
    #[test]
    fn durable_evidence_names_handoff_child_pid() {
        let value = versioned_evidence(&evidence());
        assert!(
            value.get("handoff_child_pid").is_some(),
            "missing handoff_child_pid in durable evidence: {value}"
        );
    }

    // SYSPLAN residual F-12 (RED): profile and metrics documents carry a
    // machine-readable lane discriminator.
    #[test]
    fn profile_and_metrics_documents_carry_lane_discriminator() {
        let profile = profile_json(
            &reports_fixture(),
            VersionedEvidence::wrap(&evidence()),
            &state_fixture(),
            &capture_fixture(),
        );
        assert_eq!(profile["lane"], "profile");
        let metrics = json(&reports_fixture(), &evidence(), &capture_fixture());
        assert_eq!(metrics["lane"], "metrics");
    }
}

#[cfg(test)]
#[path = "render_lossless_tests.rs"]
mod render_lossless_tests;
