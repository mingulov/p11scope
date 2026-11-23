//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Sealed authority for the changed-generation label: the ONLY module
//! that can mint exit/change proof or file the changed and unverified
//! generation pairs. The proof representation is private to this
//! module: filing sites move proof values and call the judges below,
//! but no call site can fabricate a proof without a pin read (which
//! fails to compile) or paste a pair literal (which the drift guard
//! rejects). The public wire strings are unchanged.

use crate::discovery::scan::Skipped;
use crate::process::{OriginalGenerationState, PidPin};

/// Whether a discovery-read failure detail reports a permission
/// refusal (EACCES "Permission denied", EPERM "Operation not
/// permitted"). Same markers the inspect layer already uses for its
/// sudo hint: the process may be live and unchanged, so the refusal
/// is never evidence of exit or change. Shared by the member-scan path
/// and the generation classifier.
pub(crate) fn is_permission_denial(detail: &str) -> bool {
    detail.contains("Permission denied") || detail.contains("not permitted")
}

/// What a stale generation proved: positive pin evidence that the
/// original ended or changed. Private to this module: only the judges
/// below can name a variant, so only they can mint a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofKind {
    /// At least one affected original provably exited.
    ProvenExit,
    /// At least one affected original provably changed (PID reuse: the
    /// same numeric PID now names a different start time).
    ProvenChange,
}

/// Proof that a stale generation actually ended or changed: the ONLY
/// token that can file the changed-generation label. Each proof is
/// positive pin evidence; anything else (poll failure, unreadable
/// `/proc`, missing custody, a contradicted recheck) is
/// `GenerationUnproven` and files the named not-proven gap instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GenerationProof {
    kind: ProofKind,
}

impl GenerationProof {
    /// Mint a proof from a live pin read: the ONLY production mint
    /// path. Positive exit/reuse evidence becomes a proof; every other
    /// outcome becomes the reason proof is unavailable. The observation
    /// is the discovery one: a ready original pidfd already proves the
    /// exit, so a failed `/proc` re-read can never downgrade it.
    pub(crate) fn judge_pin(pin: &PidPin) -> Result<Self, GenerationUnproven> {
        classify_generation_state(Some(pin.original_discovery_state()))
    }

    /// Mint a proof from a scripted pin answer (fault injection for
    /// the stale-set twins): test builds only. Production code has no
    /// scripted mint path.
    #[cfg(test)]
    pub(crate) fn judge_scripted(
        state: Option<Result<OriginalGenerationState, String>>,
    ) -> Result<Self, GenerationUnproven> {
        classify_generation_state(state)
    }
}

/// Why a stale generation could NOT be proven exited or changed: every
/// other outcome of the pin check. Each variant files its own named
/// not-proven gap row (never the changed label): two different losses
/// stay two records even though all project to the same public row,
/// while same-cause losses share their one row. Budget refusals never
/// reach this classifier — the work ceiling stops the pass upstream
/// and files the scan-budget row, which likewise claims neither
/// event — so no budget variant exists here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GenerationUnproven {
    /// The pin check failed (pidfd poll error, `/proc` read error).
    PinFailure,
    /// The pin check was denied (EACCES/EPERM).
    PermissionDenied,
    /// No view is retained for the stale ID (missing custody).
    MissingCustody,
    /// The pin re-reads Current: the stale report was contradicted (a
    /// transient poll error ahead of a successful recheck).
    Contradicted,
}

/// The three sites that may file the changed-generation label, each
/// with its exact internal pair. The pairs live ONLY in the two
/// constructors below; the drift guard asserts the literals appear
/// nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChangedGenerationSite {
    Candidate,
    InventoryPreflight,
    PostRetirementPreflight,
}

/// The ONE constructor for the changed-generation internal pair: it
/// takes a `GenerationProof`, which only this module's judges can mint
/// from pin evidence. No other path can file this label. Both proof
/// variants file the same exit-or-change row, which never names which
/// event proved it.
pub(crate) fn changed_generation_skip(
    proof: GenerationProof,
    site: ChangedGenerationSite,
) -> Skipped {
    // Total: a future proof variant must choose its row here.
    match proof.kind {
        ProofKind::ProvenExit | ProofKind::ProvenChange => {}
    }
    let (subject, reason) = match site {
        ChangedGenerationSite::Candidate => (
            "live discovery generation",
            "candidate generation changed before mutation; canonical identity, plan, and links were unchanged",
        ),
        ChangedGenerationSite::InventoryPreflight => (
            "live inventory generation",
            "an exact retained or newly opened process generation changed during inventory preflight",
        ),
        ChangedGenerationSite::PostRetirementPreflight => (
            "live inventory generation",
            "an exact retained or newly opened process generation changed during post-retirement preflight",
        ),
    };
    Skipped {
        subject: subject.into(),
        reason: reason.into(),
    }
}

/// The ONE constructor for the unverified-generation internal pairs:
/// every `GenerationUnproven` outcome at every site files its own
/// named not-proven gap row, which claims neither exit nor change.
/// Twelve pairs (four causes times three sites): a pin failure keeps
/// the legacy text, the other three causes name themselves, so two
/// different losses never share a record.
pub(crate) fn unproven_generation_skip(
    unproven: GenerationUnproven,
    site: ChangedGenerationSite,
) -> Skipped {
    // Total: a future unproven outcome or site must choose its gap
    // here, so no new failure mode can silently become an exit/change
    // claim — or collapse into another cause's row.
    let (subject, reason) = match (unproven, site) {
        (GenerationUnproven::PinFailure, ChangedGenerationSite::Candidate) => (
            "live discovery generation",
            "candidate generation unverified before mutation; exit or change unproven, canonical identity, plan, and links were unchanged",
        ),
        (GenerationUnproven::PinFailure, ChangedGenerationSite::InventoryPreflight) => (
            "live inventory generation",
            "an exact retained or newly opened process generation was unverified during inventory preflight; exit or change unproven",
        ),
        (GenerationUnproven::PinFailure, ChangedGenerationSite::PostRetirementPreflight) => (
            "live inventory generation",
            "an exact retained or newly opened process generation was unverified during post-retirement preflight; exit or change unproven",
        ),
        (GenerationUnproven::PermissionDenied, ChangedGenerationSite::Candidate) => (
            "live discovery generation",
            "candidate generation unverified before mutation; a pin read was denied, exit or change unproven, canonical identity, plan, and links were unchanged",
        ),
        (GenerationUnproven::PermissionDenied, ChangedGenerationSite::InventoryPreflight) => (
            "live inventory generation",
            "an exact retained or newly opened process generation was unverified during inventory preflight; a pin read was denied, exit or change unproven",
        ),
        (GenerationUnproven::PermissionDenied, ChangedGenerationSite::PostRetirementPreflight) => (
            "live inventory generation",
            "an exact retained or newly opened process generation was unverified during post-retirement preflight; a pin read was denied, exit or change unproven",
        ),
        (GenerationUnproven::MissingCustody, ChangedGenerationSite::Candidate) => (
            "live discovery generation",
            "candidate generation unverified before mutation; no generation pin was retained, exit or change unproven, canonical identity, plan, and links were unchanged",
        ),
        (GenerationUnproven::MissingCustody, ChangedGenerationSite::InventoryPreflight) => (
            "live inventory generation",
            "an exact retained or newly opened process generation was unverified during inventory preflight; no generation pin was retained, exit or change unproven",
        ),
        (GenerationUnproven::MissingCustody, ChangedGenerationSite::PostRetirementPreflight) => (
            "live inventory generation",
            "an exact retained or newly opened process generation was unverified during post-retirement preflight; no generation pin was retained, exit or change unproven",
        ),
        (GenerationUnproven::Contradicted, ChangedGenerationSite::Candidate) => (
            "live discovery generation",
            "candidate generation unverified before mutation; the stale report was contradicted, exit or change unproven, canonical identity, plan, and links were unchanged",
        ),
        (GenerationUnproven::Contradicted, ChangedGenerationSite::InventoryPreflight) => (
            "live inventory generation",
            "an exact retained or newly opened process generation was unverified during inventory preflight; the stale report was contradicted, exit or change unproven",
        ),
        (GenerationUnproven::Contradicted, ChangedGenerationSite::PostRetirementPreflight) => (
            "live inventory generation",
            "an exact retained or newly opened process generation was unverified during post-retirement preflight; the stale report was contradicted, exit or change unproven",
        ),
    };
    Skipped {
        subject: subject.into(),
        reason: reason.into(),
    }
}

/// Publication verdict: the changed row (proof) plus one unverified
/// gap row per distinct unproven cause — a mixed batch files the
/// proof and names every different refusal instead of dropping any.
/// Silence (no newly-opened stale ID, every retained stale view
/// proven) files none.
#[derive(Debug, Clone)]
pub(crate) struct GenerationSkips {
    pub(crate) proven: Option<Skipped>,
    pub(crate) unproven: Vec<Skipped>,
}

impl GenerationSkips {
    /// The silent verdict: every stale generation merely ended.
    pub(crate) fn none() -> Self {
        Self {
            proven: None,
            unproven: Vec::new(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.proven.is_none() && self.unproven.is_empty()
    }

    /// The rows to file, proof first: the batch proved an exit or
    /// change AND left refusals, in that order; refusals follow in
    /// cause order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Skipped> {
        self.proven.iter().chain(self.unproven.iter())
    }
}

/// Map one pin verdict to proof or unproven reason: `None` (no view
/// retained, or a scripted missing answer) has no custody; `Current`
/// contradicts the stale report; an error is a permission denial when
/// it carries the EACCES/EPERM markers, else a pin failure.
fn classify_generation_state(
    state: Option<Result<OriginalGenerationState, String>>,
) -> Result<GenerationProof, GenerationUnproven> {
    match state {
        Some(Ok(OriginalGenerationState::Exited)) => Ok(GenerationProof {
            kind: ProofKind::ProvenExit,
        }),
        Some(Ok(OriginalGenerationState::Reused)) => Ok(GenerationProof {
            kind: ProofKind::ProvenChange,
        }),
        Some(Ok(OriginalGenerationState::Current)) => Err(GenerationUnproven::Contradicted),
        Some(Err(detail)) if is_permission_denial(&detail) => {
            Err(GenerationUnproven::PermissionDenied)
        }
        Some(Err(_)) => Err(GenerationUnproven::PinFailure),
        None => Err(GenerationUnproven::MissingCustody),
    }
}
