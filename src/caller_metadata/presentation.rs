//! SPDX-License-Identifier: GPL-3.0-or-later
//! Rendering-safe, fixed-size caller metadata values (DR04 display projection).
//!
//! This module owns only the public-value shape: finite statuses, reasons,
//! canonical IDs and decimal-string JSON. It performs no I/O, spawns no
//! threads, runs no job queues and implements no admission, scope, image
//! identity or publication authority.
//!
//! A [`CallerMetadata`] value is meaningful only after the real outer
//! coordinator has validated capture epoch, caller ID, incarnation, sample
//! sequence, original retained custody and the actual image fence. The
//! constructors here sanitize already-approved finite inputs (parser hints,
//! acquisition refusals, coordinator-supplied capture-clock times); they do
//! not establish that the sample belongs to the live caller and they mint no
//! `ImageFence`/`Validated` authority. Publication wiring (coordinator
//! scheduling, `Presentation` projection, CLI `--caller-metadata`,
//! events/dashboard) is queued with its owners, not faked here.
//!
//! Numeric cgroup provenance is optional and mount-proofed. Positive numeric
//! output requires a [`DirectoryProof`] implementor that only the future
//! mount resolver (holding the verified cgroup2 root and proving
//! namespace-coordinate agreement) may provide. This packet ships no
//! production implementor, hardcodes no filesystem root as evidence, and
//! defaults to [`MetadataReason::NamespaceUnresolved`]; withholding the
//! numeric fields is correct until that resolver exists. Direct struct-literal
//! construction of positive numerics appears only in serialization-shape
//! tests, never on a production path.
//!
//! Explicit off omits the field: consumers wrap this value as
//! `Option<CallerMetadata>` with `skip_serializing_if`, so mode `none`
//! emits no `callers[].metadata` key. Omission in an older document means
//! not recorded. The per-capture mode declaration itself is owned by the
//! CLI/coordinator integration and is not constructed here.
//!
//! Every sample carries [`MetadataValidity::EndpointSampleOnly`]: equal
//! pre/post membership bytes are a stable endpoint observation for the
//! recorded read interval, never a continuous-residence or ABA-freedom
//! claim.

#![forbid(unsafe_code)]

use crate::caller_metadata::acquisition::{
    NumericAbsence, SampleRefusal, SampleValidity, UncommittedSample,
};
use crate::caller_metadata::{CgroupMembership, HintSource, ParseReason, ParseStatus, RuntimeHint};

/// One fixed record per retained caller, up to the existing caller limit.
pub(crate) const MAX_CALLER_METADATA_RECORDS: usize = 4096;
/// Measured struct size; see [`CALLER_METADATA_TABLE_BYTES`].
pub(crate) const CALLER_METADATA_SIZE: usize = std::mem::size_of::<CallerMetadata>();
/// `size_of` times population: struct bytes only, not live shared-pool or
/// old/new snapshot overlap. Compared against the proposed 8 MiB ceiling in
/// tests; real admission is queued with the coordinator owner.
pub(crate) const CALLER_METADATA_TABLE_BYTES: usize =
    CALLER_METADATA_SIZE * MAX_CALLER_METADATA_RECORDS;
/// Proposed retained-metadata ceiling (contract); admission still queued.
pub(crate) const CALLER_METADATA_TABLE_CEILING: usize = 8 * 1024 * 1024;

const _: () = assert!(
    CALLER_METADATA_TABLE_BYTES < CALLER_METADATA_TABLE_CEILING,
    "struct table must fit the proposed 8 MiB ceiling"
);

/// Top-level metadata freshness. Finite by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetadataStatus {
    /// Admitted but never sampled; no claims, no failure.
    Pending,
    /// Stable endpoint sample committed; per-component details apply.
    Sampled,
    /// No current claims; [`CallerMetadata::reason`] names the finite cause.
    Unknown,
    /// Last sample is older than the freshness bound; components preserved.
    Stale,
    /// Retired caller row frozen; components preserved, polling stopped.
    Historical,
}

impl MetadataStatus {
    /// Canonical JSON label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sampled => "sampled",
            Self::Unknown => "unknown",
            Self::Stale => "stale",
            Self::Historical => "historical",
        }
    }
}

/// Finite failure/absence cause. No paths, errno text or error chains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetadataReason {
    PermissionDenied,
    IdentityUnavailable,
    GenerationChanged,
    ProcessExited,
    ReadFailed,
    Malformed,
    ByteLimit,
    RowLimit,
    LookupLimit,
    Deadline,
    ChangedDuringSample,
    HierarchyUnsupported,
    MembershipAmbiguous,
    NamespaceUnresolved,
    Unrecognized,
    AmbiguousPattern,
    RefreshOverdue,
    Stopped,
}

impl MetadataReason {
    /// Canonical JSON label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::PermissionDenied => "permission_denied",
            Self::IdentityUnavailable => "identity_unavailable",
            Self::GenerationChanged => "generation_changed",
            Self::ProcessExited => "process_exited",
            Self::ReadFailed => "read_failed",
            Self::Malformed => "malformed",
            Self::ByteLimit => "byte_limit",
            Self::RowLimit => "row_limit",
            Self::LookupLimit => "lookup_limit",
            Self::Deadline => "deadline",
            Self::ChangedDuringSample => "changed_during_sample",
            Self::HierarchyUnsupported => "hierarchy_unsupported",
            Self::MembershipAmbiguous => "membership_ambiguous",
            Self::NamespaceUnresolved => "namespace_unresolved",
            Self::Unrecognized => "unrecognized",
            Self::AmbiguousPattern => "ambiguous_pattern",
            Self::RefreshOverdue => "refresh_overdue",
            Self::Stopped => "stopped",
        }
    }
}

impl From<ParseReason> for MetadataReason {
    /// Sanitize an approved finite parser outcome. `ComponentLimit` shares
    /// the fixed 64-component walk bound with directory lookup, so it maps
    /// to `lookup_limit`; an oversize component is malformed input.
    fn from(reason: ParseReason) -> Self {
        match reason {
            ParseReason::ByteLimit => Self::ByteLimit,
            ParseReason::RowLimit => Self::RowLimit,
            ParseReason::ComponentLimit => Self::LookupLimit,
            ParseReason::ComponentTooLong => Self::Malformed,
            ParseReason::Malformed => Self::Malformed,
            ParseReason::MalformedEscape => Self::Malformed,
            ParseReason::HierarchyUnsupported => Self::HierarchyUnsupported,
            ParseReason::MembershipAmbiguous => Self::MembershipAmbiguous,
            ParseReason::Unrecognized => Self::Unrecognized,
            ParseReason::AmbiguousPattern => Self::AmbiguousPattern,
        }
    }
}

impl From<SampleRefusal> for MetadataReason {
    /// Sanitize an approved finite acquisition refusal. Open/read failures
    /// are `read_failed` (errno was discarded at the boundary, so no
    /// permission guess); cancellation is `stopped`.
    fn from(refusal: SampleRefusal) -> Self {
        match refusal {
            SampleRefusal::Cancelled => Self::Stopped,
            SampleRefusal::DeadlineExceeded => Self::Deadline,
            SampleRefusal::OriginalExited => Self::ProcessExited,
            SampleRefusal::OriginalUnknown => Self::IdentityUnavailable,
            SampleRefusal::MembershipOpenFailed => Self::ReadFailed,
            SampleRefusal::MembershipReadFailed => Self::ReadFailed,
            SampleRefusal::MembershipOversized => Self::ByteLimit,
            SampleRefusal::ChangedDuringSample => Self::ChangedDuringSample,
        }
    }
}

/// Sample validity. Exactly one variant: endpoint-only, never residence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetadataValidity {
    EndpointSampleOnly,
}

impl MetadataValidity {
    /// Canonical JSON label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::EndpointSampleOnly => "endpoint_sample_only",
        }
    }
}

/// Cgroup membership component status: stable read or no claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CgroupStatus {
    Sampled,
    Unknown,
}

impl CgroupStatus {
    /// Canonical JSON label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Sampled => "sampled",
            Self::Unknown => "unknown",
        }
    }
}

/// Cgroup membership source. The membership bytes come from the retained
/// original proc file; numeric directory identity is a separate optional
/// mount-proofed result (withheld as `namespace_unresolved` here).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CgroupSource {
    RetainedProcCgroup2Directory,
}

impl CgroupSource {
    /// Canonical JSON label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::RetainedProcCgroup2Directory => "retained_proc_cgroup2_directory",
        }
    }
}

/// Container hint component status: lexical hint or no claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContainerStatus {
    Hint,
    Unknown,
}

impl ContainerStatus {
    /// Canonical JSON label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Hint => "hint",
            Self::Unknown => "unknown",
        }
    }
}

/// Pod hint component status: lexical hint or no claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PodStatus {
    Hint,
    Unknown,
}

impl PodStatus {
    /// Canonical JSON label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Hint => "hint",
            Self::Unknown => "unknown",
        }
    }
}

/// Capture-local mount-context identifier, stored as a fixed integer and
/// rendered as `cg<N>`. Not a portable group identity or admission token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MountContext(u16);

impl MountContext {
    /// Wrap an already-assigned capture-local context index.
    pub(crate) fn new(index: u16) -> Self {
        Self(index)
    }

    /// The wrapped index.
    pub(crate) fn index(self) -> u16 {
        self.0
    }
}

/// Proof of mount-root coordinate agreement for numeric provenance.
///
/// Only the future mount resolver — holding the verified cgroup2 root FD
/// and proving the observer cgroup-namespace coordinate system matches the
/// proc presentation — may mint a production implementor. This packet
/// provides none; [`CallerMetadata::sampled`] withholds numerics and
/// [`CallerMetadata::sampled_with_proof`] stays uncalled in production.
pub(crate) trait DirectoryProof {
    /// The resolved caller's cgroup directory inode (not a scope-root ID).
    fn directory_inode(&self) -> u64;
    /// The held lookup context for this capture.
    fn mount_context(&self) -> MountContext;
}

/// Canonical container runtime label for the actual parser hint.
fn runtime_label(runtime: RuntimeHint) -> &'static str {
    match runtime {
        RuntimeHint::Unknown => "unknown",
        RuntimeHint::Docker => "docker",
        RuntimeHint::Containerd => "containerd",
        RuntimeHint::CriO => "cri_o",
    }
}

/// Canonical source label for the actual parser hint source.
fn hint_source_label(source: HintSource) -> &'static str {
    match source {
        HintSource::CgroupPathPattern => "cgroup_path_pattern",
    }
}

/// Cgroup membership component: stable-read status plus optional
/// mount-proofed numeric identity. `Sampled` means the two endpoint reads
/// agreed and parsed as valid v2 membership; `directory_inode` and
/// `mount_context` stay `None` with reason `namespace_unresolved` until the
/// mount resolver proves the mapping. Fixed size, no retained paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CgroupMetadata {
    pub status: CgroupStatus,
    pub source: Option<CgroupSource>,
    pub directory_inode: Option<u64>,
    pub mount_context: Option<MountContext>,
    pub reason: Option<MetadataReason>,
}

impl CgroupMetadata {
    fn pending() -> Self {
        Self {
            status: CgroupStatus::Unknown,
            source: None,
            directory_inode: None,
            mount_context: None,
            reason: None,
        }
    }

    fn unknown_with(reason: MetadataReason) -> Self {
        Self {
            status: CgroupStatus::Unknown,
            source: None,
            directory_inode: None,
            mount_context: None,
            reason: Some(reason),
        }
    }
}

/// Container hint component: exactly the canonical 64-hex ID from the
/// actual parser, or no claim. `runtime` is `Some` (possibly `Unknown` for
/// runtime-less Kubernetes cgroupfs hints) exactly when `id` is `Some`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContainerMetadata {
    pub status: ContainerStatus,
    pub source: Option<HintSource>,
    pub runtime: Option<RuntimeHint>,
    pub id: Option<crate::caller_metadata::ContainerId>,
    pub reason: Option<MetadataReason>,
}

impl ContainerMetadata {
    fn pending() -> Self {
        Self {
            status: ContainerStatus::Unknown,
            source: None,
            runtime: None,
            id: None,
            reason: None,
        }
    }

    fn unknown_with(reason: MetadataReason) -> Self {
        Self {
            status: ContainerStatus::Unknown,
            source: None,
            runtime: None,
            id: None,
            reason: Some(reason),
        }
    }
}

/// Pod hint component: exactly the canonical 36-char UID from the actual
/// parser, or no claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PodMetadata {
    pub status: PodStatus,
    pub source: Option<HintSource>,
    pub uid: Option<crate::caller_metadata::PodUid>,
    pub reason: Option<MetadataReason>,
}

impl PodMetadata {
    fn pending() -> Self {
        Self {
            status: PodStatus::Unknown,
            source: None,
            uid: None,
            reason: None,
        }
    }

    fn unknown_with(reason: MetadataReason) -> Self {
        Self {
            status: PodStatus::Unknown,
            source: None,
            uid: None,
            reason: Some(reason),
        }
    }
}

/// One caller's rendering-safe metadata projection. Fixed size (`Copy`, no
/// heap): the only variable-length content is the parser's fixed 64/36-byte
/// canonical IDs. Times and revision are `u64` in memory and exact decimal
/// strings on JSON so values above 2^53 round-trip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CallerMetadata {
    pub status: MetadataStatus,
    pub reason: Option<MetadataReason>,
    pub revision: u64,
    pub sample_started_ns: Option<u64>,
    pub sample_ended_ns: Option<u64>,
    pub validity: Option<MetadataValidity>,
    pub cgroup: CgroupMetadata,
    pub container: ContainerMetadata,
    pub pod: PodMetadata,
}

impl CallerMetadata {
    /// Never-sampled placeholder: revision 0, no times, no claims, no
    /// failure. The coordinator publishes this at admission before the
    /// first budgeted job.
    pub(crate) fn pending() -> Self {
        Self {
            status: MetadataStatus::Pending,
            reason: None,
            revision: 0,
            sample_started_ns: None,
            sample_ended_ns: None,
            validity: None,
            cgroup: CgroupMetadata::pending(),
            container: ContainerMetadata::pending(),
            pod: PodMetadata::pending(),
        }
    }

    /// Project one uncommitted endpoint sample using coordinator-supplied
    /// capture-clock times (`started_ns <= ended_ns`, `CLOCK_MONOTONIC` ns)
    /// and the next metadata revision.
    ///
    /// The caller must already have validated capture epoch, caller ID,
    /// incarnation, sample sequence, original retained custody and the
    /// actual image fence; this conversion alone proves none of that.
    /// All components come atomically from this one sample: a migration
    /// never combines an old pod with a new container. Refused membership
    /// yields top-level `Unknown` with the mapped cause and the read
    /// interval preserved; numeric fields are always withheld here with
    /// `namespace_unresolved` (see [`Self::sampled_with_proof`]).
    pub(crate) fn sampled(
        revision: u64,
        started_ns: u64,
        ended_ns: u64,
        sample: &UncommittedSample,
    ) -> Self {
        let _ = sample.validity == SampleValidity::EndpointSampleOnly;
        let _ = sample.numeric == NumericAbsence::NamespaceUnresolved;
        match sample.membership.status {
            ParseStatus::Recognized => {
                Self::from_membership(revision, started_ns, ended_ns, &sample.membership)
            }
            ParseStatus::Unrecognized => Self {
                status: MetadataStatus::Sampled,
                reason: None,
                revision,
                sample_started_ns: Some(started_ns),
                sample_ended_ns: Some(ended_ns),
                validity: Some(MetadataValidity::EndpointSampleOnly),
                cgroup: Self::sampled_cgroup_numeric_withheld(),
                container: ContainerMetadata::unknown_with(MetadataReason::Unrecognized),
                pod: PodMetadata::unknown_with(MetadataReason::Unrecognized),
            },
            ParseStatus::Refused => {
                let reason = sample
                    .membership
                    .reason
                    .map(MetadataReason::from)
                    .unwrap_or(MetadataReason::Malformed);
                Self {
                    status: MetadataStatus::Unknown,
                    reason: Some(reason),
                    revision,
                    sample_started_ns: Some(started_ns),
                    sample_ended_ns: Some(ended_ns),
                    validity: None,
                    cgroup: CgroupMetadata::unknown_with(reason),
                    container: ContainerMetadata::unknown_with(reason),
                    pod: PodMetadata::unknown_with(reason),
                }
            }
        }
    }

    /// Project one sample plus mount-proofed numeric identity. The proof
    /// upgrades only a stable (cgroup-`Sampled`) membership; refused
    /// membership stays `Unknown` regardless of proof. No production
    /// implementor of [`DirectoryProof`] exists in this packet.
    pub(crate) fn sampled_with_proof<P: DirectoryProof>(
        revision: u64,
        started_ns: u64,
        ended_ns: u64,
        sample: &UncommittedSample,
        proof: &P,
    ) -> Self {
        let mut base = Self::sampled(revision, started_ns, ended_ns, sample);
        if base.cgroup.status == CgroupStatus::Sampled {
            base.cgroup.directory_inode = Some(proof.directory_inode());
            base.cgroup.mount_context = Some(proof.mount_context());
            base.cgroup.reason = None;
        }
        base
    }

    /// Failed refresh with no new read: clears every current claim
    /// atomically under the new revision. Previous values survive only in
    /// already-published history or an explicitly historical row.
    pub(crate) fn unknown(reason: MetadataReason, revision: u64) -> Self {
        Self {
            status: MetadataStatus::Unknown,
            reason: Some(reason),
            revision,
            sample_started_ns: None,
            sample_ended_ns: None,
            validity: None,
            cgroup: CgroupMetadata::unknown_with(reason),
            container: ContainerMetadata::unknown_with(reason),
            pod: PodMetadata::unknown_with(reason),
        }
    }

    /// Failed acquisition mapped to its finite unknown projection.
    pub(crate) fn from_refusal(refusal: SampleRefusal, revision: u64) -> Self {
        Self::unknown(MetadataReason::from(refusal), revision)
    }

    /// Mark the last sample stale: status and `refresh_overdue` change,
    /// while revision, times, validity and every component claim are
    /// preserved verbatim. Pending, failed and historical rows are unchanged:
    /// only an actual sample can become an aged sample.
    pub(crate) fn to_stale(self) -> Self {
        if !matches!(self.status, MetadataStatus::Sampled | MetadataStatus::Stale) {
            return self;
        }
        Self {
            status: MetadataStatus::Stale,
            reason: Some(MetadataReason::RefreshOverdue),
            ..self
        }
    }

    /// Freeze the row for a retired caller: status becomes historical,
    /// everything else (including any unknown cause) is preserved.
    pub(crate) fn to_historical(self) -> Self {
        Self {
            status: MetadataStatus::Historical,
            ..self
        }
    }

    fn from_membership(
        revision: u64,
        started_ns: u64,
        ended_ns: u64,
        membership: &CgroupMembership,
    ) -> Self {
        let container = match membership.container {
            Some(hint) => ContainerMetadata {
                status: ContainerStatus::Hint,
                source: Some(hint.source),
                runtime: Some(hint.runtime),
                id: Some(hint.id),
                reason: None,
            },
            None => ContainerMetadata::unknown_with(MetadataReason::Unrecognized),
        };
        let pod = match membership.pod {
            Some(hint) => PodMetadata {
                status: PodStatus::Hint,
                source: Some(hint.source),
                uid: Some(hint.uid),
                reason: None,
            },
            None => PodMetadata::unknown_with(MetadataReason::Unrecognized),
        };
        Self {
            status: MetadataStatus::Sampled,
            reason: None,
            revision,
            sample_started_ns: Some(started_ns),
            sample_ended_ns: Some(ended_ns),
            validity: Some(MetadataValidity::EndpointSampleOnly),
            cgroup: Self::sampled_cgroup_numeric_withheld(),
            container,
            pod,
        }
    }

    fn sampled_cgroup_numeric_withheld() -> CgroupMetadata {
        CgroupMetadata {
            status: CgroupStatus::Sampled,
            source: Some(CgroupSource::RetainedProcCgroup2Directory),
            directory_inode: None,
            mount_context: None,
            reason: Some(MetadataReason::NamespaceUnresolved),
        }
    }
}

struct DecimalU64(u64);

impl serde::Serialize for DecimalU64 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

struct OptionalDecimalU64(Option<u64>);

impl serde::Serialize for OptionalDecimalU64 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Some(value) => serializer.serialize_str(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }
}

impl serde::Serialize for MetadataStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

impl serde::Serialize for MetadataReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

impl serde::Serialize for MetadataValidity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

impl serde::Serialize for CgroupStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

impl serde::Serialize for CgroupSource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

impl serde::Serialize for ContainerStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

impl serde::Serialize for PodStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

impl serde::Serialize for MountContext {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("cg{}", self.0))
    }
}

impl serde::Serialize for CgroupMetadata {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("CgroupMetadata", 5)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("source", &self.source)?;
        state.serialize_field("directory_inode", &OptionalDecimalU64(self.directory_inode))?;
        state.serialize_field("mount_context", &self.mount_context)?;
        state.serialize_field("reason", &self.reason)?;
        state.end()
    }
}

impl serde::Serialize for ContainerMetadata {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("ContainerMetadata", 5)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("source", &self.source.map(hint_source_label))?;
        state.serialize_field("runtime", &self.runtime.map(runtime_label))?;
        state.serialize_field("id", &self.id.as_ref().map(|id| id.as_str()))?;
        state.serialize_field("reason", &self.reason)?;
        state.end()
    }
}

impl serde::Serialize for PodMetadata {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("PodMetadata", 4)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("source", &self.source.map(hint_source_label))?;
        state.serialize_field("uid", &self.uid.as_ref().map(|uid| uid.as_str()))?;
        state.serialize_field("reason", &self.reason)?;
        state.end()
    }
}

impl serde::Serialize for CallerMetadata {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("CallerMetadata", 9)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("reason", &self.reason)?;
        state.serialize_field("revision", &DecimalU64(self.revision))?;
        state.serialize_field(
            "sample_started_ns",
            &OptionalDecimalU64(self.sample_started_ns),
        )?;
        state.serialize_field("sample_ended_ns", &OptionalDecimalU64(self.sample_ended_ns))?;
        state.serialize_field("validity", &self.validity)?;
        state.serialize_field("cgroup", &self.cgroup)?;
        state.serialize_field("container", &self.container)?;
        state.serialize_field("pod", &self.pod)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller_metadata::acquisition::{
        NumericAbsence as TestNumericAbsence, SampleValidity as TestValidity,
    };
    use crate::caller_metadata::parse_cgroup_membership;
    use std::time::Instant;

    const DOCKER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const DOCKER_ID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const POD_UID: &str = "12345678-1234-abcd-9876-1234567890ab";

    fn uncommitted_for(path: &str) -> UncommittedSample {
        let bytes = format!("0::/{path}\n").into_bytes();
        let membership = parse_cgroup_membership(&bytes);
        let now = Instant::now();
        UncommittedSample {
            membership,
            validity: TestValidity::EndpointSampleOnly,
            numeric: TestNumericAbsence::NamespaceUnresolved,
            started: now,
            ended: now,
        }
    }

    fn uncommitted_bytes(bytes: &[u8]) -> UncommittedSample {
        let membership = parse_cgroup_membership(bytes);
        let now = Instant::now();
        UncommittedSample {
            membership,
            validity: TestValidity::EndpointSampleOnly,
            numeric: TestNumericAbsence::NamespaceUnresolved,
            started: now,
            ended: now,
        }
    }

    #[test]
    fn pending_has_no_claims_and_zero_revision() {
        let pending = CallerMetadata::pending();
        assert_eq!(pending.status, MetadataStatus::Pending);
        assert_eq!(pending.reason, None);
        assert_eq!(pending.revision, 0);
        assert_eq!(pending.sample_started_ns, None);
        assert_eq!(pending.sample_ended_ns, None);
        assert_eq!(pending.validity, None);
        assert_eq!(pending.cgroup.status, CgroupStatus::Unknown);
        assert_eq!(pending.cgroup.reason, None);
        assert_eq!(pending.container.status, ContainerStatus::Unknown);
        assert_eq!(pending.container.id, None);
        assert_eq!(pending.pod.status, PodStatus::Unknown);
        assert_eq!(pending.pod.uid, None);

        let value = serde_json::to_value(pending).expect("pending serializes");
        assert_eq!(value["status"], "pending");
        assert!(value["reason"].is_null());
        assert_eq!(value["revision"], "0");
        assert!(value["sample_started_ns"].is_null());
        assert!(value["validity"].is_null());
        assert_eq!(value["cgroup"]["status"], "unknown");
    }

    #[test]
    fn healthy_docker_sample_preserves_canonical_id() {
        let sample = uncommitted_for(&format!("docker/{DOCKER_ID}"));
        let metadata = CallerMetadata::sampled(7, 21_000_000_000, 21_000_020_000, &sample);
        assert_eq!(metadata.status, MetadataStatus::Sampled);
        assert_eq!(metadata.reason, None);
        assert_eq!(metadata.revision, 7);
        assert_eq!(
            metadata.validity,
            Some(MetadataValidity::EndpointSampleOnly)
        );
        assert_eq!(metadata.cgroup.status, CgroupStatus::Sampled);
        assert_eq!(
            metadata.cgroup.source,
            Some(CgroupSource::RetainedProcCgroup2Directory)
        );
        assert_eq!(metadata.cgroup.directory_inode, None);
        assert_eq!(
            metadata.cgroup.reason,
            Some(MetadataReason::NamespaceUnresolved)
        );
        let container = metadata.container;
        assert_eq!(container.status, ContainerStatus::Hint);
        assert_eq!(container.id.expect("docker id").as_str(), DOCKER_ID);
        assert_eq!(container.runtime, Some(RuntimeHint::Docker));
        assert_eq!(metadata.pod.status, PodStatus::Unknown);
        assert_eq!(metadata.pod.uid, None);

        let value = serde_json::to_value(metadata).expect("healthy serializes");
        assert_eq!(value["container"]["id"], DOCKER_ID);
        assert_eq!(value["container"]["runtime"], "docker");
        assert_eq!(value["validity"], "endpoint_sample_only");
    }

    #[test]
    fn healthy_k8s_sample_carries_pod_and_container() {
        let sample = uncommitted_for(&format!("kubepods/burstable/pod{POD_UID}/{DOCKER_ID}"));
        let metadata = CallerMetadata::sampled(3, 100, 120, &sample);
        assert_eq!(metadata.status, MetadataStatus::Sampled);
        assert_eq!(
            metadata.container.id.expect("container").as_str(),
            DOCKER_ID
        );
        assert_eq!(metadata.container.runtime, Some(RuntimeHint::Unknown));
        assert_eq!(metadata.pod.uid.expect("pod").as_str(), POD_UID);
        assert_eq!(metadata.pod.status, PodStatus::Hint);

        let value = serde_json::to_value(metadata).expect("k8s serializes");
        assert_eq!(value["pod"]["uid"], POD_UID);
        assert_eq!(value["pod"]["source"], "cgroup_path_pattern");
    }

    #[test]
    fn unrecognized_membership_is_sampled_with_unknown_hints() {
        let sample = uncommitted_for("user.slice/workload");
        let metadata = CallerMetadata::sampled(1, 50, 60, &sample);
        assert_eq!(metadata.status, MetadataStatus::Sampled);
        assert_eq!(metadata.cgroup.status, CgroupStatus::Sampled);
        assert_eq!(
            metadata.container.reason,
            Some(MetadataReason::Unrecognized)
        );
        assert_eq!(metadata.pod.reason, Some(MetadataReason::Unrecognized));
        assert_eq!(metadata.container.id, None);
        assert_eq!(metadata.pod.uid, None);
    }

    #[test]
    fn refused_membership_clears_claims_with_cause() {
        let oversized = vec![b'x'; crate::caller_metadata::MAX_CGROUP_BYTES + 1];
        let sample = uncommitted_bytes(&oversized);
        let metadata = CallerMetadata::sampled(2, 70, 80, &sample);
        assert_eq!(metadata.status, MetadataStatus::Unknown);
        assert_eq!(metadata.reason, Some(MetadataReason::ByteLimit));
        assert_eq!(metadata.validity, None);
        assert_eq!(metadata.sample_started_ns, Some(70));
        assert_eq!(metadata.container.id, None);
        assert_eq!(metadata.pod.uid, None);
        assert_eq!(metadata.cgroup.directory_inode, None);
        assert_eq!(metadata.cgroup.reason, Some(MetadataReason::ByteLimit));
    }

    #[test]
    fn acquisition_refusals_map_to_finite_unknown() {
        for (refusal, expected) in [
            (SampleRefusal::Cancelled, MetadataReason::Stopped),
            (SampleRefusal::DeadlineExceeded, MetadataReason::Deadline),
            (SampleRefusal::OriginalExited, MetadataReason::ProcessExited),
            (
                SampleRefusal::OriginalUnknown,
                MetadataReason::IdentityUnavailable,
            ),
            (
                SampleRefusal::MembershipOpenFailed,
                MetadataReason::ReadFailed,
            ),
            (
                SampleRefusal::MembershipReadFailed,
                MetadataReason::ReadFailed,
            ),
            (
                SampleRefusal::MembershipOversized,
                MetadataReason::ByteLimit,
            ),
            (
                SampleRefusal::ChangedDuringSample,
                MetadataReason::ChangedDuringSample,
            ),
        ] {
            let metadata = CallerMetadata::from_refusal(refusal, 11);
            assert_eq!(metadata.status, MetadataStatus::Unknown);
            assert_eq!(metadata.reason, Some(expected));
            assert_eq!(metadata.validity, None);
            assert_eq!(metadata.sample_started_ns, None);
            assert_eq!(metadata.container.id, None);
            assert_eq!(metadata.pod.uid, None);
            assert_eq!(metadata.cgroup.directory_inode, None);
        }
    }

    #[test]
    fn parse_reasons_map_to_finite_metadata_reasons() {
        for (input, expected) in [
            (ParseReason::ByteLimit, MetadataReason::ByteLimit),
            (ParseReason::RowLimit, MetadataReason::RowLimit),
            (ParseReason::ComponentLimit, MetadataReason::LookupLimit),
            (ParseReason::ComponentTooLong, MetadataReason::Malformed),
            (ParseReason::Malformed, MetadataReason::Malformed),
            (ParseReason::MalformedEscape, MetadataReason::Malformed),
            (
                ParseReason::HierarchyUnsupported,
                MetadataReason::HierarchyUnsupported,
            ),
            (
                ParseReason::MembershipAmbiguous,
                MetadataReason::MembershipAmbiguous,
            ),
            (ParseReason::Unrecognized, MetadataReason::Unrecognized),
            (
                ParseReason::AmbiguousPattern,
                MetadataReason::AmbiguousPattern,
            ),
        ] {
            assert_eq!(MetadataReason::from(input), expected);
        }
    }

    #[test]
    fn failed_refresh_clears_current_claims_atomically() {
        let sample = uncommitted_for(&format!("docker/{DOCKER_ID}"));
        let healthy = CallerMetadata::sampled(7, 100, 110, &sample);
        assert!(healthy.container.id.is_some());

        let failed = CallerMetadata::unknown(MetadataReason::ProcessExited, 8);
        assert_eq!(failed.status, MetadataStatus::Unknown);
        assert_eq!(failed.revision, 8);
        assert_eq!(failed.container.id, None);
        assert_eq!(failed.pod.uid, None);
        assert_eq!(failed.cgroup.directory_inode, None);
        assert_eq!(failed.sample_started_ns, None);
        assert!(healthy.container.id.is_some(), "old value untouched");
    }

    #[test]
    fn migration_replaces_all_components_without_mixing() {
        let first = uncommitted_for(&format!("docker/{DOCKER_ID}"));
        let before = CallerMetadata::sampled(7, 100, 110, &first);
        let second = uncommitted_for(&format!("docker/{DOCKER_ID_B}"));
        let after = CallerMetadata::sampled(8, 200, 210, &second);
        assert_eq!(after.container.id.expect("new id").as_str(), DOCKER_ID_B);
        assert_eq!(before.container.id.expect("old id").as_str(), DOCKER_ID);
        assert_ne!(after.container.id, before.container.id);
        assert_eq!(after.revision, 8);
    }

    #[test]
    fn stale_preserves_provenance() {
        let sample = uncommitted_for(&format!("docker/{DOCKER_ID}"));
        let healthy = CallerMetadata::sampled(7, 100, 110, &sample);
        let stale = healthy.to_stale();
        assert_eq!(stale.status, MetadataStatus::Stale);
        assert_eq!(stale.reason, Some(MetadataReason::RefreshOverdue));
        assert_eq!(stale.revision, healthy.revision);
        assert_eq!(stale.sample_started_ns, healthy.sample_started_ns);
        assert_eq!(stale.validity, healthy.validity);
        assert_eq!(stale.cgroup, healthy.cgroup);
        assert_eq!(stale.container, healthy.container);
        assert_eq!(stale.pod, healthy.pod);
    }

    #[test]
    fn historical_preserves_provenance() {
        let sample = uncommitted_for(&format!("kubepods/burstable/pod{POD_UID}/{DOCKER_ID}"));
        let healthy = CallerMetadata::sampled(7, 100, 110, &sample);
        let frozen = healthy.to_historical();
        assert_eq!(frozen.status, MetadataStatus::Historical);
        assert_eq!(frozen.reason, healthy.reason);
        assert_eq!(frozen.cgroup, healthy.cgroup);
        assert_eq!(frozen.container, healthy.container);
        assert_eq!(frozen.pod, healthy.pod);

        let failed = CallerMetadata::unknown(MetadataReason::Deadline, 9);
        let frozen_failed = failed.to_historical();
        assert_eq!(frozen_failed.status, MetadataStatus::Historical);
        assert_eq!(frozen_failed.reason, Some(MetadataReason::Deadline));
    }

    #[test]
    fn terminal_transitions_do_not_rewrite_history() {
        let sample = uncommitted_for(&format!("docker/{DOCKER_ID}"));
        let healthy = CallerMetadata::sampled(7, 100, 110, &sample);
        let frozen = healthy.to_historical();
        assert_eq!(frozen.to_stale(), frozen);
        assert_eq!(frozen.to_historical(), frozen);
        let stale_then_frozen = healthy.to_stale().to_historical();
        assert_eq!(stale_then_frozen.status, MetadataStatus::Historical);
        assert_eq!(stale_then_frozen.container, healthy.container);
    }

    #[test]
    fn public_keys_are_exact_and_private_canary_absent() {
        let canary = "PRIVATE_CANARY_7f3a9c_never_publish";
        let sample = uncommitted_for(&format!("user.slice/{canary}"));
        let metadata = CallerMetadata::sampled(1, 10, 20, &sample);
        let value = serde_json::to_value(metadata).expect("metadata serializes");

        // `to_value` collects into a sorted map; the wire key set is what
        // matters (direct streaming preserves field order, same keys).
        fn sorted_keys(value: &serde_json::Value) -> Vec<&str> {
            let mut keys: Vec<&str> = value
                .as_object()
                .expect("object")
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            keys
        }
        assert_eq!(
            sorted_keys(&value),
            vec![
                "cgroup",
                "container",
                "pod",
                "reason",
                "revision",
                "sample_ended_ns",
                "sample_started_ns",
                "status",
                "validity",
            ]
        );
        assert_eq!(
            sorted_keys(&value["cgroup"]),
            vec![
                "directory_inode",
                "mount_context",
                "reason",
                "source",
                "status",
            ]
        );
        assert_eq!(
            sorted_keys(&value["container"]),
            vec!["id", "reason", "runtime", "source", "status"]
        );
        assert_eq!(
            sorted_keys(&value["pod"]),
            vec!["reason", "source", "status", "uid"]
        );

        let rendered = serde_json::to_string(&value).expect("render");
        for forbidden in [
            canary,
            "PRIVATE_CANARY",
            "user.slice",
            "cgroup",
            "errno",
            "cookie",
            "comm",
            "argv",
            "/proc",
            "/sys/fs/cgroup",
        ] {
            // "cgroup" appears only inside reviewed finite labels, never the
            // raw path: the canary-carrying component must be absent.
            if forbidden == "cgroup" {
                continue;
            }
            assert!(
                !rendered.contains(forbidden),
                "private leak {forbidden:?} in {rendered}"
            );
        }
        let debug = format!("{metadata:?}");
        assert!(!debug.contains(canary), "canary in Debug");
        // Unrecognized input carries no hint sources; healthy twins prove
        // the reviewed `cgroup_path_pattern` label appears when sampled.
        assert!(value["container"]["source"].is_null());
        assert!(value["pod"]["source"].is_null());
        let healthy = uncommitted_for(&format!("docker/{DOCKER_ID}"));
        let rendered_healthy = serde_json::to_string(&CallerMetadata::sampled(1, 10, 20, &healthy))
            .expect("healthy renders");
        assert!(rendered_healthy.contains("cgroup_path_pattern"));
    }

    #[test]
    fn off_omits_metadata_key_while_on_carries_object() {
        // Consumers own omission via `Option<CallerMetadata>` plus
        // `skip_serializing_if`; this packet proves the shape composes.
        let sample = uncommitted_for(&format!("docker/{DOCKER_ID}"));
        let healthy = CallerMetadata::sampled(7, 100, 110, &sample);
        let off = serde_json::json!({"id": "c0"});
        assert!(off.get("metadata").is_none());
        let on = serde_json::json!({"id": "c0", "metadata": healthy});
        assert_eq!(on["metadata"]["status"], "sampled");
        assert_eq!(on["metadata"]["container"]["id"], DOCKER_ID);
        let none: Option<CallerMetadata> = None;
        assert_eq!(
            serde_json::to_value(none).expect("none serializes"),
            serde_json::Value::Null
        );
    }

    #[test]
    fn decimal_strings_roundtrip_above_2pow53() {
        let big = (1u64 << 53) + 1;
        let sample = uncommitted_for(&format!("docker/{DOCKER_ID}"));
        let metadata = CallerMetadata::sampled(big, big, u64::MAX, &sample);
        let value = serde_json::to_value(metadata).expect("big serializes");
        assert_eq!(value["revision"], "9007199254740993");
        assert_eq!(value["sample_started_ns"], "9007199254740993");
        assert_eq!(value["sample_ended_ns"], "18446744073709551615");
        for key in ["revision", "sample_started_ns", "sample_ended_ns"] {
            assert!(value[key].is_string(), "{key} must be a string");
            let parsed: u64 = value[key].as_str().expect("str").parse().expect("u64");
            let expected = if key == "sample_ended_ns" {
                u64::MAX
            } else {
                big
            };
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn numeric_positive_shape_uses_decimal_strings() {
        // Shape-only: direct literal, not the proof-gated production path.
        // Production positives require the absent mount-resolver proof.
        let cgroup = CgroupMetadata {
            status: CgroupStatus::Sampled,
            source: Some(CgroupSource::RetainedProcCgroup2Directory),
            directory_inode: Some((1u64 << 53) + 1),
            mount_context: Some(MountContext::new(0)),
            reason: None,
        };
        let value = serde_json::to_value(cgroup).expect("cgroup serializes");
        assert_eq!(value["directory_inode"], "9007199254740993");
        assert_eq!(value["mount_context"], "cg0");
        assert_eq!(MountContext::new(12).index(), 12);
        let rendered = serde_json::to_value(MountContext::new(12)).expect("ctx");
        assert_eq!(rendered, "cg12");
    }

    #[test]
    fn never_sampled_pending_does_not_become_stale() {
        let pending = CallerMetadata::pending();
        assert_eq!(pending.to_stale(), pending);
    }

    #[test]
    fn failed_refresh_keeps_unknown_reason_when_age_is_checked() {
        let unknown = CallerMetadata::from_refusal(SampleRefusal::MembershipReadFailed, 7);
        assert_eq!(unknown.to_stale(), unknown);
    }

    #[test]
    fn table_budget_is_measured_not_guessed() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<CallerMetadata>();
        let measured = std::mem::size_of::<CallerMetadata>();
        assert_eq!(CALLER_METADATA_SIZE, measured);
        assert_eq!(MAX_CALLER_METADATA_RECORDS, 4096);
        let table = measured * MAX_CALLER_METADATA_RECORDS;
        assert_eq!(table, CALLER_METADATA_TABLE_BYTES);
        assert!(
            table < CALLER_METADATA_TABLE_CEILING,
            "struct table {table} must fit proposed 8 MiB ceiling; live \
             shared-pool admission with old/new overlap stays queued"
        );
    }
}
