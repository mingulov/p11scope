//! Rendering. Both renderers state the capture's completeness; a report
//! that lost information never reads as complete.

use crate::attach::CapturePolicy;
use crate::metrics::{SlotReport, percentile_ns};
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Evidence {
    /// Function records present in the manifest across walked surfaces.
    pub table_entries: usize,
    /// Unique {object, file_offset} targets planned.
    pub slots: usize,
    /// Probes successfully attached (2 per fully-attached slot).
    pub attached_probes: usize,
    pub attach_failures: Vec<String>,
    /// Slots whose counts belong to a name group, not a single name.
    pub aliased: Vec<Vec<String>>,
    /// Manifest entries with no attachable target, and why.
    pub skipped: Vec<SkippedOut>,
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
    pub semantic_capture_failures: u64,
    pub unregistered_mechanisms: u64,
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
    pub semantic_state_drops: u64,
    pub pending_at_end: u64,
    /// Ring-buffer records rejected by the size check (`events::Drain`).
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
    pub completeness: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SkippedOut {
    pub name: String,
    pub reason: String,
}

impl Evidence {
    /// COMPLETE only when nothing was lost: every planned probe attached,
    /// nothing was skipped, no aliasing ambiguity, no call left in flight,
    /// every surface was fully walked with a successful acquisition, no
    /// vendor interfaces were left undecoded, (profile mode) the ring
    /// buffer neither dropped nor emitted a malformed record, no template
    /// was truncated, no mechanism's parameter decode failed on every
    /// single observed call, and no pinned provider object changed.
    pub fn verdict(&mut self) {
        let surfaces_complete = self
            .surfaces
            .iter()
            .all(|s| s.walk == "full" && s.acquisition == "ok");
        let interface_list_complete = !self.interface_list.starts_with("error:");
        self.completeness = if self.attach_failures.is_empty()
            && self.skipped.is_empty()
            && self.aliased.is_empty()
            && self.in_flight_at_end == 0
            && surfaces_complete
            && self.vendor_interfaces == 0
            && self.event_loss == 0
            && self.start_insert_failures == 0
            && self.unmatched_returns == 0
            && self.rv_update_failures == 0
            && self.cgroup_scope_failures == 0
            && self.semantic_capture_failures == 0
            && self.unregistered_mechanisms == 0
            && self.template_tail_failures == 0
            && self.process_tracking_failures == 0
            && self.process_tracking_evictions == 0
            && self.state_reconciliations == 0
            && self.session_cancel_ambiguities == 0
            && self.session_cancel_unknown_flags == 0
            && self.operation_state_imports == 0
            && self.auth_state_ambiguities == 0
            && self.async_target_failures == 0
            && self.async_orphans == 0
            && self.async_duplicates == 0
            && self.async_evictions == 0
            && self.fork_state_ambiguities == 0
            && self.semantic_state_drops == 0
            && self.pending_at_end == 0
            && self.malformed_records == 0
            && !self.templates_truncated
            && self.shape_decode_total_failures == 0
            && !self.provider_changed
            && interface_list_complete
        {
            "COMPLETE"
        } else {
            "PARTIAL"
        };
    }

    /// A detached perf link stops new invocations but does not wait for BPF
    /// callbacks already executing on another CPU. Until capture has a real
    /// kernel quiescence barrier, a terminal snapshot cannot be COMPLETE.
    pub fn mark_terminal_drain_unproven(&mut self) {
        self.completeness = "PARTIAL";
    }
}

fn label(r: &SlotReport) -> String {
    if r.aliased {
        format!("{} (aliased)", r.names.join("|"))
    } else {
        r.names.join("|")
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

/// One refreshing screen. Rows with no activity are omitted; the evidence
/// line is always present.
pub fn live(
    reports: &[SlotReport],
    ev: &Evidence,
    elapsed: Duration,
    module: &str,
    mode: &str,
    policy: CapturePolicy,
) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "p11scope — {module} — up {:02}:{:02}:{:02} — mode {mode} — privacy={}\n",
        elapsed.as_secs() / 3600,
        (elapsed.as_secs() % 3600) / 60,
        elapsed.as_secs() % 60,
        policy.privacy_mode(),
    ));
    s.push_str(&format!(
        "{:<28} {:>8} {:>6} {:>9} {:>9} {:>9} {:>9}\n",
        "FUNCTION", "CALLS", "ERR", "p50~", "p95~", "p99~", "IN-FLIGHT"
    ));
    let mut rows: Vec<&SlotReport> = reports
        .iter()
        .filter(|r| r.calls > 0 || r.in_flight > 0)
        .collect();
    rows.sort_by(|a, b| b.calls.cmp(&a.calls).then(a.names.cmp(&b.names)));
    for r in rows {
        s.push_str(&format!(
            "{:<28} {:>8} {:>6} {:>9} {:>9} {:>9} {:>9}\n",
            label(r),
            r.calls,
            r.errors,
            fmt_ns(percentile_ns(&r.buckets, 0.50)),
            fmt_ns(percentile_ns(&r.buckets, 0.95)),
            fmt_ns(percentile_ns(&r.buckets, 0.99)),
            r.in_flight
        ));
    }
    s.push_str("(~ = log2-bucket approximation, lower bound)\n");
    let surface_gaps = ev
        .surfaces
        .iter()
        .filter(|s| s.walk != "full" || s.acquisition != "ok")
        .count();
    let state_gaps = ev.process_tracking_failures
        + ev.process_tracking_evictions
        + ev.state_reconciliations
        + ev.session_cancel_ambiguities
        + ev.session_cancel_unknown_flags
        + ev.operation_state_imports
        + ev.auth_state_ambiguities
        + ev.async_target_failures
        + ev.async_orphans
        + ev.async_duplicates
        + ev.async_evictions
        + ev.fork_state_ambiguities
        + ev.semantic_state_drops
        + ev.pending_at_end;
    let mut evidence_line = format!(
        "Evidence: {}/{} probes attached · {} slots · {} aliased · {} skipped · {} in-flight",
        ev.attached_probes,
        ev.slots * 2,
        ev.slots,
        ev.aliased.len(),
        ev.skipped.len(),
        ev.in_flight_at_end,
    );
    if surface_gaps > 0
        || ev.vendor_interfaces > 0
        || ev.event_loss > 0
        || ev.start_insert_failures > 0
        || ev.unmatched_returns > 0
        || ev.rv_update_failures > 0
        || ev.cgroup_scope_failures > 0
        || ev.semantic_capture_failures > 0
        || ev.unregistered_mechanisms > 0
        || ev.template_tail_failures > 0
        || state_gaps > 0
        || ev.malformed_records > 0
        || ev.templates_truncated
        || ev.shape_decode_total_failures > 0
        || ev.provider_changed
    {
        evidence_line.push_str(" ·");
        if surface_gaps > 0 {
            evidence_line.push_str(&format!(" {surface_gaps} surface gaps"));
        }
        if ev.vendor_interfaces > 0 {
            evidence_line.push_str(&format!(" {} vendor interfaces", ev.vendor_interfaces));
        }
        if ev.event_loss > 0 {
            evidence_line.push_str(&format!(" {} events lost", ev.event_loss));
        }
        if ev.start_insert_failures > 0 {
            evidence_line.push_str(&format!(
                " {} start inserts failed",
                ev.start_insert_failures
            ));
        }
        if ev.unmatched_returns > 0 {
            evidence_line.push_str(&format!(" {} unmatched returns", ev.unmatched_returns));
        }
        if ev.rv_update_failures > 0 {
            evidence_line.push_str(&format!(" {} RV updates failed", ev.rv_update_failures));
        }
        if ev.cgroup_scope_failures > 0 {
            evidence_line.push_str(&format!(
                " {} cgroup checks failed",
                ev.cgroup_scope_failures
            ));
        }
        if ev.semantic_capture_failures > 0 {
            evidence_line.push_str(&format!(
                " {} semantic captures failed",
                ev.semantic_capture_failures
            ));
        }
        if ev.unregistered_mechanisms > 0 {
            evidence_line.push_str(&format!(
                " {} unregistered mechanisms",
                ev.unregistered_mechanisms
            ));
        }
        if ev.template_tail_failures > 0 {
            evidence_line.push_str(&format!(
                " {} template tail calls failed",
                ev.template_tail_failures
            ));
        }
        if state_gaps > 0 {
            evidence_line.push_str(&format!(" {state_gaps} semantic state gaps"));
        }
        if ev.malformed_records > 0 {
            evidence_line.push_str(&format!(" {} malformed records", ev.malformed_records));
        }
        if ev.templates_truncated {
            evidence_line.push_str(" templates truncated");
        }
        if ev.shape_decode_total_failures > 0 {
            evidence_line.push_str(&format!(
                " {n} mechanisms never decoded",
                n = ev.shape_decode_total_failures
            ));
        }
        if ev.provider_changed {
            evidence_line.push_str(" provider changed");
        }
    }
    if ev.orphan_ops > 0
        || ev.unmatched_closes > 0
        || ev.shape_decode_failures > 0
        || ev.process_tracking_fallbacks > 0
    {
        evidence_line.push_str(" · ");
        if ev.orphan_ops > 0 {
            evidence_line.push_str(&format!(
                "ℹ {orphan_ops} orphan ops",
                orphan_ops = ev.orphan_ops
            ));
        }
        if ev.unmatched_closes > 0 {
            if ev.orphan_ops > 0 {
                evidence_line.push(' ');
            }
            evidence_line.push_str(&format!(
                "ℹ {unmatched} unmatched closes",
                unmatched = ev.unmatched_closes
            ));
        }
        if ev.shape_decode_failures > 0 {
            if ev.orphan_ops > 0 || ev.unmatched_closes > 0 {
                evidence_line.push(' ');
            }
            evidence_line.push_str(&format!(
                "ℹ {n} shape decode gaps",
                n = ev.shape_decode_failures
            ));
        }
        if ev.process_tracking_fallbacks > 0 {
            evidence_line.push_str(&format!(
                " ℹ {} process trackers using /proc",
                ev.process_tracking_fallbacks
            ));
        }
    }
    evidence_line.push_str(&format!(" → {}\n", ev.completeness));
    s.push_str(&evidence_line);
    s
}

#[derive(Serialize)]
struct FunctionOut {
    names: Vec<String>,
    aliased: bool,
    calls: u64,
    errors: u64,
    pending_returns: u64,
    in_flight: u64,
    latency_ns: LatencyOut,
    rv_counts: std::collections::BTreeMap<String, u64>,
}

#[derive(Serialize)]
struct LatencyOut {
    /// Bucket-approximated; exact values are total/max.
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

/// Per-name call/error/latency counts from the **aggregate BPF maps** —
/// the count authority in every mode (see module docs on `functions`
/// sourcing in both renderers).
fn functions_out(reports: &[SlotReport]) -> Vec<FunctionOut> {
    reports
        .iter()
        .map(|r| FunctionOut {
            names: r.names.clone(),
            aliased: r.aliased,
            calls: r.calls,
            errors: r.errors,
            pending_returns: r
                .rv_counts
                .get(&pkcs11_proxy_ng_types::CkRv::PENDING.0)
                .copied()
                .unwrap_or(0),
            in_flight: r.in_flight,
            latency_ns: latency_out(&r.buckets, r.total_ns, r.max_ns),
            rv_counts: r
                .rv_counts
                .iter()
                .map(|(rv, n)| (format!("0x{rv:016x}"), *n))
                .collect(),
        })
        .collect()
}

pub fn json(reports: &[SlotReport], ev: &Evidence, capture: &CaptureMeta<'_>) -> serde_json::Value {
    serde_json::json!({
        "schema": "pkcs11-scope/observed-profile/v1.1-metrics",
        "capture": { "start": capture.started, "end": capture.ended, "mode": "metrics",
                     "privacy_mode": capture.policy.privacy_mode(),
                     "kernel": capture.kernel,
                     "module": { "path": capture.module, "build_id": capture.build_id } },
        "evidence": ev,
        "functions": functions_out(reports),
    })
}

/// One mechanism id's aggregate stats, event-derived (see module docs):
/// the aggregate maps have no per-mechanism breakdown, only the ring
/// buffer / semantic state machine does.
#[derive(Serialize)]
struct MechanismOut {
    /// Verbatim id — vendor ids survive unchanged, never renamed or dropped.
    mechanism: u64,
    mechanism_hex: String,
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
    /// driven with. See `docs/schema/observed-profile-v1.md` for the
    /// per-shape field layout.
    params: serde_json::Value,
    note: &'static str,
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
/// `docs/schema/observed-profile-v1.md`.
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
    /// `opened + inherited - closed`: sessions still live at capture end.
    balance: u64,
}

/// One mechanism id's calls/errors, scoped to one cgroup —
/// `semantics::MechCallStat` rendered.
#[derive(Serialize)]
struct CgroupMechOut {
    mechanism: u64,
    mechanism_hex: String,
    calls: u64,
    errors: u64,
}

/// One `cgroup_id`'s breakdown — `semantics::CgroupStat` rendered. Exists
/// so one node-wide attach over a cgroup shared by several containers/pods
/// (e.g. two sharing one overlay2 image layer, hence one inode) can still
/// be split back out per container: see `docs/schema/observed-profile-v1.md`
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
    /// Every event observed with this `cgroup_id`, regardless of kind.
    calls: u64,
    errors: u64,
    /// The subset of `calls` a mechanism could be attributed to.
    mechanisms: Vec<CgroupMechOut>,
}

fn cgroups_out(state: &crate::semantics::State) -> Vec<CgroupOut> {
    let root = std::path::Path::new("/sys/fs/cgroup");
    state
        .cgroups()
        .iter()
        .map(|(&cgroup_id, c)| CgroupOut {
            cgroup_id,
            label: crate::scope::label(root, cgroup_id),
            calls: c.calls,
            errors: c.errors,
            mechanisms: c
                .mechanisms
                .iter()
                .map(|(&mechanism, m)| CgroupMechOut {
                    mechanism,
                    mechanism_hex: format!("0x{mechanism:x}"),
                    calls: m.calls,
                    errors: m.errors,
                })
                .collect(),
        })
        .collect()
}

/// `capture` section fields that aren't derived from `reports`/`ev`/`state`.
pub struct CaptureMeta<'a> {
    pub module: &'a str,
    /// From the manifest's object identity; `None` when unavailable.
    pub build_id: Option<&'a str>,
    pub started: &'a str,
    pub ended: &'a str,
    pub kernel: &'a str,
    pub policy: CapturePolicy,
}

/// The v1 `observed-profile.json` document. `functions` comes from the
/// aggregate maps (count authority); `mechanisms`/`sessions`/`logins`/
/// `cgroups` come from the semantic state machine, the only place that
/// reconstructs mechanism/session/login/cgroup context from the event
/// stream.
pub fn profile_json(
    reports: &[SlotReport],
    ev: &Evidence,
    state: &crate::semantics::State,
    capture: &CaptureMeta,
) -> serde_json::Value {
    let mechanisms: Vec<MechanismOut> = state
        .mechanisms()
        .iter()
        .map(|(id, m)| {
            let combos: Vec<serde_json::Value> = m
                .param_combos
                .iter()
                .filter_map(|(&(sh, p0, p1, p2), &count)| param_combo_json(sh, p0, p1, p2, count))
                .collect();
            let (params, note) = if !capture.policy.uses_unsafe_decoders() {
                (
                    serde_json::Value::Null,
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
                        "this mechanism has a diagnostic parameter shape, but every decode \
                         attempt failed in this capture (see \
                         evidence.shape_decode_total_failures and \
                         evidence.shape_decode_failures); any successfully decoded values would \
                         be unvalidated pointer-derived metadata — never a partial decode",
                    )
                } else {
                    (
                        serde_json::Value::Null,
                        "this mechanism has no published diagnostic parameter shape; \
                         unvalidated pointer-derived decoding was not attempted, never a \
                         partial decode",
                    )
                }
            } else {
                (
                    serde_json::Value::Array(combos),
                    "unvalidated pointer-derived metadata (RSA-PSS hash/MGF/salt, GCM \
                     IV/AAD/tag length); requested values as passed to the operation, never a \
                     partial decode",
                )
            };
            MechanismOut {
                mechanism: *id,
                mechanism_hex: format!("0x{id:x}"),
                ops: m.ops.iter().cloned().collect(),
                calls: m.calls,
                errors: m.errors,
                latency_ns: latency_out(&m.buckets, m.total_ns, m.max_ns),
                params,
                note,
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

    serde_json::json!({
        "schema": "pkcs11-scope/observed-profile/v1.4",
        "capture": {
            "start": capture.started, "end": capture.ended, "mode": "profile",
            "privacy_mode": capture.policy.privacy_mode(),
            "kernel": capture.kernel,
            "module": { "path": capture.module, "build_id": capture.build_id },
        },
        "evidence": ev,
        "functions": functions_out(reports),
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::{LATENCY_BUCKETS, shape};

    fn report(name: &str, calls: u64, in_flight: u64, aliased: bool) -> SlotReport {
        SlotReport {
            names: vec![name.into()],
            aliased,
            calls,
            errors: 0,
            in_flight,
            total_ns: 0,
            max_ns: 0,
            buckets: [0; LATENCY_BUCKETS],
            rv_counts: Default::default(),
        }
    }

    fn ok_surface() -> crate::plan::SurfaceSummary {
        crate::plan::SurfaceSummary {
            source: "legacy_function_list".into(),
            walk: "full".into(),
            acquisition: "ok".into(),
            functions: 68,
        }
    }

    fn evidence() -> Evidence {
        Evidence {
            table_entries: 68,
            slots: 68,
            attached_probes: 136,
            attach_failures: vec![],
            aliased: vec![],
            skipped: vec![],
            in_flight_at_end: 0,
            surfaces: vec![ok_surface()],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
            event_loss: 0,
            start_insert_failures: 0,
            unmatched_returns: 0,
            rv_update_failures: 0,
            cgroup_scope_failures: 0,
            semantic_capture_failures: 0,
            unregistered_mechanisms: 0,
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
            semantic_state_drops: 0,
            pending_at_end: 0,
            malformed_records: 0,
            orphan_ops: 0,
            unmatched_closes: 0,
            shape_decode_failures: 0,
            shape_decode_total_failures: 0,
            templates_truncated: false,
            provider_changed: false,
            completeness: "UNKNOWN",
        }
    }

    #[test]
    fn clean_capture_is_complete() {
        let mut ev = evidence();
        ev.verdict();
        assert_eq!(ev.completeness, "COMPLETE");
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
        assert!(frame.contains("provider changed"), "{frame}");
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

    #[test]
    fn any_gap_forces_partial() {
        for mutate in [
            (|e: &mut Evidence| e.attach_failures.push("boom".into())) as fn(&mut Evidence),
            |e: &mut Evidence| {
                e.skipped.push(SkippedOut {
                    name: "C_X".into(),
                    reason: "null pointer".into(),
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
        // Evidence line shows why a PARTIAL verdict was rendered.
        assert!(
            out.contains("5 events lost"),
            "event_loss must appear in evidence line"
        );
        assert!(
            out.contains("2 malformed records"),
            "malformed_records must appear in evidence line"
        );
        assert!(out.contains("PARTIAL"));
    }

    #[test]
    fn live_view_surfaces_informational_counters_when_nonzero() {
        let mut ev = evidence();
        ev.orphan_ops = 3;
        ev.unmatched_closes = 1;
        ev.verdict();
        let out = live(
            &[report("C_Sign", 10, 0, false)],
            &ev,
            Duration::from_secs(10),
            "/opt/p11.so",
            "profile",
            CapturePolicy::Allowlisted,
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
    fn json_marks_latency_approximate_and_hex_rvs() {
        let mut ev = evidence();
        ev.verdict();
        let mut r = report("C_Sign", 1, 0, false);
        r.rv_counts.insert(0, 1);
        let capture = CaptureMeta {
            module: "/opt/p11.so",
            build_id: Some("aabb"),
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: crate::attach::CapturePolicy::AggregateOnly,
        };
        let v = json(&[r], &ev, &capture);
        assert_eq!(v["schema"], "pkcs11-scope/observed-profile/v1.1-metrics");
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
        let out = live(
            &[],
            &ev,
            Duration::ZERO,
            "/opt/p11.so",
            "profile",
            crate::attach::CapturePolicy::Allowlisted,
        );
        assert!(out.contains("privacy=allowlisted"), "{out}");
        assert!(out.contains("2 unregistered mechanisms"), "{out}");
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
            let out = live(
                &[],
                &evidence(),
                Duration::ZERO,
                "/opt/p11.so",
                "test",
                policy,
            );
            assert!(out.contains(&format!("privacy={label}")), "{out}");
        }
    }

    fn empty_plan() -> crate::plan::AttachPlan {
        crate::plan::AttachPlan {
            slots: vec![],
            modules: vec![],
            skipped: vec![],
            modules_skipped: vec![],
            entries_seen: 0,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
            module_ambiguous: 0,
        }
    }

    #[test]
    fn profile_json_has_every_required_top_level_section() {
        let mut ev = evidence();
        ev.verdict();
        let state = crate::semantics::State::with_policy(
            &empty_plan(),
            crate::attach::CapturePolicy::Allowlisted,
        );
        let capture = CaptureMeta {
            module: "/opt/p11.so",
            build_id: Some("aabb"),
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: crate::attach::CapturePolicy::Allowlisted,
        };
        let v = profile_json(&[], &ev, &state, &capture);

        assert_eq!(v["schema"], "pkcs11-scope/observed-profile/v1.4");
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
                "v1.4 document missing required section {section}"
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
        assert_eq!(v["capture"]["module"]["path"], "/opt/p11.so");
        assert_eq!(v["capture"]["module"]["build_id"], "aabb");
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
        let capture = CaptureMeta {
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: crate::attach::CapturePolicy::Allowlisted,
        };
        let value = profile_json(&[], &ev, &state, &capture);

        assert_eq!(value["mechanisms"][0]["mechanism"], u64::MAX);
        assert_eq!(
            value["mechanisms"][0]["mechanism_hex"],
            "0xffffffffffffffff"
        );
        assert_eq!(value["mechanisms"][0]["params"], serde_json::Value::Null);
        assert!(
            value["mechanisms"][0]["note"]
                .as_str()
                .unwrap()
                .contains("disabled by allowlisted")
        );
        assert_eq!(value["evidence"]["shape_decode_total_failures"], 0);
        assert_eq!(value["evidence"]["completeness"], "COMPLETE");
    }

    #[test]
    fn profile_json_mechanisms_carry_verbatim_id_hex_ops_and_null_params() {
        use p11scope_ebpf_common::{Event, USER_TYPE_NONE};

        let plan = crate::plan::AttachPlan {
            slots: vec![crate::plan::Slot {
                index: 0,
                object: crate::plan::TEST_OBJECT,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
                names: vec!["C_SignInit".into()],
                aliased: false,
                semantics: crate::kinds::descriptor("C_SignInit").unwrap(),
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![crate::plan::ModuleId(0)],
            }],
            ..empty_plan()
        };
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
        let capture = CaptureMeta {
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::Allowlisted,
        };
        let v = profile_json(&[], &ev, &state, &capture);

        let mech = &v["mechanisms"][0];
        assert_eq!(mech["mechanism"], vendor_id);
        assert_eq!(mech["mechanism_hex"], "0x80001042");
        assert_eq!(mech["ops"], serde_json::json!(["sign"]));
        assert_eq!(mech["params"], serde_json::Value::Null);
        assert_eq!(mech["calls"], 1);
        assert_eq!(v["capture"]["module"]["build_id"], serde_json::Value::Null);
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
        crate::plan::AttachPlan {
            slots: vec![crate::plan::Slot {
                index: 0,
                object: crate::plan::TEST_OBJECT,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
                names: vec!["C_SignInit".into()],
                aliased: false,
                semantics: crate::kinds::descriptor("C_SignInit").unwrap(),
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![crate::plan::ModuleId(0)],
            }],
            ..empty_plan()
        }
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
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
        };
        let v = profile_json(&[], &ev, &state, &capture);

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
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
        };
        let v = profile_json(&[], &ev, &state, &capture);

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
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
        };
        let v = profile_json(&[], &ev, &state, &capture);

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
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
        };
        let v = profile_json(&[], &ev, &state, &capture);

        assert_eq!(v["mechanisms"][0]["params"], serde_json::Value::Null);
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
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
        };
        let v = profile_json(&[], &ev, &state, &capture);
        assert_eq!(v["mechanisms"][0]["params"], serde_json::Value::Null);
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
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
        };
        let v = profile_json(&[], &ev, &state, &capture);
        assert_eq!(v["mechanisms"][0]["params"], serde_json::Value::Null);
        assert_eq!(
            v["mechanisms"][0]["note"],
            "this mechanism has no published diagnostic parameter shape; unvalidated \
             pointer-derived decoding was not attempted, never a partial decode"
        );
        assert_eq!(v["evidence"]["completeness"], "COMPLETE");
    }

    fn template_plan() -> crate::plan::AttachPlan {
        crate::plan::AttachPlan {
            slots: vec![crate::plan::Slot {
                index: 0,
                object: crate::plan::TEST_OBJECT,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x20,
                names: vec!["C_FindObjectsInit".into()],
                aliased: false,
                semantics: crate::kinds::descriptor("C_FindObjectsInit").unwrap(),
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![crate::plan::ModuleId(0)],
            }],
            ..empty_plan()
        }
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
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
        };
        let v = profile_json(&[], &ev, &state, &capture);

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
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::UnsafeUnvalidatedMetadata,
        };
        let v = profile_json(&[], &ev, &state, &capture);
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
        let capture = CaptureMeta {
            module: "/opt/p11.so",
            build_id: None,
            started: "t0",
            ended: "t1",
            kernel: "6.8.0",
            policy: CapturePolicy::Allowlisted,
        };
        let v = profile_json(&[], &ev, &state, &capture);

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
}
