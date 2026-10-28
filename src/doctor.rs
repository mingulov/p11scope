//! SPDX-License-Identifier: GPL-3.0-or-later
//! `p11scope doctor`: host and target capability probes with a verdict (spec §4.6).
//! Tells an operator *before* a capture attempt which lanes this host and this
//! target support, and what to change when one does not. `probe` runs the real
//! checks (I/O, temporary BPF loads and attaches); `render` and `verdict` are pure
//! functions over the resulting rows, so the table layout and exit-code logic
//! are both testable without any of the probes running.
//!
//! No BPF program stays loaded after `doctor` returns: `bpf_checks` owns the
//! probe handles are locally owned and drop before `probe` returns.

use anyhow::{Context as _, Result};
use aya::programs::ProgramError;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Ok(String),
    Warn(String),
    Fail(String),
    NotApplicable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapabilityTier {
    T0,
    T1,
    T2,
    T3,
    T4,
}

impl CapabilityTier {
    fn label(self) -> &'static str {
        match self {
            Self::T0 => "T0 offline",
            Self::T1 => "T1 host attach",
            Self::T2 => "T2 target readable",
            Self::T3 => "T3 lifecycle",
            Self::T4 => "T4 current full",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CapabilityTierInput {
    host_attach: bool,
    target_readable: Option<bool>,
    lifecycle: bool,
    scope: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CapabilityTierResult {
    tier: CapabilityTier,
    target_assessed: bool,
}

fn classify_capability_tier(input: CapabilityTierInput) -> CapabilityTierResult {
    let tier = if !input.host_attach {
        CapabilityTier::T0
    } else if input.target_readable != Some(true) {
        CapabilityTier::T1
    } else if !input.lifecycle {
        CapabilityTier::T2
    } else if !input.scope {
        CapabilityTier::T3
    } else {
        CapabilityTier::T4
    };
    CapabilityTierResult {
        tier,
        target_assessed: input.target_readable.is_some(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpermOrigin {
    Unknown,
    Seccomp,
    Capability,
}

#[derive(Debug, Clone, Copy)]
pub struct EpermEvidence {
    pub errno: Option<i32>,
    pub seccomp_mode: Option<u32>,
    pub controlled_seccomp_denial: bool,
    pub missing_required_capability: bool,
}

pub fn classify_eperm_origin(evidence: EpermEvidence) -> EpermOrigin {
    let _diagnostic_context_only = evidence.seccomp_mode;
    if evidence.errno != Some(libc::EPERM) {
        return EpermOrigin::Unknown;
    }
    match (
        evidence.controlled_seccomp_denial,
        evidence.missing_required_capability,
    ) {
        (true, false) => EpermOrigin::Seccomp,
        (false, true) => EpermOrigin::Capability,
        _ => EpermOrigin::Unknown,
    }
}

#[cfg(test)]
fn bounded_verifier_diagnostic(verifier_text: &str) -> String {
    const MAX_BYTES: usize = 4096;
    bounded_verifier_diagnostic_with_budget(verifier_text, MAX_BYTES)
}

/// The verifier excerpt within a caller-supplied byte budget: the errno
/// or refusal prefix keeps its own text while the excerpt shrinks, so the
/// whole diagnostic stays within 4096 bytes however the refusal is named.
fn bounded_verifier_diagnostic_with_budget(verifier_text: &str, max_bytes: usize) -> String {
    const PREFIX: &str = "verifier: ";
    const MIDDLE_OMITTED: &str = " [middle omitted] ";

    let escaped = crate::render::escape_controls(verifier_text);
    if escaped.is_empty() {
        return "verifier rejected the embedded program".to_string();
    }
    if PREFIX.len() + escaped.len() <= max_bytes {
        return format!("{PREFIX}{escaped}");
    }
    let excerpt_bytes = max_bytes.saturating_sub(PREFIX.len() + MIDDLE_OMITTED.len());
    let mut head_end = excerpt_bytes / 4;
    while !escaped.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let tail_bytes = excerpt_bytes - head_end;
    let mut tail_start = escaped.len() - tail_bytes;
    while !escaped.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    format!(
        "{PREFIX}{}{MIDDLE_OMITTED}{}",
        &escaped[..head_end],
        &escaped[tail_start..]
    )
}

const CAP_SYS_PTRACE_BIT: u32 = 19;
const CAP_SYS_ADMIN_BIT: u32 = 21;

/// Named diagnostic bits decoded from `CapEff` in `/proc/self/status`.
const CAP_BITS: [(u32, &str); 6] = [
    (2, "CAP_DAC_READ_SEARCH"),
    (CAP_SYS_PTRACE_BIT, "CAP_SYS_PTRACE"),
    (CAP_SYS_ADMIN_BIT, "CAP_SYS_ADMIN"),
    (38, "CAP_PERFMON"),
    (39, "CAP_BPF"),
    (40, "CAP_CHECKPOINT_RESTORE"),
];

/// Every probe this slice's lanes need. Pure formatting is separate (`render`,
/// `verdict`) so the table layout and exit code are testable without any of
/// these probes running.
pub fn probe(pid: Option<u32>, cgroup: Option<&Path>) -> Vec<Check> {
    probe_with_host(pid, cgroup, crate::attach::require_multi_capable_host())
}

fn probe_with_host(
    pid: Option<u32>,
    cgroup: Option<&Path>,
    host: crate::attach::MultiHostVerdict,
) -> Vec<Check> {
    let held = |bit: u32| read_cap_eff().is_ok_and(|mask| mask & (1u64 << bit) != 0);
    let mut checks = vec![
        kernel_release_check(),
        btf_check(),
        lockdown_check(),
        paranoid_check(held(CAP_SYS_ADMIN_BIT), host.is_ok()),
        sysctl_check(
            "kernel.yama.ptrace_scope",
            "/proc/sys/kernel/yama/ptrace_scope",
            1,
            "same-uid non-descendants need CAP_SYS_PTRACE",
            // Yama 1 and 2 yield to CAP_SYS_PTRACE; 3 forbids attach to all.
            Some(SysctlLift {
                capability: "CAP_SYS_PTRACE",
                up_to: 2,
                held: held(CAP_SYS_PTRACE_BIT),
            }),
        ),
        capabilities_check(),
        pid_namespace_check(crate::pidns::numbering(), pid.is_some()),
        object_capture_check(),
    ];
    checks.extend(bpf_checks(host));
    let attach_preflight = attach_preflight_checks(pid, cgroup);
    let capture_lane = !checks
        .iter()
        .chain(attach_preflight.iter())
        .any(|c| is_capture_row(&c.name) && matches!(c.status, Status::Fail(_)));
    checks.extend(live_discovery_checks(pid, capture_lane));
    checks.push(match pid {
        Some(pid) => target_readability_check(pid),
        None => not_applicable("target readability", "no --pid"),
    });
    checks.push(match pid {
        Some(pid) => proc_maps_check(pid),
        None => not_applicable("/proc/<pid>/maps", "no --pid"),
    });
    checks.push(match pid {
        Some(pid) => proc_mem_check(pid),
        None => not_applicable("/proc/<pid>/mem", "no --pid"),
    });
    checks.push(cgroup_version_check_at(
        Path::new("/sys/fs/cgroup/cgroup.controllers"),
        Path::new("/proc/self/cgroup"),
    ));
    checks.push(match cgroup {
        Some(cgroup) => cgroup_check(cgroup),
        None => not_applicable("cgroup path", "no --cgroup"),
    });
    checks.extend(attach_preflight);
    checks
}

/// Name of the inventory-object load row: load-and-release through the
/// real preparation path, never attached.
const INVENTORY_PREFLIGHT_ROW: &str = "inventory program preflight";

/// Load-and-release preflight of the embedded Inventory object:
/// `inventory --system` needs it, and doctor once reported OK on kernels
/// where it failed to load. The prepared object drops before return, so
/// no program, link, or map survives the probe.
fn inventory_preflight_check() -> Check {
    let name = INVENTORY_PREFLIGHT_ROW.to_string();
    let budget = match crate::capacity::inventory_endpoint_budget(None) {
        Ok(budget) => budget,
        Err(reason) => {
            return Check {
                name,
                status: Status::Fail(reason),
            };
        }
    };
    match crate::attach::PreparedInventory::prepare(
        crate::attach::Scope::Pid(std::process::id()),
        budget,
        crate::attach::AttachBackend::Singles,
    ) {
        Ok(prepared) => {
            drop(prepared);
            Check {
                name,
                status: Status::Ok("available".into()),
            }
        }
        Err(error) => Check {
            name,
            status: Status::Fail(format_preflight_error(error.as_ref())),
        },
    }
}

fn attach_preflight_checks(pid: Option<u32>, cgroup: Option<&Path>) -> Vec<Check> {
    let self_pid = std::process::id();
    let host = crate::attach::Session::preflight(&crate::attach::Scope::Pid(self_pid));
    let lifecycle = host.as_ref().is_ok_and(|fact| fact.lifecycle);
    let host_scope = host.as_ref().is_ok_and(|fact| fact.scope);
    let host_check = match host {
        Ok(_) => Check {
            name: "host program preflight".into(),
            status: Status::Ok("available".into()),
        },
        Err(error) => Check {
            name: "host program preflight".into(),
            status: Status::Fail(format_preflight_error(error.as_ref())),
        },
    };
    let status = |available| {
        if available {
            Status::Ok("available".into())
        } else {
            Status::Warn("unavailable".into())
        }
    };
    let scope = match (pid, cgroup) {
        (None, None) => not_applicable("scope preflight", "no requested scope"),
        (pid, cgroup) => {
            let pid_scope = pid.is_none_or(|pid| {
                if pid == self_pid {
                    host_scope
                } else {
                    crate::attach::Session::preflight(&crate::attach::Scope::Pid(pid))
                        .is_ok_and(|fact| fact.scope)
                }
            });
            let cgroup_scope = cgroup.is_none_or(|path| {
                crate::scope::capture_cgroup(path)
                    .and_then(|scope| crate::attach::Session::preflight(&scope))
                    .is_ok_and(|fact| fact.scope)
            });
            Check {
                name: "scope preflight".into(),
                status: status(pid_scope && cgroup_scope),
            }
        }
    };
    vec![
        host_check,
        inventory_preflight_check(),
        Check {
            name: "lifecycle preflight".into(),
            status: status(lifecycle),
        },
        scope,
    ]
}

/// Name of the observer's PID namespace row (DR-K8S-1/2).
const PID_NAMESPACE_ROW: &str = "PID namespace";

/// Whether `/proc` PIDs are the kernel's PIDs (DR-K8S-1/2). Outside the
/// initial PID namespace every PID-scoped capture is refused
/// (`pid-namespace-mismatch`) and cgroup/system captures stay `PARTIAL`
/// (`pid_namespace`), so this row warns, and FAILs when `--pid` was asked.
fn pid_namespace_check(numbering: &crate::pidns::PidNumbering, pid_requested: bool) -> Check {
    use crate::pidns::{ObserverPidNs, ProcView};
    let status = if numbering.agrees() {
        Status::Ok("initial — /proc PIDs are the kernel's PIDs".to_string())
    } else {
        let mut why = Vec::new();
        if let ObserverPidNs::Unknown(reason) = &numbering.observer {
            why.push(reason.clone());
        }
        match &numbering.proc_view {
            ProcView::Foreign(reason) => why.push(format!("/proc numbering foreign: {reason}")),
            ProcView::Unserved(reason) => why.push(format!(
                "/proc numbering foreign, no entry for this process: {reason}"
            )),
            ProcView::Own => {}
        }
        let why = if why.is_empty() {
            String::new()
        } else {
            format!(" ({})", why.join("; "))
        };
        let detail = if matches!(numbering.proc_view, ProcView::Unserved(_)) {
            format!(
                "{}{why} — this observer cannot read its own /proc/self, so every capture \
                 except inventory --system is refused ({}; inventory --system warns \
                 and carries the pid namespace gap)",
                numbering.observer.label(),
                crate::pidns::MISMATCH_CODE,
            )
        } else {
            format!(
                "{}{why} — the kernel numbers tasks in the initial PID namespace: --pid, run and \
                 inventory --pid are refused ({}); --cgroup/--system captures stay PARTIAL \
                 (pid_namespace / proc_namespace_mismatch)",
                numbering.observer.label(),
                crate::pidns::MISMATCH_CODE,
            )
        };
        // An unserved /proc refuses every capture except inventory
        // --system, so the row fails for every scope, not only a --pid
        // one: doctor cannot know which capture the operator will run.
        if pid_requested || matches!(numbering.proc_view, ProcView::Unserved(_)) {
            Status::Fail(detail)
        } else {
            Status::Warn(detail)
        }
    };
    Check {
        name: PID_NAMESPACE_ROW.into(),
        status,
    }
}

fn is_pid_namespace_row(name: &str) -> bool {
    name == PID_NAMESPACE_ROW
}

fn not_applicable(name: &str, reason: &str) -> Check {
    Check {
        name: name.to_string(),
        status: Status::NotApplicable(reason.to_string()),
    }
}

#[cfg(test)]
pub(crate) fn parse_major_minor(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn kernel_release_check() -> Check {
    let name = "kernel release".to_string();
    let status = match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(raw) => {
            let release = raw.trim().to_string();
            Status::Ok(format!(
                "{release} (informational; live support is capability-tested)"
            ))
        }
        Err(e) => Status::Warn(format!("/proc/sys/kernel/osrelease: {e}")),
    };
    Check { name, status }
}

fn btf_check() -> Check {
    let path = "/sys/kernel/btf/vmlinux";
    let status = match std::fs::File::open(path) {
        Ok(_) => Status::Ok(String::new()),
        Err(e) => Status::Warn(format!("{path}: {e}")),
    };
    Check {
        name: format!("BTF {path}"),
        status,
    }
}

fn parse_lockdown(content: &str) -> String {
    content
        .split_whitespace()
        .find(|word| word.starts_with('[') && word.ends_with(']'))
        .map(|word| word.trim_matches(|c| c == '[' || c == ']').to_string())
        .unwrap_or_else(|| content.trim().to_string())
}

fn lockdown_check() -> Check {
    let path = "/sys/kernel/security/lockdown";
    let status = match std::fs::read_to_string(path) {
        Ok(content) => Status::Ok(parse_lockdown(&content)),
        // Absent means no lockdown LSM loaded — genuinely "none", not unknown.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Status::Ok("none".to_string()),
        Err(e) => Status::Warn(format!("{path}: {e}")),
    };
    Check {
        name: "lockdown".to_string(),
        status,
    }
}

/// Shared shape for the two `/proc/sys` integer sysctls this slice reads:
/// `Ok` below `warn_at`, `Warn` at or above it (with the actionable reason),
/// and `Ok` when the file is absent — an absent restriction is permissive,
/// not a problem.
fn sysctl_check(
    name: &str,
    path: &str,
    warn_at: i64,
    warn_msg: &str,
    lift: Option<SysctlLift>,
) -> Check {
    Check {
        name: name.to_string(),
        status: sysctl_status(std::fs::read_to_string(path), path, warn_at, warn_msg, lift),
    }
}

/// The capability that lifts a restrictive sysctl value (for values up to
/// `up_to`), and whether this process holds it. A restriction this process
/// is exempt from does not limit its captures, so it is not a warning — and
/// must not fail `--extra-strict` for `sudo p11scope doctor` on a stock
/// Ubuntu host (`perf_event_paranoid=4`, `ptrace_scope=1`) (HIGH-5).
struct SysctlLift {
    capability: &'static str,
    up_to: i64,
    held: bool,
}

fn sysctl_status(
    read: std::io::Result<String>,
    path: &str,
    warn_at: i64,
    warn_msg: &str,
    lift: Option<SysctlLift>,
) -> Status {
    match read {
        Ok(content) => {
            let trimmed = content.trim();
            match trimmed.parse::<i64>() {
                Ok(v) if v >= warn_at => match lift {
                    Some(lift) if lift.held && v <= lift.up_to => Status::Ok(format!(
                        "{v} — {warn_msg}; this process has {}",
                        lift.capability
                    )),
                    _ => Status::Warn(format!("{v} — {warn_msg}")),
                },
                Ok(v) => Status::Ok(v.to_string()),
                Err(_) => Status::Warn(format!("{trimmed}: unparsable value")),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Status::Ok("not present".to_string()),
        Err(e) => Status::Warn(format!("{path}: {e}")),
    }
}

/// The `kernel.perf_event_paranoid` row, backend-aware. Static uprobe-multi
/// links on an eligible host never call
/// `perf_event_open`, so a restrictive paranoid does not limit them
/// (measured 136/136 at paranoid=4 with `CAP_BPF`+`CAP_PERFMON`,
/// `scripts/matrix/verify-fork-scope.sh` Part 2). But the uretprobe
/// self-probe and live-discovery loader/export probes are per-probe
/// `perf_event` uprobes on every kernel, and at paranoid ≥ 3 those need
/// `CAP_SYS_ADMIN` (DR-K8S-3), so the row warns there unless it is held.
/// The Multi fact comes from the functional load/self-link, never a release
/// number. A failed fact does not promise the per-offset fallback is eligible.
fn paranoid_check(held_sysadmin: bool, multi_capable: bool) -> Check {
    Check {
        name: "kernel.perf_event_paranoid".to_string(),
        status: paranoid_status(
            std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid"),
            "/proc/sys/kernel/perf_event_paranoid",
            held_sysadmin,
            multi_capable,
        ),
    }
}

/// Pure over the sysctl read and the backend decision, mirroring
/// `sysctl_status` outcomes: on a multi-capable kernel a value below 3 is
/// `Ok` and 3 or above warns unless CAP_SYS_ADMIN is held (the per-probe
/// self-probe and live-discovery probes); without a proven Multi fact the
/// restrictive perf-event rule stays visible as a separate diagnostic.
fn paranoid_status(
    read: std::io::Result<String>,
    path: &str,
    held_sysadmin: bool,
    multi_capable: bool,
) -> Status {
    if !multi_capable {
        return sysctl_status(
            read,
            path,
            3,
            "uprobes need CAP_SYS_ADMIN on this host",
            // Every paranoid level leaves perf events to CAP_SYS_ADMIN.
            Some(SysctlLift {
                capability: "CAP_SYS_ADMIN",
                up_to: i64::MAX,
                held: held_sysadmin,
            }),
        );
    }
    match read {
        Ok(content) => {
            let trimmed = content.trim();
            match trimmed.parse::<i64>() {
                Ok(v) if v >= crate::uretprobe_hazard::PERF_OPEN_RESTRICT_PARANOID => {
                    let limit = "does not gate static uprobe-multi links, but refuses every \
                                 perf_event_open without CAP_SYS_ADMIN (CAP_PERFMON does not \
                                 lift it): the uretprobe self-probe (--cgroup, --system, run, \
                                 confined --pid targets) and live-discovery loader/export probes";
                    if held_sysadmin {
                        Status::Ok(format!("{v} — {limit}; this process has CAP_SYS_ADMIN"))
                    } else {
                        Status::Warn(format!("{v} — {limit} need CAP_SYS_ADMIN"))
                    }
                }
                Ok(v) => Status::Ok(format!(
                    "{v} — does not limit uprobe attach for CAP_PERFMON; CAP_BPF+CAP_PERFMON \
                     suffice"
                )),
                Err(_) => Status::Warn(format!("{trimmed}: unparsable value")),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Status::Ok("not present".to_string()),
        Err(e) => Status::Warn(format!("{path}: {e}")),
    }
}

/// Decodes the bits this slice cares about from a raw `CapEff` mask,
/// alphabetically — a pure function so capability decoding is testable
/// without reading the real `/proc/self/status`.
fn decode_caps(mask: u64) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = CAP_BITS
        .iter()
        .filter(|(bit, _)| mask & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect();
    names.sort_unstable();
    names
}

fn read_cap_eff() -> Result<u64, String> {
    let content = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("/proc/self/status: {e}"))?;
    let hex = content
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .ok_or_else(|| "/proc/self/status: no CapEff line".to_string())?;
    u64::from_str_radix(hex.trim(), 16).map_err(|e| format!("CapEff {hex:?}: {e}"))
}

fn raw_errno(mut error: &(dyn std::error::Error + 'static)) -> Option<i32> {
    loop {
        if let Some(error) = error.downcast_ref::<std::io::Error>()
            && error.raw_os_error().is_some()
        {
            return error.raw_os_error();
        }
        error = error.source()?;
    }
}

fn bounded_error_detail(error: &(dyn std::error::Error + 'static)) -> String {
    bounded_error_text(&error.to_string())
}

fn bounded_error_text(message: &str) -> String {
    const MAX_BYTES: usize = 512;
    let escaped = crate::render::escape_controls(message);
    if escaped.len() <= MAX_BYTES {
        return escaped.into_owned();
    }
    let mut end = MAX_BYTES;
    while !escaped.is_char_boundary(end) {
        end -= 1;
    }
    escaped[..end].to_string()
}

/// Pushes a chain fragment unless its text is already present: wrappers
/// such as aya's `map error: {0}` repeat their source's Display, and
/// joining the whole chain would print it twice. Only verbatim-present
/// text is skipped, so no information is lost.
fn push_chain_fragment(context: &mut Vec<String>, fragment: String) {
    if fragment.is_empty() || context.join(": ").ends_with(&fragment) {
        return;
    }
    context.push(fragment);
}

fn format_preflight_error(mut error: &(dyn std::error::Error + 'static)) -> String {
    let mut context = Vec::new();
    let detail = loop {
        if let Some(
            program @ ProgramError::LoadError {
                verifier_log,
                io_error,
                ..
            },
        ) = error.downcast_ref::<ProgramError>()
        {
            // Never format LoadError itself: its Display includes the complete
            // verifier log. Keep the independently bounded excerpt instead,
            // naming a budget refusal for what it is — and, for any other
            // refusal, the errno the log alone does not name.
            let prefix = match crate::attach::verifier_budget_refusal_errno_name(program) {
                // ENOSPC proves only that the verifier log filled during a
                // very long check, not what the verifier concluded.
                Some("ENOSPC") => "verifier log filled during a very long check (ENOSPC); \
                 usually the complexity limit; "
                    .to_string(),
                Some(errno_name) => {
                    format!("verifier budget refused the program ({errno_name}); ")
                }
                None => {
                    let errno_text = match io_error.raw_os_error() {
                        Some(errno) => match crate::attach::load_refusal_errno_name(errno) {
                            Some(name) => format!("{name} (os error {errno})"),
                            None => format!("os error {errno}"),
                        },
                        None => "unknown errno".to_string(),
                    };
                    format!("BPF_PROG_LOAD failed with {errno_text}; ")
                }
            };
            let budget = 4096usize.saturating_sub(prefix.len());
            let excerpt =
                bounded_verifier_diagnostic_with_budget(&verifier_log.to_string(), budget);
            break format!("{prefix}{excerpt}");
        }
        let Some(source) = error.source() else {
            break format_operation_error(error);
        };
        push_chain_fragment(&mut context, bounded_error_detail(error));
        error = source;
    };
    if context.is_empty() {
        detail
    } else {
        // Bound the whole stage prefix as well as each individual fragment.
        // The errno or verifier excerpt retains its own budget and cannot be
        // crowded out by a long outer context.
        let stages = context.join(": ");
        if stages.ends_with(&detail) {
            bounded_error_text(&stages)
        } else {
            format!("{}: {detail}", bounded_error_text(&stages))
        }
    }
}

fn format_operation_error_with(
    error: &(dyn std::error::Error + 'static),
    seccomp_mode: Option<u32>,
    controlled_seccomp_denial: bool,
    missing_required_capability: bool,
) -> String {
    let origin = classify_eperm_origin(EpermEvidence {
        errno: raw_errno(error),
        seccomp_mode,
        controlled_seccomp_denial,
        missing_required_capability,
    });
    let label = match origin {
        EpermOrigin::Unknown => "",
        EpermOrigin::Seccomp => " (origin: controlled seccomp denial)",
        EpermOrigin::Capability => " (origin: missing required capability)",
    };
    format!("{}{label}", bounded_error_detail(error))
}

fn format_operation_error(error: &(dyn std::error::Error + 'static)) -> String {
    format_operation_error_with(error, None, false, false)
}

/// The object-capture row's by-design warning in P0 (stub) builds.
const OBJECT_CAPTURE_P0: &str = "not enabled in this P0 build";

/// Byte scope, identical on every host, read from the embedded object:
/// FULL bytes wire capture, P0 (stub) bytes warn by design (a
/// [`BUILD_LIMIT_ROWS`] member). A stale or mismatched object fails the
/// row with the same reason capture setup refuses with.
/// OD33/R-50: v0.5.0 reads attributes but reports key operations only
/// from 0.6.0, and the OK detail says so.
fn object_capture_check() -> Check {
    match crate::attach::checked_embedded_flavor() {
        Err(error) => Check {
            name: "object-attribute capture".into(),
            status: Status::Fail(format!("{error:#}")),
        },
        Ok(flavor) if !flavor.stubbed => Check {
            name: "object-attribute capture".into(),
            status: Status::Ok(
                "enabled (read only; key operations are reported from 0.6.0)".into(),
            ),
        },
        Ok(_) => Check {
            name: "object-attribute capture".into(),
            status: Status::Warn(OBJECT_CAPTURE_P0.into()),
        },
    }
}

fn capabilities_check() -> Check {
    // A read/parse failure is reported, never coerced into "(none)" — an
    // unmeasured mask must not read the same as a genuinely empty one.
    let status = match read_cap_eff() {
        Ok(mask) => {
            let names = decode_caps(mask);
            Status::Ok(if names.is_empty() {
                "(none)".to_string()
            } else {
                names.join(" ")
            })
        }
        Err(e) => Status::Warn(e),
    };
    Check {
        name: "effective capabilities".to_string(),
        status,
    }
}

/// Uses capture's complete preparation and mandatory lifecycle ownership. The
/// diagnostic link shares Session teardown ordering.
fn bpf_checks(host: crate::attach::MultiHostVerdict) -> Vec<Check> {
    bpf_checks_with_seccomp(
        crate::attach::Session::diagnostic(),
        attach_self_probe,
        uretprobe_seccomp_check,
        || uprobe_multi_check(host),
    )
}

fn bpf_checks_with_seccomp<T>(
    setup: anyhow::Result<T>,
    diagnostic: impl FnOnce(&mut T) -> Result<(), String>,
    seccomp: impl FnOnce() -> Check,
    multi: impl FnOnce() -> Check,
) -> Vec<Check> {
    let setup_succeeded = setup.is_ok();
    let mut checks = bpf_checks_with(setup, diagnostic);
    checks.push(if setup_succeeded {
        seccomp()
    } else {
        not_applicable(
            "uretprobe vs seccomp",
            "unavailable: shared capture setup refused; active probe skipped",
        )
    });
    // The independent scratch proof is needed even if full capture setup fails.
    checks.push(multi());
    checks
}

/// The singles self-probe row: `(self)` because the anchor is the
/// observer's own libc mapping, falling back to its own entry point for
/// static linkage — never libc alone. One constant for the producer and
/// the tier classifier, so the two cannot drift again (F-09).
const UPROBE_ATTACH_SELF_ROW: &str = "uprobe attach (self)";

fn bpf_checks_with<T>(
    setup: anyhow::Result<T>,
    diagnostic: impl FnOnce(&mut T) -> Result<(), String>,
) -> Vec<Check> {
    match setup {
        Ok(mut session) => {
            let status = match diagnostic(&mut session) {
                Ok(()) => Status::Ok("attached and detached".into()),
                Err(error) => Status::Fail(error),
            };
            vec![
                Check {
                    name: "BPF map create".into(),
                    status: Status::Ok(String::new()),
                },
                Check {
                    name: UPROBE_ATTACH_SELF_ROW.into(),
                    status,
                },
            ]
        }
        Err(error) => vec![
            Check {
                name: "BPF map create".into(),
                status: Status::Fail(format_preflight_error(error.as_ref())),
            },
            Check {
                name: UPROBE_ATTACH_SELF_ROW.into(),
                status: Status::Fail("skipped: shared capture setup failed".into()),
            },
        ],
    }
}

/// Whether a uretprobe on this kernel would kill a seccomp-confined target.
///
/// Informational, and deliberately absent from `capability_tier`: an affected
/// kernel captures perfectly well from every unconfined target, so this is a
/// property of the *pairing* of kernel and target, not a capability this host
/// lacks. Folding an environmental fact into the tier is exactly the mistake
/// `c1e1192` removed when it dropped the `uname` row from it.
///
/// `Warn`, not `Fail`, for the same reason: nothing here is broken, but an
/// operator pointing this host at a hardened process needs to know first.
fn uretprobe_seccomp_check() -> Check {
    let status = match crate::uretprobe_hazard::probe_kernel() {
        crate::uretprobe_hazard::KernelVerdict::Clean => Status::Ok(
            "the trampoline's syscall is exempt from seccomp; confined targets are safe"
                .to_string(),
        ),
        crate::uretprobe_hazard::KernelVerdict::Affected(how) => Status::Warn(format!(
            "attaching a uretprobe kills a seccomp-confined target on this kernel ({how}); \
             captures against confined targets are refused unless \
             --allow-uretprobe-on-confined-target is given"
        )),
        crate::uretprobe_hazard::KernelVerdict::Unknown(why) => {
            Status::Warn(format!("could not be determined: {why}"))
        }
        // DR-K8S-3: the same fact-based cause the capture's refusal names
        // (a restrictive perf_event_paranoid, a dropped CAP_SYS_ADMIN), never
        // a blanket "rerun with sudo".
        crate::uretprobe_hazard::KernelVerdict::NotPermitted(why) => Status::Warn(format!(
            "not assessed: {}",
            crate::uretprobe_hazard::not_permitted_message(
                &why,
                crate::uretprobe_hazard::PrivilegeFacts::current(),
            )
        )),
        // A broken observer build was never assessed: fail with the plain
        // gate message, not an unknown-kernel warning.
        crate::uretprobe_hazard::KernelVerdict::FlavorMismatch(why) => Status::Fail(why),
    };
    Check {
        name: "uretprobe vs seccomp".to_string(),
        status,
    }
}

/// Resolve the anchor (own libc, else own entry point), then give the
/// concrete link to Session.
fn attach_self_probe(session: &mut crate::attach::Session) -> Result<(), String> {
    let (anchor_path, offset) = self_probe_anchor().map_err(|error| format!("{error:#}"))?;
    session
        .attach_diagnostic_probe(&anchor_path, offset)
        .map_err(|e| format!("{e:#}"))?;
    session.detach_producers().map_err(|e| format!("{e:#}"))
}

/// The required host fact is the same bounded load/self-link used by capture.
/// It does not measure entry or return delivery.
fn uprobe_multi_check(host: crate::attach::MultiHostVerdict) -> Check {
    Check {
        name: "uprobe-multi attach (own libc)".to_string(),
        status: match host {
            Ok(_) => Status::Ok(
                "scratch program loaded; self-link attached and detached (delivery unmeasured)"
                    .into(),
            ),
            Err(refusal) => Status::Fail(refusal.to_string()),
        },
    }
}

/// What the live-discovery lanes need from the target's dynamic loader, read
/// with nothing but ordinary opens: whether the PT_INTERP loader could be
/// bound at all, whether it defines an executable `_dl_debug_state`, and
/// whether it defines `_r_debug` for the bounded live state read.
///
/// Every failure collapses to the negative classification. Nothing about
/// *which* loader this is may reach the row (design §9.3, §10.1), so this
/// deliberately returns three booleans and never an error string.
fn loader_facts(pid: Option<u32>) -> (bool, bool, bool) {
    let unbound = (false, false, false);
    // With no `--pid` the honest subject is this host as the observer sees it:
    // its own PT_INTERP is the build a capture on this host would bind.
    let executable = match pid {
        Some(pid) => format!("/proc/{pid}/exe"),
        None => "/proc/self/exe".to_string(),
    };
    let Ok(file) = std::fs::File::open(&executable) else {
        return unbound;
    };
    let Ok(snapshot) = p11scope_manifest::elf::ElfSnapshot::read(&file) else {
        return unbound;
    };
    let Some(interpreter) = snapshot.interpreter() else {
        return unbound;
    };
    let interpreter = PathBuf::from(std::ffi::OsString::from(
        String::from_utf8_lossy(interpreter).into_owned(),
    ));
    let Ok(loader) = std::fs::File::open(&interpreter) else {
        return unbound;
    };
    let Ok(loader) = p11scope_manifest::elf::ElfSnapshot::read(&loader) else {
        return unbound;
    };
    let hook = loader
        .defined_symbol("_dl_debug_state")
        .ok()
        .flatten()
        .is_some_and(|hook| loader.is_executable_offset(hook.file_offset));
    let state_bytes = match loader.abi() {
        p11scope_manifest::elf::ElfAbi::Lp64 => 28,
        p11scope_manifest::elf::ElfAbi::Ilp32 => 16,
    };
    let state = loader
        .defined_symbol_virtual_address("_r_debug", state_bytes)
        .ok()
        .flatten()
        .is_some();
    (true, hook, state)
}

/// The eight finite live-discovery classifications of design §10.1. Each
/// detail is exactly one word from its frozen vocabulary, never the identity
/// or the proof behind it.
fn live_discovery_checks(pid: Option<u32>, capture_lane: bool) -> Vec<Check> {
    let (bound, hook, state) = loader_facts(pid);
    let finite = |ok: bool, yes: &str, no: &str| {
        if ok {
            Status::Ok(yes.to_string())
        } else {
            // A degraded live lane is a warning: it makes complete timing
            // unavailable without making every capture lane fatal (§10.1).
            Status::Warn(no.to_string())
        }
    };
    // The compiled-in timing catalog is exactly empty (D3 amendment §3), so a
    // bound debug-state context is `unproven` and everything else is `none`.
    // No context can reach `qualified_pre_constructor`/`known_pre_relocation`.
    let timing = || Status::Warn(if hook { "unproven" } else { "none" }.to_string());
    vec![
        Check {
            name: "target loader build".into(),
            status: finite(bound, "bound", "unbound"),
        },
        Check {
            name: "debug-state hook".into(),
            status: finite(hook, "available", "unavailable"),
        },
        Check {
            name: "loader timing (initial_set)".into(),
            status: timing(),
        },
        Check {
            name: "loader timing (dlopen)".into(),
            status: timing(),
        },
        Check {
            name: "loader-state live read".into(),
            status: finite(state, "available", "unavailable"),
        },
        Check {
            // Bounded `bpf_probe_read_user` in the current task: it needs the
            // same program load the capture lane needs, and nothing more.
            name: "live export reads".into(),
            status: finite(capture_lane, "available", "unavailable"),
        },
        Check {
            // Never eligible while the catalog is empty: attach-first closure
            // cannot prove the observed event was the first relevant one.
            name: "run initial-set capture".into(),
            status: Status::Warn("none".into()),
        },
        Check {
            name: "pause".into(),
            status: Status::Ok(format!(
                "never default; explicit auto|always {} arm here",
                if capture_lane { "can" } else { "cannot" }
            )),
        },
    ]
}

fn own_libc_path() -> Result<PathBuf, String> {
    let bytes = std::fs::read("/proc/self/maps").map_err(|e| format!("/proc/self/maps: {e}"))?;
    libc_path_in_maps(&bytes)
        .ok_or_else(|| "no executable libc.so mapping in /proc/self/maps".to_string())
}

/// The executable `libc.so` mapping in one maps snapshot, if the observer
/// maps libc at all. A statically linked observer maps none — that is a
/// build fact, not a failure, and the self-probe falls back to the entry
/// point below instead of reporting it as one.
fn libc_path_in_maps(bytes: &[u8]) -> Option<PathBuf> {
    let entries = p11scope_manifest::maps::parse_maps(bytes).ok()?;
    entries.into_iter().find_map(|entry| {
        if entry.permissions[2] != b'x' {
            return None;
        }
        let raw = entry.raw_path?;
        let text = String::from_utf8_lossy(&raw).into_owned();
        text.contains("libc.so").then(|| PathBuf::from(text))
    })
}

/// Where the self-probe attaches: the observer's own libc (dynamic builds)
/// at `getpid`, else the observer's own entry point (static builds, which
/// map no libc). Either site only proves attach works — the probe is dropped
/// immediately without ever firing.
pub(crate) fn self_probe_anchor() -> Result<(PathBuf, u64)> {
    if let Ok(libc) = own_libc_path() {
        let file =
            std::fs::File::open(&libc).with_context(|| format!("open {}", libc.display()))?;
        let offset = p11scope_manifest::elf::symbol_file_offset(&file, "getpid")
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| anyhow::anyhow!("getpid not exported by {}", libc.display()))?;
        return Ok((libc, offset));
    }
    let exe = std::fs::read_link("/proc/self/exe").context("/proc/self/exe")?;
    let file = std::fs::File::open(&exe).with_context(|| format!("open {}", exe.display()))?;
    let offset = p11scope_manifest::elf::entry_file_offset(&file).map_err(anyhow::Error::msg)?.ok_or_else(|| {
        anyhow::anyhow!(
            "entry point outside every loaded segment of {}; a stripped static build has no anchor",
            exe.display()
        )
    })?;
    Ok((exe, offset))
}

/// Pure seam for the five independent facts behind `R`. Capability bits and
/// path spellings are intentionally absent: every fact is an observed target
/// operation against one retained process generation.
pub fn target_readability_proven<E>(
    operations: impl IntoIterator<Item = std::result::Result<(), E>>,
) -> bool {
    operations.into_iter().all(|result| result.is_ok())
}

fn assess_target_readability(pid: u32) -> Result<usize, &'static str> {
    use p11scope_manifest::maps::{MapIndex, MappedPath, ObjectKey, Resolved};

    let view = crate::process::ProcessView::open(crate::process::ProcessViewId(0), pid)
        .map_err(|_| "generation unavailable")?;
    let root = format!("/proc/{pid}/root");
    let maps_opened = view
        .run_while_same(|| std::fs::read(format!("/proc/{pid}/maps")))
        .map_err(|_| "generation changed")
        .and_then(|result| result.map_err(|_| "maps unavailable"));
    let maps = maps_opened.as_ref().map_err(|reason| *reason)?;
    let entries = p11scope_manifest::maps::parse_maps(maps).map_err(|_| "maps invalid")?;
    let index = MapIndex::new(&entries).map_err(|_| "maps invalid")?;
    let mem_opened = view
        .run_while_same(|| std::fs::File::open(format!("/proc/{pid}/mem")))
        .map_err(|_| "generation changed")
        .and_then(|result| result.map_err(|_| "mem unavailable"));
    let _mem = mem_opened.as_ref().map_err(|reason| *reason)?;
    let root_opened = view
        .run_while_same(|| std::fs::File::open(&root))
        .map_err(|_| "generation changed")
        .and_then(|result| result.map_err(|_| "root unavailable"));
    let _root = root_opened.as_ref().map_err(|reason| *reason)?;

    let mut executable_objects = BTreeMap::<ObjectKey, PathBuf>::new();
    for entry in index
        .entries()
        .iter()
        .filter(|entry| entry.permissions[2] == b'x' && entry.inode != 0)
    {
        match index.resolve(entry.start) {
            Resolved::File {
                path: MappedPath::Usable(path),
                device,
                inode,
                ..
            } => {
                executable_objects
                    .entry(ObjectKey { device, inode })
                    .or_insert(path);
            }
            Resolved::File { .. } | Resolved::Anonymous | Resolved::Unmapped => {
                return Err("executable identity unavailable");
            }
        }
    }

    let hooks = crate::discovery::hooks::HookRegistry::builtin();
    let wanted = hooks.names();
    let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
    let provider_identities_opened = (|| {
        let mut providers = 0usize;
        for (expected, path) in executable_objects {
            let target_path = Path::new(&root).join(
                path.strip_prefix("/")
                    .map_err(|_| "executable identity unavailable")?,
            );
            let (file, actual) =
                crate::discovery::identity::open_view_object(&view, &target_path, &mut budget)
                    .map_err(|_| "executable identity unavailable")?;
            // On pre-6.8 kernels an overlayfs fd and its mappings legitimately
            // carry different keys (overlay vs backing device); the
            // self-mapping probe asks the kernel how it renders this exact fd
            // before refusing.
            if !crate::discovery::identity::opened_file_matches_maps(
                &file,
                actual,
                expected,
                &mut budget,
                &crate::discovery::identity::KernelSelfMappingProbe,
            ) {
                return Err("executable identity mismatch");
            }
            if !p11scope_manifest::elf::exports_matching(&file, &wanted)
                .map_err(|_| "executable identity unreadable")?
                .is_empty()
            {
                providers += 1;
            }
        }
        Ok(providers)
    })();
    let providers = *provider_identities_opened
        .as_ref()
        .map_err(|reason| *reason)?;
    let generation_stable = view
        .still_the_same()
        .then_some(())
        .ok_or("generation changed");
    if !target_readability_proven([
        generation_stable.as_ref().map(|_| ()).map_err(|_| ()),
        maps_opened.as_ref().map(|_| ()).map_err(|_| ()),
        mem_opened.as_ref().map(|_| ()).map_err(|_| ()),
        root_opened.as_ref().map(|_| ()).map_err(|_| ()),
        provider_identities_opened
            .as_ref()
            .map(|_| ())
            .map_err(|_| ()),
    ]) {
        return Err("generation changed");
    }
    Ok(providers)
}

fn target_readability_check(pid: u32) -> Check {
    let status = match assess_target_readability(pid) {
        Ok(providers) => Status::Ok(format!(
            "stable generation; maps/mem/root and {providers} provider identities opened"
        )),
        Err(reason) => Status::Fail(reason.to_string()),
    };
    Check {
        name: "target readability".to_string(),
        status,
    }
}

fn short_errno(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(libc::EACCES) => "EACCES".to_string(),
        Some(libc::EPERM) => "EPERM".to_string(),
        Some(libc::ESRCH) => "ESRCH".to_string(),
        Some(libc::ENOENT) => "ENOENT".to_string(),
        _ => error.to_string(),
    }
}

fn proc_maps_check(pid: u32) -> Check {
    let name = format!("/proc/{pid}/maps");
    let status = match std::fs::File::open(&name) {
        Ok(_) => Status::Ok(String::new()),
        Err(e) => Status::Fail(format!(
            "{} — module discovery unavailable for this target",
            short_errno(&e)
        )),
    };
    Check { name, status }
}

fn proc_mem_check(pid: u32) -> Check {
    let name = format!("/proc/{pid}/mem");
    let status = match std::fs::File::open(&name) {
        Ok(_) => Status::Ok(String::new()),
        Err(e) => Status::Fail(format!(
            "{} — memory scan unavailable for this target",
            short_errno(&e)
        )),
    };
    Check { name, status }
}

/// Unified hierarchy ⟺ the root `cgroup.controllers` file exists (a v2
/// mount) and our own `/proc/self/cgroup` carries the unified `0::/` entry.
/// BPF cgroup attach is v2-only at the kernel level, so anything else fails
/// loudly here instead of surfacing a raw attach error later.
fn unified_hierarchy(controllers: &Path, self_cgroup: &Path) -> bool {
    let controllers_present = std::fs::metadata(controllers).is_ok_and(|meta| meta.is_file());
    let self_unified = std::fs::read_to_string(self_cgroup)
        .is_ok_and(|content| content.lines().any(|line| line.starts_with("0::/")));
    controllers_present && self_unified
}

fn cgroup_version_check_at(controllers: &Path, self_cgroup: &Path) -> Check {
    let status = if unified_hierarchy(controllers, self_cgroup) {
        Status::Ok("unified (cgroup v2)".to_string())
    } else {
        Status::Fail(
            "cgroup v2 required: no unified hierarchy (need \
             /sys/fs/cgroup/cgroup.controllers and a 0::/ self entry)"
                .to_string(),
        )
    };
    Check {
        name: "cgroup version".to_string(),
        status,
    }
}

fn cgroup_check(cgroup: &Path) -> Check {
    if !unified_hierarchy(
        Path::new("/sys/fs/cgroup/cgroup.controllers"),
        Path::new("/proc/self/cgroup"),
    ) {
        return Check {
            name: "cgroup path".to_string(),
            status: Status::Fail(
                "cgroup v2 required: no unified hierarchy for --cgroup attach".to_string(),
            ),
        };
    }
    // The same acceptance rule a capture applies (M-3), so doctor and
    // capture never disagree about a `--cgroup` path.
    if let Err(error) = crate::scope::capture_cgroup(cgroup) {
        return Check {
            name: "cgroup path".to_string(),
            status: Status::Fail(format!("{error:#}")),
        };
    }
    let status = match std::fs::metadata(cgroup) {
        Ok(meta) if meta.is_dir() => {
            let procs = cgroup.join("cgroup.procs");
            match std::fs::metadata(&procs) {
                Ok(_) => Status::Ok(String::new()),
                Err(e) => Status::Fail(format!("{}: {e}", procs.display())),
            }
        }
        Ok(_) => Status::Fail(format!("{}: not a directory", cgroup.display())),
        Err(e) => Status::Fail(format!("{}: {e}", cgroup.display())),
    };
    Check {
        name: "cgroup path".to_string(),
        status,
    }
}

const NAME_WIDTH: usize = 34;
const STATUS_WIDTH: usize = 6;

fn status_word(status: &Status) -> &'static str {
    match status {
        Status::Ok(_) => "ok",
        Status::Warn(_) => "warn",
        Status::Fail(_) => "FAIL",
        Status::NotApplicable(_) => "n/a",
    }
}

fn status_detail(status: &Status) -> &str {
    match status {
        Status::Ok(s) | Status::Warn(s) | Status::Fail(s) | Status::NotApplicable(s) => s,
    }
}

fn is_capture_row(name: &str) -> bool {
    name == "BPF map create"
        || name == "host program preflight"
        // `inventory --system` needs the Inventory object: its load row
        // gates the exit code with the other capture rows.
        || name == INVENTORY_PREFLIGHT_ROW
        // A flavor mismatch fails the object row, and no capture lane can
        // work then, so it gates the exit code with the other capture rows.
        || name == "object-attribute capture"
        || name == "uprobe-multi attach (own libc)"
        || name.starts_with("uprobe attach")
}

fn is_scan_row(name: &str) -> bool {
    name.starts_with("/proc/") && name.ends_with("/mem")
}

fn is_target_row(name: &str) -> bool {
    name == "target readability"
}

fn is_cgroup_row(name: &str) -> bool {
    name == "cgroup path"
}

/// The one live-discovery lane that gates the exit code: a `run` that asked
/// for initial-set capture and cannot have it is a requested lane that is
/// unavailable (§10.1). The timing rows warn instead — a degraded timing value
/// must not make every capture lane fatal.
fn is_run_capture_row(name: &str) -> bool {
    name == "run initial-set capture"
}

fn scan_pid_suffix(name: &str) -> String {
    name.strip_prefix("/proc/")
        .and_then(|rest| rest.strip_suffix("/mem"))
        .map(|pid| format!(" for pid {pid}"))
        .unwrap_or_default()
}

fn capability_tier(checks: &[Check]) -> CapabilityTierResult {
    let row_ok = |name: &str| {
        checks
            .iter()
            .find(|check| check.name == name)
            .is_some_and(|check| matches!(check.status, Status::Ok(_)))
    };
    let target_readable = checks
        .iter()
        .find(|check| check.name == "target readability")
        .and_then(|check| match &check.status {
            Status::Ok(_) => Some(true),
            Status::Fail(_) | Status::Warn(_) => Some(false),
            Status::NotApplicable(_) => None,
        });
    classify_capability_tier(CapabilityTierInput {
        // Deliberately not `row_ok("kernel release")`. That row compares
        // `uname` against a floor, and a version number is a proxy for the
        // capability; the required functional rows below test the operations:
        // they create a map, load every program, and attach a real uprobe.
        // RHEL 9 reports 5.14 with the cookie and perf-link support
        // backported, and was measured attaching 136/136 probes while this
        // function called it T0 offline on the strength of the version string
        // alone. A kernel that genuinely lacks the support fails these three
        // rows, so nothing is lost by trusting them instead.
        host_attach: row_ok("BPF map create")
            && row_ok(UPROBE_ATTACH_SELF_ROW)
            && row_ok("host program preflight")
            && row_ok("uprobe-multi attach (own libc)"),
        target_readable,
        lifecycle: row_ok("lifecycle preflight"),
        // A requested --pid lane refused for its PID namespace is not a
        // preflighted scope, whatever the filter publication proved.
        scope: row_ok("scope preflight")
            && !checks.iter().any(|check| {
                is_pid_namespace_row(&check.name) && matches!(check.status, Status::Fail(_))
            }),
    })
}

fn capability_tier_line(capability: CapabilityTierResult) -> String {
    format!(
        "capability tier: {} (target {})",
        capability.tier.label(),
        if capability.target_assessed {
            "assessed"
        } else {
            "unassessed"
        }
    )
}

/// The inventory part of the verdict line names the failure's reason, not
/// the BPF map the loader happened to attempt first: aya drains its map
/// table (a per-process `HashMap`) in an unspecified order, so two runs
/// on one host fail on different maps for the same refusal. Backticked
/// spans carry those unstable map names; the per-row diagnostic keeps
/// them, while the verdict drops them and stays categorical. The output
/// is always shorter than the input, so the row's bound still holds.
fn verdict_inventory_reason(detail: &str) -> String {
    let mut out = String::with_capacity(detail.len());
    let mut rest = detail;
    while let Some(open) = rest.find('`') {
        let (head, tail) = rest.split_at(open);
        let Some(close) = tail[1..].find('`') else {
            // Unbalanced backtick: keep the remainder verbatim.
            out.push_str(rest);
            rest = "";
            break;
        };
        let after = &tail[1 + close + 1..];
        // Drop a space left dangling before ':' or the end, so
        // "create map `X`:" reads "create map:".
        let head = head
            .strip_suffix(' ')
            .filter(|_| after.starts_with(':') || after.is_empty())
            .unwrap_or(head);
        out.push_str(head);
        rest = after;
    }
    out.push_str(rest);
    out
}

fn verdict_line(checks: &[Check]) -> String {
    // The inventory lane gets its own part below: an inventory-only
    // failure must not read as "capture unavailable" when the Detailed
    // lanes work. Exit gating is unchanged (`verdict` still counts the
    // inventory row as a requested lane).
    let capture_ok = !checks.iter().any(|c| {
        is_capture_row(&c.name)
            && c.name != INVENTORY_PREFLIGHT_ROW
            && matches!(c.status, Status::Fail(_))
    });
    let mut parts = vec![format!(
        "capture {}",
        if capture_ok {
            "available"
        } else {
            "unavailable"
        }
    )];
    if let Some(check) = checks.iter().find(|c| c.name == INVENTORY_PREFLIGHT_ROW)
        && let Status::Fail(detail) = &check.status
    {
        parts.push(format!(
            "inventory capture unavailable ({})",
            verdict_inventory_reason(detail)
        ));
    }

    if let Some(check) = checks.iter().find(|c| is_scan_row(&c.name)) {
        match &check.status {
            Status::NotApplicable(_) => {}
            Status::Fail(detail) => parts.push(format!(
                "memory scan unavailable{} ({detail})",
                scan_pid_suffix(&check.name)
            )),
            _ => parts.push("memory scan available".to_string()),
        }
    }
    if let Some(check) = checks.iter().find(|c| is_target_row(&c.name)) {
        match &check.status {
            Status::NotApplicable(_) => {}
            Status::Fail(detail) => parts.push(format!("target unavailable ({detail})")),
            _ => parts.push("target available".to_string()),
        }
    }
    if let Some(check) = checks.iter().find(|c| is_cgroup_row(&c.name)) {
        match &check.status {
            Status::NotApplicable(_) => {}
            Status::Fail(detail) => parts.push(format!("cgroup scope unavailable ({detail})")),
            _ => parts.push("cgroup scope available".to_string()),
        }
    }
    if let Some(check) = checks.iter().find(|c| is_pid_namespace_row(&c.name))
        && let Status::Warn(detail) | Status::Fail(detail) = &check.status
    {
        parts.push(format!("PID scope unavailable ({detail})"));
    }
    if let Some(check) = checks.iter().find(|c| is_run_capture_row(&c.name)) {
        match &check.status {
            Status::NotApplicable(_) => {}
            Status::Fail(detail) => parts.push(format!("run capture unavailable ({detail})")),
            // The probe reports Warn("none") while the timing catalog is
            // empty ("never eligible"): that is not availability — but `run`
            // itself still works. What `none` limits is the proof that the
            // child's initial provider set was captured from its first
            // constructor, which keeps every `run` report PARTIAL (HIGH-5).
            Status::Warn(detail) => parts.push(format!(
                "run initial-set capture {detail} (run reports stay PARTIAL; run itself works)"
            )),
            Status::Ok(_) => parts.push("run capture available".to_string()),
        }
    }
    format!("verdict: {}", parts.join("; "))
}

fn is_requested_lane(name: &str) -> bool {
    is_capture_row(name)
        || is_target_row(name)
        || is_scan_row(name)
        || is_cgroup_row(name)
        || is_run_capture_row(name)
        || is_pid_namespace_row(name)
}

/// Explain the existing requested-lane verdict and capability tier before the
/// diagnostic rows. This is pure over probe results; missing rows cannot prove
/// a target or scope ready, and copy does not change qualification or exits.
pub fn summary(checks: &[Check], extra_strict: bool) -> String {
    let assessed = checks.iter().any(|check| {
        is_requested_lane(&check.name) && !matches!(check.status, Status::NotApplicable(_))
    });
    let conclusion = if extra_strict && verdict_extra_strict(checks) != 0 {
        "extra-strict qualification refused"
    } else if !assessed {
        "no requested lanes assessed"
    } else if extra_strict {
        "extra-strict qualification passed"
    } else if verdict(checks) == 0 {
        "requested-lane checks passed"
    } else {
        "requested lane unavailable"
    };
    let mut out = format!("Doctor: {conclusion}.\n");
    let _ = writeln!(out, "{}", capability_tier_line(capability_tier(checks)));
    let assessment = |name: &str| match checks
        .iter()
        .find(|check| check.name == name)
        .map(|check| &check.status)
    {
        Some(Status::Ok(_)) => "available",
        Some(Status::Warn(_) | Status::Fail(_)) => "unavailable",
        Some(Status::NotApplicable(_)) | None => "unassessed",
    };
    let target = assessment("target readability");
    let scope = if checks
        .iter()
        .any(|check| is_pid_namespace_row(&check.name) && matches!(check.status, Status::Fail(_)))
    {
        "unavailable"
    } else {
        match assessment("cgroup path") {
            "unavailable" => "unavailable",
            _ => assessment("scope preflight"),
        }
    };
    let _ = writeln!(out, "Target: {target}.\nScope: {scope}.");
    let problem = if extra_strict {
        extra_strict_violations(checks).first().copied()
    } else {
        checks
            .iter()
            .find(|check| is_requested_lane(&check.name) && matches!(check.status, Status::Fail(_)))
            .or_else(|| {
                checks
                    .iter()
                    .find(|check| matches!(check.status, Status::Warn(_)) && !is_build_limit(check))
            })
    };
    let next = match problem {
        Some(check) => next_step(check),
        None if scope == "unassessed" =>
            "choose --pid <PID> or --cgroup <PATH> to assess a target scope".into(),
        None => "choose a capture mode with p11scope profile --help; these checks do not prove provider activity".into(),
    };
    let _ = writeln!(out, "Next: {}.", crate::render::escape_controls(&next));
    out
}

fn next_step(check: &Check) -> String {
    let detail = status_detail(&check.status);
    // These suffixes come from the existing independent EPERM classifier.
    // Seccomp mode or CapEff alone must never select a causal recommendation.
    if detail.ends_with("(origin: controlled seccomp denial)") {
        return "review the specific denied operation in the launcher seccomp policy".into();
    }
    if detail.ends_with("(origin: missing required capability)") {
        return "review the required capabilities for the failed operation".into();
    }
    if is_pid_namespace_row(&check.name) {
        return "use an observer in the initial PID namespace with a matching /proc view".into();
    }
    if is_cgroup_row(&check.name) || check.name == "cgroup version" {
        return "choose a cgroup v2 directory with cgroup.procs and check access to it".into();
    }
    if is_target_row(&check.name) || is_scan_row(&check.name) {
        if detail == "generation unavailable" {
            return "verify the target is live and readable, then rerun p11scope doctor --pid <PID>".into();
        }
        if ["generation changed", "ESRCH", "ENOENT"]
            .iter()
            .any(|cause| detail.contains(cause))
        {
            return "select a live target and rerun p11scope doctor --pid <PID>".into();
        }
        return "check access to the target's maps, memory, root and provider files; rerun p11scope doctor --pid <PID>".into();
    }
    if detail.contains("EPERM") || detail.contains("Operation not permitted") {
        return "denial cause is unclassified; inspect the failed operation and launcher policy before changing privileges".into();
    }
    if is_capture_row(&check.name)
        && ["unsupported", "not supported", "ENOSYS", "EOPNOTSUPP"]
            .iter()
            .any(|cause| detail.contains(cause))
    {
        return "use a host with the required BPF/uprobe support; check the failed feature below"
            .into();
    }
    if detail.contains("verifier:") {
        return "review the verifier diagnostic and use a build supported by this kernel".into();
    }
    format!(
        "review {} in the checks below before retrying qualification or capture",
        check.name
    )
}

/// Summary first, then every diagnostic row and the unchanged lane verdict.
/// Pure: no probe or lookup runs while formatting.
pub fn render(checks: &[Check]) -> String {
    render_with_mode(checks, false)
}

fn render_with_mode(checks: &[Check], extra_strict: bool) -> String {
    let mut out = summary(checks, extra_strict);
    for check in checks {
        let dots = NAME_WIDTH.saturating_sub(check.name.chars().count());
        let word = status_word(&check.status);
        let detail = status_detail(&check.status);
        // Details carry target-controlled bytes (paths, errors): a newline
        // must never let one check forge a second output line (SYSPLAN
        // residual F-59). The same escape the capture renderers use.
        let flattened = detail.replace('\n', "\\n");
        let detail = crate::render::escape_controls(&flattened);
        let _ = write!(out, "{} {} {word}", check.name, ".".repeat(dots));
        if !detail.is_empty() {
            let pad = STATUS_WIDTH.saturating_sub(word.len());
            let _ = write!(out, "{}{detail}", " ".repeat(pad));
        }
        out.push('\n');
    }
    let _ = writeln!(out, "{}", verdict_line(checks));
    out
}

/// Exit code: 0 when no requested lane reports `Fail` (capture, target,
/// scan, cgroup, and run initial-set capture rows), 1 otherwise. Takes no
/// pid/cgroup parameter: a lane that was not requested is always recorded
/// `Status::NotApplicable`, never `Fail`, so "any `Fail` in a requested
/// lane" reduces to "any `Fail` among these fixed row names".
pub fn verdict(checks: &[Check]) -> i32 {
    let gated = checks.iter().any(|c| {
        (is_capture_row(&c.name)
            || is_target_row(&c.name)
            || is_scan_row(&c.name)
            || is_cgroup_row(&c.name)
            || is_run_capture_row(&c.name)
            || is_pid_namespace_row(&c.name))
            && matches!(c.status, Status::Fail(_))
    });
    if gated { 1 } else { 0 }
}

/// Rows whose warning is a limit of this build, identical on every host:
/// the compiled-in loader timing catalog is exactly empty (D3 amendment §3),
/// so the two timing rows can be no better than `unproven`/`none` and an
/// owned `run` can never prove it captured its child's initial provider set
/// (`run initial-set capture: none`, which keeps `run` reports `PARTIAL`).
/// No host can clear them, so `--extra-strict` — a host qualification —
/// lists them without counting them (HIGH-5). Only these exact by-design
/// values are exempt: any other value (a future catalog) counts as usual.
const BUILD_LIMIT_ROWS: [(&str, &[&str]); 4] = [
    ("loader timing (initial_set)", &["unproven", "none"]),
    ("loader timing (dlopen)", &["unproven", "none"]),
    ("run initial-set capture", &["none"]),
    ("object-attribute capture", &[OBJECT_CAPTURE_P0]),
];

fn is_build_limit(check: &Check) -> bool {
    let Status::Warn(detail) = &check.status else {
        return false;
    };
    BUILD_LIMIT_ROWS
        .iter()
        .any(|(name, values)| check.name == *name && values.contains(&detail.as_str()))
}

/// Extra-strict qualification (T2): every `Warn` or `Fail` row is a
/// qualification violation, in any lane — not just the gated rows — except
/// the by-design [`BUILD_LIMIT_ROWS`] values, which no host can clear.
/// `NotApplicable` rows (lanes nobody requested) never violate.
pub fn extra_strict_violations(checks: &[Check]) -> Vec<&Check> {
    checks
        .iter()
        .filter(|c| matches!(c.status, Status::Warn(_) | Status::Fail(_)) && !is_build_limit(c))
        .collect()
}

/// Extra-strict exit code: 0 only when no row violates, 1 otherwise.
pub fn verdict_extra_strict(checks: &[Check]) -> i32 {
    if extra_strict_violations(checks).is_empty() {
        0
    } else {
        1
    }
}

/// Extra-strict render: the standard table plus one trailing line that
/// either names every violating row (refusal) or states explicitly that
/// no qualification violation was found. Row names are static probe
/// labels, never target-controlled bytes, so the refusal line cannot be
/// forged the way a detail could (F-59).
pub fn render_extra_strict(checks: &[Check]) -> String {
    let mut out = render_with_mode(checks, true);
    let violations = extra_strict_violations(checks);
    let exempt: Vec<&str> = checks
        .iter()
        .filter(|c| is_build_limit(c))
        .map(|c| c.name.as_str())
        .collect();
    if !exempt.is_empty() {
        let _ = writeln!(
            out,
            "extra-strict: not counted (limits of this build, the same on every host): {}",
            exempt.join("; ")
        );
    }
    if violations.is_empty() {
        out.push_str("extra-strict: no qualification violations\n");
    } else {
        let names: Vec<&str> = violations.iter().map(|c| c.name.as_str()).collect();
        let noun = if violations.len() == 1 {
            "violation"
        } else {
            "violations"
        };
        let _ = writeln!(
            out,
            "extra-strict refusal: {} qualification {noun}: {}",
            violations.len(),
            names.join("; ")
        );
    }
    out
}

/// Counter-mode capability footer for `p11scope doctor`: one line naming
/// bpf_loop (helper 181) support. A footer, not a table row: the probed-row
/// contract (pinned count, tier inputs, verdict gates) stays unchanged
/// because this capability gates only counter preparation, never ordinary
/// capture. The old-kernel refusal names the same token the footer carries.
pub(crate) fn counter_modes_footer(verdict: &crate::attach::BpfLoopVerdict) -> String {
    match verdict {
        crate::attach::BpfLoopVerdict::Available => {
            if cfg!(p11scope_counter_objects) {
                "counter modes: available (counts, timestamps, latency; subject to the kernel verifier accepting the counter programs; the kernel provides bpf_loop (helper 181))\n"
                    .to_string()
            } else {
                "counter modes: not enabled in this build (the kernel provides bpf_loop (helper 181))\n"
                    .to_string()
            }
        }
        crate::attach::BpfLoopVerdict::Unavailable(reason) => {
            format!("counter modes: counter-mode-unavailable-on-kernel ({reason})\n")
        }
        crate::attach::BpfLoopVerdict::Unknown(reason) => {
            format!("counter modes: {reason}\n")
        }
    }
}

/// Counter-mode line with load-preflight verdicts (one per mode,
/// `Ok(())` when the object loads and releases). A proven named
/// refusal (the old-kernel token or the memory-limit preflight)
/// replaces the availability sentence; an unproven load failure
/// (privilege, unexpected errors) keeps it, since only a proven
/// refusal shows unavailability.
pub(crate) fn counter_modes_footer_with_preflight(
    verdict: &crate::attach::BpfLoopVerdict,
    preflight: Option<&[(p11scope_ebpf_common::CounterMode, Result<(), String>)]>,
) -> String {
    if let (crate::attach::BpfLoopVerdict::Available, Some(loads)) = (verdict, preflight)
        && cfg!(p11scope_counter_objects)
    {
        if let Some((_, Err(refusal))) = loads.iter().find(|(_, result)| {
            result.as_ref().is_err_and(|s| {
                s.starts_with("counter-mode-") || s.starts_with("counter-memory-limit")
            })
        }) {
            return format!("counter modes: {refusal}\n");
        }
        if loads.iter().all(|(_, result)| result.is_ok()) {
            return "counter modes: available (counts, timestamps, latency; the kernel provides bpf_loop (helper 181); counter objects load on this kernel)\n"
                .to_string();
        }
    }
    counter_modes_footer(verdict)
}

fn counter_modes_for_host(
    host: crate::attach::MultiHostVerdict,
    loop_probe: impl FnOnce() -> crate::attach::BpfLoopVerdict,
    mut object_preflight: impl FnMut(p11scope_ebpf_common::CounterMode) -> Result<(), String>,
) -> String {
    if let Err(refusal) = host {
        return format!("counter modes: {refusal}\n");
    }
    let loop_probe = loop_probe();
    let loads;
    let preflight = if matches!(loop_probe, crate::attach::BpfLoopVerdict::Available)
        && cfg!(p11scope_counter_objects)
    {
        loads = [
            p11scope_ebpf_common::CounterMode::Counts,
            p11scope_ebpf_common::CounterMode::Timestamps,
            p11scope_ebpf_common::CounterMode::Latency,
        ]
        .map(|mode| (mode, object_preflight(mode)));
        Some(loads.as_slice())
    } else {
        None
    };
    counter_modes_footer_with_preflight(&loop_probe, preflight)
}

/// `p11scope doctor`: probes, prints the table, returns the exit code.
/// With `extra_strict`, any `Warn`/`Fail` row refuses (exit 1) and the
/// render names every violating row; otherwise the default gated verdict
/// applies. Both modes put the matching conclusion before the checks.
///
/// The table is written without `print!`: a reader that went away
/// (`p11scope doctor | head`, EPIPE) must not turn the verdict into a panic
/// (HIGH-4), so a broken pipe still exits with the verdict code.
pub fn run(pid: Option<u32>, cgroup: Option<&Path>, extra_strict: bool) -> Result<i32> {
    let host = crate::attach::require_multi_capable_host();
    let checks = probe_with_host(pid, cgroup, host);
    let (mut text, code) = if extra_strict {
        (render_extra_strict(&checks), verdict_extra_strict(&checks))
    } else {
        (render(&checks), verdict(&checks))
    };
    // The preflight loads each counter object and releases it without
    // attaching; only a proven bpf_loop host can answer, and omitted
    // builds refuse at the probe sentence.
    text.push_str(&counter_modes_for_host(
        host,
        crate::attach::kernel_bpf_loop_probe,
        crate::attach::counter_banks::counter_object_preflight,
    ));
    write_report(&mut std::io::stdout().lock(), &text)?;
    Ok(code)
}

fn write_report(out: &mut dyn std::io::Write, text: &str) -> Result<()> {
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error).context("writing the doctor report to stdout"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn correction1_failed_setup_never_invokes_active_seccomp_probe() {
        let mut active_calls = 0;
        let mut multi_calls = 0;
        let checks = bpf_checks_with_seccomp::<()>(
            Err(std::io::Error::from_raw_os_error(libc::EPERM).into()),
            |_| panic!("diagnostic after failed setup"),
            || {
                active_calls += 1;
                Check {
                    name: "uretprobe vs seccomp".into(),
                    status: Status::Ok("unexpected active probe".into()),
                }
            },
            || {
                multi_calls += 1;
                Check {
                    name: "uprobe-multi attach (own libc)".into(),
                    status: Status::Ok("unexpected active probe".into()),
                }
            },
        );
        assert_eq!(active_calls, 0);
        assert_eq!(multi_calls, 1);
        assert_eq!(verdict(&checks), 1);
        let seccomp = checks
            .iter()
            .find(|check| check.name == "uretprobe vs seccomp")
            .unwrap();
        assert!(matches!(seccomp.status, Status::NotApplicable(_)));
        assert!(status_detail(&seccomp.status).contains("shared capture setup refused"));
        let multi = checks.last().unwrap();
        assert_eq!(multi.name, "uprobe-multi attach (own libc)");
        assert!(matches!(multi.status, Status::Ok(_)));
    }

    #[test]
    fn correction1_successful_setup_preserves_active_seccomp_result() {
        for diagnostic_ok in [true, false] {
            let mut active_calls = 0;
            let mut multi_calls = 0;
            let checks = bpf_checks_with_seccomp(
                Ok(()),
                |_| {
                    if diagnostic_ok {
                        Ok(())
                    } else {
                        Err("diagnostic failed".into())
                    }
                },
                || {
                    active_calls += 1;
                    Check {
                        name: "uretprobe vs seccomp".into(),
                        status: Status::Warn("controlled hazard result".into()),
                    }
                },
                || {
                    multi_calls += 1;
                    Check {
                        name: "uprobe-multi attach (own libc)".into(),
                        status: Status::Ok("controlled multi result".into()),
                    }
                },
            );
            assert_eq!(active_calls, 1);
            assert_eq!(multi_calls, 1);
            let seccomp = checks
                .iter()
                .find(|check| check.name == "uretprobe vs seccomp")
                .unwrap();
            assert_eq!(
                seccomp.status,
                Status::Warn("controlled hazard result".into())
            );
            assert_eq!(
                checks.last().unwrap().status,
                Status::Ok("controlled multi result".into())
            );
            assert_eq!(verdict(&checks), i32::from(!diagnostic_ok));
        }
    }

    #[test]
    fn required_multi_row_preserves_typed_refusals_and_limited_positive() {
        use crate::attach::{MultiCapableHost, MultiHostRefusal, MultiHostStage};
        let check = uprobe_multi_check(Ok(MultiCapableHost::for_test()));
        let Status::Ok(detail) = check.status else {
            panic!("positive fact must be reported")
        };
        assert!(detail.contains("self-link attached and detached"));
        assert!(detail.contains("delivery unmeasured"));
        for (stage, errno) in [
            (MultiHostStage::ProgramLoad, libc::EACCES),
            (MultiHostStage::SelfLink, libc::EPERM),
            (MultiHostStage::SelfLink, libc::EOPNOTSUPP),
            (MultiHostStage::SelfLink, libc::EINVAL),
        ] {
            let refusal = MultiHostRefusal::for_test(stage, Some(errno));
            let check = uprobe_multi_check(Err(refusal));
            assert_eq!(check.status, Status::Fail(refusal.to_string()));
            assert_eq!(verdict(&[check]), 1);
        }
    }

    #[test]
    fn counter_footer_requires_host_before_helper_or_mode_preflights() {
        use crate::attach::{BpfLoopVerdict, MultiCapableHost, MultiHostRefusal, MultiHostStage};
        for errno in [libc::EOPNOTSUPP, libc::EPERM, libc::EINVAL] {
            let refusal = MultiHostRefusal::for_test(MultiHostStage::SelfLink, Some(errno));
            let line = counter_modes_for_host(
                Err(refusal),
                || panic!("helper probe after refused host"),
                |_| panic!("counter object load after refused host"),
            );
            assert_eq!(line, format!("counter modes: {refusal}\n"));
        }
        let line = counter_modes_for_host(
            Ok(MultiCapableHost::for_test()),
            || BpfLoopVerdict::Unavailable("helper control refused".into()),
            |_| panic!("mode preflight without its helper"),
        );
        assert!(line.contains("counter-mode-unavailable-on-kernel"));
        assert!(!line.contains("uprobe-multi-required"));
    }

    #[test]
    fn multi_host_refusal_gates_live_tier_and_exit_without_a_version_gate() {
        let mut checks = vec![
            Check {
                name: "kernel release".into(),
                status: Status::Warn("5.14 with a working backport".into()),
            },
            Check {
                name: "BPF map create".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: UPROBE_ATTACH_SELF_ROW.into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "host program preflight".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "target readability".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "lifecycle preflight".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "scope preflight".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "uprobe-multi attach (own libc)".into(),
                status: Status::Ok("self-link only".into()),
            },
        ];
        assert_eq!(capability_tier(&checks).tier, CapabilityTier::T4);
        assert_eq!(verdict(&checks), 0);
        for reason in [
            "unavailable",
            "permission or policy denied",
            "unproven probe",
        ] {
            checks.last_mut().unwrap().status =
                Status::Fail(format!("uprobe-multi-required: {reason}"));
            assert_eq!(verdict(&checks), 1, "{reason}");
            assert_eq!(
                capability_tier(&checks).tier,
                CapabilityTier::T0,
                "{reason}"
            );
            assert!(verdict_line(&checks).contains("capture unavailable"));
        }
    }

    #[test]
    fn correction1_wrapped_ordinary_errors_preserve_named_stage_and_errno() {
        for (stage, outer, errno, expected) in [
            (
                "freezing THREAD_OWNER",
                "preparing required image identity and thread ownership",
                libc::EPERM,
                "Operation not permitted",
            ),
            (
                "loading required vmlinux BTF for typed task_newtask",
                "capture setup",
                libc::ENOENT,
                "No such file or directory",
            ),
        ] {
            let error = anyhow::Error::from(std::io::Error::from_raw_os_error(errno))
                .context(stage)
                .context(outer);
            let checks = bpf_checks_with::<()>(Err(error), |_| panic!("diagnostic after failure"));
            let detail = status_detail(&checks[0].status);
            assert!(detail.contains(stage), "{detail}");
            assert!(detail.contains(outer), "{detail}");
            assert!(detail.contains(expected), "{detail}");
            assert_eq!(verdict(&checks), 1);
        }
    }

    #[test]
    fn correction1_wrapped_verifier_errors_preserve_program_and_bound_output() {
        let error = anyhow::Error::new(ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::EPERM),
            verifier_log: aya_obj::VerifierLog::new(format!("denied\u{1b}[2J{}", "é".repeat(4096))),
        })
        .context("loading required typed task_newtask")
        .context("capture\npreflight");
        let checks =
            bpf_checks_with::<()>(Err(error), |_| panic!("diagnostic after verifier failure"));
        let detail = status_detail(&checks[0].status);
        assert!(
            detail.contains("loading required typed task_newtask"),
            "{detail}"
        );
        assert!(detail.contains(r"capture\npreflight"), "{detail}");
        assert!(detail.contains(r"verifier: denied\u{1b}[2J"));
        assert!(!detail.contains('\u{1b}') && !detail.contains('\n'));
        assert!(detail.len() <= 512 + 2 + 4096);
        assert!(detail.contains(" [middle omitted] "));
        assert!(detail.ends_with('é'));
        assert!(!detail.contains('\u{fffd}'));
        assert_eq!(verdict(&checks), 1);
    }

    #[test]
    fn correction1_long_context_is_utf8_safe_escaped_and_bounded() {
        let error = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::EPERM))
            .context(format!("loading\n{}", "é".repeat(4096)));
        let detail = format_preflight_error(error.as_ref());
        assert!(detail.starts_with(r"loading\n"));
        assert!(detail.len() <= 512 + 2 + 512);
        assert!(detail.contains("Operation not permitted"));
        assert!(!detail.contains('\u{fffd}') && !detail.contains('\n'));
    }
    #[test]
    fn loader_missing_capability_stays_distinct_and_skips_diagnostic_attachment() {
        let checks = bpf_checks_with::<()>(
            Err(std::io::Error::from_raw_os_error(libc::EPERM).into()),
            |_| panic!("diagnostic link attempted after failed setup"),
        );
        assert!(matches!(checks[0].status, Status::Fail(_)));
        assert_eq!(verdict(&checks), 1);
        assert!(status_detail(&checks[0].status).contains("Operation not permitted"));
        assert!(!status_detail(&checks[0].status).contains("development build"));
    }

    #[test]
    fn loader_success_and_diagnostic_failure_are_reported_from_shared_setup() {
        let mut called = false;
        let checks = bpf_checks_with(Ok(7), |state| {
            assert_eq!(*state, 7);
            called = true;
            Err("diagnostic detach failure".into())
        });
        assert!(called);
        assert!(matches!(checks[0].status, Status::Ok(_)));
        assert_eq!(
            checks[1].status,
            Status::Fail("diagnostic detach failure".into())
        );
        assert_eq!(verdict(&checks), 1);
        let checks = bpf_checks_with(Ok(()), |_| Ok(()));
        assert!(
            checks
                .iter()
                .all(|check| matches!(check.status, Status::Ok(_)))
        );
        assert_eq!(verdict(&checks), 0);
    }

    /// F-09: the tier classifier must read the row `bpf_checks_with`
    /// actually emits. The producer said `(own libc)` while the
    /// classifier looked up `(self)`, so every real run with a working
    /// attach classified T0 offline while unit tests with hand-built
    /// `(self)` rows passed. This feeds the real rows into the real
    /// classifier — and pins the user-facing row name literally, so a
    /// shared constant cannot drift both ends together.
    #[test]
    fn tier_classification_reads_the_row_bpf_checks_actually_emits() {
        let mut checks = bpf_checks_with(Ok(()), |_| Ok(()));
        assert_eq!(checks[1].name, "uprobe attach (self)");
        checks.push(Check {
            name: "host program preflight".into(),
            status: Status::Ok("available".into()),
        });
        checks.push(Check {
            name: "uprobe-multi attach (own libc)".into(),
            status: Status::Ok("self-link proven".into()),
        });
        // Host attach works, target unassessed: T1, not T0 offline.
        assert_eq!(capability_tier(&checks).tier, CapabilityTier::T1);

        // The other direction: a failed diagnostic still classifies T0.
        let mut failed = bpf_checks_with(Ok(()), |_| Err("EACCES".into()));
        failed.push(Check {
            name: "host program preflight".into(),
            status: Status::Ok("available".into()),
        });
        assert_eq!(capability_tier(&failed).tier, CapabilityTier::T0);
    }
    use super::*;

    #[test]
    fn render_pads_names_and_shows_every_status_kind() {
        let checks = vec![
            Check {
                name: "kernel release".into(),
                status: Status::Ok("7.0.0 (floor 5.15)".into()),
            },
            Check {
                name: "kernel.perf_event_paranoid".into(),
                status: Status::Warn("4 — uprobes need CAP_SYS_ADMIN".into()),
            },
            Check {
                name: "uprobe attach".into(),
                status: Status::Fail("EACCES".into()),
            },
            Check {
                name: "/proc/<pid>/mem".into(),
                status: Status::NotApplicable("no --pid".into()),
            },
        ];
        let out = render(&checks);
        assert!(out.contains("kernel release"), "{out}");
        assert!(out.contains("ok"), "{out}");
        assert!(out.contains("warn"), "{out}");
        assert!(out.contains("FAIL"), "{out}");
        assert!(out.contains("n/a"), "{out}");
        // Verdict line is always last and always present.
        assert!(out.lines().last().unwrap().starts_with("verdict:"), "{out}");
    }

    #[test]
    fn static_maps_without_libc_yield_no_anchor_while_dynamic_maps_do() {
        let dynamic = "7f0000000000-7f0000001000 r-xp 00000000 00:20 11 /lib64/libc.so.6\n\
                       7f0000001000-7f0000002000 r--p 00001000 00:20 11 /lib64/libc.so.6\n";
        assert_eq!(
            libc_path_in_maps(dynamic.as_bytes()),
            Some(PathBuf::from("/lib64/libc.so.6"))
        );
        // A statically linked observer maps no libc at all — that selects the
        // entry-point fallback, never a failure.
        let static_maps = "555555554000-555555555000 r-xp 00000000 00:20 12 /usr/bin/tool\n\
                           7ffffffff000-7ffffffff010 r--p 00000000 00:00 0 [vdso]\n";
        assert_eq!(libc_path_in_maps(static_maps.as_bytes()), None);
        // A non-executable libc mapping alone is not an anchor either.
        let no_x = "7f0000001000-7f0000002000 r--p 00001000 00:20 11 /lib64/libc.so.6\n";
        assert_eq!(libc_path_in_maps(no_x.as_bytes()), None);
    }

    #[test]
    fn a_failed_capture_probe_is_a_nonzero_exit_but_warnings_are_not() {
        let ok = vec![Check {
            name: "uprobe attach".into(),
            status: Status::Ok("attached and detached".into()),
        }];
        assert_eq!(verdict(&ok), 0);
        let warn = vec![Check {
            name: "kernel.yama.ptrace_scope".into(),
            status: Status::Warn("1".into()),
        }];
        assert_eq!(verdict(&warn), 0, "a warning is not an unavailable lane");
        let fail = vec![Check {
            name: "BPF map create".into(),
            status: Status::Fail("EPERM".into()),
        }];
        assert_eq!(verdict(&fail), 1);

        let target = vec![Check {
            name: "target readability".into(),
            status: Status::Fail("provider identity unavailable".into()),
        }];
        assert_eq!(verdict(&target), 1);
        assert_eq!(
            verdict_line(&target),
            "verdict: capture available; target unavailable (provider identity unavailable)"
        );
    }

    #[test]
    fn a_backported_kernel_below_the_floor_is_not_forced_offline() {
        // A synthetic working Multi backport qualifies independently of its
        // low release label; this is not a claim about a stock old kernel.
        let row = |name: &str, status: Status| Check {
            name: name.to_string(),
            status,
        };
        let checks = vec![
            row(
                "kernel release",
                Status::Ok("5.14.0 with a working Multi backport; informational".into()),
            ),
            row("BPF map create", Status::Ok("created".into())),
            row(
                "uprobe attach (self)",
                Status::Ok("attached and detached".into()),
            ),
            row("host program preflight", Status::Ok("available".into())),
            row(
                "uprobe-multi attach (own libc)",
                Status::Ok("self-link proven".into()),
            ),
            row("lifecycle preflight", Status::Ok("available".into())),
            row("scope preflight", Status::NotApplicable("no scope".into())),
        ];
        assert_ne!(
            capability_tier(&checks).tier,
            CapabilityTier::T0,
            "a warning about the version string must not override three probes that succeeded"
        );

        // The other direction: a kernel that actually cannot attach is still
        // T0, so this is not "stop checking".
        let mut broken = checks;
        broken[2].status = Status::Fail("unknown func bpf_get_attach_cookie#174".into());
        assert_eq!(capability_tier(&broken).tier, CapabilityTier::T0);
    }

    #[test]
    fn capability_tier_is_monotonic_without_lease_authority() {
        let expected =
            |host_attach: bool, target_readable: Option<bool>, lifecycle: bool, scope: bool| {
                if !host_attach {
                    CapabilityTier::T0
                } else if target_readable != Some(true) {
                    CapabilityTier::T1
                } else if !lifecycle {
                    CapabilityTier::T2
                } else if !scope {
                    CapabilityTier::T3
                } else {
                    CapabilityTier::T4
                }
            };
        for host_attach in [false, true] {
            for target_readable in [None, Some(false), Some(true)] {
                for lifecycle in [false, true] {
                    for scope in [false, true] {
                        // Deliberately exhaustive: classifier authority is only
                        // H/R/L/S, with no lease, trust, uid, or root predicate.
                        let input = CapabilityTierInput {
                            host_attach,
                            target_readable,
                            lifecycle,
                            scope,
                        };
                        let result = classify_capability_tier(input);
                        assert_eq!(
                            result.tier,
                            expected(host_attach, target_readable, lifecycle, scope),
                            "{input:?}"
                        );
                        assert_eq!(result.target_assessed, target_readable.is_some());
                    }
                }
            }
        }

        let mask = (1u64 << 2) | (1u64 << 19) | (1u64 << 39);
        assert_eq!(
            decode_caps(mask),
            vec!["CAP_BPF", "CAP_DAC_READ_SEARCH", "CAP_SYS_PTRACE"]
        );
        assert!(CAP_BITS.contains(&(2, "CAP_DAC_READ_SEARCH")));
        assert!(!CAP_BITS.iter().any(|(_, name)| *name == "CAP_SYS_RESOURCE"));
        assert!(decode_caps(0).is_empty());
        // A bit outside the named set must not appear.
        assert!(decode_caps(1u64 << 12).is_empty());

        for (tier, label) in [
            (CapabilityTier::T0, "T0 offline"),
            (CapabilityTier::T1, "T1 host attach"),
            (CapabilityTier::T2, "T2 target readable"),
            (CapabilityTier::T3, "T3 lifecycle"),
            (CapabilityTier::T4, "T4 current full"),
        ] {
            for (target_assessed, assessment) in [(false, "unassessed"), (true, "assessed")] {
                assert_eq!(
                    capability_tier_line(CapabilityTierResult {
                        tier,
                        target_assessed,
                    }),
                    format!("capability tier: {label} (target {assessment})")
                );
            }
        }

        let mut operational = vec![
            Check {
                name: "uprobe-multi attach (own libc)".into(),
                status: Status::Ok("self-link proven".into()),
            },
            Check {
                name: "kernel release".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "BPF map create".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "uprobe attach (self)".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "host program preflight".into(),
                status: Status::Ok("available".into()),
            },
            Check {
                name: "target readability".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "lifecycle preflight".into(),
                status: Status::Ok("available".into()),
            },
            Check {
                name: "scope preflight".into(),
                status: Status::Warn("unavailable".into()),
            },
        ];
        assert_eq!(capability_tier(&operational).tier, CapabilityTier::T3);
        assert_eq!(
            render(&operational)
                .lines()
                .find(|line| line.starts_with("capability tier:")),
            Some("capability tier: T3 lifecycle (target assessed)")
        );
        operational.last_mut().unwrap().status = Status::Ok("available".into());
        assert_eq!(capability_tier(&operational).tier, CapabilityTier::T4);
        assert_eq!(
            render(&operational)
                .lines()
                .find(|line| line.starts_with("capability tier:")),
            Some("capability tier: T4 current full (target assessed)")
        );
    }

    #[test]
    fn host_lifecycle_survives_requested_scope_failure() {
        let checks = vec![
            Check {
                name: "uprobe-multi attach (own libc)".into(),
                status: Status::Ok("self-link proven".into()),
            },
            Check {
                name: "kernel release".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "BPF map create".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "uprobe attach (self)".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "host program preflight".into(),
                status: Status::Ok("available".into()),
            },
            Check {
                name: "target readability".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "lifecycle preflight".into(),
                status: Status::Ok("available".into()),
            },
            Check {
                name: "scope preflight".into(),
                status: Status::Warn("unavailable".into()),
            },
        ];
        assert_eq!(capability_tier(&checks).tier, CapabilityTier::T3);
    }

    #[test]
    fn eperm_origin_requires_independent_evidence() {
        let evidence =
            |seccomp_mode, controlled_seccomp_denial, missing_required_capability| EpermEvidence {
                errno: Some(libc::EPERM),
                seccomp_mode,
                controlled_seccomp_denial,
                missing_required_capability,
            };
        assert_eq!(
            classify_eperm_origin(evidence(None, false, false)),
            EpermOrigin::Unknown
        );
        assert_eq!(
            classify_eperm_origin(evidence(Some(2), false, false)),
            EpermOrigin::Unknown,
            "seccomp mode alone is diagnostic context, not causal proof"
        );
        assert_eq!(
            classify_eperm_origin(evidence(Some(2), true, false)),
            EpermOrigin::Seccomp
        );
        assert_eq!(
            classify_eperm_origin(evidence(None, false, true)),
            EpermOrigin::Capability
        );
        assert_eq!(
            classify_eperm_origin(evidence(Some(2), true, true)),
            EpermOrigin::Unknown,
            "conflicting independent facts must not guess a cause"
        );

        let denied = std::io::Error::from_raw_os_error(libc::EPERM);
        let rendered = |mode, controlled, capability| {
            format_operation_error_with(&denied, mode, controlled, capability)
        };
        assert!(!rendered(None, false, false).contains("origin:"));
        assert!(
            !rendered(Some(2), false, false).contains("origin:"),
            "seccomp mode alone must not reach the production label"
        );
        assert!(rendered(None, false, true).contains("missing required capability"));
        assert!(
            !format_operation_error(&denied).contains("origin:"),
            "production callers must not infer an EPERM origin from CapEff"
        );
        assert!(rendered(Some(2), true, false).contains("controlled seccomp denial"));
        let non_eperm = format_operation_error_with(
            &std::io::Error::from_raw_os_error(libc::EIO),
            Some(2),
            true,
            false,
        );
        assert!(non_eperm.contains("Input/output error"), "{non_eperm}");
        assert!(
            !non_eperm.contains("origin:"),
            "non-EPERM errors remain useful without a causal label"
        );
    }

    #[test]
    fn verifier_diagnostics_are_bounded() {
        let only_verifier_text: fn(&str) -> String = bounded_verifier_diagnostic;
        assert_eq!(
            only_verifier_text(""),
            "verifier rejected the embedded program"
        );
        let escaped = only_verifier_text("verifier\u{1b}[2J\rdenied");
        assert_eq!(escaped, r"verifier: verifier\u{1b}[2J\rdenied");

        let diagnostic = bounded_verifier_diagnostic(&"é".repeat(4096));
        assert!(diagnostic.len() <= 4096);
        assert!(diagnostic.contains(" [middle omitted] "), "{diagnostic:?}");
        assert!(diagnostic.ends_with('é'), "{diagnostic:?}");
        assert!(std::str::from_utf8(diagnostic.as_bytes()).is_ok());
        assert!(!diagnostic.contains('\u{fffd}'), "a UTF-8 scalar was split");
    }

    #[test]
    fn verifier_diagnostics_retain_escaped_terminal_reason_after_long_middle() {
        let verifier_log = format!(
            "program start\u{1b}[2J{}terminal\rreason: invalid é",
            "é".repeat(4096)
        );

        let diagnostic = bounded_verifier_diagnostic(&verifier_log);

        assert!(diagnostic.len() <= 4096, "{diagnostic:?}");
        assert!(
            diagnostic.starts_with(r"verifier: program start\u{1b}[2J"),
            "escaped verifier-log beginning was not retained"
        );
        assert!(
            diagnostic.contains(" [middle omitted] "),
            "middle-omission marker missing"
        );
        assert!(
            diagnostic.ends_with(r"terminal\rreason: invalid é"),
            "terminal verifier reason was not retained"
        );
        assert!(!diagnostic.contains('\u{1b}') && !diagnostic.contains('\r'));
        assert!(!diagnostic.contains('\u{fffd}'));
    }

    /// The doctor names the build's object-capture scope: enabled in
    /// FULL builds, a by-design warning in P0 (stub) builds that
    /// extra-strict qualification excuses (no host can clear it).
    /// OD33/R-50: v0.5.0 reads attributes but reports key operations
    /// only from 0.6.0, so the OK detail says so.
    #[test]
    fn object_capture_check_matches_build() {
        let check = object_capture_check();
        assert_eq!(check.name, "object-attribute capture");
        // The session reports the bytes it was set up with; the row must
        // agree with those same bytes.
        let available = !crate::attach::embedded_object_is_stubbed();
        match available {
            true => assert_eq!(
                check.status,
                Status::Ok("enabled (read only; key operations are reported from 0.6.0)".into()),
                "{check:?}"
            ),
            false => {
                assert!(matches!(check.status, Status::Warn(_)), "{check:?}");
                assert!(is_build_limit(&check), "{check:?}");
                let checks = vec![check];
                assert!(extra_strict_violations(&checks).is_empty());
            }
        }
    }

    /// A planted flavor mismatch fails the object-capture row with the
    /// same reason capture setup refuses with, and extra-strict counts
    /// it. Fails while the row derives the flavor from the feature.
    #[test]
    fn object_capture_check_fails_on_flavor_mismatch() {
        let planted = crate::attach::EmbeddedFlavor {
            stubbed: !cfg!(feature = "stub-object-attributes"),
            unsafe_present: cfg!(feature = "unsafe-unvalidated-metadata"),
        };
        let _guard = crate::attach::hold_embedded_flavor_for_test(Ok(planted));
        let check = object_capture_check();
        assert_eq!(check.name, "object-attribute capture");
        let Status::Fail(detail) = &check.status else {
            panic!(
                "mismatched flavor must Fail the row, got {:?}",
                check.status
            );
        };
        assert!(detail.contains("stale or mismatched"), "{detail}");
        assert!(detail.contains("FULL"), "{detail}");
        assert!(detail.contains("P0"), "{detail}");
        assert!(!extra_strict_violations(&[check]).is_empty());
    }

    /// Twin of the stub-direction row test: a planted unsafe-decoder
    /// disagreement fails the object-capture row with the same reason
    /// capture setup refuses with, naming the unsafe feature. Fails while
    /// the row derives the flavor from the feature, or maps only the
    /// stub direction to `Fail`.
    #[test]
    fn object_capture_check_fails_on_unsafe_flavor_mismatch() {
        let planted = crate::attach::EmbeddedFlavor {
            stubbed: cfg!(feature = "stub-object-attributes"),
            unsafe_present: !cfg!(feature = "unsafe-unvalidated-metadata"),
        };
        let _guard = crate::attach::hold_embedded_flavor_for_test(Ok(planted));
        let check = object_capture_check();
        assert_eq!(check.name, "object-attribute capture");
        let Status::Fail(detail) = &check.status else {
            panic!(
                "mismatched unsafe decoders must Fail the row, got {:?}",
                check.status
            );
        };
        assert!(detail.contains("stale or mismatched"), "{detail}");
        assert!(detail.contains("unsafe-unvalidated-metadata"), "{detail}");
        assert!(!extra_strict_violations(&[check]).is_empty());
    }

    /// A flavor mismatch exits nonzero through the object-attribute capture
    /// row itself: the row's `Fail` gates the verdict without needing a
    /// preflight row beside it. Fails while the row is not a capture row.
    #[test]
    fn object_capture_mismatch_alone_exits_nonzero() {
        let planted = crate::attach::EmbeddedFlavor {
            stubbed: !cfg!(feature = "stub-object-attributes"),
            unsafe_present: cfg!(feature = "unsafe-unvalidated-metadata"),
        };
        {
            let _guard = crate::attach::hold_embedded_flavor_for_test(Ok(planted));
            let check = object_capture_check();
            assert!(matches!(check.status, Status::Fail(_)), "{check:?}");
            assert_eq!(verdict(&[check]), 1);
        }
        let check = object_capture_check();
        assert!(
            matches!(check.status, Status::Ok(_) | Status::Warn(_)),
            "{check:?}"
        );
        assert_eq!(verdict(&[check]), 0);
    }

    /// The uretprobe row fails (not warns) on a flavor mismatch with the
    /// plain gate message: the build is broken, so the kernel was never
    /// assessed. Fails while the mismatch classifies as an unknown kernel.
    #[test]
    fn uretprobe_row_fails_on_flavor_mismatch() {
        let planted = crate::attach::EmbeddedFlavor {
            stubbed: !cfg!(feature = "stub-object-attributes"),
            unsafe_present: cfg!(feature = "unsafe-unvalidated-metadata"),
        };
        let _guard = crate::attach::hold_embedded_flavor_for_test(Ok(planted));
        let check = uretprobe_seccomp_check();
        assert_eq!(check.name, "uretprobe vs seccomp");
        let Status::Fail(detail) = &check.status else {
            panic!(
                "a flavor mismatch must Fail the row, got {:?}",
                check.status
            );
        };
        assert!(detail.contains("stale or mismatched"), "{detail}");
    }

    /// A budget refusal names its cause: E2BIG through preflight formats
    /// as a verifier-budget refusal with the bounded log excerpt.
    #[test]
    fn preflight_budget_refusal_names_cause() {
        let error = ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::E2BIG),
            verifier_log: aya_obj::VerifierLog::new("BPF program is too large".to_string()),
        };
        let wrapped = anyhow::Error::new(error).context("loading p11_entry");
        let rendered = format_preflight_error(wrapped.as_ref());
        assert!(rendered.contains("verifier budget refused"), "{rendered}");
        assert!(rendered.contains("E2BIG"), "{rendered}");
        assert!(rendered.contains("BPF program is too large"), "{rendered}");
    }

    /// Log-exhaustion twin at the doctor seam: an ENOSPC budget refusal
    /// routes to the budget row and names ENOSPC, never E2BIG.
    #[test]
    fn preflight_budget_refusal_names_log_exhaustion() {
        let error = ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::ENOSPC),
            verifier_log: aya_obj::VerifierLog::new("truncated verifier dump".to_string()),
        };
        let wrapped = anyhow::Error::new(error).context("loading p11_entry");
        let rendered = format_preflight_error(wrapped.as_ref());
        assert!(
            rendered.contains(
                "verifier log filled during a very long check (ENOSPC); usually the complexity limit"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains("verifier budget refused"), "{rendered}");
        assert!(rendered.contains("ENOSPC"), "{rendered}");
        assert!(!rendered.contains("(E2BIG)"), "{rendered}");
        assert!(rendered.contains("truncated verifier dump"), "{rendered}");
    }

    #[test]
    fn wrapped_program_load_error_keeps_named_context_and_bounded_verifier_log() {
        let error = ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::EPERM),
            verifier_log: aya_obj::VerifierLog::new("denied\u{1b}[2J".to_string()),
        };
        let wrapped = anyhow::Error::new(error).context("loading required typed task_newtask");
        let rendered = format_preflight_error(wrapped.as_ref());
        assert_eq!(
            rendered,
            r"loading required typed task_newtask: BPF_PROG_LOAD failed with EPERM (os error 1); verifier: denied\u{1b}[2J"
        );
        assert!(!rendered.contains("Operation not permitted"));

        let long = ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::EPERM),
            verifier_log: aya_obj::VerifierLog::new("é".repeat(4096)),
        };
        let rendered = format_preflight_error(anyhow::Error::new(long).as_ref());
        assert!(rendered.len() <= 4096);
        assert!(rendered.contains(" [middle omitted] "));
        assert!(rendered.ends_with('é'));
        assert!(std::str::from_utf8(rendered.as_bytes()).is_ok());
    }

    #[test]
    fn preflight_names_errno_for_non_budget_load_refusals() {
        // The budget arm names its errno; any other load refusal must name
        // its errno too, not just the verifier excerpt.
        let error = ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::EACCES),
            verifier_log: aya_obj::VerifierLog::new("R1 invalid mem access".to_string()),
        };
        let wrapped = anyhow::Error::new(error).context("loading p11_entry");
        let rendered = format_preflight_error(wrapped.as_ref());
        assert!(
            rendered.contains("BPF_PROG_LOAD failed with EACCES (os error 13); "),
            "{rendered}"
        );
        assert!(rendered.contains("R1 invalid mem access"), "{rendered}");
    }

    /// A nested map-creation refusal renders once: aya's outer
    /// `EbpfError::MapError` Display (`map error: {0}`) already contains
    /// the inner `MapError` Display, so joining the whole chain must not
    /// print the `failed to create map` phrase twice. The row keeps
    /// the map name; only the repeat goes.
    #[test]
    fn preflight_skips_chain_fragments_already_present() {
        let error = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::EPERM))
            .context("failed to create map `DISCOVERY`")
            .context("map error: failed to create map `DISCOVERY`")
            .context("loading fresh Inventory object with exact capacity")
            .context("preparing Inventory: LoadObject");
        let rendered = format_preflight_error(error.as_ref());
        assert_eq!(
            rendered,
            "preparing Inventory: LoadObject: loading fresh Inventory object with exact capacity: \
             map error: failed to create map `DISCOVERY`: Operation not permitted (os error 1)"
        );
    }

    #[test]
    fn preflight_names_numeric_errno_when_name_unknown() {
        // Errnos outside the short-name table stay numeric rather than
        // losing the failure's identity.
        let error = ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::EIO),
            verifier_log: aya_obj::VerifierLog::new("i/o hiccup".to_string()),
        };
        let rendered = format_preflight_error(anyhow::Error::new(error).as_ref());
        assert!(
            rendered.contains("BPF_PROG_LOAD failed with os error 5; "),
            "{rendered}"
        );
    }

    #[test]
    fn parse_major_minor_reads_a_real_uname_style_release() {
        assert_eq!(parse_major_minor("7.0.0-28-generic"), Some((7, 0)));
        assert_eq!(parse_major_minor("5.15.0"), Some((5, 15)));
        assert_eq!(parse_major_minor("not-a-version"), None);
    }

    /// A row that does not exist yet (`--pid`/`--cgroup` not given) is always
    /// `NotApplicable`, never absent and never `Fail` — `verdict` relies on
    /// this to infer requested lanes without a parameter of its own.
    #[test]
    fn probe_marks_unrequested_lanes_not_applicable_and_never_fails_them() {
        fn by_name_status<'a>(checks: &'a [Check], name: &str) -> &'a Status {
            &checks.iter().find(|c| c.name == name).unwrap().status
        }
        let checks = probe(None, None);
        // 13 host/target rows, eight §10.1 rows, four finite preflight rows
        // (host, inventory, lifecycle, scope), the cgroup version row, the
        // uprobe-multi self-link row, the PID namespace row, and the
        // object-attribute capture build row.
        assert_eq!(checks.len(), 29, "{checks:?}");
        // Never FAIL without --pid: a nested observer only warns here.
        assert!(!matches!(
            by_name_status(&checks, PID_NAMESPACE_ROW),
            Status::Fail(_)
        ));
        let by_name = |name: &str| checks.iter().find(|c| c.name == name).unwrap();
        assert_eq!(
            by_name("/proc/<pid>/maps").status,
            Status::NotApplicable("no --pid".into())
        );
        assert_eq!(
            by_name("/proc/<pid>/mem").status,
            Status::NotApplicable("no --pid".into())
        );
        assert_eq!(
            by_name("cgroup path").status,
            Status::NotApplicable("no --cgroup".into())
        );
        assert_eq!(
            by_name("target readability").status,
            Status::NotApplicable("no --pid".into())
        );
        // Unprivileged CI legitimately fails the BPF rows (no CAP_BPF): that
        // is real host state, not asserted here. What's invariant is that no
        // *unrequested* lane ever reports Fail.
        for name in ["/proc/<pid>/maps", "/proc/<pid>/mem", "cgroup path"] {
            assert!(
                !matches!(by_name(name).status, Status::Fail(_)),
                "{name} was not requested and must not Fail"
            );
        }
    }

    #[test]
    fn probe_reports_the_inventory_object_load_row() {
        let checks = probe(None, None);
        let row = checks
            .iter()
            .find(|c| c.name == "inventory program preflight")
            .unwrap_or_else(|| panic!("inventory preflight row is missing: {checks:?}"));
        // Host state decides Ok vs Fail (unprivileged CI legitimately
        // fails the BPF rows); what's invariant is the host row is
        // assessed, never NotApplicable.
        assert!(
            matches!(row.status, Status::Ok(_) | Status::Fail(_)),
            "unexpected status: {row:?}"
        );
    }

    #[test]
    fn inventory_preflight_failure_fails_the_requested_lane_verdict() {
        let row = |name: &str, status: Status| Check {
            name: name.into(),
            status,
        };
        let mut checks = vec![
            row("BPF map create", Status::Ok("available".into())),
            row("host program preflight", Status::Ok("available".into())),
            row(
                "inventory program preflight",
                Status::Fail(
                    "verifier budget refused the program (E2BIG); verifier: denied".into(),
                ),
            ),
        ];
        assert_eq!(verdict(&checks), 1);
        assert_eq!(
            verdict_line(&checks),
            "verdict: capture available; inventory capture unavailable \
             (verifier budget refused the program (E2BIG); verifier: denied)"
        );
        assert_eq!(
            render(&checks).lines().next(),
            Some("Doctor: requested lane unavailable.")
        );
        checks[2].status = Status::Ok("available".into());
        assert_eq!(verdict(&checks), 0);
        assert!(
            !verdict_line(&checks).contains("inventory capture"),
            "{}",
            verdict_line(&checks)
        );
    }

    #[test]
    fn verdict_names_inventory_failure_beside_host_failure() {
        // Twin: when the host lanes fail too, the verdict names both the
        // capture failure and the inventory lane's own reason. The exit
        // gating is unchanged: any failed requested lane exits 1.
        let row = |name: &str, status: Status| Check {
            name: name.into(),
            status,
        };
        let checks = vec![
            row("BPF map create", Status::Ok("available".into())),
            row(
                "host program preflight",
                Status::Fail(
                    "BPF_PROG_LOAD failed with EPERM (os error 1); verifier: denied".into(),
                ),
            ),
            row(
                "inventory program preflight",
                Status::Fail(
                    "verifier budget refused the program (E2BIG); verifier: denied".into(),
                ),
            ),
        ];
        assert_eq!(verdict(&checks), 1);
        assert_eq!(
            verdict_line(&checks),
            "verdict: capture unavailable; inventory capture unavailable \
             (verifier budget refused the program (E2BIG); verifier: denied)"
        );
    }

    /// The verdict's inventory part stays categorical across loader runs:
    /// aya drains its map table (a per-process `HashMap`) in an
    /// unspecified order, so the same EPERM names `DISCOVERY` in one run
    /// and `STACK_GUARD` in the next. The verdict drops the backticked
    /// map name; the per-row diagnostic keeps it.
    #[test]
    fn verdict_inventory_part_drops_unstable_map_names() {
        let row = |name: &str, status: Status| Check {
            name: name.into(),
            status,
        };
        let detail = |map: &str| {
            format!(
                "preparing Inventory: LoadObject: loading fresh Inventory object with exact capacity: \
                 map error: failed to create map `{map}`: Operation not permitted (os error 1)"
            )
        };
        let line = |map: &str| {
            verdict_line(&[
                row("BPF map create", Status::Ok("available".into())),
                row("host program preflight", Status::Ok("available".into())),
                row("inventory program preflight", Status::Fail(detail(map))),
            ])
        };
        assert_eq!(line("DISCOVERY"), line("STACK_GUARD"));
        assert!(
            line("DISCOVERY").contains(
                "inventory capture unavailable (preparing Inventory: LoadObject: \
                 loading fresh Inventory object with exact capacity: map error: \
                 failed to create map: Operation not permitted (os error 1))"
            ),
            "{}",
            line("DISCOVERY")
        );
        // Details without a map name pass through untouched.
        assert_eq!(
            verdict_inventory_reason(
                "verifier budget refused the program (E2BIG); verifier: denied"
            ),
            "verifier budget refused the program (E2BIG); verifier: denied"
        );
        // An unbalanced backtick keeps the remainder verbatim.
        assert_eq!(verdict_inventory_reason("broken `map"), "broken `map");
    }

    // ---- Slice 1b-2 doctor contract (design §10.1) ------------------------

    /// Every live-discovery row doctor may print, and the finite vocabulary its
    /// detail is drawn from. A row that classified itself any other way is
    /// publishing something the operator cannot act on.
    const FROZEN_ROWS: [(&str, &[&str]); 7] = [
        ("target loader build", &["bound", "unbound"]),
        ("debug-state hook", &["available", "unavailable"]),
        (
            "loader timing (initial_set)",
            &[
                "qualified_pre_constructor",
                "known_pre_relocation",
                "unproven",
                "none",
            ],
        ),
        (
            "loader timing (dlopen)",
            &[
                "qualified_pre_constructor",
                "known_pre_relocation",
                "unproven",
                "none",
            ],
        ),
        ("loader-state live read", &["available", "unavailable"]),
        ("live export reads", &["available", "unavailable"]),
        ("run initial-set capture", &["eligible", "none"]),
    ];

    #[test]
    fn doctor_classifies_every_live_discovery_row_finitely() {
        let checks = probe(None, None);
        for (name, allowed) in FROZEN_ROWS {
            let check = checks
                .iter()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("{name} row is missing: {checks:?}"));
            let detail = status_detail(&check.status);
            assert!(
                allowed.contains(&detail),
                "{name} classified itself as {detail:?}, outside {allowed:?}"
            );
        }
        // Pause: the default is stated, and an explicit policy's armability is
        // what an operator actually needs before asking for one.
        let pause = checks
            .iter()
            .find(|c| c.name == "pause")
            .expect("pause row is missing");
        let detail = status_detail(&pause.status);
        assert!(detail.starts_with("never default"), "{detail:?}");
        assert!(
            detail.contains("auto") && detail.contains("always"),
            "the pause row must say whether an explicit policy can arm: {detail:?}"
        );
        // The memory scan lane keeps its existing row and its existing rules.
        assert!(checks.iter().any(|c| c.name == "/proc/<pid>/mem"));
    }

    #[test]
    fn ordinary_doctor_output_never_prints_the_identity_behind_a_row() {
        let out = render(&probe(None, None));
        for forbidden in [
            "ld-linux", "ld-musl", "libc.so", "build_id", "sha256", "proof", "_r_debug", "0x",
        ] {
            assert!(
                !out.contains(forbidden),
                "doctor printed {forbidden:?} behind a row:\n{out}"
            );
        }
    }

    #[test]
    fn verdict_line_names_a_failed_run_capture_lane() {
        // LOW: verdict() gates the exit code on "run initial-set capture",
        // so the verdict text must name it too — never "capture available"
        // beside exit 1.
        let failed = vec![
            Check {
                name: "BPF map create".into(),
                status: Status::Ok("created".into()),
            },
            Check {
                name: "run initial-set capture".into(),
                status: Status::Fail("refused".into()),
            },
        ];
        assert_eq!(verdict(&failed), 1);
        let line = verdict_line(&failed);
        assert!(
            line.contains("run capture unavailable (refused)"),
            "verdict text hides the failing lane: {line}"
        );

        let available = vec![Check {
            name: "run initial-set capture".into(),
            status: Status::Ok("eligible".into()),
        }];
        assert_eq!(verdict(&available), 0);
        let line = verdict_line(&available);
        assert!(
            line.contains("run capture available"),
            "verdict text hides the lane: {line}"
        );

        // Fable: the probe always emits Warn("none") ("never eligible while
        // the catalog is empty"), so Warn must not render as "available".
        // HIGH-5: nor as "run capture not eligible" — `run` itself works on
        // a capable host; what `none` limits is its initial-set proof, which
        // keeps its reports PARTIAL.
        let ineligible = vec![Check {
            name: "run initial-set capture".into(),
            status: Status::Warn("none".into()),
        }];
        assert_eq!(verdict(&ineligible), 0);
        let line = verdict_line(&ineligible);
        assert!(
            line.contains(
                "run initial-set capture none (run reports stay PARTIAL; run itself works)"
            ),
            "verdict text misstates an ineligible lane: {line}"
        );
        assert!(!line.contains("not eligible"), "{line}");
        assert!(!line.contains("run capture available"), "{line}");
    }

    /// A degraded timing value is a warning: it makes complete timing
    /// unavailable without making every capture lane fatal. A requested lane
    /// that is genuinely unavailable stays nonzero.
    #[test]
    fn a_degraded_timing_row_warns_while_a_requested_lane_still_refuses() {
        let degraded = vec![
            Check {
                name: "uprobe attach (self)".into(),
                status: Status::Ok("attached and detached".into()),
            },
            Check {
                name: "loader timing (dlopen)".into(),
                status: Status::Warn("unproven".into()),
            },
        ];
        assert_eq!(verdict(&degraded), 0);

        let mut refused = degraded.clone();
        refused.push(Check {
            name: "run initial-set capture".into(),
            status: Status::Fail("none".into()),
        });
        assert_eq!(
            verdict(&refused),
            1,
            "a requested lane that cannot run is nonzero"
        );
    }

    #[test]
    fn cgroup_version_reports_unified_when_controllers_and_self_entry_agree() {
        let dir = tempfile::tempdir().unwrap();
        let controllers = dir.path().join("cgroup.controllers");
        std::fs::write(&controllers, "cpuset cpu io memory\n").unwrap();
        let self_cgroup = dir.path().join("cgroup");
        std::fs::write(&self_cgroup, "0::/user.slice\n").unwrap();
        let check = cgroup_version_check_at(&controllers, &self_cgroup);
        assert_eq!(check.name, "cgroup version");
        assert!(
            matches!(check.status, Status::Ok(_)),
            "unified hierarchy must pass: {:?}",
            check.status
        );
    }

    #[test]
    fn cgroup_version_fails_loudly_without_unified_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        // v1-style self entries and no controllers file at all.
        let self_cgroup = dir.path().join("cgroup");
        std::fs::write(
            &self_cgroup,
            "2:cpu,cpuacct:/user.slice\n1:name=systemd:/user.slice\n",
        )
        .unwrap();
        let check = cgroup_version_check_at(&dir.path().join("cgroup.controllers"), &self_cgroup);
        let detail = match check.status {
            Status::Fail(detail) => detail,
            status => panic!("a v1 host must fail loudly: {status:?}"),
        };
        assert!(
            detail.contains("cgroup v2"),
            "the failure must name the requirement: {detail}"
        );
    }

    /// `probe` loads and attaches BPF; nothing of it may outlive the call.
    #[test]
    fn no_bpf_program_link_or_map_survives_a_doctor_probe() {
        let bpf_descriptors = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|entry| std::fs::read_link(entry.unwrap().path()).ok())
                .filter(|target| target.to_string_lossy().contains("bpf"))
                .count()
        };
        let before = bpf_descriptors();
        let _ = probe(None, None);
        assert_eq!(
            bpf_descriptors(),
            before,
            "doctor left a BPF program, link, or map loaded"
        );
    }

    fn capable_host_environment_rows() -> Vec<Check> {
        [
            "kernel release",
            "BTF /sys/kernel/btf/vmlinux",
            "lockdown",
            "kernel.perf_event_paranoid",
            "kernel.yama.ptrace_scope",
            "effective capabilities",
            "BPF map create",
            UPROBE_ATTACH_SELF_ROW,
            "uretprobe vs seccomp",
            "cgroup version",
            "host program preflight",
            "lifecycle preflight",
        ]
        .into_iter()
        .map(|name| Check {
            name: name.into(),
            status: Status::Ok("ok".into()),
        })
        .collect()
    }

    /// HIGH-5: the loader timing rows and `run initial-set capture` warn on
    /// every host because this build's timing catalog is empty. They are
    /// limits of the build, not of the host, so a host whose every other
    /// row is clean must pass `--extra-strict` — and the refusal/pass line
    /// still names them, so nothing is hidden.
    #[test]
    fn extra_strict_passes_a_capable_host_whatever_this_build_cannot_prove() {
        let mut checks = capable_host_environment_rows();
        checks.extend(live_discovery_checks(Some(std::process::id()), true));
        let names = |checks: &[Check]| {
            extra_strict_violations(checks)
                .iter()
                .map(|check| check.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&checks), Vec::<String>::new());
        assert_eq!(verdict_extra_strict(&checks), 0);
        let rendered = render_extra_strict(&checks);
        assert!(
            rendered.contains("extra-strict: no qualification violations"),
            "{rendered}"
        );
        for row in [
            "loader timing (initial_set)",
            "loader timing (dlopen)",
            "run initial-set capture",
        ] {
            let line = rendered
                .lines()
                .find(|line| line.starts_with("extra-strict: not counted"))
                .unwrap_or_else(|| panic!("no not-counted line:\n{rendered}"));
            assert!(line.contains(row), "{line}");
        }

        // A real host problem still refuses, beside the exempt rows.
        checks[0].status = Status::Warn("below floor".into());
        assert_eq!(names(&checks), vec!["kernel release".to_string()]);
        // And a build-limit row with a value this build could reach (a
        // future catalog) is no longer exempt.
        let mut failed = capable_host_environment_rows();
        failed.push(Check {
            name: "run initial-set capture".into(),
            status: Status::Fail("refused".into()),
        });
        assert_eq!(verdict_extra_strict(&failed), 1);
    }

    /// HIGH-5: a restrictive sysctl is only a limit for a process that
    /// lacks the capability which lifts it. As root on stock Ubuntu
    /// (`perf_event_paranoid=4`, `ptrace_scope=1`) neither row limits the
    /// capture, so neither may fail `--extra-strict`; unprivileged, both
    /// still warn, and `ptrace_scope=3` binds even root. The paranoid half
    /// runs through the row's own constructor on the singles (below-6.9)
    /// branch, where the lift still applies.
    #[test]
    fn a_sysctl_lifted_by_a_held_capability_is_not_a_warning() {
        let paranoid = |held| {
            paranoid_status(
                Ok("4\n".into()),
                "/proc/sys/kernel/perf_event_paranoid",
                held,
                false,
            )
        };
        let Status::Ok(detail) = paranoid(true) else {
            panic!(
                "CAP_SYS_ADMIN lifts perf_event_paranoid: {:?}",
                paranoid(true)
            );
        };
        assert!(detail.starts_with("4 — "), "{detail}");
        assert!(
            detail.contains("this process has CAP_SYS_ADMIN"),
            "{detail}"
        );
        assert!(matches!(paranoid(false), Status::Warn(_)));

        let ptrace = |value: &str, held| {
            sysctl_status(
                Ok(value.into()),
                "/proc/sys/kernel/yama/ptrace_scope",
                1,
                "same-uid non-descendants need CAP_SYS_PTRACE",
                Some(SysctlLift {
                    capability: "CAP_SYS_PTRACE",
                    up_to: 2,
                    held,
                }),
            )
        };
        assert!(matches!(ptrace("1", true), Status::Ok(_)));
        assert!(matches!(ptrace("1", false), Status::Warn(_)));
        assert!(matches!(ptrace("3", true), Status::Warn(_)));
    }

    /// F3 + DR-K8S-3: on a multi-capable kernel (≥ 6.9) paranoid does not
    /// gate static uprobe-multi links, but at 3 or above it refuses every
    /// `perf_event_open` without CAP_SYS_ADMIN — and the uretprobe
    /// self-probe and live-discovery probes attach through it. So the row
    /// warns there unless CAP_SYS_ADMIN is held, and never claims that
    /// CAP_BPF+CAP_PERFMON suffice.
    #[test]
    fn paranoid_row_on_multi_kernels_names_what_still_needs_cap_sys_admin() {
        let row = |value: &str, held| {
            paranoid_status(
                Ok(value.into()),
                "/proc/sys/kernel/perf_event_paranoid",
                held,
                true,
            )
        };
        for value in ["3\n", "4\n"] {
            let Status::Warn(detail) = row(value, false) else {
                panic!(
                    "paranoid {value:?} without CAP_SYS_ADMIN must warn: {:?}",
                    row(value, false)
                );
            };
            assert!(
                detail.starts_with(&format!("{} — ", value.trim())),
                "{detail}"
            );
            assert!(detail.contains("uprobe-multi"), "{detail}");
            assert!(detail.contains("uretprobe self-probe"), "{detail}");
            assert!(detail.contains("need CAP_SYS_ADMIN"), "{detail}");
            assert!(!detail.contains("suffice"), "{detail}");
            let Status::Ok(detail) = row(value, true) else {
                panic!(
                    "CAP_SYS_ADMIN lifts paranoid {value:?}: {:?}",
                    row(value, true)
                );
            };
            assert!(
                detail.contains("this process has CAP_SYS_ADMIN"),
                "{detail}"
            );
        }
        for value in ["-1\n", "0\n", "1\n", "2\n"] {
            let Status::Ok(detail) = row(value, false) else {
                panic!(
                    "paranoid {value:?} gates nothing for CAP_PERFMON: {:?}",
                    row(value, false)
                );
            };
            assert!(detail.contains("CAP_BPF+CAP_PERFMON suffice"), "{detail}");
        }
        assert!(matches!(row("x\n", false), Status::Warn(_)));
    }

    /// DR-K8S-1: the `PID namespace` row. Initial is `ok`; a nested or
    /// unreadable namespace warns (cgroup/system captures stay PARTIAL)
    /// and FAILs when `--pid` was requested, because that capture is
    /// refused. The FAIL gates the exit code, names the refusal on the
    /// verdict line, and keeps the tier below T4.
    #[test]
    fn the_pid_namespace_row_refuses_a_requested_pid_scope_outside_the_initial_namespace() {
        use crate::pidns::{ObserverPidNs, PidNumbering, ProcView};
        let with = |observer| PidNumbering {
            observer,
            proc_view: ProcView::Own,
        };
        let initial = pid_namespace_check(&PidNumbering::agreeing(), true);
        assert_eq!(initial.name, PID_NAMESPACE_ROW);
        assert!(
            matches!(&initial.status, Status::Ok(d) if d.starts_with("initial")),
            "{initial:?}"
        );
        let foreign = PidNumbering {
            observer: ObserverPidNs::Initial,
            proc_view: ProcView::Foreign("/proc/self: gone".into()),
        };
        for numbering in [
            with(ObserverPidNs::Nested),
            with(ObserverPidNs::Unknown("gone".into())),
            foreign.clone(),
        ] {
            let observer = &numbering.observer;
            let Status::Warn(detail) = pid_namespace_check(&numbering, false).status else {
                panic!("{observer:?} without --pid must warn");
            };
            assert!(detail.starts_with(observer.label()), "{detail}");
            assert!(detail.contains("pid_namespace"), "{detail}");
            let Status::Fail(detail) = pid_namespace_check(&numbering, true).status else {
                panic!("{observer:?} with --pid must fail");
            };
            assert!(detail.contains("pid-namespace-mismatch"), "{detail}");
        }
        // DR-RETRO-PIDNS-2: a /proc with no entry for this observer fails
        // the row for every scope, saying every capture except inventory
        // --system is refused (inventory --system warns and carries the
        // pid namespace gap instead: inventory.rs lets that scope
        // through, run.rs refuses every classic scope by name).
        let unserved = PidNumbering {
            observer: ObserverPidNs::Unknown("gone".into()),
            proc_view: ProcView::Unserved("/proc/self: ENOENT".into()),
        };
        for pid_requested in [false, true] {
            let Status::Fail(detail) = pid_namespace_check(&unserved, pid_requested).status else {
                panic!("an unserved /proc must fail the row");
            };
            assert!(
                detail.contains("every capture except inventory --system is refused"),
                "{detail}"
            );
            assert!(
                detail.contains("inventory --system warns and carries the pid namespace gap"),
                "{detail}"
            );
            assert!(
                detail.contains(
                    "/proc numbering foreign, no entry for this process: /proc/self: ENOENT"
                ),
                "{detail}"
            );
        }
        let unknown = pid_namespace_check(&with(ObserverPidNs::Unknown("gone".into())), false);
        let foreign_row = pid_namespace_check(&foreign, false);
        assert!(
            matches!(&foreign_row.status, Status::Warn(d) if d.contains("/proc numbering foreign: /proc/self: gone")),
            "{foreign_row:?}"
        );
        assert!(
            matches!(&unknown.status, Status::Warn(d) if d.contains("(gone)")),
            "{unknown:?}"
        );

        let ok_row = |name: &str| Check {
            name: name.into(),
            status: Status::Ok("ok".into()),
        };
        let mut checks = vec![
            ok_row("BPF map create"),
            ok_row(UPROBE_ATTACH_SELF_ROW),
            ok_row("host program preflight"),
            ok_row("target readability"),
            ok_row("lifecycle preflight"),
            ok_row("scope preflight"),
            pid_namespace_check(&PidNumbering::agreeing(), true),
            ok_row("uprobe-multi attach (own libc)"),
        ];
        assert_eq!(verdict(&checks), 0);
        assert_eq!(capability_tier(&checks).tier, CapabilityTier::T4);
        assert!(!verdict_line(&checks).contains("PID scope"));
        checks[6] = pid_namespace_check(&with(ObserverPidNs::Nested), false);
        assert_eq!(verdict(&checks), 0, "a warning does not gate");
        assert!(
            verdict_line(&checks).starts_with("verdict: capture available; "),
            "{}",
            verdict_line(&checks)
        );
        assert!(verdict_line(&checks).contains("PID scope unavailable"));
        checks[6] = pid_namespace_check(&with(ObserverPidNs::Nested), true);
        assert_eq!(verdict(&checks), 1, "a refused --pid lane gates");
        assert_eq!(capability_tier(&checks).tier, CapabilityTier::T3);
        assert!(verdict_line(&checks).contains("PID scope unavailable"));
    }

    /// F3: below the multi floor the per-probe path still needs the old
    /// rule — restrictive paranoid warns verbatim, `CAP_SYS_ADMIN` lifts.
    #[test]
    fn paranoid_row_keeps_the_sysadmin_rule_below_the_multi_floor() {
        let warn = paranoid_status(
            Ok("4\n".into()),
            "/proc/sys/kernel/perf_event_paranoid",
            false,
            false,
        );
        let Status::Warn(detail) = warn else {
            panic!("the per-probe path must still warn: {warn:?}");
        };
        assert!(
            detail.contains("uprobes need CAP_SYS_ADMIN on this host"),
            "{detail}"
        );
        assert!(
            matches!(
                paranoid_status(
                    Ok("4\n".into()),
                    "/proc/sys/kernel/perf_event_paranoid",
                    true,
                    false,
                ),
                Status::Ok(_)
            ),
            "CAP_SYS_ADMIN still lifts paranoid below 6.9"
        );
    }

    // T2 extra-strict (RED): any Warn refuses, even where the default
    // verdict stays green.
    #[test]
    fn extra_strict_refuses_on_any_warn() {
        let checks = vec![
            Check {
                name: "BPF map create".into(),
                status: Status::Ok("created".into()),
            },
            Check {
                name: "kernel.perf_event_paranoid".into(),
                status: Status::Warn("4 — needs privilege".into()),
            },
        ];
        assert_eq!(verdict(&checks), 0, "default verdict tolerates warns");
        assert_eq!(verdict_extra_strict(&checks), 1);
        let names: Vec<&str> = extra_strict_violations(&checks)
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, vec!["kernel.perf_event_paranoid"]);
    }

    // T2 extra-strict (RED): a Fail outside the gated rows refuses too.
    #[test]
    fn extra_strict_refuses_on_fail_outside_gated_rows() {
        let checks = vec![Check {
            name: "kernel release".into(),
            status: Status::Fail("below floor".into()),
        }];
        assert_eq!(verdict(&checks), 0, "kernel release is not a gated row");
        assert_eq!(verdict_extra_strict(&checks), 1);
        assert_eq!(extra_strict_violations(&checks).len(), 1);
    }

    // T2 extra-strict (RED): Ok and NotApplicable rows never violate.
    #[test]
    fn extra_strict_passes_all_ok_and_not_applicable() {
        let checks = vec![
            Check {
                name: "BPF map create".into(),
                status: Status::Ok("created".into()),
            },
            Check {
                name: "target readability".into(),
                status: Status::NotApplicable("no --pid".into()),
            },
        ];
        assert_eq!(verdict_extra_strict(&checks), 0);
        assert!(extra_strict_violations(&checks).is_empty());
    }

    // T2 extra-strict (RED): the render names every violating row.
    // HIGH-5: `loader timing (dlopen): unproven` used to be the sample warn
    // here; it is a by-design limit of this build now listed as not counted,
    // so a genuine host warning stands in for it.
    #[test]
    fn extra_strict_render_names_violating_rows() {
        let checks = vec![
            Check {
                name: "BPF map create".into(),
                status: Status::Fail("EPERM".into()),
            },
            Check {
                name: "live export reads".into(),
                status: Status::Warn("unavailable".into()),
            },
            Check {
                name: "loader timing (dlopen)".into(),
                status: Status::Warn("unproven".into()),
            },
        ];
        let out = render_extra_strict(&checks);
        let refusal = out
            .lines()
            .find(|line| line.starts_with("extra-strict refusal:"))
            .unwrap_or_else(|| panic!("refusal line missing: {out:?}"));
        assert!(refusal.contains("BPF map create"), "{out:?}");
        assert!(refusal.contains("live export reads"), "{out:?}");
        assert!(refusal.contains("2 qualification violation"), "{out:?}");
        assert!(!refusal.contains("loader timing (dlopen)"), "{out:?}");
        assert!(
            out.contains(
                "extra-strict: not counted (limits of this build, the same on every host): \
                 loader timing (dlopen)"
            ),
            "{out:?}"
        );
    }

    // T2 extra-strict (RED): a clean render says so explicitly.
    #[test]
    fn extra_strict_render_clean_states_no_violations() {
        let checks = vec![Check {
            name: "BPF map create".into(),
            status: Status::Ok("created".into()),
        }];
        let out = render_extra_strict(&checks);
        assert!(
            out.contains("extra-strict: no qualification violations"),
            "{out:?}"
        );
        assert!(!out.contains("refusal"), "{out:?}");
    }

    // SYSPLAN residual F-59 (RED): render() sanitizes newlines in details so
    // one check can never forge a second output line.
    #[test]
    fn render_sanitizes_newlines_in_check_details() {
        let out = render(&[Check {
            name: "probe row".into(),
            status: Status::Fail("first line\nverdict: forged".into()),
        }]);
        assert!(
            !out.lines().any(|l| l == "verdict: forged"),
            "raw injected line survived render: {out:?}"
        );
        assert!(
            out.contains("first line\\nverdict: forged"),
            "detail must survive escaped on its own row: {out:?}"
        );
        assert!(
            out.lines().count() == 7,
            "one check must render five summary lines + one row + verdict: {out:?}"
        );
    }

    #[test]
    fn counter_modes_footer_names_availability_per_verdict() {
        use crate::attach::BpfLoopVerdict;
        // Builds without embedded counter objects (WIDE, SMALL) keep the
        // not-enabled line; the ordinary build names the modes available.
        let available_marker = if cfg!(p11scope_counter_objects) {
            "counter modes: available"
        } else {
            "not enabled in this build"
        };
        for (verdict, marker) in [
            (BpfLoopVerdict::Available, available_marker),
            (
                BpfLoopVerdict::Unavailable("test old kernel".into()),
                "counter-mode-unavailable-on-kernel",
            ),
            (
                BpfLoopVerdict::Unknown("test no privilege".into()),
                "test no privilege",
            ),
        ] {
            let line = counter_modes_footer(&verdict);
            assert!(line.starts_with("counter modes: "), "{line:?}");
            assert!(line.ends_with('\n'), "{line:?}");
            assert_eq!(line.lines().count(), 1, "{line:?}");
            assert!(line.contains(marker), "{line:?}");
        }
        // The Available line states the kernel fact behind the verdict.
        assert!(
            counter_modes_footer(&BpfLoopVerdict::Available)
                .contains("the kernel provides bpf_loop (helper 181)")
        );

        // The refusal token appears only on proven absence.
        assert!(
            !counter_modes_footer(&BpfLoopVerdict::Available)
                .contains("counter-mode-unavailable-on-kernel")
        );
        assert!(
            !counter_modes_footer(&BpfLoopVerdict::Unknown("x".into()))
                .contains("counter-mode-unavailable-on-kernel")
        );
        // The ordinary build names every available mode.
        if cfg!(p11scope_counter_objects) {
            let line = counter_modes_footer(&BpfLoopVerdict::Available);
            for mode in ["counts", "timestamps", "latency"] {
                assert!(line.contains(mode), "{line:?}");
            }
            // The Available line scopes the claim: the kernel verifier
            // still has to accept the counter programs (6.1 rejects them).
            assert!(
                line.contains("subject to the kernel verifier accepting the counter programs"),
                "{line:?}"
            );
        }
    }

    #[test]
    fn counter_modes_footer_with_preflight_reports_load_verdicts() {
        use crate::attach::BpfLoopVerdict;
        use p11scope_ebpf_common::CounterMode;
        let loads = |results: [Result<(), String>; 3]| {
            [
                CounterMode::Counts,
                CounterMode::Timestamps,
                CounterMode::Latency,
            ]
            .into_iter()
            .zip(results)
            .collect::<Vec<_>>()
        };
        let oks = loads([Ok(()), Ok(()), Ok(())]);
        let line = counter_modes_footer_with_preflight(&BpfLoopVerdict::Available, Some(&oks));
        if cfg!(p11scope_counter_objects) {
            assert!(
                line.contains("counter objects load on this kernel"),
                "{line:?}"
            );
        } else {
            assert!(line.contains("not enabled in this build"), "{line:?}");
        }
        assert_eq!(line.lines().count(), 1, "{line:?}");
        // A proven old-kernel token replaces the availability sentence.
        let refused = loads([
            Err("counter-mode-unavailable-on-kernel: the kernel verifier rejected a counter program as too complex (E2BIG)".to_string()),
            Ok(()),
            Ok(()),
        ]);
        let line = counter_modes_footer_with_preflight(&BpfLoopVerdict::Available, Some(&refused));
        if cfg!(p11scope_counter_objects) {
            assert!(
                line.starts_with("counter modes: counter-mode-unavailable-on-kernel:"),
                "{line:?}"
            );
            assert_eq!(line.lines().count(), 1, "{line:?}");
        } else {
            assert!(line.contains("not enabled in this build"), "{line:?}");
        }
        // A proven memory-limit refusal replaces the sentence too.
        let capped = loads([
            Err("counter-memory-limit: mode latency P 256 fixed 1 bytes per-bank 2 bytes affordable ceiling 3 endpoints (requested 4)".to_string()),
            Ok(()),
            Ok(()),
        ]);
        let line = counter_modes_footer_with_preflight(&BpfLoopVerdict::Available, Some(&capped));
        if cfg!(p11scope_counter_objects) {
            assert!(
                line.starts_with("counter modes: counter-memory-limit:"),
                "{line:?}"
            );
            assert_eq!(line.lines().count(), 1, "{line:?}");
        } else {
            assert!(line.contains("not enabled in this build"), "{line:?}");
        }
        // An unproven load failure keeps the probe sentence, whatever
        // the build carries.
        let unproven = loads([
            Err("counter object load failed (Operation not permitted (os error 1))".to_string()),
            Ok(()),
            Ok(()),
        ]);
        assert_eq!(
            counter_modes_footer_with_preflight(&BpfLoopVerdict::Available, Some(&unproven)),
            counter_modes_footer(&BpfLoopVerdict::Available)
        );
        // Other verdicts ignore the preflight.
        assert_eq!(
            counter_modes_footer_with_preflight(
                &BpfLoopVerdict::Unavailable("test old kernel".into()),
                Some(&oks)
            ),
            counter_modes_footer(&BpfLoopVerdict::Unavailable("test old kernel".into()))
        );
        assert_eq!(
            counter_modes_footer_with_preflight(&BpfLoopVerdict::Available, None),
            counter_modes_footer(&BpfLoopVerdict::Available)
        );
    }
}
