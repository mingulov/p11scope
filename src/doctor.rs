//! `p11scope doctor`: host and target capability probes with a verdict (spec §4.6).
//! Tells an operator *before* a capture attempt which lanes this host and this
//! target support, and what to change when one does not. `probe` runs the real
//! checks (I/O, temporary BPF loads and attaches); `render` and `verdict` are pure
//! functions over the resulting rows, so the table layout and exit-code logic
//! are both testable without any of the probes running.
//!
//! No BPF program stays loaded after `doctor` returns: `bpf_checks` owns the
//! probe handles are locally owned and drop before `probe` returns.

use anyhow::Result;
use aya::Ebpf;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope};
use aya::programs::{ProgramError, UProbe};
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

fn bounded_verifier_diagnostic(verifier_text: &str) -> String {
    const MAX_BYTES: usize = 4096;
    const PREFIX: &str = "verifier: ";
    const SUFFIX: &str = " [truncated]";

    let escaped = crate::render::escape_controls(verifier_text);
    if escaped.is_empty() {
        return "verifier rejected the embedded program".to_string();
    }
    if PREFIX.len() + escaped.len() <= MAX_BYTES {
        return format!("{PREFIX}{escaped}");
    }
    let mut end = MAX_BYTES - PREFIX.len() - SUFFIX.len();
    while !escaped.is_char_boundary(end) {
        end -= 1;
    }
    format!("{PREFIX}{}{SUFFIX}", &escaped[..end])
}

const KERNEL_FLOOR: (u32, u32) = (5, 15);
/// Named diagnostic bits decoded from `CapEff` in `/proc/self/status`.
const CAP_BITS: [(u32, &str); 6] = [
    (2, "CAP_DAC_READ_SEARCH"),
    (19, "CAP_SYS_PTRACE"),
    (21, "CAP_SYS_ADMIN"),
    (38, "CAP_PERFMON"),
    (39, "CAP_BPF"),
    (40, "CAP_CHECKPOINT_RESTORE"),
];

/// Every probe this slice's lanes need. Pure formatting is separate (`render`,
/// `verdict`) so the table layout and exit code are testable without any of
/// these probes running.
pub fn probe(pid: Option<u32>, cgroup: Option<&Path>) -> Vec<Check> {
    let mut checks = vec![
        kernel_release_check(),
        btf_check(),
        lockdown_check(),
        sysctl_check(
            "kernel.perf_event_paranoid",
            "/proc/sys/kernel/perf_event_paranoid",
            3,
            "uprobes need CAP_SYS_ADMIN on this host",
        ),
        sysctl_check(
            "kernel.yama.ptrace_scope",
            "/proc/sys/kernel/yama/ptrace_scope",
            1,
            "same-uid non-descendants need CAP_SYS_PTRACE",
        ),
        capabilities_check(),
    ];
    checks.extend(bpf_checks());
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
    checks.push(match cgroup {
        Some(cgroup) => cgroup_check(cgroup),
        None => not_applicable("cgroup path", "no --cgroup"),
    });
    checks.extend(attach_preflight);
    checks
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
            let pid_scope = pid.map_or(true, |pid| {
                if pid == self_pid {
                    host_scope
                } else {
                    crate::attach::Session::preflight(&crate::attach::Scope::Pid(pid))
                        .is_ok_and(|fact| fact.scope)
                }
            });
            let cgroup_scope = cgroup.is_none_or(|path| {
                crate::scope::cgroup(path)
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
        Check {
            name: "lifecycle preflight".into(),
            status: status(lifecycle),
        },
        scope,
    ]
}

fn not_applicable(name: &str, reason: &str) -> Check {
    Check {
        name: name.to_string(),
        status: Status::NotApplicable(reason.to_string()),
    }
}

fn parse_major_minor(release: &str) -> Option<(u32, u32)> {
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
            match parse_major_minor(&release) {
                Some(version) if version >= KERNEL_FLOOR => Status::Ok(format!(
                    "{release} (floor {}.{})",
                    KERNEL_FLOOR.0, KERNEL_FLOOR.1
                )),
                Some(_) => Status::Warn(format!(
                    "{release} is below the documented floor {}.{}",
                    KERNEL_FLOOR.0, KERNEL_FLOOR.1
                )),
                None => Status::Warn(format!("{release}: could not parse a kernel version")),
            }
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
fn sysctl_check(name: &str, path: &str, warn_at: i64, warn_msg: &str) -> Check {
    let status = match std::fs::read_to_string(path) {
        Ok(content) => {
            let trimmed = content.trim();
            match trimmed.parse::<i64>() {
                Ok(v) if v >= warn_at => Status::Warn(format!("{v} — {warn_msg}")),
                Ok(v) => Status::Ok(v.to_string()),
                Err(_) => Status::Warn(format!("{trimmed}: unparsable value")),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Status::Ok("not present".to_string()),
        Err(e) => Status::Warn(format!("{path}: {e}")),
    };
    Check {
        name: name.to_string(),
        status,
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
    const MAX_BYTES: usize = 512;
    let message = error.to_string();
    let escaped = crate::render::escape_controls(&message);
    if escaped.len() <= MAX_BYTES {
        return escaped.into_owned();
    }
    let mut end = MAX_BYTES;
    while !escaped.is_char_boundary(end) {
        end -= 1;
    }
    escaped[..end].to_string()
}

fn format_preflight_error(mut error: &(dyn std::error::Error + 'static)) -> String {
    loop {
        if let Some(ProgramError::LoadError { verifier_log, .. }) =
            error.downcast_ref::<ProgramError>()
        {
            return bounded_verifier_diagnostic(&verifier_log.to_string());
        }
        let Some(source) = error.source() else {
            return bounded_error_detail(error);
        };
        error = source;
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

/// `BPF map create` (`Ebpf::load` succeeding) and `uprobe attach` (attaching
/// `p11_entry` to the observer's own libc, then dropping). Both rows share
/// one `Ebpf` handle, which is local to this function and therefore dropped
/// — detaching and unloading everything — before it returns.
fn bpf_checks() -> Vec<Check> {
    match Ebpf::load(crate::EBPF_OBJECT) {
        Ok(mut ebpf) => {
            let map_create = Check {
                name: "BPF map create".to_string(),
                status: Status::Ok(String::new()),
            };
            let uprobe = uprobe_attach_check(&mut ebpf);
            vec![map_create, uprobe]
        }
        Err(e) => vec![
            Check {
                name: "BPF map create".to_string(),
                status: Status::Fail(format!(
                    "{} — {}",
                    format_operation_error(&e),
                    crate::attach::UNSUPPORTED_ENV_HINT
                )),
            },
            Check {
                name: "uprobe attach (own libc)".to_string(),
                status: Status::Fail("skipped: BPF map create failed".to_string()),
            },
        ],
    }
}

fn uprobe_attach_check(ebpf: &mut Ebpf) -> Check {
    let status = match attach_self_probe(ebpf) {
        Ok(()) => Status::Ok("attached and detached".to_string()),
        Err(e) => Status::Fail(e),
    };
    Check {
        name: "uprobe attach (own libc)".to_string(),
        status,
    }
}

/// Finds the observer's own libc via `/proc/self/maps` (reusing the shared
/// maps parser, Task 3), resolves `getpid`'s file offset via
/// `p11scope_manifest::elf::symbol_file_offset` (Task 4) rather than
/// hardcoding one, then loads and attaches `p11_entry` there. The link and
/// the loaded program both live inside `ebpf`, which the caller drops.
fn attach_self_probe(ebpf: &mut Ebpf) -> Result<(), String> {
    let libc_path = own_libc_path()?;
    let file = std::fs::File::open(&libc_path)
        .map_err(|e| format!("open {}: {e}", libc_path.display()))?;
    let offset = p11scope_manifest::elf::symbol_file_offset(&file, "getpid")?
        .ok_or_else(|| format!("getpid not exported by {}", libc_path.display()))?;

    let prog: &mut UProbe = ebpf
        .program_mut("p11_entry")
        .ok_or_else(|| "program p11_entry missing from the BPF object".to_string())?
        .try_into()
        .map_err(|e: aya::programs::ProgramError| e.to_string())?;
    prog.load().map_err(|error| match error {
        ProgramError::LoadError { verifier_log, .. } => {
            bounded_verifier_diagnostic(&verifier_log.to_string())
        }
        error => format!(
            "loading p11_entry: {} — {}",
            format_operation_error(&error),
            crate::attach::UNSUPPORTED_ENV_HINT
        ),
    })?;
    let point = UProbeAttachPoint {
        location: UProbeAttachLocation::AbsoluteOffset(offset),
        cookie: None,
    };
    prog.attach(point, &libc_path, UProbeScope::CallingProcess)
        .map_err(|e| {
            format!(
                "{} — {}",
                format_operation_error(&e),
                crate::attach::UNSUPPORTED_ENV_HINT
            )
        })?;
    Ok(())
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
    let state = loader.defined_symbol("_r_debug").ok().flatten().is_some();
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
    let entries = p11scope_manifest::maps::parse_maps(&bytes)?;
    entries
        .into_iter()
        .find_map(|entry| {
            if entry.permissions[2] != b'x' {
                return None;
            }
            let raw = entry.raw_path?;
            let text = String::from_utf8_lossy(&raw).into_owned();
            text.contains("libc.so").then(|| PathBuf::from(text))
        })
        .ok_or_else(|| "no executable libc.so mapping in /proc/self/maps".to_string())
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
    let index = MapIndex::new(&entries).ok_or("maps invalid")?;
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
    let provider_identities_opened = (|| {
        let mut providers = 0usize;
        for (expected, path) in executable_objects {
            let target_path = Path::new(&root).join(
                path.strip_prefix("/")
                    .map_err(|_| "executable identity unavailable")?,
            );
            let (file, actual) = crate::discovery::identity::open_view_object(&view, &target_path)
                .map_err(|_| "executable identity unavailable")?;
            if actual != expected {
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

fn cgroup_check(cgroup: &Path) -> Check {
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
        host_attach: row_ok("kernel release")
            && row_ok("BPF map create")
            && row_ok("uprobe attach (own libc)")
            && row_ok("host program preflight"),
        target_readable,
        lifecycle: row_ok("lifecycle preflight"),
        scope: row_ok("scope preflight"),
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

fn verdict_line(checks: &[Check]) -> String {
    let capture_ok = !checks
        .iter()
        .any(|c| is_capture_row(&c.name) && matches!(c.status, Status::Fail(_)));
    let mut parts = vec![format!(
        "capture {}",
        if capture_ok {
            "available"
        } else {
            "unavailable"
        }
    )];

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
    format!("verdict: {}", parts.join("; "))
}

/// Pads `name` to 34 columns with dots and prints `ok` / `warn` / `FAIL` /
/// `n/a` followed by the detail (when there is one), then a final
/// `verdict:` line naming what is available. Pure: takes the probe result,
/// returns the text, so the layout is testable without any probe running.
pub fn render(checks: &[Check]) -> String {
    let mut out = String::new();
    for check in checks {
        let dots = NAME_WIDTH.saturating_sub(check.name.chars().count());
        let word = status_word(&check.status);
        let detail = status_detail(&check.status);
        let _ = write!(out, "{} {} {word}", check.name, ".".repeat(dots));
        if !detail.is_empty() {
            let pad = STATUS_WIDTH.saturating_sub(word.len());
            let _ = write!(out, "{}{detail}", " ".repeat(pad));
        }
        out.push('\n');
    }
    let _ = writeln!(out, "{}", capability_tier_line(capability_tier(checks)));
    let _ = write!(out, "{}", verdict_line(checks));
    out
}

/// Exit code: 0 when the capture lane (and the scan lane, if `--pid` was
/// given, and the cgroup lane, if `--cgroup` was given) is available, 1
/// otherwise. Takes no pid/cgroup parameter: a lane that was not requested
/// is always recorded `Status::NotApplicable`, never `Fail`, so "any `Fail`
/// in a requested lane" reduces to "any `Fail` among these fixed row names".
pub fn verdict(checks: &[Check]) -> i32 {
    let gated = checks.iter().any(|c| {
        (is_capture_row(&c.name)
            || is_target_row(&c.name)
            || is_scan_row(&c.name)
            || is_cgroup_row(&c.name)
            || is_run_capture_row(&c.name))
            && matches!(c.status, Status::Fail(_))
    });
    if gated { 1 } else { 0 }
}

/// `p11scope doctor`: probes, prints the table, returns the exit code.
pub fn run(pid: Option<u32>, cgroup: Option<&Path>) -> Result<i32> {
    let checks = probe(pid, cgroup);
    print!("{}", render(&checks));
    Ok(verdict(&checks))
}

#[cfg(test)]
mod tests {
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
                name: "kernel release".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "BPF map create".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "uprobe attach (own libc)".into(),
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
                name: "kernel release".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "BPF map create".into(),
                status: Status::Ok(String::new()),
            },
            Check {
                name: "uprobe attach (own libc)".into(),
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
        let escaped = only_verifier_text("verifier\u{1b}[2J\rdenied");
        assert_eq!(escaped, r"verifier: verifier\u{1b}[2J\rdenied");

        let diagnostic = bounded_verifier_diagnostic(&"é".repeat(4096));
        assert_eq!(
            diagnostic.len(),
            4096,
            "complete fragment must fill its cap"
        );
        assert!(diagnostic.ends_with(" [truncated]"), "{diagnostic:?}");
        assert!(std::str::from_utf8(diagnostic.as_bytes()).is_ok());
        assert!(!diagnostic.contains('\u{fffd}'), "a UTF-8 scalar was split");
    }

    #[test]
    fn wrapped_program_load_error_surfaces_only_the_bounded_verifier_log() {
        let error = ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::EPERM),
            verifier_log: aya_obj::VerifierLog::new("denied\u{1b}[2J".to_string()),
        };
        let wrapped = anyhow::Error::new(error).context("forbidden /proc/target/path");
        let rendered = format_preflight_error(wrapped.as_ref());
        assert_eq!(rendered, r"verifier: denied\u{1b}[2J");
        assert!(!rendered.contains("/proc/target/path"));
        assert!(!rendered.contains("Operation not permitted"));

        let long = ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::EPERM),
            verifier_log: aya_obj::VerifierLog::new("é".repeat(4096)),
        };
        let rendered = format_preflight_error(anyhow::Error::new(long).as_ref());
        assert_eq!(rendered.len(), 4096);
        assert!(rendered.ends_with(" [truncated]"));
        assert!(std::str::from_utf8(rendered.as_bytes()).is_ok());
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
        let checks = probe(None, None);
        // 12 host/target rows, eight §10.1 rows, and three finite preflight rows.
        assert_eq!(checks.len(), 23, "{checks:?}");
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

    /// A degraded timing value is a warning: it makes complete timing
    /// unavailable without making every capture lane fatal. A requested lane
    /// that is genuinely unavailable stays nonzero.
    #[test]
    fn a_degraded_timing_row_warns_while_a_requested_lane_still_refuses() {
        let degraded = vec![
            Check {
                name: "uprobe attach (own libc)".into(),
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
}
