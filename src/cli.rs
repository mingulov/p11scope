//! SPDX-License-Identifier: GPL-3.0-or-later
//! Command-line parsing for every subcommand: one parser body for profile and
//! trace, durations with suffixes, hints for removed flags.

use crate::attach::BackendSelection;
use crate::discovery::hooks::HookRegistry;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Profile,
    Trace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeArg {
    Pid(u32),
    Cgroup(PathBuf),
    System,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureArgs {
    pub kind: Kind,
    /// `--module` hints; empty ⇒ discover every PKCS#11-looking object in scope.
    pub modules: Vec<PathBuf>,
    /// `--manifest` inputs; empty ⇒ scan only. Repeatable (spec §4.6).
    pub manifests: Vec<PathBuf>,
    pub hooks: HookRegistry,
    pub scope: ScopeArg,
    /// `--mode metrics` (profile only).
    pub metrics: bool,
    pub duration: Option<Duration>,
    pub out: Option<PathBuf>,
    pub max_events: Option<u64>,
    /// `--max-scan-pids`: scope members scanned per pass; None ⇒ 256 default.
    pub max_scan_pids: Option<usize>,
    /// `--ring-bytes`: EVENTS ringbuf size override; None ⇒ 4 MiB default.
    pub ring_bytes: Option<u32>,
    /// `--drain-interval-ms`: capture-loop tick override; None ⇒ per-mode default.
    pub drain_interval: Option<Duration>,
    pub unsafe_requested: bool,
    /// `--allow-uretprobe-on-confined-target`: attach uretprobes even when this
    /// kernel is measured to kill a seccomp-confined target for doing so.
    pub allow_confined_uretprobe: bool,
    /// `--attach-backend`: static attach backend; Auto follows the policy.
    pub attach_backend: BackendSelection,
}

/// What `run` is allowed to do to its own child to keep loader discovery from
/// racing an unobserved `dlopen`. `Never` is the omission default: nothing this
/// observer starts is stopped unless the operator asked for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PausePolicy {
    #[default]
    Never,
    Auto,
    Always,
}

/// `p11scope run`: the capture options above, plus the child this observer
/// starts and owns. There is no scope flag — the scope *is* the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunArgs {
    /// `--trace` selects `Kind::Trace`; otherwise this is a profile capture.
    pub kind: Kind,
    pub modules: Vec<PathBuf>,
    pub manifests: Vec<PathBuf>,
    pub hooks: HookRegistry,
    /// `--mode metrics` (rejected beside `--trace`).
    pub metrics: bool,
    pub duration: Option<Duration>,
    pub out: Option<PathBuf>,
    pub max_events: Option<u64>,
    /// `--max-scan-pids`: scope members scanned per pass; None ⇒ 256 default.
    pub max_scan_pids: Option<usize>,
    /// `--ring-bytes`: EVENTS ringbuf size override; None ⇒ 4 MiB default.
    pub ring_bytes: Option<u32>,
    /// `--drain-interval-ms`: capture-loop tick override; None ⇒ per-mode default.
    pub drain_interval: Option<Duration>,
    pub unsafe_requested: bool,
    /// `--allow-uretprobe-on-confined-target`: attach uretprobes even when this
    /// kernel is measured to kill a seccomp-confined target for doing so.
    pub allow_confined_uretprobe: bool,
    pub pause: PausePolicy,
    /// `--attach-backend`: static attach backend; Auto follows the policy.
    pub attach_backend: BackendSelection,
    /// `--kill-on-timeout`: `--duration` expiry ends the child too, instead of
    /// handing it back still running.
    pub kill_on_timeout: bool,
    /// Everything after `--`, verbatim — bytes, not text: Linux arguments
    /// need not be UTF-8 (M-9). Never empty.
    pub command: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectArgs {
    pub pid: u32,
    pub modules: Vec<PathBuf>,
    pub hooks: HookRegistry,
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorArgs {
    pub pid: Option<u32>,
    pub cgroup: Option<PathBuf>,
    pub extra_strict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Version,
    Profile(CaptureArgs),
    Trace(CaptureArgs),
    Run(RunArgs),
    Inspect(InspectArgs),
    Doctor(DoctorArgs),
}

/// Which help text `--help` asked for: the global usage or one subcommand's
/// scoped section plus the shared notes footer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpTopic {
    Global,
    Profile,
    Trace,
    Run,
    Inspect,
    Doctor,
}

impl HelpTopic {
    pub fn text(self) -> &'static str {
        match self {
            HelpTopic::Global => USAGE,
            HelpTopic::Profile => PROFILE_HELP,
            HelpTopic::Trace => TRACE_HELP,
            HelpTopic::Run => RUN_HELP,
            HelpTopic::Inspect => INSPECT_HELP,
            HelpTopic::Doctor => DOCTOR_HELP,
        }
    }
}

impl Kind {
    fn help_topic(self) -> HelpTopic {
        match self {
            Kind::Profile => HelpTopic::Profile,
            Kind::Trace => HelpTopic::Trace,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    Usage(String),
    Help(HelpTopic),
}

pub const USAGE: &str = "usage:
  p11scope --version
  p11scope profile [--pid <n> | --cgroup <path> | --system] [--module <provider.so>]... [--manifest <m.json>]...
                   [--mode profile|metrics] [--duration <30|30s|5m|1h>] [-o <out.json>]
                   [--hook-symbol <NAME[:functionlist|interfacelist|interface]>]...
                   [--unsafe-unvalidated-metadata]
                   [--allow-uretprobe-on-confined-target]
                   [--ring-bytes <n[K|M]>] [--drain-interval-ms <n>]
                   [--attach-backend auto|multi|singles]
                   [--max-scan-pids <n>]
  p11scope trace   [same scope and discovery options] [--duration <…>] [--max-events <n>] [-o <out.file>]
                   [--ring-bytes <n[K|M]>] [--drain-interval-ms <n>]
                   [--attach-backend auto|multi|singles]
  p11scope run     [same discovery options] [--mode profile|metrics | --trace] [--duration <…>]
                   [-o <out>] [--pause never|auto|always] [--kill-on-timeout]
                   [--attach-backend auto|multi|singles]
                   [--ring-bytes <n[K|M]>] [--drain-interval-ms <n>] -- CMD [ARGS...]
  p11scope inspect --pid <n> [--module <provider.so>]... [--hook-symbol <…>]... [--json]
  p11scope doctor  [--pid <n>] [--cgroup <path>] [--extra-strict]
  p11scope-discover --module <provider.so> [-o <manifest.json>]   (offline helper; executes provider code)

notes: discovery scans the target's mapped memory — no manifest and no helper are required.
--module narrows the scan to named providers. --manifest is explicit operator attestation of exact accepted function-name/offset claims; it is corroborated against the scan when possible.
scan-only discovery is semantics-unverified and count-only; aggregate counts/RVs/latency remain available. Scanning continues for the life of the capture, not just at attach.
run starts CMD itself and captures exactly that command; it takes no --pid/--cgroup/--system. --pause
selects what run may do to its own child while it observes loading: never (default) touches
nothing, auto only when the child would otherwise load unobserved, always on every load.
--kill-on-timeout ends the child when --duration expires instead of leaving it running.
--attach-backend selects the static probe backend: auto (default) uses one
multi-uprobe link per attach group on kernels 6.9+ and per-offset links below,
multi forces multi (needs 6.6+), singles forces per-offset. Dynamic loader and
export probes always use per-offset links.
--mode defaults to profile; --mode metrics is the lighter maps-only level. Ctrl-C or SIGTERM
ends a capture cleanly (final frame printed, -o written). --cgroup matches that cgroup and
every descendant (kernel >= 5.15). --system requests whole-machine capture with
no cgroup path; per-process and per-module attribution is still recorded. Provider
identity is pinned by SHA-256 at attach and
checked for in-place change during capture (evidence.provider_changed).
trace without --max-events still stops at a 10,000,000-event default cap; the TRUNCATED line cites the effective cap.
environment: P11SCOPE_BROAD_ADMIT=1 enables experiment-only broad provider admission (anything else keeps the narrow default).
P11SCOPE_LOADER_ENV_SANITIZED is the offline discover helper's loader-environment marker (forged values are rejected).
capture evidence records the active value of each (evidence.p11scope_env); docs/usage.md documents every P11SCOPE_* input.
";
/// `p11scope profile --help`: that subcommand's usage section plus the
/// shared notes footer. Every line is verbatim from [`USAGE`]; update
/// both together when the CLI changes.
const PROFILE_HELP: &str = "usage:
  p11scope profile [--pid <n> | --cgroup <path> | --system] [--module <provider.so>]... [--manifest <m.json>]...
                   [--mode profile|metrics] [--duration <30|30s|5m|1h>] [-o <out.json>]
                   [--hook-symbol <NAME[:functionlist|interfacelist|interface]>]...
                   [--unsafe-unvalidated-metadata]
                   [--allow-uretprobe-on-confined-target]
                   [--ring-bytes <n[K|M]>] [--drain-interval-ms <n>]
                   [--attach-backend auto|multi|singles]
                   [--max-scan-pids <n>]

notes: discovery scans the target's mapped memory — no manifest and no helper are required.
--module narrows the scan to named providers. --manifest is explicit operator attestation of exact accepted function-name/offset claims; it is corroborated against the scan when possible.
scan-only discovery is semantics-unverified and count-only; aggregate counts/RVs/latency remain available. Scanning continues for the life of the capture, not just at attach.
run starts CMD itself and captures exactly that command; it takes no --pid/--cgroup/--system. --pause
selects what run may do to its own child while it observes loading: never (default) touches
nothing, auto only when the child would otherwise load unobserved, always on every load.
--kill-on-timeout ends the child when --duration expires instead of leaving it running.
--attach-backend selects the static probe backend: auto (default) uses one
multi-uprobe link per attach group on kernels 6.9+ and per-offset links below,
multi forces multi (needs 6.6+), singles forces per-offset. Dynamic loader and
export probes always use per-offset links.
--mode defaults to profile; --mode metrics is the lighter maps-only level. Ctrl-C or SIGTERM
ends a capture cleanly (final frame printed, -o written). --cgroup matches that cgroup and
every descendant (kernel >= 5.15). --system requests whole-machine capture with
no cgroup path; per-process and per-module attribution is still recorded. Provider
identity is pinned by SHA-256 at attach and
checked for in-place change during capture (evidence.provider_changed).
trace without --max-events still stops at a 10,000,000-event default cap; the TRUNCATED line cites the effective cap.
environment: P11SCOPE_BROAD_ADMIT=1 enables experiment-only broad provider admission (anything else keeps the narrow default).
P11SCOPE_LOADER_ENV_SANITIZED is the offline discover helper's loader-environment marker (forged values are rejected).
capture evidence records the active value of each (evidence.p11scope_env); docs/usage.md documents every P11SCOPE_* input.
";

/// `p11scope trace --help`: that subcommand's usage section plus the
/// shared notes footer. Every line is verbatim from [`USAGE`]; update
/// both together when the CLI changes.
const TRACE_HELP: &str = "usage:
  p11scope trace   [same scope and discovery options] [--duration <…>] [--max-events <n>] [-o <out.file>]
                   [--ring-bytes <n[K|M]>] [--drain-interval-ms <n>]
                   [--attach-backend auto|multi|singles]

notes: discovery scans the target's mapped memory — no manifest and no helper are required.
--module narrows the scan to named providers. --manifest is explicit operator attestation of exact accepted function-name/offset claims; it is corroborated against the scan when possible.
scan-only discovery is semantics-unverified and count-only; aggregate counts/RVs/latency remain available. Scanning continues for the life of the capture, not just at attach.
run starts CMD itself and captures exactly that command; it takes no --pid/--cgroup/--system. --pause
selects what run may do to its own child while it observes loading: never (default) touches
nothing, auto only when the child would otherwise load unobserved, always on every load.
--kill-on-timeout ends the child when --duration expires instead of leaving it running.
--attach-backend selects the static probe backend: auto (default) uses one
multi-uprobe link per attach group on kernels 6.9+ and per-offset links below,
multi forces multi (needs 6.6+), singles forces per-offset. Dynamic loader and
export probes always use per-offset links.
--mode defaults to profile; --mode metrics is the lighter maps-only level. Ctrl-C or SIGTERM
ends a capture cleanly (final frame printed, -o written). --cgroup matches that cgroup and
every descendant (kernel >= 5.15). --system requests whole-machine capture with
no cgroup path; per-process and per-module attribution is still recorded. Provider
identity is pinned by SHA-256 at attach and
checked for in-place change during capture (evidence.provider_changed).
trace without --max-events still stops at a 10,000,000-event default cap; the TRUNCATED line cites the effective cap.
environment: P11SCOPE_BROAD_ADMIT=1 enables experiment-only broad provider admission (anything else keeps the narrow default).
P11SCOPE_LOADER_ENV_SANITIZED is the offline discover helper's loader-environment marker (forged values are rejected).
capture evidence records the active value of each (evidence.p11scope_env); docs/usage.md documents every P11SCOPE_* input.
";

/// `p11scope run --help`: that subcommand's usage section plus the
/// shared notes footer. Every line is verbatim from [`USAGE`]; update
/// both together when the CLI changes.
const RUN_HELP: &str = "usage:
  p11scope run     [same discovery options] [--mode profile|metrics | --trace] [--duration <…>]
                   [-o <out>] [--pause never|auto|always] [--kill-on-timeout]
                   [--attach-backend auto|multi|singles]
                   [--ring-bytes <n[K|M]>] [--drain-interval-ms <n>] -- CMD [ARGS...]

notes: discovery scans the target's mapped memory — no manifest and no helper are required.
--module narrows the scan to named providers. --manifest is explicit operator attestation of exact accepted function-name/offset claims; it is corroborated against the scan when possible.
scan-only discovery is semantics-unverified and count-only; aggregate counts/RVs/latency remain available. Scanning continues for the life of the capture, not just at attach.
run starts CMD itself and captures exactly that command; it takes no --pid/--cgroup/--system. --pause
selects what run may do to its own child while it observes loading: never (default) touches
nothing, auto only when the child would otherwise load unobserved, always on every load.
--kill-on-timeout ends the child when --duration expires instead of leaving it running.
--attach-backend selects the static probe backend: auto (default) uses one
multi-uprobe link per attach group on kernels 6.9+ and per-offset links below,
multi forces multi (needs 6.6+), singles forces per-offset. Dynamic loader and
export probes always use per-offset links.
--mode defaults to profile; --mode metrics is the lighter maps-only level. Ctrl-C or SIGTERM
ends a capture cleanly (final frame printed, -o written). --cgroup matches that cgroup and
every descendant (kernel >= 5.15). --system requests whole-machine capture with
no cgroup path; per-process and per-module attribution is still recorded. Provider
identity is pinned by SHA-256 at attach and
checked for in-place change during capture (evidence.provider_changed).
trace without --max-events still stops at a 10,000,000-event default cap; the TRUNCATED line cites the effective cap.
environment: P11SCOPE_BROAD_ADMIT=1 enables experiment-only broad provider admission (anything else keeps the narrow default).
P11SCOPE_LOADER_ENV_SANITIZED is the offline discover helper's loader-environment marker (forged values are rejected).
capture evidence records the active value of each (evidence.p11scope_env); docs/usage.md documents every P11SCOPE_* input.
";

/// `p11scope inspect --help`: that subcommand's usage section plus the
/// shared notes footer. Every line is verbatim from [`USAGE`]; update
/// both together when the CLI changes.
const INSPECT_HELP: &str = "usage:
  p11scope inspect --pid <n> [--module <provider.so>]... [--hook-symbol <…>]... [--json]

notes: discovery scans the target's mapped memory — no manifest and no helper are required.
--module narrows the scan to named providers. --manifest is explicit operator attestation of exact accepted function-name/offset claims; it is corroborated against the scan when possible.
scan-only discovery is semantics-unverified and count-only; aggregate counts/RVs/latency remain available. Scanning continues for the life of the capture, not just at attach.
run starts CMD itself and captures exactly that command; it takes no --pid/--cgroup/--system. --pause
selects what run may do to its own child while it observes loading: never (default) touches
nothing, auto only when the child would otherwise load unobserved, always on every load.
--kill-on-timeout ends the child when --duration expires instead of leaving it running.
--attach-backend selects the static probe backend: auto (default) uses one
multi-uprobe link per attach group on kernels 6.9+ and per-offset links below,
multi forces multi (needs 6.6+), singles forces per-offset. Dynamic loader and
export probes always use per-offset links.
--mode defaults to profile; --mode metrics is the lighter maps-only level. Ctrl-C or SIGTERM
ends a capture cleanly (final frame printed, -o written). --cgroup matches that cgroup and
every descendant (kernel >= 5.15). --system requests whole-machine capture with
no cgroup path; per-process and per-module attribution is still recorded. Provider
identity is pinned by SHA-256 at attach and
checked for in-place change during capture (evidence.provider_changed).
trace without --max-events still stops at a 10,000,000-event default cap; the TRUNCATED line cites the effective cap.
environment: P11SCOPE_BROAD_ADMIT=1 enables experiment-only broad provider admission (anything else keeps the narrow default).
P11SCOPE_LOADER_ENV_SANITIZED is the offline discover helper's loader-environment marker (forged values are rejected).
capture evidence records the active value of each (evidence.p11scope_env); docs/usage.md documents every P11SCOPE_* input.
";

/// `p11scope doctor --help`: that subcommand's usage section plus the
/// shared notes footer. Every line is verbatim from [`USAGE`]; update
/// both together when the CLI changes.
const DOCTOR_HELP: &str = "usage:
  p11scope doctor  [--pid <n>] [--cgroup <path>] [--extra-strict]

notes: discovery scans the target's mapped memory — no manifest and no helper are required.
--module narrows the scan to named providers. --manifest is explicit operator attestation of exact accepted function-name/offset claims; it is corroborated against the scan when possible.
scan-only discovery is semantics-unverified and count-only; aggregate counts/RVs/latency remain available. Scanning continues for the life of the capture, not just at attach.
run starts CMD itself and captures exactly that command; it takes no --pid/--cgroup/--system. --pause
selects what run may do to its own child while it observes loading: never (default) touches
nothing, auto only when the child would otherwise load unobserved, always on every load.
--kill-on-timeout ends the child when --duration expires instead of leaving it running.
--attach-backend selects the static probe backend: auto (default) uses one
multi-uprobe link per attach group on kernels 6.9+ and per-offset links below,
multi forces multi (needs 6.6+), singles forces per-offset. Dynamic loader and
export probes always use per-offset links.
--mode defaults to profile; --mode metrics is the lighter maps-only level. Ctrl-C or SIGTERM
ends a capture cleanly (final frame printed, -o written). --cgroup matches that cgroup and
every descendant (kernel >= 5.15). --system requests whole-machine capture with
no cgroup path; per-process and per-module attribution is still recorded. Provider
identity is pinned by SHA-256 at attach and
checked for in-place change during capture (evidence.provider_changed).
trace without --max-events still stops at a 10,000,000-event default cap; the TRUNCATED line cites the effective cap.
environment: P11SCOPE_BROAD_ADMIT=1 enables experiment-only broad provider admission (anything else keeps the narrow default).
P11SCOPE_LOADER_ENV_SANITIZED is the offline discover helper's loader-environment marker (forged values are rejected).
capture evidence records the active value of each (evidence.p11scope_env); docs/usage.md documents every P11SCOPE_* input.
";

const REMOVED_FLAG_HINT: &str = "removed in productization slice 1a: the observer pins provider \
identity by SHA-256 and fstat; see docs/usage.md";

fn usage_err(msg: impl Into<String>) -> CliError {
    CliError::Usage(format!("{}\n{USAGE}", msg.into()))
}

/// A textual option value (a number, a keyword, a hook spec). Linux hands
/// over bytes; a value that is not UTF-8 is a usage error, never a panic.
fn require_value(
    args: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<String, CliError> {
    require_os_value(args, flag)?
        .into_string()
        .map_err(|value| usage_err(format!("{flag}: invalid value {value:?}: not valid UTF-8")))
}

/// A path option value, kept as the exact bytes given (M-9).
fn require_os_value(
    args: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<OsString, CliError> {
    args.next()
        .ok_or_else(|| usage_err(format!("{flag} requires a value")))
}

fn require_path(
    args: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<PathBuf, CliError> {
    let value = require_os_value(args, flag)?;
    if value.is_empty() {
        return Err(usage_err(format!("{flag} requires a non-empty value")));
    }
    Ok(PathBuf::from(value))
}

/// Flags and subcommands are matched as text; a non-UTF-8 word can never
/// equal one, so its lossy form is only ever shown in an "unknown" refusal.
fn word(arg: &std::ffi::OsStr) -> std::borrow::Cow<'_, str> {
    arg.to_string_lossy()
}

fn require_pid(args: &mut impl Iterator<Item = OsString>) -> Result<u32, CliError> {
    let v = require_value(args, "--pid")?;
    let pid: u32 = v
        .parse()
        .map_err(|_| usage_err(format!("--pid: invalid number {v:?}")))?;
    if pid == 0 {
        return Err(usage_err("--pid must be greater than zero"));
    }
    Ok(pid)
}

/// `--hook-symbol NAME[:abi]`, validated by the registry itself so the CLI has
/// no second copy of the ABI names; its message is propagated verbatim.
fn add_hook(
    hooks: &mut HookRegistry,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<(), CliError> {
    let spec = require_value(args, "--hook-symbol")?;
    hooks.add_spec(&spec).map_err(usage_err)
}

/// One place decides what an unrecognised argument means, so a removed flag
/// gets its hint whichever subcommand it was typed after.
fn unknown_arg(arg: &str) -> CliError {
    match arg {
        "--provenance-module" | "--trusted-workload" => {
            usage_err(format!("{arg}: {REMOVED_FLAG_HINT}"))
        }
        // Pause policy is only meaningful for a child this observer owns, so it
        // is refused by name everywhere else rather than silently ignored.
        "--pause" => usage_err(
            "--pause is a `p11scope run` option: only a child this observer started can be \
             paused",
        ),
        other => usage_err(format!("unknown argument: {other}")),
    }
}

/// `run`'s unrecognised argument: a bare word is the command typed without
/// its `--` separator, so the refusal names the separator and the concrete
/// next command; a mistyped flag keeps the generic message.
fn run_unknown_arg(arg: &str) -> CliError {
    if arg.starts_with('-') || arg.is_empty() {
        unknown_arg(arg)
    } else {
        usage_err(format!(
            "unknown argument: {arg} (run takes its command after `--`: `p11scope run -- {arg}`)"
        ))
    }
}

/// The discovery and capture options every capturing subcommand shares.
/// `metrics` stays `None` until `--mode` is given so `--trace`/`trace` can
/// refuse a mode whichever order the two were typed in.
/// `HookRegistry`'s own `Default` is the builtin set, so a defaulted `Common`
/// starts with exactly the five documented hook symbols.
#[derive(Debug, Default)]
struct Common {
    modules: Vec<PathBuf>,
    manifests: Vec<PathBuf>,
    hooks: HookRegistry,
    metrics: Option<bool>,
    duration: Option<Duration>,
    out: Option<PathBuf>,
    max_events: Option<u64>,
    max_scan_pids: Option<usize>,
    ring_bytes: Option<u32>,
    drain_interval: Option<Duration>,
    unsafe_requested: bool,
    allow_confined_uretprobe: bool,
    attach_backend: BackendSelection,
    /// `--attach-backend` is scalar like the rest, but its type has no
    /// unset state, so repeats are tracked separately.
    attach_backend_seen: bool,
}

impl Common {
    /// One `--mode` rule for every capture surface: raw event streaming has no
    /// mode, whether it was selected as the `trace` subcommand or `run --trace`.
    fn metrics_for(&self, kind: Kind, subject: &str) -> Result<bool, CliError> {
        match (kind, self.metrics) {
            (Kind::Trace, Some(_)) => Err(usage_err(format!(
                "{subject} has no --mode; it always streams raw events"
            ))),
            _ => Ok(self.metrics.unwrap_or(false)),
        }
    }
}

/// Handles one shared capture option, or reports that `arg` is not one — so
/// each subcommand keeps exactly its own rules for everything else.
fn capture_option(
    common: &mut Common,
    arg: &str,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<bool, CliError> {
    match arg {
        "--module" => common.modules.push(require_path(args, "--module")?),
        "--manifest" => common.manifests.push(require_path(args, "--manifest")?),
        "--hook-symbol" => add_hook(&mut common.hooks, args)?,
        "--mode" => {
            if common.metrics.is_some() {
                return Err(usage_err("--mode given twice"));
            }
            let v = require_value(args, "--mode")?;
            common.metrics = Some(match v.as_str() {
                "profile" => false,
                "metrics" => true,
                "trace" => {
                    return Err(usage_err(
                        "trace is a subcommand (`p11scope trace …`) or the `run --trace` flag, \
                         not --mode trace",
                    ));
                }
                other => {
                    return Err(usage_err(format!(
                        "--mode: invalid value {other:?} (expected profile|metrics)"
                    )));
                }
            });
        }
        "--duration" => {
            if common.duration.is_some() {
                return Err(usage_err("--duration given twice"));
            }
            let v = require_value(args, "--duration")?;
            let duration = parse_duration(&v)
                .map_err(|e| usage_err(format!("--duration: invalid value {v:?}: {e}")))?;
            if duration.is_zero() {
                return Err(usage_err("--duration must be greater than zero"));
            }
            common.duration = Some(duration);
        }
        "--max-events" => {
            if common.max_events.is_some() {
                return Err(usage_err("--max-events given twice"));
            }
            let v = require_value(args, "--max-events")?;
            let value = v
                .parse::<u64>()
                .map_err(|_| usage_err(format!("--max-events: invalid number {v:?}")))?;
            if value == 0 {
                return Err(usage_err("--max-events must be greater than zero"));
            }
            common.max_events = Some(value);
        }
        "--max-scan-pids" => {
            if common.max_scan_pids.is_some() {
                return Err(usage_err("--max-scan-pids given twice"));
            }
            let v = require_value(args, "--max-scan-pids")?;
            let value = v
                .parse::<usize>()
                .map_err(|_| usage_err(format!("--max-scan-pids: invalid number {v:?}")))?;
            if value == 0 {
                return Err(usage_err("--max-scan-pids must be greater than zero"));
            }
            common.max_scan_pids = Some(value);
        }
        "--ring-bytes" => {
            if common.ring_bytes.is_some() {
                return Err(usage_err("--ring-bytes given twice"));
            }
            let v = require_value(args, "--ring-bytes")?;
            common.ring_bytes = Some(
                parse_ring_bytes(&v)
                    .map_err(|e| usage_err(format!("--ring-bytes: invalid value {v:?}: {e}")))?,
            );
        }
        "--drain-interval-ms" => {
            if common.drain_interval.is_some() {
                return Err(usage_err("--drain-interval-ms given twice"));
            }
            let v = require_value(args, "--drain-interval-ms")?;
            let ms = v
                .parse::<u64>()
                .map_err(|_| usage_err(format!("--drain-interval-ms: invalid number {v:?}")))?;
            if !(5..=60000).contains(&ms) {
                return Err(usage_err("--drain-interval-ms must be between 5 and 60000"));
            }
            common.drain_interval = Some(Duration::from_millis(ms));
        }
        "--attach-backend" => {
            if common.attach_backend_seen {
                return Err(usage_err("--attach-backend given twice"));
            }
            let v = require_value(args, "--attach-backend")?;
            common.attach_backend =
                BackendSelection::from_cli(&v).map_err(|e| usage_err(format!("{e:#}")))?;
            common.attach_backend_seen = true;
        }
        "-o" => {
            if common.out.is_some() {
                return Err(usage_err("-o given twice"));
            }
            common.out = Some(require_path(args, "-o")?);
        }
        "--unsafe-unvalidated-metadata" => common.unsafe_requested = true,
        "--allow-uretprobe-on-confined-target" => common.allow_confined_uretprobe = true,
        _ => return Ok(false),
    }
    Ok(true)
}

/// The whole command line: the subcommand plus its own arguments. Pure — no I/O,
/// no process exit; the caller decides how to report `CliError`. Takes the
/// arguments as the OS gives them (`std::env::args_os`), so a non-UTF-8
/// argument is a usage error or, for a path or a `run` command word, kept
/// byte for byte — never a panic (M-9). `String` items still work.
pub fn parse(argv: impl IntoIterator<Item = impl Into<OsString>>) -> Result<Command, CliError> {
    let mut argv = argv.into_iter().map(Into::into);
    let first = argv.next();
    match first.as_deref().map(word).as_deref() {
        Some("--version" | "-V") => match argv.next() {
            None => Ok(Command::Version),
            Some(_) => Err(usage_err("--version takes no arguments")),
        },
        Some("profile") => Ok(Command::Profile(parse_capture(Kind::Profile, argv)?)),
        Some("trace") => Ok(Command::Trace(parse_capture(Kind::Trace, argv)?)),
        Some("run") => Ok(Command::Run(parse_run(argv)?)),
        Some("inspect") => Ok(Command::Inspect(parse_inspect(argv)?)),
        Some("doctor") => Ok(Command::Doctor(parse_doctor(argv)?)),
        Some("--help" | "-h") => Err(CliError::Help(HelpTopic::Global)),
        Some("discover") => Err(usage_err(
            "`p11scope discover` was removed: run `p11scope-discover --module <provider.so> \
             -o <manifest.json>` (offline helper; executes provider code)",
        )),
        Some(other) => Err(usage_err(format!("unknown subcommand: {other}"))),
        None => Err(usage_err("missing subcommand")),
    }
}

/// `p11scope inspect`: one target, discovery options only — no capture policy,
/// no duration, no output file (spec §4.6).
fn parse_inspect(mut args: impl Iterator<Item = OsString>) -> Result<InspectArgs, CliError> {
    let mut pid: Option<u32> = None;
    let mut modules = Vec::new();
    let mut hooks = HookRegistry::builtin();
    let mut json = false;
    while let Some(a) = args.next() {
        match word(&a).as_ref() {
            "--help" | "-h" => return Err(CliError::Help(HelpTopic::Inspect)),
            "--pid" => {
                if pid.is_some() {
                    return Err(usage_err("--pid given twice"));
                }
                pid = Some(require_pid(&mut args)?);
            }
            "--module" => modules.push(require_path(&mut args, "--module")?),
            "--hook-symbol" => add_hook(&mut hooks, &mut args)?,
            "--json" => json = true,
            other => return Err(unknown_arg(other)),
        }
    }
    Ok(InspectArgs {
        pid: pid.ok_or_else(|| usage_err("inspect requires --pid <n>"))?,
        modules,
        hooks,
        json,
    })
}

/// `p11scope doctor`: every argument optional — a lane nobody named is reported
/// as not applicable rather than failed.
fn parse_doctor(mut args: impl Iterator<Item = OsString>) -> Result<DoctorArgs, CliError> {
    let mut doctor = DoctorArgs {
        pid: None,
        cgroup: None,
        extra_strict: false,
    };
    while let Some(a) = args.next() {
        match word(&a).as_ref() {
            "--help" | "-h" => return Err(CliError::Help(HelpTopic::Doctor)),
            "--pid" => {
                if doctor.pid.is_some() {
                    return Err(usage_err("--pid given twice"));
                }
                doctor.pid = Some(require_pid(&mut args)?);
            }
            "--cgroup" => {
                if doctor.cgroup.is_some() {
                    return Err(usage_err("--cgroup given twice"));
                }
                doctor.cgroup = Some(require_path(&mut args, "--cgroup")?);
            }
            "--extra-strict" => doctor.extra_strict = true,
            "--module" => {
                return Err(usage_err(
                    "doctor --module is not supported; use inspect --pid <n> --module \
                     <provider.so> for module-specific discovery",
                ));
            }
            "--system" => {
                return Err(usage_err(
                    "doctor --system is not supported; doctor checks this host \
                     and takes no capture scope",
                ));
            }
            other => return Err(unknown_arg(other)),
        }
    }
    Ok(doctor)
}

/// Parses the arguments shared by `profile` and `trace` into one
/// `CaptureArgs`. Pure: no I/O, no process exit — the caller decides how
/// to report `CliError`.
pub fn parse_capture(
    kind: Kind,
    args: impl IntoIterator<Item = impl Into<OsString>>,
) -> Result<CaptureArgs, CliError> {
    let mut args = args.into_iter().map(Into::into);
    let mut common = Common::default();
    let mut pid: Option<u32> = None;
    let mut cgroup: Option<PathBuf> = None;
    let mut system = false;

    while let Some(a) = args.next() {
        let arg = word(&a);
        if capture_option(&mut common, &arg, &mut args)? {
            continue;
        }
        match arg.as_ref() {
            "--help" | "-h" => return Err(CliError::Help(kind.help_topic())),
            "--pid" => {
                if pid.is_some() {
                    return Err(usage_err("--pid given twice"));
                }
                pid = Some(require_pid(&mut args)?);
            }
            "--cgroup" => {
                if cgroup.is_some() {
                    return Err(usage_err("--cgroup given twice"));
                }
                cgroup = Some(require_path(&mut args, "--cgroup")?);
            }
            "--system" => system = true,
            other => return Err(unknown_arg(other)),
        }
    }

    let scope = match (pid, cgroup, system) {
        (Some(p), None, false) => ScopeArg::Pid(p),
        (None, Some(c), false) => ScopeArg::Cgroup(c),
        (None, None, true) => ScopeArg::System,
        (None, None, false) => {
            return Err(usage_err(
                "exactly one of --pid, --cgroup, or --system is required",
            ));
        }
        _ => {
            return Err(usage_err(
                "--pid, --cgroup, and --system are mutually exclusive",
            ));
        }
    };

    if kind == Kind::Profile && common.max_events.is_some() {
        return Err(usage_err(
            "--max-events is a trace option; profile publishes one aggregate document",
        ));
    }

    let metrics = common.metrics_for(kind, "trace")?;
    Ok(CaptureArgs {
        kind,
        modules: common.modules,
        manifests: common.manifests,
        hooks: common.hooks,
        scope,
        metrics,
        duration: common.duration,
        out: common.out,
        max_events: common.max_events,
        max_scan_pids: common.max_scan_pids,
        ring_bytes: common.ring_bytes,
        drain_interval: common.drain_interval,
        unsafe_requested: common.unsafe_requested,
        allow_confined_uretprobe: common.allow_confined_uretprobe,
        attach_backend: common.attach_backend,
    })
}

/// `p11scope run`: the shared capture options, this observer's own pause
/// policy, and the command it starts. The command is everything after `--`,
/// taken verbatim so an argument meant for the child is never consumed here.
fn parse_run(mut args: impl Iterator<Item = OsString>) -> Result<RunArgs, CliError> {
    let mut common = Common::default();
    let mut pause = PausePolicy::Never;
    let mut pause_seen = false;
    let mut kill_on_timeout = false;
    let mut trace = false;
    let mut command: Vec<OsString> = Vec::new();

    while let Some(a) = args.next() {
        let arg = word(&a);
        if capture_option(&mut common, &arg, &mut args)? {
            continue;
        }
        match arg.as_ref() {
            "--help" | "-h" => return Err(CliError::Help(HelpTopic::Run)),
            "--trace" => trace = true,
            "--pause" => {
                if pause_seen {
                    return Err(usage_err("--pause given twice"));
                }
                let v = require_value(&mut args, "--pause")?;
                pause_seen = true;
                pause = match v.as_str() {
                    "never" => PausePolicy::Never,
                    "auto" => PausePolicy::Auto,
                    "always" => PausePolicy::Always,
                    other => {
                        return Err(usage_err(format!(
                            "--pause: invalid value {other:?} (expected never|auto|always)"
                        )));
                    }
                };
            }
            "--kill-on-timeout" => kill_on_timeout = true,
            "--pid" | "--cgroup" | "--system" => {
                return Err(usage_err(
                    "run has no --pid, --cgroup, or --system: it captures exactly the command it starts",
                ));
            }
            "--" => {
                command.extend(args.by_ref());
                break;
            }
            other => return Err(run_unknown_arg(other)),
        }
    }

    // No `--`, nothing after it, and an empty program name are the same
    // refusal: there is no command for this observer to start and own.
    if command.first().is_none_or(|program| program.is_empty()) {
        return Err(usage_err(
            "run requires a command: `p11scope run [options] -- CMD [ARGS...]`",
        ));
    }
    let kind = if trace { Kind::Trace } else { Kind::Profile };
    if kind == Kind::Profile && common.max_events.is_some() {
        return Err(usage_err(
            "--max-events is a trace option; profile publishes one aggregate document",
        ));
    }
    let metrics = common.metrics_for(kind, "run --trace")?;
    Ok(RunArgs {
        kind,
        modules: common.modules,
        manifests: common.manifests,
        hooks: common.hooks,
        metrics,
        duration: common.duration,
        out: common.out,
        max_events: common.max_events,
        max_scan_pids: common.max_scan_pids,
        ring_bytes: common.ring_bytes,
        drain_interval: common.drain_interval,
        unsafe_requested: common.unsafe_requested,
        allow_confined_uretprobe: common.allow_confined_uretprobe,
        pause,
        attach_backend: common.attach_backend,
        kill_on_timeout,
        command,
    })
}

/// Parses a duration given as bare seconds or with a single trailing
/// `s`/`m`/`h` suffix — `"30"`, `"30s"`, `"5m"`, `"1h"`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (digits, mult) = match s.as_bytes()[s.len() - 1] {
        b's' => (&s[..s.len() - 1], 1u64),
        b'm' => (&s[..s.len() - 1], 60u64),
        b'h' => (&s[..s.len() - 1], 3600u64),
        _ => (s, 1u64),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid duration {s:?}"));
    }
    let secs: u64 = digits
        .parse()
        .map_err(|_| format!("invalid duration {s:?}"))?;
    let secs = secs
        .checked_mul(mult)
        .ok_or_else(|| format!("duration {s:?} overflows"))?;
    Ok(Duration::from_secs(secs))
}

/// Parses a ring-buffer size given as plain bytes or with a single trailing
/// `K`/`M` suffix — `"262144"`, `"256K"`, `"1M"`. Must be a power of two
/// between one page (4096) and 64 MiB; the kernel ringbuf requires both.
pub fn parse_ring_bytes(s: &str) -> Result<u32, String> {
    if s.is_empty() {
        return Err("empty size".to_string());
    }
    let (digits, mult) = match s.as_bytes()[s.len() - 1] {
        b'K' | b'k' => (&s[..s.len() - 1], 1024u64),
        b'M' | b'm' => (&s[..s.len() - 1], 1024u64 * 1024),
        _ => (s, 1u64),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid size {s:?}"));
    }
    let bytes: u64 = digits.parse().map_err(|_| format!("invalid size {s:?}"))?;
    let bytes = bytes
        .checked_mul(mult)
        .ok_or_else(|| format!("size {s:?} overflows"))?;
    if !(4096..=67108864).contains(&bytes) {
        return Err(format!("size {s:?} outside 4K..64M"));
    }
    if !bytes.is_power_of_two() {
        return Err(format!("size {s:?} is not a power of two"));
    }
    Ok(bytes as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::hooks::HookAbi;

    fn args(v: &[&str]) -> std::vec::IntoIter<String> {
        v.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn capture_needs_no_manifest_and_accepts_repeated_discovery_flags() {
        let Command::Profile(a) = parse(args(&[
            "profile",
            "--pid",
            "42",
            "--module",
            "/opt/a.so",
            "--module",
            "/opt/b.so",
            "--manifest",
            "/tmp/m1.json",
            "--manifest",
            "/tmp/m2.json",
            "--hook-symbol",
            "V_GetTable:interface",
        ]))
        .unwrap() else {
            panic!("expected profile")
        };
        assert_eq!(a.modules.len(), 2);
        assert_eq!(a.manifests.len(), 2);
        assert_eq!(a.hooks.abi("V_GetTable"), Some(HookAbi::Interface));
        assert_eq!(a.scope, ScopeArg::Pid(42));
    }

    #[test]
    fn a_scalar_flag_given_twice_is_a_usage_error_naming_the_flag() {
        for (argv, flag) in [
            (
                vec![
                    "profile",
                    "--pid",
                    "42",
                    "--duration",
                    "5",
                    "--duration",
                    "10",
                ],
                "--duration",
            ),
            (vec!["profile", "--pid", "42", "-o", "a", "-o", "b"], "-o"),
            (vec!["profile", "--pid", "1", "--pid", "2"], "--pid"),
            (
                vec![
                    "profile", "--pid", "42", "--mode", "profile", "--mode", "metrics",
                ],
                "--mode",
            ),
            (
                vec![
                    "profile",
                    "--pid",
                    "42",
                    "--ring-bytes",
                    "1M",
                    "--ring-bytes",
                    "2M",
                ],
                "--ring-bytes",
            ),
            (
                vec![
                    "profile",
                    "--pid",
                    "42",
                    "--drain-interval-ms",
                    "50",
                    "--drain-interval-ms",
                    "100",
                ],
                "--drain-interval-ms",
            ),
            (
                vec![
                    "trace",
                    "--pid",
                    "42",
                    "--max-events",
                    "1",
                    "--max-events",
                    "2",
                ],
                "--max-events",
            ),
            (
                vec![
                    "run",
                    "--pause",
                    "never",
                    "--pause",
                    "auto",
                    "--",
                    "/bin/true",
                ],
                "--pause",
            ),
            (
                vec![
                    "profile",
                    "--pid",
                    "42",
                    "--attach-backend",
                    "auto",
                    "--attach-backend",
                    "multi",
                ],
                "--attach-backend",
            ),
            (
                vec!["profile", "--cgroup", "/x", "--cgroup", "/y"],
                "--cgroup",
            ),
            (
                vec![
                    "profile",
                    "--pid",
                    "42",
                    "--max-scan-pids",
                    "64",
                    "--max-scan-pids",
                    "128",
                ],
                "--max-scan-pids",
            ),
            (vec!["inspect", "--pid", "1", "--pid", "2"], "--pid"),
            (vec!["doctor", "--pid", "1", "--pid", "2"], "--pid"),
            (
                vec!["doctor", "--cgroup", "/x", "--cgroup", "/y"],
                "--cgroup",
            ),
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage(m)) if m.contains(&format!("{flag} given twice"))),
                "{argv:?}"
            );
        }
        // Repeatable flags stay repeatable.
        let Command::Profile(a) = parse(args(&[
            "profile",
            "--pid",
            "42",
            "--module",
            "/opt/a.so",
            "--module",
            "/opt/b.so",
            "--manifest",
            "m1.json",
            "--manifest",
            "m2.json",
            "--hook-symbol",
            "V_GetTable:interface",
            "--hook-symbol",
            "C_Sign:functionlist",
        ]))
        .unwrap() else {
            panic!("expected profile")
        };
        assert_eq!(a.modules.len(), 2);
        assert_eq!(a.manifests.len(), 2);
    }

    #[test]
    fn empty_string_option_values_are_usage_errors() {
        for argv in [
            vec!["profile", "--pid", "42", "--module", ""],
            vec!["profile", "--pid", "42", "--manifest", ""],
            vec!["profile", "--cgroup", ""],
            vec!["profile", "--pid", "42", "-o", ""],
            vec!["run", "-o", "", "--", "/bin/true"],
            vec!["inspect", "--pid", "42", "--module", ""],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage(m)) if m.contains("requires a non-empty value")),
                "{argv:?}"
            );
        }
        // `--hook-symbol` already refuses an empty name; pin the usage error.
        assert!(matches!(
            parse(args(&["profile", "--pid", "42", "--hook-symbol", ""])),
            Err(CliError::Usage(m)) if m.contains("empty symbol name")
        ));
    }

    #[test]
    fn pid_zero_is_a_usage_error_not_a_late_runtime_failure() {
        for argv in [
            vec!["profile", "--pid", "0"],
            vec!["trace", "--pid", "0"],
            vec!["inspect", "--pid", "0"],
            vec!["doctor", "--pid", "0"],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage(m)) if m.contains("--pid must be greater than zero")),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn inspect_and_doctor_parse_with_their_own_rules() {
        let Command::Inspect(i) = parse(args(&["inspect", "--pid", "7", "--json"])).unwrap() else {
            panic!("expected inspect")
        };
        assert_eq!((i.pid, i.json), (7, true));
        assert!(
            matches!(parse(args(&["inspect"])), Err(CliError::Usage(m)) if m.contains("--pid"))
        );

        let Command::Doctor(d) = parse(args(&["doctor"])).unwrap() else {
            panic!("expected doctor")
        };
        assert_eq!((d.pid, d.cgroup), (None, None));
    }

    #[test]
    fn doctor_rejects_unsupported_module_option() {
        assert!(matches!(
            parse(args(&["doctor", "--module", "/opt/provider.so"])),
            Err(CliError::Usage(m)) if m.contains("doctor --module is not supported")
        ));
    }

    #[test]
    fn doctor_extra_strict_defaults_off_and_parses() {
        let Command::Doctor(d) = parse(args(&["doctor"])).unwrap() else {
            panic!("expected doctor");
        };
        assert!(!d.extra_strict);
        let Command::Doctor(d) = parse(args(&["doctor", "--extra-strict"])).unwrap() else {
            panic!("expected doctor");
        };
        assert!(d.extra_strict);
        let Command::Doctor(d) =
            parse(args(&["doctor", "--pid", "123", "--extra-strict"])).unwrap()
        else {
            panic!("expected doctor");
        };
        assert!(d.extra_strict);
        assert_eq!(d.pid, Some(123));
    }

    #[test]
    fn doctor_rejects_system_scope_with_a_named_reason() {
        assert!(matches!(
            parse(args(&["doctor", "--system"])),
            Err(CliError::Usage(m)) if m.contains("doctor --system is not supported")
        ));
    }

    #[test]
    fn scope_is_still_exactly_one_of_pid_or_cgroup_and_removed_flags_still_hint() {
        assert!(
            matches!(parse(args(&["profile"])), Err(CliError::Usage(m)) if m.contains("exactly one"))
        );
        assert!(matches!(
            parse(args(&["profile", "--pid", "1", "--cgroup", "/sys/fs/cgroup/x"])),
            Err(CliError::Usage(m)) if m.contains("mutually exclusive")
        ));
        assert!(matches!(
            parse(args(&["profile", "--pid", "1", "--provenance-module", "/opt/x.so"])),
            Err(CliError::Usage(m)) if m.contains("removed in productization slice 1a")
        ));
    }

    #[test]
    fn system_scope_selects_the_whole_machine_with_no_path() {
        let Command::Profile(a) = parse(args(&["profile", "--system"])).unwrap() else {
            panic!("expected profile")
        };
        assert_eq!(a.scope, ScopeArg::System);
        let Command::Trace(t) = parse(args(&["trace", "--system", "--max-events", "10"])).unwrap()
        else {
            panic!("expected trace")
        };
        assert_eq!(t.scope, ScopeArg::System);
        assert_eq!(t.max_events, Some(10));
    }

    #[test]
    fn system_scope_is_mutually_exclusive_with_pid_and_cgroup() {
        for extra in [
            vec!["--pid", "1"],
            vec!["--cgroup", "/sys/fs/cgroup/x"],
            vec!["--pid", "1", "--cgroup", "/sys/fs/cgroup/x"],
        ] {
            let mut argv = vec!["profile", "--system"];
            argv.extend(extra);
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage(m)) if m.contains("mutually exclusive")),
                "{argv:?}"
            );
        }
        assert!(
            matches!(parse(args(&["profile"])), Err(CliError::Usage(m)) if m.contains("--system"))
        );
    }

    #[test]
    fn a_malformed_hook_symbol_is_a_usage_error_naming_the_spec() {
        assert!(matches!(
            parse(args(&["profile", "--pid", "1", "--hook-symbol", "X:bogus"])),
            Err(CliError::Usage(m)) if m.contains("functionlist")
        ));
    }

    #[test]
    fn duration_accepts_bare_seconds_and_suffixes() {
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        for bad in ["", "5x", "-1", "s", "1.5m"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn zero_duration_is_a_usage_error_on_every_capture_surface() {
        for argv in [
            vec!["profile", "--pid", "42", "--duration", "0"],
            vec!["profile", "--pid", "42", "--duration", "0s"],
            vec!["profile", "--pid", "42", "--duration", "0m"],
            vec!["trace", "--pid", "42", "--duration", "0"],
            vec!["run", "--duration", "0h", "--", "/bin/true"],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage(m)) if m.contains("--duration must be greater than zero")),
                "{argv:?}"
            );
        }
        // Non-zero durations still parse.
        let Command::Profile(a) =
            parse(args(&["profile", "--pid", "42", "--duration", "30"])).unwrap()
        else {
            panic!("expected profile")
        };
        assert_eq!(a.duration, Some(Duration::from_secs(30)));
    }

    #[test]
    fn profile_requires_exactly_one_scope_and_no_manifest() {
        let a = parse_capture(
            Kind::Profile,
            args(&[
                "--manifest",
                "m.json",
                "--pid",
                "12",
                "--duration",
                "2m",
                "-o",
                "out.json",
            ]),
        )
        .unwrap();
        assert_eq!(a.scope, ScopeArg::Pid(12));
        assert_eq!(a.duration, Some(Duration::from_secs(120)));
        // A manifest is now optional: the scan is the default discovery source.
        let scan_only = parse_capture(Kind::Profile, args(&["--pid", "1"])).unwrap();
        assert!(scan_only.manifests.is_empty() && scan_only.modules.is_empty());
        assert_eq!(
            scan_only.hooks,
            crate::discovery::hooks::HookRegistry::builtin()
        );
        assert!(
            matches!(parse_capture(Kind::Profile, args(&["--manifest", "m", "--pid", "1", "--cgroup", "/sys/fs/cgroup/x"])), Err(CliError::Usage(m)) if m.contains("mutually exclusive"))
        );
        assert!(
            matches!(parse_capture(Kind::Profile, args(&["--manifest", "m"])), Err(CliError::Usage(m)) if m.contains("exactly one of --pid, --cgroup, or --system"))
        );
    }

    #[test]
    fn removed_flags_get_a_named_hint() {
        for flag in ["--provenance-module", "--trusted-workload"] {
            let err = parse_capture(
                Kind::Profile,
                args(&["--manifest", "m", "--pid", "1", flag, "x"]),
            )
            .unwrap_err();
            assert!(
                matches!(err, CliError::Usage(m) if m.contains("removed in productization slice 1a")),
                "{flag}"
            );
        }
        assert!(
            matches!(parse_capture(Kind::Profile, args(&["--manifest", "m", "--pid", "1", "--mode", "trace"])), Err(CliError::Usage(m)) if m.contains("trace is a subcommand"))
        );
    }

    #[test]
    fn trace_rejects_mode_and_accepts_the_rest() {
        assert!(matches!(
            parse_capture(
                Kind::Trace,
                args(&["--manifest", "m", "--pid", "1", "--mode", "metrics"])
            ),
            Err(CliError::Usage(_))
        ));
        let a = parse_capture(
            Kind::Trace,
            args(&[
                "--manifest",
                "m",
                "--cgroup",
                "/sys/fs/cgroup/x",
                "--unsafe-unvalidated-metadata",
            ]),
        )
        .unwrap();
        assert!(a.unsafe_requested);
        assert_eq!(a.scope, ScopeArg::Cgroup(PathBuf::from("/sys/fs/cgroup/x")));
    }

    #[test]
    fn trace_takes_a_max_events_bound_and_profile_refuses_it() {
        let a = parse_capture(Kind::Trace, args(&["--pid", "1", "--max-events", "1"])).unwrap();
        assert_eq!(a.max_events, Some(1));
        assert!(matches!(
            parse_capture(
                Kind::Profile,
                args(&["--pid", "1", "--max-events", "1"])
            ),
            Err(CliError::Usage(m)) if m.contains("--max-events is a trace option")
        ));
        assert!(matches!(
            parse_capture(Kind::Trace, args(&["--pid", "1", "--max-events", "x"])),
            Err(CliError::Usage(m)) if m.contains("invalid number")
        ));
        assert!(matches!(
            parse_capture(Kind::Trace, args(&["--pid", "1", "--max-events", "0"])),
            Err(CliError::Usage(m)) if m.contains("must be greater than zero")
        ));
    }

    #[test]
    fn max_scan_pids_is_an_optional_shared_capture_bound() {
        let Command::Profile(a) = parse(args(&[
            "profile",
            "--cgroup",
            "/x",
            "--max-scan-pids",
            "64",
        ]))
        .unwrap() else {
            panic!("expected profile")
        };
        assert_eq!(a.max_scan_pids, Some(64));
        let Command::Profile(bare) = parse(args(&["profile", "--cgroup", "/x"])).unwrap() else {
            panic!("expected profile")
        };
        assert_eq!(bare.max_scan_pids, None);
        // A shared capture option, like --ring-bytes: trace and run take it too.
        let Command::Trace(t) =
            parse(args(&["trace", "--pid", "42", "--max-scan-pids", "64"])).unwrap()
        else {
            panic!("expected trace")
        };
        assert_eq!(t.max_scan_pids, Some(64));
        let Command::Run(r) = parse(args(&["run", "--max-scan-pids", "64", "--", "true"])).unwrap()
        else {
            panic!("expected run")
        };
        assert_eq!(r.max_scan_pids, Some(64));
        assert!(matches!(
            parse(args(&["profile", "--pid", "42", "--max-scan-pids", "x"])),
            Err(CliError::Usage(m)) if m.contains("invalid number")
        ));
        assert!(matches!(
            parse(args(&["profile", "--pid", "42", "--max-scan-pids", "0"])),
            Err(CliError::Usage(m)) if m.contains("must be greater than zero")
        ));
        assert!(
            USAGE.contains("--max-scan-pids"),
            "help names the scan cap flag"
        );
    }

    #[test]
    fn attach_backend_flag_selects_the_static_backend_on_every_capture_surface() {
        let Command::Profile(a) = parse(args(&[
            "profile",
            "--pid",
            "42",
            "--attach-backend",
            "multi",
        ]))
        .unwrap() else {
            panic!("expected profile")
        };
        assert_eq!(a.attach_backend, BackendSelection::Multi);
        let Command::Trace(a) = parse(args(&[
            "trace",
            "--pid",
            "42",
            "--attach-backend",
            "singles",
        ]))
        .unwrap() else {
            panic!("expected trace")
        };
        assert_eq!(a.attach_backend, BackendSelection::Singles);
        let Command::Run(a) =
            parse(args(&["run", "--attach-backend", "multi", "--", "true"])).unwrap()
        else {
            panic!("expected run")
        };
        assert_eq!(a.attach_backend, BackendSelection::Multi);
        let Command::Profile(a) = parse(args(&["profile", "--pid", "42"])).unwrap() else {
            panic!("expected profile")
        };
        assert_eq!(a.attach_backend, BackendSelection::Auto);
        assert!(matches!(
            parse(args(&["profile", "--pid", "42", "--attach-backend", "uprobe-multi"])),
            Err(CliError::Usage(m)) if m.contains("--attach-backend: invalid value")
        ));
        assert!(
            USAGE.contains("--attach-backend"),
            "help names the backend flag"
        );
    }

    #[test]
    fn run_takes_capture_options_a_pause_policy_and_the_trailing_command() {
        let Command::Run(a) = parse(args(&[
            "run",
            "--module",
            "/opt/a.so",
            "--manifest",
            "/tmp/m.json",
            "--hook-symbol",
            "V_GetTable:interface",
            "--mode",
            "metrics",
            "--duration",
            "5m",
            "-o",
            "out.json",
            "--unsafe-unvalidated-metadata",
            "--pause",
            "always",
            "--kill-on-timeout",
            "--",
            "/usr/bin/app",
            "--pid",
            "7",
        ]))
        .unwrap() else {
            panic!("expected run")
        };
        assert_eq!(a.kind, Kind::Profile);
        assert_eq!(a.modules, vec![PathBuf::from("/opt/a.so")]);
        assert_eq!(a.manifests, vec![PathBuf::from("/tmp/m.json")]);
        assert_eq!(a.hooks.abi("V_GetTable"), Some(HookAbi::Interface));
        assert!(a.metrics);
        assert_eq!(a.duration, Some(Duration::from_secs(300)));
        assert_eq!(a.out, Some(PathBuf::from("out.json")));
        assert!(a.unsafe_requested);
        assert_eq!(a.pause, PausePolicy::Always);
        assert!(a.kill_on_timeout);
        // Everything after `--` is the command verbatim, flags included: the
        // observer must never consume an argument meant for the child.
        assert_eq!(a.command, ["/usr/bin/app", "--pid", "7"]);
    }

    /// M-9: paths and the `run` command are bytes; they survive parsing
    /// exactly, and a non-UTF-8 flag or number is a usage error.
    #[test]
    fn non_utf8_paths_and_run_arguments_pass_through_byte_for_byte() {
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
        let bytes = |raw: &[u8]| OsString::from_vec(raw.to_vec());
        let module = bytes(b"/opt/caf\xe9/pkcs11.so");
        let Command::Run(a) = parse([
            OsString::from("run"),
            OsString::from("--module"),
            module.clone(),
            OsString::from("-o"),
            bytes(b"out-\xff.json"),
            OsString::from("--"),
            OsString::from("/bin/echo"),
            bytes(b"caf\xe9"),
        ])
        .unwrap() else {
            panic!("expected run")
        };
        assert_eq!(a.modules, vec![PathBuf::from(module)]);
        assert_eq!(a.out.unwrap().as_os_str().as_bytes(), b"out-\xff.json");
        assert_eq!(
            a.command,
            vec![OsString::from("/bin/echo"), bytes(b"caf\xe9")]
        );

        let Command::Profile(p) = parse([
            OsString::from("profile"),
            OsString::from("--cgroup"),
            bytes(b"/sys/fs/cgroup/\xe9.slice"),
        ])
        .unwrap() else {
            panic!("expected profile")
        };
        assert_eq!(
            p.scope,
            ScopeArg::Cgroup(PathBuf::from(bytes(b"/sys/fs/cgroup/\xe9.slice")))
        );

        for argv in [
            vec![bytes(b"prof\xe9le")],
            vec![
                OsString::from("profile"),
                OsString::from("--pid"),
                bytes(b"1\xe9"),
            ],
            vec![
                OsString::from("profile"),
                OsString::from("--pid"),
                OsString::from("1"),
                bytes(b"--\xe9"),
            ],
        ] {
            assert!(
                matches!(parse(argv.clone()), Err(CliError::Usage(_))),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn run_trace_selects_the_trace_kind_and_omitted_pause_is_never() {
        let Command::Run(a) = parse(args(&["run", "--trace", "--", "/bin/true"])).unwrap() else {
            panic!("expected run")
        };
        assert_eq!(a.kind, Kind::Trace);
        assert_eq!(a.pause, PausePolicy::Never);
        assert!(!a.kill_on_timeout);
        assert!(!a.metrics);
        assert_eq!(a.command, ["/bin/true"]);
        // `--trace` streams raw events, so it has no `--mode`, whichever order
        // the two are typed in.
        for both in [
            vec!["run", "--trace", "--mode", "metrics", "--", "/bin/true"],
            vec!["run", "--mode", "metrics", "--trace", "--", "/bin/true"],
        ] {
            assert!(
                matches!(parse(args(&both)), Err(CliError::Usage(m)) if m.contains("has no --mode")),
                "{both:?}"
            );
        }
    }

    #[test]
    fn run_rejects_scope_flags_an_empty_command_and_unknown_pause_values() {
        for scoped in [
            vec!["run", "--pid", "1", "--", "/bin/true"],
            vec!["run", "--cgroup", "/sys/fs/cgroup/x", "--", "/bin/true"],
            vec!["run", "--system", "--", "/bin/true"],
        ] {
            assert!(
                matches!(parse(args(&scoped)), Err(CliError::Usage(m)) if m.contains("run has no --pid, --cgroup, or --system")),
                "{scoped:?}"
            );
        }
        for empty in [
            vec!["run"],
            vec!["run", "--pause", "auto"],
            vec!["run", "--"],
            vec!["run", "--", ""],
        ] {
            assert!(
                matches!(parse(args(&empty)), Err(CliError::Usage(m)) if m.contains("-- CMD [ARGS...]")),
                "{empty:?}"
            );
        }
        assert!(matches!(
            parse(args(&["run", "--pause", "sometimes", "--", "/bin/true"])),
            Err(CliError::Usage(m)) if m.contains("never|auto|always")
        ));
        assert!(matches!(
            parse(args(&["run", "--pause"])),
            Err(CliError::Usage(m)) if m.contains("--pause requires a value")
        ));
        assert_eq!(
            parse(args(&["run", "--help"])).unwrap_err(),
            CliError::Help(HelpTopic::Run)
        );
    }

    #[test]
    fn pause_is_a_run_only_option() {
        for elsewhere in [
            vec!["profile", "--pid", "1", "--pause", "auto"],
            vec!["trace", "--pid", "1", "--pause", "never"],
            vec!["inspect", "--pid", "1", "--pause", "always"],
            vec!["doctor", "--pause", "auto"],
        ] {
            assert!(
                matches!(parse(args(&elsewhere)), Err(CliError::Usage(m)) if m.contains("`p11scope run`")),
                "{elsewhere:?}"
            );
        }
    }

    #[test]
    fn each_pause_policy_spelling_parses_exactly() {
        for (spelling, expected) in [
            ("never", PausePolicy::Never),
            ("auto", PausePolicy::Auto),
            ("always", PausePolicy::Always),
        ] {
            let Command::Run(a) =
                parse(args(&["run", "--pause", spelling, "--", "/bin/true"])).unwrap()
            else {
                panic!("expected run")
            };
            assert_eq!(a.pause, expected, "{spelling}");
        }
    }

    #[test]
    fn help_is_not_an_error() {
        assert_eq!(
            parse_capture(Kind::Profile, args(&["--help"])).unwrap_err(),
            CliError::Help(HelpTopic::Profile)
        );
    }

    #[test]
    fn subcommand_help_is_scoped_to_that_subcommand() {
        // `profile --help` shows its own scope, never another subcommand's
        // usage; `doctor --help` likewise.
        let profile = HelpTopic::Profile.text();
        assert!(profile.contains("[--pid"), "{profile}");
        assert!(!profile.contains("p11scope trace"), "{profile}");
        let doctor = HelpTopic::Doctor.text();
        assert!(doctor.contains("p11scope doctor"), "{doctor}");
        assert!(!doctor.contains("p11scope profile"), "{doctor}");
        assert!(!doctor.contains("p11scope trace"), "{doctor}");
        // Every `--help` routes to its own topic.
        for (argv, topic) in [
            (vec!["profile", "--help"], HelpTopic::Profile),
            (vec!["trace", "--help"], HelpTopic::Trace),
            (vec!["run", "--help"], HelpTopic::Run),
            (vec!["inspect", "--help"], HelpTopic::Inspect),
            (vec!["doctor", "--help"], HelpTopic::Doctor),
            (vec!["--help"], HelpTopic::Global),
            (vec!["-h"], HelpTopic::Global),
        ] {
            assert_eq!(
                parse(args(&argv)).unwrap_err(),
                CliError::Help(topic),
                "{argv:?}"
            );
        }
        // Every scoped help carries the shared notes footer and nothing else.
        for topic in [
            HelpTopic::Profile,
            HelpTopic::Trace,
            HelpTopic::Run,
            HelpTopic::Inspect,
            HelpTopic::Doctor,
        ] {
            let text = topic.text();
            assert!(text.contains("notes: discovery scans"), "{topic:?}");
            assert!(!text.contains("p11scope-discover"), "{topic:?}");
        }
    }

    #[test]
    fn scoped_help_lines_are_verbatim_from_global_usage() {
        let global: Vec<&str> = USAGE.lines().collect();
        for topic in [
            HelpTopic::Profile,
            HelpTopic::Trace,
            HelpTopic::Run,
            HelpTopic::Inspect,
            HelpTopic::Doctor,
        ] {
            for line in topic.text().lines() {
                assert!(
                    global.contains(&line),
                    "{topic:?}: {line:?} is not verbatim from USAGE"
                );
            }
        }
    }

    #[test]
    fn global_help_text_is_pinned_byte_for_byte() {
        // FNV-1a over the UTF-8 bytes, so USAGE cannot drift silently.
        let mut hash: u64 = 14695981039346656037;
        for byte in USAGE.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1099511628211);
        }
        assert_eq!(USAGE.len(), 3461);
        assert_eq!(hash, 0x9986ad8b_a334f261);
        assert_eq!(HelpTopic::Global.text(), USAGE);
    }

    #[test]
    fn help_states_manifest_attestation_and_scan_only_limits() {
        for statement in [
            "--manifest is explicit operator attestation of exact accepted function-name/offset claims",
            "scan-only discovery is semantics-unverified and count-only",
            "aggregate counts/RVs/latency remain available",
        ] {
            assert!(
                USAGE.contains(statement),
                "missing help statement: {statement}"
            );
        }
    }

    #[test]
    fn ring_bytes_accepts_plain_and_suffixed_powers_of_two() {
        for (input, want) in [
            ("4096", 4096u32),
            ("262144", 262144),
            ("256K", 262144),
            ("256k", 262144),
            ("1M", 1048576),
            ("64M", 67108864),
        ] {
            let Command::Profile(a) =
                parse(args(&["profile", "--pid", "42", "--ring-bytes", input])).unwrap()
            else {
                panic!("expected profile for {input}");
            };
            assert_eq!(a.ring_bytes, Some(want), "input {input}");
        }
    }

    #[test]
    fn ring_bytes_rejects_non_power_of_two_and_out_of_range() {
        for input in [
            "0", "1000", "1K", "3M", "100K", "128M", "1G", "1.5M", "abc", "",
        ] {
            assert!(
                parse(args(&["profile", "--pid", "42", "--ring-bytes", input])).is_err(),
                "input {input} must be rejected"
            );
        }
    }

    #[test]
    fn drain_interval_ms_accepts_bounded_values() {
        for (input, want_ms) in [("5", 5u64), ("50", 50), ("200", 200), ("60000", 60000)] {
            let Command::Profile(a) = parse(args(&[
                "profile",
                "--pid",
                "42",
                "--drain-interval-ms",
                input,
            ]))
            .unwrap() else {
                panic!("expected profile for {input}");
            };
            assert_eq!(
                a.drain_interval,
                Some(Duration::from_millis(want_ms)),
                "input {input}"
            );
        }
    }

    #[test]
    fn drain_interval_ms_rejects_out_of_range() {
        for input in [
            "0",
            "4",
            "61000",
            "99999999999999999999999",
            "abc",
            "50ms",
            "",
        ] {
            assert!(
                parse(args(&[
                    "profile",
                    "--pid",
                    "42",
                    "--drain-interval-ms",
                    input
                ]))
                .is_err(),
                "input {input} must be rejected"
            );
        }
    }

    #[test]
    fn new_capture_flags_default_to_none() {
        let Command::Profile(a) = parse(args(&["profile", "--pid", "42"])).unwrap() else {
            panic!("expected profile")
        };
        assert_eq!(a.ring_bytes, None);
        assert_eq!(a.drain_interval, None);
    }

    #[test]
    fn run_and_trace_accept_the_new_capture_flags() {
        let Command::Run(r) = parse(args(&[
            "run",
            "--ring-bytes",
            "1M",
            "--drain-interval-ms",
            "100",
            "--",
            "true",
        ]))
        .unwrap() else {
            panic!("expected run")
        };
        assert_eq!(r.ring_bytes, Some(1048576));
        assert_eq!(r.drain_interval, Some(Duration::from_millis(100)));
        let Command::Trace(t) = parse(args(&[
            "trace",
            "--pid",
            "42",
            "--ring-bytes",
            "512K",
            "--drain-interval-ms",
            "25",
        ]))
        .unwrap() else {
            panic!("expected trace")
        };
        assert_eq!(t.ring_bytes, Some(524288));
        assert_eq!(t.drain_interval, Some(Duration::from_millis(25)));
    }

    #[test]
    fn help_documents_the_new_capture_flags() {
        for statement in ["--ring-bytes", "--drain-interval-ms"] {
            assert!(USAGE.contains(statement), "missing help text: {statement}");
        }
    }

    // SYSPLAN residual F-17 (RED): the hidden 10M default trace cap is
    // surfaced in help.
    #[test]
    fn help_surfaces_default_trace_event_cap() {
        assert!(
            USAGE.contains("10,000,000"),
            "help never names the default trace event cap"
        );
        assert!(
            USAGE.contains("TRUNCATED"),
            "help never explains the TRUNCATED line"
        );
    }

    // SYSPLAN residual F-26 (RED): every P11SCOPE_* behavior switch is
    // listed in --help/usage.
    #[test]
    fn help_lists_every_p11scope_env_switch() {
        for var in ["P11SCOPE_BROAD_ADMIT", "P11SCOPE_LOADER_ENV_SANITIZED"] {
            assert!(USAGE.contains(var), "help never names {var}");
        }
    }

    // SYSPLAN residual F-26 (GREEN): help and the evidence table agree —
    // a switch added to one without the other fails here.
    #[test]
    fn help_and_evidence_env_table_agree() {
        for (name, _) in crate::render::P11SCOPE_ENV_VARS {
            assert!(USAGE.contains(name), "help never names {name}");
        }
        const USAGE_MD: &str = include_str!("../docs/usage.md");
        for (name, _) in crate::render::P11SCOPE_ENV_VARS {
            assert!(USAGE_MD.contains(name), "usage.md never names {name}");
        }
    }

    // SYSPLAN residual F-30 (RED): docs/usage.md documents every CLI flag
    // USAGE advertises, so help and the usage doc cannot drift apart.
    #[test]
    fn usage_doc_documents_every_cli_flag() {
        const USAGE_MD: &str = include_str!("../docs/usage.md");
        for flag in cli_flags_in(USAGE) {
            assert!(
                USAGE_MD.contains(&flag),
                "docs/usage.md never documents {flag}"
            );
        }
    }

    /// Every `--flag` token advertised in `text` (`--mode`, not `--mode's`).
    fn cli_flags_in(text: &str) -> Vec<String> {
        let mut flags = Vec::new();
        for token in text.split(|c: char| c.is_whitespace() || c == '[' || c == ']') {
            let token = token.trim_matches(|c| c == ',' || c == '.' || c == ')');
            let flag = token.split('=').next().unwrap_or("");
            if flag.len() > 2
                && flag.starts_with("--")
                && flag[2..]
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '-')
                && !flags.contains(&flag.to_string())
            {
                flags.push(flag.to_string());
            }
        }
        flags
    }
}
