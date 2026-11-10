//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Command-line parsing for every subcommand: one parser body for profile and
//! trace, durations with suffixes, hints for removed flags.

use crate::attach::BackendSelection;
use crate::discovery::caller_registry::MAX_MAX_GAPS;
use crate::discovery::hooks::HookRegistry;
use p11scope_ebpf_common::CounterMode;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Profile,
    Trace,
}

/// Terminal text verbosity (CLI-1 owner ruling): default output is
/// concise, `-v`/`--verbose` shows full detail, and `--quiet` prints
/// only the summary head. Where present, `--json` (inspect, inventory)
/// and `-o` (profile, trace, run, inventory) are always complete and
/// never consult this switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextVerbosity {
    Quiet,
    #[default]
    Concise,
    Verbose,
}

impl TextVerbosity {
    /// Maps the two flags to a level. Both together are a usage error,
    /// never a silent precedence.
    pub fn resolve(verbose: bool, quiet: bool) -> Result<Self, CliError> {
        match (verbose, quiet) {
            (true, true) => Err(usage_err("--quiet and --verbose are mutually exclusive")),
            (true, false) => Ok(Self::Verbose),
            (false, true) => Ok(Self::Quiet),
            (false, false) => Ok(Self::Concise),
        }
    }
}

/// The hint every concise text report ends with.
pub const VERBOSE_HINT: &str = "run with -v for details";

/// Run-scoped text verbosity, mirroring the scan-progress toggle: set
/// once at command entry, restored on exit, so the deep run wrappers
/// need no new display parameter. The default is [`TextVerbosity::Concise`].
static TEXT_VERBOSITY: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);

/// Sets the run-scoped verbosity; returns the previous setting.
pub fn set_text_verbosity(verbosity: TextVerbosity) -> TextVerbosity {
    let next = match verbosity {
        TextVerbosity::Quiet => 0,
        TextVerbosity::Concise => 1,
        TextVerbosity::Verbose => 2,
    };
    match TEXT_VERBOSITY.swap(next, std::sync::atomic::Ordering::SeqCst) {
        0 => TextVerbosity::Quiet,
        2 => TextVerbosity::Verbose,
        _ => TextVerbosity::Concise,
    }
}

/// The current run-scoped verbosity.
pub fn text_verbosity() -> TextVerbosity {
    match TEXT_VERBOSITY.load(std::sync::atomic::Ordering::SeqCst) {
        0 => TextVerbosity::Quiet,
        2 => TextVerbosity::Verbose,
        _ => TextVerbosity::Concise,
    }
}

/// True only under `-v`/`--verbose`: full detail plus informational
/// stderr notes.
pub fn text_is_verbose() -> bool {
    text_verbosity() == TextVerbosity::Verbose
}

/// True only under `--quiet`: summary head only, for scripts.
pub fn text_is_quiet() -> bool {
    text_verbosity() == TextVerbosity::Quiet
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
    /// `--exclude-module` inputs; empty ⇒ exclude nothing. Repeatable.
    /// A full path (contains `/`) excludes exactly that file by identity;
    /// a bare name excludes every file with that basename or ELF soname.
    pub exclude_modules: Vec<PathBuf>,
    /// `--manifest` inputs; empty ⇒ scan only. Repeatable (spec §4.6).
    pub manifests: Vec<PathBuf>,
    /// `--prearm-module` inputs (packet 6.13): provider files to pin and
    /// pre-arm before any mapping. Repeatable; empty ⇒ no pre-arming.
    /// Never a scan filter (that is `--module`) and never function claims
    /// (that is `--manifest`).
    pub prearm_modules: Vec<PathBuf>,
    /// `--forwarding-module` inputs; empty ⇒ no declared layers.
    /// Repeatable. A full path (contains `/`) declares exactly that file
    /// by path and inode; a bare name declares every file with that basename.
    /// Declared modules split out of headline totals exactly like a
    /// closure-array forwarding layer under the same gates.
    pub forwarding_modules: Vec<PathBuf>,
    pub hooks: HookRegistry,
    pub scope: ScopeArg,
    /// `--mode metrics` (profile only).
    pub metrics: bool,
    /// Explicit metrics measurement request; omission keeps legacy behavior.
    pub counter_mode: Option<CounterMode>,
    /// `--select-endpoint` (6.15): one endpoint function name to detail
    /// while aggregate counters continue; None ⇒ aggregate-only capture.
    pub select_endpoint: Option<String>,
    pub duration: Option<Duration>,
    pub out: Option<PathBuf>,
    pub max_events: Option<u64>,
    /// `--max-scan-pids`: scope members scanned per pass; None ⇒ 256 default.
    pub max_scan_pids: Option<usize>,
    /// `--ring-bytes`: EVENTS ringbuf size override; None ⇒ 32 MiB default.
    pub ring_bytes: Option<u32>,
    /// `--drain-interval-ms`: capture-loop tick override; None ⇒ per-mode default.
    pub drain_interval: Option<Duration>,
    pub unsafe_requested: bool,
    /// `--allow-uretprobe-on-confined-target`: attach uretprobes even when this
    /// kernel is measured to kill a seccomp-confined target for doing so.
    pub allow_confined_uretprobe: bool,
    /// `--attach-backend`: static attach backend; Auto follows the policy.
    pub attach_backend: BackendSelection,
    /// `--track-short-lived`: extensive mode (6.14 Option B, widened
    /// by 7.10b). The kernel records exec-time exe identity; the
    /// engine classifies novel unmatched exits into static-linkage
    /// hints on cgroup/system scopes and validated target execs on
    /// exact-PID scope. Default off.
    pub track_short_lived: bool,
    /// `-v`/`--verbose`: full text detail plus informational stderr
    /// notes. Default off; refused beside `--quiet`.
    pub verbose: bool,
    /// `--quiet`: summary head only, for scripts. Default off; refused
    /// beside `--verbose`.
    pub quiet: bool,
}

/// What `run` is allowed to do to its own child to keep loader discovery from
/// racing an unobserved `dlopen`. `Auto` is the omission default: a first run
/// holds the child at loader hits until its probes attach, so early calls are
/// counted. `Never` stays available for runs that must not delay the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PausePolicy {
    Never,
    #[default]
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
    pub exclude_modules: Vec<PathBuf>,
    pub manifests: Vec<PathBuf>,
    /// `--prearm-module` inputs (packet 6.13); see `CaptureArgs`.
    pub prearm_modules: Vec<PathBuf>,
    /// `--forwarding-module` inputs; see `CaptureArgs`.
    pub forwarding_modules: Vec<PathBuf>,
    pub hooks: HookRegistry,
    /// `--mode metrics` (rejected beside `--trace`).
    pub metrics: bool,
    /// Explicit metrics measurement request; omission keeps legacy behavior.
    pub counter_mode: Option<CounterMode>,
    /// `--select-endpoint` (6.15): one endpoint function name to detail
    /// while aggregate counters continue; None ⇒ aggregate-only capture.
    pub select_endpoint: Option<String>,
    pub duration: Option<Duration>,
    pub out: Option<PathBuf>,
    pub max_events: Option<u64>,
    /// `--max-scan-pids`: scope members scanned per pass; None ⇒ 256 default.
    pub max_scan_pids: Option<usize>,
    /// `--ring-bytes`: EVENTS ringbuf size override; None ⇒ 32 MiB default.
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
    /// `--track-short-lived`: extensive mode (6.14 Option B, widened
    /// by 7.10b), same as profile: an owned run arms the PID
    /// target-exec consumer for its child. Default off.
    pub track_short_lived: bool,
    /// `-v`/`--verbose`: full text detail plus informational stderr
    /// notes. Default off; refused beside `--quiet`.
    pub verbose: bool,
    /// `--quiet`: summary head only, for scripts. Default off; refused
    /// beside `--verbose`.
    pub quiet: bool,
    /// `--user <name|uid>`: start the command as that account (root
    /// only, like `strace -u`), with its groups and home environment
    /// from the passwd entry. `None` keeps the default: under sudo
    /// the invoker, otherwise the observer itself.
    pub user: Option<OsString>,
    /// Everything after `--`, verbatim — bytes, not text: Linux arguments
    /// need not be UTF-8 (M-9). Never empty.
    pub command: Vec<OsString>,
}

/// What `p11scope inspect` scans: one named process, or every process on
/// the machine. System scope reuses the capture two-phase scan (enumerate,
/// sweep, rarity-selected deep scans) with a published cap record, but stays
/// scan-only: no live capture, no manifest reads, no capture state. It loads
/// a short-lived kernel identity check for overlay/9p original-file proofs;
/// without `CAP_BPF`/`CAP_PERFMON` those providers become named gaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectScope {
    Pid(u32),
    System,
}

impl From<InspectScope> for ScopeArg {
    fn from(scope: InspectScope) -> Self {
        match scope {
            InspectScope::Pid(pid) => Self::Pid(pid),
            InspectScope::System => Self::System,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectArgs {
    pub scope: InspectScope,
    pub modules: Vec<PathBuf>,
    pub exclude_modules: Vec<PathBuf>,
    pub hooks: HookRegistry,
    pub json: bool,
    /// `--max-scan-pids`: members deep-scanned per pass; None ⇒ 256 default.
    /// Only `--system` scans more than one member, so only it reads this.
    pub max_scan_pids: Option<usize>,
    /// `-v`/`--verbose`: full text detail plus informational stderr
    /// notes. Default off; refused beside `--quiet`.
    pub verbose: bool,
    /// `--quiet`: summary head only, for scripts. Default off; refused
    /// beside `--verbose`.
    pub quiet: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorArgs {
    pub pid: Option<u32>,
    pub cgroup: Option<PathBuf>,
    pub extra_strict: bool,
    pub verbose: bool,
    pub quiet: bool,
}

/// What `p11scope inventory` observes: one process, a retained cgroup and
/// its descendants, or every process, for one snapshot or across `--duration`.
/// The scan lane loads a short-lived kernel identity check for overlay/9p
/// original-file proofs; the native usage lane (`--capture`) adds the
/// Inventory BPF object's witnesses. Usage columns read unknown unless
/// a feed observed them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryArgs {
    pub scope: ScopeArg,
    pub modules: Vec<PathBuf>,
    pub exclude_modules: Vec<PathBuf>,
    /// Explicit operator inputs for the optional Detailed subset; repeatable.
    pub manifests: Vec<PathBuf>,
    /// `--prearm-module` inputs (packet 6.13); see `CaptureArgs`. Refused
    /// under `--capture scan`, like `--manifest`.
    pub prearm_modules: Vec<PathBuf>,
    /// `--forwarding-module` inputs; see `CaptureArgs`.
    pub forwarding_modules: Vec<PathBuf>,
    /// `--key-operations`: opt-in per-key tracking (linked journal lane).
    /// Default off; refused under `--capture scan`, like `--manifest`.
    pub key_operations: bool,
    pub hooks: HookRegistry,
    pub json: bool,
    /// `--max-scan-pids`: members deep-scanned per pass; None ⇒ 256 default.
    /// System and cgroup scopes may scan multiple members; this is not a tree cap.
    pub max_scan_pids: Option<usize>,
    /// `--max-gaps`: retained gap history bound; None ⇒ 1024 default.
    pub max_gaps: Option<usize>,
    /// `--max-endpoints`: capture-lifetime physical endpoint IDs; None ⇒ 32768.
    pub max_endpoints: Option<u64>,
    /// `--duration`: keep observing (rescanning) until the deadline;
    /// None ⇒ a single snapshot pass (or, with `--dashboard`, until quit).
    pub duration: Option<Duration>,
    /// `-o`: write the JSON inventory document to this file (atomic).
    pub out: Option<PathBuf>,
    /// `--dashboard`: live dashboard on stdout when it is a terminal
    /// (scrollable edge table, coverage header, log tail; `d` requests
    /// Detailed capture for the selected pair, `x` cancels); degraded
    /// honestly to snapshots/JSON on a pipe, never ANSI.
    pub dashboard: bool,
    /// `--event-log`: append the JSONL observation-event stream
    /// (`p11scope/inventory-events/v1`) to this file, with rotation;
    /// `-` streams it to stdout instead (never rotated, never beside
    /// `--json`/`--dashboard`/rotation options).
    pub event_log: Option<PathBuf>,
    /// `--event-rotate-bytes`: rotation threshold; None ⇒ 1 MiB default.
    pub event_rotate_bytes: Option<u64>,
    /// `--event-max-files`: live file plus retained rotations;
    /// None ⇒ 5 default.
    pub event_max_files: Option<usize>,
    /// `--event-interval`: cadence of periodic `totals` events on the
    /// stream; None ⇒ off.
    pub event_interval: Option<Duration>,
    /// `--diagnostics`: write bounded native count decisions as JSONL after stop.
    pub diagnostics: Option<PathBuf>,
    /// `--diagnostics-pid`: select one PID's diagnostics without narrowing capture.
    pub diagnostics_pid: Option<u32>,
    /// `--quiet`: print only the summary head (totals plus
    /// application/module edges) and silence scan progress. `--json`,
    /// `-o`, and logs are unchanged. Refused beside `--verbose`.
    pub quiet: bool,
    /// `-v`/`--verbose`: full text detail plus informational stderr
    /// notes. Default off; refused beside `--quiet`.
    pub verbose: bool,
    /// `--capture`: which usage lane runs; `auto` by default.
    pub capture: CaptureMode,
    /// Opt-in finite display hints; never changes capture or scope.
    pub caller_metadata: CallerMetadataMode,
    /// `--attach-backend`: how the native lane attaches its usage entries
    /// (C5.11); `auto` by default. The scan lane attaches nothing.
    pub attach_backend: BackendSelection,
    /// `--identity-backend`: the system sweep identity proof backend
    /// (D3d); `auto` by default. System scope only.
    pub identity_backend: IdentityBackendSelection,
    /// Whether `--identity-backend` was given explicitly. An explicit
    /// selection outside `--system` is a usage error; the implicit
    /// default under `--pid`/`--cgroup` loads nothing and emits no field.
    pub identity_backend_explicit: bool,
}

/// `inventory --caller-metadata`: local finite display hints only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CallerMetadataMode {
    #[default]
    None,
    Cgroup,
}
impl CallerMetadataMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Cgroup => "cgroup",
        }
    }
    fn from_cli(value: &str) -> Result<Self, CliError> {
        match value {
            "none" => Ok(Self::None),
            "cgroup" => Ok(Self::Cgroup),
            _ => Err(usage_err(format!(
                "--caller-metadata: invalid value {value:?}: expected none or cgroup"
            ))),
        }
    }
}

/// `inventory --capture`: the usage lane (Task 6 C5.1, plan §10 ruling D1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// Native when it can start; otherwise the scan lane plus a named gap
    /// (`native usage feed unavailable`).
    Auto,
    /// The scan lane only: usage stays `unknown (scan only)`. It loads a
    /// short-lived kernel identity check for overlay/9p original-file
    /// proofs; without `CAP_BPF`/`CAP_PERFMON` those providers become
    /// named gaps.
    Scan,
    /// The native usage lane or a hard error (exit 1) naming why not.
    Native,
}

impl CaptureMode {
    pub fn label(self) -> &'static str {
        match self {
            CaptureMode::Auto => "auto",
            CaptureMode::Scan => "scan",
            CaptureMode::Native => "native",
        }
    }
}

/// `inventory --identity-backend` (D3d): the system sweep identity proof
/// backend. `auto` (default) defers any identity load until the first
/// nonempty proof plan, then uses kernel proof when eligible; `userspace`
/// never loads identity BPF; `kernel` validates numbering/BTF, strict
/// load and functional probe before capture starts, or refuses with a
/// named nonzero error. System scope only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdentityBackendSelection {
    #[default]
    Auto,
    Userspace,
    Kernel,
}

impl IdentityBackendSelection {
    pub fn from_cli(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::Auto),
            "userspace" => Ok(Self::Userspace),
            "kernel" => Ok(Self::Kernel),
            _ => Err(format!(
                "--identity-backend: invalid value {value:?} (expected auto|userspace|kernel)"
            )),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Userspace => "userspace",
            Self::Kernel => "kernel",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryDiffArgs {
    pub before: PathBuf,
    pub after: PathBuf,
    pub json: bool,
    pub out: Option<PathBuf>,
    /// `-v`/`--verbose`: full text detail. Default off; refused beside
    /// `--quiet`.
    pub verbose: bool,
    /// `--quiet`: the concise summary without the detail hint. Default
    /// off; refused beside `--verbose`.
    pub quiet: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryCbomArgs {
    pub input: PathBuf,
    pub json: bool,
    pub out: Option<PathBuf>,
    /// `-v`/`--verbose`: full text detail. Default off; refused beside
    /// `--quiet`.
    pub verbose: bool,
    /// `--quiet`: the concise summary without the detail hint. Default
    /// off; refused beside `--verbose`.
    pub quiet: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Version,
    Profile(CaptureArgs),
    Trace(CaptureArgs),
    Run(RunArgs),
    Inspect(InspectArgs),
    Doctor(DoctorArgs),
    Inventory(InventoryArgs),
    InventoryDiff(InventoryDiffArgs),
    InventoryCbom(InventoryCbomArgs),
}

/// Which help text `--help` asked for: global usage or task-oriented scoped guidance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpTopic {
    Global,
    Profile,
    Trace,
    Run,
    Inspect,
    Doctor,
    Inventory,
    InventoryDiff,
    InventoryCbom,
}

impl HelpTopic {
    pub fn hint(self) -> &'static str {
        match self {
            Self::Global => "Try 'p11scope --help'.",
            Self::Profile => "Try 'p11scope profile --help'.",
            Self::Trace => "Try 'p11scope trace --help'.",
            Self::Run => "Try 'p11scope run --help'.",
            Self::Inspect => "Try 'p11scope inspect --help'.",
            Self::Doctor => "Try 'p11scope doctor --help'.",
            Self::Inventory => "Try 'p11scope inventory --help'.",
            Self::InventoryDiff => "Try 'p11scope inventory diff --help'.",
            Self::InventoryCbom => "Try 'p11scope inventory cbom --help'.",
        }
    }

    pub fn text(self) -> String {
        match self {
            HelpTopic::Global => USAGE.to_string(),
            HelpTopic::Profile => PROFILE_HELP.to_string(),
            HelpTopic::Trace => trace_help(),
            HelpTopic::Run => RUN_HELP.to_string(),
            HelpTopic::Inspect => INSPECT_HELP.to_string(),
            HelpTopic::Doctor => DOCTOR_HELP.to_string(),
            HelpTopic::Inventory => inventory_help(),
            HelpTopic::InventoryDiff => inventory_diff_help(),
            HelpTopic::InventoryCbom => inventory_cbom_help(),
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
    Usage { message: String, topic: HelpTopic },
    Help(HelpTopic),
}

impl CliError {
    /// Scope a usage refusal without changing successful help routing.
    pub fn with_topic(self, topic: HelpTopic) -> Self {
        match self {
            Self::Usage { message, .. } => Self::Usage { message, topic },
            error @ Self::Help(_) => error,
        }
    }
}

pub const USAGE: &str = "p11scope observes PKCS#11 provider use without changing the target.

Choose a task:
  doctor: check host and target readiness before capture.
  inspect: list mapped providers; mapping is not evidence of calls.
  profile: summarize aggregate completed calls and latency.
  trace: show completed call events.
  run: start and observe your own command after --.
  inventory: separate mapped modules from observed usage entries.
  inventory diff: compare two saved inventory files offline.
  inventory cbom: export a saved file as CycloneDX CBOM offline.
Use p11scope <command> --help for examples and mode-specific guidance.

usage:
  p11scope --version
  p11scope help [command]
  p11scope profile [--pid <n> | --cgroup <path> | --system] [--mode profile|metrics] [--duration <…>] [-o <out.json>] [-v] [--quiet]
  p11scope trace [--pid <n> | --cgroup <path> | --system] [--duration <…>] [--max-events <n>] [-o <out.file>] [-v] [--quiet]
  p11scope run [--mode profile|metrics | --trace] [--pause never|auto|always] [--user <name|uid>] [-v] [--quiet] -- CMD [ARGS...]
  p11scope inspect --pid <n> [--json] [-v] [--quiet]
  p11scope inspect --system [--json] [-v] [--quiet]
  p11scope inventory --pid <n> [--capture auto|scan|native] [--manifest <m.json>]... [--duration <…>] [--json] [-v] [--quiet] [-o <out.json>]
  p11scope inventory --cgroup <path> [--capture auto|scan|native] [--manifest <m.json>]... [--duration <…>] [--json] [-v] [--quiet] [-o <out.json>]
  p11scope inventory --system [--capture auto|scan|native] [--manifest <m.json>]... [--duration <…>] [--json] [-v] [--quiet] [-o <out.json>]
  p11scope inventory diff BEFORE.json AFTER.json [--json] [-o DIFF.json] [-v] [--quiet]
  p11scope inventory cbom INPUT.json [--json] [-o OUT.cdx.json] [-v] [--quiet]
  p11scope doctor [--pid <n>] [--cgroup <path>] [--extra-strict] [-v] [--quiet]
  p11scope-discover --module <provider.so> [-o <manifest.json>]   (offline helper; executes provider code)

discovery scans the target's mapped memory — no manifest and no helper are required for providers whose function table is in the file.
Live capture needs root; inspect, inventory diff, inventory cbom and inventory --capture scan do not.
Default text output is concise: the main results, one coverage line, and a hint. -v, --verbose shows full detail; --quiet prints only the summary head.
Complete JSON: --json on inspect/inventory (incl. diff, cbom); -o FILE on profile/trace/run/inventory; trace takes -o -; inventory streams --event-log; doctor is text-only.
--help and --version also answer to -h and -V.
Environment (advanced; normally unset): P11SCOPE_BROAD_ADMIT, P11SCOPE_LOADER_ENV_SANITIZED; docs/usage.md documents every P11SCOPE_* input.

examples:
  sudo p11scope run --pause auto -- pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -L
  sudo p11scope profile --pid 4242 --duration 30s -o profile.json
  sudo p11scope inventory --system --duration 30s

exit codes: 0 ok; 1 the command failed; 2 wrong arguments. run exits with its command's status.
";
/// `p11scope profile --help`: scoped syntax, examples and evidence limits.
const PROFILE_HELP: &str = "usage:
  p11scope profile [--pid <n> | --cgroup <path> | --system] [--module <provider.so>]... [--exclude-module <path-or-name>]... [--manifest <m.json>]... [--prearm-module <provider.so>]... [--forwarding-module <path-or-name>]...
                   [--mode profile|metrics] [--counter-mode counts|timestamps|latency] [--select-endpoint <FUNCTION>] [--duration <30|30s|5m|1h>] [-o <out.json>]
                   [--hook-symbol <NAME[:functionlist|interfacelist|interface]>]...
                   [--unsafe-unvalidated-metadata]
                   [--allow-uretprobe-on-confined-target]
                   [--track-short-lived]
                   [--ring-bytes <n[K|M]>] [--drain-interval-ms <n>]
                   [--attach-backend auto|multi|singles]
                   [--max-scan-pids <n>]
                   [-v] [--quiet]

examples (4242 is an example PID, not a detected target):
  p11scope profile --pid 4242 --duration 30s -o profile.json
  p11scope profile --system --mode metrics --duration 30s -o metrics.json

notes: discovery scans the target's mapped memory — no manifest and no helper are required for providers whose function table is in the file. Providers that build the table at run time need a manifest: run p11scope-discover --module <provider.so> -o <manifest.json> and pass --manifest <manifest.json>.
--module narrows the scan to named providers.
--exclude-module <path-or-name> is repeatable and does the opposite: discovery stays automatic, except excluded files get no probes and use no slots.
--ring-bytes <n[K|M]> sizes the capture's EVENTS ring (default 32M, 4M with --mode metrics, which writes no per-call records; 4K..64M, a power of two; one ring per capture, held as locked kernel memory). If a report counts lost events under very heavy call rates, raise it up to 64M.
--manifest is explicit operator attestation of exact accepted function-name/offset claims; matching a digest is not attestation. Claims are checked against the scan when possible.
--prearm-module <provider.so> is repeatable: it pins the named provider file before any mapping and watches the file from before it loads, using offsets already proven from the file or a manifest. It is not a scan filter (that is --module) and carries no function claims (that is --manifest).
--forwarding-module <path-or-name> is repeatable: it declares named files as forwarding layers (interposing shims such as pkcs11-spy), splitting their calls out of headline totals exactly like a closure-array layer under the same gates. A full path matches by path and inode; a bare name matches by basename. Without the declaration the observer never guesses a forwarding role.
scan-only discovery names functions from the standard table without confirming them; aggregate counts/RVs/latency remain available. Scanning continues for the life of the capture, not just at attach.
Provider identity is pinned by SHA-256 at attach and checked for in-place change during capture.
Aggregate across the selected scope; counts are not per application.
--mode metrics is the lighter maps-only profile mode; metrics is not a subcommand.
--counter-mode counts|timestamps|latency selects the metrics measurement for profile or run with --mode metrics.
counts reports calls and errors without timing; timestamps adds total and max call time; latency adds a latency histogram.
Omit --counter-mode to keep existing metrics behavior. Selections can refuse with a named reason, including on kernels without bpf_loop helper support, on builds without counter objects, past the mode's endpoint ceiling, and where the kernel verifier rejects the counter programs.
--select-endpoint <FUNCTION> with --mode metrics and --counter-mode names one endpoint for full
detail while aggregate counters continue; the name must match exactly one watched function (narrow with --module if it matches several), once at
start (a provider loaded after start needs --prearm-module <provider.so>). The detail is the function's
own counter values between selection and close; an exec of the watched process in between withholds it with a named
reason, a leader exit that is the last lifecycle record ends the window cleanly, and
--cgroup/--system refuse by name.
The selection attempt is recorded in the report; aggregate and detail counts are never summed.
Exactly one of --pid, --cgroup, or --system is required; --cgroup includes descendants.
--track-short-lived also records exec-time detail (extra detail; default off): the kernel records exec-time
executable identity for grouping by linkage.
Refused beside --counter-mode: it arms Detailed captures only.
On --cgroup/--system captures it groups unmatched exits by linkage; on --pid it groups the target's own execs.
--attach-backend auto (default) uses one multi-uprobe link per attach group where one links, else safe per-offset fallback; multi forces multi, singles forces per-offset.
Live capture needs root and usable uprobe_multi host capability (normally Linux 6.6+).
Ctrl-C or SIGTERM ends capture cleanly and writes the final -o report.
Default text output is concise: totals, coverage, and the function and mechanism tables. -v, --verbose adds every gap and reason, Evidence, and timing plus informational stderr notes. --quiet prints only the totals and coverage. Evidence counts probes: one entry and one return probe per watched function, so probes run at twice functions.
exit codes: 0 ok (partial results still exit 0); 1 capture failed; 2 wrong arguments.
";

/// `p11scope trace --help`: scoped syntax, examples and evidence limits.
const TRACE_HELP_HEAD: &str = "usage:
  p11scope trace   [same scope and discovery options] [--duration <…>] [--max-events <n>] [-o <out.file>]
                   [--ring-bytes <n[K|M]>] [--drain-interval-ms <n>]
                   [--attach-backend auto|multi|singles]
                   [--track-short-lived]
                   [-v] [--quiet]

example (4242 is an example PID, not a detected target):
  p11scope trace --pid 4242 --duration 10s --max-events 1000

notes: discovery scans the target's mapped memory — no manifest and no helper are required for providers whose function table is in the file. Providers that build the table at run time need a manifest: run p11scope-discover --module <provider.so> -o <manifest.json> and pass --manifest <manifest.json>.
--module narrows the scan to named providers.
--exclude-module <path-or-name> is repeatable and does the opposite: discovery stays automatic, except excluded files get no probes and use no slots.
--ring-bytes <n[K|M]> sizes the capture's EVENTS ring (default 32M; 4K..64M, a power of two; one ring per capture, held as locked kernel memory). If a report counts lost events under very heavy call rates, raise it up to 64M.
--manifest is explicit operator attestation of exact accepted function-name/offset claims; matching a digest is not attestation. Claims are checked against the scan when possible.
--prearm-module <provider.so> is repeatable: it pins the named provider file before any mapping and watches the file from before it loads, using offsets already proven from the file or a manifest. It is not a scan filter (that is --module) and carries no function claims (that is --manifest).
--forwarding-module <path-or-name> is repeatable: it declares named files as forwarding layers (interposing shims such as pkcs11-spy), splitting their calls out of headline totals exactly like a closure-array layer under the same gates. A full path matches by path and inode; a bare name matches by basename. Without the declaration the observer never guesses a forwarding role.
scan-only discovery names functions from the standard table without confirming them; aggregate counts/RVs/latency remain available. Scanning continues for the life of the capture, not just at attach.
Provider identity is pinned by SHA-256 at attach and checked for in-place change during capture.
Trace reports completed call events; PID/TID are diagnostic identifiers.
Executable names require verified event-image evidence; missing identity stays unknown.
Exactly one of --pid, --cgroup, or --system is required; --cgroup includes descendants.
--track-short-lived also records exec-time detail (extra detail; default off): the kernel records exec-time
executable identity for grouping by linkage.
On --cgroup/--system captures it groups unmatched exits by linkage; on --pid it groups the target's own execs.
--attach-backend auto (default) uses one multi-uprobe link per attach group where one links, else safe per-offset fallback; multi forces multi, singles forces per-offset.
Live capture needs root and usable uprobe_multi host capability (normally Linux 6.6+).
";

/// The `--max-events` default cap line carries the live constant, never a
/// hard-coded copy: the number below follows
/// [`crate::run::DEFAULT_TRACE_MAX_EVENTS`].
fn trace_cap_line() -> String {
    format!(
        "Without --max-events, trace stops at a {}-event default cap; TRUNCATED names the effective cap.\n",
        grouped_count(crate::run::DEFAULT_TRACE_MAX_EVENTS),
    )
}

const TRACE_HELP_TAIL: &str = "-o copies the trace to a file; -o - uses stdout only.
Ctrl-C or SIGTERM ends capture cleanly.
Trace events print the same at every verbosity; -v, --verbose additionally shows informational stderr notes (discovery, timing).
exit codes: 0 ok (partial results still exit 0); 1 capture failed; 2 wrong arguments.
";

/// `p11scope run --help`: scoped syntax, examples and evidence limits.
const RUN_HELP: &str = "usage:
  p11scope run     [same discovery options] [--mode profile|metrics | --trace] [--counter-mode counts|timestamps|latency] [--select-endpoint <FUNCTION>] [--duration <…>]
                   [-o <out>] [--pause never|auto|always] [--kill-on-timeout] [--user <name|uid>]
                   [--attach-backend auto|multi|singles]
                   [--track-short-lived]
                   [--ring-bytes <n[K|M]>] [--drain-interval-ms <n>] [-v] [--quiet] -- CMD [ARGS...]

example:
  sudo p11scope run --pause auto -- pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -L  # Debian/Ubuntu
  sudo p11scope run --pause auto -- pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so -L  # Fedora/RHEL
  sudo p11scope run --pause auto --user alice -- pkcs11-tool --module ... -L

notes: discovery scans the target's mapped memory — no manifest and no helper are required for providers whose function table is in the file. Providers that build the table at run time need a manifest: run p11scope-discover --module <provider.so> -o <manifest.json> and pass --manifest <manifest.json>.
--module narrows the scan to named providers.
--exclude-module <path-or-name> is repeatable and does the opposite: discovery stays automatic, except excluded files get no probes and use no slots.
--ring-bytes <n[K|M]> sizes the capture's EVENTS ring (default 32M, 4M with --mode metrics, which writes no per-call records; 4K..64M, a power of two; one ring per capture, held as locked kernel memory). If a report counts lost events under very heavy call rates, raise it up to 64M.
--manifest is explicit operator attestation of exact accepted function-name/offset claims; matching a digest is not attestation. Claims are checked against the scan when possible.
--prearm-module <provider.so> is repeatable: it pins the named provider file before any mapping and watches the file from before it loads, using offsets already proven from the file or a manifest. It is not a scan filter (that is --module) and carries no function claims (that is --manifest).
--forwarding-module <path-or-name> is repeatable: it declares named files as forwarding layers (interposing shims such as pkcs11-spy), splitting their calls out of headline totals exactly like a closure-array layer under the same gates. A full path matches by path and inode; a bare name matches by basename. Without the declaration the observer never guesses a forwarding role.
scan-only discovery names functions from the standard table without confirming them; aggregate counts/RVs/latency remain available. Scanning continues for the life of the capture, not just at attach.
Provider identity is pinned by SHA-256 at attach and checked for in-place change during capture.
run starts CMD itself and captures the command with its child processes; it takes no --pid/--cgroup/--system.
Without permission to create its cgroup, run observes only CMD itself and names the gap in the report.
Everything after -- belongs to CMD, including its flags and non-UTF-8 arguments.
CMD inherits the observer's environment unchanged, except SUDO_* and P11SCOPE_* (named on stderr under -v when withheld).
Under sudo the child runs as the invoker with the invoker's groups and HOME/USER/LOGNAME/SHELL from the passwd entry (plus XDG_RUNTIME_DIR when /run/user/<uid> is the invoker's own); -v prints the restored identity.
Profile and metrics counts are aggregate, not per application; --trace selects completed events.
--counter-mode counts|timestamps|latency selects the metrics measurement for profile or run with --mode metrics.
counts reports calls and errors without timing; timestamps adds total and max call time; latency adds a latency histogram.
Omit --counter-mode to keep existing metrics behavior. Selections can refuse with a named reason, including on kernels without bpf_loop helper support, on builds without counter objects, past the mode's endpoint ceiling, and where the kernel verifier rejects the counter programs.
--select-endpoint <FUNCTION> with --mode metrics and --counter-mode names one endpoint for full
detail while aggregate counters continue; the name must match exactly one watched function (narrow with --module if it matches several), once at
start (a provider loaded after start needs --prearm-module <provider.so>; with run it is usually
required). The detail is the function's own counter values between selection and close; an exec of the owned child in between withholds it with a named reason
while a leader exit that is the last lifecycle record ends the window cleanly.
The selection attempt is recorded in the report; aggregate and detail counts are never summed.
--pause auto (default) pauses only when the child would load unobserved; never does not pause the child (for runs that must not delay it); always pauses on every load.
--kill-on-timeout ends the child when --duration expires instead of leaving it running.
--track-short-lived also records exec-time detail (extra detail; default off): the kernel records exec-time
executable identity and the child's own execs are grouped by linkage.
Refused beside --counter-mode: it arms Detailed captures only.
--attach-backend auto (default) uses one multi-uprobe link per attach group where one links, else safe per-offset fallback; multi forces multi, singles forces per-offset.
Live capture needs root and usable uprobe_multi host capability (normally Linux 6.6+).
Ctrl-C or SIGTERM ends the capture cleanly.
Default text output is concise: totals, coverage, and the function and mechanism tables. -v, --verbose adds every gap and reason, Evidence, and timing plus informational stderr notes. --quiet prints only the totals and coverage. Evidence counts probes: one entry and one return probe per watched function, so probes run at twice functions. Under --trace, events print the same at every level; -v adds stderr notes.
-v/--verbose prints one line naming the run-as identity (running CMD as USER (uid N); the sudo-drop path adds (groups and home restored)).
--user <name|uid> (root only, like strace -u) starts CMD as that account with its groups and home environment; --user root stays root on purpose.
exit codes: the command's exit status; 1 if observing failed; 2 for wrong arguments.
";

/// `p11scope inspect --help`: scoped syntax, examples and evidence limits.
const INSPECT_HELP: &str = "usage:
  p11scope inspect --pid <n> [--module <provider.so>]... [--exclude-module <path-or-name>]... [--hook-symbol <…>]... [--json]
                   [-v] [--quiet]
  p11scope inspect --system [--module <provider.so>]... [--exclude-module <path-or-name>]... [--hook-symbol <…>]... [--json] [--max-scan-pids <n>]
                   [-v] [--quiet]

example (4242 is an example PID, not a detected target):
  p11scope inspect --pid 4242 --json

notes: discovery scans the target's mapped memory — no manifest and no helper are required for providers whose function table is in the file. Providers that build the table at run time need a manifest: run p11scope-discover --module <provider.so> -o <manifest.json> and pass --manifest <manifest.json>.
--module narrows the scan to named providers.
--exclude-module <path-or-name> is repeatable and does the opposite: discovery stays automatic, except excluded files get no probes and use no slots.
Inspect reports mapped providers and discovery evidence; a mapping does not prove a call.
Choose --pid or --system. --json preserves the same discovery facts for scripts.
Unreadable or unexamined identities remain unknown.
Inspect reads mappings without live capture; it loads a short-lived kernel identity check for overlay/9p original-file proofs, and without CAP_BPF/CAP_PERFMON those providers become named gaps.
Default text output is concise: the mapped providers, one coverage line, and a hint. -v, --verbose shows every gap and reason with per-table data. --quiet prints only the summary head.
exit codes: 0 ok (partial results still exit 0); 1 the target could not be read; 2 wrong arguments.
";

/// `p11scope doctor --help`: scoped syntax, examples and evidence limits.
const DOCTOR_HELP: &str = "usage:
  p11scope doctor  [--pid <n>] [--cgroup <path>] [--extra-strict] [-v] [--quiet]

example (4242 is an example PID, not a detected target):
  p11scope doctor --pid 4242

Check host and requested-target capability before capture.
Without --pid or --cgroup, target readiness is unassessed.
Live capture needs root and usable uprobe_multi host capability (normally Linux 6.6+); this command only checks.
--extra-strict also treats warnings as failure; see docs/usage.md for privilege requirements.
Default text output is concise: the verdict, the failing and warning rows, and the next step. -v, --verbose shows every row; --quiet prints only the Doctor line.
exit codes: 0 every requested lane passed; 1 a requested lane is unavailable (--extra-strict: any warning fails too); 2 wrong arguments.
";

/// `p11scope inventory --help`: scoped syntax, examples and evidence limits.
const INVENTORY_HELP_HEAD: &str = "usage:
  p11scope inventory --pid <n> [--module <provider.so>]... [--exclude-module <path-or-name>]... [--manifest <m.json>]... [--prearm-module <provider.so>]... [--forwarding-module <path-or-name>]...
                   [--key-operations] [--hook-symbol <…>]... [--duration <…>] [--json] [--quiet] [-v] [-o <out.json>]
                   [--max-gaps <n>] [--max-endpoints <n>] [--capture auto|scan|native] [--caller-metadata none|cgroup]
                   [--attach-backend auto|multi|singles] [--dashboard]
                   [--event-log <f.jsonl|-> [--event-rotate-bytes <n[K|M]>] [--event-max-files <n>] [--event-interval <dur>]]
                   [--diagnostics <f.jsonl> [--diagnostics-pid <n>]]
  p11scope inventory --cgroup <path> [--module <provider.so>]... [--exclude-module <path-or-name>]... [--manifest <m.json>]... [--prearm-module <provider.so>]... [--forwarding-module <path-or-name>]...
                   [--key-operations] [--hook-symbol <…>]... [--duration <…>] [--json] [--quiet] [-v] [-o <out.json>]
                   [--max-scan-pids <n>] [--max-gaps <n>] [--max-endpoints <n>] [--capture auto|scan|native] [--caller-metadata none|cgroup]
                   [--attach-backend auto|multi|singles] [--dashboard]
                   [--event-log <f.jsonl|-> [--event-rotate-bytes <n[K|M]>] [--event-max-files <n>] [--event-interval <dur>]]
                   [--diagnostics <f.jsonl> [--diagnostics-pid <n>]]
  p11scope inventory --system [--module <provider.so>]... [--exclude-module <path-or-name>]... [--manifest <m.json>]... [--prearm-module <provider.so>]... [--forwarding-module <path-or-name>]...
                   [--key-operations] [--hook-symbol <…>]... [--duration <…>] [--json] [--quiet] [-v] [-o <out.json>]
                   [--max-scan-pids <n>] [--max-gaps <n>] [--max-endpoints <n>] [--capture auto|scan|native] [--caller-metadata none|cgroup]
                   [--attach-backend auto|multi|singles] [--identity-backend auto|userspace|kernel] [--dashboard]
                   [--event-log <f.jsonl|-> [--event-rotate-bytes <n[K|M]>] [--event-max-files <n>] [--event-interval <dur>]]
                   [--diagnostics <f.jsonl> [--diagnostics-pid <n>]]
  p11scope inventory diff BEFORE.json AFTER.json [--json] [-o DIFF.json] [-v] [--quiet]
  p11scope inventory cbom INPUT.json [--json] [-o OUT.cdx.json] [-v] [--quiet]

example (4242 is an example PID, not a detected target):
  p11scope inventory --pid 4242 --capture scan --json -o inventory.json
  p11scope inventory --cgroup <path> --capture native --duration 30s --diagnostics inventory-debug.jsonl --diagnostics-pid 4242 -o inventory.json
  sudo p11scope inventory --system --duration 30s

notes: discovery scans the target's mapped memory — no manifest and no helper are required for providers whose function table is in the file. Providers that build the table at run time need a manifest: run p11scope-discover --module <provider.so> -o <manifest.json> and pass --manifest <manifest.json>.
Choose exactly one of --pid, --cgroup, or --system; --cgroup includes descendants.
Idle cgroup usage remains unknown: endpoint samples do not prove continuous membership.
Cgroup discovery is bounded and cooperative; --max-scan-pids limits deep scans, not the cgroup tree.
--module narrows the scan to named providers.
--exclude-module <path-or-name> is repeatable and does the opposite: discovery stays automatic, except excluded files get no probes and use no slots.
--manifest is repeatable explicit operator attestation for the optional Detailed subset; requires auto or native.
--prearm-module <provider.so> is repeatable: it pins the named provider file before any mapping and watches the file from before it loads through the inventory lane, with one interval row per input; requires auto or native.
--forwarding-module <path-or-name> is repeatable: it declares named files as forwarding layers (interposing shims such as pkcs11-spy), splitting their calls out of headline totals exactly like a closure-array layer under the same gates. A full path matches by path and inode; a bare name matches by basename. Without the declaration the observer never guesses a forwarding role.
--key-operations also tracks which key each operation used (needs --capture auto or native; start the observer before the application for best coverage). Without it you still get per-provider function and mechanism counts.
Per-key results appear under object_observations in --json and in the key operations: line.
Inventory separates mapped modules from observed usage entries; entries are not completed calls.
";

/// The `--max-endpoints` line carries the live budget constants, never a
/// hard-coded copy: the numbers below follow
/// [`crate::capacity::DEFAULT_INVENTORY_ENDPOINT_LIMIT`] and
/// [`crate::capacity::MAX_INVENTORY_ENDPOINT_LIMIT`].
fn inventory_max_endpoints_line() -> String {
    format!(
        "--max-endpoints selects capture-lifetime physical endpoint IDs: 1–{}, default {}; unloading does not refund IDs.\n",
        crate::capacity::MAX_INVENTORY_ENDPOINT_LIMIT,
        crate::capacity::DEFAULT_INVENTORY_ENDPOINT_LIMIT,
    )
}

const INVENTORY_HELP_TAIL: &str = "--capture scan disables usage BPF and leaves usage unknown. auto prefers native and falls back to scan with a named gap (needs root for live capture; without root a PID capture still reports its scan). native fails if unavailable.
Inventory rescans in passes; a process that starts after its last pass is reported, not scanned (system and pid scopes).
System inventory selects its identity backend separately; --identity-backend auto may load identity BPF even with --capture scan.
For system inventory that loads no BPF, use: p11scope inventory --system --capture scan --identity-backend userspace
--identity-backend selects the system sweep identity proof backend: auto (default) defers any
identity load until the first nonempty proof plan, userspace never loads identity BPF, kernel
validates numbering/BTF, strict load and functional probe before capture starts. System scope
only; explicit use under --pid/--cgroup is refused.
--quiet prints only the summary head (totals plus application/module edges) and silences scan progress; --json, -o and logs are unchanged.
Default text output is concise: the summary head plus the limits line. -v, --verbose shows full detail (every gap and reason, per-caller/module/edge data, budgets, timing) plus informational stderr notes.
--json and -o contain the same inventory facts; --event-log appends bounded JSONL history with rotation.
--event-log - streams that history to stdout instead (no rotation; refused beside --json and --dashboard; the text summary moves to stderr). --event-interval <dur> adds periodic totals events to either sink.
--diagnostics writes bounded native count decisions after capture stops; requires auto or native and a separate regular file.
--diagnostics-pid selects that PID's diagnostics without changing capture scope; global health records remain included.
A missing observation or incomplete retained history does not establish zero activity.
Compare saved files offline with inventory diff, and export one saved file as CycloneDX CBOM with inventory cbom; see docs/usage.md.
--attach-backend auto (default) uses one multi-uprobe link per attach group where one links, else safe per-offset fallback; multi forces multi, singles forces per-offset.
Live capture (auto/native) needs root and usable uprobe_multi host capability (normally Linux 6.6+); --capture scan does not.
exit codes: 0 ok (partial results still exit 0); 1 nothing could be observed; 2 wrong arguments.
";

/// The assembled inventory help: head, the live `--max-endpoints` line,
/// and tail.
fn inventory_help() -> String {
    format!(
        "{INVENTORY_HELP_HEAD}{}{INVENTORY_HELP_TAIL}",
        inventory_max_endpoints_line()
    )
}

/// Offline diff help is separate from capture scope and privileges.
const INVENTORY_DIFF_HELP_HEAD: &str = "usage:
  p11scope inventory diff BEFORE.json AFTER.json [--json] [-o DIFF.json] [-v] [--quiet]

Compare saved p11scope/inventory/v1 files offline, without privileges.
Default stdout is readable text; --json writes one inventory-diff/v1 JSON document.
Default text output is concise: counts plus caveats. -v, --verbose shows full detail; --quiet omits the detail hint.
-o saves the same JSON atomically before stdout. Use -- before dash-prefixed inputs.
Stdin (-) and -o - are unsupported; use --json for JSON on stdout.
exit codes: differences and unknown evidence exit 0; input/output failures exit 1; usage exits 2.
Counts describe independent windows; absence does not prove removal.
";

/// The per-input bounds line carries the live reader constants, never a
/// hard-coded copy: the numbers below follow
/// [`crate::inventory_diff::input`]'s `DEFAULT_INPUT_*` bounds.
fn inventory_diff_limits_line() -> String {
    use crate::inventory_diff::input::{
        DEFAULT_INPUT_BYTES, DEFAULT_INPUT_DEPTH, DEFAULT_INPUT_NODES, DEFAULT_INPUT_ROWS,
        DEFAULT_INPUT_STRING_BYTES,
    };
    format!(
        "Per input: {} read, {} rows, {} decoded bytes per string/key,\nnesting depth {}, and {} JSON values plus object keys.\n",
        mib_or_bytes(DEFAULT_INPUT_BYTES as u64),
        grouped_count(DEFAULT_INPUT_ROWS as u64),
        grouped_count(DEFAULT_INPUT_STRING_BYTES as u64),
        grouped_count(DEFAULT_INPUT_DEPTH as u64),
        grouped_count(DEFAULT_INPUT_NODES as u64),
    )
}

/// The assembled diff help: head plus the live bounds line.
fn inventory_diff_help() -> String {
    format!("{INVENTORY_DIFF_HELP_HEAD}{}", inventory_diff_limits_line())
}

/// Offline CBOM help is separate from capture scope and privileges.
const INVENTORY_CBOM_HELP_HEAD: &str = "usage:
  p11scope inventory cbom INPUT.json [--json] [-o OUT.cdx.json] [-v] [--quiet]

Convert one saved p11scope/inventory/v1 or observed-profile file offline, without privileges, into a CycloneDX 1.6 cryptographic bill of materials.
Default stdout is readable text; --json writes one CycloneDX JSON document.
Default text output is concise: counts plus caveats. -v, --verbose shows full detail; --quiet omits the detail hint.
-o saves the same JSON atomically before stdout. Use -- before a dash-prefixed input.
Stdin (-) and -o - are unsupported; use --json for JSON on stdout.
Only fields already present in the saved file are converted; nothing new is captured and unknowns stay explicit.
exit codes: unknown evidence exits 0; input/output failures exit 1; usage exits 2.
Counts describe one observation window; absence does not prove inactivity.
";

/// The CBOM reader shares the diff reader's per-input bounds, so this
/// line carries the same live constants, never a hard-coded copy.
fn inventory_cbom_limits_line() -> String {
    use crate::inventory_diff::input::{
        DEFAULT_INPUT_BYTES, DEFAULT_INPUT_DEPTH, DEFAULT_INPUT_NODES, DEFAULT_INPUT_ROWS,
        DEFAULT_INPUT_STRING_BYTES,
    };
    format!(
        "Input limits: {} read, {} rows, {} decoded bytes per string/key,\nnesting depth {}, and {} JSON values plus object keys.\n",
        mib_or_bytes(DEFAULT_INPUT_BYTES as u64),
        grouped_count(DEFAULT_INPUT_ROWS as u64),
        grouped_count(DEFAULT_INPUT_STRING_BYTES as u64),
        grouped_count(DEFAULT_INPUT_DEPTH as u64),
        grouped_count(DEFAULT_INPUT_NODES as u64),
    )
}

/// The assembled CBOM help: head plus the live bounds line.
fn inventory_cbom_help() -> String {
    format!("{INVENTORY_CBOM_HELP_HEAD}{}", inventory_cbom_limits_line())
}

/// The assembled trace help: head, the live cap line, and tail.
fn trace_help() -> String {
    format!("{TRACE_HELP_HEAD}{}{TRACE_HELP_TAIL}", trace_cap_line())
}

/// A count with thousands separators (`10000000` -> `10,000,000`), for
/// help lines built from constants.
fn grouped_count(mut value: u64) -> String {
    if value == 0 {
        return "0".to_string();
    }
    let mut groups = Vec::new();
    while value > 0 {
        groups.push(format!("{:03}", value % 1000));
        value /= 1000;
    }
    if let Some(most) = groups.last_mut() {
        *most = most.trim_start_matches('0').to_string();
        if most.is_empty() {
            *most = "0".to_string();
        }
    }
    groups.reverse();
    groups.join(",")
}

/// A byte bound as whole MiB when exact (`67108864` -> `64 MiB`),
/// otherwise as raw bytes so help never rounds.
fn mib_or_bytes(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{bytes} bytes")
    }
}

const REMOVED_FLAG_HINT: &str = "removed in productization slice 1a: the observer pins provider \
identity by SHA-256 and fstat; see docs/usage.md";

fn usage_err(msg: impl Into<String>) -> CliError {
    CliError::Usage {
        message: crate::render::escape_controls(&msg.into()).into_owned(),
        topic: HelpTopic::Global,
    }
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

/// Validate `--exclude-module` inputs at startup (after parsing, before
/// discovery, so usage errors exit 2 with the command's hint).
/// - A full path (contains `/`) must exist (follow symlinks, like `--module`);
///   otherwise a named usage error. Bare names need no existence: they match
///   every copy by file name or ELF soname, including container and snap copies
///   the observer never opens directly.
/// - `--module X` with a matching `--exclude-module` is refused with a named
///   error (exact string, same file identity, or bare-name basename match).
///   Bare-name soname conflicts surface during discovery where the target file
///   is open and its soname is read.
pub fn validate_excludes(modules: &[PathBuf], excludes: &[PathBuf]) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt as _;
    let is_path = |p: &PathBuf| p.as_os_str().as_bytes().contains(&b'/');
    for exclude in excludes {
        if is_path(exclude) {
            std::fs::metadata(exclude).map_err(|error| {
                format!(
                    "--exclude-module {} does not exist: {error}",
                    exclude.display()
                )
            })?;
        }
    }
    for module in modules {
        for exclude in excludes {
            if let Some(reason) = include_exclude_conflict("--module", module, exclude) {
                return Err(reason);
            }
        }
    }
    Ok(())
}

/// Which startup exclusion rule an included path trips against an
/// `--exclude-module` input, if any. Shared by `--module`,
/// `--prearm-module` and manifest-attested paths; only the message subject
/// differs.
enum ExcludeConflict {
    SameInput,
    SameFile { dev: u64, ino: u64 },
    FileName,
}

/// The three startup conflict rules: exact string, same file identity,
/// bare-name basename match. Bare-name soname conflicts surface during
/// discovery where the target file is open and its soname is read.
fn exclude_conflict(include: &Path, exclude: &Path) -> Option<ExcludeConflict> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    let is_path = |p: &Path| p.as_os_str().as_bytes().contains(&b'/');
    if include == exclude {
        return Some(ExcludeConflict::SameInput);
    }
    if is_path(include)
        && is_path(exclude)
        && let (Ok(left), Ok(right)) = (std::fs::metadata(include), std::fs::metadata(exclude))
        && (left.dev(), left.ino()) == (right.dev(), right.ino())
    {
        return Some(ExcludeConflict::SameFile {
            dev: left.dev(),
            ino: left.ino(),
        });
    }
    if !is_path(exclude)
        && let Some(base) = include.file_name()
        && base == exclude.as_os_str()
    {
        return Some(ExcludeConflict::FileName);
    }
    None
}

/// The named-error shape for an include flag (`--module`, `--prearm-module`)
/// matching an exclusion.
fn include_exclude_conflict(flag: &str, include: &Path, exclude: &Path) -> Option<String> {
    match exclude_conflict(include, exclude)? {
        ExcludeConflict::SameInput => Some(format!(
            "{flag} {} and --exclude-module {} name the same input; refusing a module that is both included and excluded",
            include.display(),
            exclude.display()
        )),
        ExcludeConflict::SameFile { dev, ino } => Some(format!(
            "{flag} {} and --exclude-module {} are the same file (device {dev} inode {ino}); refusing a module that is both included and excluded",
            include.display(),
            exclude.display()
        )),
        ExcludeConflict::FileName => Some(format!(
            "{flag} {} is matched by --exclude-module {} (file name); refusing a module that is both included and excluded",
            include.display(),
            exclude.display()
        )),
    }
}

/// Validate `--prearm-module` inputs against `--exclude-module` at startup
/// (same exit-2 usage-error shape as [`validate_excludes`]): a pre-armed
/// provider matching an exclusion is refused, never silently coexisting
/// with it. PA-5 I3: opens each prearm path and reuses
/// [`crate::discovery::scan::startup_exclude_conflict`] (identity, resolved
/// basename, soname) in addition to the three string rules below, so
/// `--prearm-module …/p11-kit-proxy.so --exclude-module libp11-kit.so.0`
/// (a symlink whose soname matches) is refused here.
pub fn validate_prearm_excludes(prearm: &[PathBuf], excludes: &[PathBuf]) -> Result<(), String> {
    for input in prearm {
        for exclude in excludes {
            if let Some(reason) = include_exclude_conflict("--prearm-module", input, exclude) {
                return Err(reason);
            }
        }
        if let Some(matched) = crate::discovery::scan::startup_exclude_conflict(input, excludes) {
            return Err(format!(
                "--prearm-module {} is matched by --exclude-module {} (opened file); refusing a module that is both included and excluded",
                input.display(),
                matched.display()
            ));
        }
    }
    Ok(())
}

/// Validate `--forwarding-module` inputs at startup (same exit-2
/// usage-error shape as [`validate_excludes`]): a full path (contains
/// `/`) must exist, and a declared layer matching an exclusion is
/// refused — an excluded file gets no probes, so there is nothing to
/// split. Bare names need no existence: they match by basename at
/// evidence assembly.
pub fn validate_forwarding(forwarding: &[PathBuf], excludes: &[PathBuf]) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt as _;
    for input in forwarding {
        // A declaration that contradicts an exclusion is refused first: it
        // names the operator's intent conflict, not a typo.
        for exclude in excludes {
            if let Some(reason) = include_exclude_conflict("--forwarding-module", input, exclude) {
                return Err(reason);
            }
        }
        if let Some(matched) = crate::discovery::scan::startup_exclude_conflict(input, excludes) {
            return Err(format!(
                "--forwarding-module {} is matched by --exclude-module {} (opened file); refusing a module that is both included and excluded",
                input.display(),
                matched.display()
            ));
        }
        // A full path must resolve: a typo'd declaration must fail here,
        // not surface later as an unmatched declaration.
        if input.as_os_str().as_bytes().contains(&b'/') && std::fs::metadata(input).is_err() {
            return Err(format!(
                "--forwarding-module {} does not exist",
                input.display()
            ));
        }
    }
    Ok(())
}

/// Validate `--manifest` inputs against `--exclude-module` at startup (same
/// exit-2 usage-error shape as [`validate_excludes`]): a manifest attesting
/// a provider that matches an exclusion is refused. Attested paths are the
/// manifest's `module_path` plus every attested object path, compared by
/// the same three rules plus PA-5 I3's opened-file check (identity, resolved
/// basename, soname). Best-effort: an unreadable or unparsable manifest, or
/// an unattested path that cannot be opened, is left for discovery to report
/// precisely.
pub fn validate_manifest_excludes(
    manifests: &[PathBuf],
    excludes: &[PathBuf],
) -> Result<(), String> {
    for manifest in manifests {
        for attested in manifest_attested_paths(manifest) {
            for exclude in excludes {
                if let Some(reason) = manifest_exclude_conflict(manifest, &attested, exclude) {
                    return Err(reason);
                }
            }
            if let Some(matched) =
                crate::discovery::scan::startup_exclude_conflict(&attested, excludes)
            {
                return Err(format!(
                    "--manifest {} attests {}, matched by --exclude-module {} (opened file); refusing a module that is both included and excluded",
                    manifest.display(),
                    attested.display(),
                    matched.display()
                ));
            }
        }
    }
    Ok(())
}

/// Attested provider paths of one `--manifest` file: `module_path` plus
/// every object path. Best-effort JSON only (no schema check — discovery
/// reports a malformed manifest precisely); unreadable or unparsable
/// input yields no candidates.
fn manifest_attested_paths(manifest: &Path) -> Vec<PathBuf> {
    let Ok(text) = std::fs::read_to_string(manifest) else {
        return Vec::new();
    };
    let Ok(document) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    if let Some(path) = document
        .get("module_path")
        .and_then(serde_json::Value::as_str)
    {
        paths.push(PathBuf::from(path));
    }
    if let Some(objects) = document
        .get("objects")
        .and_then(serde_json::Value::as_array)
    {
        for object in objects {
            if let Some(path) = object.get("path").and_then(serde_json::Value::as_str) {
                paths.push(PathBuf::from(path));
            }
        }
    }
    paths
}

/// The named-error shape for a `--manifest` attesting an excluded provider.
fn manifest_exclude_conflict(manifest: &Path, attested: &Path, exclude: &Path) -> Option<String> {
    match exclude_conflict(attested, exclude)? {
        ExcludeConflict::SameInput => Some(format!(
            "--manifest {} attests {} and --exclude-module {} names the same input; refusing a module that is both included and excluded",
            manifest.display(),
            attested.display(),
            exclude.display()
        )),
        ExcludeConflict::SameFile { dev, ino } => Some(format!(
            "--manifest {} attests {} and --exclude-module {} is the same file (device {dev} inode {ino}); refusing a module that is both included and excluded",
            manifest.display(),
            attested.display(),
            exclude.display()
        )),
        ExcludeConflict::FileName => Some(format!(
            "--manifest {} attests {}, matched by --exclude-module {} (file name); refusing a module that is both included and excluded",
            manifest.display(),
            attested.display(),
            exclude.display()
        )),
    }
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
        // Same for the run-as account: no other subcommand starts a child.
        "--user" => usage_err(
            "--user is a `p11scope run` option: only a child this observer started can run \
             as another account",
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
    exclude_modules: Vec<PathBuf>,
    manifests: Vec<PathBuf>,
    prearm_modules: Vec<PathBuf>,
    forwarding_modules: Vec<PathBuf>,
    hooks: HookRegistry,
    metrics: Option<bool>,
    counter_mode: Option<CounterMode>,
    select_endpoint: Option<String>,
    duration: Option<Duration>,
    out: Option<PathBuf>,
    max_events: Option<u64>,
    max_scan_pids: Option<usize>,
    ring_bytes: Option<u32>,
    drain_interval: Option<Duration>,
    unsafe_requested: bool,
    allow_confined_uretprobe: bool,
    track_short_lived: bool,
    verbose: bool,
    quiet: bool,
    attach_backend: BackendSelection,
    /// `--attach-backend` is scalar like the rest, but its type has no
    /// unset state, so repeats are tracked separately.
    attach_backend_seen: bool,
}

impl Common {
    /// One `--mode` rule for every capture surface: raw event streaming has no
    /// mode, whether it was selected as the `trace` subcommand or `run --trace`.
    fn metrics_for(&self, kind: Kind, subject: &str) -> Result<bool, CliError> {
        if self.select_endpoint.is_some() && self.counter_mode.is_none() {
            return Err(usage_err(
                "--select-endpoint requires --counter-mode counts|timestamps|latency \
                 on --mode metrics",
            ));
        }
        if self.counter_mode.is_some() {
            if kind != Kind::Profile || self.metrics != Some(true) {
                return Err(usage_err(
                    "--counter-mode requires --mode metrics on profile or run",
                ));
            }
            if self.unsafe_requested {
                return Err(usage_err(
                    "--counter-mode cannot be combined with --unsafe-unvalidated-metadata",
                ));
            }
        }
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
        "--exclude-module" => common
            .exclude_modules
            .push(require_path(args, "--exclude-module")?),
        "--manifest" => common.manifests.push(require_path(args, "--manifest")?),
        "--prearm-module" => common
            .prearm_modules
            .push(require_path(args, "--prearm-module")?),
        "--forwarding-module" => common
            .forwarding_modules
            .push(require_path(args, "--forwarding-module")?),
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
        "--counter-mode" => {
            if common.counter_mode.is_some() {
                return Err(usage_err("--counter-mode given twice"));
            }
            let value = require_value(args, "--counter-mode")?;
            common.counter_mode = Some(CounterMode::parse(&value).ok_or_else(|| {
                usage_err(format!(
                    "--counter-mode: invalid value {value:?} (expected counts|timestamps|latency)"
                ))
            })?);
        }
        "--select-endpoint" => {
            if common.select_endpoint.is_some() {
                return Err(usage_err("--select-endpoint given twice"));
            }
            let value = require_value(args, "--select-endpoint")?;
            if value.is_empty() {
                return Err(usage_err(
                    "--select-endpoint: invalid value \"\" (expected one endpoint function name)",
                ));
            }
            common.select_endpoint = Some(value);
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
        "--track-short-lived" => common.track_short_lived = true,
        "-v" | "--verbose" => common.verbose = true,
        "--quiet" => common.quiet = true,
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
        Some("profile") => parse_capture(Kind::Profile, argv)
            .map(Command::Profile)
            .map_err(|error| error.with_topic(HelpTopic::Profile)),
        Some("trace") => parse_capture(Kind::Trace, argv)
            .map(Command::Trace)
            .map_err(|error| error.with_topic(HelpTopic::Trace)),
        Some("run") => parse_run(argv)
            .map(Command::Run)
            .map_err(|error| error.with_topic(HelpTopic::Run)),
        Some("inspect") => parse_inspect(argv)
            .map(Command::Inspect)
            .map_err(|error| error.with_topic(HelpTopic::Inspect)),
        Some("doctor") => parse_doctor(argv)
            .map(Command::Doctor)
            .map_err(|error| error.with_topic(HelpTopic::Doctor)),
        Some("inventory") => {
            let mut args = argv.peekable();
            if args.peek().is_some_and(|value| value == "diff") {
                args.next();
                parse_inventory_diff(args)
                    .map(Command::InventoryDiff)
                    .map_err(|error| error.with_topic(HelpTopic::InventoryDiff))
            } else if args.peek().is_some_and(|value| value == "cbom") {
                args.next();
                parse_inventory_cbom(args)
                    .map(Command::InventoryCbom)
                    .map_err(|error| error.with_topic(HelpTopic::InventoryCbom))
            } else {
                parse_inventory(args)
                    .map(Command::Inventory)
                    .map_err(|error| error.with_topic(HelpTopic::Inventory))
            }
        }
        Some("--help" | "-h") => Err(CliError::Help(HelpTopic::Global)),
        Some("discover") => Err(usage_err(
            "`p11scope discover` was removed: run `p11scope-discover --module <provider.so> \
             -o <manifest.json>` (offline helper; executes provider code)",
        )),
        Some("help") => Err(parse_help_topic(argv)),
        Some(other) => Err(usage_err(format!("unknown subcommand: {other}"))),
        None => Err(CliError::Help(HelpTopic::Global)),
    }
}

/// `p11scope help [topic]`: the task list, or one command's scoped help.
/// Pure like `parse`: an unknown topic is a usage error, never a panic.
fn parse_help_topic(argv: impl Iterator<Item = OsString>) -> CliError {
    let words: Vec<String> = argv.map(|arg| word(&arg).into_owned()).collect();
    let topic = match words
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["--help"] | ["-h"] => HelpTopic::Global,
        ["profile"] => HelpTopic::Profile,
        ["trace"] => HelpTopic::Trace,
        ["run"] => HelpTopic::Run,
        ["inspect"] => HelpTopic::Inspect,
        ["doctor"] => HelpTopic::Doctor,
        ["inventory"] => HelpTopic::Inventory,
        ["inventory", "diff"] => HelpTopic::InventoryDiff,
        ["inventory", "cbom"] => HelpTopic::InventoryCbom,
        [unknown] => {
            return usage_err(format!("unknown help topic: {unknown}"));
        }
        [_, _, ..] => {
            return usage_err("help takes one topic (`help inventory diff` for diff)");
        }
    };
    CliError::Help(topic)
}

/// `p11scope inspect`: one target or the whole machine, discovery options
/// only — no capture policy, no duration, no output file (spec §4.6).
/// `--pid` and `--system` name the scope and are mutually exclusive;
/// `--max-scan-pids` bounds the system two-phase scan like a capture.
fn parse_inspect(mut args: impl Iterator<Item = OsString>) -> Result<InspectArgs, CliError> {
    let mut pid: Option<u32> = None;
    let mut system = false;
    let mut modules = Vec::new();
    let mut exclude_modules = Vec::new();
    let mut hooks = HookRegistry::builtin();
    let mut json = false;
    let mut max_scan_pids: Option<usize> = None;
    let mut verbose = false;
    let mut quiet = false;
    while let Some(a) = args.next() {
        match word(&a).as_ref() {
            "--help" | "-h" => return Err(CliError::Help(HelpTopic::Inspect)),
            "-v" | "--verbose" => verbose = true,
            "--quiet" => quiet = true,
            "--pid" => {
                if pid.is_some() {
                    return Err(usage_err("--pid given twice"));
                }
                pid = Some(require_pid(&mut args)?);
            }
            "--system" => system = true,
            "--module" => modules.push(require_path(&mut args, "--module")?),
            "--exclude-module" => {
                exclude_modules.push(require_path(&mut args, "--exclude-module")?)
            }
            "--hook-symbol" => add_hook(&mut hooks, &mut args)?,
            "--json" => json = true,
            "--max-scan-pids" => {
                if max_scan_pids.is_some() {
                    return Err(usage_err("--max-scan-pids given twice"));
                }
                let v = require_value(&mut args, "--max-scan-pids")?;
                let value = v
                    .parse::<usize>()
                    .map_err(|_| usage_err(format!("--max-scan-pids: invalid number {v:?}")))?;
                if value == 0 {
                    return Err(usage_err("--max-scan-pids must be greater than zero"));
                }
                max_scan_pids = Some(value);
            }
            other => return Err(unknown_arg(other)),
        }
    }
    if system && pid.is_some() {
        return Err(usage_err("--pid and --system are mutually exclusive"));
    }
    TextVerbosity::resolve(verbose, quiet)?;
    let scope = match (pid, system) {
        (Some(pid), false) => InspectScope::Pid(pid),
        (None, true) => InspectScope::System,
        (None, false) => return Err(usage_err("inspect requires --pid <n> or --system")),
        (Some(_), true) => unreachable!("mutual exclusion returns above"),
    };
    Ok(InspectArgs {
        scope,
        modules,
        exclude_modules,
        hooks,
        json,
        max_scan_pids,
        verbose,
        quiet,
    })
}

/// Offline comparison options are parsed before capture scope requirements.
fn parse_inventory_diff(
    mut args: impl Iterator<Item = OsString>,
) -> Result<InventoryDiffArgs, CliError> {
    let error = |message: &str| usage_err(message).with_topic(HelpTopic::InventoryDiff);
    let mut inputs = Vec::new();
    let mut json = false;
    let mut out = None;
    let mut verbose = false;
    let mut quiet = false;
    let mut positional = false;
    while let Some(value) = args.next() {
        if !positional {
            match value.to_str() {
                Some("--help" | "-h") => return Err(CliError::Help(HelpTopic::InventoryDiff)),
                Some("--") => {
                    positional = true;
                    continue;
                }
                Some("--json") => {
                    if json {
                        return Err(error("--json given twice"));
                    }
                    json = true;
                    continue;
                }
                Some("-v" | "--verbose") => {
                    verbose = true;
                    continue;
                }
                Some("--quiet") => {
                    quiet = true;
                    continue;
                }
                Some("-o") => {
                    if out.is_some() {
                        return Err(error("-o given twice"));
                    }
                    let path = args.next().ok_or_else(|| error("-o requires a path"))?;
                    if path == "-" {
                        return Err(error("-o - is unsupported; use --json for JSON on stdout"));
                    }
                    if path.is_empty() || path.as_bytes().starts_with(b"-") {
                        return Err(error("-o requires a path (prefix a leading dash with ./)"));
                    }
                    out = Some(PathBuf::from(path));
                    continue;
                }
                _ if value.as_bytes().starts_with(b"-") && value != "-" => {
                    return Err(error(&format!("unknown inventory diff option: {value:?}")));
                }
                _ => {}
            }
        }
        if value == "-" {
            return Err(error(
                "stdin is unsupported; pass two regular inventory files",
            ));
        }
        if value.is_empty() {
            return Err(error("inventory diff requires non-empty input paths"));
        }
        inputs.push(PathBuf::from(value));
        if inputs.len() > 2 {
            return Err(error(
                "inventory diff requires exactly BEFORE and AFTER files",
            ));
        }
    }
    if inputs.len() != 2 {
        return Err(error(
            "inventory diff requires exactly BEFORE and AFTER files",
        ));
    }
    TextVerbosity::resolve(verbose, quiet)
        .map_err(|error| error.with_topic(HelpTopic::InventoryDiff))?;
    let after = inputs.pop().expect("two input paths validated");
    let before = inputs.pop().expect("two input paths validated");
    Ok(InventoryDiffArgs {
        before,
        after,
        json,
        out,
        verbose,
        quiet,
    })
}

/// `p11scope inventory cbom`: one saved file in, CycloneDX out.
/// Mirrors the diff option shape; parsing here never changes the
/// capture path below.
fn parse_inventory_cbom(
    mut args: impl Iterator<Item = OsString>,
) -> Result<InventoryCbomArgs, CliError> {
    let error = |message: &str| usage_err(message).with_topic(HelpTopic::InventoryCbom);
    let mut input = None;
    let mut json = false;
    let mut out = None;
    let mut verbose = false;
    let mut quiet = false;
    let mut positional = false;
    while let Some(value) = args.next() {
        if !positional {
            match value.to_str() {
                Some("--help" | "-h") => return Err(CliError::Help(HelpTopic::InventoryCbom)),
                Some("--") => {
                    positional = true;
                    continue;
                }
                Some("--json") => {
                    if json {
                        return Err(error("--json given twice"));
                    }
                    json = true;
                    continue;
                }
                Some("-v" | "--verbose") => {
                    verbose = true;
                    continue;
                }
                Some("--quiet") => {
                    quiet = true;
                    continue;
                }
                Some("-o") => {
                    if out.is_some() {
                        return Err(error("-o given twice"));
                    }
                    let path = args.next().ok_or_else(|| error("-o requires a path"))?;
                    if path == "-" {
                        return Err(error("-o - is unsupported; use --json for JSON on stdout"));
                    }
                    if path.is_empty() || path.as_bytes().starts_with(b"-") {
                        return Err(error("-o requires a path (prefix a leading dash with ./)"));
                    }
                    out = Some(PathBuf::from(path));
                    continue;
                }
                _ if value.as_bytes().starts_with(b"-") && value != "-" => {
                    return Err(error(&format!("unknown inventory cbom option: {value:?}")));
                }
                _ => {}
            }
        }
        if value == "-" {
            return Err(error(
                "stdin is unsupported; pass one regular inventory or profile file",
            ));
        }
        if value.is_empty() {
            return Err(error("inventory cbom requires a non-empty input path"));
        }
        if input.is_some() {
            return Err(error("inventory cbom takes exactly one input file"));
        }
        input = Some(PathBuf::from(value));
    }
    let Some(input) = input else {
        return Err(error("inventory cbom takes exactly one input file"));
    };
    TextVerbosity::resolve(verbose, quiet)
        .map_err(|error| error.with_topic(HelpTopic::InventoryCbom))?;
    Ok(InventoryCbomArgs {
        input,
        json,
        out,
        verbose,
        quiet,
    })
}

/// `p11scope inventory`: capture scope/discovery options plus a duration and
/// saved JSON report. Diff parsing above never changes this capture path.
fn parse_inventory(mut args: impl Iterator<Item = OsString>) -> Result<InventoryArgs, CliError> {
    let mut pid: Option<u32> = None;
    let mut cgroup: Option<PathBuf> = None;
    let mut system = false;
    let mut modules = Vec::new();
    let mut exclude_modules = Vec::new();
    let mut manifests = Vec::new();
    let mut prearm_modules = Vec::new();
    let mut forwarding_modules = Vec::new();
    let mut key_operations = false;
    let mut hooks = HookRegistry::builtin();
    let mut json = false;
    let mut max_scan_pids: Option<usize> = None;
    let mut max_gaps: Option<usize> = None;
    let mut max_endpoints: Option<u64> = None;
    let mut duration: Option<Duration> = None;
    let mut out: Option<PathBuf> = None;
    let mut dashboard = false;
    let mut event_log: Option<PathBuf> = None;
    let mut event_rotate_bytes: Option<u64> = None;
    let mut event_max_files: Option<usize> = None;
    let mut event_interval: Option<Duration> = None;
    let mut diagnostics: Option<PathBuf> = None;
    let mut diagnostics_pid: Option<u32> = None;
    let mut quiet = false;
    let mut verbose = false;
    let mut capture: Option<CaptureMode> = None;
    let mut caller_metadata: Option<CallerMetadataMode> = None;
    let mut attach_backend: Option<BackendSelection> = None;
    let mut identity_backend: Option<IdentityBackendSelection> = None;
    while let Some(a) = args.next() {
        match word(&a).as_ref() {
            "--help" | "-h" => return Err(CliError::Help(HelpTopic::Inventory)),
            "--caller-metadata" => {
                if caller_metadata.is_some() {
                    return Err(usage_err("--caller-metadata given twice"));
                }
                let value = require_value(&mut args, "--caller-metadata")?;
                caller_metadata = Some(CallerMetadataMode::from_cli(&value)?);
            }
            value if value.starts_with("--caller-metadata=") => {
                if caller_metadata.is_some() {
                    return Err(usage_err("--caller-metadata given twice"));
                }
                caller_metadata = Some(CallerMetadataMode::from_cli(
                    &value["--caller-metadata=".len()..],
                )?);
            }
            "--capture" => {
                if capture.is_some() {
                    return Err(usage_err("--capture given twice"));
                }
                let v = require_value(&mut args, "--capture")?;
                capture = Some(match v.as_str() {
                    "auto" => CaptureMode::Auto,
                    "scan" => CaptureMode::Scan,
                    "native" => CaptureMode::Native,
                    _ => {
                        return Err(usage_err(format!(
                            "--capture: invalid value {v:?}: expected auto, scan or native"
                        )));
                    }
                });
            }
            "--attach-backend" => {
                if attach_backend.is_some() {
                    return Err(usage_err("--attach-backend given twice"));
                }
                let v = require_value(&mut args, "--attach-backend")?;
                attach_backend =
                    Some(BackendSelection::from_cli(&v).map_err(|e| usage_err(format!("{e:#}")))?);
            }
            "--identity-backend" => {
                if identity_backend.is_some() {
                    return Err(usage_err("--identity-backend given twice"));
                }
                let v = require_value(&mut args, "--identity-backend")?;
                identity_backend = Some(IdentityBackendSelection::from_cli(&v).map_err(usage_err)?);
            }
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
            "--module" => modules.push(require_path(&mut args, "--module")?),
            "--exclude-module" => {
                exclude_modules.push(require_path(&mut args, "--exclude-module")?)
            }
            "--manifest" => manifests.push(require_path(&mut args, "--manifest")?),
            "--prearm-module" => prearm_modules.push(require_path(&mut args, "--prearm-module")?),
            "--forwarding-module" => {
                forwarding_modules.push(require_path(&mut args, "--forwarding-module")?)
            }
            "--key-operations" => key_operations = true,
            "--hook-symbol" => add_hook(&mut hooks, &mut args)?,
            "--json" => json = true,
            "--quiet" => quiet = true,
            "-v" | "--verbose" => verbose = true,
            "--dashboard" => dashboard = true,
            "--event-log" => {
                if event_log.is_some() {
                    return Err(usage_err("--event-log given twice"));
                }
                event_log = Some(require_path(&mut args, "--event-log")?);
            }
            "--diagnostics" => {
                if diagnostics.is_some() {
                    return Err(usage_err("--diagnostics given twice"));
                }
                diagnostics = Some(require_path(&mut args, "--diagnostics")?);
            }
            "--diagnostics-pid" => {
                if diagnostics_pid.is_some() {
                    return Err(usage_err("--diagnostics-pid given twice"));
                }
                let value = require_value(&mut args, "--diagnostics-pid")?;
                let pid = value.parse::<u32>().map_err(|_| {
                    usage_err(format!("--diagnostics-pid: invalid number {value:?}"))
                })?;
                if pid == 0 {
                    return Err(usage_err("--diagnostics-pid must be greater than zero"));
                }
                diagnostics_pid = Some(pid);
            }
            "--event-rotate-bytes" => {
                if event_rotate_bytes.is_some() {
                    return Err(usage_err("--event-rotate-bytes given twice"));
                }
                let v = require_value(&mut args, "--event-rotate-bytes")?;
                event_rotate_bytes = Some(parse_event_bytes(&v).map_err(|e| {
                    usage_err(format!("--event-rotate-bytes: invalid value {v:?}: {e}"))
                })?);
            }
            "--event-max-files" => {
                if event_max_files.is_some() {
                    return Err(usage_err("--event-max-files given twice"));
                }
                let v = require_value(&mut args, "--event-max-files")?;
                let value = v
                    .parse::<usize>()
                    .map_err(|_| usage_err(format!("--event-max-files: invalid number {v:?}")))?;
                if value == 0 {
                    return Err(usage_err("--event-max-files must be greater than zero"));
                }
                event_max_files = Some(value);
            }
            "--event-interval" => {
                if event_interval.is_some() {
                    return Err(usage_err("--event-interval given twice"));
                }
                let v = require_value(&mut args, "--event-interval")?;
                let value = parse_duration(&v).map_err(|e| {
                    usage_err(format!("--event-interval: invalid value {v:?}: {e}"))
                })?;
                if value.is_zero() {
                    return Err(usage_err("--event-interval must be greater than zero"));
                }
                event_interval = Some(value);
            }
            "--max-scan-pids" => {
                if max_scan_pids.is_some() {
                    return Err(usage_err("--max-scan-pids given twice"));
                }
                let v = require_value(&mut args, "--max-scan-pids")?;
                let value = v
                    .parse::<usize>()
                    .map_err(|_| usage_err(format!("--max-scan-pids: invalid number {v:?}")))?;
                if value == 0 {
                    return Err(usage_err("--max-scan-pids must be greater than zero"));
                }
                max_scan_pids = Some(value);
            }
            "--max-gaps" => {
                if max_gaps.is_some() {
                    return Err(usage_err("--max-gaps given twice"));
                }
                let v = require_value(&mut args, "--max-gaps")?;
                let value = v
                    .parse::<usize>()
                    .map_err(|_| usage_err(format!("--max-gaps: invalid number {v:?}")))?;
                if value == 0 {
                    return Err(usage_err("--max-gaps must be greater than zero"));
                }
                if value > MAX_MAX_GAPS {
                    return Err(usage_err(format!(
                        "--max-gaps must not exceed {MAX_MAX_GAPS}"
                    )));
                }
                max_gaps = Some(value);
            }
            "--max-endpoints" => {
                if max_endpoints.is_some() {
                    return Err(usage_err("--max-endpoints given twice"));
                }
                let value = require_value(&mut args, "--max-endpoints")?;
                let endpoints = value
                    .parse::<u64>()
                    .map_err(|_| usage_err(format!("--max-endpoints: invalid number {value:?}")))?;
                // Validate usage here; the runtime retains the one resolved
                // budget before it opens any output or capture resources.
                crate::capacity::inventory_endpoint_budget(Some(endpoints)).map_err(usage_err)?;
                max_endpoints = Some(endpoints);
            }
            "--duration" => {
                if duration.is_some() {
                    return Err(usage_err("--duration given twice"));
                }
                let v = require_value(&mut args, "--duration")?;
                let value = parse_duration(&v)
                    .map_err(|e| usage_err(format!("--duration: invalid value {v:?}: {e}")))?;
                if value.is_zero() {
                    return Err(usage_err("--duration must be greater than zero"));
                }
                duration = Some(value);
            }
            "-o" => {
                if out.is_some() {
                    return Err(usage_err("-o given twice"));
                }
                out = Some(require_path(&mut args, "-o")?);
            }
            other => return Err(unknown_arg(other)),
        }
    }
    let selected = usize::from(pid.is_some()) + usize::from(cgroup.is_some()) + usize::from(system);
    if selected > 1 {
        return Err(usage_err(
            "--pid, --cgroup, and --system are mutually exclusive",
        ));
    }
    let scope = match (pid, cgroup, system) {
        (Some(pid), None, false) => ScopeArg::Pid(pid),
        (None, Some(path), false) => ScopeArg::Cgroup(path),
        (None, None, true) => ScopeArg::System,
        (None, None, false) => {
            return Err(usage_err(
                "inventory requires --pid <n>, --cgroup <path>, or --system",
            ));
        }
        _ => unreachable!("mutual exclusion returns above"),
    };
    if out.as_deref() == Some(std::path::Path::new("-")) {
        return Err(usage_err(
            "-o - writes to stdout, which inventory does not support for its report \
             (omit -o for the text summary, or pass --json for the document on stdout; \
             the report requires a file)",
        ));
    }
    if event_log.is_none()
        && (event_rotate_bytes.is_some() || event_max_files.is_some() || event_interval.is_some())
    {
        return Err(usage_err(
            "--event-rotate-bytes/--event-max-files/--event-interval require --event-log <f.jsonl|->",
        ));
    }
    // `--event-log -` owns stdout for the JSONL stream: nothing else
    // may write there. The human text summary moves to stderr instead
    // (the runner owns that routing); the JSON document and the
    // dashboard have nowhere else to go, so they are refused, as are
    // the file-only rotation options.
    let event_stdout = event_log.as_deref() == Some(std::path::Path::new("-"));
    if event_stdout && json {
        return Err(usage_err(
            "--event-log - owns stdout, so it cannot be combined with --json \
             (the JSON document goes to stdout)",
        ));
    }
    if event_stdout && dashboard {
        return Err(usage_err(
            "--event-log - owns stdout, so it cannot be combined with --dashboard \
             (the dashboard needs the terminal)",
        ));
    }
    if event_stdout && (event_rotate_bytes.is_some() || event_max_files.is_some()) {
        return Err(usage_err(
            "--event-rotate-bytes/--event-max-files cannot be combined with --event-log - \
             (stdout is not rotated)",
        ));
    }
    if diagnostics.is_none() && diagnostics_pid.is_some() {
        return Err(usage_err(
            "--diagnostics-pid requires --diagnostics <f.jsonl>",
        ));
    }
    if diagnostics.as_deref() == Some(std::path::Path::new("-")) {
        return Err(usage_err(
            "--diagnostics does not support stdout; pass a regular file path",
        ));
    }
    if !manifests.is_empty() && capture == Some(CaptureMode::Scan) {
        return Err(usage_err("--manifest requires --capture auto or native"));
    }
    if !prearm_modules.is_empty() && capture == Some(CaptureMode::Scan) {
        return Err(usage_err(
            "--prearm-module requires --capture auto or native",
        ));
    }
    if key_operations && capture == Some(CaptureMode::Scan) {
        return Err(usage_err(
            "--key-operations requires --capture auto or native",
        ));
    }
    if diagnostics.is_some() && capture == Some(CaptureMode::Scan) {
        return Err(usage_err("--diagnostics requires --capture auto or native"));
    }
    // D3d: identity selection affects system inventory only. An explicit
    // value under --pid or --cgroup is refused by name; the implicit
    // default elsewhere loads nothing and emits no field.
    if identity_backend.is_some() && !matches!(scope, ScopeArg::System) {
        let with = match &scope {
            ScopeArg::Pid(_) => "--pid",
            ScopeArg::Cgroup(_) => "--cgroup",
            ScopeArg::System => unreachable!("system scope accepts identity selection"),
        };
        return Err(usage_err(format!(
            "--identity-backend cannot be used with {with} (system inventory only; \
             use inventory --system)"
        )));
    }
    TextVerbosity::resolve(verbose, quiet)?;
    Ok(InventoryArgs {
        scope,
        modules,
        exclude_modules,
        manifests,
        prearm_modules,
        forwarding_modules,
        key_operations,
        hooks,
        json,
        max_scan_pids,
        max_gaps,
        max_endpoints,
        duration,
        out,
        dashboard,
        event_log,
        event_rotate_bytes,
        event_max_files,
        event_interval,
        diagnostics,
        diagnostics_pid,
        quiet,
        verbose,
        capture: capture.unwrap_or(CaptureMode::Auto),
        caller_metadata: caller_metadata.unwrap_or_default(),
        attach_backend: attach_backend.unwrap_or_default(),
        identity_backend_explicit: identity_backend.is_some(),
        identity_backend: identity_backend.unwrap_or_default(),
    })
}

/// `p11scope doctor`: every argument optional — a lane nobody named is reported
/// as not applicable rather than failed.
fn parse_doctor(mut args: impl Iterator<Item = OsString>) -> Result<DoctorArgs, CliError> {
    let mut doctor = DoctorArgs {
        pid: None,
        cgroup: None,
        extra_strict: false,
        verbose: false,
        quiet: false,
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
            "-v" | "--verbose" => doctor.verbose = true,
            "--quiet" => doctor.quiet = true,
            "--module" => {
                return Err(usage_err(
                    "doctor --module is not supported; use 'p11scope inspect --pid <n> --module \
                     <provider.so>' to list mapped providers",
                ));
            }
            "--system" => {
                return Err(usage_err(
                    "doctor --system is not supported; use --pid <n> or --cgroup <path> \
                     to check a target",
                ));
            }
            "--json" => {
                return Err(usage_err(
                    "unknown argument: --json (doctor is text-only; inspect and inventory take --json)",
                ));
            }
            other => return Err(unknown_arg(other)),
        }
    }
    TextVerbosity::resolve(doctor.verbose, doctor.quiet)?;
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
            "--json" => {
                let route = match kind {
                    Kind::Profile => "profile writes JSON with -o FILE",
                    Kind::Trace => "trace writes with -o FILE (or -o - for stdout)",
                };
                return Err(usage_err(format!("unknown argument: --json ({route})")));
            }
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
    // The level itself resolves at command entry; parsing only refuses
    // the contradictory pair.
    TextVerbosity::resolve(common.verbose, common.quiet)?;

    let metrics = common.metrics_for(kind, "trace")?;
    let out = resolve_dash_out(kind, "profile", common.out)?;
    Ok(CaptureArgs {
        kind,
        modules: common.modules,
        exclude_modules: common.exclude_modules,
        manifests: common.manifests,
        prearm_modules: common.prearm_modules,
        forwarding_modules: common.forwarding_modules,
        hooks: common.hooks,
        scope,
        metrics,
        counter_mode: common.counter_mode,
        select_endpoint: common.select_endpoint,
        duration: common.duration,
        out,
        max_events: common.max_events,
        max_scan_pids: common.max_scan_pids,
        ring_bytes: common.ring_bytes,
        drain_interval: common.drain_interval,
        unsafe_requested: common.unsafe_requested,
        allow_confined_uretprobe: common.allow_confined_uretprobe,
        attach_backend: common.attach_backend,
        track_short_lived: common.track_short_lived,
        verbose: common.verbose,
        quiet: common.quiet,
    })
}

/// `p11scope run`: the shared capture options, this observer's own pause
/// policy, and the command it starts. The command is everything after `--`,
/// taken verbatim so an argument meant for the child is never consumed here.
fn parse_run(mut args: impl Iterator<Item = OsString>) -> Result<RunArgs, CliError> {
    let mut common = Common::default();
    let mut pause = PausePolicy::Auto;
    let mut pause_seen = false;
    let mut kill_on_timeout = false;
    let mut trace = false;
    let mut user: Option<OsString> = None;
    let mut command: Vec<OsString> = Vec::new();

    while let Some(a) = args.next() {
        let arg = word(&a);
        if capture_option(&mut common, &arg, &mut args)? {
            continue;
        }
        match arg.as_ref() {
            "--help" | "-h" => return Err(CliError::Help(HelpTopic::Run)),
            "--trace" => trace = true,
            "--user" => {
                if user.is_some() {
                    return Err(usage_err("--user given twice"));
                }
                let value = require_os_value(&mut args, "--user")?;
                if value.is_empty() {
                    return Err(usage_err("--user requires a non-empty value"));
                }
                user = Some(value);
            }
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
            "--json" => {
                return Err(usage_err(
                    "unknown argument: --json (run writes JSON with -o FILE; run --trace also takes -o -)",
                ));
            }
            other => return Err(run_unknown_arg(other)),
        }
    }

    // 7.10b: an owned run arms the PID target-exec consumer for
    // its child, so the flag is accepted here like everywhere else.
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
    TextVerbosity::resolve(common.verbose, common.quiet)?;
    let metrics = common.metrics_for(kind, "run --trace")?;
    let out = resolve_dash_out(kind, "run without --trace", common.out)?;
    Ok(RunArgs {
        kind,
        modules: common.modules,
        exclude_modules: common.exclude_modules,
        manifests: common.manifests,
        prearm_modules: common.prearm_modules,
        forwarding_modules: common.forwarding_modules,
        hooks: common.hooks,
        metrics,
        counter_mode: common.counter_mode,
        select_endpoint: common.select_endpoint,
        duration: common.duration,
        out,
        max_events: common.max_events,
        max_scan_pids: common.max_scan_pids,
        ring_bytes: common.ring_bytes,
        drain_interval: common.drain_interval,
        unsafe_requested: common.unsafe_requested,
        allow_confined_uretprobe: common.allow_confined_uretprobe,
        pause,
        attach_backend: common.attach_backend,
        kill_on_timeout,
        track_short_lived: common.track_short_lived,
        verbose: common.verbose,
        quiet: common.quiet,
        user,
        command,
    })
}

/// `-o -` is stdout where the mode already streams there (trace and
/// `run --trace` print their lines to stdout when `-o` is omitted), and
/// is refused for profile, whose report requires a file: stdout carries
/// display frames only there. Either way no file literally named `-`
/// is ever created.
fn resolve_dash_out(
    kind: Kind,
    profile_subject: &str,
    out: Option<PathBuf>,
) -> Result<Option<PathBuf>, CliError> {
    match out {
        Some(path) if path.as_os_str() == std::ffi::OsStr::new("-") => match kind {
            Kind::Trace => Ok(None),
            Kind::Profile => Err(usage_err(format!(
                "-o - writes to stdout, which {profile_subject} does not support for its report \
                 (omit -o for display frames on stdout; the report requires a file)"
            ))),
        },
        out => Ok(out),
    }
}

/// The longest `--duration` any capture accepts: 366 days (one leap
/// year), far past any real observation window yet small enough that
/// `Instant::now() + d` can never overflow on a supported host.
pub const MAX_DURATION_SECS: u64 = 366 * 24 * 3600;

/// Parses a duration given as bare seconds or with a single trailing
/// `s`/`m`/`h` suffix — `"30"`, `"30s"`, `"5m"`, `"1h"` — up to
/// [`MAX_DURATION_SECS`]. The suffix multiplication is checked, and a
/// value past the bound is refused, so no accepted duration can
/// overflow the clock arithmetic a capture builds on it (B2: a bare
/// `u64::MAX` used to panic `inventory` in `Instant::now() + window`).
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
        return Err(format!("invalid duration {s:?} (use 30, 30s, 5m or 1h)"));
    }
    let secs: u64 = digits
        .parse()
        .map_err(|_| format!("invalid duration {s:?} (use 30, 30s, 5m or 1h)"))?;
    let secs = secs
        .checked_mul(mult)
        .ok_or_else(|| format!("duration {s:?} overflows"))?;
    if secs > MAX_DURATION_SECS {
        return Err(format!(
            "duration {s:?} exceeds the maximum {MAX_DURATION_SECS} seconds (366 days)"
        ));
    }
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

/// Parses an event-stream rotation threshold as plain bytes or with a
/// single trailing `K`/`M` suffix — `"4096"`, `"256K"`, `"1M"`. Any
/// positive value fits (rotation needs no power-of-two alignment).
pub fn parse_event_bytes(s: &str) -> Result<u64, String> {
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
    if bytes == 0 {
        return Err(format!("size {s:?} must be greater than zero"));
    }
    Ok(bytes)
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
    fn track_short_lived_defaults_off_and_parses_on_profile_and_run() {
        let Command::Profile(plain) = parse(args(&["profile", "--pid", "4242"])).unwrap() else {
            panic!("profile must parse");
        };
        assert!(!plain.track_short_lived);
        let Command::Profile(armed) =
            parse(args(&["profile", "--pid", "4242", "--track-short-lived"])).unwrap()
        else {
            panic!("profile --track-short-lived must parse");
        };
        assert!(armed.track_short_lived);
        // 7.10b widening: an owned run arms the PID target-exec
        // consumer for its child, so the flag parses there.
        let Command::Run(run_armed) =
            parse(args(&["run", "--track-short-lived", "--", "true"])).unwrap()
        else {
            panic!("run --track-short-lived must parse");
        };
        assert!(run_armed.track_short_lived);
        let Command::Run(run_plain) = parse(args(&["run", "--", "true"])).unwrap() else {
            panic!("run must parse");
        };
        assert!(!run_plain.track_short_lived);
    }

    #[test]
    fn inventory_cgroup_accepts_capture_modes_and_output_forms() {
        let outputs: &[&[&str]] = &[
            &[],
            &["--json"],
            &["--dashboard"],
            &["-o", "inventory.json"],
        ];
        for capture in ["scan", "auto", "native"] {
            for output in outputs {
                let mut argv = vec![
                    "inventory",
                    "--cgroup",
                    "/sys/fs/cgroup/owned.scope",
                    "--capture",
                    capture,
                    "--max-scan-pids",
                    "2",
                ];
                argv.extend_from_slice(output);
                let result = parse(args(&argv));
                let Ok(Command::Inventory(parsed)) = result else {
                    panic!("cgroup {capture} with {output:?} must parse: {result:?}");
                };
                assert_eq!(
                    parsed.scope,
                    ScopeArg::Cgroup(PathBuf::from("/sys/fs/cgroup/owned.scope"))
                );
                assert_eq!(parsed.max_scan_pids, Some(2));
                assert_eq!(parsed.json, output.contains(&"--json"));
                assert_eq!(parsed.dashboard, output.contains(&"--dashboard"));
                assert_eq!(
                    parsed.capture,
                    match capture {
                        "scan" => CaptureMode::Scan,
                        "auto" => CaptureMode::Auto,
                        "native" => CaptureMode::Native,
                        _ => unreachable!(),
                    }
                );
            }
        }
    }

    #[test]
    fn inventory_cgroup_accepts_non_utf8_operator_path() {
        use std::os::unix::ffi::OsStringExt;
        let result = parse(vec![
            OsString::from("inventory"),
            OsString::from("--cgroup"),
            OsString::from_vec(b"/sys/fs/cgroup/owned-\xff.scope".to_vec()),
            OsString::from("--capture"),
            OsString::from("scan"),
        ]);
        let Ok(Command::Inventory(parsed)) = result else {
            panic!("the byte path must parse: {result:?}");
        };
        assert_eq!(
            parsed.scope,
            ScopeArg::Cgroup(PathBuf::from(OsString::from_vec(
                b"/sys/fs/cgroup/owned-\xff.scope".to_vec()
            )))
        );
    }

    #[test]
    fn inventory_cgroup_help_names_scope_and_coverage_limit() {
        let help = HelpTopic::Inventory.text();
        assert!(help.contains("--cgroup <path>"), "{help}");
        assert!(help.contains("descendants"), "{help}");
        assert!(help.contains("Idle cgroup usage remains unknown"), "{help}");
        assert!(
            !help.contains("Quiet cgroup"),
            "cgroup idleness must not read as --quiet: {help}"
        );
    }

    #[test]
    fn inventory_help_states_manifest_s1_scope_and_opt_in_key_operations() {
        let help = HelpTopic::Inventory.text();
        assert!(
            help.contains("also tracks which key each operation used"),
            "{help}"
        );
        assert!(
            help.contains("Per-key results appear under object_observations"),
            "{help}"
        );
    }

    #[test]
    fn inventory_help_names_discover_for_run_time_tables() {
        let help = HelpTopic::Inventory.text();
        assert!(help.contains("example"), "{help}");
        assert!(
            help.contains(
                "Providers that build the table at run time need a manifest: run \
                 p11scope-discover --module <provider.so> -o <manifest.json> and pass \
                 --manifest <manifest.json>."
            ),
            "{help}"
        );
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
    fn dash_output_is_stdout_for_trace_and_refused_for_profile() {
        // Trace streams to stdout by default, so `-o -` is stdout.
        let Command::Trace(t) = parse(args(&["trace", "--pid", "42", "-o", "-"])).unwrap() else {
            panic!("expected trace")
        };
        assert_eq!(t.out, None);
        let Command::Run(r) =
            parse(args(&["run", "--trace", "-o", "-", "--", "/bin/true"])).unwrap()
        else {
            panic!("expected run")
        };
        assert_eq!(r.out, None);
        // Profile's report requires a file; the refusal says how to get
        // stdout output instead.
        for argv in [
            vec!["profile", "--pid", "42", "-o", "-"],
            vec!["run", "-o", "-", "--", "/bin/true"],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. }) if m.contains("-o -") && m.contains("omit -o")),
                "{argv:?}"
            );
        }
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
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. }) if m.contains(&format!("{flag} given twice"))),
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
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. }) if m.contains("requires a non-empty value")),
                "{argv:?}"
            );
        }
        // `--hook-symbol` already refuses an empty name; pin the usage error.
        assert!(matches!(
            parse(args(&["profile", "--pid", "42", "--hook-symbol", ""])),
            Err(CliError::Usage { message: m, .. }) if m.contains("empty symbol name")
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
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. }) if m.contains("--pid must be greater than zero")),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn inspect_and_doctor_parse_with_their_own_rules() {
        let Command::Inspect(i) = parse(args(&["inspect", "--pid", "7", "--json"])).unwrap() else {
            panic!("expected inspect")
        };
        assert_eq!((i.scope, i.json), (InspectScope::Pid(7), true));
        assert_eq!(i.max_scan_pids, None);
        assert!(
            matches!(parse(args(&["inspect"])), Err(CliError::Usage { message: m, .. }) if m.contains("--pid"))
        );

        let Command::Doctor(d) = parse(args(&["doctor"])).unwrap() else {
            panic!("expected doctor")
        };
        assert_eq!((d.pid, d.cgroup), (None, None));
    }

    #[test]
    fn inspect_system_scope_parses_and_excludes_pid() {
        let Command::Inspect(i) = parse(args(&[
            "inspect",
            "--system",
            "--json",
            "--max-scan-pids",
            "8",
        ]))
        .unwrap() else {
            panic!("expected inspect")
        };
        assert_eq!(i.scope, InspectScope::System);
        assert!(i.json);
        assert_eq!(i.max_scan_pids, Some(8));
        // No scope at all names both spellings.
        assert!(
            matches!(parse(args(&["inspect"])), Err(CliError::Usage { message: m, .. })
                if m.contains("--pid") && m.contains("--system"))
        );
        // The mutual-exclusion refusal names both flags, whichever order.
        for argv in [
            vec!["inspect", "--pid", "7", "--system"],
            vec!["inspect", "--system", "--pid", "7"],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. })
                    if m.contains("--pid") && m.contains("--system") && m.contains("mutually exclusive")),
                "{argv:?}"
            );
        }
        // `--max-scan-pids` keeps the capture validation wording.
        assert!(matches!(
            parse(args(&["inspect", "--system", "--max-scan-pids", "0"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--max-scan-pids must be greater than zero")
        ));
        assert!(matches!(
            parse(args(&[
                "inspect",
                "--system",
                "--max-scan-pids",
                "1",
                "--max-scan-pids",
                "2"
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--max-scan-pids given twice")
        ));
    }

    #[test]
    fn inventory_endpoint_policy_checks_range_and_exact_payload() {
        let Ok(Command::Inventory(default)) = parse(args(&["inventory", "--system"])) else {
            panic!("expected inventory default");
        };
        assert_eq!(default.max_endpoints, None);
        for endpoints in [1_u64, 4097, 6531, 8192] {
            for capture in ["scan", "auto", "native"] {
                let value = endpoints.to_string();
                let parsed = parse(args(&[
                    "inventory",
                    "--pid",
                    "7",
                    "--max-endpoints",
                    &value,
                    "--capture",
                    capture,
                ]));
                let Ok(Command::Inventory(parsed)) = parsed else {
                    panic!("selected endpoint budget {endpoints} in {capture}: {parsed:?}");
                };
                assert_eq!(parsed.max_endpoints, Some(endpoints));
                let budget =
                    crate::capacity::inventory_endpoint_budget(parsed.max_endpoints).unwrap();
                assert_eq!(budget.endpoint_limit(), endpoints);
                assert_eq!(budget.payload_bytes(), endpoints * 8);
            }
        }
    }

    #[test]
    fn inventory_endpoint_policy_refuses_invalid_and_duplicate_values() {
        for value in ["0", "131073", "4294967296", "18446744073709551615"] {
            assert!(
                matches!(
                    parse(args(&["inventory", "--system", "--max-endpoints", value])),
                    Err(CliError::Usage { message, .. })
                        if message.contains("--max-endpoints") && message.contains("1–131072")
                ),
                "out-of-policy endpoint budget {value} names the accepted range"
            );
        }
        for value in ["oops", "1.5", "18446744073709551616"] {
            assert!(
                matches!(
                    parse(args(&["inventory", "--system", "--max-endpoints", value])),
                    Err(CliError::Usage { message, .. })
                        if message.contains("--max-endpoints") && message.contains("invalid number")
                ),
                "malformed endpoint budget {value} names the numeric error"
            );
        }
        assert!(matches!(
            parse(args(&[
                "inventory", "--system", "--max-endpoints", "4097", "--max-endpoints", "8192"
            ])),
            Err(CliError::Usage { message, .. }) if message.contains("--max-endpoints given twice")
        ));
    }

    #[test]
    fn max_endpoints_is_inventory_only_and_its_help_names_the_policy() {
        for command in ["inspect", "profile", "trace"] {
            assert!(matches!(
                parse(args(&[command, "--system", "--max-endpoints", "8192"])),
                Err(CliError::Usage { message, .. }) if message.contains("--max-endpoints")
            ));
        }
        assert!(matches!(
            parse(args(&["run", "--max-endpoints", "8192", "--", "/bin/true"])),
            Err(CliError::Usage { message, .. }) if message.contains("--max-endpoints")
        ));
        let help = HelpTopic::Inventory.text();
        assert!(help.contains("[--max-endpoints <n>]"), "{help}");
        // The line carries the live budget constants, never a hard-coded
        // copy, so a limit change moves the help with it.
        assert!(
            help.contains(&format!(
                "1–{}, default {}",
                crate::capacity::MAX_INVENTORY_ENDPOINT_LIMIT,
                crate::capacity::DEFAULT_INVENTORY_ENDPOINT_LIMIT
            )),
            "{help}"
        );
        assert!(!help.contains("1..=8192"), "{help}");
    }

    #[test]
    fn inventory_endpoint_policy_admits_the_raised_ceiling() {
        for endpoints in [20_000_u64, 32_768, 131_072] {
            let value = endpoints.to_string();
            let parsed = parse(args(&["inventory", "--system", "--max-endpoints", &value]));
            let Ok(Command::Inventory(parsed)) = parsed else {
                panic!("raised endpoint budget {endpoints}: {parsed:?}");
            };
            assert_eq!(parsed.max_endpoints, Some(endpoints));
            let budget = crate::capacity::inventory_endpoint_budget(parsed.max_endpoints).unwrap();
            assert_eq!(budget.endpoint_limit(), endpoints);
        }
        assert!(matches!(
            parse(args(&["inventory", "--system", "--max-endpoints", "131073"])),
            Err(CliError::Usage { message, .. })
                if message.contains("--max-endpoints") && message.contains("1–131072")
        ));
        let help = HelpTopic::Inventory.text();
        assert!(
            help.contains("1–131072") && help.contains("32768"),
            "help must name the raised policy"
        );
    }

    #[test]
    fn inventory_parses_scope_duration_and_output() {
        let Command::Inventory(i) = parse(args(&[
            "inventory",
            "--pid",
            "7",
            "--duration",
            "60s",
            "-o",
            "inventory.json",
        ]))
        .unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(i.scope, ScopeArg::Pid(7));
        assert_eq!(i.duration, Some(Duration::from_secs(60)));
        assert_eq!(i.out, Some(PathBuf::from("inventory.json")));
        assert!(!i.json);
        let Command::Inventory(i) = parse(args(&[
            "inventory",
            "--system",
            "--json",
            "--max-scan-pids",
            "8",
            "--duration",
            "5m",
        ]))
        .unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(i.scope, ScopeArg::System);
        assert!(i.json);
        assert_eq!(i.max_scan_pids, Some(8));
        assert_eq!(i.duration, Some(Duration::from_secs(300)));
        assert_eq!(i.out, None);
        // No scope at all names both spellings.
        assert!(
            matches!(parse(args(&["inventory"])), Err(CliError::Usage { message: m, .. })
                if m.contains("--pid") && m.contains("--system"))
        );
        // The mutual-exclusion refusal names both flags, whichever order.
        for argv in [
            vec!["inventory", "--pid", "7", "--system"],
            vec!["inventory", "--system", "--pid", "7"],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. })
                    if m.contains("--pid") && m.contains("--system") && m.contains("mutually exclusive")),
                "{argv:?}"
            );
        }
    }

    /// Task 6 C5.1: `--capture auto|scan|native`, default `auto` (plan
    /// §10 ruling D1); once only; anything else is a usage error.
    #[test]
    fn inventory_capture_defaults_to_auto_and_parses_each_lane() {
        let Command::Inventory(plain) = parse(args(&["inventory", "--system"])).unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(plain.capture, CaptureMode::Auto);
        for (word, mode) in [
            ("auto", CaptureMode::Auto),
            ("scan", CaptureMode::Scan),
            ("native", CaptureMode::Native),
        ] {
            let Command::Inventory(i) =
                parse(args(&["inventory", "--pid", "7", "--capture", word])).unwrap()
            else {
                panic!("expected inventory")
            };
            assert_eq!(i.capture, mode, "{word}");
            assert_eq!(mode.label(), word);
        }
        assert!(matches!(
            parse(args(&["inventory", "--system", "--capture", "bpf"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--capture") && m.contains("auto, scan or native")
        ));
        assert!(matches!(
            parse(args(&["inventory", "--system", "--capture"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--capture")
        ));
        assert!(matches!(
            parse(args(&[
                "inventory", "--system", "--capture", "scan", "--capture", "native"
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--capture given twice")
        ));
    }

    /// The inventory scan promise bounds its late edge: inventory
    /// rescans in passes, and a process that starts after its last
    /// pass is reported, not scanned. The promise names its scopes:
    /// cgroup coverage is transactional, not pass-based, so the
    /// reported-not-scanned bound holds for system and pid scopes.
    #[test]
    fn inventory_help_bounds_late_process_scanning() {
        let help = HelpTopic::Inventory.text();
        assert!(
            help.contains("a process that starts after its last pass is reported, not scanned"),
            "{help:.500}"
        );
        assert!(
            help.contains("is reported, not scanned (system and pid scopes)"),
            "the late-process bound must name the scopes it covers: {help:.500}"
        );
    }

    /// One wrapped synopsis block per inventory scope: the prefixed
    /// line plus its continuation lines, joined. The synopsis wraps
    /// one option group per line (HELP-1); flags live anywhere in
    /// their scope's block.
    fn inventory_usage_blocks(text: &str) -> Vec<String> {
        let lines: Vec<&str> = text.lines().collect();
        let mut blocks = Vec::new();
        for (start, line) in lines.iter().enumerate() {
            if !(line.contains("p11scope inventory --") && line.contains("[--")) {
                continue;
            }
            let mut block = line.to_string();
            for following in lines.iter().skip(start + 1) {
                if following.starts_with("                   [") {
                    block.push_str(following);
                } else {
                    break;
                }
            }
            blocks.push(block);
        }
        blocks
    }

    fn inventory_usage_block_for<'a>(blocks: &'a [String], prefix: &str) -> &'a str {
        let matches: Vec<&String> = blocks
            .iter()
            .filter(|block| block.starts_with(prefix))
            .collect();
        assert_eq!(matches.len(), 1, "missing or duplicate {prefix:?} block");
        matches[0]
    }

    /// The C8 harness probes `--capture` on a usage line that names
    /// `p11scope inventory` (`inventory-native-oracle.py probe-help`): every
    /// inventory scope usage line carries it, in global and scoped help alike.
    #[test]
    fn inventory_usage_lines_carry_the_capture_flag() {
        for text in [USAGE.to_string(), HelpTopic::Inventory.text()] {
            let blocks = inventory_usage_blocks(&text);
            assert_eq!(blocks.len(), 3, "{text}");
            for prefix in [
                "  p11scope inventory --pid ",
                "  p11scope inventory --cgroup ",
                "  p11scope inventory --system ",
            ] {
                let block = inventory_usage_block_for(&blocks, prefix);
                assert!(block.contains("[--capture auto|scan|native]"), "{block}");
            }
        }
    }

    #[test]
    fn inventory_diff_parser_accepts_offline_files_and_scoped_options() {
        for words in [
            vec!["inventory", "diff", "before.json", "after.json"],
            vec![
                "inventory",
                "diff",
                "--json",
                "before.json",
                "after.json",
                "-o",
                "report.json",
            ],
            vec!["inventory", "diff", "--", "-before.json", "-after.json"],
        ] {
            let command = parse(args(&words)).unwrap();
            assert!(format!("{command:?}").starts_with("InventoryDiff("));
        }
    }

    #[test]
    fn inventory_diff_help_has_its_own_offline_topic() {
        let Err(CliError::Help(topic)) = parse(args(&["inventory", "diff", "--help"])) else {
            panic!("diff help must select an offline help topic")
        };
        assert!(topic.text().contains("inventory diff BEFORE"));
        assert!(!topic.text().contains("--pid"));
    }

    #[test]
    fn inventory_diff_parses_verbosity_and_defaults_it_off() {
        let Command::InventoryDiff(plain) =
            parse(args(&["inventory", "diff", "before.json", "after.json"])).unwrap()
        else {
            panic!("expected diff")
        };
        assert!(!plain.verbose, "verbose defaults off");
        assert!(!plain.quiet, "quiet defaults off");
        let Command::InventoryDiff(verbose) = parse(args(&[
            "inventory",
            "diff",
            "-v",
            "before.json",
            "after.json",
        ]))
        .unwrap() else {
            panic!("expected diff")
        };
        assert!(verbose.verbose, "-v selects verbose");
        assert!(!verbose.quiet);
        let Command::InventoryDiff(quiet) = parse(args(&[
            "inventory",
            "diff",
            "before.json",
            "after.json",
            "--quiet",
        ]))
        .unwrap() else {
            panic!("expected diff")
        };
        assert!(!quiet.verbose);
        assert!(quiet.quiet, "--quiet selects quiet");
    }

    #[test]
    fn inventory_cbom_parser_accepts_one_offline_file_and_scoped_options() {
        for words in [
            vec!["inventory", "cbom", "input.json"],
            vec![
                "inventory",
                "cbom",
                "--json",
                "input.json",
                "-o",
                "out.cdx.json",
            ],
            vec!["inventory", "cbom", "--", "-input.json"],
        ] {
            let command = parse(args(&words)).unwrap();
            assert!(format!("{command:?}").starts_with("InventoryCbom("));
        }
        for words in [
            vec!["inventory", "cbom"],
            vec!["inventory", "cbom", "a.json", "b.json"],
            vec!["inventory", "cbom", "-"],
            vec!["inventory", "cbom", "a.json", "-o", "-"],
            vec!["inventory", "cbom", "a.json", "-v", "--quiet"],
        ] {
            assert!(parse(args(&words)).is_err(), "{words:?} must be refused");
        }
    }

    #[test]
    fn inventory_cbom_help_has_its_own_offline_topic() {
        let Err(CliError::Help(topic)) = parse(args(&["inventory", "cbom", "--help"])) else {
            panic!("cbom help must select an offline help topic")
        };
        assert!(topic.text().contains("inventory cbom INPUT"));
        assert!(!topic.text().contains("--pid"));
    }

    #[test]
    fn inventory_cbom_parses_verbosity_and_defaults_it_off() {
        let Command::InventoryCbom(plain) =
            parse(args(&["inventory", "cbom", "input.json"])).unwrap()
        else {
            panic!("expected cbom")
        };
        assert!(!plain.verbose, "verbose defaults off");
        assert!(!plain.quiet, "quiet defaults off");
        let Command::InventoryCbom(verbose) =
            parse(args(&["inventory", "cbom", "-v", "input.json"])).unwrap()
        else {
            panic!("expected cbom")
        };
        assert!(verbose.verbose, "-v selects verbose");
        assert!(!verbose.quiet);
        let Command::InventoryCbom(quiet) =
            parse(args(&["inventory", "cbom", "input.json", "--quiet"])).unwrap()
        else {
            panic!("expected cbom")
        };
        assert!(!quiet.verbose);
        assert!(quiet.quiet, "--quiet selects quiet");
    }

    #[test]
    fn inventory_help_states_the_auto_pid_scan_fallback() {
        let help = HelpTopic::Inventory.text();
        assert!(
            help.contains(
                "auto prefers native and falls back to scan with a named gap (needs root \
                 for live capture; without root a PID capture still reports its scan)"
            ),
            "{help}"
        );
    }

    #[test]
    fn dr04_caller_metadata_is_opt_in_and_accepts_split_and_equals_forms() {
        let default = parse(args(&["inventory", "--pid", "7"])).unwrap();
        assert!(format!("{default:?}").contains("caller_metadata: None"));
        for scope in [
            vec!["--pid", "7"],
            vec!["--system"],
            vec!["--cgroup", "/owned"],
        ] {
            for option in [
                vec!["--caller-metadata", "cgroup"],
                vec!["--caller-metadata=cgroup"],
            ] {
                let mut words = vec!["inventory"];
                words.extend_from_slice(&scope);
                words.extend_from_slice(&option);
                let parsed = parse(args(&words)).expect("explicit metadata option");
                assert!(format!("{parsed:?}").contains("caller_metadata: Cgroup"));
            }
        }
        assert!(
            parse(args(&[
                "inventory",
                "--system",
                "--caller-metadata",
                "runtime"
            ]))
            .is_err()
        );
        assert!(
            parse(args(&[
                "inventory",
                "--system",
                "--caller-metadata",
                "cgroup",
                "--caller-metadata=none"
            ]))
            .is_err()
        );
        assert!(parse(args(&["trace", "--pid", "7", "--caller-metadata=cgroup"])).is_err());
    }

    /// D3d RED: `inventory --identity-backend` selects the system sweep
    /// identity backend; `auto` by default, system scope only.
    #[test]
    fn d3d_identity_backend_defaults_to_auto_and_parses_each_value() {
        let Command::Inventory(plain) = parse(args(&["inventory", "--system"])).unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(
            plain.identity_backend,
            IdentityBackendSelection::Auto,
            "default identity selection is auto"
        );
        assert!(
            !plain.identity_backend_explicit,
            "implicit default is not an explicit selection"
        );
        for (word, expected) in [
            ("auto", IdentityBackendSelection::Auto),
            ("userspace", IdentityBackendSelection::Userspace),
            ("kernel", IdentityBackendSelection::Kernel),
        ] {
            let Command::Inventory(i) =
                parse(args(&["inventory", "--system", "--identity-backend", word])).unwrap()
            else {
                panic!("expected inventory")
            };
            assert_eq!(i.identity_backend, expected, "word {word}");
            assert!(i.identity_backend_explicit, "word {word} is explicit");
        }
    }

    /// D3d RED: duplicate/missing/invalid identity selection and explicit
    /// use outside system scope are usage errors.
    #[test]
    fn d3d_identity_backend_refuses_duplicate_missing_invalid_and_pid_scope() {
        assert!(matches!(
            parse(args(&["inventory", "--system", "--identity-backend", "both"])),
            Err(CliError::Usage { message: m, .. })
                if m.contains("--identity-backend: invalid value")
        ));
        assert!(matches!(
            parse(args(&[
                "inventory",
                "--system",
                "--identity-backend",
                "kernel",
                "--identity-backend",
                "userspace",
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--identity-backend given twice")
        ));
        assert!(matches!(
            parse(args(&["inventory", "--system", "--identity-backend"])),
            Err(CliError::Usage { message: m, .. })
                if m.contains("--identity-backend requires a value")
        ));
        assert!(matches!(
            parse(args(&["inventory", "--pid", "7", "--identity-backend", "kernel"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--identity-backend")
        ));
        assert!(matches!(
            parse(args(&[
                "inventory",
                "--cgroup",
                "/sys/fs/cgroup/owned.scope",
                "--identity-backend",
                "kernel",
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--identity-backend")
        ));
        // Implicit default under --pid parses and stays non-explicit.
        let Command::Inventory(pid) = parse(args(&["inventory", "--pid", "7"])).unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(pid.identity_backend, IdentityBackendSelection::Auto);
        assert!(!pid.identity_backend_explicit);
    }

    /// C5.11: `inventory --attach-backend` selects the native lane's attach
    /// backend; `auto` by default, each value parsed, repeats refused, and
    /// both usage lines carry it.
    #[test]
    fn inventory_attach_backend_defaults_to_auto_and_parses_each_value() {
        use crate::attach::BackendSelection;
        let Command::Inventory(plain) = parse(args(&["inventory", "--system"])).unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(plain.attach_backend, BackendSelection::Auto);
        for (word, expected) in [
            ("auto", BackendSelection::Auto),
            ("multi", BackendSelection::Multi),
            ("singles", BackendSelection::Singles),
        ] {
            let Command::Inventory(i) =
                parse(args(&["inventory", "--system", "--attach-backend", word])).unwrap()
            else {
                panic!("expected inventory")
            };
            assert_eq!(i.attach_backend, expected);
        }
        assert!(matches!(
            parse(args(&["inventory", "--system", "--attach-backend", "both"])),
            Err(CliError::Usage { .. })
        ));
        assert!(matches!(
            parse(args(&[
                "inventory", "--system", "--attach-backend", "multi", "--attach-backend", "singles"
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("given twice")
        ));
        // Global help shows one short line per scope; the scoped help
        // carries the full per-scope synopsis.
        let global_blocks = inventory_usage_blocks(USAGE);
        assert_eq!(global_blocks.len(), 3, "{USAGE}");
        let scoped_blocks = inventory_usage_blocks(&HelpTopic::Inventory.text());
        assert_eq!(scoped_blocks.len(), 3);
        for prefix in [
            "  p11scope inventory --pid ",
            "  p11scope inventory --cgroup ",
            "  p11scope inventory --system ",
        ] {
            let block = inventory_usage_block_for(&scoped_blocks, prefix);
            assert!(
                block.contains("[--attach-backend auto|multi|singles]"),
                "{block}"
            );
        }
    }

    #[test]
    fn inventory_max_gaps_defaults_to_none_and_parses_when_set() {
        // Absent ⇒ None; the runner applies the 1024 default.
        let Command::Inventory(plain) = parse(args(&["inventory", "--pid", "7"])).unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(plain.max_gaps, None);
        let Command::Inventory(i) = parse(args(&[
            "inventory",
            "--system",
            "--json",
            "--max-gaps",
            "4096",
        ]))
        .unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(i.max_gaps, Some(4096));
    }

    #[test]
    fn inventory_refuses_bad_max_gaps() {
        assert!(matches!(
            parse(args(&["inventory", "--pid", "7", "--max-gaps", "0"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--max-gaps must be greater than zero")
        ));
        assert!(matches!(
            parse(args(&["inventory", "--pid", "7", "--max-gaps", "many"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--max-gaps: invalid number")
        ));
        assert!(matches!(
            parse(args(&[
                "inventory", "--pid", "7", "--max-gaps", "8", "--max-gaps", "9"
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--max-gaps given twice")
        ));
        assert!(matches!(
            parse(args(&["inventory", "--pid", "7", "--max-gaps", "65537"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--max-gaps must not exceed 65536")
        ));
        // The ceiling itself parses.
        let Command::Inventory(i) =
            parse(args(&["inventory", "--pid", "7", "--max-gaps", "65536"])).unwrap()
        else {
            panic!("expected inventory")
        };
        assert_eq!(i.max_gaps, Some(65536));
    }

    #[test]
    fn inventory_refuses_bad_duration_and_stdout_report() {
        assert!(matches!(
            parse(args(&["inventory", "--pid", "7", "--duration", "0"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--duration must be greater than zero")
        ));
        assert!(matches!(
            parse(args(&[
                "inventory", "--pid", "7", "--duration", "10", "--duration", "20"
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--duration given twice")
        ));
        assert!(matches!(
            parse(args(&["inventory", "--pid", "7", "--duration", "soon"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--duration: invalid value")
        ));
        assert!(matches!(
            parse(args(&["inventory", "--pid", "7", "-o", "a", "-o", "b"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("-o given twice")
        ));
        // The report requires a file, like profile's.
        assert!(matches!(
            parse(args(&["inventory", "--pid", "7", "-o", "-"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("-o - writes to stdout")
        ));
        assert!(matches!(
            parse(args(&["inventory", "--system", "--bogus"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("unknown argument: --bogus")
        ));
    }

    #[test]
    fn inventory_diagnostics_accepts_native_and_auto() {
        for mode in ["auto", "native"] {
            let Command::Inventory(parsed) = parse(args(&[
                "inventory",
                "--system",
                "--capture",
                mode,
                "--diagnostics",
                "inventory-debug.jsonl",
                "--diagnostics-pid",
                "42",
            ]))
            .unwrap() else {
                panic!("expected inventory")
            };
            assert_eq!(parsed.scope, ScopeArg::System);
            assert_eq!(parsed.capture.label(), mode);
            assert_eq!(
                parsed.diagnostics,
                Some(PathBuf::from("inventory-debug.jsonl"))
            );
            assert_eq!(parsed.diagnostics_pid, Some(42));
        }
    }

    #[test]
    fn inventory_diagnostics_defaults_and_filter_preserve_capture_scope() {
        let Command::Inventory(plain) = parse(args(&["inventory", "--pid", "7"])).unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(plain.diagnostics, None);
        assert_eq!(plain.diagnostics_pid, None);
        let Command::Inventory(parsed) = parse(args(&[
            "inventory",
            "--pid",
            "7",
            "--diagnostics",
            "debug.jsonl",
            "--diagnostics-pid",
            "4294967295",
        ]))
        .unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(parsed.scope, ScopeArg::Pid(7));
        assert_eq!(parsed.capture, CaptureMode::Auto);
        assert_eq!(parsed.diagnostics_pid, Some(u32::MAX));
        let Command::Inventory(unfiltered) = parse(args(&[
            "inventory",
            "--system",
            "--diagnostics",
            "debug.jsonl",
        ]))
        .unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(unfiltered.diagnostics_pid, None);
    }

    #[test]
    fn inventory_diagnostics_preserves_path_bytes_and_rejects_non_utf8_pid() {
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
        let path = OsString::from_vec(b"debug-\xff.jsonl".to_vec());
        let Command::Inventory(parsed) = parse([
            OsString::from("inventory"),
            OsString::from("--system"),
            OsString::from("--diagnostics"),
            path.clone(),
        ])
        .unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(
            parsed.diagnostics.unwrap().as_os_str().as_bytes(),
            path.as_bytes()
        );
        assert!(matches!(
            parse([
                OsString::from("inventory"),
                OsString::from("--system"),
                OsString::from("--diagnostics-pid"),
                OsString::from_vec(b"42\xff".to_vec()),
            ]),
            Err(CliError::Usage { message, topic: HelpTopic::Inventory })
                if message.contains("--diagnostics-pid") && message.contains("not valid UTF-8")
        ));
    }

    #[test]
    fn inventory_diagnostics_refuses_invalid_combinations_and_values() {
        for (options, expected) in [
            (vec!["--diagnostics-pid", "42"], "requires --diagnostics"),
            (vec!["--diagnostics", "-"], "does not support stdout"),
            (
                vec!["--diagnostics", "debug.jsonl", "--capture", "scan"],
                "requires --capture auto or native",
            ),
            (
                vec!["--capture", "scan", "--diagnostics", "debug.jsonl"],
                "requires --capture auto or native",
            ),
            (vec!["--diagnostics", ""], "requires a non-empty value"),
            (vec!["--diagnostics"], "--diagnostics requires a value"),
            (
                vec!["--diagnostics", "a", "--diagnostics", "b"],
                "--diagnostics given twice",
            ),
            (
                vec!["--diagnostics-pid", "42", "--diagnostics-pid", "43"],
                "--diagnostics-pid given twice",
            ),
            (
                vec!["--diagnostics-pid"],
                "--diagnostics-pid requires a value",
            ),
            (
                vec!["--diagnostics-pid", "0"],
                "--diagnostics-pid must be greater than zero",
            ),
            (
                vec!["--diagnostics-pid", "-1"],
                "--diagnostics-pid: invalid number",
            ),
            (
                vec!["--diagnostics-pid", "4294967296"],
                "--diagnostics-pid: invalid number",
            ),
            (
                vec!["--diagnostics-pid", "many"],
                "--diagnostics-pid: invalid number",
            ),
        ] {
            let mut argv = vec!["inventory", "--system"];
            argv.extend(options);
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage { message, topic: HelpTopic::Inventory })
                    if message.contains(expected)),
                "{argv:?} should report {expected}"
            );
        }
    }

    #[test]
    fn inventory_prearm_module_parses_and_refuses_scan() {
        // Repeatable input surface on inventory.
        let Command::Inventory(parsed) = parse(args(&[
            "inventory",
            "--pid",
            "7",
            "--prearm-module",
            "a.so",
            "--prearm-module",
            "b.so",
        ]))
        .unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(
            parsed.prearm_modules,
            vec![
                std::path::PathBuf::from("a.so"),
                std::path::PathBuf::from("b.so")
            ]
        );
        // Refused by name under `--capture scan`, like `--manifest`.
        for argv in [
            vec![
                "inventory",
                "--pid",
                "7",
                "--capture",
                "scan",
                "--prearm-module",
                "a.so",
            ],
            vec![
                "inventory",
                "--pid",
                "7",
                "--prearm-module",
                "a.so",
                "--capture",
                "scan",
            ],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage { message, topic: HelpTopic::Inventory })
                    if message.contains("--prearm-module requires --capture auto or native")),
                "{argv:?} should refuse --prearm-module under scan"
            );
        }
    }

    #[test]
    fn inventory_key_operations_parses_and_defaults_off() {
        // Opt-in on every scope, never narrowed to one scope.
        for scope in [
            vec!["--pid", "7"],
            vec!["--cgroup", "/sys/fs/cgroup/p11scope.slice"],
            vec!["--system"],
        ] {
            let mut argv = vec!["inventory", "--key-operations"];
            argv.extend(scope);
            let Command::Inventory(parsed) = parse(args(&argv)).unwrap() else {
                panic!("{argv:?} should parse as inventory");
            };
            assert!(parsed.key_operations, "{argv:?} should opt in");
        }
        // Absent means off.
        let Command::Inventory(parsed) = parse(args(&["inventory", "--pid", "7"])).unwrap() else {
            panic!("expected inventory");
        };
        assert!(!parsed.key_operations, "the flag defaults off");
    }

    #[test]
    fn inventory_key_operations_refuses_scan() {
        // Refused by name under `--capture scan`, like `--manifest`,
        // whichever order the flags arrive in.
        for argv in [
            vec![
                "inventory",
                "--pid",
                "7",
                "--capture",
                "scan",
                "--key-operations",
            ],
            vec![
                "inventory",
                "--pid",
                "7",
                "--key-operations",
                "--capture",
                "scan",
            ],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage { message, topic: HelpTopic::Inventory })
                    if message.contains("--key-operations requires --capture auto or native")),
                "{argv:?} should refuse --key-operations under scan"
            );
        }
    }

    #[test]
    fn inventory_help_names_key_operations_flag() {
        // The flag, its scope, and its capture requirement are
        // documented where the inventory flag surface is pinned.
        let help = HelpTopic::Inventory.text();
        assert!(help.contains("[--key-operations]"), "{help}");
        assert!(help.contains("--key-operations"), "{help}");
        assert!(help.contains("needs --capture auto or native"), "{help}");
    }

    #[test]
    fn inventory_quiet_parses_and_defaults_off() {
        // Opt-in on every scope, never narrowed to one scope.
        for scope in [
            vec!["--pid", "7"],
            vec!["--cgroup", "/sys/fs/cgroup/p11scope.slice"],
            vec!["--system"],
        ] {
            let mut argv = vec!["inventory", "--quiet"];
            argv.extend(scope);
            let Command::Inventory(parsed) = parse(args(&argv)).unwrap() else {
                panic!("{argv:?} should parse as inventory");
            };
            assert!(parsed.quiet, "{argv:?} should opt in");
        }
        // Absent means off.
        let Command::Inventory(parsed) = parse(args(&["inventory", "--pid", "7"])).unwrap() else {
            panic!("expected inventory");
        };
        assert!(!parsed.quiet, "the flag defaults off");
    }

    #[test]
    fn inventory_help_names_quiet_flag() {
        let help = HelpTopic::Inventory.text();
        assert!(help.contains("[--quiet]"), "{help}");
        assert!(
            help.contains("--quiet prints only the summary head"),
            "{help}"
        );
    }

    #[test]
    fn verbosity_flags_parse_on_every_user_facing_command() {
        // `-v` and `--verbose` spell the same flag; `--quiet` is the
        // scripts-only summary head. All four user-facing commands plus
        // trace (stderr notes only there) accept them; omission means off.
        let Command::Profile(profile) = parse(args(&["profile", "--pid", "7", "-v"])).unwrap()
        else {
            panic!("expected profile");
        };
        assert!(profile.verbose);
        assert!(!profile.quiet);
        let Command::Trace(trace) = parse(args(&[
            "trace",
            "--pid",
            "7",
            "--duration",
            "1s",
            "--verbose",
        ]))
        .unwrap() else {
            panic!("expected trace");
        };
        assert!(trace.verbose);
        assert!(!trace.quiet);
        let Command::Run(run) = parse(args(&["run", "--quiet", "--", "/bin/true"])).unwrap() else {
            panic!("expected run");
        };
        assert!(!run.verbose);
        assert!(run.quiet);
        let Command::Inspect(inspect) =
            parse(args(&["inspect", "--pid", "7", "--verbose"])).unwrap()
        else {
            panic!("expected inspect");
        };
        assert!(inspect.verbose);
        assert!(!inspect.quiet);
        let Command::Inspect(system) = parse(args(&["inspect", "--system", "-v"])).unwrap() else {
            panic!("expected inspect");
        };
        assert!(system.verbose);
        let Command::Inventory(inventory) = parse(args(&["inventory", "--system", "-v"])).unwrap()
        else {
            panic!("expected inventory");
        };
        assert!(inventory.verbose);
        assert!(!inventory.quiet);
        let Command::Inventory(plain) = parse(args(&["inventory", "--pid", "7"])).unwrap() else {
            panic!("expected inventory");
        };
        assert!(!plain.verbose, "verbose defaults off");
        assert!(!plain.quiet, "quiet defaults off");
    }

    #[test]
    fn quiet_and_verbose_together_are_refused_on_every_command() {
        for argv in [
            vec!["profile", "--pid", "7", "--quiet", "--verbose"],
            vec!["trace", "--pid", "7", "-v", "--quiet"],
            vec!["run", "-v", "--quiet", "--", "/bin/true"],
            vec!["inspect", "--pid", "7", "--quiet", "-v"],
            vec!["inspect", "--system", "--verbose", "--quiet"],
            vec!["inventory", "--pid", "7", "--quiet", "--verbose"],
            vec!["doctor", "--quiet", "--verbose"],
            vec!["inventory", "diff", "a.json", "b.json", "-v", "--quiet"],
        ] {
            let Err(CliError::Usage { message, .. }) = parse(args(&argv)) else {
                panic!("{argv:?} should refuse the contradictory pair");
            };
            assert!(
                message.contains("--quiet and --verbose are mutually exclusive"),
                "{argv:?}: {message}"
            );
        }
    }

    #[test]
    fn verbosity_level_resolves_flags_without_precedence() {
        assert_eq!(
            TextVerbosity::resolve(false, false).unwrap(),
            TextVerbosity::Concise
        );
        assert_eq!(
            TextVerbosity::resolve(true, false).unwrap(),
            TextVerbosity::Verbose
        );
        assert_eq!(
            TextVerbosity::resolve(false, true).unwrap(),
            TextVerbosity::Quiet
        );
        assert!(TextVerbosity::resolve(true, true).is_err());
        assert_eq!(TextVerbosity::default(), TextVerbosity::Concise);
        assert_eq!(text_verbosity(), TextVerbosity::Concise);
    }

    #[test]
    fn verbosity_synopsis_and_notes_are_advertised() {
        for topic in [
            HelpTopic::Global,
            HelpTopic::Profile,
            HelpTopic::Trace,
            HelpTopic::Run,
            HelpTopic::Inspect,
            HelpTopic::Doctor,
            HelpTopic::Inventory,
        ] {
            let help = topic.text();
            assert!(help.contains("[-v]"), "{topic:?}: {help}");
            assert!(help.contains("[--quiet]"), "{topic:?}: {help}");
        }
        assert!(USAGE.contains("-v, --verbose shows full detail"), "{USAGE}");
        // HELP-1: no synopsis line wraps a terminal at 80 columns by
        // itself; the inventory usage wraps one option group per line.
        for line in USAGE.lines().filter(|line| line.contains("p11scope ")) {
            assert!(line.len() < 200, "overlong synopsis line: {line}");
        }
    }

    #[test]
    fn inventory_diagnostics_options_are_capture_only() {
        for (argv, expected) in [
            (
                vec!["profile", "--pid", "7", "--diagnostics", "debug.jsonl"],
                "unknown argument: --diagnostics",
            ),
            (
                vec!["trace", "--pid", "7", "--diagnostics-pid", "42"],
                "unknown argument: --diagnostics-pid",
            ),
            (
                vec![
                    "inventory",
                    "diff",
                    "before.json",
                    "after.json",
                    "--diagnostics",
                    "debug.jsonl",
                ],
                "unknown inventory diff option",
            ),
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage { message, .. })
                    if message.contains(expected)),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn inventory_diagnostics_help_names_options_and_limits_scope() {
        // Global help shows one short line per scope; the full synopsis
        // lives in the scoped help.
        assert_eq!(inventory_usage_blocks(USAGE).len(), 3, "{USAGE}");
        let help = HelpTopic::Inventory.text();
        for block in inventory_usage_blocks(&help) {
            assert!(
                block.contains("[--diagnostics <f.jsonl> [--diagnostics-pid <n>]]"),
                "{block}"
            );
        }
        assert!(help.contains("without changing capture scope"), "{help}");
        assert!(help.contains("auto or native"), "{help}");
        assert!(help.contains("after capture stops"), "{help}");
        assert!(!inventory_diff_help().contains("--diagnostics"));
    }

    #[test]
    fn inventory_parses_dashboard_and_event_stream_options() {
        let Command::Inventory(i) = parse(args(&[
            "inventory",
            "--pid",
            "7",
            "--dashboard",
            "--event-log",
            "events.jsonl",
            "--event-rotate-bytes",
            "64K",
            "--event-max-files",
            "3",
        ]))
        .unwrap() else {
            panic!("expected inventory")
        };
        assert!(i.dashboard);
        assert_eq!(i.event_log, Some(PathBuf::from("events.jsonl")));
        assert_eq!(i.event_rotate_bytes, Some(65536));
        assert_eq!(i.event_max_files, Some(3));
        // Defaults are unset (the runner applies them).
        let Command::Inventory(plain) = parse(args(&["inventory", "--pid", "7"])).unwrap() else {
            panic!("expected inventory")
        };
        assert!(!plain.dashboard);
        assert_eq!(plain.event_log, None);
        assert_eq!(plain.event_rotate_bytes, None);
        assert_eq!(plain.event_max_files, None);
    }

    #[test]
    fn inventory_refuses_dangling_event_options_and_bad_sizes() {
        // Rotation/retention without a stream file is refused, never
        // silently ignored.
        for argv in [
            vec!["inventory", "--pid", "7", "--event-rotate-bytes", "1M"],
            vec!["inventory", "--pid", "7", "--event-max-files", "3"],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. })
                    if m.contains("require --event-log")),
                "{argv:?}"
            );
        }
        assert!(matches!(
            parse(args(&[
                "inventory", "--pid", "7",
                "--event-log", "e.jsonl",
                "--event-rotate-bytes", "0",
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--event-rotate-bytes: invalid value")
        ));
        assert!(matches!(
            parse(args(&[
                "inventory", "--pid", "7",
                "--event-log", "e.jsonl",
                "--event-max-files", "0",
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--event-max-files must be greater than zero")
        ));
        assert!(matches!(
            parse(args(&[
                "inventory", "--pid", "7",
                "--event-log", "a",
                "--event-log", "b",
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--event-log given twice")
        ));
    }

    #[test]
    fn inventory_event_stdout_accepts_dash_and_refuses_stdout_rivals() {
        // `--event-log -` streams events to stdout: accepted on its
        // own and beside `-o` (an independent file sink).
        for extra in [
            vec!["inventory", "--pid", "7", "--event-log", "-"],
            vec![
                "inventory",
                "--pid",
                "7",
                "--event-log",
                "-",
                "-o",
                "report.json",
            ],
        ] {
            let Command::Inventory(i) = parse(args(&extra)).unwrap() else {
                panic!("expected inventory for {extra:?}");
            };
            assert_eq!(i.event_log, Some(PathBuf::from("-")), "{extra:?}");
        }
        // `--json` and `--dashboard` also own stdout: refused beside `-`.
        for argv in [
            vec!["inventory", "--pid", "7", "--event-log", "-", "--json"],
            vec!["inventory", "--pid", "7", "--event-log", "-", "--dashboard"],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. })
                    if m.contains("--event-log -")),
                "{argv:?}"
            );
        }
        // Rotation/retention describe files: refused with `-`, which is
        // never rotated.
        for argv in [
            vec![
                "inventory",
                "--pid",
                "7",
                "--event-log",
                "-",
                "--event-rotate-bytes",
                "1M",
            ],
            vec![
                "inventory",
                "--pid",
                "7",
                "--event-log",
                "-",
                "--event-max-files",
                "3",
            ],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. })
                    if m.contains("--event-log -")),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn inventory_event_interval_parses_and_requires_a_stream() {
        // Off by default; a duration value parses beside either sink.
        let Command::Inventory(plain) = parse(args(&["inventory", "--pid", "7"])).unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(plain.event_interval, None);
        for sink in ["events.jsonl", "-"] {
            let Command::Inventory(i) = parse(args(&[
                "inventory",
                "--pid",
                "7",
                "--event-log",
                sink,
                "--event-interval",
                "10s",
            ]))
            .unwrap() else {
                panic!("expected inventory for sink {sink}")
            };
            assert_eq!(i.event_interval, Some(std::time::Duration::from_secs(10)));
        }
        // Without a stream the cadence has nowhere to go: refused, never
        // silently ignored.
        assert!(matches!(
            parse(args(&["inventory", "--pid", "7", "--event-interval", "10s"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("require --event-log")
        ));
        // Zero, repeated and malformed values are refused by name.
        assert!(matches!(
            parse(args(&[
                "inventory", "--pid", "7",
                "--event-log", "e.jsonl",
                "--event-interval", "0",
            ])),
            Err(CliError::Usage { message: m, .. })
                if m.contains("--event-interval must be greater than zero")
        ));
        assert!(matches!(
            parse(args(&[
                "inventory", "--pid", "7",
                "--event-log", "e.jsonl",
                "--event-interval", "10s",
                "--event-interval", "30s",
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--event-interval given twice")
        ));
        assert!(matches!(
            parse(args(&[
                "inventory", "--pid", "7",
                "--event-log", "e.jsonl",
                "--event-interval", "soon",
            ])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--event-interval: invalid value")
        ));
    }

    #[test]
    fn event_bytes_accepts_plain_and_suffixed_sizes() {
        for (input, want) in [
            ("1", 1u64),
            ("4096", 4096),
            ("1000", 1000),
            ("256K", 262144),
            ("256k", 262144),
            ("1M", 1048576),
            ("64M", 67108864),
        ] {
            assert_eq!(parse_event_bytes(input), Ok(want), "input {input}");
        }
        for input in ["0", "0K", "1G", "1.5M", "abc", ""] {
            assert!(parse_event_bytes(input).is_err(), "input {input} must fail");
        }
    }

    #[test]
    fn doctor_rejects_unsupported_module_option() {
        assert!(matches!(
            parse(args(&["doctor", "--module", "/opt/provider.so"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("doctor --module is not supported")
        ));
    }

    /// Item 31: the `doctor --module` refusal names the runnable
    /// `p11scope` command, like every sibling refusal.
    #[test]
    fn doctor_module_refusal_names_runnable_p11scope_command() {
        let Err(CliError::Usage { message, .. }) =
            parse(args(&["doctor", "--module", "/opt/provider.so"]))
        else {
            panic!("doctor --module must be refused");
        };
        assert_eq!(
            message,
            "doctor --module is not supported; use 'p11scope inspect --pid <n> --module \
             <provider.so>' to list mapped providers"
        );
    }

    /// Item 17: profile/trace/run helps say scan-only discovery names
    /// functions from the standard table without confirming them (the
    /// output names them; "counted but not named" contradicts it).
    #[test]
    fn scan_only_help_names_unconfirmed_standard_table_names() {
        let trace = trace_help();
        for help in [PROFILE_HELP, trace.as_str(), RUN_HELP] {
            assert!(
                help.contains(
                    "scan-only discovery names functions from the standard table without \
                     confirming them"
                ),
                "{help:.300}"
            );
            assert!(!help.contains("counted but not named"), "{help:.300}");
        }
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
            Err(CliError::Usage { message: m, .. }) if m.contains("doctor --system is not supported")
        ));
    }

    #[test]
    fn scope_is_still_exactly_one_of_pid_or_cgroup_and_removed_flags_still_hint() {
        assert!(
            matches!(parse(args(&["profile"])), Err(CliError::Usage { message: m, .. }) if m.contains("exactly one"))
        );
        assert!(matches!(
            parse(args(&["profile", "--pid", "1", "--cgroup", "/sys/fs/cgroup/x"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("mutually exclusive")
        ));
        assert!(matches!(
            parse(args(&["profile", "--pid", "1", "--provenance-module", "/opt/x.so"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("removed in productization slice 1a")
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
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. }) if m.contains("mutually exclusive")),
                "{argv:?}"
            );
        }
        assert!(
            matches!(parse(args(&["profile"])), Err(CliError::Usage { message: m, .. }) if m.contains("--system"))
        );
    }

    #[test]
    fn a_malformed_hook_symbol_is_a_usage_error_naming_the_spec() {
        assert!(matches!(
            parse(args(&["profile", "--pid", "1", "--hook-symbol", "X:bogus"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("functionlist")
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

    /// B2: absurd durations are usage errors, never clock overflows. A
    /// bare `u64::MAX` used to parse and then panic `inventory` in
    /// `Instant::now() + window`; a suffixed value whose seconds
    /// overflow `u64` is refused by the checked multiplication.
    #[test]
    fn huge_durations_are_refused_at_the_cli_boundary() {
        for bad in ["18446744073709551615", "99999999999999999h"] {
            let error = parse_duration(bad).expect_err("a huge duration must be refused");
            assert!(
                error.contains("exceeds the maximum") || error.contains("overflows"),
                "{bad}: {error}"
            );
        }
        // The bound itself is exact: the maximum parses, one past it
        // does not, in bare and suffixed spellings alike.
        assert_eq!(
            parse_duration(&MAX_DURATION_SECS.to_string()).unwrap(),
            Duration::from_secs(MAX_DURATION_SECS)
        );
        assert_eq!(
            parse_duration("8784h").unwrap(),
            Duration::from_secs(MAX_DURATION_SECS)
        );
        assert!(parse_duration(&(MAX_DURATION_SECS + 1).to_string()).is_err());
        assert!(parse_duration("8785h").is_err());
        // Huge values stay usage errors (exit 2 surfaces) on every
        // capture, not panics or late runtime failures.
        for argv in [
            vec![
                "profile",
                "--pid",
                "42",
                "--duration",
                "18446744073709551615",
            ],
            vec!["trace", "--pid", "42", "--duration", "99999999999999999h"],
            vec![
                "run",
                "--duration",
                "18446744073709551615",
                "--",
                "/bin/true",
            ],
            vec![
                "inventory",
                "--pid",
                "7",
                "--duration",
                "18446744073709551615",
            ],
            vec!["inventory", "--system", "--duration", "99999999999999999h"],
        ] {
            assert!(
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. }) if m.contains("--duration: invalid value")),
                "{argv:?}"
            );
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
                matches!(parse(args(&argv)), Err(CliError::Usage { message: m, .. }) if m.contains("--duration must be greater than zero")),
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
            matches!(parse_capture(Kind::Profile, args(&["--manifest", "m", "--pid", "1", "--cgroup", "/sys/fs/cgroup/x"])), Err(CliError::Usage { message: m, .. }) if m.contains("mutually exclusive"))
        );
        assert!(
            matches!(parse_capture(Kind::Profile, args(&["--manifest", "m"])), Err(CliError::Usage { message: m, .. }) if m.contains("exactly one of --pid, --cgroup, or --system"))
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
                matches!(err, CliError::Usage { message: m, .. } if m.contains("removed in productization slice 1a")),
                "{flag}"
            );
        }
        assert!(
            matches!(parse_capture(Kind::Profile, args(&["--manifest", "m", "--pid", "1", "--mode", "trace"])), Err(CliError::Usage { message: m, .. }) if m.contains("trace is a subcommand"))
        );
    }

    #[test]
    fn trace_rejects_mode_and_accepts_the_rest() {
        assert!(matches!(
            parse_capture(
                Kind::Trace,
                args(&["--manifest", "m", "--pid", "1", "--mode", "metrics"])
            ),
            Err(CliError::Usage { .. })
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
            Err(CliError::Usage { message: m, .. }) if m.contains("--max-events is a trace option")
        ));
        assert!(matches!(
            parse_capture(Kind::Trace, args(&["--pid", "1", "--max-events", "x"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("invalid number")
        ));
        assert!(matches!(
            parse_capture(Kind::Trace, args(&["--pid", "1", "--max-events", "0"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("must be greater than zero")
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
            Err(CliError::Usage { message: m, .. }) if m.contains("invalid number")
        ));
        assert!(matches!(
            parse(args(&["profile", "--pid", "42", "--max-scan-pids", "0"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("must be greater than zero")
        ));
        for help in [
            PROFILE_HELP.to_string(),
            INSPECT_HELP.to_string(),
            HelpTopic::Inventory.text(),
        ] {
            assert!(
                help.contains("--max-scan-pids"),
                "help names the scan cap flag"
            );
        }
    }

    #[test]
    fn metrics_counter_capabilities_accept_all_three_modes() {
        use std::os::unix::ffi::OsStringExt as _;
        let child = vec![
            OsString::from("/bin/echo"),
            OsString::from("--counter-mode"),
            OsString::from("latency"),
            OsString::from("--mode"),
            OsString::from("profile"),
            OsString::from_vec(b"child-\xff".to_vec()),
        ];
        for (mode, expected) in [
            ("counts", CounterMode::Counts),
            ("timestamps", CounterMode::Timestamps),
            ("latency", CounterMode::Latency),
        ] {
            for options in [
                ["--mode", "metrics", "--counter-mode", mode],
                ["--counter-mode", mode, "--mode", "metrics"],
            ] {
                let mut profile = vec!["profile", "--pid", "42"];
                profile.extend_from_slice(&options);
                let parsed = parse(args(&profile)).unwrap_or_else(|error| {
                    panic!("profile metrics must accept {mode}, {options:?}: {error:?}")
                });
                let Command::Profile(profile) = parsed else {
                    panic!("counter selection must remain a profile capture");
                };
                assert_eq!(profile.kind, Kind::Profile);
                assert_eq!(profile.scope, ScopeArg::Pid(42));
                assert!(profile.metrics && !profile.unsafe_requested);
                assert_eq!(profile.counter_mode, Some(expected));
                assert_eq!(profile.attach_backend, BackendSelection::Auto);

                let mut run = vec![OsString::from("run")];
                run.extend(options.iter().map(|option| OsString::from(*option)));
                run.push(OsString::from("--"));
                run.extend(child.iter().cloned());
                let parsed = parse(run).unwrap_or_else(|error| {
                    panic!("run metrics must accept {mode}, {options:?}: {error:?}")
                });
                let Command::Run(run) = parsed else {
                    panic!("counter selection must retain the owned run surface");
                };
                assert_eq!(run.kind, Kind::Profile);
                assert!(run.metrics && !run.unsafe_requested);
                assert_eq!(run.counter_mode, Some(expected));
                assert_eq!(run.pause, PausePolicy::Auto);
                assert_eq!(run.attach_backend, BackendSelection::Auto);
                assert_eq!(run.command, child, "child flags and bytes belong after --");
            }
        }
    }

    #[test]
    fn metrics_counter_capabilities_refuse_nonmetrics_and_repeats() {
        // Omission keeps the legacy path, rather than selecting the default
        // CounterMode variant as a new measurement request.
        for (argv, metrics) in [
            (vec!["profile", "--pid", "42"], false),
            (vec!["profile", "--pid", "42", "--mode", "metrics"], true),
        ] {
            let Command::Profile(profile) = parse(args(&argv)).unwrap() else {
                panic!("expected legacy profile surface");
            };
            assert_eq!(profile.kind, Kind::Profile);
            assert_eq!(profile.metrics, metrics);
            assert_eq!(profile.counter_mode, None);
            assert!(!profile.unsafe_requested);
            assert_eq!(profile.scope, ScopeArg::Pid(42));
        }
        for (argv, metrics) in [
            (
                vec!["run", "--", "/bin/echo", "--counter-mode", "counts"],
                false,
            ),
            (
                vec![
                    "run",
                    "--mode",
                    "metrics",
                    "--",
                    "/bin/echo",
                    "--counter-mode",
                    "counts",
                ],
                true,
            ),
        ] {
            let Command::Run(run) = parse(args(&argv)).unwrap() else {
                panic!("expected legacy owned run surface");
            };
            assert_eq!(run.kind, Kind::Profile);
            assert_eq!(run.metrics, metrics);
            assert_eq!(run.counter_mode, None);
            assert!(!run.unsafe_requested);
            assert_eq!(run.pause, PausePolicy::Auto);
            assert_eq!(run.command, ["/bin/echo", "--counter-mode", "counts"]);
        }

        let refuses = |argv: &[&str], reasons: &[&str]| {
            let error = parse(args(argv)).expect_err("counter option combination must refuse");
            let CliError::Usage { message, .. } = error else {
                panic!("{argv:?}: expected usage refusal, got {error:?}");
            };
            for reason in reasons {
                assert!(
                    message.contains(reason),
                    "{argv:?}: refusal must explain {reason:?}, got {message:?}"
                );
            }
        };
        for mode in ["counts", "timestamps", "latency"] {
            refuses(
                &["inventory", "--pid", "42", "--counter-mode", mode],
                &["--counter-mode"],
            );
            for argv in [
                vec!["profile", "--pid", "42", "--counter-mode", mode],
                vec![
                    "profile",
                    "--pid",
                    "42",
                    "--mode",
                    "profile",
                    "--counter-mode",
                    mode,
                ],
                vec![
                    "profile",
                    "--counter-mode",
                    mode,
                    "--mode",
                    "profile",
                    "--pid",
                    "42",
                ],
                vec!["trace", "--pid", "42", "--counter-mode", mode],
                vec!["run", "--counter-mode", mode, "--", "/bin/true"],
                vec!["run", "--trace", "--counter-mode", mode, "--", "/bin/true"],
                vec!["run", "--counter-mode", mode, "--trace", "--", "/bin/true"],
            ] {
                refuses(&argv, &["--counter-mode", "metrics"]);
            }
            for argv in [
                vec![
                    "profile",
                    "--pid",
                    "42",
                    "--mode",
                    "metrics",
                    "--unsafe-unvalidated-metadata",
                    "--counter-mode",
                    mode,
                ],
                vec![
                    "profile",
                    "--pid",
                    "42",
                    "--counter-mode",
                    mode,
                    "--mode",
                    "metrics",
                    "--unsafe-unvalidated-metadata",
                ],
                vec![
                    "run",
                    "--mode",
                    "metrics",
                    "--unsafe-unvalidated-metadata",
                    "--counter-mode",
                    mode,
                    "--",
                    "/bin/true",
                ],
                vec![
                    "run",
                    "--counter-mode",
                    mode,
                    "--mode",
                    "metrics",
                    "--unsafe-unvalidated-metadata",
                    "--",
                    "/bin/true",
                ],
            ] {
                refuses(&argv, &["--counter-mode", "unsafe"]);
            }
            refuses(
                &[
                    "profile",
                    "--pid",
                    "42",
                    "--mode",
                    "metrics",
                    "--counter-mode",
                    mode,
                    "--counter-mode",
                    mode,
                ],
                &["--counter-mode", "twice"],
            );
            refuses(
                &[
                    "run",
                    "--mode",
                    "metrics",
                    "--counter-mode",
                    mode,
                    "--counter-mode",
                    "latency",
                    "--",
                    "/bin/true",
                ],
                &["--counter-mode", "twice"],
            );
        }
        for mode in ["", "count", "COUNTS", "unknown"] {
            refuses(
                &[
                    "profile",
                    "--pid",
                    "42",
                    "--mode",
                    "metrics",
                    "--counter-mode",
                    mode,
                ],
                &["--counter-mode", "invalid"],
            );
            refuses(
                &[
                    "run",
                    "--mode",
                    "metrics",
                    "--counter-mode",
                    mode,
                    "--",
                    "/bin/true",
                ],
                &["--counter-mode", "invalid"],
            );
        }
        for argv in [
            vec![
                "profile",
                "--pid",
                "42",
                "--mode",
                "metrics",
                "--counter-mode",
            ],
            vec!["run", "--mode", "metrics", "--counter-mode"],
        ] {
            refuses(&argv, &["--counter-mode", "value"]);
        }
    }

    #[test]
    fn select_endpoint_accepts_one_function_on_profile_and_run_metrics() {
        // 6.15 CLI selection: one endpoint function name rides a
        // metrics+counter capture; omission keeps legacy behavior.
        for options in [
            vec![
                "profile",
                "--pid",
                "42",
                "--mode",
                "metrics",
                "--counter-mode",
                "counts",
                "--select-endpoint",
                "C_Sign",
            ],
            vec![
                "profile",
                "--select-endpoint",
                "C_Sign",
                "--counter-mode",
                "latency",
                "--mode",
                "metrics",
                "--pid",
                "42",
            ],
        ] {
            let Command::Profile(profile) = parse(args(&options)).unwrap_or_else(|error| {
                panic!("profile metrics must accept --select-endpoint, {options:?}: {error:?}")
            }) else {
                panic!("endpoint selection must remain a profile capture");
            };
            assert_eq!(profile.kind, Kind::Profile);
            assert!(profile.metrics);
            assert!(profile.counter_mode.is_some());
            assert_eq!(profile.select_endpoint.as_deref(), Some("C_Sign"));
        }
        // The child owns everything after `--`: its flags and bytes are
        // never consumed as an endpoint selection.
        let child = ["--select-endpoint", "C_Verify"];
        let argv: Vec<String> = ["run", "--mode", "metrics", "--counter-mode", "timestamps"]
            .into_iter()
            .map(str::to_string)
            .chain(["--".to_string(), "/bin/echo".to_string()])
            .chain(child.iter().map(|word| word.to_string()))
            .collect();
        let Command::Run(run) = parse(argv).unwrap_or_else(|error| {
            panic!("run metrics must accept a child carrying the flag bytes: {error:?}")
        }) else {
            panic!("endpoint selection must retain the owned run surface");
        };
        assert_eq!(run.select_endpoint, None);
        assert_eq!(
            run.command,
            [
                OsString::from("/bin/echo"),
                OsString::from("--select-endpoint"),
                OsString::from("C_Verify")
            ]
        );

        let argv = vec![
            "run",
            "--mode",
            "metrics",
            "--counter-mode",
            "latency",
            "--select-endpoint",
            "C_Encrypt",
            "--",
            "/bin/true",
        ];
        let Command::Run(run) = parse(args(&argv)).unwrap_or_else(|error| {
            panic!("run metrics must accept --select-endpoint, {argv:?}: {error:?}")
        }) else {
            panic!("endpoint selection must retain the owned run surface");
        };
        assert_eq!(run.kind, Kind::Profile);
        assert!(run.metrics);
        assert_eq!(run.select_endpoint.as_deref(), Some("C_Encrypt"));
        // Omission keeps the legacy path: no selection rides along.
        let Command::Profile(legacy) = parse(args(&[
            "profile",
            "--pid",
            "42",
            "--mode",
            "metrics",
            "--counter-mode",
            "counts",
        ]))
        .unwrap() else {
            panic!("expected legacy profile surface");
        };
        assert_eq!(legacy.select_endpoint, None);
    }

    #[test]
    fn select_endpoint_refuses_nonmetrics_repeats_and_bad_values() {
        let refuses = |argv: &[&str], reasons: &[&str]| {
            let error = parse(args(argv)).expect_err("endpoint selection must refuse");
            let CliError::Usage { message, .. } = error else {
                panic!("{argv:?}: expected usage refusal, got {error:?}");
            };
            for reason in reasons {
                assert!(
                    message.contains(reason),
                    "{argv:?}: refusal must explain {reason:?}, got {message:?}"
                );
            }
        };
        // Without metrics+counter selection the flag has no broad to detail.
        for argv in [
            vec!["profile", "--pid", "42", "--select-endpoint", "C_Sign"],
            vec![
                "profile",
                "--pid",
                "42",
                "--mode",
                "profile",
                "--select-endpoint",
                "C_Sign",
            ],
            vec![
                "profile",
                "--pid",
                "42",
                "--mode",
                "metrics",
                "--select-endpoint",
                "C_Sign",
            ],
            vec!["trace", "--pid", "42", "--select-endpoint", "C_Sign"],
            vec![
                "run",
                "--trace",
                "--select-endpoint",
                "C_Sign",
                "--",
                "/bin/true",
            ],
            vec!["run", "--select-endpoint", "C_Sign", "--", "/bin/true"],
        ] {
            refuses(&argv, &["--select-endpoint", "--counter-mode", "metrics"]);
        }
        // A counter-mode trace still refuses: selection details a metrics broad.
        refuses(
            &[
                "run",
                "--trace",
                "--mode",
                "metrics",
                "--counter-mode",
                "counts",
                "--select-endpoint",
                "C_Sign",
                "--",
                "/bin/true",
            ],
            &["--counter-mode", "metrics"],
        );
        // Scalar like the rest: repeats, empties and missing values refuse.
        refuses(
            &[
                "profile",
                "--pid",
                "42",
                "--mode",
                "metrics",
                "--counter-mode",
                "counts",
                "--select-endpoint",
                "C_Sign",
                "--select-endpoint",
                "C_Verify",
            ],
            &["--select-endpoint", "twice"],
        );
        refuses(
            &[
                "run",
                "--mode",
                "metrics",
                "--counter-mode",
                "counts",
                "--select-endpoint",
                "C_Sign",
                "--select-endpoint",
                "C_Sign",
                "--",
                "/bin/true",
            ],
            &["--select-endpoint", "twice"],
        );
        refuses(
            &[
                "profile",
                "--pid",
                "42",
                "--mode",
                "metrics",
                "--counter-mode",
                "counts",
                "--select-endpoint",
                "",
            ],
            &["--select-endpoint", "invalid"],
        );
        refuses(
            &[
                "profile",
                "--pid",
                "42",
                "--mode",
                "metrics",
                "--counter-mode",
                "counts",
                "--select-endpoint",
            ],
            &["--select-endpoint", "value"],
        );
        // Inventory owns no counter broad: the flag is not its option.
        refuses(
            &["inventory", "--pid", "42", "--select-endpoint", "C_Sign"],
            &["--select-endpoint"],
        );
    }

    #[test]
    fn select_endpoint_is_documented_on_profile_and_run_help() {
        for (topic, help) in [("profile", PROFILE_HELP), ("run", RUN_HELP)] {
            assert!(
                help.contains("--select-endpoint"),
                "{topic} help must document the endpoint-selection flag"
            );
        }
        assert!(
            !trace_help().contains("--select-endpoint"),
            "trace streams raw events and must not offer endpoint selection"
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
            Err(CliError::Usage { message: m, .. }) if m.contains("--attach-backend: invalid value")
        ));
        for help in [
            PROFILE_HELP.to_string(),
            trace_help(),
            RUN_HELP.to_string(),
            HelpTopic::Inventory.text(),
        ] {
            assert!(
                help.contains("--attach-backend"),
                "help names the backend flag"
            );
        }
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

    #[test]
    fn run_verbose_parses_short_and_long_and_defaults_off() {
        let Command::Run(a) = parse(args(&["run", "--", "/bin/true"])).unwrap() else {
            panic!("expected run")
        };
        assert!(!a.verbose);
        for flag in ["-v", "--verbose"] {
            let Command::Run(a) = parse(args(&["run", flag, "--", "/bin/true"])).unwrap() else {
                panic!("expected run")
            };
            assert!(a.verbose, "{flag} must opt in");
            assert_eq!(a.command, ["/bin/true"]);
        }
        // A `-v` after `--` is the child's own argument, never the flag.
        let Command::Run(a) = parse(args(&["run", "--", "/bin/true", "-v"])).unwrap() else {
            panic!("expected run")
        };
        assert!(!a.verbose);
        assert_eq!(a.command, ["/bin/true", "-v"]);
        // Shortened help since CLI-1: usage lines carry `[-v]`, the prose
        // names both spellings; topics keep the same shapes.
        for (topic, help) in [("global", USAGE), ("run", RUN_HELP)] {
            assert!(
                help.contains("[-v]"),
                "{topic} help must advertise the verbose flag"
            );
            assert!(
                help.contains("-v, --verbose"),
                "{topic} help must name both verbose spellings"
            );
        }
    }

    #[test]
    fn run_user_parses_name_and_uid_and_defaults_off() {
        let Command::Run(a) = parse(args(&["run", "--", "/bin/true"])).unwrap() else {
            panic!("expected run")
        };
        assert_eq!(a.user, None);
        for value in ["alice", "1000", "0", "root"] {
            let Command::Run(a) =
                parse(args(&["run", "--user", value, "--", "/bin/true"])).unwrap()
            else {
                panic!("expected run")
            };
            assert_eq!(
                a.user.as_deref(),
                Some(std::ffi::OsStr::new(value)),
                "{value}"
            );
            assert_eq!(a.command, ["/bin/true"]);
        }
        // A `--user` after `--` is the child's own argument, never the flag.
        let Command::Run(a) = parse(args(&["run", "--", "/bin/true", "--user", "alice"])).unwrap()
        else {
            panic!("expected run")
        };
        assert_eq!(a.user, None);
        assert_eq!(a.command, ["/bin/true", "--user", "alice"]);
        // Shortened help since CLI-1: global usage names the flag, the
        // document sentence and example live in the run topic.
        for (topic, help) in [("global", USAGE), ("run", RUN_HELP)] {
            assert!(
                help.contains("[--user <name|uid>]"),
                "{topic} help must advertise the user flag"
            );
        }
        assert!(
            RUN_HELP.contains("--user <name|uid> (root only, like strace -u)"),
            "run help must document the user flag"
        );
        assert!(
            RUN_HELP.contains(
                "sudo p11scope run --pause auto --user alice -- pkcs11-tool --module ... -L"
            ),
            "run help must carry the --user example"
        );
    }

    #[test]
    fn run_user_refusals_name_the_flag() {
        let Err(CliError::Usage { message, .. }) = parse(args(&[
            "run",
            "--user",
            "alice",
            "--user",
            "bob",
            "--",
            "/bin/true",
        ])) else {
            panic!("--user given twice must be refused");
        };
        assert_eq!(message, "--user given twice");
        let Err(CliError::Usage { message, .. }) = parse(args(&["run", "--user"])) else {
            panic!("--user without a value must be refused");
        };
        assert_eq!(message, "--user requires a value");
        let Err(CliError::Usage { message, .. }) =
            parse(args(&["run", "--user", "", "--", "/bin/true"]))
        else {
            panic!("--user with an empty value must be refused");
        };
        assert_eq!(message, "--user requires a non-empty value");
        // `--user` is a `run` option everywhere else, like `--pause`.
        let Err(CliError::Usage { message, .. }) =
            parse(args(&["profile", "--pid", "42", "--user", "alice"]))
        else {
            panic!("--user outside run must be refused");
        };
        assert!(
            message.contains("--user is a `p11scope run` option"),
            "{message:?}"
        );
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
                matches!(parse(argv.clone()), Err(CliError::Usage { .. })),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn run_trace_selects_the_trace_kind_and_omitted_pause_is_auto() {
        let Command::Run(a) = parse(args(&["run", "--trace", "--", "/bin/true"])).unwrap() else {
            panic!("expected run")
        };
        assert_eq!(a.kind, Kind::Trace);
        assert_eq!(a.pause, PausePolicy::Auto);
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
                matches!(parse(args(&both)), Err(CliError::Usage { message: m, .. }) if m.contains("has no --mode")),
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
                matches!(parse(args(&scoped)), Err(CliError::Usage { message: m, .. }) if m.contains("run has no --pid, --cgroup, or --system")),
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
                matches!(parse(args(&empty)), Err(CliError::Usage { message: m, .. }) if m.contains("-- CMD [ARGS...]")),
                "{empty:?}"
            );
        }
        assert!(matches!(
            parse(args(&["run", "--pause", "sometimes", "--", "/bin/true"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("never|auto|always")
        ));
        assert!(matches!(
            parse(args(&["run", "--pause"])),
            Err(CliError::Usage { message: m, .. }) if m.contains("--pause requires a value")
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
                matches!(parse(args(&elsewhere)), Err(CliError::Usage { message: m, .. }) if m.contains("`p11scope run`")),
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
            (vec!["inventory", "--help"], HelpTopic::Inventory),
            (
                vec!["inventory", "diff", "--help"],
                HelpTopic::InventoryDiff,
            ),
            (
                vec!["inventory", "cbom", "--help"],
                HelpTopic::InventoryCbom,
            ),
            (vec!["--help"], HelpTopic::Global),
            (vec!["-h"], HelpTopic::Global),
        ] {
            assert_eq!(
                parse(args(&argv)).unwrap_err(),
                CliError::Help(topic),
                "{argv:?}"
            );
        }
        // Scoped guidance carries its own example. Capture helps name the
        // offline helper for providers that build their table at run time;
        // doctor (no capture) names no helper workflow.
        for topic in [
            HelpTopic::Profile,
            HelpTopic::Trace,
            HelpTopic::Run,
            HelpTopic::Inspect,
        ] {
            let text = topic.text();
            assert!(text.contains("example"), "{topic:?}");
            assert!(
                text.contains(
                    "Providers that build the table at run time need a manifest: run \
                     p11scope-discover --module <provider.so> -o <manifest.json> and pass \
                     --manifest <manifest.json>."
                ),
                "{topic:?}"
            );
        }
        let doctor = HelpTopic::Doctor.text();
        assert!(doctor.contains("example"), "Doctor");
        assert!(!doctor.contains("p11scope-discover"), "Doctor");
    }

    #[test]
    fn every_flag_is_documented_in_some_help() {
        // Global help shows short usage lines; scoped help carries the
        // full synopsis and notes. Every usable flag must appear in at
        // least one help text, so shortening one help cannot orphan it.
        let all = [
            HelpTopic::Global,
            HelpTopic::Profile,
            HelpTopic::Trace,
            HelpTopic::Run,
            HelpTopic::Inspect,
            HelpTopic::Doctor,
            HelpTopic::Inventory,
            HelpTopic::InventoryDiff,
            HelpTopic::InventoryCbom,
        ]
        .iter()
        .map(|topic| topic.text())
        .collect::<Vec<_>>()
        .join("\n");
        for flag in [
            "--help",
            "-h",
            "--version",
            "-V",
            "--pid",
            "--cgroup",
            "--system",
            "--module",
            "--exclude-module",
            "--manifest",
            "--prearm-module",
            "--hook-symbol",
            "--mode",
            "--counter-mode",
            "--select-endpoint",
            "--duration",
            "--max-events",
            "--max-scan-pids",
            "--max-gaps",
            "--max-endpoints",
            "--ring-bytes",
            "--drain-interval-ms",
            "--attach-backend",
            "--identity-backend",
            "--capture",
            "--caller-metadata",
            "--key-operations",
            "--dashboard",
            "--event-log",
            "--event-rotate-bytes",
            "--event-max-files",
            "--diagnostics",
            "--diagnostics-pid",
            "--trace",
            "--pause",
            "--kill-on-timeout",
            "--unsafe-unvalidated-metadata",
            "--allow-uretprobe-on-confined-target",
            "--track-short-lived",
            "--extra-strict",
            "-v",
            "--verbose",
            "--quiet",
            "--json",
            "-o",
        ] {
            assert!(all.contains(flag), "no help documents {flag}");
        }
        // Removed flags stay refused by name, never documented as usable.
        for dead in ["--provenance-module", "--trusted-workload"] {
            assert!(!all.contains(dead), "help documents removed {dead}");
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
        // Short global help (description, task list, short usage lines,
        // three examples): notes moved into scoped help, every flag kept
        // somewhere (see every_flag_is_documented_in_some_help). The
        // late-process scope bound moved with the notes into
        // inventory help (see inventory_help_bounds_late_process_scanning).
        // 2740 / 0xba5954dfb55f7904 (run `--user`): diff vs the
        // 2720/0x80058f0fef22a940 pin is exactly ` [--user <name|uid>]`
        // on the run synopsis line (+20); no other drift.
        // 2900 / 0x503e1b5b770a1434 (inventory cbom): diff vs the
        // 2740/0xba5954dfb55f7904 pin is exactly the `inventory cbom`
        // task line (+64), its usage line (+81) and `, inventory cbom`
        // on the live-gate line (+15); no other drift.
        // 2913 / 0x10e2dd34bc1280dd (paused run example): diff vs the
        // 2900/0x503e1b5b770a1434 pin is exactly ` --pause auto` on the
        // run example line (+13); no other drift.
        // 3051 / 0x7e7075c0c7f701ba (qualified JSON routes): diff vs the
        // 2913/0x10e2dd34bc1280dd pin is exactly the completeness line
        // split into the short text line plus the `Complete JSON:` route
        // line naming --json/-o/-o -/--event-log per command (+138); no
        // other drift.
        assert_eq!(USAGE.len(), 3051);
        assert_eq!(hash, 0x7e7075c0c7f701ba);
        assert_eq!(HelpTopic::Global.text(), USAGE.to_string());
    }

    /// F4: help uses plain words (HELP-3/KEY-6), not internal names.
    /// No parser change; JSON keeps the machine tokens.
    #[test]
    fn help_uses_plain_words_without_internal_names() {
        let inventory = HelpTopic::Inventory.text();
        let trace = trace_help();
        let diff = inventory_diff_help();
        let cbom = inventory_cbom_help();
        let helps = [
            ("USAGE", USAGE),
            ("PROFILE_HELP", PROFILE_HELP),
            ("TRACE_HELP", trace.as_str()),
            ("RUN_HELP", RUN_HELP),
            ("INSPECT_HELP", INSPECT_HELP),
            ("DOCTOR_HELP", DOCTOR_HELP),
            ("INVENTORY_HELP", inventory.as_str()),
            ("INVENTORY_DIFF_HELP", diff.as_str()),
            ("INVENTORY_CBOM_HELP", cbom.as_str()),
        ];
        for (name, help) in helps {
            for jargon in [
                "corroborated against the scan",
                "semantics-unverified",
                "STATIC HINT",
                "pid_descendant_gaps",
                "helper 181",
                "broad slot",
                "broad-counter",
                "selected_detail",
                "linked journal session",
                "journal object",
                "Subset preparation",
                "positive instance delivery",
                "pre-arms its proved offsets",
                "attaches proved offsets",
                "extensive mode",
            ] {
                assert!(
                    !help.contains(jargon),
                    "{name} still contains jargon {jargon:?}"
                );
            }
        }
        // The plain replacements land where the jargon was. Notes live in
        // scoped help; global help stays short.
        let trace = trace_help();
        for help in [PROFILE_HELP, trace.as_str(), RUN_HELP] {
            assert!(
                help.contains("checked against the scan when possible"),
                "{help:.200}"
            );
            assert!(
                help.contains(
                    "scan-only discovery names functions from the standard table without \
                     confirming them"
                ),
                "{help:.200}"
            );
            assert!(
                help.contains("watches the file from before it loads"),
                "{help:.200}"
            );
        }
        assert!(
            PROFILE_HELP.contains("also records exec-time detail"),
            "profile documents the flag in scope-neutral words"
        );
        for help in [PROFILE_HELP, RUN_HELP] {
            assert!(help.contains("exactly one watched function"), "{help:.200}");
            assert!(help.contains("counter values"), "{help:.200}");
            assert!(help.contains("bpf_loop helper"), "{help:.200}");
            assert!(!help.contains("helper 181"), "{help:.200}");
            assert!(help.contains("recorded in the report;"), "{help:.200}");
            assert!(!help.contains("counter-mode-unwired"), "{help:.200}");
        }
        assert!(USAGE.contains("Environment (advanced; normally unset)"));
        assert!(!USAGE.contains("helper 181"));
        assert!(
            inventory.contains("also tracks which key each operation used"),
            "{inventory:.500}"
        );
        assert!(
            inventory.contains("Per-key results appear under object_observations"),
            "{inventory:.500}"
        );
    }

    #[test]
    fn help_states_manifest_attestation_and_scan_only_limits() {
        let trace = trace_help();
        for help in [PROFILE_HELP, trace.as_str(), RUN_HELP] {
            for statement in [
                "--manifest is explicit operator attestation of exact accepted function-name/offset claims",
                "scan-only discovery names functions from the standard table without confirming them",
                "aggregate counts/RVs/latency remain available",
            ] {
                assert!(
                    help.contains(statement),
                    "missing help statement: {statement}"
                );
            }
        }
    }

    #[test]
    fn help_names_counter_mode_availability() {
        for help in [PROFILE_HELP, RUN_HELP] {
            for statement in [
                "--counter-mode counts|timestamps|latency selects the metrics measurement for profile or run with --mode metrics.",
                "counts reports calls and errors without timing; timestamps adds total and max call time; latency adds a latency histogram.",
                "Omit --counter-mode to keep existing metrics behavior.",
                "can refuse with a named reason, including on kernels without bpf_loop helper support",
                "where the kernel verifier rejects the counter programs",
            ] {
                assert!(
                    help.contains(statement),
                    "missing help statement: {statement}"
                );
            }
            assert!(
                !help.contains("counter-mode-unwired"),
                "help still states the removed refusal"
            );
            // The refusal list is non-exhaustive: the old exhaustive sentence
            // also overclaimed by omitting the verifier refusal.
            assert!(
                !help.contains(
                    "Selections refuse with a named reason on kernels without bpf_loop (helper 181), on builds without counter objects, and past the mode's endpoint ceiling."
                ),
                "help still states the exhaustive refusal list"
            );
        }
        assert!(
            PROFILE_HELP.contains("[--counter-mode counts|timestamps|latency]"),
            "profile --help never names --counter-mode"
        );
        assert!(
            RUN_HELP.contains("[--counter-mode counts|timestamps|latency]"),
            "run --help never names --counter-mode"
        );
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
        let trace = trace_help();
        for help in [PROFILE_HELP, trace.as_str(), RUN_HELP] {
            for statement in [
                "--ring-bytes",
                "--drain-interval-ms",
                "(default 32M",
                "; 4K..64M, a power of two",
            ] {
                assert!(help.contains(statement), "missing help text: {statement}");
            }
        }
        // Metrics (and counter) captures keep the 4M ring; trace has no
        // metrics mode.
        let metrics = "4M with --mode metrics, which writes no per-call records";
        assert!(PROFILE_HELP.contains(metrics) && RUN_HELP.contains(metrics));
        assert!(!trace.contains(metrics));
    }

    // v070-event-stdout pin: `docs/usage.md` documents the `--event-log -`
    // stdout stream and `--event-interval` totals next to the file
    // stream, with the container example.
    #[test]
    fn usage_doc_documents_event_stdout_and_interval() {
        const USAGE_MD: &str = include_str!("../docs/usage.md");
        for statement in [
            "--event-log -",
            "--event-interval",
            "docker run",
            "the text summary moves to stderr",
        ] {
            assert!(
                USAGE_MD.contains(statement),
                "missing usage text: {statement}"
            );
        }
    }

    // SYSPLAN residual F-17 (RED): the hidden 10M default trace cap is
    // surfaced in help, rendered from the live constant.
    #[test]
    fn help_surfaces_default_trace_event_cap() {
        let help = trace_help();
        let live = grouped_count(crate::run::DEFAULT_TRACE_MAX_EVENTS);
        assert!(
            help.contains(&live),
            "help never names the default trace event cap {live}"
        );
        assert_eq!(live, "10,000,000", "the default cap moved; update the pin");
        assert!(
            help.contains("TRUNCATED"),
            "help never explains the TRUNCATED line"
        );
    }

    #[test]
    fn help_counts_group_with_thousands_separators() {
        for (value, expected) in [
            (0, "0"),
            (7, "7"),
            (64, "64"),
            (999, "999"),
            (1000, "1,000"),
            (16384, "16,384"),
            (250000, "250,000"),
            (2000000, "2,000,000"),
            (10000000, "10,000,000"),
        ] {
            assert_eq!(grouped_count(value), expected, "value={value}");
        }
        assert_eq!(mib_or_bytes(67_108_864), "64 MiB");
        assert_eq!(mib_or_bytes(1024), "1024 bytes");
    }

    #[test]
    fn diff_help_publishes_the_live_input_bounds() {
        use crate::inventory_diff::input::{
            DEFAULT_INPUT_BYTES, DEFAULT_INPUT_DEPTH, DEFAULT_INPUT_NODES, DEFAULT_INPUT_ROWS,
            DEFAULT_INPUT_STRING_BYTES,
        };
        let help = inventory_diff_help();
        for expected in [
            mib_or_bytes(DEFAULT_INPUT_BYTES as u64),
            grouped_count(DEFAULT_INPUT_ROWS as u64),
            grouped_count(DEFAULT_INPUT_STRING_BYTES as u64),
            grouped_count(DEFAULT_INPUT_DEPTH as u64),
            grouped_count(DEFAULT_INPUT_NODES as u64),
        ] {
            assert!(help.contains(&expected), "missing {expected:?}: {help}");
        }
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

    #[test]
    fn exclude_module_parses_repeatable_on_profile_run_inspect_and_inventory() {
        let Command::Profile(a) = parse(args(&[
            "profile",
            "--pid",
            "42",
            "--exclude-module",
            "/opt/a.so",
            "--exclude-module",
            "libp11-kit.so.0",
        ]))
        .unwrap() else {
            panic!("expected profile")
        };
        assert_eq!(
            a.exclude_modules,
            vec![PathBuf::from("/opt/a.so"), PathBuf::from("libp11-kit.so.0")]
        );
        let Command::Run(r) = parse(args(&[
            "run",
            "--exclude-module",
            "libp11-kit.so.0",
            "--",
            "/bin/true",
        ]))
        .unwrap() else {
            panic!("expected run")
        };
        assert_eq!(r.exclude_modules, vec![PathBuf::from("libp11-kit.so.0")]);
        let Command::Inspect(i) = parse(args(&[
            "inspect",
            "--pid",
            "42",
            "--exclude-module",
            "/opt/a.so",
        ]))
        .unwrap() else {
            panic!("expected inspect")
        };
        assert_eq!(i.exclude_modules, vec![PathBuf::from("/opt/a.so")]);
        let Command::Inventory(v) = parse(args(&[
            "inventory",
            "--system",
            "--exclude-module",
            "libp11-kit.so.0",
        ]))
        .unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(v.exclude_modules, vec![PathBuf::from("libp11-kit.so.0")]);
    }

    #[test]
    fn forwarding_module_parses_repeatable_on_profile_run_trace_and_inventory() {
        let Command::Profile(a) = parse(args(&[
            "profile",
            "--pid",
            "42",
            "--forwarding-module",
            "/opt/shim.so",
            "--forwarding-module",
            "pkcs11-spy.so",
        ]))
        .unwrap() else {
            panic!("expected profile")
        };
        assert_eq!(
            a.forwarding_modules,
            vec![
                PathBuf::from("/opt/shim.so"),
                PathBuf::from("pkcs11-spy.so")
            ]
        );
        let Command::Run(r) = parse(args(&[
            "run",
            "--forwarding-module",
            "pkcs11-spy.so",
            "--",
            "/bin/true",
        ]))
        .unwrap() else {
            panic!("expected run")
        };
        assert_eq!(r.forwarding_modules, vec![PathBuf::from("pkcs11-spy.so")]);
        let Command::Trace(t) = parse(args(&[
            "trace",
            "--pid",
            "42",
            "--forwarding-module",
            "s.so",
        ]))
        .unwrap() else {
            panic!("expected trace")
        };
        assert_eq!(t.forwarding_modules, vec![PathBuf::from("s.so")]);
        let Command::Inventory(v) = parse(args(&[
            "inventory",
            "--system",
            "--forwarding-module",
            "pkcs11-spy.so",
        ]))
        .unwrap() else {
            panic!("expected inventory")
        };
        assert_eq!(v.forwarding_modules, vec![PathBuf::from("pkcs11-spy.so")]);
    }

    /// The declaration only affects counting, and `inspect` never counts:
    /// the flag is refused there, keeping the scan surface unchanged.
    #[test]
    fn forwarding_module_is_refused_on_inspect() {
        let result = parse(args(&[
            "inspect",
            "--pid",
            "42",
            "--forwarding-module",
            "s.so",
        ]));
        assert!(
            result.is_err(),
            "inspect takes no --forwarding-module: {result:?}"
        );
    }

    #[test]
    fn forwarding_module_conflicts_with_exclude() {
        let error = validate_forwarding(
            &[PathBuf::from("/opt/shim.so")],
            &[PathBuf::from("/opt/shim.so")],
        )
        .expect_err("same input must conflict");
        assert!(
            error.contains("--forwarding-module") && error.contains("--exclude-module"),
            "the conflict names both flags: {error}"
        );
        let error = validate_forwarding(
            &[PathBuf::from("/opt/shim.so")],
            &[PathBuf::from("shim.so")],
        )
        .expect_err("bare-name basename match must conflict");
        assert!(
            error.contains("--forwarding-module") && error.contains("--exclude-module"),
            "the conflict names both flags: {error}"
        );
    }

    #[test]
    fn forwarding_module_path_must_exist() {
        let error = validate_forwarding(
            &[PathBuf::from("/opt/definitely-missing-shim-7f3a.so")],
            &[],
        )
        .expect_err("a missing path must fail");
        assert!(
            error.contains("--forwarding-module") && error.contains("does not exist"),
            "a missing path names the flag: {error}"
        );
        assert!(
            validate_forwarding(&[PathBuf::from("bare-name.so")], &[]).is_ok(),
            "bare names need no existence"
        );
    }

    #[test]
    fn forwarding_module_help_names_flag() {
        for topic in [
            HelpTopic::Profile,
            HelpTopic::Run,
            HelpTopic::Trace,
            HelpTopic::Inventory,
        ] {
            assert!(
                topic.text().contains("--forwarding-module"),
                "{topic:?} help names the flag"
            );
        }
    }

    /// Controller ruling (remedies): every remedy a refusal can name is a
    /// real flag where it is shown. Trace shares the capture surface for
    /// `--module` and `--exclude-module`, but has no `--mode metrics`, so
    /// the `--counter-mode` remedy never shows there.
    #[test]
    fn refusal_remedies_are_valid_flags_on_trace() {
        let Command::Trace(t) = parse(args(&[
            "trace",
            "--pid",
            "42",
            "--module",
            "a.so",
            "--exclude-module",
            "b.so",
        ]))
        .unwrap() else {
            panic!("expected trace")
        };
        assert_eq!(t.modules, vec![PathBuf::from("a.so")]);
        assert_eq!(t.exclude_modules, vec![PathBuf::from("b.so")]);
        assert!(!t.metrics);
        assert_eq!(t.counter_mode, None);
        assert!(parse(args(&["trace", "--pid", "42", "--mode", "metrics"])).is_err());
    }

    #[test]
    fn validate_excludes_refuses_missing_paths_and_module_conflicts() {
        let slice_of = std::slice::from_ref;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("libreal.so.1.2");
        std::fs::write(&real, b"fake").unwrap();
        let link = dir.path().join("liblink.so");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // Missing path is a usage error.
        let missing = dir.path().join("nope.so");
        assert!(validate_excludes(&[], &[missing]).is_err());
        // Bare names need no existence.
        assert!(validate_excludes(&[], &[PathBuf::from("libp11-kit.so.0")]).is_ok());
        // Exact conflict.
        assert!(validate_excludes(slice_of(&real), slice_of(&real)).is_err());
        // Same file via symlink.
        assert!(validate_excludes(slice_of(&real), slice_of(&link)).is_err());
        // Bare-name basename conflict.
        assert!(validate_excludes(slice_of(&real), &[PathBuf::from("libreal.so.1.2")]).is_err());
        // No conflict.
        assert!(validate_excludes(slice_of(&real), &[PathBuf::from("other.so")]).is_ok());
        assert!(validate_excludes(&[], slice_of(&real)).is_ok());
    }

    /// A `--prearm-module` matching an `--exclude-module` is refused at
    /// startup with the same named-error shape as the `--module` conflict.
    #[test]
    fn validate_prearm_excludes_refuses_prearm_conflicts() {
        let slice_of = std::slice::from_ref;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("libreal.so.1.2");
        std::fs::write(&real, b"fake").unwrap();
        let link = dir.path().join("liblink.so");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // Exact conflict, same shape as --module.
        let error = validate_prearm_excludes(slice_of(&real), slice_of(&real))
            .expect_err("prearm naming an excluded file is refused");
        assert!(error.contains("--prearm-module"), "{error}");
        assert!(error.contains("--exclude-module"), "{error}");
        assert!(
            error.contains("refusing a module that is both included and excluded"),
            "{error}"
        );
        // Same file via symlink.
        assert!(validate_prearm_excludes(slice_of(&real), slice_of(&link)).is_err());
        // Bare-name basename conflict.
        assert!(
            validate_prearm_excludes(slice_of(&real), &[PathBuf::from("libreal.so.1.2")]).is_err()
        );
        // No conflict.
        assert!(validate_prearm_excludes(slice_of(&real), &[PathBuf::from("other.so")]).is_ok());
        assert!(validate_prearm_excludes(&[], slice_of(&real)).is_ok());
    }

    /// PA-5 I3 symlink twin: a prearm via a symlink is matched by the
    /// resolved basename, not just the given basename. `liblink.so` ->
    /// `libreal.so.1.2`, excluded by bare name `libreal.so.1.2`.
    #[test]
    fn validate_prearm_excludes_matches_resolved_basename_through_symlink() {
        let slice_of = std::slice::from_ref;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("libreal.so.1.2");
        std::fs::write(&real, b"fake").unwrap();
        let link = dir.path().join("liblink.so");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let error = validate_prearm_excludes(slice_of(&link), &[PathBuf::from("libreal.so.1.2")])
            .expect_err("resolved basename matches through the symlink");
        assert!(error.contains("--prearm-module"), "{error}");
        assert!(error.contains("--exclude-module"), "{error}");
        assert!(
            error.contains("refusing a module that is both included and excluded"),
            "{error}"
        );
    }

    /// PA-5 I3 soname twin: `--prearm-module …/p11-kit-proxy.so`
    /// `--exclude-module libp11-kit.so.0`. The proxy is a symlink to
    /// `libp11-kit.so.0.4.8` whose ELF soname is `libp11-kit.so.0`; neither
    /// the given nor the resolved basename matches, only the soname.
    #[test]
    fn validate_prearm_excludes_matches_proxy_soname() {
        let candidates = [
            "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so",
            "/usr/lib64/p11-kit-proxy.so",
        ];
        let Some(proxy) = candidates.iter().map(PathBuf::from).find(|p| p.is_file()) else {
            // No p11-kit proxy on this host: nothing to conflict.
            return;
        };
        let error = validate_prearm_excludes(
            std::slice::from_ref(&proxy),
            &[PathBuf::from("libp11-kit.so.0")],
        )
        .expect_err("proxy soname matches the exclusion");
        assert!(error.contains("--prearm-module"), "{error}");
        assert!(error.contains("libp11-kit.so.0"), "{error}");
        assert!(
            error.contains("refusing a module that is both included and excluded"),
            "{error}"
        );
    }

    /// A `--manifest` attesting an excluded provider is refused at startup
    /// with the same named-error shape; unreadable manifests are left for
    /// discovery to report precisely.
    #[test]
    fn validate_manifest_excludes_refuses_manifest_conflicts() {
        let slice_of = std::slice::from_ref;
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("libattested.so.1");
        std::fs::write(&provider, b"fake").unwrap();
        let manifest = dir.path().join("attested.json");
        std::fs::write(
            &manifest,
            format!(
                "{{\"module_path\": \"{}\", \"objects\": [{{\"id\": 0, \"path\": \"{}\"}}]}}",
                provider.display(),
                provider.display()
            ),
        )
        .unwrap();
        // Attested module path matching an exclusion is refused.
        let error = validate_manifest_excludes(slice_of(&manifest), slice_of(&provider))
            .expect_err("a manifest attesting an excluded provider is refused");
        assert!(error.contains("--manifest"), "{error}");
        assert!(error.contains("libattested.so.1"), "{error}");
        assert!(error.contains("--exclude-module"), "{error}");
        assert!(
            error.contains("refusing a module that is both included and excluded"),
            "{error}"
        );
        // Bare-name match on the attested basename.
        assert!(
            validate_manifest_excludes(slice_of(&manifest), &[PathBuf::from("libattested.so.1")])
                .is_err()
        );
        // No conflict.
        assert!(
            validate_manifest_excludes(slice_of(&manifest), &[PathBuf::from("other.so")]).is_ok()
        );
        // Unreadable or unparsable manifests are skipped, never misreported.
        let missing = dir.path().join("nope.json");
        assert!(validate_manifest_excludes(slice_of(&missing), slice_of(&provider)).is_ok());
        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, b"not json").unwrap();
        assert!(validate_manifest_excludes(slice_of(&broken), slice_of(&provider)).is_ok());
    }

    #[test]
    fn bare_argv_prints_global_help() {
        assert_eq!(parse(args(&[])), Err(CliError::Help(HelpTopic::Global)));
    }

    #[test]
    fn help_routes_to_topics() {
        for (words, topic) in [
            (vec!["help"], HelpTopic::Global),
            (vec!["help", "profile"], HelpTopic::Profile),
            (vec!["help", "trace"], HelpTopic::Trace),
            (vec!["help", "run"], HelpTopic::Run),
            (vec!["help", "inspect"], HelpTopic::Inspect),
            (vec!["help", "doctor"], HelpTopic::Doctor),
            (vec!["help", "inventory"], HelpTopic::Inventory),
            (vec!["help", "inventory", "diff"], HelpTopic::InventoryDiff),
            (vec!["help", "inventory", "cbom"], HelpTopic::InventoryCbom),
        ] {
            assert_eq!(parse(args(&words)), Err(CliError::Help(topic)), "{words:?}");
        }
        let Err(CliError::Usage { message, topic }) = parse(args(&["help", "frobnicate"])) else {
            panic!("unknown help topic must be a usage error");
        };
        assert!(message.contains("unknown help topic"), "{message}");
        assert_eq!(topic, HelpTopic::Global);
    }

    // 7.10b widening: an owned run arms the PID target-exec
    // consumer for its child, so the flag parses there (the old
    // "records nothing beside run" refusal is gone).
    #[test]
    fn run_accepts_track_short_lived() {
        let Command::Run(armed) =
            parse(args(&["run", "--track-short-lived", "--", "true"])).unwrap()
        else {
            panic!("run --track-short-lived must parse");
        };
        assert!(armed.track_short_lived);
        let Command::Profile(profile_armed) =
            parse(args(&["profile", "--pid", "4242", "--track-short-lived"])).unwrap()
        else {
            panic!("profile --track-short-lived must parse");
        };
        assert!(profile_armed.track_short_lived);
    }

    // 7.10b finding-32 fix: run help documents the flag on its own
    // surface, so help and the parser agree (no "records nothing"
    // contradiction). The counter-mode refusal stays. Both sentences
    // are pinned exactly: the flag description must stay true for the
    // owned child (no "short-lived processes" overclaim), and the
    // refusal sentence must name the policy.
    #[test]
    fn run_help_documents_track_short_lived() {
        let run = HelpTopic::Run.text();
        let flag_sentence = "--track-short-lived also records exec-time detail (extra detail; default off): the kernel records exec-time\nexecutable identity and the child's own execs are grouped by linkage.";
        assert!(run.contains(flag_sentence), "{run}");
        assert!(
            run.contains("Refused beside --counter-mode: it arms Detailed captures only."),
            "{run}"
        );
    }

    // 7.10b widening: profile help no longer confines the flag to
    // cgroup/system captures; it names the --pid arming too.
    #[test]
    fn profile_help_describes_widened_track_short_lived() {
        let profile = HelpTopic::Profile.text();
        assert!(profile.contains("--track-short-lived"), "{profile}");
        assert!(
            !profile.contains("elsewhere it records nothing"),
            "{profile}"
        );
        assert!(
            profile.contains("on --pid it groups the target's own execs"),
            "{profile}"
        );
    }

    // 7.10b widening: trace arms the flag, so trace help documents it.
    #[test]
    fn trace_help_documents_track_short_lived() {
        let trace = HelpTopic::Trace.text();
        assert!(trace.contains("--track-short-lived"), "{trace}");
        assert!(
            trace.contains("on --pid it groups the target's own execs"),
            "{trace}"
        );
    }

    #[test]
    fn invalid_duration_names_examples() {
        let error = parse_duration("5x").expect_err("5x is not a duration");
        assert!(error.contains("(use 30, 30s, 5m or 1h)"), "{error}");
        for argv in [
            vec!["profile", "--pid", "4242", "--duration", "5x"],
            vec!["inventory", "--pid", "4242", "--duration", "5x"],
        ] {
            let Err(CliError::Usage { message, .. }) = parse(args(&argv)) else {
                panic!("{argv:?} must be a usage error");
            };
            assert!(
                message.contains("--duration: invalid value \"5x\""),
                "{message}"
            );
            assert!(message.contains("(use 30, 30s, 5m or 1h)"), "{message}");
            assert!(!message.contains('\n'), "{message}");
        }
    }

    #[test]
    fn doctor_system_names_pid_or_cgroup() {
        let Err(CliError::Usage { message, topic }) = parse(args(&["doctor", "--system"])) else {
            panic!("doctor --system must be a usage error");
        };
        assert!(
            message.contains("--pid") && message.contains("--cgroup"),
            "{message}"
        );
        assert!(!message.contains("takes no capture scope"), "{message}");
        assert_eq!(topic, HelpTopic::Doctor);
    }

    #[test]
    fn doctor_module_names_mapped_providers() {
        let Err(CliError::Usage { message, .. }) = parse(args(&["doctor", "--module", "x.so"]))
        else {
            panic!("doctor --module must be a usage error");
        };
        assert!(message.contains("to list mapped providers"), "{message}");
        assert!(!message.contains("module-specific discovery"), "{message}");
    }

    #[test]
    fn doctor_accepts_verbose_and_quiet() {
        let Command::Doctor(verbose) = parse(args(&["doctor", "-v"])).unwrap() else {
            panic!("doctor -v must parse");
        };
        assert!(verbose.verbose && !verbose.quiet);
        let Command::Doctor(quiet) = parse(args(&["doctor", "--quiet"])).unwrap() else {
            panic!("doctor --quiet must parse");
        };
        assert!(quiet.quiet && !quiet.verbose);
        let Command::Doctor(plain) = parse(args(&["doctor"])).unwrap() else {
            panic!("doctor must parse");
        };
        assert!(!plain.verbose && !plain.quiet);
        assert!(
            matches!(
                parse(args(&["doctor", "-v", "--quiet"])),
                Err(CliError::Usage { .. })
            ),
            "doctor must refuse -v with --quiet"
        );
    }

    #[test]
    fn global_help_is_short_with_examples_and_exit_line() {
        assert!(USAGE.lines().count() < 45, "{}", USAGE.lines().count());
        for line in USAGE.lines() {
            assert!(line.len() < 200, "overlong global help line: {line}");
        }
        assert!(USAGE.contains("p11scope help [command]"), "{USAGE}");
        for example in [
            "sudo p11scope run --pause auto -- pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -L",
            "sudo p11scope profile --pid 4242 --duration 30s -o profile.json",
            "sudo p11scope inventory --system --duration 30s",
        ] {
            assert!(USAGE.contains(example), "{USAGE}");
        }
        assert_eq!(USAGE.matches("exit codes:").count(), 1, "{USAGE}");
    }

    #[test]
    fn every_help_carries_one_exit_code_line() {
        for topic in [
            HelpTopic::Global,
            HelpTopic::Profile,
            HelpTopic::Trace,
            HelpTopic::Run,
            HelpTopic::Inspect,
            HelpTopic::Doctor,
            HelpTopic::Inventory,
            HelpTopic::InventoryDiff,
            HelpTopic::InventoryCbom,
        ] {
            let help = topic.text();
            assert_eq!(
                help.matches("exit codes:").count(),
                1,
                "{topic:?} must carry exactly one exit-code line"
            );
        }
    }

    #[test]
    fn capture_examples_show_sudo_and_parse() {
        let run = HelpTopic::Run.text();
        for example in [
            "sudo p11scope run --pause auto -- pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -L",
            "sudo p11scope run --pause auto -- pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so -L",
        ] {
            assert!(run.contains(example), "{run}");
        }
        assert!(!run.contains("/absolute/path/to/program"), "{run}");
        // 7.10b: run help documents the flag now (pinned by
        // run_help_documents_track_short_lived).
        let inventory = HelpTopic::Inventory.text();
        assert!(
            inventory.contains("sudo p11scope inventory --system --duration 30s"),
            "{inventory}"
        );
        // The sudo examples parse once the privilege prefix is stripped.
        for words in [
            "p11scope run --pause auto -- pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -L",
            "p11scope run --pause auto -- pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so -L",
            "p11scope inventory --system --duration 30s",
        ] {
            parse(args(&words.split_whitespace().skip(1).collect::<Vec<_>>()))
                .unwrap_or_else(|error| panic!("{words} must parse: {error:?}"));
        }
    }

    #[test]
    fn global_help_qualifies_json_routes() {
        assert!(
            USAGE.contains("--json on inspect/inventory"),
            "global help must name which commands take --json: {USAGE}"
        );
        assert!(
            USAGE.contains("-o FILE on profile/trace/run/inventory"),
            "global help must name the -o JSON route: {USAGE}"
        );
        assert!(
            USAGE.contains("trace takes -o -"),
            "global help must name trace -o -: {USAGE}"
        );
        assert!(
            USAGE.contains("--event-log"),
            "global help must name the inventory event stream: {USAGE}"
        );
        assert!(
            USAGE.contains("doctor is text-only"),
            "global help must state doctor has no JSON: {USAGE}"
        );
        assert!(
            !USAGE.contains("--json and -o are always complete"),
            "global help must not claim --json is universal: {USAGE}"
        );
    }

    #[test]
    fn json_flag_refusal_points_to_the_commands_json_route() {
        for (argv, route) in [
            (vec!["profile", "--pid", "7", "--json"], "-o FILE"),
            (vec!["trace", "--pid", "7", "--json"], "-o"),
            (vec!["run", "--json", "--", "/bin/true"], "-o FILE"),
            (vec!["doctor", "--json"], "text-only"),
        ] {
            let Err(CliError::Usage { message, .. }) = parse(args(&argv)) else {
                panic!("{argv:?} must refuse --json");
            };
            assert!(
                message.contains("unknown argument: --json"),
                "{argv:?}: {message}"
            );
            assert!(message.contains(route), "{argv:?}: {message}");
        }
        parse(args(&["inspect", "--pid", "7", "--json"])).unwrap();
        parse(args(&["inventory", "--pid", "7", "--json"])).unwrap();
    }

    #[test]
    fn docs_qualify_json_routes() {
        const README: &str = include_str!("../README.md");
        const USAGE_MD: &str = include_str!("../docs/usage.md");
        const OVERVIEW_MD: &str = include_str!("../docs/overview.md");
        for (name, text) in [
            ("README.md", README),
            ("docs/usage.md", USAGE_MD),
            ("docs/overview.md", OVERVIEW_MD),
        ] {
            // Backticks and line wraps are layout; the wording is the contract.
            let flat = text.replace('`', "").replace('\n', " ");
            assert!(
                flat.contains("--json on inspect/inventory"),
                "{name} must name which commands take --json"
            );
            assert!(
                flat.contains("doctor is text-only"),
                "{name} must state doctor has no JSON"
            );
        }
        assert!(
            !README.contains("--json` is always complete"),
            "README must not claim --json is universal"
        );
        assert!(
            !USAGE_MD.contains("`--json` and `-o` are always complete"),
            "usage.md must not claim --json is universal"
        );
        assert!(
            !OVERVIEW_MD.contains("`--json` and `-o` are always"),
            "overview.md must not claim --json is universal"
        );
    }
}
