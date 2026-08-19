//! Command-line parsing for every subcommand: one parser body for profile and
//! trace, durations with suffixes, hints for removed flags.

use crate::discovery::hooks::HookRegistry;
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
    pub unsafe_requested: bool,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Profile(CaptureArgs),
    Trace(CaptureArgs),
    Inspect(InspectArgs),
    Doctor(DoctorArgs),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    Usage(String),
    Help,
}

pub const USAGE: &str = "usage:
  p11scope profile [--pid <n> | --cgroup <path>] [--module <provider.so>]... [--manifest <m.json>]...
                   [--mode profile|metrics] [--duration <30|30s|5m|1h>] [-o <out.json>]
                   [--hook-symbol <NAME[:functionlist|interfacelist|interface]>]...
                   [--unsafe-unvalidated-metadata]
  p11scope trace   [same scope and discovery options] [--duration <…>] [-o <out.file>]
  p11scope inspect --pid <n> [--module <provider.so>]... [--hook-symbol <…>]... [--json]
  p11scope doctor  [--pid <n>] [--cgroup <path>]
  p11scope-discover --module <provider.so> [-o <manifest.json>]   (offline helper; executes provider code)

notes: discovery scans the target's mapped memory — no manifest and no helper are required.
--module narrows the scan to named providers. --manifest is explicit operator attestation of exact accepted function-name/offset claims; it is corroborated against the scan when possible.
scan-only discovery is semantics-unverified and count-only; aggregate counts/RVs/latency remain available. Scanning happens once, at attach time.
--mode defaults to profile; --mode metrics is the lighter maps-only level. Ctrl-C or SIGTERM
ends a capture cleanly (final frame printed, -o written). --cgroup matches that cgroup and
every descendant (kernel >= 5.15). Provider identity is pinned by SHA-256 at attach and
checked for in-place change during capture (evidence.provider_changed).
";

const REMOVED_FLAG_HINT: &str = "removed in productization slice 1a: the observer pins provider \
identity by SHA-256 and fstat; see docs/usage.md";

fn usage_err(msg: impl Into<String>) -> CliError {
    CliError::Usage(format!("{}\n{USAGE}", msg.into()))
}

fn require_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, CliError> {
    args.next()
        .ok_or_else(|| usage_err(format!("{flag} requires a value")))
}

fn require_pid(args: &mut impl Iterator<Item = String>) -> Result<u32, CliError> {
    let v = require_value(args, "--pid")?;
    v.parse()
        .map_err(|_| usage_err(format!("--pid: invalid number {v:?}")))
}

/// `--hook-symbol NAME[:abi]`, validated by the registry itself so the CLI has
/// no second copy of the ABI names; its message is propagated verbatim.
fn add_hook(
    hooks: &mut HookRegistry,
    args: &mut impl Iterator<Item = String>,
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
        other => usage_err(format!("unknown argument: {other}")),
    }
}

/// The whole command line: the subcommand plus its own arguments. Pure — no I/O,
/// no process exit; the caller decides how to report `CliError`.
pub fn parse(mut argv: impl Iterator<Item = String>) -> Result<Command, CliError> {
    match argv.next().as_deref() {
        Some("profile") => Ok(Command::Profile(parse_capture(Kind::Profile, argv)?)),
        Some("trace") => Ok(Command::Trace(parse_capture(Kind::Trace, argv)?)),
        Some("inspect") => Ok(Command::Inspect(parse_inspect(argv)?)),
        Some("doctor") => Ok(Command::Doctor(parse_doctor(argv)?)),
        Some("--help" | "-h") => Err(CliError::Help),
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
fn parse_inspect(mut args: impl Iterator<Item = String>) -> Result<InspectArgs, CliError> {
    let mut pid: Option<u32> = None;
    let mut modules = Vec::new();
    let mut hooks = HookRegistry::builtin();
    let mut json = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--help" | "-h" => return Err(CliError::Help),
            "--pid" => pid = Some(require_pid(&mut args)?),
            "--module" => modules.push(require_value(&mut args, "--module")?.into()),
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
fn parse_doctor(mut args: impl Iterator<Item = String>) -> Result<DoctorArgs, CliError> {
    let mut doctor = DoctorArgs {
        pid: None,
        cgroup: None,
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--help" | "-h" => return Err(CliError::Help),
            "--pid" => doctor.pid = Some(require_pid(&mut args)?),
            "--cgroup" => doctor.cgroup = Some(require_value(&mut args, "--cgroup")?.into()),
            "--module" => {
                return Err(usage_err(
                    "doctor --module is not supported; use inspect --pid <n> --module \
                     <provider.so> for module-specific discovery",
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
    mut args: impl Iterator<Item = String>,
) -> Result<CaptureArgs, CliError> {
    let mut modules = Vec::new();
    let mut manifests = Vec::new();
    let mut hooks = HookRegistry::builtin();
    let mut pid: Option<u32> = None;
    let mut cgroup: Option<PathBuf> = None;
    let mut metrics = false;
    let mut duration: Option<Duration> = None;
    let mut out: Option<PathBuf> = None;
    let mut unsafe_requested = false;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--help" | "-h" => return Err(CliError::Help),
            "--module" => modules.push(require_value(&mut args, "--module")?.into()),
            "--manifest" => manifests.push(require_value(&mut args, "--manifest")?.into()),
            "--hook-symbol" => add_hook(&mut hooks, &mut args)?,
            "--pid" => pid = Some(require_pid(&mut args)?),
            "--cgroup" => cgroup = Some(require_value(&mut args, "--cgroup")?.into()),
            "--mode" => {
                let v = require_value(&mut args, "--mode")?;
                if kind == Kind::Trace {
                    return Err(usage_err(
                        "trace has no --mode; it always streams raw events",
                    ));
                }
                match v.as_str() {
                    "profile" => metrics = false,
                    "metrics" => metrics = true,
                    "trace" => {
                        return Err(usage_err(
                            "trace is a subcommand: `p11scope trace …`, not --mode trace",
                        ));
                    }
                    other => return Err(usage_err(format!("--mode: invalid value {other:?}"))),
                }
            }
            "--duration" => {
                let v = require_value(&mut args, "--duration")?;
                duration = Some(
                    parse_duration(&v)
                        .map_err(|e| usage_err(format!("--duration: invalid value {v:?}: {e}")))?,
                );
            }
            "-o" => out = Some(require_value(&mut args, "-o")?.into()),
            "--unsafe-unvalidated-metadata" => unsafe_requested = true,
            other => return Err(unknown_arg(other)),
        }
    }

    let scope = match (pid, cgroup) {
        (Some(p), None) => ScopeArg::Pid(p),
        (None, Some(c)) => ScopeArg::Cgroup(c),
        (None, None) => return Err(usage_err("exactly one of --pid or --cgroup is required")),
        (Some(_), Some(_)) => return Err(usage_err("--pid and --cgroup are mutually exclusive")),
    };

    Ok(CaptureArgs {
        kind,
        modules,
        manifests,
        hooks,
        scope,
        metrics,
        duration,
        out,
        unsafe_requested,
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
            matches!(parse_capture(Kind::Profile, args(&["--manifest", "m"])), Err(CliError::Usage(m)) if m.contains("exactly one of --pid or --cgroup"))
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
    fn help_is_not_an_error() {
        assert_eq!(
            parse_capture(Kind::Profile, args(&["--help"])).unwrap_err(),
            CliError::Help
        );
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
}
