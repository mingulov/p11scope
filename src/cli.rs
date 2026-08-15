//! Command-line parsing for the capture subcommands: one parser for profile
//! and trace, durations with suffixes, hints for removed flags.

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
    pub manifest: PathBuf,
    pub scope: ScopeArg,
    /// `--mode metrics` (profile only).
    pub metrics: bool,
    pub duration: Option<Duration>,
    pub out: Option<PathBuf>,
    pub unsafe_requested: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    Usage(String),
    Help,
}

pub const USAGE: &str = "usage:
  p11scope profile --manifest <m.json> (--pid <n> | --cgroup <path>) [--mode profile|metrics] [--unsafe-unvalidated-metadata] [--duration <30|30s|5m|1h>] [-o <out.json>]
  p11scope trace   --manifest <m.json> (--pid <n> | --cgroup <path>) [--unsafe-unvalidated-metadata] [--duration <…>] [-o <out.file>]
  p11scope-discover --module <provider.so> [-o <manifest.json>]   (offline helper; executes provider code)

notes: --mode defaults to profile; --mode metrics is the lighter maps-only level.
Ctrl-C or SIGTERM ends a capture cleanly (final frame printed, -o written). --cgroup matches
that cgroup and every descendant (kernel >= 5.15). Provider identity is pinned by SHA-256 at
attach and checked for in-place change during capture (evidence.provider_changed).
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

/// Parses the arguments shared by `profile` and `trace` into one
/// `CaptureArgs`. Pure: no I/O, no process exit — the caller decides how
/// to report `CliError`.
pub fn parse_capture(
    kind: Kind,
    mut args: impl Iterator<Item = String>,
) -> Result<CaptureArgs, CliError> {
    let mut manifest: Option<PathBuf> = None;
    let mut pid: Option<u32> = None;
    let mut cgroup: Option<PathBuf> = None;
    let mut metrics = false;
    let mut duration: Option<Duration> = None;
    let mut out: Option<PathBuf> = None;
    let mut unsafe_requested = false;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--help" | "-h" => return Err(CliError::Help),
            "--manifest" => manifest = Some(require_value(&mut args, "--manifest")?.into()),
            "--pid" => {
                let v = require_value(&mut args, "--pid")?;
                pid = Some(
                    v.parse()
                        .map_err(|_| usage_err(format!("--pid: invalid number {v:?}")))?,
                );
            }
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
            "--provenance-module" | "--trusted-workload" => {
                return Err(usage_err(format!("{a}: {REMOVED_FLAG_HINT}")));
            }
            other => return Err(usage_err(format!("unknown argument: {other}"))),
        }
    }

    let manifest = manifest.ok_or_else(|| usage_err("--manifest is required"))?;
    let scope = match (pid, cgroup) {
        (Some(p), None) => ScopeArg::Pid(p),
        (None, Some(c)) => ScopeArg::Cgroup(c),
        (None, None) => return Err(usage_err("exactly one of --pid or --cgroup is required")),
        (Some(_), Some(_)) => return Err(usage_err("--pid and --cgroup are mutually exclusive")),
    };

    Ok(CaptureArgs {
        kind,
        manifest,
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
    fn args(v: &[&str]) -> std::vec::IntoIter<String> {
        v.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
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
    fn profile_requires_manifest_and_exactly_one_scope() {
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
        assert!(
            matches!(parse_capture(Kind::Profile, args(&["--pid", "1"])), Err(CliError::Usage(m)) if m.contains("--manifest is required"))
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
}
