//! SPDX-License-Identifier: GPL-3.0-or-later
//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes). CLI entry
//! point only: argument dispatch and the process exit code. Every capture
//! loop lives in the `p11scope` library crate (`src/run.rs`) so that
//! `profile`, `trace`, and `run` share exactly one profile loop and one trace
//! loop, and so integration tests can exercise them directly.

use std::io::Write as _;

use anyhow::{Context as _, Result};
use p11scope::cli::{self, CliError, Command};
use p11scope::{
    capture, capture_startup_signal_dispositions, doctor, failure_already_reported,
    failure_exit_code, inspect, inventory, pidns, run_owned,
};

fn main() {
    match run() {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(e) => {
            // Every failure the observer can name arrives here as one line: an
            // unreadable target, a stale manifest, an environment without BPF.
            // Never `eprintln!`: a closed stderr would turn exit 1 into a
            // panic (HIGH-4), so a failed diagnostic write is dropped. A link
            // cleanup abandoned by a second SIGINT already printed its
            // progress and "cleanup incomplete", and exits 130 like any
            // shell-interrupted command (SG-I7).
            if !failure_already_reported(&e) {
                let _ = writeln!(std::io::stderr(), "p11scope: {e:#}");
            }
            std::process::exit(failure_exit_code(&e));
        }
    }
}

/// Writes exit-0 text (help, version) to stdout. A reader that went away
/// (`p11scope --help | head -1`, EPIPE) is not a failure of the command: the
/// Rust runtime ignores SIGPIPE, so `println!` would panic here (HIGH-4).
fn print_stdout(text: std::fmt::Arguments<'_>) -> Result<i32> {
    let mut stdout = std::io::stdout().lock();
    match stdout.write_fmt(text).and_then(|()| stdout.flush()) {
        Ok(()) => Ok(0),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(0),
        Err(error) => Err(error).context("writing stdout"),
    }
}

fn run() -> Result<i32> {
    // Before any handler installs: the owned command inherits exactly the
    // dispositions captured here for every signal the observer changes.
    capture_startup_signal_dispositions();
    // `args_os`: `std::env::args()` panics on a non-UTF-8 argument (M-9).
    match cli::parse(std::env::args_os().skip(1)) {
        Ok(Command::Version) => {
            print_stdout(format_args!("p11scope {}\n", env!("CARGO_PKG_VERSION")))
        }
        // `kind` travels inside the arguments, so both capture subcommands share
        // one arm as well as one parser.
        Ok(Command::Profile(a) | Command::Trace(a)) => capture(&a).map(|()| 0),
        // `run` owns its child from fork to reap and reports the status a shell
        // would. A child deliberately handed back still running is a success
        // for the observer, so it exits 0.
        Ok(Command::Run(a)) => run_owned(&a).map(|outcome| outcome.child_exit_code.unwrap_or(0)),
        // Both of `inspect`'s hard failures — a pid that names nothing, and a target
        // that exited while its objects were being pinned — mean "the target could
        // not be read at all": one line here, exit 1, never a panic. A
        // fully-unreadable machine fails the same way under `--system`.
        Ok(Command::Inspect(a)) => {
            let scope = match a.scope {
                cli::InspectScope::Pid(pid) => format!("inspect --pid {pid}"),
                cli::InspectScope::System => "inspect --system".to_string(),
            };
            inspect::run(a.scope, &a.modules, &a.hooks, a.json, a.max_scan_pids)
                .with_context(|| scope)
        }
        Ok(Command::Doctor(a)) => doctor::run(a.pid, a.cgroup.as_deref(), a.extra_strict),
        // `inventory`'s hard failures — an unreadable target, an
        // unwritable `-o` — mean "nothing could be observed": one line
        // here, exit 1, never a panic and never an empty-success report.
        Ok(Command::Inventory(a)) => {
            let scope = match a.scope {
                cli::InspectScope::Pid(pid) => format!("inventory --pid {pid}"),
                cli::InspectScope::System => "inventory --system".to_string(),
            };
            // DR-K8S-1: the kernel-side PID filter numbers tasks in the
            // initial PID namespace; a nested observer's --pid would match
            // nothing, so it is refused by name before anything runs.
            let observer = pidns::numbering();
            if matches!(a.scope, cli::InspectScope::Pid(_)) {
                pidns::require_numbering_agrees(observer, &scope)?;
            } else if let Some(warning) = pidns::nested_warning(observer) {
                let _ = writeln!(std::io::stderr(), "{warning}");
            }
            inventory::run(
                a.scope,
                &a.modules,
                &a.hooks,
                a.json,
                a.max_scan_pids,
                a.max_gaps,
                a.duration,
                a.out.as_deref(),
                a.dashboard,
                a.event_log.as_deref(),
                a.event_rotate_bytes,
                a.event_max_files,
                a.capture,
            )
            .with_context(|| scope)
        }
        // Exit-0 help goes to stdout, so `p11scope --help | grep …` works.
        Err(CliError::Help(topic)) => print_stdout(format_args!("{}\n", topic.text())),
        Err(CliError::Usage(msg)) => {
            let _ = writeln!(std::io::stderr(), "{msg}");
            Ok(2)
        }
    }
}
