//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes). CLI entry
//! point only: argument dispatch and the process exit code. Every capture
//! loop lives in the `p11scope` library crate (`src/run.rs`) so that
//! `profile`, `trace`, and `run` share exactly one profile loop and one trace
//! loop, and so integration tests can exercise them directly.

use anyhow::{Context as _, Result};
use p11scope::cli::{self, CliError, Command};
use p11scope::{capture, doctor, inspect, run_owned};

fn main() {
    match run() {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(e) => {
            // Every failure the observer can name arrives here as one line: an
            // unreadable target, a stale manifest, an environment without BPF.
            eprintln!("p11scope: {e:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32> {
    match cli::parse(std::env::args().skip(1)) {
        // `kind` travels inside the arguments, so both capture subcommands share
        // one arm as well as one parser.
        Ok(Command::Profile(a) | Command::Trace(a)) => capture(&a).map(|()| 0),
        // `run` owns its child from fork to reap and reports the status a shell
        // would. A child deliberately handed back still running is a success
        // for the observer, so it exits 0.
        Ok(Command::Run(a)) => run_owned(&a).map(|outcome| outcome.child_exit_code.unwrap_or(0)),
        // Both of `inspect`'s hard failures — a pid that names nothing, and a target
        // that exited while its objects were being pinned — mean "the target could
        // not be read at all": one line here, exit 1, never a panic.
        Ok(Command::Inspect(a)) => inspect::run(a.pid, &a.modules, &a.hooks, a.json)
            .with_context(|| format!("inspect --pid {}", a.pid)),
        Ok(Command::Doctor(a)) => doctor::run(a.pid, a.cgroup.as_deref()),
        Err(CliError::Help) => {
            eprintln!("{}", cli::USAGE);
            Ok(0)
        }
        Err(CliError::Usage(msg)) => {
            eprintln!("{msg}");
            Ok(2)
        }
    }
}
