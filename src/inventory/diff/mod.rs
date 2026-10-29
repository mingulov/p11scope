//! SPDX-License-Identifier: GPL-3.0-or-later
//! Offline comparison of saved inventory evidence.

// parse_snapshot and reduced-limit entry points are retained reader test seams.
#[allow(dead_code)]
mod input;

mod compare;
mod model;

mod render;

#[cfg(test)]
mod render_tests;

use anyhow::{Context as _, Result, ensure};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use crate::cli::InventoryDiffArgs;
use crate::inventory_output::{FdStdout, FinalStdout, StdoutFailureReason};
use crate::output::AtomicFile;

/// Offline file comparison; stdout uses the existing nonblocking transport and
/// inactivity bound. No capture setup or target/process/provider lookup occurs.
pub fn run(args: &InventoryDiffArgs) -> Result<i32> {
    let signals = || 0;
    let mut stdout = FdStdout::new(1, &signals);
    sanitize(run_inner(
        args,
        |bytes| {
            stdout.begin_finalization();
            stdout.write_document(bytes).map(|_| ()).map_err(|failure| {
                let message = format!(
                    "stdout accepted {}/{} bytes",
                    failure.accepted, failure.total
                );
                match failure.reason {
                    StdoutFailureReason::Io(error) => {
                        io::Error::new(error.kind(), format!("{message}: {error}"))
                    }
                    StdoutFailureReason::NoProgress => io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("{message}: no progress before inactivity limit"),
                    ),
                    StdoutFailureReason::Cancelled => {
                        io::Error::new(io::ErrorKind::Interrupted, format!("{message}: cancelled"))
                    }
                }
            })
        },
        || {},
    ))
}

/// Injectable writers claim no fd transport bound. Production uses `run`.
pub fn run_with_writer(args: &InventoryDiffArgs, out: &mut dyn Write) -> Result<i32> {
    sanitize(run_inner(
        args,
        |bytes| out.write_all(bytes).and_then(|()| out.flush()),
        || {},
    ))
}

#[cfg(test)]
fn run_with_writer_before_commit(
    args: &InventoryDiffArgs,
    out: &mut dyn Write,
    before_commit: impl FnOnce(),
) -> Result<i32> {
    sanitize(run_inner(
        args,
        |bytes| out.write_all(bytes).and_then(|()| out.flush()),
        before_commit,
    ))
}

fn sanitize(result: Result<i32>) -> Result<i32> {
    result.map_err(|error| {
        anyhow::anyhow!("{}", crate::render::escape_controls(&format!("{error:#}")))
    })
}

fn run_inner(
    args: &InventoryDiffArgs,
    stdout: impl FnOnce(&[u8]) -> io::Result<()>,
    before_commit: impl FnOnce(),
) -> Result<i32> {
    let before = input::read_snapshot(&args.before).context("before snapshot")?;
    let after = input::read_snapshot(&args.after).context("after snapshot")?;
    let input_paths = [
        normalized_path(&args.before)?,
        normalized_path(&args.after)?,
    ];
    let sources = [&before.source, &after.source];
    let report = compare::compare(&before.snapshot, &after.snapshot);
    if let Some(path) = &args.out {
        check_output_alias(path, &input_paths, sources)?;
        let mut sink = AtomicFile::create(path).map_err(anyhow::Error::msg)?;
        serde_json::to_writer(sink.file(), &report).context("writing JSON report")?;
        sink.file()
            .write_all(b"\n")
            .context("writing report newline")?;
        before_commit();
        // These descriptors are retained, even if their original names are
        // replaced. AtomicFile independently enforces trusted ancestors and
        // final-name checks. The same-owner check/rename race stays within its
        // documented trusted-directory boundary; this is not a path lock.
        check_output_alias(path, &input_paths, sources)?;
        sink.commit().map_err(anyhow::Error::msg)?;
    }
    let mut bytes = Vec::new();
    if args.json {
        serde_json::to_writer(&mut bytes, &report).context("rendering JSON stdout")?;
        bytes.push(b'\n');
    } else {
        render::render_text(&report, &mut bytes).context("rendering inventory diff")?;
    }
    match stdout(&bytes) {
        Ok(()) => Ok(0),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(0),
        Err(error) => Err(error).context("writing inventory diff stdout"),
    }
}

fn normalized_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolving relative inventory path")?
            .join(path)
    };
    let mut result = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => result.push(name),
            Component::ParentDir => {
                result.pop();
            }
            Component::Prefix(_) => anyhow::bail!("unsupported inventory path prefix"),
        }
    }
    Ok(result)
}

fn check_output_alias(path: &Path, input_paths: &[PathBuf; 2], sources: [&File; 2]) -> Result<()> {
    let normalized = normalized_path(path)?;
    ensure!(
        !input_paths.contains(&normalized),
        "output {} is an input alias",
        path.display()
    );
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("checking output {}", path.display()));
        }
    };
    for source in sources {
        let held = source
            .metadata()
            .context("checking retained inventory input descriptor")?;
        ensure!(
            metadata.dev() != held.dev() || metadata.ino() != held.ino(),
            "output {} is an input alias",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod input_tests;

#[cfg(test)]
mod compare_tests;
