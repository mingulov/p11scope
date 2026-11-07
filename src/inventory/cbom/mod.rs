//! SPDX-License-Identifier: GPL-3.0-or-later
//! Offline CycloneDX CBOM export from saved inventory or profile evidence.

pub(crate) mod classify;
pub(crate) mod input;
mod render;

#[cfg(test)]
mod cbom_tests;

use anyhow::{Context as _, Result, ensure};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use crate::cli::InventoryCbomArgs;
use crate::inventory_output::{FdStdout, FinalStdout, StdoutFailureReason};
use crate::output::AtomicFile;

/// Offline file conversion; stdout uses the existing nonblocking transport
/// and inactivity bound. No capture setup or target/process/provider
/// lookup occurs.
pub fn run(args: &InventoryCbomArgs) -> Result<i32> {
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
pub fn run_with_writer(args: &InventoryCbomArgs, out: &mut dyn Write) -> Result<i32> {
    sanitize(run_inner(
        args,
        |bytes| out.write_all(bytes).and_then(|()| out.flush()),
        || {},
    ))
}

#[cfg(test)]
fn run_with_writer_before_commit(
    args: &InventoryCbomArgs,
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
    args: &InventoryCbomArgs,
    stdout: impl FnOnce(&[u8]) -> io::Result<()>,
    before_commit: impl FnOnce(),
) -> Result<i32> {
    let loaded = input::read_input(&args.input).context("CBOM input")?;
    let input_path = normalized_path(&args.input)?;
    let document = render::render_json(&loaded.projection);
    if let Some(path) = &args.out {
        check_output_alias(path, &input_path, &loaded.source)?;
        let mut sink = AtomicFile::create(path).map_err(anyhow::Error::msg)?;
        serde_json::to_writer(sink.file(), &document).context("writing CBOM JSON")?;
        sink.file()
            .write_all(b"\n")
            .context("writing CBOM newline")?;
        before_commit();
        // The descriptor is retained even if its original name is
        // replaced. AtomicFile independently enforces trusted ancestors
        // and final-name checks. The same-owner check/rename race stays
        // within its documented trusted-directory boundary; this is not
        // a path lock.
        check_output_alias(path, &input_path, &loaded.source)?;
        sink.commit().map_err(anyhow::Error::msg)?;
    }
    let mut bytes = Vec::new();
    if args.json {
        serde_json::to_writer(&mut bytes, &document).context("rendering CBOM stdout")?;
        bytes.push(b'\n');
    } else if crate::cli::text_verbosity() == crate::cli::TextVerbosity::Verbose {
        render::render_verbose(&loaded.projection, &mut bytes).context("rendering CBOM detail")?;
    } else {
        render::render_concise(&loaded.projection, &mut bytes).context("rendering CBOM summary")?;
    }
    match stdout(&bytes) {
        Ok(()) => Ok(0),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(0),
        Err(error) => Err(error).context("writing CBOM stdout"),
    }
}

fn normalized_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolving relative CBOM path")?
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
            Component::Prefix(_) => anyhow::bail!("unsupported CBOM path prefix"),
        }
    }
    Ok(result)
}

fn check_output_alias(path: &Path, input_path: &PathBuf, source: &File) -> Result<()> {
    let normalized = normalized_path(path)?;
    ensure!(
        normalized != *input_path,
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
    let held = source
        .metadata()
        .context("checking retained CBOM input descriptor")?;
    ensure!(
        metadata.dev() != held.dev() || metadata.ino() != held.ino(),
        "output {} is an input alias",
        path.display()
    );
    Ok(())
}
