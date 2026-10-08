//! SPDX-License-Identifier: GPL-3.0-or-later
//! Complete inventory documents with exact local accepted-byte accounting.
//!
//! Positive writes reset the inactivity budget; there is no total deadline.
//! Pipe/TTY transports are private and nonblocking, and socket sends use
//! per-call nonblocking flags. Regular-file, block-device and arbitrary driver
//! calls can still wait inside the kernel. Completion means ordinary flush
//! succeeded after all payload bytes were accepted, not consumer parsing,
//! terminal display or durable storage. Drop never retries pending output.

use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::sink::{SINK_BUFFER_BYTES, SINK_POLL_SLICE, StdoutInner, stdout_transport_on_fd};

pub(crate) const FINAL_STDOUT_IDLE: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(crate) enum StdoutFailureReason {
    NoProgress,
    Cancelled,
    Io(io::Error),
}

#[derive(Debug)]
pub(crate) struct StdoutFailure {
    pub(crate) accepted: usize,
    pub(crate) total: usize,
    pub(crate) reason: StdoutFailureReason,
}

pub(crate) type StdoutResult = Result<usize, StdoutFailure>;

pub(crate) trait FinalStdout {
    fn begin_finalization(&mut self);
    fn write_document(&mut self, bytes: &[u8]) -> StdoutResult;
}

/// Borrows an inherited descriptor and a delivered-signal counter. Construction
/// does no I/O; acquisition happens only when the caller attempts stdout.
pub(crate) struct FdStdout<'a> {
    fd: RawFd,
    signals: &'a dyn Fn() -> usize,
    baseline: Option<usize>,
}

impl<'a> FdStdout<'a> {
    pub(crate) fn new(fd: RawFd, signals: &'a dyn Fn() -> usize) -> Self {
        Self {
            fd,
            signals,
            baseline: None,
        }
    }

    fn write_document_with_transport(
        &mut self,
        bytes: &[u8],
        acquire: impl FnOnce() -> io::Result<StdoutInner>,
    ) -> StdoutResult {
        // Callers freeze the baseline at their finalization boundary. If they
        // omit that call, conservatively cancel on any delivered signal rather
        // than absorbing it into a late baseline here.
        let baseline = self.baseline.unwrap_or(0);
        let cancelled = || (self.signals)() > baseline;
        if cancelled() {
            return Err(failure(0, bytes.len(), StdoutFailureReason::Cancelled));
        }
        let mut transport =
            acquire().map_err(|error| failure(0, bytes.len(), StdoutFailureReason::Io(error)))?;
        write_document(&mut transport, bytes, FINAL_STDOUT_IDLE, &cancelled)
    }
}

impl FinalStdout for FdStdout<'_> {
    fn begin_finalization(&mut self) {
        if self.baseline.is_none() {
            self.baseline = Some((self.signals)().min(1));
        }
    }

    fn write_document(&mut self, bytes: &[u8]) -> StdoutResult {
        let fd = self.fd;
        self.write_document_with_transport(bytes, || stdout_transport_on_fd(fd))
    }
}

fn failure(accepted: usize, total: usize, reason: StdoutFailureReason) -> StdoutFailure {
    StdoutFailure {
        accepted,
        total,
        reason,
    }
}

fn write_document<W: Write + AsRawFd>(
    writer: &mut W,
    bytes: &[u8],
    idle: Duration,
    cancelled: &dyn Fn() -> bool,
) -> StdoutResult {
    let total = bytes.len();
    let mut accepted = 0;
    let mut progress = Instant::now();
    while accepted < total {
        if cancelled() {
            return Err(failure(accepted, total, StdoutFailureReason::Cancelled));
        }
        if progress.elapsed() >= idle {
            return Err(failure(accepted, total, StdoutFailureReason::NoProgress));
        }
        let end = accepted + (total - accepted).min(SINK_BUFFER_BYTES);
        match writer.write(&bytes[accepted..end]) {
            Ok(0) => {
                return Err(failure(
                    accepted,
                    total,
                    StdoutFailureReason::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "stdout accepted zero bytes from a nonempty document",
                    )),
                ));
            }
            Ok(wrote) => {
                accepted += wrote;
                progress = Instant::now();
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                if cancelled() {
                    return Err(failure(accepted, total, StdoutFailureReason::Cancelled));
                }
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(failure(accepted, total, StdoutFailureReason::Io(error))),
        }

        if cancelled() {
            return Err(failure(accepted, total, StdoutFailureReason::Cancelled));
        }
        let remaining = idle.saturating_sub(progress.elapsed());
        if remaining.is_zero() {
            return Err(failure(accepted, total, StdoutFailureReason::NoProgress));
        }
        let slice = remaining.min(SINK_POLL_SLICE);
        // Ceiling milliseconds avoid spinning when less than a millisecond
        // remains. The slice cap keeps the conversion within poll's i32 range.
        let timeout = slice.as_nanos().div_ceil(1_000_000) as i32;
        let mut fd = libc::pollfd {
            fd: writer.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: poll only accesses this one initialized pollfd.
        let ready = unsafe { libc::poll(&raw mut fd, 1, timeout) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(failure(accepted, total, StdoutFailureReason::Io(error)));
            }
            if cancelled() {
                return Err(failure(accepted, total, StdoutFailureReason::Cancelled));
            }
        } else if fd.revents & libc::POLLNVAL != 0 {
            return Err(failure(
                accepted,
                total,
                StdoutFailureReason::Io(io::Error::from_raw_os_error(libc::EBADF)),
            ));
        }
        // Readiness, timeout, hangup and poll errors are never byte progress.
        // The next write determines actual acceptance or the transport error.
    }
    // No unaccepted suffix remains. Complete the ordinary flush exactly once,
    // including when a signal arrived after the last positive write.
    writer
        .flush()
        .map_err(|error| failure(accepted, total, StdoutFailureReason::Io(error)))?;
    Ok(accepted)
}

/// Existing arbitrary-Write test seams have no fd and claim no idle bound.
#[cfg(test)]
pub(crate) struct WriterStdout<'a>(pub(crate) &'a mut dyn Write);

#[cfg(test)]
impl FinalStdout for WriterStdout<'_> {
    fn begin_finalization(&mut self) {}

    fn write_document(&mut self, bytes: &[u8]) -> StdoutResult {
        let total = bytes.len();
        let mut accepted = 0;
        while accepted < total {
            let end = accepted + (total - accepted).min(SINK_BUFFER_BYTES);
            match self.0.write(&bytes[accepted..end]) {
                Ok(0) => {
                    return Err(failure(
                        accepted,
                        total,
                        StdoutFailureReason::Io(io::ErrorKind::WriteZero.into()),
                    ));
                }
                Ok(wrote) => accepted += wrote,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(failure(accepted, total, StdoutFailureReason::Io(error))),
            }
        }
        self.0
            .flush()
            .map_err(|error| failure(accepted, total, StdoutFailureReason::Io(error)))?;
        Ok(accepted)
    }
}

#[cfg(test)]
#[path = "inventory_output_tests.rs"]
mod tests;
