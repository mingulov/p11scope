//! SPDX-License-Identifier: GPL-3.0-or-later
//! The bounded-wait-drop stdout sink: a stalled flush waits at most the
//! per-tick budget, then its pending bytes are dropped with counters,
//! never held unboundedly. The capture continues; the evidence says what
//! left through the sink and what did not.

use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

/// Sink buffer size: one 64 KiB batch per tick instead of a syscall per
/// line. Ticks flush, so the first frame and trace lines still land
/// promptly; buffering only coalesces the writes between flushes.
pub(crate) const SINK_BUFFER_BYTES: usize = 65536;

/// Per-tick flush budget shared by every sink write of the tick: a stall
/// past this drops the pending bytes with counters instead of holding
/// the capture loop.
pub(crate) const SINK_TICK_BUDGET: Duration = Duration::from_millis(250);

/// What the bounded-wait-drop window discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct SinkDrops {
    pub(crate) timeouts: u64,
    pub(crate) dropped_bytes: u64,
    pub(crate) stall_ms: u64,
}

/// A `Write` sink with a bounded buffer and a poll-bounded flush: bytes
/// batch up to [`SINK_BUFFER_BYTES`], and every flush waits for
/// writability only within the tick budget opened by [`begin_tick`].
/// A flush that still cannot proceed drops its pending bytes and counts
/// them; only transport errors (broken pipe and friends) propagate.
/// Like `BufWriter`, an errored flush keeps its buffer for the caller to
/// retry or abandon by closing the sink.
///
/// [`begin_tick`]: SinkWriter::begin_tick
pub(crate) struct SinkWriter<W: Write + AsRawFd> {
    inner: W,
    buf: Vec<u8>,
    tick_budget: Duration,
    drops: SinkDrops,
}

impl<W: Write + AsRawFd> SinkWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(SINK_BUFFER_BYTES),
            tick_budget: Duration::ZERO,
            drops: SinkDrops::default(),
        }
    }

    /// Opens the flush budget for a tick. Every flush of the tick draws
    /// from it, so a slow sink stalls a tick by at most `budget` in
    /// total before bytes start dropping with counters.
    pub(crate) fn begin_tick(&mut self, budget: Duration) {
        self.tick_budget = budget;
    }

    /// Drains the drop counters accumulated since the last call.
    pub(crate) fn take_drops(&mut self) -> SinkDrops {
        std::mem::take(&mut self.drops)
    }

    fn flush_bounded(&mut self) -> io::Result<()> {
        let start = Instant::now();
        while !self.buf.is_empty() {
            let remaining = self.tick_budget.saturating_sub(start.elapsed());
            let mut waiting = libc::pollfd {
                fd: self.inner.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let timeout_ms = remaining.as_millis().min(u128::from(i32::MAX as u32)) as i32;
            // SAFETY: `poll` on one valid stack `pollfd` writes only its
            // `revents`; the fd is borrowed, never owned or closed here.
            let ready = unsafe { libc::poll(&mut waiting, 1, timeout_ms) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                self.drops.timeouts = self.drops.timeouts.saturating_add(1);
                self.drops.dropped_bytes = self
                    .drops
                    .dropped_bytes
                    .saturating_add(self.buf.len() as u64);
                self.buf.clear();
                self.tick_budget = Duration::ZERO;
                break;
            }
            // Ready, hung up, or errored: attempt the write and propagate
            // its truth, so a dead peer still surfaces as broken pipe.
            match self.inner.write(&self.buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "sink wrote zero bytes with a non-empty buffer",
                    ));
                }
                Ok(wrote) => {
                    self.buf.drain(..wrote);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    // Re-poll within the remaining budget.
                }
                Err(error) => return Err(error),
            }
        }
        let stalled = start.elapsed();
        self.drops.stall_ms = self
            .drops
            .stall_ms
            .saturating_add(stalled.as_millis().min(u128::from(u64::MAX)) as u64);
        self.tick_budget = self.tick_budget.saturating_sub(stalled);
        self.inner.flush()
    }
}

impl<W: Write + AsRawFd> Write for SinkWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.buf.len() >= SINK_BUFFER_BYTES {
            self.flush_bounded()?;
        }
        self.buf.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_bounded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    #[test]
    fn flush_delivers_bytes_to_a_live_reader() {
        let (writer, mut reader) = pair();
        let mut sink = SinkWriter::new(writer);
        sink.begin_tick(Duration::from_millis(250));

        sink.write_all(b"LOST 3 events\n").unwrap();
        sink.flush().unwrap();

        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut got = vec![0u8; b"LOST 3 events\n".len()];
        reader.read_exact(&mut got).unwrap();
        assert_eq!(got, b"LOST 3 events\n");
        assert_eq!(sink.take_drops(), SinkDrops::default());
    }

    #[test]
    fn stalled_flush_drops_with_counters_past_its_budget() {
        let (writer, reader) = pair();
        // No reader drains: fill the socket buffer, then the bounded flush
        // must time out instead of blocking forever.
        let mut filler = writer.try_clone().unwrap();
        filler.set_nonblocking(true).unwrap();
        let chunk = vec![7u8; 65536];
        while filler.write(&chunk).is_ok() {}
        let mut sink = SinkWriter::new(writer);
        sink.begin_tick(Duration::ZERO);

        sink.write_all(b"stalled frame\n").unwrap();
        sink.flush().unwrap();

        let drops = sink.take_drops();
        assert_eq!(drops.timeouts, 1);
        assert_eq!(drops.dropped_bytes, b"stalled frame\n".len() as u64);
        assert_eq!(sink.take_drops(), SinkDrops::default());
        drop(reader);
    }

    #[test]
    fn writes_past_the_cap_flush_through_a_live_reader() {
        let (writer, mut reader) = pair();
        reader.set_nonblocking(true).unwrap();
        let mut sink = SinkWriter::new(writer);
        sink.begin_tick(Duration::from_secs(30));

        let chunk = vec![9u8; SINK_BUFFER_BYTES * 3];
        sink.write_all(&chunk).unwrap();
        sink.flush().unwrap();

        let mut got = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while got.len() < chunk.len() {
            assert!(std::time::Instant::now() < deadline, "reader starved");
            let mut buf = vec![0u8; 65536];
            match reader.read(&mut buf) {
                Ok(0) => std::thread::sleep(Duration::from_millis(1)),
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("reader failed: {error}"),
            }
        }
        assert_eq!(got, chunk);
        assert_eq!(sink.take_drops(), SinkDrops::default());
    }

    #[test]
    fn broken_pipe_is_an_error_not_a_drop() {
        let (writer, reader) = pair();
        drop(reader);
        let mut sink = SinkWriter::new(writer);
        sink.begin_tick(Duration::from_millis(250));

        sink.write_all(b"no one listens\n").unwrap();
        let error = sink.flush().unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(sink.take_drops(), SinkDrops::default());
    }
}
