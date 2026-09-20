//! SPDX-License-Identifier: GPL-3.0-or-later
//! The bounded-wait-drop stdout sink: a stalled flush waits at most the
//! per-tick budget, then its pending bytes are dropped with counters,
//! never held unboundedly. The capture continues; the evidence says what
//! left through the sink and what did not.

use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

/// Sink buffer size: one 64 KiB batch per tick instead of a syscall per
/// line. Ticks flush, so the first frame and trace lines still land
/// promptly; buffering only coalesces the writes between flushes.
pub(crate) const SINK_BUFFER_BYTES: usize = 65536;

/// Per-tick flush budget shared by every sink write of the tick: a stall
/// past this drops the pending bytes with counters instead of holding
/// the capture loop.
pub(crate) const SINK_TICK_BUDGET: Duration = Duration::from_millis(250);

/// Longest one `poll` wait inside a bounded flush. The tick budget is
/// unchanged — slices of at most this draw from it — but cancellation
/// is consulted on every interruption and between slices, so a pending
/// cancel sheds promptly instead of riding out the whole budget (F4: a
/// single 250ms poll held 232ms past SIGINT by retrying the
/// interruption without consulting cancellation). Sized so one slice
/// plus the loop-exit marker stays well under the 100ms cancel budget
/// even where the wait runs to its slice end.
pub(crate) const SINK_POLL_SLICE: Duration = Duration::from_millis(25);

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
    cancel: Option<Arc<AtomicBool>>,
}

/// Production's stdout sink: a dup'd raw fd, unbuffered, so every byte
/// passes through the poll bound. (A buffered inner would park bytes
/// past the poll loop and its EAGAIN would escape as a hard error.)
/// The dup shares the open file description with fd 1, so fd 1 itself
/// becomes nonblocking too; nothing else in the observer writes
/// stdout directly (diagnostics use stderr).
pub(crate) fn stdout_sink() -> io::Result<SinkWriter<std::fs::File>> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe { libc::dup(std::io::stdout().as_raw_fd()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `dup` succeeded, so the new fd is open and owned here.
    SinkWriter::new(unsafe { std::fs::File::from_raw_fd(fd) })
}

impl<W: Write + AsRawFd> SinkWriter<W> {
    /// Marks the fd nonblocking, so the poll bound actually binds: a
    /// blocking write past a poll-ready notification would trickle an
    /// unbounded stall (E-slow-sink: one flush held the drain thread
    /// 28.7s and bled 13707 ring records). Regular files and /dev/null
    /// ignore the flag. Fails closed: without the flag the tick budget
    /// cannot be honored.
    pub(crate) fn new(inner: W) -> io::Result<Self> {
        // SAFETY: fcntl flag reads/writes touch only the fd's own flags.
        let flags = unsafe { libc::fcntl(inner.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: same fd; OR-ing O_NONBLOCK preserves the other flags.
        if unsafe { libc::fcntl(inner.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            inner,
            buf: Vec::with_capacity(SINK_BUFFER_BYTES),
            tick_budget: Duration::ZERO,
            drops: SinkDrops::default(),
            cancel: None,
        })
    }

    /// Opens the flush budget for a tick. Every flush of the tick draws
    /// from it, so a slow sink stalls a tick by at most `budget` in
    /// total before bytes start dropping with counters.
    pub(crate) fn begin_tick(&mut self, budget: Duration) {
        self.tick_budget = budget;
    }

    /// Watches the capture's cancellation flag: a flush that sees it set
    /// stops waiting and sheds promptly (F4) instead of riding out the
    /// tick budget. Unset (unit-test default), flushes keep the legacy
    /// wait-out-the-budget behavior.
    pub(crate) fn set_cancel_flag(&mut self, cancel: Arc<AtomicBool>) {
        self.cancel = Some(cancel);
    }

    fn cancelled(&self) -> bool {
        self.cancel
            .as_deref()
            .is_some_and(|cancel| cancel.load(Ordering::SeqCst))
    }

    /// Drains the drop counters accumulated since the last call.
    pub(crate) fn take_drops(&mut self) -> SinkDrops {
        std::mem::take(&mut self.drops)
    }

    /// Drops the pending buffer with counters: the slow-sink policy's
    /// explicit shed, never a silent stall.
    fn drop_pending(&mut self) {
        self.drops.timeouts = self.drops.timeouts.saturating_add(1);
        self.drops.dropped_bytes = self
            .drops
            .dropped_bytes
            .saturating_add(self.buf.len() as u64);
        self.buf.clear();
        self.tick_budget = Duration::ZERO;
    }

    /// Prompt cancel shed: no waiting at all — nonblocking writes take
    /// whatever room the reader already offers, then whatever remains is
    /// dropped with the standard counters. Every pending byte is either
    /// delivered or counted; none is silently held, and the flush
    /// returns without consulting the tick budget. Only transport
    /// errors propagate, as in the bounded path.
    fn abort_wait(&mut self) -> io::Result<()> {
        while !self.buf.is_empty() {
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
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    // No room right now (or a stray signal): shed the
                    // rest with counters rather than waiting for room.
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if !self.buf.is_empty() {
            self.drop_pending();
        }
        Ok(())
    }

    fn flush_bounded(&mut self) -> io::Result<()> {
        let start = Instant::now();
        while !self.buf.is_empty() {
            if self.cancelled() {
                self.abort_wait()?;
                break;
            }
            let remaining = self.tick_budget.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                // Budget spent: a trickling reader would otherwise keep
                // re-arming poll(0) on each freed page, stretching this
                // flush reader-paced instead of budget-paced. Drop.
                self.drop_pending();
                break;
            }
            let mut waiting = libc::pollfd {
                fd: self.inner.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // Sliced, not one wait: cancellation is consulted between
            // slices (see SINK_POLL_SLICE). Slices draw from the same
            // tick budget, so the drop policy is unchanged.
            let slice = remaining.min(SINK_POLL_SLICE);
            let timeout_ms = slice.as_millis().min(u128::from(i32::MAX as u32)) as i32;
            // SAFETY: `poll` on one valid stack `pollfd` writes only its
            // `revents`; the fd is borrowed, never owned or closed here.
            let ready = unsafe { libc::poll(&mut waiting, 1, timeout_ms) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    // A signal cut the slice short: the top of the loop
                    // consults cancellation before re-polling, so an
                    // interrupting cancel sheds instead of retrying.
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                // One slice spent, not the budget: re-check cancellation
                // and the remaining budget at the top of the loop. Only
                // a spent budget drops.
                continue;
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
        let mut sink = SinkWriter::new(writer).unwrap();
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
        let mut sink = SinkWriter::new(writer).unwrap();
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
        let mut sink = SinkWriter::new(writer).unwrap();
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
    fn partial_space_does_not_block_past_the_budget() {
        use std::os::fd::{AsRawFd, FromRawFd};
        // A pipe, like the slow-pipe sink: POLLOUT fires on ANY free
        // space (unix sockets wait for a substantially drained buffer,
        // which would only re-test the timeout path). Fill it, free a
        // single trickle, then flush a full buffer against a reader
        // that only trickles: every freed byte re-arms poll and a
        // blocking write trickles the whole buffer. The bounded flush
        // must time out and drop instead (E-slow-sink: trickle-flushes
        // stalled 28.7s past the budget and bled 13707 ring records).
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: `pipe` succeeded, so both fds are open and owned here.
        let mut reader = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        // SAFETY: same pipe; the write end is open and owned here.
        let mut writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        set_blocking(writer.as_raw_fd(), false);
        let chunk = vec![7u8; 65536];
        while writer.write(&chunk).is_ok() {}
        set_blocking(writer.as_raw_fd(), true);
        // Free a whole page: pipes gate POLLOUT on page slots, not
        // bytes, so poll fires and a blocking write proceeds into the
        // trickle instead of timing out up front.
        let mut trickle = vec![0u8; 4096];
        reader.read_exact(&mut trickle).unwrap();
        // A continuously trickling reader, like the 4 KB/s slow-pipe:
        // every freed byte re-arms poll, so a bound-defying flush
        // trickles the whole buffer instead of timing out.
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_reader = stop.clone();
        let reader_thread = std::thread::spawn(move || {
            use std::os::fd::AsRawFd as _;
            set_blocking(reader.as_raw_fd(), false);
            let mut buf = vec![0u8; 100];
            while !stop_reader.load(std::sync::atomic::Ordering::Relaxed) {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => std::thread::sleep(Duration::from_millis(10)),
                    Err(_) => std::thread::sleep(Duration::from_millis(1)),
                }
            }
        });

        let mut sink = SinkWriter::new(writer).unwrap();
        sink.begin_tick(Duration::from_millis(20));
        sink.write_all(&vec![8u8; SINK_BUFFER_BYTES]).unwrap();
        let start = Instant::now();
        sink.flush().unwrap();
        let elapsed = start.elapsed();
        let drops = sink.take_drops();
        drop(sink);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        reader_thread.join().unwrap();

        assert_eq!(
            drops.timeouts, 1,
            "flush waited out the stall instead of dropping"
        );
        assert!(drops.dropped_bytes > 0, "stall dropped no bytes");
        assert!(
            elapsed < Duration::from_millis(150),
            "flush blocked {elapsed:?} past its 20ms budget"
        );
    }

    #[cfg(test)]
    fn set_blocking(fd: std::os::fd::RawFd, blocking: bool) {
        // SAFETY: fd is an open pipe end owned by the test.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0);
        let flags = if blocking {
            flags & !libc::O_NONBLOCK
        } else {
            flags | libc::O_NONBLOCK
        };
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) }, 0);
    }

    #[test]
    fn stdout_sink_is_unbuffered_by_construction() {
        // The poll bound can only meter bytes it can see: a buffered
        // inner (StdoutLock's LineWriter) parks bytes past the poll
        // loop, and its EAGAIN escapes as a hard error that kills the
        // observer (E-slow-sink rerun: "flushing stdout: Resource
        // temporarily unavailable"). Production's constructor returns
        // a raw File, unbuffered; this pins the type at compile time.
        fn assert_raw_file(_: &SinkWriter<std::fs::File>) {}
        let mut sink = stdout_sink().unwrap();
        assert_raw_file(&sink);
        assert_eq!(sink.take_drops(), SinkDrops::default());
    }

    /// Fills the socket buffer behind `writer`'s back, so the sink's
    /// flush finds no room and must wait out its budget (or abort on
    /// cancellation). Returns the payload the test offered the sink.
    fn stalled_sink_with(
        budget: Duration,
        cancel: Option<Arc<AtomicBool>>,
    ) -> (SinkWriter<UnixStream>, UnixStream, Vec<u8>) {
        let (writer, reader) = pair();
        let mut filler = writer.try_clone().unwrap();
        filler.set_nonblocking(true).unwrap();
        let chunk = vec![7u8; 65536];
        while filler.write(&chunk).is_ok() {}
        drop(filler);
        let mut sink = SinkWriter::new(writer).unwrap();
        if let Some(cancel) = cancel {
            sink.set_cancel_flag(cancel);
        }
        sink.begin_tick(budget);
        let payload = vec![8u8; 4096];
        sink.write_all(&payload).unwrap();
        (sink, reader, payload)
    }

    #[test]
    fn stalled_flush_without_cancel_waits_out_its_budget() {
        // Control for the cancel test below: unwatched, the same stalled
        // flush rides out the whole budget before dropping. (Sliced
        // polls draw from the same budget, so the drop policy is
        // unchanged.)
        let (mut sink, _reader, payload) = stalled_sink_with(Duration::from_millis(250), None);
        let start = Instant::now();
        sink.flush().unwrap();
        let elapsed = start.elapsed();
        let drops = sink.take_drops();
        assert!(
            elapsed >= Duration::from_millis(200),
            "fixture did not stall: flush returned in {elapsed:?}"
        );
        assert_eq!(drops.timeouts, 1);
        assert_eq!(drops.dropped_bytes, payload.len() as u64);
    }

    #[test]
    fn cancel_flag_aborts_a_stalled_flush_promptly_with_counters() {
        // F4: SIGINT during a slow-sink flush held 232ms past the signal
        // (one 250ms poll retried past the interruption). With the flag
        // watched, the flush sheds on the interruption, or at worst at
        // the next slice end.
        let cancel = Arc::new(AtomicBool::new(false));
        let (mut sink, _reader, payload) =
            stalled_sink_with(Duration::from_millis(250), Some(Arc::clone(&cancel)));
        let setter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            let set = Instant::now();
            cancel.store(true, Ordering::SeqCst);
            set
        });
        sink.flush().unwrap();
        let returned = Instant::now();
        let set = setter.join().unwrap();
        // Saturating: if the setter thread itself stalls past the flush,
        // the bound holds trivially instead of flaking.
        let after_set = returned.saturating_duration_since(set);
        assert!(
            after_set < Duration::from_millis(150),
            "cancel abort took {after_set:?} after the flag (budget 250ms)"
        );
        let drops = sink.take_drops();
        assert_eq!(drops.timeouts, 1);
        assert_eq!(drops.dropped_bytes, payload.len() as u64);
    }

    #[test]
    fn cancel_with_room_available_delivers_instead_of_dropping() {
        // The prompt shed is not a blind drop: bytes the reader already
        // has room for still leave, so a fast-sink cancel stays lossless.
        let (writer, mut reader) = pair();
        let cancel = Arc::new(AtomicBool::new(true));
        let mut sink = SinkWriter::new(writer).unwrap();
        sink.set_cancel_flag(cancel);
        sink.begin_tick(Duration::from_millis(250));
        sink.write_all(b"late trace bytes\n").unwrap();
        sink.flush().unwrap();
        assert_eq!(sink.take_drops(), SinkDrops::default());
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut got = vec![0u8; b"late trace bytes\n".len()];
        reader.read_exact(&mut got).unwrap();
        assert_eq!(got, b"late trace bytes\n");
    }

    #[test]
    fn broken_pipe_is_an_error_not_a_drop() {
        let (writer, reader) = pair();
        drop(reader);
        let mut sink = SinkWriter::new(writer).unwrap();
        sink.begin_tick(Duration::from_millis(250));

        sink.write_all(b"no one listens\n").unwrap();
        let error = sink.flush().unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(sink.take_drops(), SinkDrops::default());
    }
}
