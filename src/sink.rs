//! SPDX-License-Identifier: GPL-3.0-or-later
//! The bounded-wait-drop stdout sink: a stalled flush waits at most the
//! per-tick budget, then its pending bytes are dropped with counters,
//! never held unboundedly. The capture continues; the evidence says what
//! left through the sink and what did not.

use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt as _;
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

/// What `stdout_sink` writes through: unbuffered, so every byte passes
/// through the poll bound. (A buffered inner would park bytes past the
/// poll loop and its EAGAIN would escape as a hard error.)
///
/// Every variant leaves the shared open file description's status flags
/// alone (F-11): the owned child inherits fd 1's description, so a sink
/// that flips `O_NONBLOCK` on it flips the child's writes to EAGAIN
/// under backpressure — and a second `dup` cannot provide isolation,
/// because `dup` aliases the description.
pub(crate) enum StdoutInner {
    /// A pipe or terminal reopened as a private description (whose own
    /// flags the sink may set), or a shared regular file or block device
    /// (whose kernel I/O is not bounded by O_NONBLOCK).
    File(std::fs::File),
    /// A shared socket, written with per-call `MSG_DONTWAIT`, so no flag
    /// change is needed either.
    Socket(SocketWriter),
}

impl Write for StdoutInner {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            StdoutInner::File(file) => file.write(bytes),
            StdoutInner::Socket(socket) => socket.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            StdoutInner::File(file) => file.flush(),
            StdoutInner::Socket(socket) => socket.flush(),
        }
    }
}

impl AsRawFd for StdoutInner {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            StdoutInner::File(file) => file.as_raw_fd(),
            StdoutInner::Socket(socket) => socket.as_raw_fd(),
        }
    }
}

/// A socket stdout that never changes shared status flags: every write
/// is one `send` with `MSG_DONTWAIT`, giving the bounded flush its
/// nonblocking writes without touching the description the owned child
/// shares. `MSG_NOSIGNAL` keeps a dead peer as EPIPE, not SIGPIPE.
pub(crate) struct SocketWriter {
    fd: OwnedFd,
}

impl SocketWriter {
    fn new(fd: OwnedFd) -> Self {
        Self { fd }
    }
}

impl Write for SocketWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // SAFETY: `send` reads `bytes` only; the fd is owned and open.
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsRawFd for SocketWriter {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Production's stdout sink: [`stdout_sink_from`] on fd 1.
pub(crate) fn stdout_sink() -> io::Result<SinkWriter<StdoutInner>> {
    stdout_sink_from(std::io::stdout().as_raw_fd())
}

/// The same sink over any writer fd (the dashboard passes its stderr):
/// bounded diagnostic lines next to an interactive view, whose terminal
/// may be the stalled one (C5.3).
pub(crate) fn sink_on_fd(fd: RawFd) -> io::Result<SinkWriter<StdoutInner>> {
    stdout_sink_from(fd)
}

/// Best-effort diagnostics: use existing descriptor-safe transports and
/// immediate nonblocking writes. A full pipe/socket must not delay cleanup.
/// Callers must not treat a missing diagnostic as a successful measurement.
pub(crate) fn try_stderr_line(line: &str) -> io::Result<SinkDrops> {
    try_diagnostic_line_on_fd(std::io::stderr().as_raw_fd(), line)
}

fn try_diagnostic_line_on_fd(fd: RawFd, line: &str) -> io::Result<SinkDrops> {
    let mut sink = stdout_sink_from(fd)?;
    writeln!(sink, "{line}")?;
    sink.abort_wait()?;
    Ok(sink.take_drops())
}

/// Builds the stdout sink for any writer fd (production passes fd 1),
/// dispatching on file type so the shared description's status flags
/// are never changed: pipes and terminals are reopened as private
/// descriptions, sockets use per-call nonblocking sends, and regular
/// files are shared without any flag change. Sharing keeps the observer's
/// and child's file offsets advancing together; filesystem and block-device
/// calls can still wait inside the kernel regardless of O_NONBLOCK.
fn stdout_sink_from(fd: RawFd) -> io::Result<SinkWriter<StdoutInner>> {
    Ok(SinkWriter::without_flag_change(stdout_transport_on_fd(fd)?))
}

/// Acquires the unbuffered transport without mutating inherited status flags.
/// A failed private reopen is an error; there is no blocking fallback.
pub(crate) fn stdout_transport_on_fd(fd: RawFd) -> io::Result<StdoutInner> {
    stdout_transport_with_reopen(fd, |fd| {
        std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{fd}"))
    })
}

fn stdout_transport_with_reopen(
    fd: RawFd,
    reopen: impl FnOnce(RawFd) -> io::Result<std::fs::File>,
) -> io::Result<StdoutInner> {
    // SAFETY: `fstat` only reads the fd's metadata.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &raw mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFIFO | libc::S_IFCHR => {
            // A fresh description with its own flags: opening
            // `/proc/self/fd/N` re-opens the pipe or device instead of
            // aliasing the description the way `dup` does.
            // `O_NONBLOCK` at open so a readerless FIFO fails instead of
            // blocking the observer here.
            Ok(StdoutInner::File(reopen(fd)?))
        }
        libc::S_IFSOCK => {
            let duped = dup_cloexec(fd)?;
            Ok(StdoutInner::Socket(SocketWriter::new(duped)))
        }
        libc::S_IFREG | libc::S_IFBLK => {
            use std::os::fd::FromRawFd as _;
            let file = unsafe { std::fs::File::from_raw_fd(dup_cloexec(fd)?.into_raw_fd()) };
            Ok(StdoutInner::File(file))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "stdout has unsupported file type {other:#o}; refusing to risk blocking the \
                 capture or changing shared open-file status flags"
            ),
        )),
    }
}

#[cfg(test)]
pub(crate) fn test_transport_with_reopen(
    fd: RawFd,
    reopen: impl FnOnce(RawFd) -> io::Result<std::fs::File>,
) -> io::Result<StdoutInner> {
    stdout_transport_with_reopen(fd, reopen)
}

/// `dup` with `CLOEXEC`: the sink fd must not leak into owned children.
fn dup_cloexec(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `F_DUPFD_CLOEXEC` returns a fresh owned fd, or -1.
    let duped = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duped < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fcntl` returned a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duped) })
}

impl<W: Write + AsRawFd> SinkWriter<W> {
    /// Marks the fd nonblocking, so the poll bound actually binds: a
    /// blocking write past a poll-ready notification would trickle an
    /// unbounded stall (E-slow-sink: one flush held the drain thread
    /// 28.7s and bled 13707 ring records). Fails closed: without the
    /// flag the tick budget cannot be honored. The caller grants flag
    /// ownership: never call this on a description whose flags are
    /// shared (F-11) — use [`without_flag_change`](Self::without_flag_change).
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
        Ok(Self::without_flag_change(inner))
    }

    /// Wraps an acquired transport without touching its status flags. Private
    /// descriptions and per-call socket flags bound ordinary backpressure;
    /// regular-file/block-device writes can still wait in the kernel and
    /// ignore O_NONBLOCK, so setting that flag would not add a latency bound.
    pub(crate) fn without_flag_change(inner: W) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(SINK_BUFFER_BYTES),
            tick_budget: Duration::ZERO,
            drops: SinkDrops::default(),
            cancel: None,
        }
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

    #[test]
    fn diagnostic_line_reaches_a_ready_reader_without_waiting() {
        let (writer, mut reader) = pair();
        reader
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let drops = try_diagnostic_line_on_fd(writer.as_raw_fd(), "diagnostic").unwrap();
        let mut received = [0; 11];
        reader.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"diagnostic\n");
        assert_eq!(drops, SinkDrops::default());
    }

    #[test]
    fn diagnostic_line_sheds_a_stalled_sink_without_changing_shared_flags() {
        let (writer, _reader) = pair();
        let mut filler = writer.try_clone().unwrap();
        filler.set_nonblocking(true).unwrap();
        while filler.write(&[7; 65536]).is_ok() {}
        filler.set_nonblocking(false).unwrap();
        let started = Instant::now();
        let drops = try_diagnostic_line_on_fd(writer.as_raw_fd(), "diagnostic").unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(drops.dropped_bytes, 11);
        assert_eq!(drops.timeouts, 1);
        // SAFETY: querying flags on our still-owned socket.
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
    }

    #[test]
    fn diagnostic_line_returns_closed_sink_errors_without_panicking() {
        let (writer, reader) = pair();
        drop(reader);
        assert!(try_diagnostic_line_on_fd(writer.as_raw_fd(), "diagnostic").is_err());
    }

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

    /// F-11: the owned child inherits fd 1's open file description, so a
    /// sink that flips O_NONBLOCK on the shared description flips the
    /// child's writes to EAGAIN under backpressure — and a second `dup`
    /// cannot provide isolation, because `dup` aliases the description.
    /// The sink must leave the shared description's status flags alone.
    fn description_flags(fd: std::os::fd::RawFd) -> libc::c_int {
        // SAFETY: the test owns every fd it reads here.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0, "fcntl F_GETFL failed");
        flags
    }

    fn pipe_files() -> (std::fs::File, std::fs::File) {
        use std::os::fd::FromRawFd as _;
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: `pipe` succeeded, so both fds are open and owned here.
        unsafe {
            (
                std::fs::File::from_raw_fd(fds[0]),
                std::fs::File::from_raw_fd(fds[1]),
            )
        }
    }

    #[test]
    fn stdout_sink_from_a_pipe_leaves_the_shared_description_blocking() {
        let (mut reader, writer) = pipe_files();
        // The sibling shares the description the way an owned child's
        // inherited fd 1 does.
        let sibling = writer.try_clone().unwrap();
        let mut sink = stdout_sink_from(writer.as_raw_fd()).unwrap();
        assert_eq!(
            description_flags(sibling.as_raw_fd()) & libc::O_NONBLOCK,
            0,
            "the sink changed the shared description's status flags"
        );
        // The sink itself still delivers through the poll bound.
        sink.begin_tick(Duration::from_millis(250));
        sink.write_all(b"pipe bytes\n").unwrap();
        sink.flush().unwrap();
        let mut got = vec![0u8; b"pipe bytes\n".len()];
        reader.read_exact(&mut got).unwrap();
        assert_eq!(got, b"pipe bytes\n");
        assert_eq!(sink.take_drops(), SinkDrops::default());
    }

    #[test]
    fn stdout_sink_from_a_socket_leaves_the_shared_description_blocking() {
        let (writer, mut reader) = pair();
        let sibling = writer.try_clone().unwrap();
        let mut sink = stdout_sink_from(writer.as_raw_fd()).unwrap();
        assert_eq!(
            description_flags(sibling.as_raw_fd()) & libc::O_NONBLOCK,
            0,
            "the sink changed the shared description's status flags"
        );
        sink.begin_tick(Duration::from_millis(250));
        sink.write_all(b"socket bytes\n").unwrap();
        sink.flush().unwrap();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut got = vec![0u8; b"socket bytes\n".len()];
        reader.read_exact(&mut got).unwrap();
        assert_eq!(got, b"socket bytes\n");
        assert_eq!(sink.take_drops(), SinkDrops::default());
    }

    #[test]
    fn stdout_sink_from_a_file_leaves_the_shared_description_alone() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let sibling = file.as_file().try_clone().unwrap();
        let before = description_flags(sibling.as_raw_fd());
        let mut sink = stdout_sink_from(file.as_raw_fd()).unwrap();
        assert_eq!(
            description_flags(sibling.as_raw_fd()),
            before,
            "the sink changed the shared description's status flags"
        );
        sink.begin_tick(Duration::from_millis(250));
        sink.write_all(b"file bytes\n").unwrap();
        sink.flush().unwrap();
        assert_eq!(sink.take_drops(), SinkDrops::default());
        let landed = std::fs::read(file.path()).unwrap();
        assert_eq!(landed, b"file bytes\n");
    }

    #[test]
    fn stdout_sink_is_unbuffered_by_construction() {
        // The poll bound can only meter bytes it can see: a buffered
        // inner (StdoutLock's LineWriter) parks bytes past the poll
        // loop, and its EAGAIN escapes as a hard error that kills the
        // observer (E-slow-sink rerun: "flushing stdout: Resource
        // temporarily unavailable"). Production's constructor returns
        // the raw-fd enum, unbuffered; this pins the type at compile time.
        fn assert_raw_inner(_: &SinkWriter<StdoutInner>) {}
        let mut sink = stdout_sink().unwrap();
        assert_raw_inner(&sink);
        assert_eq!(sink.take_drops(), SinkDrops::default());
    }

    #[test]
    fn the_reopened_pipe_sink_binds_its_own_private_description() {
        // The other half of the F-11 contract: the sink's own pipe fd
        // carries O_NONBLOCK (the poll bound binds), while the shared
        // description it was reopened from stays blocking.
        let (_reader, writer) = pipe_files();
        let sibling = writer.try_clone().unwrap();
        let sink = stdout_sink_from(writer.as_raw_fd()).unwrap();
        assert_ne!(
            description_flags(sink.inner.as_raw_fd()) & libc::O_NONBLOCK,
            0,
            "the sink's private description must be nonblocking"
        );
        assert_eq!(
            description_flags(sibling.as_raw_fd()) & libc::O_NONBLOCK,
            0,
            "the shared description must stay blocking"
        );
    }

    #[test]
    fn the_socket_sink_uses_per_call_flags_not_fd_flags() {
        // Documents the socket design: neither the sink's dup nor the
        // shared description carries O_NONBLOCK, because every write is
        // a MSG_DONTWAIT send.
        let (writer, _reader) = pair();
        let sibling = writer.try_clone().unwrap();
        let sink = stdout_sink_from(writer.as_raw_fd()).unwrap();
        assert!(matches!(sink.inner, StdoutInner::Socket(_)));
        assert_eq!(
            description_flags(sink.inner.as_raw_fd()) & libc::O_NONBLOCK,
            0
        );
        assert_eq!(description_flags(sibling.as_raw_fd()) & libc::O_NONBLOCK, 0);
    }

    #[test]
    fn a_dead_socket_peer_is_an_error_not_a_drop() {
        // The socket path keeps broken-pipe semantics: MSG_NOSIGNAL
        // turns the dead peer into EPIPE, which propagates instead of
        // counting as a drop.
        let (writer, reader) = pair();
        drop(reader);
        let mut sink = stdout_sink_from(writer.as_raw_fd()).unwrap();
        sink.begin_tick(Duration::from_millis(250));
        sink.write_all(b"no one listens\n").unwrap();
        let error = sink.flush().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
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
