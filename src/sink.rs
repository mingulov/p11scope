//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! The bounded-wait-drop stdout sink: a stalled flush waits at most the
//! per-tick budget, then its pending bytes are dropped with counters,
//! never held unboundedly. The capture continues; the evidence says what
//! left through the sink and what did not.

use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::sync::{
    Arc, OnceLock,
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

/// A closed capture stdout: the degraded sink a capture holds when fd 1
/// is unusable at capture start, so the run continues (other transports
/// still publish) instead of aborting before settlement. Callers start
/// closed and never write through it, but a write is safe: bytes go to
/// `/dev/null`.
pub(crate) fn null_sink() -> io::Result<SinkWriter<StdoutInner>> {
    let null = std::fs::OpenOptions::new().write(true).open("/dev/null")?;
    Ok(SinkWriter::without_flag_change(StdoutInner::File(null)))
}

/// Best-effort diagnostics: use existing descriptor-safe transports and
/// immediate nonblocking writes. A full pipe/socket must not delay cleanup.
/// Callers must not treat a missing diagnostic as a successful measurement.
pub(crate) fn try_stderr_line(line: &str) -> io::Result<SinkDrops> {
    try_diagnostic_line_on_fd(std::io::stderr().as_raw_fd(), line)
}

/// Best-effort diagnostics without the trailing newline (the bounded
/// `eprint!`): the same no-wait delivery as [`try_stderr_line`], bytes
/// verbatim. Retained without current production callers so the shadow
/// stays complete: a future `eprint!` must shed like every other
/// diagnostic, never reintroduce a blocking write.
/// The F3 shape test pins the macro on this helper.
#[allow(dead_code)]
pub(crate) fn try_stderr_text(text: &str) -> io::Result<SinkDrops> {
    try_diagnostic_bytes_on_fd(std::io::stderr().as_raw_fd(), text.as_bytes())
}

fn try_diagnostic_line_on_fd(fd: RawFd, line: &str) -> io::Result<SinkDrops> {
    let mut owned = Vec::with_capacity(line.len() + 1);
    owned.extend_from_slice(line.as_bytes());
    owned.push(b'\n');
    try_diagnostic_bytes_on_fd(fd, &owned)
}

/// One diagnostic's bytes on any writer fd, written at once without ever
/// waiting: the transport takes what it takes now and the unsent tail
/// sheds with the standard counters. Only transport errors propagate.
fn try_diagnostic_bytes_on_fd(fd: RawFd, bytes: &[u8]) -> io::Result<SinkDrops> {
    try_diagnostic_bytes_with_reopen(fd, bytes, proc_self_fd_reopen)
}

/// [`try_diagnostic_bytes_on_fd`] with an injectable reopen (tests pass an
/// `EACCES` denial to model the shed boundary; production reopens
/// `/proc/self/fd/N`). The borrow dispatch is production's own.
fn try_diagnostic_bytes_with_reopen(
    fd: RawFd,
    bytes: &[u8],
    reopen: impl FnOnce(RawFd) -> io::Result<std::fs::File>,
) -> io::Result<SinkDrops> {
    match stdout_sink_with_reopen(fd, reopen) {
        Ok(mut sink) => {
            sink.write_diagnostic_bytes(bytes)?;
            Ok(sink.take_drops())
        }
        // No fresh descriptor (EMFILE/ENFILE): borrow a suitable
        // existing transport for the immediate write instead of losing
        // the diagnostic. Unsuitable types (a blocking pipe with no
        // preserved channel) keep the original error, which callers drop.
        Err(error) if is_fd_exhaustion(&error) => match borrowed_diagnostic_transport(fd) {
            Some(borrowed) => write_borrowed_diagnostic(borrowed, bytes),
            None => Err(error),
        },
        Err(error) => Err(error),
    }
}

/// A no-wait stderr `Write` for drivers that own their own text (detach
/// progress, doctor probes): the raw transport takes what it takes now —
/// pipes and sockets never wait, files write through the page cache —
/// and a transport that cannot be opened sheds every line to the sink.
/// Write errors are immediate (a full pipe fails fast); callers drop
/// them, so diagnostics never fail or stall the driver. Unlike
/// [`SinkWriter`], this never polls and never holds bytes past the call.
pub(crate) fn bounded_stderr_writer() -> Box<dyn Write> {
    bounded_writer_on_fd(std::io::stderr().as_raw_fd())
}

/// [`bounded_stderr_writer`] over any writer fd (tests pass their pipe).
pub(crate) fn bounded_writer_on_fd(fd: RawFd) -> Box<dyn Write> {
    bounded_writer_with_reopen(fd, proc_self_fd_reopen)
}

/// [`bounded_writer_on_fd`] with an injectable reopen (tests pass an
/// `EACCES` denial; production reopens `/proc/self/fd/N`). The borrow
/// dispatch is production's own.
fn bounded_writer_with_reopen(
    fd: RawFd,
    reopen: impl FnOnce(RawFd) -> io::Result<std::fs::File>,
) -> Box<dyn Write> {
    match stdout_transport_with_reopen(fd, reopen) {
        Ok(writer) => Box::new(writer),
        // Same exhausted-descriptor borrow as the one-shot diagnostic
        // path: a suitable existing transport writes immediately,
        // unsuitable types shed to the sink as before.
        Err(error) if is_fd_exhaustion(&error) => match borrowed_diagnostic_transport(fd) {
            Some(BorrowedDiagnostic::File(raw)) => Box::new(BorrowedDiagnosticWriter {
                fd: raw,
                socket: false,
            }),
            Some(BorrowedDiagnostic::Socket(raw)) => Box::new(BorrowedDiagnosticWriter {
                fd: raw,
                socket: true,
            }),
            None => Box::new(std::io::sink()),
        },
        Err(_) => Box::new(std::io::sink()),
    }
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

/// [`stdout_sink_from`] with an injectable reopen (see
/// [`try_diagnostic_bytes_with_reopen`]).
fn stdout_sink_with_reopen(
    fd: RawFd,
    reopen: impl FnOnce(RawFd) -> io::Result<std::fs::File>,
) -> io::Result<SinkWriter<StdoutInner>> {
    Ok(SinkWriter::without_flag_change(
        stdout_transport_with_reopen(fd, reopen)?,
    ))
}

/// The production `/proc/self/fd/N` reopen: a fresh description with its
/// own flags (`O_NONBLOCK`, so a readerless FIFO fails instead of
/// blocking; `O_CLOEXEC`, so it never reaches an owned child).
fn proc_self_fd_reopen(fd: RawFd) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{fd}"))
}

/// A saved stdio file plus the identity of the fd it was saved from
/// (`st_dev`/`st_ino`): the dashboard's stderr capture replaces fd 2
/// with its own pipe, so the copy is only valid while the fd still
/// names the same file.
struct PreservedFd {
    file: std::fs::File,
    dev: u64,
    ino: u64,
}

/// Private stdout/stderr descriptions preserved before the startup
/// capability shed: under `sudo … | cat` (or a user-owned terminal with
/// old sudo) fds 1 and 2 are pipes the invoking user owns, while the
/// observer shed `CAP_DAC_OVERRIDE` at startup — so a later
/// `/proc/self/fd/N` reopen fails EACCES. Opening the private
/// descriptions once, while the full grant still holds, needs no extra
/// capability for the run. The files stay open for the process's life;
/// every transport clones them instead of reopening, while its fd still
/// names the saved file (see [`preserved_stdio_file`]).
struct PreservedStdio {
    stdout: Option<PreservedFd>,
    stderr: Option<PreservedFd>,
}

static PRESERVED_STDIO: OnceLock<PreservedStdio> = OnceLock::new();

/// Opens a private description of `fd` when it is a FIFO or terminal,
/// the same open the transports use (`O_NONBLOCK`, so a readerless
/// FIFO fails instead of blocking the observer here; `O_CLOEXEC`, so
/// the preserved files never reach an owned child across exec).
/// Anything else — not a FIFO/terminal, or an open that fails — is
/// `None`, and the transports keep their reopen fallback.
fn private_description(fd: RawFd) -> Option<PreservedFd> {
    // SAFETY: `fstat` only reads the fd's metadata.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &raw mut stat) } != 0 {
        return None;
    }
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFIFO | libc::S_IFCHR => {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
                .open(format!("/proc/self/fd/{fd}"))
                .ok()?;
            // SAFETY: `fstat` only reads the saved file's metadata.
            let mut saved: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(file.as_raw_fd(), &raw mut saved) } != 0 {
                return None;
            }
            Some(PreservedFd {
                file,
                dev: saved.st_dev as u64,
                ino: saved.st_ino as u64,
            })
        }
        _ => None,
    }
}

/// Preserves the private stdout/stderr descriptions for the shed run.
/// Call once, before the startup capability drop: afterwards a reopen
/// of an invoker-owned pipe or terminal fails EACCES. Best-effort: a
/// fd that is not a FIFO/terminal, or whose open fails (a readerless
/// FIFO fails ENXIO here as it would at first write), simply has no
/// preserved file, and the transports fall back to their reopen.
pub(crate) fn preserve_stdio_private_descriptions() {
    PRESERVED_STDIO.get_or_init(|| PreservedStdio {
        stdout: private_description(1),
        stderr: private_description(2),
    });
}

/// A preserved private description for `fd` (1 or 2) when one exists
/// **and the fd still names the saved file**: a `try_clone` of the
/// startup file, so no reopen — and no extra capability — is needed
/// to write the observer's own stdio. When the fd was replaced after
/// the save (the dashboard's capture pipe takes over fd 2), there is
/// no preserved file and the transports fall back to their reopen —
/// the replacement is ours, so it needs no capability either.
pub(crate) fn preserved_stdio_file(fd: RawFd) -> Option<std::fs::File> {
    match preserved_stdio_clone(fd) {
        PreservedClone::Cloned(file) => Some(file),
        PreservedClone::Missing | PreservedClone::CloneFailed(_) => None,
    }
}

/// What cloning the preserved description yields: a missing or replaced
/// file is [`PreservedClone::Missing`] (fall back to the reopen); a
/// failed clone keeps its error so exhaustion (`EMFILE`/`ENFILE`) is not
/// masked by a later reopen denial (`EACCES` after the shed).
enum PreservedClone {
    Missing,
    Cloned(std::fs::File),
    CloneFailed(io::Error),
}

/// Clones the preserved private description for `fd` (1 or 2) when one
/// exists **and the fd still names the saved file**, keeping a clone
/// failure distinct from a missing/mismatched file. Same identity check
/// as [`preserved_stdio_file`]; no flag change.
fn preserved_stdio_clone(fd: RawFd) -> PreservedClone {
    let preserved = match PRESERVED_STDIO.get() {
        Some(preserved) => preserved,
        None => return PreservedClone::Missing,
    };
    let saved = match fd {
        1 => preserved.stdout.as_ref(),
        2 => preserved.stderr.as_ref(),
        _ => return PreservedClone::Missing,
    };
    let saved = match saved {
        Some(saved) => saved,
        None => return PreservedClone::Missing,
    };
    // SAFETY: `fstat` only reads the fd's metadata.
    let mut current: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &raw mut current) } != 0 {
        return PreservedClone::Missing;
    }
    if current.st_dev as u64 != saved.dev || current.st_ino as u64 != saved.ino {
        return PreservedClone::Missing;
    }
    match saved.file.try_clone() {
        Ok(file) => PreservedClone::Cloned(file),
        Err(error) => PreservedClone::CloneFailed(error),
    }
}

/// Acquires the unbuffered transport without mutating inherited status flags.
/// A failed private reopen is an error; there is no blocking fallback.
pub(crate) fn stdout_transport_on_fd(fd: RawFd) -> io::Result<StdoutInner> {
    stdout_transport_with_reopen(fd, proc_self_fd_reopen)
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
            // blocking the observer here. After the startup shed a
            // reopen of an invoker-owned pipe or terminal fails
            // EACCES, so prefer the description preserved before the
            // shed (a clone of our own file needs no capability).
            if let Some(file) = preserved_stdio_file(fd) {
                return Ok(StdoutInner::File(file));
            }
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

/// True when the transport failed only because no fresh descriptor could
/// be allocated. Other errors (unsupported type, EACCES, ENXIO, EPIPE at
/// open) keep their existing shed/propagate policy.
fn is_fd_exhaustion(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EMFILE || code == libc::ENFILE
    )
}

/// A diagnostic channel borrowed without allocating a descriptor: the raw
/// fd to write, either the caller's own fd or a preserved private stdio
/// description. The fd is never closed here; stdio fds and the preserved
/// files live for the process's life, and test callers hold their pipe
/// while the borrowed writer is alive.
#[derive(Debug, Clone, Copy)]
enum BorrowedDiagnostic {
    File(RawFd),
    Socket(RawFd),
}

/// Selects the borrowed channel for `fd` when no new descriptor can be
/// allocated. Regular files and block devices write through the page
/// cache, so the inherited fd is already non-waiting; sockets send with
/// per-call `MSG_DONTWAIT`, so no flag change is needed. Pipes and
/// terminals borrow the preserved `O_NONBLOCK` description when its
/// identity still matches, else the inherited fd when it is already
/// nonblocking; a blocking pipe with no preserved channel has no safe
/// borrow (writing would park, toggling `O_NONBLOCK` would touch the
/// shared description), so it stays `None` and the diagnostic sheds.
fn borrowed_diagnostic_transport(fd: RawFd) -> Option<BorrowedDiagnostic> {
    // SAFETY: `fstat` only reads the fd's metadata.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &raw mut stat) } != 0 {
        return None;
    }
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG | libc::S_IFBLK => Some(BorrowedDiagnostic::File(fd)),
        libc::S_IFSOCK => Some(BorrowedDiagnostic::Socket(fd)),
        libc::S_IFIFO | libc::S_IFCHR => {
            if let Some(raw) = preserved_stdio_borrowed_fd(fd) {
                return Some(BorrowedDiagnostic::File(raw));
            }
            if fd_is_nonblocking(fd) {
                return Some(BorrowedDiagnostic::File(fd));
            }
            None
        }
        _ => None,
    }
}

/// The preserved private description's own fd, without the clone that
/// [`preserved_stdio_file`] needs a fresh descriptor for. Same identity
/// check: only while the fd still names the saved file.
fn preserved_stdio_borrowed_fd(fd: RawFd) -> Option<RawFd> {
    let preserved = PRESERVED_STDIO.get()?;
    let saved = match fd {
        1 => preserved.stdout.as_ref()?,
        2 => preserved.stderr.as_ref()?,
        _ => return None,
    };
    // SAFETY: `fstat` only reads the fd's metadata.
    let mut current: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &raw mut current) } != 0 {
        return None;
    }
    if current.st_dev as u64 != saved.dev || current.st_ino as u64 != saved.ino {
        return None;
    }
    Some(saved.file.as_raw_fd())
}

/// Whether `fd` already carries `O_NONBLOCK`, read without changing it.
fn fd_is_nonblocking(fd: RawFd) -> bool {
    // SAFETY: `F_GETFL` only reads the fd's flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    flags >= 0 && (flags & libc::O_NONBLOCK) != 0
}

/// Writes one diagnostic through a borrowed channel, with the same
/// immediate head/tail policy as [`SinkWriter::write_diagnostic_bytes`]:
/// the transport takes what it takes now, the unsent tail sheds with
/// the standard counters. Never waits, never touches status flags.
fn write_borrowed_diagnostic(transport: BorrowedDiagnostic, bytes: &[u8]) -> io::Result<SinkDrops> {
    let mut drops = SinkDrops::default();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let wrote = match transport {
            BorrowedDiagnostic::File(raw) => {
                // SAFETY: `write` reads `remaining` only; the borrowed fd
                // is open for the whole diagnostic call.
                let wrote = unsafe { libc::write(raw, remaining.as_ptr().cast(), remaining.len()) };
                if wrote < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(wrote as usize)
                }
            }
            BorrowedDiagnostic::Socket(raw) => {
                // SAFETY: `send` reads `remaining` only; the borrowed fd
                // is open for the whole diagnostic call.
                let sent = unsafe {
                    libc::send(
                        raw,
                        remaining.as_ptr().cast(),
                        remaining.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                if sent < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(sent as usize)
                }
            }
        };
        match wrote {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "sink wrote zero bytes with a non-empty buffer",
                ));
            }
            Ok(wrote) => {
                remaining = &remaining[wrote..];
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                // No room right now (or a stray signal): shed the tail
                // with counters rather than waiting for room.
                break;
            }
            Err(error) => return Err(error),
        }
    }
    if !remaining.is_empty() {
        drops.timeouts = drops.timeouts.saturating_add(1);
        drops.dropped_bytes = drops.dropped_bytes.saturating_add(remaining.len() as u64);
    }
    Ok(drops)
}

/// A [`bounded_writer_on_fd`] fallback that writes through a borrowed
/// channel without owning a descriptor. Single immediate attempts, like
/// the owned transport: a full pipe fails fast for the caller to drop.
/// Never closes the borrowed fd.
struct BorrowedDiagnosticWriter {
    fd: RawFd,
    socket: bool,
}

impl Write for BorrowedDiagnosticWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.socket {
            // SAFETY: `send` reads `bytes` only; the borrowed fd is open
            // while this short-lived writer is alive.
            let sent = unsafe {
                libc::send(
                    self.fd,
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
        } else {
            // SAFETY: `write` reads `bytes` only; the borrowed fd is open
            // while this short-lived writer is alive.
            let wrote = unsafe { libc::write(self.fd, bytes.as_ptr().cast(), bytes.len()) };
            if wrote < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(wrote as usize)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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

    /// One diagnostic's bytes, written at once without ever waiting:
    /// the transport takes what it takes now, and the unsent tail sheds
    /// with the standard counters. Bypasses the tick buffer, whose
    /// zero-budget flush would drop an oversized line's head and deliver
    /// its tail; here the head is delivered and the tail sheds. Called
    /// on a fresh sink only, so the buffer stays empty. Only transport
    /// errors propagate, as in [`abort_wait`](Self::abort_wait).
    fn write_diagnostic_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        debug_assert!(self.buf.is_empty(), "diagnostics bypass the tick buffer");
        let mut remaining = bytes;
        while !remaining.is_empty() {
            match self.inner.write(remaining) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "sink wrote zero bytes with a non-empty buffer",
                    ));
                }
                Ok(wrote) => {
                    remaining = &remaining[wrote..];
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    // No room right now (or a stray signal): shed the
                    // tail with counters rather than waiting for room.
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if !remaining.is_empty() {
            self.drops.timeouts = self.drops.timeouts.saturating_add(1);
            self.drops.dropped_bytes = self
                .drops
                .dropped_bytes
                .saturating_add(remaining.len() as u64);
            self.tick_budget = Duration::ZERO;
        }
        Ok(())
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
        // Bounded partial write: accept only the free prefix so one large
        // frame never grows the buffer past the ceiling. `write_all`
        // retries the remainder, flushing full buffers in order; a flush
        // that drops or errors preserves its accounting and buffer.
        let free = SINK_BUFFER_BYTES.saturating_sub(self.buf.len());
        if free == 0 {
            // Unreachable with the current flush (success empties the
            // buffer), but never report a 0-write for non-empty input.
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "sink buffer still full after flush",
            ));
        }
        let accepted = free.min(bytes.len());
        self.buf.extend_from_slice(&bytes[..accepted]);
        Ok(accepted)
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

    /// Stall bound for the draining-reader tests. The writer must block
    /// until the reader drains, so `stall_ms` measures scheduling
    /// jitter, not loss: exact-0 fails under load (28 ms max across the
    /// feature-combo matrix, 2 ms in a full default run, 1 flake in 55
    /// isolated runs). 100 ms is ~3.5x the max observed yet 50x under
    /// the tests' own 5 s reader timeout.
    const DRAINING_READER_MAX_STALL_MS: u64 = 100;

    /// Lossless delivery to a draining reader: every byte arrives, no
    /// timeout, no drop, and the poll wait stays within scheduling
    /// jitter (see [`DRAINING_READER_MAX_STALL_MS`]).
    fn assert_lossless_drain(drops: SinkDrops) {
        assert_eq!(drops.timeouts, 0, "draining reader timed out: {drops:?}");
        assert_eq!(drops.dropped_bytes, 0, "draining reader dropped: {drops:?}");
        assert!(
            drops.stall_ms <= DRAINING_READER_MAX_STALL_MS,
            "draining stall {} ms exceeds {DRAINING_READER_MAX_STALL_MS} ms: {drops:?}",
            drops.stall_ms
        );
    }

    #[test]
    fn lossless_drain_bound_bites_one_past_the_pinned_ceiling() {
        // Pins the ceiling: a bump needs a new measurement note on the const.
        assert_eq!(DRAINING_READER_MAX_STALL_MS, 100);
        let over = SinkDrops {
            timeouts: 0,
            dropped_bytes: 0,
            stall_ms: 101,
        };
        // Expected-panic noise: the hook is process-global, so no swap.
        let caught = std::panic::catch_unwind(|| assert_lossless_drain(over));
        assert!(caught.is_err(), "a 101 ms stall must fail the drain bound");
        assert_lossless_drain(SinkDrops {
            timeouts: 0,
            dropped_bytes: 0,
            stall_ms: 100,
        });
    }

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
        let mut sink = SinkWriter::new(writer).unwrap();
        sink.begin_tick(Duration::from_secs(30));

        let chunk = vec![9u8; SINK_BUFFER_BYTES * 3];
        let expected_len = chunk.len();
        // A live reader drains concurrently: a bounded writer cannot promise
        // that the socket buffers an entire multi-batch frame before reading.
        let reader_thread = std::thread::spawn(move || {
            reader
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut got = vec![0u8; expected_len];
            reader.read_exact(&mut got).unwrap();
            got
        });
        sink.write_all(&chunk).unwrap();
        sink.flush().unwrap();
        let got = reader_thread.join().unwrap();
        assert_eq!(got, chunk);
        assert_lossless_drain(sink.take_drops());
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

    /// PA-14: a single write larger than the ceiling must not grow the
    /// buffer past `SINK_BUFFER_BYTES`. Bounded partial writes accept only
    /// the free prefix; the remainder follows via `write_all` with byte
    /// order preserved to a ready reader.
    #[test]
    fn single_write_larger_than_ceiling_is_partial_and_bounded() {
        let (writer, reader) = pair();
        let mut sink = SinkWriter::new(writer).unwrap();
        sink.begin_tick(Duration::from_secs(30));
        let len = SINK_BUFFER_BYTES + 32768;
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

        let accepted = sink.write(&payload).unwrap();
        assert_eq!(
            accepted, SINK_BUFFER_BYTES,
            "oversize write must fill only the ceiling"
        );
        assert!(accepted < payload.len());
        assert!(
            sink.buf.len() <= SINK_BUFFER_BYTES,
            "buffer grew past ceiling: {}",
            sink.buf.len()
        );

        let reader_thread = std::thread::spawn(move || {
            let mut reader = reader;
            reader
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut got = vec![0u8; len];
            reader.read_exact(&mut got).unwrap();
            got
        });
        sink.write_all(&payload[accepted..]).unwrap();
        sink.flush().unwrap();
        let got = reader_thread.join().unwrap();
        assert_eq!(got, payload);
        assert_lossless_drain(sink.take_drops());
    }

    /// PA-14 healthy twin: the same large frame via `write_all` reaches a
    /// ready reader whole, in order, without drops.
    #[test]
    fn write_all_twin_delivers_same_large_frame_losslessly() {
        let (writer, reader) = pair();
        let mut sink = SinkWriter::new(writer).unwrap();
        sink.begin_tick(Duration::from_secs(30));
        let len = SINK_BUFFER_BYTES + 32768;
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

        let reader_thread = std::thread::spawn(move || -> io::Result<Vec<u8>> {
            let mut reader = reader;
            reader.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut got = vec![0u8; len];
            reader.read_exact(&mut got)?;
            Ok(got)
        });
        sink.write_all(&payload).unwrap();
        sink.flush().unwrap();
        let got = reader_thread.join().unwrap().unwrap();
        assert_eq!(got, payload);
        assert_lossless_drain(sink.take_drops());
    }

    /// PA-14: when the buffer is partly full, `write` reports only the
    /// free space instead of growing past the ceiling.
    #[test]
    fn write_reports_free_space_when_buffer_partly_full() {
        let (writer, _reader) = pair();
        let mut sink = SinkWriter::new(writer).unwrap();
        sink.begin_tick(Duration::from_secs(30));

        let prefix = vec![1u8; 1000];
        assert_eq!(sink.write(&prefix).unwrap(), 1000);

        let payload = vec![2u8; SINK_BUFFER_BYTES];
        let accepted = sink.write(&payload).unwrap();
        assert_eq!(accepted, SINK_BUFFER_BYTES - 1000);
        assert_eq!(sink.buf.len(), SINK_BUFFER_BYTES);
    }

    /// PA-14: a multi-chunk `write_all` stays bounded before the final
    /// flush and still delivers every byte in order to a draining reader.
    #[test]
    fn large_multi_chunk_write_all_stays_bounded_and_ordered() {
        let (writer, reader) = pair();
        let mut sink = SinkWriter::new(writer).unwrap();
        sink.begin_tick(Duration::from_secs(30));
        let len = SINK_BUFFER_BYTES * 3 + 12345;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 31) % 256) as u8).collect();

        let reader_thread = std::thread::spawn(move || -> io::Result<Vec<u8>> {
            let mut reader = reader;
            reader.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut got = vec![0u8; len];
            reader.read_exact(&mut got)?;
            Ok(got)
        });
        sink.write_all(&payload).unwrap();
        assert!(
            sink.buf.len() <= SINK_BUFFER_BYTES,
            "buffered {} past ceiling after write_all",
            sink.buf.len()
        );
        sink.flush().unwrap();
        let got = reader_thread.join().unwrap().unwrap();
        assert_eq!(got, payload);
        assert_lossless_drain(sink.take_drops());
    }

    /// PA-14: a stalled large offer sheds with a finite buffer: every
    /// offered byte is counted as dropped, none is held past the flush.
    #[test]
    fn stalled_large_write_sheds_with_finite_buffer() {
        let (writer, _reader) = pair();
        let mut filler = writer.try_clone().unwrap();
        filler.set_nonblocking(true).unwrap();
        let chunk = vec![7u8; 65536];
        while filler.write(&chunk).is_ok() {}
        drop(filler);

        let mut sink = SinkWriter::new(writer).unwrap();
        sink.begin_tick(Duration::ZERO);
        let len = SINK_BUFFER_BYTES * 2 + 1000;
        let payload = vec![8u8; len];

        let start = Instant::now();
        sink.write_all(&payload).unwrap();
        assert!(
            sink.buf.len() <= SINK_BUFFER_BYTES,
            "stalled write buffered {} past ceiling",
            sink.buf.len()
        );
        sink.flush().unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(1),
            "stalled large write blocked {elapsed:?}"
        );
        let drops = sink.take_drops();
        assert_eq!(drops.dropped_bytes, len as u64);
        assert!(drops.timeouts >= 1);
        assert!(sink.buf.is_empty());
    }

    /// PA-14: a cancelled large offer sheds promptly with a finite buffer.
    #[test]
    fn cancelled_large_write_sheds_promptly_with_finite_buffer() {
        let (writer, _reader) = pair();
        let mut filler = writer.try_clone().unwrap();
        filler.set_nonblocking(true).unwrap();
        let chunk = vec![7u8; 65536];
        while filler.write(&chunk).is_ok() {}
        drop(filler);

        let cancel = Arc::new(AtomicBool::new(true));
        let mut sink = SinkWriter::new(writer).unwrap();
        sink.set_cancel_flag(Arc::clone(&cancel));
        sink.begin_tick(Duration::from_millis(250));
        let len = SINK_BUFFER_BYTES * 2 + 1000;
        let payload = vec![8u8; len];

        let start = Instant::now();
        sink.write_all(&payload).unwrap();
        assert!(
            sink.buf.len() <= SINK_BUFFER_BYTES,
            "cancelled write buffered {} past ceiling",
            sink.buf.len()
        );
        sink.flush().unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(150),
            "cancelled large write took {elapsed:?}"
        );
        let drops = sink.take_drops();
        assert_eq!(drops.dropped_bytes, len as u64);
        assert!(drops.timeouts >= 1);
        assert!(sink.buf.is_empty());
    }

    /// PA-14: a large offer to a dead peer is a transport error, not a
    /// drop, and the retained buffer stays within the ceiling.
    #[test]
    fn large_write_to_dead_peer_is_error_not_drop_with_bounded_buffer() {
        let (writer, reader) = pair();
        drop(reader);
        let mut sink = SinkWriter::new(writer).unwrap();
        sink.begin_tick(Duration::from_millis(250));
        let len = SINK_BUFFER_BYTES + 1000;
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

        let accepted = sink.write(&payload).unwrap();
        assert_eq!(accepted, SINK_BUFFER_BYTES);
        assert_eq!(sink.buf.len(), SINK_BUFFER_BYTES);

        let error = sink.write(&payload[accepted..]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(sink.take_drops(), SinkDrops::default());
        assert!(sink.buf.len() <= SINK_BUFFER_BYTES);

        let (writer, reader) = pair();
        drop(reader);
        let mut sink = SinkWriter::new(writer).unwrap();
        sink.begin_tick(Duration::from_millis(250));
        let error = sink.write_all(&payload).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(sink.take_drops(), SinkDrops::default());
        assert!(sink.buf.len() <= SINK_BUFFER_BYTES);
    }

    /// The startup stdio preserve: after
    /// [`preserve_stdio_private_descriptions`], a transport for fd 1
    /// must come from the preserved clone, never from a reopen — a
    /// shed reopen of an invoker-owned pipe fails EACCES. The preserve
    /// runs in a child (a fresh `OnceLock`, piped stdout), with a
    /// reopen that always fails the way the shed one does.
    const PRESERVE_CHILD: &str = "P11SCOPE_SINK_PRESERVE_CHILD";
    const PRESERVED_LINE: &[u8] = b"PRESERVED STDOUT\n";

    fn preserve_child() {
        let mode = std::env::var(PRESERVE_CHILD).unwrap_or_default();
        if mode.is_empty() {
            return;
        }
        // The parent pipes our stdout: fd 1 must be the FIFO case.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(1, &raw mut stat) }, 0);
        assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFIFO);
        let eacces = || io::Error::from_raw_os_error(libc::EACCES);
        match mode.as_str() {
            "preserve" => {
                preserve_stdio_private_descriptions();
                let mut transport = test_transport_with_reopen(1, |_| Err(eacces()))
                    .expect("preserved stdout must bypass the reopen");
                transport.write_all(PRESERVED_LINE).unwrap();
                transport.flush().unwrap();
            }
            "no-preserve" => match test_transport_with_reopen(1, |_| Err(eacces())) {
                Ok(_) => panic!("unpreserved stdout must use the reopen"),
                Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EACCES)),
            },
            "retarget" => {
                preserve_stdio_private_descriptions();
                // A fresh pipe takes over fd 1, the way the dashboard's
                // capture pipe takes over fd 2: the fd still names a
                // FIFO, but a different file than the saved one.
                let mut ends = [0; 2];
                assert_eq!(
                    unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) },
                    0,
                    "pipe2 failed: {}",
                    io::Error::last_os_error()
                );
                // SAFETY: both ends are fresh descriptors owned here.
                let (read, write) = unsafe {
                    (
                        std::fs::File::from_raw_fd(ends[0]),
                        std::fs::File::from_raw_fd(ends[1]),
                    )
                };
                // SAFETY: `dup2` of our own pipe end onto fd 1.
                assert_eq!(unsafe { libc::dup2(write.as_raw_fd(), 1) }, 1);
                drop(write);
                let mut transport = stdout_transport_on_fd(1).expect("retargeted stdout must open");
                transport.write_all(PRESERVED_LINE).unwrap();
                transport.flush().unwrap();
                drop(transport);
                // fd 1 still holds the new pipe's write end, so the read
                // end never sees EOF: poll it nonblocking instead.
                // SAFETY: flag change on our own pipe end.
                let flags = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFL) };
                assert!(
                    unsafe {
                        libc::fcntl(read.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                    } >= 0,
                    "O_NONBLOCK failed: {}",
                    io::Error::last_os_error()
                );
                let mut got = Vec::new();
                let mut chunk = [0u8; 4096];
                let mut read = read;
                loop {
                    match read.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(read) => got.extend_from_slice(&chunk[..read]),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("new pipe read failed: {error}"),
                    }
                }
                assert!(
                    got.windows(PRESERVED_LINE.len())
                        .any(|bytes| bytes == PRESERVED_LINE),
                    "the transport must write the retargeted fd 1, not the saved \
                     description: new pipe held {got:?}",
                );
            }
            other => panic!("unknown preserve child mode {other:?}"),
        }
        std::process::exit(0);
    }

    fn preserve_command(test: &str, mode: &str) -> std::process::Command {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        let module = module_path!().split_once("::").unwrap().1;
        command
            .args(["--exact", &format!("{module}::{test}"), "--nocapture"])
            .env(PRESERVE_CHILD, mode)
            .stdout(std::process::Stdio::piped());
        command
    }

    #[test]
    fn preserved_stdout_bypasses_a_failing_reopen() {
        preserve_child();
        let output = preserve_command("preserved_stdout_bypasses_a_failing_reopen", "preserve")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            output
                .stdout
                .windows(PRESERVED_LINE.len())
                .any(|bytes| bytes == PRESERVED_LINE),
            "preserved stdout never delivered the line: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// A retargeted stdio fd must not use the saved description: after
    /// the save, a fresh pipe takes over fd 1 (the dashboard's capture
    /// takes over fd 2 the same way), and the transport must write the
    /// new pipe — never the startup file. The child asserts the line
    /// reached the new pipe; the parent asserts it never reached the
    /// saved one (the child's original stdout).
    #[test]
    fn retargeted_stdout_ignores_the_preserved_description() {
        preserve_child();
        let output = preserve_command(
            "retargeted_stdout_ignores_the_preserved_description",
            "retarget",
        )
        .output()
        .unwrap();
        assert!(
            output.status.success(),
            "retargeted stdout must write the new pipe: {output:?}"
        );
        assert!(
            !output
                .stdout
                .windows(PRESERVED_LINE.len())
                .any(|bytes| bytes == PRESERVED_LINE),
            "retargeted stdout must not write the saved description: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn unpreserved_stdout_still_uses_the_reopen() {
        preserve_child();
        let output = preserve_command("unpreserved_stdout_still_uses_the_reopen", "no-preserve")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            !output
                .stdout
                .windows(PRESERVED_LINE.len())
                .any(|bytes| bytes == PRESERVED_LINE),
            "unpreserved stdout must not deliver without the reopen: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// v070-stderr-stall: a diagnostic past the tick buffer still delivers
    /// whole to a draining reader. The tick-buffered write would flush
    /// mid-line with a zero budget and drop the head, delivering the tail.
    #[test]
    fn diagnostic_line_delivers_a_whole_oversized_line_to_a_draining_reader() {
        let (writer, mut reader) = pair();
        let line = "d".repeat(SINK_BUFFER_BYTES * 3 + 17);
        let expected = format!("{line}\n");
        let expected_len = expected.len();
        let reader_thread = std::thread::spawn(move || {
            reader
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut got = vec![0u8; expected_len];
            reader.read_exact(&mut got).unwrap();
            got
        });
        let drops = try_diagnostic_line_on_fd(writer.as_raw_fd(), &line).unwrap();
        let got = reader_thread.join().unwrap();
        assert_eq!(got, expected.as_bytes());
        assert_eq!(drops, SinkDrops::default());
    }

    /// v070-stderr-stall: the no-newline diagnostic (the bounded `eprint!`)
    /// writes its bytes verbatim, with no wait and no added newline.
    #[test]
    fn diagnostic_text_writes_bytes_verbatim_without_a_newline() {
        let (writer, mut reader) = pair();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let drops = try_diagnostic_bytes_on_fd(writer.as_raw_fd(), b"partial").unwrap();
        let mut received = [0; 7];
        reader.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"partial");
        assert_eq!(drops, SinkDrops::default());
    }

    /// v070-stderr-stall: drivers that own their own text (detach
    /// progress) write stderr through a transport that never waits: a
    /// full pipe fails fast — the driver drops the line — instead of
    /// parking the run past its stop.
    #[test]
    fn bounded_writer_on_a_full_pipe_fails_fast_without_waiting() {
        let (writer, _reader) = pair();
        let mut filler = writer.try_clone().unwrap();
        filler.set_nonblocking(true).unwrap();
        while filler.write(&[7; 65536]).is_ok() {}
        filler.set_nonblocking(false).unwrap();
        let mut out = bounded_writer_on_fd(writer.as_raw_fd());
        let started = Instant::now();
        let result = out.write_all(b"p11scope: cleanup completed, 5/5 links released, 0 s\n");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            result.is_err(),
            "a full pipe must fail fast, not park: {result:?}"
        );
    }

    /// The same writer delivers whole lines to a draining reader.
    #[test]
    fn bounded_writer_delivers_whole_lines_to_a_draining_reader() {
        let (writer, mut reader) = pair();
        reader
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut out = bounded_writer_on_fd(writer.as_raw_fd());
        out.write_all(b"p11scope: cleanup completed, 5/5 links released, 0 s\n")
            .unwrap();
        out.flush().unwrap();
        let mut got = vec![0u8; 53];
        reader.read_exact(&mut got).unwrap();
        assert_eq!(
            got,
            b"p11scope: cleanup completed, 5/5 links released, 0 s\n"
        );
    }

    /// A fd no transport can be opened on sheds every line to the sink:
    /// writes succeed and the driver never learns stderr is gone.
    #[test]
    fn bounded_writer_on_an_unusable_fd_sheds_to_the_sink() {
        let mut out = bounded_writer_on_fd(-1);
        out.write_all(b"anything").unwrap();
        out.flush().unwrap();
    }

    /// v070-stderr-stall fix2 (codex fix1 F1): a preserved stderr pipe
    /// under clone exhaustion plus an `EACCES` reopen denial must still
    /// deliver through the borrowed preserved description — the clone's
    /// `EMFILE` must not be masked by the reopen's `EACCES`. Each
    /// diagnostic API has a healthy twin (clone succeeds, `EACCES`
    /// never reached) and an exhausted twin (clone `EMFILE`, borrow
    /// past `EACCES`); both require the actual refusal line on the
    /// pipe, not merely a successful write result. The child runs in a
    /// fresh process (a new `OnceLock`, piped stderr, stdout on null so
    /// only stderr preservation takes a fd), preserves, then — in the
    /// exhausted modes — drops `RLIMIT_NOFILE` to 4 before the call.
    const EXHAUST_CHILD: &str = "P11SCOPE_SINK_EXHAUST_CHILD";
    const EXHAUST_REFUSAL: &[u8] =
        b"p11scope: inventory --system: live capture did not start: Too many open files\n";

    fn exhaust_child() {
        let mode = std::env::var(EXHAUST_CHILD).unwrap_or_default();
        if mode.is_empty() {
            return;
        }
        // The parent piped our stderr: fd 2 must be the FIFO case.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(2, &raw mut stat) }, 0);
        assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFIFO);
        let eacces = || io::Error::from_raw_os_error(libc::EACCES);
        let exhaust = || {
            let limit = libc::rlimit {
                rlim_cur: 4,
                rlim_max: 4,
            };
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) },
                0,
                "setrlimit failed: {}",
                io::Error::last_os_error()
            );
        };
        match mode.as_str() {
            "oneshot-healthy" => {
                preserve_stdio_private_descriptions();
                let drops = try_diagnostic_bytes_with_reopen(2, EXHAUST_REFUSAL, |_| Err(eacces()))
                    .expect("healthy preserved stderr must deliver past an EACCES reopen");
                assert_eq!(drops, SinkDrops::default());
            }
            "oneshot-exhausted" => {
                preserve_stdio_private_descriptions();
                exhaust();
                // Production drops this result (`let _ =`); the parent
                // requires the line itself. Pre-fix this is `EACCES`
                // with zero bytes on the pipe.
                let _ = try_diagnostic_bytes_with_reopen(2, EXHAUST_REFUSAL, |_| Err(eacces()));
            }
            "bounded-healthy" => {
                preserve_stdio_private_descriptions();
                let mut out = bounded_writer_with_reopen(2, |_| Err(eacces()));
                out.write_all(EXHAUST_REFUSAL)
                    .expect("healthy bounded writer must deliver past an EACCES reopen");
                out.flush().expect("flush");
            }
            "bounded-exhausted" => {
                preserve_stdio_private_descriptions();
                exhaust();
                // Pre-fix this writer is the sink: the write succeeds
                // but no byte reaches the pipe, so the parent — not the
                // result — decides.
                let mut out = bounded_writer_with_reopen(2, |_| Err(eacces()));
                let _ = out.write_all(EXHAUST_REFUSAL);
                let _ = out.flush();
            }
            other => panic!("unknown exhaust child mode {other:?}"),
        }
        std::process::exit(0);
    }

    fn exhaust_command(test: &str, mode: &str) -> std::process::Command {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        let module = module_path!().split_once("::").unwrap().1;
        command
            .args(["--exact", &format!("{module}::{test}"), "--nocapture"])
            .env(EXHAUST_CHILD, mode)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        command
    }

    fn assert_exhaust_delivers(test: &str, mode: &str) {
        exhaust_child();
        let output = exhaust_command(test, mode).output().unwrap();
        assert!(
            output.status.success(),
            "{mode} child must exit 0: {output:?}"
        );
        assert!(
            output
                .stderr
                .windows(EXHAUST_REFUSAL.len())
                .any(|bytes| bytes == EXHAUST_REFUSAL),
            "{mode} must deliver the refusal line to preserved stderr: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn diagnostic_oneshot_healthy_preserved_stderr_bypasses_eacces_reopen() {
        assert_exhaust_delivers(
            "diagnostic_oneshot_healthy_preserved_stderr_bypasses_eacces_reopen",
            "oneshot-healthy",
        );
    }

    #[test]
    fn diagnostic_oneshot_borrows_preserved_stderr_past_clone_exhaustion_and_eacces() {
        assert_exhaust_delivers(
            "diagnostic_oneshot_borrows_preserved_stderr_past_clone_exhaustion_and_eacces",
            "oneshot-exhausted",
        );
    }

    #[test]
    fn bounded_writer_healthy_preserved_stderr_bypasses_eacces_reopen() {
        assert_exhaust_delivers(
            "bounded_writer_healthy_preserved_stderr_bypasses_eacces_reopen",
            "bounded-healthy",
        );
    }

    #[test]
    fn bounded_writer_borrows_preserved_stderr_past_clone_exhaustion_and_eacces() {
        assert_exhaust_delivers(
            "bounded_writer_borrows_preserved_stderr_past_clone_exhaustion_and_eacces",
            "bounded-exhausted",
        );
    }
}
