// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Instant;

const SHORT_IDLE: Duration = Duration::from_millis(60);

fn pipe() -> (File, File) {
    let mut fds = [-1; 2];
    // SAFETY: pipe2 initializes the two owned descriptors on success.
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    // SAFETY: both descriptors were freshly returned by pipe2.
    let reader = unsafe { File::from_raw_fd(fds[0]) };
    let writer = unsafe { File::from_raw_fd(fds[1]) };
    // SAFETY: changing the capacity of our owned pipe only.
    assert_eq!(
        unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) },
        4096
    );
    (reader, writer)
}

struct ReaderGuard {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<u8>>>,
}

impl ReaderGuard {
    fn trickle(mut reader: File, total: usize) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut received = Vec::with_capacity(total);
            let mut buf = [0; 4096];
            while received.len() < total && !stopping.load(Ordering::SeqCst) {
                assert!(Instant::now() < deadline, "reader watchdog expired");
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        received.extend_from_slice(&buf[..n]);
                        thread::sleep(Duration::from_millis(12));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("reader failed: {error}"),
                }
            }
            received
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Vec<u8> {
        self.handle.take().unwrap().join().unwrap()
    }
}

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct ObservedWriter {
    inner: File,
    progress: Vec<Instant>,
}

impl AsRawFd for ObservedWriter {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl Write for ObservedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(bytes)?;
        if n > 0 {
            self.progress.push(Instant::now());
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

enum Action {
    Accept(usize),
    Interrupted,
    WouldBlock,
    Zero,
}

struct FaultWriter {
    fd: UnixStream,
    _peer: UnixStream,
    actions: VecDeque<Action>,
    accepted: Vec<u8>,
    writes: usize,
    flushes: usize,
    flush_error: bool,
    interrupt_always: bool,
    progress: Arc<AtomicUsize>,
}

impl FaultWriter {
    fn new(actions: impl IntoIterator<Item = Action>) -> Self {
        let (fd, peer) = UnixStream::pair().unwrap();
        Self {
            fd,
            _peer: peer,
            actions: actions.into_iter().collect(),
            accepted: Vec::new(),
            writes: 0,
            flushes: 0,
            flush_error: false,
            interrupt_always: false,
            progress: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl AsRawFd for FaultWriter {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Write for FaultWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        assert!(bytes.len() <= 65536, "unbounded write chunk");
        if self.interrupt_always {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = match self.actions.pop_front().unwrap_or(Action::Accept(7)) {
            Action::Interrupted => return Err(io::ErrorKind::Interrupted.into()),
            Action::WouldBlock => return Err(io::ErrorKind::WouldBlock.into()),
            Action::Zero => 0,
            Action::Accept(n) => n.min(bytes.len()),
        };
        self.accepted.extend_from_slice(&bytes[..n]);
        self.progress.store(self.accepted.len(), Ordering::SeqCst);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.flush_error {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn healthy_large_document_has_no_total_deadline() {
    // Catches a total deadline or a size cap; byte expectations are independent.
    let (reader, writer) = pipe();
    let bytes: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let reader = ReaderGuard::trickle(reader, bytes.len());
    let mut writer = ObservedWriter {
        inner: writer,
        progress: Vec::new(),
    };
    let start = Instant::now();
    let watchdog = || start.elapsed() >= Duration::from_secs(18);
    let result = write_document(&mut writer, &bytes, FINAL_STDOUT_IDLE, &watchdog);
    drop(writer.inner);
    assert!(!watchdog(), "writer watchdog expired");
    assert_eq!(result.unwrap(), bytes.len());
    let elapsed = start.elapsed();
    assert!(
        elapsed > Duration::from_secs(5),
        "positive control too fast: {elapsed:?}"
    );
    let largest_gap = writer
        .progress
        .windows(2)
        .map(|times| times[1] - times[0])
        .max()
        .unwrap();
    assert!(
        largest_gap < FINAL_STDOUT_IDLE,
        "progress gap {largest_gap:?}"
    );
    assert_eq!(reader.finish(), bytes);
    eprintln!(
        "healthy: accepted={} elapsed={elapsed:?} largest_progress_gap={largest_gap:?}; watchdog=false",
        bytes.len()
    );
}

#[test]
fn stalled_document_counts_exact_prefix() {
    // Catches drop-as-success, byte-zero retry, and inaccurate accepted accounting.
    let (mut reader, mut writer) = pipe();
    let bytes = vec![23; 65536];
    let start = Instant::now();
    let failure = write_document(&mut writer, &bytes, SHORT_IDLE, &|| {
        start.elapsed() > Duration::from_secs(2)
    })
    .unwrap_err();
    assert!(matches!(failure.reason, StdoutFailureReason::NoProgress));
    assert_eq!(failure.accepted, 4096);
    assert_eq!(failure.total, 65536);
    assert_eq!(failure.total - failure.accepted, 61440);
    assert!(start.elapsed() >= SHORT_IDLE && start.elapsed() < Duration::from_secs(2));
    drop(writer);
    let mut drained = Vec::new();
    reader.read_to_end(&mut drained).unwrap();
    assert_eq!(drained.len(), failure.accepted);
    assert_eq!(drained, bytes[..4096]);
    eprintln!(
        "stalled: accepted={} total={} drained={} elapsed={:?}; watchdog=false",
        failure.accepted,
        failure.total,
        drained.len(),
        start.elapsed()
    );
}

#[test]
fn ready_then_would_block_retries_suffix() {
    // The real socket remains pollable. The second EAGAIN follows poll readiness;
    // stale readiness must retry the suffix without duplicating accepted bytes.
    let mut writer = FaultWriter::new([
        Action::Accept(3),
        Action::WouldBlock,
        Action::WouldBlock,
        Action::Interrupted,
        Action::Accept(2),
    ]);
    assert_eq!(
        write_document(&mut writer, b"abcdefghijk", SHORT_IDLE, &|| false).unwrap(),
        11
    );
    assert_eq!(writer.accepted, b"abcdefghijk");
    assert_eq!(writer.flushes, 1);
    assert!(writer.writes >= 6);
}

#[test]
fn interruptions_do_not_reset_idle() {
    // Catches treating EINTR as progress, with cancellation bounding a broken loop.
    let mut writer = FaultWriter::new([]);
    writer.interrupt_always = true;
    let start = Instant::now();
    let failure = write_document(&mut writer, b"pending", SHORT_IDLE, &|| {
        start.elapsed() > Duration::from_secs(2)
    })
    .unwrap_err();
    assert!(matches!(failure.reason, StdoutFailureReason::NoProgress));
    assert_eq!(failure.accepted, 0);
    assert_eq!(failure.total, 7);
    assert!(writer.writes > 1);
    assert_eq!(writer.flushes, 0);
    assert!(start.elapsed() >= SHORT_IDLE && start.elapsed() < Duration::from_secs(1));
}

#[test]
fn zero_write_and_flush_failure_are_errors() {
    // Completion requires a flush even after every byte has been accepted.
    let mut writer = FaultWriter::new([Action::Accept(2), Action::Zero]);
    let failure = write_document(&mut writer, b"four", SHORT_IDLE, &|| false).unwrap_err();
    assert_eq!((failure.accepted, failure.total), (2, 4));
    assert!(
        matches!(failure.reason, StdoutFailureReason::Io(ref error) if error.kind() == io::ErrorKind::WriteZero)
    );
    assert_eq!(writer.flushes, 0);
    let mut writer = FaultWriter::new([]);
    writer.flush_error = true;
    let failure = write_document(&mut writer, b"four", SHORT_IDLE, &|| false).unwrap_err();
    assert_eq!((failure.accepted, failure.total), (4, 4));
    assert!(
        matches!(failure.reason, StdoutFailureReason::Io(ref error) if error.kind() == io::ErrorKind::BrokenPipe)
    );
    assert_eq!(writer.accepted, b"four");
    assert_eq!(writer.flushes, 1);
}

#[test]
fn empty_document_flushes_without_writing() {
    let mut writer = FaultWriter::new([Action::Zero]);
    assert_eq!(
        write_document(&mut writer, b"", SHORT_IDLE, &|| false).unwrap(),
        0
    );
    assert_eq!(writer.writes, 0);
    assert_eq!(writer.flushes, 1);
}

#[test]
fn cancel_is_checked_even_while_writable() {
    // Catches cancellation checked only on stalled poll paths.
    let mut writer = FaultWriter::new([Action::Accept(65536)]);
    let progress = Arc::clone(&writer.progress);
    let failure = write_document(&mut writer, &vec![19; 3 * 65536], SHORT_IDLE, &|| {
        progress.load(Ordering::SeqCst) >= 65536
    })
    .unwrap_err();
    assert!(matches!(failure.reason, StdoutFailureReason::Cancelled));
    assert_eq!((failure.accepted, failure.total), (65536, 196608));
    assert_eq!(writer.flushes, 0);
}

#[test]
fn last_accepted_chunk_flushes_once() {
    // With no pending suffix, a signal after the last accepted chunk must
    // not suppress the ordinary flush required for local completion.
    let mut writer = FaultWriter::new([Action::Accept(4)]);
    let progress = Arc::clone(&writer.progress);
    assert_eq!(
        write_document(&mut writer, b"four", SHORT_IDLE, &|| {
            progress.load(Ordering::SeqCst) == 4
        })
        .unwrap(),
        4
    );
    assert_eq!(writer.accepted, b"four");
    assert_eq!(writer.flushes, 1);
}

#[test]
fn begin_finalization_never_recaptures_signal_count() {
    // Capturing again would swallow a signal delivered after the boundary.
    let count = AtomicUsize::new(0);
    let signals = || count.load(Ordering::SeqCst);
    let mut stdout = FdStdout::new(-1, &signals);
    stdout.begin_finalization();
    count.store(1, Ordering::SeqCst);
    stdout.begin_finalization();
    let failure = stdout.write_document(b"pending").unwrap_err();
    assert!(matches!(failure.reason, StdoutFailureReason::Cancelled));
    assert_eq!((failure.accepted, failure.total), (0, 7));
}

fn flags(fd: RawFd) -> i32 {
    // SAFETY: only querying an owned, open descriptor.
    let value = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(value >= 0);
    value
}

fn blocking(fd: RawFd) {
    let previous = flags(fd);
    // SAFETY: our fixture owns this descriptor and its description.
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFL, previous & !libc::O_NONBLOCK) },
        0
    );
}

struct OwnedTestChild(std::process::Child);

impl Drop for OwnedTestChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Starts the parent watchdog before the child acquires any transport or PTY.
/// The child alone owns the fixture, so even a blocking syscall or a broken
/// inactivity clock cannot hang the parent test or alter its descriptors.
fn owned_cell(test: &str, cell: &str, body: impl FnOnce()) {
    const CHILD_CELL: &str = "P11SCOPE_INVENTORY_OUTPUT_OWNED_CELL";
    if let Some(requested) = std::env::var_os(CHILD_CELL) {
        if requested == cell {
            body();
        }
        return;
    }

    let start = Instant::now();
    let deadline = start + Duration::from_secs(3);
    let mut child = OwnedTestChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env(CHILD_CELL, cell)
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            eprintln!(
                "owned cell {cell}: exit={status} elapsed={:?} watchdog=false reaped=true",
                start.elapsed()
            );
            assert!(status.success(), "owned cell {cell} failed: {status}");
            return;
        }
        if Instant::now() >= deadline {
            let pid = child.0.id();
            child.0.kill().unwrap();
            let status = child.0.wait().unwrap();
            panic!(
                "owned cell watchdog expired: {cell}, owned_pid={pid}, \
                 elapsed={:?}, killed=true reaped=true status={status}",
                start.elapsed()
            );
        }
        thread::sleep(Duration::from_millis(5));
    }
}

struct StoppedPty {
    _master: File,
    slave: File,
}

impl StoppedPty {
    fn new() -> Self {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: openpty initializes fresh owned fds, with default termios.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &raw mut master,
                    &raw mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: openpty succeeded; each fd is wrapped exactly once.
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let pty = Self {
            _master: master,
            slave,
        };
        // SAFETY: stopping output only on this owned PTY.
        assert_eq!(
            unsafe { libc::tcflow(pty.slave.as_raw_fd(), libc::TCOOFF) },
            0
        );
        pty
    }
}

impl Drop for StoppedPty {
    fn drop(&mut self) {
        // SAFETY: release flow control before closing our still-owned PTY.
        let _ = unsafe { libc::tcflow(self.slave.as_raw_fd(), libc::TCOON) };
    }
}

fn check_stalled_flags(fd: RawFd, destination: &str) {
    let original = flags(fd);
    // SAFETY: creates a fresh owned duplicate of this fixture descriptor.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    assert!(duplicate >= 0);
    // SAFETY: fcntl returned a fresh owned descriptor.
    let duplicate = unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicate) };
    let mut transport = crate::sink::stdout_transport_on_fd(fd).unwrap();
    if destination != "socket" {
        assert_ne!(flags(transport.as_raw_fd()) & libc::O_NONBLOCK, 0);
    }
    // SAFETY: querying our transport's owned descriptor flags.
    assert_ne!(
        unsafe { libc::fcntl(transport.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let checks = AtomicUsize::new(0);
    let cancelled = || {
        assert_eq!(flags(fd), original);
        assert_eq!(flags(duplicate.as_raw_fd()), original);
        checks.fetch_add(1, Ordering::SeqCst);
        false
    };
    let failure = write_document(
        &mut transport,
        &vec![31; 2 * 1024 * 1024],
        SHORT_IDLE,
        &cancelled,
    )
    .unwrap_err();
    assert!(
        matches!(failure.reason, StdoutFailureReason::NoProgress),
        "stall failed on fd {fd}: {failure:?}"
    );
    assert!(
        checks.load(Ordering::SeqCst) > 2,
        "no during-stall flag observations"
    );
    assert_eq!(flags(fd), original);
    assert_eq!(flags(duplicate.as_raw_fd()), original);
    drop(transport);
    assert_eq!(flags(fd), original);
    assert_eq!(flags(duplicate.as_raw_fd()), original);
    eprintln!(
        "flags {destination}: before/during/after unchanged, checks={}, accepted={}, CLOEXEC verified",
        checks.load(Ordering::SeqCst),
        failure.accepted
    );
}

struct SocketPeerGuard {
    release: std::sync::mpsc::Sender<()>,
    handle: Option<JoinHandle<()>>,
    watchdog: Arc<AtomicBool>,
}

impl SocketPeerGuard {
    fn new(peer: UnixStream) -> Self {
        let (release, released) = std::sync::mpsc::channel();
        let watchdog = Arc::new(AtomicBool::new(false));
        let expired = Arc::clone(&watchdog);
        let handle = thread::spawn(move || {
            if released.recv_timeout(Duration::from_secs(2)).is_err() {
                expired.store(true, Ordering::SeqCst);
            }
            // Closing only this owned peer rescues an accidentally blocking
            // send; any such watchdog rescue remains a failing assertion.
            drop(peer);
        });
        Self {
            release,
            handle: Some(handle),
            watchdog,
        }
    }
}

impl Drop for SocketPeerGuard {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn transport_preserves_inherited_flags_during_stall() {
    const TEST: &str = "inventory_output::tests::transport_preserves_inherited_flags_during_stall";
    owned_cell(TEST, "flags-pipe", || {
        let (_reader, writer) = pipe();
        blocking(writer.as_raw_fd());
        check_stalled_flags(writer.as_raw_fd(), "pipe");
    });
    owned_cell(TEST, "flags-pty", || {
        let pty = StoppedPty::new();
        check_stalled_flags(pty.slave.as_raw_fd(), "PTY");
    });
    owned_cell(TEST, "flags-socket", || {
        let (writer, peer) = UnixStream::pair().unwrap();
        let peer = SocketPeerGuard::new(peer);
        check_stalled_flags(writer.as_raw_fd(), "socket");
        assert!(
            !peer.watchdog.load(Ordering::SeqCst),
            "socket stall watchdog rescued a blocked send"
        );
    });
}

#[test]
fn file_transport_preserves_shared_offset() {
    use std::io::{Seek, SeekFrom};
    let mut inherited = tempfile::tempfile().unwrap();
    inherited.write_all(b"prefix:").unwrap();
    let before = flags(inherited.as_raw_fd());
    let mut transport = crate::sink::stdout_transport_on_fd(inherited.as_raw_fd()).unwrap();
    assert_eq!(
        write_document(&mut transport, b"document", SHORT_IDLE, &|| false).unwrap(),
        8
    );
    drop(transport);
    inherited.write_all(b":suffix").unwrap();
    assert_eq!(flags(inherited.as_raw_fd()), before);
    inherited.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    inherited.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"prefix:document:suffix");
}

#[test]
fn private_reopen_failure_is_not_blocking_fallback() {
    let (mut reader, writer) = pipe();
    blocking(writer.as_raw_fd());
    let before = flags(writer.as_raw_fd());
    let signals = || 0;
    let mut stdout = FdStdout::new(writer.as_raw_fd(), &signals);
    stdout.begin_finalization();
    let called = AtomicBool::new(false);
    let failure = stdout
        .write_document_with_transport(b"pending", || {
            crate::sink::test_transport_with_reopen(writer.as_raw_fd(), |_| {
                called.store(true, Ordering::SeqCst);
                Err(io::ErrorKind::PermissionDenied.into())
            })
        })
        .unwrap_err();
    assert!(
        called.load(Ordering::SeqCst),
        "private acquisition was not exercised"
    );
    assert!(
        matches!(failure.reason, StdoutFailureReason::Io(ref e) if e.kind() == io::ErrorKind::PermissionDenied)
    );
    assert_eq!((failure.accepted, failure.total), (0, 7));
    assert_eq!(flags(writer.as_raw_fd()), before);
    assert_eq!(
        reader.read(&mut [0; 16]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn closed_peer_is_io_failure() {
    let signals = || 0;
    let (reader, writer) = pipe();
    drop(reader);
    let mut stdout = FdStdout::new(writer.as_raw_fd(), &signals);
    stdout.begin_finalization();
    let failure = stdout.write_document(b"closed").unwrap_err();
    assert!(matches!(failure.reason, StdoutFailureReason::Io(_)));
    assert_eq!((failure.accepted, failure.total), (0, 6));
    let (writer, reader) = UnixStream::pair().unwrap();
    drop(reader);
    let mut stdout = FdStdout::new(writer.as_raw_fd(), &signals);
    stdout.begin_finalization();
    let failure = stdout.write_document(b"closed").unwrap_err();
    assert!(
        matches!(failure.reason, StdoutFailureReason::Io(ref e) if e.kind() == io::ErrorKind::BrokenPipe),
        "closed socket: {failure:?}"
    );
    assert_eq!((failure.accepted, failure.total), (0, 6));
}

#[test]
fn cancel_interrupts_stalled_poll() {
    let (_reader, mut writer) = pipe();
    writer.write_all(&[9; 4096]).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let setter_flag = Arc::clone(&cancel);
    let setter = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        let delivered = Instant::now();
        setter_flag.store(true, Ordering::SeqCst);
        delivered
    });
    let observed = std::cell::Cell::new(None);
    let start = Instant::now();
    let cancelled = || {
        if cancel.load(Ordering::SeqCst) {
            if observed.get().is_none() {
                observed.set(Some(Instant::now()));
            }
            true
        } else {
            start.elapsed() >= Duration::from_secs(2)
        }
    };
    let result = write_document(&mut writer, b"pending", Duration::from_secs(1), &cancelled);
    let returned = Instant::now();
    let delivered = setter.join().unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "writer watchdog expired"
    );
    let failure = result.unwrap_err();
    assert!(matches!(failure.reason, StdoutFailureReason::Cancelled));
    assert_eq!((failure.accepted, failure.total), (0, 7));
    let after_observed = returned.duration_since(observed.get().expect("cancellation unobserved"));
    let after_delivery = returned.saturating_duration_since(delivered);
    assert!(
        after_observed < Duration::from_millis(100),
        "observed cancel took {after_observed:?}"
    );
    assert!(
        after_delivery < Duration::from_millis(100),
        "delivered cancel took {after_delivery:?}"
    );
    eprintln!(
        "cancel: delivered_to_return={after_delivery:?} observed_to_return={after_observed:?}; 4KiB full pipe, 20ms setter, concurrent libtest load; watchdog=false"
    );
}

#[test]
fn pty_flow_stop_is_real() {
    owned_cell(
        "inventory_output::tests::pty_flow_stop_is_real",
        "flow-stopped-pty",
        || {
            let pty = StoppedPty::new();
            let mut transport = crate::sink::stdout_transport_on_fd(pty.slave.as_raw_fd()).unwrap();
            assert_ne!(
                flags(transport.as_raw_fd()) & libc::O_NONBLOCK,
                0,
                "PTY transport must be nonblocking before its first write"
            );
            assert_eq!(
                transport.write(b"backpressure").unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            let start = Instant::now();
            let failure = write_document(&mut transport, b"pending", SHORT_IDLE, &|| {
                start.elapsed() > Duration::from_secs(2)
            })
            .unwrap_err();
            assert!(matches!(failure.reason, StdoutFailureReason::NoProgress));
            assert_eq!((failure.accepted, failure.total), (0, 7));
            assert!(start.elapsed() >= SHORT_IDLE && start.elapsed() < Duration::from_secs(2));
            eprintln!(
                "PTY: TCOOFF confirmed EAGAIN, accepted=0 total=7 elapsed={:?}; stayed stopped through writer return; TCOON in owned cleanup; watchdog=false",
                start.elapsed()
            );
        },
    );
}

#[test]
fn capture_stop_signal_preserves_output_but_second_signal_cancels() {
    let destination = File::options().write(true).open("/dev/null").unwrap();
    let count = AtomicUsize::new(1);
    let signals = || count.load(Ordering::SeqCst);
    let mut stdout = FdStdout::new(destination.as_raw_fd(), &signals);
    stdout.begin_finalization();
    assert_eq!(stdout.write_document(b"complete").unwrap(), 8);
    count.store(2, Ordering::SeqCst);
    let mut stdout = FdStdout::new(destination.as_raw_fd(), &signals);
    stdout.begin_finalization();
    let failure = stdout.write_document(b"cancel").unwrap_err();
    assert!(matches!(failure.reason, StdoutFailureReason::Cancelled));
    assert_eq!((failure.accepted, failure.total), (0, 6));
}

#[test]
fn invalid_poll_descriptor_is_io_failure() {
    struct InvalidWriter;
    impl AsRawFd for InvalidWriter {
        fn as_raw_fd(&self) -> RawFd {
            i32::MAX
        }
    }
    impl Write for InvalidWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("must not flush an invalid descriptor")
        }
    }
    let failure =
        write_document(&mut InvalidWriter, b"pending", SHORT_IDLE, &|| false).unwrap_err();
    assert!(
        matches!(failure.reason, StdoutFailureReason::Io(ref e) if e.raw_os_error() == Some(libc::EBADF))
    );
    assert_eq!((failure.accepted, failure.total), (0, 7));
}

#[test]
fn writer_adapter_counts_short_writes_and_flush_failure() {
    let mut writer = FaultWriter::new([Action::Accept(3), Action::Interrupted, Action::Accept(2)]);
    assert_eq!(
        WriterStdout(&mut writer)
            .write_document(b"adapter")
            .unwrap(),
        7
    );
    assert_eq!(writer.accepted, b"adapter");
    assert_eq!(writer.flushes, 1);
    let mut writer = FaultWriter::new([Action::Accept(3), Action::Zero]);
    let failure = WriterStdout(&mut writer)
        .write_document(b"adapter")
        .unwrap_err();
    assert_eq!((failure.accepted, failure.total), (3, 7));
    assert!(
        matches!(failure.reason, StdoutFailureReason::Io(ref e) if e.kind() == io::ErrorKind::WriteZero)
    );
    assert_eq!(writer.flushes, 0);
    let mut writer = FaultWriter::new([]);
    writer.flush_error = true;
    let failure = WriterStdout(&mut writer)
        .write_document(b"adapter")
        .unwrap_err();
    assert_eq!((failure.accepted, failure.total), (7, 7));
    assert!(matches!(failure.reason, StdoutFailureReason::Io(_)));
}

#[test]
fn fd_counts_after_success_error_and_cancel() {
    const CHILD: &str = "P11SCOPE_INVENTORY_OUTPUT_FD_COUNT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let signals = || 0;
        let destination = File::options().write(true).open("/dev/null").unwrap();
        let before = count();
        for _ in 0..8 {
            let mut stdout = FdStdout::new(destination.as_raw_fd(), &signals);
            stdout.begin_finalization();
            assert_eq!(stdout.write_document(b"complete").unwrap(), 8);
        }
        assert_eq!(count(), before, "fd leak after success");
        eprintln!(
            "fd success: before={before} after={}; 8 acquired transports",
            count()
        );
        let (writer, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let before = count();
        for _ in 0..8 {
            let mut stdout = FdStdout::new(writer.as_raw_fd(), &signals);
            stdout.begin_finalization();
            assert!(stdout.write_document(b"error").is_err());
        }
        assert_eq!(count(), before, "fd leak after I/O error");
        eprintln!(
            "fd I/O error: before={before} after={}; 8 acquired transports",
            count()
        );
        let before = count();
        for _ in 0..8 {
            let mut transport =
                crate::sink::stdout_transport_on_fd(destination.as_raw_fd()).unwrap();
            let failure =
                write_document(&mut transport, b"cancel", SHORT_IDLE, &|| true).unwrap_err();
            assert!(matches!(failure.reason, StdoutFailureReason::Cancelled));
        }
        assert_eq!(
            count(),
            before,
            "fd leak after acquired-transport cancellation"
        );
        eprintln!(
            "fd cancellation: before={before} after={}; 8 acquired transports",
            count()
        );
        return;
    }
    let mut child = OwnedTestChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "inventory_output::tests::fd_counts_after_success_error_and_cancel",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "isolated descriptor proof failed: {status}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "descriptor proof watchdog expired"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
