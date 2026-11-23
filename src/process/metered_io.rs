//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Metered I/O primitives for the resume, cursor-key, replay,
//! cache-victim and closing-bracket code (INV-2: one admitted unit per
//! native call).
//!
//! Each primitive asks `admit()` immediately before each native call it
//! issues and never retries: every kernel entry goes through [`native`]
//! exactly once, straight to `libc` (std's wrappers retry `EINTR` or
//! grow buffers under one unit, so they are not used here). An open buys
//! its close together with it, so the close a [`MeteredFile`] drop
//! issues is prepaid even when a later admission refuses. A refused
//! admission returns `None` with no native call issued.
//!
//! # The errno table
//!
//! A failed call proves nothing about a process, file or link. Every
//! errno, including `ENOENT` (hidepid, a namespace boundary, a racing
//! exit), `EINTR`, `EAGAIN`, `ENOMEM`, `EACCES` and `EPERM`, becomes an
//! [`Unproven`] error that callers can only treat as unknown. The one
//! exception is the pid probe [`pid_absent`]:
//!
//! | call | result | outcome |
//! |---|---|---|
//! | any primitive | success | the value read |
//! | any primitive | any errno | `Unproven` (unknown) |
//! | `kill(pid, 0)` | success or `EPERM` | the pid is held |
//! | `kill(pid, 0)` | `ESRCH` | no process holds the pid (a proof) |
//! | `kill(pid, 0)` | any other errno | `Unproven` |
//!
//! The source guard `resume_io_sites_admit_every_syscall` pins these
//! bodies and forbids raw syscalls and errno inspection in the callers.

use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, RawFd};

/// A failed native call. It proves nothing (see the errno table): the
/// error is kept for its message and for capability notes only.
#[derive(Debug)]
pub(crate) struct Unproven(io::Error);

impl Unproven {
    pub(crate) fn new(error: io::Error) -> Self {
        Self(error)
    }

    fn invalid(message: &'static str) -> Self {
        Self(io::Error::other(message))
    }

    /// Permission was refused (`EACCES`/`EPERM`): for capability notes.
    pub(crate) fn denied(&self) -> bool {
        matches!(self.0.raw_os_error(), Some(libc::EACCES | libc::EPERM))
    }

    /// The entry was absent (`ENOENT`). A routing hint only (a leader
    /// that left its namespace link may still have survivors), never a
    /// proof that a process exited.
    pub(crate) fn entry_absent(&self) -> bool {
        self.0.raw_os_error() == Some(libc::ENOENT)
    }
}

impl std::fmt::Display for Unproven {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A metered result: the value, or an unproven failure.
pub(crate) type Native<T> = Result<T, Unproven>;

/// The native calls the primitives issue. Every one goes through
/// [`native`] exactly once, so the test counter sees each attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeOp {
    Open,
    Read,
    Pread,
    Close,
    Readlink,
    Poll,
    Fstat,
    Fstatfs,
    Stat,
    Statx,
    Getdents,
    Kill,
}

/// Test-only record of the native calls the primitives issued on this
/// thread, with errno injection: an armed fault makes the `n`th later
/// call of one operation fail with that errno instead of reaching the
/// kernel (a close still closes, then reports the error).
#[cfg(test)]
pub(crate) mod syscall_test {
    use super::NativeOp;
    use std::cell::{Cell, RefCell};

    thread_local! {
        static CALLS: RefCell<Vec<NativeOp>> = const { RefCell::new(Vec::new()) };
        static FAULT: Cell<Option<(NativeOp, u32, i32)>> = const { Cell::new(None) };
    }

    /// Record one call of `op`; `Some(errno)` when an armed fault fires.
    pub(crate) fn issue(op: NativeOp) -> Option<i32> {
        CALLS.with(|calls| calls.borrow_mut().push(op));
        FAULT.with(|fault| match fault.get() {
            Some((armed, 0, errno)) if armed == op => {
                fault.set(None);
                Some(errno)
            }
            Some((armed, n, errno)) if armed == op => {
                fault.set(Some((armed, n - 1, errno)));
                None
            }
            _ => None,
        })
    }

    /// Native calls issued so far on this thread.
    pub(crate) fn count() -> u64 {
        CALLS.with(|calls| calls.borrow().len() as u64)
    }

    /// The calls issued since the count was `from`, in order.
    pub(crate) fn since(from: u64) -> Vec<NativeOp> {
        CALLS.with(|calls| calls.borrow()[from as usize..].to_vec())
    }

    /// Fail the `nth` (0-based) next call of `op` with `errno`.
    pub(crate) fn fail_nth(op: NativeOp, nth: u32, errno: i32) {
        FAULT.with(|fault| fault.set(Some((op, nth, errno))));
    }

    pub(crate) fn disarm() {
        FAULT.with(|fault| fault.set(None));
    }
}

/// Issue one native call: the single place every primitive reaches the
/// kernel, once per admitted unit (a close once per open). `call`
/// returns the raw syscall result; a negative result reads `errno`.
fn native(op: NativeOp, call: impl FnOnce() -> i64) -> io::Result<i64> {
    #[cfg(test)]
    if let Some(errno) = syscall_test::issue(op) {
        if op == NativeOp::Close {
            let _ = call();
        }
        return Err(io::Error::from_raw_os_error(errno));
    }
    #[cfg(not(test))]
    let _ = op;
    let result = call();
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn c_path(path: &str) -> Native<std::ffi::CString> {
    std::ffi::CString::new(path).map_err(|_| Unproven::invalid("path holds a NUL byte"))
}

/// One open file whose close was bought with its open.
pub(crate) struct MeteredFile {
    fd: RawFd,
}

impl MeteredFile {
    /// Open `path` read-only and close-on-exec with one `open(2)`: two
    /// units, the open and the close its drop will issue. An interrupted
    /// open is an error, never retried.
    pub(crate) fn open(path: &str, admit: &mut dyn FnMut() -> bool) -> Option<Native<Self>> {
        let path = match c_path(path) {
            Ok(path) => path,
            Err(error) => return Some(Err(error)),
        };
        if !admit() {
            return None;
        }
        if !admit() {
            return None;
        }
        let flags = libc::O_RDONLY | libc::O_CLOEXEC;
        // SAFETY: `path` is NUL-terminated; the result is a new descriptor or -1.
        let opened = native(NativeOp::Open, || {
            unsafe { libc::open(path.as_ptr(), flags) }.into()
        });
        Some(opened.map(|fd| Self { fd: fd as RawFd }).map_err(Unproven))
    }

    /// Open the directory `path` read-only and close-on-exec with one
    /// `open(2)`: two units, the open and the close its drop issues.
    pub(crate) fn directory(path: &str, admit: &mut dyn FnMut() -> bool) -> Option<Native<Self>> {
        let path = match c_path(path) {
            Ok(path) => path,
            Err(error) => return Some(Err(error)),
        };
        if !admit() {
            return None;
        }
        if !admit() {
            return None;
        }
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        // SAFETY: `path` is NUL-terminated; the result is a new descriptor or -1.
        let opened = native(NativeOp::Open, || {
            unsafe { libc::open(path.as_ptr(), flags) }.into()
        });
        Some(opened.map(|fd| Self { fd: fd as RawFd }).map_err(Unproven))
    }

    /// One `getdents64(2)` of this directory into `buf`: one unit, no
    /// retry. `Ok(0)` is the end of the directory; parse the records
    /// with [`dirent_names`].
    pub(crate) fn getdents(
        &mut self,
        buf: &mut [u8],
        admit: &mut dyn FnMut() -> bool,
    ) -> Option<Native<usize>> {
        if !admit() {
            return None;
        }
        let fd = self.fd;
        // SAFETY: `fd` is an open directory and `buf` is writable for its
        // length; the kernel writes whole records only.
        let read = native(NativeOp::Getdents, || unsafe {
            libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) as i64
        });
        Some(read.map(|count| count as usize).map_err(Unproven))
    }

    /// One `read(2)` into `buf`: one unit, no retry.
    pub(crate) fn read(
        &mut self,
        buf: &mut [u8],
        admit: &mut dyn FnMut() -> bool,
    ) -> Option<Native<usize>> {
        if !admit() {
            return None;
        }
        let fd = self.fd;
        // SAFETY: `fd` is open and `buf` is writable for its length.
        let read = native(NativeOp::Read, || unsafe {
            libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) as i64
        });
        Some(read.map(|count| count as usize).map_err(Unproven))
    }
}

impl Drop for MeteredFile {
    fn drop(&mut self) {
        // The close's unit was bought by the open. A failed close is not
        // retried: Linux releases the descriptor either way.
        let fd = self.fd;
        // SAFETY: `fd` is this file's own open descriptor, closed once here.
        let _ = native(NativeOp::Close, || unsafe { libc::close(fd) }.into());
    }
}

/// The longest procfs row the row reader accepts.
pub(crate) const MAX_ROW_BYTES: usize = 64 * 1024;

const CHUNK_BYTES: usize = 4096;

/// The first row of a procfs file that `find` accepts, read in 4 KiB
/// chunks through [`MeteredFile`]: the open (with its close), each
/// chunk read and each 64 rows examined are admitted first; `None` is a
/// refusal. The search stops at the first match, so an early row never
/// costs the whole table. A row longer than [`MAX_ROW_BYTES`], or one
/// that is not UTF-8, fails closed before it reaches `find`.
pub(crate) fn find_line<T>(
    path: &str,
    admit: &mut dyn FnMut() -> bool,
    mut find: impl FnMut(&str) -> Option<T>,
) -> Option<Native<Option<T>>> {
    let mut file = match MeteredFile::open(path, admit)? {
        Ok(file) => file,
        Err(error) => return Some(Err(error)),
    };
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = [0u8; CHUNK_BYTES];
    let mut rows = 0u64;
    loop {
        let count = match file.read(&mut chunk, admit)? {
            Ok(count) => count,
            Err(error) => return Some(Err(error)),
        };
        let eof = count == 0;
        // The carried partial row holds no newline: search the new bytes.
        let mut search = pending.len();
        pending.extend_from_slice(&chunk[..count]);
        let mut start = 0;
        loop {
            let end = match pending[search..].iter().position(|byte| *byte == b'\n') {
                Some(offset) => search + offset,
                None if eof && start < pending.len() => pending.len(),
                None => break,
            };
            if end - start > MAX_ROW_BYTES {
                return Some(Err(Unproven::invalid("procfs row exceeds 64 KiB")));
            }
            rows += 1;
            if rows.is_multiple_of(64) && !admit() {
                return None;
            }
            let Ok(row) = std::str::from_utf8(&pending[start..end]) else {
                return Some(Err(Unproven::invalid("procfs row is not UTF-8")));
            };
            if let Some(found) = find(row) {
                return Some(Ok(Some(found)));
            }
            start = (end + 1).min(pending.len());
            search = start;
            if end == pending.len() {
                break;
            }
        }
        pending.drain(..start);
        if eof {
            return Some(Ok(None));
        }
        if pending.len() > MAX_ROW_BYTES {
            return Some(Err(Unproven::invalid("procfs row exceeds 64 KiB")));
        }
    }
}

/// A whole procfs record of at most `max` bytes, read in 4 KiB chunks
/// to end of file through [`MeteredFile`] (the open with its close and
/// each chunk read admitted first): for records whose fields can hold a
/// newline, such as `/proc/<pid>/stat` with a newline in the task name.
/// A record over `max` fails closed.
pub(crate) fn read_record(
    path: &str,
    max: usize,
    admit: &mut dyn FnMut() -> bool,
) -> Option<Native<Vec<u8>>> {
    let mut file = match MeteredFile::open(path, admit)? {
        Ok(file) => file,
        Err(error) => return Some(Err(error)),
    };
    let mut record = Vec::new();
    let mut chunk = [0u8; CHUNK_BYTES];
    loop {
        let count = match file.read(&mut chunk, admit)? {
            Ok(count) => count,
            Err(error) => return Some(Err(error)),
        };
        if count == 0 {
            return Some(Ok(record));
        }
        if record.len() + count > max {
            return Some(Err(Unproven::invalid("procfs record exceeds its bound")));
        }
        record.extend_from_slice(&chunk[..count]);
    }
}

/// The outcome of one bounded readlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinkRead {
    /// The whole target.
    Target(Vec<u8>),
    /// Any failure (`ENOENT` included: a hidden or racing link is no
    /// proof of an image-less process), or a possibly truncated target.
    Unknown,
}

/// One `readlink(2)` into a `PATH_MAX` buffer: one unit, no retry. A
/// target that fills the buffer may be truncated and reads as unknown.
pub(crate) fn readlink_once(path: &str, admit: &mut dyn FnMut() -> bool) -> Option<LinkRead> {
    let Ok(path) = c_path(path) else {
        return Some(LinkRead::Unknown);
    };
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    if !admit() {
        return None;
    }
    let len = buf.len();
    let target = buf.as_mut_ptr();
    // SAFETY: `path` is NUL-terminated and `buf` is writable for `len` bytes.
    let read = native(NativeOp::Readlink, || unsafe {
        libc::readlink(path.as_ptr(), target.cast(), len) as i64
    });
    let Ok(read) = read else {
        return Some(LinkRead::Unknown);
    };
    let read = read as usize;
    if read >= buf.len() {
        return Some(LinkRead::Unknown);
    }
    buf.truncate(read);
    Some(LinkRead::Target(buf))
}

/// One non-blocking `poll(2)` of a pidfd: one unit, no retry.
/// `Ok(true)` is readable (the process exited); an interrupted or failed
/// poll is unproven.
pub(crate) fn poll_ready_once(
    fd: BorrowedFd<'_>,
    admit: &mut dyn FnMut() -> bool,
) -> Option<Native<bool>> {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if !admit() {
        return None;
    }
    let target = &mut pollfd as *mut libc::pollfd;
    // SAFETY: one valid pollfd, zero timeout.
    let polled = native(NativeOp::Poll, || {
        unsafe { libc::poll(target, 1, 0) }.into()
    });
    Some(match polled {
        Err(error) => Err(Unproven(error)),
        Ok(_) if pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 => Err(Unproven(
            io::Error::other(format!("pidfd poll failed: revents={:#x}", pollfd.revents)),
        )),
        Ok(_) => Ok(pollfd.revents & libc::POLLIN != 0),
    })
}

/// One `fstat(2)` of a held descriptor: one unit.
pub(crate) fn fstat(fd: RawFd, admit: &mut dyn FnMut() -> bool) -> Option<Native<libc::stat>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if !admit() {
        return None;
    }
    #[cfg(test)]
    crate::discovery::identity::provider_metadata_read_test::metadata_read();
    let target = stat.as_mut_ptr();
    // SAFETY: `fstat` fills `stat` for a valid fd; it is read only on success.
    let result = native(NativeOp::Fstat, || {
        unsafe { libc::fstat(fd, target) }.into()
    });
    Some(match result {
        // SAFETY: initialized by the successful call above.
        Ok(_) => Ok(unsafe { stat.assume_init() }),
        Err(error) => Err(Unproven(error)),
    })
}

/// One positioned `pread(2)` of a held descriptor at `offset`: one
/// unit, one attempt (an interrupted or short read is not retried).
pub(crate) fn pread_once(
    fd: BorrowedFd<'_>,
    buf: &mut [u8],
    offset: u64,
    admit: &mut dyn FnMut() -> bool,
) -> Option<Native<usize>> {
    let Ok(offset) = libc::off_t::try_from(offset) else {
        return Some(Err(Unproven::invalid(
            "positioned read offset out of range",
        )));
    };
    if !admit() {
        return None;
    }
    let fd = fd.as_raw_fd();
    // SAFETY: `fd` is a held open descriptor and `buf` is writable for
    // its length.
    let read = native(NativeOp::Pread, || unsafe {
        libc::pread(fd, buf.as_mut_ptr().cast(), buf.len(), offset) as i64
    });
    Some(read.map(|count| count as usize).map_err(Unproven))
}

/// One `fstatfs(2)` of a held descriptor: one unit.
pub(crate) fn fstatfs(fd: RawFd, admit: &mut dyn FnMut() -> bool) -> Option<Native<libc::statfs>> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if !admit() {
        return None;
    }
    #[cfg(test)]
    crate::discovery::identity::provider_metadata_read_test::metadata_read();
    let target = stat.as_mut_ptr();
    // SAFETY: `fstatfs` fills `stat` for a valid fd; it is read only on success.
    let result = native(NativeOp::Fstatfs, || {
        unsafe { libc::fstatfs(fd, target) }.into()
    });
    Some(match result {
        // SAFETY: initialized by the successful call above.
        Ok(_) => Ok(unsafe { stat.assume_init() }),
        Err(error) => Err(Unproven(error)),
    })
}

/// One `stat(2)` of a path: one unit.
pub(crate) fn stat_path(path: &str, admit: &mut dyn FnMut() -> bool) -> Option<Native<libc::stat>> {
    let path = match c_path(path) {
        Ok(path) => path,
        Err(error) => return Some(Err(error)),
    };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if !admit() {
        return None;
    }
    let target = stat.as_mut_ptr();
    // SAFETY: `path` is NUL-terminated; `stat` is read only on success.
    let result = native(NativeOp::Stat, || {
        unsafe { libc::stat(path.as_ptr(), target) }.into()
    });
    Some(match result {
        // SAFETY: initialized by the successful call above.
        Ok(_) => Ok(unsafe { stat.assume_init() }),
        Err(error) => Err(Unproven(error)),
    })
}

/// The mount-id bit of `statx(2)`'s mask (Linux 5.8).
const STATX_MNT_ID: u32 = 0x0000_1000;
/// The inode bit of `statx(2)`'s mask.
const STATX_INO: u32 = 0x0000_0100;

/// The kernel's `struct statx` (uapi `linux/stat.h`, 256 bytes), read
/// through the raw syscall: not every libc target binds `statx` (musl's
/// `libc` crate does not), so the layout is the kernel's own.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(
    dead_code,
    reason = "the kernel layout: unread fields keep the offsets"
)]
pub(crate) struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    spare0: u16,
    pub(crate) stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_times: [[u64; 2]; 4],
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    pub(crate) stx_dev_major: u32,
    pub(crate) stx_dev_minor: u32,
    pub(crate) stx_mnt_id: u64,
    spare: [u64; 13],
}

const _: () = assert!(std::mem::size_of::<Statx>() == 256);

/// One `statx(2)` of `path` (following links) for its device, inode and
/// mount id: one unit, no retry.
pub(crate) fn statx_path(path: &str, admit: &mut dyn FnMut() -> bool) -> Option<Native<Statx>> {
    let path = match c_path(path) {
        Ok(path) => path,
        Err(error) => return Some(Err(error)),
    };
    let mut stat = std::mem::MaybeUninit::<Statx>::zeroed();
    if !admit() {
        return None;
    }
    let target = stat.as_mut_ptr();
    let mask = STATX_INO | STATX_MNT_ID;
    // SAFETY: `path` is NUL-terminated; `stat` is a zeroed kernel-layout
    // `struct statx` written by the kernel, read only on success.
    let result = native(NativeOp::Statx, || unsafe {
        libc::syscall(
            libc::SYS_statx,
            libc::AT_FDCWD,
            path.as_ptr(),
            0,
            mask,
            target,
        )
    });
    Some(match result {
        // SAFETY: zero-initialized and filled by the successful call above.
        Ok(_) => Ok(unsafe { stat.assume_init() }),
        Err(error) => Err(Unproven(error)),
    })
}

/// The entry names of `getdents64(2)` records in `buf[..len]` (no
/// native call). A malformed record ends the walk.
pub(crate) fn dirent_names(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut names = Vec::new();
    let mut at = 0usize;
    // Each record: d_ino (8), d_off (8), d_reclen (2), d_type (1), name.
    while let Some(header) = buf.get(at..at + 19) {
        let reclen = usize::from(u16::from_ne_bytes([header[16], header[17]]));
        let Some(record) = buf.get(at..at + reclen).filter(|_| reclen > 19) else {
            break;
        };
        let name = &record[19..];
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        names.push(name[..end].to_vec());
        at += reclen;
    }
    names
}

/// Whether no process holds `pid`, from one `kill(pid, 0)` (no signal
/// is sent): one unit. `ESRCH` proves the pid unused, in the caller's
/// pid namespace (the one `pidfd_open` and procfs pids use); success or
/// `EPERM` proves it held. A pid above `i32::MAX` can never be assigned
/// and is absent with no call. Pid 0 names the caller's own process
/// group, so it proves nothing.
pub(crate) fn pid_absent(pid: u32, admit: &mut dyn FnMut() -> bool) -> Option<Native<bool>> {
    let Ok(raw) = libc::pid_t::try_from(pid) else {
        return Some(Ok(true));
    };
    if raw == 0 {
        return Some(Err(Unproven::invalid("pid 0 names the caller's group")));
    }
    if !admit() {
        return None;
    }
    // SAFETY: signal 0 only checks that `raw` names a process.
    let probed = native(NativeOp::Kill, || unsafe { libc::kill(raw, 0) }.into());
    Some(match probed {
        Ok(_) => Ok(false),
        Err(error) => match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(true),
            Some(libc::EPERM) => Ok(false),
            _ => Err(Unproven(error)),
        },
    })
}
