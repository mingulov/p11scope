//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Metered I/O primitives for the resume, cursor-key, replay,
//! closing-bracket, provider-facts, census and kernel-thread code
//! (INV-2: one admitted unit per native call).
//!
//! Each primitive asks `admit()` immediately before its single native
//! call and never retries: an interrupted or failed call returns its
//! error for the caller to treat as unknown. An open buys its close
//! together with it, so the close a [`MeteredFile`] drop issues is
//! prepaid even when a later admission refuses. A refused admission
//! returns `None` with no native call issued. The source guard
//! `resume_io_sites_admit_every_syscall` pins these bodies and forbids
//! raw syscalls in their callers.

use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, RawFd};

/// Test-only count of native calls the primitives issued on this
/// thread (opens, reads, closes, polls, readlinks, stats, fstat and
/// fstatfs).
#[cfg(test)]
pub(crate) mod syscall_test {
    use std::cell::Cell;

    thread_local! {
        static ISSUED: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn issued() {
        ISSUED.with(|issued| issued.set(issued.get() + 1));
    }

    pub(crate) fn count() -> u64 {
        ISSUED.with(Cell::get)
    }
}

fn issued() {
    #[cfg(test)]
    syscall_test::issued();
}

/// One open file whose close was bought with its open.
pub(crate) struct MeteredFile(std::fs::File);

impl MeteredFile {
    /// Open `path` read-only: two units, the open and the close its
    /// drop will issue.
    pub(crate) fn open(path: &str, admit: &mut dyn FnMut() -> bool) -> Option<io::Result<Self>> {
        if !admit() {
            return None;
        }
        if !admit() {
            return None;
        }
        issued();
        Some(std::fs::File::open(path).map(Self))
    }

    /// One `read(2)` into `buf`: one unit, no retry.
    pub(crate) fn read(
        &mut self,
        buf: &mut [u8],
        admit: &mut dyn FnMut() -> bool,
    ) -> Option<io::Result<usize>> {
        if !admit() {
            return None;
        }
        issued();
        Some(io::Read::read(&mut self.0, buf))
    }
}

impl Drop for MeteredFile {
    fn drop(&mut self) {
        // The field's own drop closes the descriptor; its unit was
        // bought by the open.
        issued();
    }
}

/// The longest procfs row the row reader accepts.
pub(crate) const MAX_ROW_BYTES: usize = 64 * 1024;

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
) -> Option<io::Result<Option<T>>> {
    const CHUNK_BYTES: usize = 4096;
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
                return Some(Err(over_long_row()));
            }
            rows += 1;
            if rows.is_multiple_of(64) && !admit() {
                return None;
            }
            let Ok(row) = std::str::from_utf8(&pending[start..end]) else {
                return Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "procfs row is not UTF-8",
                )));
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
            return Some(Err(over_long_row()));
        }
    }
}

fn over_long_row() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "procfs row exceeds 64 KiB")
}

/// The outcome of one bounded readlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinkRead {
    /// The whole target.
    Target(Vec<u8>),
    /// The link is gone (`ENOENT`).
    Missing,
    /// Any other failure, or a target that may have been truncated.
    Unknown,
}

/// One `readlink(2)` into a `PATH_MAX` buffer: one unit, no retry. A
/// target that fills the buffer may be truncated and reads as unknown.
pub(crate) fn readlink_once(path: &str, admit: &mut dyn FnMut() -> bool) -> Option<LinkRead> {
    let Ok(path) = std::ffi::CString::new(path) else {
        return Some(LinkRead::Unknown);
    };
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    if !admit() {
        return None;
    }
    issued();
    // SAFETY: `path` is NUL-terminated and `buf` is writable for its length.
    let read = unsafe { libc::readlink(path.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if read < 0 {
        return Some(
            if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                LinkRead::Missing
            } else {
                LinkRead::Unknown
            },
        );
    }
    let read = read as usize;
    if read >= buf.len() {
        return Some(LinkRead::Unknown);
    }
    buf.truncate(read);
    Some(LinkRead::Target(buf))
}

/// One non-blocking `poll(2)` of a pidfd: one unit, no retry.
/// `Ok(true)` is readable (the process exited); an interrupted or failed
/// poll is an error the caller treats as unknown.
pub(crate) fn poll_ready_once(
    fd: BorrowedFd<'_>,
    admit: &mut dyn FnMut() -> bool,
) -> Option<io::Result<bool>> {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if !admit() {
        return None;
    }
    issued();
    // SAFETY: one valid pollfd, zero timeout.
    let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
    Some(if result < 0 {
        Err(io::Error::last_os_error())
    } else if pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        Err(io::Error::other(format!(
            "pidfd poll failed: revents={:#x}",
            pollfd.revents
        )))
    } else {
        Ok(result > 0 && pollfd.revents & libc::POLLIN != 0)
    })
}

/// One `fstat(2)` of a held descriptor: one unit.
pub(crate) fn fstat(fd: RawFd, admit: &mut dyn FnMut() -> bool) -> Option<io::Result<libc::stat>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if !admit() {
        return None;
    }
    issued();
    #[cfg(test)]
    crate::discovery::identity::provider_metadata_read_test::metadata_read();
    // SAFETY: `fstat` fills `stat` for a valid fd; it is read only on success.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Some(Err(io::Error::last_os_error()));
    }
    // SAFETY: initialized by the successful call above.
    Some(Ok(unsafe { stat.assume_init() }))
}

/// One `fstatfs(2)` of a held descriptor: one unit.
pub(crate) fn fstatfs(
    fd: RawFd,
    admit: &mut dyn FnMut() -> bool,
) -> Option<io::Result<libc::statfs>> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if !admit() {
        return None;
    }
    issued();
    #[cfg(test)]
    crate::discovery::identity::provider_metadata_read_test::metadata_read();
    // SAFETY: `fstatfs` fills `stat` for a valid fd; it is read only on success.
    if unsafe { libc::fstatfs(fd, stat.as_mut_ptr()) } != 0 {
        return Some(Err(io::Error::last_os_error()));
    }
    // SAFETY: initialized by the successful call above.
    Some(Ok(unsafe { stat.assume_init() }))
}

/// One `stat(2)` of a path: one unit, no retry. Like
/// [`std::fs::metadata`], links are followed. An interrupted or failed
/// call returns its error for the caller to treat as unknown.
pub(crate) fn stat_path(
    path: &std::path::Path,
    admit: &mut dyn FnMut() -> bool,
) -> Option<io::Result<libc::stat>> {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return Some(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stat path holds a NUL byte",
        )));
    };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if !admit() {
        return None;
    }
    issued();
    // SAFETY: `path` is NUL-terminated; `stat` is read only on success.
    if unsafe { libc::stat(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Some(Err(io::Error::last_os_error()));
    }
    // SAFETY: initialized by the successful call above.
    Some(Ok(unsafe { stat.assume_init() }))
}

/// Whether a procfs file holds at least one byte, read through
/// [`MeteredFile`]: the open (with its close) plus one single-byte
/// read, each admitted first; `None` is a refusal. A mapping-heavy
/// address space is never read whole: one byte decides.
pub(crate) fn read_first_byte(
    path: &str,
    admit: &mut dyn FnMut() -> bool,
) -> Option<io::Result<Option<u8>>> {
    let mut file = match MeteredFile::open(path, admit)? {
        Ok(file) => file,
        Err(error) => return Some(Err(error)),
    };
    let mut byte = [0u8; 1];
    match file.read(&mut byte, admit)? {
        Ok(0) => Some(Ok(None)),
        Ok(_) => Some(Ok(Some(byte[0]))),
        Err(error) => Some(Err(error)),
    }
}
