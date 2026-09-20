//! SPDX-License-Identifier: GPL-3.0-or-later
//! Multi-uprobe link creation plus bounded poison-offset isolation.
//!
//! Provenance: `link_create` UAPI layout is borrowed from `ossl-bpf-sys`
//! v1.0.0 (`osslscope/crates/bpf-sys/src/lib.rs`, 306 lines, GPL-3.0-or-later,
//! UAPI verified against `linux/bpf.h`); attach semantics (pid handling,
//! cookie batching, error classification) follow upstream Aya PR #1417
//! ("aya: add multi-uprobe attach support", merged 2026-07-31 as
//! `5c1a79e0bdc36e77b304c1a08ff8b05e6b823108`); `bisect_attach` is ported
//! from osslscope `src/plan.rs` (`bisect_attach`, bounded log-n poison
//! isolation). See `docs/notes/multi-loader-spike.md` for the comparison
//! measurements and the loader decision.
//!
//! Composition (Task 2.2): program loading stays in backported Aya 0.14
//! (`UProbe::load_multi` selects `expected_attach_type=48` for the twins).
//! This crate owns multi LINK creation against those Aya-loaded programs
//! plus the bisect that isolates kernel-rejected offsets. The session
//! selects multi behind a functional probe with a whole-session singles
//! fallback, mirroring the backported Unknown-mode fallback semantics
//! (multi first, singles on unsupported) at session granularity — a
//! 48-loaded program cannot single-attach, so fallback rebuilds with
//! 0-loaded twins rather than mixing link types.
//!
//! Scope is DELIBERATELY link-only: program loading (ELF/BTF/relocation,
//! map creation, CO-RE, tail-call program arrays, task storage) stays in
//! Aya 0.14 plus the narrow load-flag backport. The sibling raw
//! `prog_load`/`map_create`/`prepare` path is REJECTED for p11scope: it
//! fail-closes on `.BTF`/`.BTF.ext`, legacy-only map defs, and
//! uprobe/uretprobe-only sections, while the real p11scope objects carry
//! BTF, `.maps` task storage, `raw_tp`/`tp_btf` programs, and two
//! tail-call targets (spike: both objects rejected with zero fd leak).
//!
//! Raw-UAPI pid semantics (NOT libbpf's): `pid==0` means NO task filter
//! (all processes). Aya PR #1417 maps `UProbeScope::AllProcesses` to 0,
//! `OneProcess(pid)` to `pid`, and `CallingProcess` to the REAL pid (raw
//! zero would unfilter); the legacy perf path keeps `pid=0` for the
//! calling thread. p11scope multi uses `pid=0` plus the existing in-BPF
//! `PID_FILTER` for `Scope::Pid` (osslscope-proven: the 6.9.x pid-filter
//! thread bug misses sibling threads).
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

pub const BPF_LINK_CREATE: u32 = 28;
pub const BPF_TRACE_UPROBE_MULTI: u32 = 48;
/// uprobe_multi link flag for return probes (`linux/bpf.h`:
/// `BPF_F_UPROBE_MULTI_RETURN = (1U << 0)`). Lives in the member flags
/// at attr offset 52, NOT the common flags at 12 (setting 12 EINVALs).
pub const BPF_F_UPROBE_MULTI_RETURN: u32 = 1;

/// Member flags for one multi link: the return bit for return probes,
/// zero for entry probes.
pub fn multi_link_flags(is_return: bool) -> u32 {
    u32::from(is_return) * BPF_F_UPROBE_MULTI_RETURN
}

/// `BPF_LINK_CREATE` attr, `uprobe_multi` member layout (field offsets
/// verified against `linux/bpf.h` by the sibling crate).
#[repr(C)]
struct LinkAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    common_flags: u32, // 12: must stay 0 for multi
    path: u64,
    offsets: u64,
    ref_ctr_offsets: u64, // 32: 0 = none
    cookies: u64,
    cnt: u32,
    flags: u32, // 52: BPF_F_UPROBE_MULTI_RETURN goes here
    pid: u32,
}

fn bpf(cmd: u32, attr: *mut std::ffi::c_void, size: usize) -> io::Result<i32> {
    // SAFETY: raw bpf() with a caller-sized attr; exactly what libbpf does.
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd as libc::c_long, attr, size) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as i32)
    }
}

fn zeroed<T>() -> T {
    // SAFETY: all attr structs are plain-old-data (ints/arrays).
    unsafe { std::mem::zeroed() }
}

/// One uprobe_multi link: `offsets[i]` fires with `cookies[i]`.
/// `pid==0` attaches to all processes (raw-UAPI semantics).
/// Detach by dropping the returned fd.
pub fn link_create_uprobe_multi(
    prog_fd: RawFd,
    path: &CStr,
    offsets: &[u64],
    cookies: &[u64],
    pid: u32,
) -> io::Result<OwnedFd> {
    link_create_multi(prog_fd, path, offsets, cookies, pid, 0)
}

/// One uretprobe_multi link (return probes): same shape, the
/// `BPF_F_UPROBE_MULTI_RETURN` member flag set.
pub fn link_create_uretprobe_multi(
    prog_fd: RawFd,
    path: &CStr,
    offsets: &[u64],
    cookies: &[u64],
    pid: u32,
) -> io::Result<OwnedFd> {
    link_create_multi(
        prog_fd,
        path,
        offsets,
        cookies,
        pid,
        BPF_F_UPROBE_MULTI_RETURN,
    )
}

fn link_create_multi(
    prog_fd: RawFd,
    path: &CStr,
    offsets: &[u64],
    cookies: &[u64],
    pid: u32,
    flags: u32,
) -> io::Result<OwnedFd> {
    if offsets.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "multi link needs at least one offset",
        ));
    }
    if offsets.len() != cookies.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "multi link cookies len {} != offsets len {}",
                cookies.len(),
                offsets.len()
            ),
        ));
    }
    debug_assert_eq!(size_of::<LinkAttr>(), 64);
    debug_assert_eq!(std::mem::offset_of!(LinkAttr, flags), 52);
    let mut attr: LinkAttr = zeroed();
    attr.prog_fd = prog_fd as u32;
    attr.attach_type = BPF_TRACE_UPROBE_MULTI;
    attr.flags = flags;
    attr.path = path.as_ptr() as u64;
    attr.offsets = offsets.as_ptr() as u64;
    attr.cookies = cookies.as_ptr() as u64;
    attr.cnt = offsets.len() as u32;
    attr.pid = pid;
    let fd = bpf(
        BPF_LINK_CREATE,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<LinkAttr>(),
    )?;
    // SAFETY: bpf() returned a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// One multi link over `path` (production `bisect_attach` leaf).
/// `is_return` selects the uretprobe_multi member flag; entry otherwise.
/// Takes the path as bytes like the singles path: only NUL is rejected,
/// non-UTF8 provider paths reach the kernel unchanged.
pub fn attach_group(
    prog_fd: RawFd,
    pid: u32,
    path: &Path,
    offsets: &[u64],
    cookies: &[u64],
    is_return: bool,
) -> io::Result<OwnedFd> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in link path"))?;
    if is_return {
        link_create_uretprobe_multi(prog_fd, &cpath, offsets, cookies, pid)
    } else {
        link_create_uprobe_multi(prog_fd, &cpath, offsets, cookies, pid)
    }
}

/// Permission-class failures are systemic (caps/LSM), never per-offset:
/// fail the whole slice without a retry storm.
fn is_permission_err(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM))
}

/// The fd table is full: nothing more can attach, so the whole run ends
/// instead of bisecting (a split would fail identically).
fn is_exhaustion_err(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EMFILE)
}

/// Kernel-rejected multi support (old kernel without `uprobe_multi`):
/// `ENOTSUP`/`EOPNOTSUPP` unconditionally; `EINVAL` only for the unknown
/// attach type on pre-6.6 kernels (multi landed in 6.6; on newer kernels
/// `EINVAL` from a correctly loaded multi program means poison offsets
/// and must bisect, never fall back). Mirrors Aya PR #1417
/// `try_attach_uprobe_multi_link` classification. Callers only invoke
/// multi attach where the backend policy allows it (6.9+), so under the
/// session this predicate alone decides fallback; the doctor scratch
/// probe adds its own EINVAL-if-old-kernel rule.
pub fn is_unsupported_kernel_errno(errno: i32) -> bool {
    errno == libc::ENOTSUP || errno == libc::EOPNOTSUPP
}

/// Why a group attach stopped instead of producing links: either the
/// kernel lacks multi support (the caller falls back to singles) or the
/// fd table is full (the caller ends the run with one summary).
#[derive(Debug)]
pub enum GroupHalt {
    /// `ENOTSUP`/`EOPNOTSUPP` from `BPF_LINK_CREATE`: multi unsupported.
    Unsupported(io::Error),
    /// `EMFILE` from `BPF_LINK_CREATE`: nothing more can attach.
    Exhausted(io::Error),
}

impl std::fmt::Display for GroupHalt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(error) => write!(f, "multi-uprobe unsupported: {error}"),
            Self::Exhausted(error) => write!(f, "fd table exhausted: {error}"),
        }
    }
}

impl std::error::Error for GroupHalt {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unsupported(error) | Self::Exhausted(error) => Some(error),
        }
    }
}

/// One site the kernel refused, with the error that refused it: the
/// singleton slice's own error, or the fail-fast error shared by its
/// slice (OS errors round-trip exactly; anything else keeps its text).
#[derive(Debug)]
pub struct RefusedSite {
    /// Index into the `sites` slice passed to [`bisect_attach`].
    pub index: usize,
    /// The error that refused this site.
    pub error: io::Error,
}

/// One error value per refused index. `io::Error` is not `Clone`; every
/// production leaf error is an OS error, which round-trips exactly.
fn split_error(error: &io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(errno) => io::Error::from_raw_os_error(errno),
        None => io::Error::new(error.kind(), error.to_string()),
    }
}

/// Attach one group's sites, bisecting attach errors to isolate
/// kernel-rejected offsets (bounded: <= 2n-1 attempts, log n depth).
/// `attach` tries a slice as ONE multi link. Permission-class errors
/// fail the whole slice without splitting; anything else (EINVAL,
/// unknown kernel errnos — RHEL returns 524 for un-attachable offsets)
/// bisects, so one poison offset cannot sink good siblings. Unsupported
/// kernels and fd exhaustion halt with [`GroupHalt`] instead of
/// becoming refusals: the former needs a backend fallback, the latter
/// ends the run. Returns live links + refused site indices with errors
/// (which become per-slot attach failures). Generic over the link
/// handle so the isolation logic unit-tests without caps or fds;
/// production passes [`attach_group`].
pub type TryAttach<'a, T> = dyn Fn(&[(u64, u64)]) -> io::Result<T> + 'a;

pub fn bisect_attach<T>(
    attach: &TryAttach<'_, T>,
    sites: &[(u64, u64)],
) -> Result<(Vec<T>, Vec<RefusedSite>), GroupHalt> {
    let mut links = Vec::new();
    let mut bad = Vec::new();
    let mut stack: Vec<Vec<usize>> = vec![(0..sites.len()).collect()];
    while let Some(idxs) = stack.pop() {
        if idxs.is_empty() {
            continue;
        }
        let slice: Vec<(u64, u64)> = idxs.iter().map(|&i| sites[i]).collect();
        match attach(&slice) {
            Ok(l) => links.push(l),
            Err(error)
                if error
                    .raw_os_error()
                    .is_some_and(is_unsupported_kernel_errno) =>
            {
                return Err(GroupHalt::Unsupported(error));
            }
            Err(error) if is_exhaustion_err(&error) => {
                return Err(GroupHalt::Exhausted(error));
            }
            Err(error) => {
                if idxs.len() > 1 && !is_permission_err(&error) {
                    let mid = idxs.len() / 2;
                    stack.push(idxs[mid..].to_vec());
                    stack.push(idxs[..mid].to_vec());
                } else if idxs.len() == 1 {
                    bad.push(RefusedSite {
                        index: idxs[0],
                        error,
                    });
                } else {
                    for index in idxs {
                        bad.push(RefusedSite {
                            index,
                            error: split_error(&error),
                        });
                    }
                }
            }
        }
    }
    bad.sort_by_key(|refused| refused.index);
    Ok((links, bad))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn os_error(errno: i32) -> io::Error {
        io::Error::from_raw_os_error(errno)
    }

    #[test]
    fn multi_link_flags_set_only_the_return_bit() {
        assert_eq!(multi_link_flags(false), 0);
        assert_eq!(multi_link_flags(true), BPF_F_UPROBE_MULTI_RETURN);
        assert_eq!(BPF_F_UPROBE_MULTI_RETURN, 1);
    }

    #[test]
    fn unsupported_errno_is_not_poison_or_pressure() {
        assert!(is_unsupported_kernel_errno(libc::ENOTSUP));
        assert!(is_unsupported_kernel_errno(libc::EOPNOTSUPP));
        for errno in [0, libc::EINVAL, libc::EPERM, libc::EACCES, libc::EMFILE] {
            assert!(!is_unsupported_kernel_errno(errno), "errno {errno}");
        }
    }

    #[test]
    fn link_validation_rejects_empty_and_misaligned_without_a_syscall() {
        let path = c"/probe-target";
        let empty = link_create_uprobe_multi(-1, path, &[], &[], 0).unwrap_err();
        assert_eq!(empty.kind(), io::ErrorKind::InvalidInput);
        let mismatch = link_create_uretprobe_multi(-1, path, &[1, 2], &[7], 0).unwrap_err();
        assert_eq!(mismatch.kind(), io::ErrorKind::InvalidInput);
        // Only this crate's own validation produces InvalidInput here; the
        // kernel answers failed link creates with OS errors instead.
        assert!(empty.raw_os_error().is_none());
        assert!(mismatch.raw_os_error().is_none());
    }

    #[test]
    fn attach_group_rejects_nul_paths() {
        use std::os::unix::ffi::OsStrExt as _;
        let nul = std::ffi::OsStr::from_bytes(b"a\0b");
        let error = attach_group(-1, 0, Path::new(nul), &[1], &[1], false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn attach_group_accepts_non_utf8_paths_up_to_the_syscall() {
        use std::os::unix::ffi::OsStrExt as _;
        let raw = std::ffi::OsStr::from_bytes(b"/no/such/\xff.so");
        let error = attach_group(-1, 0, Path::new(raw), &[1], &[1], true).unwrap_err();
        // Validation passed (only NUL is rejected); the kernel answered.
        assert!(error.raw_os_error().is_some());
    }

    #[test]
    fn bisect_all_good_attaches_once() {
        let sites: Vec<(u64, u64)> = (0..8).map(|i| (i, 100 + i)).collect();
        let calls = Cell::new(0);
        let (links, refused) = bisect_attach(
            &|slice| {
                calls.set(calls.get() + 1);
                Ok(slice.to_vec())
            },
            &sites,
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0], sites);
        assert!(refused.is_empty());
    }

    #[test]
    fn bisect_empty_sites_is_a_vacuous_success() {
        let (links, refused) = bisect_attach(&|slice| Ok(slice.to_vec()), &[]).unwrap();
        assert!(links.is_empty());
        assert!(refused.is_empty());
    }

    #[test]
    fn bisect_isolates_one_poison_offset_with_bounded_attempts() {
        const POISON: u64 = 0xdead;
        let sites: Vec<(u64, u64)> = (0..8)
            .map(|i| (if i == 3 { POISON } else { i }, 100 + i))
            .collect();
        let calls = Cell::new(0);
        let (links, refused) = bisect_attach(
            &|slice: &[(u64, u64)]| {
                calls.set(calls.get() + 1);
                if slice.iter().any(|&(offset, _)| offset == POISON) {
                    Err(os_error(libc::EINVAL))
                } else {
                    Ok(slice.to_vec())
                }
            },
            &sites,
        )
        .unwrap();
        assert_eq!(refused.iter().map(|r| r.index).collect::<Vec<_>>(), vec![3]);
        assert_eq!(refused[0].error.raw_os_error(), Some(libc::EINVAL));
        let mut covered: Vec<(u64, u64)> = links.concat();
        covered.sort();
        let mut expected: Vec<(u64, u64)> =
            sites.iter().copied().filter(|s| s.0 != POISON).collect();
        expected.sort();
        assert_eq!(covered, expected);
        assert!(calls.get() < 2 * sites.len(), "calls {}", calls.get());
    }

    #[test]
    fn bisect_permission_fails_fast_without_splitting() {
        let sites: Vec<(u64, u64)> = (0..8).map(|i| (i, i)).collect();
        let calls = Cell::new(0);
        let (links, refused) = bisect_attach(
            &|_| {
                calls.set(calls.get() + 1);
                Err::<Vec<(u64, u64)>, _>(os_error(libc::EPERM))
            },
            &sites,
        )
        .unwrap();
        assert!(links.is_empty());
        assert_eq!(calls.get(), 1);
        assert_eq!(
            refused.iter().map(|r| r.index).collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
        for site in &refused {
            assert_eq!(site.error.raw_os_error(), Some(libc::EPERM));
        }
    }

    #[test]
    fn bisect_exhaustion_and_unsupported_halt_instead_of_refusing() {
        let sites: Vec<(u64, u64)> = (0..4).map(|i| (i, i)).collect();
        let calls = Cell::new(0);
        let halted = bisect_attach(
            &|_| {
                calls.set(calls.get() + 1);
                Err::<Vec<(u64, u64)>, _>(os_error(libc::EMFILE))
            },
            &sites,
        )
        .unwrap_err();
        assert!(matches!(halted, GroupHalt::Exhausted(_)), "{halted:?}");
        assert_eq!(
            halted.to_string(),
            "fd table exhausted: Too many open files (os error 24)"
        );
        let halted = bisect_attach(
            &|_| {
                calls.set(calls.get() + 1);
                Err::<Vec<(u64, u64)>, _>(os_error(libc::ENOTSUP))
            },
            &sites,
        )
        .unwrap_err();
        assert!(matches!(halted, GroupHalt::Unsupported(_)), "{halted:?}");
        // Halts stop the walk: exactly one attempt each, nothing refused.
        assert_eq!(calls.get(), 2);
    }
}
