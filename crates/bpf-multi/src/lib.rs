// SPDX-License-Identifier: GPL-3.0-or-later
//! Minimal multi-uprobe link helper (Task 2.1 spike vendor, UNWIRED).
//!
//! Provenance: `link_create` UAPI layout is borrowed from `ossl-bpf-sys`
//! v1.0.0 (`osslscope/crates/bpf-sys/src/lib.rs`, 306 lines, GPL-3.0-or-later,
//! UAPI verified against `linux/bpf.h`); attach semantics (pid handling,
//! cookie batching, error classification) follow upstream Aya PR #1417
//! ("aya: add multi-uprobe attach support", merged 2026-07-31 as
//! `5c1a79e0bdc36e77b304c1a08ff8b05e6b823108`); `bisect_attach` is ported
//! from osslscope `src/plan.rs` (`bisect_attach`, bounded log-n poison
//! isolation). See `docs/notes/multi-loader-spike.md` for the comparison
//! measurements and the decision.
//!
//! Scope is DELIBERATELY link-only: program loading (ELF/BTF/relocation,
//! map creation, CO-RE, tail-call program arrays, task storage) stays in
//! Aya 0.14 plus the narrow Task 2.2 load-flag backport. The sibling raw
//! `prog_load`/`map_create`/`prepare` path is REJECTED for p11scope: it
//! fail-closes on `.BTF`/`.BTF.ext`, legacy-only map defs, and
//! uprobe/uretprobe-only sections, while the real p11scope objects carry
//! BTF, `.maps` task storage, `raw_tp`/`tp_btf` programs, and two
//! tail-call targets (spike: both objects rejected with zero fd leak).
//!
//! Wiring is reserved for Task 2.2 (no `Cargo.toml`, no workspace member,
//! no root dependency yet) to avoid conflicts with parallel workers.
//! Task 2.2 adds the manifest (`libc`-only, already in tree), wires the
//! path dependency, and pairs this helper with the backported Aya load
//! flag (`expected_attach_type=48`) behind a runtime functional probe
//! with the 5.15 singles fallback.
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

pub const BPF_LINK_CREATE: u32 = 28;
pub const BPF_TRACE_UPROBE_MULTI: u32 = 48;
/// uprobe_multi link flag for return probes (`linux/bpf.h`:
/// `BPF_F_UPROBE_MULTI_RETURN = (1U << 0)`). Lives in the member flags
/// at attr offset 52, NOT the common flags at 12 (setting 12 EINVALs).
pub const BPF_F_UPROBE_MULTI_RETURN: u32 = 1;

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
    assert!(offsets.len() == cookies.len() && !offsets.is_empty());
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
/// Entry flavor; the return flavor is selected per group by Task 2.2.
pub fn attach_group(
    prog_fd: RawFd,
    pid: u32,
    path: &str,
    offsets: &[u64],
    cookies: &[u64],
) -> io::Result<OwnedFd> {
    let cpath = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in link path"))?;
    link_create_uprobe_multi(prog_fd, &cpath, offsets, cookies, pid)
}

/// Permission-class failures are systemic (caps/LSM), never per-offset:
/// fail the whole slice without a retry storm.
fn is_permission_err(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM))
}

/// Kernel-rejected multi support (old kernel without `uprobe_multi`):
/// `ENOTSUP`/`EOPNOTSUPP` unconditionally; `EINVAL` only for the unknown
/// attach type on pre-6.6 kernels (multi landed in 6.6; on newer kernels
/// `EINVAL` from a correctly loaded multi program means poison offsets
/// and must bisect, never fall back). Mirrors Aya PR #1417
/// `try_attach_uprobe_multi_link` classification.
pub fn is_unsupported_kernel_errno(errno: i32) -> bool {
    errno == libc::ENOTSUP || errno == libc::EOPNOTSUPP
}

/// Attach one group's sites, bisecting attach errors to isolate
/// kernel-rejected offsets (bounded: <= 2n-1 attempts, log n depth).
/// `attach` tries a slice as ONE multi link. Only permission-class
/// errors fail the whole slice; anything else (EINVAL, unknown kernel
/// errnos — RHEL returns 524 for un-attachable offsets) bisects, so one
/// poison offset cannot sink good siblings. Returns live links +
/// refused site indices (which become `unresolved_offsets` evidence).
/// Generic over the link handle so the isolation logic unit-tests
/// without caps or fds; production passes `attach_group`.
pub type TryAttach<'a, T> = dyn Fn(&[(u64, u64)]) -> io::Result<T> + 'a;

pub fn bisect_attach<T>(attach: &TryAttach<'_, T>, sites: &[(u64, u64)]) -> (Vec<T>, Vec<usize>) {
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
            Err(e) if !is_permission_err(&e) && idxs.len() > 1 => {
                let mid = idxs.len() / 2;
                stack.push(idxs[mid..].to_vec());
                stack.push(idxs[..mid].to_vec());
            }
            Err(_) => bad.extend(idxs),
        }
    }
    bad.sort_unstable();
    (links, bad)
}
