//! SPDX-License-Identifier: GPL-3.0-or-later
//! Optional isolated profile for the discover helper.
//!
//! Contract: `docs/superpowers/specs/2026-11-06-v070-helper-isolation-contract.md`
//! (task 7.07a, helper-policy part). The fence is Landlock (read-only
//! filesystem plus denied TCP bind/connect) followed by a seccomp denylist
//! (no IP networking or socket connect/bind; no exec, mount, ptrace, BPF,
//! io_uring, keyring or file-metadata syscalls; no terminal-input-injection
//! or inode-attribute ioctls). Every denial fails with `EACCES`, never
//! kill/trap, so a fenced
//! provider call reads as an ordinary error. Applied after the shared
//! privilege drop and before any provider code runs; any failure refuses
//! before `dlopen`.
//!
//! Documented residuals: the provider still runs in-process as the
//! helper's uid with its environment, supplementary groups, readable
//! files, signaling and limit/priority changes (setpriority,
//! sched_setscheduler, ioprio_set); other terminal ioctls pass, as does
//! `AF_UNIX` datagram `sendto` without `connect`.

use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

/// Minimum Landlock ABI: 5 carries `IOCTL_DEV` on top of the ABI 4 TCP
/// rights, so every handled right below is enforceable. Below the floor
/// the profile refuses; it never silently runs weaker.
pub const LANDLOCK_ABI_FLOOR: libc::c_long = 5;

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

// Filesystem rights (linux/landlock.h, ABI 1 unless noted).
const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
const FS_REFER: u64 = 1 << 13; // ABI 2
const FS_TRUNCATE: u64 = 1 << 14; // ABI 3
const FS_IOCTL_DEV: u64 = 1 << 15; // ABI 5
// Network rights (ABI 4). No port rules are ever added: handling them
// without a rule denies every TCP bind/connect.
const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;

/// Everything the ruleset mediates. Reads and execute are granted on `/`
/// (§4 needs matrix); writes only on the `-o` parent directory, which
/// must be dedicated: the rule covers its whole subtree.
const HANDLED_FS: u64 = FS_EXECUTE
    | FS_WRITE_FILE
    | FS_READ_FILE
    | FS_READ_DIR
    | FS_REMOVE_DIR
    | FS_REMOVE_FILE
    | FS_MAKE_CHAR
    | FS_MAKE_DIR
    | FS_MAKE_REG
    | FS_MAKE_SOCK
    | FS_MAKE_FIFO
    | FS_MAKE_BLOCK
    | FS_MAKE_SYM
    | FS_REFER
    | FS_TRUNCATE
    | FS_IOCTL_DEV;
const HANDLED_NET: u64 = NET_BIND_TCP | NET_CONNECT_TCP;

/// Granted on `/`: the loader, lazy dependencies, provider reads and the
/// helper's own `/proc/self/maps` and object-identity reads keep working.
const ALLOW_TREE_READ_EXEC: u64 = FS_READ_FILE | FS_READ_DIR | FS_EXECUTE;
/// Granted on the `-o` parent directory: create, fsync, rename over a
/// regular file, unlink on failure. Nothing else is writable, and no
/// refer/truncate: the writer creates with `O_EXCL`, never truncates or
/// links, and renames within the directory.
const ALLOW_OUTPUT_DIR: u64 =
    FS_READ_FILE | FS_WRITE_FILE | FS_READ_DIR | FS_REMOVE_FILE | FS_MAKE_REG;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
    // Explicit padding. The kernel's own struct is these leading 12
    // bytes (`allowed_access` + `parent_fd`); the tail is ignored.
    _padding: u32,
}

// --- seccomp filter -----------------------------------------------------

const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
// The full audit arch token the kernel reports in seccomp_data.arch:
// EM_X86_64 (62) with the 64-bit and little-endian bits set. Comparing
// against bare 62 denies every syscall with ENOSYS.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const ARCH_OFFSET: u32 = 4;
const NR_OFFSET: u32 = 0;
const ARG0_LO_OFFSET: u32 = 16;
const ARG1_LO_OFFSET: u32 = 24;
const AF_UNIX: u32 = 1;
const AF_NETLINK: u32 = 16;
// Ioctl commands denied below: terminal-input-injection plus the inode
// mutators reachable from an O_RDONLY fd (Landlock's IOCTL_DEV does not
// mediate regular files). Every other ioctl stays allowed.
const TIOCSTI: u32 = 0x5412;
const TIOCLINUX: u32 = 0x541C;
// linux/fs.h, linux/fsverity.h, linux/fscrypt.h. The 32-bit SETFLAGS is
// _IOW('f', 2, int) for compat callers.
const FS_IOC_SETFLAGS: u32 = 0x4008_6602;
const FS_IOC_SETFLAGS32: u32 = 0x4004_6602;
const FS_IOC_FSSETXATTR: u32 = 0x401c_5820;
const FS_IOC_ENABLE_VERITY: u32 = 0x4080_6685;
const FS_IOC_SET_ENCRYPTION_POLICY: u32 = 0x800c_6613;
const FS_IOC_SETVERSION: u32 = 0x4008_7602;

// x86-64 syscall numbers in the denylist (contract §5).
const SYS_IOCTL: u32 = 16;
const SYS_SOCKET: u32 = 41;
const SYS_PRLIMIT64: u32 = 302;
const SYS_CONNECT: u32 = 42;
const SYS_BIND: u32 = 49;
const SYS_LISTEN: u32 = 50;
const SYS_ACCEPT: u32 = 43;
const SYS_ACCEPT4: u32 = 288;
const SYS_EXECVE: u32 = 59;
const SYS_EXECVEAT: u32 = 322;
const SYS_MOUNT: u32 = 165;
const SYS_UMOUNT2: u32 = 166;
const SYS_PIVOT_ROOT: u32 = 155;
const SYS_MOVE_MOUNT: u32 = 429;
const SYS_OPEN_TREE: u32 = 428;
const SYS_OPEN_TREE_ATTR: u32 = 467;
const SYS_MOUNT_SETATTR: u32 = 442;
const SYS_FSOPEN: u32 = 430;
const SYS_FSMOUNT: u32 = 432;
const SYS_PTRACE: u32 = 101;
const SYS_PROCESS_VM_WRITEV: u32 = 311;
const SYS_BPF: u32 = 321;
const SYS_PERF_EVENT_OPEN: u32 = 298;
const SYS_USERFAULTFD: u32 = 323;
const SYS_NAME_TO_HANDLE_AT: u32 = 303;
const SYS_OPEN_BY_HANDLE_AT: u32 = 304;
const SYS_KEYCTL: u32 = 250;
const SYS_ADD_KEY: u32 = 248;
const SYS_REQUEST_KEY: u32 = 249;
const SYS_INIT_MODULE: u32 = 175;
const SYS_FINIT_MODULE: u32 = 313;
const SYS_DELETE_MODULE: u32 = 176;
const SYS_KEXEC_LOAD: u32 = 246;
const SYS_KEXEC_FILE_LOAD: u32 = 320;
const SYS_REBOOT: u32 = 169;
const SYS_IOPL: u32 = 172;
const SYS_IOPERM: u32 = 173;
const SYS_SWAPON: u32 = 167;
const SYS_SWAPOFF: u32 = 168;
const SYS_SETHOSTNAME: u32 = 170;
const SYS_SETDOMAINNAME: u32 = 171;
const SYS_ACCT: u32 = 163;
// io_uring syscalls never hit the seccomp network checks, so the ring
// itself is denied: otherwise socket/connect run fenced only by Landlock
// (TCP), leaving UDP and AF_UNIX egress open.
const SYS_IO_URING_SETUP: u32 = 425;
const SYS_IO_URING_ENTER: u32 = 426;
const SYS_IO_URING_REGISTER: u32 = 427;
// File metadata Landlock cannot restrict (mode, owner, xattr, times,
// inode flags via file_setattr).
const SYS_FILE_SETATTR: u32 = 469;
const SYS_CHMOD: u32 = 90;
const SYS_FCHMOD: u32 = 91;
const SYS_FCHMODAT: u32 = 268;
const SYS_FCHMODAT2: u32 = 452;
const SYS_CHOWN: u32 = 92;
const SYS_FCHOWN: u32 = 93;
const SYS_LCHOWN: u32 = 94;
const SYS_FCHOWNAT: u32 = 260;
const SYS_SETXATTR: u32 = 188;
const SYS_LSETXATTR: u32 = 189;
const SYS_FSETXATTR: u32 = 190;
const SYS_REMOVEXATTR: u32 = 197;
const SYS_LREMOVEXATTR: u32 = 198;
const SYS_FREMOVEXATTR: u32 = 199;
const SYS_SETXATTRAT: u32 = 463;
const SYS_REMOVEXATTRAT: u32 = 466;
const SYS_UTIME: u32 = 132;
const SYS_UTIMES: u32 = 235;
const SYS_FUTIMESAT: u32 = 261;
const SYS_UTIMENSAT: u32 = 280;

/// Unconditional denials. `socket`, `ioctl` and `prlimit64` are handled
/// separately: `AF_UNIX` and `AF_NETLINK` socket domains stay allowed
/// while every other domain is denied, only the listed terminal-injection
/// and inode-attribute ioctl commands are denied, and only `prlimit64`
/// on pid 0 (the calling process) stays allowed.
const DENY_ALWAYS: &[u32] = &[
    SYS_CONNECT,
    SYS_BIND,
    SYS_LISTEN,
    SYS_ACCEPT,
    SYS_ACCEPT4,
    SYS_EXECVE,
    SYS_EXECVEAT,
    SYS_MOUNT,
    SYS_UMOUNT2,
    SYS_PIVOT_ROOT,
    SYS_MOVE_MOUNT,
    SYS_OPEN_TREE,
    SYS_OPEN_TREE_ATTR,
    SYS_MOUNT_SETATTR,
    SYS_FSOPEN,
    SYS_FSMOUNT,
    SYS_PTRACE,
    SYS_PROCESS_VM_WRITEV,
    SYS_BPF,
    SYS_PERF_EVENT_OPEN,
    SYS_USERFAULTFD,
    SYS_NAME_TO_HANDLE_AT,
    SYS_OPEN_BY_HANDLE_AT,
    SYS_KEYCTL,
    SYS_ADD_KEY,
    SYS_REQUEST_KEY,
    SYS_INIT_MODULE,
    SYS_FINIT_MODULE,
    SYS_DELETE_MODULE,
    SYS_KEXEC_LOAD,
    SYS_KEXEC_FILE_LOAD,
    SYS_REBOOT,
    SYS_IOPL,
    SYS_IOPERM,
    SYS_SWAPON,
    SYS_SWAPOFF,
    SYS_SETHOSTNAME,
    SYS_SETDOMAINNAME,
    SYS_ACCT,
    SYS_IO_URING_SETUP,
    SYS_IO_URING_ENTER,
    SYS_IO_URING_REGISTER,
    SYS_CHMOD,
    SYS_FCHMOD,
    SYS_FCHMODAT,
    SYS_FCHMODAT2,
    SYS_CHOWN,
    SYS_FCHOWN,
    SYS_LCHOWN,
    SYS_FCHOWNAT,
    SYS_SETXATTR,
    SYS_LSETXATTR,
    SYS_FSETXATTR,
    SYS_REMOVEXATTR,
    SYS_LREMOVEXATTR,
    SYS_FREMOVEXATTR,
    SYS_SETXATTRAT,
    SYS_REMOVEXATTRAT,
    SYS_UTIME,
    SYS_UTIMES,
    SYS_FUTIMESAT,
    SYS_UTIMENSAT,
    SYS_FILE_SETATTR,
];

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

// Classic BPF opcodes: ld [k] is LD|W|ABS, jeq #k is JMP|JEQ|K,
// jge #k is JMP|JGE|K, ret #k.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;

/// The x32 ABI bit: x32 syscalls arrive with the audit arch of x86-64
/// but nr | 0x4000_0000, matching no 64-bit equality check.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// A classic-BPF assembler with patched jumps, so every target is an
/// instruction index that [`validate_filter`] bounds-checks.
struct FilterBuilder {
    insns: Vec<SockFilter>,
}

impl FilterBuilder {
    fn new() -> Self {
        FilterBuilder { insns: Vec::new() }
    }

    fn emit(&mut self, insn: SockFilter) -> usize {
        self.insns.push(insn);
        self.insns.len() - 1
    }

    fn jeq(&mut self, k: u32) -> usize {
        self.emit(stmt(BPF_JMP_JEQ_K, k))
    }

    fn jge(&mut self, k: u32) -> usize {
        self.emit(stmt(BPF_JMP_JGE_K, k))
    }

    /// Point instruction `at` at absolute targets `jt` (equal) and `jf`.
    fn patch(&mut self, at: usize, jt: usize, jf: usize) -> Result<(), String> {
        let here = at + 1;
        let rel = |target: usize| target.checked_sub(here).filter(|&d| d <= u8::MAX as usize);
        let (Some(jt), Some(jf)) = (rel(jt), rel(jf)) else {
            return Err(format!("seccomp jump from {at} out of range"));
        };
        self.insns[at].jt = jt as u8;
        self.insns[at].jf = jf as u8;
        Ok(())
    }

    fn build(mut self) -> Result<Vec<SockFilter>, String> {
        // Gate on the native 64-bit ABI; anything else reads as ENOSYS.
        let arch = self.emit(stmt(BPF_LD_W_ABS, ARCH_OFFSET));
        let arch_ok = self.jeq(AUDIT_ARCH_X86_64);
        let bad_arch = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
        let load_nr = self.emit(stmt(BPF_LD_W_ABS, NR_OFFSET));
        self.patch(arch_ok, load_nr, bad_arch)?;
        let _ = arch;

        // x32 numbers share the audit arch but match no 64-bit equality
        // check; reject them before any of those checks run.
        let x32 = self.jge(X32_SYSCALL_BIT);
        let mut deny_jumps = Vec::with_capacity(DENY_ALWAYS.len());
        for nr in DENY_ALWAYS {
            deny_jumps.push(self.jeq(*nr));
        }
        let socket_jump = self.jeq(SYS_SOCKET);
        let ioctl_jump = self.jeq(SYS_IOCTL);
        let prlimit_jump = self.jeq(SYS_PRLIMIT64);
        let allow = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        let deny = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EACCES as u32));
        let x32_deny = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
        // socket(domain, ...): AF_UNIX and AF_NETLINK stay allowed.
        let socket_check = self.emit(stmt(BPF_LD_W_ABS, ARG0_LO_OFFSET));
        let is_unix = self.jeq(AF_UNIX);
        let is_netlink = self.jeq(AF_NETLINK);
        let deny_socket = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EACCES as u32));
        let allow_unix = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        // ioctl(fd, cmd, ...): TIOCSTI/TIOCLINUX inject input into the
        // operator's terminal, and the inode ioctls mutate flags, xattr,
        // version, encryption policy or verity from an O_RDONLY fd, so
        // those commands are denied and every other ioctl stays allowed.
        let ioctl_check = self.emit(stmt(BPF_LD_W_ABS, ARG1_LO_OFFSET));
        let mut ioctl_jumps = Vec::with_capacity(8);
        for cmd in [
            TIOCSTI,
            TIOCLINUX,
            FS_IOC_SETFLAGS,
            FS_IOC_SETFLAGS32,
            FS_IOC_FSSETXATTR,
            FS_IOC_ENABLE_VERITY,
            FS_IOC_SET_ENCRYPTION_POLICY,
            FS_IOC_SETVERSION,
        ] {
            ioctl_jumps.push(self.jeq(cmd));
        }
        let deny_ioctl = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EACCES as u32));
        let allow_ioctl = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        // prlimit64(pid, ...): pid 0 is the calling process (what libc
        // passes for self) and stays allowed; any other pid would lower
        // a sibling's limits and is denied.
        let prlimit_check = self.emit(stmt(BPF_LD_W_ABS, ARG0_LO_OFFSET));
        let is_self = self.jeq(0);
        let deny_prlimit = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EACCES as u32));
        let allow_prlimit = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        // Every target is known now; patch the whole chain explicitly.
        // Each `jeq nr`: equal falls into `deny`, else the next check,
        // walked back to front so `next` is always the following check.
        let mut next = socket_jump;
        for at in deny_jumps.iter().rev() {
            self.patch(*at, deny, next)?;
            next = *at;
        }
        self.patch(x32, x32_deny, next)?;
        self.patch(socket_jump, socket_check, ioctl_jump)?;
        self.patch(ioctl_jump, ioctl_check, prlimit_jump)?;
        self.patch(prlimit_jump, prlimit_check, allow)?;
        self.patch(is_unix, allow_unix, is_netlink)?;
        self.patch(is_netlink, allow_unix, deny_socket)?;
        // Each denied ioctl: equal falls into `deny_ioctl`, else the next
        // command check, walked back to front; the last falls to allow.
        let mut next_ioctl = allow_ioctl;
        for at in ioctl_jumps.iter().rev() {
            self.patch(*at, deny_ioctl, next_ioctl)?;
            next_ioctl = *at;
        }
        self.patch(is_self, allow_prlimit, deny_prlimit)?;
        validate_filter(&self.insns)?;
        Ok(self.insns)
    }
}

/// Every jump lands inside the program and the program ends in returns.
fn validate_filter(insns: &[SockFilter]) -> Result<(), String> {
    if insns.is_empty() || insns.len() > 4096 {
        return Err("seccomp program has an invalid length".into());
    }
    for (at, insn) in insns.iter().enumerate() {
        if insn.code == BPF_JMP_JEQ_K || insn.code == BPF_JMP_JGE_K {
            let jt = at + 1 + insn.jt as usize;
            let jf = at + 1 + insn.jf as usize;
            if jt >= insns.len() || jf >= insns.len() {
                return Err(format!("seccomp jump from {at} leaves the program"));
            }
        } else if insn.code != BPF_LD_W_ABS && insn.code != BPF_RET_K {
            return Err(format!(
                "unexpected seccomp opcode {:#x} at {at}",
                insn.code
            ));
        }
    }
    Ok(())
}

fn os_error(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}

/// Open the `/` rule path (`O_PATH`). It keeps its own wording: the tree
/// rule is not the output directory.
fn open_rule_path(path: &Path) -> Result<File, String> {
    use std::ffi::CString;
    let raw = match CString::new(path.as_os_str().as_bytes()) {
        Ok(raw) => raw,
        Err(_) => {
            return Err(format!(
                "isolated profile: cannot open {}: path has a NUL byte",
                path.display()
            ));
        }
    };
    let fd = unsafe { libc::open(raw.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!(
            "isolated profile: cannot open {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Open the `-o` parent for Landlock rule use and return the same
/// descriptor the rule is built on: one open, every check on that fd, so
/// no later reopen can resolve anywhere else.
///
/// A Landlock path rule grants a whole subtree, so the parent must be a
/// dedicated directory: empty, or holding only `target` as a single-link
/// regular file (the rename-over case). Any other type or a hard link
/// would grant the shared subtree or inode through the writable rule, so
/// it refuses with the not-empty wording. A parent that *is* the
/// filesystem root — by device and inode, which also catches a bind mount
/// of `/` — refuses with the root wording. Anything else unusable refuses
/// as `isolated profile: output directory <dir> is unusable: <reason>`.
fn open_output_dir(dir: &Path, target: &std::ffi::OsStr) -> Result<File, String> {
    use std::ffi::CString;
    use std::os::unix::fs::MetadataExt as _;
    let unusable = |reason: String| {
        format!(
            "isolated profile: output directory {} is unusable: {reason}",
            dir.display()
        )
    };
    let raw = match CString::new(dir.as_os_str().as_bytes()) {
        Ok(raw) => raw,
        Err(_) => {
            return Err(unusable(format!(
                "cannot open {}: path has a NUL byte",
                dir.display()
            )));
        }
    };
    let fd = unsafe {
        libc::open(
            raw.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let errno = std::io::Error::last_os_error();
        // `O_DIRECTORY` fails on non-directories: a file (or a symlink to
        // one) keeps the not-a-directory wording.
        let not_a_dir = std::fs::symlink_metadata(dir).is_ok_and(|meta| !meta.file_type().is_dir());
        if not_a_dir {
            return Err(format!(
                "isolated profile: output directory {} is unusable: not a directory",
                dir.display()
            ));
        }
        return Err(unusable(format!("cannot open {}: {errno}", dir.display())));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    // The filesystem root by identity, not by spelling: a canonical path
    // misses bind mounts and races a reopen; this held fd can be neither.
    let same_as_root = file
        .metadata()
        .and_then(|ours| std::fs::metadata("/").map(|root| (ours, root)))
        .map(|(ours, root)| ours.dev() == root.dev() && ours.ino() == root.ino())
        .map_err(|error| unusable(format!("cannot stat {}: {error}", dir.display())))?;
    if same_as_root {
        return Err(
            "isolated profile: output directory / is unusable: refusing the filesystem root".into(),
        );
    }
    // The listing runs against the held descriptor (`/proc/self/fd/N`
    // names the same open file description), so it cannot race a rename.
    let listing = std::fs::read_dir(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|error| unusable(format!("cannot list {}: {error}", dir.display())))?;
    let mut seen_target = false;
    for entry in listing {
        let entry =
            entry.map_err(|error| unusable(format!("cannot list {}: {error}", dir.display())))?;
        let name = entry.file_name();
        if name == target {
            seen_target = true;
            continue;
        }
        if name != "." && name != ".." {
            return Err(unusable("not empty; use a dedicated directory".into()));
        }
    }
    // The rename-over exception holds only for a single-link regular
    // file: a directory would grant its subtree, a hard link the shared
    // inode, and any other type a writer the fence must not grant.
    // Checked on the same held descriptor, never a reopened path.
    if seen_target {
        let target_raw = match CString::new(target.as_bytes()) {
            Ok(raw) => raw,
            Err(_) => {
                return Err(unusable("not empty; use a dedicated directory".into()));
            }
        };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                file.as_raw_fd(),
                target_raw.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(unusable(format!(
                "cannot stat {}: {}",
                dir.display(),
                std::io::Error::last_os_error()
            )));
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 {
            return Err(unusable("not empty; use a dedicated directory".into()));
        }
    }
    Ok(file)
}

fn landlock_abi() -> Result<libc::c_long, String> {
    let abi = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 0 {
        return Err(os_error("isolated profile: Landlock unavailable"));
    }
    Ok(abi)
}

fn apply_landlock(out: Option<&Path>) -> Result<(), String> {
    let abi = landlock_abi()?;
    if abi < LANDLOCK_ABI_FLOOR {
        return Err(format!(
            "isolated profile: Landlock ABI {abi} below required {LANDLOCK_ABI_FLOOR}"
        ));
    }
    let root = open_rule_path(Path::new("/"))?;
    // The parent rule matches the manifest writer's directory choice (a
    // bare name means `.`); the target name is the only entry a
    // dedicated directory may already hold. A `-o` without a file name
    // leaves no exception: the directory must be empty.
    let output = out
        .map(|path| {
            let parent = match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };
            let target = path.file_name().unwrap_or(std::ffi::OsStr::new(""));
            open_output_dir(parent, target)
        })
        .transpose()?;
    let attr = RulesetAttr {
        handled_access_fs: HANDLED_FS,
        handled_access_net: HANDLED_NET,
    };
    let ruleset = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr,
            size_of::<RulesetAttr>(),
            0,
        )
    };
    if ruleset < 0 {
        return Err(os_error("isolated profile: Landlock ruleset create failed"));
    }
    let ruleset = unsafe { File::from_raw_fd(ruleset as i32) };
    let add = |allowed: u64, parent: &File| {
        let rule = PathBeneathAttr {
            allowed_access: allowed,
            parent_fd: parent.as_raw_fd(),
            _padding: 0,
        };
        if unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &rule,
                0,
            )
        } != 0
        {
            return Err(os_error("isolated profile: Landlock rule add failed"));
        }
        Ok(())
    };
    add(ALLOW_TREE_READ_EXEC, &root)?;
    if let Some(output) = &output {
        add(ALLOW_OUTPUT_DIR, output)?;
    }
    if unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset.as_raw_fd(), 0) } != 0 {
        return Err(os_error("isolated profile: Landlock restrict failed"));
    }
    Ok(())
}

fn apply_seccomp() -> Result<(), String> {
    if !cfg!(target_arch = "x86_64") {
        return Err("isolated profile: x86-64 only".into());
    }
    let insns = FilterBuilder::new().build()?;
    let prog = SockFprog {
        len: insns.len() as u16,
        filter: insns.as_ptr(),
    };
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &prog as *const SockFprog,
            0,
            0,
        )
    } != 0
    {
        return Err(os_error("isolated profile: seccomp install failed"));
    }
    // The kernel copied the program; dropping `insns` here is safe.
    Ok(())
}

/// Apply the isolated fence with injectable stages (test seam): the
/// architecture gate runs before any raw syscall, so a non-x86-64 build
/// refuses with `x86-64 only` instead of probing Landlock with the wrong
/// syscall numbers (contract R6).
fn apply_isolated_with(
    is_x86_64: bool,
    out: Option<&Path>,
    landlock: impl FnOnce(Option<&Path>) -> Result<(), String>,
    seccomp: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if !is_x86_64 {
        return Err("isolated profile: x86-64 only".into());
    }
    landlock(out)?;
    seccomp()
}

/// The calling context the fence requires. Landlock `restrict_self`
/// and seccomp fence only the calling thread, and both need
/// `no_new_privs` for unprivileged use — so the fence is applied only by
/// a single-threaded, non-root, no-new-privs caller, never by whatever
/// thread happens to call it after a fork or a dropped guard.
struct FenceContext {
    no_new_privs: libc::c_int,
    euid: libc::uid_t,
    threads: u32,
}

fn read_fence_context() -> Result<FenceContext, String> {
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privs < 0 {
        return Err(os_error("isolated profile: cannot read no_new_privs"));
    }
    let euid = unsafe { libc::geteuid() };
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("isolated profile: cannot read /proc/self/status: {error}"))?;
    let threads = status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|value| value.trim().parse::<u32>().ok())
        .ok_or_else(|| "isolated profile: cannot count process threads".to_string())?;
    Ok(FenceContext {
        no_new_privs,
        euid,
        threads,
    })
}

fn check_fence_context(context: &FenceContext) -> Result<(), String> {
    if context.no_new_privs != 1 {
        return Err("isolated profile: refusing to fence without no_new_privs".into());
    }
    if context.euid == 0 {
        return Err("isolated profile: refusing to fence as root".into());
    }
    if context.threads != 1 {
        return Err("isolated profile: refusing to fence a multithreaded process".into());
    }
    Ok(())
}

/// Apply the isolated fence: the caller-context check, then the
/// architecture gate, then Landlock, then seccomp. `out` is the full
/// `-o` path, or `None` for stdout output (the whole tree stays
/// read-only). The `-o` parent must be a dedicated directory, opened
/// once and checked on the same descriptor the Landlock rule is built
/// on. On success the caller may load the provider; on failure it must
/// exit before `dlopen` — provider code never runs.
pub fn apply_isolated(out: Option<&Path>) -> Result<(), String> {
    check_fence_context(&read_fence_context()?)?;
    apply_isolated_with(
        cfg!(target_arch = "x86_64"),
        out,
        apply_landlock,
        apply_seccomp,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_starts_with_the_arch_gate_and_covers_the_denylist() {
        let insns = FilterBuilder::new().build().unwrap();
        assert_eq!(insns[0].code, BPF_LD_W_ABS);
        assert_eq!(insns[0].k, ARCH_OFFSET);
        assert_eq!(insns[1].code, BPF_JMP_JEQ_K);
        assert_eq!(insns[1].k, AUDIT_ARCH_X86_64);
        let jeq: Vec<u32> = insns
            .iter()
            .filter(|insn| insn.code == BPF_JMP_JEQ_K)
            .map(|insn| insn.k)
            .collect();
        for probe in [
            SYS_SOCKET,
            SYS_CONNECT,
            SYS_EXECVE,
            SYS_MOUNT,
            SYS_PTRACE,
            SYS_BPF,
            SYS_PERF_EVENT_OPEN,
            AF_UNIX,
            AF_NETLINK,
        ] {
            assert!(jeq.contains(&probe), "denylist lost {probe}");
        }
        // Default and AF_UNIX/NETLINK exits allow; denials use EACCES.
        let returns: Vec<u32> = insns
            .iter()
            .filter(|insn| insn.code == BPF_RET_K)
            .map(|insn| insn.k)
            .collect();
        assert!(returns.contains(&SECCOMP_RET_ALLOW));
        assert!(returns.contains(&(SECCOMP_RET_ERRNO | libc::EACCES as u32)));
        assert!(!returns.contains(&0x0000_0000)); // kill
        assert!(!returns.contains(&0x0003_0000)); // trap
    }

    #[test]
    fn arch_token_is_the_full_audit_value_not_the_elf_machine() {
        // EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE. Bare 62 never
        // matches seccomp_data.arch and would ENOSYS every syscall.
        assert_eq!(AUDIT_ARCH_X86_64, 62 | 0x8000_0000 | 0x4000_0000);
    }

    #[test]
    fn validator_rejects_jumps_that_leave_the_program() {
        let good = FilterBuilder::new().build().unwrap();
        assert!(validate_filter(&good).is_ok());
        let mut bad = good.clone();
        bad[1].jt = u8::MAX;
        assert!(validate_filter(&bad).is_err());
        assert!(validate_filter(&[]).is_err());
    }

    #[test]
    fn handled_rights_fit_the_abi_floor() {
        // Every handled bit exists at or below ABI 5 (IOCTL_DEV is the
        // highest, introduced at 5); higher rights must never sneak in.
        assert_eq!(HANDLED_FS, (1 << 16) - 1);
        assert_eq!(HANDLED_NET, NET_BIND_TCP | NET_CONNECT_TCP);
        assert_eq!(LANDLOCK_ABI_FLOOR, 5);
        // The output rule grants no execute and no device control.
        assert_eq!(ALLOW_OUTPUT_DIR & FS_EXECUTE, 0);
        assert_eq!(ALLOW_OUTPUT_DIR & FS_IOCTL_DEV, 0);
        // The tree rule grants no write of any kind.
        assert_eq!(
            ALLOW_TREE_READ_EXEC & (FS_WRITE_FILE | FS_MAKE_REG | FS_TRUNCATE),
            0
        );
    }

    #[test]
    fn rule_paths_reject_files_for_the_output_directory() {
        let target = std::ffi::OsStr::new("manifest.json");
        let dir = std::env::temp_dir().join(format!("isolation-rule-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(open_output_dir(&empty, target).is_ok());
        let error = open_output_dir(&file, target).unwrap_err();
        assert!(error.contains("not a directory"), "{error}");
        assert!(open_rule_path(&file).is_ok());
        assert!(open_output_dir(&dir.join("missing"), target).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unusable_output_directories_use_the_contract_wording() {
        use std::os::unix::ffi::OsStrExt as _;
        let target = std::ffi::OsStr::new("manifest.json");
        let dir = std::env::temp_dir().join(format!("isolation-wording-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Missing, file-as-parent and NUL parents all refuse with the
        // contract §3 step-1 shape; the `/` rule path keeps its own.
        let missing = dir.join("no-such-dir");
        let error = open_output_dir(&missing, target).unwrap_err();
        assert!(
            error.starts_with("isolated profile: output directory ")
                && error.contains(" is unusable: "),
            "{error}"
        );
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        let error = open_output_dir(&file, target).unwrap_err();
        assert!(
            error.starts_with("isolated profile: output directory ")
                && error.contains(" is unusable: "),
            "{error}"
        );
        let nul = std::ffi::OsStr::from_bytes(b"bad\0dir");
        let error = open_output_dir(Path::new(nul), target).unwrap_err();
        assert!(
            error.starts_with("isolated profile: output directory ")
                && error.contains(" is unusable: "),
            "{error}"
        );
        let error = open_rule_path(&missing).unwrap_err();
        assert!(error.contains("cannot open"), "{error}");
        assert!(
            !error.contains("output directory"),
            "the tree rule is not the output dir: {error}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_nonempty_output_directory_names_dedication() {
        let target = std::ffi::OsStr::new("manifest.json");
        let dir = std::env::temp_dir().join(format!("isolation-dedicated-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = dir.join("out");
        let sub = out.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("victim"), b"keep").unwrap();
        let error = open_output_dir(&out, target).unwrap_err();
        assert!(
            error.contains("not empty; use a dedicated directory"),
            "{error}"
        );
        // Empty, or holding only the target name: accepted.
        std::fs::remove_dir_all(&out).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        assert!(open_output_dir(&out, target).is_ok());
        std::fs::write(out.join("manifest.json"), b"stale").unwrap();
        assert!(open_output_dir(&out, target).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn target_name_exception_rejects_a_directory() {
        let target = std::ffi::OsStr::new("manifest.json");
        let dir = std::env::temp_dir().join(format!("isolation-target-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = dir.join("out");
        std::fs::create_dir_all(out.join("manifest.json")).unwrap();
        std::fs::write(out.join("manifest.json").join("victim"), b"keep").unwrap();
        let error = open_output_dir(&out, target).unwrap_err();
        assert!(
            error.contains("not empty; use a dedicated directory"),
            "{error}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn target_name_exception_rejects_a_hard_link() {
        let target = std::ffi::OsStr::new("manifest.json");
        let dir =
            std::env::temp_dir().join(format!("isolation-target-nlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let outside = dir.join("outside.txt");
        std::fs::write(&outside, b"outside-keep").unwrap();
        std::fs::hard_link(&outside, out.join("manifest.json")).unwrap();
        let error = open_output_dir(&out, target).unwrap_err();
        assert!(
            error.contains("not empty; use a dedicated directory"),
            "{error}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn target_name_exception_rejects_a_symlink() {
        let target = std::ffi::OsStr::new("manifest.json");
        let dir =
            std::env::temp_dir().join(format!("isolation-target-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let outside = dir.join("outside.txt");
        std::fs::write(&outside, b"outside-keep").unwrap();
        std::os::unix::fs::symlink(&outside, out.join("manifest.json")).unwrap();
        let error = open_output_dir(&out, target).unwrap_err();
        assert!(
            error.contains("not empty; use a dedicated directory"),
            "{error}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn arch_gate_runs_before_any_fence_syscall() {
        use std::cell::Cell;
        let landlock_called = Cell::new(false);
        let seccomp_called = Cell::new(false);
        let error = apply_isolated_with(
            false,
            Some(Path::new("/no-such-output-dir")),
            |_| {
                landlock_called.set(true);
                Ok(())
            },
            || {
                seccomp_called.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error, "isolated profile: x86-64 only");
        assert!(
            !landlock_called.get(),
            "the arch gate must run before Landlock"
        );
        assert!(
            !seccomp_called.get(),
            "the arch gate must run before seccomp"
        );
    }

    #[test]
    fn supported_arch_runs_both_stages_in_order() {
        use std::cell::RefCell;
        let order = RefCell::new(Vec::new());
        let result = apply_isolated_with(
            true,
            None,
            |dir| {
                order.borrow_mut().push("landlock");
                assert_eq!(dir, None);
                Ok(())
            },
            || {
                order.borrow_mut().push("seccomp");
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert_eq!(*order.borrow(), ["landlock", "seccomp"]);
        let error = apply_isolated_with(
            true,
            None,
            |_| Err("landlock stage failed".to_string()),
            || {
                panic!("seccomp must not run after a Landlock failure");
            },
        )
        .unwrap_err();
        assert_eq!(error, "landlock stage failed");
    }

    /// A classic-BPF interpreter over (arch, nr, arg0, arg1): the
    /// executable meaning of the built filter. Every denylisted number
    /// below is evaluated to its verdict, so a mistargeted jump or a
    /// flipped patch fails here instead of silently fencing the wrong
    /// syscall.
    fn eval_filter(insns: &[SockFilter], arch: u32, nr: u32, arg0: u32, arg1: u32) -> u32 {
        let mut acc = 0u32;
        let mut pc = 0usize;
        for _ in 0..insns.len() + 16 {
            let insn = &insns[pc];
            match insn.code {
                BPF_LD_W_ABS => {
                    acc = match insn.k {
                        NR_OFFSET => nr,
                        ARCH_OFFSET => arch,
                        ARG0_LO_OFFSET => arg0,
                        ARG1_LO_OFFSET => arg1,
                        other => panic!("evaluator hit an unexpected load offset {other}"),
                    };
                    pc += 1;
                }
                BPF_JMP_JEQ_K => {
                    pc += 1 + if acc == insn.k { insn.jt } else { insn.jf } as usize;
                }
                BPF_JMP_JGE_K => {
                    pc += 1 + if acc >= insn.k { insn.jt } else { insn.jf } as usize;
                }
                BPF_RET_K => return insn.k,
                other => panic!("evaluator hit an unexpected opcode {other:#x}"),
            }
        }
        panic!("filter did not return");
    }

    #[test]
    fn every_denied_syscall_evaluates_to_eacces() {
        let insns = FilterBuilder::new().build().unwrap();
        let denied = SECCOMP_RET_ERRNO | libc::EACCES as u32;
        // Each number is keyed to libc, not to itself: a wrong constant
        // fails the equality instead of fencing the wrong syscall.
        let keyed: &[(u32, libc::c_long, &str)] = &[
            (SYS_CONNECT, libc::SYS_connect, "connect"),
            (SYS_BIND, libc::SYS_bind, "bind"),
            (SYS_LISTEN, libc::SYS_listen, "listen"),
            (SYS_ACCEPT, libc::SYS_accept, "accept"),
            (SYS_ACCEPT4, libc::SYS_accept4, "accept4"),
            (SYS_EXECVE, libc::SYS_execve, "execve"),
            (SYS_EXECVEAT, libc::SYS_execveat, "execveat"),
            (SYS_MOUNT, libc::SYS_mount, "mount"),
            (SYS_UMOUNT2, libc::SYS_umount2, "umount2"),
            (SYS_PIVOT_ROOT, libc::SYS_pivot_root, "pivot_root"),
            (SYS_MOVE_MOUNT, libc::SYS_move_mount, "move_mount"),
            (SYS_OPEN_TREE, libc::SYS_open_tree, "open_tree"),
            // open_tree_attr postdates libc 0.2.189; its number is from
            // asm/unistd_64.h: 467.
            (SYS_OPEN_TREE_ATTR, 467, "open_tree_attr"),
            (SYS_MOUNT_SETATTR, libc::SYS_mount_setattr, "mount_setattr"),
            (SYS_FSOPEN, libc::SYS_fsopen, "fsopen"),
            (SYS_FSMOUNT, libc::SYS_fsmount, "fsmount"),
            (SYS_PTRACE, libc::SYS_ptrace, "ptrace"),
            (
                SYS_PROCESS_VM_WRITEV,
                libc::SYS_process_vm_writev,
                "process_vm_writev",
            ),
            (SYS_BPF, libc::SYS_bpf, "bpf"),
            (
                SYS_PERF_EVENT_OPEN,
                libc::SYS_perf_event_open,
                "perf_event_open",
            ),
            (SYS_USERFAULTFD, libc::SYS_userfaultfd, "userfaultfd"),
            (
                SYS_NAME_TO_HANDLE_AT,
                libc::SYS_name_to_handle_at,
                "name_to_handle_at",
            ),
            (
                SYS_OPEN_BY_HANDLE_AT,
                libc::SYS_open_by_handle_at,
                "open_by_handle_at",
            ),
            (SYS_KEYCTL, libc::SYS_keyctl, "keyctl"),
            (SYS_ADD_KEY, libc::SYS_add_key, "add_key"),
            (SYS_REQUEST_KEY, libc::SYS_request_key, "request_key"),
            (SYS_INIT_MODULE, libc::SYS_init_module, "init_module"),
            (SYS_FINIT_MODULE, libc::SYS_finit_module, "finit_module"),
            (SYS_DELETE_MODULE, libc::SYS_delete_module, "delete_module"),
            (SYS_KEXEC_LOAD, libc::SYS_kexec_load, "kexec_load"),
            (
                SYS_KEXEC_FILE_LOAD,
                libc::SYS_kexec_file_load,
                "kexec_file_load",
            ),
            (SYS_REBOOT, libc::SYS_reboot, "reboot"),
            (SYS_IOPL, libc::SYS_iopl, "iopl"),
            (SYS_IOPERM, libc::SYS_ioperm, "ioperm"),
            (SYS_SWAPON, libc::SYS_swapon, "swapon"),
            (SYS_SWAPOFF, libc::SYS_swapoff, "swapoff"),
            (SYS_SETHOSTNAME, libc::SYS_sethostname, "sethostname"),
            (SYS_SETDOMAINNAME, libc::SYS_setdomainname, "setdomainname"),
            (SYS_ACCT, libc::SYS_acct, "acct"),
            (
                SYS_IO_URING_SETUP,
                libc::SYS_io_uring_setup,
                "io_uring_setup",
            ),
            (
                SYS_IO_URING_ENTER,
                libc::SYS_io_uring_enter,
                "io_uring_enter",
            ),
            (
                SYS_IO_URING_REGISTER,
                libc::SYS_io_uring_register,
                "io_uring_register",
            ),
            (SYS_CHMOD, libc::SYS_chmod, "chmod"),
            (SYS_FCHMOD, libc::SYS_fchmod, "fchmod"),
            (SYS_FCHMODAT, libc::SYS_fchmodat, "fchmodat"),
            (SYS_FCHMODAT2, libc::SYS_fchmodat2, "fchmodat2"),
            (SYS_CHOWN, libc::SYS_chown, "chown"),
            (SYS_FCHOWN, libc::SYS_fchown, "fchown"),
            (SYS_LCHOWN, libc::SYS_lchown, "lchown"),
            (SYS_FCHOWNAT, libc::SYS_fchownat, "fchownat"),
            (SYS_SETXATTR, libc::SYS_setxattr, "setxattr"),
            (SYS_LSETXATTR, libc::SYS_lsetxattr, "lsetxattr"),
            (SYS_FSETXATTR, libc::SYS_fsetxattr, "fsetxattr"),
            (SYS_REMOVEXATTR, libc::SYS_removexattr, "removexattr"),
            (SYS_LREMOVEXATTR, libc::SYS_lremovexattr, "lremovexattr"),
            (SYS_FREMOVEXATTR, libc::SYS_fremovexattr, "fremovexattr"),
            // setxattrat/removexattrat postdate libc 0.2.189; their
            // numbers are from asm/unistd_64.h: 463 and 466.
            (SYS_SETXATTRAT, 463, "setxattrat"),
            (SYS_REMOVEXATTRAT, 466, "removexattrat"),
            (SYS_UTIME, libc::SYS_utime, "utime"),
            (SYS_UTIMES, libc::SYS_utimes, "utimes"),
            (SYS_FUTIMESAT, libc::SYS_futimesat, "futimesat"),
            (SYS_UTIMENSAT, libc::SYS_utimensat, "utimensat"),
            // file_setattr postdates libc 0.2.189; its number is from
            // asm/unistd_64.h: 469.
            (SYS_FILE_SETATTR, 469, "file_setattr"),
        ];
        assert_eq!(
            keyed.len(),
            DENY_ALWAYS.len(),
            "the libc-keyed table must cover the whole denylist"
        );
        for (ours, want, name) in keyed {
            assert_eq!(*ours, *want as u32, "wrong number for {name}");
            assert_eq!(
                eval_filter(&insns, AUDIT_ARCH_X86_64, *ours, 0, 0),
                denied,
                "{name} escapes the fence"
            );
        }
        // socket() with an IP domain is denied; AF_UNIX and AF_NETLINK
        // stay allowed for the loader.
        assert_eq!(
            eval_filter(
                &insns,
                AUDIT_ARCH_X86_64,
                SYS_SOCKET,
                2, /* AF_INET */
                0
            ),
            denied,
            "AF_INET socket escapes the fence"
        );
        assert_eq!(
            eval_filter(&insns, AUDIT_ARCH_X86_64, SYS_SOCKET, AF_UNIX, 0),
            SECCOMP_RET_ALLOW,
            "AF_UNIX socket must stay allowed"
        );
        assert_eq!(
            eval_filter(&insns, AUDIT_ARCH_X86_64, SYS_SOCKET, AF_NETLINK, 0),
            SECCOMP_RET_ALLOW,
            "AF_NETLINK socket must stay allowed"
        );
        // An ordinary syscall stays allowed.
        assert_eq!(
            eval_filter(&insns, AUDIT_ARCH_X86_64, libc::SYS_read as u32, 0, 0),
            SECCOMP_RET_ALLOW,
            "read must stay allowed"
        );
    }

    #[test]
    fn a_foreign_arch_gets_enosys() {
        let insns = FilterBuilder::new().build().unwrap();
        let enosys = SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
        for arch in [
            62,          // bare EM_X86_64, never the seccomp_data value
            0x4000_0003, // AUDIT_ARCH_I386
        ] {
            assert_eq!(
                eval_filter(&insns, arch, libc::SYS_read as u32, 0, 0),
                enosys,
                "arch {arch:#x} escapes the gate"
            );
        }
    }

    #[test]
    fn fence_context_checks_reject_every_weak_caller() {
        // Landlock `restrict_self` and seccomp fence only the calling
        // thread and need `no_new_privs`: anything else refuses.
        let weak = [
            (
                FenceContext {
                    no_new_privs: 0,
                    euid: 1000,
                    threads: 1,
                },
                "no_new_privs",
            ),
            (
                FenceContext {
                    no_new_privs: 1,
                    euid: 0,
                    threads: 1,
                },
                "root",
            ),
            (
                FenceContext {
                    no_new_privs: 1,
                    euid: 1000,
                    threads: 2,
                },
                "multithreaded",
            ),
        ];
        for (context, cause) in weak {
            let error = check_fence_context(&context).unwrap_err();
            assert!(
                error.starts_with("isolated profile: refusing to fence"),
                "{cause}: {error}"
            );
        }
        assert!(
            check_fence_context(&FenceContext {
                no_new_privs: 1,
                euid: 1000,
                threads: 1,
            })
            .is_ok()
        );
    }

    #[test]
    fn fence_context_reads_the_calling_process() {
        let context = read_fence_context().unwrap();
        assert_eq!(context.euid, unsafe { libc::geteuid() });
        assert!(context.threads >= 1, "a process has at least one thread");
        assert!(context.no_new_privs == 0 || context.no_new_privs == 1);
    }

    #[test]
    fn apply_isolated_refuses_without_fence_context_in_a_child() {
        // Wiring: apply_isolated must refuse when the calling context is
        // weak. The test runner has no_new_privs unset, so the child
        // must return the fence-context refusal. Fork so a successful
        // fence (or a mutant that skips the check and fences) cannot
        // affect the runner. The child prints nothing and exits 0 only
        // on the expected refusal.
        let parent = read_fence_context().unwrap();
        if parent.no_new_privs == 1 && parent.euid != 0 {
            eprintln!("SKIP: test runner is already fence-ready");
            return;
        }
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // _exit directly in each arm: no drop in the child after fork.
            match apply_isolated(None) {
                Err(error) if error.contains("refusing to fence") => unsafe { libc::_exit(0) },
                Err(_) => unsafe { libc::_exit(2) },
                Ok(()) => unsafe { libc::_exit(3) },
            }
        }
        let mut status = 0;
        let waited = loop {
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break waited;
        };
        assert_eq!(waited, pid, "waitpid failed");
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child must refuse with fence-context wording, status={status}"
        );
    }

    #[test]
    fn terminal_injection_ioctls_evaluate_to_eacces() {
        let insns = FilterBuilder::new().build().unwrap();
        let denied = SECCOMP_RET_ERRNO | libc::EACCES as u32;
        assert_eq!(SYS_IOCTL, libc::SYS_ioctl as u32, "wrong number for ioctl");
        assert_eq!(TIOCSTI, libc::TIOCSTI as u32, "wrong TIOCSTI");
        assert_eq!(TIOCLINUX, libc::TIOCLINUX as u32, "wrong TIOCLINUX");
        // TIOCSTI/TIOCLINUX inject input into the operator's terminal;
        // they are denied alongside the inode-attribute commands below,
        // while ordinary ioctls stay allowed.
        for cmd in [TIOCSTI, TIOCLINUX] {
            assert_eq!(
                eval_filter(&insns, AUDIT_ARCH_X86_64, SYS_IOCTL, 0, cmd),
                denied,
                "ioctl {cmd:#x} escapes the fence"
            );
        }
        assert_eq!(
            eval_filter(
                &insns,
                AUDIT_ARCH_X86_64,
                SYS_IOCTL,
                0,
                0x5401 /* TCGETS */
            ),
            SECCOMP_RET_ALLOW,
            "ordinary ioctls must stay allowed"
        );
    }

    #[test]
    fn inode_attribute_ioctls_evaluate_to_eacces() {
        let insns = FilterBuilder::new().build().unwrap();
        let denied = SECCOMP_RET_ERRNO | libc::EACCES as u32;
        // Inode mutators reachable from an O_RDONLY fd (Landlock's
        // IOCTL_DEV does not mediate regular files): each must deny.
        // Numbers from linux/fs.h, linux/fsverity.h and linux/fscrypt.h;
        // the 32-bit SETFLAGS is _IOW('f', 2, int).
        let cmds: &[(u32, u32, &str)] = &[
            (FS_IOC_SETFLAGS, 0x4008_6602, "FS_IOC_SETFLAGS"),
            (FS_IOC_SETFLAGS32, 0x4004_6602, "FS_IOC_SETFLAGS32"),
            (FS_IOC_FSSETXATTR, 0x401c_5820, "FS_IOC_FSSETXATTR"),
            (FS_IOC_ENABLE_VERITY, 0x4080_6685, "FS_IOC_ENABLE_VERITY"),
            (
                FS_IOC_SET_ENCRYPTION_POLICY,
                0x800c_6613,
                "FS_IOC_SET_ENCRYPTION_POLICY",
            ),
            (FS_IOC_SETVERSION, 0x4008_7602, "FS_IOC_SETVERSION"),
        ];
        for (ours, want, name) in cmds {
            assert_eq!(*ours, *want, "wrong number for {name}");
            assert_eq!(
                eval_filter(&insns, AUDIT_ARCH_X86_64, SYS_IOCTL, 0, *ours),
                denied,
                "{name} ({ours:#x}) escapes the fence"
            );
        }
        assert_eq!(
            eval_filter(
                &insns,
                AUDIT_ARCH_X86_64,
                SYS_IOCTL,
                0,
                0x5401 /* TCGETS */
            ),
            SECCOMP_RET_ALLOW,
            "ordinary ioctls must stay allowed"
        );
    }

    #[test]
    fn ioctl_mutation_type_bytes_evaluate_to_eacces() {
        let insns = FilterBuilder::new().build().unwrap();
        let denied = SECCOMP_RET_ERRNO | libc::EACCES as u32;
        // Filesystem-mutation ioctls are denied by type byte (_IOC_TYPE
        // in bits 8-15): btrfs subvolume/snapshot creation bypasses the
        // Landlock path hooks, so exact-command denials cannot cover
        // it. Numbers from linux/btrfs.h, linux/fs.h, linux/fscrypt.h,
        // linux/ext4.h and linux/f2fs.h.
        let cmds: &[(u32, &str)] = &[
            (0x5000_940e, "BTRFS_IOC_SUBVOL_CREATE"),
            (0x5000_9418, "BTRFS_IOC_SUBVOL_CREATE_V2"),
            (0x5000_9401, "BTRFS_IOC_SNAP_CREATE"),
            (0x5000_9417, "BTRFS_IOC_SNAP_CREATE_V2"),
            (0x5000_940f, "BTRFS_IOC_SNAP_DESTROY"),
            (0x4008_941a, "BTRFS_IOC_SUBVOL_SETFLAGS"),
            (0x4004_9409, "FICLONE"),
            (0x4008_6604, "EXT4_IOC_SETVERSION"),
            (0xc040_6618, "FS_IOC_REMOVE_ENCRYPTION_KEY"),
            (0x4004_f50d, "F2FS_IOC_SET_PIN_FILE"),
        ];
        for (cmd, name) in cmds {
            assert_eq!(
                eval_filter(&insns, AUDIT_ARCH_X86_64, SYS_IOCTL, 0, *cmd),
                denied,
                "{name} ({cmd:#x}) escapes the fence"
            );
        }
        // Ordinary terminal-window and availability queries stay
        // allowed: the type rule must not swallow type 'T' (0x54).
        for cmd in [
            0x5401, /* TCGETS */
            0x5413, /* TIOCGWINSZ */
            0x541b, /* FIONREAD */
            0x5421, /* FIONBIO */
        ] {
            assert_eq!(
                eval_filter(&insns, AUDIT_ARCH_X86_64, SYS_IOCTL, 0, cmd),
                SECCOMP_RET_ALLOW,
                "ioctl {cmd:#x} must stay allowed"
            );
        }
    }

    #[test]
    fn file_setattr_evaluates_to_eacces() {
        let insns = FilterBuilder::new().build().unwrap();
        let denied = SECCOMP_RET_ERRNO | libc::EACCES as u32;
        // file_setattr postdates libc 0.2.189; the number is from
        // asm/unistd_64.h: 469. It mutates inode flags Landlock cannot
        // restrict, like the SETFLAGS ioctl above.
        assert_eq!(SYS_FILE_SETATTR, 469, "wrong number for file_setattr");
        assert_eq!(
            eval_filter(&insns, AUDIT_ARCH_X86_64, SYS_FILE_SETATTR, 0, 0),
            denied,
            "file_setattr escapes the fence"
        );
    }

    #[test]
    fn prlimit64_on_other_pids_evaluates_to_eacces() {
        let insns = FilterBuilder::new().build().unwrap();
        let denied = SECCOMP_RET_ERRNO | libc::EACCES as u32;
        // prlimit64: pid 0 is the calling process (libc passes 0 for
        // self), which stays allowed; any other pid would lower a
        // sibling's limits and is denied.
        assert_eq!(
            SYS_PRLIMIT64,
            libc::SYS_prlimit64 as u32,
            "wrong number for prlimit64"
        );
        assert_eq!(
            eval_filter(&insns, AUDIT_ARCH_X86_64, SYS_PRLIMIT64, 0, 0),
            SECCOMP_RET_ALLOW,
            "prlimit64 on self must stay allowed"
        );
        for pid in [1u32, 1234u32, u32::MAX] {
            assert_eq!(
                eval_filter(&insns, AUDIT_ARCH_X86_64, SYS_PRLIMIT64, pid, 0),
                denied,
                "prlimit64 on pid {pid} escapes the fence"
            );
        }
    }

    #[test]
    fn mount_attribute_syscalls_evaluate_to_eacces() {
        let insns = FilterBuilder::new().build().unwrap();
        let denied = SECCOMP_RET_ERRNO | libc::EACCES as u32;
        // mount_setattr retunes a mount; open_tree_attr postdates libc
        // 0.2.189 (asm/unistd_64.h: 467) and opens a detached mount with
        // attributes. Both escape mount-namespace containment like the
        // already-denied open_tree/move_mount.
        assert_eq!(
            SYS_MOUNT_SETATTR,
            libc::SYS_mount_setattr as u32,
            "wrong number for mount_setattr"
        );
        assert_eq!(SYS_OPEN_TREE_ATTR, 467, "wrong number for open_tree_attr");
        for (nr, name) in [
            (SYS_MOUNT_SETATTR, "mount_setattr"),
            (SYS_OPEN_TREE_ATTR, "open_tree_attr"),
        ] {
            assert_eq!(
                eval_filter(&insns, AUDIT_ARCH_X86_64, nr, 0, 0),
                denied,
                "{name} escapes the fence"
            );
        }
    }

    #[test]
    fn x32_syscall_numbers_get_enosys() {
        let insns = FilterBuilder::new().build().unwrap();
        let enosys = SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
        for nr in [
            0x4000_0000 | libc::SYS_read as u32,
            0x4000_0000 | SYS_SOCKET,
            0x4000_0000 | SYS_EXECVE,
            u32::MAX,
        ] {
            assert_eq!(
                eval_filter(&insns, AUDIT_ARCH_X86_64, nr, 0, 0),
                enosys,
                "x32 nr {nr:#x} escapes the fence"
            );
        }
    }
}
