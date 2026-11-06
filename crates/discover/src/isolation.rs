//! SPDX-License-Identifier: GPL-3.0-or-later
//! Optional isolated profile for the discover helper.
//!
//! Contract: `docs/superpowers/specs/2026-11-06-v070-helper-isolation-contract.md`
//! (task 7.07a, helper-policy part). The fence is Landlock (read-only
//! filesystem plus denied TCP bind/connect) followed by a seccomp denylist
//! (no network, no exec/mount/ptrace/BPF/keyring syscalls). Every denial
//! fails with `EACCES`, never kill/trap, so a fenced provider call reads as
//! an ordinary error. Applied after the shared privilege drop and before
//! any provider code runs; any failure refuses before `dlopen`.

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
/// (§4 needs matrix); writes only on the `-o` parent directory.
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
/// regular file, unlink on failure. Nothing else is writable.
const ALLOW_OUTPUT_DIR: u64 = FS_READ_FILE
    | FS_WRITE_FILE
    | FS_READ_DIR
    | FS_REMOVE_FILE
    | FS_MAKE_REG
    | FS_REFER
    | FS_TRUNCATE;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
    // Explicit padding: the kernel reads 16 bytes.
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
const AF_UNIX: u32 = 1;
const AF_NETLINK: u32 = 16;

// x86-64 syscall numbers in the denylist (contract §5).
const SYS_SOCKET: u32 = 41;
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
const SYS_REBOOT: u32 = 169;
const SYS_IOPL: u32 = 172;
const SYS_IOPERM: u32 = 173;
const SYS_SWAPON: u32 = 167;
const SYS_SWAPOFF: u32 = 168;
const SYS_SETHOSTNAME: u32 = 170;
const SYS_SETDOMAINNAME: u32 = 171;
const SYS_ACCT: u32 = 163;

/// Unconditional denials. `socket` is handled separately: `AF_UNIX` and
/// `AF_NETLINK` stay allowed, every other domain is denied.
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
    SYS_REBOOT,
    SYS_IOPL,
    SYS_IOPERM,
    SYS_SWAPON,
    SYS_SWAPOFF,
    SYS_SETHOSTNAME,
    SYS_SETDOMAINNAME,
    SYS_ACCT,
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

// Classic BPF opcodes: ld [k] is LD|W|ABS, jeq #k is JMP|JEQ|K, ret #k.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

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

        let mut deny_jumps = Vec::with_capacity(DENY_ALWAYS.len());
        for nr in DENY_ALWAYS {
            deny_jumps.push((self.jeq(*nr), *nr));
        }
        let socket_jump = self.jeq(SYS_SOCKET);
        let allow = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        let deny = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EACCES as u32));
        // Each `jeq nr`: equal falls into `deny`, else the next check.
        let mut next = allow;
        // Walked back to front so `next` is always the following check.
        let mut checks: Vec<usize> = deny_jumps.iter().map(|(at, _)| *at).collect();
        checks.push(socket_jump);
        for at in checks.iter().rev() {
            if *at == socket_jump {
                let socket_check = self.insns.len();
                self.patch(*at, socket_check, next)?;
                next = *at;
                continue;
            }
            self.patch(*at, deny, next)?;
            next = *at;
        }
        // socket(domain, ...): AF_UNIX and AF_NETLINK stay allowed.
        let socket_check = self.emit(stmt(BPF_LD_W_ABS, ARG0_LO_OFFSET));
        debug_assert_eq!(socket_check, self.insns.len() - 1);
        let is_unix = self.jeq(AF_UNIX);
        let is_netlink = self.jeq(AF_NETLINK);
        let deny_socket = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EACCES as u32));
        let allow_unix = self.emit(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        self.patch(is_unix, allow_unix, is_netlink)?;
        self.patch(is_netlink, allow_unix, deny_socket)?;
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
        if insn.code == BPF_JMP_JEQ_K {
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

/// Open `path` for Landlock rule use (`O_PATH`), refusing non-directories
/// when `want_dir` so a file can never stand in for the output directory.
fn open_rule_path(path: &Path, want_dir: bool) -> Result<File, String> {
    use std::ffi::CString;
    // Contract §3 step 1: any unusable `-o` parent refuses as
    // `isolated profile: output directory <dir> is unusable: <reason>`.
    // The `/` rule path keeps its own wording: it is not the output dir.
    let unusable = |reason: String| {
        if want_dir {
            format!(
                "isolated profile: output directory {} is unusable: {reason}",
                path.display()
            )
        } else {
            format!("isolated profile: {reason}")
        }
    };
    let raw = match CString::new(path.as_os_str().as_bytes()) {
        Ok(raw) => raw,
        Err(_) => {
            return Err(unusable(format!(
                "cannot open {}: path has a NUL byte",
                path.display()
            )));
        }
    };
    let fd = unsafe { libc::open(raw.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(unusable(format!(
            "cannot open {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if want_dir && !file.metadata().is_ok_and(|meta| meta.file_type().is_dir()) {
        return Err(format!(
            "isolated profile: output directory {} is unusable: not a directory",
            path.display()
        ));
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

fn apply_landlock(writable_dir: Option<&Path>) -> Result<(), String> {
    let abi = landlock_abi()?;
    if abi < LANDLOCK_ABI_FLOOR {
        return Err(format!(
            "isolated profile: Landlock ABI {abi} below required {LANDLOCK_ABI_FLOOR}"
        ));
    }
    let root = open_rule_path(Path::new("/"), false)?;
    let output = writable_dir
        .map(|dir| open_rule_path(dir, true))
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
    writable_dir: Option<&Path>,
    landlock: impl FnOnce(Option<&Path>) -> Result<(), String>,
    seccomp: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    landlock(writable_dir)?;
    if !is_x86_64 {
        return Err("isolated profile: x86-64 only".into());
    }
    seccomp()
}

/// Apply the isolated fence: Landlock first, then seccomp. `writable_dir`
/// is the `-o` parent directory, or `None` for stdout output. On success
/// the caller may load the provider; on failure it must exit before
/// `dlopen` — provider code never runs.
pub fn apply_isolated(writable_dir: Option<&Path>) -> Result<(), String> {
    apply_isolated_with(
        cfg!(target_arch = "x86_64"),
        writable_dir,
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
        let dir = std::env::temp_dir().join(format!("isolation-rule-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(open_rule_path(&dir, true).is_ok());
        let error = open_rule_path(&file, true).unwrap_err();
        assert!(error.contains("not a directory"), "{error}");
        assert!(open_rule_path(&file, false).is_ok());
        assert!(open_rule_path(&dir.join("missing"), true).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unusable_output_directories_use_the_contract_wording() {
        use std::os::unix::ffi::OsStrExt as _;
        let dir = std::env::temp_dir().join(format!("isolation-wording-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Missing, file-as-parent and NUL parents all refuse with the
        // contract §3 step-1 shape; the `/` rule path keeps its own.
        let missing = dir.join("no-such-dir");
        let error = open_rule_path(&missing, true).unwrap_err();
        assert!(
            error.starts_with("isolated profile: output directory ")
                && error.contains(" is unusable: "),
            "{error}"
        );
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        let error = open_rule_path(&file, true).unwrap_err();
        assert!(
            error.starts_with("isolated profile: output directory ")
                && error.contains(" is unusable: "),
            "{error}"
        );
        let nul = std::ffi::OsStr::from_bytes(b"bad\0dir");
        let error = open_rule_path(Path::new(nul), true).unwrap_err();
        assert!(
            error.starts_with("isolated profile: output directory ")
                && error.contains(" is unusable: "),
            "{error}"
        );
        let error = open_rule_path(&missing, false).unwrap_err();
        assert!(error.contains("cannot open"), "{error}");
        assert!(
            !error.contains("output directory"),
            "the tree rule is not the output dir: {error}"
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
}
