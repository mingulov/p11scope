//! SPDX-License-Identifier: GPL-3.0-or-later
//! Whether attaching a uretprobe would kill the process being observed.
//!
//! Linux 6.11 moved uretprobes to a syscall trampoline: when a probed function
//! returns, the kernel makes the **target** issue `__NR_uretprobe` from a
//! trampoline page. A seccomp filter that does not allow that number therefore
//! fires on a syscall the target never wrote. Until the upstream passthrough
//! fix (`cf6cb56ef244`, 6.14-rc2) that killed the target with SIGSYS on the
//! first return, and delivered zero events in exchange. All five of this
//! tool's uretprobes are on that path.
//!
//! Measured 2026-09-05 (`scripts/matrix/verify-uretprobe-seccomp.sh`, and
//! `docs/notes/2026-09-05-kernel-and-config-test-matrix.md` §5): Ubuntu
//! `6.11.0-17` is affected and `6.11.0-29` is clean — same upstream minor,
//! same distro, one SRU apart. **The affected set is not a version range**, so
//! nothing here may consult `uname`; that is the same mistake `c1e1192` fixed
//! in `doctor`. The verdict comes from actually running the mechanism against
//! a child of our own.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use aya::Ebpf;
use aya::programs::UProbe;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope};

/// x86-64 `__NR_uretprobe`. The syscall exists only on kernels that use the
/// trampoline; on older ones this number is unallocated, the filter below
/// never matches, and the probe correctly reports `Clean`.
#[cfg(target_arch = "x86_64")]
const NR_URETPROBE: u32 = 335;

/// What this kernel does with the uretprobe syscall when the target is filtered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KernelVerdict {
    /// A returning uretprobe is filtered by seccomp: the target dies.
    Affected(&'static str),
    /// The kernel exempts the trampoline. Uretprobes are safe here.
    Clean,
    /// The probe could not reach a verdict. Never treated as `Clean`: the
    /// failure it guards against is fatal and lands on someone else's process.
    Unknown(String),
    /// The kernel refused to let this process load or attach the probe's BPF
    /// at all (EPERM, or EACCES from the uprobe attach) — a missing-privilege
    /// fact about the observer, not a verdict about the kernel (HIGH-1). The
    /// capture would be refused the same way at attach, so it is reported as
    /// what it is, and the uretprobe override cannot help.
    NotPermitted(String),
}

/// The target's seccomp mode, as `/proc/<pid>/status` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeccompMode {
    Disabled,
    /// `SECCOMP_MODE_STRICT`. Measured behaviour covers filter mode only, so
    /// this is treated as risky rather than claimed safe: a strict-mode task is
    /// killed by any syscall outside a four-call allowlist, which the
    /// trampoline's syscall is not in.
    Strict,
    Filter,
}

impl SeccompMode {
    /// Whether a uretprobe's syscall could be refused in this mode.
    fn confines_syscalls(self) -> bool {
        matches!(self, Self::Strict | Self::Filter)
    }
}

/// What to do about one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    Proceed,
    /// Attaching would kill the target. Carries the operator-facing reason.
    Refuse(String),
    /// The operator accepted the risk explicitly. Carries the warning.
    ProceedUnderOverride(String),
    /// The self-probe was not permitted to load BPF: whatever the override
    /// says, nothing can attach. Carries the kernel's refusal.
    NotPermitted(String),
}

/// The whole policy, in one pure function so it is testable without a kernel.
///
/// Two facts decide it: whether this kernel filters the trampoline's syscall,
/// and whether the target confines syscalls at all. Both must be true for the
/// hazard to exist, so an ordinary unconfined target — the common case — is
/// never refused however bad the kernel is.
pub(crate) fn decide(
    kernel: &KernelVerdict,
    target: Option<SeccompMode>,
    overridden: bool,
) -> Action {
    let reason = match (kernel, target) {
        // Nothing to fear: the kernel exempts the trampoline.
        (KernelVerdict::Clean, _) => return Action::Proceed,
        // The target cannot refuse a syscall, so the trampoline cannot kill it.
        (_, Some(mode)) if !mode.confines_syscalls() => return Action::Proceed,
        // Not a hazard verdict at all: this process may not load BPF, so the
        // override (which only accepts a hazard) must not be offered or taken.
        (KernelVerdict::NotPermitted(why), _) => return Action::NotPermitted(why.clone()),
        (KernelVerdict::Affected(how), Some(_)) => format!(
            "this kernel filters the uretprobe trampoline's syscall through seccomp (self-probe: \
             {how}) and the target confines syscalls, so attaching a uretprobe would kill it on \
             the first return and capture nothing"
        ),
        (KernelVerdict::Affected(how), None) => format!(
            "this kernel filters the uretprobe trampoline's syscall through seccomp (self-probe: \
             {how}) and the target cannot be shown unconfined (its seccomp mode could not be \
             read, the scope's targets cannot be enumerated, or an owned run child may confine \
             itself after attach), so attaching a uretprobe might kill it"
        ),
        (KernelVerdict::Unknown(why), Some(_)) => format!(
            "the target confines syscalls and this kernel could not be shown to exempt the \
             uretprobe trampoline's syscall ({why}), so attaching a uretprobe might kill it"
        ),
        // F-01: fail closed. An unproven kernel with a target that cannot be
        // shown unconfined is the widest blast radius under the weakest
        // protection; it used to proceed.
        (KernelVerdict::Unknown(why), None) => format!(
            "this kernel could not be shown to exempt the uretprobe trampoline's syscall \
             ({why}) and the target cannot be shown unconfined (its seccomp mode could not \
             be read, the scope's targets cannot be enumerated, or an owned run child may \
             confine itself after attach), so attaching a uretprobe might kill it"
        ),
    };
    if overridden {
        Action::ProceedUnderOverride(reason)
    } else {
        Action::Refuse(reason)
    }
}

/// Reads the target's seccomp mode. `None` when the field is absent or the
/// process is gone — never an invented `Disabled`, because "unknown" and
/// "unconfined" lead to different decisions above.
pub(crate) fn target_seccomp_mode(pid: u32) -> Option<SeccompMode> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_seccomp_mode(&status)
}

/// `Seccomp:` has been in `/proc/<pid>/status` since 3.5, but only when
/// `CONFIG_SECCOMP` is set, so its absence is `None` rather than `Disabled`.
fn parse_seccomp_mode(status: &str) -> Option<SeccompMode> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp:"))?
        .trim();
    match value {
        "0" => Some(SeccompMode::Disabled),
        "1" => Some(SeccompMode::Strict),
        "2" => Some(SeccompMode::Filter),
        // A mode this build does not know is confining until proven otherwise.
        _ => Some(SeccompMode::Filter),
    }
}

/// Turns a reaped child's raw wait status into a verdict.
fn classify_probe_child(status: i32) -> KernelVerdict {
    if libc::WIFSIGNALED(status) {
        return match libc::WTERMSIG(status) {
            libc::SIGSYS => KernelVerdict::Affected("the probe child was killed by SIGSYS"),
            // The `SECCOMP_RET_ERRNO` shape: the syscall is stubbed out, so the
            // trampoline never restores the return address and the child jumps
            // into nothing. Measured on 6.11.0-17.
            libc::SIGSEGV => KernelVerdict::Affected(
                "the probe child was killed by SIGSEGV, the trampoline never returning",
            ),
            other => KernelVerdict::Unknown(format!("the probe child died of signal {other}")),
        };
    }
    if libc::WIFEXITED(status) {
        return match libc::WEXITSTATUS(status) {
            0 => KernelVerdict::Clean,
            code => KernelVerdict::Unknown(format!("the probe child exited {code}")),
        };
    }
    KernelVerdict::Unknown(format!("the probe child ended with raw status {status}"))
}

/// The attach point for the self-probe, and nothing else.
///
/// It must be a real call that really returns, in this executable's own text,
/// so `#[inline(never)]` and the `black_box` are both load-bearing: without a
/// return there is no trampoline and the probe would report every kernel clean.
#[inline(never)]
pub(crate) extern "C" fn probe_point(seed: u64) -> u64 {
    std::hint::black_box(seed).wrapping_add(1)
}

/// Whether the expensive self-probe is worth running for this target.
///
/// A target that cannot refuse a syscall cannot be killed by the trampoline,
/// so the common case — an ordinary unconfined process — never pays for the
/// fork. `None` (a cgroup scope, or a target we could not read) does probe:
/// there the blast radius is every process mapping the object, which is
/// exactly when a wrong guess is worst.
fn needs_kernel_probe(mode: Option<SeccompMode>) -> bool {
    !matches!(mode, Some(mode) if !mode.confines_syscalls())
}

/// The hazard for one capture, cheapest check first.
///
/// `target` is the single pid a `--pid` capture probes. `None` means the scope
/// installs probes process-wide (`--cgroup` attaches `AllProcesses` and filters
/// in BPF), so the set of processes that would run the trampoline cannot be
/// enumerated and must be treated as possibly confined — or an owned `run`
/// child, which may confine itself after attach.
pub(crate) fn evaluate(target: Option<u32>, overridden: bool) -> Action {
    let mode = target.and_then(target_seccomp_mode);
    evaluate_mode(mode, overridden, probe_kernel)
}

/// The policy half of [`evaluate`], with the kernel verdict injected so the
/// verdict/target matrix is testable without forking a self-probe — `run`
/// reaches it as `evaluate_mode(None, …)`, the shape an owned child that
/// may confine itself after attach requires.
fn evaluate_mode(
    mode: Option<SeccompMode>,
    overridden: bool,
    probe: impl FnOnce() -> KernelVerdict,
) -> Action {
    if !needs_kernel_probe(mode) {
        return Action::Proceed;
    }
    decide(&probe(), mode, overridden)
}

/// Runs the self-probe: fork a child, have it refuse the uretprobe syscall,
/// attach a real uretprobe to it, and see whether it survives its own return.
///
/// The victim is a child of ours, so no target process is ever at risk of
/// answering this question. `p11_return` is the probe program deliberately —
/// it is the one that would kill a target, so the probe exercises the exact
/// path it is protecting rather than a stand-in. With no entry ever recorded
/// for the child it takes its `START.get` miss and returns 0, so the probe
/// emits nothing into the ring.
///
/// Every failure is `Unknown`, never `Clean`: this exists to prevent an
/// irreversible harm to someone else's process, so silence is not consent.
/// Loads its own copy of the BPF object rather than borrowing the capture's.
/// The probe then needs nothing from the attach path, runs before a session
/// exists, and cannot leave a link or a stray event behind in one.
pub(crate) fn probe_kernel() -> KernelVerdict {
    match probe_kernel_inner() {
        Ok(verdict) => verdict,
        Err(error) => classify_probe_error(&error),
    }
}

/// Context the self-probe puts on its uprobe attach; an EACCES there is the
/// perf-event permission check (`kernel.perf_event_paranoid`, CAP_PERFMON).
const SELF_PROBE_ATTACH_CONTEXT: &str = "attaching the uretprobe self-probe";

/// A self-probe failure is `NotPermitted` when the kernel refused this
/// process permission: EPERM anywhere in the chain (the `bpf(2)` capability
/// checks), or EACCES from the uprobe attach. An EACCES from a program load
/// is a verifier rejection, which says something about the kernel, not about
/// privilege, so it stays `Unknown` like every other failure.
fn classify_probe_error(error: &anyhow::Error) -> KernelVerdict {
    let errno = |wanted: libc::c_int| {
        error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error)
                == Some(wanted)
        })
    };
    let attaching = error.to_string() == SELF_PROBE_ATTACH_CONTEXT;
    if errno(libc::EPERM) || (attaching && errno(libc::EACCES)) {
        KernelVerdict::NotPermitted(format!("{error:#}"))
    } else {
        KernelVerdict::Unknown(format!("{error:#}"))
    }
}

/// The operator-facing refusal for [`Action::NotPermitted`]: what was
/// refused, what privilege it takes, and how to get it — never the uretprobe
/// override, which cannot grant privilege.
pub(crate) fn not_permitted_message(why: &str, running_as_root: bool) -> String {
    if running_as_root {
        format!(
            "cannot load p11scope's BPF programs even as root ({why}): a kernel lockdown, an \
             LSM policy, or a container's seccomp profile is refusing BPF here. Run \
             `p11scope doctor` to see which"
        )
    } else {
        format!(
            "cannot load p11scope's BPF programs: the kernel refused ({why}). Capturing requires \
             root, or CAP_SYS_ADMIN, CAP_BPF and CAP_PERFMON: run it with sudo. `p11scope \
             doctor` shows what this host allows"
        )
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn probe_kernel_inner() -> Result<KernelVerdict> {
    Ok(KernelVerdict::Unknown(
        "the self-probe knows the uretprobe syscall number for x86-64 only".to_string(),
    ))
}

#[cfg(target_arch = "x86_64")]
fn probe_kernel_inner() -> Result<KernelVerdict> {
    // The production object uses task storage without an Aya typed wrapper.
    let mut ebpf = aya::EbpfLoader::new()
        .allow_unsupported_maps()
        .load(crate::EBPF_OBJECT)
        .context("loading the BPF object")?;
    {
        let program: &mut UProbe = ebpf
            .program_mut("p11_return")
            .context("program p11_return missing from the BPF object")?
            .try_into()
            .map_err(|error: aya::programs::ProgramError| anyhow!("{error}"))?;
        program.load().context("loading p11_return")?;
    }
    let ebpf = &mut ebpf;
    let offset = own_text_file_offset(probe_point as *const () as usize as u64)
        .context("locating the self-probe attach point in this executable")?;
    let (ready_read, ready_write) = pipe_pair().context("self-probe readiness pipe")?;
    let (release_read, release_write) = pipe_pair().context("self-probe release pipe")?;

    // SAFETY: nothing below the fork allocates, locks, or touches libc state
    // that a forked child may not: prctl, seccomp, read, write and `_exit` are
    // async-signal-safe, and `probe_point` is arithmetic.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(anyhow!(
            "fork for the uretprobe self-probe: {}",
            std::io::Error::last_os_error()
        ));
    }
    if child == 0 {
        unsafe {
            libc::close(ready_read.as_raw_fd());
            libc::close(release_write.as_raw_fd());
            if arm_deny_uretprobe().is_err() {
                libc::_exit(90);
            }
            let byte = 1u8;
            if libc::write(ready_write.as_raw_fd(), (&raw const byte).cast(), 1) != 1 {
                libc::_exit(91);
            }
            let mut go = 0u8;
            loop {
                let read = libc::read(release_read.as_raw_fd(), (&raw mut go).cast(), 1);
                // The parent releases by closing its end, so EOF (0) is the
                // signal, not a failure; a byte would do just as well.
                if read >= 0 {
                    break;
                }
                if last_errno() != libc::EINTR {
                    libc::_exit(92);
                }
            }
            // The measured moment: this call returns, the kernel runs the
            // trampoline, and the child's own filter sees a syscall it never
            // made. On an affected kernel the process dies here.
            std::hint::black_box(probe_point(1));
            libc::_exit(0);
        }
    }

    drop(ready_write);
    drop(release_read);
    let child = child as u32;
    let verdict = probe_parent(ebpf, child, offset, &ready_read, release_write);
    // The child is unreaped and its pid cannot have been reused, so this is a
    // safe cleanup rather than a general signal fallback.
    if verdict.is_err() {
        unsafe { libc::kill(child as libc::pid_t, libc::SIGKILL) };
        let _ = reap(child, Duration::from_secs(2));
    }
    verdict
}

#[cfg(target_arch = "x86_64")]
fn probe_parent(
    ebpf: &mut Ebpf,
    child: u32,
    offset: u64,
    ready_read: &OwnedFd,
    release_write: OwnedFd,
) -> Result<KernelVerdict> {
    let mut byte = 0u8;
    // SAFETY: `ready_read` is an open fd this process owns, and one byte fits.
    let read = unsafe { libc::read(ready_read.as_raw_fd(), (&raw mut byte).cast(), 1) };
    if read != 1 {
        return Err(anyhow!("the self-probe child never armed its filter"));
    }

    let program: &mut UProbe = ebpf
        .program_mut("p11_return")
        .context("program p11_return missing from the BPF object")?
        .try_into()
        .map_err(|error: aya::programs::ProgramError| anyhow!("{error}"))?;
    let point = UProbeAttachPoint {
        location: UProbeAttachLocation::AbsoluteOffset(offset),
        cookie: None,
    };
    let scope = UProbeScope::OneProcess(
        std::num::NonZeroU32::new(child).context("the self-probe child pid must be non-zero")?,
    );
    let link = program
        .attach([point], "/proc/self/exe", scope)
        .context(SELF_PROBE_ATTACH_CONTEXT)?;

    drop(release_write); // the child's blocking read returns 0 -> it proceeds
    let status = reap(child, Duration::from_secs(10));
    // Detached before the verdict is returned: this link must never outlive the
    // probe and reach the real capture's accounting.
    let _ = program.detach(link);
    let status = status.context("waiting for the self-probe child")?;
    Ok(classify_probe_child(status))
}

/// The child releases on EOF, so the write end is closed rather than written.
#[cfg(target_arch = "x86_64")]
fn pipe_pair() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a two-element array, which is what `pipe2` writes.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `pipe2` returned two fresh owned descriptors.
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

fn last_errno() -> libc::c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Bounded reap. A child that will not die within the deadline is killed and
/// its status reported as unknown rather than blocking a capture forever.
fn reap(pid: u32, deadline: Duration) -> Result<i32> {
    let started = Instant::now();
    loop {
        let mut status = 0;
        // SAFETY: this process is the parent of that exact unreaped child.
        let waited = unsafe { libc::waitpid(pid as libc::pid_t, &raw mut status, libc::WNOHANG) };
        if waited == pid as libc::pid_t {
            return Ok(status);
        }
        if waited < 0 && last_errno() != libc::EINTR {
            return Err(anyhow!(
                "waitpid on the self-probe child: {}",
                std::io::Error::last_os_error()
            ));
        }
        if started.elapsed() >= deadline {
            // SAFETY: still unreaped, so the pid cannot have been reused.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            let mut status = 0;
            // SAFETY: same child, now certain to be reapable.
            unsafe { libc::waitpid(pid as libc::pid_t, &raw mut status, 0) };
            return Err(anyhow!("the self-probe child did not finish in time"));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Converts a runtime code address into the file offset a uprobe wants, using
/// the same `/proc/self/maps` parser the rest of the tool reads targets with.
/// Deriving it from the mapping rather than an ELF symbol keeps the probe
/// working in a stripped release build.
fn own_text_file_offset(address: u64) -> Result<u64> {
    let bytes = std::fs::read("/proc/self/maps").context("/proc/self/maps")?;
    let entries = p11scope_manifest::maps::parse_maps(&bytes).map_err(|error| anyhow!(error))?;
    entries
        .into_iter()
        .find(|entry| entry.permissions[2] == b'x' && (entry.start..entry.end).contains(&address))
        .map(|entry| entry.file_offset + (address - entry.start))
        .context("no executable mapping contains the self-probe attach point")
}

/// Denies exactly one syscall and allows everything else.
///
/// A denylist of one is the whole filter: the child must keep working normally
/// right up to the return being probed, and an allowlist would risk killing it
/// for an unrelated syscall and reporting that as this defect.
#[cfg(target_arch = "x86_64")]
unsafe fn arm_deny_uretprobe() -> std::result::Result<(), ()> {
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;
    // `struct seccomp_data` field offsets.
    const NR: u32 = 0;
    const ARCH: u32 = 4;
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;

    let stmt = |code: u16, k: u32| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| libc::sock_filter { code, jt, jf, k };
    // Jump targets are relative to the *next* instruction.
    let mut filter = [
        stmt(BPF_LD | BPF_W | BPF_ABS, ARCH),
        // A foreign personality cannot be running our x86-64 trampoline.
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2),
        stmt(BPF_LD | BPF_W | BPF_ABS, NR),
        jump(BPF_JMP | BPF_JEQ | BPF_K, NR_URETPROBE, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: caller is the forked child; both calls take only the arguments
    // constructed above, and `program` outlives the seccomp call.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(());
        }
        if libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0,
            (&raw const program).cast::<libc::c_void>(),
        ) != 0
        {
            return Err(());
        }
    }
    Ok(())
}

/// The shell convention `run` reports the child with: 128 + N when a signal
/// ended it. `None` for an ordinary exit.
fn signal_from_shell_status(exit_code: i32) -> Option<i32> {
    (exit_code > 128 && exit_code <= 128 + 64).then_some(exit_code - 128)
}

fn signal_name(signal: i32) -> &'static str {
    match signal {
        libc::SIGSYS => "SIGSYS",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGKILL => "SIGKILL",
        libc::SIGTERM => "SIGTERM",
        libc::SIGINT => "SIGINT",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGILL => "SIGILL",
        _ => "an unnamed signal",
    }
}

/// The two deaths this defect produces, measured: `SECCOMP_RET_KILL_*` gives
/// SIGSYS, and `SECCOMP_RET_ERRNO` gives SIGSEGV because the trampoline never
/// restores the return address.
fn is_trampoline_death_shape(signal: i32) -> bool {
    signal == libc::SIGSYS || signal == libc::SIGSEGV
}

/// Names how the owned child died, so a capture never reports a signalled
/// death as an ordinary exit code.
///
/// `probe` supplies the kernel verdict, and is only consulted for the two
/// signals this defect produces — a normal capture never pays for it. Split
/// out from [`describe_owned_child_death`] so the wording is testable without
/// forking anything.
fn describe_owned_child_death_with(
    exit_code: i32,
    attached_probes: usize,
    probe: impl FnOnce() -> KernelVerdict,
) -> Option<String> {
    let signal = signal_from_shell_status(exit_code)?;
    let named = signal_name(signal);
    let mut message =
        format!("the target was killed by {named} ({signal}) during capture, not exited");
    if is_trampoline_death_shape(signal) {
        // Blaming ourselves for a death we could not have caused would be the
        // same dishonesty as hiding one we did: with no probe installed there
        // is no trampoline in that process, whatever the kernel does.
        if attached_probes == 0 {
            message.push_str(
                ". p11scope had no probe attached to it, so its uretprobes are not the cause",
            );
            return Some(message);
        }
        match probe() {
            KernelVerdict::Affected(how) => message.push_str(&format!(
                ". This kernel filters the uretprobe trampoline's syscall through seccomp \
                 (self-probe: {how}), so if the target confined syscalls, p11scope's own \
                 uretprobes are the likely cause and the capture will be missing its returns"
            )),
            KernelVerdict::Clean => message.push_str(
                ". This kernel exempts the uretprobe trampoline from seccomp, so p11scope's \
                 uretprobes are not the cause",
            ),
            KernelVerdict::Unknown(why) | KernelVerdict::NotPermitted(why) => {
                message.push_str(&format!(
                    ". Whether this kernel filters the uretprobe trampoline could not be \
                     established ({why}), so p11scope's uretprobes cannot be ruled out"
                ))
            }
        }
    }
    Some(message)
}

/// Production wiring for [`describe_owned_child_death_with`].
pub(crate) fn describe_owned_child_death(exit_code: i32, attached_probes: usize) -> Option<String> {
    describe_owned_child_death_with(exit_code, attached_probes, probe_kernel)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io_chain(errno: libc::c_int, context: &str) -> anyhow::Error {
        anyhow::Error::new(std::io::Error::from_raw_os_error(errno))
            .context("map error: failed to create map `STATS`")
            .context(context.to_string())
    }

    /// HIGH-1: EPERM from loading the probe's BPF, or EACCES from its uprobe
    /// attach, is missing privilege; a verifier EACCES or anything else stays
    /// an unknown kernel verdict.
    #[test]
    fn a_refused_self_probe_is_classified_as_not_permitted() {
        for (errno, context, not_permitted) in [
            (libc::EPERM, "loading the BPF object", true),
            (libc::EPERM, "loading p11_return", true),
            (libc::EPERM, SELF_PROBE_ATTACH_CONTEXT, true),
            (libc::EACCES, SELF_PROBE_ATTACH_CONTEXT, true),
            (libc::EACCES, "loading p11_return", false),
            (libc::EINVAL, "loading the BPF object", false),
            (libc::ENOENT, "loading the BPF object", false),
        ] {
            let verdict = classify_probe_error(&io_chain(errno, context));
            assert_eq!(
                matches!(verdict, KernelVerdict::NotPermitted(_)),
                not_permitted,
                "{errno} in {context}: {verdict:?}"
            );
            if !not_permitted {
                assert!(matches!(verdict, KernelVerdict::Unknown(_)), "{verdict:?}");
            }
        }
    }

    /// A not-permitted self-probe is never a hazard verdict and never
    /// something the override can accept, for any target that needed it.
    #[test]
    fn a_not_permitted_probe_refuses_by_privilege_whatever_the_override() {
        let refused = KernelVerdict::NotPermitted("Operation not permitted".to_string());
        for target in [Some(SeccompMode::Strict), Some(SeccompMode::Filter), None] {
            for overridden in [false, true] {
                assert_eq!(
                    decide(&refused, target, overridden),
                    Action::NotPermitted("Operation not permitted".to_string()),
                    "{target:?} overridden={overridden}"
                );
            }
        }
        assert_eq!(
            decide(&refused, Some(SeccompMode::Disabled), false),
            Action::Proceed
        );
    }

    #[test]
    fn the_not_permitted_message_names_the_privilege_and_never_the_override() {
        let why = "loading the BPF object: Operation not permitted (os error 1)";
        let user = not_permitted_message(why, false);
        let root = not_permitted_message(why, true);
        for message in [&user, &root] {
            assert!(message.contains(why), "{message}");
            assert!(message.contains("p11scope doctor"), "{message}");
            assert!(
                !message.contains("--allow-uretprobe-on-confined-target"),
                "{message}"
            );
            assert!(!message.contains("seccomp filter"), "{message}");
        }
        assert!(user.contains("requires root"), "{user}");
        assert!(user.contains("sudo"), "{user}");
        assert!(root.contains("even as root"), "{root}");
    }

    #[test]
    fn a_clean_kernel_never_refuses_however_confined_the_target_is() {
        for mode in [
            SeccompMode::Disabled,
            SeccompMode::Strict,
            SeccompMode::Filter,
        ] {
            assert_eq!(
                decide(&KernelVerdict::Clean, Some(mode), false),
                Action::Proceed,
                "{mode:?}"
            );
        }
        assert_eq!(
            decide(&KernelVerdict::Clean, None, false),
            Action::Proceed,
            "an unreadable target on a clean kernel is still safe"
        );
    }

    #[test]
    fn an_unconfined_target_is_never_refused_however_bad_the_kernel_is() {
        for kernel in [
            KernelVerdict::Affected("test"),
            KernelVerdict::Unknown("test".to_string()),
        ] {
            assert_eq!(
                decide(&kernel, Some(SeccompMode::Disabled), false),
                Action::Proceed,
                "{kernel:?}"
            );
        }
    }

    #[test]
    fn an_affected_kernel_refuses_a_confined_target() {
        for mode in [SeccompMode::Strict, SeccompMode::Filter] {
            let action = decide(
                &KernelVerdict::Affected("killed by SIGSYS"),
                Some(mode),
                false,
            );
            let Action::Refuse(reason) = action else {
                panic!("{mode:?} must be refused, got {action:?}");
            };
            assert!(
                reason.contains("would kill it") && reason.contains("killed by SIGSYS"),
                "the refusal must name the harm and the evidence: {reason}"
            );
        }
    }

    /// The harm lands on someone else's process and is irreversible, so an
    /// unreadable target on a known-bad kernel is refused, not assumed safe.
    #[test]
    fn an_affected_kernel_refuses_a_target_it_cannot_read() {
        assert!(matches!(
            decide(&KernelVerdict::Affected("killed by SIGSYS"), None, false),
            Action::Refuse(_)
        ));
    }

    /// An unknown verdict is not a clean one: it refuses a confined target
    /// and anything that cannot be shown unconfined. Only a positively
    /// unconfined target escapes it, so a failed self-probe cannot break
    /// ordinary captures but can never silently authorize a risky one.
    #[test]
    fn an_unprovable_kernel_refuses_everything_but_an_unconfined_target() {
        let unknown = KernelVerdict::Unknown("fork failed".to_string());
        for target in [Some(SeccompMode::Strict), Some(SeccompMode::Filter), None] {
            assert!(
                matches!(decide(&unknown, target, false), Action::Refuse(_)),
                "{target:?} must be refused"
            );
        }
        assert_eq!(
            decide(&unknown, Some(SeccompMode::Disabled), false),
            Action::Proceed
        );
    }

    /// F-01: an Unknown kernel with an unspecified target (`--cgroup` /
    /// `--system`, whose targets cannot be enumerated) or an unreadable
    /// one must fail closed — that is the widest blast radius under the
    /// weakest protection, and it used to proceed.
    #[test]
    fn an_unprovable_kernel_with_an_unreadable_target_refuses() {
        let Action::Refuse(reason) = decide(
            &KernelVerdict::Unknown("BPF load failed".to_string()),
            None,
            false,
        ) else {
            panic!("Unknown kernel + unreadable target must refuse");
        };
        assert!(
            reason.contains("might kill it") && reason.contains("BPF load failed"),
            "the refusal must name the harm and the evidence: {reason}"
        );
    }

    /// The complete policy matrix: every kernel verdict against every
    /// target kind. Clean never refuses; Disabled never refuses; every
    /// other combination refuses by default.
    #[test]
    fn the_full_verdict_target_matrix_fails_closed() {
        let affected = KernelVerdict::Affected("killed by SIGSYS");
        let unknown = KernelVerdict::Unknown("fork failed".to_string());
        for (kernel, target, refuses) in [
            (&KernelVerdict::Clean, Some(SeccompMode::Disabled), false),
            (&KernelVerdict::Clean, Some(SeccompMode::Strict), false),
            (&KernelVerdict::Clean, Some(SeccompMode::Filter), false),
            (&KernelVerdict::Clean, None, false),
            (&affected, Some(SeccompMode::Disabled), false),
            (&affected, Some(SeccompMode::Strict), true),
            (&affected, Some(SeccompMode::Filter), true),
            (&affected, None, true),
            (&unknown, Some(SeccompMode::Disabled), false),
            (&unknown, Some(SeccompMode::Strict), true),
            (&unknown, Some(SeccompMode::Filter), true),
            (&unknown, None, true),
        ] {
            let action = decide(kernel, target, false);
            assert_eq!(
                matches!(action, Action::Refuse(_)),
                refuses,
                "{kernel:?} + {target:?} -> {action:?}"
            );
        }
    }

    #[test]
    fn the_override_converts_every_refusal_into_a_warning_with_the_same_reason() {
        for (kernel, target) in [
            (
                KernelVerdict::Affected("killed by SIGSYS"),
                Some(SeccompMode::Filter),
            ),
            (KernelVerdict::Affected("killed by SIGSYS"), None),
            (
                KernelVerdict::Unknown("x".to_string()),
                Some(SeccompMode::Filter),
            ),
            (KernelVerdict::Unknown("x".to_string()), None),
        ] {
            let Action::Refuse(refused) = decide(&kernel, target, false) else {
                panic!("{kernel:?}/{target:?} must refuse by default");
            };
            let Action::ProceedUnderOverride(warned) = decide(&kernel, target, true) else {
                panic!("{kernel:?}/{target:?} must proceed under the override");
            };
            assert_eq!(refused, warned, "the override must not soften the reason");
        }
    }

    /// The override is a safety valve, not a mode: it must not manufacture a
    /// warning where there was no hazard.
    #[test]
    fn the_override_is_silent_when_there_was_nothing_to_refuse() {
        assert_eq!(
            decide(&KernelVerdict::Clean, Some(SeccompMode::Filter), true),
            Action::Proceed
        );
    }

    /// The ordering promise: an ordinary target never pays for the fork.
    #[test]
    fn only_a_confined_or_unknown_target_is_worth_probing_the_kernel_for() {
        assert!(!needs_kernel_probe(Some(SeccompMode::Disabled)));
        assert!(needs_kernel_probe(Some(SeccompMode::Filter)));
        assert!(needs_kernel_probe(Some(SeccompMode::Strict)));
        assert!(
            needs_kernel_probe(None),
            "a scope whose targets cannot be enumerated must still be probed"
        );
    }

    /// A pid with no readable status is not unconfined: it feeds the
    /// fail-closed `None` arm, never a guessed mode.
    #[test]
    fn a_pid_without_readable_status_has_no_mode() {
        assert_eq!(target_seccomp_mode(u32::MAX), None);
    }

    /// `run`'s exact call shape: an unprovable kernel refuses an owned
    /// child it cannot show unconfined, and the override converts that
    /// refusal into a warning with the same reason.
    #[test]
    fn an_owned_child_needs_positive_kernel_evidence() {
        assert!(matches!(
            evaluate_mode(None, false, || KernelVerdict::Unknown(
                "BPF load failed".to_string()
            )),
            Action::Refuse(_)
        ));
        assert!(matches!(
            evaluate_mode(None, false, || KernelVerdict::Affected(
                "the probe child was killed by SIGSYS"
            )),
            Action::Refuse(_)
        ));
        assert_eq!(
            evaluate_mode(None, false, || KernelVerdict::Clean),
            Action::Proceed
        );
        let Action::Refuse(refused) =
            evaluate_mode(None, false, || KernelVerdict::Unknown("x".to_string()))
        else {
            panic!("an unprovable kernel must refuse an owned child");
        };
        let Action::ProceedUnderOverride(warned) =
            evaluate_mode(None, true, || KernelVerdict::Unknown("x".to_string()))
        else {
            panic!("the override must convert the refusal");
        };
        assert_eq!(refused, warned, "the override must not soften the reason");
    }

    /// The probe is only consulted when the target side needs it: an
    /// unconfined target proceeds without forking anything.
    #[test]
    fn an_unconfined_target_never_pays_for_the_fork() {
        assert_eq!(
            evaluate_mode(Some(SeccompMode::Disabled), false, || panic!(
                "an unconfined target must not probe the kernel"
            )),
            Action::Proceed
        );
    }

    #[test]
    fn an_ordinary_exit_is_never_described_as_a_death() {
        for code in [0, 1, 42, 127, 128] {
            assert_eq!(
                describe_owned_child_death_with(code, 136, || panic!("must not probe")),
                None,
                "exit {code}"
            );
        }
    }

    /// The whole point of layer one: a signalled death must never read as an
    /// ordinary exit code.
    #[test]
    fn a_signalled_death_is_named_as_one() {
        let message = describe_owned_child_death_with(128 + libc::SIGTERM, 136, || {
            panic!("SIGTERM is not this defect's shape")
        })
        .expect("a signalled death must be described");
        assert!(
            message.contains("SIGTERM") && message.contains("not exited"),
            "{message}"
        );
    }

    #[test]
    fn the_two_measured_shapes_consult_the_kernel_and_say_what_it_found() {
        for signal in [libc::SIGSYS, libc::SIGSEGV] {
            let affected = describe_owned_child_death_with(128 + signal, 136, || {
                KernelVerdict::Affected("the probe child was killed by SIGSYS")
            })
            .expect("described");
            assert!(
                affected.contains("likely cause") && affected.contains(signal_name(signal)),
                "{affected}"
            );

            let clean = describe_owned_child_death_with(128 + signal, 136, || KernelVerdict::Clean)
                .expect("described");
            assert!(clean.contains("not the cause"), "{clean}");

            let unknown = describe_owned_child_death_with(128 + signal, 136, || {
                KernelVerdict::Unknown("no bpf".into())
            })
            .expect("described");
            assert!(unknown.contains("cannot be ruled out"), "{unknown}");
        }
    }

    /// The tool must not claim a kill it could not have performed — and must
    /// not pay for the kernel probe to find that out.
    #[test]
    fn a_death_with_no_probe_attached_is_never_blamed_on_our_uretprobes() {
        for signal in [libc::SIGSYS, libc::SIGSEGV] {
            let message = describe_owned_child_death_with(128 + signal, 0, || {
                panic!("no probe was attached, so the kernel cannot be at issue")
            })
            .expect("described");
            assert!(
                message.contains("not the cause") && message.contains(signal_name(signal)),
                "{message}"
            );
        }
    }

    /// An unrelated signal must not drag the kernel probe in, or every SIGTERM
    /// would fork a child and load a BPF object.
    #[test]
    fn only_the_defects_own_shapes_pay_for_the_kernel_probe() {
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGKILL, libc::SIGABRT] {
            assert!(!is_trampoline_death_shape(signal), "signal {signal}");
        }
        assert!(is_trampoline_death_shape(libc::SIGSYS));
        assert!(is_trampoline_death_shape(libc::SIGSEGV));
    }

    #[test]
    fn the_shell_status_convention_is_read_the_way_run_writes_it() {
        assert_eq!(
            signal_from_shell_status(128 + libc::SIGSYS),
            Some(libc::SIGSYS)
        );
        assert_eq!(signal_from_shell_status(0), None);
        assert_eq!(signal_from_shell_status(128), None, "128 is an exit code");
        assert_eq!(
            signal_from_shell_status(255),
            None,
            "beyond the signal range"
        );
    }

    #[test]
    fn seccomp_mode_is_read_from_the_status_field() {
        let status =
            "Name:\tsofthsm\nThreads:\t1\nSeccomp:\t2\nSpeculation_Store_Bypass:\tthread\n";
        assert_eq!(parse_seccomp_mode(status), Some(SeccompMode::Filter));
        assert_eq!(
            parse_seccomp_mode("Seccomp:\t0\n"),
            Some(SeccompMode::Disabled)
        );
        assert_eq!(
            parse_seccomp_mode("Seccomp:\t1\n"),
            Some(SeccompMode::Strict)
        );
    }

    /// Absent is not zero: a kernel built without `CONFIG_SECCOMP` omits the
    /// field, and so does a process that exited between the two reads.
    #[test]
    fn an_absent_seccomp_field_is_unknown_not_unconfined() {
        assert_eq!(parse_seccomp_mode("Name:\tx\nThreads:\t1\n"), None);
    }

    /// A mode number this build predates must not read as unconfined.
    #[test]
    fn an_unrecognised_seccomp_mode_is_treated_as_confining() {
        assert_eq!(
            parse_seccomp_mode("Seccomp:\t9\n"),
            Some(SeccompMode::Filter)
        );
        assert!(
            parse_seccomp_mode("Seccomp:\t9\n")
                .expect("parsed")
                .confines_syscalls()
        );
    }

    #[test]
    fn both_measured_death_shapes_are_affected_and_a_clean_exit_is_clean() {
        // 128+n is the shell convention; a raw wait status encodes the signal
        // in the low byte, which is what `WTERMSIG` reads.
        assert!(matches!(
            classify_probe_child(libc::SIGSYS),
            KernelVerdict::Affected(_)
        ));
        assert!(matches!(
            classify_probe_child(libc::SIGSEGV),
            KernelVerdict::Affected(_)
        ));
        assert_eq!(classify_probe_child(0), KernelVerdict::Clean);
    }

    /// A child that died some other way proves nothing either way.
    #[test]
    fn an_unexpected_child_end_is_unknown() {
        assert!(matches!(
            classify_probe_child(libc::SIGKILL),
            KernelVerdict::Unknown(_)
        ));
        // exit code 90: the child could not arm its own filter.
        assert!(matches!(
            classify_probe_child(90 << 8),
            KernelVerdict::Unknown(_)
        ));
    }

    /// Without a real return there is no trampoline, and the probe would call
    /// every kernel clean. Cheap guard that the call is not folded away.
    #[test]
    fn the_probe_point_is_a_real_call_that_returns() {
        assert_eq!(probe_point(41), 42);
    }
}
