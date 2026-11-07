//! SPDX-License-Identifier: GPL-3.0-or-later
//! Least-privilege capability profiles for the observer.
//!
//! p11scope runs as an ordinary user with file capabilities (`setcap` on
//! the binary): no sudo and no `CAP_SYS_ADMIN`. This module owns the
//! minimal live-capture set, the per-command keep sets dropped to at
//! startup, the exact missing-capability lines the doctor and capture
//! renders print, and the one-line `setcap` recipe. See `docs/usage.md`
//! ("Run without sudo") for the operator story.

use std::io;

/// `CAP_CHOWN` (`linux/capability.h`): hand `-o` outputs to the invoking
/// user (root runs). Never in the file set.
pub(crate) const CAP_CHOWN_BIT: u32 = 0;
/// `CAP_DAC_OVERRIDE` (`linux/capability.h`): write `-o` outputs where
/// only privilege allows (root runs). Never in the file set.
pub(crate) const CAP_DAC_OVERRIDE_BIT: u32 = 1;
/// `CAP_DAC_READ_SEARCH` (`linux/capability.h`): open provider files and
/// traverse target paths the observer could not otherwise read.
pub(crate) const CAP_DAC_READ_SEARCH_BIT: u32 = 2;
/// `CAP_FOWNER` (`linux/capability.h`): chmod a handed-over `-o` stream
/// private after the sudo handover (root runs). Never in the file set.
pub(crate) const CAP_FOWNER_BIT: u32 = 3;
/// `CAP_KILL` (`linux/capability.h`): signal the re-owned `run` child
/// across uids (root runs). Never in the file set.
pub(crate) const CAP_KILL_BIT: u32 = 5;
/// `CAP_SETGID` / `CAP_SETUID` (`linux/capability.h`): the `run` identity
/// change — the sudo drop as well as `--user` (root runs). Never in the
/// file set.
pub(crate) const CAP_SETGID_BIT: u32 = 6;
pub(crate) const CAP_SETUID_BIT: u32 = 7;
/// `CAP_SYS_PTRACE` (`linux/capability.h`): read a target's memory under
/// ptrace/Yama and cross-UID checks.
pub(crate) const CAP_SYS_PTRACE_BIT: u32 = 19;
/// `CAP_SYS_ADMIN` (`linux/capability.h`): only the per-probe singles
/// fallback still needs it (paranoid 3+). Never in the file set; kept at
/// startup so root singles captures keep working, dropped after setup
/// when the session runs uprobe-multi.
pub(crate) const CAP_SYS_ADMIN_BIT: u32 = 21;
/// `CAP_PERFMON` (`linux/capability.h`): the BPF/perf half of program load.
pub(crate) const CAP_PERFMON_BIT: u32 = 38;
/// `CAP_BPF` (`linux/capability.h`): load BPF programs and attach links.
pub(crate) const CAP_BPF_BIT: u32 = 39;
/// `CAP_CHECKPOINT_RESTORE` (`linux/capability.h`): follow target
/// `map_files` for the executable-identity proof.
pub(crate) const CAP_CHECKPOINT_RESTORE_BIT: u32 = 40;

/// One capability of the minimal live-capture set: its `CapEff` bit, its
/// display name, and what it enables. `CAP_SYS_ADMIN` is deliberately
/// absent: every probe attaches through uprobe-multi links, which
/// `kernel.perf_event_paranoid` does not gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KnownCap {
    /// Bit in the `CapEff` mask.
    pub bit: u32,
    /// Display name (`CAP_BPF`); lowercased it is the `setcap(8)` name.
    pub name: &'static str,
    /// What live capture uses it for, in operator words.
    pub enables: &'static str,
}

/// The minimal live-capture set, in canonical (alphabetical) order. One
/// source for the doctor row, the capture hints, the keep sets and the
/// `setcap` recipe, so they cannot drift apart.
pub(crate) const MINIMAL_LIVE: [KnownCap; 5] = [
    KnownCap {
        bit: CAP_BPF_BIT,
        name: "CAP_BPF",
        enables: "load BPF programs and attach probes",
    },
    KnownCap {
        bit: CAP_CHECKPOINT_RESTORE_BIT,
        name: "CAP_CHECKPOINT_RESTORE",
        enables: "prove executables through /proc/<pid>/map_files",
    },
    KnownCap {
        bit: CAP_DAC_READ_SEARCH_BIT,
        name: "CAP_DAC_READ_SEARCH",
        enables: "open provider files and target paths unreadable to the observer",
    },
    KnownCap {
        bit: CAP_PERFMON_BIT,
        name: "CAP_PERFMON",
        enables: "load BPF programs alongside CAP_BPF",
    },
    KnownCap {
        bit: CAP_SYS_PTRACE_BIT,
        name: "CAP_SYS_PTRACE",
        enables: "read a target's memory",
    },
];

/// The minimal live-capture set as a `CapEff` mask.
pub(crate) fn minimal_live_mask() -> u64 {
    MINIMAL_LIVE
        .iter()
        .fold(0u64, |mask, cap| mask | (1u64 << cap.bit))
}

/// The minimal-set capabilities absent from `effective`, in canonical
/// order. Empty when the set is complete.
pub(crate) fn missing_for_live(effective: u64) -> Vec<&'static KnownCap> {
    MINIMAL_LIVE
        .iter()
        .filter(|cap| effective & (1u64 << cap.bit) == 0)
        .collect()
}

/// The exact remediation line for one missing capability.
pub(crate) fn needs_line(cap: &KnownCap) -> String {
    format!("needs {} ({})", cap.name, cap.enables)
}

/// The `setcap(8)` capability list granting exactly the minimal live set:
/// canonical order, `=ep` (effective + permitted, never ambient: the `run`
/// child must not inherit any).
fn setcap_spec() -> String {
    let names: Vec<String> = MINIMAL_LIVE
        .iter()
        .map(|cap| cap.name.to_ascii_lowercase())
        .collect();
    format!("{}=ep", names.join(","))
}

/// Shell-quote `binary` for the recipe line: bare when it is plain path
/// characters, single-quoted otherwise, so a hostile path cannot break
/// out of the one-liner.
fn quote_binary(binary: &str) -> String {
    const PLAIN: fn(char) -> bool = |c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-')
    };
    if !binary.is_empty() && binary.chars().all(PLAIN) {
        binary.to_string()
    } else {
        format!("'{}'", binary.replace('\'', "'\\''"))
    }
}

/// The exact one-line `setcap` command granting exactly the minimal live
/// set to `binary`.
pub(crate) fn setcap_command(binary: &str) -> String {
    format!("sudo setcap '{}' {}", setcap_spec(), quote_binary(binary))
}

/// The `CapEff` bits gating BPF program load and link attach: a load
/// refusal names the missing ones of these, never the wider live set.
pub(crate) const LOAD_BITS: [u32; 2] = [CAP_BPF_BIT, CAP_PERFMON_BIT];

/// The `CapEff` bits gating reads of another process's memory, mount
/// namespace and mappings: either can be the cause of an access refusal.
pub(crate) const TARGET_READ_BITS: [u32; 2] = [CAP_DAC_READ_SEARCH_BIT, CAP_SYS_PTRACE_BIT];

/// The `CapEff` bit gating `/proc/<pid>/map_files` for another uid.
pub(crate) const MAP_FILES_BITS: [u32; 1] = [CAP_CHECKPOINT_RESTORE_BIT];

/// Among `bits`, the known minimal-live entries absent from `effective`,
/// in canonical order. Empty when the gated operation's set is complete.
pub(crate) fn missing_in(effective: u64, bits: &[u32]) -> Vec<&'static KnownCap> {
    MINIMAL_LIVE
        .iter()
        .filter(|cap| bits.contains(&cap.bit) && effective & (1u64 << cap.bit) == 0)
        .collect()
}

/// This binary's path for the recipe line: the running executable, or a
/// bare `p11scope` when it cannot be determined.
pub(crate) fn current_binary() -> String {
    std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "p11scope".to_string())
}

/// The plain clause for a refusal gated by `missing`: each capability
/// with what it enables, then the one-line setcap recipe. Never empty:
/// callers use it only for a non-empty missing set.
pub(crate) fn lacking_line(missing: &[&KnownCap], binary: &str) -> String {
    let needs: Vec<String> = missing.iter().map(|cap| needs_line(cap)).collect();
    format!(
        "{}. Grant the minimal set: {}",
        needs.join("; "),
        setcap_command(binary)
    )
}

/// Name the missing ones of `bits` on stderr, once per process per
/// capability: a missing capability gets its line exactly where its
/// operation fails, without repeating for every object in a scan. A
/// closed stderr drops the line instead of panicking.
pub(crate) fn note_lacking(bits: &[u32]) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NOTED: AtomicU64 = AtomicU64::new(0);
    let Some(effective) = read_effective() else {
        return;
    };
    let mut newly = Vec::new();
    for cap in missing_in(effective, bits) {
        let bit = 1u64 << cap.bit;
        if NOTED.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
            newly.push(cap);
        }
    }
    if !newly.is_empty() {
        let _ = crate::try_stderr_line(&format!(
            "p11scope: {}",
            lacking_line(&newly, &current_binary())
        ));
    }
}

/// The keep mask after setup: a multi session whose dynamic probes link
/// (`dynamic_multi`: multi backend plus a proven kernel pid filter, so
/// no `perf_event_open` remains past attach, measured lane F15) sheds
/// the transient `CAP_SYS_ADMIN`, unless it is the only map_files grant
/// — the effective set lacks `CAP_CHECKPOINT_RESTORE` (the DaemonSet),
/// so later identity proofs still need it. A singles session, or a multi
/// session whose dynamics stay on perf (an unproven pid filter on 6.6-6.9
/// without the backport), keeps it for dynamic perf re-attach.
pub(crate) fn post_setup_keep(multi: bool, dynamic_multi: bool, effective: u64) -> u64 {
    if multi
        && dynamic_multi
        && effective & (1u64 << CAP_CHECKPOINT_RESTORE_BIT) != 0
    {
        effective & !(1u64 << CAP_SYS_ADMIN_BIT)
    } else {
        effective
    }
}

/// This process's effective capabilities, from `/proc/self/status`
/// `CapEff`; `None` when unreadable or unparsable.
pub(crate) fn read_effective() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_cap_eff(&status)
}

fn parse_cap_eff(status: &str) -> Option<u64> {
    let hex = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?;
    u64::from_str_radix(hex.trim(), 16).ok()
}

/// This thread's effective capabilities via `capget` (no `/proc` read,
/// so a broken `/proc` cannot zero the set the shed computes from).
/// Fails closed on syscall error; callers propagate instead of guessing.
pub(crate) fn read_effective_via_capget() -> io::Result<u64> {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: version-3 header with pid 0 addresses this thread; the two
    // data words are caller-owned stack with the kernel's layout.
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((data[0].effective as u64) | ((data[1].effective as u64) << 32))
}

/// `capget`/`capset` header (`linux/capability.h`, version 3).
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

/// One `capget`/`capset` data word pair (`linux/capability.h`).
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Drop every capability outside `keep` from this process (effective,
/// permitted, inheritable, ambient). Only ever removes: each set is
/// intersected with its current value, so bits outside the current sets
/// are ignored, never added, and the call needs no privilege of its own.
/// Detaching BPF links, draining rings and reaping children need no
/// capabilities, so a correct keep set never breaks cleanup.
pub(crate) fn drop_to_keep(keep: u64) -> io::Result<()> {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut current = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: version-3 header with pid 0 addresses this thread; the two
    // data words are caller-owned stack with the kernel's layout.
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, current.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // The two words cover capabilities 0-31 and 32-63; intersect each
    // set with the kept half, keeping effective inside permitted.
    let half = |word: CapData, shift: u32| {
        let keep_half = (keep >> shift) as u32;
        let permitted = word.permitted & keep_half;
        CapData {
            effective: word.effective & permitted,
            permitted,
            inheritable: word.inheritable & keep_half,
        }
    };
    let masked = [half(current[0], 0), half(current[1], 32)];
    // SAFETY: same header and caller-owned words as the `capget` above.
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, masked.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `PR_CAP_AMBIENT_CLEAR_ALL` takes no pointer arguments.
    if unsafe {
        libc::syscall(
            libc::SYS_prctl,
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The capabilities one command keeps after startup: everything it can
/// need later, nothing else. That is the minimal live set plus the
/// root-functional extras, each conditioned on the flags that need it:
/// `-o` anywhere needs DAC_OVERRIDE, CHOWN and FOWNER (the handover
/// plus the post-handover chmod), the singles fallback needs
/// SYS_ADMIN, `run` always needs SETUID/SETGID/KILL (the sudo drop runs
/// without `--user`, and the parent signals the re-owned child across
/// uids). A setcap user never holds the extras, so the same masks shed
/// the whole grant surplus there; root keeps a functional subset instead
/// of the full set. Live capture keeps the minimal set whole (dynamic
/// attach and rescans run until the end); `doctor` keeps it too (it
/// reports the invoking set, so it must not drop first); `inspect` never
/// loads BPF, and scan-only `inventory` keeps only its
/// target-read/map-files bits; `diff` keeps file IO only.
pub(crate) fn keep_mask_for_command(command: &crate::cli::Command) -> u64 {
    use crate::cli::Command;
    let live = minimal_live_mask();
    let sys_admin = 1u64 << CAP_SYS_ADMIN_BIT;
    let out = |out: &Option<std::path::PathBuf>| {
        if out.is_some() {
            (1u64 << CAP_CHOWN_BIT) | (1u64 << CAP_DAC_OVERRIDE_BIT) | (1u64 << CAP_FOWNER_BIT)
        } else {
            0
        }
    };
    match command {
        Command::Profile(a) | Command::Trace(a) => live | sys_admin | out(&a.out),
        Command::Inventory(a) if a.capture == crate::cli::CaptureMode::Scan => {
            // Scan reads `/proc` only: no BPF load, no links, no perf.
            (live & !((1u64 << CAP_BPF_BIT) | (1u64 << CAP_PERFMON_BIT))) | out(&a.out)
        }
        Command::Inventory(a) => live | sys_admin | out(&a.out),
        Command::Run(a) => {
            // Always: the sudo drop re-owns the child without `--user`
            // (setgroups/setresgid/setresuid need SETGID/SETUID), and the
            // parent signals it across uids (pidfd/kill need KILL).
            let ids = (1u64 << CAP_SETUID_BIT) | (1u64 << CAP_SETGID_BIT) | (1u64 << CAP_KILL_BIT);
            live | sys_admin | out(&a.out) | ids
        }
        // The diagnostic session links its self-probe on multi hosts,
        // so doctor needs no SYS_ADMIN even at paranoid 4; the perf
        // fallback on pre-multi hosts degrades to a failed row.
        Command::Doctor(_) => live,
        // `inspect` reads memory and files only ("No BPF" is its module
        // contract, and it has no `-o`); the witness still needs
        // checkpoint/restore.
        Command::Inspect(_) => live & !((1u64 << CAP_BPF_BIT) | (1u64 << CAP_PERFMON_BIT)),
        Command::InventoryDiff(a) => (1u64 << CAP_DAC_READ_SEARCH_BIT) | out(&a.out),
        Command::Version => 0,
    }
}

/// The BPF/PERFMON/CHECKPOINT_RESTORE bits `command` needs for its own
/// operations: where the effective set lacks any of them, `CAP_SYS_ADMIN`
/// is the only grant the kernel accepts instead (the DaemonSet holds
/// SYS_ADMIN, not the narrow caps), so the keep must retain it. Live
/// capture keeps SYS_ADMIN already for the singles fallback; doctor needs
/// the BPF pair for its self-probe link plus map_files; inspect and scan
/// need map_files only; diff and version need none of the three.
fn sys_admin_fallback_bits(command: &crate::cli::Command) -> u64 {
    use crate::cli::Command;
    let bpf = (1u64 << CAP_BPF_BIT)
        | (1u64 << CAP_PERFMON_BIT)
        | (1u64 << CAP_CHECKPOINT_RESTORE_BIT);
    let map_files = 1u64 << CAP_CHECKPOINT_RESTORE_BIT;
    match command {
        Command::Profile(_)
        | Command::Trace(_)
        | Command::Run(_)
        | Command::Doctor(_)
        | Command::Inventory(_) => {
            // Inventory scan drops the BPF pair it never loads, so it
            // needs map_files only; every other live lane needs all three.
            if let Command::Inventory(a) = command
                && a.capture == crate::cli::CaptureMode::Scan
            {
                return map_files;
            }
            bpf
        }
        Command::Inspect(_) => map_files,
        Command::InventoryDiff(_) | Command::Version => 0,
    }
}

/// The keep mask for `command` given the `effective` set it runs with:
/// the static keep plus `CAP_SYS_ADMIN` when the effective set lacks any
/// of the BPF/PERFMON/CHECKPOINT_RESTORE bits the command needs (the
/// DaemonSet holds SYS_ADMIN, not the narrow caps, and the kernel
/// accepts SYS_ADMIN for those checks).
pub(crate) fn keep_mask_for_command_in(
    effective: u64,
    command: &crate::cli::Command,
) -> u64 {
    let base = keep_mask_for_command(command);
    let needs = sys_admin_fallback_bits(command);
    if effective & needs != needs {
        base | (1u64 << CAP_SYS_ADMIN_BIT)
    } else {
        base
    }
}

/// Drop what `command` never needs, before it runs. Returns the kept mask.
/// The fallback reads the effective set from `/proc`; an unreadable
/// status keeps `CAP_SYS_ADMIN` (fail-safe, never a silent loss of the
/// only grant), and a refused drop still fails closed below.
pub fn drop_unneeded_for_command(command: &crate::cli::Command) -> io::Result<u64> {
    let effective = read_effective().unwrap_or(0);
    let keep = keep_mask_for_command_in(effective, command);
    drop_to_keep(keep)?;
    Ok(keep)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stub bodies above must fail these until implemented (RED).
    #[test]
    fn minimal_set_lists_five_caps_in_canonical_order() {
        let names: Vec<&str> = MINIMAL_LIVE.iter().map(|cap| cap.name).collect();
        assert_eq!(
            names,
            [
                "CAP_BPF",
                "CAP_CHECKPOINT_RESTORE",
                "CAP_DAC_READ_SEARCH",
                "CAP_PERFMON",
                "CAP_SYS_PTRACE",
            ]
        );
        assert_eq!(
            minimal_live_mask(),
            (1u64 << CAP_BPF_BIT)
                | (1u64 << CAP_CHECKPOINT_RESTORE_BIT)
                | (1u64 << CAP_DAC_READ_SEARCH_BIT)
                | (1u64 << CAP_PERFMON_BIT)
                | (1u64 << CAP_SYS_PTRACE_BIT)
        );
        assert!(
            !names.contains(&"CAP_SYS_ADMIN"),
            "the minimal set must never need CAP_SYS_ADMIN"
        );
    }

    /// Per-capability twins: held -> absent from the missing list, missing
    /// -> exactly its own entry, with the exact remediation line.
    #[test]
    fn each_minimal_cap_missing_gives_its_exact_line() {
        let full = minimal_live_mask();
        assert!(missing_for_live(full).is_empty());
        assert!(missing_for_live(u64::MAX).is_empty());
        for cap in &MINIMAL_LIVE {
            assert!(
                missing_for_live(full)
                    .iter()
                    .all(|got| got.name != cap.name),
                "{} held but reported missing",
                cap.name
            );
            let missing = missing_for_live(full & !(1u64 << cap.bit));
            assert_eq!(missing, vec![cap], "only {} is missing", cap.name);
            assert_eq!(
                needs_line(cap),
                format!("needs {} ({})", cap.name, cap.enables),
                "exact line for {}",
                cap.name
            );
        }
        let all_missing = missing_for_live(0);
        assert_eq!(all_missing.len(), MINIMAL_LIVE.len());
    }

    #[test]
    fn setcap_command_grants_exactly_the_minimal_set() {
        assert_eq!(
            setcap_command("/usr/local/bin/p11scope"),
            "sudo setcap 'cap_bpf,cap_checkpoint_restore,cap_dac_read_search,cap_perfmon,cap_sys_ptrace=ep' /usr/local/bin/p11scope"
        );
        assert_eq!(setcap_command("/usr/local/bin/p11scope").lines().count(), 1);
    }

    #[test]
    fn setcap_command_quotes_a_hostile_binary_path() {
        let line = setcap_command("/tmp/evil dir/p11scope;id");
        assert_eq!(line.lines().count(), 1);
        assert!(
            line.ends_with("'/tmp/evil dir/p11scope;id'") || !line.contains(";id"),
            "the path must not break out of the command line: {line}"
        );
    }

    /// A refusal names only the capabilities gating its own operation:
    /// a load refusal never blames checkpoint/restore, a map_files
    /// refusal never blames the BPF pair.
    #[test]
    fn missing_in_scopes_blame_to_the_gated_operation() {
        let full = minimal_live_mask();
        assert!(missing_in(full, &LOAD_BITS).is_empty());
        assert!(missing_in(u64::MAX, &LOAD_BITS).is_empty());
        let names =
            |missing: Vec<&KnownCap>| missing.iter().map(|cap| cap.name).collect::<Vec<_>>();
        // One load cap missing: exactly it, even with the rest held.
        assert_eq!(
            names(missing_in(full & !(1u64 << CAP_BPF_BIT), &LOAD_BITS)),
            ["CAP_BPF"]
        );
        assert_eq!(
            names(missing_in(full & !(1u64 << CAP_PERFMON_BIT), &LOAD_BITS)),
            ["CAP_PERFMON"]
        );
        // Capabilities outside the gated set are never blamed.
        assert!(missing_in(full & !(1u64 << CAP_CHECKPOINT_RESTORE_BIT), &LOAD_BITS).is_empty());
        assert!(missing_in(full & !(1u64 << CAP_BPF_BIT), &MAP_FILES_BITS).is_empty());
        // The target-read pair blames either member, in canonical order.
        assert_eq!(
            names(missing_in(0, &TARGET_READ_BITS)),
            ["CAP_DAC_READ_SEARCH", "CAP_SYS_PTRACE"]
        );
    }

    /// The refusal clause: every missing capability with what it
    /// enables, then the one-line recipe. Byte-exact: refusals embed it.
    #[test]
    fn lacking_line_names_each_cap_then_the_recipe() {
        let binary = "/usr/bin/p11scope";
        let line = lacking_line(&missing_in(0, &LOAD_BITS), binary);
        assert_eq!(
            line,
            "needs CAP_BPF (load BPF programs and attach probes); needs CAP_PERFMON \
             (load BPF programs alongside CAP_BPF). Grant the minimal set: sudo setcap \
             'cap_bpf,cap_checkpoint_restore,cap_dac_read_search,cap_perfmon,cap_sys_ptrace=ep' \
             /usr/bin/p11scope"
        );
        assert_eq!(line.lines().count(), 1);
    }

    /// Post-setup least privilege: multi with linked dynamics sheds the
    /// transient `CAP_SYS_ADMIN`, singles keeps it, multi with perf
    /// dynamics (an unproven pid filter) keeps it for re-attach, and a
    /// setcap process without it is untouched either way.
    #[test]
    fn post_setup_keep_sheds_only_the_transient_sys_admin() {
        let sys_admin = 1u64 << CAP_SYS_ADMIN_BIT;
        let live = minimal_live_mask();
        assert_eq!(post_setup_keep(true, true, live | sys_admin), live);
        assert_eq!(post_setup_keep(true, true, live), live);
        assert_eq!(
            post_setup_keep(true, true, u64::MAX),
            u64::MAX & !sys_admin
        );
        assert_eq!(
            post_setup_keep(false, false, live | sys_admin),
            live | sys_admin
        );
        assert_eq!(post_setup_keep(false, false, live), live);
        // Multi backend with perf dynamics: the pid-filter probe failed,
        // so dynamic re-attach still needs SYS_ADMIN.
        assert_eq!(
            post_setup_keep(true, false, live | sys_admin),
            live | sys_admin
        );
        assert_eq!(post_setup_keep(true, false, u64::MAX), u64::MAX);
    }

    fn parse(argv: &[&str]) -> crate::cli::Command {
        crate::cli::parse(argv.iter().map(std::ffi::OsString::from)).expect("test argv parses")
    }

    /// Per-command keep sets: live capture keeps the minimal set plus
    /// the root-functional extras (`-o` anywhere needs DAC_OVERRIDE and
    /// CHOWN for the handoff, the singles fallback needs SYS_ADMIN,
    /// `run` always keeps SETUID/SETGID/KILL for the sudo-drop identity
    /// change and signalling its re-owned child);
    /// `inspect` drops the BPF pair it never uses; `diff` keeps file IO
    /// only; `--version` keeps nothing. A setcap user never holds the
    /// extras, so the same masks shed them there automatically.
    #[test]
    fn keep_masks_match_command_needs() {
        let live = minimal_live_mask();
        assert_ne!(live, 0, "the live set is not empty");
        for cap in &MINIMAL_LIVE {
            assert_ne!(live & (1u64 << cap.bit), 0, "{} is kept", cap.name);
        }
        // `-o` extras: CHOWN for the handover, DAC_OVERRIDE to write
        // where only privilege allows, FOWNER to chmod the handed-over
        // stream private.
        let file_out = (1u64 << CAP_CHOWN_BIT)
            | (1u64 << CAP_DAC_OVERRIDE_BIT)
            | (1u64 << CAP_FOWNER_BIT);
        let sys_admin = 1u64 << CAP_SYS_ADMIN_BIT;
        let set_ids = (1u64 << CAP_SETUID_BIT) | (1u64 << CAP_SETGID_BIT);
        let kill = 1u64 << CAP_KILL_BIT;
        let run_keep = live | sys_admin | set_ids | kill;
        // Live capture without `-o`: minimal set plus the singles fallback.
        for argv in [
            vec!["profile", "--pid", "1"],
            vec!["trace", "--pid", "1"],
            vec!["inventory", "--system"],
        ] {
            assert_eq!(
                keep_mask_for_command(&parse(&argv)),
                live | sys_admin,
                "{argv:?}"
            );
        }
        // `run` without `--user` still drops to the sudo invoker and
        // signals across uids, so it keeps the identity caps always.
        for argv in [
            vec!["run", "--", "/bin/true"],
            vec!["run", "--user", "nobody", "--", "/bin/true"],
        ] {
            assert_eq!(keep_mask_for_command(&parse(&argv)), run_keep, "{argv:?}");
        }
        // `-o` anywhere needs DAC_OVERRIDE on top (root runs).
        for argv in [
            vec!["profile", "--pid", "1", "-o", "out.json"],
            vec!["trace", "--pid", "1", "-o", "out.json"],
            vec!["inventory", "--system", "-o", "out.json"],
        ] {
            assert_eq!(
                keep_mask_for_command(&parse(&argv)),
                live | sys_admin | file_out,
                "{argv:?}"
            );
        }
        for argv in [
            vec!["run", "-o", "out.json", "--", "/bin/true"],
            vec![
                "run",
                "--user",
                "nobody",
                "-o",
                "out.json",
                "--",
                "/bin/true",
            ],
        ] {
            assert_eq!(
                keep_mask_for_command(&parse(&argv)),
                run_keep | file_out,
                "{argv:?}"
            );
        }
        let inspect = live & !((1u64 << CAP_BPF_BIT) | (1u64 << CAP_PERFMON_BIT));
        for argv in [vec!["inspect", "--pid", "1"], vec!["inspect", "--system"]] {
            assert_eq!(keep_mask_for_command(&parse(&argv)), inspect, "{argv:?}");
        }
        // Doctor needs no SYS_ADMIN: its self-probe links on multi
        // hosts, and the perf fallback only degrades a row elsewhere.
        assert_eq!(keep_mask_for_command(&parse(&["doctor"])), live);
        // `diff` reads two inputs and optionally writes one output.
        let dac_read_search = 1u64 << CAP_DAC_READ_SEARCH_BIT;
        assert_eq!(
            keep_mask_for_command(&parse(&["inventory", "diff", "a.json", "b.json"])),
            dac_read_search
        );
        assert_eq!(
            keep_mask_for_command(&parse(&[
                "inventory",
                "diff",
                "a.json",
                "b.json",
                "-o",
                "out.json"
            ])),
            dac_read_search | file_out
        );
        assert_eq!(keep_mask_for_command(&parse(&["--version"])), 0);
    }

    /// Scan-only inventory loads no BPF and links nothing, so it keeps
    /// only the target-read/map-files bits plus `-o` extras, never the
    /// BPF pair or the singles `SYS_ADMIN` transient.
    #[test]
    fn scan_inventory_drops_load_and_sys_admin_it_never_uses() {
        let live = minimal_live_mask();
        let scan_keep = live & !((1u64 << CAP_BPF_BIT) | (1u64 << CAP_PERFMON_BIT));
        let file_out = (1u64 << CAP_CHOWN_BIT)
            | (1u64 << CAP_DAC_OVERRIDE_BIT)
            | (1u64 << CAP_FOWNER_BIT);
        let sys_admin = 1u64 << CAP_SYS_ADMIN_BIT;
        // Scan in every scope keeps only target-read/map-files.
        for argv in [
            vec!["inventory", "--system", "--capture", "scan"],
            vec!["inventory", "--pid", "1", "--capture", "scan"],
            vec![
                "inventory",
                "--cgroup",
                "/sys/fs/cgroup/test.slice",
                "--capture",
                "scan",
            ],
        ] {
            let mask = keep_mask_for_command(&parse(&argv));
            assert_eq!(mask, scan_keep, "{argv:?}");
            assert_eq!(
                mask & ((1u64 << CAP_BPF_BIT) | (1u64 << CAP_PERFMON_BIT) | sys_admin),
                0,
                "{argv:?} must not keep load or sys_admin"
            );
        }
        // Scan with `-o` adds only file extras.
        assert_eq!(
            keep_mask_for_command(&parse(&[
                "inventory",
                "--system",
                "--capture",
                "scan",
                "-o",
                "out.json"
            ])),
            scan_keep | file_out
        );
        // Auto/native still need live plus the transient.
        for argv in [
            vec!["inventory", "--system", "--capture", "auto"],
            vec!["inventory", "--system", "--capture", "native"],
            vec!["inventory", "--pid", "1", "--capture", "native"],
        ] {
            assert_eq!(
                keep_mask_for_command(&parse(&argv)),
                live | sys_admin,
                "{argv:?}"
            );
        }
    }

    #[test]
    fn read_effective_matches_proc_self_status() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let expected = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok());
        assert_eq!(read_effective(), expected);
    }

    /// Runs `action` (syscalls only, no allocation) in a fork child and
    /// polls the child's own `/proc/<pid>/status` until its
    /// (`CapEff`, `CapAmb`) reaches `expect`, or a one-second deadline.
    /// Returns the last observed pair. The child is killed and reaped, so
    /// the parent's sets are untouched and this is safe in every lane.
    fn child_cap_sets_after(
        expect: (u64, u64),
        action: impl FnOnce() -> std::io::Result<u64>,
    ) -> (Option<u64>, Option<u64>) {
        // SAFETY: the child runs only the syscall-only action, then spins
        // on `usleep` until killed; it `_exit`s on every path, so no
        // destructors run post-fork.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            let outcome = action();
            unsafe {
                if outcome.is_err() {
                    libc::_exit(41);
                }
                for _ in 0..200 {
                    libc::usleep(100_000);
                }
                libc::_exit(42);
            }
        }
        let child = child as u32;
        let status_path = format!("/proc/{child}/status");
        let mut observed = (None, None);
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            let Ok(status) = std::fs::read_to_string(&status_path) else {
                break;
            };
            let at = |label: &str| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix(label))
                    .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            };
            observed = (at("CapEff:"), at("CapAmb:"));
            if observed == (Some(expect.0), Some(expect.1)) {
                break;
            }
        }
        unsafe {
            libc::kill(child as i32, libc::SIGKILL);
        }
        let mut status = 0;
        unsafe {
            libc::waitpid(child as i32, &mut status, 0);
        }
        observed
    }

    /// The drop runs in a fork child and the parent reads the child's own
    /// `CapEff`: dropping to zero must zero it (non-vacuous as root, where
    /// the child starts with capabilities), and ambient must clear too.
    /// The parent's sets are untouched, so this is safe in every lane.
    #[test]
    fn drop_to_keep_zeroes_a_child_without_touching_the_parent() {
        let parent_before = read_effective();
        let observed = child_cap_sets_after((0, 0), || drop_to_keep(0).map(|()| 0));
        assert_eq!(
            observed,
            (Some(0), Some(0)),
            "the child must reach zero effective+ambient capabilities"
        );
        assert_eq!(read_effective(), parent_before, "the parent keeps its sets");
    }

    /// The startup entry keeps exactly the command's keep set intersected
    /// with what the process holds (non-vacuous as root: `inspect` keeps
    /// three of the five minimal capabilities there).
    #[test]
    fn drop_unneeded_for_command_applies_per_command_keep_sets() {
        let parent_before = read_effective();
        let command = parse(&["inspect", "--pid", "1"]);
        let keep = keep_mask_for_command(&command);
        let expected = parent_before.unwrap_or(0) & keep;
        let observed = child_cap_sets_after((expected, 0), || drop_unneeded_for_command(&command));
        assert_eq!(
            observed,
            (Some(expected), Some(0)),
            "the child must keep exactly the inspect set"
        );
        assert_eq!(read_effective(), parent_before, "the parent keeps its sets");
    }

    /// The DaemonSet grant (`SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH`):
    /// where it lacks a narrow capability the command needs, the keep
    /// must retain `SYS_ADMIN` as the only grant the kernel accepts for
    /// it; where the narrow set is complete, no `SYS_ADMIN` is kept.
    #[test]
    fn sys_admin_fallback_keeps_the_only_grant() {
        let daemonset = (1u64 << CAP_SYS_ADMIN_BIT)
            | (1u64 << CAP_SYS_PTRACE_BIT)
            | (1u64 << CAP_DAC_READ_SEARCH_BIT);
        let sys_admin = 1u64 << CAP_SYS_ADMIN_BIT;
        let live = minimal_live_mask();
        // Doctor needs the BPF pair: the DaemonSet lacks both, so the
        // keep retains SYS_ADMIN; the minimal set holds both, so none.
        let doctor = parse(&["doctor"]);
        assert_ne!(
            keep_mask_for_command_in(daemonset, &doctor) & sys_admin,
            0,
            "doctor under the DaemonSet set must keep SYS_ADMIN for BPF"
        );
        assert_eq!(
            keep_mask_for_command_in(live, &doctor) & sys_admin,
            0,
            "doctor with the minimal set must not keep SYS_ADMIN"
        );
        // Inspect and scan need map_files only: the DaemonSet lacks
        // CHECKPOINT_RESTORE, so SYS_ADMIN stays; the minimal set holds
        // it, so SYS_ADMIN goes.
        for argv in [
            vec!["inspect", "--pid", "1"],
            vec!["inspect", "--system"],
            vec!["inventory", "--system", "--capture", "scan"],
            vec!["inventory", "--pid", "1", "--capture", "scan"],
        ] {
            let command = parse(&argv);
            assert_ne!(
                keep_mask_for_command_in(daemonset, &command) & sys_admin,
                0,
                "{argv:?} under the DaemonSet set must keep SYS_ADMIN for map_files"
            );
            assert_eq!(
                keep_mask_for_command_in(live, &command) & sys_admin,
                0,
                "{argv:?} with the minimal set must not keep SYS_ADMIN"
            );
        }
        // Live `--system` capture keeps SYS_ADMIN either way (the singles
        // fallback), so the DaemonSet twin pins the kept bit.
        for argv in [
            vec!["inventory", "--system"],
            vec!["profile", "--system", "--duration", "1s"],
        ] {
            let command = parse(&argv);
            assert_ne!(
                keep_mask_for_command_in(daemonset, &command) & sys_admin,
                0,
                "{argv:?} under the DaemonSet set must keep SYS_ADMIN"
            );
        }
        // Post-setup: multi sheds only when CHECKPOINT_RESTORE survives
        // it; the DaemonSet lacks it, so the shed keeps SYS_ADMIN.
        assert_eq!(
            post_setup_keep(true, true, daemonset),
            daemonset,
            "post-setup under the DaemonSet set must keep SYS_ADMIN for map_files"
        );
        assert_eq!(
            post_setup_keep(true, true, live | sys_admin),
            live,
            "post-setup with CHECKPOINT_RESTORE sheds SYS_ADMIN"
        );
        // The capget read agrees with `/proc` (no silent divergence
        // between the shed's input and the observable set).
        assert_eq!(
            read_effective_via_capget().ok(),
            read_effective(),
            "capget and /proc must report the same effective set"
        );
    }
}
