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

/// `CAP_DAC_READ_SEARCH` (`linux/capability.h`): open provider files and
/// traverse target paths the observer could not otherwise read.
pub(crate) const CAP_DAC_READ_SEARCH_BIT: u32 = 2;
/// `CAP_SYS_PTRACE` (`linux/capability.h`): read a target's memory under
/// ptrace/Yama and cross-UID checks.
pub(crate) const CAP_SYS_PTRACE_BIT: u32 = 19;
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
    0
}

/// The minimal-set capabilities absent from `effective`, in canonical
/// order. Empty when the set is complete.
pub(crate) fn missing_for_live(effective: u64) -> Vec<&'static KnownCap> {
    let _ = effective;
    Vec::new()
}

/// The exact remediation line for one missing capability.
pub(crate) fn needs_line(cap: &KnownCap) -> String {
    let _ = cap;
    String::new()
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
    let _ = binary;
    String::new()
}

/// This process's effective capabilities, from `/proc/self/status`
/// `CapEff`; `None` when unreadable or unparsable.
pub(crate) fn read_effective() -> Option<u64> {
    None
}

fn parse_cap_eff(status: &str) -> Option<u64> {
    let hex = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?;
    u64::from_str_radix(hex.trim(), 16).ok()
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
    let _ = keep;
    Ok(())
}

/// The capabilities one command keeps after startup: everything it can
/// need later, nothing else. Live capture keeps the full minimal set
/// (dynamic attach and rescans run until the end); `doctor` keeps it too
/// (it reports the invoking set, so it must not drop first); `inspect`
/// never loads BPF; offline commands keep nothing.
pub(crate) fn keep_mask_for_command(command: &crate::cli::Command) -> u64 {
    let _ = command;
    0
}

/// Drop what `command` never needs, before it runs. Returns the kept mask.
pub fn drop_unneeded_for_command(command: &crate::cli::Command) -> io::Result<u64> {
    let _ = command;
    Ok(0)
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

    fn parse(argv: &[&str]) -> crate::cli::Command {
        crate::cli::parse(argv.iter().map(std::ffi::OsString::from)).expect("test argv parses")
    }

    /// Per-command keep sets: live capture keeps the full minimal set,
    /// `inspect` drops the BPF pair it never uses, offline commands and
    /// `--version` keep nothing.
    #[test]
    fn keep_masks_match_command_needs() {
        let live = minimal_live_mask();
        assert_ne!(live, 0, "the live set is not empty");
        for cap in &MINIMAL_LIVE {
            assert_ne!(live & (1u64 << cap.bit), 0, "{} is kept", cap.name);
        }
        for argv in [
            vec!["profile", "--pid", "1"],
            vec!["trace", "--pid", "1"],
            vec!["run", "--", "/bin/true"],
            vec!["inventory", "--system"],
        ] {
            assert_eq!(keep_mask_for_command(&parse(&argv)), live, "{argv:?}");
        }
        let inspect = live & !((1u64 << CAP_BPF_BIT) | (1u64 << CAP_PERFMON_BIT));
        for argv in [vec!["inspect", "--pid", "1"], vec!["inspect", "--system"]] {
            assert_eq!(keep_mask_for_command(&parse(&argv)), inspect, "{argv:?}");
        }
        assert_eq!(keep_mask_for_command(&parse(&["doctor"])), live);
        assert_eq!(
            keep_mask_for_command(&parse(&["inventory", "diff", "a.json", "b.json"])),
            0
        );
        assert_eq!(keep_mask_for_command(&parse(&["--version"])), 0);
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

    /// The drop runs in a fork child and the parent reads the child's own
    /// `CapEff`: dropping to zero must zero it (non-vacuous as root, where
    /// the child starts with capabilities), and ambient must clear too.
    /// The parent's sets are untouched, so this is safe in every lane.
    #[test]
    fn drop_to_keep_zeroes_a_child_without_touching_the_parent() {
        let parent_before = read_effective();
        // SAFETY: the child only issues syscalls and `_exit`.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe {
                let outcome = drop_to_keep(0);
                // Signal readiness through the exit path is racy; spin
                // instead so the parent can poll our status first.
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
        let mut observed = None;
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            let Ok(status) = std::fs::read_to_string(&status_path) else {
                break;
            };
            let eff = status
                .lines()
                .find_map(|line| line.strip_prefix("CapEff:"))
                .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok());
            let amb = status
                .lines()
                .find_map(|line| line.strip_prefix("CapAmb:"))
                .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok());
            if eff == Some(0) && amb == Some(0) {
                observed = Some((eff, amb));
                break;
            }
            observed = Some((eff, amb));
        }
        unsafe {
            libc::kill(child as i32, libc::SIGKILL);
        }
        let mut status = 0;
        unsafe {
            libc::waitpid(child as i32, &mut status, 0);
        }
        assert_eq!(
            observed,
            Some((Some(0), Some(0))),
            "the child must reach zero effective+ambient capabilities"
        );
        assert_eq!(read_effective(), parent_before, "the parent keeps its sets");
    }
}
