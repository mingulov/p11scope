//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//!
//! Plain hint when an AppArmor-confined observer cannot read other processes.
//!
//! A container run with `--pid=host` and the capabilities but WITHOUT
//! `--security-opt apparmor=p11scope-observer` holds `CAP_SYS_PTRACE` while
//! the confining profile (e.g. `docker-default`) denies ptrace-mode reads of
//! every host process. Discovery then sees almost nothing, and the gaps blame
//! the scan cap instead of the confinement. This module detects exactly that:
//! the observer's own label is not `unconfined`, `CAP_SYS_PTRACE` is effective,
//! and opening other processes' `/proc/<pid>/mem` fails with `EACCES`/`EPERM`
//! for most sampled processes. The label is the observer's own; no target
//! fields are read here, so the privacy allowlist is untouched.
//!
//! [`sample`] and [`assess`] are pure over injected readers, so the confined
//! twin is a unit test; [`detect`] and [`probe_check`] do the live reads.

use std::sync::atomic::{AtomicBool, Ordering};

/// The doctor row and the report gap share one subject.
pub(crate) const CHECK_NAME: &str = "process access";
/// How many sampled processes are mem-probed at most.
pub(crate) const SAMPLE_ATTEMPTS: usize = 32;
/// How many enumerated pids are scanned for live user processes.
pub(crate) const SAMPLE_CANDIDATES: usize = 64;
/// Below this many mem probes no assessment is made: with one or two other
/// processes a denial is a per-process fact (a snap-confined app), not proof
/// the observer itself is confined.
pub(crate) const MIN_ATTEMPTED: usize = 3;

/// The one fix, shared by the doctor row, the stderr line and the gap.
pub(crate) const FIX: &str = "load deploy/apparmor-p11scope with `apparmor_parser -r deploy/apparmor-p11scope` and re-run with `--security-opt apparmor=p11scope-observer`";

/// One sampling run: how many other processes were mem-probed and how many
/// of those probes failed with `EACCES`/`EPERM`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessSample {
    pub attempted: usize,
    pub denied: usize,
}

/// A proven confinement block: the observer's own label plus the counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessBlock {
    pub label: String,
    pub denied: usize,
    pub attempted: usize,
}

/// The profile name in one attr file's text, if it names an AppArmor label:
/// the first token (`docker-default (enforce)` reads `docker-default`).
/// `None` for empty text and for non-AppArmor LSM text (an SELinux context
/// carries `:`; AppArmor profile names never do).
pub(crate) fn parse_label(text: &str) -> Option<String> {
    let token = text.split_whitespace().next()?;
    // An SELinux context (`unconfined_u:...`) is not an AppArmor label:
    // AppArmor profile names never carry `:`.
    if token.contains(':') {
        return None;
    }
    Some(token.to_string())
}

/// Whether `label` is the unconfined label.
pub(crate) fn is_unconfined(label: &str) -> bool {
    label == "unconfined"
}

/// The observer's own AppArmor label, if it has one: the AppArmor attr file
/// first, the generic LSM attr file behind it.
pub(crate) fn own_label() -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/attr/apparmor/current")
        .or_else(|_| std::fs::read_to_string("/proc/self/attr/current"))
        .ok()?;
    parse_label(&text)
}

/// Whether `CAP_SYS_PTRACE` is in the observer's current effective set (the
/// post-shed truth: every live command keeps it when it was granted).
pub(crate) fn ptrace_held() -> bool {
    crate::caps::read_effective()
        .is_some_and(|mask| mask & (1u64 << crate::caps::CAP_SYS_PTRACE_BIT) != 0)
}

/// Mem-probe other processes: for each candidate with readable maps content
/// (kernel threads, zombies and the already-exited never count), open
/// `/proc/<pid>/mem` and count the `EACCES`/`EPERM` refusals. The observer's
/// own pid never counts. Pure over the injected readers.
pub(crate) fn sample<M, R>(candidates: &[u32], has_maps: &M, open_mem: &R) -> AccessSample
where
    M: Fn(u32) -> bool,
    R: Fn(u32) -> std::io::Result<()>,
{
    let me = std::process::id();
    let mut attempted = 0usize;
    let mut denied = 0usize;
    for &pid in candidates.iter().take(SAMPLE_CANDIDATES) {
        if attempted >= SAMPLE_ATTEMPTS {
            break;
        }
        if pid == me || !has_maps(pid) {
            continue;
        }
        attempted += 1;
        match open_mem(pid) {
            Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
                denied += 1;
            }
            _ => {}
        }
    }
    AccessSample { attempted, denied }
}

/// The confinement verdict over one sample: `Some` exactly when the label is
/// a confined one, `CAP_SYS_PTRACE` is held, and most sampled processes were
/// denied. Pure.
pub(crate) fn assess(
    label: Option<&str>,
    sample: &AccessSample,
    ptrace_held: bool,
) -> Option<AccessBlock> {
    let label = label?;
    if is_unconfined(label) || !ptrace_held {
        return None;
    }
    if sample.attempted < MIN_ATTEMPTED {
        return None;
    }
    // Most means a strict majority: exactly half denied proves nothing.
    if sample.denied * 2 <= sample.attempted {
        return None;
    }
    Some(AccessBlock {
        label: label.to_string(),
        denied: sample.denied,
        attempted: sample.attempted,
    })
}

/// Whether `pid` has maps content to gate on: kernel threads read empty,
/// zombies and the already-exited fail the open, and foreign-uid processes
/// fail it for an unprivileged observer. Any of those skips the pid instead
/// of counting it.
fn live_has_maps(pid: u32) -> bool {
    use std::io::Read as _;
    let mut file = match std::fs::File::open(format!("/proc/{pid}/maps")) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut byte = [0u8; 1];
    matches!(file.read(&mut byte), Ok(1))
}

/// The live probe behind [`sample`]: opening `/proc/<pid>/mem` needs
/// ptrace-mode access, which is exactly what a confining profile denies
/// while the capabilities are held.
fn live_open_mem(pid: u32) -> std::io::Result<()> {
    std::fs::File::open(format!("/proc/{pid}/mem")).map(|_| ())
}

/// The live detection over enumerated pids: label and capability fast paths
/// first (no sampling on healthy hosts), then [`sample`] plus [`assess`].
pub(crate) fn detect(candidates: &[u32]) -> Option<AccessBlock> {
    let label = own_label();
    match label.as_deref() {
        Some(label) if !is_unconfined(label) => {}
        _ => return None,
    }
    if !ptrace_held() {
        return None;
    }
    let sample = sample(candidates, &live_has_maps, &live_open_mem);
    assess(label.as_deref(), &sample, true)
}

static WARNED: AtomicBool = AtomicBool::new(false);

/// The one plain stderr line, emitted once per process no matter how many
/// passes detect the block. Returns whether this call emitted.
pub(crate) fn warn_once(block: &AccessBlock) -> bool {
    if WARNED.swap(true, Ordering::SeqCst) {
        return false;
    }
    // Never `eprintln!`: a closed stderr must not fail the run.
    let _ = crate::sink::try_stderr_line(&crate::render::escape_controls(&stderr_line(block)));
    true
}

/// The stderr line text (pure, for tests).
pub(crate) fn stderr_line(block: &AccessBlock) -> String {
    format!(
        "p11scope: AppArmor label `{}` blocks reading other processes although CAP_SYS_PTRACE is held ({} of {} sampled processes unreadable); discovery will see almost nothing — {FIX}",
        block.label, block.denied, block.attempted
    )
}

/// The report gap text (pure): sample counts plus, when the caller already
/// scanned members, the exact unreadable-selected count.
pub(crate) fn gap_reason(block: &AccessBlock, unreadable_selected: Option<usize>) -> String {
    let mut reason = format!(
        "AppArmor label `{}` blocks reading other processes although CAP_SYS_PTRACE is held ({} of {} sampled processes unreadable",
        block.label, block.denied, block.attempted
    );
    if let Some(unreadable) = unreadable_selected.filter(|count| *count > 0) {
        reason.push_str(&format!(
            ", {unreadable} selected processes unreadable this pass"
        ));
    }
    reason.push_str(&format!("); discovery sees almost nothing — {FIX}"));
    reason
}

/// The doctor row over an assessed sample (pure): Fail names the label and
/// the fix; readable, unconfined and unassessable shapes stay Ok or n/a.
pub(crate) fn check_row(
    label: Option<&str>,
    sample: &AccessSample,
    ptrace_held: bool,
) -> crate::doctor::Check {
    use crate::doctor::{Check, Status};
    let status = match label {
        None => Status::NotApplicable("no AppArmor label (nothing to assess)".to_string()),
        Some(label) if !ptrace_held => {
            Status::NotApplicable(format!("label `{label}` needs CAP_SYS_PTRACE to assess"))
        }
        Some(label) if sample.attempted == 0 => {
            Status::NotApplicable(format!("label `{label}` has no other processes to sample"))
        }
        Some(label) => match assess(Some(label), sample, true) {
            Some(block) => Status::Fail(format!(
                "AppArmor label `{}` blocks reading other processes although CAP_SYS_PTRACE is held ({} of {} sampled processes unreadable) — {FIX}",
                block.label, block.denied, block.attempted
            )),
            None if is_unconfined(label) => Status::Ok(format!(
                "unconfined; {} of {} sampled processes readable",
                sample.attempted - sample.denied,
                sample.attempted
            )),
            None => Status::Ok(format!(
                "label `{label}`; {} of {} sampled processes readable",
                sample.attempted - sample.denied,
                sample.attempted
            )),
        },
    };
    Check {
        name: CHECK_NAME.to_string(),
        status,
    }
}

/// The live doctor probe: enumerate, sample, assess, render.
pub(crate) fn probe_check() -> crate::doctor::Check {
    let empty = AccessSample {
        attempted: 0,
        denied: 0,
    };
    let Some(label) = own_label() else {
        return check_row(None, &empty, ptrace_held());
    };
    if !ptrace_held() {
        return check_row(Some(&label), &empty, false);
    }
    let scope = crate::attach::Scope::System;
    let (pids, _) = crate::discovery::engine::scope_pids(&scope);
    let sample = sample(&pids, &live_has_maps, &live_open_mem);
    check_row(Some(&label), &sample, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Status;
    use std::io::{Error, ErrorKind};

    const LABEL: &str = "docker-default";

    fn denied_os(error: i32) -> std::io::Result<()> {
        Err(Error::from_raw_os_error(error))
    }

    #[test]
    fn label_parse_reads_the_profile_token() {
        assert_eq!(
            parse_label("docker-default (enforce)\n"),
            Some("docker-default".to_string())
        );
        assert_eq!(
            parse_label("p11scope-observer (enforce)"),
            Some("p11scope-observer".to_string())
        );
        assert_eq!(parse_label("unconfined\n"), Some("unconfined".to_string()));
    }

    #[test]
    fn label_parse_rejects_empty_and_foreign_lsm_text() {
        assert_eq!(parse_label(""), None);
        assert_eq!(parse_label("   \n"), None);
        // An SELinux context is not an AppArmor label: never assess it.
        assert_eq!(
            parse_label("unconfined_u:unconfined_r:unconfined_t:s0"),
            None
        );
    }

    #[test]
    fn unconfined_matches_only_the_unconfined_label() {
        assert!(is_unconfined("unconfined"));
        assert!(!is_unconfined("docker-default"));
        assert!(!is_unconfined("unconfined-docker"));
    }

    #[test]
    fn assess_fires_on_a_confined_majority_with_ptrace() {
        let sample = AccessSample {
            attempted: 32,
            denied: 31,
        };
        let block = assess(Some(LABEL), &sample, true).expect("must fire");
        assert_eq!(block.label, LABEL);
        assert_eq!((block.denied, block.attempted), (31, 32));
    }

    #[test]
    fn assess_stays_quiet_without_confinement_evidence() {
        let blocked = AccessSample {
            attempted: 32,
            denied: 31,
        };
        assert_eq!(assess(Some("unconfined"), &blocked, true), None);
        assert_eq!(assess(None, &blocked, true), None);
        assert_eq!(assess(Some(LABEL), &blocked, false), None);
    }

    #[test]
    fn assess_needs_most_processes_denied() {
        // Exactly half is not most.
        for (denied, attempted, fires) in [
            (17, 32, true),
            (16, 32, false),
            (3, 3, true),
            (2, 3, true),
            (1, 3, false),
            (2, 2, false),
            (1, 1, false),
            (0, 3, false),
            (31, 32, true),
        ] {
            let sample = AccessSample { attempted, denied };
            assert_eq!(
                assess(Some(LABEL), &sample, true).is_some(),
                fires,
                "{denied} of {attempted}"
            );
        }
    }

    #[test]
    fn sample_counts_only_eacces_and_eperm_denials() {
        let candidates = [101, 102, 103, 104, 105, 106];
        let has_maps = |_: u32| true;
        let open_mem = |pid: u32| match pid {
            101 => denied_os(libc::EACCES),
            102 => denied_os(libc::EPERM),
            103 => Ok(()),
            104 => Err(Error::new(ErrorKind::NotFound, "exited")),
            105 => denied_os(libc::ESRCH),
            _ => Err(Error::other("unreadable")),
        };
        let sample = sample(&candidates, &has_maps, &open_mem);
        assert_eq!(
            sample,
            AccessSample {
                attempted: 6,
                denied: 2,
            }
        );
    }

    #[test]
    fn sample_skips_self_and_mapsless_processes() {
        let me = std::process::id();
        let candidates = [me, 201, 202, 203];
        let has_maps = |pid: u32| pid != 202;
        let open_mem = |_: u32| denied_os(libc::EACCES);
        let sample = sample(&candidates, &has_maps, &open_mem);
        assert_eq!(
            sample,
            AccessSample {
                attempted: 2,
                denied: 2,
            }
        );
    }

    #[test]
    fn sample_bounds_the_probe_count() {
        let candidates: Vec<u32> = (1000..1100).collect();
        let probed = std::sync::Mutex::new(0usize);
        let has_maps = |_: u32| true;
        let open_mem = |_: u32| {
            *probed.lock().unwrap() += 1;
            Ok(())
        };
        let sample = sample(&candidates, &has_maps, &open_mem);
        assert_eq!(sample.attempted, SAMPLE_ATTEMPTS);
        assert_eq!(*probed.lock().unwrap(), SAMPLE_ATTEMPTS);
    }

    #[test]
    fn failing_row_names_the_label_counts_and_fix() {
        let sample = AccessSample {
            attempted: 32,
            denied: 31,
        };
        let check = check_row(Some(LABEL), &sample, true);
        assert_eq!(check.name, CHECK_NAME);
        let Status::Fail(detail) = check.status else {
            panic!("must fail, got {:?}", check.status);
        };
        assert!(detail.contains(LABEL), "{detail}");
        assert!(detail.contains("31 of 32"), "{detail}");
        assert!(detail.contains("CAP_SYS_PTRACE"), "{detail}");
        assert!(detail.contains("apparmor_parser -r"), "{detail}");
        assert!(
            detail.contains("--security-opt apparmor=p11scope-observer"),
            "{detail}"
        );
    }

    #[test]
    fn row_stays_ok_or_na_when_nothing_is_blocked() {
        let readable = AccessSample {
            attempted: 32,
            denied: 0,
        };
        let ok = check_row(Some(LABEL), &readable, true);
        assert!(matches!(ok.status, Status::Ok(_)), "{ok:?}");
        let ok = check_row(Some("unconfined"), &readable, true);
        assert!(matches!(ok.status, Status::Ok(_)), "{ok:?}");
        let blocked = AccessSample {
            attempted: 32,
            denied: 31,
        };
        let na = check_row(Some(LABEL), &blocked, false);
        assert!(matches!(na.status, Status::NotApplicable(_)), "{na:?}");
        let na = check_row(None, &blocked, true);
        assert!(matches!(na.status, Status::NotApplicable(_)), "{na:?}");
        let na = check_row(
            Some(LABEL),
            &AccessSample {
                attempted: 0,
                denied: 0,
            },
            true,
        );
        assert!(matches!(na.status, Status::NotApplicable(_)), "{na:?}");
    }

    #[test]
    fn gap_and_stderr_carry_label_counts_and_fix() {
        let block = AccessBlock {
            label: LABEL.to_string(),
            denied: 31,
            attempted: 32,
        };
        for text in [
            stderr_line(&block),
            gap_reason(&block, None),
            gap_reason(&block, Some(164)),
        ] {
            assert!(text.contains(LABEL), "{text}");
            assert!(text.contains("31 of 32"), "{text}");
            assert!(
                text.contains("--security-opt apparmor=p11scope-observer"),
                "{text}"
            );
            // Generic hint: no distribution names.
            for distro in ["Ubuntu", "Debian", "Fedora"] {
                assert!(!text.contains(distro), "{text}");
            }
        }
        assert!(
            gap_reason(&block, Some(164)).contains("164"),
            "exact member count"
        );
        assert!(stderr_line(&block).starts_with("p11scope: "));
    }
}
