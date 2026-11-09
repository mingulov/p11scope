//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Use the observer's required Multi probe, not the aggregate doctor verdict.

use p11scope::doctor::{Check, Status};

/// The refusal as the observer binary prints it: the recipe names that
/// binary. Compare a spawned `p11scope`'s stderr with this.
#[allow(dead_code)]
pub fn refusal() -> Option<String> {
    in_process_refusal().map(|reason| {
        let probe = std::env::current_exe().expect("test executable path");
        as_observer(
            &reason,
            &probe.display().to_string(),
            env!("CARGO_BIN_EXE_p11scope"),
        )
    })
}

/// The refusal as this test process meets it: a capture run in process
/// (through the library, not the binary) names this test executable in
/// its recipe. Compare an in-process capture error with this.
#[allow(dead_code)]
pub fn in_process_refusal() -> Option<String> {
    refusal_from_checks(&p11scope::doctor::probe(None, None))
}

/// The in-process probe's setcap recipe names its own executable (this
/// test binary); the observer names itself. Every other byte is shared,
/// so retarget exactly the recipe's path and nothing else.
fn as_observer(reason: &str, probe: &str, observer: &str) -> String {
    let from = format!("=ep' {probe}, or use ");
    if reason.matches(&from).count() == 1 {
        reason.replacen(&from, &format!("=ep' {observer}, or use "), 1)
    } else {
        reason.to_string()
    }
}

fn refusal_from_checks(checks: &[Check]) -> Option<String> {
    let mut required = checks
        .iter()
        .filter(|check| check.name == "uprobe-multi attach (own libc)");
    let check = required
        .next()
        .expect("doctor omitted required Multi probe");
    assert!(required.next().is_none(), "duplicate required Multi probe");
    match &check.status {
        Status::Ok(_) => None,
        Status::Fail(reason)
            if is_denied(reason)
                || reason.starts_with("live capture unavailable: ")
                || reason.starts_with("live capture did not start: ") =>
        {
            Some(reason.clone())
        }
        status => panic!("unexpected required Multi probe status: {status:?}"),
    }
}

/// The permission refusal: it names the missing load capabilities and
/// the setcap recipe (`live capture needs CAP_…`), or, with the load set
/// (or `CAP_SYS_ADMIN`) held, blames other enforcement
/// (`live capture refused: …`).
pub fn is_denied(reason: &str) -> bool {
    reason.starts_with("live capture needs CAP_") || reason.starts_with("live capture refused: ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required(status: Status) -> Check {
        Check {
            name: "uprobe-multi attach (own libc)".into(),
            status,
        }
    }

    #[test]
    fn eligible_multi_probe_is_independent_of_other_doctor_failures() {
        let checks = [
            Check {
                name: "unrelated required capability".into(),
                status: Status::Fail("unavailable".into()),
            },
            required(Status::Ok("self-link proven; delivery unmeasured".into())),
        ];
        assert_eq!(refusal_from_checks(&checks), None);
    }

    #[test]
    fn ineligible_multi_probe_retains_the_exact_named_reason() {
        for reason in [
            "live capture needs CAP_BPF (load BPF programs and attach probes); needs CAP_PERFMON (load BPF programs alongside CAP_BPF): the kernel refused to load p11scope's BPF programs (Operation not permitted). Grant the minimal set: sudo setcap 'cap_bpf,cap_checkpoint_restore,cap_dac_read_search,cap_perfmon,cap_sys_ptrace=ep' /usr/bin/p11scope, or use 'p11scope inspect --pid N' for a scan without capture.",
            "live capture refused: the kernel refused to load p11scope's BPF programs (Operation not permitted) with CAP_BPF and CAP_PERFMON held — a kernel lockdown, an LSM policy, or a container's seccomp profile is refusing BPF here. Run 'p11scope doctor' for host readiness, or use 'p11scope inspect --pid N' for a scan without capture.",
            "live capture unavailable: loading p11scope's BPF programs is not supported on this host; run 'p11scope doctor' for host readiness, or use 'p11scope inspect --pid N' for a scan without capture.",
            "live capture did not start: loading p11scope's BPF programs failed; run 'p11scope doctor' for host readiness, or use 'p11scope inspect --pid N' for a scan without capture.",
        ] {
            assert_eq!(
                refusal_from_checks(&[required(Status::Fail(reason.into()))]),
                Some(reason.into())
            );
        }
    }

    #[test]
    fn the_recipe_path_is_retargeted_to_the_observer_only() {
        let reason = "live capture needs CAP_BPF (load BPF programs and attach probes): the \
                      kernel refused to load p11scope's BPF programs (Operation not permitted). \
                      Grant the minimal set: sudo setcap 'cap_bpf=ep' /t/deps/ux-1, or use \
                      'p11scope inspect --pid N' for a scan without capture.";
        let observer = as_observer(reason, "/t/deps/ux-1", "/t/p11scope");
        assert_eq!(
            observer,
            reason.replace("'cap_bpf=ep' /t/deps/ux-1,", "'cap_bpf=ep' /t/p11scope,")
        );
        assert!(!observer.contains("/t/deps/ux-1"), "{observer}");
        // A reason without the recipe is returned unchanged.
        let other = "live capture unavailable: not supported on this host /t/deps/ux-1";
        assert_eq!(as_observer(other, "/t/deps/ux-1", "/t/p11scope"), other);
    }

    #[test]
    fn unknown_missing_or_duplicate_multi_results_are_failures() {
        for checks in [
            vec![],
            vec![Check {
                name: "uprobe attach (self)".into(),
                status: Status::Ok("available".into()),
            }],
            vec![required(Status::Warn("unproven".into()))],
            vec![required(Status::NotApplicable("unavailable".into()))],
            vec![required(Status::Fail("unrelated failure".into()))],
            vec![required(Status::Fail(
                "live capture needs root: the old root-only wording".into(),
            ))],
            vec![
                required(Status::Ok("available".into())),
                required(Status::Ok("available".into())),
            ],
        ] {
            assert!(
                std::panic::catch_unwind(|| refusal_from_checks(&checks)).is_err(),
                "accepted unknown Multi result: {checks:?}"
            );
        }
    }
}
