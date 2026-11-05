//! SPDX-License-Identifier: GPL-3.0-or-later
//! Use the observer's required Multi probe, not the aggregate doctor verdict.

use p11scope::doctor::{Check, Status};

pub fn refusal() -> Option<String> {
    refusal_from_checks(&p11scope::doctor::probe(None, None))
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
            if reason.starts_with("live capture needs root: ")
                || reason.starts_with("live capture unavailable: ")
                || reason.starts_with("live capture did not start: ") =>
        {
            Some(reason.clone())
        }
        status => panic!("unexpected required Multi probe status: {status:?}"),
    }
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
            "live capture needs root: the kernel refused to load p11scope's BPF programs (Operation not permitted). Run with sudo, or use 'p11scope inspect --pid N' for a scan without capture.",
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
