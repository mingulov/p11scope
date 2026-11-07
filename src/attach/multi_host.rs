//! SPDX-License-Identifier: GPL-3.0-or-later
//! Invocation-local admission for live capture, independent of its backend.

use std::io;
use std::os::fd::AsRawFd as _;
use std::sync::Mutex;

/// Only a successful scratch program load and self-link mint this fact.
/// It proves neither probe delivery nor any target-specific capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MultiCapableHost(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MultiHostStage {
    Anchor,
    ProgramLoad,
    SelfLink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MultiHostCause {
    Unavailable,
    Denied,
    Unproven,
}

/// Keep syscall evidence typed until the public pathless explanation is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MultiHostRefusal {
    pub(crate) stage: MultiHostStage,
    pub(crate) errno: Option<i32>,
    pub(crate) cause: MultiHostCause,
}

pub(crate) type MultiHostVerdict = Result<MultiCapableHost, MultiHostRefusal>;

impl MultiHostRefusal {
    fn at(stage: MultiHostStage, errno: Option<i32>) -> Self {
        let cause = match (stage, errno) {
            (MultiHostStage::Anchor, _) => MultiHostCause::Unproven,
            (_, Some(libc::ENOSYS | libc::EOPNOTSUPP)) => MultiHostCause::Unavailable,
            (_, Some(libc::EPERM)) | (MultiHostStage::SelfLink, Some(libc::EACCES)) => {
                MultiHostCause::Denied
            }
            // Program-load EACCES can be a verifier rejection, and EINVAL
            // does not identify kernel age at either operation.
            _ => MultiHostCause::Unproven,
        };
        Self {
            stage,
            errno,
            cause,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(stage: MultiHostStage, errno: Option<i32>) -> Self {
        Self::at(stage, errno)
    }

    /// Whether sudo can help this refusal: only a `Denied` cause
    /// (permission/policy) is privilege-shaped. An old kernel or a
    /// verifier-shaped refusal must never carry sudo advice.
    pub(crate) fn needs_privilege_hint(&self) -> bool {
        self.cause == MultiHostCause::Denied
    }

    /// Whether the probe shape proves the kernel itself lacks Multi: the
    /// scratch self-link refusal observed on 6.1, an explicit unsupported
    /// answer at load or link time, or a load refusal for the unknown
    /// attach type. Every other shape (permission or policy at any stage,
    /// a resource error, ENOSYS, an anchor failure) may come from a
    /// capable but confined host, so doctor still test-loads the capture
    /// objects there: they fail fast and keep their guidance.
    pub(crate) fn is_premulti_kernel(&self) -> bool {
        matches!(
            (self.stage, self.errno),
            (MultiHostStage::SelfLink, Some(libc::EINVAL))
                | (MultiHostStage::ProgramLoad, Some(libc::EINVAL))
                | (
                    MultiHostStage::ProgramLoad | MultiHostStage::SelfLink,
                    Some(libc::EOPNOTSUPP)
                )
        )
    }
}

/// The errno's short name ("Operation not permitted") for one-line
/// operator text: [`io::Error`]'s own rendering carries a redundant
/// " (os error N)" suffix, which is dropped when it is there.
fn errno_name(errno: i32) -> String {
    let full = io::Error::from_raw_os_error(errno).to_string();
    full.strip_suffix(&format!(" (os error {errno})"))
        .unwrap_or(&full)
        .to_string()
}

/// The `Denied` refusal over explicit privilege facts: names each
/// missing load capability with what it enables, plus the one-line
/// recipe; when the load set is complete the refusal is other
/// enforcement (lockdown, LSM, seccomp), never more privilege.
pub(crate) fn denied_line(operation: &str, reason: &str, effective: u64, binary: &str) -> String {
    let missing = crate::caps::missing_in(effective, &crate::caps::LOAD_BITS);
    if missing.is_empty() {
        format!(
            "live capture refused: the kernel refused to {operation}{reason} with CAP_BPF and \
             CAP_PERFMON held — a kernel lockdown, an LSM policy, or a container's seccomp \
             profile is refusing BPF here. Run 'p11scope doctor' for host readiness, or use \
             'p11scope inspect --pid N' for a scan without capture."
        )
    } else {
        let needs: Vec<String> = missing
            .iter()
            .map(|cap| crate::caps::needs_line(cap))
            .collect();
        format!(
            "live capture {}: the kernel refused to {operation}{reason}. Grant the minimal \
             set: {}, or use 'p11scope inspect --pid N' for a scan without capture.",
            needs.join("; "),
            crate::caps::setcap_command(binary)
        )
    }
}

impl std::fmt::Display for MultiHostRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // One plain line, no internal codes: the default text an operator
        // reads when live capture cannot start.
        let operation = match self.stage {
            MultiHostStage::Anchor => "prepare p11scope's self-probe",
            MultiHostStage::ProgramLoad => "load p11scope's BPF programs",
            MultiHostStage::SelfLink => "attach p11scope's probes",
        };
        let doing = match self.stage {
            MultiHostStage::Anchor => "preparing p11scope's self-probe",
            MultiHostStage::ProgramLoad => "loading p11scope's BPF programs",
            MultiHostStage::SelfLink => "attaching p11scope's probes",
        };
        let reason = self.errno.map(errno_name).unwrap_or_default();
        let reason = if reason.is_empty() {
            String::new()
        } else {
            format!(" ({reason})")
        };
        match self.cause {
            MultiHostCause::Denied => {
                let effective = crate::caps::read_effective().unwrap_or(0);
                write!(
                    out,
                    "{}",
                    denied_line(
                        operation,
                        &reason,
                        effective,
                        &crate::caps::current_binary()
                    )
                )
            }
            MultiHostCause::Unavailable => {
                write!(
                    out,
                    "live capture unavailable: {doing} is not supported on this host{reason}; \
                     run 'p11scope doctor' for host readiness, or use 'p11scope inspect --pid N' \
                     for a scan without capture."
                )
            }
            MultiHostCause::Unproven => {
                write!(
                    out,
                    "live capture did not start: {doing} failed{reason}; run 'p11scope doctor' \
                     for host readiness, or use 'p11scope inspect --pid N' for a scan \
                     without capture."
                )
            }
        }
    }
}

impl std::error::Error for MultiHostRefusal {}

impl MultiCapableHost {
    /// A case-local synthetic fact for tests of a downstream, separate gate.
    /// This does not set or bypass the production invocation cache.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self(())
    }
}

/// A capture invocation does not change credentials. Reuse only its actual
/// successful fact, including across selected-preparation worker threads.
/// Failed probes never become a cached positive or a scoped fallback.
struct InvocationAdmission(Mutex<Option<MultiCapableHost>>);

impl InvocationAdmission {
    const fn new() -> Self {
        Self(Mutex::new(None))
    }

    fn require(&self, probe: impl FnOnce() -> MultiHostVerdict) -> MultiHostVerdict {
        let mut admitted = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        if let Some(fact) = *admitted {
            return Ok(fact);
        }
        let fact = probe()?;
        *admitted = Some(fact);
        Ok(fact)
    }
}

pub(crate) fn require_multi_capable_host() -> MultiHostVerdict {
    static INVOCATION: InvocationAdmission = InvocationAdmission::new();
    INVOCATION.require(|| {
        probe_with(
            crate::doctor::self_probe_anchor,
            p11scope_bpf_multi::prog_load_scratch_multi,
            |program, (path, offset)| {
                p11scope_bpf_multi::attach_group(
                    program.as_raw_fd(),
                    std::process::id(),
                    path,
                    &[*offset],
                    &[1],
                    false,
                )
                .map(drop)
            },
        )
    })
}

fn probe_with<A, P>(
    anchor: impl FnOnce() -> anyhow::Result<A>,
    load: impl FnOnce() -> io::Result<P>,
    link: impl FnOnce(&P, &A) -> io::Result<()>,
) -> MultiHostVerdict {
    let anchor = anchor().map_err(|error| {
        let errno = error.chain().find_map(|cause| {
            cause
                .downcast_ref::<io::Error>()
                .and_then(io::Error::raw_os_error)
        });
        MultiHostRefusal::at(MultiHostStage::Anchor, errno)
    })?;
    let program = load()
        .map_err(|error| MultiHostRefusal::at(MultiHostStage::ProgramLoad, error.raw_os_error()))?;
    link(&program, &anchor)
        .map_err(|error| MultiHostRefusal::at(MultiHostStage::SelfLink, error.raw_os_error()))?;
    Ok(MultiCapableHost(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn typed_probe_preserves_stage_errno_without_guessing_kernel_age() {
        for (stage, errno, cause) in [
            (
                MultiHostStage::ProgramLoad,
                libc::EACCES,
                MultiHostCause::Unproven,
            ),
            (
                MultiHostStage::ProgramLoad,
                libc::EPERM,
                MultiHostCause::Denied,
            ),
            (
                MultiHostStage::SelfLink,
                libc::EACCES,
                MultiHostCause::Denied,
            ),
            (
                MultiHostStage::SelfLink,
                libc::EOPNOTSUPP,
                MultiHostCause::Unavailable,
            ),
            (
                MultiHostStage::ProgramLoad,
                libc::ENOSYS,
                MultiHostCause::Unavailable,
            ),
            (
                MultiHostStage::SelfLink,
                libc::EINVAL,
                MultiHostCause::Unproven,
            ),
            (
                MultiHostStage::ProgramLoad,
                libc::EINVAL,
                MultiHostCause::Unproven,
            ),
            (
                MultiHostStage::SelfLink,
                libc::EMFILE,
                MultiHostCause::Unproven,
            ),
        ] {
            let result = probe_with(
                || Ok(()),
                || {
                    if stage == MultiHostStage::ProgramLoad {
                        Err(io::Error::from_raw_os_error(errno))
                    } else {
                        Ok(())
                    }
                },
                |_, _| {
                    if stage == MultiHostStage::SelfLink {
                        Err(io::Error::from_raw_os_error(errno))
                    } else {
                        Ok(())
                    }
                },
            );
            let error = result.unwrap_err();
            assert_eq!(
                (error.stage, error.errno, error.cause),
                (stage, Some(errno), cause)
            );
            let text = error.to_string();
            // The denied wording depends on the test runner's own
            // capabilities (missing set vs complete set): both read
            // below, and the exact bytes are pinned on `denied_line`.
            if cause == MultiHostCause::Denied {
                assert!(
                    text.starts_with("live capture needs ")
                        || text.starts_with("live capture refused: "),
                    "{text}"
                );
            } else {
                assert!(
                    text.starts_with("live capture unavailable: ")
                        || text.starts_with("live capture did not start: "),
                    "{text}"
                );
                assert!(!text.contains("/"), "{text}");
            }
            assert!(!text.contains("uprobe-multi-required"), "{text}");
            assert!(!text.contains("upgrade") && !text.contains("6.6"));
            assert_eq!(text.lines().count(), 1);
            assert!(text.len() < 1_024, "{text}");
        }
        let error = probe_with(
            || Err::<(), _>(anyhow::anyhow!("anchor unavailable")),
            || Ok(()),
            |_, _| Ok(()),
        )
        .unwrap_err();
        assert_eq!(
            (error.stage, error.errno, error.cause),
            (MultiHostStage::Anchor, None, MultiHostCause::Unproven)
        );
    }

    #[test]
    fn anchor_errno_survives_context_without_publishing_private_paths() {
        for errno in [libc::EACCES, libc::EPERM, libc::EOPNOTSUPP] {
            let source = anyhow::Error::new(io::Error::from_raw_os_error(errno))
                .context("opening private /observer/anchor.so");
            let error = probe_with(
                || Err::<(), _>(source),
                || -> io::Result<()> { panic!("load without a self-probe anchor") },
                |_, _| panic!("link without a self-probe anchor"),
            )
            .unwrap_err();
            assert_eq!(
                (error.stage, error.errno, error.cause),
                (
                    MultiHostStage::Anchor,
                    Some(errno),
                    MultiHostCause::Unproven
                )
            );
            assert!(
                !error.to_string().contains("/observer")
                    && !error.to_string().contains("anchor.so")
            );
        }
    }

    #[test]
    fn denied_refusal_is_one_plain_line_naming_caps_and_the_scan_fallback() {
        // The deprived first-run refusal, byte for byte over explicit
        // privilege facts (the `Display` reads the runner's own mask).
        assert_eq!(
            super::denied_line(
                "load p11scope's BPF programs",
                " (Operation not permitted)",
                0,
                "/usr/bin/p11scope",
            ),
            "live capture needs CAP_BPF (load BPF programs and attach probes); needs CAP_PERFMON \
             (load BPF programs alongside CAP_BPF): the kernel refused to load p11scope's BPF programs \
             (Operation not permitted). Grant the minimal set: sudo setcap \
             'cap_bpf,cap_checkpoint_restore,cap_dac_read_search,cap_perfmon,cap_sys_ptrace=ep' \
             /usr/bin/p11scope, or use 'p11scope inspect --pid N' for a scan without capture."
        );
        for (stage, errno, operation) in [
            (
                MultiHostStage::ProgramLoad,
                libc::EPERM,
                "load p11scope's BPF programs",
            ),
            (
                MultiHostStage::SelfLink,
                libc::EPERM,
                "attach p11scope's probes",
            ),
            (
                MultiHostStage::SelfLink,
                libc::EACCES,
                "attach p11scope's probes",
            ),
        ] {
            let refusal = MultiHostRefusal::at(stage, Some(errno));
            assert_eq!(refusal.cause, MultiHostCause::Denied);
            let text = refusal.to_string();
            assert!(
                text.starts_with("live capture needs ")
                    || text.starts_with("live capture refused: "),
                "{text}"
            );
            assert!(text.contains(operation), "{text}");
            assert!(text.contains("p11scope inspect --pid N"), "{text}");
            assert!(text.contains("for a scan without capture"), "{text}");
            assert!(!text.contains("uprobe-multi-required"), "{text}");
            assert!(!text.contains("--allow-uretprobe-on-confined-target"));
            assert!(!text.contains("seccomp") && !text.contains("trampoline"));
            assert_eq!(text.lines().count(), 1);
            assert!(text.len() < 1_024, "{text}");
        }
    }

    /// Per-capability twins for the denied refusal: each missing load
    /// capability gives its exact `needs` clause plus the one-line
    /// recipe, never "needs root"; a complete load set reads as other
    /// enforcement, never more privilege.
    #[test]
    fn denied_line_names_the_missing_load_cap_and_the_recipe() {
        use crate::caps;
        let full = caps::minimal_live_mask();
        let binary = "/usr/bin/p11scope";
        let recipe = caps::setcap_command(binary);
        for (bit, needs) in [
            (
                caps::CAP_BPF_BIT,
                "needs CAP_BPF (load BPF programs and attach probes)",
            ),
            (
                caps::CAP_PERFMON_BIT,
                "needs CAP_PERFMON (load BPF programs alongside CAP_BPF)",
            ),
        ] {
            let line = super::denied_line(
                "load p11scope's BPF programs",
                " (Operation not permitted)",
                full & !(1u64 << bit),
                binary,
            );
            assert!(line.contains(needs), "{line}");
            assert!(line.contains(&recipe), "{line}");
            assert!(
                line.contains("the kernel refused to load p11scope's BPF programs"),
                "{line}"
            );
            assert!(!line.contains("needs root"), "{line}");
            assert!(!line.contains("Run with sudo"), "{line}");
            assert!(line.contains("p11scope inspect --pid N"), "{line}");
            assert_eq!(line.lines().count(), 1);
            assert!(line.len() < 1_024, "{line}");
        }
        // The load set complete: other enforcement, never privilege.
        let line = super::denied_line(
            "attach p11scope's probes",
            " (Operation not permitted)",
            u64::MAX,
            binary,
        );
        assert!(
            line.contains("the kernel refused to attach p11scope's probes"),
            "{line}"
        );
        assert!(line.contains("lockdown"), "{line}");
        assert!(!line.contains("needs CAP_"), "{line}");
        assert!(!line.contains("needs root"), "{line}");
        assert_eq!(line.lines().count(), 1);
        assert!(line.len() < 1_024, "{line}");
    }

    /// `CAP_SYS_ADMIN` suffices for BPF load, so its holder is never
    /// told to grant more privilege: a DaemonSet-like mask (SYS_ADMIN
    /// without BPF/PERFMON) reads as other enforcement, like the
    /// complete set.
    #[test]
    fn denied_line_with_sys_admin_blames_lockdown_not_privilege() {
        use crate::caps;
        let binary = "/usr/bin/p11scope";
        let sys_admin = 1u64 << caps::CAP_SYS_ADMIN_BIT;
        for effective in [
            sys_admin,
            sys_admin | (1u64 << caps::CAP_BPF_BIT),
            sys_admin | (1u64 << caps::CAP_PERFMON_BIT),
        ] {
            let line = super::denied_line(
                "load p11scope's BPF programs",
                " (Operation not permitted)",
                effective,
                binary,
            );
            assert!(
                line.contains("the kernel refused to load p11scope's BPF programs"),
                "{line}"
            );
            assert!(line.contains("lockdown"), "{line}");
            assert!(line.contains("CAP_SYS_ADMIN"), "{line}");
            assert!(!line.contains("needs CAP_"), "{line}");
            assert!(!line.contains("needs root"), "{line}");
            assert!(!line.contains("Grant the minimal set"), "{line}");
            assert!(line.contains("p11scope inspect --pid N"), "{line}");
            assert_eq!(line.lines().count(), 1);
            assert!(line.len() < 1_024, "{line}");
        }
    }

    #[test]
    fn unproven_or_unavailable_guidance_does_not_guess_privilege_or_kernel_age() {
        for (stage, errno) in [
            (MultiHostStage::Anchor, None),
            (MultiHostStage::Anchor, Some(libc::EPERM)),
            (MultiHostStage::ProgramLoad, Some(libc::ENOSYS)),
            (MultiHostStage::ProgramLoad, Some(libc::EOPNOTSUPP)),
            (MultiHostStage::ProgramLoad, Some(libc::EACCES)),
            (MultiHostStage::ProgramLoad, Some(libc::EINVAL)),
            (MultiHostStage::SelfLink, Some(libc::EOPNOTSUPP)),
            (MultiHostStage::SelfLink, Some(libc::EINVAL)),
            (MultiHostStage::SelfLink, Some(libc::EMFILE)),
        ] {
            let refusal = MultiHostRefusal::at(stage, errno);
            assert_ne!(refusal.cause, MultiHostCause::Denied);
            let text = refusal.to_string();
            assert!(
                text.starts_with("live capture unavailable: ")
                    || text.starts_with("live capture did not start: "),
                "{text}"
            );
            assert!(
                text.contains("'p11scope doctor' for host readiness"),
                "{text}"
            );
            assert!(text.contains("p11scope inspect --pid N"), "{text}");
            assert!(text.contains("for a scan without capture"), "{text}");
            for unsupported_claim in [
                "needs root",
                "requires root",
                "sudo",
                "uprobe-multi-required",
                "cannot load p11scope's BPF programs",
                "upgrade",
                "6.6",
                "unsupported kernel",
                "--allow-uretprobe-on-confined-target",
            ] {
                assert!(!text.contains(unsupported_claim), "{text}");
            }
            assert_eq!(text.lines().count(), 1);
            assert!(text.len() < 1_024, "{text}");
        }
    }

    #[test]
    fn premulti_predicate_covers_only_shapes_where_the_kernel_lacks_multi() {
        for (stage, errno, premulti) in [
            // Known pre-Multi shapes: the observed 6.1 scratch-link
            // refusal, the unknown attach type refused at load, and an
            // explicit unsupported answer at load or link time.
            (MultiHostStage::SelfLink, Some(libc::EINVAL), true),
            (MultiHostStage::ProgramLoad, Some(libc::EINVAL), true),
            (MultiHostStage::ProgramLoad, Some(libc::EOPNOTSUPP), true),
            (MultiHostStage::SelfLink, Some(libc::EOPNOTSUPP), true),
            // Permission or policy at any stage: a capable but
            // unprivileged host.
            (MultiHostStage::Anchor, Some(libc::EPERM), false),
            (MultiHostStage::Anchor, Some(libc::EACCES), false),
            (MultiHostStage::ProgramLoad, Some(libc::EPERM), false),
            (MultiHostStage::ProgramLoad, Some(libc::EACCES), false),
            (MultiHostStage::SelfLink, Some(libc::EPERM), false),
            (MultiHostStage::SelfLink, Some(libc::EACCES), false),
            // Resource errors: a capable but exhausted host.
            (MultiHostStage::ProgramLoad, Some(libc::EMFILE), false),
            (MultiHostStage::ProgramLoad, Some(libc::ENOMEM), false),
            (MultiHostStage::SelfLink, Some(libc::EMFILE), false),
            (MultiHostStage::SelfLink, Some(libc::ENOMEM), false),
            // ENOSYS may be a seccomp mask on a capable host.
            (MultiHostStage::ProgramLoad, Some(libc::ENOSYS), false),
            (MultiHostStage::SelfLink, Some(libc::ENOSYS), false),
            // An anchor failure never shows the kernel lacks Multi.
            (MultiHostStage::Anchor, None, false),
            (MultiHostStage::Anchor, Some(libc::EOPNOTSUPP), false),
            // Any other errno stays unproven and keeps its loads.
            (MultiHostStage::ProgramLoad, Some(libc::E2BIG), false),
            (MultiHostStage::SelfLink, Some(libc::EFAULT), false),
        ] {
            let refusal = MultiHostRefusal::at(stage, errno);
            assert_eq!(refusal.is_premulti_kernel(), premulti, "{refusal}");
        }
    }

    #[test]
    fn invocation_reuses_only_a_successful_actual_probe() {
        let invocation = InvocationAdmission::new();
        let calls = Cell::new(0);
        assert!(
            invocation
                .require(|| {
                    calls.set(calls.get() + 1);
                    Err(MultiHostRefusal::at(
                        MultiHostStage::SelfLink,
                        Some(libc::EINVAL),
                    ))
                })
                .is_err()
        );
        let first = invocation
            .require(|| {
                calls.set(calls.get() + 1);
                probe_with(|| Ok(()), || Ok(()), |_, _| Ok(()))
            })
            .unwrap();
        let again = invocation
            .require(|| panic!("successful admission must be reused"))
            .unwrap();
        assert_eq!(first, again);
        assert_eq!(calls.get(), 2);
    }
}
