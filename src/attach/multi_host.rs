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
}

impl std::fmt::Display for MultiHostRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stage = match self.stage {
            MultiHostStage::Anchor => "self-probe anchor",
            MultiHostStage::ProgramLoad => "scratch program load",
            MultiHostStage::SelfLink => "scratch self-link",
        };
        let cause = match self.cause {
            MultiHostCause::Unavailable => "Multi capability unavailable",
            MultiHostCause::Denied => "Multi probe denied by permission or policy",
            MultiHostCause::Unproven => "Multi capability unproven",
        };
        write!(out, "uprobe-multi-required: {cause} at {stage}")?;
        if let Some(errno) = self.errno {
            write!(
                out,
                " (errno {errno}: {})",
                io::Error::from_raw_os_error(errno)
            )?;
        }
        if self.cause == MultiHostCause::Denied {
            let operation = match self.stage {
                MultiHostStage::Anchor => "prepare p11scope's self-probe anchor",
                MultiHostStage::ProgramLoad => "load p11scope's BPF programs",
                MultiHostStage::SelfLink => "attach p11scope's required Multi probe",
            };
            write!(
                out,
                "; cannot {operation}; live capture requires root or appropriate capabilities \
                 and a permitting host policy (for example, sudo)"
            )?;
        }
        write!(
            out,
            "; run `p11scope doctor` for host readiness or \
             `p11scope doctor --pid <n>` for target readiness; \
             `p11scope inspect --pid <n>` lists readable mapped providers without live capture"
        )
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
            assert!(text.starts_with("uprobe-multi-required:"));
            assert!(!text.contains("upgrade") && !text.contains("6.6") && !text.contains("/"));
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
    fn denied_guidance_names_the_failed_stage_and_offline_next_steps() {
        for (stage, errno) in [
            (MultiHostStage::ProgramLoad, libc::EPERM),
            (MultiHostStage::SelfLink, libc::EPERM),
            (MultiHostStage::SelfLink, libc::EACCES),
        ] {
            let refusal = MultiHostRefusal::at(stage, Some(errno));
            assert_eq!(refusal.cause, MultiHostCause::Denied);
            let text = refusal.to_string();
            assert!(text.starts_with("uprobe-multi-required: "), "{text}");
            assert!(text.contains("requires root"), "{text}");
            assert!(text.contains("appropriate capabilities"), "{text}");
            assert!(text.contains("policy") && text.contains("sudo"), "{text}");
            assert!(
                text.contains("`p11scope doctor` for host readiness"),
                "{text}"
            );
            assert!(text.contains("p11scope doctor --pid <n>"), "{text}");
            assert!(text.contains("p11scope inspect --pid <n>"), "{text}");
            assert!(text.contains("without live capture"), "{text}");
            assert_eq!(
                text.contains("cannot load p11scope's BPF programs"),
                stage == MultiHostStage::ProgramLoad,
                "{text}"
            );
            assert_eq!(
                text.contains("cannot attach p11scope's required Multi probe"),
                stage == MultiHostStage::SelfLink,
                "{text}"
            );
            assert!(!text.contains("--allow-uretprobe-on-confined-target"));
            assert!(!text.contains("seccomp") && !text.contains("trampoline"));
            assert_eq!(text.lines().count(), 1);
            assert!(text.len() < 1_024, "{text}");
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
            assert!(text.starts_with("uprobe-multi-required: "), "{text}");
            assert!(
                text.contains("`p11scope doctor` for host readiness"),
                "{text}"
            );
            assert!(text.contains("p11scope doctor --pid <n>"), "{text}");
            assert!(text.contains("p11scope inspect --pid <n>"), "{text}");
            assert!(text.contains("without live capture"), "{text}");
            for unsupported_claim in [
                "requires root",
                "sudo",
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
