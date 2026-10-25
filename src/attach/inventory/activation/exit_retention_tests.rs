//! SPDX-License-Identifier: GPL-3.0-or-later
//! Host retirement owners only: no fabricated Ebpf, maps, or native receipt.

use super::*;
use crate::attach::cleanup_worker::concurrency_tests::CloseGate;
use std::os::fd::{AsRawFd as _, RawFd};
use std::sync::Weak;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(in crate::attach::inventory) struct HostExitOwner {
    pub(in crate::attach::inventory) retiring: RetiringInventory,
    pub(in crate::attach::inventory) gate: Arc<CloseGate>,
    pub(in crate::attach::inventory) pin: Weak<std::fs::File>,
    pub(in crate::attach::inventory) raw_fd: RawFd,
    pub(in crate::attach::inventory) calls: Arc<AtomicUsize>,
    pub(in crate::attach::inventory) counts: (usize, usize, usize),
}

impl RetiringInventory {
    /// Construct the real retirement job/work over a harmless owned fd.
    /// The state is absent because a native Ebpf capture cannot be built
    /// unprivileged. CaptureBook/root custody is added by the facade fixture.
    pub(in crate::attach::inventory) fn host_exit_owner(mode: &str) -> HostExitOwner {
        let file = Arc::new(tempfile::tempfile().unwrap());
        let pin = Arc::downgrade(&file);
        let fd = std::fs::File::open("/dev/null").unwrap();
        let raw_fd = fd.as_raw_fd();
        let work = RetirementWork::new(
            retirement_links([(
                InventoryLinkIdentity::Entry(575),
                vec![InventoryFd::Multi(fd.into())],
            )]),
            vec![file],
        );
        let gate = Arc::new(CloseGate::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut retiring = RetiringInventory {
            state: None,
            job: None,
            unstarted: None,
            empty_worker: None,
            cleanup: None,
            control_error: None,
        };
        let counts = match mode {
            "pending" => {
                let closer_gate = Arc::clone(&gate);
                let closer_pin = pin.clone();
                let observed = Arc::clone(&calls);
                retiring.job = Some(
                    RetirementJob::start(work, move |fds| {
                        observed.fetch_add(1, Ordering::SeqCst);
                        if closer_pin.upgrade().is_none() {
                            closer_gate.missing_pin();
                        }
                        closer_gate.before_close(0);
                        close_inventory_fds(fds)?;
                        if closer_pin.upgrade().is_none() {
                            closer_gate.missing_pin();
                        }
                        closer_gate.after_close(0);
                        Ok(())
                    })
                    .unwrap_or_else(|failure| panic!("host worker: {}", failure.error)),
                );
                (0, 0, 0)
            }
            "unstarted" => {
                let failure = RetirementJob::start_with(
                    work,
                    |_| panic!("refused worker cannot close"),
                    |_| Err(std::io::Error::other("owned startup refusal")),
                )
                .err()
                .expect("injected startup refused");
                retiring.unstarted = Some(failure.work);
                retiring.empty_worker = failure.empty_worker;
                retiring.control_error = Some(failure.error.to_string());
                (0, 0, 0)
            }
            "handoff" => {
                let empty_gate = Arc::clone(&gate);
                let failure = RetirementJob::start_with(
                    work,
                    |_| panic!("failed initial handoff cannot close"),
                    move |task| {
                        drop(task); // Close the actual receiver before send.
                        std::thread::Builder::new().spawn(move || {
                            empty_gate.before_close(9);
                            empty_gate.after_close(9);
                            None
                        })
                    },
                )
                .err()
                .expect("closed receiver returned the original owned work");
                retiring.unstarted = Some(failure.work);
                retiring.empty_worker = failure.empty_worker;
                retiring.control_error = Some(failure.error.to_string());
                (0, 0, 0)
            }
            "residual" => {
                let observed = Arc::clone(&calls);
                let mut job = RetirementJob::start(work, move |_| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    bail!("owned close refusal before fd release")
                })
                .unwrap_or_else(|failure| panic!("host worker: {}", failure.error));
                let work = collect_job(&mut job);
                let counts = (
                    work.receipt.attempted,
                    work.receipt.closed,
                    work.receipt.failures.len(),
                );
                // Keep genuine failed residual work in this owned shell.
                // No native state/registry recovery or Closed is synthesized.
                retiring.unstarted = Some(work);
                retiring.control_error = Some("owned close refusal".into());
                counts
            }
            _ => panic!("unknown host exit-retention case"),
        };
        HostExitOwner {
            retiring,
            gate,
            pin,
            raw_fd,
            calls,
            counts,
        }
    }
}
