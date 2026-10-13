//! SPDX-License-Identifier: GPL-3.0-or-later
//! Real file custody with gated inner drops, without a native-speed claim.

use super::*;
use crate::attach::cleanup_worker::concurrency_tests::{CloseGate, ReleaseGuard};
use std::os::fd::OwnedFd;
use std::sync::Weak;

struct GuardedInnerFd {
    id: usize,
    fd: Option<OwnedFd>,
    pin: Weak<std::fs::File>,
    gate: Arc<CloseGate>,
}

impl Drop for GuardedInnerFd {
    fn drop(&mut self) {
        // Do not keep the Weak upgrade across the gate: that would repair a
        // missing retirement lease inside this test's substituted close.
        if self.pin.upgrade().is_none() {
            self.gate.missing_pin();
        }
        self.gate.before_close(self.id);
        drop(self.fd.take());
        if self.pin.upgrade().is_none() {
            self.gate.missing_pin();
        }
        self.gate.after_close(self.id);
    }
}

#[test]
fn bounded_cleanup_inventory_overlaps_entries_keeps_pins_and_retires_roots_last() {
    let fixture = Fixture::new();
    let targets = fixture.targets(5, 5);
    let lease = targets.pins.values().next().unwrap().retirement_lease();
    let weak = Arc::downgrade(&lease);
    let gate = Arc::new(CloseGate::default());
    // Match the actual transaction: lifecycle roots are inserted before
    // ordinary entries, and current retirement walks it in reverse.
    let links = [
        (InventoryLinkIdentity::Lifecycle("sched_process_exec"), 5),
        (InventoryLinkIdentity::Lifecycle("sched_process_exit"), 6),
    ]
    .into_iter()
    .chain((0..5).map(|id| (InventoryLinkIdentity::Entry(id as u32), id)))
    .map(|(target, id)| {
        (
            target,
            vec![GuardedInnerFd {
                id,
                fd: Some(std::fs::File::open("/dev/null").unwrap().into()),
                pin: weak.clone(),
                gate: Arc::clone(&gate),
            }],
        )
    });
    let work = RetirementWork::new(retirement_links(links), vec![lease]);
    // The job becomes the only strong owner of the original physical file.
    drop(targets);
    drop(fixture);
    let mut job = RetirementJob::start(work, |handles| {
        handles.clear();
        Ok(())
    })
    .unwrap_or_else(|failure| panic!("worker start: {}", failure.error));
    let release_guard = ReleaseGuard(Arc::clone(&gate));
    let concurrent = gate.wait_for(Duration::from_secs(2), |state| {
        state.started.iter().filter(|id| **id < 5).count() >= 4
    });
    let excessive = gate.wait_for(Duration::from_millis(100), |state| state.in_flight > 4);
    let first = gate.snapshot();
    let pin_while_pending = weak.upgrade().is_some();
    let expired_retains_job = matches!(job.poll(Instant::now()), Ok(None));
    let mut roots_wait_for_entries = false;
    let mut final_inner_drop_pending = false;
    if concurrent {
        let last_entry = (0..5).find(|id| !first.started.contains(id));
        gate.release(first.started.iter().copied().filter(|id| *id < 5));
        if let Some(last_entry) = last_entry {
            let entered = gate.wait_for(Duration::from_secs(2), |state| {
                state.started.contains(&last_entry)
            });
            roots_wait_for_entries = entered && gate.snapshot().started.iter().all(|id| *id < 5);
            final_inner_drop_pending = matches!(
                job.poll(Instant::now() + Duration::from_millis(50)),
                Ok(None)
            );
            gate.release([last_entry]);
        }
        let roots_started = gate.wait_for(Duration::from_secs(2), |state| {
            state.started.contains(&5) || state.started.contains(&6)
        });
        let roots = gate.snapshot();
        roots_wait_for_entries &= roots_started && (0..5).all(|id| roots.completed.contains(&id));
        final_inner_drop_pending &= weak.upgrade().is_some()
            && matches!(
                job.poll(Instant::now() + Duration::from_millis(50)),
                Ok(None)
            );
    }
    // Even a serial RED releases and joins before its first assertion.
    gate.release_all();
    let collected = collect_job(&mut job);
    drop(job);
    drop(release_guard);
    let settled = gate.snapshot();
    let pin_through_result = weak.upgrade().is_some();
    let receipt = &collected.receipt;
    assert!(
        concurrent,
        "serial same-rank inner drops do not overlap: {first:?}; {receipt:?}"
    );
    assert!(!excessive && settled.maximum_in_flight == 4, "{settled:?}");
    assert!(pin_while_pending && expired_retains_job && pin_through_result);
    assert!(
        roots_wait_for_entries && final_inner_drop_pending,
        "{settled:?}"
    );
    assert_eq!((receipt.attempted, receipt.closed), (7, 7));
    assert!(receipt.failures.is_empty(), "{receipt:?}");
    assert!(settled.failures.is_empty(), "{settled:?}");
    drop(collected);
    assert!(
        weak.upgrade().is_none(),
        "settled job must release its original lease"
    );
}
