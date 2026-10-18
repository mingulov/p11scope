// SPDX-License-Identifier: GPL-3.0-or-later
//! One owned cancellable blocking job. A dropped capture never detaches it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub(crate) struct WorkSlot<T, Guard = ()> {
    state: Mutex<State<T, Guard>>,
}
struct State<T, Guard> {
    serial: u64,
    owner: Option<u64>,
    running: Option<Running<T, Guard>>,
}
struct Running<T, Guard> {
    cancelled: Arc<AtomicBool>,
    handle: JoinHandle<T>,
    retained: Guard,
}

pub(crate) struct WorkOwner<'a, T, Guard = ()> {
    slot: &'a WorkSlot<T, Guard>,
    serial: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkFailure {
    Busy,
    Spawn,
    Panic,
    Exhausted,
}

impl<T: Send + 'static, Guard: Send + 'static> WorkSlot<T, Guard> {
    pub(crate) const fn new() -> Self {
        Self {
            state: Mutex::new(State {
                serial: 0,
                owner: None,
                running: None,
            }),
        }
    }
    pub(crate) fn claim(&self) -> Result<WorkOwner<'_, T, Guard>, WorkFailure> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.owner.is_some() {
            return Err(WorkFailure::Busy);
        }
        if state
            .running
            .as_ref()
            .is_some_and(|work| !work.handle.is_finished())
        {
            return Err(WorkFailure::Busy);
        }
        if let Some(finished) = state.running.take() {
            let _ = finished.handle.join();
        }
        state.serial = state.serial.checked_add(1).ok_or(WorkFailure::Exhausted)?;
        let serial = state.serial;
        state.owner = Some(serial);
        Ok(WorkOwner { slot: self, serial })
    }
}
impl<T: Send + 'static, Guard: Send + 'static> WorkOwner<'_, T, Guard> {
    pub(crate) fn start_retained<F>(&self, task: F, retained: Guard) -> Result<(), WorkFailure>
    where
        F: FnOnce(Arc<AtomicBool>) -> T + Send + 'static,
    {
        let mut state = self
            .slot
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.owner != Some(self.serial) || state.running.is_some() {
            return Err(WorkFailure::Busy);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        let handle = std::thread::Builder::new()
            .name("p11scope-caller-metadata".into())
            .stack_size(256 * 1024)
            .spawn(move || task(flag))
            .map_err(|_| WorkFailure::Spawn)?;
        state.running = Some(Running {
            cancelled,
            handle,
            retained,
        });
        Ok(())
    }
    pub(crate) fn poll_retained(&self) -> Option<(Result<T, WorkFailure>, Guard)> {
        let mut state = self
            .slot
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.owner != Some(self.serial)
            || state
                .running
                .as_ref()
                .is_none_or(|work| !work.handle.is_finished())
        {
            return None;
        }
        let work = state.running.take().expect("finished worker");
        drop(state);
        Some((
            work.handle.join().map_err(|_| WorkFailure::Panic),
            work.retained,
        ))
    }
    pub(crate) fn cancel(&self) {
        let state = self
            .slot
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.owner == Some(self.serial) {
            if let Some(work) = &state.running {
                work.cancelled.store(true, Ordering::Release);
            }
        }
    }
    pub(crate) fn idle(&self) -> bool {
        let state = self
            .slot
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.owner == Some(self.serial) && state.running.is_none()
    }
}
impl<T, Guard> Drop for WorkOwner<'_, T, Guard> {
    fn drop(&mut self) {
        let mut state = self
            .slot
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.owner == Some(self.serial) {
            if let Some(work) = &state.running {
                work.cancelled.store(true, Ordering::Release);
            }
            state.owner = None;
            // The process-lifetime slot still OWNS the JoinHandle, original
            // custody and its allocation leases. New owners cannot bypass it.
        }
    }
}

#[cfg(test)]
impl<T: Send + 'static> WorkOwner<'_, T> {
    fn start<F>(&self, task: F) -> Result<(), WorkFailure>
    where
        F: FnOnce(Arc<AtomicBool>) -> T + Send + 'static,
    {
        self.start_retained(task, ())
    }
    fn poll(&self) -> Option<Result<T, WorkFailure>> {
        self.poll_retained().map(|(value, ())| value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn until(mut test: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !test() {
            assert!(Instant::now() < deadline, "worker failed to finish");
            std::thread::yield_now();
        }
    }

    #[test]
    fn blocked_worker_cancelled_owner_drop_keeps_custody_and_refuses_new_owner() {
        let slot = WorkSlot::<Arc<()>>::new();
        let owner = slot.claim().unwrap();
        let serial = owner.serial;
        let custody = Arc::new(());
        let weak = Arc::downgrade(&custody);
        let (entered, arrived) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        owner
            .start(move |cancelled| {
                entered.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(3)).unwrap();
                assert!(cancelled.load(Ordering::Acquire));
                custody
            })
            .unwrap();
        arrived.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(owner.poll().is_none());
        assert!(owner.start(|_| Arc::new(())).is_err());
        drop(owner);
        assert!(
            slot.claim().is_err(),
            "old blocking job cannot be detached or bypassed"
        );
        assert!(weak.upgrade().is_some(), "original custody still held");
        release.send(()).unwrap();
        let mut successor = None;
        until(|| {
            successor = slot.claim().ok();
            successor.is_some()
        });
        assert!(
            weak.upgrade().is_none(),
            "finished orphan and its completion actually dropped"
        );
        let successor = successor.unwrap();
        assert!(successor.serial > serial, "old owner token never reused");
        assert!(successor.idle());
    }

    #[test]
    fn one_job_one_completion_is_retained_until_poll_and_then_reusable() {
        let slot = WorkSlot::<u64>::new();
        let owner = slot.claim().unwrap();
        owner.start(|_| 7).unwrap();
        let mut result = None;
        until(|| {
            result = owner.poll();
            result.is_some()
        });
        assert_eq!(result, Some(Ok(7)));
        assert!(owner.idle());
        assert!(owner.poll().is_none());
        owner.start(|_| 8).unwrap();
        until(|| owner.poll().is_some());
    }

    #[test]
    fn actual_retention_guard_survives_blocked_drop_and_completion_until_last_owner() {
        struct Guard(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let charged = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let slot = WorkSlot::<u64, Guard>::new();
        let owner = slot.claim().unwrap();
        owner
            .start_retained(|_| 7, Guard(Arc::clone(&charged)))
            .unwrap();
        let mut result = None;
        until(|| {
            result = owner.poll_retained();
            result.is_some()
        });
        assert_eq!(
            charged.load(Ordering::Acquire),
            1,
            "returned completion still owns its reservation"
        );
        assert_eq!(result.as_ref().map(|(result, _)| *result), Some(Ok(7)));
        drop(result.take());
        assert_eq!(
            charged.load(Ordering::Acquire),
            0,
            "final completion refunds exactly once"
        );

        charged.store(1, Ordering::Release);
        owner
            .start_retained(
                |_| panic!("owned retention test"),
                Guard(Arc::clone(&charged)),
            )
            .unwrap();
        until(|| {
            result = owner.poll_retained();
            result.is_some()
        });
        assert_eq!(
            charged.load(Ordering::Acquire),
            1,
            "panic cannot refund retained slot/flag early"
        );
        drop(result.take());
        assert_eq!(charged.load(Ordering::Acquire), 0);
    }

    #[test]
    fn cancellation_is_cooperative_and_finished_panic_has_finite_result() {
        let slot = WorkSlot::<()>::new();
        let owner = slot.claim().unwrap();
        owner
            .start(|cancelled| {
                while !cancelled.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            })
            .unwrap();
        owner.cancel();
        until(|| owner.poll().is_some());
        owner.start(|_| panic!("owned test worker")).unwrap();
        let mut result = None;
        until(|| {
            result = owner.poll();
            result.is_some()
        });
        assert_eq!(result, Some(Err(WorkFailure::Panic)));
    }
}
