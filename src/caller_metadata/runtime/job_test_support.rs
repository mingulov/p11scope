// SPDX-License-Identifier: GPL-3.0-or-later
//! Test-only blocking fault at the actual production work owner and budget.
//! It cannot fabricate a completion, expected image or publishable sample.

use super::*;
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

pub(crate) fn worker_lock() -> MutexGuard<'static, ()> {
    static TEST_WORKER: Mutex<()> = Mutex::new(());
    TEST_WORKER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) struct HeldMetadataWorker {
    release: Option<SyncSender<()>>,
    cancelled: Arc<AtomicBool>,
}
impl HeldMetadataWorker {
    pub(crate) fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
    pub(crate) fn release(mut self) {
        self.unblock();
    }
    fn unblock(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}
impl Drop for HeldMetadataWorker {
    fn drop(&mut self) {
        self.unblock();
    }
}

impl MetadataLane {
    pub(crate) fn hold_worker_for_test(&mut self) -> HeldMetadataWorker {
        let active = self.active.as_mut().expect("actual enabled owner");
        let storage = active.runtime.reserve_worker().expect("one worker charge");
        let (release, wait) = sync_channel(1);
        let (started, ready) = sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&cancelled);
        active
            .worker
            .start_retained(
                move |cancel| {
                    started.send(()).unwrap();
                    loop {
                        if cancel.load(Ordering::Acquire) {
                            observed.store(true, Ordering::Release);
                        }
                        match wait.recv_timeout(Duration::from_millis(1)) {
                            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                            Err(RecvTimeoutError::Timeout) => {}
                        }
                    }
                    panic!("injected held metadata worker failure; no sample produced")
                },
                storage,
            )
            .expect("start actual retained worker");
        let held = HeldMetadataWorker {
            release: Some(release),
            cancelled,
        };
        ready
            .recv_timeout(Duration::from_secs(1))
            .expect("actual worker started");
        held
    }
}
