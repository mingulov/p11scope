//! SPDX-License-Identifier: GPL-3.0-or-later
//! Optional caller hints serviced through the one retained native capture.

use super::*;
use crate::attach::capture::{CallerImageObservation, ReadWindow};
use crate::caller_metadata::runtime::{MetadataFrame, job::MetadataLane};

impl<Source: ProcessSource> InventoryCoordinator<Source> {
    pub(crate) fn enable_caller_metadata(&mut self, epoch: u64) -> Result<()> {
        if self.caller_metadata.is_none() {
            self.binder.qualify_metadata_clock();
            if !self.exit_clocks_comparable {
                self.binder.invalidate_metadata_clock();
            }
            self.caller_metadata =
                Some(MetadataLane::try_new(epoch).unwrap_or_else(MetadataLane::unavailable));
        }
        Ok(())
    }

    pub(crate) fn service_caller_metadata(
        &mut self,
        observe: impl FnMut(&Arc<crate::process::PidPin>, ReadWindow) -> Result<CallerImageObservation>,
        now_ns: u64,
    ) {
        if let Some(metadata) = self.caller_metadata.as_mut() {
            if !self.exit_clocks_comparable {
                self.binder.invalidate_metadata_clock();
            }
            metadata.tick(&self.adapter, &self.binder, now_ns, observe);
        }
    }

    pub(crate) fn stop_caller_metadata(&mut self) {
        if let Some(metadata) = self.caller_metadata.as_mut() {
            metadata.stop();
        }
    }

    /// Drain only the already owned worker after fencing new work. A true
    /// result means its actual JoinHandle has completed; dropping the lane
    /// while false keeps the helper's static owner and memory charge.
    pub(crate) fn poll_caller_metadata_stop(&mut self, now_ns: u64) -> bool {
        let Some(metadata) = self.caller_metadata.as_mut() else {
            return true;
        };
        metadata.stop();
        metadata.tick(&self.adapter, &self.binder, now_ns, |_, _| {
            Err(anyhow::anyhow!("caller metadata is stopping"))
        });
        metadata.idle()
    }

    pub(super) fn synchronize_caller_metadata(&mut self, now_ns: u64) {
        if let Some(metadata) = self.caller_metadata.as_mut() {
            // Publication can precede the first service tick. Account every
            // current/retired row without starting native or proc I/O here.
            if !self.exit_clocks_comparable {
                self.binder.invalidate_metadata_clock();
            }
            metadata.synchronize(&self.adapter, &self.binder, now_ns);
        }
    }

    pub(crate) fn metadata_frame(&self) -> MetadataFrame {
        self.caller_metadata
            .as_ref()
            .map_or_else(MetadataFrame::default, MetadataLane::frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller_metadata::runtime::job::test_support::worker_lock;
    use crate::discovery::caller_registry::OsProcessSource;
    use std::time::{Duration, Instant};

    fn coordinator() -> InventoryCoordinator<OsProcessSource> {
        InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap()
    }

    #[test]
    fn caller_metadata_stop_poll_disabled_is_allocation_free() {
        let mut coordinator = coordinator();
        let (joined, allocations, bytes) =
            crate::test_alloc::count_allocs_during(|| coordinator.poll_caller_metadata_stop(1));
        assert!(joined);
        assert_eq!((allocations, bytes), (0, 0));
        assert!(coordinator.caller_metadata.is_none());
    }

    #[test]
    fn caller_metadata_stop_poll_waits_for_actual_worker_join() {
        let _serial = worker_lock();
        let mut coordinator = coordinator();
        coordinator.enable_caller_metadata(1).unwrap();
        let before = coordinator.metadata_frame().summary.retained_bytes;
        let held = coordinator
            .caller_metadata
            .as_mut()
            .unwrap()
            .hold_worker_for_test();
        let retained = coordinator.metadata_frame().summary.retained_bytes;
        assert!(
            retained > before,
            "the actual worker owns its runtime budget"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(!coordinator.poll_caller_metadata_stop(2));
            assert_eq!(
                coordinator.metadata_frame().summary.retained_bytes,
                retained
            );
            if held.cancelled() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the actual worker observed no cancellation"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // The helper deliberately panics after release; it cannot fabricate a
        // metadata Completion, identity observation or qualified sample.
        held.release();
        while !coordinator.poll_caller_metadata_stop(3) {
            assert!(
                Instant::now() < deadline,
                "the finished worker was not joined"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(coordinator.metadata_frame().summary.retained_bytes, before);
        assert!(coordinator.poll_caller_metadata_stop(4));
    }
}
