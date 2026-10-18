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
