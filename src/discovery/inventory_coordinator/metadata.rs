//! SPDX-License-Identifier: GPL-3.0-or-later
//! Optional caller hints serviced through the one retained native capture.

use super::*;
use crate::attach::capture::{CallerImageObservation, ReadWindow};
use crate::caller_metadata::runtime::{MetadataFrame, job::MetadataLane};

impl<Source: ProcessSource> InventoryCoordinator<Source> {
    pub(crate) fn enable_caller_metadata(&mut self, epoch: u64) -> Result<()> {
        if self.caller_metadata.is_none() {
            self.caller_metadata = Some(MetadataLane::try_new(epoch).map_err(|reason| {
                anyhow::anyhow!("caller metadata initialization refused: {reason:?}")
            })?);
        }
        Ok(())
    }

    pub(crate) fn service_caller_metadata(
        &mut self,
        observe: impl FnMut(&Arc<crate::process::PidPin>, ReadWindow) -> Result<CallerImageObservation>,
        now_ns: u64,
    ) {
        if let Some(metadata) = self.caller_metadata.as_mut() {
            metadata.tick(&self.adapter, now_ns, observe);
        }
    }

    pub(crate) fn stop_caller_metadata(&mut self) {
        if let Some(metadata) = self.caller_metadata.as_mut() {
            metadata.stop();
        }
    }

    pub(crate) fn metadata_frame(&self) -> MetadataFrame {
        self.caller_metadata
            .as_ref()
            .map_or_else(MetadataFrame::default, MetadataLane::frame)
    }
}
