//! SPDX-License-Identifier: GPL-3.0-or-later
//! Display-only access to already-admitted original process custody.

use super::{CallerAdapter, CallerId, CallerLifecycle, ProcessSource};
use crate::caller_metadata::presentation::MetadataReason;
use crate::caller_metadata::runtime::MetadataCaller;
use crate::discovery::native_binding::{BinderMetadataImage, NativeBinder};
use crate::process::PidPin;
use std::sync::Arc;

pub(crate) struct MetadataTarget {
    pub(crate) caller: MetadataCaller,
    pub(crate) original: Arc<PidPin>,
    pub(crate) expected: BinderMetadataImage,
}

impl<Source: ProcessSource> CallerAdapter<Source> {
    pub(crate) fn metadata_callers<'a>(
        &'a self,
        binder: &'a NativeBinder,
    ) -> impl Iterator<Item = MetadataCaller> + 'a {
        self.records().map(move |record| MetadataCaller {
            id: record.id,
            incarnation: record.incarnation,
            image: binder.metadata_key(record),
            retired: record.retired || record.lifecycle != CallerLifecycle::Mapped,
        })
    }

    /// Borrow the adapter's concrete original Arc. No numeric-PID open, fresh
    /// admission, proof upgrade, or duplicated pin for a queued population.
    pub(crate) fn metadata_target(
        &self,
        binder: &NativeBinder,
        id: CallerId,
    ) -> Result<MetadataTarget, MetadataReason> {
        let record = self.record(id).ok_or(MetadataReason::IdentityUnavailable)?;
        if record.retired || record.lifecycle != CallerLifecycle::Mapped {
            return Err(MetadataReason::ProcessExited);
        }
        if record.start_time.is_none() {
            return Err(MetadataReason::IdentityUnavailable);
        }
        let original = self
            .shared_semantic_custody(id)
            .ok_or(MetadataReason::IdentityUnavailable)?;
        if original.pid() != record.pid
            || original.start_time() != record.start_time
            || original.pidfd().is_err()
        {
            return Err(MetadataReason::IdentityUnavailable);
        }
        let expected = binder
            .metadata_image(self, id, &original)
            .ok_or(MetadataReason::IdentityUnavailable)?;
        Ok(MetadataTarget {
            caller: MetadataCaller {
                id,
                incarnation: record.incarnation,
                image: Some(expected.key()),
                retired: false,
            },
            original,
            expected,
        })
    }
}
