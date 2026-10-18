// SPDX-License-Identifier: GPL-3.0-or-later
//! Display-only access to already-admitted original process custody.

use super::{CallerAdapter, CallerId, CallerLifecycle, ImageAuthority, ProcessSource};
use crate::caller_metadata::presentation::MetadataReason;
use crate::caller_metadata::runtime::MetadataCaller;
use crate::process::PidPin;
use std::sync::Arc;

pub(crate) struct MetadataTarget {
    pub(crate) caller: MetadataCaller,
    pub(crate) original: Arc<PidPin>,
}

impl<Source: ProcessSource> CallerAdapter<Source> {
    pub(crate) fn metadata_callers(&self) -> impl Iterator<Item = MetadataCaller> + '_ {
        self.records().map(|record| MetadataCaller {
            id: record.id,
            incarnation: record.incarnation,
            image: match record.authority {
                ImageAuthority::NativeExact {
                    task_cookie,
                    exec_id,
                } => Some((task_cookie, exec_id)),
                ImageAuthority::ScanPinned => None,
            },
            retired: record.retired || record.lifecycle != CallerLifecycle::Mapped,
        })
    }

    /// Borrow the adapter's concrete original Arc. No numeric-PID open, fresh
    /// admission, proof upgrade, or duplicated pin for a queued population.
    pub(crate) fn metadata_target(&self, id: CallerId) -> Result<MetadataTarget, MetadataReason> {
        let record = self.record(id).ok_or(MetadataReason::IdentityUnavailable)?;
        if record.retired || record.lifecycle != CallerLifecycle::Mapped {
            return Err(MetadataReason::ProcessExited);
        }
        let ImageAuthority::NativeExact {
            task_cookie,
            exec_id,
        } = record.authority
        else {
            return Err(MetadataReason::IdentityUnavailable);
        };
        if task_cookie == 0 || record.start_time.is_none() {
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
        Ok(MetadataTarget {
            caller: MetadataCaller {
                id,
                incarnation: record.incarnation,
                image: Some((task_cookie, exec_id)),
                retired: false,
            },
            original,
        })
    }
}
