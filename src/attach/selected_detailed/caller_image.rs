//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private endpoint image facts for bounded caller-context sampling. They never
//! establish caller admission, scope, provider permission or promotion readiness.
use super::{NativeDomainId, PidPin, ReadWindow};
use crate::attach::capture::DomainCookie;
use anyhow::{Context as _, Result};
use std::sync::Arc;

/// Constructed only by the genuine Inventory native query below. Retaining the
/// same original Arc adds no descriptor or allocation and preserves its charge.
/// There is no raw identity getter, caller-minted constructor or serialization.
pub(crate) struct CallerImageObservation {
    domain: NativeDomainId,
    generation: u64,
    original: Arc<PidPin>,
    cookie: u64,
    exec_id: u64,
}

impl CallerImageObservation {
    pub(crate) fn matches_original_and_image(
        &self,
        original: &Arc<PidPin>,
        task_cookie: u64,
        full_exec_id: u64,
    ) -> bool {
        self.generation != 0
            && Arc::ptr_eq(&self.original, original)
            && self.cookie == task_cookie
            && self.exec_id == full_exec_id
    }

    pub(crate) fn same_image(&self, other: &Self) -> bool {
        self.domain == other.domain
            && other.matches_original_and_image(&self.original, self.cookie, self.exec_id)
            && self.generation != 0
    }

    pub(crate) fn matches_binding(
        &self,
        original: &Arc<PidPin>,
        image: DomainCookie,
        full_exec_id: u64,
    ) -> bool {
        image == DomainCookie::new(self.domain, self.cookie)
            && self.matches_original_and_image(original, self.cookie, full_exec_id)
    }
}

impl std::fmt::Debug for CallerImageObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallerImageObservation(<retained>)")
    }
}

/// Exclusive facade calls bracket the metadata worker. A later observation can
/// confirm an independently proven native image, never upgrade ScanPinned.
pub(crate) fn observe_caller_image(
    ebpf: &mut aya::Ebpf,
    domain: NativeDomainId,
    generation: u64,
    original: &Arc<PidPin>,
    window: ReadWindow,
) -> Result<CallerImageObservation> {
    let image = super::query_native(ebpf, generation, 1, |_| original, window)?
        .pop()
        .context("caller image query returned no native identity")?;
    Ok(CallerImageObservation {
        domain,
        generation,
        original: Arc::clone(original),
        cookie: image.cookie,
        exec_id: image.exec_id,
    })
}

#[cfg(test)]
#[path = "caller_image_tests.rs"]
mod tests;
