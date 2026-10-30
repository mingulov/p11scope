//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private endpoint image facts for bounded caller-context sampling. Ordinary
//! metadata observations still cannot upgrade admission, scope, provider
//! permission or Detailed readiness; the specifically approved
//! inventory-owner guard may check an independently supplied expected
//! binding through a fresh observation.
use super::{NativeDomainId, PidPin, ReadWindow};
use crate::attach::capture::DomainCookie;
use anyhow::{Context as _, Result};
use std::sync::Arc;

/// Constructed only by the genuine Inventory native query below. Retaining the
/// same original Arc adds no descriptor or allocation and preserves its charge.
/// There is no raw identity getter, caller-minted constructor or serialization
/// (tests script observations through the real decoder only).
pub(crate) struct CallerImageObservation {
    domain: NativeDomainId,
    generation: u64,
    original: Arc<PidPin>,
    cookie: u64,
    exec_id: u64,
}

/// How one fresh observation relates to one expected binding: provenance
/// first (a foreign domain, foreign original allocation, or invalid query
/// generation is `Unavailable`), image equality only within a well-formed
/// observation of the correct original in the correct domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingObservation {
    Match,
    DifferentImage,
    Unavailable,
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

    pub(crate) fn compare_binding(
        &self,
        original: &Arc<PidPin>,
        image: DomainCookie,
        full_exec_id: u64,
    ) -> BindingObservation {
        // Provenance first: a foreign domain, a foreign original
        // allocation, or an invalid query generation is Unavailable,
        // never a terminal image verdict.
        if image.domain() != self.domain
            || !Arc::ptr_eq(&self.original, original)
            || self.generation == 0
        {
            BindingObservation::Unavailable
        } else if self.matches_binding(original, image, full_exec_id) {
            BindingObservation::Match
        } else {
            BindingObservation::DifferentImage
        }
    }
}

/// Test-only observation through the real baseline decoder: the bytes carry
/// one identity row plus the END row, decoded exactly like a genuine
/// answer. Never a production constructor.
#[cfg(test)]
pub(crate) fn scripted_observation(
    domain: NativeDomainId,
    original: &Arc<PidPin>,
    generation: u64,
    cookie: u64,
    exec_id: u64,
) -> Result<CallerImageObservation> {
    let mut bytes = Vec::new();
    for (cookie, exec_id, visits, slot, status) in
        [(cookie, exec_id, 1u64, 0u32, 1u32), (0, 0, 2, 1, 2)]
    {
        for word in [generation, cookie, exec_id, visits] {
            bytes.extend_from_slice(&word.to_ne_bytes());
        }
        bytes.extend_from_slice(&slot.to_ne_bytes());
        bytes.extend_from_slice(&status.to_ne_bytes());
    }
    let image = super::super::wire::parse_baseline(&bytes, generation, 1, 65536)
        .context("scripted caller image bytes failed baseline decoding")?
        .images
        .pop()
        .context("scripted caller image decoded no identity")?;
    Ok(CallerImageObservation {
        domain,
        generation,
        original: Arc::clone(original),
        cookie: image.cookie,
        exec_id: image.exec_id,
    })
}

impl std::fmt::Debug for CallerImageObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallerImageObservation(<retained>)")
    }
}

/// Exclusive facade calls bracket the metadata worker. A later observation can
/// confirm an independently proven native image, never upgrade ScanPinned —
/// except through the specifically approved inventory-owner guard, which is
/// this operation's one admission-adjacent consumer.
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
