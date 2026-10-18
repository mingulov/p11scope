//! SPDX-License-Identifier: GPL-3.0-or-later
//! Display-only expected images from already-proven native caller bindings.
//! These facts never upgrade caller, Engine, provider or scope authority.
use super::*;
use crate::attach::capture::CallerImageObservation;
use crate::discovery::caller_registry::{CallerLifecycle, CallerRecord};
use crate::process::WeakProcessCustody;
use std::sync::Arc;

/// Scheduling coordinate only. A copied key cannot construct an image proof.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct BinderMetadataKey {
    caller: CallerId,
    incarnation: u32,
    pid: u32,
    start_time: u64,
    first_seen_ns: u64,
    admitted_ns: u64,
    image: DomainCookie,
    exec_id: u64,
}
impl std::fmt::Debug for BinderMetadataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BinderMetadataKey(<retained>)")
    }
}
impl BinderMetadataKey {
    /// Pure scheduler fixtures only; no path accepts this key to mint a proof.
    #[cfg(test)]
    pub(crate) fn for_test(caller: CallerId, incarnation: u32, cookie: u64, exec: u64) -> Self {
        static DOMAIN: std::sync::OnceLock<NativeDomainId> = std::sync::OnceLock::new();
        Self {
            caller,
            incarnation,
            pid: 0,
            start_time: 0,
            first_seen_ns: 0,
            admitted_ns: 0,
            image: DomainCookie::new(*DOMAIN.get_or_init(NativeDomainId::mint), cookie),
            exec_id: exec,
        }
    }
}

/// Selected-only private binding of the genuine key to the adapter's original
/// allocation. Paired Weak custody preserves its charge without another FD.
pub(crate) struct BinderMetadataImage {
    key: BinderMetadataKey,
    original: WeakProcessCustody,
}
impl BinderMetadataImage {
    pub(crate) fn key(&self) -> BinderMetadataKey {
        self.key
    }
    pub(crate) fn matches_observation(
        &self,
        original: &Arc<PidPin>,
        observation: &CallerImageObservation,
    ) -> bool {
        self.original.matches_original(original)
            && observation.matches_binding(original, self.key.image, self.key.exec_id)
    }
}
impl std::fmt::Debug for BinderMetadataImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BinderMetadataImage(<retained>)")
    }
}

impl NativeBinder {
    /// One observer-context read at explicit opt-in, outside admission/render.
    pub(crate) fn qualify_metadata_clock(&mut self) {
        self.metadata_clock_qualified = crate::attach::clock_origins_comparable();
    }

    pub(crate) fn invalidate_metadata_clock(&mut self) {
        self.metadata_clock_qualified = false;
    }

    /// Cheap publication/scheduling lookup. C1's precoverage revalidation is
    /// intentionally insufficient: it can miss a same-binary earlier reexec.
    pub(crate) fn metadata_key(&self, record: &CallerRecord) -> Option<BinderMetadataKey> {
        if !self.metadata_clock_qualified
            || record.retired
            || record.lifecycle != CallerLifecycle::Mapped
            || record.admitted_ns == 0
            || record.admitted_ns == u64::MAX
            || record.admitted_ns < record.first_seen_ns
        {
            return None;
        }
        let start_time = record.start_time?;
        let mut result = None;
        for state in &self.domains {
            let Some(&(image, exec_id)) = state.callers.get(&record.id) else {
                continue;
            };
            if state.finished
                || !state.metadata_health_proven
                || state
                    .coverage_ns
                    .is_none_or(|start| record.first_seen_ns < start)
                || state.ended.contains(&record.id)
                || state
                    .exec_ns
                    .get(&record.pid)
                    .is_some_and(|ns| *ns >= record.first_seen_ns)
                || state.loss_ns.is_some_and(|ns| ns >= record.first_seen_ns)
                || state.lifecycle_ns.is_none_or(|ns| ns <= record.admitted_ns)
                || state.health_ns.is_none_or(|ns| ns <= record.admitted_ns)
                || state.cookies.get(&image).is_none_or(|execs| {
                    execs.keys().next_back().is_none_or(|exec| *exec != exec_id)
                })
            {
                continue;
            }
            let key = BinderMetadataKey {
                caller: record.id,
                incarnation: record.incarnation,
                pid: record.pid,
                start_time,
                first_seen_ns: record.first_seen_ns,
                admitted_ns: record.admitted_ns,
                image,
                exec_id,
            };
            // Never select arbitrarily between coexisting native domains.
            if result.replace(key).is_some() {
                return None;
            }
        }
        result
    }

    /// No new process open or admission: qualify only the adapter's exact
    /// original Arc. A caller-minted/scheduler key cannot enter this factory.
    pub(crate) fn metadata_image<Source: ProcessSource>(
        &self,
        adapter: &CallerAdapter<Source>,
        caller: CallerId,
        original: &Arc<PidPin>,
    ) -> Option<BinderMetadataImage> {
        let key = self.metadata_key(adapter.record(caller)?)?;
        let actual = adapter.shared_semantic_custody(caller)?;
        if !Arc::ptr_eq(&actual, original)
            || original.pid() != key.pid
            || original.start_time() != Some(key.start_time)
            || original.pidfd().is_err()
        {
            return None;
        }
        Some(BinderMetadataImage {
            key,
            original: PidPin::downgrade_shared(original)?,
        })
    }
}
