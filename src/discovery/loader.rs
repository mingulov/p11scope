#[cfg(test)]
use p11scope_ebpf_common::{LOADER_CONTEXT_ID_MASK, valid_loader_cookie};
use p11scope_ebpf_common::{
    LOADER_STATE_ABSENT_SENTINEL, LOADER_STATE_PRESENT, LOADER_STATE_SHIFT,
};
use p11scope_manifest::elf::SymbolFact;
use p11scope_manifest::maps::MapEntry;

use crate::discovery::identity::{PinnedObjectId, PinnedObjects};
use crate::process::ProcessViewId;

pub(crate) const MAX_LOADER_CONTEXTS: usize = 256;
const MIN_STATE_DELTA: i64 = -(1_i64 << 54);
const MAX_STATE_DELTA: i64 = (1_i64 << 54) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoaderContextId(u16);

impl LoaderContextId {
    pub(crate) fn get(self) -> u16 {
        self.0
    }

    #[cfg(test)]
    fn case_id(self) -> u8 {
        (self.0 - 1) as u8
    }

    pub(crate) fn from_case_id(case_id: u8) -> Self {
        Self(u16::from(case_id) + 1)
    }
}

pub(crate) fn encode_loader_cookie(
    context_id: u16,
    state_delta: Option<i64>,
) -> Result<u64, String> {
    if !(1..=MAX_LOADER_CONTEXTS as u16).contains(&context_id) {
        return Err(format!("loader context id {context_id} is outside 1..=256"));
    }
    let case_id = u64::from(context_id - 1);
    match state_delta {
        None => Ok((LOADER_STATE_ABSENT_SENTINEL << LOADER_STATE_SHIFT) | case_id),
        Some(delta) if (MIN_STATE_DELTA..=MAX_STATE_DELTA).contains(&delta) => {
            Ok(((delta as u64) << LOADER_STATE_SHIFT) | LOADER_STATE_PRESENT | case_id)
        }
        Some(delta) => Err(format!(
            "loader state delta {delta} does not fit signed 55 bits"
        )),
    }
}

#[cfg(test)]
fn decode_loader_cookie(cookie: u64) -> Result<(LoaderContextId, Option<i64>), String> {
    if !valid_loader_cookie(cookie) {
        return Err(format!("invalid loader cookie {cookie:#x}"));
    }
    let context = LoaderContextId((cookie & LOADER_CONTEXT_ID_MASK) as u16 + 1);
    let delta =
        (cookie & LOADER_STATE_PRESENT != 0).then_some((cookie as i64) >> LOADER_STATE_SHIFT);
    Ok((context, delta))
}

#[derive(Debug, Clone)]
pub(crate) struct LoaderContextSpec {
    pub(crate) view: ProcessViewId,
    pub(crate) loader: PinnedObjectId,
    pub(crate) mapping: MapEntry,
    pub(crate) hook: SymbolFact,
    pub(crate) state: Option<SymbolFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoaderContextState {
    Prepared,
    Attached,
    Tombstoned,
}

#[derive(Debug, Clone)]
pub(crate) struct LoaderContext {
    pub(crate) spec: LoaderContextSpec,
    pub(crate) cookie: u64,
    expected_hook_ip: u64,
    state: LoaderContextState,
    pub(crate) was_attached: bool,
    pub(crate) earliest_hit_ns: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct PreparedLoaderContext {
    id: LoaderContextId,
    context: LoaderContext,
}

impl PreparedLoaderContext {
    pub(crate) fn cookie(&self) -> u64 {
        self.context.cookie
    }
}

pub(crate) struct LoaderRegistry {
    contexts: [Option<LoaderContext>; MAX_LOADER_CONTEXTS],
    allocated: usize,
    discovery_truncated: u64,
    context_failures: u64,
}

impl Default for LoaderRegistry {
    fn default() -> Self {
        Self {
            contexts: std::array::from_fn(|_| None),
            allocated: 0,
            discovery_truncated: 0,
            context_failures: 0,
        }
    }
}

impl LoaderRegistry {
    /// Computes every finite context/cookie requirement without changing registry state.
    pub(crate) fn preflight(
        &self,
        spec: LoaderContextSpec,
    ) -> Result<PreparedLoaderContext, String> {
        if self.allocated == MAX_LOADER_CONTEXTS {
            return Err("loader context capacity 256 is exhausted".into());
        }
        if spec.mapping.permissions[2] != b'x' || spec.mapping.inode == 0 {
            return Err("loader hook mapping is not a file-backed executable mapping".into());
        }
        let hook_delta = spec
            .hook
            .file_offset
            .checked_sub(spec.mapping.file_offset)
            .ok_or_else(|| "loader hook file offset precedes its mapping".to_string())?;
        let expected_hook_ip = spec
            .mapping
            .start
            .checked_add(hook_delta)
            .filter(|ip| *ip < spec.mapping.end)
            .ok_or_else(|| "loader hook IP is outside its mapping".to_string())?;
        let state_delta = spec
            .state
            .map(|state| signed_delta(state.virtual_address, spec.hook.virtual_address))
            .transpose()?;
        let id = LoaderContextId((self.allocated + 1) as u16);
        let cookie = encode_loader_cookie(id.get(), state_delta)?;
        Ok(PreparedLoaderContext {
            id,
            context: LoaderContext {
                spec,
                cookie,
                expected_hook_ip,
                state: LoaderContextState::Prepared,
                was_attached: false,
                earliest_hit_ns: None,
            },
        })
    }

    /// Commits a successfully preflighted context. In this single-threaded registry,
    /// any failure here is an internal lifecycle invariant, not an ordinary refusal.
    pub(crate) fn prepare(
        &mut self,
        prepared: PreparedLoaderContext,
    ) -> Result<LoaderContextId, String> {
        let expected = LoaderContextId((self.allocated.saturating_add(1)) as u16);
        if self.allocated == MAX_LOADER_CONTEXTS
            || prepared.id != expected
            || self.contexts[self.allocated].is_some()
        {
            return Err("preflighted loader context no longer matches registry state".into());
        }
        let id = prepared.id;
        self.contexts[self.allocated] = Some(prepared.context);
        self.allocated += 1;
        Ok(id)
    }

    pub(crate) fn record_preflight_failure(&mut self) {
        if self.allocated == MAX_LOADER_CONTEXTS {
            self.discovery_truncated = self.discovery_truncated.saturating_add(1);
        }
    }

    pub(crate) fn context(&self, id: LoaderContextId) -> Option<&LoaderContext> {
        self.contexts.get(usize::from(id.get() - 1))?.as_ref()
    }

    pub(crate) fn is_tombstoned(&self, id: LoaderContextId) -> bool {
        self.context(id)
            .is_some_and(|context| context.state == LoaderContextState::Tombstoned)
    }

    fn context_mut(&mut self, id: LoaderContextId) -> Result<&mut LoaderContext, String> {
        self.contexts
            .get_mut(usize::from(id.get().saturating_sub(1)))
            .and_then(Option::as_mut)
            .ok_or_else(|| format!("loader context {} is not active", id.get()))
    }

    pub(crate) fn mark_attached(&mut self, id: LoaderContextId) -> Result<(), String> {
        let context = self.context_mut(id)?;
        if context.state != LoaderContextState::Prepared {
            return Err(format!("loader context {} is not prepared", id.get()));
        }
        context.state = LoaderContextState::Attached;
        context.was_attached = true;
        Ok(())
    }

    pub(crate) fn tombstone(&mut self, id: LoaderContextId) -> Result<(), String> {
        let context = self.context_mut(id)?;
        if context.state != LoaderContextState::Attached {
            return Err(format!("loader context {} is not attached", id.get()));
        }
        context.state = LoaderContextState::Tombstoned;
        Ok(())
    }

    pub(crate) fn cancel_prepared(&mut self, id: LoaderContextId) -> Result<(), String> {
        let context = self.context_mut(id)?;
        if context.state != LoaderContextState::Prepared {
            return Err(format!("loader context {} is not prepared", id.get()));
        }
        context.state = LoaderContextState::Tombstoned;
        Ok(())
    }

    pub(crate) fn remove(&mut self, id: LoaderContextId) -> Result<(), String> {
        let index = usize::from(id.get().saturating_sub(1));
        let context = self
            .contexts
            .get(index)
            .and_then(Option::as_ref)
            .ok_or_else(|| format!("loader context {} is not active", id.get()))?;
        if context.state != LoaderContextState::Tombstoned {
            return Err(format!("loader context {} is not tombstoned", id.get()));
        }
        self.contexts[index] = None;
        Ok(())
    }

    pub(crate) fn validate_hit(
        &mut self,
        case_id: u8,
        view: ProcessViewId,
        loader: PinnedObjectId,
        mapping: &MapEntry,
        hook_ip: u64,
        timestamp_ns: u64,
    ) -> Result<&LoaderContext, String> {
        let id = LoaderContextId(u16::from(case_id) + 1);
        self.validate_hit_in_state(
            id,
            LoaderContextState::Attached,
            view,
            loader,
            mapping,
            hook_ip,
            timestamp_ns,
        )
    }

    pub(crate) fn validate_terminal_hit(
        &mut self,
        id: LoaderContextId,
        view: ProcessViewId,
        loader: PinnedObjectId,
        mapping: &MapEntry,
        hook_ip: u64,
        timestamp_ns: u64,
    ) -> Result<&LoaderContext, String> {
        self.validate_hit_in_state(
            id,
            LoaderContextState::Tombstoned,
            view,
            loader,
            mapping,
            hook_ip,
            timestamp_ns,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "fixed loader-record identity boundary; grouping one caller shape adds boilerplate"
    )]
    fn validate_hit_in_state(
        &mut self,
        id: LoaderContextId,
        state: LoaderContextState,
        view: ProcessViewId,
        loader: PinnedObjectId,
        mapping: &MapEntry,
        hook_ip: u64,
        timestamp_ns: u64,
    ) -> Result<&LoaderContext, String> {
        let valid = self.context(id).is_some_and(|context| {
            context.state == state
                && context.spec.view == view
                && context.spec.loader == loader
                && context.spec.mapping == *mapping
                && context.expected_hook_ip == hook_ip
        });
        if !valid {
            self.context_failures = self.context_failures.saturating_add(1);
            return Err(format!(
                "loader context {} does not match this event",
                id.get()
            ));
        }
        let context = self.context_mut(id)?;
        context.earliest_hit_ns = Some(
            context
                .earliest_hit_ns
                .map_or(timestamp_ns, |earliest| earliest.min(timestamp_ns)),
        );
        Ok(context)
    }

    pub(crate) fn discovery_truncated(&self) -> u64 {
        self.discovery_truncated
    }

    pub(crate) fn context_failures(&self) -> u64 {
        self.context_failures
    }

    pub(crate) fn reject_hit(&mut self) {
        self.context_failures = self.context_failures.saturating_add(1);
    }

    pub(crate) fn ids_for_view(&self, view: ProcessViewId) -> Vec<LoaderContextId> {
        self.contexts
            .iter()
            .enumerate()
            .filter_map(|(index, context)| {
                context
                    .as_ref()
                    .filter(|context| context.spec.view == view)
                    .map(|_| LoaderContextId((index + 1) as u16))
            })
            .collect()
    }

    pub(crate) fn contexts_missing_from(&self, pinned: &PinnedObjects) -> Vec<LoaderContextId> {
        self.contexts
            .iter()
            .enumerate()
            .filter_map(|(index, context)| {
                context
                    .as_ref()
                    .filter(|context| pinned.summary(context.spec.loader).is_none())
                    .map(|_| LoaderContextId((index + 1) as u16))
            })
            .collect()
    }
}

fn signed_delta(address: u64, base: u64) -> Result<i64, String> {
    if address >= base {
        i64::try_from(address - base).map_err(|_| "loader state delta overflows i64".into())
    } else {
        let magnitude = base - address;
        let magnitude =
            i64::try_from(magnitude).map_err(|_| "loader state delta overflows i64".to_string())?;
        Ok(-magnitude)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_manifest::maps::Device;

    fn mapping() -> MapEntry {
        MapEntry {
            start: 0x4000_0000,
            end: 0x4000_1000,
            file_offset: 0x2000,
            permissions: *b"r-xp",
            device: Device { major: 8, minor: 1 },
            inode: 7,
            raw_path: Some(b"/lib64/ld-linux-x86-64.so.2".to_vec()),
        }
    }

    fn spec(state_vaddr: Option<u64>) -> LoaderContextSpec {
        LoaderContextSpec {
            view: ProcessViewId(7),
            loader: PinnedObjectId(9),
            mapping: mapping(),
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            state: state_vaddr.map(|virtual_address| SymbolFact {
                virtual_address,
                file_offset: 0x2800,
            }),
        }
    }

    fn prepare(registry: &mut LoaderRegistry, spec: LoaderContextSpec) -> LoaderContextId {
        let prepared = registry.preflight(spec).unwrap();
        registry.prepare(prepared).unwrap()
    }

    #[test]
    fn loader_registry_enforces_monotonic_contexts_and_retirement() {
        assert_eq!(encode_loader_cookie(1, None).unwrap(), 512);
        assert_eq!(encode_loader_cookie(1, Some(0)).unwrap(), 256);
        assert!(decode_loader_cookie(0).is_err());

        let mut registry = LoaderRegistry::default();
        let first = prepare(&mut registry, spec(None));
        assert_eq!(first.get(), 1);
        let context = registry.context(first).unwrap();
        assert_eq!(context.cookie, 512);
        assert!(!context.was_attached);
        assert_eq!(context.spec.loader, PinnedObjectId(9));

        assert!(registry.tombstone(first).is_err());
        assert!(registry.remove(first).is_err());

        registry.mark_attached(first).unwrap();
        assert!(registry.context(first).unwrap().was_attached);
        assert!(registry.mark_attached(first).is_err());
        assert!(registry.remove(first).is_err());
        registry
            .validate_hit(
                first.case_id(),
                ProcessViewId(7),
                PinnedObjectId(9),
                &mapping(),
                0x4000_0100,
                20,
            )
            .unwrap();
        registry
            .validate_hit(
                first.case_id(),
                ProcessViewId(7),
                PinnedObjectId(9),
                &mapping(),
                0x4000_0100,
                30,
            )
            .unwrap();
        assert_eq!(registry.context(first).unwrap().earliest_hit_ns, Some(20));

        registry.tombstone(first).unwrap();
        assert!(registry.mark_attached(first).is_err());
        assert!(registry.tombstone(first).is_err());
        assert!(
            registry
                .validate_hit(
                    first.case_id(),
                    ProcessViewId(7),
                    PinnedObjectId(9),
                    &mapping(),
                    0x4000_0100,
                    10,
                )
                .is_err(),
            "a queued record must not resolve after tombstoning"
        );
        registry.remove(first).unwrap();
        assert!(registry.context(first).is_none());
        assert!(registry.mark_attached(first).is_err());
        assert!(registry.tombstone(first).is_err());
        assert!(registry.remove(first).is_err());

        let cancelled = prepare(&mut registry, spec(None));
        assert_eq!(cancelled.get(), 2);
        registry.cancel_prepared(cancelled).unwrap();
        assert!(!registry.context(cancelled).unwrap().was_attached);
        registry.remove(cancelled).unwrap();
        assert!(registry.context(cancelled).is_none());

        for expected in 3..=MAX_LOADER_CONTEXTS as u16 {
            let id = prepare(&mut registry, spec(None));
            assert_eq!(id.get(), expected);
            registry.mark_attached(id).unwrap();
            registry.tombstone(id).unwrap();
            registry.remove(id).unwrap();
        }
        let allocated = registry.allocated;
        let truncated = registry.discovery_truncated();
        let error = registry.preflight(spec(None)).unwrap_err();
        assert_eq!(registry.allocated, allocated);
        assert_eq!(registry.discovery_truncated(), truncated);
        assert!(registry.ids_for_view(ProcessViewId(7)).is_empty());
        registry.record_preflight_failure();
        assert!(error.contains("capacity 256"), "{error}");
        assert_eq!(registry.discovery_truncated(), 1);
        assert_eq!(registry.context_failures(), 1);
    }

    #[test]
    fn loader_cookies_round_trip_signed_bounds_and_refuse_overflow() {
        for context in [1, 256] {
            for delta in [MIN_STATE_DELTA, -17, -1, 0, 1, 29, MAX_STATE_DELTA] {
                let cookie = encode_loader_cookie(context, Some(delta)).unwrap();
                let (decoded_context, decoded_delta) = decode_loader_cookie(cookie).unwrap();
                assert_eq!(decoded_context.get(), context);
                assert_eq!(decoded_delta, Some(delta));
            }
            let cookie = encode_loader_cookie(context, None).unwrap();
            let (decoded_context, decoded_delta) = decode_loader_cookie(cookie).unwrap();
            assert_eq!(decoded_context.get(), context);
            assert_eq!(decoded_delta, None);
        }
        assert!(encode_loader_cookie(0, None).is_err());
        assert!(encode_loader_cookie(257, None).is_err());
        assert!(encode_loader_cookie(1, Some(MIN_STATE_DELTA - 1)).is_err());
        assert!(encode_loader_cookie(1, Some(MAX_STATE_DELTA + 1)).is_err());
        assert!(decode_loader_cookie(0).is_err());
    }

    #[test]
    fn loader_hit_requires_generation_mapping_identity_and_hook_ip() {
        let mut registry = LoaderRegistry::default();
        let id = prepare(&mut registry, spec(Some(0x2100)));
        assert_eq!(registry.context(id).unwrap().cookie, 256);
        registry.mark_attached(id).unwrap();

        let mut wrong_mapping = mapping();
        wrong_mapping.inode += 1;
        for (view, loader, map, hook_ip) in [
            (ProcessViewId(8), PinnedObjectId(9), mapping(), 0x4000_0100),
            (ProcessViewId(7), PinnedObjectId(10), mapping(), 0x4000_0100),
            (
                ProcessViewId(7),
                PinnedObjectId(9),
                wrong_mapping,
                0x4000_0100,
            ),
            (ProcessViewId(7), PinnedObjectId(9), mapping(), 0x4000_0101),
        ] {
            assert!(
                registry
                    .validate_hit(id.case_id(), view, loader, &map, hook_ip, 5)
                    .is_err()
            );
        }
        assert_eq!(registry.context_failures(), 4);
        assert_eq!(registry.context(id).unwrap().earliest_hit_ns, None);

        registry
            .validate_hit(
                id.case_id(),
                ProcessViewId(7),
                PinnedObjectId(9),
                &mapping(),
                0x4000_0100,
                50,
            )
            .unwrap();
        registry
            .validate_hit(
                id.case_id(),
                ProcessViewId(7),
                PinnedObjectId(9),
                &mapping(),
                0x4000_0100,
                40,
            )
            .unwrap();
        assert_eq!(registry.context(id).unwrap().earliest_hit_ns, Some(40));
    }
}
