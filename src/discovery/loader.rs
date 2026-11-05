//! SPDX-License-Identifier: GPL-3.0-or-later
#[cfg(test)]
use p11scope_ebpf_common::{LOADER_CONTEXT_ID_MASK, valid_loader_cookie};
use p11scope_ebpf_common::{
    LOADER_STATE_ABSENT_SENTINEL, LOADER_STATE_PRESENT, LOADER_STATE_SHIFT,
};
use p11scope_manifest::elf::SymbolFact;
use p11scope_manifest::maps::MapEntry;

use crate::discovery::identity::{PinnedObjectId, PinnedObjects};
use crate::process::ProcessViewId;

use super::loader_lifetime::{
    LoaderToken, decode_loader_cookie as decode_token_cookie, loader_attach_cookie,
};

pub(crate) const MAX_LOADER_CONTEXTS: usize = 256;
/// Generation pinned by the pre-reuse token adapter: production allocation
/// issues each context exactly once and never recycles storage, so every
/// allocated context is its slot's first incarnation.
// Staged until reuse activation wires the adapter; only tests use it now.
#[allow(dead_code)]
pub(crate) const LOADER_ADAPTER_GENERATION: u32 = 1;
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
    /// Existing-view contexts freeze a mapped range. A direct-ELF pre-exec
    /// context deliberately leaves the future load base unbound and validates
    /// the actual mapping from the first record instead.
    pub(crate) mapping: Option<MapEntry>,
    pub(crate) hook: SymbolFact,
    pub(crate) state_address: Option<u64>,
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
    expected_hook_ip: Option<u64>,
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
    /// Heap slot table: 256 entries (~43 KiB) that must never sit in a
    /// construction frame. `Engine`/`InventoryCoordinator` move by value
    /// through deep `new` chains on small stacks, and every by-value
    /// copy would carry this table.
    contexts: Box<[Option<LoaderContext>; MAX_LOADER_CONTEXTS]>,
    allocated: usize,
    discovery_truncated: u64,
    context_failures: u64,
    #[cfg(test)]
    attempt_ledger: std::cell::RefCell<AttemptLedger>,
}

impl Default for LoaderRegistry {
    fn default() -> Self {
        // Fill on the heap: `Box::new(from_fn(..))` would still build the
        // table on this frame before moving it into the box.
        let contexts: Box<[Option<LoaderContext>; MAX_LOADER_CONTEXTS]> =
            vec![Option::<LoaderContext>::None; MAX_LOADER_CONTEXTS]
                .into_boxed_slice()
                .try_into()
                .expect("loader slot table holds exactly MAX_LOADER_CONTEXTS entries");
        Self {
            contexts,
            allocated: 0,
            discovery_truncated: 0,
            context_failures: 0,
            #[cfg(test)]
            attempt_ledger: std::cell::RefCell::new(AttemptLedger::default()),
        }
    }
}

impl LoaderRegistry {
    /// Computes every finite context/cookie requirement without changing registry state.
    pub(crate) fn preflight(
        &self,
        spec: LoaderContextSpec,
    ) -> Result<PreparedLoaderContext, String> {
        #[cfg(test)]
        let pending = self.take_pending_attempt();
        #[cfg(test)]
        let view = spec.view;
        let result = self.preflight_checked(spec);
        #[cfg(test)]
        self.push_attempt(
            LoaderAttemptKind::Preflight,
            pending,
            Some(view),
            result.as_ref().ok().map(|prepared| prepared.id),
            result.as_ref().err().cloned(),
        );
        result
    }

    fn preflight_checked(&self, spec: LoaderContextSpec) -> Result<PreparedLoaderContext, String> {
        if self.allocated == MAX_LOADER_CONTEXTS {
            return Err("loader context capacity 256 is exhausted".into());
        }
        let expected_hook_ip = spec
            .mapping
            .as_ref()
            .map(|mapping| expected_hook_ip(mapping, spec.hook.file_offset))
            .transpose()?;
        let state_delta = spec
            .state_address
            .map(|state| signed_delta(state, spec.hook.virtual_address))
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
        #[cfg(test)]
        let pending = self.take_pending_attempt();
        #[cfg(test)]
        let view = prepared.context.spec.view;
        let result = self.prepare_checked(prepared);
        #[cfg(test)]
        {
            let (context_id, refusal) = match &result {
                Ok(id) => (Some(*id), None),
                Err(reason) => (None, Some(reason.clone())),
            };
            self.push_attempt(
                LoaderAttemptKind::Prepare,
                pending,
                Some(view),
                context_id,
                refusal,
            );
        }
        result
    }

    fn prepare_checked(
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

    pub(crate) fn attached_contexts(
        &self,
    ) -> impl Iterator<Item = (LoaderContextId, &LoaderContext)> {
        self.contexts
            .iter()
            .enumerate()
            .filter_map(|(index, context)| {
                context
                    .as_ref()
                    .filter(|context| context.state == LoaderContextState::Attached)
                    .map(|context| (LoaderContextId((index + 1) as u16), context))
            })
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
        #[cfg(test)]
        let pending = self.take_pending_attempt();
        #[cfg(test)]
        let view = self.context(id).map(|context| context.spec.view);
        let result = self.remove_checked(id);
        #[cfg(test)]
        {
            let (context_id, refusal) = match &result {
                Ok(()) => (Some(id), None),
                Err(reason) => (None, Some(reason.clone())),
            };
            self.push_attempt(
                LoaderAttemptKind::Remove,
                pending,
                view,
                context_id,
                refusal,
            );
        }
        result
    }

    fn remove_checked(&mut self, id: LoaderContextId) -> Result<(), String> {
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
                && context
                    .spec
                    .mapping
                    .as_ref()
                    .is_none_or(|expected| expected == mapping)
                && context.expected_hook_ip.map_or_else(
                    || {
                        expected_hook_ip(mapping, context.spec.hook.file_offset).ok()
                            == Some(hook_ip)
                    },
                    |expected| expected == hook_ip,
                )
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

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoaderAttemptOwner {
    Owned,
    Ambient,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoaderAttemptKind {
    Preflight,
    Prepare,
    Remove,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoaderAttempt {
    pub(crate) ordinal: usize,
    pub(crate) kind: LoaderAttemptKind,
    pub(crate) pid: Option<u32>,
    pub(crate) owner: Option<LoaderAttemptOwner>,
    pub(crate) view: Option<ProcessViewId>,
    pub(crate) context_id: Option<LoaderContextId>,
    pub(crate) refusal: Option<String>,
    pub(crate) truncated_delta: u64,
    pub(crate) failures_delta: u64,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoaderPrepareReason {
    Initial,
    Rearm,
    Readmit,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
struct PendingAttempt {
    pid: u32,
    owner: LoaderAttemptOwner,
    truncated_delta: u64,
    failures_delta: u64,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct AttemptLedger {
    entries: Vec<LoaderAttempt>,
    pending: Option<PendingAttempt>,
}

#[cfg(test)]
impl LoaderRegistry {
    fn take_pending_attempt(&self) -> Option<PendingAttempt> {
        self.attempt_ledger.borrow_mut().pending.take()
    }

    fn push_attempt(
        &self,
        kind: LoaderAttemptKind,
        pending: Option<PendingAttempt>,
        view: Option<ProcessViewId>,
        context_id: Option<LoaderContextId>,
        refusal: Option<String>,
    ) {
        let mut ledger = self.attempt_ledger.borrow_mut();
        let ordinal = ledger.entries.len() + 1;
        let (pid, owner, truncated_delta, failures_delta) = match pending {
            Some(context) => (
                Some(context.pid),
                Some(context.owner),
                context.truncated_delta,
                context.failures_delta,
            ),
            None => (None, None, 0, 0),
        };
        ledger.entries.push(LoaderAttempt {
            ordinal,
            kind,
            pid,
            owner,
            view,
            context_id,
            refusal,
            truncated_delta,
            failures_delta,
        });
    }

    pub(crate) fn set_next_attempt(
        &self,
        pid: u32,
        owned: bool,
        truncated_delta: u64,
        failures_delta: u64,
    ) {
        let owner = if owned {
            LoaderAttemptOwner::Owned
        } else {
            LoaderAttemptOwner::Ambient
        };
        self.attempt_ledger.borrow_mut().pending = Some(PendingAttempt {
            pid,
            owner,
            truncated_delta,
            failures_delta,
        });
    }

    pub(crate) fn attempts(&self) -> Vec<LoaderAttempt> {
        self.attempt_ledger.borrow().entries.clone()
    }

    pub(crate) fn successful_prepare_count(&self) -> usize {
        self.attempt_ledger
            .borrow()
            .entries
            .iter()
            .filter(|entry| entry.kind == LoaderAttemptKind::Prepare && entry.refusal.is_none())
            .count()
    }

    pub(crate) fn prepare_reasons(&self) -> Vec<(usize, u32, LoaderPrepareReason)> {
        let ledger = self.attempt_ledger.borrow();
        let mut last_view: std::collections::HashMap<u32, ProcessViewId> =
            std::collections::HashMap::new();
        let mut reasons = Vec::new();
        for entry in ledger
            .entries
            .iter()
            .filter(|entry| entry.kind == LoaderAttemptKind::Prepare && entry.refusal.is_none())
        {
            let (Some(pid), Some(view)) = (entry.pid, entry.view) else {
                continue;
            };
            let reason = match last_view.get(&pid) {
                None => LoaderPrepareReason::Initial,
                Some(previous) if *previous == view => LoaderPrepareReason::Rearm,
                Some(_) => LoaderPrepareReason::Readmit,
            };
            last_view.insert(pid, view);
            reasons.push((entry.ordinal, pid, reason));
        }
        reasons
    }

    pub(crate) fn preflight_recorded(
        &mut self,
        spec: LoaderContextSpec,
        pid: u32,
        owned: bool,
        truncated_delta: u64,
        failures_delta: u64,
    ) -> Result<PreparedLoaderContext, String> {
        self.set_next_attempt(pid, owned, truncated_delta, failures_delta);
        self.preflight(spec)
    }

    pub(crate) fn prepare_recorded(
        &mut self,
        prepared: PreparedLoaderContext,
        pid: u32,
        owned: bool,
        truncated_delta: u64,
        failures_delta: u64,
    ) -> Result<LoaderContextId, String> {
        self.set_next_attempt(pid, owned, truncated_delta, failures_delta);
        self.prepare(prepared)
    }

    pub(crate) fn remove_recorded(
        &mut self,
        id: LoaderContextId,
        pid: u32,
        owned: bool,
        truncated_delta: u64,
        failures_delta: u64,
    ) -> Result<(), String> {
        self.set_next_attempt(pid, owned, truncated_delta, failures_delta);
        self.remove(id)
    }
}

// Staged pre-reuse token adapter: converts identities only, never delegates
// to the generation registry. Reuse activation wires it; until then only
// tests resolve through it.
#[allow(dead_code)]
impl LoaderRegistry {
    /// Token view of one allocated context. Generation is fixed at
    /// [`LOADER_ADAPTER_GENERATION`]; never-allocated and removed ids refuse
    /// without touching the registry.
    pub(crate) fn token_for(&self, id: LoaderContextId) -> Option<LoaderToken> {
        self.context(id)?;
        LoaderToken::new(LOADER_ADAPTER_GENERATION, (id.get() - 1) as u8)
    }

    /// Context view of one adapter token. Only generation-1 tokens for
    /// allocated storage resolve; every other token refuses.
    pub(crate) fn id_for_token(&self, token: LoaderToken) -> Option<LoaderContextId> {
        if token.generation() != LOADER_ADAPTER_GENERATION {
            return None;
        }
        let id = LoaderContextId::from_case_id(token.slot());
        self.context(id)?;
        Some(id)
    }

    /// T-L2c gate wire view: the attach cookie for one allocated context is
    /// exactly its adapter token bits. Never-allocated and removed ids
    /// refuse without touching the registry.
    pub(crate) fn attach_cookie_for(&self, id: LoaderContextId) -> Option<u64> {
        self.token_for(id).map(loader_attach_cookie)
    }

    /// T-L2c gate lookup view: only adapter token cookies for allocated
    /// storage resolve. Stale/foreign tokens, malformed cookies and
    /// old-format cookies refuse closed, except for the numeric twins in
    /// the collision set. Read as 40-bit `(generation << 8) | slot`
    /// tokens, every old-format absent cookie is a generation-2 token for
    /// its case slot, and every old-format present cookie with
    /// `0 <= delta < 2^31` is a generation-`2*delta+1` token for its case
    /// slot (even generations >= 4 have no old twin; negative or
    /// `>= 2^31` deltas overflow 40 bits and refuse). This adapter pins
    /// generation 1, so only the delta-0 twin resolves here, while its
    /// slot is allocated; the wider gate admits every generation and
    /// resolves every twin. The atomic cutover requires every old-format
    /// producer to drain first, not just delta-0 ones.
    pub(crate) fn id_for_attach_cookie(&self, cookie: u64) -> Option<LoaderContextId> {
        self.id_for_token(decode_token_cookie(cookie)?)
    }
}

fn expected_hook_ip(mapping: &MapEntry, hook_file_offset: u64) -> Result<u64, String> {
    if mapping.permissions[2] != b'x' || mapping.inode == 0 {
        return Err("loader hook mapping is not a file-backed executable mapping".into());
    }
    let hook_delta = hook_file_offset
        .checked_sub(mapping.file_offset)
        .ok_or_else(|| "loader hook file offset precedes its mapping".to_string())?;
    mapping
        .start
        .checked_add(hook_delta)
        .filter(|ip| *ip < mapping.end)
        .ok_or_else(|| "loader hook IP is outside its mapping".to_string())
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
    use crate::discovery::loader_lifetime::{LifetimeDomain, LifetimeRegistry};
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
            mapping: Some(mapping()),
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            state_address: state_vaddr,
        }
    }

    fn prepare(registry: &mut LoaderRegistry, spec: LoaderContextSpec) -> LoaderContextId {
        let prepared = registry.preflight(spec).unwrap();
        registry.prepare(prepared).unwrap()
    }

    fn spec_with_view(view: ProcessViewId) -> LoaderContextSpec {
        LoaderContextSpec {
            view,
            loader: PinnedObjectId(9),
            mapping: Some(mapping()),
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            state_address: None,
        }
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

    #[test]
    fn preexec_context_validates_the_actual_future_mapping_without_a_load_base() {
        let mut registry = LoaderRegistry::default();
        let mut context = spec(None);
        context.mapping = None;
        let id = prepare(&mut registry, context);
        registry.mark_attached(id).unwrap();

        registry
            .validate_hit(
                id.case_id(),
                ProcessViewId(7),
                PinnedObjectId(9),
                &mapping(),
                0x4000_0100,
                5,
            )
            .unwrap();
        assert!(
            registry
                .validate_hit(
                    id.case_id(),
                    ProcessViewId(7),
                    PinnedObjectId(9),
                    &mapping(),
                    0x4000_0101,
                    6,
                )
                .is_err()
        );
    }

    #[test]
    fn loader_registry_token_adapter_resolves_generation_one_and_refuses_the_rest() {
        let mut registry = LoaderRegistry::default();
        let unallocated = LoaderContextId::from_case_id(0);
        assert_eq!(registry.token_for(unallocated), None);
        assert_eq!(registry.id_for_token(LoaderToken::new(1, 0).unwrap()), None);

        let id = prepare(&mut registry, spec(None));
        let token = registry
            .token_for(id)
            .expect("allocated context has a token");
        assert_eq!(token.generation(), LOADER_ADAPTER_GENERATION);
        assert_eq!(token.slot(), 0);
        assert_eq!(token.bits(), 0x100);
        assert_eq!(registry.id_for_token(token), Some(id));

        // Prepared, attached and tombstoned storage all resolve; only the
        // generation and the allocation are checked.
        registry.mark_attached(id).unwrap();
        assert_eq!(registry.token_for(id), Some(token));
        registry.tombstone(id).unwrap();
        assert_eq!(registry.id_for_token(token), Some(id));

        // Any other generation refuses, even for the allocated slot.
        assert_eq!(registry.id_for_token(LoaderToken::new(2, 0).unwrap()), None);
        // Generation-1 tokens past the allocation refuse.
        assert_eq!(registry.id_for_token(LoaderToken::new(1, 5).unwrap()), None);
        // Removed storage loses its token.
        registry.remove(id).unwrap();
        assert_eq!(registry.token_for(id), None);
        assert_eq!(registry.id_for_token(token), None);
    }

    #[test]
    fn loader_attach_cookie_gate_round_trips_only_allocated_storage() {
        // T-L2c gate healthy twin: the attach cookie is exactly the adapter
        // token bits, and only allocated storage resolves back.
        let mut registry = LoaderRegistry::default();
        let unallocated = LoaderContextId::from_case_id(0);
        assert_eq!(registry.attach_cookie_for(unallocated), None);
        assert_eq!(registry.id_for_attach_cookie(0x100), None);

        let id = prepare(&mut registry, spec(None));
        let cookie = registry
            .attach_cookie_for(id)
            .expect("allocated context has an attach cookie");
        assert_eq!(cookie, 0x100);
        assert_eq!(registry.id_for_attach_cookie(cookie), Some(id));

        // Prepared, attached and tombstoned storage all resolve; only the
        // generation and the allocation are checked.
        registry.mark_attached(id).unwrap();
        assert_eq!(registry.attach_cookie_for(id), Some(cookie));
        registry.tombstone(id).unwrap();
        assert_eq!(registry.id_for_attach_cookie(cookie), Some(id));

        // Removed storage loses its cookie.
        registry.remove(id).unwrap();
        assert_eq!(registry.attach_cookie_for(id), None);
        assert_eq!(registry.id_for_attach_cookie(cookie), None);
    }

    #[test]
    fn loader_attach_cookie_gate_refuses_stale_foreign_and_old_format() {
        // T-L2c gate failure twins: stale/foreign tokens, malformed cookies
        // and old-format cookies refuse closed.
        let mut registry = LoaderRegistry::default();
        let id = prepare(&mut registry, spec(None));
        let cookie = registry.attach_cookie_for(id).unwrap();
        assert_eq!(cookie, 0x100);

        // Any other generation refuses, even for the allocated slot.
        let stale = LoaderToken::new(2, 0).unwrap().bits();
        assert_eq!(registry.id_for_attach_cookie(stale), None);
        // Generation-1 tokens past the allocation refuse.
        let foreign = LoaderToken::new(1, 5).unwrap().bits();
        assert_eq!(registry.id_for_attach_cookie(foreign), None);
        // Malformed cookies refuse: zero, generation zero, over 40 bits.
        for malformed in [0, 5, 0xff, 1 << 40, u64::MAX] {
            assert_eq!(registry.id_for_attach_cookie(malformed), None);
        }
        // Old-format absent cookies refuse (generation 2, never adapter 1).
        let old_absent = encode_loader_cookie(1, None).unwrap();
        assert_eq!(old_absent, 0x200);
        assert_eq!(registry.id_for_attach_cookie(old_absent), None);
        // Old-format present cookies with a nonzero delta refuse.
        let old_delta = encode_loader_cookie(1, Some(5)).unwrap();
        assert_eq!(old_delta, 0xb00);
        assert_eq!(registry.id_for_attach_cookie(old_delta), None);
    }

    #[test]
    fn loader_attach_cookie_old_format_delta_zero_is_a_generation_one_twin() {
        // Quiescence obligation, pinned: an old-format present cookie with a
        // zero delta is numerically identical to the generation-1 adapter
        // token for the same case, so the atomic cutover is only safe after
        // every old-format producer has drained through an owned disposition.
        assert_eq!(encode_loader_cookie(1, Some(0)).unwrap(), 0x100);
        assert_eq!(encode_loader_cookie(3, Some(0)).unwrap(), 0x102);
        assert_eq!(
            LoaderToken::new(1, 0).unwrap().bits(),
            encode_loader_cookie(1, Some(0)).unwrap()
        );
        assert_eq!(
            LoaderToken::new(1, 2).unwrap().bits(),
            encode_loader_cookie(3, Some(0)).unwrap()
        );

        let mut registry = LoaderRegistry::default();
        let id = prepare(&mut registry, spec(None));
        // While the twin slot is allocated, the old-format cookie resolves
        // through the token path: the gate cannot tell them apart.
        assert_eq!(registry.id_for_attach_cookie(0x100), Some(id));
    }

    #[test]
    fn loader_lifetime_fresh_prepare_new_mints_generation_one_for_slot_zero() {
        // Generation-one premise, adapted to the crate-visible lifetime
        // API: the loader-gate work stages identity through the token
        // adapter, but the generation registry still burns from zero, so
        // a fresh prepare mints generation 1 for slot 0.
        let domain = LifetimeDomain::mint();
        let mut registry = LifetimeRegistry::new(domain, 4096).unwrap();
        let token = registry.prepare_new(domain).unwrap();
        assert_eq!(token.generation(), 1);
        assert_eq!(token.slot(), 0);
        assert_eq!(token.bits(), 0x100);
    }

    #[test]
    fn loader_attempt_ledger_counts_match_allocation_across_allocate_refuse_remove() {
        let mut registry = LoaderRegistry::default();
        for pid in [100u32, 101] {
            let prepared = registry
                .preflight_recorded(spec(None), pid, true, 0, 0)
                .unwrap();
            registry
                .prepare_recorded(prepared, pid, true, 0, 0)
                .unwrap();
        }
        assert_eq!(registry.successful_prepare_count(), 2);
        assert_eq!(registry.allocated, 2);
        assert_eq!(registry.attempts().len(), 4);

        let first = registry
            .preflight_recorded(spec(None), 102, true, 1, 2)
            .unwrap();
        let stale = registry
            .preflight_recorded(spec(None), 102, true, 3, 4)
            .unwrap();
        registry.prepare_recorded(first, 102, true, 5, 6).unwrap();
        let refusal = registry
            .prepare_recorded(stale, 102, true, 7, 8)
            .unwrap_err();
        assert_eq!(
            refusal,
            "preflighted loader context no longer matches registry state"
        );
        assert_eq!(registry.successful_prepare_count(), 3);
        assert_eq!(registry.allocated, 3);
        assert_eq!(registry.attempts().len(), 8);
        let refused = registry.attempts().last().unwrap().clone();
        assert_eq!(refused.kind, LoaderAttemptKind::Prepare);
        assert_eq!(refused.refusal.as_deref(), Some(refusal.as_str()));
        assert_eq!(refused.pid, Some(102));
        assert_eq!(refused.owner, Some(LoaderAttemptOwner::Owned));
        assert_eq!(refused.truncated_delta, 7);
        assert_eq!(refused.failures_delta, 8);

        let id = LoaderContextId::from_case_id(0);
        let remove_refusal = registry.remove_recorded(id, 100, true, 9, 10).unwrap_err();
        assert!(
            remove_refusal.contains("not tombstoned"),
            "{remove_refusal}"
        );
        assert_eq!(registry.attempts().len(), 9);
        registry.mark_attached(id).unwrap();
        registry.tombstone(id).unwrap();
        registry.remove_recorded(id, 100, true, 11, 12).unwrap();
        assert_eq!(registry.attempts().len(), 10);
        assert_eq!(registry.successful_prepare_count(), 3);
        assert_eq!(registry.allocated, 3);
        let removed = registry.attempts().last().unwrap().clone();
        assert_eq!(removed.kind, LoaderAttemptKind::Remove);
        assert_eq!(removed.refusal, None);
        assert_eq!(removed.context_id, Some(id));
    }

    #[test]
    fn loader_attempt_ledger_ordinals_are_gapless_from_one() {
        let mut registry = LoaderRegistry::default();
        let prepared = registry
            .preflight_recorded(spec(None), 200, true, 0, 0)
            .unwrap();
        let id = registry
            .prepare_recorded(prepared, 200, true, 0, 0)
            .unwrap();
        registry.mark_attached(id).unwrap();
        registry.tombstone(id).unwrap();
        registry.remove_recorded(id, 200, true, 0, 0).unwrap();
        let _ = registry.remove_recorded(id, 200, true, 0, 0).unwrap_err();
        let ordinals: Vec<usize> = registry
            .attempts()
            .iter()
            .map(|entry| entry.ordinal)
            .collect();
        assert_eq!(ordinals, vec![1, 2, 3, 4]);
    }

    #[test]
    fn loader_attempt_ledger_refuses_257th_owned_prepare_with_capacity_reason() {
        let mut registry = LoaderRegistry::default();
        for ordinal in 0..MAX_LOADER_CONTEXTS {
            let pid = 1000 + ordinal as u32;
            let prepared = registry
                .preflight_recorded(spec(None), pid, true, 0, 0)
                .expect("envelope fill must preflight below capacity");
            registry
                .prepare_recorded(prepared, pid, true, 0, 0)
                .expect("envelope fill must prepare");
        }
        assert_eq!(registry.successful_prepare_count(), 256);
        assert_eq!(registry.allocated, 256);
        assert_eq!(registry.attempts().len(), 512);
        let refusal = registry
            .preflight_recorded(spec(None), 2000, true, 13, 17)
            .unwrap_err();
        assert_eq!(refusal, "loader context capacity 256 is exhausted");
        assert_eq!(registry.successful_prepare_count(), 256);
        assert_eq!(registry.allocated, 256);
        assert_eq!(registry.attempts().len(), 513);
        let refused = registry.attempts().last().unwrap().clone();
        assert_eq!(refused.ordinal, 513);
        assert_eq!(refused.kind, LoaderAttemptKind::Preflight);
        assert_eq!(refused.refusal.as_deref(), Some(refusal.as_str()));
        assert_eq!(refused.pid, Some(2000));
        assert_eq!(refused.owner, Some(LoaderAttemptOwner::Owned));
        assert_eq!(refused.truncated_delta, 13);
        assert_eq!(refused.failures_delta, 17);
    }

    #[test]
    fn loader_attempt_ledger_derives_initial_rearm_readmit_per_pid() {
        let mut registry = LoaderRegistry::default();
        let view_a = ProcessViewId(7);
        let view_b = ProcessViewId(8);
        let view_c = ProcessViewId(9);
        let cases = [
            (100u32, view_a, true),
            (100, view_a, true),
            (100, view_b, true),
            (200, view_c, false),
        ];
        for (index, (pid, view, owned)) in cases.iter().enumerate() {
            let prepared = registry
                .preflight_recorded(
                    spec_with_view(*view),
                    *pid,
                    *owned,
                    index as u64,
                    index as u64 + 100,
                )
                .unwrap();
            registry
                .prepare_recorded(prepared, *pid, *owned, index as u64 + 1, index as u64 + 101)
                .unwrap();
        }
        assert_eq!(
            registry.prepare_reasons(),
            vec![
                (2, 100, LoaderPrepareReason::Initial),
                (4, 100, LoaderPrepareReason::Rearm),
                (6, 100, LoaderPrepareReason::Readmit),
                (8, 200, LoaderPrepareReason::Initial),
            ]
        );
        let attempts = registry.attempts();
        assert_eq!(attempts.len(), 8);
        assert_eq!(attempts[1].pid, Some(100));
        assert_eq!(attempts[1].owner, Some(LoaderAttemptOwner::Owned));
        assert_eq!(attempts[1].view, Some(view_a));
        assert_eq!(attempts[1].truncated_delta, 1);
        assert_eq!(attempts[1].failures_delta, 101);
        assert_eq!(attempts[7].pid, Some(200));
        assert_eq!(attempts[7].owner, Some(LoaderAttemptOwner::Ambient));
        assert_eq!(attempts[7].view, Some(view_c));
    }
}
