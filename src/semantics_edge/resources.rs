//! SPDX-License-Identifier: GPL-3.0-or-later
//! Capture-wide S1 allocation charges. This is a requested-allocation
//! envelope on the pinned Rust x86-64 implementation, never an RSS limit.
//! One registry owns the pool; reducers retain move-only leases from it.

use std::sync::{Arc, Mutex};

// Compiler host metadata is validated by build.rs; target ABI is a separate
// guard. Both supported x86-64 Linux libc targets use this alloc layout.
#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64",
    any(target_env = "gnu", target_env = "musl")
)))]
compile_error!("semantic allocation charges require revalidation for this target ABI");
const _: &str = env!("P11SCOPE_SEMANTIC_RUSTC_PROOF");

// Pinned Rust1.99.1 alloc source, not portable BTreeMap folklore:
// https://github.com/rust-lang/rust/blob/1.99.1/library/alloc/src/collections/btree/node.rs
// B=6, capacity11; LeafNode parent pointer+u16 index+u16 len occupies16B;
// InternalNode adds12 pointers. Every key/value here aligns at most8.
// map.rs maintains >=5 keys in non-root nodes; thus a nonempty tree has
// no more nodes than entries. Charging one full internal node per entry
// dominates retained nodes; base covers each potentially empty root.
const fn internal_node<K, V>() -> usize {
    16 + 11 * (std::mem::size_of::<K>() + std::mem::size_of::<V>()) + 12 * 8
}
const fn leaf_node<K, V>() -> usize {
    internal_node::<K, V>() - 12 * 8
}

const OPEN_NODE: usize = internal_node::<u64, u64>();
const ACTIVE_NODE: usize = internal_node::<(u64, u16), super::OpMachine>();
const MECHANISM_NODE: usize = internal_node::<u64, super::EdgeMechStat>();
const PENDING_NODE: usize = internal_node::<(u64, u32), super::PendingCall>();
const DETACHED_NODE: usize = internal_node::<(u64, u32, u64), super::AsyncId>();
const CATEGORY_NODE: usize = internal_node::<&'static str, ()>();
const FUNCTION_NODE: usize = internal_node::<String, ()>();
const RETURN_NODE: usize = internal_node::<u64, ()>();

const _: () = {
    assert!(std::mem::align_of::<super::EdgeSemantics>() == 8);
    assert!(std::mem::align_of::<super::PendingCall>() == 8);
    assert!(std::mem::align_of::<super::AsyncId>() == 8);
    assert!(std::mem::size_of::<super::SemanticCall>() == 96);
    // H9 stores the machine's fixed key receipt (56 = 32 + 24 for
    // niche-filled `Option<KeyReceipt>`); the machine charge below
    // still dominates the node plus entry.
    assert!(std::mem::size_of::<super::OpMachine>() == 64);
    assert!(std::mem::size_of::<super::EdgeMechStat>() == 104);
    // Final lease-bearing layouts, rather than the earlier probe types.
    assert!(std::mem::size_of::<super::PendingCall>() == 144);
    assert!(std::mem::size_of::<super::AsyncId>() == 160);
    assert!(std::mem::size_of::<ResourceLease>() == 16);
    assert!(std::mem::align_of::<crate::inventory_semantics::SemanticProviderTarget>() <= 8);
    assert!(std::mem::size_of::<crate::inventory_semantics::SemanticProviderTarget>() <= 1024);
    assert!(std::mem::size_of::<(u16, Option<u64>)>() == 24);
    assert!(std::mem::size_of::<String>() == 24);
    // H9 adds the `id_exhaustions` u64 (368 = 360 + 8); the base
    // charge below still dominates the struct plus empty roots.
    assert!(std::mem::size_of::<super::EdgeSemantics>() == 368);
    assert!(OPEN_NODE + 32 <= OPEN_BINDING_CHARGE);
    assert!(ACTIVE_NODE + 32 <= ACTIVE_MACHINE_CHARGE);
    assert!(MECHANISM_NODE + 32 <= MECHANISM_CHARGE);
    assert!(PENDING_NODE + 32 <= ASYNC_FACT_CHARGE);
    assert!(DETACHED_NODE + 32 <= ASYNC_FACT_CHARGE);
    assert!(CATEGORY_NODE + 32 <= CATEGORY_CHARGE);
    assert!(FUNCTION_NODE + 32 <= FUNCTION_CHARGE);
    assert!(RETURN_NODE + 32 <= RETURN_CHARGE);
    let empty_roots = leaf_node::<u64, u64>()
        + leaf_node::<(u64, u16), super::OpMachine>()
        + leaf_node::<u64, super::EdgeMechStat>()
        + leaf_node::<(u64, u32), super::PendingCall>()
        + leaf_node::<(u64, u32, u64), super::AsyncId>();
    assert!(
        std::mem::size_of::<super::EdgeSemantics>() + empty_roots + 5 * 32 <= REDUCER_BASE_CHARGE
    );
};

// One serialized scratch reservation covers all overlapping transition
// temporaries. Source: set.rs FromIterator collects and stable-sorts a Vec;
// map.rs/append.rs bulk_push builds/fixes the tree's right border; raw_vec
// grows capacity by max(2*old,required); slice/sort/stable/mod.rs chooses
// max(n-n/2,min(n,8_000_000/size(T)),48) scratch, bounded here by4096 u64s.
// These sources are pinned to the same1.99.1 source directory as node.rs.
// <=2048 active+256 total async owners can be unproven. Count all below
// together, even when phases cannot overlap, and include old+new Vec
// requests during realloc. A <=2304-key B-tree's minimum occupancy5
// limits height to4; eight largest-node requests cover split/right-border
// chains. No temporary carries an unbounded copied name or origin vector.
pub(super) const SCRATCH_PROVEN_BYTES: usize = 2304 * 256                         // owner BTreeSet nodes incl32B padding
    + (2048 + 4096) * 8 + 2 * 32     // collected owner Vec old+new
    + 4096 * 8 + 32                  // stable-sort scratch
    + (512 + 1024) * 8 + 2 * 32      // proven-session Vec old+new
    + (1024 + 2048) * 16 + 2 * 32    // nested doomed machine Vec old+new
    + 8 * 4096                       // largest node split/right-border chain
    + 16 * 256                       // bounded touched-mechanism temporary set
    + 16 * 24 + 32                   // maximum operation-bit origin temporary
    // Cgroup's bounded four-slot owner preparation Vec can coexist with
    // reduction. Charge the final real candidate/receipt/provider/lease type,
    // including empty or refused slots. Provider-owned copied strings and
    // accepted boxed capacity have separate persistent leases.
    + 4 * std::mem::size_of::<(
        crate::discovery::engine::inventory_coordinator::semantics::SemanticAdmissionCandidate,
        crate::inventory_semantics::PreparedSemanticAdmission,
    )>() + 32
    + 4096; // fixed padding/stack-independent slack
const _: () = assert!(SCRATCH_PROVEN_BYTES <= SEMANTIC_TRANSITION_SCRATCH);

pub(crate) const SEMANTIC_RESOURCE_LIMIT: usize = 64 * 1024 * 1024;
pub(crate) const SEMANTIC_TRANSITION_SCRATCH: usize = 1024 * 1024;
pub(crate) const REDUCER_BASE_CHARGE: usize = 8192;
pub(crate) const OPEN_BINDING_CHARGE: usize = 512;
pub(crate) const ACTIVE_MACHINE_CHARGE: usize = 1024;
pub(crate) const ASYNC_FACT_CHARGE: usize = 4096;
pub(crate) const MECHANISM_CHARGE: usize = 2048;
pub(crate) const CATEGORY_CHARGE: usize = 512;
pub(crate) const FUNCTION_CHARGE: usize = 512;
pub(crate) const RETURN_CHARGE: usize = 256;
pub(crate) const OWNED_ALLOCATION_PADDING: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SemanticResourceSnapshot {
    pub limit_bytes: usize,
    pub charged_bytes: usize,
    pub peak_charged_bytes: usize,
    pub refused: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SemanticResourceRefusal {
    pub limit_bytes: usize,
    pub requested_bytes: usize,
}

struct SharedPool {
    limit: usize,
    charged: usize,
    peak: usize,
    refused: u64,
    scratch_borrowed: bool,
}

/// No Clone: replacing the registry owner does not mint another budget.
pub(crate) struct SemanticResourcePool {
    shared: Arc<Mutex<SharedPool>>,
}

/// A reservation handle on the registry's existing pool, never a new budget.
pub(crate) struct SemanticResourceReserver {
    shared: Arc<Mutex<SharedPool>>,
}

impl SemanticResourceReserver {
    pub(crate) fn reserve(&self, bytes: usize) -> Result<ResourceLease, SemanticResourceRefusal> {
        ResourceLease::acquire(&self.shared, bytes)
    }

    /// Checks this lease's live charge in the original pool without changing it.
    /// Coverage alone grants no input identity or native mutation authority.
    pub(crate) fn covers(&self, lease: &ResourceLease, required_bytes: usize) -> bool {
        Arc::ptr_eq(&self.shared, &lease.shared) && lease.bytes >= required_bytes
    }
}

impl Default for SemanticResourcePool {
    fn default() -> Self {
        Self::new(SEMANTIC_RESOURCE_LIMIT)
    }
}

impl SemanticResourcePool {
    pub(crate) fn reserver(&self) -> SemanticResourceReserver {
        SemanticResourceReserver {
            shared: Arc::clone(&self.shared),
        }
    }

    #[cfg(test)]
    pub(crate) fn reference_set_limit(&self, limit: usize) {
        let mut state = self
            .shared
            .lock()
            .expect("resource locks never hold callbacks");
        assert!(
            limit >= state.charged,
            "a test limit cannot discard existing charges"
        );
        state.limit = limit;
    }

    fn new(limit: usize) -> Self {
        assert!(limit >= SEMANTIC_TRANSITION_SCRATCH);
        Self {
            shared: Arc::new(Mutex::new(SharedPool {
                limit,
                charged: SEMANTIC_TRANSITION_SCRATCH,
                peak: SEMANTIC_TRANSITION_SCRATCH,
                refused: 0,
                scratch_borrowed: false,
            })),
        }
    }

    #[cfg(test)]
    pub(crate) fn reference_limit(limit: usize) -> Self {
        Self::new(limit)
    }

    pub(crate) fn snapshot(&self) -> SemanticResourceSnapshot {
        self.shared
            .lock()
            .expect("resource locks never hold callbacks")
            .snapshot()
    }

    pub(crate) fn reserve(&self, bytes: usize) -> Result<ResourceLease, SemanticResourceRefusal> {
        ResourceLease::acquire(&self.shared, bytes)
    }
}

impl SharedPool {
    fn snapshot(&self) -> SemanticResourceSnapshot {
        SemanticResourceSnapshot {
            limit_bytes: self.limit,
            charged_bytes: self.charged,
            peak_charged_bytes: self.peak,
            refused: self.refused,
        }
    }

    fn refuse(&mut self, requested_bytes: usize) -> SemanticResourceRefusal {
        self.refused = self.refused.saturating_add(1);
        SemanticResourceRefusal {
            limit_bytes: self.limit,
            requested_bytes,
        }
    }
}

/// The only persistent charge owner. In particular an async lease will move
/// with its original call through pending, detached and local completion.
/// No Clone/Copy or scalar constructor can duplicate its ownership.
pub(crate) struct ResourceLease {
    shared: Arc<Mutex<SharedPool>>,
    bytes: usize,
}

impl std::fmt::Debug for ResourceLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceLease")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl ResourceLease {
    fn acquire(
        shared: &Arc<Mutex<SharedPool>>,
        bytes: usize,
    ) -> Result<Self, SemanticResourceRefusal> {
        let mut state = shared.lock().expect("resource locks never hold callbacks");
        let requested = state
            .charged
            .checked_add(bytes)
            .ok_or_else(|| state.refuse(usize::MAX))?;
        if requested > state.limit {
            return Err(state.refuse(requested));
        }
        state.charged = requested;
        state.peak = state.peak.max(requested);
        Ok(Self {
            shared: Arc::clone(shared),
            bytes,
        })
    }

    pub(super) fn reserve(&self, bytes: usize) -> Result<Self, SemanticResourceRefusal> {
        Self::acquire(&self.shared, bytes)
    }

    pub(super) fn split(&mut self, bytes: usize) -> Self {
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .expect("preflight covers growth");
        Self {
            shared: Arc::clone(&self.shared),
            bytes,
        }
    }

    pub(super) fn absorb(&mut self, mut lease: Self) {
        assert!(Arc::ptr_eq(&self.shared, &lease.shared));
        self.bytes = self
            .bytes
            .checked_add(lease.bytes)
            .expect("bounded pool charge");
        lease.bytes = 0;
    }

    pub(super) fn release(&mut self, bytes: usize) {
        self.bytes = self.bytes.checked_sub(bytes).expect("owned live charge");
        let mut state = self
            .shared
            .lock()
            .expect("resource locks never hold callbacks");
        state.charged = state.charged.checked_sub(bytes).expect("owned pool charge");
    }

    pub(super) fn scratch(&self) -> Result<ScratchLease, SemanticResourceRefusal> {
        let mut state = self
            .shared
            .lock()
            .expect("resource locks never hold callbacks");
        if state.scratch_borrowed {
            let charged = state.charged;
            return Err(state.refuse(charged));
        }
        state.scratch_borrowed = true;
        Ok(ScratchLease {
            shared: Arc::clone(&self.shared),
        })
    }
}

impl Drop for ResourceLease {
    fn drop(&mut self) {
        #[cfg(test)]
        REFUND_OBSERVER.with(|observer| {
            if let Some(observe) = observer.get() {
                observe(self.bytes);
            }
        });
        let mut state = self
            .shared
            .lock()
            .expect("resource locks never hold callbacks");
        state.charged = state
            .charged
            .checked_sub(self.bytes)
            .expect("each charge lease returns its own bytes once");
    }
}

#[cfg(test)]
thread_local! {
    static REFUND_OBSERVER: std::cell::Cell<Option<fn(usize)>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) fn observe_refunds(run: impl FnOnce(), observe: fn(usize)) {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            REFUND_OBSERVER.with(|observer| observer.set(None));
        }
    }
    REFUND_OBSERVER.with(|observer| {
        assert!(observer.get().is_none());
        observer.set(Some(observe));
    });
    let guard = Guard;
    run();
    drop(guard);
}

/// The pool's permanently reserved scratch may be used by one transition.
/// The private move-only guard prevents overlapping users, including two
/// different reducers sharing the registry's pool.
pub(super) struct ScratchLease {
    shared: Arc<Mutex<SharedPool>>,
}

impl Drop for ScratchLease {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .lock()
            .expect("resource locks never hold callbacks");
        assert!(state.scratch_borrowed);
        state.scratch_borrowed = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserver_coverage_rejects_foreign_or_insufficient_live_lease() {
        let pool = SemanticResourcePool::reference_limit(SEMANTIC_TRANSITION_SCRATCH + 4096);
        let foreign = SemanticResourcePool::reference_limit(SEMANTIC_TRANSITION_SCRATCH + 4096);
        let reserver = pool.reserver();
        let lease = reserver.reserve(256).unwrap();
        let foreign_lease = foreign.reserve(256).unwrap();
        let before = pool.snapshot();
        let foreign_before = foreign.snapshot();

        assert!(reserver.covers(&lease, 0));
        assert!(reserver.covers(&lease, 256));
        assert!(pool.reserver().covers(&lease, 256));
        assert!(!reserver.covers(&lease, 257));
        assert!(!reserver.covers(&lease, usize::MAX));
        assert!(!reserver.covers(&foreign_lease, 256));
        assert!(!reserver.covers(&foreign_lease, 0));
        assert!(!foreign.reserver().covers(&lease, 256));
        assert_eq!(pool.snapshot(), before);
        assert_eq!(foreign.snapshot(), foreign_before);
    }

    #[test]
    fn reserver_coverage_follows_split_and_refund_without_borrowing_other_charge() {
        let pool = SemanticResourcePool::reference_limit(SEMANTIC_TRANSITION_SCRATCH + 4096);
        let reserver = pool.reserver();
        let base = pool.snapshot().charged_bytes;
        let mut lease = reserver.reserve(256).unwrap();
        let child = lease.split(96);

        assert!(reserver.covers(&lease, 160));
        assert!(!reserver.covers(&lease, 161));
        assert!(reserver.covers(&child, 96));
        assert!(!reserver.covers(&child, 97));
        assert_eq!(pool.snapshot().charged_bytes, base + 256);
        drop(child);
        assert_eq!(pool.snapshot().charged_bytes, base + 160);
        lease.release(32);
        assert!(reserver.covers(&lease, 128));
        assert!(!reserver.covers(&lease, 129));
        assert_eq!(pool.snapshot().charged_bytes, base + 128);
        drop(lease);
        assert_eq!(pool.snapshot().charged_bytes, base);
    }

    #[test]
    fn pool_with_limit_charges_scratch_against_limit() {
        const LIMIT: usize = 256 * 1024 * 1024;
        let pool = SemanticResourcePool::with_limit(LIMIT);
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.limit_bytes, LIMIT);
        assert_eq!(snapshot.charged_bytes, SEMANTIC_TRANSITION_SCRATCH);
        assert_eq!(snapshot.peak_charged_bytes, SEMANTIC_TRANSITION_SCRATCH);
        assert_eq!(snapshot.refused, 0);
        let reserver = pool.reserver();
        let lease = reserver.reserve(1024).unwrap();
        assert_eq!(
            pool.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH + 1024
        );
        assert!(reserver.covers(&lease, 1024));
        assert!(!reserver.covers(&lease, 1025));
        drop(lease);
        assert_eq!(
            pool.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH
        );
        assert_eq!(
            pool.snapshot().peak_charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH + 1024
        );
    }

    #[test]
    fn pool_with_limit_refuses_beyond_limit_without_touching_charges() {
        let pool = SemanticResourcePool::with_limit(SEMANTIC_TRANSITION_SCRATCH + 1024);
        let reserver = pool.reserver();
        let lease = reserver.reserve(1024).unwrap();
        let charged = pool.snapshot().charged_bytes;
        assert_eq!(charged, SEMANTIC_TRANSITION_SCRATCH + 1024);
        let refusal = reserver.reserve(1).unwrap_err();
        assert_eq!(refusal.limit_bytes, SEMANTIC_TRANSITION_SCRATCH + 1024);
        assert_eq!(refusal.requested_bytes, charged + 1);
        assert_eq!(pool.snapshot().charged_bytes, charged);
        assert_eq!(pool.snapshot().refused, 1);
        let foreign = SemanticResourcePool::with_limit(SEMANTIC_TRANSITION_SCRATCH + 2048);
        let foreign_lease = foreign.reserver().reserve(512).unwrap();
        assert!(!reserver.covers(&foreign_lease, 0));
        assert!(!foreign.reserver().covers(&lease, 0));
        drop(lease);
        drop(foreign_lease);
        assert_eq!(
            pool.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH
        );
    }
}
