//! SPDX-License-Identifier: GPL-3.0-or-later
//! Capture-local retained executable receipts and event-time lookup.

use crate::attach::detailed_identity::{ProofSession, TraceProofUnknown, VerifiedTraceSeed};
use crate::semantics::ProcessKey;
use std::collections::BTreeMap;

pub(crate) type TraceIdentityUnknown = TraceProofUnknown;

pub(crate) struct TraceIdentityStore {
    owner: ProofSession,
    entries: BTreeMap<ProcessKey, TraceIdentityEntry>,
}

struct TraceIdentityEntry {
    receipt: VerifiedTraceSeed,
    invalid: Option<TraceIdentityUnknown>,
}

impl TraceIdentityStore {
    pub(crate) fn new(owner: ProofSession) -> Self {
        Self {
            owner,
            entries: BTreeMap::new(),
        }
    }

    pub(crate) fn admit(&mut self, receipt: VerifiedTraceSeed) -> Result<(), TraceIdentityUnknown> {
        if !self.owner.owns_verified(&receipt) {
            return Err(TraceIdentityUnknown::DomainMismatch);
        }
        // Rejected/duplicate receipts drop after the map mutation completes.
        // The store never holds a proof-ledger lock or an independent charge.
        match self.entries.entry(receipt.key()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(TraceIdentityEntry {
                    receipt,
                    invalid: None,
                });
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if let Some(reason) = entry.get().invalid {
                    Err(reason)
                } else if entry.get().receipt.identity() != receipt.identity() {
                    entry.get_mut().invalid = Some(TraceIdentityUnknown::ExecChanged);
                    Err(TraceIdentityUnknown::ExecChanged)
                } else {
                    // Keep the first image and its immutable eligibility boundary.
                    Ok(())
                }
            }
        }
    }

    pub(crate) fn lookup(&self, key: ProcessKey, event_ts_ns: u64) -> TraceExecutableView<'_> {
        let Some(entry) = self.entries.get(&key) else {
            return TraceExecutableView::unknown(TraceIdentityUnknown::NotSeeded);
        };
        if let Some(reason) = entry.invalid {
            return TraceExecutableView::unknown(reason);
        }
        if event_ts_ns == u64::MAX {
            return TraceExecutableView::unknown(TraceIdentityUnknown::Unreadable);
        }
        if event_ts_ns <= entry.receipt.eligible_after_ns() {
            return TraceExecutableView::unknown(TraceIdentityUnknown::AfterEvent);
        }
        TraceExecutableView {
            result: Ok(entry.receipt.path()),
        }
    }
}

#[derive(Debug)]
pub(crate) struct TraceExecutableView<'a> {
    result: Result<&'a str, TraceIdentityUnknown>,
}

impl<'a> TraceExecutableView<'a> {
    pub(crate) fn unknown(reason: TraceIdentityUnknown) -> Self {
        Self {
            result: Err(reason),
        }
    }

    pub(crate) fn path(&self) -> Option<&'a str> {
        self.result.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::engine::tests::detailed_proof_driver::{
        cgroup_verified_fixture, verified_conflicting_fixture, verified_duplicate_fixture,
        verified_fixture,
    };

    // Catches using either warm-up witness as the immutable event-time boundary,
    // PID-only lookup, and moving that boundary after delayed event delivery.
    #[test]
    fn cgroup_trace_bracket_store_uses_strict_sample_boundary_and_exact_key() {
        let (proof, receipt) = cgroup_verified_fixture();
        let key = receipt.key();
        assert!(proof.is_cgroup());
        assert_eq!(receipt.eligible_after_ns(), 106);
        let mut store = TraceIdentityStore::new(proof.clone());
        assert_eq!(store.lookup(key, 115).path(), None);
        assert_eq!(store.admit(receipt), Ok(()));
        for ts in [0, 101, 105, 106] {
            assert_eq!(
                store.lookup(key, ts).result,
                Err(TraceIdentityUnknown::AfterEvent)
            );
        }
        for ts in [107, 114, 1_000] {
            assert_eq!(store.lookup(key, ts).path(), Some("/owned/fixture"));
        }
        assert_eq!(
            store.lookup(key, u64::MAX).result,
            Err(TraceIdentityUnknown::Unreadable)
        );
        for foreign in [
            ProcessKey { exec_id: 1, ..key },
            ProcessKey {
                generation: 12,
                ..key
            },
            ProcessKey { domain: 8, ..key },
            ProcessKey::from_pid(key.pid),
        ] {
            assert_eq!(
                store.lookup(foreign, 115).result,
                Err(TraceIdentityUnknown::NotSeeded)
            );
        }
        assert_eq!(
            store
                .lookup(
                    ProcessKey {
                        pid: key.pid + 1,
                        ..key
                    },
                    115
                )
                .path(),
            Some("/owned/fixture")
        );
        assert_eq!(
            store.lookup(key, 106).result,
            Err(TraceIdentityUnknown::AfterEvent)
        );
        assert_eq!(proof.usage(), (1, 14));
        drop(store);
        assert_eq!(proof.usage(), (0, 0));
    }

    // Catches treating numeric key equality as receipt authority, or retaining
    // the foreign receipt's accepted-key metadata and reservation on refusal.
    #[test]
    fn cgroup_trace_bracket_store_rejects_foreign_receipt_and_releases_charge() {
        let (owner, first) = cgroup_verified_fixture();
        let (foreign, receipt) = cgroup_verified_fixture();
        let key = first.key();
        assert_eq!(receipt.key(), key);
        assert!(!owner.same_allocation(&foreign));
        let mut store = TraceIdentityStore::new(owner.clone());
        store.admit(first).unwrap();
        assert_eq!(
            store.admit(receipt),
            Err(TraceIdentityUnknown::DomainMismatch)
        );
        assert_eq!(foreign.usage(), (0, 0));
        assert_eq!(owner.usage(), (1, 14));
        assert_eq!(store.lookup(key, 115).path(), Some("/owned/fixture"));
        drop(store);
        assert_eq!(owner.usage(), (0, 0));
    }

    // Catches PID-indexed/successor lookup and failure to retain a real receipt.
    #[test]
    fn trace_identity_exact_image_lookup() {
        let (proof, receipt) = verified_fixture();
        let key = receipt.key();
        let mut store = TraceIdentityStore::new(proof);
        assert_eq!(store.admit(receipt), Ok(()));
        assert_eq!(store.lookup(key, 20).path(), Some("/owned/fixture"));
        for foreign in [
            ProcessKey { exec_id: 1, ..key },
            ProcessKey {
                generation: 12,
                ..key
            },
            ProcessKey { domain: 8, ..key },
            ProcessKey::from_pid(key.pid),
        ] {
            assert_eq!(
                store.lookup(foreign, 20).result,
                Err(TraceIdentityUnknown::NotSeeded)
            );
        }
        assert_eq!(
            store
                .lookup(
                    ProcessKey {
                        pid: key.pid + 1,
                        ..key
                    },
                    20
                )
                .path(),
            Some("/owned/fixture"),
            "authenticated image identity is not indexed by diagnostic PID"
        );
    }

    // Catches moving the immutable lower boundary backwards on delayed events.
    #[test]
    fn trace_identity_same_key_preseed_event_is_unknown() {
        let (proof, receipt) = verified_fixture();
        let key = receipt.key();
        assert_eq!(receipt.eligible_after_ns(), 10);
        let mut store = TraceIdentityStore::new(proof);
        assert_eq!(store.lookup(key, 5).path(), None);
        assert_eq!(store.admit(receipt), Ok(()));
        assert_eq!(store.lookup(key, 20).path(), Some("/owned/fixture"));
        for old_or_equal in [5, 10] {
            assert_eq!(
                store.lookup(key, old_or_equal).result,
                Err(TraceIdentityUnknown::AfterEvent)
            );
        }
        assert_eq!(store.lookup(key, 21).path(), Some("/owned/fixture"));
    }

    // Catches treating an invalid/unstamped clock as positive event-time proof.
    #[test]
    fn trace_identity_invalid_event_clock_is_unknown() {
        let (proof, receipt) = verified_fixture();
        let key = receipt.key();
        let mut store = TraceIdentityStore::new(proof);
        assert_eq!(store.admit(receipt), Ok(()));
        assert_eq!(
            store.lookup(key, u64::MAX).result,
            Err(TraceIdentityUnknown::Unreadable)
        );
        assert_eq!(
            store.lookup(key, 0).result,
            Err(TraceIdentityUnknown::AfterEvent)
        );
        assert_eq!(store.lookup(key, 20).path(), Some("/owned/fixture"));
    }

    // Catches accepting unrelated allocations with equal numeric domain IDs.
    #[test]
    fn trace_identity_foreign_session_equal_domain_refuses() {
        let (owner, own_receipt) = verified_fixture();
        let (foreign, foreign_receipt) = verified_fixture();
        assert!(!owner.same_allocation(&foreign));
        assert_eq!(own_receipt.key(), foreign_receipt.key());
        drop(own_receipt);
        let key = foreign_receipt.key();
        let mut store = TraceIdentityStore::new(owner);
        assert_eq!(
            store.admit(foreign_receipt),
            Err(TraceIdentityUnknown::DomainMismatch)
        );
        assert_eq!(foreign.usage(), (0, 0));
        assert_eq!(store.lookup(key, 20).path(), None);
    }

    // Catches duplicate replacement, an eligibility regression or leaked charge.
    #[test]
    fn trace_identity_duplicate_keeps_boundary_and_releases_charge() {
        let (proof, first, duplicate) = verified_duplicate_fixture();
        let key = first.key();
        assert_eq!(first.eligible_after_ns(), 10);
        assert_eq!(duplicate.key(), key);
        assert!(duplicate.eligible_after_ns() > 20);
        assert_eq!(proof.usage(), (2, 28));
        let mut store = TraceIdentityStore::new(proof.clone());
        assert_eq!(store.admit(first), Ok(()));
        assert_eq!(store.admit(duplicate), Ok(()));
        assert_eq!(proof.usage(), (1, 14));
        assert_eq!(store.lookup(key, 20).path(), Some("/owned/fixture"));
        assert_eq!(
            store.lookup(key, 10).result,
            Err(TraceIdentityUnknown::AfterEvent)
        );
        drop(store);
        assert_eq!(proof.usage(), (0, 0));
    }

    // Catches replacing the first same-key receipt after a link rename.
    #[test]
    fn trace_identity_conflicting_receipt_withholds_name() {
        let (proof, first, conflicting) = verified_conflicting_fixture();
        let key = first.key();
        assert_eq!(conflicting.key(), key);
        assert_eq!(first.path(), "/owned/fixture");
        assert_eq!(conflicting.path(), "/renamed/fixture");
        assert_eq!(proof.usage(), (2, 30));
        let mut store = TraceIdentityStore::new(proof.clone());
        assert_eq!(store.admit(first), Ok(()));
        assert_eq!(store.lookup(key, 20).path(), Some("/owned/fixture"));
        assert_eq!(
            store.admit(conflicting),
            Err(TraceIdentityUnknown::ExecChanged)
        );
        assert_eq!(proof.usage(), (1, 14));
        for ts in [20, 100, 1000] {
            assert_eq!(
                store.lookup(key, ts).result,
                Err(TraceIdentityUnknown::ExecChanged)
            );
        }
        drop(store);
        assert_eq!(proof.usage(), (0, 0));
    }

    // Catches an independent store budget or retaining receipt charges on drop.
    #[test]
    fn trace_identity_budget_is_shared_and_drop_releases() {
        let (proof, receipt) = verified_fixture();
        let mut store = TraceIdentityStore::new(proof.clone());
        assert_eq!(store.admit(receipt), Ok(()));
        assert_eq!(proof.usage(), (1, 14));
        let held: Vec<_> = (0..16383).map(|_| proof.reserve(0).unwrap()).collect();
        assert_eq!(proof.usage(), (16384, 14));
        assert!(matches!(
            proof.reserve(0),
            Err(TraceIdentityUnknown::Budget)
        ));
        drop(held);
        let bytes = proof.reserve(8 * 1024 * 1024 - 14).unwrap();
        assert!(matches!(
            proof.reserve(1),
            Err(TraceIdentityUnknown::Budget)
        ));
        drop(bytes);
        assert_eq!(proof.usage(), (1, 14));
        drop(store);
        assert_eq!(proof.usage(), (0, 0));
        let entry = proof.reserve(0).unwrap();
        assert_eq!(proof.usage(), (1, 0));
        drop(entry);
        assert_eq!(proof.usage(), (0, 0));
    }
}
