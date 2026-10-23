//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private two-cell Counts transaction. This is not general counter growth.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::identity::PinnedObjectId;
    use crate::plan::{AttachPlan, Slot};
    use crate::semantics_edge::resources::{
        ResourceLease, SEMANTIC_TRANSITION_SCRATCH, SemanticResourcePool,
    };
    use std::collections::BTreeMap;

    fn slot(index: u32, object: u32) -> Slot {
        Slot {
            index,
            descriptor_index: 0,
            object: PinnedObjectId(object),
            object_path: "/owned-provider.so".into(),
            file_offset: 0x80,
            names: vec!["C_Initialize".into()],
            aliased: false,
            semantics: crate::kinds::DESCRIPTORS[0],
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![],
        }
    }

    fn plan(count: u32) -> AttachPlan {
        AttachPlan::from_slots((0..count).map(|index| slot(index, index + 1)).collect())
    }

    fn reservation() -> BankReservation {
        BankReservation {
            retained_bytes: 64 * 1024,
            transient_bytes: 32 * 1024,
            metadata_bytes: 8 * 1024,
            file_descriptors: 32,
        }
    }

    #[test]
    fn fixed_counter_roots_resolve_abis_then_attach_returns_before_entries() {
        use crate::attach::{
            CapturePolicy, StaticRoots, attach_targets_observed_with_roots, pid_continuity,
        };
        use p11scope_manifest::elf::ElfAbi;
        use std::cell::RefCell;

        let slots = plan(2).slots;
        let calls = RefCell::new(Vec::new());
        let outcome = attach_targets_observed_with_roots(
            &slots,
            CapturePolicy::AggregateOnly,
            false,
            StaticRoots::CounterBanks,
            |slot| {
                calls.borrow_mut().push(("abi", slot.index));
                Ok(ElfAbi::Lp64)
            },
            |program, slot, _| {
                calls.borrow_mut().push((program, slot.index));
                pid_continuity::NativeAttempt {
                    started_ns: Some(1),
                    result: Ok(()),
                }
            },
            |_| Some(2),
        )
        .unwrap();
        assert!(outcome.failures.is_empty());
        assert_eq!(outcome.completed.len(), 2);
        assert_eq!(
            calls.into_inner(),
            vec![
                ("abi", 0), ("abi", 1),
                ("p11_counter_bank_return", 0), ("p11_counter_bank_return", 1),
                ("p11_counter_bank_entry", 0), ("p11_counter_bank_entry", 1),
            ]
        );
        let mut attached = false;
        let refused = attach_targets_observed_with_roots(
            &slots,
            CapturePolicy::AggregateOnly,
            false,
            StaticRoots::CounterBanks,
            |_| Ok(ElfAbi::Ilp32),
            |_, _, _| {
                attached = true;
                pid_continuity::NativeAttempt { started_ns: None, result: Ok(()) }
            },
            |_| None,
        );
        assert!(refused.is_err(), "this bounded host proof is LP64 only");
        assert!(!attached, "all ABI validation precedes the first link");
    }

    #[derive(Default)]
    struct Native {
        trace: Vec<&'static str>,
        inners: BTreeMap<u32, u32>,
        metadata: BTreeMap<u32, BankMetadata>,
        commits: BTreeMap<u64, BankCommit>,
        held: Vec<ResourceLease>,
        acknowledgements: Vec<CommitAck>,
        fail: Option<&'static str>,
        foreign_inner: Option<u32>,
        failed_delete: bool,
    }

    impl BankIo for Native {
        fn validate_targets(&mut self, _: &[Slot]) -> Result<(), BankRefusal> {
            self.trace.push("validate");
            Ok(())
        }

        fn retain_charge(&mut self, charge: ResourceLease) {
            self.held.push(charge);
        }

        fn allocate(&mut self, slot: u32) -> Result<(), BankRefusal> {
            assert!(!self.held.is_empty(), "precharge precedes native allocation");
            self.trace.push("allocate");
            if self.fail == Some("allocate") {
                return Err(BankRefusal::Native);
            }
            if self.foreign_inner == Some(slot) {
                self.inners.insert(slot, 99);
            }
            Ok(())
        }

        fn insert_inner(&mut self, slot: u32) -> Result<(), BankRefusal> {
            self.trace.push("inner");
            if self.inners.contains_key(&slot) {
                return Err(BankRefusal::Ownership);
            }
            self.inners.insert(slot, slot + 1);
            Ok(())
        }

        fn insert_metadata(
            &mut self,
            slot: u32,
            metadata: BankMetadata,
        ) -> Result<(), BankRefusal> {
            self.trace.push("metadata");
            if self.fail == Some("metadata") || self.metadata.contains_key(&slot) {
                return Err(BankRefusal::Native);
            }
            self.metadata.insert(slot, metadata);
            Ok(())
        }

        fn attach_inactive(&mut self, slots: &[Slot]) -> Result<(), BankRefusal> {
            assert!(slots.iter().all(|slot| {
                let metadata = self.metadata[&slot.index];
                !self.commits.contains_key(&metadata.transaction)
            }));
            self.trace.extend(["return", "entry"]);
            if self.fail == Some("entry") {
                return Err(BankRefusal::Links);
            }
            Ok(())
        }

        fn insert_commit(
            &mut self,
            transaction: u64,
            commit: BankCommit,
        ) -> Result<(), BankRefusal> {
            self.trace.push("commit");
            assert!(!self.commits.contains_key(&transaction));
            if self.fail != Some("commit-absent") {
                self.commits.insert(transaction, commit);
            }
            if self.fail == Some("commit-absent") || self.fail == Some("commit-ack-lost") {
                Err(BankRefusal::Commit)
            } else {
                Ok(())
            }
        }

        fn acknowledge(&mut self, transaction: u64) -> CommitAck {
            self.trace.push("ack");
            if !self.acknowledgements.is_empty() {
                return self.acknowledgements.remove(0);
            }
            match self.commits.get(&transaction) {
                Some(commit) => CommitAck::Present(*commit),
                None => CommitAck::Absent,
            }
        }

        fn remove_metadata_owned(
            &mut self,
            slot: u32,
            expected: BankMetadata,
        ) -> Result<(), BankRefusal> {
            self.trace.push("remove-metadata");
            if self.failed_delete || self.metadata.get(&slot) != Some(&expected) {
                return Err(BankRefusal::Ownership);
            }
            self.metadata.remove(&slot);
            Ok(())
        }

        fn remove_inner_owned(&mut self, slot: u32) -> Result<(), BankRefusal> {
            self.trace.push("remove-inner");
            if self.failed_delete || self.inners.get(&slot) != Some(&(slot + 1)) {
                return Err(BankRefusal::Ownership);
            }
            self.inners.remove(&slot);
            Ok(())
        }

        fn retire_links(&mut self, _: &[Slot]) -> Result<(), BankRefusal> {
            self.trace.push("retire-links");
            if self.fail == Some("retire") {
                Err(BankRefusal::Links)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn staging_precharges_before_native_mutation_and_links_return_first() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut directory = BankDirectory::default();
        let mut native = Native::default();
        assert!(matches!(
            directory.stage_with(&mut native, &plan(2), reservation(), &pool.reserver()),
            BankPublication::Published { mask: 3, .. }
        ));
        let return_at = native.trace.iter().position(|step| *step == "return").unwrap();
        let entry_at = native.trace.iter().position(|step| *step == "entry").unwrap();
        let commit_at = native.trace.iter().position(|step| *step == "commit").unwrap();
        assert!(return_at < entry_at && entry_at < commit_at);
        assert!(pool.snapshot().charged_bytes > SEMANTIC_TRANSITION_SCRATCH);

        let refused = SemanticResourcePool::reference_limit(SEMANTIC_TRANSITION_SCRATCH);
        let mut native = Native::default();
        let mut directory = BankDirectory::default();
        assert_eq!(
            directory.stage_with(&mut native, &plan(1), reservation(), &refused.reserver()),
            BankPublication::Refused(BankRefusal::Budget)
        );
        assert!(native.trace.is_empty());
        assert_eq!(directory.published_mask(), 0);
        drop(native);
    }

    #[test]
    fn exact_commit_ack_publishes_once_and_preserves_old_routes() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut directory = BankDirectory::default();
        let mut native = Native::default();
        let BankPublication::Published { transaction: old, mask: 1 } =
            directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver())
        else {
            panic!("first real transaction did not publish");
        };
        let original = native.metadata[&0];
        native.fail = Some("commit-ack-lost");
        let BankPublication::Published { transaction: new, mask: 2 } =
            directory.stage_with(&mut native, &plan(2), reservation(), &pool.reserver())
        else {
            panic!("matching readback must resolve lost syscall acknowledgement");
        };
        assert!(new > old);
        assert_eq!(native.metadata[&0], original);
        assert_eq!(original.transaction, old);
        assert_eq!(native.metadata[&1].transaction, new);
        assert_eq!(native.commits[&old].mask, 1);
        assert_eq!(native.commits[&new].mask, 2);
        assert_eq!(directory.published_mask(), 3);
        assert!(directory.validate_read_plan(&plan(2)).is_ok());

        let before = native.trace.len();
        let mut replacement = plan(2);
        replacement.slots[0].object = PinnedObjectId(99);
        assert_eq!(
            directory.stage_with(&mut native, &replacement, reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Topology)
        );
        assert_eq!(native.trace.len(), before, "mismatch precedes native mutation");
        assert_eq!(directory.published_mask(), 3);
    }

    #[test]
    fn absent_commit_rolls_back_only_candidate_owned_keys() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        for failure in ["metadata", "entry", "commit-absent"] {
            let mut directory = BankDirectory::default();
            let mut native = Native { fail: Some(failure), ..Native::default() };
            assert!(matches!(
                directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver()),
                BankPublication::RolledBack { .. }
            ), "{failure}");
            assert!(native.inners.is_empty(), "{failure}");
            assert!(native.metadata.is_empty(), "{failure}");
            assert!(native.commits.is_empty(), "{failure}");
            assert_eq!(directory.published_mask(), 0);
            assert!(!native.held.is_empty(), "cleanup custody retains the charge");
            let before = native.trace.len();
            assert!(matches!(
                directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver()),
                BankPublication::Refused(BankRefusal::Allocated)
            ));
            assert_eq!(native.trace.len(), before, "allocated positions are never revived");
        }
        let mut directory = BankDirectory::default();
        let mut native = Native { foreign_inner: Some(0), ..Native::default() };
        assert!(matches!(
            directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver()),
            BankPublication::RolledBack { .. }
        ));
        assert_eq!(native.inners.get(&0), Some(&99));
        assert!(!native.trace.contains(&"remove-inner"));
        assert!(!native.trace.contains(&"commit"));
    }

    #[test]
    fn ambiguous_ack_retains_custody_and_refuses_reads() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        for acknowledgement in [
            CommitAck::Unreadable,
            CommitAck::Present(BankCommit { mask: 2, configuration: BANK_CONFIG }),
            CommitAck::Present(BankCommit { mask: 1, configuration: BANK_CONFIG ^ 1 }),
        ] {
            let mut directory = BankDirectory::default();
            let mut native = Native {
                acknowledgements: vec![acknowledgement],
                ..Native::default()
            };
            assert!(matches!(
                directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver()),
                BankPublication::Quarantined { .. }
            ));
            assert_eq!(native.inners.len(), 1);
            assert_eq!(native.metadata.len(), 1);
            assert!(!native.held.is_empty());
            assert!(!native.trace.contains(&"remove-inner"));
            assert_eq!(directory.validate_read_plan(&plan(1)), Err(BankRefusal::Quarantined));
            let before = native.trace.len();
            assert_eq!(
                directory.stage_with(&mut native, &plan(2), reservation(), &pool.reserver()),
                BankPublication::Refused(BankRefusal::Quarantined)
            );
            assert_eq!(native.trace.len(), before);
        }
        let mut directory = BankDirectory::default();
        let mut native = Native {
            fail: Some("commit-absent"),
            failed_delete: true,
            ..Native::default()
        };
        assert!(matches!(
            directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver()),
            BankPublication::Quarantined { .. }
        ));
        assert!(!native.inners.is_empty());
        assert!(!native.held.is_empty());
        assert_eq!(directory.validate_read_plan(&plan(1)), Err(BankRefusal::Quarantined));
    }

    #[test]
    fn native_limits_and_transaction_exhaustion_refuse_before_mutation() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut native = Native::default();
        let mut directory = BankDirectory::default();
        assert_eq!(
            directory.stage_with(&mut native, &plan(3), reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Shape),
        );
        let mut aliases = plan(2);
        aliases.slots[1].object = aliases.slots[0].object;
        assert_eq!(
            directory.stage_with(&mut native, &aliases, reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Topology),
        );
        assert!(native.trace.is_empty());
        directory.next_transaction = std::num::NonZeroU64::new(u64::MAX);
        assert!(matches!(
            directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver()),
            BankPublication::Published { transaction: u64::MAX, .. }
        ));
        let before = native.trace.len();
        assert_eq!(
            directory.stage_with(&mut native, &plan(2), reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Exhausted),
        );
        assert_eq!(native.trace.len(), before);
        assert!(directory.validate_read_plan(&plan(1)).is_ok());
        assert_eq!(directory.published_mask(), 1);
    }
}
