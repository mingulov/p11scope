//! SPDX-License-Identifier: GPL-3.0-or-later
//! Genuine prior sealed history, retained by the canonical owner and pool.

use super::audit_handoff::{acquire, attachment, claim_and_finish};
use super::*;
use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
use crate::semantics_objects::journal::{
    BootstrapReceipt, ScriptedBirthSource, SessionClosureGrant,
};
use crate::semantics_objects::{Lifetime, ObjectEffect, ObjectGap};

/// The allocation budget is not the first poll's work allowance. Reading
/// one BEGIN must leave room for its later physical END in this SAME owner.
#[test]
fn joint_machine_initial_work_preserves_full_original_capacity() {
    let mut scene = JointScene::for_audit(1);
    let pid = std::process::id();
    scene.real.bind(
        pid,
        ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        },
        0,
    );
    let (begin, end) = scene.encoded(pid, 0, "C_SignInit", 1);
    scene.drain.source_mut().push_record(begin.to_vec());
    let reserve = scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_storage_reserver();
    let (mut raw, poll) = RawJointQuantum::begin_bounded_with_adapter(
        &mut scene.drain,
        &publish_object_descriptors(),
        4_096,
        1,
        None,
        &BirthFault,
        &scene.producers,
        |bytes| reserve.reserve(bytes),
        scene
            .real
            .scene
            .coordinator
            .joint_capture_mut()
            .adapter_mut(),
    )
    .unwrap();
    assert_eq!(poll.unwrap().attempted, 1);
    assert_eq!(scene.drain.source_mut().remaining(), 0);
    let identity = raw.h0_identity();
    let held = scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .charged_bytes;
    // A genuine idle poll between the original BEGIN and END is not a new
    // allocation or an admission/terminal for that unfinished invocation.
    let idle = raw
        .continue_bounded_with_adapter(
            &mut scene.drain,
            &publish_object_descriptors(),
            1,
            None,
            &BirthFault,
            &scene.producers,
            scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut(),
        )
        .unwrap();
    assert_eq!(idle.attempted, 0);
    scene.drain.source_mut().push_record(end.to_vec());
    let completed = raw
        .continue_bounded_with_adapter(
            &mut scene.drain,
            &publish_object_descriptors(),
            1,
            None,
            &BirthFault,
            &scene.producers,
            scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut(),
        )
        .unwrap();
    assert_eq!(completed.attempted, 1);
    assert!(raw.h0_identity() == identity);
    assert_eq!(raw.pending_h0_records(), 1);
    assert_eq!(
        scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        held
    );
    assert_eq!(scene.drain.source_mut().remaining(), 0);
}

/// Zero initial work is unobserved, not an observed-empty read certificate.
#[test]
fn joint_machine_zero_initial_work_never_observes_empty() {
    let mut scene = JointScene::for_audit(1);
    let pid = std::process::id();
    scene.real.bind(
        pid,
        ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        },
        0,
    );
    scene.push(pid, 0, "C_SignInit", 1);
    let boundary = scene.drain.consumption_cut().unwrap();
    let reserve = scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_storage_reserver();
    let adapter = scene
        .real
        .scene
        .coordinator
        .joint_capture_mut()
        .adapter_mut();
    let (mut raw, poll) = RawJointQuantum::begin_bounded_with_adapter(
        &mut scene.drain,
        &publish_object_descriptors(),
        4_096,
        0,
        None,
        &BirthFault,
        &scene.producers,
        |bytes| reserve.reserve(bytes),
        adapter,
    )
    .unwrap();
    assert!(
        poll.is_none(),
        "no poll result exists until the cursor was actually serviced"
    );
    assert_eq!(scene.drain.source_mut().remaining(), 2);
    assert!(boundary.same_boundary(&scene.drain.consumption_cut().unwrap()));
    assert_eq!(raw.pending_h0_records(), 0);
    assert_eq!(
        raw.validate_preparation(adapter, &scene.producers),
        Err(RawQuantumRefusal::H0Undelivered)
    );
    {
        let mut owned = scene.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *owned;
        let empty_report = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(empty_report.calls().count(), 0);
        assert_eq!(
            raw.validate_preparation(adapter, &scene.producers),
            Err(RawQuantumRefusal::H0Undelivered),
            "an H0 report cannot turn an unpolled Raw into an observed cut"
        );
    }
    let identity = raw.h0_identity();
    let poll = raw
        .continue_bounded_with_adapter(
            &mut scene.drain,
            &publish_object_descriptors(),
            1,
            None,
            &BirthFault,
            &scene.producers,
            adapter,
        )
        .unwrap();
    assert_eq!(poll.attempted, 1);
    assert_eq!(scene.drain.source_mut().remaining(), 1);
    assert!(raw.h0_identity() == identity);
}

// The machine owns all policy/state. This test adapter replaces only the
// existing Session cursor/map leaves and calls the real Capture, coordinator,
// birth validator and scoped native-reader builder below that boundary.
struct MachineNativeRows {
    publisher: NativePublisher,
    rows: std::collections::BTreeMap<crate::semantics_objects::ObjectDomain, NativeBirthRows>,
    reads: Cell<(usize, usize)>,
    preparations: Vec<(
        crate::semantics_objects::journal::joint_driver::RawQuantumIdentity,
        bool,
    )>,
    fail_after_preparation: bool,
    fail_births: bool,
    absence_reads: Vec<(u64, ImageIdentity, u32)>,
    birth_outcomes: Vec<(
        u32,
        Result<crate::semantics_objects::journal::BirthKind, BirthObservationRefusal>,
    )>,
    pending_q_resolutions: usize,
    pending_q_calls: usize,
}

struct HeldMachineIo<'a> {
    drain: &'a mut EventDrain<ScriptedRecords>,
    h0: &'a SharedH0,
    producers: &'a SessionDrainProducers,
    attached: &'a crate::attach::AttachedSemanticSet,
    native: &'a mut MachineNativeRows,
    finish: Option<&'a mut FinishMachineFixture>,
}

/// Original terminal I/O only. The machine owns Q, the final Raw, reports,
/// leases and publication association; these counters observe actual calls.
struct FinishMachineFixture {
    observer: crate::attach::CollectedFinishQObserverForTest,
    staged: crate::attach::DiscoveryStage,
    stop_requests: usize,
    q_observations: usize,
    stops: usize,
    at_stop: Option<FinishStopObservation>,
}

struct FinishStopObservation {
    raw: crate::semantics_objects::journal::joint_driver::RawQuantumIdentity,
    revision: u64,
    reduced: u64,
    validations: usize,
    h3: (usize, bool),
}

impl HeldMachineIo<'_> {
    /// Match Session's fresh original-cursor check before any at-Q leaf.
    /// A pending prefix may precede Q; its producers may never advance Q.
    fn validate_finish_q(
        &self,
        q: &crate::attach::CollectedFinishQ,
    ) -> Result<(), SemanticRefusal> {
        let finish = self.finish.as_deref().ok_or(SemanticRefusal::Unavailable)?;
        let events = self
            .drain
            .consumption_cut()
            .map_err(|_| SemanticRefusal::Unavailable)?;
        let drain = finish.observer.discovery_drain();
        let discovery = crate::events::discovery_drain_positions(drain);
        if !q.matches_owner(self.producers, finish.observer.discovery_domain())
            || !q.matches_discovery_drain(self.producers, drain)
            || !q.covers_events_bounds(&events)
            || events.producer_bound() != q.events_stop()
            || discovery.producer != q.discovery_stop()
            || discovery.consumer > q.discovery_stop()
        {
            return Err(SemanticRefusal::Unavailable);
        }
        Ok(())
    }
}

impl crate::inventory_semantics::JointMachineIo for HeldMachineIo<'_> {
    fn producers(&self) -> &SessionDrainProducers {
        self.producers
    }

    fn request_finish_stop(
        &mut self,
        lane: &mut AttestedSemanticLane,
    ) -> Result<(), SemanticRefusal> {
        let finish = self
            .finish
            .as_deref_mut()
            .ok_or(SemanticRefusal::Unavailable)?;
        lane.request_semantic_stop();
        finish.observer.request_stop();
        finish.stop_requests += 1;
        Ok(())
    }

    fn observe_finish_q(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        grant: Option<&crate::semantics_objects::journal::SessionDrainGrant>,
    ) -> Result<Option<crate::attach::CollectedFinishQ>, SemanticRefusal> {
        let finish = self
            .finish
            .as_deref_mut()
            .ok_or(SemanticRefusal::Unavailable)?;
        let observed = finish
            .observer
            .observe(self.producers, grant, self.drain)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        finish.q_observations += usize::from(observed.is_some());
        Ok(observed)
    }

    fn finish_discovery_domain(&self) -> Result<&crate::events::DiscoveryDomain, SemanticRefusal> {
        Ok(self
            .finish
            .as_deref()
            .ok_or(SemanticRefusal::Unavailable)?
            .observer
            .discovery_domain())
    }

    fn collect_raw_at_q(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        adapter: &mut JournalAdapter,
        reserve: &crate::semantics_edge::resources::SemanticResourceReserver,
        q: &crate::attach::CollectedFinishQ,
        capacity: usize,
        work: usize,
    ) -> Result<(RawJointQuantum, Option<crate::events::DispatchPoll>), RawQuantumRefusal> {
        self.validate_finish_q(q)
            .map_err(|_| RawQuantumRefusal::Stopped)?;
        RawJointQuantum::begin_bounded_with_adapter(
            self.drain,
            &publish_object_descriptors(),
            capacity,
            work,
            Some(q.events_stop()),
            &DisposedNativeFault((*self.h0).clone()),
            self.producers,
            |bytes| reserve.reserve(bytes),
            adapter,
        )
    }

    fn continue_raw_at_q(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        raw: &mut RawJointQuantum,
        adapter: &mut JournalAdapter,
        q: &crate::attach::CollectedFinishQ,
        work: usize,
    ) -> Result<crate::events::DispatchPoll, RawQuantumRefusal> {
        self.validate_finish_q(q)
            .map_err(|_| RawQuantumRefusal::Stopped)?;
        raw.continue_bounded_with_adapter(
            self.drain,
            &publish_object_descriptors(),
            work,
            Some(q.events_stop()),
            &DisposedNativeFault((*self.h0).clone()),
            self.producers,
            adapter,
        )
    }

    fn service_finish_discovery(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        q: &crate::attach::CollectedFinishQ,
        work: usize,
    ) -> Result<crate::inventory_semantics::LaneDrainOutcome, SemanticRefusal> {
        self.validate_finish_q(q)?;
        let finish = self
            .finish
            .as_deref_mut()
            .ok_or(SemanticRefusal::Unavailable)?;
        coordinator.service_collected_finish_discovery(
            q,
            self.producers,
            finish.observer.discovery_drain_mut(),
            &mut finish.staged,
            work,
        )
    }

    fn finish_h0_storage_bytes(
        &self,
        _lane: &AttestedSemanticLane,
        raw: &RawJointQuantum,
        adapter: &JournalAdapter,
        q: &crate::attach::CollectedFinishQ,
    ) -> Result<usize, SemanticRefusal> {
        self.validate_finish_q(q)?;
        let finish = self.finish.as_deref().ok_or(SemanticRefusal::Unavailable)?;
        self.h0
            .0
            .borrow()
            .capture
            .collected_stop_at_q_storage_bytes(
                raw,
                adapter,
                self.producers,
                finish.observer.discovery_domain(),
                q,
            )
            .map_err(|_| SemanticRefusal::ProviderStorage)
    }

    fn finish_h0_at_q(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        coordinator: &InventoryCoordinator<OsProcessSource>,
        raw: &mut RawJointQuantum,
        q: &crate::attach::CollectedFinishQ,
        report: &mut TickReport,
    ) -> Result<(), SemanticRefusal> {
        self.validate_finish_q(q)?;
        let finish = self
            .finish
            .as_deref_mut()
            .ok_or(SemanticRefusal::Unavailable)?;
        let mut held = self.h0.0.borrow_mut();
        let HeldH0 { capture, .. } = &mut *held;
        assert!(!capture.stopped, "the actual Capture stops only once");
        capture
            .stop_collected_at_q(
                raw,
                coordinator.joint_capture().adapter(),
                self.producers,
                finish.observer.discovery_domain(),
                q,
                report,
            )
            .map_err(|_| SemanticRefusal::Unavailable)?;
        assert!(capture.stopped);
        assert!(report.current().is_empty());
        finish.stops += 1;
        finish.at_stop = Some(FinishStopObservation {
            raw: raw.h0_identity(),
            revision: coordinator.registry().published_revision(),
            reduced: coordinator
                .registry()
                .instance_semantic_edges()
                .map(|record| record.feed.reduced())
                .sum(),
            validations: held.validations,
            h3: coordinator.reference_h3_audit_state(),
        });
        Ok(())
    }
    fn collect_raw(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        adapter: &mut JournalAdapter,
        reserve: &crate::semantics_edge::resources::SemanticResourceReserver,
        capacity: usize,
        work: usize,
    ) -> Result<(RawJointQuantum, Option<crate::events::DispatchPoll>), RawQuantumRefusal> {
        RawJointQuantum::begin_bounded_with_adapter(
            self.drain,
            &publish_object_descriptors(),
            capacity,
            work,
            None,
            &DisposedNativeFault((*self.h0).clone()),
            self.producers,
            |bytes| reserve.reserve(bytes),
            adapter,
        )
    }

    fn continue_raw(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        raw: &mut RawJointQuantum,
        adapter: &mut JournalAdapter,
        work: usize,
    ) -> Result<crate::events::DispatchPoll, RawQuantumRefusal> {
        raw.continue_bounded_with_adapter(
            self.drain,
            &publish_object_descriptors(),
            work,
            None,
            &DisposedNativeFault((*self.h0).clone()),
            self.producers,
            adapter,
        )
    }

    fn tick_collected(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        bindings: &[SemanticCallerBinding],
        raw: &mut RawJointQuantum,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        let mut owned = self.h0.0.borrow_mut();
        if let Some(retained) = &owned.collected_producers {
            assert!(retained.same_producers(self.producers));
        } else {
            owned.collected_producers = Some(self.producers.clone());
        }
        let HeldH0 {
            capture, io, stash, ..
        } = &mut *owned;
        let mut report = capture
            .tick_collected_with(io, raw)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        assert_eq!(merge_stash_into_report(stash, &mut report), 0);
        for current in report.current() {
            let binding = bindings.iter().find(|binding| {
                binding.domain() == current.domain() && binding.image() == current.image()
            });
            eprintln!(
                "machine_current file={} has_birth={} same_raw={} instances={} binding={} provider={} same_pin={}",
                current.endpoint().file_slot,
                current.birth_quantum().is_some(),
                current.birth_quantum() == Some(raw.h0_identity()),
                current.instances().len(),
                binding.is_some(),
                binding.is_some_and(|binding| binding
                    .provider_for_endpoint(current.endpoint())
                    .is_some()),
                binding.is_some_and(|binding| Arc::ptr_eq(&binding.pin(), current.original_pin())),
            );
        }
        SemanticBatch::from_tick_report(
            self.producers.native_domain(),
            report,
            Vec::new(),
            now_ns(),
        )
    }

    fn prepare_publication(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        raw: &mut RawJointQuantum,
        engine_changed: bool,
    ) -> anyhow::Result<()> {
        self.native
            .preparations
            .push((raw.h0_identity(), engine_changed));
        coordinator.prepare_joint_publication(engine_changed, lane, raw, self.producers)?;
        if self.native.fail_after_preparation {
            // The real engine/context already moved. A failed caller return
            // must not make the machine replay those actual side effects.
            return Err(anyhow::anyhow!(
                "actual preparation completed before failed handoff"
            ));
        }
        Ok(())
    }

    fn tick_collected_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        bindings: &[SemanticCallerBinding],
        raw: &mut RawJointQuantum,
        q: &crate::attach::CollectedFinishQ,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        self.validate_finish_q(q)?;
        self.tick_collected(lane, bindings, raw)
    }

    fn prepare_publication_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        raw: &mut RawJointQuantum,
        changed: bool,
        q: &crate::attach::CollectedFinishQ,
    ) -> anyhow::Result<()> {
        self.validate_finish_q(q).map_err(anyhow::Error::msg)?;
        self.prepare_publication(lane, coordinator, raw, changed)
    }

    fn pending_h0_at_q_storage_bytes(
        &self,
        _lane: &AttestedSemanticLane,
        raw: &RawJointQuantum,
        adapter: &JournalAdapter,
        q: &crate::attach::CollectedFinishQ,
        discovery: &crate::events::DiscoveryDomain,
    ) -> Result<usize, SemanticRefusal> {
        // Standalone pending-Q tests borrow their separate original observer;
        // their strict wrapper/Raw checks do not create a global Finish owner.
        if self.finish.is_some() {
            self.validate_finish_q(q)?;
        }
        self.h0
            .0
            .borrow()
            .capture
            .pending_h0_at_q_storage_bytes(raw, adapter, self.producers, discovery, q)
            .map_err(|_| SemanticRefusal::ProviderStorage)
    }

    fn resolve_pending_h0_at_q(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        raw: &mut RawJointQuantum,
        adapter: &JournalAdapter,
        q: &crate::attach::CollectedFinishQ,
        discovery: &crate::events::DiscoveryDomain,
        report: &mut TickReport,
    ) -> Result<(), SemanticRefusal> {
        if self.finish.is_some() {
            self.validate_finish_q(q)?;
        }
        let mut owned = self.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *owned;
        self.native.pending_q_resolutions += 1;
        capture
            .resolve_collected_pending_at_q_with(
                io,
                raw,
                adapter,
                self.producers,
                discovery,
                q,
                report,
            )
            .map_err(|_| SemanticRefusal::Unavailable)?;
        self.native.pending_q_calls += report.calls().count();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // Substitute native rows beneath the actual original consumer.
    fn consume_birth(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        candidate: H0BirthCandidate,
        absence: Option<CommittedAbsenceBirth>,
        input: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
        binding: &SemanticCallerBinding,
        proof: &JournalDomainProof,
        adapter: &JournalAdapter,
    ) -> Result<RetainedBirthWitness, BirthObservationRefusal> {
        let unmarked = self.native.fail_births
            || absence.is_some()
            || input.s1_facts().function == "C_GetSessionInfo";
        let (row, control, _) = self.native.publisher.publish_stamped(
            if unmarked {
                &["0", "0", "0", "0", "1"]
            } else {
                &["0", "0"]
            },
            self.attached.generation(),
        );
        let mut rows = NativeBirthRows { row, control };
        let mut owned = self.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *owned;
        capture.validate_birth_candidate(io, &candidate, false)?;
        let file = candidate.receipt.endpoint().file_slot;
        let result = capture.finish_birth(
            candidate,
            absence,
            input,
            binding,
            self.attached,
            proof,
            adapter,
            &mut rows,
        );
        self.native.birth_outcomes.push((
            file,
            result
                .as_ref()
                .map(|witness| witness.receipt().birth())
                .map_err(|reason| *reason),
        ));
        let witness = result?;
        assert!(
            self.native
                .rows
                .insert(witness.receipt().domain(), rows)
                .is_none()
        );
        Ok(witness)
    }

    #[allow(clippy::too_many_arguments)] // Preserve the original candidate and the same native subject.
    fn consume_birth_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        candidate: H0BirthCandidate,
        absence: Option<CommittedAbsenceBirth>,
        input: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
        binding: &SemanticCallerBinding,
        proof: &JournalDomainProof,
        adapter: &JournalAdapter,
        q: &crate::attach::CollectedFinishQ,
    ) -> Result<RetainedBirthWitness, BirthObservationRefusal> {
        self.validate_finish_q(q)
            .map_err(|_| BirthObservationRefusal::BindingMismatch)?;
        self.consume_birth(lane, candidate, absence, input, binding, proof, adapter)
    }

    fn acquire_absence(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        binding: &SemanticCallerBinding,
        slot: u32,
        adapter: &mut JournalAdapter,
    ) -> Result<CommittedAbsenceBirth, BirthObservationRefusal> {
        let before = self
            .drain
            .consumption_cut()
            .map_err(|_| BirthObservationRefusal::StreamCut)?;
        if !before.is_drained() {
            return Err(BirthObservationRefusal::StreamCut);
        }
        let mut held = self.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *held;
        let endpoint = io
            .endpoint(slot)
            .ok_or(BirthObservationRefusal::AttachmentMismatch)?;
        self.native
            .absence_reads
            .push((capture.identity, binding.image(), endpoint.file_slot));
        let maps = io
            .watched
            .iter()
            .enumerate()
            .filter(|(file, _)| !io.absent_files.contains(&(*file as u32)))
            .map(|(file, watched)| {
                let key = watched.object_key();
                let (base, _, _) = io.scan_input(file as u32);
                p11scope_manifest::maps::MapEntry {
                    start: base,
                    end: base + 0x10000,
                    file_offset: 0,
                    permissions: *b"r-xp",
                    device: key.device,
                    inode: key.inode,
                    raw_path: None,
                }
            })
            .collect();
        let target = io.watched[endpoint.file_slot as usize].object_key();
        let dev = libc::makedev(
            target
                .device
                .major
                .try_into()
                .map_err(|_| BirthObservationRefusal::CurrentPartition)?,
            target
                .device
                .minor
                .try_into()
                .map_err(|_| BirthObservationRefusal::CurrentPartition)?,
        );
        let proof = crate::attach::image_query::acquire_test_absence(
            io.script.domain,
            binding.image(),
            endpoint.file_slot,
            CompleteEpochs {
                local: u64::from(io.scan_input(endpoint.file_slot).1),
                global: 0,
                fault: io.script.last_health.fault,
                sticky: io.script.last_health.sticky,
                record_flags: 0,
            },
            maps,
            self.attached.generation(),
            vec![target],
            crate::discovery::instances::MappedFileIdentity {
                dev,
                ino: target.inode,
            },
            |_, _| {
                Ok(crate::discovery::instances::MappedFileIdentity {
                    dev,
                    ino: target.inode,
                })
            },
            capture.router.fence(),
        )
        .map_err(|_| BirthObservationRefusal::CurrentPartition)?;
        let after = self
            .drain
            .consumption_cut()
            .map_err(|_| BirthObservationRefusal::StreamCut)?;
        capture.commit_absence_with(
            io,
            proof,
            before,
            after,
            binding,
            self.attached,
            slot,
            adapter,
            self.producers,
        )
    }

    fn absence_query_storage_bytes(
        &self,
        lane: &AttestedSemanticLane,
        object: crate::discovery::identity::PinnedObjectId,
        target_copy: usize,
    ) -> Option<usize> {
        let held = self.h0.0.borrow();
        if !held
            .io
            .watched
            .iter()
            .any(|target| target.same_object_as(lane.subset().pins(), object))
        {
            return None;
        }
        // acquire_absence passes exactly one original watched key and the
        // actual fixture seals both sides of each retained plan slot.
        crate::attach::image_query::absence_query_storage_bytes(
            1,
            target_copy,
            lane.subset().plan().slots.len().checked_mul(2)?,
        )
    }

    fn with_native<R>(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        witnesses: &crate::inventory_semantics::RetainedJointBirths,
        inspect: impl for<'io> FnOnce(crate::inventory_semantics::JointCommitIo<'io>) -> R,
    ) -> Result<R, SemanticRefusal> {
        let mut owned = self
            .h0
            .0
            .try_borrow_mut()
            .map_err(|_| SemanticRefusal::Unavailable)?;
        let HeldH0 {
            capture, io, stash, ..
        } = &mut *owned;
        let rows = self
            .native
            .rows
            .iter_mut()
            .map(|(domain, rows)| (*domain, rows))
            .collect();
        let mut native = HeldCommitNative {
            io,
            rows,
            reads: &self.native.reads,
        };
        let native = RefCell::new(&mut native);
        crate::inventory_semantics::with_joint_commit_io_for_births_test(
            capture,
            stash,
            self.producers,
            self.attached,
            witnesses,
            &native,
            inspect,
        )
    }

    fn with_native_at_q<R>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        witnesses: &crate::inventory_semantics::RetainedJointBirths,
        q: &crate::attach::CollectedFinishQ,
        inspect: impl for<'io> FnOnce(crate::inventory_semantics::JointCommitIo<'io>) -> R,
    ) -> Result<R, SemanticRefusal> {
        self.validate_finish_q(q)?;
        self.with_native(lane, witnesses, inspect)
    }
}

struct MachineScene {
    scene: JointScene,
    machine: crate::inventory_semantics::LiveJointMachine,
    native: MachineNativeRows,
    finish: Option<FinishMachineFixture>,
}

impl MachineScene {
    fn absence_scene(providers: usize) -> Self {
        let mut fixture = Self::with_initial_files(providers, &[0], true);
        fixture.push_quiet();
        fixture.published_labeled("absence-quiet-prefix", None);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .joint_feeds(),
            0
        );
        assert!(
            fixture
                .native
                .birth_outcomes
                .iter()
                .any(|(file, result)| *file == 0 && result.is_err())
        );
        fixture
    }

    fn push_quiet(&mut self) {
        let mut held = self.scene.real.h0.0.borrow_mut();
        held.io
            .enqueue(std::process::id(), 0, "C_GetSessionInfo", 0, 0);
        let mut record = held.io.script.records.pop_back().unwrap();
        // HeldIo's algorithm fixture has no physical invocation by default.
        // The actual ordinary producer returns on a real thread with a
        // nonzero, unsaturated interval, as collected_tick models too.
        record.base.event.pid_tgid |= record.base.event.pid_tgid >> 32;
        record.base.event.duration_ns = 1;
        record.base.event.target_function = p11scope_ebpf_common::FUNCTION_NONE;
        assert_ne!(record.base.event.pid_tgid as u32, 0);
        assert!(
            record.base.event.duration_ns != 0
                && record
                    .base
                    .event
                    .ts_ns
                    .checked_sub(record.base.event.duration_ns)
                    .is_some()
        );
        assert_eq!(
            record.base.event.target_function,
            p11scope_ebpf_common::FUNCTION_NONE
        );
        let bytes = crate::events::record_bytes(&record.base);
        drop(held);
        self.scene.drain.source_mut().push_record(bytes);
    }

    fn pending_absence(&self, file: u32) -> Option<&CommittedAbsenceBirth> {
        self.machine
            .retained_births_for_test()
            .pending_for_test()
            .find(|negative| negative.proof.file_slot() == file)
    }

    fn ready_birth(&self, file: u32) -> Option<&RetainedBirthWitness> {
        self.machine
            .retained_births_for_test()
            .ready_for_test()
            .find(|witness| witness.candidate.receipt.endpoint().file_slot == file)
    }

    fn wait_absence(&mut self, file: u32) {
        for _ in 0..128 {
            if self.pending_absence(file).is_some() {
                return;
            }
            self.service(1).unwrap();
        }
        panic!("actual absent target {file} must be selected before a later appearance");
    }

    fn appear(&mut self, file: u32, epoch: u32) {
        self.stage_appearance_mapping(file);
        self.make_provider_present(file, epoch);
    }

    fn stage_appearance_mapping(&mut self, file: u32) {
        let pid = std::process::id();
        let caller = self
            .scene
            .real
            .scene
            .coordinator
            .adapter()
            .live_id(pid)
            .unwrap();
        let (module, path) = &self.scene.real.modules[file as usize];
        self.scene
            .real
            .scene
            .coordinator
            .registry_mut()
            .note_mapping(
                caller,
                pid,
                ModuleInfo {
                    path: path.clone(),
                    key: module.clone(),
                    double_loaded: false,
                    build_id: None,
                    identity_source: Some("held-provider-appearance".into()),
                    admission: AdmissionState::Admitted,
                    admission_class: Some("exact".into()),
                    admission_endpoints: Some(5),
                    admission_reasons: Vec::new(),
                },
                70,
            );
    }

    fn make_provider_present(&mut self, file: u32, epoch: u32) {
        let mut held = self.scene.real.h0.0.borrow_mut();
        assert!(held.io.absent_files.remove(&file));
        let (base, _, global) = held.io.scan_input(file);
        held.io.scan_inputs.insert(file, (base, epoch, global));
    }

    fn reach_phase(&mut self, phase: &str) {
        for _ in 0..512 {
            if self.machine.diagnostic_snapshot_for_test().0 == phase {
                return;
            }
            self.service(1).unwrap_or_else(|reason| {
                self.publication_failed(phase, None, Some(reason));
            });
        }
        self.publication_failed(phase, None, None);
    }

    fn new(providers: usize) -> Self {
        Self::with_initial_files(providers, &(0..providers as u32).collect::<Vec<_>>(), false)
    }

    fn with_initial_files(providers: usize, mapped: &[u32], quiet: bool) -> Self {
        let (held, attached) = HeldProviders::with_attachment(
            providers,
            if quiet {
                &[
                    "C_CreateObject",
                    "C_SignInit",
                    "C_SignUpdate",
                    "C_SignFinal",
                    "C_GetSessionInfo",
                ]
            } else {
                &[
                    "C_CreateObject",
                    "C_SignInit",
                    "C_SignUpdate",
                    "C_SignFinal",
                ]
            },
        );
        let mut scene = JointScene::from_held(held, Some(attached));
        let pid = std::process::id();
        SIGHT_NS.with(|clock| clock.set(1_005));
        scene.real.h0.0.borrow_mut().io.script.local = 1;
        let caller = scene.real.scene.admit(pid, 50);
        for (_, (module, path)) in scene
            .real
            .modules
            .iter()
            .enumerate()
            .filter(|(file, _)| mapped.contains(&(*file as u32)))
        {
            scene.real.scene.coordinator.registry_mut().note_mapping(
                caller,
                pid,
                ModuleInfo {
                    path: path.clone(),
                    key: module.clone(),
                    double_loaded: false,
                    build_id: None,
                    identity_source: Some("held-provider".into()),
                    admission: AdmissionState::Admitted,
                    admission_class: Some("exact".into()),
                    admission_endpoints: Some(if quiet { 5 } else { 4 }),
                    admission_reasons: Vec::new(),
                },
                60,
            );
        }
        scene.real.scene.coordinator.commit_batch(false).unwrap();
        let candidate = scene
            .real
            .scene
            .coordinator
            .prepare_legacy_semantic_candidate(caller, scene.real.lane.domain())
            .unwrap();
        scene.real.h0.0.borrow_mut().io.targets.insert(
            pid,
            (
                candidate.pin(),
                ImageIdentity {
                    task_cookie: 71,
                    exec_id: 0,
                },
            ),
        );
        drop(candidate);
        scene.real.h0.0.borrow_mut().io.absent_files = (0..providers as u32)
            .filter(|file| !mapped.contains(file))
            .collect();
        assert_eq!(scene.real.scene.coordinator.semantic_bindings().len(), 0);
        let reserve = scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_storage_reserver();
        let machine =
            crate::inventory_semantics::LiveJointMachine::new(&scene.producers, &reserve).unwrap();
        Self {
            scene,
            machine,
            finish: None,
            native: MachineNativeRows {
                publisher: NativePublisher::build(),
                rows: std::collections::BTreeMap::new(),
                reads: Cell::new((0, 0)),
                preparations: Vec::new(),
                fail_after_preparation: false,
                fail_births: false,
                absence_reads: Vec::new(),
                birth_outcomes: Vec::new(),
                pending_q_resolutions: 0,
                pending_q_calls: 0,
            },
        }
    }

    fn service(
        &mut self,
        work: usize,
    ) -> Result<crate::inventory_semantics::JointServiceProgress, SemanticRefusal> {
        let mut budget = crate::inventory_semantics::JointWorkBudget {
            remaining_actions: work,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let Self {
            scene,
            machine,
            native,
            finish,
        } = self;
        let mut io = HeldMachineIo {
            drain: &mut scene.drain,
            h0: &scene.real.h0,
            producers: &scene.producers,
            attached: scene.attached.as_ref().unwrap(),
            native,
            finish: finish.as_mut(),
        };
        machine.service_with_io(
            &mut scene.real.lane,
            &mut scene.real.scene.coordinator,
            &mut io,
            crate::inventory_semantics::JointServiceMode::Running,
            &mut budget,
        )
    }

    fn poll_commit(
        &mut self,
        work: usize,
    ) -> Result<crate::discovery::engine::inventory_coordinator::JointCommitProgress, SemanticRefusal>
    {
        let mut budget = crate::inventory_semantics::JointWorkBudget {
            remaining_actions: work,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let Self {
            scene,
            machine,
            native,
            finish,
        } = self;
        let mut io = HeldMachineIo {
            drain: &mut scene.drain,
            h0: &scene.real.h0,
            producers: &scene.producers,
            attached: scene.attached.as_ref().unwrap(),
            native,
            finish: finish.as_mut(),
        };
        machine.poll_commit_with_io(
            &mut scene.real.lane,
            &mut scene.real.scene.coordinator,
            &mut io,
            &mut budget,
        )
    }

    fn resolve_pending_q(
        &mut self,
        q: &crate::attach::CollectedFinishQ,
        discovery: &crate::events::DiscoveryDomain,
        work: usize,
    ) -> Result<crate::inventory_semantics::JointServiceProgress, SemanticRefusal> {
        let mut budget = crate::inventory_semantics::JointWorkBudget {
            remaining_actions: work,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let Self {
            scene,
            machine,
            native,
            finish,
        } = self;
        let mut io = HeldMachineIo {
            drain: &mut scene.drain,
            h0: &scene.real.h0,
            producers: &scene.producers,
            attached: scene.attached.as_ref().unwrap(),
            native,
            finish: finish.as_mut(),
        };
        machine.resolve_pending_h0_at_q_with_io(
            &mut scene.real.lane,
            &mut scene.real.scene.coordinator,
            &mut io,
            q,
            discovery,
            &mut budget,
        )
    }

    fn enable_finish_fixture(&mut self, discovery: Vec<Vec<u8>>) {
        assert!(self.finish.is_none());
        self.finish = Some(FinishMachineFixture {
            observer: crate::attach::CollectedFinishQObserverForTest::with_discovery_bytes(
                &self.scene.producers,
                discovery,
            ),
            staged: crate::attach::DiscoveryStage::default(),
            stop_requests: 0,
            q_observations: 0,
            stops: 0,
            at_stop: None,
        });
    }

    fn begin_finish(&mut self) -> Result<(), SemanticRefusal> {
        let Self {
            scene,
            machine,
            native,
            finish,
        } = self;
        let mut io = HeldMachineIo {
            drain: &mut scene.drain,
            h0: &scene.real.h0,
            producers: &scene.producers,
            attached: scene.attached.as_ref().unwrap(),
            native,
            finish: finish.as_mut(),
        };
        machine.begin_finish_with_io(
            &mut scene.real.lane,
            &mut scene.real.scene.coordinator,
            &mut io,
        )
    }

    fn poll_finish(
        &mut self,
        work: usize,
    ) -> Result<crate::discovery::engine::inventory_coordinator::JointCommitProgress, SemanticRefusal>
    {
        let Self {
            scene,
            machine,
            native,
            finish,
        } = self;
        let mut io = HeldMachineIo {
            drain: &mut scene.drain,
            h0: &scene.real.h0,
            producers: &scene.producers,
            attached: scene.attached.as_ref().unwrap(),
            native,
            finish: finish.as_mut(),
        };
        let mut budget = crate::inventory_semantics::JointWorkBudget {
            remaining_actions: work,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        machine.poll_finish_with_io(
            &mut scene.real.lane,
            &mut scene.real.scene.coordinator,
            &mut io,
            &mut budget,
        )
    }

    /// Poll Finish with a scripted discovery IO (progress tests): the
    /// first `progressed_for` discovery credits report Engine progress
    /// with zero records, later ones report none. Returns the poll
    /// outcome and the discovery service call count.
    fn poll_finish_discovery_scripted(
        &mut self,
        work: usize,
        progressed_for: usize,
    ) -> (
        Result<
            crate::discovery::engine::inventory_coordinator::JointCommitProgress,
            SemanticRefusal,
        >,
        usize,
    ) {
        let mut budget = crate::inventory_semantics::JointWorkBudget {
            remaining_actions: work,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let mut script = DiscoveryScriptIo {
            producers: &self.scene.producers,
            discovery: self
                .finish
                .as_ref()
                .expect("finish fixture enabled")
                .observer
                .discovery_domain(),
            calls: Cell::new(0),
            progressed_for,
        };
        let result = self.machine.poll_finish_with_io(
            &mut self.scene.real.lane,
            &mut self.scene.real.scene.coordinator,
            &mut script,
            &mut budget,
        );
        (result, script.calls.get())
    }

    fn reach_finish_stop_ready(&mut self) {
        for _ in 0..512 {
            if self.machine.finish_stop_ready_for_test() {
                assert!(!self.scene.real.h0.0.borrow().capture.stopped);
                assert_eq!(self.finish.as_ref().unwrap().stops, 0);
                return;
            }
            assert!(matches!(
                self.poll_finish(1).unwrap(),
                crate::discovery::engine::inventory_coordinator::JointCommitProgress::Pending
            ));
        }
        self.publication_failed("Finish final original before Stop", None, None);
    }

    fn finish_published(
        &mut self,
    ) -> crate::discovery::engine::inventory_coordinator::BatchReceipt {
        for _ in 0..512 {
            match self.poll_finish(1).unwrap_or_else(|reason| {
                self.publication_failed("matching collected Finish", None, Some(reason));
            }) {
                crate::discovery::engine::inventory_coordinator::JointCommitProgress::Pending => {
                    assert!(!self.scene.real.lane.is_finished());
                    assert!(self.scene.real.lane.begin_owned_terminal_cleanup().is_err());
                }
                crate::discovery::engine::inventory_coordinator::JointCommitProgress::Published(
                    receipt,
                ) => {
                    assert!(self.scene.real.lane.is_finished());
                    return receipt;
                }
            }
        }
        self.publication_failed("matching collected Finish", None, None);
    }

    fn finish_storage_bytes(&self) -> usize {
        let finish = self.finish.as_ref().unwrap();
        self.scene
            .real
            .h0
            .0
            .borrow()
            .capture
            .collected_stop_at_q_storage_bytes(
                self.machine.retained_raw_for_test().unwrap(),
                self.scene.real.scene.coordinator.joint_capture().adapter(),
                &self.scene.producers,
                finish.observer.discovery_domain(),
                self.machine.retained_finish_q_for_test().unwrap(),
            )
            .unwrap()
    }

    fn published(&mut self) {
        self.published_labeled("unlabeled", None);
    }

    fn published_labeled(&mut self, label: &str, frozen: Option<bool>) {
        for _ in 0..512 {
            let progress = self.service(1).unwrap_or_else(|reason| {
                self.publication_failed(label, frozen, Some(reason));
            });
            if label.starts_with("absence")
                && self.machine.diagnostic_snapshot_for_test().0 == "Births"
                && let Some(prepared) = self.scene.real.scene.coordinator.prepared_semantic_batch()
            {
                eprintln!(
                    "machine_prepared label={label} entries={} current={} new={} admissions={} claims_ok={} claims_err={}",
                    prepared.entry_count(),
                    prepared.current_receipts().len(),
                    prepared
                        .current_receipts()
                        .iter()
                        .filter(|receipt| receipt.birth_quantum().is_some())
                        .count(),
                    prepared.admissions().count(),
                    prepared
                        .claims()
                        .filter(|(_, result)| result.is_ok())
                        .count(),
                    prepared
                        .claims()
                        .filter(|(_, result)| result.is_err())
                        .count(),
                );
            }
            if matches!(
                progress,
                crate::inventory_semantics::JointServiceProgress::Published
            ) {
                return;
            }
        }
        self.publication_failed(label, frozen, None);
    }

    fn publication_failed(
        &self,
        label: &str,
        frozen: Option<bool>,
        refusal: Option<SemanticRefusal>,
    ) -> ! {
        let coordinator = &self.scene.real.scene.coordinator;
        panic!(
            "the same machine must publish the retained original within its finite work bound; \
             label={label} frozen={frozen:?} refusal={refusal:?} snapshot={:?} preparations={} revision={} \
             publication_pending={} h3={:?} claims={} roles={:?} audit={:?} \
             absence_queries={} birth_outcomes={:?}",
            self.machine.diagnostic_snapshot_for_test(),
            self.native.preparations.len(),
            coordinator.registry().published_revision(),
            coordinator.publication_pending(),
            coordinator.reference_h3_audit_state(),
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test()
                .0,
            coordinator.joint_capture().ledger().roles_for_test(),
            self.machine.diagnostic_audit_for_test(),
            self.native.absence_reads.len(),
            self.native.birth_outcomes,
        );
    }

    fn prime(&mut self, providers: usize) {
        for file in 0..providers {
            self.scene.push(
                std::process::id(),
                file as u32,
                "C_CreateObject",
                file as u64 + 1,
            );
        }
        self.published();
        assert_eq!(
            self.scene.real.scene.coordinator.registry().joint_feeds(),
            providers
        );
    }

    fn reduced_for(&self, file: usize) -> u64 {
        let registry = self.scene.real.scene.coordinator.registry();
        let module = registry
            .modules()
            .find(|module| module.key == self.scene.real.modules[file].0)
            .unwrap()
            .id;
        let mut records = registry
            .instance_semantic_edges()
            .filter(|record| record.module == module);
        let result = records.next().unwrap().feed.reduced();
        assert!(
            records.next().is_none(),
            "this fixture has one original incarnation per provider"
        );
        result
    }

    fn reduced(&self) -> Vec<u64> {
        self.scene
            .real
            .scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .map(|record| record.feed.reduced())
            .collect()
    }
}

/// Same decoded DISCOVERY transport as the production reader, scoped to an
/// owned child. This controlled LEADER_EXIT stimulus is never physical-exit,
/// Q, Current, cessation or completion authority.
fn finish_discovery_bytes(pid: u32, at: u64) -> Vec<u8> {
    let mut record: p11scope_ebpf_common::DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT;
    record.pid_tgid = (u64::from(pid) << 32) | u64::from(pid);
    record.hook_ts_ns = at;
    // SAFETY: the shared repr(C) transport is completely initialized above,
    // including padding from zeroed, just as existing discovery fixtures.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&record as *const p11scope_ebpf_common::DiscoveryRecord).cast::<u8>(),
            size_of::<p11scope_ebpf_common::DiscoveryRecord>(),
        )
        .to_vec()
    };
    assert!(crate::events::decode_discovery(&bytes).is_some());
    bytes
}

/// An EXEC discovery record (a process birth): same transport shape
/// as the exit records, leader pid/tgid, unknown classification.
fn finish_exec_bytes(pid: u32, at: u64) -> Vec<u8> {
    let mut record: p11scope_ebpf_common::DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = p11scope_ebpf_common::DISCOVERY_KIND_EXEC;
    record.case_id = p11scope_ebpf_common::DISCOVERY_EXEC_UNKNOWN;
    record.pid_tgid = (u64::from(pid) << 32) | u64::from(pid);
    record.hook_ts_ns = at;
    // SAFETY: the shared repr(C) transport is completely initialized above,
    // including padding from zeroed, just as existing discovery fixtures.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&record as *const p11scope_ebpf_common::DiscoveryRecord).cast::<u8>(),
            size_of::<p11scope_ebpf_common::DiscoveryRecord>(),
        )
        .to_vec()
    };
    assert!(crate::events::decode_discovery(&bytes).is_some());
    bytes
}

struct FinishCustody {
    raw: Option<crate::semantics_objects::journal::joint_driver::RawQuantumIdentity>,
    boundary: crate::events::EventsConsumptionCut,
    revision: u64,
    h3: (usize, bool),
    frontier: crate::semantics_objects::journal::ConsumptionOrdinal,
    publication_pending: bool,
    roles: [usize; 5],
    claims: (usize, Vec<(u64, JournalDomainProof)>),
    model: crate::semantics_objects::ObjectProjection,
    charged: usize,
    stops: usize,
    preparations: usize,
    validations: usize,
    finished: bool,
    stopped: bool,
}

impl FinishCustody {
    fn observe(fixture: &MachineScene) -> Self {
        let coordinator = &fixture.scene.real.scene.coordinator;
        let held = fixture.scene.real.h0.0.borrow();
        Self {
            raw: fixture
                .machine
                .retained_raw_for_test()
                .map(RawJointQuantum::h0_identity),
            boundary: fixture.scene.drain.consumption_cut().unwrap(),
            revision: coordinator.registry().published_revision(),
            h3: coordinator.reference_h3_audit_state(),
            frontier: coordinator.joint_capture().adapter().consumed_frontier(),
            publication_pending: coordinator.publication_pending(),
            roles: coordinator.joint_capture().ledger().roles_for_test(),
            claims: coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            model: coordinator.joint_capture().model().project(),
            charged: coordinator
                .registry()
                .semantic_resource_snapshot()
                .charged_bytes,
            stops: fixture.finish.as_ref().unwrap().stops,
            preparations: fixture.native.preparations.len(),
            validations: held.validations,
            finished: fixture.scene.real.lane.is_finished(),
            stopped: held.capture.stopped,
        }
    }

    fn assert_unchanged(&self, fixture: &MachineScene) {
        let after = Self::observe(fixture);
        assert!(after.raw == self.raw);
        assert!(after.boundary.same_boundary(&self.boundary));
        assert_eq!(after.revision, self.revision);
        assert_eq!(after.h3, self.h3);
        assert!(after.frontier == self.frontier);
        assert_eq!(after.publication_pending, self.publication_pending);
        assert_eq!(after.roles, self.roles);
        assert!(after.claims == self.claims);
        assert!(after.model == self.model);
        assert_eq!(after.charged, self.charged);
        assert_eq!(after.stops, self.stops);
        assert_eq!(after.preparations, self.preparations);
        assert_eq!(after.validations, self.validations);
        assert_eq!(after.finished, self.finished);
        assert_eq!(after.stopped, self.stopped);
    }
}

/// The real caller/mapping admission already exists, but no ordinary machine
/// service or H8 grant precedes Finish. Q must retain that original absence of
/// a grant without making the first actual admission unusable later.
#[test]
fn joint_machine_collected_finish_first_unread_work_reaches_h9() {
    use crate::discovery::caller_registry::MappingState;

    let mut fixture = MachineScene::new(1);
    assert_eq!(fixture.machine.diagnostic_snapshot_for_test().0, "Idle");
    assert!(fixture.machine.retained_drain_grant_for_test().is_none());
    assert!(fixture.machine.retained_raw_for_test().is_none());
    assert!(fixture.native.preparations.is_empty());
    assert!(fixture.native.birth_outcomes.is_empty());
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .semantic_bindings()
            .len(),
        0
    );
    let pid = std::process::id();
    let caller = fixture
        .scene
        .real
        .scene
        .coordinator
        .adapter()
        .live_id(pid)
        .unwrap();
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .modules()
            .any(|module| {
                module.key == fixture.scene.real.modules[0].0
                    && fixture
                        .scene
                        .real
                        .scene
                        .coordinator
                        .registry()
                        .edge(caller, module.id)
                        .is_some_and(|edge| edge.mapping == MappingState::Mapped)
            }),
        "first work uses the fixture's actual preexisting caller/mapping admission"
    );
    for (name, sequence) in [("C_CreateObject", 1), ("C_SignInit", 2), ("C_SignFinal", 3)] {
        fixture.scene.push(pid, 0, name, sequence);
    }
    let unread = fixture.scene.drain.consumption_cut().unwrap();
    assert!(!unread.is_drained());
    assert_eq!(fixture.scene.drain.source_mut().remaining(), 6);
    fixture.enable_finish_fixture(Vec::new());
    let revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    let h3 = fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_h3_audit_state();
    fixture.begin_finish().unwrap();
    assert!(unread.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
    assert!(fixture.machine.retained_drain_grant_for_test().is_none());
    assert!(fixture.scene.real.lane.tick(&[]).is_err());
    assert!(
        fixture
            .scene
            .real
            .lane
            .begin_owned_terminal_cleanup()
            .is_err()
    );
    let zero = FinishCustody::observe(&fixture);
    fixture.poll_finish(0).unwrap();
    zero.assert_unchanged(&fixture);

    let mut first_raw = None;
    let mut refusal = None;
    for _ in 0..512 {
        let progress = fixture.poll_finish(1);
        if let Some(raw) = fixture.machine.retained_raw_for_test() {
            let original = *first_raw.get_or_insert(raw.h0_identity());
            assert!(
                original == raw.h0_identity(),
                "the first owned collection is retained"
            );
        }
        assert!(!fixture.scene.real.h0.0.borrow().capture.stopped);
        assert!(!fixture.scene.real.lane.is_finished());
        assert_eq!(fixture.finish.as_ref().unwrap().stops, 0);
        assert!(
            fixture
                .scene
                .real
                .lane
                .begin_owned_terminal_cleanup()
                .is_err()
        );
        match progress {
            Ok(crate::discovery::engine::inventory_coordinator::JointCommitProgress::Pending) => {}
            Ok(
                crate::discovery::engine::inventory_coordinator::JointCommitProgress::Published(_),
            ) => {
                panic!("Finish cannot publish before observing the useful last return while live");
            }
            Err(reason) => {
                // Preserve a diagnostic for the intended current guard RED;
                // unrelated fixture/owner/capacity errors are not this seam.
                assert_eq!(reason, SemanticRefusal::Unavailable);
                let q = fixture.machine.retained_finish_q_for_test().unwrap();
                let grant = fixture
                    .machine
                    .retained_drain_grant_for_test()
                    .expect("only the actual original admission may change None to Some");
                assert!(grant.matches_producers(&fixture.scene.producers));
                assert!(!q.matches_retained_grant(grant));
                let raw = fixture.machine.retained_raw_for_test().unwrap();
                let adapter = fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .adapter();
                raw.validate_preparation(adapter, &fixture.scene.producers)
                    .unwrap();
                raw.validate_collected_q(
                    &fixture.scene.producers,
                    fixture.finish.as_ref().unwrap().observer.discovery_domain(),
                    q,
                )
                .unwrap();
                refusal = Some(reason);
                break;
            }
        }
        if fixture.reduced() == [3]
            && fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .published_revision()
                == revision + 1
            && !fixture.scene.real.scene.coordinator.publication_pending()
        {
            break;
        }
    }
    assert_eq!(
        fixture.reduced(),
        [3],
        "the first real New/claim and its last return must reach actual H9 before Stop; refusal={refusal:?}, phase={:?}, native_births={:?}",
        fixture.machine.diagnostic_snapshot_for_test(),
        fixture.native.birth_outcomes
    );
    assert!(first_raw.is_some());
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .joint_feeds(),
        1
    );
    assert!(fixture.ready_birth(0).is_some());
    assert_eq!(
        fixture
            .native
            .birth_outcomes
            .iter()
            .filter(|(_, result)| result.is_ok())
            .count(),
        1
    );
    assert!(
        fixture.native.absence_reads.is_empty(),
        "Q starts no fresh absence acquisition"
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision(),
        revision + 1
    );
    assert_eq!(fixture.native.preparations.len(), 1);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state()
            .0,
        h3.0 + 1
    );
    assert_eq!(fixture.scene.drain.source_mut().remaining(), 0);
    assert!(
        fixture
            .scene
            .drain
            .consumption_cut()
            .unwrap()
            .clean_successor_of(&unread)
    );
    let q = fixture.machine.retained_finish_q_for_test().unwrap();
    assert!(q.matches_owner(
        &fixture.scene.producers,
        fixture.finish.as_ref().unwrap().observer.discovery_domain()
    ));
    assert!(q.events_at_bound(&fixture.scene.drain.consumption_cut().unwrap()));
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        0
    );

    // The final empty original still owes real physical-tail processing while
    // Capture is live; no receipt or initial grant can substitute for it.
    fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_mark_tail(caller);
    let raises = fixture.scene.real.h0.0.borrow().io.script.raises;
    let receipt = fixture.finish_published();
    assert_eq!(receipt.registry_published, revision + 2);
    assert_eq!(fixture.native.preparations.len(), 2);
    let finish = fixture.finish.as_ref().unwrap();
    assert_eq!(
        (finish.stop_requests, finish.q_observations, finish.stops),
        (1, 1, 1)
    );
    let stopped = finish.at_stop.as_ref().unwrap();
    assert!(
        Some(stopped.raw) != first_raw,
        "the final empty Raw is its own original"
    );
    assert_eq!(stopped.reduced, 3);
    assert_eq!(stopped.revision, revision + 1);
    assert!(fixture.scene.real.h0.0.borrow().io.script.raises > raises);
    assert_eq!(
        fixture.scene.real.h0.0.borrow().validations,
        stopped.validations
    );
    assert_eq!(fixture.reduced(), [3]);
    assert!(fixture.scene.real.lane.is_finished());
    assert!(
        fixture
            .scene
            .real
            .lane
            .begin_owned_terminal_cleanup()
            .is_ok()
    );
    let completed = FinishCustody::observe(&fixture);
    assert!(fixture.poll_finish(1).is_err());
    completed.assert_unchanged(&fixture);
}

/// Stopping before the final return's real seal, or applying a physical tail
/// only after Capture.stop, must fail this useful reduction/order control.
#[test]
fn joint_machine_collected_finish_preserves_last_return_before_stopped() {
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.scene.push(std::process::id(), 0, "C_SignInit", 2);
    fixture.published_labeled("Finish prior Init", None);
    assert_eq!(fixture.reduced(), [2]);
    fixture.scene.push(std::process::id(), 0, "C_SignFinal", 3);
    fixture.enable_finish_fixture(Vec::new());
    let revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    let h3 = fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_h3_audit_state();
    fixture.begin_finish().unwrap();
    assert!(
        fixture.scene.real.lane.tick(&[]).is_err(),
        "ordinary H0 admission is gated"
    );
    let mut saw_last_return = false;
    let mut last_return_published = false;
    for _ in 0..512 {
        assert!(matches!(
            fixture.poll_finish(1).unwrap(),
            crate::discovery::engine::inventory_coordinator::JointCommitProgress::Pending
        ));
        assert!(!fixture.scene.real.h0.0.borrow().capture.stopped);
        assert_eq!(fixture.finish.as_ref().unwrap().stops, 0);
        if fixture.reduced() == [3] && !saw_last_return {
            saw_last_return = true;
            assert!(fixture.scene.real.scene.coordinator.publication_pending());
        }
        if saw_last_return {
            assert_eq!(fixture.reduced(), [3]);
            let current_revision = fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .published_revision();
            assert!(current_revision <= revision + 1);
            if current_revision == revision + 1
                && !fixture.scene.real.scene.coordinator.publication_pending()
            {
                last_return_published = true;
                break;
            }
        }
    }
    assert!(
        saw_last_return,
        "the last original reaches actual H9 before Stop"
    );
    assert!(
        last_return_published,
        "the actual original publishes before Stop"
    );
    assert!(!fixture.scene.real.h0.0.borrow().capture.stopped);
    assert_eq!(fixture.finish.as_ref().unwrap().stops, 0);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision(),
        revision + 1
    );
    // A nonempty physical tail belongs to the final original. Its actual
    // Capture.apply_physical_gaps must run while that Capture is still live.
    let caller = fixture
        .scene
        .real
        .scene
        .coordinator
        .adapter()
        .live_id(std::process::id())
        .unwrap();
    fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_mark_tail(caller);
    let raises = fixture.scene.real.h0.0.borrow().io.script.raises;
    let receipt = fixture.finish_published();
    assert!(receipt.registry_published > revision + 1);
    let finish = fixture.finish.as_ref().unwrap();
    assert_eq!(
        (finish.stop_requests, finish.q_observations, finish.stops),
        (1, 1, 1)
    );
    let at_stop = finish.at_stop.as_ref().unwrap();
    assert_eq!(at_stop.reduced, 3);
    assert!(at_stop.revision >= revision + 1);
    assert_eq!(
        at_stop.h3.0,
        h3.0 + 1,
        "the useful original finishes its own H3 before Stop"
    );
    assert!(
        fixture.scene.real.h0.0.borrow().io.script.raises > raises,
        "the genuine physical tail was applied before actual Stop"
    );
    assert_eq!(
        fixture.scene.real.h0.0.borrow().validations,
        at_stop.validations,
        "no Current validation is deferred until after Stopped"
    );
    assert_eq!(fixture.reduced(), [3]);
    assert!(fixture.scene.real.lane.tick(&[]).is_err());
    assert!(
        fixture
            .scene
            .real
            .lane
            .begin_owned_terminal_cleanup()
            .is_ok()
    );
}

/// Final Idle work uses a real new Raw on the SAME cursor, accounts for both
/// rings/FIFO/Engine backlog, and refuses a genuine post-Q producer movement.
#[test]
fn joint_machine_collected_finish_idle_uses_same_cursor_q() {
    let child = OwnedStoppedChild::new();
    let exited_pid = child.id();
    drop(child); // Reap this separate owned subject; the active semantic owner remains live.
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(vec![
        finish_discovery_bytes(exited_pid, 100),
        finish_discovery_bytes(exited_pid, 101),
        finish_discovery_bytes(exited_pid, 102),
    ]);
    // The first ORIGINAL record reaches the Engine's real ingestion path in
    // an exhausted live frame. That path retains it in pending_discovery_records
    // without dispatch. A vanished queue alone is not a processing oracle.
    let mut engine_input = None;
    {
        let finish = fixture.finish.as_mut().unwrap();
        let drain = finish.observer.discovery_drain_mut();
        let bound = crate::events::discovery_drain_positions(drain).producer;
        crate::events::poll_discovery_to_position(drain, bound, Some(1), |item| {
            let crate::events::DiscoveryItem::Record(record) = item else {
                panic!("the owned child's original DISCOVERY input decodes");
            };
            assert!(engine_input.replace(record).is_none());
            std::ops::ControlFlow::Continue(())
        })
        .unwrap();
    }
    let record = engine_input.unwrap();
    assert_eq!(record.hook_ts_ns, 100);
    assert_eq!(record.pid_tgid >> 32, u64::from(exited_pid));
    assert_eq!(
        record.kind,
        p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_finish_exit_subject_for_test(exited_pid, 100),
        (true, false, false),
        "System scope admits generations, but this separate subject has no matched Engine view or covering admission"
    );
    fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_defer_finish_discovery_for_test(record)
        .unwrap();
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_collected_finish_discovery_head_for_test(),
        Some((
            exited_pid,
            100,
            p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT
        )),
        "actual exhausted-frame ingestion retains this original at the Engine head"
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_collected_finish_discovery_backlog(0)
            .0,
        1
    );
    assert!(
        !fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_unmatched_finish_exit_for_test(exited_pid, 100)
    );
    // Move one actual decoded item into the existing Session FIFO before Q.
    // Its credit and bytes remain held; the ring retains the third item.
    {
        let FinishMachineFixture {
            observer, staged, ..
        } = fixture.finish.as_mut().unwrap();
        let drain = observer.discovery_drain_mut();
        let bound = crate::events::discovery_drain_positions(drain).producer;
        crate::events::poll_discovery_to_position(drain, bound, Some(1), |item| {
            let mut original = Some(item);
            let staged_outcome = staged.stage(1, crate::attach::DiscoveryStage::CAPACITY, || {
                original.take()
            });
            assert_eq!(staged_outcome.staged, 1);
            std::ops::ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(observer.discovery_remaining(), 1);
    }
    let cursor = fixture.scene.drain.consumption_cut().unwrap();
    let h3 = fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_h3_audit_state();
    fixture.begin_finish().unwrap();
    let zero = FinishCustody::observe(&fixture);
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_collected_finish_discovery_backlog(1)
            .0
            > 0
    );
    assert!(matches!(
        fixture.poll_finish(0).unwrap(),
        crate::discovery::engine::inventory_coordinator::JointCommitProgress::Pending
    ));
    zero.assert_unchanged(&fixture);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_collected_finish_discovery_head_for_test(),
        Some((
            exited_pid,
            100,
            p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT
        ))
    );
    assert!(!fixture.scene.real.lane.is_finished());
    assert!(
        fixture
            .scene
            .real
            .lane
            .begin_owned_terminal_cleanup()
            .is_err()
    );
    let mut reached_final_original = false;
    for _ in 0..512 {
        let progress = fixture.poll_finish(1).unwrap();
        let finish = fixture.finish.as_ref().unwrap();
        let pending = fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_collected_finish_discovery_backlog(finish.staged.len());
        if pending.0 > 0 || pending.1 {
            assert!(matches!(
                progress,
                crate::discovery::engine::inventory_coordinator::JointCommitProgress::Pending
            ));
            assert!(!fixture.scene.real.h0.0.borrow().capture.stopped);
            assert_eq!(finish.stops, 0);
            assert!(!fixture.scene.real.lane.is_finished());
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .registry()
                    .published_revision(),
                zero.revision
            );
            assert!(
                fixture
                    .scene
                    .real
                    .lane
                    .begin_owned_terminal_cleanup()
                    .is_err()
            );
        }
        if fixture.machine.finish_stop_ready_for_test() {
            reached_final_original = true;
            break;
        }
    }
    assert!(
        reached_final_original,
        "the retained actual Engine/FIFO/ring work progresses within the original bound"
    );
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_unmatched_finish_exit_for_test(exited_pid, 100),
        "the exact original LEADER_EXIT must reach actual lifecycle dispatch; discarding it is not progress"
    );
    let raw = fixture
        .machine
        .retained_raw_for_test()
        .expect("Idle creates the actual final Raw");
    let final_id = raw.h0_identity();
    let q = fixture.machine.retained_finish_q_for_test().unwrap();
    assert!(q.events_at_bound(&fixture.scene.drain.consumption_cut().unwrap()));
    assert!(cursor.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
    assert_eq!(fixture.finish.as_ref().unwrap().staged.len(), 0);
    assert_eq!(
        fixture
            .finish
            .as_ref()
            .unwrap()
            .observer
            .discovery_remaining(),
        0
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_collected_finish_discovery_backlog(0),
        (0, false)
    );
    assert!(!fixture.scene.real.h0.0.borrow().capture.stopped);
    fixture.finish_published();
    let at_stop = fixture.finish.as_ref().unwrap().at_stop.as_ref().unwrap();
    assert!(
        at_stop.raw == final_id,
        "Stop output belongs to the same final Raw"
    );
    assert_eq!(fixture.finish.as_ref().unwrap().stops, 1);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (h3.0 + 1, false)
    );

    let mut moved = MachineScene::new(1);
    moved.enable_finish_fixture(Vec::new());
    moved.begin_finish().unwrap();
    for _ in 0..128 {
        if moved.machine.retained_finish_q_for_test().is_some() {
            break;
        }
        moved.poll_finish(1).unwrap();
    }
    assert!(moved.machine.retained_finish_q_for_test().is_some());
    let boundary = moved.scene.drain.consumption_cut().unwrap();
    let (begin, _) = moved
        .scene
        .encoded(std::process::id(), 0, "C_CreateObject", 1);
    moved.scene.drain.source_mut().push_record(begin.to_vec());
    let mut refused = false;
    for _ in 0..128 {
        if moved.poll_finish(1).is_err() {
            refused = true;
            break;
        }
    }
    assert!(
        refused,
        "the original Q never silently advances to a later producer bound"
    );
    assert_eq!(moved.scene.drain.source_mut().remaining(), 1);
    assert!(
        moved
            .scene
            .drain
            .consumption_cut()
            .unwrap()
            .same_boundary(&boundary)
    );
    assert_eq!(moved.finish.as_ref().unwrap().stops, 0);
    assert!(!moved.scene.real.lane.is_finished());
    assert!(
        moved
            .scene
            .real
            .lane
            .begin_owned_terminal_cleanup()
            .is_err()
    );
}

/// A Stop report or Copy BatchReceipt is insufficient: a held final frame or
/// publication error must withhold every cleanup entrypoint until disposal.
#[test]
fn joint_machine_collected_finish_pending_publication_blocks_detach() {
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    fixture.begin_finish().unwrap();
    fixture.reach_finish_stop_ready();
    fixture.machine.reference_refuse_finish_q_merge_once();
    let before = FinishCustody::observe(&fixture);
    let mut refused = false;
    for _ in 0..128 {
        if let Err(reason) = fixture.poll_finish(1) {
            assert_eq!(reason, SemanticRefusal::ProviderStorage);
            refused = true;
            break;
        }
        assert!(!fixture.scene.real.lane.is_finished());
    }
    assert!(refused);
    assert_eq!(fixture.finish.as_ref().unwrap().stops, 1);
    assert!(fixture.scene.real.h0.0.borrow().capture.stopped);
    assert!(fixture.machine.retained_finish_report_for_test().is_some());
    assert!(!fixture.scene.real.lane.is_finished());
    assert!(
        fixture
            .scene
            .real
            .lane
            .begin_owned_terminal_cleanup()
            .is_err()
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        before.h3
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision(),
        before.revision
    );
    let retained_stop = FinishCustody::observe(&fixture);
    assert!(
        fixture.scene.real.lane.finish_semantic_stop().is_none(),
        "the legacy shortcut cannot mark a collected Finish published"
    );
    retained_stop.assert_unchanged(&fixture);
    // Refuse at the actual publication receiver, after the original final
    // report has been retained. It supplies neither a seal nor completion.
    fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_refuse_joint_finish_publication_once();
    let mut publication_refused = false;
    for _ in 0..512 {
        if fixture.poll_finish(1).is_err() {
            publication_refused = true;
            break;
        }
        assert!(!fixture.scene.real.lane.is_finished());
        assert!(
            fixture
                .scene
                .real
                .lane
                .begin_owned_terminal_cleanup()
                .is_err()
        );
    }
    assert!(publication_refused);
    assert!(fixture.scene.real.scene.coordinator.publication_pending());
    assert!(
        fixture
            .machine
            .retained_finish_disposition_for_test()
            .is_some(),
        "the actual disposed original stays owned before any Copy receipt"
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision(),
        before.revision
    );
    assert_eq!(fixture.finish.as_ref().unwrap().stops, 1);
    assert!(!fixture.scene.real.lane.is_finished());
    assert!(
        fixture
            .scene
            .real
            .lane
            .begin_owned_terminal_cleanup()
            .is_err()
    );
    // The consuming helper must reject this SAME unpublished owner too. No
    // detach/join is simulated, and an errored publication is not replayed.
    let machine = fixture.machine;
    assert!(
        fixture
            .scene
            .real
            .lane
            .finish_owned_terminal_cleanup(&|| false, &mut Vec::new(),)
            .is_err()
    );
    assert!(machine.retained_finish_disposition_for_test().is_some());
}

#[test]
fn joint_machine_current_provider_uses_frozen_physical_mapping_only() {
    for mapping in ["healthy", "later", "foreign", "unscanned", "retired"] {
        let mut fixture = MachineScene::absence_scene(3);
        fixture.wait_absence(1);
        fixture.make_provider_present(1, 2);
        if mapping != "later" {
            fixture.stage_appearance_mapping(if mapping == "foreign" { 2 } else { 1 });
        }
        if mapping == "healthy" {
            // Two notes of the SAME exact key do not introduce ambiguity.
            fixture.stage_appearance_mapping(1);
        }
        let coordinator = &mut fixture.scene.real.scene.coordinator;
        let caller = coordinator.adapter().live_id(std::process::id()).unwrap();
        if mapping == "unscanned" {
            coordinator.registry_mut().note_member_unscanned(caller);
        } else if mapping == "retired" {
            coordinator.registry_mut().retire_caller(
                caller,
                "original physical retirement".into(),
                71,
            );
        }
        fixture
            .scene
            .push(std::process::id(), 1, "C_CreateObject", 2);
        fixture.reach_phase("PreparingAdmissions");
        let identity = fixture
            .machine
            .retained_raw_for_test()
            .unwrap()
            .h0_identity();
        if mapping == "later" {
            fixture.stage_appearance_mapping(1);
            // A repeated preparation cannot widen the original prefix to
            // admit a note queued AFTER its physical context was frozen.
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry_mut()
                .freeze_joint_physical_prefix(fixture.machine.retained_raw_for_test().unwrap())
                .unwrap();
        }
        fixture.reach_phase("BindingKeys");
        let coordinator = &fixture.scene.real.scene.coordinator;
        let prepared = coordinator.prepared_semantic_batch().unwrap();
        let current = prepared
            .current_receipts()
            .iter()
            .find(|receipt| receipt.endpoint().file_slot == 1)
            .unwrap();
        assert!(current.birth_quantum() == Some(identity), "{mapping}");
        let binding = coordinator
            .semantic_bindings()
            .find_by_image(current.domain(), current.image())
            .unwrap();
        assert!(Arc::ptr_eq(&binding.pin(), current.original_pin()));
        let module = coordinator.registry().joint_current_provider_module(
            current,
            binding,
            fixture.scene.real.lane.subset(),
        );
        assert_eq!(
            module,
            (mapping == "healthy").then_some(&fixture.scene.real.modules[1].0),
            "{mapping}: only the exact frozen physical context may label this Current"
        );
        assert_eq!(
            binding.provider_for_endpoint(current.endpoint()).is_some(),
            mapping == "healthy",
            "{mapping}: a mapping label must still traverse the actual owner validator and promotion"
        );
        assert!(fixture.pending_absence(1).is_some());
        assert!(fixture.ready_birth(1).is_none());
        assert!(
            fixture
                .native
                .birth_outcomes
                .iter()
                .all(|(file, _)| *file != 1),
            "{mapping}: provider preparation does not consume the original New"
        );
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test()
                .0,
            0
        );
        if mapping == "healthy" {
            fixture.published_labeled("absence-frozen-mapping", None);
            assert!(fixture.pending_absence(1).is_none());
            assert!(fixture.ready_birth(1).is_some());
            assert_eq!(fixture.reduced_for(1), 1);
        }
    }
}

#[test]
fn joint_machine_current_provider_validation_and_storage_preserve_original() {
    for refusal in ["healthy", "epoch", "storage"] {
        let mut fixture = MachineScene::absence_scene(2);
        fixture.wait_absence(1);
        fixture.appear(1, 2);
        fixture
            .scene
            .push(std::process::id(), 1, "C_CreateObject", 2);
        fixture.reach_phase("BindingKeys");
        let coordinator = &fixture.scene.real.scene.coordinator;
        let current = coordinator
            .prepared_semantic_batch()
            .unwrap()
            .current_receipts()
            .iter()
            .find(|receipt| receipt.endpoint().file_slot == 1)
            .unwrap();
        let original = (
            current.birth_quantum().unwrap(),
            Arc::as_ptr(current.original_pin()),
            current.watched().retirement_lease(),
            current.instances().to_vec(),
        );
        let binding = coordinator
            .semantic_bindings()
            .find_by_image(current.domain(), current.image())
            .unwrap();
        let module = coordinator
            .registry()
            .joint_current_provider_module(current, binding, fixture.scene.real.lane.subset())
            .unwrap();
        let reserve = coordinator.registry().semantic_storage_reserver();
        let before = coordinator.registry().semantic_resource_snapshot();
        let roles = coordinator.joint_capture().ledger().roles_for_test();
        let claims = coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test();
        let h3 = coordinator.reference_h3_audit_state();
        if refusal == "epoch" {
            let mut held = fixture.scene.real.h0.0.borrow_mut();
            let (base, epoch, global) = held.io.scan_input(1);
            held.io.scan_inputs.insert(1, (base, epoch + 1, global));
        }
        let hold = (refusal == "storage").then(|| {
            reserve
                .reserve(before.limit_bytes - before.charged_bytes)
                .unwrap()
        });
        let reservation_calls = Cell::new(0);
        let validations = fixture.scene.real.h0.0.borrow().validations;
        let mut report = TickReport::default();
        let result = fixture.scene.real.lane.validate_current_for_provider(
            current,
            Some(module),
            &mut report,
            |bytes| {
                reservation_calls.set(reservation_calls.get() + 1);
                reserve.reserve(bytes)
            },
        );
        assert_eq!(
            fixture.scene.real.h0.0.borrow().validations,
            validations + 1
        );
        match refusal {
            "healthy" => {
                let (_, provider) = result.unwrap();
                let provider = provider.unwrap();
                assert!(
                    coordinator
                        .registry()
                        .semantic_resource_snapshot()
                        .charged_bytes
                        > before.charged_bytes
                );
                drop(provider);
                assert_eq!(reservation_calls.get(), 1);
            }
            "epoch" => {
                assert!(matches!(result, Err(CurrentReceiptRefusal::Epoch)));
                assert_eq!(reservation_calls.get(), 0);
            }
            "storage" => {
                assert!(matches!(
                    result,
                    Ok((_, Err(SemanticRefusal::ProviderStorage)))
                ));
                assert_eq!(reservation_calls.get(), 1);
            }
            _ => unreachable!(),
        }
        drop(hold);
        assert_eq!(
            coordinator
                .registry()
                .semantic_resource_snapshot()
                .charged_bytes,
            before.charged_bytes,
            "{refusal}: rejected and temporary provider copies refund their exact leases"
        );
        assert!(current.birth_quantum() == Some(original.0));
        assert_eq!(Arc::as_ptr(current.original_pin()), original.1);
        assert!(Arc::ptr_eq(
            &current.watched().retirement_lease(),
            &original.2
        ));
        assert_eq!(current.instances(), original.3);
        assert!(fixture.pending_absence(1).is_some());
        assert!(fixture.ready_birth(1).is_none());
        assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            claims
        );
        assert_eq!(coordinator.reference_h3_audit_state(), h3);
        assert!(
            fixture
                .native
                .birth_outcomes
                .iter()
                .all(|(file, _)| *file != 1)
        );
    }
}

#[test]
fn joint_machine_absence_before_appearance_publishes_first_joint() {
    use crate::semantics_objects::journal::BirthKind;
    let mut fixture = MachineScene::absence_scene(2);
    let pending_before = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    fixture.wait_absence(1);
    let negative = fixture.pending_absence(1).unwrap();
    assert_eq!(
        negative.proof.image(),
        ImageIdentity {
            task_cookie: 71,
            exec_id: 0
        }
    );
    assert_eq!(negative.proof.epochs().local, 1);
    let original = (
        negative.capture,
        Arc::as_ptr(&negative.pin),
        negative.proof.fence(),
    );
    let reads = fixture
        .native
        .absence_reads
        .iter()
        .filter(|(_, _, file)| *file == 1)
        .count();
    for _ in 0..3 {
        fixture.service(1).unwrap();
        let negative = fixture.pending_absence(1).unwrap();
        assert_eq!(
            (
                negative.capture,
                Arc::as_ptr(&negative.pin),
                negative.proof.fence()
            ),
            original
        );
    }
    assert_eq!(
        fixture
            .native
            .absence_reads
            .iter()
            .filter(|(_, _, file)| *file == 1)
            .count(),
        reads
    );
    fixture.appear(1, 2);
    fixture
        .scene
        .push(std::process::id(), 1, "C_CreateObject", 2);
    fixture.scene.push(std::process::id(), 1, "C_SignInit", 3);
    fixture.published_labeled("absence-appearance-create-init", None);
    assert!(
        fixture.pending_absence(1).is_none(),
        "pending B after appearance receipt: snapshot={:?} remaining_wire={} preparations={} births={:?} claims={} roles={:?} h3={:?}",
        fixture.machine.diagnostic_snapshot_for_test(),
        fixture.scene.drain.source_mut().remaining(),
        fixture.native.preparations.len(),
        fixture.native.birth_outcomes,
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
    );
    let witness = fixture.ready_birth(1).unwrap();
    assert_eq!(witness.receipt().birth(), BirthKind::AbsenceAppearance);
    assert!(witness.receipt().birth_cut() >= 1);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .joint_feeds(),
        1
    );
    assert_eq!(fixture.reduced_for(1), 2);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision(),
        pending_before + 1
    );
    fixture.scene.push(std::process::id(), 1, "C_SignFinal", 4);
    fixture.published_labeled("absence-fresh-final", None);
    assert_eq!(fixture.reduced_for(1), 3);
    assert!(fixture.native.reads.get().0 > 0 && fixture.native.reads.get().1 > 0);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        0
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test()[..4],
        [0, 0, 0, 0]
    );
}

#[test]
fn joint_machine_absence_rejects_late_busy_and_affecting_prefix() {
    // Reservation-source healthy twin: BUSY owns its queued bytes and position;
    // releasing unmasks that same item rather than retracting a producer slot.
    let bytes = vec![0x31, 0x22, 0x13];
    let mut source = ScriptedRecords::records([bytes.clone()], 1);
    source.block_front();
    let reserved = crate::events::BoundedRecordSource::positions(&source);
    let (_, allocations, allocated_bytes) = crate::test_alloc::count_allocs_during(|| {
        assert!(crate::events::RecordSource::next_record(&mut source).is_none());
        assert!(matches!(
            crate::events::BoundedRecordSource::bounded_record(&mut source, reserved.producer)
                .unwrap(),
            crate::events::BoundedRecord::Pending
        ));
    });
    assert_eq!((allocations, allocated_bytes), (0, 0));
    assert_eq!(
        crate::events::BoundedRecordSource::positions(&source).consumer,
        reserved.consumer
    );
    source.release_front();
    assert_eq!(
        crate::events::BoundedRecordSource::positions(&source).producer,
        reserved.producer
    );
    match crate::events::BoundedRecordSource::bounded_record(&mut source, reserved.producer)
        .unwrap()
    {
        crate::events::BoundedRecord::Item(item) => assert_eq!(&*item, bytes.as_slice()),
        _ => panic!("the same committed reservation must be read once"),
    }
    assert!(matches!(
        crate::events::BoundedRecordSource::bounded_record(&mut source, reserved.producer).unwrap(),
        crate::events::BoundedRecord::Reached
    ));

    for boundary in ["late", "busy", "affecting"] {
        let mut fixture = MachineScene::absence_scene(2);
        let before = fixture.scene.drain.consumption_cut().unwrap();
        if boundary == "late" {
            fixture.appear(1, 1);
        } else if boundary == "busy" {
            fixture.push_quiet();
            fixture.scene.drain.source_mut().block_front();
            let busy = fixture.scene.drain.consumption_cut().unwrap();
            assert!(!busy.is_drained());
            let queued = fixture.scene.drain.source_mut().remaining();
            for _ in 0..3 {
                fixture.service(1).unwrap();
                assert!(fixture.pending_absence(1).is_none());
                assert!(busy.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
                assert_eq!(fixture.scene.drain.source_mut().remaining(), queued);
            }
            fixture.scene.drain.source_mut().release_front();
            assert!(
                busy.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()),
                "unmasking cannot retreat the producer or advance the consumer"
            );
            fixture.published();
            assert_eq!(fixture.scene.drain.source_mut().remaining(), 0);
            fixture.wait_absence(1);
            fixture.appear(1, 2);
        } else {
            let (begin, _) = fixture
                .scene
                .encoded(std::process::id(), 0, "C_CreateObject", 2);
            fixture.scene.drain.source_mut().push_record(begin.to_vec());
            fixture.machine.begin_commit(false).unwrap();
            fixture.published();
            for _ in 0..4 {
                fixture.service(1).unwrap();
            }
            assert!(fixture.pending_absence(1).is_none());
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .adapter()
                    .retained_start_bytes_for_test((u64::from(std::process::id()), 2)),
                Some(begin)
            );
            fixture.appear(1, 2);
        }
        fixture
            .scene
            .push(std::process::id(), 1, "C_CreateObject", 3);
        fixture.published();
        assert_eq!(fixture.ready_birth(1).is_some(), boundary == "busy");
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .joint_feeds(),
            usize::from(boundary == "busy")
        );
        if boundary == "late" {
            assert!(!before.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
        }
    }
}

#[test]
fn joint_machine_absence_selects_exact_subject_with_mixed_ready_and_pending() {
    let mut fixture = MachineScene::absence_scene(3);
    fixture.wait_absence(1);
    fixture.wait_absence(2);
    let foreign_capture = SemanticCapture::in_domain(
        fixture.scene.producers.native_domain(),
        TickLimits::default(),
    )
    .unwrap();
    let foreign_session = MachineScene::with_initial_files(2, &[0], true);
    let foreign_pin = Arc::new(crate::process::PidPin::open(std::process::id()).unwrap());
    {
        let held = fixture.scene.real.h0.0.borrow();
        let negative = fixture.pending_absence(1).unwrap();
        let image = negative.proof.image();
        let pin = negative.pin.clone();
        let endpoint = held.io.endpoint(held.io.slot(1, "C_CreateObject")).unwrap();
        let adapter = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter();
        let attached = fixture.scene.attached.as_ref().unwrap();
        assert!(negative.matches_origin(
            &held.capture,
            &fixture.scene.producers,
            image,
            &pin,
            endpoint,
            attached,
            adapter
        ));
        assert!(!negative.matches_origin(
            &foreign_capture,
            &fixture.scene.producers,
            image,
            &pin,
            endpoint,
            attached,
            adapter
        ));
        assert!(!negative.matches_origin(
            &held.capture,
            &foreign_session.scene.producers,
            image,
            &pin,
            endpoint,
            attached,
            adapter
        ));
        assert!(!negative.matches_origin(
            &held.capture,
            &fixture.scene.producers,
            image,
            &foreign_pin,
            endpoint,
            attached,
            adapter
        ));
        assert!(!negative.matches_origin(
            &held.capture,
            &fixture.scene.producers,
            ImageIdentity {
                task_cookie: image.task_cookie,
                exec_id: image.exec_id + 1
            },
            &pin,
            endpoint,
            attached,
            adapter
        ));
        let other = held.io.endpoint(held.io.slot(2, "C_CreateObject")).unwrap();
        assert!(!negative.matches_origin(
            &held.capture,
            &fixture.scene.producers,
            image,
            &pin,
            other,
            attached,
            adapter
        ));
    }
    fixture.appear(2, 2);
    fixture
        .scene
        .push(std::process::id(), 2, "C_CreateObject", 2);
    fixture.published();
    assert!(fixture.pending_absence(1).is_some() && fixture.ready_birth(2).is_some());
    assert!(fixture.ready_birth(1).is_none());
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .joint_feeds(),
        1
    );
    assert_eq!(fixture.reduced_for(2), 1);
    let table = fixture.machine.retained_births_for_test();
    let mut matched_targets = 0;
    for (target, _) in fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_history_targets()
    {
        let witness = table
            .find_ready(&target)
            .expect("the exact actual Ready target must be found across pending B");
        assert_eq!(witness.receipt().domain(), target.bootstrap().domain());
        assert_eq!(witness.candidate.receipt.endpoint().file_slot, 2);
        assert_eq!(witness.receipt(), target.bootstrap());
        matched_targets += 1;
    }
    assert_eq!(
        matched_targets, 1,
        "the mixed-table lookup must not be vacuous"
    );
    let coordinator = &fixture.scene.real.scene.coordinator;
    let before_revision = coordinator.registry().published_revision();
    let before_h3 = coordinator.reference_h3_audit_state();
    let before_births = fixture.native.birth_outcomes.len();
    let before_birth_reads = fixture.native.reads.get().0;
    let negative = fixture.pending_absence(1).unwrap();
    let original_negative = (
        negative.capture,
        Arc::as_ptr(&negative.pin),
        negative.proof.fence(),
    );
    fixture.appear(1, 2);
    fixture
        .scene
        .push(std::process::id(), 1, "C_CreateObject", 3);
    fixture.reach_phase("Births");
    {
        let prepared = fixture
            .scene
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap();
        let current = prepared
            .current_receipts()
            .iter()
            .find(|receipt| receipt.endpoint().file_slot == 1)
            .unwrap();
        assert!(current.birth_quantum() == Some(fixture.native.preparations.last().unwrap().0));
        assert_eq!(prepared.claims().count(), 1);
        assert_eq!(
            prepared.claims().find_map(|(ordinal, result)| result
                .as_ref()
                .err()
                .map(|reason| (ordinal, *reason))),
            Some((3, AttestationRefusal::ImageSealed)),
            "a new same-image sibling cannot reinterpret C's already converted history"
        );
    }
    let mut original_negative_audited = false;
    for _ in 0..512 {
        if let Some((gap, h3, _, _, _)) = fixture.machine.diagnostic_audit_for_test() {
            assert_eq!(
                gap,
                Some(crate::semantics_objects::journal::JournalGap::ImageTainted)
            );
            assert_eq!(h3, "Clean");
            original_negative_audited = true;
            break;
        }
        fixture.service(1).unwrap();
    }
    assert!(original_negative_audited);
    fixture.published();
    // Runtime §E keeps ImageSealed conservative: this late sibling stays
    // S1Only and its ORIGINAL ImageTainted negative reaches existing C.
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .joint_feeds(),
        0
    );
    let s1 = |fixture: &MachineScene, file: usize| {
        let registry = fixture.scene.real.scene.coordinator.registry();
        let module = registry
            .module_id_for(&fixture.scene.real.modules[file].0)
            .unwrap();
        let mut rows = registry
            .instance_semantic_edges()
            .filter(|row| row.module == module);
        let row = rows.next().unwrap();
        assert!(rows.next().is_none());
        (
            row.feed.mode(),
            row.feed.reduced(),
            row.api_returns,
            row.semantics.as_ref().unwrap().calls(),
        )
    };
    assert_eq!(
        s1(&fixture, 1),
        (crate::semantics_key_use::FeedMode::S1Only, 0, Some(1), 1),
        "B's actual S1 consumer, independently of the H9 reduced counter"
    );
    assert_eq!(
        s1(&fixture, 2),
        (crate::semantics_key_use::FeedMode::S1Only, 1, Some(1), 1)
    );
    assert_eq!(fixture.native.birth_outcomes.len(), before_births);
    assert_eq!(fixture.native.reads.get().0, before_birth_reads);
    assert!(fixture.ready_birth(1).is_none());
    assert!(fixture.ready_birth(2).is_some());
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(
        coordinator.registry().published_revision(),
        before_revision + 1
    );
    assert_eq!(
        coordinator.reference_h3_audit_state(),
        (before_h3.0 + 1, false)
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        0
    );
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test(),
        [0; 5]
    );
    let negative = fixture.pending_absence(1).unwrap();
    assert_eq!(
        (
            negative.capture,
            Arc::as_ptr(&negative.pin),
            negative.proof.fence()
        ),
        original_negative
    );

    // A genuine later Continued call remains direct S1. It cannot consume
    // the old absence or recreate a New after the exact claim refusal.
    fixture
        .scene
        .push(std::process::id(), 1, "C_CreateObject", 4);
    fixture.reach_phase("Births");
    let prepared = fixture
        .scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap();
    let mut continued = prepared
        .current_receipts()
        .iter()
        .filter(|receipt| receipt.endpoint().file_slot == 1);
    assert!(
        continued
            .next()
            .expect("the same provider has an actual Continued Current")
            .birth_quantum()
            .is_none()
    );
    assert!(continued.all(|receipt| receipt.birth_quantum().is_none()));
    fixture.published();
    assert_eq!(
        s1(&fixture, 1),
        (crate::semantics_key_use::FeedMode::S1Only, 0, Some(2), 2)
    );
    assert_eq!(fixture.reduced_for(2), 1);
    assert_eq!(fixture.native.birth_outcomes.len(), before_births);
    assert_eq!(fixture.native.reads.get().0, before_birth_reads);
    assert!(fixture.ready_birth(1).is_none());
    let negative = fixture.pending_absence(1).unwrap();
    assert_eq!(
        (
            negative.capture,
            Arc::as_ptr(&negative.pin),
            negative.proof.fence()
        ),
        original_negative
    );
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(coordinator.registry().joint_feeds(), 0);
    assert_eq!(
        coordinator.registry().published_revision(),
        before_revision + 2
    );
    assert_eq!(
        coordinator.reference_h3_audit_state(),
        (before_h3.0 + 2, false)
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        0
    );
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test(),
        [0; 5]
    );
}

#[test]
fn joint_machine_absence_two_new_keys_share_first_conversion() {
    use crate::semantics_objects::journal::BirthKind;
    for order in [[1, 2], [2, 1]] {
        let mut fixture = MachineScene::absence_scene(3);
        fixture.wait_absence(1);
        fixture.wait_absence(2);
        let coordinator = &fixture.scene.real.scene.coordinator;
        let revision = coordinator.registry().published_revision();
        let h3 = coordinator.reference_h3_audit_state();
        assert_eq!(coordinator.registry().joint_feeds(), 0);
        assert!(
            coordinator
                .joint_capture()
                .model()
                .project()
                .objects
                .is_empty()
        );
        fixture.appear(1, 2);
        fixture.appear(2, 2);
        for (at, file) in order.into_iter().enumerate() {
            fixture
                .scene
                .push(std::process::id(), file, "C_CreateObject", at as u64 + 2);
        }
        fixture.reach_phase("Births");
        let original = fixture.native.preparations.last().unwrap().0;
        let coordinator = &fixture.scene.real.scene.coordinator;
        let prepared = coordinator.prepared_semantic_batch().unwrap();
        assert_eq!(prepared.admissions().count(), 2);
        assert_eq!(prepared.claims().count(), 2);
        assert!(
            prepared.claims().all(
                |(ordinal, result)| result.as_ref().is_ok_and(|proof| prepared
                    .admissions()
                    .any(|input| input.h0_ordinal() == ordinal && proof.matches_admitted(input)))
            )
        );
        for file in [1, 2] {
            let receipt = prepared
                .current_receipts()
                .iter()
                .find(|receipt| receipt.endpoint().file_slot == file)
                .unwrap();
            assert!(receipt.birth_quantum() == Some(original));
            assert!(fixture.pending_absence(file).is_some());
            assert!(fixture.ready_birth(file).is_none());
        }
        assert!(
            coordinator
                .joint_capture()
                .model()
                .project()
                .objects
                .is_empty(),
            "B and C's actual keys/claims must both exist BEFORE the first conversion"
        );
        fixture.published();
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(coordinator.registry().joint_feeds(), 2);
        assert_eq!(coordinator.registry().published_revision(), revision + 1);
        assert_eq!(coordinator.reference_h3_audit_state(), (h3.0 + 1, false));
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test()
                .0,
            0
        );
        assert_eq!(
            coordinator.joint_capture().ledger().roles_for_test(),
            [0; 5]
        );
        assert_eq!(
            coordinator
                .joint_capture()
                .model()
                .project()
                .objects
                .iter()
                .filter(|object| object.lifetime == Lifetime::Live)
                .count(),
            2
        );
        let table = fixture.machine.retained_births_for_test();
        assert_eq!(table.ready_for_test().count(), 2);
        let mut targets = 0;
        for (target, _) in coordinator.registry().joint_history_targets() {
            let witness = table
                .find_ready(&target)
                .expect("each exact original Ready must serve its actual target");
            assert_eq!(witness.receipt(), target.bootstrap());
            assert!(witness.original.in_quantum(original));
            assert!(witness.candidate.quantum == original);
            assert_eq!(witness.receipt().birth(), BirthKind::AbsenceAppearance);
            targets += 1;
        }
        assert_eq!(targets, 2);
        for file in [1, 2] {
            assert!(fixture.pending_absence(file).is_none());
            assert!(fixture.ready_birth(file).is_some());
            assert_eq!(fixture.reduced_for(file as usize), 1);
            assert_eq!(
                fixture
                    .native
                    .birth_outcomes
                    .iter()
                    .filter(|(actual, result)| *actual == file
                        && *result == Ok(BirthKind::AbsenceAppearance))
                    .count(),
                1
            );
        }
    }
}

#[test]
fn joint_machine_absence_stale_inputs_end_in_permanent_s1() {
    for stale in ["epoch", "fence", "closure"] {
        let mut fixture = MachineScene::absence_scene(2);
        fixture.wait_absence(1);
        if stale == "closure" {
            let old = fixture.scene.attached.take().unwrap();
            fixture.scene.attached = Some(crate::attach::reseal_test_attachment(
                old,
                fixture.scene.real.lane.subset().pins(),
            ));
        } else if stale == "fence" {
            let caller = fixture
                .scene
                .real
                .scene
                .coordinator
                .adapter()
                .live_id(std::process::id())
                .unwrap();
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_mark_tail(caller);
            fixture.push_quiet();
            fixture.published();
        }
        fixture.appear(1, if stale == "epoch" { 1 } else { 2 });
        fixture
            .scene
            .push(std::process::id(), 1, "C_CreateObject", 2);
        fixture.published();
        assert!(
            fixture.ready_birth(1).is_none(),
            "{stale} cannot mint a replacement receipt"
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .joint_feeds(),
            0
        );
        assert!(
            fixture
                .native
                .birth_outcomes
                .iter()
                .any(|(file, outcome)| *file == 1 && outcome.is_err())
        );
        let first_attempts = fixture
            .native
            .birth_outcomes
            .iter()
            .filter(|(file, _)| *file == 1)
            .count();
        fixture.scene.push(std::process::id(), 1, "C_SignInit", 3);
        fixture.published();
        assert_eq!(
            fixture
                .native
                .birth_outcomes
                .iter()
                .filter(|(file, _)| *file == 1)
                .count(),
            first_attempts,
            "the same-epoch Continued call cannot consume a replacement New"
        );
        assert!(
            fixture.ready_birth(1).is_none(),
            "an actual later Continued observation cannot upgrade S1"
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .joint_feeds(),
            0
        );
    }
}

#[test]
fn joint_machine_absence_storage_precedes_query_and_refunds_owned_overlap() {
    for refusal in ["healthy", "retained-overlap", "query"] {
        let refuse = refusal != "healthy";
        let mut fixture = MachineScene::absence_scene(3);
        fixture.wait_absence(1);
        let before_reads = fixture.native.absence_reads.len();
        let reserve = fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_storage_reserver();
        let (old, new, nested) = fixture
            .machine
            .next_absence_allocation_for_test(
                &fixture.scene.real.lane,
                &fixture.scene.real.scene.coordinator,
            )
            .unwrap();
        assert!(old > 0 && new > old && nested > 0);
        let query = crate::attach::image_query::absence_query_storage_bytes(
            1,
            nested,
            fixture.scene.real.lane.subset().plan().slots.len() * 2,
        )
        .unwrap();
        assert!(query > 8 * 1024 * 1024);
        assert!(query < crate::semantics_edge::resources::SEMANTIC_RESOURCE_LIMIT);
        let snapshot = fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot();
        let hold = refuse.then(|| {
            let remaining = if refusal == "query" {
                // Retention's real old allocation refunds AFTER the resize;
                // then exactly query-1 bytes remain for the actual query lease.
                new - old + nested + query - 1
            } else {
                new - old + nested
            };
            reserve
                .reserve(snapshot.limit_bytes - snapshot.charged_bytes - remaining)
                .unwrap()
        });
        if refuse {
            let pending = fixture.pending_absence(1).unwrap();
            let original = (
                pending.capture,
                Arc::as_ptr(&pending.pin),
                pending.proof.fence(),
            );
            let mut refused = false;
            for _ in 0..128 {
                match fixture.service(1) {
                    Err(SemanticRefusal::ProviderStorage) => {
                        refused = true;
                        break;
                    }
                    Err(reason) => panic!("unexpected absence reservation refusal: {reason:?}"),
                    Ok(_) => {}
                }
            }
            assert!(
                refused,
                "{refusal}: the actual reservation must refuse before native acquisition"
            );
            assert_eq!(
                fixture.native.absence_reads.len(),
                before_reads,
                "{refusal}: full retained overlap and the full query bound precede the callback"
            );
            let pending = fixture.pending_absence(1).unwrap();
            assert_eq!(
                (
                    pending.capture,
                    Arc::as_ptr(&pending.pin),
                    pending.proof.fence()
                ),
                original
            );
            assert!(fixture.pending_absence(2).is_none());
        } else {
            fixture.wait_absence(2);
            assert!(fixture.native.absence_reads.len() > before_reads);
        }
        drop(hold);
        let charged = fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes;
        let owned = fixture.machine.retained_storage_for_test();
        assert!(owned > 0);
        drop(fixture.machine);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .semantic_resource_snapshot()
                .charged_bytes,
            charged - owned
        );
    }
}

/// Reverting the machine to a 1024-total-wire guard leaves END(1) unread.
#[test]
fn joint_machine_begin_prefix_crosses_1024_before_real_end() {
    let mut fixture = MachineScene::new(1);
    fixture.scene.drain.source_mut().bound = 1_025;
    let pid = std::process::id();
    let (begin, first_end) = fixture.scene.encoded(pid, 0, "C_CreateObject", 1);
    fixture.scene.drain.source_mut().push_record(begin.to_vec());
    fixture.service(1).unwrap();
    let identity = fixture
        .machine
        .retained_raw_for_test()
        .unwrap()
        .h0_identity();
    // The actual scripted ring holds512 records. Stream through that same
    // producer/cursor in bounded chunks rather than invent an overfull cut.
    for chunk in (2..=1_024).collect::<Vec<_>>().chunks(256) {
        for sequence in chunk {
            let (begin, _) = fixture.scene.encoded(pid, 0, "C_CreateObject", *sequence);
            fixture.scene.drain.source_mut().push_record(begin.to_vec());
        }
        fixture.service(chunk.len()).unwrap();
        assert_eq!(fixture.scene.drain.source_mut().remaining(), 0);
        assert!(
            fixture
                .machine
                .retained_raw_for_test()
                .unwrap()
                .h0_identity()
                == identity
        );
    }
    fixture
        .scene
        .drain
        .source_mut()
        .push_record(first_end.to_vec());
    fixture.service(1).unwrap();
    let raw = fixture.machine.retained_raw_for_test().unwrap();
    assert!(raw.h0_identity() == identity);
    assert_eq!(
        raw.pending_h0_records(),
        1,
        "the genuine wire1025 END reached the same Raw"
    );
    assert_eq!(fixture.scene.drain.source_mut().remaining(), 0);
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(coordinator.semantic_bindings().len(), 0);
    assert!(fixture.native.preparations.is_empty());
    assert_eq!(coordinator.reference_h3_audit_state(), (0, false));
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        0
    );
    let roles = coordinator.joint_capture().ledger().roles_for_test();
    assert_eq!((roles[0], roles[1], roles[2], roles[3]), (1_024, 0, 0, 0));
}

/// The true 4096-wire owner holds its original memberships on refusal; the
/// next physical record cannot enter the full allocation or a replacement.
#[test]
fn joint_machine_full_raw_capacity_preserves_n_plus_one() {
    let mut fixture = MachineScene::new(1);
    fixture.scene.drain.source_mut().bound = 4_097;
    let mut identity = None;
    for chunk in (1..=4_096).collect::<Vec<_>>().chunks(256) {
        for sequence in chunk {
            let (begin, _) =
                fixture
                    .scene
                    .encoded(std::process::id(), 0, "C_CreateObject", *sequence);
            fixture.scene.drain.source_mut().push_record(begin.to_vec());
        }
        assert_eq!(
            fixture.service(chunk.len()).unwrap(),
            crate::inventory_semantics::JointServiceProgress::Pending
        );
        assert_eq!(fixture.scene.drain.source_mut().remaining(), 0);
        let actual = fixture
            .machine
            .retained_raw_for_test()
            .unwrap()
            .h0_identity();
        if let Some(first) = identity {
            assert!(first == actual);
        } else {
            identity = Some(actual);
        }
    }
    let identity = identity.unwrap();
    let (next, _) = fixture
        .scene
        .encoded(std::process::id(), 0, "C_CreateObject", 4_097);
    fixture.scene.drain.source_mut().push_record(next.to_vec());
    assert_eq!(fixture.scene.drain.source_mut().remaining(), 1);
    let boundary = fixture.scene.drain.consumption_cut().unwrap();
    let coordinator = &fixture.scene.real.scene.coordinator;
    let roles = coordinator.joint_capture().ledger().roles_for_test();
    assert_eq!((roles[0], roles[1], roles[2], roles[3]), (1_024, 0, 0, 0));
    let reserve = coordinator.registry().semantic_storage_reserver();
    let snapshot = coordinator.registry().semantic_resource_snapshot();
    let hold = reserve
        .reserve(snapshot.limit_bytes - snapshot.charged_bytes)
        .unwrap();
    fixture.service(1).unwrap();
    assert!(fixture.machine.report_preparation_pending_for_test());
    assert_eq!(fixture.service(1), Err(SemanticRefusal::ProviderStorage));
    assert!(
        fixture
            .machine
            .retained_raw_for_test()
            .unwrap()
            .h0_identity()
            == identity
    );
    assert!(boundary.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
    assert_eq!(fixture.scene.drain.source_mut().remaining(), 1);
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
    assert_eq!(coordinator.reference_h3_audit_state(), (0, false));
    assert_eq!(coordinator.semantic_bindings().len(), 0);
    assert!(fixture.native.rows.is_empty());
    drop(hold);
    assert_eq!(
        coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        snapshot.charged_bytes
    );
}

/// A payload estimate must not clone watched Entry text before the pool can
/// cover the retained report. The actual healthy path still reaches Joint.
#[test]
fn joint_machine_report_precharge_refuses_before_watched_copy() {
    for refuse in [true, false] {
        let mut fixture = MachineScene::new(1);
        fixture
            .scene
            .push(std::process::id(), 0, "C_CreateObject", 1);
        for _ in 0..16 {
            fixture.service(1).unwrap();
            if fixture.machine.report_preparation_pending_for_test() {
                break;
            }
        }
        assert!(fixture.machine.report_preparation_pending_for_test());
        let identity = fixture
            .machine
            .retained_raw_for_test()
            .unwrap()
            .h0_identity();
        let boundary = fixture.scene.drain.consumption_cut().unwrap();
        let coordinator = &fixture.scene.real.scene.coordinator;
        let snapshot = coordinator.registry().semantic_resource_snapshot();
        let roles = coordinator.joint_capture().ledger().roles_for_test();
        let reserve = coordinator.registry().semantic_storage_reserver();
        let hold = refuse.then(|| {
            reserve
                .reserve(snapshot.limit_bytes - snapshot.charged_bytes)
                .unwrap()
        });
        let (result, allocations, bytes) =
            crate::test_alloc::count_allocs_during(|| fixture.service(1));
        if refuse {
            assert_eq!(result, Err(SemanticRefusal::ProviderStorage));
            assert_eq!(
                (allocations, bytes),
                (0, 0),
                "the exhausted real pool refuses before any watched Entry copy"
            );
            let coordinator = &fixture.scene.real.scene.coordinator;
            assert!(
                fixture
                    .machine
                    .retained_raw_for_test()
                    .unwrap()
                    .h0_identity()
                    == identity
            );
            assert!(boundary.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
            assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
            assert_eq!(coordinator.reference_h3_audit_state(), (0, false));
            assert_eq!(coordinator.semantic_bindings().len(), 0);
            assert!(fixture.native.preparations.is_empty());
        } else {
            result.unwrap();
            assert!(allocations >= 3);
            assert!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .registry()
                    .semantic_resource_snapshot()
                    .charged_bytes
                    > snapshot.charged_bytes
            );
            fixture.published();
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .registry()
                    .joint_feeds(),
                1
            );
            assert_eq!(fixture.reduced(), [1]);
        }
        drop(hold);
    }
}

/// A physical requester needs a finite original negative even when the first
/// native BEGIN has no admission/grant. No END, birth or positive is invented.
#[test]
fn joint_machine_begin_only_request_publishes_original_negative() {
    use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
    use crate::semantics_objects::journal::joint_driver::RawDisposeReason;
    let mut fixture = MachineScene::new(1);
    let (begin, _) = fixture
        .scene
        .encoded(std::process::id(), 0, "C_CreateObject", 1);
    fixture.scene.drain.source_mut().push_record(begin.to_vec());
    let revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    fixture.machine.begin_commit(true).unwrap();
    let mut observed_original_negative = false;
    let mut published = false;
    for _ in 0..128 {
        let progress = fixture.service(1).unwrap();
        if let Some(disposed) = fixture.machine.retained_negative_for_test() {
            assert_eq!(disposed.reason(), RawDisposeReason::NoAdmission);
            assert!(disposed.failure().is_some());
            observed_original_negative = true;
        }
        if progress == crate::inventory_semantics::JointServiceProgress::Published {
            published = true;
            break;
        }
    }
    assert!(observed_original_negative && published);
    assert!(matches!(
        fixture.poll_commit(0).unwrap(),
        JointCommitProgress::Published(_)
    ));
    assert!(matches!(
        fixture.poll_commit(0).unwrap(),
        JointCommitProgress::Pending
    ));
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(coordinator.registry().published_revision(), revision + 1);
    assert_eq!(coordinator.registry().joint_feeds(), 0);
    assert!(
        coordinator
            .registry()
            .instance_semantic_edges()
            .all(|record| record.feed.reduced() == 0)
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        0
    );
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test()[..4],
        [0, 0, 0, 0]
    );
    assert!(
        coordinator
            .joint_capture()
            .model()
            .project()
            .objects
            .is_empty()
    );
    assert!(fixture.native.rows.is_empty());
}

/// Sorted fingerprint of every published gap row with its repeat count.
fn gap_fingerprint(coordinator: &InventoryCoordinator<OsProcessSource>) -> Vec<String> {
    let registry = coordinator.registry();
    let mut rows: Vec<String> = registry
        .gaps()
        .iter()
        .zip(registry.gap_repeats().iter())
        .map(|(gap, repeats)| format!("{gap:?} x{repeats}"))
        .collect();
    rows.sort();
    rows.push(format!("suppressed={}", registry.gaps_suppressed()));
    rows
}

/// Per-edge call facts: api returns, reduced, started, completed.
type EdgeCallFacts = (Option<u64>, u64, Option<u64>, Option<u64>);

/// Sorted per-edge call facts: api returns, reduced, started, completed.
fn edge_call_facts(coordinator: &InventoryCoordinator<OsProcessSource>) -> Vec<EdgeCallFacts> {
    let mut facts: Vec<_> = coordinator
        .registry()
        .instance_semantic_edges()
        .map(|record| {
            (
                record.api_returns,
                record.feed.reduced(),
                record.semantics.as_ref().map(|edge| edge.started()),
                record.semantics.as_ref().map(|edge| edge.completed()),
            )
        })
        .collect();
    facts.sort();
    facts
}

/// Demandless idle service with an empty drain publishes nothing: no
/// revision, no H3 take, no replay, no gaps. The live first-birth
/// cell's idle loop relies on this whenever no ambient records land.
#[test]
fn joint_machine_idle_service_without_records_publishes_nothing() {
    let mut fixture = MachineScene::new(2);
    fixture.prime(2);
    let revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    let h3 = fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_h3_audit_state();
    let reduced = fixture.reduced();
    let edges = edge_call_facts(&fixture.scene.real.scene.coordinator);
    let gaps = gap_fingerprint(&fixture.scene.real.scene.coordinator);
    let claims = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test()
        .0;
    let roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    for _ in 0..3 {
        let progress = fixture.service(64).unwrap();
        assert_eq!(
            progress,
            crate::inventory_semantics::JointServiceProgress::Pending,
            "an empty idle service never publishes"
        );
        let reduced_now = fixture.reduced();
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(coordinator.registry().published_revision(), revision);
        assert_eq!(coordinator.reference_h3_audit_state(), h3);
        assert_eq!(reduced_now, reduced);
        assert_eq!(edge_call_facts(coordinator), edges);
        assert_eq!(gap_fingerprint(coordinator), gaps);
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test()
                .0,
            claims
        );
        assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
    }
    assert_eq!(fixture.scene.drain.source_mut().remaining(), 0);
}

/// Demandless idle service WITH new non-call (FORK lifecycle) records
/// legally publishes exactly once: one revision, one H3 take, and zero
/// call facts — no api/reduced/started/completed movement, no gaps.
/// This is the live first-birth cell's idle publish: ambient task
/// records collected without a demand are real new facts, not silence.
#[test]
fn joint_machine_idle_service_with_fork_records_publishes_without_call_facts() {
    use p11scope_ebpf_common::{Event, event_type};
    let mut fixture = MachineScene::new(2);
    fixture.prime(2);
    let revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    let h3 = fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_h3_audit_state();
    let reduced = fixture.reduced();
    let edges = edge_call_facts(&fixture.scene.real.scene.coordinator);
    let gaps = gap_fingerprint(&fixture.scene.real.scene.coordinator);
    let claims = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test()
        .0;
    let roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    for (index, child) in [1001u32, 1002].into_iter().enumerate() {
        let fork = Event {
            event_type: event_type::FORK,
            pid_tgid: (u64::from(child) << 32) | u64::from(child),
            session: u64::from(child),
            ts_ns: 2_000_000 + index as u64,
            ..Event::default()
        };
        fixture
            .scene
            .drain
            .source_mut()
            .push_record(crate::events::event_bytes(&fork));
    }
    let mut publishes = 0u32;
    for _ in 0..512 {
        let progress = fixture.service(1).unwrap();
        if progress == crate::inventory_semantics::JointServiceProgress::Published {
            publishes += 1;
            break;
        }
    }
    assert_eq!(
        publishes, 1,
        "two fork records publish exactly once without a demand"
    );
    assert_eq!(fixture.scene.drain.source_mut().remaining(), 0);
    let reduced_now = fixture.reduced();
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(
        coordinator.registry().published_revision(),
        revision + 1,
        "the fork records publish one revision"
    );
    assert_eq!(
        coordinator.reference_h3_audit_state(),
        (h3.0 + 1, h3.1),
        "one H3 take per publish, no new pending"
    );
    assert_eq!(reduced_now, reduced, "fork records replay nothing");
    assert_eq!(edge_call_facts(coordinator), edges);
    assert_eq!(gap_fingerprint(coordinator), gaps);
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        claims
    );
    assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
}

#[test]
fn joint_machine_routes_first_birth_to_actual_registry() {
    let mut fixture = MachineScene::new(1);
    let revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    fixture
        .scene
        .push(std::process::id(), 0, "C_CreateObject", 1);
    fixture.scene.push(std::process::id(), 0, "C_SignInit", 2);
    fixture.published();
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(coordinator.registry().joint_feeds(), 1);
    assert_eq!(fixture.reduced(), [2]);
    assert_eq!(coordinator.registry().published_revision(), revision + 1);
    assert_eq!(coordinator.reference_h3_audit_state(), (1, false));
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        0
    );
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test()[..2],
        [0, 0]
    );
    assert_eq!(fixture.native.rows.len(), 1);
    assert!(fixture.native.reads.get().0 > 0 && fixture.native.reads.get().1 > 0);
    assert!(
        coordinator
            .joint_capture()
            .model()
            .project()
            .objects
            .iter()
            .any(|object| object.lifetime == Lifetime::Live)
    );
}

#[test]
fn joint_machine_begin_slices_and_h0_pending_do_not_repoll() {
    let mut fixture = MachineScene::new(2);
    fixture.prime(2);
    let before_b = fixture.reduced_for(1);
    {
        let mut held = fixture.scene.real.h0.0.borrow_mut();
        let (base, epoch, global) = held.io.scan_input(0);
        held.io
            .scan_inputs
            .insert(0, (base + 0x20_000, epoch + 1, global));
        held.io.script.fail_file = Some(0);
    }
    fixture.scene.push(std::process::id(), 0, "C_SignInit", 3);
    fixture.scene.push(std::process::id(), 1, "C_SignInit", 4);
    for _ in 0..128 {
        fixture.service(1).unwrap();
        if fixture.scene.real.h0.0.borrow().capture.awaiting.len() == 1
            && fixture.machine.retained_h0_for_test().is_some()
        {
            break;
        }
    }
    assert_eq!(fixture.scene.real.h0.0.borrow().capture.awaiting.len(), 1);
    let raw = fixture.machine.retained_raw_for_test().unwrap();
    assert_eq!(
        raw.pending_h0_records(),
        0,
        "the first real H0 report already acknowledged its ordinary bytes"
    );
    let identity = raw.h0_identity();
    let (outcomes, current) = fixture.machine.retained_h0_for_test().unwrap();
    let ready = outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            TickOutcome::Call(call) => {
                Some((call.token().unwrap(), call.collected_origin().unwrap()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        ready.len(),
        1,
        "B is genuinely ready while H0 still owns pending A"
    );
    assert!(
        current
            .iter()
            .any(|receipt| receipt.endpoint().file_slot == 1)
    );
    let original_boundary = fixture.scene.drain.consumption_cut().unwrap();
    fixture.scene.drain.source_mut().push_record(vec![0; 17]);
    for _ in 0..3 {
        fixture.service(4).unwrap();
        assert!(
            fixture
                .machine
                .retained_raw_for_test()
                .unwrap()
                .h0_identity()
                == identity
        );
        assert!(original_boundary.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
        assert_eq!(fixture.scene.drain.source_mut().remaining(), 1);
        let (outcomes, _) = fixture.machine.retained_h0_for_test().unwrap();
        assert_eq!(
            outcomes
                .iter()
                .filter_map(|outcome| match outcome {
                    TickOutcome::Call(call) =>
                        Some((call.token().unwrap(), call.collected_origin().unwrap())),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            ready
        );
    }
    fixture.scene.real.h0.0.borrow_mut().io.script.fail_file = None;
    fixture.published();
    assert_eq!(
        fixture.scene.drain.source_mut().remaining(),
        1,
        "completing the original frame must return before reading the next one"
    );
    assert_eq!(
        fixture.reduced_for(1) - before_b,
        1,
        "the retained ready B original reduces once"
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        0
    );
}

/// Only fixture observations: the original Raw, Capture, reports and all
/// authority stay in their existing owners. Opaque identities use equality.
struct PendingQCustody {
    raw: crate::semantics_objects::journal::joint_driver::RawQuantumIdentity,
    boundary: crate::events::EventsConsumptionCut,
    capture: u64,
    pending: Vec<(
        u64,
        crate::semantics_objects::journal::joint_driver::CollectedCallOrigin,
    )>,
    ready: Vec<(
        u64,
        crate::semantics_objects::journal::joint_driver::CollectedCallOrigin,
    )>,
    current_files: Vec<u32>,
    roles: [usize; 5],
    frontier: crate::semantics_objects::journal::ConsumptionOrdinal,
    claims: (
        usize,
        Vec<(u64, crate::semantics_objects::journal::JournalDomainProof)>,
    ),
    model: crate::semantics_objects::ObjectProjection,
    h3: (usize, bool),
    acked: u64,
    revision: u64,
    charged: usize,
    resolutions: usize,
    unobserved: u64,
}

impl PendingQCustody {
    fn observe(fixture: &MachineScene) -> Self {
        let coordinator = &fixture.scene.real.scene.coordinator;
        let held = fixture.scene.real.h0.0.borrow();
        let (ready, current_files) = fixture
            .machine
            .retained_h0_for_test()
            .map(|(outcomes, current)| {
                (
                    outcomes
                        .iter()
                        .filter_map(|outcome| match outcome {
                            TickOutcome::Call(call) => {
                                Some((call.token().unwrap(), call.collected_origin().unwrap()))
                            }
                            _ => None,
                        })
                        .collect(),
                    current
                        .iter()
                        .map(|receipt| receipt.endpoint().file_slot)
                        .collect(),
                )
            })
            .unwrap_or_default();
        Self {
            raw: fixture
                .machine
                .retained_raw_for_test()
                .unwrap()
                .h0_identity(),
            boundary: fixture.scene.drain.consumption_cut().unwrap(),
            capture: held.capture.identity,
            pending: held
                .capture
                .awaiting
                .iter()
                .map(|(position, waiting)| (*position, waiting.collected_origin.unwrap()))
                .collect(),
            ready,
            current_files,
            roles: coordinator.joint_capture().ledger().roles_for_test(),
            frontier: coordinator.joint_capture().adapter().consumed_frontier(),
            claims: coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            model: coordinator.joint_capture().model().project(),
            h3: coordinator.reference_h3_audit_state(),
            acked: coordinator.reference_h3_acknowledged_below(),
            revision: coordinator.registry().published_revision(),
            charged: coordinator
                .registry()
                .semantic_resource_snapshot()
                .charged_bytes,
            resolutions: fixture.native.pending_q_resolutions,
            unobserved: held
                .capture
                .router
                .unknown_counts()
                .get(&crate::discovery::instances::UnknownReason::Unobserved)
                .copied()
                .unwrap_or(0),
        }
    }

    fn assert_unchanged(&self, fixture: &MachineScene) {
        let after = Self::observe(fixture);
        assert!(after.raw == self.raw);
        assert!(after.boundary.same_boundary(&self.boundary));
        assert_eq!(after.capture, self.capture);
        assert!(after.pending == self.pending);
        assert!(after.ready == self.ready);
        assert_eq!(after.current_files, self.current_files);
        assert_eq!(after.roles, self.roles);
        assert!(after.frontier == self.frontier);
        assert!(after.claims == self.claims);
        assert!(
            after.model == self.model,
            "the retained model changed on refusal"
        );
        assert_eq!(after.h3, self.h3);
        assert_eq!(after.acked, self.acked);
        assert_eq!(after.revision, self.revision);
        assert_eq!(after.charged, self.charged);
        assert_eq!(after.resolutions, self.resolutions);
        assert_eq!(after.unobserved, self.unobserved);
        assert!(!fixture.scene.real.h0.0.borrow().capture.stopped);
    }
}

fn pending_h0_finish_fixture(
    reverse: bool,
) -> (
    MachineScene,
    crate::attach::CollectedFinishQObserverForTest,
    JournalAdapter,
) {
    let mut fixture = MachineScene::new(2);
    let observer = crate::attach::CollectedFinishQObserverForTest::new(&fixture.scene.producers);
    assert!(
        observer
            .observe(&fixture.scene.producers, None, &fixture.scene.drain)
            .unwrap()
            .is_none(),
        "an actual zero count WITHOUT STOP cannot mint Q"
    );
    // Bind a genuinely different ledger while this SAME cursor is still at
    // its initial boundary. No consumed-prefix setter or second cursor.
    let registry = fixture.scene.real.scene.coordinator.registry();
    let reserve = registry.semantic_storage_reserver();
    let mut foreign = JournalAdapter::with_ledger(
        crate::semantics_objects::journal::JournalLimits::policy(),
        crate::semantics_objects::journal::StagingLedger::with_resources(
            registry.semantic_storage_reserver(),
        ),
    );
    let initial = fixture.scene.drain.consumption_cut().unwrap();
    assert!(initial.is_initial());
    let (unobserved, poll) = RawJointQuantum::begin_bounded_with_adapter(
        &mut fixture.scene.drain,
        &publish_object_descriptors(),
        4,
        0,
        None,
        &BirthFault,
        &fixture.scene.producers,
        |bytes| reserve.reserve(bytes),
        &mut foreign,
    )
    .unwrap();
    assert!(poll.is_none());
    assert!(initial.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
    drop(unobserved);
    fixture.prime(2);
    let a = u32::from(reverse);
    let b = 1 - a;
    {
        let mut held = fixture.scene.real.h0.0.borrow_mut();
        let (base, epoch, global) = held.io.scan_input(a);
        held.io
            .scan_inputs
            .insert(a, (base + 0x20_000, epoch + 1, global));
        held.io.script.fail_file = Some(a);
    }
    let calls = if reverse {
        [(b, 4), (a, 3)]
    } else {
        [(a, 3), (b, 4)]
    };
    for (file, sequence) in calls {
        fixture
            .scene
            .push(std::process::id(), file, "C_SignInit", sequence);
    }
    for _ in 0..128 {
        fixture.service(1).unwrap();
        if fixture.scene.real.h0.0.borrow().capture.awaiting.len() == 1
            && fixture.machine.retained_h0_for_test().is_some()
        {
            break;
        }
    }
    let before = PendingQCustody::observe(&fixture);
    assert_eq!(fixture.machine.diagnostic_snapshot_for_test().0, "AwaitH0");
    assert_eq!(before.pending.len(), 1);
    assert_eq!(before.ready.len(), 1);
    assert!(before.pending[0].1.in_quantum(before.raw));
    assert!(before.ready[0].1.in_quantum(before.raw));
    assert!(
        before.current_files.contains(&b),
        "B has a genuine retained Current"
    );
    let raw = fixture.machine.retained_raw_for_test().unwrap();
    assert_eq!(
        raw.pending_h0_records(),
        0,
        "ordinary delivery already happened once"
    );
    assert!(
        raw.ledger_binding()
            .unwrap()
            .matches_owner(fixture.scene.real.scene.coordinator.joint_capture())
    );
    (fixture, observer, foreign)
}

fn observe_pending_finish_q(
    fixture: &MachineScene,
    observer: &crate::attach::CollectedFinishQObserverForTest,
) -> crate::attach::CollectedFinishQ {
    observer.request_stop();
    let q = observer
        .observe(
            &fixture.scene.producers,
            fixture.machine.retained_drain_grant_for_test(),
            &fixture.scene.drain,
        )
        .unwrap()
        .expect("the same original producers reached actual STOP/count0");
    assert!(q.matches_owner(&fixture.scene.producers, observer.discovery_domain()));
    assert!(q.matches_retained_grant(fixture.machine.retained_drain_grant_for_test().unwrap()));
    assert_eq!(
        observer.discovery_remaining(),
        1,
        "Q is not a completed drain"
    );
    q
}

/// Catches dropping B's original Current, stopping before resolving A,
/// pretending expiry is clean, and repeating the same original resolution.
#[test]
fn joint_machine_collected_finish_resolves_pending_h0_union_once() {
    use crate::semantics_objects::journal::JournalGap;
    for reverse in [false, true] {
        let (mut fixture, observer, _foreign) = pending_h0_finish_fixture(reverse);
        let before = PendingQCustody::observe(&fixture);
        let b = 1 - u32::from(reverse);
        // Q can cover a bounded older original WITHOUT requiring it to drain
        // the next owned record. That suffix remains in the original cursor.
        let (later, _) = fixture
            .scene
            .encoded(std::process::id(), b, "C_SignUpdate", 5);
        fixture.scene.drain.source_mut().push_record(later.to_vec());
        let q = observe_pending_finish_q(&fixture, &observer);
        assert!(q.covers_events_bounds(&before.boundary));
        assert!(!q.events_at_bound(&before.boundary));
        let at_q = PendingQCustody::observe(&fixture);
        fixture
            .resolve_pending_q(&q, observer.discovery_domain(), 0)
            .unwrap();
        at_q.assert_unchanged(&fixture);
        for _ in 0..128 {
            fixture
                .resolve_pending_q(&q, observer.discovery_domain(), 1)
                .unwrap();
            if fixture.scene.real.h0.0.borrow().capture.awaiting.is_empty()
                && fixture
                    .machine
                    .retained_pending_q_report_for_test()
                    .is_none()
            {
                break;
            }
        }
        assert_eq!(fixture.native.pending_q_resolutions, 1);
        assert_eq!(fixture.native.pending_q_calls, 1);
        {
            let held = fixture.scene.real.h0.0.borrow();
            assert!(held.capture.awaiting.is_empty());
            assert!(held.capture.jobs.is_empty());
            assert!(!held.capture.stopped);
            assert_eq!(
                held.capture.router.unknown_counts()
                    [&crate::discovery::instances::UnknownReason::Unobserved],
                before.unobserved + 1
            );
        }
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_audit_state(),
            before.h3
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_acknowledged_below(),
            before.acked
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .published_revision(),
            before.revision
        );
        assert!(
            fixture
                .machine
                .retained_raw_for_test()
                .unwrap()
                .h0_identity()
                == before.raw
        );
        assert!(
            fixture
                .scene
                .drain
                .consumption_cut()
                .unwrap()
                .same_boundary(&at_q.boundary)
        );
        fixture.reach_phase("BindingKeys");
        let prepared = fixture
            .scene
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap();
        assert!(
            prepared
                .current_receipts()
                .iter()
                .any(|receipt| receipt.endpoint().file_slot == b)
        );
        let admitted = prepared.admissions().collect::<Vec<_>>();
        assert_eq!(
            admitted.len(),
            1,
            "only B is joined; expired A is an original shed"
        );
        assert!(admitted[0].collected_origin() == Some(before.ready[0].1));
        fixture.reach_phase("Audited");
        let audit = fixture.machine.diagnostic_audit_for_test().unwrap();
        assert_eq!(audit.0, Some(JournalGap::H3Loss));
        assert_eq!(audit.1, "StagedLoss");
        assert_eq!(audit.2, Some(before.pending[0].0));
        assert_eq!(audit.3, None);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_acknowledged_below(),
            before.acked,
            "no acknowledgement before actual fanout/disposal"
        );
        fixture.published_labeled("pending-at-Q shared loss", None);
        assert_eq!(fixture.native.pending_q_resolutions, 1);
        assert_eq!(fixture.scene.drain.source_mut().remaining(), 1);
        assert_eq!(observer.discovery_remaining(), 1);
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(
            coordinator.registry().published_revision(),
            before.revision + 1
        );
        assert_eq!(
            coordinator.reference_h3_audit_state(),
            (before.h3.0 + 1, false)
        );
        assert!(coordinator.reference_h3_acknowledged_below() > before.pending[0].0);
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test()
                .0,
            0
        );
        let roles = coordinator.joint_capture().ledger().roles_for_test();
        assert_eq!((roles[0], roles[1], roles[3]), (0, 0, 0));
        assert!(
            coordinator
                .joint_capture()
                .model()
                .project()
                .objects
                .iter()
                .all(|object| object.lifetime != Lifetime::Live)
        );
    }
}

/// A same-domain owner or equal numeric cuts do not replace the original
/// Capture, ledger, frontier or Q. A foreign Finish Q latches the Finish
/// disposition (fail closed); a refusal-free original still resolves once.
#[test]
fn joint_machine_collected_finish_rejects_foreign_stale_duplicate() {
    let (mut fixture, observer, foreign) = pending_h0_finish_fixture(false);
    let q = observe_pending_finish_q(&fixture, &observer);
    let before = PendingQCustody::observe(&fixture);
    let foreign_owner =
        crate::attach::CollectedFinishQObserverForTest::new(&fixture.scene.producers);
    let foreign_q = observe_pending_finish_q(&fixture, &foreign_owner);
    assert!(!foreign_q.matches_owner(&fixture.scene.producers, observer.discovery_domain()));
    assert!(
        fixture
            .resolve_pending_q(&foreign_q, observer.discovery_domain(), 1)
            .is_err()
    );
    before.assert_unchanged(&fixture);
    let other_producer = JointScene::new(1);
    assert!(matches!(
        fixture
            .machine
            .retained_raw_for_test()
            .unwrap()
            .validate_pending_finish(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .adapter(),
                &other_producer.producers,
                observer.discovery_domain(),
                &q
            ),
        Err(RawQuantumRefusal::ForeignCapture)
    ));
    before.assert_unchanged(&fixture);
    assert!(matches!(
        fixture
            .machine
            .retained_raw_for_test()
            .unwrap()
            .validate_pending_finish(
                &foreign,
                &fixture.scene.producers,
                observer.discovery_domain(),
                &q
            ),
        Err(RawQuantumRefusal::ForeignLedger)
    ));
    before.assert_unchanged(&fixture);
    let mut other_capture =
        SemanticCapture::in_domain(fixture.scene.real.lane.domain(), TickLimits::default())
            .unwrap();
    std::mem::swap(
        &mut fixture.scene.real.h0.0.borrow_mut().capture,
        &mut other_capture,
    );
    assert!(
        fixture
            .resolve_pending_q(&q, observer.discovery_domain(), 1)
            .is_err()
    );
    std::mem::swap(
        &mut fixture.scene.real.h0.0.borrow_mut().capture,
        &mut other_capture,
    );
    before.assert_unchanged(&fixture);
    // Move, never reconstruct or clone, another genuine awaiting original.
    // The receiving Capture keeps its identity, so owner equality alone is
    // insufficient: exact Raw origin/resource association must also refuse.
    let (other_original, _observer, _ledger) = pending_h0_finish_fixture(true);
    let other_before = PendingQCustody::observe(&other_original);
    {
        let mut retained = fixture.scene.real.h0.0.borrow_mut();
        let mut foreign = other_original.scene.real.h0.0.borrow_mut();
        std::mem::swap(
            &mut retained.capture.awaiting,
            &mut foreign.capture.awaiting,
        );
    }
    assert!(
        fixture
            .resolve_pending_q(&q, observer.discovery_domain(), 1)
            .is_err()
    );
    {
        let mut retained = fixture.scene.real.h0.0.borrow_mut();
        let mut foreign = other_original.scene.real.h0.0.borrow_mut();
        std::mem::swap(
            &mut retained.capture.awaiting,
            &mut foreign.capture.awaiting,
        );
    }
    before.assert_unchanged(&fixture);
    other_before.assert_unchanged(&other_original);
    for _ in 0..128 {
        fixture
            .resolve_pending_q(&q, observer.discovery_domain(), 1)
            .unwrap();
        if fixture.scene.real.h0.0.borrow().capture.awaiting.is_empty()
            && fixture
                .machine
                .retained_pending_q_report_for_test()
                .is_none()
        {
            break;
        }
    }
    let resolved = PendingQCustody::observe(&fixture);
    assert!(resolved.pending.is_empty());
    assert!(
        fixture
            .resolve_pending_q(&q, observer.discovery_domain(), 1)
            .is_err(),
        "an already-resolved original cannot expire twice"
    );
    resolved.assert_unchanged(&fixture);
    fixture.published_labeled("pending-at-Q correct original retry", None);
    assert_eq!(fixture.native.pending_q_resolutions, 1);

    // Move the actual adapter frontier with a real decoded BEGIN. This hostile
    // legacy consumer breaks canonical custody; no scalar frontier setter.
    let (mut stale, stale_observer, _foreign) = pending_h0_finish_fixture(false);
    let (begin, _) = stale
        .scene
        .encoded(std::process::id(), 1, "C_SignUpdate", 5);
    stale.scene.drain.source_mut().push_record(begin.to_vec());
    let stale_q = observe_pending_finish_q(&stale, &stale_observer);
    let before_frontier = stale
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .consumed_frontier();
    {
        let scene = &mut stale.scene;
        let adapter = scene
            .real
            .scene
            .coordinator
            .joint_capture_mut()
            .adapter_mut();
        let poll = scene.drain.poll_dispatched_quantum(
            Some(1),
            &publish_object_descriptors(),
            |_| panic!("the queued original is a journal BEGIN"),
            |record| {
                adapter.ingest_any(
                    crate::semantics_objects::journal::JournalIngestItem::Journal(record),
                );
                std::ops::ControlFlow::Continue(())
            },
        );
        assert_eq!(poll.attempted, 1);
    }
    assert!(
        stale
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .consumed_frontier()
            != before_frontier
    );
    let moved = PendingQCustody::observe(&stale);
    assert!(matches!(
        stale
            .machine
            .retained_raw_for_test()
            .unwrap()
            .validate_pending_finish(
                stale.scene.real.scene.coordinator.joint_capture().adapter(),
                &stale.scene.producers,
                stale_observer.discovery_domain(),
                &stale_q
            ),
        Err(RawQuantumRefusal::StaleFrontier)
    ));
    assert!(
        stale
            .resolve_pending_q(&stale_q, stale_observer.discovery_domain(), 1)
            .is_err()
    );
    moved.assert_unchanged(&stale);

    // A genuinely capacity-full ORIGINAL may end before Q. Exercise this
    // raw/Capture gate separately from the running machine's fixed 4096
    // capacity; the normal constructor actually consumes all four slots.
    let mut full = JointScene::for_audit(2);
    let pid = std::process::id();
    full.bind(
        pid,
        ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        },
        &[0, 1],
    );
    {
        let mut held = full.real.h0.0.borrow_mut();
        let (base, epoch, global) = held.io.scan_input(0);
        held.io
            .scan_inputs
            .insert(0, (base + 0x20_000, epoch + 1, global));
        held.io.script.fail_file = Some(0);
    }
    full.push(pid, 0, "C_SignInit", 1);
    full.push(pid, 1, "C_SignInit", 2);
    let reserve = full
        .real
        .scene
        .coordinator
        .registry()
        .semantic_storage_reserver();
    let (raw, poll) = RawJointQuantum::begin_bounded_with_adapter(
        &mut full.drain,
        &publish_object_descriptors(),
        4,
        4,
        None,
        &BirthFault,
        &full.producers,
        |bytes| reserve.reserve(bytes),
        full.real
            .scene
            .coordinator
            .joint_capture_mut()
            .adapter_mut(),
    )
    .unwrap();
    assert_eq!(poll.unwrap().attempted, 4);
    let identity = raw.h0_identity();
    full.real.h0.0.borrow_mut().collected = Some(raw);
    let ready = full.real.tick();
    let raw = full.real.h0.0.borrow_mut().collected.take().unwrap();
    assert!(raw.h0_identity() == identity);
    assert_eq!(raw.pending_h0_records(), 0);
    assert_eq!(full.real.h0.0.borrow().capture.awaiting.len(), 1);
    assert!(
        ready
            .current_receipts()
            .iter()
            .any(|receipt| receipt.endpoint().file_slot == 1)
    );
    let old_end = full.drain.consumption_cut().unwrap();
    let (later, _) = full.encoded(pid, 1, "C_SignUpdate", 3);
    full.drain.source_mut().push_record(later.to_vec());
    let owner = crate::attach::CollectedFinishQObserverForTest::new(&full.producers);
    owner.request_stop();
    let q = owner
        .observe(&full.producers, None, &full.drain)
        .unwrap()
        .unwrap();
    assert!(q.covers_events_bounds(&old_end));
    assert!(!q.events_at_bound(&old_end));
    raw.validate_pending_finish(
        full.real.scene.coordinator.joint_capture().adapter(),
        &full.producers,
        owner.discovery_domain(),
        &q,
    )
    .expect("pending-at-Q does not demand the final global Q drain from a full original");
    assert_eq!(full.drain.source_mut().remaining(), 1);
    assert_eq!(full.real.h0.0.borrow().capture.awaiting.len(), 1);

    // The Finish association is tied to the retained Q/producer/ledger and
    // actual coordinator, rather than a Copy receipt from another publication.
    let mut finishing = MachineScene::new(1);
    finishing.prime(1);
    let stale_receipt = finishing
        .scene
        .real
        .scene
        .coordinator
        .commit_batch(false)
        .unwrap();
    finishing.enable_finish_fixture(Vec::new());
    finishing.begin_finish().unwrap();
    finishing.reach_finish_stop_ready();
    let before = FinishCustody::observe(&finishing);
    assert!(stale_receipt.registry_published <= before.revision);
    assert!(
        finishing
            .scene
            .real
            .lane
            .begin_owned_terminal_cleanup()
            .is_err()
    );
    // Keep the actual Q in the machine, but present another owning DISCOVERY
    // allocation at the native I/O boundary. Refusal cannot consume that Q.
    let original_finish = finishing.finish.take().unwrap();
    finishing.enable_finish_fixture(Vec::new());
    assert!(finishing.poll_finish(1).is_err());
    finishing.finish = Some(original_finish);
    before.assert_unchanged(&finishing);
    let mut foreign_coordinator = MachineScene::new(1);
    {
        let MachineScene {
            scene,
            machine,
            native,
            finish,
        } = &mut finishing;
        let mut io = HeldMachineIo {
            drain: &mut scene.drain,
            h0: &scene.real.h0,
            producers: &scene.producers,
            attached: scene.attached.as_ref().unwrap(),
            native,
            finish: finish.as_mut(),
        };
        let mut work = crate::inventory_semantics::JointWorkBudget {
            remaining_actions: 1,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        assert!(
            machine
                .poll_finish_with_io(
                    &mut scene.real.lane,
                    &mut foreign_coordinator.scene.real.scene.coordinator,
                    &mut io,
                    &mut work,
                )
                .is_err()
        );
    }
    before.assert_unchanged(&finishing);
    assert!(!finishing.scene.real.lane.is_finished());
    assert!(
        finishing.machine.finish_disposition_required(),
        "a foreign Finish Q latches the disposition"
    );
    assert_eq!(
        finishing.poll_finish(1),
        Err(SemanticRefusal::Unavailable),
        "the first latched reason is kept after the owner is restored"
    );
    assert!(
        !finishing.scene.real.lane.is_finished(),
        "a latched Finish publishes nothing"
    );
    before.assert_unchanged(&finishing);
    // A Finish that saw no refusal still publishes exactly once.
    let mut clean = MachineScene::new(1);
    clean.prime(1);
    clean.enable_finish_fixture(Vec::new());
    clean.begin_finish().unwrap();
    clean.reach_finish_stop_ready();
    clean.finish_published();
    let completed = FinishCustody::observe(&clean);
    assert!(
        clean.begin_finish().is_err(),
        "a finished association is not a new Finish"
    );
    assert!(
        !matches!(
            clean.poll_finish(0),
            Ok(crate::discovery::engine::inventory_coordinator::JointCommitProgress::Published(_))
        ),
        "the completed Finish receipt is delivered once"
    );
    completed.assert_unchanged(&clean);
}

/// A tight pool refuses before expiry, and a later receiver refusal retains
/// the produced report/lease plus resolution state instead of re-expiring A.
#[test]
fn joint_machine_collected_finish_budget_refusal_preserves_originals() {
    let (mut fixture, observer, _foreign) = pending_h0_finish_fixture(false);
    let q = observe_pending_finish_q(&fixture, &observer);
    let before = PendingQCustody::observe(&fixture);
    let bytes = {
        let held = fixture.scene.real.h0.0.borrow();
        held.capture
            .pending_h0_at_q_storage_bytes(
                fixture.machine.retained_raw_for_test().unwrap(),
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .adapter(),
                &fixture.scene.producers,
                observer.discovery_domain(),
                &q,
            )
            .unwrap()
    };
    assert!(bytes > 0, "the report and all expiry temporaries are paid");
    let snapshot = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let hold = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes - (bytes - 1))
        .unwrap();
    let tight = PendingQCustody::observe(&fixture);
    let (refused, allocations, _) =
        crate::test_alloc::count_allocs_during(|| -> Result<(), SemanticRefusal> {
            for _ in 0..128 {
                fixture.resolve_pending_q(&q, observer.discovery_domain(), 1)?;
            }
            panic!("the actual tight expiry precharge must refuse within the bounded service");
        });
    assert_eq!(refused, Err(SemanticRefusal::ProviderStorage));
    assert_eq!(
        allocations, 0,
        "preflight does not allocate uncharged expiry scratch"
    );
    tight.assert_unchanged(&fixture);
    drop(hold);
    before.assert_unchanged(&fixture);
    fixture.machine.reference_refuse_pending_q_merge_once();
    let (refused, peak) =
        crate::test_alloc::requested_peak_during(|| -> Result<(), SemanticRefusal> {
            for _ in 0..128 {
                fixture.resolve_pending_q(&q, observer.discovery_domain(), 1)?;
            }
            panic!("the actual receiver must expose its injected refusal after real expiry");
        });
    assert_eq!(refused, Err(SemanticRefusal::ProviderStorage));
    assert!(!peak.incomplete);
    assert!(
        peak.realloc_overlap_bytes <= bytes,
        "the declared bound includes actual old/new overlap"
    );
    assert_eq!(fixture.native.pending_q_resolutions, 1);
    assert_eq!(fixture.native.pending_q_calls, 1);
    assert!(fixture.scene.real.h0.0.borrow().capture.awaiting.is_empty());
    assert!(!fixture.scene.real.h0.0.borrow().capture.stopped);
    let (report, paid) = fixture
        .machine
        .retained_pending_q_report_for_test()
        .unwrap();
    assert!(paid > 0);
    assert_eq!(report.awaiting_floor(), None);
    let calls = report.calls().collect::<Vec<_>>();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].token(), Some(before.pending[0].0));
    assert!(calls[0].collected_origin() == Some(before.pending[0].1));
    assert_eq!(
        calls[0].route(),
        crate::discovery::instances::Route::Unknown(
            crate::discovery::instances::UnknownReason::Unobserved
        )
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        before.charged + paid,
        "both original reports remain paid across receiver refusal"
    );
    let (ready, current) = fixture.machine.retained_h0_for_test().unwrap();
    assert_eq!(
        ready
            .iter()
            .filter(|outcome| matches!(outcome, TickOutcome::Call(_)))
            .count(),
        1
    );
    assert!(
        current
            .iter()
            .any(|receipt| receipt.endpoint().file_slot == 1)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        before.h3
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        before.acked
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision(),
        before.revision
    );
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .model()
            .project()
            == before.model
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        before.roles
    );
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            == before.claims
    );
    assert!(
        fixture
            .machine
            .retained_raw_for_test()
            .unwrap()
            .h0_identity()
            == before.raw
    );
    for _ in 0..128 {
        fixture
            .resolve_pending_q(&q, observer.discovery_domain(), 1)
            .unwrap();
        if fixture
            .machine
            .retained_pending_q_report_for_test()
            .is_none()
        {
            break;
        }
    }
    assert_eq!(
        fixture.native.pending_q_resolutions, 1,
        "retry only transfers the original report"
    );
    assert_eq!(fixture.native.pending_q_calls, 1);
    assert!(
        fixture
            .machine
            .retained_pending_q_report_for_test()
            .is_none()
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        before.charged,
        "drop incoming buffers before refunding their exact lease; the original accumulator stays paid"
    );
    fixture.published_labeled("pending-at-Q paid merge retry", None);
    assert_eq!(fixture.native.pending_q_resolutions, 1);

    // The final Stop is a separate mutation boundary. Zero work and a tight
    // pool refuse BEFORE it; a later receiver refusal retains its real output.
    let mut ending = MachineScene::new(1);
    ending.prime(1);
    ending.enable_finish_fixture(Vec::new());
    ending.begin_finish().unwrap();
    ending.reach_finish_stop_ready();
    let before_stop = FinishCustody::observe(&ending);
    ending.poll_finish(0).unwrap();
    before_stop.assert_unchanged(&ending);
    let bytes = ending.finish_storage_bytes();
    assert!(bytes > 0);
    let resource = ending
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let hold = ending
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(resource.limit_bytes - resource.charged_bytes - (bytes - 1))
        .unwrap();
    let tight = FinishCustody::observe(&ending);
    let (refused, allocations, _) =
        crate::test_alloc::count_allocs_during(|| ending.poll_finish(1));
    assert!(matches!(refused, Err(SemanticRefusal::ProviderStorage)));
    assert_eq!(
        allocations, 0,
        "no Stop output is allocated before its pool precharge"
    );
    tight.assert_unchanged(&ending);
    assert!(ending.machine.retained_finish_report_for_test().is_none());
    drop(hold);
    before_stop.assert_unchanged(&ending);
    ending.machine.reference_refuse_finish_q_merge_once();
    let mut refused = false;
    for _ in 0..128 {
        if let Err(reason) = ending.poll_finish(1) {
            assert_eq!(reason, SemanticRefusal::ProviderStorage);
            refused = true;
            break;
        }
    }
    assert!(refused);
    assert_eq!(ending.finish.as_ref().unwrap().stops, 1);
    assert!(ending.scene.real.h0.0.borrow().capture.stopped);
    let (report, paid) = ending.machine.retained_finish_report_for_test().unwrap();
    assert_eq!(paid, bytes);
    assert!(report.current().is_empty());
    assert!(report.outcomes().iter().any(|outcome| matches!(outcome,
        TickOutcome::Invalidation(invalidation) if matches!(invalidation.scope(), InvalidationScope::Stopped)
    )));
    let report_facts = (
        report.allocated_below(),
        report.awaiting_floor(),
        report.shed_floor(),
        report.exhausted(),
        report.outcomes().len(),
    );
    let held = FinishCustody::observe(&ending);
    assert_eq!(held.charged, before_stop.charged + paid);
    assert_eq!(
        held.h3, before_stop.h3,
        "no H3 take before the Stop union transfers"
    );
    assert_eq!(held.revision, before_stop.revision);
    assert_eq!(held.roles, before_stop.roles);
    assert!(held.claims == before_stop.claims);
    assert!(held.model == before_stop.model);
    assert!(!ending.scene.real.lane.is_finished());
    assert!(
        ending
            .scene
            .real
            .lane
            .begin_owned_terminal_cleanup()
            .is_err()
    );
    ending.poll_finish(0).unwrap();
    held.assert_unchanged(&ending);
    let (same, same_paid) = ending.machine.retained_finish_report_for_test().unwrap();
    assert_eq!(same_paid, paid);
    assert_eq!(
        (
            same.allocated_below(),
            same.awaiting_floor(),
            same.shed_floor(),
            same.exhausted(),
            same.outcomes().len()
        ),
        report_facts
    );
    ending.poll_finish(1).unwrap();
    assert!(ending.machine.retained_finish_report_for_test().is_none());
    assert_eq!(
        ending.finish.as_ref().unwrap().stops,
        1,
        "retry only transfers the produced Stop report"
    );
    assert_eq!(
        ending
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        before_stop.charged,
        "the incoming Stop buffers drop before their temporary lease refunds"
    );
    ending.finish_published();
    assert_eq!(ending.finish.as_ref().unwrap().stops, 1);
}

#[test]
fn joint_machine_pending_a_allows_q2_real_end() {
    for reverse in [false, true] {
        for idle_demand in [false, true] {
            let mut fixture = MachineScene::new(2);
            fixture.prime(2);
            let before = fixture.reduced();
            let (a, b) = if reverse { (1, 0) } else { (0, 1) };
            let (a_sequence, b_sequence) = if reverse { (4, 3) } else { (3, 4) };
            let (begin_a, end_a) =
                fixture
                    .scene
                    .encoded(std::process::id(), a, "C_SignInit", a_sequence);
            let (begin_b, end_b) =
                fixture
                    .scene
                    .encoded(std::process::id(), b, "C_SignInit", b_sequence);
            let begins = if reverse {
                [begin_b, begin_a]
            } else {
                [begin_a, begin_b]
            };
            for bytes in begins
                .into_iter()
                .map(|bytes| bytes.to_vec())
                .chain([end_b.to_vec()])
            {
                fixture.scene.drain.source_mut().push_record(bytes);
            }
            fixture.published();
            assert_eq!(
                fixture.reduced(),
                before,
                "q1 cannot replay through the missing original END(A)"
            );
            // Native invocation identity is the BEGIN header's thread,
            // independently from the ordinary payload's pid_tgid word.
            let native_a = (u64::from(std::process::id()), a_sequence);
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .adapter()
                    .retained_start_bytes_for_test(native_a),
                Some(begin_a),
                "q1 publication keeps the exact physical START for q2's END"
            );
            assert!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .ledger()
                    .roles_for_test()[1]
                    > 0
            );
            let coordinator = &fixture.scene.real.scene.coordinator;
            let claims = coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test();
            let roles = coordinator.joint_capture().ledger().roles_for_test();
            let h3 = coordinator.reference_h3_audit_state();
            let revision = coordinator.registry().published_revision();
            assert_eq!(claims.0, 1);
            assert_eq!((roles[0], roles[1], roles[3]), (0, 2, 1));
            for _ in 0..3 {
                fixture.service(1).unwrap();
                let coordinator = &fixture.scene.real.scene.coordinator;
                assert_eq!(
                    coordinator
                        .joint_capture()
                        .adapter()
                        .invocation_claims_for_test(),
                    claims
                );
                assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
                assert_eq!(coordinator.reference_h3_audit_state(), h3);
                assert_eq!(coordinator.registry().published_revision(), revision);
            }
            if idle_demand {
                use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
                fixture.machine.begin_commit(true).unwrap();
                let mut completed = false;
                let mut retained_claim_requires_ingestion = false;
                for _ in 0..128 {
                    if fixture.machine.diagnostic_snapshot_for_test().0 == "Ingesting" {
                        let raw = fixture.machine.retained_raw_for_test().unwrap();
                        assert_eq!(
                            raw.can_dispose_empty(
                                fixture
                                    .scene
                                    .real
                                    .scene
                                    .coordinator
                                    .joint_capture()
                                    .adapter(),
                                &fixture.scene.producers,
                            ),
                            Ok(false),
                            "the original COMPLETE/claim must keep this empty quantum ingested"
                        );
                        retained_claim_requires_ingestion = true;
                    }
                    if matches!(
                        fixture.poll_commit(1).unwrap(),
                        JointCommitProgress::Published(_)
                    ) {
                        completed = true;
                        break;
                    }
                }
                assert!(
                    completed,
                    "the genuine retained grant services this idle demand without disposing the unmatched COMPLETE"
                );
                assert!(retained_claim_requires_ingestion);
                assert_eq!(fixture.reduced(), before);
                let coordinator = &fixture.scene.real.scene.coordinator;
                assert_eq!(
                    coordinator
                        .joint_capture()
                        .adapter()
                        .invocation_claims_for_test(),
                    claims
                );
                assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
                assert_eq!(coordinator.registry().published_revision(), revision + 1);
                assert_eq!(coordinator.reference_h3_audit_state(), (h3.0 + 1, false));
                assert_eq!(
                    coordinator
                        .joint_capture()
                        .adapter()
                        .retained_start_bytes_for_test(native_a),
                    Some(begin_a)
                );
            }
            fixture.scene.drain.source_mut().push_record(end_a.to_vec());
            fixture.published();
            assert_eq!(
                fixture.reduced(),
                before.iter().map(|count| count + 1).collect::<Vec<_>>()
            );
            let coordinator = &fixture.scene.real.scene.coordinator;
            assert_eq!(
                coordinator
                    .joint_capture()
                    .adapter()
                    .invocation_claims_for_test()
                    .0,
                0
            );
            let roles = coordinator.joint_capture().ledger().roles_for_test();
            assert_eq!((roles[0], roles[1], roles[3]), (0, 0, 0));
            assert!(
                coordinator
                    .joint_capture()
                    .adapter()
                    .retained_start_bytes_for_test(native_a)
                    .is_none()
            );
        }
    }
}

#[test]
fn joint_machine_negative_dispositions_are_finite() {
    for malformed in [false, true] {
        let mut fixture = MachineScene::new(1);
        let revision = fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision();
        if malformed {
            fixture.scene.drain.source_mut().push_record(vec![0; 17]);
        }
        let boundary = fixture.scene.drain.consumption_cut().unwrap();
        fixture.service(0).unwrap();
        assert!(boundary.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .published_revision(),
            revision
        );
        assert!(fixture.native.preparations.is_empty());
        fixture.machine.begin_commit(false).unwrap();
        let mut published = None;
        for _ in 0..128 {
            if let crate::discovery::engine::inventory_coordinator::JointCommitProgress::Published(
                receipt,
            ) = fixture.poll_commit(1).unwrap()
            {
                published = Some(receipt);
                break;
            }
        }
        let published =
            published.expect("the exact original negative publication acknowledges its requester");
        assert_eq!(published.registry_published, revision + 1);
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(coordinator.registry().published_revision(), revision + 1);
        assert_eq!(coordinator.registry().joint_feeds(), 0);
        assert!(fixture.native.rows.is_empty());
        assert!(
            coordinator
                .joint_capture()
                .model()
                .project()
                .objects
                .is_empty()
        );
        assert_eq!(
            coordinator.joint_capture().ledger().roles_for_test()[..4],
            [0, 0, 0, 0]
        );
        let completed = coordinator.registry().published_revision();
        let model = coordinator.joint_capture().model().project();
        let claims = coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test();
        let roles = coordinator.joint_capture().ledger().roles_for_test();
        let h3 = coordinator.reference_h3_audit_state();
        let frontier = coordinator.joint_capture().adapter().consumed_frontier();
        let charged = coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes;
        assert!(!coordinator.publication_pending());
        let boundary = fixture.scene.drain.consumption_cut().unwrap();
        let cut = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture_mut()
            .adapter_mut()
            .resolve_birth_cut(&boundary, &fixture.scene.producers);
        if malformed {
            assert_eq!(
                cut.err(),
                Some(crate::semantics_objects::journal::BirthCutRefusal::Gap),
                "the completed malformed prefix permanently breaks this stream"
            );
            assert_eq!(fixture.service(1), Err(SemanticRefusal::Unavailable));
            assert!(fixture.machine.retained_raw_for_test().is_none());
            assert!(
                fixture.machine.begin_commit(false).is_err(),
                "a new demand cannot heal the original gap"
            );
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .registry()
                    .semantic_resource_snapshot()
                    .charged_bytes,
                charged
            );
        } else {
            assert!(cut.is_ok());
            assert_eq!(
                fixture.service(1).unwrap(),
                crate::inventory_semantics::JointServiceProgress::Pending
            );
            assert!(
                fixture.machine.retained_raw_for_test().is_some(),
                "a healthy idle read keeps its actual paid allocation"
            );
        }
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert!(boundary.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
        assert_eq!(
            coordinator.registry().published_revision(),
            completed,
            "an idle slice cannot spin through repeated empty publications"
        );
        assert_eq!(coordinator.joint_capture().model().project(), model);
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            claims
        );
        assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
        assert_eq!(coordinator.reference_h3_audit_state(), h3);
        assert!(coordinator.joint_capture().adapter().consumed_frontier() == frontier);
        assert!(!coordinator.publication_pending());
    }
}

#[test]
fn joint_machine_request_ack_tracks_actual_preparation_and_attempted_error() {
    use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
    for frozen in [false, true] {
        let mut fixture = MachineScene::new(1);
        fixture
            .scene
            .push(std::process::id(), 0, "C_CreateObject", 1);
        let old = fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision();
        let tails = fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_engine_tail_stats();
        let unprepared = if frozen {
            for _ in 0..128 {
                fixture.service(1).unwrap();
                if fixture.scene.real.scene.coordinator.publication_pending() {
                    break;
                }
            }
            assert!(fixture.scene.real.scene.coordinator.publication_pending());
            None
        } else {
            fixture.service(1).unwrap();
            assert!(!fixture.scene.real.scene.coordinator.publication_pending());
            Some(
                fixture
                    .machine
                    .retained_raw_for_test()
                    .unwrap()
                    .h0_identity(),
            )
        };
        fixture.machine.begin_commit(true).unwrap();
        assert!(
            fixture.machine.begin_commit(false).is_err(),
            "a second request cannot replace the original demand"
        );
        if frozen {
            fixture.published_labeled("older frozen publication", Some(frozen));
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .registry()
                    .published_revision(),
                old + 1
            );
            assert!(
                matches!(
                    fixture.poll_commit(1).unwrap(),
                    JointCommitProgress::Pending
                ),
                "the older actual publication cannot acknowledge the later request"
            );
        }
        let before_requested = frozen.then(|| {
            (
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .model()
                    .project(),
                fixture.reduced(),
                fixture.scene.drain.consumption_cut().unwrap(),
            )
        });
        // Autonomous service may finish the demand, but cannot consume the
        // requester's acknowledgement or allow a new request to replace it.
        fixture.published_labeled("requested publication", Some(frozen));
        if let Some((model, reduced, boundary)) = before_requested {
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .model()
                    .project(),
                model,
                "a quiet metadata publication cannot manufacture another object transition"
            );
            assert_eq!(fixture.reduced(), reduced);
            assert!(boundary.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
        }
        assert_eq!(fixture.reduced(), [1]);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_audit_state(),
            (if frozen { 2 } else { 1 }, false),
            "each original publication takes exactly its own actual H3"
        );
        assert!(fixture.machine.begin_commit(false).is_err());
        let mut foreign = InventoryCoordinator::new(
            Scope::System,
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let foreign_revision = foreign.registry().published_revision();
        let native_reads = fixture.native.reads.get();
        {
            let MachineScene {
                scene,
                machine,
                native,
                finish,
            } = &mut fixture;
            let mut io = HeldMachineIo {
                drain: &mut scene.drain,
                h0: &scene.real.h0,
                producers: &scene.producers,
                attached: scene.attached.as_ref().unwrap(),
                native,
                finish: finish.as_mut(),
            };
            let mut budget = crate::inventory_semantics::JointWorkBudget {
                remaining_actions: 0,
                deadline: Instant::now() + Duration::from_secs(1),
            };
            assert!(
                machine
                    .poll_commit_with_io(&mut scene.real.lane, &mut foreign, &mut io, &mut budget)
                    .is_err(),
                "same producer words do not bind another canonical ledger to the pending acknowledgement"
            );
        }
        assert_eq!(foreign.registry().published_revision(), foreign_revision);
        assert_eq!(fixture.native.reads.get(), native_reads);
        let JointCommitProgress::Published(completion) = fixture.poll_commit(0).unwrap() else {
            panic!("service must retain the actual receipt until the requester consumes it");
        };
        if let Some(original) = unprepared {
            assert!(
                fixture.native.preparations[0].0 == original,
                "a request may bind to an old Raw only at its actual preparation"
            );
        }
        assert_eq!(
            completion.registry_published,
            old + if frozen { 2 } else { 1 }
        );
        let after = fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_engine_tail_stats();
        assert_eq!(
            after.0 + after.1 - tails.0 - tails.1,
            if frozen { 2 } else { 1 }
        );
        assert_eq!(
            fixture
                .native
                .preparations
                .iter()
                .map(|(_, changed)| *changed)
                .collect::<Vec<_>>(),
            if frozen {
                vec![false, true]
            } else {
                vec![true]
            }
        );
        assert!(
            matches!(
                fixture.poll_commit(1).unwrap(),
                JointCommitProgress::Pending
            ),
            "a Published acknowledgement is consumed exactly once"
        );
    }

    let mut fixture = MachineScene::new(1);
    fixture
        .scene
        .push(std::process::id(), 0, "C_CreateObject", 1);
    fixture.native.fail_after_preparation = true;
    fixture.machine.begin_commit(true).unwrap();
    let tails = fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_engine_tail_stats();
    let mut failed = false;
    for _ in 0..128 {
        if fixture.service(1).is_err() {
            failed = true;
            break;
        }
    }
    assert!(
        failed,
        "the real preparation is followed by the failed owned handoff"
    );
    assert!(fixture.scene.real.scene.coordinator.publication_pending());
    let attempted = fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_engine_tail_stats();
    assert_eq!(attempted.0 + attempted.1 - tails.0 - tails.1, 1);
    assert_eq!(fixture.native.preparations.len(), 1);
    let identity = fixture.native.preparations[0].0;
    for _ in 0..3 {
        assert!(fixture.service(8).is_err());
        assert!(fixture.machine.begin_commit(false).is_err());
        assert!(
            fixture
                .machine
                .retained_raw_for_test()
                .unwrap()
                .h0_identity()
                == identity
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_engine_tail_stats(),
            attempted
        );
        assert_eq!(fixture.native.preparations.len(), 1);
    }
}

#[test]
fn joint_machine_empty_disposition_requires_actual_quiet_original() {
    use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
    use crate::semantics_objects::journal::JournalGap;
    use crate::semantics_objects::journal::joint_driver::RawDisposeReason;

    for native_loss in [false, true] {
        let mut fixture = MachineScene::new(1);
        fixture.prime(1);
        let before = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .model()
            .project();
        assert!(
            before
                .objects
                .iter()
                .any(|object| object.lifetime == Lifetime::Live)
        );
        let reduced = fixture.reduced();
        let h3 = fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state();
        let revision = fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision();
        fixture.machine.begin_commit(false).unwrap();
        // Idle first walks the retained Ready/absence subjects. A single
        // budget-one action need not have polled the original cursor yet.
        for _ in 0..128 {
            if fixture.machine.diagnostic_snapshot_for_test().0 == "Collecting" {
                break;
            }
            fixture.service(1).unwrap();
        }
        assert_eq!(
            fixture.machine.diagnostic_snapshot_for_test().0,
            "Collecting"
        );
        let original = fixture.machine.retained_raw_for_test().unwrap();
        let identity = original.h0_identity();
        assert_eq!(
            original.can_dispose_empty(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .adapter(),
                &fixture.scene.producers,
            ),
            Err(RawQuantumRefusal::H0Undelivered),
            "a real empty poll does not replace actual H0 disposition"
        );
        for _ in 0..128 {
            if fixture.machine.diagnostic_snapshot_for_test().0 == "Ingesting" {
                break;
            }
            fixture.service(1).unwrap();
        }
        assert_eq!(
            fixture.machine.diagnostic_snapshot_for_test().0,
            "Ingesting"
        );
        let boundary = fixture.scene.drain.consumption_cut().unwrap();
        let coordinator = &fixture.scene.real.scene.coordinator;
        let roles = coordinator.joint_capture().ledger().roles_for_test();
        let claims = coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test();
        let charged = coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes;
        let original = fixture.machine.retained_raw_for_test().unwrap();
        assert!(original.h0_identity() == identity);
        assert_eq!(
            original.can_dispose_empty(
                coordinator.joint_capture().adapter(),
                &fixture.scene.producers
            ),
            Ok(true)
        );
        let foreign = SessionDrainProducers::test_pair(
            fixture.scene.producers.native_domain(),
            crate::events::EventsDomain::test_standin(fixture.scene.producers.events_id()),
        );
        assert_eq!(
            original.can_dispose_empty(coordinator.joint_capture().adapter(), &foreign),
            Err(RawQuantumRefusal::ForeignCapture)
        );
        let foreign_owner = crate::semantics_objects::journal::joint_driver::JointCaptureOwner::new(
            crate::semantics_objects::journal::JournalLimits::policy(),
            coordinator.registry().semantic_storage_reserver(),
        );
        assert!(
            original
                .can_dispose_empty(foreign_owner.adapter(), &fixture.scene.producers)
                .is_err()
        );
        drop(foreign_owner);
        assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            claims
        );
        assert_eq!(
            coordinator
                .registry()
                .semantic_resource_snapshot()
                .charged_bytes,
            charged
        );
        assert_eq!(coordinator.reference_h3_audit_state(), h3);
        assert_eq!(coordinator.registry().published_revision(), revision);
        assert!(boundary.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
        if native_loss {
            fixture
                .scene
                .real
                .h0
                .0
                .borrow()
                .io
                .script
                .fault_cell
                .store(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                fixture
                    .machine
                    .retained_raw_for_test()
                    .unwrap()
                    .can_dispose_empty(
                        fixture
                            .scene
                            .real
                            .scene
                            .coordinator
                            .joint_capture()
                            .adapter(),
                        &fixture.scene.producers,
                    ),
                Ok(true),
                "this read-only route cannot substitute for the later fresh native audit"
            );
        }
        let mut saw_empty = false;
        let mut saw_fault = false;
        let mut published = false;
        for _ in 0..128 {
            let progress = fixture.service(1).unwrap();
            if let Some(disposed) = fixture.machine.retained_negative_for_test() {
                assert_eq!(disposed.reason(), RawDisposeReason::Empty);
                assert!(disposed.identity() == identity);
                saw_empty = true;
            }
            if let Some((gap, _, _, _, _)) = fixture.machine.diagnostic_audit_for_test() {
                assert_eq!(gap, native_loss.then_some(JournalGap::FaultChanged));
                saw_fault |= gap == Some(JournalGap::FaultChanged);
            }
            if progress == crate::inventory_semantics::JointServiceProgress::Published {
                published = true;
                break;
            }
        }
        assert!(saw_empty && published);
        assert_eq!(saw_fault, native_loss);
        assert_eq!(fixture.reduced(), reduced);
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(coordinator.registry().published_revision(), revision + 1);
        assert_eq!(coordinator.reference_h3_audit_state(), (h3.0 + 1, false));
        let after = coordinator.joint_capture().model().project();
        if native_loss {
            assert_ne!(
                after, before,
                "actual native loss still invalidates the retained live object"
            );
            assert!(
                after
                    .objects
                    .iter()
                    .all(|object| object.lifetime != Lifetime::Live)
            );
        } else {
            assert_eq!(after, before);
        }
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            claims
        );
        assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
        assert!(boundary.same_boundary(&fixture.scene.drain.consumption_cut().unwrap()));
        assert!(matches!(
            fixture.poll_commit(0).unwrap(),
            JointCommitProgress::Published(_)
        ));
        assert!(matches!(
            fixture.poll_commit(0).unwrap(),
            JointCommitProgress::Pending
        ));
    }
}

#[derive(Clone, Copy)]
enum PublicationReceipts {
    All,
    Missing,
    Capacity(usize),
}

/// Stop the existing genuine collection/admission seam before its original
/// New receipts move. Registry registration remains staged, not selected.
fn prepared_birth_originals(
    providers: usize,
    repeated_key: bool,
    stop_after_first_claim: bool,
) -> (
    JointScene,
    IngestedRaw,
    crate::attach::AttachedSemanticSet,
    SessionDrainGrant,
) {
    prepared_birth_with_claim_predecessor(providers, repeated_key, stop_after_first_claim, false)
}

fn prepared_birth_with_claim_predecessor(
    providers: usize,
    repeated_key: bool,
    stop_after_first_claim: bool,
    refused_predecessor: bool,
) -> (
    JointScene,
    IngestedRaw,
    crate::attach::AttachedSemanticSet,
    SessionDrainGrant,
) {
    let (held, attached) =
        HeldProviders::with_attachment(providers, &["C_CreateObject", "C_SignInit"]);
    let mut scene = JointScene::from_held(held, Some(attached));
    scene.real.h0.0.borrow_mut().io.script.local = 1;
    let pid = std::process::id();
    let caller = scene.real.bind(
        pid,
        ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        },
        0,
    );
    let files = (0..providers as u32).collect::<Vec<_>>();
    if refused_predecessor {
        assert_eq!(
            (providers, repeated_key, stop_after_first_claim),
            (1, true, false)
        );
        scene
            .real
            .scene
            .coordinator
            .joint_capture_mut()
            .adapter_mut()
            .restrict_thread_floors_for_test(1);
        let (_, first) = scene.encoded(pid, 0, "C_CreateObject", 1);
        let (begin, end) = scene.encoded(pid, 0, "C_CreateObject", 2);
        let mut ordinary = first[24..392].to_vec();
        let thread = std::mem::offset_of!(p11scope_ebpf_common::Event, pid_tgid);
        ordinary[thread..thread + 8]
            .copy_from_slice(&((u64::from(pid) << 32) | u64::from(pid + 1)).to_le_bytes());
        scene.drain.source_mut().push_record(begin.to_vec());
        scene.drain.source_mut().push_record(ordinary);
        scene.drain.source_mut().push_record(end.to_vec());
    } else {
        for file in &files {
            scene.push(pid, *file, "C_CreateObject", u64::from(*file) + 1);
        }
        if repeated_key {
            scene.push(pid, 0, "C_CreateObject", providers as u64 + 1);
        }
    }
    let raw = scene.collect_with_fault(&BirthFault);
    scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = scene.real.tick();
    scene.admit_providers(pid, caller, &files);
    scene.prepare_batch(batch, providers + usize::from(repeated_key));
    let raw = scene.real.h0.0.borrow_mut().collected.take().unwrap();
    let (ingested, _, grant) = scene.ingest_with_grant(raw);
    let mut count = 0;
    while let Some((_, claim)) = scene
        .real
        .scene
        .coordinator
        .claim_next_prepared_admission(&scene.producers, &ingested)
        .unwrap()
    {
        count += 1;
        if refused_predecessor && count == 1 {
            assert_eq!(claim, Err(AttestationRefusal::ClaimsExhausted));
        } else {
            assert_eq!(claim.is_ok(), !stop_after_first_claim || count == 1);
        }
        if stop_after_first_claim && count == 1 {
            let (adapter, model) = scene.real.scene.coordinator.joint_capture_mut().parts();
            adapter.stop(model);
        }
    }
    assert_eq!(count, providers + usize::from(repeated_key));
    let attached = attachment(&mut scene);
    assert!(
        scene
            .real
            .scene
            .coordinator
            .joint_capture_mut()
            .adapter_mut()
            .install_closure_grant(&SessionClosureGrant::observe(&attached))
    );
    (scene, ingested, attached, grant)
}

#[test]
fn joint_birth_reservation_keeps_original_until_one_install() {
    use crate::inventory_semantics::RetainedJointBirths;

    for refuse_storage in [false, true] {
        let (mut scene, mut ingested, attached, _grant) = prepared_birth_originals(2, false, false);
        let original_claims = scene
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap()
            .claims()
            .map(|(ordinal, result)| (ordinal, *result))
            .collect::<Vec<_>>();
        assert_eq!(original_claims.len(), 2);
        assert!(original_claims.iter().all(|(_, result)| result.is_ok()));
        let canonical_claims = scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test();
        assert_eq!(canonical_claims.0, 2);
        let original_new = scene
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap()
            .current_receipts()
            .iter()
            .map(|receipt| {
                receipt
                    .birth
                    .as_ref()
                    .map(|(capture, _, raw)| (*capture, *raw))
            })
            .collect::<Vec<_>>();
        assert!(original_new.iter().all(Option::is_some));
        let inputs = scene
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .cloned()
            .collect::<Vec<_>>();
        let original_roles = scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test();
        let reserve = scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_storage_reserver();
        let hold = refuse_storage.then(|| {
            let snapshot = scene
                .real
                .scene
                .coordinator
                .registry()
                .semantic_resource_snapshot();
            reserve
                .reserve(snapshot.limit_bytes - snapshot.charged_bytes)
                .unwrap()
        });
        let mut births = RetainedJointBirths::new();
        let h0 = scene.real.h0.clone();
        let publisher = NativePublisher::build();
        let mut native_calls = 0;
        let mut native_rows = Vec::new();
        let disposition = scene
            .real
            .scene
            .coordinator
            .prepare_joint_births(
                &ingested,
                &scene.producers,
                &mut births,
                |candidate, absence, input, binding, proof, adapter| {
                    native_calls += 1;
                    let (row, control, _) =
                        publisher.publish_stamped(&["0", "0"], attached.generation());
                    let mut rows = NativeBirthRows { row, control };
                    let mut owned = h0.0.borrow_mut();
                    let HeldH0 { capture, io, .. } = &mut *owned;
                    capture.validate_birth_candidate(io, &candidate, false)?;
                    let witness = capture.finish_birth(
                        candidate, absence, input, binding, &attached, proof, adapter, &mut rows,
                    )?;
                    native_rows.push((witness.receipt().domain(), rows));
                    Ok(witness)
                },
            )
            .unwrap();
        assert_eq!(native_calls, if refuse_storage { 0 } else { 2 });
        assert_eq!(disposition.installed, native_calls);
        assert_eq!(births.as_slice().len(), native_calls);
        if refuse_storage {
            assert!(
                scene
                    .real
                    .scene
                    .coordinator
                    .prepared_semantic_batch()
                    .unwrap()
                    .current_receipts()
                    .iter()
                    .map(|receipt| receipt
                        .birth
                        .as_ref()
                        .map(|(capture, _, raw)| (*capture, *raw)))
                    .collect::<Vec<_>>()
                    == original_new,
                "capacity refusal must retain the actual original New before any native consumption"
            );
        }
        assert_eq!(
            scene
                .real
                .scene
                .coordinator
                .prepared_semantic_batch()
                .unwrap()
                .claims()
                .map(|(ordinal, result)| (ordinal, *result))
                .collect::<Vec<_>>(),
            original_claims
        );
        let grants = scene
            .real
            .scene
            .coordinator
            .registry()
            .pending_joint_receipts_for_test();
        assert_eq!(grants.len(), native_calls);
        for (origin, proof) in &grants {
            assert!(
                inputs
                    .iter()
                    .any(|input| input.collected_origin() == Some(*origin)
                        && proof.matches_admitted(input))
            );
        }
        assert_eq!(
            scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test(),
            original_roles
        );
        drop(hold);
        let retry = scene
            .real
            .scene
            .coordinator
            .prepare_joint_births(
                &ingested,
                &scene.producers,
                &mut births,
                |_, _, _, _, _, _| {
                    panic!("a decided original may never consume New or read native twice")
                },
            )
            .unwrap();
        assert_eq!(retry.installed, 0);
        assert_eq!(
            scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            canonical_claims
        );
        assert!(
            scene
                .real
                .scene
                .coordinator
                .registry()
                .pending_joint_receipts_for_test()
                == grants
        );
        while scene
            .real
            .scene
            .coordinator
            .stage_next_prepared_admission_with_disposition(&scene.producers, &mut ingested)
            .unwrap()
        {}
        assert!(
            scene
                .real
                .scene
                .coordinator
                .finish_prepared_semantic_batch(&scene.real.lane)
        );
        scene
            .real
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut scene.real.lane))
            .unwrap();
        assert_eq!(
            scene.real.scene.coordinator.registry().joint_feeds(),
            native_calls
        );
        assert_eq!(
            scene
                .real
                .scene
                .coordinator
                .registry()
                .instance_semantic_edges()
                .count(),
            2
        );
        if !refuse_storage {
            crate::discovery::caller_registry::instance_input::joint_grant_post_removal_growth_probe_for_test(*births.ready_for_test().next().unwrap().receipt());
        }
        let frame = scene
            .real
            .scene
            .coordinator
            .audit_ingested_quantum(ingested, &scene.producers, &attached, &BirthFault)
            .unwrap_or_else(|(_, reason)| panic!("actual original first audit: {reason:?}"));
        finish_reserved_birth_frame(&mut scene, &attached, &births, &mut native_rows, frame);
        assert_eq!(
            scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .model()
                .project()
                .objects
                .iter()
                .filter(|object| object.lifetime == Lifetime::Live)
                .count(),
            native_calls
        );
        scene.assert_claims(&[]);
        assert_eq!(
            scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test()[..4],
            [0, 0, 0, 0]
        );
    }
}

fn finish_reserved_birth_frame(
    scene: &mut JointScene,
    attached: &crate::attach::AttachedSemanticSet,
    births: &crate::inventory_semantics::RetainedJointBirths,
    rows: &mut [(crate::semantics_objects::ObjectDomain, NativeBirthRows)],
    frame: IngestedJointQuantum,
) {
    use crate::semantics_objects::journal::joint_audit::JointBirthEvidenceSource;
    struct Reads<'a>(&'a mut dyn JointBirthEvidenceSource);
    impl JointBirthEvidenceSource for Reads<'_> {
        fn take_for(
            &mut self,
            target: &JointFeedTarget,
            binding: &SemanticCallerBinding,
        ) -> Result<SessionBirthEvidence, BirthObservationRefusal> {
            self.0.take_for(target, binding)
        }
    }
    struct Fault<'a>(&'a dyn crate::semantics_objects::journal::FaultEpoch);
    impl crate::semantics_objects::journal::FaultEpoch for Fault<'_> {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            self.0.fault_epoch()
        }
    }
    let expected_reads = rows.len();
    let mut owned = scene.real.h0.0.borrow_mut();
    let HeldH0 {
        capture, io, stash, ..
    } = &mut *owned;
    let reads = Cell::new((0, 0));
    let mut native = HeldCommitNative {
        io,
        rows: rows
            .iter_mut()
            .map(|(domain, rows)| (*domain, rows))
            .collect(),
        reads: &reads,
    };
    let native = RefCell::new(&mut native);
    crate::inventory_semantics::with_joint_commit_io_for_births_test(
        capture,
        stash,
        &scene.producers,
        attached,
        births,
        &native,
        |io| {
            let (_, births, fault) = io.into_parts();
            let mut births = Reads(births);
            let fault = Fault(fault);
            let mut frame = Some(frame);
            let mut ports = scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&scene.producers)
                .unwrap();
            frame.as_mut().unwrap().bind_targets(&ports).unwrap();
            let mut complete = false;
            for _ in 0..256 {
                let held = frame.as_mut().unwrap();
                held.seal_next(&mut ports, &mut births, &fault).unwrap();
                let mut work = 1;
                if held.deliver_next_bounded(&mut ports, &mut work).unwrap()
                    == QuantumSealProgress::Complete
                {
                    complete = true;
                    break;
                }
            }
            assert!(
                complete,
                "actual first Joint calls reduce through the paid original witness table"
            );
            frame
                .take()
                .unwrap()
                .finish_frame(&mut ports)
                .unwrap_or_else(|(_, reason)| {
                    panic!("first original terminal disposition: {reason:?}")
                });
        },
    )
    .unwrap();
    assert_eq!(
        reads.get().0,
        expected_reads,
        "each original selected domain rechecks the same live native source once"
    );
}

#[test]
fn joint_birth_reservation_refuses_foreign_or_late_subject() {
    use crate::discovery::caller_registry::instance_input::JointReceiptInstallRefusal;
    use crate::inventory_semantics::RetainedJointBirths;

    let (mut scene, mut ingested, attached, _grant) = prepared_birth_originals(1, true, false);
    let inputs = scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .cloned()
        .collect::<Vec<_>>();
    assert!(inputs[0].collected_origin() != inputs[1].collected_origin());
    let (mut foreign, _frame) = CanonicalFanoutScene::first_publication_with_functions(
        1,
        &["C_CreateObject", "C_SignInit"],
        PublicationReceipts::All,
    );
    let token = scene
        .real
        .scene
        .coordinator
        .registry_mut()
        .reserve_admitted_joint_receipt(&inputs[0])
        .unwrap_or_else(|reason| panic!("original reservation: {reason:?}"));
    let token = match token.install(&inputs[1], &foreign.births[0].1) {
        Err((token, JointReceiptInstallRefusal::SubjectMismatch)) => token,
        _ => panic!("same-key sibling position must not consume the original reservation"),
    };
    let token = match token.install(&inputs[0], &foreign.births[0].1) {
        Err((token, JointReceiptInstallRefusal::ReceiptMismatch)) => token,
        _ => panic!("a genuine foreign receipt must not authorize this original"),
    };
    drop(token);
    assert!(
        scene
            .real
            .scene
            .coordinator
            .registry()
            .pending_joint_receipts_for_test()
            .is_empty()
    );
    let h0 = scene.real.h0.clone();
    let publisher = NativePublisher::build();
    let mut native_calls = 0;
    let mut births = RetainedJointBirths::new();
    let result = scene
        .real
        .scene
        .coordinator
        .prepare_joint_births(
            &ingested,
            &scene.producers,
            &mut births,
            |candidate, absence, input, binding, proof, adapter| {
                native_calls += 1;
                let (row, control, _) =
                    publisher.publish_stamped(&["0", "0"], attached.generation() + 1);
                let mut rows = NativeBirthRows { row, control };
                let mut owned = h0.0.borrow_mut();
                let HeldH0 { capture, io, .. } = &mut *owned;
                capture.validate_birth_candidate(io, &candidate, false)?;
                let refused = capture.finish_birth(
                    candidate, absence, input, binding, &attached, proof, adapter, &mut rows,
                );
                assert!(
                    refused.is_err(),
                    "the actual wrong native generation must refuse"
                );
                refused
            },
        )
        .unwrap();
    assert_eq!(
        (native_calls, result.installed, births.as_slice().len()),
        (1, 0, 0)
    );
    scene
        .real
        .scene
        .coordinator
        .prepare_joint_births(
            &ingested,
            &scene.producers,
            &mut births,
            |_, _, _, _, _, _| panic!("native refusal is final S1, never a late upgrade"),
        )
        .unwrap();
    while scene
        .real
        .scene
        .coordinator
        .stage_next_prepared_admission_with_disposition(&scene.producers, &mut ingested)
        .unwrap()
    {}
    assert!(
        scene
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&scene.real.lane)
    );
    scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut scene.real.lane))
        .unwrap();
    assert!(
        scene
            .real
            .scene
            .coordinator
            .registry_mut()
            .reserve_admitted_joint_receipt(&inputs[0])
            .is_err()
    );
    assert_eq!(scene.real.scene.coordinator.registry().joint_feeds(), 0);

    // A callback can return another real witness; the owner must rejoin the
    // exact original candidate/allocation before installing or retaining it.
    let (mut other, other_ingested, _, _) = prepared_birth_originals(1, false, false);
    let mut foreign_witness = Some(foreign.births.swap_remove(0).1);
    let mut retained = RetainedJointBirths::new();
    let refused = other
        .real
        .scene
        .coordinator
        .prepare_joint_births(
            &other_ingested,
            &other.producers,
            &mut retained,
            |_, _, _, _, _, _| Ok(foreign_witness.take().unwrap()),
        )
        .unwrap();
    assert_eq!(refused.installed, 0);
    assert!(retained.as_slice().is_empty());
    assert!(
        other
            .real
            .scene
            .coordinator
            .registry()
            .pending_joint_receipts_for_test()
            .is_empty()
    );
    other
        .real
        .scene
        .coordinator
        .prepare_joint_births(
            &other_ingested,
            &other.producers,
            &mut retained,
            |_, _, _, _, _, _| panic!("foreign witness refusal cannot recreate the local New"),
        )
        .unwrap();

    let (stopped, _, _, _) = prepared_birth_originals(1, true, true);
    let claims = stopped
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .claims()
        .map(|(ordinal, result)| (ordinal, *result))
        .collect::<Vec<_>>();
    assert!(matches!(
        claims.as_slice(),
        [(1, Ok(_)), (2, Err(AttestationRefusal::Stopped))]
    ));
}

#[test]
fn joint_birth_first_refused_claim_blocks_later_same_key_original() {
    use crate::inventory_semantics::RetainedJointBirths;
    let (mut scene, ingested, attached, _) =
        prepared_birth_with_claim_predecessor(1, true, false, true);
    let coordinator = &mut scene.real.scene.coordinator;
    let claims = coordinator
        .prepared_semantic_batch()
        .unwrap()
        .claims()
        .map(|(at, result)| (at, *result))
        .collect::<Vec<_>>();
    assert!(matches!(
        claims.as_slice(),
        [(1, Err(AttestationRefusal::ClaimsExhausted)), (2, Ok(_))]
    ));
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        1
    );
    let roles = coordinator.joint_capture().ledger().roles_for_test();
    let mut births = RetainedJointBirths::new();
    let result = coordinator
        .prepare_joint_births(
            &ingested,
            &scene.producers,
            &mut births,
            |_, _, _, _, _, _| {
                panic!("a later successful sibling cannot consume the first original's New")
            },
        )
        .unwrap();
    assert_eq!(result.installed, 0);
    assert!(births.as_slice().is_empty());
    assert!(
        coordinator
            .registry()
            .pending_joint_receipts_for_test()
            .is_empty()
    );
    assert_eq!(
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .current_receipts()
            .iter()
            .filter(|receipt| receipt.birth.is_some())
            .count(),
        1
    );
    assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
    assert_eq!(
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .claims()
            .map(|(at, result)| (at, *result))
            .collect::<Vec<_>>(),
        claims
    );
    // A has no physical BEGIN/END. Preserve direct S1 and settle the held B
    // only through an actual later native fault, never a fabricated terminal.
    coordinator.dispose_prepared_claims_s1();
    while coordinator.stage_next_prepared_admission() {}
    assert!(coordinator.finish_prepared_semantic_batch(&scene.real.lane));
    coordinator
        .commit_batch_with_semantics(false, Some(&mut scene.real.lane))
        .unwrap();
    assert_eq!(coordinator.registry().joint_feeds(), 0);
    scene
        .real
        .h0
        .0
        .borrow()
        .io
        .script
        .fault_cell
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let fault = DisposedNativeFault(scene.real.h0.clone());
    let mut frame = coordinator
        .audit_ingested_quantum(ingested, &scene.producers, &attached, &fault)
        .unwrap_or_else(|(_, reason)| panic!("original disclosed fault: {reason:?}"));
    assert_eq!(
        frame.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::FaultChanged
    );
    let mut ports = coordinator.joint_frame_ports(&scene.producers).unwrap();
    frame.bind_targets(&ports).unwrap();
    frame
        .finish_frame(&mut ports)
        .unwrap_or_else(|(_, reason)| {
            panic!("actual negative finishes both originals: {reason:?}")
        });
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test()[..4],
        [0, 0, 0, 0]
    );
    scene.assert_claims(&[]);
}

#[test]
fn joint_birth_install_refuses_same_quantum_sibling_witness() {
    use crate::discovery::caller_registry::instance_input::JointReceiptInstallRefusal;
    use crate::inventory_semantics::RetainedJointBirths;
    let (mut scene, _ingested, attached, _) = prepared_birth_originals(1, true, false);
    let inputs = scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .cloned()
        .collect::<Vec<_>>();
    assert!(inputs[0].collected_origin() != inputs[1].collected_origin());
    let nested = scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .current_receipts()[0]
        .owned_storage_bytes()
        .unwrap();
    let reserve = scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_storage_reserver();
    let mut births = RetainedJointBirths::new();
    let slot = births
        .reserve_for(&reserve, nested)
        .unwrap_or_else(|_| panic!("actual witness allocation is paid before New moves"));
    let mut current = scene
        .real
        .scene
        .coordinator
        .take_prepared_current_for_birth_test()
        .unwrap();
    assert_eq!(current.len(), 1);
    let candidate = current
        .pop()
        .unwrap()
        .into_birth_candidate()
        .unwrap_or_else(|_| panic!("one actual collected New"));
    assert!(inputs.iter().all(|input| {
        input
            .collected_origin()
            .unwrap()
            .in_quantum(candidate.quantum)
    }));
    while scene.real.scene.coordinator.stage_next_prepared_admission() {}
    assert!(
        scene
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&scene.real.lane)
    );
    let before = scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    let publisher = NativePublisher::build();
    let (row, control, _) = publisher.publish_stamped(&["0", "0"], attached.generation());
    let mut rows = NativeBirthRows { row, control };
    let h3 = scene.real.scene.coordinator.reference_h3_audit_state();
    // Bind the actual existing namespace; this borrow neither takes H3 nor
    // constructs evidence. The final port then splits those exact producers.
    scene
        .real
        .scene
        .coordinator
        .session_h3_finalizer(&scene.producers)
        .unwrap();
    assert_eq!(scene.real.scene.coordinator.reference_h3_audit_state(), h3);
    let mut ports = scene
        .real
        .scene
        .coordinator
        .joint_frame_ports(&scene.producers)
        .unwrap();
    let (registry, owner, bindings, _, _) = ports.split();
    let token = registry
        .reserve_admitted_joint_receipt(&inputs[0])
        .unwrap_or_else(|reason| panic!("original reservation: {reason:?}"));
    let binding = bindings.get(inputs[1].journal_binding().3).unwrap();
    let proof = owner.adapter().invocation_claims_for_test().1[1].1;
    let witness = {
        let mut h0 = scene.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *h0;
        capture
            .validate_birth_candidate(io, &candidate, false)
            .unwrap();
        capture
            .finish_birth(
                candidate,
                None,
                &inputs[1],
                binding,
                &attached,
                &proof,
                owner.adapter(),
                &mut rows,
            )
            .unwrap()
    };
    let token = match token.install(&inputs[0], &witness) {
        Err((token, JointReceiptInstallRefusal::ReceiptMismatch)) => token,
        _ => {
            panic!("same-quantum same-key sibling witness must not authorize the reserved original")
        }
    };
    assert!(matches!(
        token.install(&inputs[1], &witness),
        Err((_, JointReceiptInstallRefusal::SubjectMismatch))
    ));
    assert!(registry.pending_joint_receipts_for_test().is_empty());
    assert_eq!(owner.ledger().roles_for_test(), before);
    slot.retain(witness);
}

struct DisposedMustNotReadBirth;
impl crate::semantics_objects::journal::joint_audit::JointBirthEvidenceSource
    for DisposedMustNotReadBirth
{
    fn take_for(
        &mut self,
        _: &crate::discovery::caller_registry::instance_input::JointFeedTarget,
        _: &SemanticCallerBinding,
    ) -> Result<
        crate::semantics_objects::journal::SessionBirthEvidence,
        crate::attach::BirthObservationRefusal,
    > {
        panic!("disposed provenance cannot enter a positive seal or native birth read")
    }
}

/// Read the same real native health cell that Capture::raise_fault changes.
struct DisposedNativeFault(SharedH0);
impl crate::semantics_objects::journal::FaultEpoch for DisposedNativeFault {
    fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
        let value = self
            .0
            .0
            .borrow()
            .io
            .script
            .fault_cell
            .load(std::sync::atomic::Ordering::SeqCst);
        if value > u64::from(u32::MAX) {
            Err(crate::semantics_objects::journal::FaultReadError::Saturated)
        } else {
            Ok(value)
        }
    }
}

fn finish_disposed_negative_frame(
    fixture: &mut CanonicalFanoutScene,
    frame: IngestedJointQuantum,
    fault: &impl crate::semantics_objects::journal::FaultEpoch,
) {
    finish_original_negative_frame(
        &mut fixture.scene.real.scene.coordinator,
        &fixture.scene.producers,
        frame,
        fault,
    );
}

fn finish_original_negative_frame<Source: crate::discovery::caller_registry::ProcessSource>(
    coordinator: &mut crate::discovery::engine::inventory_coordinator::InventoryCoordinator<Source>,
    producers: &SessionDrainProducers,
    mut frame: IngestedJointQuantum,
    fault: &impl crate::semantics_objects::journal::FaultEpoch,
) {
    let mut births = DisposedMustNotReadBirth;
    let mut ports = coordinator.joint_frame_ports(producers).unwrap();
    frame.bind_targets(&ports).unwrap();
    let mut finished = false;
    for _ in 0..256 {
        frame.seal_next(&mut ports, &mut births, fault).unwrap();
        assert!(frame.active_seal_for_test().is_none());
        let mut work = 1;
        if matches!(
            frame.deliver_next_bounded(&mut ports, &mut work).unwrap(),
            QuantumSealProgress::Complete | QuantumSealProgress::AwaitFutureInput
        ) {
            finished = true;
            break;
        }
    }
    assert!(
        finished,
        "a qualified negative-only frame must make finite progress"
    );
    frame
        .finish_frame(&mut ports)
        .unwrap_or_else(|(_, reason)| panic!("original negative consumers: {reason:?}"));
}

#[test]
fn joint_birth_full_registration_table_refuses_before_new() {
    use crate::inventory_semantics::RetainedJointBirths;
    // Two already-committed real incarnations leave no slot for C, even
    // though the pending grant table itself is empty.
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    fixture
        .scene
        .real
        .scene
        .coordinator
        .registry_mut()
        .reference_instance_limit(2);
    let child = OwnedStoppedChild::new();
    let pid = child.id();
    let caller = fixture.scene.real.bind(
        pid,
        ImageIdentity {
            task_cookie: 73,
            exec_id: 0,
        },
        0,
    );
    fixture.scene.push(pid, 0, "C_CreateObject", 1);
    let raw = fixture.scene.collect_with_fault(&BirthFault);
    fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = fixture.scene.real.tick();
    fixture.scene.admit_providers(pid, caller, &[0]);
    fixture.scene.prepare_batch(batch, 1);
    let raw = fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .collected
        .take()
        .unwrap();
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    let mut ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("same original C input: {reason:?}"));
    assert!(
        coordinator
            .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
            .unwrap()
            .unwrap()
            .1
            .is_ok()
    );
    assert!(
        coordinator
            .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
            .unwrap()
            .is_none()
    );
    let mut births = RetainedJointBirths::new();
    let result = coordinator
        .prepare_joint_births(
            &ingested,
            &fixture.scene.producers,
            &mut births,
            |_, _, _, _, _, _| {
                panic!("a full actual registration table must refuse before consuming New/native")
            },
        )
        .unwrap();
    assert_eq!(result.installed, 0);
    assert!(
        coordinator
            .registry()
            .pending_joint_receipts_for_test()
            .is_empty()
    );
    assert!(
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .current_receipts()
            .iter()
            .any(|receipt| receipt.image().task_cookie == 73 && receipt.birth.is_some())
    );
    while coordinator
        .stage_next_prepared_admission_with_disposition(&fixture.scene.producers, &mut ingested)
        .unwrap()
    {}
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    assert_eq!(coordinator.registry().joint_feeds(), 2);
    assert!(
        coordinator
            .registry()
            .pending_joint_receipts_for_test()
            .is_empty()
    );
    let mut frame = coordinator
        .audit_ingested_quantum(
            ingested,
            &fixture.scene.producers,
            &fixture.attached,
            &BirthFault,
        )
        .unwrap_or_else(|(_, reason)| {
            panic!("capacity negative remains with the original audit: {reason:?}")
        });
    {
        let ports = coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
    }
    fixture.finish_bounded_batch(frame, false);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .model()
            .project()
            .objects
            .iter()
            .filter(|object| object.lifetime == Lifetime::Live)
            .count(),
        2
    );
}

#[test]
fn joint_birth_queued_registrations_preserve_actual_first_slot() {
    use crate::inventory_semantics::RetainedJointBirths;
    // The actual queued registration order, rather than reverse New-removal
    // order or pending-grant count, controls the one remaining slot.
    let (mut scene, mut ingested, attached, _) = prepared_birth_originals(2, false, false);
    scene
        .real
        .scene
        .coordinator
        .registry_mut()
        .reference_instance_limit(1);
    let inputs = scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .cloned()
        .collect::<Vec<_>>();
    let h0 = scene.real.h0.clone();
    let publisher = NativePublisher::build();
    let mut births = RetainedJointBirths::new();
    let mut attempted = 0;
    let result = scene
        .real
        .scene
        .coordinator
        .prepare_joint_births(
            &ingested,
            &scene.producers,
            &mut births,
            |candidate, absence, input, binding, proof, adapter| {
                assert!(
                    input.collected_origin() == inputs[0].collected_origin(),
                    "an earlier queued S1 registration owns the last slot, never the later New"
                );
                attempted += 1;
                let (row, control, _) =
                    publisher.publish_stamped(&["0", "0"], attached.generation());
                let mut rows = NativeBirthRows { row, control };
                let mut owned = h0.0.borrow_mut();
                let HeldH0 { capture, io, .. } = &mut *owned;
                capture.validate_birth_candidate(io, &candidate, false)?;
                capture.finish_birth(
                    candidate, absence, input, binding, &attached, proof, adapter, &mut rows,
                )
            },
        )
        .unwrap();
    assert_eq!(result.installed, attempted);
    assert!(attempted <= 1);
    assert!(
        scene
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap()
            .current_receipts()
            .iter()
            .any(|receipt| receipt.endpoint().file_slot == 1 && receipt.birth.is_some()),
        "the later queued key keeps its original New on capacity refusal"
    );
    while scene
        .real
        .scene
        .coordinator
        .stage_next_prepared_admission_with_disposition(&scene.producers, &mut ingested)
        .unwrap()
    {}
    assert!(
        scene
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&scene.real.lane)
    );
    scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut scene.real.lane))
        .unwrap();
    assert!(
        scene
            .real
            .scene
            .coordinator
            .registry()
            .pending_joint_receipts_for_test()
            .is_empty(),
        "a refused actual registration cannot strand a grant"
    );
    assert_eq!(
        scene
            .real
            .scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .count(),
        1
    );
    let frame = scene
        .real
        .scene
        .coordinator
        .audit_ingested_quantum(ingested, &scene.producers, &attached, &BirthFault)
        .unwrap_or_else(|(_, reason)| panic!("queued capacity negative: {reason:?}"));
    finish_original_negative_frame(
        &mut scene.real.scene.coordinator,
        &scene.producers,
        frame,
        &BirthFault,
    );
    scene.assert_claims(&[]);
    assert_eq!(
        scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test()[..4],
        [0, 0, 0, 0]
    );
}

#[test]
fn joint_raw_disposition_precharges_following_audit_before_advance() {
    use crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING;
    use crate::semantics_objects::journal::joint_driver::{RawDisposeReason, RawDisposition};
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    fixture.scene.drain.source_mut().push_record(vec![0; 17]);
    let raw = fixture.scene.prepare(0);
    let identity = raw.h0_identity();
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    let before_model = coordinator.joint_capture().model().project();
    let roles = coordinator.joint_capture().ledger().roles_for_test();
    let h3 = coordinator.reference_h3_audit_state();
    let (objects, sessions) = coordinator
        .joint_capture()
        .model()
        .audit_loss_record_counts();
    let keys = fixture.births.len();
    assert_eq!(keys, 2);
    let effect_capacity = (objects + sessions + 2 * keys)
        .checked_mul(2)
        .unwrap()
        .max(4);
    // This intentionally covers the previous raw-only/one-negative envelope,
    // while excluding the following actual frame and its second original.
    let one_failure = keys * std::mem::size_of::<crate::semantics_objects::ObjectDomain>()
        + OWNED_ALLOCATION_PADDING
        + effect_capacity * std::mem::size_of::<ObjectEffect>()
        + OWNED_ALLOCATION_PADDING;
    let raw_only = std::mem::size_of::<RawDisposition>() + one_failure;
    let reserve = coordinator.registry().semantic_storage_reserver();
    let snapshot = coordinator.registry().semantic_resource_snapshot();
    let hold = reserve
        .reserve(snapshot.limit_bytes - snapshot.charged_bytes - raw_only)
        .unwrap();
    let (raw, reason) = raw
        .dispose_without_ingest(
            coordinator.joint_capture_mut(),
            &fixture.scene.producers,
            RawDisposeReason::NoAdmission,
        )
        .err()
        .expect(
            "raw-only storage must not advance before its complete future audit envelope is paid",
        );
    assert!(matches!(
        reason,
        RawQuantumRefusal::Resource(_) | RawQuantumRefusal::Capacity
    ));
    assert!(raw.h0_identity() == identity);
    assert_eq!(coordinator.joint_capture().model().project(), before_model);
    assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
    assert_eq!(coordinator.reference_h3_audit_state(), h3);
    drop(hold);
    let disposed = raw
        .dispose_without_ingest(
            coordinator.joint_capture_mut(),
            &fixture.scene.producers,
            RawDisposeReason::NoAdmission,
        )
        .unwrap_or_else(|(_, reason)| panic!("full initial allowance: {reason:?}"));
    assert!(!disposed.failure().unwrap().effects.effects.is_empty());
    coordinator.dispose_prepared_claims_s1();
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    let snapshot = coordinator.registry().semantic_resource_snapshot();
    let hold = reserve
        .reserve(snapshot.limit_bytes - snapshot.charged_bytes)
        .unwrap();
    let fault = DisposedNativeFault(fixture.scene.real.h0.clone());
    let frame = coordinator
        .audit_disposed_quantum(
            disposed,
            &fixture.scene.producers,
            &fixture.attached,
            &fault,
        )
        .unwrap_or_else(|(_, reason)| {
            panic!("unchanged model uses the SAME already-paid audit allowance: {reason:?}")
        });
    assert_eq!(coordinator.reference_h3_audit_state(), (h3.0 + 1, false));
    drop(hold);
    finish_disposed_negative_frame(&mut fixture, frame, &fault);
}

#[test]
fn joint_raw_disposition_audits_original_failures_once() {
    use crate::semantics_objects::journal::joint_driver::RawDisposeReason;
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let fault = DisposedNativeFault(fixture.scene.real.h0.clone());
    let domains = fixture
        .receipts()
        .into_iter()
        .map(|receipt| receipt.domain())
        .collect::<Vec<_>>();
    fixture.scene.drain.source_mut().push_record(vec![0; 17]);
    let raw = fixture.scene.prepare(0);
    let identity = raw.h0_identity();
    let before_roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    let before_model = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    assert_eq!(
        before_model
            .objects
            .iter()
            .filter(|object| object.lifetime == Lifetime::Live)
            .count(),
        2
    );
    let before_h3 = fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_h3_audit_state();
    let snapshot = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let hold = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes)
        .unwrap();
    let (raw, reason) = raw
        .dispose_without_ingest(
            fixture.scene.real.scene.coordinator.joint_capture_mut(),
            &fixture.scene.producers,
            RawDisposeReason::NoAdmission,
        )
        .err()
        .expect("failure storage must be paid before the original model/key/frontier changes");
    assert!(matches!(
        reason,
        RawQuantumRefusal::Resource(_) | RawQuantumRefusal::Capacity
    ));
    assert!(raw.h0_identity() == identity);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        before_roles
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .model()
            .project(),
        before_model
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        before_h3
    );
    drop(hold);
    let disposed = raw
        .dispose_without_ingest(
            fixture.scene.real.scene.coordinator.joint_capture_mut(),
            &fixture.scene.producers,
            RawDisposeReason::NoAdmission,
        )
        .unwrap_or_else(|(_, reason)| panic!("paid original raw negative: {reason:?}"));
    let failure = disposed
        .failure()
        .expect("malformed original has an affecting loss");
    assert!(!failure.effects.effects.is_empty());
    for domain in domains {
        assert!(failure.affects_domain(domain));
    }
    let original_span = failure.effects.effects.as_ptr();
    let original_len = failure.effects.effects.len();
    let original_gap = failure.gap;
    fixture
        .scene
        .real
        .scene
        .coordinator
        .dispose_prepared_claims_s1();
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&fixture.scene.real.lane)
    );
    let foreign = crate::attach::SessionDrainProducers::test_pair(
        fixture.scene.real.lane.domain(),
        EventsDomain::test_standin(fixture.scene.producers.events_id()),
    );
    let (disposed, reason) = fixture
        .scene
        .real
        .scene
        .coordinator
        .audit_disposed_quantum(disposed, &foreign, &fixture.attached, &fault)
        .err()
        .expect("equal IDs do not own the original disposed allocation");
    assert_eq!(reason, RawQuantumRefusal::ForeignCapture);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state()
            .0,
        before_h3.0
    );
    let frame = fixture
        .scene
        .real
        .scene
        .coordinator
        .audit_disposed_quantum(
            disposed,
            &fixture.scene.producers,
            &fixture.attached,
            &fault,
        )
        .unwrap_or_else(|(_, reason)| panic!("same-owner disposed audit: {reason:?}"));
    let carried = frame
        .original_failures_for_test()
        .find(|failure| failure.effects.effects.as_ptr() == original_span)
        .expect("the original buffer is transferred, not regenerated");
    assert_eq!(
        (carried.gap, carried.effects.effects.len()),
        (original_gap, original_len)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (before_h3.0 + 1, false)
    );
    finish_disposed_negative_frame(&mut fixture, frame, &fault);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .model()
            .project()
            .objects
            .iter()
            .filter(|object| object.lifetime == Lifetime::Live)
            .count(),
        0
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state()
            .0,
        before_h3.0 + 1
    );

    // Marked original S1Only subjects belong to the ingested two-original
    // union. A later raw owner cannot silently consume them as a third cause.
    let (mut marked, mut ingested, _, _) = prepared_birth_originals(1, false, false);
    while marked
        .real
        .scene
        .coordinator
        .stage_next_prepared_admission_with_disposition(&marked.producers, &mut ingested)
        .unwrap()
    {}
    assert!(
        marked
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&marked.real.lane)
    );
    let starts = marked
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .retained_starts_for_test();
    let roles = marked
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    let h3 = marked.real.scene.coordinator.reference_h3_audit_state();
    let mut raw = marked.collect_with_fault(&BirthFault);
    {
        let mut owned = marked.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *owned;
        capture.tick_collected_with(io, &mut raw).unwrap();
    }
    let (_, reason) = raw
        .dispose_without_ingest(
            marked.real.scene.coordinator.joint_capture_mut(),
            &marked.producers,
            RawDisposeReason::Empty,
        )
        .err()
        .expect("the ingested subject owner must remain untouched");
    assert_eq!(reason, RawQuantumRefusal::DispositionMismatch);
    assert_eq!(
        marked
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        starts
    );
    assert_eq!(
        marked
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        roles
    );
    assert_eq!(marked.real.scene.coordinator.reference_h3_audit_state(), h3);
}

#[test]
fn joint_raw_disposition_quiet_and_pending_paths_are_finite() {
    use crate::semantics_objects::journal::joint_driver::RawDisposeReason;
    // No previous admitted call exists: the actual negative finalizer must
    // take this genuine H3 without manufacturing seal_admission or genesis.
    let mut empty = JointScene::for_audit(1);
    let raw = empty.prepare(0);
    let identity = raw.h0_identity();
    let disposed = raw
        .dispose_without_ingest(
            empty.real.scene.coordinator.joint_capture_mut(),
            &empty.producers,
            RawDisposeReason::Empty,
        )
        .unwrap_or_else(|(_, reason)| panic!("first actual empty raw: {reason:?}"));
    assert!(disposed.failure().is_none());
    empty.real.scene.coordinator.dispose_prepared_claims_s1();
    assert!(
        empty
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&empty.real.lane)
    );
    let attached = attachment(&mut empty);
    let mut frame = empty
        .real
        .scene
        .coordinator
        .audit_disposed_quantum(disposed, &empty.producers, &attached, &BirthFault)
        .unwrap_or_else(|(_, reason)| panic!("negative H3 needs no admission: {reason:?}"));
    let mut ports = empty
        .real
        .scene
        .coordinator
        .joint_frame_ports(&empty.producers)
        .unwrap();
    frame.bind_targets(&ports).unwrap();
    let done = frame
        .finish_frame(&mut ports)
        .unwrap_or_else(|(_, reason)| panic!("zero-head original: {reason:?}"));
    assert!(done.identity() == identity);
    assert_eq!(
        empty.real.scene.coordinator.reference_h3_audit_state(),
        (1, false)
    );

    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let pid = std::process::id();
    let (begin, end) = fixture.scene.encoded(pid, 0, "C_SignInit", 2);
    fixture.scene.drain.source_mut().push_record(begin.to_vec());
    let q1 = fixture.audited(0, 0, &BirthFault);
    let mut q1 = Some(q1);
    {
        let h0 = fixture.scene.real.h0.clone();
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &fixture.attached,
            retained: &mut fixture.births,
            seen: Vec::new(),
            unreadable: false,
        };
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q1.as_mut().unwrap().bind_targets(&ports).unwrap();
        let mut future = false;
        for _ in 0..16 {
            let held = q1.as_mut().unwrap();
            held.seal_next(&mut ports, &mut births, &BirthFault)
                .unwrap();
            let mut work = 1;
            if held.deliver_next_bounded(&mut ports, &mut work).unwrap()
                == QuantumSealProgress::AwaitFutureInput
            {
                future = true;
                break;
            }
        }
        assert!(
            future,
            "the actual unreturned BEGIN needs genuine future input"
        );
        q1.take()
            .unwrap()
            .finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| panic!("genuine waiting H8 BEGIN: {reason:?}"));
    }
    let starts = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .retained_starts_for_test();
    let roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    assert_eq!(starts.len(), 1);
    let raw = fixture.scene.prepare(0);
    let disposed = raw
        .dispose_without_ingest(
            fixture.scene.real.scene.coordinator.joint_capture_mut(),
            &fixture.scene.producers,
            RawDisposeReason::Empty,
        )
        .unwrap_or_else(|(_, reason)| panic!("same-owner quiet raw: {reason:?}"));
    fixture
        .scene
        .real
        .scene
        .coordinator
        .dispose_prepared_claims_s1();
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&fixture.scene.real.lane)
    );
    let frame = fixture
        .scene
        .real
        .scene
        .coordinator
        .audit_disposed_quantum(
            disposed,
            &fixture.scene.producers,
            &fixture.attached,
            &BirthFault,
        )
        .unwrap_or_else(|(_, reason)| panic!("genuine future-only disposed frame: {reason:?}"));
    assert!(frame.failure_for_test().is_none());
    finish_disposed_negative_frame(&mut fixture, frame, &BirthFault);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        starts
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        roles
    );
    fixture.scene.drain.source_mut().push_record(end.to_vec());
    let mut q3 = fixture.audited(1, 1, &BirthFault);
    {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q3.bind_targets(&ports).unwrap();
    }
    fixture.finish_bounded_batch(q3, false);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test()[..4],
        [0, 0, 0, 0]
    );

    // A real pending floor does not excuse a different original COMPLETE.
    // Try the new negative handoff while the original H3 is still untaken.
    let _unmatched =
        pending_h3_with_sibling_before_audit(true, false, &BirthFault, |fixture, _| {
            let owner = fixture.scene.real.scene.coordinator.joint_capture();
            let starts = owner.adapter().retained_starts_for_test();
            let claims = owner.adapter().invocation_claims_for_test();
            let roles = owner.ledger().roles_for_test();
            let h3 = fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_audit_state();
            assert_eq!(starts.len(), 4);
            assert_eq!(claims.0, 1);
            assert_eq!(roles[..4], [0, 4, 0, 1]);
            assert!(h3.1);
            let mut raw = fixture.scene.collect_with_fault(&BirthFault);
            {
                let mut owned = fixture.scene.real.h0.0.borrow_mut();
                let HeldH0 { capture, io, .. } = &mut *owned;
                capture.tick_collected_with(io, &mut raw).unwrap();
            }
            let disposed = raw
                .dispose_without_ingest(
                    fixture.scene.real.scene.coordinator.joint_capture_mut(),
                    &fixture.scene.producers,
                    RawDisposeReason::Empty,
                )
                .unwrap_or_else(|(_, reason)| panic!("genuine empty collection: {reason:?}"));
            let (_, reason) = fixture
                .scene
                .real
                .scene
                .coordinator
                .audit_disposed_quantum(
                    disposed,
                    &fixture.scene.producers,
                    &fixture.attached,
                    &BirthFault,
                )
                .err()
                .expect("unmatched original COMPLETE must refuse before taking pending H3");
            assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
            let owner = fixture.scene.real.scene.coordinator.joint_capture();
            assert_eq!(owner.adapter().retained_starts_for_test(), starts);
            assert_eq!(owner.adapter().invocation_claims_for_test(), claims);
            assert_eq!(owner.ledger().roles_for_test(), roles);
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .reference_h3_audit_state(),
                h3
            );
        });
}

#[test]
fn joint_raw_disposition_reaches_retained_s1only_history() {
    use crate::semantics_key_use::SealFailureDisposition;
    use crate::semantics_objects::journal::joint_driver::RawDisposeReason;
    use crate::semantics_objects::journal::{H3DispositionEvidence, JournalGap};
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    fixture.push_two("C_SignInit", 2);
    let mut frame = fixture.audited(2, 2, &BirthFault);
    let (first, pid) = fixture.replay_target();
    {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
    }
    fixture.seal_selected_for_batch(&mut frame, true);
    for _ in 0..32 {
        fixture.deliver_one_work(&mut frame);
        if fixture
            .feeds()
            .iter()
            .find(|feed| feed.id == first.id())
            .unwrap()
            .fallback
        {
            break;
        }
    }
    assert_eq!(fixture.s1_counts(first.id()), (2, 1, 0, 0, 1));
    fixture.finish_bounded_batch(frame, false);
    let fault = FrameFault::clean();
    for sequence in [3, 4, 5] {
        let original_s1 = fixture.s1_counts(first.id());
        assert_eq!(original_s1.4, usize::from(sequence < 5));
        if sequence >= 4 {
            assert!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .adapter()
                    .proof_refused_for_test(first.bootstrap().proof())
            );
        }
        let calls = if sequence == 5 {
            // A fresh actual loss with no new S1 operation cannot count the
            // already-ended call again. Keep collection/fresh fault reads at
            // the same epoch installed by the previous real loss.
            fixture.scene.drain.source_mut().push_record(vec![0; 17]);
            0
        } else {
            let (_, end) = fixture.scene.encoded(pid, 0, "C_SignUpdate", sequence);
            let mut ordinary = end[24..392].to_vec();
            ordinary[108..112].copy_from_slice(&u32::MAX.to_le_bytes());
            fixture.scene.drain.source_mut().push_record(ordinary);
            1
        };
        let raw = fixture.scene.prepare_with_fault(calls, &fault);
        let disposed = raw
            .dispose_without_ingest(
                fixture.scene.real.scene.coordinator.joint_capture_mut(),
                &fixture.scene.producers,
                RawDisposeReason::NoAdmission,
            )
            .unwrap_or_else(|(_, reason)| panic!("localized original affecting raw: {reason:?}"));
        assert!(
            disposed
                .failure()
                .unwrap()
                .affects_domain(first.bootstrap().domain()),
            "localized scope must retain the already-refused S1Only incarnation"
        );
        fixture
            .scene
            .real
            .scene
            .coordinator
            .dispose_prepared_claims_s1();
        while fixture
            .scene
            .real
            .scene
            .coordinator
            .stage_next_prepared_admission()
        {}
        assert!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .finish_prepared_semantic_batch(&fixture.scene.real.lane)
        );
        fixture
            .scene
            .real
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
            .unwrap();
        let before = fixture.s1_counts(first.id());
        assert_eq!(
            (before.3, before.4),
            (original_s1.3, original_s1.4),
            "sequence {sequence}: ordinary publication must preserve the original S1 operation"
        );
        if sequence == 4 {
            fault.epoch.set(1); // Actual later read, after this original collection.
        }
        let frame = fixture
            .scene
            .real
            .scene
            .coordinator
            .audit_disposed_quantum(
                disposed,
                &fixture.scene.producers,
                &fixture.attached,
                &fault,
            )
            .unwrap_or_else(|(_, reason)| {
                panic!("original raw plus actual later fault: {reason:?}")
            });
        let audited = frame
            .audited_failure_for_test(first.bootstrap().domain())
            .expect("the original negative binds this retained S1Only history");
        if sequence == 3 {
            assert_eq!(audited.failure().gap, JournalGap::ImageTainted);
            assert_eq!(audited.disposition(), SealFailureDisposition::Fallback);
            assert!(matches!(
                audited.h3(),
                H3DispositionEvidence::Clean {
                    pending_floor: None,
                    ..
                }
            ));
        } else {
            assert_eq!(audited.disposition(), SealFailureDisposition::HistoryLoss);
            if sequence == 4 {
                assert!(
                    frame
                        .original_failures_for_test()
                        .any(|failure| failure.gap == JournalGap::FaultChanged)
                );
            }
        }
        finish_disposed_negative_frame(&mut fixture, frame, &fault);
        let after = fixture.s1_counts(first.id());
        assert_eq!(
            after.3,
            before.3 + u64::from(sequence == 4),
            "sequence {sequence}: only actual history loss ends the original S1 call, once"
        );
        assert_eq!(
            after.4,
            if sequence == 3 { before.4 } else { 0 },
            "proof-only refusal preserves active S1; actual loss ends it"
        );
    }
}

/// A payload-only envelope must fail against the actual std HashMap requests,
/// including every resize and the bucket allocation retained after removal.
#[test]
fn joint_grant_table_envelope_covers_actual_capacity_transitions() {
    let (fixture, _frame) = CanonicalFanoutScene::first_publication_with_functions(
        1,
        &["C_CreateObject", "C_SignInit"],
        PublicationReceipts::All,
    );
    crate::discovery::caller_registry::instance_input::joint_grant_allocation_probe_for_test(
        *fixture.births[0].1.receipt(),
    );
}

/// The complete first-table charge must refuse before the actual original New
/// is moved, even when the pool could cover the visible-entry payload alone.
#[test]
fn joint_grant_allocation_refuses_before_original_new_moves() {
    let mut scene = JointScene::for_audit(1);
    scene.real.h0.0.borrow_mut().io.script.local = 1;
    let pid = std::process::id();
    let image = ImageIdentity {
        task_cookie: 71,
        exec_id: 0,
    };
    let caller = scene.real.bind(pid, image, 0);
    scene.push(pid, 0, "C_SignInit", 1);
    let raw = scene.collect_with_fault(&BirthFault);
    let quantum = raw.h0_identity();
    scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = scene.real.tick();
    scene.admit_providers(pid, caller, &[0]);
    scene.prepare_batch(batch, 1);
    let input = scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .next()
        .unwrap()
        .clone();
    let original_origin = input.collected_origin();
    assert!(
        original_origin.is_some(),
        "the admission retains its actual collected allocation"
    );
    let mut current = scene
        .real
        .scene
        .coordinator
        .take_prepared_current_for_birth_test()
        .unwrap();
    assert_eq!(current.len(), 1);
    let current = current.pop().unwrap();
    let original_pin = Arc::clone(current.original_pin());
    let registry = scene.real.scene.coordinator.registry();
    let (payload_only, complete) = registry
        .joint_grant_initial_allocation_for_test(&input)
        .unwrap();
    assert!(complete > payload_only);
    let baseline = registry.semantic_resource_snapshot();
    let original_roles = scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    let original_claims = scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    for allowance in [payload_only, complete - 1, complete] {
        let hold = registry
            .reserve_semantic_storage(baseline.limit_bytes - baseline.charged_bytes - allowance)
            .unwrap();
        let (reserved, allocations, bytes) =
            crate::test_alloc::count_allocs_during(|| registry.reserve_semantic_storage(complete));
        assert_eq!((allocations, bytes), (0, 0));
        assert_eq!(reserved.is_ok(), allowance == complete);
        drop(reserved);
        drop(hold);
        assert_eq!(
            registry.semantic_resource_snapshot().charged_bytes,
            baseline.charged_bytes
        );
        assert!(input.collected_origin() == original_origin);
        assert_eq!(
            scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test(),
            original_roles
        );
        assert_eq!(
            scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            original_claims
        );
        assert!(
            scene
                .real
                .h0
                .0
                .borrow()
                .collected
                .as_ref()
                .unwrap()
                .h0_identity()
                == quantum
        );
        assert_eq!(registry.joint_feeds(), 0);
    }
    let candidate = current
        .into_birth_candidate()
        .unwrap_or_else(|_| panic!("precharge refusal must preserve the actual collected New"));
    assert!(candidate.quantum == quantum);
    assert_eq!(candidate.receipt.image(), image);
    assert!(Arc::ptr_eq(candidate.receipt.original_pin(), &original_pin));
}

/// The real binder must not spend New before the same collected H0 can carry
/// its birth. Only the native I/O is substituted; no semantic binding exists
/// before this production refresh/admission path runs.
#[test]
fn joint_real_bind_refresh_preserves_collected_first_new() {
    for (tick_first, refuse_first) in [(true, false), (true, true), (false, false), (false, true)] {
        let (held, attached) = HeldProviders::with_attachment(1, &["C_CreateObject", "C_SignInit"]);
        let mut scene = JointScene::from_held(held, Some(attached));
        // Bind a genuinely different ledger to this same actual producer
        // allocation while its cursor is still initial. It cannot refresh a
        // later raw collected through the canonical owner.
        let mut foreign_adapter =
            JournalAdapter::new(crate::semantics_objects::journal::JournalLimits::policy());
        let reserve = scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_storage_reserver();
        let foreign_raw = RawJointQuantum::collect_bounded_with_adapter(
            &mut scene.drain,
            &publish_object_descriptors(),
            64,
            None,
            &BirthFault,
            &scene.producers,
            |bytes| reserve.reserve(bytes),
            &mut foreign_adapter,
        )
        .unwrap();
        drop(foreign_raw);
        let pid = std::process::id();
        let image = ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        };
        SIGHT_NS.with(|clock| clock.set(1_005));
        scene.real.h0.0.borrow_mut().io.script.local = 1;
        let caller = scene.real.scene.admit(pid, 50);
        let (module, path) = &scene.real.modules[0];
        scene.real.scene.coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: path.clone(),
                key: module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("held-provider".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(2),
                admission_reasons: Vec::new(),
            },
            60,
        );
        scene.real.scene.coordinator.commit_batch(false).unwrap();
        let candidate = scene
            .real
            .scene
            .coordinator
            .prepare_legacy_semantic_candidate(caller, scene.real.lane.domain())
            .expect("the actual Detailed caller retains its first custody allocation");
        let original_pin = candidate.pin();
        drop(candidate);
        scene
            .real
            .h0
            .0
            .borrow_mut()
            .io
            .targets
            .insert(pid, (original_pin.clone(), image));
        assert_eq!(scene.real.scene.coordinator.semantic_bindings().len(), 0);
        scene.push(pid, 0, "C_CreateObject", 1);
        let raw = scene.collect_with_fault(&BirthFault);
        let original_quantum = raw.h0_identity();
        assert_eq!(raw.pending_h0_records(), 1);
        let original_boundary = scene.drain.consumption_cut().unwrap();
        scene.real.h0.0.borrow_mut().collected = Some(raw);
        let early_batch = tick_first.then(|| scene.real.tick());
        let retained_records = scene
            .real
            .h0
            .0
            .borrow()
            .collected
            .as_ref()
            .unwrap()
            .pending_h0_records();
        let roles = scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test();
        let hold = refuse_first.then(|| {
            let registry = scene.real.scene.coordinator.registry();
            let snapshot = registry.semantic_resource_snapshot();
            registry
                .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes)
                .unwrap()
        });
        let mut raw = scene.real.h0.0.borrow_mut().collected.take().unwrap();
        assert_eq!(
            raw.validate_refresh(&foreign_adapter, &scene.producers),
            Err(RawQuantumRefusal::ForeignLedger),
            "equal producer allocation cannot replace the original ledger"
        );
        let foreign_producers = crate::attach::SessionDrainProducers::test_pair(
            scene.real.lane.domain(),
            EventsDomain::test_standin(scene.producers.events_id()),
        );
        assert_eq!(
            crate::inventory::bind_semantic_callers_for_test(
                &mut scene.real.scene.coordinator,
                &mut scene.real.lane,
                &mut raw,
                &foreign_producers,
            ),
            Err(RawQuantumRefusal::ForeignCapture),
            "equal native/map IDs cannot start a foreign refresh"
        );
        assert!(scene.real.h0.0.borrow().last_refresh_observation.is_none());
        assert_eq!(scene.real.scene.coordinator.semantic_bindings().len(), 0);
        crate::inventory::bind_semantic_callers_for_test(
            &mut scene.real.scene.coordinator,
            &mut scene.real.lane,
            &mut raw,
            &scene.producers,
        )
        .expect("the binder borrows the same original collected prefix");
        {
            let mut owned = scene.real.h0.0.borrow_mut();
            let slot = owned.io.slot(0, "C_SignInit");
            let before = (
                owned.io.script.now,
                owned.io.script.health.len(),
                owned.io.script.raises,
                owned.capture.next_token,
                raw.pending_h0_records(),
            );
            let mut foreign_capture =
                SemanticCapture::in_domain(scene.real.lane.domain(), TickLimits::default())
                    .unwrap();
            assert!(
                foreign_capture
                    .refresh_collected_with(
                        &mut owned.io,
                        original_pin.clone(),
                        slot,
                        &mut raw,
                        scene.real.scene.coordinator.joint_capture().adapter(),
                        &scene.producers,
                    )
                    .is_err()
            );
            assert_eq!(
                (
                    owned.io.script.now,
                    owned.io.script.health.len(),
                    owned.io.script.raises,
                    owned.capture.next_token,
                    raw.pending_h0_records(),
                ),
                before,
                "another Capture in the same native domain refuses before any audit or scan"
            );
        }
        scene.real.h0.0.borrow_mut().collected = Some(raw);
        {
            let owned = scene.real.h0.0.borrow();
            assert_eq!(
                owned.last_refresh_observation,
                Some(if tick_first {
                    ObserveOutcome::Continued
                } else {
                    ObserveOutcome::New
                }),
                "real refresh observation: tick_first={tick_first}, refuse_first={refuse_first}"
            );
            let raw = owned.collected.as_ref().unwrap();
            assert!(raw.h0_identity() == original_quantum);
            assert_eq!(raw.pending_h0_records(), retained_records);
        }
        assert_eq!(
            scene.real.scene.coordinator.semantic_bindings().len(),
            usize::from(!refuse_first),
            "the storage refusal exercises the actual admission consumer"
        );
        if refuse_first {
            // Refusal diagnostics are still staged at this boundary; the
            // published gaps cannot describe this uncommitted attempt yet.
            let snapshot = scene
                .real
                .scene
                .coordinator
                .registry()
                .semantic_resource_snapshot();
            assert_eq!(snapshot.charged_bytes, snapshot.limit_bytes);
        }
        drop(hold);
        // The newest matching receipt on retry is Continued. It may support
        // admission, but cannot replace or recreate the original New.
        let mut raw = scene.real.h0.0.borrow_mut().collected.take().unwrap();
        crate::inventory::bind_semantic_callers_for_test(
            &mut scene.real.scene.coordinator,
            &mut scene.real.lane,
            &mut raw,
            &scene.producers,
        )
        .expect("the retry retains that same original collected prefix");
        scene.real.h0.0.borrow_mut().collected = Some(raw);
        {
            let owned = scene.real.h0.0.borrow();
            assert_eq!(
                owned.last_refresh_observation,
                Some(ObserveOutcome::Continued)
            );
            assert!(owned.last_refresh_birth.is_none());
            let raw = owned.collected.as_ref().unwrap();
            assert!(raw.h0_identity() == original_quantum);
            assert_eq!(raw.pending_h0_records(), retained_records);
        }
        assert!(
            scene
                .drain
                .consumption_cut()
                .unwrap()
                .same_boundary(&original_boundary),
            "refresh/retry must not poll or replace the collected cursor"
        );
        assert_eq!(
            scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test(),
            roles,
            "refresh must not acknowledge or release any original raw role"
        );
        let binding = scene
            .real
            .scene
            .coordinator
            .semantic_bindings()
            .get(caller)
            .expect("the retry admits through the original current receipt");
        assert!(Arc::ptr_eq(&binding.pin(), &original_pin));
        let endpoint = scene.real.h0.0.borrow().io.endpoint(0).unwrap();
        assert!(binding.provider_for_endpoint(endpoint).is_some());
        let batch = early_batch.unwrap_or_else(|| scene.real.tick());
        scene.prepare_batch(batch, 1);
        let current = scene
            .real
            .scene
            .coordinator
            .take_prepared_current_for_birth_test()
            .unwrap();
        let births = current
            .into_iter()
            .filter_map(|receipt| receipt.into_birth_candidate().ok())
            .collect::<Vec<_>>();
        assert_eq!(
            births.len(),
            1,
            "same original New must survive real bind/refresh/retry, stash merge and prepared move: tick_first={tick_first}, refuse_first={refuse_first}"
        );
        assert!(births[0].quantum == original_quantum);
        assert!(Arc::ptr_eq(births[0].receipt.original_pin(), &original_pin));
        assert_eq!(births[0].receipt.image(), image);
    }
}

#[test]
fn joint_collected_refresh_rejects_stale_or_stopped_owner() {
    fn assert_refused(
        scene: &mut JointScene,
        raw: &mut RawJointQuantum,
        reason: RawQuantumRefusal,
    ) {
        let before = {
            let owned = scene.real.h0.0.borrow();
            (
                owned.capture.next_token,
                owned.io.script.now,
                owned.io.script.health.len(),
                owned.io.script.raises,
                owned.last_refresh_observation.clone(),
                raw.pending_h0_records(),
            )
        };
        let roles = scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test();
        scene.assert_claims(&[]);
        assert_eq!(
            crate::inventory::bind_semantic_callers_for_test(
                &mut scene.real.scene.coordinator,
                &mut scene.real.lane,
                raw,
                &scene.producers,
            ),
            Err(reason)
        );
        let owned = scene.real.h0.0.borrow();
        assert_eq!(
            (
                owned.capture.next_token,
                owned.io.script.now,
                owned.io.script.health.len(),
                owned.io.script.raises,
                owned.last_refresh_observation.clone(),
                raw.pending_h0_records(),
            ),
            before,
            "refusal precedes any refresh audit, scan or raw delivery"
        );
        assert_eq!(
            scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test(),
            roles
        );
        scene.assert_claims(&[]);
    }

    let mut scene = JointScene::for_audit(1);
    let pid = std::process::id();
    scene.bind(pid, image(71), &[0]);
    // Retain an actual earlier empty Raw, then advance its SAME owner's
    // frontier by ingesting the actual later completed call. No cut is reset.
    let mut stale = scene.collect_with_fault(&BirthFault);
    let original = stale.h0_identity();
    stale
        .validate_refresh(
            scene.real.scene.coordinator.joint_capture().adapter(),
            &scene.producers,
        )
        .unwrap();
    scene.push(pid, 0, "C_SignInit", 1);
    let raw = scene.prepare(1);
    let (_ingested, _) = scene.ingest(raw);
    assert_refused(&mut scene, &mut stale, RawQuantumRefusal::StaleFrontier);
    {
        let (adapter, model) = scene.real.scene.coordinator.joint_capture_mut().parts();
        let _ = adapter.stop(model);
    }
    assert_refused(&mut scene, &mut stale, RawQuantumRefusal::Stopped);
    assert!(stale.h0_identity() == original);
}

impl CanonicalFanoutScene {
    fn publication_step(
        &mut self,
        frame: &mut Option<IngestedJointQuantum>,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
        remaining: &mut usize,
    ) -> anyhow::Result<Option<crate::discovery::engine::inventory_coordinator::BatchReceipt>> {
        use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
        let h0 = self.scene.real.h0.clone();
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &self.attached,
            retained: &mut self.births,
            seen: Vec::new(),
            unreadable: false,
        };
        let progress = self.scene.real.scene.coordinator.commit_joint_batch(
            &mut self.scene.real.lane,
            &self.scene.producers,
            frame,
            &mut births,
            fault,
            remaining,
        )?;
        Ok(match progress {
            JointCommitProgress::Pending => None,
            JointCommitProgress::Published(receipt) => Some(receipt),
        })
    }

    fn assert_publication_hidden(&self, old_revision: u64) {
        use crate::inventory_present::Presentation;
        let coordinator = &self.scene.real.scene.coordinator;
        assert!(coordinator.publication_pending());
        assert_eq!(coordinator.registry().published_revision(), old_revision);
        assert!(Presentation::try_capture(coordinator, "system", 1, 2, 1).is_err());
        assert!(Presentation::try_capture_dashboard(coordinator, "system", 1, 2, 1, 2, 1).is_err());
        // Legacy entrypoints share the pre-read guard while the ordinary
        // lane remains inactive. They cannot construct a partial snapshot.
        for dashboard in [false, true] {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if dashboard {
                        Presentation::capture_dashboard(coordinator, "system", 1, 2, 1, 2, 1)
                    } else {
                        Presentation::capture(coordinator, "system", 1, 2, 1)
                    }
                }))
                .is_err()
            );
        }
    }

    fn complete_publication(
        &mut self,
        frame: &mut Option<IngestedJointQuantum>,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
        old_revision: u64,
    ) -> crate::discovery::engine::inventory_coordinator::BatchReceipt {
        // Every slice shares one unit across all actual feeds/effects. The
        // fixture has <128 transitions, so this also detects stranded heads.
        for _ in 0..256 {
            let mut remaining = 1;
            if let Some(receipt) = self
                .publication_step(frame, fault, &mut remaining)
                .expect("same original publication remains runnable")
            {
                assert!(frame.is_none(), "only actual disposal consumes the frame");
                assert!(!self.scene.real.scene.coordinator.publication_pending());
                assert_eq!(receipt.registry_published, old_revision + 1);
                return receipt;
            }
            self.assert_publication_hidden(old_revision);
        }
        panic!("same original publication must reach its real finished boundary")
    }
}

/// Catches registration selecting permanent S1Only before a genuine receipt
/// arrives, publishing an empty first head, or exposing an applied partial view.
#[test]
fn joint_first_real_birth_publishes_one_revision() {
    use crate::inventory_present::Presentation;
    for (policy, joint) in [
        (PublicationReceipts::All, 2),
        (PublicationReceipts::Missing, 0),
        (PublicationReceipts::Capacity(1), 1),
    ] {
        let (mut fixture, original) = CanonicalFanoutScene::first_publication_with_functions(
            1,
            &["C_CreateObject", "C_SignInit"],
            policy,
        );
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(coordinator.registry().joint_feeds(), 0);
        let old_revision = coordinator.registry().published_revision();
        let old_text = format!("{:?}", fixture.published_before);
        assert!(fixture.published_before.instances.is_empty());
        let claims = coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test();
        assert_eq!(
            claims.0, joint,
            "selected originals stay claimed; actual S1Only negatives already dispose their own"
        );
        let mut frame = Some(original);
        let receipt = fixture.complete_publication(&mut frame, &BirthFault, old_revision);
        assert!(receipt.registry_applied > 0);
        assert_eq!(format!("{:?}", fixture.published_before), old_text);
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(coordinator.registry().joint_feeds(), joint);
        let feeds = fixture.feeds();
        assert_eq!(feeds.len(), 2, "denied receipt does not drop an admission");
        assert_eq!(
            feeds.iter().map(|feed| feed.reduced).sum::<u64>(),
            joint as u64
        );
        assert!(feeds.iter().all(|feed| feed.staged == 0));
        for feed in feeds {
            assert_eq!(fixture.s1_counts(feed.id), (1, 0, 0, 0, 0));
        }
        let published = Presentation::try_capture(coordinator, "system", 1, 3, 1).unwrap();
        assert_eq!(published.instances.len(), 2);
        assert_eq!(published.semantic_edges.len(), 2);
        assert!(
            published
                .semantic_edges
                .iter()
                .all(|edge| edge.api_returns == Some(1))
        );
        assert_eq!(coordinator.reference_h3_audit_state(), (1, false));
        fixture.scene.assert_claims(&[]);
        assert_eq!(
            coordinator.joint_capture().ledger().roles_for_test()[..4],
            [0, 0, 0, 0]
        );
    }
}

/// A real physical tail must join the one original H3/audit before any
/// claim/stage decision. A new tail minted at commit cannot replace it later.
#[test]
fn joint_physical_tail_precedes_claims_and_one_audit() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    struct NativeFault(SharedH0);
    impl crate::semantics_objects::journal::FaultEpoch for NativeFault {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            let value = self.0.0.borrow().io.script.last_health.fault;
            if value > u64::from(u32::MAX) {
                Err(crate::semantics_objects::journal::FaultReadError::Saturated)
            } else {
                Ok(value)
            }
        }
    }
    let native = NativeFault(fixture.scene.real.h0.clone());
    let caller = fixture.births[0].0;
    let before = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    assert_eq!(before.objects.len(), 2);
    fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_mark_tail(caller);
    fixture.push_two("C_SignInit", 2);
    let raw = fixture.scene.collect_with_fault(&native);
    fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = fixture.scene.real.tick();
    let mut raw = fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .collected
        .take()
        .unwrap();
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    coordinator.stage_semantic_batch(batch);
    coordinator
        .prepare_joint_publication(
            false,
            &mut fixture.scene.real.lane,
            &mut raw,
            &fixture.scene.producers,
        )
        .unwrap();
    coordinator
        .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
        .unwrap();
    let mut ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("original physical-tail collection: {reason:?}"));
    while coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
        .is_some()
    {}
    while coordinator
        .stage_next_prepared_admission_with_disposition(&fixture.scene.producers, &mut ingested)
        .unwrap()
    {}
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    let frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &native);
    assert!(
        matches!(
            frame.audit_for_test().h3_for_test(),
            H3DispositionEvidence::StagedLoss { .. }
        ),
        "the original audit must own the real physical cut, not a later replacement H3"
    );
    let failure = frame
        .failure_for_test()
        .expect("actual original physical loss");
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::FaultChanged,
        "the physical cut raised the same actual native fault cell after raw collection"
    );
    for object in &before.objects {
        assert!(failure.effects.effects.iter().any(|effect| matches!(effect,
            ObjectEffect::Retired { object: id, reason: ObjectGap::OutcomeLost } if *id == object.id)));
    }
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(coordinator.reference_h3_audit_state(), (2, false));
    let revision = coordinator.registry().published_revision();
    let before_feeds = fixture.feeds();
    fixture.complete_publication(&mut Some(frame), &native, revision);
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(
        coordinator.reference_h3_audit_state(),
        (2, false),
        "no second H3 take or stranded replacement"
    );
    let after = coordinator.joint_capture().model().project();
    for object in &before.objects {
        assert_eq!(
            after.object(object.id).unwrap().lifetime,
            Lifetime::Retired(ObjectGap::OutcomeLost)
        );
    }
    assert_eq!(
        fixture.feeds().iter().map(|feed| feed.reduced).sum::<u64>(),
        before_feeds.iter().map(|feed| feed.reduced).sum::<u64>()
    );
    fixture.scene.assert_claims(&[]);
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test()[..4],
        [0, 0, 0, 0]
    );
}

/// Catches a retry repeating original admission, physical publication,
/// diagnostics, H9 reduction, or silently applying a later staged batch.
#[test]
fn joint_publication_retry_does_not_repeat_admission_or_reducer() {
    use crate::inventory_diagnostics::{
        CaptureOutcome, CaptureSettlement, DiagnosticConfig, DiagnosticOutcome,
        RetainedIdentityView,
    };
    let (mut fixture, original) = CanonicalFanoutScene::first_publication_inputs(
        1,
        &["C_CreateObject", "C_SignInit"],
        PublicationReceipts::All,
        true,
        true,
    );
    let caller = fixture.births[0].0;
    let module_key = fixture.scene.real.modules[0].0.clone();
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    let module = coordinator.registry().module_id_for(&module_key).unwrap();
    coordinator
        .enable_diagnostics(DiagnosticConfig::default())
        .unwrap();
    coordinator
        .registry_mut()
        .note_counted_use(caller, &module_key, 7, 1, 2, 0);
    let old_revision = coordinator.registry().published_revision();
    let claims = coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    assert_eq!(claims.0, 2);
    let mut frame = Some(original);
    let mut remaining = 1;
    let mut zero = 0;
    assert!(
        fixture
            .publication_step(&mut frame, &BirthFault, &mut zero)
            .unwrap()
            .is_none()
    );
    fixture.assert_publication_hidden(old_revision);
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(
        coordinator
            .registry()
            .edge(caller, module)
            .unwrap()
            .entry_count,
        7
    );
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.reduced == 0 && feed.staged == 1)
    );
    // The next batch stays in the original staging Vec, without being folded
    // into the already-applied phase by either the Joint or legacy paths.
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    coordinator
        .registry_mut()
        .note_counted_use(caller, &module_key, 4, 3, 4, 7);
    assert!(coordinator.commit_batch(true).is_err());
    assert!(
        coordinator
            .commit_batch_with_semantics(true, Some(&mut fixture.scene.real.lane))
            .is_err()
    );
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| coordinator
            .registry_mut()
            .publish()))
        .is_err()
    );
    for _ in 0..3 {
        let feeds = fixture.feeds();
        let claims = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test();
        assert!(
            fixture
                .publication_step(&mut frame, &BirthFault, &mut zero)
                .unwrap()
                .is_none()
        );
        fixture.assert_publication_hidden(old_revision);
        assert_eq!(fixture.feeds(), feeds);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            claims
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .edge(caller, module)
                .unwrap()
                .entry_count,
            7
        );
    }
    let (mut foreign, foreign_frame) = CanonicalFanoutScene::first_publication_with_functions(
        1,
        &["C_CreateObject", "C_SignInit"],
        PublicationReceipts::All,
    );
    let mut foreign_frame = Some(foreign_frame);
    let foreign_id = foreign_frame.as_ref().unwrap().identity();
    assert!(
        fixture
            .publication_step(&mut foreign_frame, &BirthFault, &mut remaining)
            .is_err()
    );
    assert!(foreign_frame.as_ref().unwrap().identity() == foreign_id);
    fixture.assert_publication_hidden(old_revision);
    let first = fixture.complete_publication(&mut frame, &BirthFault, old_revision);
    let feeds = fixture.feeds();
    assert!(
        feeds
            .iter()
            .all(|feed| feed.reduced == 1 && feed.staged == 0)
    );
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    assert_eq!(
        coordinator
            .registry()
            .edge(caller, module)
            .unwrap()
            .entry_count,
        7
    );
    let next = coordinator.commit_batch(false).unwrap();
    assert_eq!(next.registry_published, first.registry_published + 1);
    assert_eq!(
        coordinator
            .registry()
            .edge(caller, module)
            .unwrap()
            .entry_count,
        11
    );
    assert_eq!(fixture.feeds(), feeds);
    let finished = fixture
        .scene
        .real
        .scene
        .coordinator
        .take_diagnostics(DiagnosticOutcome {
            capture_outcome: CaptureOutcome::Completed,
            capture_settlement: CaptureSettlement::Settled,
        })
        .unwrap();
    struct Identities<'a, S: crate::discovery::caller_registry::ProcessSource>(
        &'a crate::discovery::engine::inventory_coordinator::InventoryCoordinator<S>,
    );
    impl<S: crate::discovery::caller_registry::ProcessSource> RetainedIdentityView
        for Identities<'_, S>
    {
        fn application(&self, caller: u32) -> Option<&str> {
            self.0
                .adapter()
                .record(CallerId(caller))?
                .exe
                .as_ref()?
                .path
                .as_deref()
        }
        fn module(&self, module: u32) -> Option<&str> {
            self.0
                .registry()
                .module(crate::discovery::caller_registry::ModuleId(module))?
                .paths
                .first()
                .map(String::as_str)
        }
    }
    let mut bytes = Vec::new();
    finished
        .write_jsonl(
            &mut bytes,
            &Identities(&fixture.scene.real.scene.coordinator),
            || false,
        )
        .unwrap();
    let rows = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|row| row["kind"] == "publication")
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        2,
        "one observer call for each original mutation, never each retry"
    );
    assert_eq!(
        (
            rows[0]["staged"].as_u64(),
            rows[0]["base"].as_u64(),
            rows[0]["edge_total"].as_u64()
        ),
        (Some(7), Some(0), Some(7))
    );
    assert_eq!(
        (
            rows[1]["staged"].as_u64(),
            rows[1]["base"].as_u64(),
            rows[1]["edge_total"].as_u64()
        ),
        (Some(4), Some(7), Some(11))
    );
    let foreign_revision = foreign
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    foreign.complete_publication(&mut foreign_frame, &BirthFault, foreign_revision);
}

/// Catches a second domain's real late broad loss becoming visible after an
/// intermediate positive revision, or skipping earlier already-delivered heads.
#[test]
fn joint_second_domain_fault_is_invisible_until_fanout() {
    use crate::inventory_present::Presentation;
    let (mut fixture, original) = CanonicalFanoutScene::first_publication_with_functions(
        1,
        &["C_CreateObject", "C_SignInit"],
        PublicationReceipts::All,
    );
    let old_revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    let old_text = format!("{:?}", fixture.published_before);
    let fault = FrameFault::clean();
    let mut frame = Some(original);
    let mut first_reduced = false;
    for _ in 0..64 {
        let mut remaining = 1;
        assert!(
            fixture
                .publication_step(&mut frame, &fault, &mut remaining)
                .unwrap()
                .is_none()
        );
        fixture.assert_publication_hidden(old_revision);
        let reduced = fixture.feeds().iter().map(|feed| feed.reduced).sum::<u64>();
        assert!(
            reduced <= 1,
            "one service slice cannot silently replay the next domain"
        );
        if reduced == 1 {
            first_reduced = true;
            break;
        }
    }
    assert!(first_reduced);
    let grown = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    assert_eq!(
        grown.objects.len(),
        1,
        "the first actual seal creates live history"
    );
    assert_eq!(grown.objects[0].lifetime, Lifetime::Live);
    fault.epoch.set(1);
    let receipt = fixture.complete_publication(&mut frame, &fault, old_revision);
    assert_eq!(receipt.registry_published, old_revision + 1);
    assert_eq!(format!("{:?}", fixture.published_before), old_text);
    let coordinator = &fixture.scene.real.scene.coordinator;
    let history = coordinator.joint_capture().model().project();
    assert_eq!(
        history.object(grown.objects[0].id).unwrap().lifetime,
        Lifetime::Retired(ObjectGap::OutcomeLost)
    );
    let feeds = fixture.feeds();
    assert_eq!(feeds.iter().map(|feed| feed.reduced).sum::<u64>(), 1);
    assert_eq!(feeds.iter().map(|feed| feed.disposed).sum::<u64>(), 1);
    assert!(feeds.iter().all(|feed| feed.degraded && feed.staged == 0));
    assert!(Presentation::try_capture(coordinator, "system", 1, 3, 1).is_ok());
    fixture.scene.assert_claims(&[]);
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test()[..4],
        [0, 0, 0, 0]
    );
    assert_eq!(coordinator.reference_h3_audit_state(), (1, false));

    // A global FrameFault truthfully affects every retained key. A separate
    // genuine localized negative proves that disjoint proved domains survive.
    let (mut fixture, first) = CanonicalFanoutScene::first_publication_with_functions(
        1,
        &["C_CreateObject", "C_SignInit"],
        PublicationReceipts::All,
    );
    let first_revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    fixture.complete_publication(&mut Some(first), &BirthFault, first_revision);
    let before = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    assert_eq!(before.objects.len(), 2);
    let raw_children = [OwnedStoppedChild::new(), OwnedStoppedChild::new()];
    let mut callers = Vec::new();
    for (offset, child) in raw_children.iter().enumerate() {
        let caller = fixture.scene.real.bind(
            child.id(),
            ImageIdentity {
                task_cookie: 73 + offset as u64,
                exec_id: 0,
            },
            0,
        );
        fixture.scene.push(child.id(), 0, "C_CreateObject", 1);
        callers.push(caller);
    }
    let raw = fixture.scene.collect_with_fault(&BirthFault);
    fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = fixture.scene.real.tick();
    for (child, caller) in raw_children.iter().zip(&callers) {
        fixture.scene.admit_providers(child.id(), *caller, &[0]);
    }
    let mut raw = fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .collected
        .take()
        .unwrap();
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    coordinator.stage_semantic_batch(batch);
    coordinator
        .prepare_joint_publication(
            false,
            &mut fixture.scene.real.lane,
            &mut raw,
            &fixture.scene.producers,
        )
        .unwrap();
    coordinator
        .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
        .unwrap();
    let mut ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("original localized C/D input: {reason:?}"));
    let mut claims = Vec::new();
    while let Some((position, proof)) = coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
    {
        claims.push((position, proof.expect("genuine localized C/D claim")));
    }
    assert_eq!(
        claims
            .iter()
            .map(|(position, _)| *position)
            .collect::<Vec<_>>(),
        [3, 4]
    );
    let roles = coordinator.joint_capture().ledger().roles_for_test();
    assert_eq!(roles[..4], [0, 2, 0, 0]);
    while coordinator
        .stage_next_prepared_admission_with_disposition(&fixture.scene.producers, &mut ingested)
        .unwrap()
    {}
    assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    let localized = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    let failure = localized.failure_for_test().unwrap();
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::ImageTainted
    );
    assert!(
        claims
            .iter()
            .all(|(_, proof)| failure.affects_proof_for_test(proof))
    );
    assert!(
        fixture
            .receipts()
            .iter()
            .all(|receipt| !failure.affects_domain(receipt.domain()))
    );
    let revision = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .published_revision();
    fixture.complete_publication(&mut Some(localized), &BirthFault, revision);
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(coordinator.registry().joint_feeds(), 2);
    for caller in callers {
        let direct = coordinator
            .registry()
            .instance_semantic_edges()
            .find(|record| record.caller == caller)
            .unwrap();
        assert_eq!(
            coordinator.registry().feed_mode_for_test(direct.id),
            Some(crate::semantics_key_use::FeedMode::S1Only)
        );
        assert_eq!(fixture.s1_counts(direct.id), (1, 0, 0, 0, 0));
    }
    let after = coordinator.joint_capture().model().project();
    for object in &before.objects {
        assert_eq!(after.object(object.id).unwrap().lifetime, Lifetime::Live);
    }
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| !feed.degraded && !feed.fallback && feed.staged == 0)
    );
    assert!(Presentation::try_capture(coordinator, "system", 1, 4, 1).is_ok());
    fixture.scene.assert_claims(&[]);
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test()[..4],
        [0, 0, 0, 0]
    );
}

struct CanonicalFanoutScene {
    scene: JointScene,
    attached: crate::attach::AttachedSemanticSet,
    births: Vec<(CallerId, RetainedBirthWitness, NativeBirthRows)>,
    grant: SessionDrainGrant,
    published_before: crate::inventory_present::Presentation,
    _child: OwnedStoppedChild,
}

impl CanonicalFanoutScene {
    /// Retain the actual collected New carried by a later stash merge. Its
    /// original cut/subject, not the current quantum number, authorizes birth.
    fn retain_collected_birth(
        &mut self,
        input: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
        current: crate::semantic_capture::CurrentPartitionReceipt,
        proof: crate::semantics_objects::journal::JournalDomainProof,
    ) {
        let candidate = current.into_birth_candidate().unwrap_or_else(|_| {
            panic!("the original pending job must retain its actual collected New")
        });
        assert_eq!(candidate.receipt.image(), input.journal_binding().1);
        let publisher = NativePublisher::build();
        let (row, control, _) = publisher.publish_stamped(&["0", "0"], self.attached.generation());
        let mut rows = NativeBirthRows { row, control };
        let caller = input.journal_binding().3;
        let witness = {
            let mut h0 = self.scene.real.h0.0.borrow_mut();
            let HeldH0 { capture, io, .. } = &mut *h0;
            capture
                .validate_birth_candidate(io, &candidate, false)
                .unwrap();
            capture
                .finish_birth(
                    candidate,
                    None,
                    input,
                    self.scene
                        .real
                        .scene
                        .coordinator
                        .semantic_bindings()
                        .get(caller)
                        .unwrap(),
                    &self.attached,
                    &proof,
                    self.scene.real.scene.coordinator.joint_capture().adapter(),
                    &mut rows,
                )
                .expect("the retained actual New and original subject authorize birth")
        };
        assert!(
            self.scene
                .real
                .scene
                .coordinator
                .registry_mut()
                .install_joint_receipt(input.instance_key_for_test(), *witness.receipt(),)
        );
        self.births.push((caller, witness, rows));
    }

    fn prior_sealed() -> Self {
        Self::prior_sealed_with_providers(1)
    }

    fn prior_sealed_with_providers(providers: usize) -> Self {
        Self::prior_sealed_with_functions(
            providers,
            &[
                "C_CreateObject",
                "C_SignInit",
                "C_SignUpdate",
                "C_SignFinal",
            ],
        )
    }

    fn first_publication_with_functions(
        providers: usize,
        functions: &[&str],
        receipt_policy: PublicationReceipts,
    ) -> (Self, IngestedJointQuantum) {
        Self::first_publication_inputs(providers, functions, receipt_policy, true, false)
    }

    fn first_publication_inputs(
        providers: usize,
        functions: &[&str],
        receipt_policy: PublicationReceipts,
        joint_preparation: bool,
        probe_preparation_refusal: bool,
    ) -> (Self, IngestedJointQuantum) {
        Self::first_publication_inputs_at_start(
            providers,
            functions,
            receipt_policy,
            joint_preparation,
            probe_preparation_refusal,
            |_| (),
        )
        .0
    }

    fn first_publication_inputs_at_start<R>(
        providers: usize,
        functions: &[&str],
        receipt_policy: PublicationReceipts,
        joint_preparation: bool,
        probe_preparation_refusal: bool,
        observe: impl FnOnce(&mut JointScene) -> R,
    ) -> ((Self, IngestedJointQuantum), R) {
        let (held, attached) = HeldProviders::with_attachment(providers, functions);
        let mut scene = JointScene::from_held(held, Some(attached));
        let initial = observe(&mut scene);
        scene.real.h0.0.borrow_mut().io.script.local = 1;
        let child = OwnedStoppedChild::new();
        let first = scene.real.bind(
            std::process::id(),
            ImageIdentity {
                task_cookie: 71,
                exec_id: 0,
            },
            0,
        );
        let second = scene.real.bind(
            child.id(),
            ImageIdentity {
                task_cookie: 72,
                exec_id: 0,
            },
            0,
        );
        let published_before = crate::inventory_present::Presentation::capture(
            &scene.real.scene.coordinator,
            "system",
            1,
            2,
            1,
        );
        // The first accepted H0 scan happens through the actual collected
        // quantum. A preliminary provider refresh would spend New too early.
        scene.push(std::process::id(), 0, "C_CreateObject", 1);
        scene.push(child.id(), 0, "C_CreateObject", 1);
        let raw = scene.collect_with_fault(&BirthFault);
        scene.real.h0.0.borrow_mut().collected = Some(raw);
        let batch = scene.real.tick();
        scene.admit_providers(std::process::id(), first, &[0]);
        scene.admit_providers(child.id(), second, &[0]);
        let mut raw = scene.real.h0.0.borrow_mut().collected.take().unwrap();
        let coordinator = &mut scene.real.scene.coordinator;
        coordinator.stage_semantic_batch(batch);
        if joint_preparation {
            if probe_preparation_refusal {
                // Equal native IDs do not let another real Capture route or
                // restamp this already-collected original, even for a no-op.
                let mut owned = scene.real.h0.0.borrow_mut();
                let HeldH0 { capture, io, .. } = &mut *owned;
                let mut foreign = SemanticCapture::in_domain(
                    scene.producers.native_domain(),
                    TickLimits::default(),
                )
                .unwrap();
                let before = (
                    capture.next_token,
                    io.script.now,
                    io.script.raises,
                    io.script.health.len(),
                    raw.pending_h0_records(),
                );
                assert!(foreign.tick_collected_with(io, &mut raw).is_err());
                assert!(
                    foreign
                        .apply_physical_gaps_collected_with(io, Vec::new(), &mut raw)
                        .is_err()
                );
                assert_eq!(
                    (
                        capture.next_token,
                        io.script.now,
                        io.script.raises,
                        io.script.health.len(),
                        raw.pending_h0_records(),
                    ),
                    before,
                    "foreign Capture refuses before routing or native audit"
                );
                capture.validate_collected_preparation(&raw).unwrap();
                drop(owned);
                let revision = coordinator.registry().published_revision();
                let roles = coordinator.joint_capture().ledger().roles_for_test();
                let snapshot = coordinator.registry().semantic_resource_snapshot();
                let hold = coordinator
                    .registry()
                    .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes)
                    .unwrap();
                assert!(
                    coordinator
                        .prepare_joint_publication(
                            false,
                            &mut scene.real.lane,
                            &mut raw,
                            &scene.producers
                        )
                        .is_err()
                );
                assert!(!coordinator.publication_pending());
                assert_eq!(coordinator.registry().published_revision(), revision);
                assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
                assert!(
                    coordinator.prepared_semantic_batch().is_none(),
                    "no admission was prepared on refusal"
                );
                drop(hold);
            }
            coordinator
                .prepare_joint_publication(false, &mut scene.real.lane, &mut raw, &scene.producers)
                .unwrap();
            let charged = coordinator
                .registry()
                .semantic_resource_snapshot()
                .charged_bytes;
            coordinator
                .prepare_joint_publication(false, &mut scene.real.lane, &mut raw, &scene.producers)
                .unwrap();
            assert_eq!(
                coordinator
                    .registry()
                    .semantic_resource_snapshot()
                    .charged_bytes,
                charged,
                "same original preparation does not charge/repeat"
            );
        }
        coordinator
            .prepare_staged_semantic_batch(&mut scene.real.lane, None)
            .unwrap();
        assert_eq!(
            coordinator
                .prepared_semantic_batch()
                .unwrap()
                .admissions()
                .count(),
            2
        );
        let (mut ingested, _, grant) = scene.ingest_with_grant(raw);
        let admitted = {
            let (prepared, _) = scene.real.scene.coordinator.prepared_joint_parts().unwrap();
            prepared.admissions().cloned().collect::<Vec<_>>()
        };
        let current = scene
            .real
            .scene
            .coordinator
            .take_prepared_current_for_birth_test()
            .unwrap();
        assert_eq!(admitted.len(), 2);
        assert_eq!(current.len(), 2, "two actual collected New receipts");
        let mut claims = Vec::new();
        while let Some((position, proof)) = scene
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&scene.producers, &ingested)
            .unwrap()
        {
            claims.push((position, proof.expect("actual first key claim")));
        }
        assert_eq!(claims.len(), 2);
        let attached = attachment(&mut scene);
        assert!(
            scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut()
                .install_closure_grant(&SessionClosureGrant::observe(&attached)),
            "install the genuine current attachment before any birth attestation"
        );
        let publisher = NativePublisher::build();
        let mut births = Vec::new();
        for receipt in current {
            let candidate = receipt.into_birth_candidate().unwrap_or_else(|_| {
                panic!("provider admission must preserve the original collected New")
            });
            let input = admitted
                .iter()
                .find(|input| input.journal_binding().1 == candidate.receipt.image())
                .unwrap();
            let proof = claims
                .iter()
                .find(|(ordinal, _)| *ordinal == input.h0_ordinal())
                .unwrap()
                .1;
            let caller = input.journal_binding().3;
            let (row, control, _) = publisher.publish_stamped(&["0", "0"], attached.generation());
            let mut rows = NativeBirthRows { row, control };
            let mut h0 = scene.real.h0.0.borrow_mut();
            let HeldH0 { capture, io, .. } = &mut *h0;
            capture
                .validate_birth_candidate(io, &candidate, false)
                .unwrap();
            let witness = capture
                .finish_birth(
                    candidate,
                    None,
                    input,
                    scene
                        .real
                        .scene
                        .coordinator
                        .semantic_bindings()
                        .get(caller)
                        .unwrap(),
                    &attached,
                    &proof,
                    scene.real.scene.coordinator.joint_capture().adapter(),
                    &mut rows,
                )
                .expect("the original actual New and native marker authorize this subject");
            assert_eq!(
                witness.receipt().closure_generation(),
                attached.generation()
            );
            births.push((caller, witness, rows));
        }
        assert_ne!(
            births[0].1.receipt().domain(),
            births[1].1.receipt().domain()
        );
        if let PublicationReceipts::Capacity(limit) = receipt_policy {
            scene
                .real
                .scene
                .coordinator
                .registry_mut()
                .reference_instance_limit(limit);
        }
        let mut installed = 0;
        for (caller, witness, _) in &births {
            let input = admitted
                .iter()
                .find(|input| input.journal_binding().3 == *caller)
                .unwrap();
            if matches!(receipt_policy, PublicationReceipts::Missing) {
                continue;
            }
            let accepted = scene
                .real
                .scene
                .coordinator
                .registry_mut()
                .install_joint_receipt(input.instance_key_for_test(), *witness.receipt());
            let expected = match receipt_policy {
                PublicationReceipts::All => true,
                PublicationReceipts::Capacity(limit) => installed < limit,
                PublicationReceipts::Missing => unreachable!(),
            };
            assert_eq!(accepted, expected, "actual grant capacity is respected");
            installed += usize::from(accepted);
        }
        if matches!(receipt_policy, PublicationReceipts::Capacity(_)) {
            // The exercised refusal is receipt installation. Restore the
            // ordinary instance cap so both genuine admissions still publish.
            scene
                .real
                .scene
                .coordinator
                .registry_mut()
                .reference_instance_limit(usize::MAX);
        }
        // Selection is settled before the actual disposition port: missing
        // grants must become S1Only negatives, never hidden by old staging.
        while scene
            .real
            .scene
            .coordinator
            .stage_next_prepared_admission_with_disposition(&scene.producers, &mut ingested)
            .unwrap()
        {}
        assert!(
            scene
                .real
                .scene
                .coordinator
                .finish_prepared_semantic_batch(&scene.real.lane)
        );
        let frame = acquire(&mut scene, ingested, &attached, &BirthFault);
        if matches!(receipt_policy, PublicationReceipts::All) {
            assert!(frame.failure_for_test().is_none());
        } else {
            assert_eq!(
                frame.failure_for_test().unwrap().gap,
                crate::semantics_objects::journal::JournalGap::ImageTainted
            );
        }
        (
            (
                Self {
                    scene,
                    attached,
                    births,
                    grant,
                    published_before,
                    _child: child,
                },
                frame,
            ),
            initial,
        )
    }

    fn prior_sealed_with_functions(providers: usize, functions: &[&str]) -> Self {
        Self::prior_sealed_with_functions_at_start(providers, functions, |_| ()).0
    }

    fn prior_sealed_with_functions_at_start<R>(
        providers: usize,
        functions: &[&str],
        observe: impl FnOnce(&mut JointScene) -> R,
    ) -> (Self, R) {
        let ((mut fixture, frame), initial) = Self::first_publication_inputs_at_start(
            providers,
            functions,
            PublicationReceipts::All,
            false,
            false,
            observe,
        );
        let Self {
            scene,
            attached,
            births,
            ..
        } = &mut fixture;
        scene
            .real
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut scene.real.lane))
            .unwrap();
        assert_eq!(scene.real.scene.coordinator.registry().joint_feeds(), 2);
        // Bootstrap the fixture with actual native rechecks and the SAME
        // acquired audit/model/ledger. Tests below exercise new frame delivery.
        for (caller, witness, rows) in births.iter_mut() {
            let fresh = {
                let mut h0 = scene.real.h0.0.borrow_mut();
                let HeldH0 { capture, io, .. } = &mut *h0;
                witness
                    .fresh_evidence_with(
                        io,
                        rows,
                        capture,
                        attached,
                        scene
                            .real
                            .scene
                            .coordinator
                            .semantic_bindings()
                            .get(*caller)
                            .unwrap(),
                    )
                    .unwrap()
            };
            let (adapter, model) = scene.real.scene.coordinator.joint_capture_mut().parts();
            let sealed = adapter
                .seal(
                    model,
                    frame.audit_for_test(),
                    witness.receipt(),
                    frame.frontier(),
                    &mut ScriptedBirthSource::once(fresh),
                    &BirthFault,
                )
                .expect("actual native birth seals original history on canonical owner");
            assert_eq!(sealed.prefix.settled().len(), 1);
            let id = scene
                .real
                .scene
                .coordinator
                .registry()
                .instance_semantic_edges()
                .find(|record| record.caller == *caller)
                .unwrap()
                .id;
            assert_eq!(
                scene
                    .real
                    .scene
                    .coordinator
                    .deliver_canonical_joint_seal_for_test(id, &sealed),
                crate::semantics_key_use::SealApplyOutcome::ReplayedOne
            );
        }
        drop(frame);
        let history = scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .model()
            .project();
        assert_eq!(history.objects.len(), 2);
        assert!(
            history
                .objects
                .iter()
                .all(|object| object.lifetime == Lifetime::Live)
        );
        (fixture, initial)
    }

    fn receipts(&self) -> Vec<BootstrapReceipt> {
        self.births
            .iter()
            .map(|(_, witness, _)| *witness.receipt())
            .collect()
    }
}

#[test]
fn joint_prior_sealed_fixture_keeps_nonempty_original_two_domain_effects() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let before = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    let receipts = fixture.receipts();
    fixture.scene.drain.source_mut().push_record(vec![1, 2, 3]);
    let raw = fixture.scene.prepare(0);
    let ingested = raw
        .ingest(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("original malformed collection: {reason:?}"));
    assert!(claim_and_finish(&mut fixture.scene, &ingested).is_empty());
    let before_audit = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    for object in &before.objects {
        assert_eq!(
            before_audit.object(object.id).unwrap().lifetime,
            Lifetime::Live
        );
    }
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (1, true)
    );
    let frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    let failure = frame
        .failure_for_test()
        .expect("actual original broad loss");
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::Malformed
    );
    assert!(
        receipts
            .iter()
            .all(|receipt| failure.affects_domain(receipt.domain()))
    );
    for object in &before.objects {
        assert!(
            failure.effects.effects.iter().any(|effect| matches!(
                effect,
                ObjectEffect::Retired { object: affected, reason: ObjectGap::OutcomeLost }
                    if *affected == object.id
            )),
            "audit Voided must retain each original OutcomeLost retirement: {:?}",
            failure.effects
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .model()
                .project()
                .object(object.id)
                .unwrap()
                .lifetime,
            Lifetime::Retired(ObjectGap::OutcomeLost)
        );
    }
    assert!(!failure.effects.effects.is_empty());
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );
    let original_effects = failure.effects.clone();
    fixture
        .scene
        .push(std::process::id(), 0, "C_CreateObject", 2);
    let cut = fixture.scene.drain.consumption_cut().unwrap();
    let reserve = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_storage_reserver();
    let next = RawJointQuantum::collect_bounded_with_adapter(
        &mut fixture.scene.drain,
        &publish_object_descriptors(),
        64,
        None,
        &BirthFault,
        &fixture.scene.producers,
        |bytes| reserve.reserve(bytes),
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture_mut()
            .adapter_mut(),
    );
    assert!(matches!(
        next,
        Err(RawQuantumRefusal::Cut(
            crate::semantics_objects::journal::BirthCutRefusal::Gap
        ))
    ));
    assert!(
        fixture
            .scene
            .drain
            .consumption_cut()
            .unwrap()
            .same_boundary(&cut)
    );
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .consumed_frontier()
            == frame.frontier()
    );
    assert_eq!(failure.effects, original_effects);
    assert!(
        receipts
            .iter()
            .all(|receipt| failure.affects_domain(receipt.domain()))
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
}

use crate::attach::{BirthObservationRefusal, BirthRowError, BirthRowReader};
use crate::discovery::caller_registry::instance_input::{JointFeedTarget, RegistryInstanceId};
use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
use crate::semantics_objects::journal::SessionBirthEvidence;
use crate::semantics_objects::journal::joint_audit::{
    IngestedJointQuantum, JointBirthEvidenceSource, QuantumSealProgress,
};
use std::cell::Cell;

/// Reads the genuine retained native row through the same verifier. Refusal
/// substitutes only the row I/O leaf, never a birth value or target counter.
struct NativeFrameBirths<'a> {
    h0: &'a SharedH0,
    attached: &'a crate::attach::AttachedSemanticSet,
    retained: &'a mut [(CallerId, RetainedBirthWitness, NativeBirthRows)],
    seen: Vec<(
        RegistryInstanceId,
        CallerId,
        ImageIdentity,
        crate::semantics_objects::ObjectDomain,
    )>,
    unreadable: bool,
}

struct UnreadableRows<'a>(&'a mut NativeBirthRows);
impl BirthRowReader for UnreadableRows<'_> {
    fn read_marker_row(&mut self) -> Result<p11scope_ebpf_common::InstanceRecord, BirthRowError> {
        Err(BirthRowError::Unreadable)
    }
    fn read_admission_control(
        &mut self,
    ) -> Result<p11scope_ebpf_common::JournalAdmissionControl, BirthRowError> {
        self.0.read_admission_control()
    }
}

impl JointBirthEvidenceSource for NativeFrameBirths<'_> {
    fn take_for(
        &mut self,
        target: &JointFeedTarget,
        binding: &SemanticCallerBinding,
    ) -> Result<SessionBirthEvidence, BirthObservationRefusal> {
        assert_eq!(target.caller(), binding.caller());
        let (_, witness, rows) = self
            .retained
            .iter_mut()
            .find(|(caller, witness, _)| {
                *caller == binding.caller()
                    && witness.receipt().domain() == target.bootstrap().domain()
            })
            .expect("the selected typed target names its own original binding/witness");
        self.seen.push((
            target.id(),
            binding.caller(),
            binding.image(),
            target.bootstrap().domain(),
        ));
        let mut h0 = self.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *h0;
        if self.unreadable {
            witness.fresh_evidence_with(
                io,
                &mut UnreadableRows(rows),
                capture,
                self.attached,
                binding,
            )
        } else {
            witness.fresh_evidence_with(io, rows, capture, self.attached, binding)
        }
    }
}

struct RefuseOneBirth<'a> {
    inner: NativeFrameBirths<'a>,
    refused: Option<CallerId>,
}
impl JointBirthEvidenceSource for RefuseOneBirth<'_> {
    fn take_for(
        &mut self,
        target: &JointFeedTarget,
        binding: &SemanticCallerBinding,
    ) -> Result<SessionBirthEvidence, BirthObservationRefusal> {
        self.inner.unreadable = self.refused == Some(target.caller());
        self.inner.take_for(target, binding)
    }
}

/// Only the native leaf is substituted. Capture, stash, witnesses and frame
/// remain the originals from the real collection/admission path above.
struct HeldCommitNative<'a> {
    io: &'a mut HeldIo,
    rows: Vec<(
        crate::semantics_objects::ObjectDomain,
        &'a mut NativeBirthRows,
    )>,
    reads: &'a Cell<(usize, usize)>,
}

impl crate::inventory_semantics::JointNativeIo for HeldCommitNative<'_> {
    fn recheck_birth(
        &mut self,
        witness: &RetainedBirthWitness,
        capture: &SemanticCapture,
        attached: &crate::attach::AttachedSemanticSet,
        binding: &SemanticCallerBinding,
    ) -> Result<SessionBirthEvidence, BirthObservationRefusal> {
        let (births, faults) = self.reads.get();
        self.reads.set((births + 1, faults));
        let (_, rows) = self
            .rows
            .iter_mut()
            .find(|(domain, _)| *domain == witness.receipt().domain())
            .ok_or(BirthObservationRefusal::BindingMismatch)?;
        witness.fresh_evidence_with(self.io, *rows, capture, attached, binding)
    }

    fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
        use crate::semantics_objects::journal::FaultReadError;
        use std::sync::atomic::Ordering;
        let (births, faults) = self.reads.get();
        self.reads.set((births, faults + 1));
        let epoch = self.io.script.fault_cell.load(Ordering::SeqCst);
        if epoch > u64::from(u32::MAX) {
            Err(FaultReadError::Saturated)
        } else {
            Ok(epoch)
        }
    }
}

fn with_held_commit_io<R>(
    h0: &SharedH0,
    attached: &crate::attach::AttachedSemanticSet,
    retained: &mut [(CallerId, RetainedBirthWitness, NativeBirthRows)],
    reads: &Cell<(usize, usize)>,
    hold_native_read: bool,
    inspect: impl for<'io> FnOnce(crate::inventory_semantics::JointCommitIo<'io>) -> R,
) -> Result<R, SemanticRefusal> {
    let mut owned =
        h0.0.try_borrow_mut()
            .map_err(|_| SemanticRefusal::Unavailable)?;
    // One whole-owner borrow is split once, before either native reader is
    // constructed. No callback tries to borrow the SharedH0 again.
    let HeldH0 {
        capture,
        io,
        stash,
        collected_producers,
        ..
    } = &mut *owned;
    let producers = collected_producers
        .as_ref()
        .ok_or(SemanticRefusal::Unavailable)?;
    let (mut witnesses, rows): (Vec<_>, Vec<_>) = retained
        .iter_mut()
        .map(|(_, witness, rows)| (&*witness, (witness.receipt().domain(), rows)))
        .unzip();
    witnesses.sort_unstable_by_key(|witness| witness.receipt().domain());
    let mut native = HeldCommitNative { io, rows, reads };
    let native = RefCell::new(&mut native);
    // This holds the exact native cell, not the Capture/stash. Its only use
    // is the direct read-preflight refusal twin below.
    let hold = hold_native_read.then(|| native.borrow_mut());
    let result = crate::inventory_semantics::with_joint_commit_io_for_test(
        capture, stash, producers, attached, &witnesses, &native, inspect,
    );
    drop(hold);
    result
}

#[test]
fn joint_commit_io_shares_capture_and_fresh_native_reads() {
    use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
    use std::sync::atomic::Ordering;
    for move_fault in [false, true] {
        let (mut fixture, original) = CanonicalFanoutScene::first_publication_with_functions(
            1,
            &["C_CreateObject", "C_SignInit"],
            PublicationReceipts::All,
        );
        let identity = original.identity();
        let old_revision = fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .published_revision();
        let h0 = fixture.scene.real.h0.clone();
        let fault_cell = h0.0.borrow().io.script.fault_cell.clone();
        let reads = Cell::new((0, 0));
        let mut frame = Some(original);
        let mut fault_moved = false;
        let mut published = false;
        for _ in 0..256 {
            let mut remaining = 1;
            let CanonicalFanoutScene {
                scene,
                attached,
                births,
                ..
            } = &mut fixture;
            let progress = with_held_commit_io(&h0, attached, births, &reads, false, |io| {
                scene.real.scene.coordinator.commit_joint_batch_with_io(
                    io,
                    &scene.producers,
                    &mut frame,
                    &mut remaining,
                )
            })
            .expect("one disjoint borrow of the original H0 owner")
            .expect("the real publication uses the same scoped readers");
            if let JointCommitProgress::Published(receipt) = progress {
                assert!(frame.is_none());
                assert_eq!(receipt.registry_published, old_revision + 1);
                published = true;
                break;
            }
            fixture.assert_publication_hidden(old_revision);
            assert!(frame.as_ref().unwrap().identity() == identity);
            if move_fault && !fault_moved && fixture.feeds().iter().any(|feed| feed.reduced == 1) {
                assert!(
                    fixture
                        .scene
                        .real
                        .scene
                        .coordinator
                        .joint_capture()
                        .model()
                        .project()
                        .objects
                        .iter()
                        .any(|object| object.lifetime == Lifetime::Live)
                );
                // The next scope must reread the native cell, rather than
                // reuse the initial audit's clean scalar.
                fault_cell.store(1, Ordering::SeqCst);
                fault_moved = true;
            }
        }
        assert!(published, "bounded same-frame service must finish");
        assert!(reads.get().0 != 0 && reads.get().1 != 0);
        if move_fault {
            assert!(fault_moved);
            assert!(fixture.feeds().iter().all(|feed| feed.degraded));
            assert_eq!(
                fixture.feeds().iter().map(|feed| feed.reduced).sum::<u64>(),
                1
            );
            assert!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .model()
                    .project()
                    .objects
                    .iter()
                    .all(|object| object.lifetime != Lifetime::Live)
            );
        } else {
            assert!(fixture.feeds().iter().all(|feed| {
                feed.reduced == 1 && feed.staged == 0 && !feed.degraded && !feed.fallback
            }));
        }
        fixture.scene.assert_claims(&[]);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test()[..4],
            [0, 0, 0, 0]
        );
    }
}

#[test]
fn joint_commit_io_foreign_and_busy_reads_preserve_originals() {
    use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
    use crate::semantics_objects::journal::FaultReadError;
    let snapshot = |fixture: &CanonicalFanoutScene| {
        let coordinator = &fixture.scene.real.scene.coordinator;
        (
            coordinator.registry().published_revision(),
            fixture.feeds(),
            coordinator.joint_capture().ledger().roles_for_test(),
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
        )
    };
    let (mut fixture, original) = CanonicalFanoutScene::first_publication_with_functions(
        1,
        &["C_CreateObject", "C_SignInit"],
        PublicationReceipts::All,
    );
    let identity = original.identity();
    let h0 = fixture.scene.real.h0.clone();
    let reads = Cell::new((0, 0));
    let mut frame = Some(original);
    let before = snapshot(&fixture);
    let foreign = crate::attach::SessionDrainProducers::test_pair(
        fixture.scene.producers.native_domain(),
        EventsDomain::test_standin(fixture.scene.producers.events_id()),
    );
    let mut remaining = 1;
    let CanonicalFanoutScene {
        scene,
        attached,
        births,
        ..
    } = &mut fixture;
    assert!(
        with_held_commit_io(&h0, attached, births, &reads, false, |io| {
            scene.real.scene.coordinator.commit_joint_batch_with_io(
                io,
                &foreign,
                &mut frame,
                &mut remaining,
            )
        })
        .unwrap()
        .is_err()
    );
    assert_eq!(
        reads.get(),
        (0, 0),
        "foreign allocation refuses before native I/O"
    );
    assert_eq!(remaining, 1);
    assert!(frame.as_ref().unwrap().identity() == identity);
    assert_eq!(snapshot(&fixture), before);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .joint_feeds(),
        0
    );
    // Apply the actual originals with no delivery allowance, so typed target
    // selection is available for the direct read-preflight controls.
    let mut zero = 0;
    let CanonicalFanoutScene {
        scene,
        attached,
        births,
        ..
    } = &mut fixture;
    assert!(matches!(
        with_held_commit_io(&h0, attached, births, &reads, false, |io| {
            scene.real.scene.coordinator.commit_joint_batch_with_io(
                io,
                &scene.producers,
                &mut frame,
                &mut zero,
            )
        })
        .unwrap()
        .unwrap(),
        JointCommitProgress::Pending
    ));
    let targets = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 2);
    let before = snapshot(&fixture);
    for busy in [true, false] {
        let CanonicalFanoutScene {
            scene,
            attached,
            births,
            ..
        } = &mut fixture;
        with_held_commit_io(&h0, attached, births, &reads, busy, |mut io| {
            let (births, fault) = io.native_checks();
            let bindings = scene.real.scene.coordinator.semantic_bindings();
            let own = bindings.get(targets[0].caller()).unwrap();
            let other = bindings.get(targets[1].caller()).unwrap();
            assert!(matches!(
                births.take_for(&targets[0], other),
                Err(BirthObservationRefusal::BindingMismatch)
            ));
            assert_eq!(
                reads.get(),
                (0, 0),
                "foreign binding never reaches native I/O"
            );
            if busy {
                assert_eq!(fault.fault_epoch(), Err(FaultReadError::Unreadable));
                assert!(matches!(
                    births.take_for(&targets[0], own),
                    Err(BirthObservationRefusal::CurrentPartition)
                ));
                assert_eq!(
                    reads.get(),
                    (0, 0),
                    "busy cell refuses before either native read"
                );
            } else {
                assert_eq!(fault.fault_epoch(), Ok(0));
                assert!(births.take_for(&targets[0], own).is_ok());
            }
        })
        .unwrap();
        assert_eq!(snapshot(&fixture), before);
        assert!(frame.as_ref().unwrap().identity() == identity);
    }
    assert_eq!(reads.get(), (1, 1));
}

#[test]
fn joint_commit_io_pending_continuation_keeps_original_stash() {
    let PendingH3Scene {
        mut fixture,
        mut frame,
        child_c: _child_c,
        ..
    } = pending_h3_from_stash(false, &BirthFault);
    let coordinator = &fixture.scene.real.scene.coordinator;
    let before = (
        fixture.feeds(),
        coordinator.joint_capture().ledger().roles_for_test(),
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
    );
    assert_eq!(before.1[..4], [0, 3, 0, 1]);
    let h0 = fixture.scene.real.h0.clone();
    assert_eq!(h0.0.borrow().stash.min_outcome_position(), Some(4));
    let reads = Cell::new((0, 0));
    let CanonicalFanoutScene {
        scene,
        attached,
        births,
        ..
    } = &mut fixture;
    with_held_commit_io(&h0, attached, births, &reads, false, |io| {
        let mut ports = scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
        assert_eq!(
            frame.defer_pending_h3_with_view(&mut ports, io.continuation()),
            Ok(QuantumSealProgress::AwaitFutureInput)
        );
        frame
            .finish_pending_h3_with_view(&mut ports, io.continuation())
            .unwrap_or_else(|(_, reason)| {
                panic!("same producer-owned stash remains available: {reason:?}")
            });
    })
    .unwrap();
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(
        (
            fixture.feeds(),
            coordinator.joint_capture().ledger().roles_for_test(),
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            coordinator
                .joint_capture()
                .adapter()
                .retained_starts_for_test(),
        ),
        before
    );
    assert_eq!(h0.0.borrow().stash.min_outcome_position(), Some(4));
    assert_eq!(coordinator.reference_h3_acknowledged_below(), 0);
    assert_eq!(
        reads.get(),
        (0, 0),
        "pending custody neither seals nor invents a native recheck"
    );
}

#[derive(Debug, PartialEq, Eq)]
struct FeedState {
    id: RegistryInstanceId,
    caller: CallerId,
    reduced: u64,
    staged: usize,
    disposed: u64,
    degraded: bool,
    fallback: bool,
}

struct FrameFault {
    epoch: Cell<u64>,
    reads: Cell<usize>,
}
impl FrameFault {
    fn clean() -> Self {
        Self {
            epoch: Cell::new(0),
            reads: Cell::new(0),
        }
    }
}
impl crate::semantics_objects::journal::FaultEpoch for FrameFault {
    fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.epoch.get())
    }
}

impl CanonicalFanoutScene {
    fn feeds(&self) -> Vec<FeedState> {
        self.scene
            .real
            .scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .map(|record| FeedState {
                id: record.id,
                caller: record.caller,
                reduced: record.feed.reduced(),
                staged: record.feed.staged_len(),
                disposed: record.feed.history_disposed(),
                degraded: record.feed.degraded_loss(),
                fallback: record.feed.fell_back(),
            })
            .collect()
    }

    fn push_two(&mut self, name: &str, sequence: u64) {
        for pid in [std::process::id(), self._child.id()] {
            self.scene.push(pid, 0, name, sequence);
        }
    }

    fn push_distinct_create(&mut self, pid: u32, sequence: u64, result: u64) {
        let (begin, _) = self.scene.encoded(pid, 0, "C_CreateObject", sequence);
        let end = crate::semantics_objects::journal::tests::end_bytes_result(
            &begin,
            p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE,
            0,
            ENTRY_NS + 10,
            result,
        );
        self.scene.drain.source_mut().push_record(begin.to_vec());
        self.scene.drain.source_mut().push_record(end.to_vec());
    }

    fn audited(
        &mut self,
        physical: usize,
        admissions: usize,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
    ) -> IngestedJointQuantum {
        let raw = self.scene.collect_with_fault(fault);
        assert_eq!(
            raw.h0_input(self.scene.real.lane.domain(), 64)
                .unwrap()
                .0
                .len(),
            physical
        );
        self.scene.real.h0.0.borrow_mut().collected = Some(raw);
        let batch = self.scene.real.tick();
        assert_eq!(self.scene.real.h0.0.borrow().last_calls.len(), physical);
        let coordinator = &mut self.scene.real.scene.coordinator;
        coordinator.stage_semantic_batch(batch);
        coordinator
            .prepare_staged_semantic_batch(&mut self.scene.real.lane, None)
            .unwrap();
        assert_eq!(
            coordinator
                .prepared_semantic_batch()
                .unwrap()
                .admissions()
                .count(),
            admissions
        );
        let raw = self.scene.real.h0.0.borrow_mut().collected.take().unwrap();
        let ingested = raw
            .ingest(
                coordinator.joint_capture_mut().adapter_mut(),
                &self.scene.producers,
                &self.grant,
            )
            .unwrap_or_else(|(_, reason)| panic!("same original ingestion: {reason:?}"));
        assert_eq!(
            claim_and_finish(&mut self.scene, &ingested).len(),
            admissions
        );
        // Existing commit applies actual staged payloads to the selected feeds.
        // Atomic publication/revision wiring is explicitly the later Task5 gate.
        self.scene
            .real
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut self.scene.real.lane))
            .unwrap();
        acquire(&mut self.scene, ingested, &self.attached, fault)
    }
}

#[test]
fn joint_one_audit_fans_out_two_domains() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    fixture.push_two("C_SignInit", 2);
    let mut frame = fixture.audited(2, 2, &BirthFault);
    let identity = frame.identity();
    let frontier = frame.frontier();
    assert_eq!(
        fixture
            .feeds()
            .iter()
            .map(|feed| (feed.reduced, feed.staged))
            .collect::<Vec<_>>(),
        [(1, 1), (1, 1)]
    );
    let targets = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 2);
    for target in &targets {
        assert!(
            fixture
                .births
                .iter()
                .any(|(caller, witness, _)| *caller == target.caller()
                    && witness.receipt().domain() == target.bootstrap().domain())
        );
    }
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
        assert_eq!(
            frame.bind_targets(&ports),
            Err(RawQuantumRefusal::DispositionMismatch)
        );
        for index in 0..2 {
            assert_eq!(
                frame.seal_next(&mut ports, &mut births, &BirthFault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(births.seen.len(), index + 1);
            assert_eq!(
                frame.seal_next(&mut ports, &mut births, &BirthFault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(
                births.seen.len(),
                index + 1,
                "retry never seals or reads birth twice"
            );
            assert_eq!(
                frame.deliver_next(&mut ports),
                Ok(if index == 0 {
                    QuantumSealProgress::LocalPending
                } else {
                    QuantumSealProgress::Complete
                })
            );
        }
        assert_eq!(
            frame.seal_next(&mut ports, &mut births, &BirthFault),
            Ok(QuantumSealProgress::Complete)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::Complete)
        );
        let disposed = frame
            .finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| panic!("all consumers disposed: {reason:?}"));
        assert!(disposed.identity() == identity);
        assert_eq!(disposed.frontier(), frontier);
    }
    assert_ne!(
        births.seen[0].2, births.seen[1].2,
        "different original images/bindings"
    );
    assert_eq!(
        births.seen.iter().map(|seen| seen.0).collect::<Vec<_>>(),
        targets.iter().map(JointFeedTarget::id).collect::<Vec<_>>()
    );
    drop(births);
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.reduced == 2 && feed.staged == 0 && !feed.degraded && !feed.fallback)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );
    fixture.scene.assert_claims(&[]);
}

#[test]
fn joint_two_feeds_share_nonzero_audited_fallback_once() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    fixture.push_two("C_SignInit", 2);
    let mut frame = fixture.audited(2, 2, &BirthFault);
    assert!(matches!(
        frame.audit_for_test().h3_for_test(),
        H3DispositionEvidence::Clean {
            staged_max: 4,
            pending_floor: None
        }
    ));
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: true,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
        for index in 0..2 {
            assert_eq!(
                frame.seal_next(&mut ports, &mut births, &BirthFault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(
                frame.deliver_next(&mut ports),
                Ok(if index == 0 {
                    QuantumSealProgress::LocalPending
                } else {
                    QuantumSealProgress::Complete
                })
            );
        }
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::Complete)
        );
        frame
            .finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| panic!("audited fallback disposed both: {reason:?}"));
    }
    assert_eq!(births.seen.len(), 2);
    assert_ne!(
        births.seen[0].2, births.seen[1].2,
        "first refusal does not choose the next witness by guessed ordinal"
    );
    drop(births);
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.reduced == 2 && feed.staged == 0 && feed.fallback && !feed.degraded)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false),
        "both feeds borrow the same nonzero taken H3, no genesis second take"
    );
    fixture.scene.assert_claims(&[]);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test()[..4],
        [0, 0, 0, 0],
        "completed originals release Raw/H8/Model/H9 after once-only fallback; legitimate live S1 associations keep their own roles"
    );
}

#[test]
fn joint_fallback_preflight_preserves_incomplete_admitted_original() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let first = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .next()
        .unwrap();
    let pid = fixture
        .scene
        .real
        .scene
        .coordinator
        .semantic_bindings()
        .get(first.caller())
        .unwrap()
        .pin()
        .pid();
    let (begin, end) = fixture.scene.encoded(pid, 0, "C_SignInit", 2);
    fixture.scene.drain.source_mut().push_record(begin.to_vec());
    // H0 genuinely admits the ordinary physical return, while the journal
    // retains START without its END. Completeness of H3 cannot invent END.
    fixture
        .scene
        .drain
        .source_mut()
        .push_record(end[24..392].to_vec());
    let mut frame = fixture.audited(1, 1, &BirthFault);
    let before = fixture.feeds();
    let owner = fixture.scene.real.scene.coordinator.joint_capture();
    let claims = owner.adapter().invocation_claims_for_test();
    let starts = owner.adapter().retained_starts_for_test();
    let roles = owner.ledger().roles_for_test();
    assert_eq!(claims.0, 1);
    assert_eq!(roles[..4], [0, 1, 0, 1]);
    assert_eq!(
        owner
            .adapter()
            .retained_start_bytes_for_test((u64::from(pid), 2)),
        Some(begin)
    );
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: true,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut births, &BirthFault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Err(RawQuantumRefusal::DispositionMismatch),
            "completed-original preflight precedes any H9 fallback mutation"
        );
    }
    drop(births);
    assert_eq!(fixture.feeds(), before);
    let owner = fixture.scene.real.scene.coordinator.joint_capture();
    assert_eq!(owner.adapter().invocation_claims_for_test(), claims);
    assert_eq!(owner.adapter().retained_starts_for_test(), starts);
    assert_eq!(owner.ledger().roles_for_test(), roles);
    assert_eq!(
        owner
            .adapter()
            .retained_start_bytes_for_test((u64::from(pid), 2)),
        Some(begin)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false),
        "refusal neither retakes H3 nor acknowledges a loss"
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
}

struct NoFrameBirths;
impl JointBirthEvidenceSource for NoFrameBirths {
    fn take_for(
        &mut self,
        _: &JointFeedTarget,
        _: &SemanticCallerBinding,
    ) -> Result<SessionBirthEvidence, BirthObservationRefusal> {
        panic!("collection-wide loss must fan out before any fresh per-domain birth");
    }
}

#[test]
fn joint_original_loss_fans_out_before_ack() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let original = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project()
        .objects;
    fixture.push_two("C_SignInit", 2);
    // Genuine H0 no-file refusal: ordinary bytes from the native END recipe,
    // with its actual descriptor removed only at the injected H0 I/O leaf.
    // H3 itself must produce the loss barrier; no scripted disposition/cut.
    let (_, ordinary) = fixture
        .scene
        .encoded(std::process::id(), 0, "C_SignFinal", 3);
    let slot = fixture.scene.real.h0.0.borrow().io.slot(0, "C_SignFinal");
    fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .io
        .endpoints
        .retain(|(index, _, _)| *index != slot);
    fixture
        .scene
        .drain
        .source_mut()
        .push_record(ordinary[24..392].to_vec());
    let mut frame = fixture.audited(3, 2, &BirthFault);
    let failure = frame
        .failure_for_test()
        .expect("actual finalizer loss is adjudicated once");
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::H3Loss
    );
    let voided = failure
        .h3_voided
        .expect("the original H3 barrier needs acknowledgement");
    for object in &original {
        assert!(failure.effects.effects.iter().any(|effect| matches!(effect, ObjectEffect::Retired { object: id, reason: ObjectGap::OutcomeLost } if *id == object.id)));
    }
    let effects = failure.effects.clone();
    let receipts = fixture.receipts();
    {
        let a = frame
            .audited_failure_for_test(receipts[0].domain())
            .unwrap();
        let b = frame
            .audited_failure_for_test(receipts[1].domain())
            .unwrap();
        assert!(
            std::ptr::eq(a.failure(), b.failure()),
            "both domains borrow the original failure, never recomputed scope/effects"
        );
        assert!(std::ptr::eq(a.h3(), b.h3()), "same original audit H3");
        assert!(a.identity() == frame.identity());
        assert_eq!(a.frontier(), frame.frontier());
    }
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut NoFrameBirths, &BirthFault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::LocalPending)
        );
        frame = match frame.finish_frame(&mut ports) {
            Err((original, reason)) => {
                assert_eq!(reason, RawQuantumRefusal::DispositionMismatch);
                original
            }
            Ok(_) => panic!("one consumer cannot acknowledge a collection-wide void"),
        };
    }
    assert_eq!(
        fixture.feeds().iter().filter(|feed| feed.degraded).count(),
        1
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
    assert_eq!(frame.failure_for_test().unwrap().effects, effects);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut NoFrameBirths, &BirthFault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::Complete)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::Complete)
        );
    }
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0,
        "delivery is not acknowledgement"
    );
    assert!(fixture.feeds().iter().all(|feed| feed.degraded
        && !feed.fallback
        && feed.reduced == 1
        && feed.staged == 0
        && feed.disposed == 1));
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame
            .finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| {
                panic!("both original loss deliveries complete: {reason:?}")
            });
    }
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        voided
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );
}

#[test]
fn joint_later_loss_precharges_newly_sealed_objects_before_mutation() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let before = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    let targets = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 2);
    for (index, target) in targets.iter().enumerate() {
        let pid = fixture
            .scene
            .real
            .scene
            .coordinator
            .semantic_bindings()
            .get(target.caller())
            .unwrap()
            .pin()
            .pid();
        fixture.push_distinct_create(pid, 2, 0x5000 + index as u64);
    }
    let fault = FrameFault::clean();
    let mut frame = fixture.audited(2, 2, &fault);
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut births, &fault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::LocalPending)
        );
    }
    let grown = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    assert_eq!(
        grown.objects.len(),
        before.objects.len() + 1,
        "first seal genuinely creates a new retained view"
    );
    let new_id = grown
        .objects
        .iter()
        .find(|object| !before.objects.iter().any(|old| old.id == object.id))
        .unwrap()
        .id;
    assert_eq!(grown.object(new_id).unwrap().lifetime, Lifetime::Live);
    let snapshot = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let hold = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes)
        .unwrap();
    let reads = fault.reads.get();
    fault.epoch.set(1);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert!(matches!(
            frame.seal_next(&mut ports, &mut births, &fault),
            Err(RawQuantumRefusal::Resource(_))
        ));
    }
    assert_eq!(
        fault.reads.get(),
        reads,
        "post-growth retained failure capacity is prepaid before audit/fault mutation"
    );
    assert_eq!(
        births.seen.len(),
        1,
        "capacity refusal does not select or reread a birth"
    );
    assert!(frame.failure_for_test().is_none());
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .model()
            .project()
            .object(new_id)
            .unwrap()
            .lifetime,
        Lifetime::Live
    );
    drop(hold);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut births, &fault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
    }
    let failure = frame.failure_for_test().unwrap();
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::FaultChanged
    );
    for object in &grown.objects {
        assert!(failure.effects.effects.iter().any(|effect| matches!(effect, ObjectEffect::Retired { object: id, reason: ObjectGap::OutcomeLost } if *id == object.id)), "late failure includes original and newly-created live views");
    }
    let effects = failure.effects.clone();
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::LocalPending)
        );
        assert_eq!(
            frame.seal_next(&mut ports, &mut NoFrameBirths, &fault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(
            frame.deliver_next(&mut ports),
            Ok(QuantumSealProgress::Complete)
        );
    }
    assert_eq!(frame.failure_for_test().unwrap().effects, effects);
    drop(births);
    let feeds = fixture.feeds();
    assert!(feeds.iter().all(|feed| feed.degraded && feed.staged == 0));
    assert_eq!(
        feeds
            .iter()
            .find(|feed| feed.id == targets[0].id())
            .unwrap()
            .reduced,
        2,
        "already delivered success is not replayed while its original loss fans out"
    );
    assert_eq!(
        feeds
            .iter()
            .find(|feed| feed.id == targets[1].id())
            .unwrap()
            .disposed,
        1
    );
    let mut ports = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_frame_ports(&fixture.scene.producers)
        .unwrap();
    frame
        .finish_frame(&mut ports)
        .unwrap_or_else(|(_, reason)| panic!("original later loss delivered to both: {reason:?}"));
}

#[test]
fn joint_frame_preflight_keeps_targets_and_birth_selection_on_retry() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    fixture.push_two("C_SignInit", 2);
    let fault = FrameFault::clean();
    let mut frame = fixture.audited(2, 2, &fault);
    let identity = frame.identity();
    let frontier = frame.frontier();
    let before = fixture.feeds();
    let foreign = SessionDrainProducers::test_pair(
        fixture.scene.producers.native_domain(),
        EventsDomain::test_standin(fixture.scene.producers.events_id()),
    );
    assert!(
        matches!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&foreign),
            Err(RawQuantumRefusal::ForeignCapture)
        ),
        "equal numeric map id cannot lend the retained Session port"
    );
    let snapshot = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let hold = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes)
        .unwrap();
    {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert!(matches!(
            frame.bind_targets(&ports),
            Err(RawQuantumRefusal::Resource(_))
        ));
    }
    assert_eq!(fixture.feeds(), before);
    assert!(frame.identity() == identity);
    assert_eq!(frame.frontier(), frontier);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        snapshot.limit_bytes,
        "refused target acquisition refunds its own attempt"
    );
    drop(hold);
    {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
    }
    let targets = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .collect::<Vec<_>>();
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    let snapshot = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let hold = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes)
        .unwrap();
    let reads = fault.reads.get();
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert!(matches!(
            frame.seal_next(&mut ports, &mut births, &fault),
            Err(RawQuantumRefusal::Resource(_))
        ));
    }
    assert_eq!(fault.reads.get(), reads);
    assert!(births.seen.is_empty());
    drop(hold);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert_eq!(targets.len(), 2);
        for (index, target) in targets.iter().enumerate() {
            assert_eq!(
                frame.seal_next(&mut ports, &mut births, &fault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(
                births.seen[index].0,
                target.id(),
                "a refused attempt cannot advance the typed subject"
            );
            assert_eq!(
                frame.deliver_next(&mut ports),
                Ok(if index == 0 {
                    QuantumSealProgress::LocalPending
                } else {
                    QuantumSealProgress::Complete
                })
            );
        }
        frame
            .finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| panic!("same originals retry after refund: {reason:?}"));
    }
    drop(births);
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.reduced == 2 && feed.staged == 0 && !feed.fallback && !feed.degraded)
    );
}

#[test]
fn joint_future_end_disposes_frame_without_disposing_call() {
    let mut previous_generation = None;
    for (b_begin_first, fallback_b) in [(false, false), (true, false), (false, true), (true, true)]
    {
        eprintln!("future-END arm: b_begin_first={b_begin_first}, fallback_b={fallback_b}");
        let mut fixture = CanonicalFanoutScene::prior_sealed();
        let generation = fixture.attached.generation();
        assert!(previous_generation.is_none_or(|previous| generation > previous));
        previous_generation = Some(generation);
        let a = std::process::id();
        let b = fixture._child.id();
        let (begin_a, end_a) = fixture.scene.encoded(a, 0, "C_SignInit", 2);
        let (begin_b, end_b) = fixture.scene.encoded(b, 0, "C_SignInit", 2);
        for begin in if b_begin_first {
            [begin_b, begin_a]
        } else {
            [begin_a, begin_b]
        } {
            fixture.scene.drain.source_mut().push_record(begin.to_vec());
        }
        fixture.scene.drain.source_mut().push_record(end_b.to_vec());
        let mut q1 = fixture.audited(1, 1, &BirthFault);
        assert!(q1.failure_for_test().is_none());
        let h0 = fixture.scene.real.h0.clone();
        let b_caller = fixture
            .feeds()
            .iter()
            .find(|feed| {
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .semantic_bindings()
                    .get(feed.caller)
                    .unwrap()
                    .pin()
                    .pid()
                    == b
            })
            .unwrap()
            .caller;
        let mut births = RefuseOneBirth {
            inner: NativeFrameBirths {
                h0: &h0,
                attached: &fixture.attached,
                retained: &mut fixture.births,
                seen: Vec::new(),
                unreadable: false,
            },
            refused: fallback_b.then_some(b_caller),
        };
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            q1.bind_targets(&ports).unwrap();
            let mut future = 0;
            let mut delivered = 0;
            for _ in 0..2 {
                match q1.seal_next(&mut ports, &mut births, &BirthFault).unwrap() {
                    QuantumSealProgress::AwaitFutureInput => future += 1,
                    QuantumSealProgress::DeliveryReady => {
                        delivered += 1;
                        assert!(matches!(
                            q1.deliver_next(&mut ports).unwrap(),
                            QuantumSealProgress::LocalPending
                                | QuantumSealProgress::AwaitFutureInput
                        ));
                    }
                    progress => panic!("unexpected q1 progress: {progress:?}"),
                }
            }
            assert_eq!((future, delivered), (1, 1));
            assert_eq!(
                q1.seal_next(&mut ports, &mut births, &BirthFault),
                Ok(QuantumSealProgress::AwaitFutureInput)
            );
        }
        drop(births);
        let starts = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test();
        assert_eq!(starts.len(), 1);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .retained_start_bytes_for_test((u64::from(a), 2)),
            Some(begin_a),
            "fallback retains the exact original incomplete START bytes"
        );
        assert_eq!(
            (starts[0].0, starts[0].1),
            (u64::from(a), 2),
            "the original actual A START remains unconverted"
        );
        fixture.scene.assert_claims(&[]);
        let roles = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test();
        assert_eq!(
            roles[..4],
            [0, 1, 0, 0],
            "q1 releases physical raw/H9 and keeps only original A H8 custody; associations have their own owners"
        );
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            q1.finish_frame(&mut ports).unwrap_or_else(|(_, reason)| {
                panic!("future genuine END releases only the completed frame: {reason:?}")
            });
        }
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .retained_starts_for_test(),
            starts
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test(),
            roles
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .retained_start_bytes_for_test((u64::from(a), 2)),
            Some(begin_a)
        );
        let before_b = fixture
            .feeds()
            .into_iter()
            .find(|feed| {
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .semantic_bindings()
                    .get(feed.caller)
                    .unwrap()
                    .pin()
                    .pid()
                    == b
            })
            .unwrap();
        assert_eq!((before_b.reduced, before_b.staged), (2, 0));
        assert_eq!(before_b.fallback, fallback_b);
        // The SAME original END arrives through the SAME actual consumer later.
        fixture.scene.drain.source_mut().push_record(end_a.to_vec());
        let mut q2 = fixture.audited(1, 1, &BirthFault);
        assert!(q2.failure_for_test().is_none());
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &fixture.attached,
            retained: &mut fixture.births,
            seen: Vec::new(),
            unreadable: false,
        };
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            q2.bind_targets(&ports).unwrap();
            let target_count = if fallback_b { 1 } else { 2 };
            for index in 0..target_count {
                assert_eq!(
                    q2.seal_next(&mut ports, &mut births, &BirthFault),
                    Ok(QuantumSealProgress::DeliveryReady)
                );
                assert_eq!(
                    q2.deliver_next(&mut ports),
                    Ok(if index + 1 < target_count {
                        QuantumSealProgress::LocalPending
                    } else {
                        QuantumSealProgress::Complete
                    })
                );
            }
            q2.finish_frame(&mut ports)
                .unwrap_or_else(|(_, reason)| panic!("actual later END settles once: {reason:?}"));
        }
        drop(births);
        assert!(fixture.feeds().iter().all(|feed| {
            feed.reduced == 2
                && feed.staged == 0
                && !feed.degraded
                && feed.fallback == (fallback_b && feed.id == before_b.id)
        }));
        assert_eq!(
            fixture
                .feeds()
                .into_iter()
                .find(|feed| feed.id == before_b.id)
                .unwrap(),
            before_b,
            "empty later work cannot replay or erase B"
        );
        assert!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .retained_starts_for_test()
                .is_empty()
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test()[..4],
            [0, 0, 0, 0]
        );
        fixture.scene.assert_claims(&[]);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_audit_state(),
            (3, false)
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_acknowledged_below(),
            0,
            "a future terminal wait never invents a loss void"
        );
    }
}

struct PendingH3Scene {
    fixture: CanonicalFanoutScene,
    frame: IngestedJointQuantum,
    child_c: OwnedStoppedChild,
    c_caller: CallerId,
    c_image: ImageIdentity,
    end_b: [u8; 632],
}

fn pending_h3_from_stash(
    unmatched_complete: bool,
    audit_fault: &impl crate::semantics_objects::journal::FaultEpoch,
) -> PendingH3Scene {
    pending_h3_with_sibling(unmatched_complete, false, audit_fault)
}

fn pending_h3_with_sibling(
    unmatched_complete: bool,
    dispose_sibling: bool,
    audit_fault: &impl crate::semantics_objects::journal::FaultEpoch,
) -> PendingH3Scene {
    pending_h3_with_sibling_before_audit(
        unmatched_complete,
        dispose_sibling,
        audit_fault,
        |_, _| {},
    )
}

fn pending_h3_with_sibling_before_audit(
    unmatched_complete: bool,
    dispose_sibling: bool,
    audit_fault: &impl crate::semantics_objects::journal::FaultEpoch,
    before_audit: impl FnOnce(&mut CanonicalFanoutScene, &IngestedRaw),
) -> PendingH3Scene {
    let mut fixture =
        CanonicalFanoutScene::prior_sealed_with_providers(if unmatched_complete { 2 } else { 1 });
    let a = std::process::id();
    let b = fixture._child.id();
    let child_c = OwnedStoppedChild::new();
    let c = child_c.id();
    let c_image = ImageIdentity {
        task_cookie: 73,
        exec_id: 0,
    };
    let c_caller = fixture.scene.real.bind(c, c_image, 0);
    let (begin_b, end_b) = fixture.scene.encoded(b, 0, "C_SignInit", 2);
    fixture.scene.push(a, 0, "C_SignInit", 2);
    fixture.scene.push(c, 0, "C_SignInit", 1);
    fixture
        .scene
        .drain
        .source_mut()
        .push_record(begin_b.to_vec());
    if unmatched_complete {
        let caller = fixture
            .births
            .iter()
            .find(|(caller, _, _)| {
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .semantic_bindings()
                    .get(*caller)
                    .unwrap()
                    .pin()
                    .pid()
                    == a
            })
            .unwrap()
            .0;
        fixture.scene.admit_providers(a, caller, &[1]);
        fixture.scene.push(a, 1, "C_SignInit", 3);
    }
    let mut raw = fixture.scene.collect_with_fault(&BirthFault);
    let first = {
        let mut h0 = fixture.scene.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *h0;
        io.script.fail_cookie = Some(c_image.task_cookie);
        let first = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(first.calls().count(), 1 + usize::from(unmatched_complete));
        assert_eq!(first.awaiting_floor(), Some(4));
        first
    };
    let first = SemanticBatch::from_tick_report(
        fixture.scene.real.lane.domain(),
        first,
        Vec::new(),
        now_ns(),
    )
    .unwrap();
    {
        let mut h0 = fixture.scene.real.h0.0.borrow_mut();
        let HeldH0 {
            capture, io, stash, ..
        } = &mut *h0;
        io.script.fail_cookie = None;
        // The actual original scan job owns the q1 birth cut. An empty
        // service of the SAME raw clears its actual pending disposition;
        // every resulting call/receipt moves into the existing lane stash.
        let mut completed = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(completed.calls().count(), 1);
        assert_eq!(completed.awaiting_floor(), None);
        assert_eq!(
            completed.allocated_below(),
            5 + u64::from(unmatched_complete)
        );
        assert_eq!(completed.calls().next().unwrap().position(), Some(4));
        assert_eq!(stash_refresh_report(stash, &mut completed).1, 0);
        assert_eq!(stash.min_outcome_position(), Some(4));
    }
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    coordinator.stage_semantic_batch(first);
    coordinator
        .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
        .unwrap();
    assert_eq!(
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .count(),
        1 + usize::from(unmatched_complete)
    );
    let mut ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| {
            panic!("the genuine same raw is now H0 disposed: {reason:?}")
        });
    let first_claim = coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
        .unwrap();
    assert_eq!(first_claim.0, 3);
    assert!(first_claim.1.is_ok());
    if unmatched_complete {
        assert_eq!(
            coordinator
                .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
                .unwrap(),
            Some((
                5,
                Err(crate::semantics_objects::journal::AttestationRefusal::ImageSealed)
            )),
            "late provider is genuinely admitted but cannot replace the already-sealed image key"
        );
    }
    assert!(
        coordinator
            .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
            .unwrap()
            .is_none()
    );
    let mut staged = 0;
    while if dispose_sibling {
        coordinator
            .stage_next_prepared_admission_with_disposition(&fixture.scene.producers, &mut ingested)
            .unwrap()
    } else {
        coordinator.stage_next_prepared_admission()
    } {
        staged += 1;
    }
    assert_eq!(staged, 1 + usize::from(unmatched_complete));
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    fixture
        .scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    before_audit(&mut fixture, &ingested);
    let q1 = acquire(&mut fixture.scene, ingested, &fixture.attached, audit_fault);

    PendingH3Scene {
        fixture,
        frame: q1,
        child_c,
        c_caller,
        c_image,
        end_b,
    }
}

/// Catches treating truthful acquired H3Pending as a permanent local retry.
/// The deferred call is an original collected END, resolved by its existing
/// H0 scan job and retained in the real lane stash; B also keeps a real START.
#[test]
fn joint_pending_h3_stash_disposes_frame_and_claims_original_in_next_quantum() {
    let PendingH3Scene {
        mut fixture,
        frame: mut q1,
        child_c,
        c_caller,
        c_image,
        end_b,
    } = pending_h3_from_stash(false, &BirthFault);
    let c = child_c.id();
    let b = fixture._child.id();
    assert_eq!(
        q1.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::H3Pending
    );
    assert!(matches!(
        q1.audit_for_test().h3_for_test(),
        H3DispositionEvidence::Clean {
            staged_max: 3,
            pending_floor: Some(4),
        }
    ));
    let before_feeds = fixture.feeds();
    let before_claims = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    assert_eq!(before_claims.0, 1);
    assert_eq!(
        before_claims
            .1
            .iter()
            .map(|(at, _)| *at)
            .collect::<Vec<_>>(),
        [3]
    );
    let before_roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    assert_eq!(before_roles[..4], [0, 3, 0, 1]);
    assert_eq!(
        crate::semantics_objects::journal::JournalAdapter::open_entry_size_for_test(),
        1208
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_open_charges_for_test(),
        [1208; 3]
    );
    let before_starts = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .retained_starts_for_test();
    assert_eq!(before_starts.len(), 3);
    let start_b = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .retained_start_bytes_for_test((u64::from(b), 2))
        .unwrap();
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q1.bind_targets(&ports).unwrap();
        let real_producers = h0.0.borrow().collected_producers.clone().unwrap();
        h0.0.borrow_mut().collected_producers = Some(SessionDrainProducers::test_pair(
            real_producers.native_domain(),
            crate::events::EventsDomain::test_standin(real_producers.events_id()),
        ));
        assert_eq!(
            q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
            Ok(QuantumSealProgress::LocalPending),
            "equal numeric EVENTS identity cannot grant a foreign allocation continuation"
        );
        h0.0.borrow_mut().collected_producers = Some(real_producers);
        let retained_outcomes = h0.0.borrow_mut().stash.take_outcomes();
        assert_eq!(
            q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
            Ok(QuantumSealProgress::LocalPending),
            "the old floor grants nothing after actual stash ownership moved"
        );
        assert_eq!(
            h0.0.borrow_mut()
                .stash
                .push_all(Vec::new(), retained_outcomes),
            0
        );
        for _ in 0..2 {
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::AwaitFutureInput)
            );
        }
        assert_eq!(
            q1.seal_next(&mut ports, &mut births, &BirthFault),
            Ok(QuantumSealProgress::AwaitFutureInput)
        );
        let (retained, reason) = q1
            .finish_frame(&mut ports)
            .err()
            .expect("generic finish has no continuation authority");
        assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
        q1 = retained;
        q1.finish_pending_h3(&mut ports, &fixture.scene.real.lane)
            .unwrap_or_else(|(_, reason)| {
                panic!("truthful producer-owned pending evidence must allow q2: {reason:?}")
            });
    }
    drop(births);
    assert_eq!(fixture.feeds(), before_feeds);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        before_claims
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        before_roles
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        before_starts
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_start_bytes_for_test((u64::from(b), 2)),
        Some(start_b)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );

    // q2 receives B's exact END and merges C's original Call/New. H0 ordinal
    // order is C=4, then B=5 even though the ring returns B before the merge.
    fixture.scene.drain.source_mut().push_record(end_b.to_vec());
    let raw = fixture.scene.collect_with_fault(&BirthFault);
    fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = fixture.scene.real.tick();
    fixture.scene.admit_providers(c, c_caller, &[0]);
    fixture.scene.prepare_batch(batch, 2);
    let admitted = fixture
        .scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        admitted
            .iter()
            .map(|input| input.h0_ordinal())
            .collect::<Vec<_>>(),
        [4, 5]
    );
    let current = fixture
        .scene
        .real
        .scene
        .coordinator
        .take_prepared_current_for_birth_test()
        .unwrap();
    let current_c = current
        .into_iter()
        .find(|receipt| receipt.image() == c_image)
        .unwrap();
    let raw = fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .collected
        .take()
        .unwrap();
    let ingested = raw
        .ingest(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("actual next raw: {reason:?}"));
    assert!(
        !ingested.matches_admission(&admitted[0]),
        "C is still the actual q1 allocation"
    );
    assert!(
        ingested.matches_retained_admission(
            &admitted[0],
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
        )
    );
    let claims = claim_and_finish(&mut fixture.scene, &ingested);
    assert!(
        !ingested.matches_retained_admission(
            &admitted[0],
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
        ),
        "the original is claimed at most once"
    );
    assert_eq!(claims.iter().map(|(at, _)| *at).collect::<Vec<_>>(), [4, 5]);
    let actual_claims = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    assert_eq!(actual_claims.0, 3);
    assert_eq!(
        actual_claims
            .1
            .iter()
            .map(|(at, _)| *at)
            .collect::<Vec<_>>(),
        [3, 4, 5]
    );
    fixture.retain_collected_birth(&admitted[0], current_c, claims[0].1);
    fixture
        .scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    let mut q2 = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    assert!(q2.failure_for_test().is_none());
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q2.bind_targets(&ports).unwrap();
        for remaining in [2, 1, 0] {
            assert_eq!(
                q2.seal_next(&mut ports, &mut births, &BirthFault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(
                q2.deliver_next(&mut ports),
                Ok(if remaining == 0 {
                    QuantumSealProgress::Complete
                } else {
                    QuantumSealProgress::LocalPending
                })
            );
        }
        q2.finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| panic!("originals settle once: {reason:?}"));
    }
    drop(births);
    assert_eq!(
        fixture.feeds().iter().map(|feed| feed.reduced).sum::<u64>(),
        5
    );
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.staged == 0 && !feed.degraded && !feed.fallback)
    );
    fixture.scene.assert_claims(&[]);
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test()
            .is_empty()
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test()[..4],
        [0, 0, 0, 0]
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (3, false)
    );
}

#[test]
fn joint_pending_h3_keeps_unmatched_complete_original_local() {
    let PendingH3Scene {
        mut fixture,
        frame: mut q1,
        child_c: _child_c,
        c_caller: _,
        c_image: _,
        end_b: _,
    } = pending_h3_from_stash(true, &BirthFault);
    assert_eq!(
        q1.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::H3Pending
    );
    assert!(matches!(
        q1.audit_for_test().h3_for_test(),
        H3DispositionEvidence::Clean {
            staged_max: 5,
            pending_floor: Some(4),
        }
    ));
    let before_feeds = fixture.feeds();
    let owner = fixture.scene.real.scene.coordinator.joint_capture();
    let claims = owner.adapter().invocation_claims_for_test();
    let starts = owner.adapter().retained_starts_for_test();
    let roles = owner.ledger().roles_for_test();
    assert_eq!(starts.len(), 4);
    assert_eq!(claims.0, 1);
    assert_eq!(roles[..4], [0, 4, 0, 1]);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q1.bind_targets(&ports).unwrap();
        for _ in 0..2 {
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::LocalPending)
            );
        }
        let (same, reason) = q1
            .finish_pending_h3(&mut ports, &fixture.scene.real.lane)
            .err()
            .expect("a truthful floor cannot forgive an unrelated completed original");
        assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
        q1 = same;
        assert!(q1.finish_frame(&mut ports).is_err());
    }
    assert_eq!(fixture.feeds(), before_feeds);
    let owner = fixture.scene.real.scene.coordinator.joint_capture();
    assert_eq!(owner.adapter().invocation_claims_for_test(), claims);
    assert_eq!(owner.adapter().retained_starts_for_test(), starts);
    assert_eq!(owner.ledger().roles_for_test(), roles);
    assert_eq!(
        fixture
            .scene
            .real
            .h0
            .0
            .borrow()
            .stash
            .min_outcome_position(),
        Some(4)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
}

#[test]
fn joint_pending_h3_continuation_cannot_forgive_native_fault() {
    struct ChangedFault;
    impl crate::semantics_objects::journal::FaultEpoch for ChangedFault {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            Ok(1)
        }
    }
    let PendingH3Scene {
        mut fixture,
        frame: mut q1,
        child_c: _child_c,
        c_caller: _,
        c_image: _,
        end_b: _,
    } = pending_h3_from_stash(false, &ChangedFault);
    let original = q1.failure_for_test().unwrap();
    assert_eq!(
        original.gap,
        crate::semantics_objects::journal::JournalGap::FaultChanged
    );
    assert!(
        !original.effects.effects.is_empty(),
        "the same two original live objects must produce actual loss effects"
    );
    let effects = original.effects.clone();
    let roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q1.bind_targets(&ports).unwrap();
        assert_eq!(
            q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
            Ok(QuantumSealProgress::LocalPending)
        );
        assert_eq!(q1.failure_for_test().unwrap().effects, effects);
        let (same, reason) = q1
            .finish_pending_h3(&mut ports, &fixture.scene.real.lane)
            .err()
            .expect("a real pending owner never changes an original fault into Future");
        assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
        q1 = same;
    }
    assert_eq!(q1.failure_for_test().unwrap().effects, effects);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        roles
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
}

#[test]
fn joint_first_pending_h3_pins_native_baseline_before_next_fault() {
    // This owner has never acquired a healthy audit or sealed a model call.
    // A's genuine New still registers one Joint consumer before its first
    // pending audit; C's original remains in the same real lane stash.
    let mut scene = JointScene::for_audit(1);
    scene.real.h0.0.borrow_mut().io.script.local = 1;
    let a = std::process::id();
    let child_b = OwnedStoppedChild::new();
    let child_c = OwnedStoppedChild::new();
    let a_caller = scene.real.bind(
        a,
        ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        },
        0,
    );
    scene.real.bind(
        child_b.id(),
        ImageIdentity {
            task_cookie: 72,
            exec_id: 0,
        },
        0,
    );
    let c_image = ImageIdentity {
        task_cookie: 73,
        exec_id: 0,
    };
    scene.real.bind(child_c.id(), c_image, 0);
    scene.push(a, 0, "C_SignInit", 1);
    scene.push(child_c.id(), 0, "C_SignInit", 1);
    let begin_b = scene.encoded(child_b.id(), 0, "C_SignInit", 1).0;
    scene.drain.source_mut().push_record(begin_b.to_vec());
    let mut raw = scene.collect_with_fault(&BirthFault);
    let first = {
        let mut h0 = scene.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *h0;
        io.script.fail_cookie = Some(c_image.task_cookie);
        let first = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(first.calls().count(), 1);
        assert_eq!(first.awaiting_floor(), Some(2));
        first
    };
    let batch =
        SemanticBatch::from_tick_report(scene.real.lane.domain(), first, Vec::new(), now_ns())
            .unwrap();
    scene.admit_providers(a, a_caller, &[0]);
    {
        let mut h0 = scene.real.h0.0.borrow_mut();
        let HeldH0 {
            capture,
            io,
            stash,
            collected_producers,
            ..
        } = &mut *h0;
        *collected_producers = Some(raw.producers_for_test().clone());
        io.script.fail_cookie = None;
        let mut completed = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(completed.calls().next().unwrap().position(), Some(2));
        assert_eq!(completed.awaiting_floor(), None);
        assert_eq!(stash_refresh_report(stash, &mut completed).1, 0);
    }
    scene.real.scene.coordinator.stage_semantic_batch(batch);
    scene
        .real
        .scene
        .coordinator
        .prepare_staged_semantic_batch(&mut scene.real.lane, None)
        .unwrap();
    let admitted = scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .next()
        .unwrap()
        .clone();
    let current = scene
        .real
        .scene
        .coordinator
        .take_prepared_current_for_birth_test()
        .unwrap()
        .into_iter()
        .find(|receipt| receipt.image() == admitted.journal_binding().1)
        .unwrap();
    let (ingested, proof, grant) = scene.ingest_with_grant(raw);
    assert_eq!(claim_and_finish(&mut scene, &ingested).len(), 1);
    let attached = attachment(&mut scene);
    assert!(
        scene
            .real
            .scene
            .coordinator
            .joint_capture_mut()
            .adapter_mut()
            .install_closure_grant(&SessionClosureGrant::observe(&attached))
    );
    let published_before = crate::inventory_present::Presentation::capture(
        &scene.real.scene.coordinator,
        "system",
        1,
        2,
        1,
    );
    let mut fixture = CanonicalFanoutScene {
        scene,
        attached,
        births: Vec::new(),
        grant,
        published_before,
        _child: child_b,
    };
    fixture.retain_collected_birth(&admitted, current, proof);
    fixture
        .scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    let mut q1 = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    assert_eq!(
        q1.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::H3Pending
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .fault_baseline_for_test(),
        None
    );
    let roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    let claims = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        q1.bind_targets(&ports).unwrap();
        assert_eq!(
            q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
            Ok(QuantumSealProgress::AwaitFutureInput)
        );
        q1.finish_pending_h3(&mut ports, &fixture.scene.real.lane)
            .unwrap_or_else(|(_, reason)| panic!("actual first pending frame: {reason:?}"));
    }
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .fault_baseline_for_test(),
        Some(0)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        roles
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        claims
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
    struct ChangedFault;
    impl crate::semantics_objects::journal::FaultEpoch for ChangedFault {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            Ok(1)
        }
    }
    fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .io
        .script
        .last_health
        .fault = 1;
    let raw = fixture.scene.collect_with_fault(&ChangedFault);
    fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = fixture.scene.real.tick();
    fixture
        .scene
        .real
        .scene
        .coordinator
        .stage_semantic_batch(batch);
    fixture
        .scene
        .real
        .scene
        .coordinator
        .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
        .unwrap();
    let raw = fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .collected
        .take()
        .unwrap();
    let ingested = raw
        .ingest(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("genuine q2 fault collection: {reason:?}"));
    while fixture
        .scene
        .real
        .scene
        .coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
        .is_some()
    {}
    while fixture
        .scene
        .real
        .scene
        .coordinator
        .stage_next_prepared_admission()
    {}
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&fixture.scene.real.lane)
    );
    fixture
        .scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    let q2 = acquire(
        &mut fixture.scene,
        ingested,
        &fixture.attached,
        &ChangedFault,
    );
    assert_eq!(
        q2.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::FaultChanged
    );
}

struct ZeroHeadPendingScene {
    fixture: CanonicalFanoutScene,
    frame: IngestedJointQuantum,
    caller: CallerId,
    image: ImageIdentity,
}

fn first_pending_h3_without_joint_head() -> ZeroHeadPendingScene {
    let (held, subset) = HeldProviders::with_attachment(
        1,
        &[
            "C_GetSessionInfo",
            "C_SignInit",
            "C_SignUpdate",
            "C_SignFinal",
        ],
    );
    let mut scene = JointScene::from_held(held, Some(subset));
    scene.real.h0.0.borrow_mut().io.script.local = 1;
    let a = std::process::id();
    scene.bind(
        a,
        ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        },
        &[0],
    );
    // The actual ordinary allowlisted GetSessionInfo establishes the native
    // Session association on direct S1. It has no journal invocation, grants
    // no birth, and is proved irrelevant before its original raw is disposed.
    let mut quiet = scene.encoded(a, 0, "C_GetSessionInfo", 1).1;
    // Ordinary synchronous CALL uses the real producer's no-async-target
    // sentinel. Canonical admission, never this scalar, proves irrelevance.
    quiet[24 + 108..24 + 112].copy_from_slice(&u32::MAX.to_le_bytes());
    scene
        .drain
        .source_mut()
        .push_record(quiet[24..392].to_vec());
    let mut raw = scene.prepare(1);
    let input = scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .next()
        .unwrap()
        .clone();
    assert_eq!(input.s1_facts().function, "C_GetSessionInfo");
    raw.classify_ordinary(&input).unwrap();
    let grant = SessionDrainGrant::observe(&scene.producers, &input).unwrap();
    let owner = scene.real.scene.coordinator.joint_capture_mut();
    owner.adapter_mut().bind_admitted_key(&input).unwrap();
    owner.adapter_mut().bind_session_drain(&grant).unwrap();
    let disposed = raw
        .dispose_without_ingest(
            owner,
            &scene.producers,
            crate::semantics_objects::journal::joint_driver::RawDisposeReason::NoAdmission,
        )
        .unwrap_or_else(|(_, reason)| panic!("actual quiet direct-S1 raw: {reason:?}"));
    assert!(disposed.failure().is_none());
    scene.real.scene.coordinator.dispose_prepared_claims_s1();
    assert!(scene.real.scene.coordinator.stage_next_prepared_admission());
    assert!(!scene.real.scene.coordinator.stage_next_prepared_admission());
    assert!(
        scene
            .real
            .scene
            .coordinator
            .finish_prepared_semantic_batch(&scene.real.lane)
    );
    scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut scene.real.lane))
        .unwrap();
    assert_eq!(
        scene
            .real
            .scene
            .coordinator
            .registry()
            .joint_feed_targets()
            .count(),
        0
    );
    assert_eq!(scene.real.scene.coordinator.reference_h3_audit_state().0, 0);
    assert_eq!(
        scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .fault_baseline_for_test(),
        None
    );
    drop(disposed);

    let child = OwnedStoppedChild::new();
    let image = ImageIdentity {
        task_cookie: 73,
        exec_id: 0,
    };
    let caller = scene.real.bind(child.id(), image, 0);
    scene.push(child.id(), 0, "C_SignInit", 1);
    let mut raw = scene.collect_with_fault(&BirthFault);
    let first = {
        let mut h0 = scene.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *h0;
        io.script.fail_cookie = Some(image.task_cookie);
        let first = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(first.calls().count(), 0);
        assert_eq!(first.awaiting_floor(), Some(2));
        first
    };
    let batch =
        SemanticBatch::from_tick_report(scene.real.lane.domain(), first, Vec::new(), now_ns())
            .unwrap();
    {
        let mut h0 = scene.real.h0.0.borrow_mut();
        let HeldH0 {
            capture, io, stash, ..
        } = &mut *h0;
        io.script.fail_cookie = None;
        let mut completed = capture.tick_collected_with(io, &mut raw).unwrap();
        assert_eq!(completed.calls().next().unwrap().position(), Some(2));
        assert_eq!(completed.awaiting_floor(), None);
        assert_eq!(stash_refresh_report(stash, &mut completed).1, 0);
    }
    let coordinator = &mut scene.real.scene.coordinator;
    coordinator.stage_semantic_batch(batch);
    coordinator
        .prepare_staged_semantic_batch(&mut scene.real.lane, None)
        .unwrap();
    assert_eq!(
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .count(),
        0
    );
    let ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &scene.producers,
            &grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("actual no-head pending original: {reason:?}"));
    assert!(
        coordinator
            .claim_next_prepared_admission(&scene.producers, &ingested)
            .unwrap()
            .is_none()
    );
    assert!(!coordinator.stage_next_prepared_admission());
    assert!(coordinator.finish_prepared_semantic_batch(&scene.real.lane));
    coordinator
        .commit_batch_with_semantics(false, Some(&mut scene.real.lane))
        .unwrap();
    let attached = attachment(&mut scene);
    let published_before = crate::inventory_present::Presentation::capture(
        &scene.real.scene.coordinator,
        "system",
        1,
        2,
        1,
    );
    let mut fixture = CanonicalFanoutScene {
        scene,
        attached,
        births: Vec::new(),
        grant,
        published_before,
        _child: child,
    };
    let frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    assert_eq!(
        frame.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::H3Pending
    );
    assert!(matches!(
        frame.audit_for_test().h3_for_test(),
        H3DispositionEvidence::Clean {
            staged_max: 1,
            pending_floor: Some(2),
        }
    ));
    ZeroHeadPendingScene {
        fixture,
        frame,
        caller,
        image,
    }
}

#[test]
fn joint_zero_head_pending_h3_requires_original_continuation_and_keeps_fault_prefix() {
    for changed_fault in [false, true] {
        let ZeroHeadPendingScene {
            mut fixture,
            mut frame,
            caller,
            image,
        } = first_pending_h3_without_joint_head();
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .joint_feed_targets()
                .count(),
            0
        );
        let owner = fixture.scene.real.scene.coordinator.joint_capture();
        let starts = owner.adapter().retained_starts_for_test();
        let claims = owner.adapter().invocation_claims_for_test();
        let roles = owner.ledger().roles_for_test();
        assert_eq!(starts.len(), 1);
        assert_eq!(claims.0, 0);
        assert_eq!(roles[..4], [0, 1, 0, 0]);
        assert_eq!(owner.adapter().fault_baseline_for_test(), None);
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            frame.bind_targets(&ports).unwrap();
            let (same, reason) = frame.finish_frame(&mut ports).err().expect(
                "zero eligible heads do not forgive actual pending H3 or its native prefix",
            );
            assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
            frame = same;
        }
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .fault_baseline_for_test(),
            None,
            "generic refusal preserves the first native baseline"
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test(),
            roles
        );
        let retained_outcomes = fixture.scene.real.h0.0.borrow_mut().stash.take_outcomes();
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            let (same, reason) = frame
                .finish_pending_h3(&mut ports, &fixture.scene.real.lane)
                .err()
                .expect("a zero-head finish still needs actual stash ownership");
            assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
            frame = same;
        }
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .fault_baseline_for_test(),
            None
        );
        assert_eq!(
            fixture
                .scene
                .real
                .h0
                .0
                .borrow_mut()
                .stash
                .push_all(Vec::new(), retained_outcomes),
            0
        );
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            // Explicit disposal must revalidate the actual owner even when
            // no domain consumer needed a separate defer operation.
            frame
                .finish_pending_h3(&mut ports, &fixture.scene.real.lane)
                .unwrap_or_else(|(_, reason)| {
                    panic!("actual zero-head continuation progresses: {reason:?}")
                });
        }
        let owner = fixture.scene.real.scene.coordinator.joint_capture();
        assert_eq!(owner.adapter().retained_starts_for_test(), starts);
        assert_eq!(owner.adapter().invocation_claims_for_test(), claims);
        assert_eq!(owner.ledger().roles_for_test(), roles);
        assert_eq!(owner.adapter().fault_baseline_for_test(), Some(0));
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_audit_state(),
            (1, false)
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_acknowledged_below(),
            0
        );
        struct NextFault(bool);
        impl crate::semantics_objects::journal::FaultEpoch for NextFault {
            fn fault_epoch(
                &self,
            ) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
                Ok(u64::from(self.0))
            }
        }
        fixture
            .scene
            .real
            .h0
            .0
            .borrow_mut()
            .io
            .script
            .last_health
            .fault = u64::from(changed_fault);
        let fault = NextFault(changed_fault);
        let raw = fixture.scene.collect_with_fault(&fault);
        fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
        let batch = fixture.scene.real.tick();
        if !changed_fault {
            fixture
                .scene
                .admit_providers(fixture._child.id(), caller, &[0]);
        }
        let coordinator = &mut fixture.scene.real.scene.coordinator;
        coordinator.stage_semantic_batch(batch);
        coordinator
            .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
            .unwrap();
        let admitted = coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].h0_ordinal(), 2);
        let current = coordinator.take_prepared_current_for_birth_test().unwrap();
        let raw = fixture
            .scene
            .real
            .h0
            .0
            .borrow_mut()
            .collected
            .take()
            .unwrap();
        let ingested = raw
            .ingest(
                coordinator.joint_capture_mut().adapter_mut(),
                &fixture.scene.producers,
                &fixture.grant,
            )
            .unwrap_or_else(|(_, reason)| panic!("actual zero-head q2: {reason:?}"));
        let mut q2_proof = None;
        while let Some((ordinal, proof)) = coordinator
            .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
            .unwrap()
        {
            let owner = coordinator.joint_capture();
            assert_eq!(owner.adapter().retained_starts_for_test(), starts);
            assert_eq!(ordinal, 2);
            let proof = proof.expect("the same retained original claims before audit");
            assert_eq!(
                owner.adapter().invocation_claims_for_test(),
                (1, vec![(2, proof)])
            );
            assert_eq!(owner.ledger().roles_for_test()[..4], [0, 1, 0, 0]);
            assert!(q2_proof.replace(proof).is_none());
        }
        let proof = q2_proof.expect("the original is claimed exactly once in either arm");
        while coordinator.stage_next_prepared_admission() {}
        assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
        // A retained claim corroborates the original before the collection
        // audit. Only the healthy arm may establish birth and a Joint feed.
        if !changed_fault {
            let original_new = current
                .into_iter()
                .find(|receipt| receipt.image() == image)
                .unwrap();
            fixture.retain_collected_birth(&admitted[0], original_new, proof);
        }
        fixture
            .scene
            .real
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
            .unwrap();
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .adapter()
                .fault_baseline_for_test(),
            Some(0),
            "claiming and staging never forgive the original native prefix"
        );
        let before_audit = fixture.feeds();
        let mut q2 = acquire(&mut fixture.scene, ingested, &fixture.attached, &fault);
        if changed_fault {
            assert_eq!(
                q2.failure_for_test().unwrap().gap,
                crate::semantics_objects::journal::JournalGap::FaultChanged
            );
            assert!(fixture.births.is_empty());
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .registry()
                    .joint_feed_targets()
                    .count(),
                0
            );
            assert_eq!(fixture.feeds(), before_audit);
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .reference_h3_audit_state(),
                (2, false)
            );
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .reference_h3_acknowledged_below(),
                0
            );
            continue;
        }
        assert!(q2.failure_for_test().is_none());
        let h0 = fixture.scene.real.h0.clone();
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &fixture.attached,
            retained: &mut fixture.births,
            seen: Vec::new(),
            unreadable: false,
        };
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            q2.bind_targets(&ports).unwrap();
            assert_eq!(
                q2.seal_next(&mut ports, &mut births, &fault),
                Ok(QuantumSealProgress::DeliveryReady)
            );
            assert_eq!(
                q2.deliver_next(&mut ports),
                Ok(QuantumSealProgress::Complete)
            );
            q2.finish_frame(&mut ports).unwrap_or_else(|(_, reason)| {
                panic!("actual first useful domain settles: {reason:?}")
            });
        }
        drop(births);
        let target = fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .joint_feed_targets()
            .next()
            .unwrap();
        assert_eq!(target.caller(), caller);
        assert!(fixture.feeds().iter().any(|feed| feed.caller == caller
            && !feed.fallback
            && feed.reduced == 1
            && feed.staged == 0));
        fixture.scene.assert_claims(&[]);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test()[..4],
            [0, 0, 0, 0]
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_audit_state(),
            (2, false)
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_acknowledged_below(),
            0
        );
    }
}

/// The same actual collector, owner, model and frame used above; this gate
/// observes conversion only. Multi-call H9 delivery deliberately stays held.
struct ObservationWire {
    label: &'static str,
    begin: [u8; 224],
    end: [u8; 632],
}

/// An omitted empty transition, a guessed call index, or a reordered effect
/// range must fail at the same original seal H9 will eventually borrow.
fn assert_original_replay_partition(seal: &crate::semantics_objects::journal::SealSuccess) {
    use crate::semantics_objects::journal::SealReplayPhase;
    let mut next = 0;
    for step in seal.prefix.replay_steps() {
        let range = step.effect_range();
        assert_eq!(range.start, next, "steps partition the original buffer");
        assert!(range.end >= range.start && range.end <= seal.effects.effects.len());
        let original = &seal.effects.effects[range.clone()];
        let borrowed = seal.effects_for_step(step).unwrap();
        assert_eq!(borrowed, original);
        assert_eq!(borrowed.as_ptr(), original.as_ptr(), "no cloned facts");
        if matches!(
            step.phase(),
            SealReplayPhase::Begin | SealReplayPhase::End | SealReplayPhase::BoundedLoss
        ) {
            let call = seal
                .prefix
                .call_for_step(step)
                .expect("original call index");
            assert!(seal.prefix.replay_calls().contains(call));
            if step.phase() == SealReplayPhase::BoundedLoss {
                assert!(call.abandoned && call.end_cut.is_none());
                assert!(step.cut().is_some(), "actual corroborated loss bound");
            } else {
                assert_eq!(
                    step.cut(),
                    if step.phase() == SealReplayPhase::End {
                        call.end_cut
                    } else {
                        Some(call.begin_cut)
                    }
                );
            }
        } else {
            assert!(seal.prefix.call_for_step(step).is_none());
        }
        next = range.end;
    }
    assert_eq!(next, seal.effects.effects.len());
}

fn observation_wire(
    fixture: &CanonicalFanoutScene,
    pid: u32,
    label: &'static str,
    function: &'static str,
    sequence: u64,
) -> ObservationWire {
    use crate::semantics_objects::journal::tests::{end_bytes_getattr, end_bytes_result};
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_ACTION_DESTROY, OBJECT_ACTION_SET,
    };
    let (mut begin, _) = fixture.scene.encoded(pid, 0, function, sequence);
    // A fresh handle, distinct from both prior-sealed fixture objects. The
    // END builders copy this exact original argument/status into their tails.
    if matches!(
        function,
        "C_SignInit" | "C_GetAttributeValue" | "C_SetAttributeValue" | "C_DestroyObject"
    ) {
        begin[88..96].copy_from_slice(&0x5151u64.to_le_bytes());
        begin[126] = 1;
    }
    let end = match function {
        "C_CreateObject" => {
            end_bytes_result(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 10, 0x5151)
        }
        "C_GetAttributeValue" => end_bytes_getattr(
            &begin,
            0,
            ENTRY_NS + 10,
            &[
                (1, 1, 3),
                (2, 1, 0),
                (5, 1, if label == "metadata" { 2048 } else { 4096 }),
            ],
        ),
        "C_SetAttributeValue" => end_bytes(&begin, OBJECT_ACTION_SET, 0, ENTRY_NS + 10),
        "C_DestroyObject" => end_bytes(&begin, OBJECT_ACTION_DESTROY, 0, ENTRY_NS + 10),
        "C_SignInit" => end_bytes(&begin, OBJECT_ACTION_ACCESS, 0, ENTRY_NS + 10),
        _ => end_bytes_absent(&begin, 0, ENTRY_NS + 10),
    };
    ObservationWire { label, begin, end }
}

/// Route these exact physical originals through the existing H0 validator,
/// sorted admission handoff, raw owner, claims and one real collection audit.
fn prepare_wire_frame(
    fixture: &mut CanonicalFanoutScene,
    wires: &[ObservationWire],
    physical: &[(usize, bool)],
    reverse_delivery: bool,
) -> (IngestedJointQuantum, Vec<(u64, u64)>, u64) {
    for (index, terminal) in physical {
        fixture.scene.drain.source_mut().push_record(if *terminal {
            wires[*index].end.to_vec()
        } else {
            wires[*index].begin.to_vec()
        });
    }
    let mut raw = fixture.scene.collect_with_fault(&BirthFault);
    let mut report = {
        let mut h0 = fixture.scene.real.h0.0.borrow_mut();
        let HeldH0 { capture, io, .. } = &mut *h0;
        capture.tick_collected_with(io, &mut raw).unwrap()
    };
    assert_eq!(report.calls().count(), wires.len());
    assert_eq!(report.awaiting_floor(), None);
    assert_eq!(report.shed_floor(), None);
    let originals: Vec<_> = report
        .calls()
        .map(|call| {
            (
                call.position().unwrap(),
                call.collected_origin().unwrap(),
                call.record().event.ts_ns,
            )
        })
        .collect();
    let base_admission = originals.iter().map(|entry| entry.0).min().unwrap();
    let watermark = report.allocated_below();
    if reverse_delivery {
        let mut original_outcomes = report.take_outcomes();
        original_outcomes.reverse();
        assert_eq!(report.merge_stashed_outcomes(original_outcomes), 0);
    }
    let mut after: Vec<_> = report
        .calls()
        .map(|call| {
            (
                call.position().unwrap(),
                call.collected_origin().unwrap(),
                call.record().event.ts_ns,
            )
        })
        .collect();
    after.sort_by_key(|entry| entry.0);
    let mut before = originals;
    before.sort_by_key(|entry| entry.0);
    assert_eq!(after, before, "delivery never remints original H0 identity");
    assert_eq!(report.allocated_below(), watermark);
    let batch = SemanticBatch::from_tick_report(
        fixture.scene.real.lane.domain(),
        report,
        Vec::new(),
        now_ns(),
    )
    .unwrap();
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    coordinator.stage_semantic_batch(batch);
    coordinator
        .prepare_staged_semantic_batch(&mut fixture.scene.real.lane, None)
        .unwrap();
    let admissions: Vec<_> = coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .map(|input| (input.h0_ordinal(), input.s1_facts().ts_ns))
        .collect();
    assert_eq!(
        admissions.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        (base_admission..watermark).collect::<Vec<_>>()
    );
    let ingested = raw
        .ingest(
            coordinator.joint_capture_mut().adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("original observation raw: {reason:?}"));
    assert_eq!(
        claim_and_finish(&mut fixture.scene, &ingested).len(),
        wires.len()
    );
    fixture
        .scene
        .real
        .scene
        .coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    let frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    assert!(frame.failure_for_test().is_none());
    (frame, admissions, base_admission)
}

fn with_genuine_settlement_order(
    late_metadata: bool,
    mut after_observation: impl FnMut(
        &mut CanonicalFanoutScene,
        &mut IngestedJointQuantum,
        JointFeedTarget,
    ) -> bool,
) {
    use crate::semantics_key_use::KeyUseReducer;
    use crate::semantics_objects::{KeyLabel, trace_settlement_for_test};
    use pkcs11_types::CkRv;
    let mut completion_tuples = Vec::new();
    for reverse_end in [false, true] {
        let mut delivery_tuple = None;
        for reverse_delivery in [false, true] {
            let mut fixture = CanonicalFanoutScene::prior_sealed_with_functions(
                1,
                &[
                    "C_CreateObject",
                    "C_GetAttributeValue",
                    "C_SetAttributeValue",
                    "C_DestroyObject",
                    "C_SignInit",
                    "C_SignUpdate",
                    "C_SignFinal",
                ],
            );
            let target = fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .joint_feed_targets()
                .min_by_key(JointFeedTarget::id)
                .unwrap();
            let primary = if fixture.births[0].0 == target.caller() {
                std::process::id()
            } else {
                fixture._child.id()
            };
            let peer = if primary == std::process::id() {
                fixture._child.id()
            } else {
                std::process::id()
            };
            let mut wires = Vec::new();
            let mut physical = Vec::new();
            let init_sequence = if late_metadata { 3 } else { 4 };
            {
                let mut pair = |wire: ObservationWire| {
                    let index = wires.len();
                    physical.push((index, false));
                    physical.push((index, true));
                    wires.push(wire);
                };
                pair(observation_wire(
                    &fixture,
                    primary,
                    "create",
                    "C_CreateObject",
                    2,
                ));
                if !late_metadata {
                    pair(observation_wire(
                        &fixture,
                        primary,
                        "metadata",
                        "C_GetAttributeValue",
                        3,
                    ));
                }
            }
            let init_index = wires.len();
            let mut init = observation_wire(&fixture, primary, "init", "C_SignInit", init_sequence);
            let mut independent =
                observation_wire(&fixture, peer, "independent", "C_SignUpdate", 2);
            // Two different retained physical threads/images overlap, while
            // Init still finishes before any dependent metadata mutation.
            let entry = u64::from_le_bytes(init.begin[48..56].try_into().unwrap());
            independent.begin[48..56].copy_from_slice(&(entry + 1).to_le_bytes());
            init.end = end_bytes(
                &init.begin,
                OBJECT_ACTION_ACCESS,
                CkRv::OK.0,
                ENTRY_NS + if reverse_end { 20 } else { 10 },
            );
            independent.end = end_bytes_absent(
                &independent.begin,
                CkRv::OK.0,
                ENTRY_NS + if reverse_end { 9 } else { 19 },
            );
            assert_ne!(&init.begin[8..24], &independent.begin[8..24]);
            wires.push(init);
            wires.push(independent);
            physical.extend([(init_index, false), (init_index + 1, false)]);
            if reverse_end {
                physical.extend([(init_index + 1, true), (init_index, true)]);
            } else {
                physical.extend([(init_index, true), (init_index + 1, true)]);
            }
            let mut sequence = init_sequence + 1;
            if late_metadata {
                let index = wires.len();
                wires.push(observation_wire(
                    &fixture,
                    primary,
                    "metadata",
                    "C_GetAttributeValue",
                    sequence,
                ));
                physical.extend([(index, false), (index, true)]);
                sequence += 1;
            }
            for (label, name) in [
                ("conflict", "C_GetAttributeValue"),
                ("invalidate", "C_SetAttributeValue"),
                ("destroy", "C_DestroyObject"),
                ("reuse", "C_CreateObject"),
                ("replacement_metadata", "C_GetAttributeValue"),
                ("final", "C_SignFinal"),
            ] {
                let index = wires.len();
                wires.push(observation_wire(&fixture, primary, label, name, sequence));
                physical.extend([(index, false), (index, true)]);
                sequence += 1;
            }
            assert_eq!(wires.len(), 10);
            let (mut frame, admissions, base_admission) =
                prepare_wire_frame(&mut fixture, &wires, &physical, reverse_delivery);
            let feeds_before = fixture.feeds();
            let h0 = fixture.scene.real.h0.clone();
            let mut births = NativeFrameBirths {
                h0: &h0,
                attached: &fixture.attached,
                retained: &mut fixture.births,
                seen: Vec::new(),
                unreadable: false,
            };
            let trace = {
                let mut ports = fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_frame_ports(&fixture.scene.producers)
                    .unwrap();
                frame.bind_targets(&ports).unwrap();
                let (progress, trace) =
                    trace_settlement_for_test(target.bootstrap().domain(), || {
                        frame.seal_next(&mut ports, &mut births, &BirthFault)
                    });
                assert_eq!(progress, Ok(QuantumSealProgress::DeliveryReady));
                trace
            };
            assert_eq!(births.seen.len(), 1);
            drop(births);
            let seal = frame
                .active_seal_for_test()
                .expect("borrow the actual retained seal");
            assert_eq!(seal.prefix.domain(), target.bootstrap().domain());
            assert_eq!(seal.prefix.settled().len(), 9);
            assert_eq!(trace.settlements, 1);
            assert_eq!(
                trace.steps.len(),
                18,
                "every real BEGIN and END, including empty effects"
            );
            let conversion_len = seal
                .effects
                .effects
                .len()
                .checked_sub(trace.effects.len())
                .unwrap();
            assert_eq!(&seal.effects.effects[conversion_len..], trace.effects);
            assert_eq!(
                conversion_len, 0,
                "healthy conversion emitted no pre-settlement effects"
            );
            assert_original_replay_partition(seal);
            use crate::semantics_objects::journal::SealReplayPhase;
            assert_eq!(seal.prefix.replay_calls(), seal.prefix.settled());
            assert_eq!(seal.prefix.replay_steps().len(), 38);
            let actual_steps: Vec<_> = seal
                .prefix
                .replay_steps()
                .iter()
                .filter(|step| {
                    matches!(step.phase(), SealReplayPhase::Begin | SealReplayPhase::End)
                })
                .collect();
            assert_eq!(actual_steps.len(), trace.steps.len());
            for (actual, observed) in actual_steps.iter().zip(&trace.steps) {
                let original = seal.prefix.call_for_step(actual).unwrap();
                assert_eq!(original.ticket, observed.call);
                assert_eq!(actual.cut(), Some(observed.cut));
                assert_eq!(actual.phase() == SealReplayPhase::End, observed.terminal);
                assert_eq!(actual.effect_range(), observed.effects.clone());
            }
            assert_eq!(
                seal.prefix
                    .replay_steps()
                    .iter()
                    .filter(|step| step.phase() == SealReplayPhase::Conversion)
                    .count(),
                18,
                "each real conversion stays distinct even when it emits no effects"
            );
            let prefix_base = seal.prefix.frontier_cut() - physical.len() as u64;
            let mut keyuse = KeyUseReducer::new();
            let mut selected = Vec::new();
            for (index, wire) in wires
                .iter()
                .enumerate()
                .filter(|(_, wire)| wire.label != "independent")
            {
                let begin_index = physical
                    .iter()
                    .position(|item| *item == (index, false))
                    .unwrap();
                let end_index = physical
                    .iter()
                    .position(|item| *item == (index, true))
                    .unwrap();
                let begin_cut = prefix_base + begin_index as u64 + 1;
                let end_cut = prefix_base + end_index as u64 + 1;
                let settled = seal
                    .prefix
                    .settled()
                    .iter()
                    .find(|call| call.begin_cut == begin_cut)
                    .unwrap();
                let ts = u64::from_le_bytes(wire.end[24..32].try_into().unwrap());
                let admission = admissions.iter().find(|entry| entry.1 == ts).unwrap().0;
                assert_eq!(settled.key.admission(), admission);
                assert_eq!(settled.end_cut, Some(end_cut));
                let steps: Vec<_> = trace
                    .steps
                    .iter()
                    .filter(|step| step.call == settled.ticket)
                    .collect();
                assert_eq!(steps.len(), 2);
                assert_eq!((steps[0].cut, steps[0].terminal), (begin_cut, false));
                assert_eq!((steps[1].cut, steps[1].terminal), (end_cut, true));
                assert!(steps[0].effects.is_empty());
                let receipts = keyuse.receipts_for_call(
                    seal,
                    settled,
                    fixture.scene.real.scene.coordinator.joint_capture().model(),
                    admission,
                );
                selected.push((wire.label, *settled, steps[1], receipts));
            }
            assert!(trace.steps.windows(2).all(|pair| pair[0].cut < pair[1].cut));
            let find = |label| selected.iter().find(|entry| entry.0 == label).unwrap();
            let create = find("create");
            let old = trace.effects[create.2.effects.clone()]
                .iter()
                .find_map(|effect| match effect {
                    ObjectEffect::Created { call, object, .. } if *call == create.1.ticket => {
                        Some(*object)
                    }
                    _ => None,
                })
                .unwrap();
            let reuse = find("reuse");
            let replacement = trace.effects[reuse.2.effects.clone()]
                .iter()
                .find_map(|effect| match effect {
                    ObjectEffect::Created { call, object, .. } if *call == reuse.1.ticket => {
                        Some(*object)
                    }
                    _ => None,
                })
                .unwrap();
            assert_ne!(old, replacement);
            let init = find("init");
            assert_eq!(init.3.len(), 1);
            let receipt = init.3[0];
            assert_eq!(
                (receipt.key, receipt.input, receipt.position),
                (old, 0, init.1.key.admission())
            );
            assert!(receipt.attribution_valid);
            assert_eq!(
                receipt.label,
                if late_metadata {
                    None
                } else {
                    Some(KeyLabel::Rsa { modulus_bits: 2048 })
                }
            );
            assert_eq!(
                receipt.metadata.established_count(),
                if late_metadata { 0 } else { 3 }
            );
            let conflict = find("conflict");
            assert!(trace.effects[conflict.2.effects.clone()].iter().any(|effect| matches!(effect,
                ObjectEffect::MetadataConflict { call, object, .. } if *call == conflict.1.ticket && *object == old)));
            let invalidation = find("invalidate");
            assert!(
                trace.effects[invalidation.2.effects.clone()]
                    .iter()
                    .any(|effect| matches!(effect,
                ObjectEffect::MetadataInvalidated { object, .. } if *object == old))
            );
            let destroy = find("destroy");
            assert!(trace.effects[destroy.2.effects.clone()].iter().any(|effect| matches!(effect,
                ObjectEffect::Destroyed { call, object } if *call == destroy.1.ticket && *object == old)));
            let final_call = find("final");
            assert!(
                final_call.2.effects.is_empty(),
                "Final still needs its actual empty transition boundary"
            );
            assert!(final_call.3.is_empty());
            assert!(
                init.2.cut < conflict.2.cut
                    && conflict.2.cut < invalidation.2.cut
                    && invalidation.2.cut < destroy.2.cut
                    && destroy.2.cut < reuse.2.cut
                    && reuse.2.cut < final_call.2.cut
            );
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .model()
                    .receipt_snapshot(replacement)
                    .unwrap()
                    .label,
                Some(KeyLabel::Rsa { modulus_bits: 4096 })
            );
            let tuple = (
                init.1.key.admission(),
                init.1.begin_cut,
                init.1.end_cut.unwrap(),
            );
            eprintln!(
                "observation late={late_metadata} reverse_end={reverse_end} reverse_delivery={reverse_delivery}: init={tuple:?}, frozen={:?}, conflict={}, invalidation={} {:?}, destroy={}, reuse={}, final={} {:?}, pre_settlement_effects={conversion_len}",
                receipt.label,
                conflict.2.cut,
                invalidation.2.cut,
                invalidation.2.effects,
                destroy.2.cut,
                reuse.2.cut,
                final_call.2.cut,
                final_call.2.effects,
            );
            let offset = if late_metadata { 1 } else { 2 };
            assert_eq!(tuple.0, base_admission + offset + u64::from(reverse_end));
            if let Some(previous) = delivery_tuple {
                assert_eq!(tuple, previous);
            }
            delivery_tuple = Some(tuple);
            assert_eq!(
                fixture.feeds(),
                feeds_before,
                "observation performs no H9 replay"
            );
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .reference_h3_audit_state(),
                (2, false)
            );
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .reference_h3_acknowledged_below(),
                0
            );
            if after_observation(&mut fixture, &mut frame, target) {
                fixture.finish_bounded_batch(frame, false);
            }
        }
        completion_tuples.push(delivery_tuple.unwrap());
    }
    assert_eq!(completion_tuples[0].1, completion_tuples[1].1);
    assert_eq!(completion_tuples[0].0 + 1, completion_tuples[1].0);
    assert_eq!(completion_tuples[0].2 + 1, completion_tuples[1].2);
}

fn observe_genuine_settlement_order(late_metadata: bool) {
    with_genuine_settlement_order(late_metadata, |_, _, _| false);
}

#[test]
fn joint_seal_observation_trace_keeps_call_positions() {
    observe_genuine_settlement_order(false);
}

#[test]
fn joint_seal_observation_trace_never_backfills_init() {
    observe_genuine_settlement_order(true);
}

impl CanonicalFanoutScene {
    fn replay_target(&self) -> (JointFeedTarget, u32) {
        let target = self
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .joint_feed_targets()
            .min_by_key(JointFeedTarget::id)
            .unwrap();
        let pid = self
            .scene
            .real
            .scene
            .coordinator
            .semantic_bindings()
            .get(target.caller())
            .unwrap()
            .pin()
            .pid();
        (target, pid)
    }

    fn seal_replay_head(
        &mut self,
        frame: &mut IngestedJointQuantum,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
    ) {
        {
            let ports = self
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&self.scene.producers)
                .unwrap();
            frame.bind_targets(&ports).unwrap();
        }
        self.seal_replay_bound_head(frame, fault);
    }

    fn seal_replay_bound_head(
        &mut self,
        frame: &mut IngestedJointQuantum,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
    ) {
        let h0 = self.scene.real.h0.clone();
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &self.attached,
            retained: &mut self.births,
            seen: Vec::new(),
            unreadable: false,
        };
        let mut ports = self
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&self.scene.producers)
            .unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut births, fault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert_eq!(births.seen.len(), 1);
        assert!(
            frame.active_seal_for_test().is_some(),
            "genuine frame must retain the positive"
        );
    }
}

fn with_genuine_prior_terminal(
    reverse_head: bool,
    drive_h9: bool,
    after_seal: impl FnOnce(
        &mut CanonicalFanoutScene,
        &mut IngestedJointQuantum,
        JointFeedTarget,
        crate::semantics_objects::journal::SealedCall,
        crate::semantics_objects::journal::SealedCall,
    ) -> bool,
) {
    use crate::semantics_objects::journal::SealReplayPhase;
    use crate::semantics_objects::journal::tests::abandon_bytes;
    use p11scope_ebpf_common::object_journal::JOURNAL_REASON_SYNC_RETURN_RESULT_LOST;
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let (target, pid) = fixture.replay_target();
    let (open, ordinary) = fixture.scene.encoded(
        pid,
        0,
        if drive_h9 {
            "C_SignInit"
        } else {
            "C_SignUpdate"
        },
        2,
    );
    let (held, complete) = fixture.scene.encoded(pid, 0, "C_SignInit", 3);
    let ordinary = if reverse_head {
        // B began first but returns after A. H0 therefore admits A before B,
        // while q2 still emits B's loss span before A's actual settlement END.
        end_bytes_absent(&open, 0, ENTRY_NS + 2_010)
    } else {
        ordinary
    };
    fixture.scene.drain.source_mut().push_record(open.to_vec());
    if !reverse_head {
        fixture
            .scene
            .drain
            .source_mut()
            .push_record(ordinary[24..392].to_vec());
    }
    fixture.scene.drain.source_mut().push_record(held.to_vec());
    fixture
        .scene
        .drain
        .source_mut()
        .push_record(complete.to_vec());
    if reverse_head {
        fixture
            .scene
            .drain
            .source_mut()
            .push_record(ordinary[24..392].to_vec());
    }
    let mut q1 = fixture.audited(2, 2, &BirthFault);
    assert!(
        q1.failure_for_test().is_none(),
        "q1 must have an actual clean audit: {:?}",
        q1.failure_for_test()
    );
    fixture.seal_replay_head(&mut q1, &BirthFault);
    let first = q1.active_seal_for_test().unwrap();
    assert_eq!(first.prefix.domain(), target.bootstrap().domain());
    assert_eq!(first.prefix.settled().len(), 2);
    let old = *first
        .prefix
        .settled()
        .iter()
        .find(|call| call.end_cut.is_some())
        .unwrap();
    let lost = *first
        .prefix
        .settled()
        .iter()
        .find(|call| call.end_cut.is_none())
        .unwrap();
    let loss_bound = first.prefix.frontier_cut() - 4 + if reverse_head { 4 } else { 2 };
    assert_eq!(old.key.admission() < lost.key.admission(), reverse_head);
    assert!(
        first.effects.effects.is_empty(),
        "the real open holds the watermark"
    );
    assert_original_replay_partition(first);
    assert!(
        !first
            .prefix
            .replay_steps()
            .iter()
            .any(|step| step.phase() == SealReplayPhase::End)
    );
    if drive_h9 {
        let feeds = fixture.feeds();
        let roles = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test();
        for _ in 0..8 {
            assert_ne!(
                fixture.deliver_one_work(&mut q1),
                QuantumSealProgress::Complete
            );
        }
        assert_eq!(
            fixture.feeds(),
            feeds,
            "no actual End or subject-bound loss yet"
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test(),
            roles
        );
    }
    fixture.scene.assert_claims(&[]);
    let before_feeds = fixture.feeds();
    let before_roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    assert_eq!(before_roles[..4], [0, 2, 2, 2]);

    let image = fixture
        .scene
        .real
        .scene
        .coordinator
        .semantic_bindings()
        .get(target.caller())
        .unwrap()
        .image();
    let mut abandon = abandon_bytes(
        u64::from(pid),
        2,
        JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
        (image.task_cookie, image.exec_id),
    );
    abandon[24..32].copy_from_slice(&open[24..32]);
    abandon[48..52].copy_from_slice(&open[104..108]);
    abandon[56..64].copy_from_slice(&open[48..56]);
    fixture
        .scene
        .drain
        .source_mut()
        .push_record(abandon.to_vec());
    let mut q2 = fixture.audited(0, 0, &BirthFault);
    assert!(
        q2.failure_for_test().is_none(),
        "q2 bounded ABANDON must preserve resource custody: {:?}",
        q2.failure_for_test()
    );
    fixture.seal_replay_head(&mut q2, &BirthFault);
    let second = q2.active_seal_for_test().unwrap();
    assert_eq!(
        second.prefix.settled().len(),
        1,
        "legacy delta stays unchanged"
    );
    assert!(second.prefix.settled()[0].abandoned);
    assert_eq!(second.prefix.replay_calls().len(), 2);
    assert_eq!(
        second.prefix.replay_calls()[1],
        old,
        "capture the retained original before prune"
    );
    assert_original_replay_partition(second);
    for foreign in q1.active_seal_for_test().unwrap().prefix.replay_steps() {
        assert!(second.prefix.call_for_step(foreign).is_none());
        assert!(second.effects_for_step(foreign).is_none());
    }
    let conversion = second
        .prefix
        .replay_steps()
        .iter()
        .find(|step| step.phase() == SealReplayPhase::BoundedLoss)
        .unwrap();
    assert!(!conversion.effect_range().is_empty());
    let loss_call = second.prefix.call_for_step(conversion).unwrap();
    assert_eq!((loss_call.key, loss_call.ticket), (lost.key, lost.ticket));
    assert!(loss_call.abandoned && loss_call.end_cut.is_none());
    assert_eq!(conversion.cut(), Some(loss_bound));
    assert!(
        second
            .effects_for_step(conversion)
            .unwrap()
            .iter()
            .any(|effect| matches!(
                effect,
                ObjectEffect::Retired {
                    reason: ObjectGap::OutcomeLost,
                    ..
                }
            ))
    );
    let terminal: Vec<_> = second
        .prefix
        .replay_steps()
        .iter()
        .filter(|step| step.phase() == SealReplayPhase::End)
        .collect();
    assert_eq!(
        terminal.len(),
        1,
        "only the different complete original actually settles"
    );
    assert_eq!(second.prefix.call_for_step(terminal[0]), Some(&old));
    assert_eq!(terminal[0].cut(), old.end_cut);
    assert!(
        second
            .effects_for_step(terminal[0])
            .unwrap()
            .iter()
            .any(|effect| matches!(
                effect,
                ObjectEffect::Gap {
                    reason: ObjectGap::BootstrapUnproven
                }
            ))
    );
    assert!(
        !second.effects.effects.iter().any(|effect| matches!(effect,
        ObjectEffect::Referenced { call, .. } if *call == old.ticket)),
        "conversion loss cannot fabricate a qualified receipt"
    );
    assert_eq!(
        fixture.feeds(),
        before_feeds,
        "representation activates no H9 replay"
    );
    fixture.scene.assert_claims(&[]);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test()[..4],
        [0, 0, 0, 2]
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (3, false)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
    if after_seal(&mut fixture, &mut q2, target, old, lost) {
        fixture.finish_bounded_batch(q2, false);
    }
}

#[test]
fn joint_replay_steps_keep_prior_terminal_after_conversion_loss() {
    with_genuine_prior_terminal(false, false, |_, _, _, _, _| false);
}

#[test]
fn joint_replay_step_capacity_refusal_preserves_original() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let (_, pid) = fixture.replay_target();
    fixture.scene.push(pid, 0, "C_SignInit", 2);
    let fault = FrameFault::clean();
    let mut frame = fixture.audited(1, 1, &fault);
    {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
    }
    let (legacy, retained, temporary) = {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.replay_reservation_for_test(&ports).unwrap()
    };
    assert!(retained > 0 && temporary > 0);
    let available = legacy
        .checked_add(retained)
        .unwrap()
        .checked_add(temporary)
        .unwrap()
        .checked_sub(1)
        .unwrap();
    let coordinator = &fixture.scene.real.scene.coordinator;
    let claims = coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    let starts = coordinator
        .joint_capture()
        .adapter()
        .retained_starts_for_test();
    let roles = coordinator.joint_capture().ledger().roles_for_test();
    let model = coordinator.joint_capture().model().project();
    let cursor = (frame.identity(), frame.frontier());
    let feeds = fixture.feeds();
    let snapshot = coordinator.registry().semantic_resource_snapshot();
    let hold = coordinator
        .registry()
        .reserve_semantic_storage(snapshot.limit_bytes - snapshot.charged_bytes - available)
        .unwrap();
    let h0 = fixture.scene.real.h0.clone();
    let mut births = NativeFrameBirths {
        h0: &h0,
        attached: &fixture.attached,
        retained: &mut fixture.births,
        seen: Vec::new(),
        unreadable: false,
    };
    let reads = fault.reads.get();
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert!(
            matches!(
                frame.seal_next(&mut ports, &mut births, &fault),
                Err(RawQuantumRefusal::Resource(_))
            ),
            "the old result charge alone cannot pay for steps and the temporary locator"
        );
    }
    assert_eq!(fault.reads.get(), reads);
    assert!(births.seen.is_empty());
    drop(births);
    assert_eq!(fixture.feeds(), feeds);
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        claims
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        starts
    );
    assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
    assert_eq!(coordinator.joint_capture().model().project(), model);
    assert!(frame.identity() == cursor.0);
    assert_eq!(frame.frontier(), cursor.1);
    assert_eq!(
        coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes,
        snapshot.limit_bytes - available,
        "the whole failed preflight is refunded"
    );
    drop(hold);
    fixture.seal_replay_bound_head(&mut frame, &fault);
    assert_original_replay_partition(frame.active_seal_for_test().unwrap());
    assert_eq!(
        fixture.feeds(),
        feeds,
        "retry still does not publish or replay"
    );
}

impl CanonicalFanoutScene {
    fn s1_counts(&self, id: RegistryInstanceId) -> (u64, u64, u64, u64, usize) {
        let s1 = self
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .find(|record| record.id == id)
            .unwrap()
            .semantics
            .as_ref()
            .unwrap();
        (
            s1.calls(),
            s1.started(),
            s1.completed(),
            s1.unknown(),
            s1.active_summary()
                .iter()
                .map(|entry| entry.2 as usize)
                .sum(),
        )
    }

    /// A service slice has ONE work unit shared by every selected consumer.
    /// Reductions/disposals cannot each receive a fresh per-feed allowance.
    fn deliver_one_work(&mut self, frame: &mut IngestedJointQuantum) -> QuantumSealProgress {
        let before: u64 = self
            .feeds()
            .iter()
            .map(|feed| feed.reduced + feed.disposed)
            .sum();
        let audit = self.scene.real.scene.coordinator.reference_h3_audit_state();
        let ack = self
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below();
        let mut remaining = 1;
        let progress = {
            let mut ports = self
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&self.scene.producers)
                .unwrap();
            frame
                .deliver_next_bounded(&mut ports, &mut remaining)
                .unwrap()
        };
        let after: u64 = self
            .feeds()
            .iter()
            .map(|feed| feed.reduced + feed.disposed)
            .sum();
        assert!(
            after >= before && after - before <= 1,
            "one shared service unit"
        );
        if after != before {
            assert_eq!(remaining, 0, "a terminal disposition is charged work");
        }
        assert!(remaining <= 1);
        assert_eq!(
            self.scene.real.scene.coordinator.reference_h3_audit_state(),
            audit,
            "a yielded/retried delivery never takes H3 again"
        );
        assert_eq!(
            self.scene
                .real
                .scene
                .coordinator
                .reference_h3_acknowledged_below(),
            ack,
            "no acknowledgement while an original result is retained"
        );
        progress
    }

    fn seal_selected_for_batch(&mut self, frame: &mut IngestedJointQuantum, unreadable: bool) {
        let h0 = self.scene.real.h0.clone();
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &self.attached,
            retained: &mut self.births,
            seen: Vec::new(),
            unreadable,
        };
        let mut ports = self
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&self.scene.producers)
            .unwrap();
        assert!(matches!(
            frame
                .seal_next(&mut ports, &mut births, &BirthFault)
                .unwrap(),
            QuantumSealProgress::DeliveryReady | QuantumSealProgress::Complete
        ));
        assert!(births.seen.len() <= 1);
    }

    fn finish_bounded_batch(&mut self, mut frame: IngestedJointQuantum, unreadable: bool) {
        let mut complete = false;
        // This fixture has fewer than 128 original transitions/effects. The
        // finite guard catches a hidden head/cursor deadlock, not slow I/O.
        for _ in 0..256 {
            self.seal_selected_for_batch(&mut frame, unreadable);
            if self.deliver_one_work(&mut frame) == QuantumSealProgress::Complete {
                complete = true;
                break;
            }
        }
        assert!(
            complete,
            "every exact original must reach a terminal disposition"
        );
        let feeds = self.feeds();
        assert_eq!(
            self.deliver_one_work(&mut frame),
            QuantumSealProgress::Complete
        );
        assert_eq!(
            self.feeds(),
            feeds,
            "a completed frame never replays/disposes twice"
        );
        let mut ports = self
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&self.scene.producers)
            .unwrap();
        frame
            .finish_frame(&mut ports)
            .unwrap_or_else(|(_, reason)| panic!("bounded consumers remain: {reason:?}"));
        self.scene.assert_claims(&[]);
        assert_eq!(
            self.scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .ledger()
                .roles_for_test()[..4],
            [0, 0, 0, 0]
        );
    }
}

/// Catches the old multi-call hold, prefix-only redemption, unbounded per-feed
/// work, and replacing an original admission with an equal-shaped Update.
#[test]
fn key_operation_joint_batch_replays_exact_order() {
    for reverse_end in [false, true] {
        for reverse_delivery in [false, true] {
            let mut fixture = CanonicalFanoutScene::prior_sealed();
            let (target, primary) = fixture.replay_target();
            let peer = if primary == std::process::id() {
                fixture._child.id()
            } else {
                std::process::id()
            };
            let before = fixture.feeds();
            let before_s1 = fixture.s1_counts(target.id());
            let mut wires = Vec::new();
            let mut physical = Vec::new();
            for (offset, function) in [
                "C_CreateObject",
                "C_SignInit",
                "C_SignUpdate",
                "C_SignUpdate",
                "C_SignFinal",
            ]
            .into_iter()
            .enumerate()
            {
                let first = wires.len();
                for pid in [primary, peer] {
                    wires.push(observation_wire(
                        &fixture,
                        pid,
                        "batch",
                        function,
                        offset as u64 + 2,
                    ));
                }
                physical.extend([(first, false), (first + 1, false)]);
                physical.extend(if reverse_end {
                    [(first + 1, true), (first, true)]
                } else {
                    [(first, true), (first + 1, true)]
                });
            }
            let (mut frame, admissions, _) =
                prepare_wire_frame(&mut fixture, &wires, &physical, reverse_delivery);
            assert_eq!(admissions.len(), 10);
            fixture.seal_replay_head(&mut frame, &BirthFault);
            let seal = frame.active_seal_for_test().unwrap();
            assert_original_replay_partition(seal);
            assert_eq!(seal.prefix.replay_calls().len(), 5);
            assert_eq!(
                seal.prefix
                    .replay_steps()
                    .iter()
                    .filter(|step| step.phase()
                        == crate::semantics_objects::journal::SealReplayPhase::End)
                    .count(),
                5
            );
            let mut original = seal
                .prefix
                .replay_calls()
                .iter()
                .map(|call| (call.key.admission(), call.function))
                .collect::<Vec<_>>();
            original.sort_unstable_by_key(|call| call.0);
            assert_eq!(
                original.iter().map(|call| call.1).collect::<Vec<_>>(),
                [
                    "C_CreateObject",
                    "C_SignInit",
                    "C_SignUpdate",
                    "C_SignUpdate",
                    "C_SignFinal"
                ]
                .map(function_id)
            );
            assert!(original.windows(2).all(|pair| pair[0].0 < pair[1].0));
            let base = before
                .iter()
                .find(|feed| feed.id == target.id())
                .unwrap()
                .reduced;
            let mut done = false;
            for _ in 0..128 {
                fixture.deliver_one_work(&mut frame);
                let feed = fixture
                    .feeds()
                    .into_iter()
                    .find(|feed| feed.id == target.id())
                    .unwrap();
                let n = feed.reduced - base;
                let counts = fixture.s1_counts(target.id());
                assert_eq!(
                    counts.0 - before_s1.0,
                    n,
                    "only the next original enters S1"
                );
                assert_eq!(counts.1 - before_s1.1, u64::from(n >= 2));
                assert_eq!(counts.2 - before_s1.2, u64::from(n == 5));
                assert_eq!(counts.3, before_s1.3);
                assert_eq!(counts.4, usize::from((2..5).contains(&n)));
                assert_eq!(feed.disposed, 0);
                if n == 5 {
                    assert_eq!(feed.staged, 0);
                    done = true;
                    break;
                }
            }
            assert!(
                done,
                "the genuine five-call prefix must progress with budget one"
            );
            let delivered = fixture.feeds();
            fixture.deliver_one_work(&mut frame);
            assert_eq!(
                fixture.feeds(),
                delivered,
                "retry of consumed original table is inert"
            );
            fixture.finish_bounded_batch(frame, false);
            for feed in fixture.feeds() {
                let original = before.iter().find(|old| old.id == feed.id).unwrap();
                assert_eq!(
                    (feed.reduced - original.reduced, feed.disposed, feed.staged),
                    (5, 0, 0)
                );
                assert!(!feed.fallback && !feed.degraded);
            }
        }
    }
}

/// Catches applying the batch's final invalidations before Init, relabeling
/// from the current replacement object, or losing an empty Final boundary.
#[test]
fn key_operation_joint_batch_receipts_keep_observation_time() {
    for late_metadata in [false, true] {
        with_genuine_settlement_order(late_metadata, |fixture, frame, target| {
            let seal = frame.active_seal_for_test().unwrap();
            let mut calls = seal.prefix.replay_calls().to_vec();
            calls.sort_unstable_by_key(|call| call.key.admission());
            let init_rank = calls
                .iter()
                .position(|call| call.function == function_id("C_SignInit"))
                .unwrap() as u64
                + 1;
            let before = fixture
                .feeds()
                .into_iter()
                .find(|feed| feed.id == target.id())
                .unwrap()
                .reduced;
            let mut saw_init = false;
            let mut saw_retirement = false;
            let mut done = false;
            for _ in 0..192 {
                fixture.deliver_one_work(frame);
                let feed = fixture
                    .feeds()
                    .into_iter()
                    .find(|feed| feed.id == target.id())
                    .unwrap();
                let keyuse = fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .registry()
                    .keyuse_for_test();
                let buckets: Vec<_> = keyuse
                    .aggregates()
                    .iter()
                    .filter(|(key, _)| key.instance == target.id())
                    .collect();
                assert!(
                    buckets.iter().all(|(key, _)| key.metadata != "rsa_4096"),
                    "later replacement metadata cannot label the original use"
                );
                if !saw_init && feed.reduced - before == init_rank {
                    saw_init = true;
                    if late_metadata {
                        assert!(
                            buckets.is_empty(),
                            "metadata learned later never backfills Init"
                        );
                    } else {
                        assert_eq!(buckets.len(), 1);
                        assert_eq!(buckets[0].0.metadata, "rsa_2048");
                        assert_eq!(
                            (
                                buckets[0].1.started,
                                buckets[0].1.active,
                                buckets[0].1.key_join_lost
                            ),
                            (1, 1, 0)
                        );
                    }
                }
                if buckets
                    .iter()
                    .any(|(_, counters)| counters.key_join_lost != 0)
                {
                    assert!(saw_init, "the original Init must precede its invalidation");
                    saw_retirement = true;
                    assert_eq!((buckets[0].1.active, buckets[0].1.key_join_lost), (0, 1));
                }
                if feed.reduced - before == 9 {
                    assert_eq!(feed.staged, 0);
                    assert_eq!(
                        keyuse
                            .open()
                            .keys()
                            .filter(|(instance, _)| *instance == target.id())
                            .count(),
                        0
                    );
                    done = true;
                    break;
                }
            }
            assert!(done && saw_init);
            assert_eq!(saw_retirement, !late_metadata);
            // The oracle above already checked the actual object is now
            // RSA4096; replay must retain the earlier frozen label instead.
            true
        });
    }
}

/// Catches spending a fresh H3 for feed two, switching to S1Only before its
/// suffix is disposed, or replaying the same retained head on budget retry.
#[test]
fn key_operation_two_feeds_share_audited_fallback_once() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    for (offset, function) in ["C_SignInit", "C_SignUpdate", "C_SignFinal"]
        .into_iter()
        .enumerate()
    {
        fixture.push_two(function, offset as u64 + 2);
    }
    let mut frame = fixture.audited(6, 6, &BirthFault);
    assert!(matches!(
        frame.audit_for_test().h3_for_test(),
        H3DispositionEvidence::Clean {
            staged_max: 8,
            pending_floor: None
        }
    ));
    let before = fixture.feeds();
    {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
    }
    for _ in 0..128 {
        fixture.seal_selected_for_batch(&mut frame, true);
        let progress = fixture.deliver_one_work(&mut frame);
        for feed in fixture.feeds() {
            let start = before.iter().find(|old| old.id == feed.id).unwrap();
            assert_eq!(feed.reduced - start.reduced + feed.staged as u64, 3);
            assert_eq!(feed.disposed, 0);
            assert_eq!(
                feed.fallback,
                feed.staged == 0,
                "mode changes only after that feed's entire original suffix"
            );
            assert!(!feed.degraded);
        }
        if progress == QuantumSealProgress::Complete {
            break;
        }
    }
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.staged == 0 && feed.fallback)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (2, false)
    );
    fixture.finish_bounded_batch(frame, true);
    for feed in fixture.feeds() {
        assert_eq!(fixture.s1_counts(feed.id), (4, 1, 1, 0, 0));
    }
}

/// Catches inferring a terminal from table.abandoned, disposing an equal-shaped
/// sibling, or blocking A forever behind the earlier-emitted loss span of B.
#[test]
fn key_operation_joint_batch_bounded_loss_keeps_exact_admission_head() {
    for reverse_head in [false, true] {
        with_genuine_prior_terminal(
            reverse_head,
            true,
            |fixture, frame, target, complete, lost| {
                assert_eq!(
                    complete.function, lost.function,
                    "same-shaped distinct originals"
                );
                assert_ne!(complete.key, lost.key);
                assert_ne!(complete.ticket, lost.ticket);
                let seal = frame.active_seal_for_test().unwrap();
                use crate::semantics_objects::journal::SealReplayPhase;
                let loss_index = seal
                    .prefix
                    .replay_steps()
                    .iter()
                    .position(|step| step.phase() == SealReplayPhase::BoundedLoss)
                    .unwrap();
                let end_index = seal
                    .prefix
                    .replay_steps()
                    .iter()
                    .position(|step| step.phase() == SealReplayPhase::End)
                    .unwrap();
                assert!(loss_index < end_index);
                assert_eq!(
                    complete.key.admission() < lost.key.admission(),
                    reverse_head
                );
                assert!(!seal.effects.effects.iter().any(|effect| matches!(effect,
                ObjectEffect::Referenced { call, .. } if *call == complete.ticket || *call == lost.ticket)));
                let before = fixture.feeds();
                let target_before = before.iter().find(|feed| feed.id == target.id()).unwrap();
                let base = (target_before.reduced, target_before.disposed);
                let counts = fixture.s1_counts(target.id());
                let roles = fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .ledger()
                    .roles_for_test();
                assert_eq!(roles[..4], [0, 0, 0, 2]);
                // The same-shaped originals of a different producer allocation
                // cannot authorize either loss disposal or actual-End replay.
                let mut foreign = CanonicalFanoutScene::prior_sealed();
                let mut remaining = 1;
                {
                    let mut ports = foreign
                        .scene
                        .real
                        .scene
                        .coordinator
                        .joint_frame_ports(&foreign.scene.producers)
                        .unwrap();
                    assert_eq!(
                        frame.deliver_next_bounded(&mut ports, &mut remaining),
                        Err(RawQuantumRefusal::ForeignCapture)
                    );
                }
                assert_eq!(remaining, 1);
                assert_eq!(fixture.feeds(), before);
                assert_eq!(
                    fixture
                        .scene
                        .real
                        .scene
                        .coordinator
                        .joint_capture()
                        .ledger()
                        .roles_for_test(),
                    roles
                );
                let mut done = false;
                for _ in 0..64 {
                    let progress = fixture.deliver_one_work(frame);
                    let feed = fixture
                        .feeds()
                        .into_iter()
                        .find(|feed| feed.id == target.id())
                        .unwrap();
                    let (replayed, disposed) = (feed.reduced - base.0, feed.disposed - base.1);
                    assert_eq!(
                        replayed + disposed + feed.staged as u64,
                        2,
                        "every original is replayed, explicitly disposed, or still owned"
                    );
                    assert!(replayed <= 1 && disposed <= 1);
                    if reverse_head && disposed != 0 {
                        assert_eq!(
                            replayed, 1,
                            "B cannot discard the earlier equal-shaped A head"
                        );
                    }
                    if !reverse_head && replayed != 0 {
                        assert_eq!(disposed, 1, "A cannot skip the earlier B head");
                    }
                    let current = fixture.s1_counts(target.id());
                    assert_eq!(
                        current.0 - counts.0,
                        replayed,
                        "bounded loss is history disposal, never S1-positive replay"
                    );
                    assert!(
                        fixture
                            .scene
                            .real
                            .scene
                            .coordinator
                            .registry()
                            .keyuse_for_test()
                            .aggregates()
                            .iter()
                            .all(|(key, counters)| key.instance != target.id()
                                || counters.active == 0)
                    );
                    if feed.staged != 0 {
                        assert_ne!(progress, QuantumSealProgress::Complete);
                    } else {
                        assert_eq!((replayed, disposed), (1, 1));
                        assert_eq!(
                            current.4,
                            usize::from(!reverse_head),
                            "B's later loss must close A's earlier Init, never resurrect it"
                        );
                        assert_eq!(current.3 - counts.3, u64::from(reverse_head));
                        done = true;
                        break;
                    }
                }
                assert!(
                    done,
                    "independent span and exact-head cursors must both progress"
                );
                let feeds = fixture.feeds();
                let s1 = fixture.s1_counts(target.id());
                let evidence = fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .registry()
                    .keyuse_for_test()
                    .evidence();
                for _ in 0..3 {
                    fixture.deliver_one_work(frame);
                }
                assert_eq!(fixture.feeds(), feeds);
                assert_eq!(fixture.s1_counts(target.id()), s1);
                assert_eq!(
                    fixture
                        .scene
                        .real
                        .scene
                        .coordinator
                        .registry()
                        .keyuse_for_test()
                        .evidence(),
                    evidence,
                    "consumed loss neither invalidates nor disposes twice"
                );
                true
            },
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SiblingLossMoment {
    None,
    BeforeProofRefusal,
    AfterProofRefusal,
}

fn exercise_s1only_sibling_raw(sibling_first: bool, loss_moment: SiblingLossMoment) {
    use crate::semantics_key_use::FeedMode;
    let fault = FrameFault::clean();
    let mut fixture = CanonicalFanoutScene::prior_sealed_with_providers(2);
    if loss_moment != SiblingLossMoment::None {
        fixture.push_two("C_SignInit", 2);
        let mut prior = fixture.audited(2, 2, &BirthFault);
        {
            let ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            prior.bind_targets(&ports).unwrap();
        }
        fixture.finish_bounded_batch(prior, false);
        for feed in fixture.feeds() {
            assert_eq!(
                fixture.s1_counts(feed.id),
                (2, 1, 0, 0, 1),
                "retain one genuine live S1 operation before overlapping original loss effects"
            );
        }
    }
    let targets = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .collect::<Vec<_>>();
    assert_eq!(targets.len(), 2);
    let before = fixture.feeds();
    let before_model = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    let mut subjects = Vec::new();
    for target in &targets {
        let pid = fixture
            .scene
            .real
            .scene
            .coordinator
            .semantic_bindings()
            .get(target.caller())
            .unwrap()
            .pin()
            .pid();
        fixture.scene.admit_providers(pid, target.caller(), &[1]);
        subjects.push((target.caller(), pid));
    }
    let mut b_returns = Vec::new();
    for (offset, function) in ["C_SignInit", "C_SignUpdate", "C_SignFinal"]
        .into_iter()
        .enumerate()
    {
        for (caller, pid) in &subjects {
            for (within, file) in if sibling_first { [1, 0] } else { [0, 1] }
                .into_iter()
                .enumerate()
            {
                let (begin, end) = fixture.scene.encoded(
                    *pid,
                    file,
                    function,
                    (if loss_moment == SiblingLossMoment::None {
                        2
                    } else {
                        4
                    }) + offset as u64 * 2
                        + within as u64,
                );
                // Same image/session/mechanism and input handle; only
                // actual provider/slot and original invocation differ.
                if file == 1 {
                    b_returns.push((*caller, u64::from_le_bytes(end[24..32].try_into().unwrap())));
                }
                fixture.scene.drain.source_mut().push_record(begin.to_vec());
                fixture.scene.drain.source_mut().push_record(end.to_vec());
            }
        }
    }
    if loss_moment == SiblingLossMoment::BeforeProofRefusal {
        fault.epoch.set(1);
    }
    let raw = fixture.scene.prepare_with_fault(12, &fault);
    let inputs: Vec<_> = fixture
        .scene
        .real
        .scene
        .coordinator
        .prepared_semantic_batch()
        .unwrap()
        .admissions()
        .map(|input| {
            (
                input.h0_ordinal(),
                input.journal_binding().3,
                input.s1_facts().ts_ns,
                input.collected_origin().unwrap(),
            )
        })
        .collect();
    assert_eq!(inputs.len(), 12);
    let b_ordinals = inputs
        .iter()
        .filter(|input| b_returns.contains(&(input.1, input.2)))
        .map(|input| input.0)
        .collect::<Vec<_>>();
    assert_eq!(b_ordinals.len(), 6);
    let b_originals = subjects
        .iter()
        .map(|(caller, _)| {
            fixture
                .scene
                .real
                .scene
                .coordinator
                .prepared_semantic_batch()
                .unwrap()
                .admissions()
                .find(|input| {
                    input.journal_binding().3 == *caller && b_ordinals.contains(&input.h0_ordinal())
                })
                .unwrap()
                .clone()
        })
        .collect::<Vec<_>>();
    let mut ingested = raw
        .ingest(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("original sibling raw: {reason:?}"));
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    let mut claims = Vec::new();
    while let Some((ordinal, result)) = coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
    {
        if b_ordinals.contains(&ordinal) {
            assert_eq!(
                result,
                Err(crate::semantics_objects::journal::AttestationRefusal::ImageSealed),
                "a genuinely late provider never upgrades the already-sealed image"
            );
        } else {
            assert!(result.is_ok());
        }
        claims.push(ordinal);
    }
    assert_eq!(
        claims,
        inputs.iter().map(|input| input.0).collect::<Vec<_>>()
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test()
            .0,
        6
    );
    if loss_moment == SiblingLossMoment::AfterProofRefusal {
        fault.epoch.set(1);
    }
    let starts = coordinator
        .joint_capture()
        .adapter()
        .retained_starts_for_test();
    let exact_claims = coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    let exact_roles = coordinator.joint_capture().ledger().roles_for_test();
    let foreign = SessionDrainProducers::test_pair(
        fixture.scene.producers.native_domain(),
        EventsDomain::test_standin(fixture.scene.producers.events_id()),
    );
    assert_eq!(
        coordinator.stage_next_prepared_admission_with_disposition(&foreign, &mut ingested),
        Err(RawQuantumRefusal::ForeignCapture)
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        starts
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        exact_claims
    );
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test(),
        exact_roles
    );
    assert_eq!(
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .map(|input| (
                input.h0_ordinal(),
                input.journal_binding().3,
                input.s1_facts().ts_ns,
                input.collected_origin().unwrap()
            ))
            .collect::<Vec<_>>(),
        inputs,
        "foreign allocation cannot mark, stage or substitute any original"
    );
    let mut staged = 0;
    while coordinator
        .stage_next_prepared_admission_with_disposition(&fixture.scene.producers, &mut ingested)
        .unwrap()
    {
        staged += 1;
    }
    assert_eq!(staged, 12);
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        starts,
        "negative association is retained before physical disposal"
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        exact_claims
    );
    assert_eq!(coordinator.joint_capture().model().project(), before_model);
    assert_eq!(
        coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .count(),
        0
    );
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    assert_eq!(
        coordinator.joint_capture().ledger().roles_for_test()[..4],
        [0, 12, 0, 6],
        "marking negative originals must not erase A's source reservation before H9 joins it"
    );
    for target in &targets {
        let a = coordinator
            .registry()
            .instance_semantic_edges()
            .find(|record| record.id == target.id())
            .unwrap();
        let prior = before
            .iter()
            .find(|feed| feed.id == target.id())
            .unwrap()
            .reduced;
        assert_eq!((a.feed.staged_len(), a.feed.reduced()), (3, prior));
        assert_eq!(
            a.semantics.as_ref().unwrap().calls(),
            prior,
            "A has not escaped through direct fallback"
        );
    }
    let b_ids = coordinator
        .registry()
        .instance_semantic_edges()
        .filter(|record| {
            subjects.iter().any(|subject| subject.0 == record.caller)
                && !targets.iter().any(|target| target.id() == record.id)
        })
        .map(|record| record.id)
        .collect::<Vec<_>>();
    assert_eq!(b_ids.len(), 2);
    for id in &b_ids {
        assert_eq!(
            coordinator.registry().feed_mode_for_test(*id),
            Some(FeedMode::S1Only)
        );
    }
    for id in &b_ids {
        assert_eq!(fixture.s1_counts(*id), (3, 1, 1, 0, 0));
    }
    let mut frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &fault);
    use crate::semantics_objects::journal::JournalGap;
    let failures = frame.original_failures_for_test().collect::<Vec<_>>();
    assert!(
        failures
            .iter()
            .any(|failure| failure.gap == JournalGap::ImageTainted),
        "retain the original bulk sibling refusal, including its own scope/effects"
    );
    let failure = frame
        .failure_for_test()
        .expect("the original unowned sibling effects must be disclosed");
    if loss_moment != SiblingLossMoment::None {
        assert_eq!(
            failures.len(),
            2,
            "one bulk sibling result and the actual audit result"
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.gap == JournalGap::FaultChanged)
        );
        assert_eq!(
            failure.gap,
            JournalGap::FaultChanged,
            "a proof-only first reason cannot certify clean fallback across actual loss"
        );
    }
    assert!(
        targets
            .iter()
            .all(|target| failure.affects_domain(target.bootstrap().domain())),
        "the second image's original negative cannot be lost behind the first"
    );
    for object in &before_model.objects {
        assert!(failures.iter().any(|failure| {
            failure.effects.effects.iter().any(|effect| {
                matches!(effect,
            ObjectEffect::Retired { object: retired, .. } if *retired == object.id)
            })
        }));
        assert_ne!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture()
                .model()
                .project()
                .object(object.id)
                .unwrap()
                .lifetime,
            Lifetime::Live
        );
    }
    {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
    }
    fixture.finish_bounded_batch(frame, false);
    for target in &targets {
        let feed = fixture
            .feeds()
            .into_iter()
            .find(|feed| feed.id == target.id())
            .unwrap();
        let original = before.iter().find(|feed| feed.id == target.id()).unwrap();
        assert_eq!(
            feed.reduced - original.reduced + feed.disposed - original.disposed,
            3
        );
        assert_eq!(feed.staged, 0);
        assert!(
            feed.fallback || feed.degraded,
            "loss/refusal remains explicit"
        );
        if loss_moment != SiblingLossMoment::None {
            assert!(
                feed.degraded && !feed.fallback,
                "actual loss dominates proof refusal in either order"
            );
            assert_eq!(
                feed.reduced, original.reduced,
                "no clean S1 fallback after native loss"
            );
            assert_eq!(feed.disposed - original.disposed, 3);
            assert_eq!(
                fixture.s1_counts(target.id()),
                (2, 1, 0, 1, 0),
                "both original loss buffers end the one existing operation exactly once"
            );
        }
    }
    for id in &b_ids {
        assert_eq!(
            fixture.s1_counts(*id),
            (3, 1, 1, 0, 0),
            "direct S1 cannot replay during negative disposal"
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .feed_mode_for_test(*id),
            Some(FeedMode::S1Only)
        );
    }
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .keyuse_for_test()
            .aggregates()
            .is_empty(),
        "neither colliding provider receives object proof after disclosed loss"
    );
    let roles = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .ledger()
        .roles_for_test();
    for original in &b_originals {
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut()
                .bind_admitted_key(original),
            Err(crate::semantics_objects::journal::AttestationRefusal::ImageTainted),
            "a later original/quiet cut cannot heal the unowned affecting image"
        );
    }
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test(),
        roles
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_audit_state(),
        (
            if loss_moment == SiblingLossMoment::None {
                2
            } else {
                3
            },
            false
        )
    );
}

/// Catches a late S1Only provider pinning a Joint sibling's raw head forever,
/// tainting only the first image, or erasing A's reservation before H9 joins it.
#[test]
fn joint_s1_original_disposition_preserves_interleaved_healthy_image() {
    use crate::semantics_objects::journal::{AttestationRefusal, JournalGap};
    for tainted_first in [false, true] {
        for stale_frontier in [false, true] {
            let (mut fixture, mut foreign) =
                CanonicalFanoutScene::prior_sealed_with_functions_at_start(
                    2,
                    &[
                        "C_CreateObject",
                        "C_SignInit",
                        "C_SignUpdate",
                        "C_SignFinal",
                    ],
                    |scene| {
                        // Bind resource producers at the ACTUAL initial boundary,
                        // before this cursor has consumed any fixture record.
                        // No extra cursor, prefix setter or semantic grant exists.
                        let before = scene.drain.consumption_cut().unwrap();
                        assert!(before.is_initial());
                        let reserve = scene
                            .real
                            .scene
                            .coordinator
                            .registry()
                            .semantic_storage_reserver();
                        let mut foreign = JournalAdapter::with_ledger(
                            crate::semantics_objects::journal::JournalLimits::policy(),
                            crate::semantics_objects::journal::StagingLedger::with_resources(
                                scene
                                    .real
                                    .scene
                                    .coordinator
                                    .registry()
                                    .semantic_storage_reserver(),
                            ),
                        );
                        let (unobserved, poll) = RawJointQuantum::begin_bounded_with_adapter(
                            &mut scene.drain,
                            &publish_object_descriptors(),
                            4,
                            0,
                            None,
                            &BirthFault,
                            &scene.producers,
                            |bytes| reserve.reserve(bytes),
                            &mut foreign,
                        )
                        .unwrap();
                        assert!(poll.is_none());
                        assert!(before.same_boundary(&scene.drain.consumption_cut().unwrap()));
                        assert_eq!(scene.drain.source_mut().remaining(), 0);
                        drop(unobserved);
                        foreign
                    },
                );
            let targets = fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .joint_feed_targets()
                .collect::<Vec<_>>();
            assert_eq!(targets.len(), 2);
            let victim = targets[0];
            let healthy = targets[1];
            let victim_pid = fixture
                .scene
                .real
                .scene
                .coordinator
                .semantic_bindings()
                .get(victim.caller())
                .unwrap()
                .pin()
                .pid();
            let healthy_pid = fixture
                .scene
                .real
                .scene
                .coordinator
                .semantic_bindings()
                .get(healthy.caller())
                .unwrap()
                .pin()
                .pid();
            assert_ne!(victim_pid, healthy_pid);
            fixture
                .scene
                .admit_providers(victim_pid, victim.caller(), &[1]);
            let mut old_original = None;
            for sequence in [2, 3] {
                // A and B are different real images under one actual Session,
                // ledger and raw collection. Only B's image becomes tainted.
                for (pid, file) in if tainted_first {
                    [(victim_pid, 1), (healthy_pid, 0)]
                } else {
                    [(healthy_pid, 0), (victim_pid, 1)]
                } {
                    fixture.scene.push(
                        pid,
                        file,
                        if pid == victim_pid {
                            "C_CreateObject"
                        } else if sequence == 2 {
                            "C_SignInit"
                        } else {
                            "C_SignFinal"
                        },
                        sequence,
                    );
                }
                let raw = fixture.scene.prepare(2);
                let identity = raw.h0_identity();
                let mut ingested = raw
                    .ingest(
                        fixture
                            .scene
                            .real
                            .scene
                            .coordinator
                            .joint_capture_mut()
                            .adapter_mut(),
                        &fixture.scene.producers,
                        &fixture.grant,
                    )
                    .unwrap_or_else(|(_, reason)| panic!("actual mixed original: {reason:?}"));
                {
                    let coordinator = &mut fixture.scene.real.scene.coordinator;
                    while let Some((ordinal, result)) = coordinator
                        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
                        .unwrap()
                    {
                        let input = coordinator
                            .prepared_semantic_batch()
                            .unwrap()
                            .admissions()
                            .find(|input| input.h0_ordinal() == ordinal)
                            .unwrap();
                        if input.journal_binding().3 == victim.caller() {
                            assert_eq!(
                                result.as_ref().err().copied(),
                                Some(if sequence == 2 {
                                    AttestationRefusal::ImageSealed
                                } else {
                                    AttestationRefusal::ImageTainted
                                })
                            );
                            if sequence == 2 {
                                old_original = Some(input.clone());
                            }
                        } else {
                            assert!(result.is_ok());
                        }
                    }
                }
                if sequence == 3 && stale_frontier {
                    // Deliberately advance the SAME real cursor/adapter with
                    // a later journal-only BEGIN, while the old prepared row
                    // stays retained. No scalar frontier setter or H3 mint.
                    let (begin, _) = fixture.scene.encoded(healthy_pid, 0, "C_CreateObject", 4);
                    fixture.scene.drain.source_mut().push_record(begin.to_vec());
                    let next = fixture.scene.collect_with_fault(&BirthFault);
                    fixture.scene.real.h0.0.borrow_mut().collected = Some(next);
                    let next_report = fixture.scene.real.tick();
                    let next = fixture
                        .scene
                        .real
                        .h0
                        .0
                        .borrow_mut()
                        .collected
                        .take()
                        .unwrap();
                    let _next = next
                        .ingest(
                            fixture
                                .scene
                                .real
                                .scene
                                .coordinator
                                .joint_capture_mut()
                                .adapter_mut(),
                            &fixture.scene.producers,
                            &fixture.grant,
                        )
                        .unwrap_or_else(|(_, reason)| panic!("actual later BEGIN: {reason:?}"));
                    let coordinator = &mut fixture.scene.real.scene.coordinator;
                    let (prepared, owner) = coordinator.prepared_joint_parts().unwrap();
                    let input = prepared
                        .admissions()
                        .find(|input| input.journal_binding().3 == victim.caller())
                        .unwrap();
                    let before = (
                        owner.ledger().roles_for_test(),
                        owner.adapter().invocation_claims_for_test(),
                        owner.adapter().retained_starts_for_test(),
                    );
                    assert!(matches!(
                        ingested.disposition_s1only_original(
                            owner.adapter_mut(),
                            &fixture.scene.producers,
                            input
                        ),
                        Err(RawQuantumRefusal::StaleFrontier)
                    ));
                    assert_eq!(
                        (
                            owner.ledger().roles_for_test(),
                            owner.adapter().invocation_claims_for_test(),
                            owner.adapter().retained_starts_for_test()
                        ),
                        before
                    );
                    drop(next_report);
                    break;
                }
                if sequence == 3 {
                    let coordinator = &mut fixture.scene.real.scene.coordinator;
                    let (prepared, owner) = coordinator.prepared_joint_parts().unwrap();
                    let input = prepared
                        .admissions()
                        .find(|input| input.journal_binding().3 == victim.caller())
                        .unwrap();
                    assert!(input.collected_origin().unwrap().in_quantum(identity));
                    let before = (
                        owner.ledger().roles_for_test(),
                        owner.adapter().invocation_claims_for_test(),
                        owner.adapter().retained_starts_for_test(),
                    );
                    assert!(
                        before.0[1] > 0 && before.1.0 == 1,
                        "healthy original H8 and its claim are genuinely retained"
                    );
                    let foreign_producers = SessionDrainProducers::test_pair(
                        fixture.scene.producers.native_domain(),
                        EventsDomain::test_standin(fixture.scene.producers.events_id()),
                    );
                    assert!(matches!(
                        ingested.disposition_s1only_original(
                            owner.adapter_mut(),
                            &foreign_producers,
                            input
                        ),
                        Err(RawQuantumRefusal::ForeignCapture)
                    ));
                    assert!(matches!(
                        ingested.disposition_s1only_original(
                            &mut foreign,
                            &fixture.scene.producers,
                            input
                        ),
                        Err(RawQuantumRefusal::ForeignLedger)
                    ));
                    assert!(matches!(
                        ingested.disposition_s1only_original(
                            owner.adapter_mut(),
                            &fixture.scene.producers,
                            old_original.as_ref().unwrap()
                        ),
                        Err(RawQuantumRefusal::Admission)
                    ));
                    let same_shape = input.clone();
                    assert!(matches!(
                        ingested
                            .disposition_s1only_original(
                                owner.adapter_mut(),
                                &fixture.scene.producers,
                                input
                            )
                            .unwrap()
                            .consume_for(&same_shape),
                        Err(RawQuantumRefusal::Admission)
                    ));
                    ingested
                        .disposition_s1only_original(
                            owner.adapter_mut(),
                            &fixture.scene.producers,
                            input,
                        )
                        .unwrap()
                        .consume_for(input)
                        .unwrap();
                    assert_eq!(
                        (
                            owner.ledger().roles_for_test(),
                            owner.adapter().invocation_claims_for_test(),
                            owner.adapter().retained_starts_for_test()
                        ),
                        before,
                        "present-state S1 bookkeeping releases none of the healthy image's real custody"
                    );
                }
                let coordinator = &mut fixture.scene.real.scene.coordinator;
                let mut staged = 0;
                loop {
                    if sequence == 2 {
                        let (prepared, owner) = coordinator.prepared_joint_parts().unwrap();
                        if let Some(input) = prepared.next_admission()
                            && input.journal_binding().3 == victim.caller()
                        {
                            let original = input.collected_origin();
                            let before = (
                                owner.ledger().roles_for_test(),
                                owner.adapter().invocation_claims_for_test(),
                                owner.adapter().retained_starts_for_test(),
                            );
                            // This original REALLY owns H8/END custody, and
                            // its failed ImageSealed claim has not tainted it
                            // yet. Both tokens must use the strict path.
                            assert!(before.0[1] >= 2);
                            {
                                let _unused = ingested
                                    .disposition_s1only_original(
                                        owner.adapter_mut(),
                                        &fixture.scene.producers,
                                        input,
                                    )
                                    .unwrap();
                            }
                            let same_shape = input.clone();
                            assert!(matches!(
                                ingested
                                    .disposition_s1only_original(
                                        owner.adapter_mut(),
                                        &fixture.scene.producers,
                                        input,
                                    )
                                    .unwrap()
                                    .consume_for(&same_shape),
                                Err(RawQuantumRefusal::Admission)
                            ));
                            // A successful new preflight proves neither
                            // unused/wrong token wrote the once-only marker.
                            {
                                let _correct_retry = ingested
                                    .disposition_s1only_original(
                                        owner.adapter_mut(),
                                        &fixture.scene.producers,
                                        input,
                                    )
                                    .unwrap();
                            }
                            assert_eq!(
                                prepared.next_admission().unwrap().collected_origin(),
                                original
                            );
                            assert_eq!(
                                (
                                    owner.ledger().roles_for_test(),
                                    owner.adapter().invocation_claims_for_test(),
                                    owner.adapter().retained_starts_for_test(),
                                ),
                                before
                            );
                        }
                    }
                    // The correct real cursor retry now consumes the token
                    // and writes its marker immediately before this move.
                    if !coordinator
                        .stage_next_prepared_admission_with_disposition(
                            &fixture.scene.producers,
                            &mut ingested,
                        )
                        .unwrap()
                    {
                        break;
                    }
                    staged += 1;
                }
                assert_eq!(staged, 2);
                assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
                coordinator
                    .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
                    .unwrap();
                let mut frame =
                    acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
                if sequence == 2 {
                    assert_eq!(
                        frame.failure_for_test().unwrap().gap,
                        JournalGap::ImageTainted
                    );
                    assert!(
                        !frame
                            .failure_for_test()
                            .unwrap()
                            .affects_domain(healthy.bootstrap().domain())
                    );
                }
                {
                    let ports = fixture
                        .scene
                        .real
                        .scene
                        .coordinator
                        .joint_frame_ports(&fixture.scene.producers)
                        .unwrap();
                    frame.bind_targets(&ports).unwrap();
                }
                fixture.finish_bounded_batch(frame, false);
                let coordinator = &fixture.scene.real.scene.coordinator;
                let healthy_feed = coordinator
                    .registry()
                    .instance_semantic_edges()
                    .find(|record| record.id == healthy.id())
                    .unwrap();
                assert_eq!(
                    healthy_feed.feed.mode(),
                    crate::semantics_key_use::FeedMode::Joint
                );
                assert_eq!(healthy_feed.feed.reduced(), sequence);
                assert_eq!(healthy_feed.semantics.as_ref().unwrap().calls(), sequence);
                let b_module = coordinator
                    .registry()
                    .module_id_for(&fixture.scene.real.modules[1].0)
                    .unwrap();
                let b = coordinator
                    .registry()
                    .instance_semantic_edges()
                    .find(|record| record.caller == victim.caller() && record.module == b_module)
                    .unwrap();
                assert_eq!(b.feed.mode(), crate::semantics_key_use::FeedMode::S1Only);
                assert_eq!(b.feed.reduced(), 0);
                assert_eq!(
                    (b.api_returns, b.semantics.as_ref().unwrap().calls()),
                    (Some(sequence - 1), sequence - 1)
                );
                assert_eq!(coordinator.registry().joint_feeds(), 1);
            }
        }
    }
}

#[test]
fn key_operation_s1only_sibling_raw_reaches_terminal() {
    for sibling_first in [false, true] {
        exercise_s1only_sibling_raw(sibling_first, SiblingLossMoment::None);
    }
}

/// A real moved native prefix is loss regardless of whether its collection
/// predates the ImageSealed refusal or it moves after that genuine refusal.
/// Both original causes/effect buffers remain owned; neither manufactures H3.
#[test]
fn key_operation_s1only_sibling_mixed_loss_overrides_proof_refusal() {
    for sibling_first in [false, true] {
        for moment in [
            SiblingLossMoment::BeforeProofRefusal,
            SiblingLossMoment::AfterProofRefusal,
        ] {
            exercise_s1only_sibling_raw(sibling_first, moment);
        }
    }
}

/// A delivered negative span is not fallback or released history. The real
/// producer's refresh-stashed C original must allow the next quantum while
/// A's exact START/claim/H9 remains owned, even though A's key is tainted.
#[test]
fn key_operation_s1only_sibling_pending_h3_reaches_next_frame() {
    // Healthy progress, native loss in q2, and a damaged original H9 role.
    for arm in 0..3 {
        let PendingH3Scene {
            mut fixture,
            frame: mut q1,
            child_c,
            c_caller,
            c_image,
            end_b,
        } = pending_h3_with_sibling(true, true, &BirthFault);
        use crate::semantics_objects::journal::JournalGap;
        let gaps = q1
            .original_failures_for_test()
            .map(|failure| failure.gap)
            .collect::<Vec<_>>();
        assert_eq!(gaps, [JournalGap::ImageTainted, JournalGap::H3Pending]);
        let effects = q1
            .original_failures_for_test()
            .next()
            .unwrap()
            .effects
            .effects
            .len();
        assert!(
            effects != 0,
            "genuine prior live object produces original loss effects"
        );
        assert!(matches!(
            q1.audit_for_test().h3_for_test(),
            H3DispositionEvidence::Clean {
                staged_max: 5,
                pending_floor: Some(4),
            }
        ));
        let coordinator = &fixture.scene.real.scene.coordinator;
        let a = coordinator
            .registry()
            .joint_feed_targets()
            .find(|target| {
                q1.failure_for_test()
                    .unwrap()
                    .affects_domain(target.bootstrap().domain())
            })
            .unwrap();
        let direct = coordinator
            .registry()
            .instance_semantic_edges()
            .find(|record| record.caller == a.caller() && record.id != a.id())
            .unwrap()
            .id;
        let direct_before = fixture.s1_counts(direct);
        assert_eq!(direct_before, (1, 1, 0, 0, 1));
        let feeds = fixture.feeds();
        let claims = coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test();
        assert_eq!(claims.0, 1);
        assert_eq!(
            claims
                .1
                .iter()
                .map(|(ordinal, _)| *ordinal)
                .collect::<Vec<_>>(),
            [3]
        );
        let starts = coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test();
        let roles = coordinator.joint_capture().ledger().roles_for_test();
        assert_eq!(roles[..4], [0, 3, 0, 1]);
        let audit = coordinator.reference_h3_audit_state();
        assert_eq!(audit, (2, false));
        let h0 = fixture.scene.real.h0.clone();
        let stash_originals = fixture
            .scene
            .real
            .lane
            .with_pending_h3_continuation(|pending| {
                pending
                    .originals()
                    .map(|(position, origin, record, resource)| {
                        (
                            position,
                            origin,
                            record.event.ts_ns,
                            resource.map(|resource| resource.invocation()),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap();
        assert_eq!(stash_originals.len(), 1);
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            q1.bind_targets(&ports).unwrap();
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::LocalPending),
                "the original negative has not reached its consumer"
            );
            let (retained, reason) = q1
                .finish_frame(&mut ports)
                .err()
                .expect("generic finish cannot consume pending H3");
            assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
            q1 = retained;
        }
        // Work includes a visit to an earlier nonaffecting target. Read the
        // SAME original cursor; no assumed one-call/one-effect mapping or
        // unbounded retry can hide a stranded negative consumer.
        let bound = effects
            + fixture
                .scene
                .real
                .scene
                .coordinator
                .registry()
                .joint_feed_targets()
                .count();
        for _ in 0..bound {
            if q1.negative_effects_complete_for_test(a.bootstrap().domain()) == Some(true) {
                break;
            }
            {
                let mut ports = fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_frame_ports(&fixture.scene.producers)
                    .unwrap();
                assert_eq!(
                    q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                    Ok(QuantumSealProgress::LocalPending),
                    "every incomplete original span refuses Future"
                );
            }
            fixture.deliver_one_work(&mut q1);
        }
        assert_eq!(
            q1.negative_effects_complete_for_test(a.bootstrap().domain()),
            Some(true),
            "a nonaffecting target cannot starve the later original negative span"
        );
        assert_eq!(
            fixture.feeds(),
            feeds,
            "q1 delivers negative effects without replay/disposal"
        );
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .retained_starts_for_test(),
            starts
        );
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            claims
        );
        assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
        assert_eq!(coordinator.reference_h3_audit_state(), audit);
        assert_eq!(coordinator.reference_h3_acknowledged_below(), 0);
        if arm == 2 {
            // An actual lost membership is not excused by an effects cursor
            // or a numeric position. No repair/mint is supplied by this test.
            let coordinator = &mut fixture.scene.real.scene.coordinator;
            coordinator
                .joint_capture_mut()
                .ledger_mut()
                .release_collected(fixture.scene.producers.native_domain(), 3);
            let damaged_roles = coordinator.joint_capture().ledger().roles_for_test();
            assert_eq!(damaged_roles[3], 0);
            let mut ports = coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::LocalPending)
            );
            let (retained, reason) = q1
                .finish_pending_h3(&mut ports, &fixture.scene.real.lane)
                .err()
                .expect("missing original H9 role refuses");
            assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
            drop(retained);
            assert_eq!(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture()
                    .ledger()
                    .roles_for_test(),
                damaged_roles
            );
            continue;
        }
        {
            let mut ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            let real = h0.0.borrow().collected_producers.clone().unwrap();
            h0.0.borrow_mut().collected_producers = Some(SessionDrainProducers::test_pair(
                real.native_domain(),
                EventsDomain::test_standin(real.events_id()),
            ));
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::LocalPending)
            );
            h0.0.borrow_mut().collected_producers = Some(real);
            let original_stash = h0.0.borrow_mut().stash.take_outcomes();
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::LocalPending)
            );
            assert_eq!(
                h0.0.borrow_mut().stash.push_all(Vec::new(), original_stash),
                0
            );
            assert_eq!(
                q1.defer_pending_h3(&mut ports, &fixture.scene.real.lane),
                Ok(QuantumSealProgress::AwaitFutureInput),
                "delivered original negative plus exact producer continuation must allow q2"
            );
            let (retained, reason) = q1
                .finish_frame(&mut ports)
                .err()
                .expect("Future still grants no generic finish");
            assert_eq!(reason, RawQuantumRefusal::H3Undisposed);
            q1 = retained;
            q1.finish_pending_h3(&mut ports, &fixture.scene.real.lane)
                .unwrap_or_else(|(_, reason)| {
                    panic!("original pending sibling continuation arm{arm}: {reason:?}")
                });
        }
        assert_eq!(fixture.feeds(), feeds);
        let coordinator = &fixture.scene.real.scene.coordinator;
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .retained_starts_for_test(),
            starts
        );
        assert_eq!(
            coordinator
                .joint_capture()
                .adapter()
                .invocation_claims_for_test(),
            claims
        );
        assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
        assert_eq!(coordinator.reference_h3_audit_state(), audit);
        assert_eq!(coordinator.reference_h3_acknowledged_below(), 0);
        assert_eq!(
            fixture
                .scene
                .real
                .lane
                .with_pending_h3_continuation(|pending| {
                    pending
                        .originals()
                        .map(|(position, origin, record, resource)| {
                            (
                                position,
                                origin,
                                record.event.ts_ns,
                                resource.map(|resource| resource.invocation()),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap(),
            stash_originals
        );

        // The next actual collection merges C's retained q1 original and B's
        // real END; it cannot replay the already-direct S1Only sibling.
        let fault = FrameFault::clean();
        if arm == 1 {
            fault.epoch.set(1);
        }
        fixture.scene.drain.source_mut().push_record(end_b.to_vec());
        let raw = fixture.scene.collect_with_fault(&fault);
        fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
        let batch = fixture.scene.real.tick();
        fixture.scene.admit_providers(child_c.id(), c_caller, &[0]);
        fixture.scene.prepare_batch(batch, 2);
        let admitted = fixture
            .scene
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            admitted
                .iter()
                .map(|input| input.h0_ordinal())
                .collect::<Vec<_>>(),
            [4, 6]
        );
        let current = fixture
            .scene
            .real
            .scene
            .coordinator
            .take_prepared_current_for_birth_test()
            .unwrap();
        let current_c = current
            .into_iter()
            .find(|receipt| receipt.image() == c_image)
            .unwrap();
        let raw = h0.0.borrow_mut().collected.take().unwrap();
        let ingested = raw
            .ingest(
                fixture
                    .scene
                    .real
                    .scene
                    .coordinator
                    .joint_capture_mut()
                    .adapter_mut(),
                &fixture.scene.producers,
                &fixture.grant,
            )
            .unwrap_or_else(|(_, reason)| panic!("actual pending sibling q2: {reason:?}"));
        let mut claims_q2 = Vec::new();
        while let Some((position, proof)) = fixture
            .scene
            .real
            .scene
            .coordinator
            .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
            .unwrap()
        {
            claims_q2.push((position, proof.expect("genuine C/B original admissions")));
        }
        assert_eq!(
            claims_q2
                .iter()
                .map(|(position, _)| *position)
                .collect::<Vec<_>>(),
            [4, 6]
        );
        if arm == 0 {
            fixture.retain_collected_birth(&admitted[0], current_c, claims_q2[0].1);
        }
        // On actual native loss no C birth/Joint grant is minted from claims.
        while fixture
            .scene
            .real
            .scene
            .coordinator
            .stage_next_prepared_admission()
        {}
        assert!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .finish_prepared_semantic_batch(&fixture.scene.real.lane)
        );
        fixture
            .scene
            .real
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
            .unwrap();
        let mut q2 = acquire(&mut fixture.scene, ingested, &fixture.attached, &fault);
        if arm == 1 {
            assert_eq!(q2.failure_for_test().unwrap().gap, JournalGap::FaultChanged);
        } else {
            assert!(q2.failure_for_test().is_none());
        }
        {
            let ports = fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_frame_ports(&fixture.scene.producers)
                .unwrap();
            q2.bind_targets(&ports).unwrap();
        }
        fixture.finish_bounded_batch(q2, false);
        let a_after = fixture
            .feeds()
            .into_iter()
            .find(|feed| feed.id == a.id())
            .unwrap();
        let a_before = feeds.iter().find(|feed| feed.id == a.id()).unwrap();
        assert_eq!(a_after.staged, 0);
        if arm == 0 {
            assert!(a_after.fallback && !a_after.degraded);
            assert_eq!(a_after.reduced - a_before.reduced, 1);
            assert_eq!(a_after.disposed, a_before.disposed);
            assert_eq!(fixture.s1_counts(a.id()), (2, 1, 0, 0, 1));
        } else {
            assert!(a_after.degraded && !a_after.fallback);
            assert_eq!(a_after.reduced, a_before.reduced);
            assert_eq!(a_after.disposed - a_before.disposed, 1);
            assert_eq!(fixture.s1_counts(a.id()), (1, 0, 0, 0, 0));
        }
        assert_eq!(fixture.s1_counts(direct), direct_before);
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_audit_state(),
            (3, false)
        );
        assert_eq!(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .reference_h3_acknowledged_below(),
            0
        );
    }
}

fn fallback_history_then_later_loss(next_frame: bool) {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    fixture.push_two("C_SignInit", 2);
    let fault = FrameFault::clean();
    let mut frame = fixture.audited(2, 2, &fault);
    let first = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .joint_feed_targets()
        .next()
        .unwrap();
    let initial = fixture.feeds();
    {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
    }
    fixture.seal_selected_for_batch(&mut frame, true);
    for _ in 0..32 {
        fixture.deliver_one_work(&mut frame);
        if fixture
            .feeds()
            .iter()
            .find(|feed| feed.id == first.id())
            .unwrap()
            .fallback
        {
            break;
        }
    }
    let fallback = fixture
        .feeds()
        .into_iter()
        .find(|feed| feed.id == first.id())
        .unwrap();
    assert!(fallback.fallback && !fallback.degraded);
    assert_eq!(
        (fallback.staged, fixture.s1_counts(first.id())),
        (0, (2, 1, 0, 0, 1))
    );
    if next_frame {
        fixture.finish_bounded_batch(frame, false);
        fault.epoch.set(1);
        frame = fixture.audited(0, 0, &fault);
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
    } else {
        fault.epoch.set(1);
        let h0 = fixture.scene.real.h0.clone();
        let mut births = NativeFrameBirths {
            h0: &h0,
            attached: &fixture.attached,
            retained: &mut fixture.births,
            seen: Vec::new(),
            unreadable: false,
        };
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        assert_eq!(
            frame.seal_next(&mut ports, &mut births, &fault),
            Ok(QuantumSealProgress::DeliveryReady)
        );
        assert!(
            births.seen.is_empty(),
            "actual moved fault refuses before birth"
        );
    }
    let failure = frame.failure_for_test().unwrap();
    assert_eq!(
        failure.gap,
        crate::semantics_objects::journal::JournalGap::FaultChanged
    );
    assert!(failure.affects_domain(first.bootstrap().domain()));
    assert!(!failure.effects.effects.is_empty());
    let mut foreign = CanonicalFanoutScene::prior_sealed();
    let before = fixture.feeds();
    let mut remaining = 1;
    {
        let mut ports = foreign
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&foreign.scene.producers)
            .unwrap();
        assert_eq!(
            frame.deliver_next_bounded(&mut ports, &mut remaining),
            Err(RawQuantumRefusal::ForeignCapture)
        );
    }
    assert_eq!(remaining, 1);
    assert_eq!(fixture.feeds(), before);
    {
        let mut ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        let (retained, _) = frame
            .finish_frame(&mut ports)
            .err()
            .expect("no early finish before actual affecting negative delivery");
        frame = retained;
    }
    for _ in 0..128 {
        if fixture.deliver_one_work(&mut frame) == QuantumSealProgress::Complete {
            break;
        }
    }
    assert_eq!(
        fixture.s1_counts(first.id()),
        (2, 1, 0, 1, 0),
        "S1Only gates positive replay, never authenticated affecting loss"
    );
    let after = fixture
        .feeds()
        .into_iter()
        .find(|feed| feed.id == first.id())
        .unwrap();
    assert!(after.degraded);
    assert_eq!(
        (after.reduced, after.disposed, after.staged),
        (fallback.reduced, fallback.disposed, 0)
    );
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .feed_mode_for_test(first.id()),
        Some(crate::semantics_key_use::FeedMode::S1Only)
    );
    assert!(
        !fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .keyuse_for_test()
            .open()
            .keys()
            .any(|(id, _)| *id == first.id())
    );
    for feed in fixture.feeds() {
        let prior = initial.iter().find(|old| old.id == feed.id).unwrap();
        if feed.id != first.id() {
            assert!(feed.degraded);
            assert_eq!(
                feed.reduced - prior.reduced + feed.disposed - prior.disposed,
                1
            );
        }
    }
    let counts = fixture.s1_counts(first.id());
    let evidence = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .keyuse_for_test()
        .evidence();
    for _ in 0..3 {
        fixture.deliver_one_work(&mut frame);
    }
    assert_eq!(fixture.s1_counts(first.id()), counts);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .keyuse_for_test()
            .evidence(),
        evidence
    );
    fixture.finish_bounded_batch(frame, false);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_h3_acknowledged_below(),
        0
    );
}

#[test]
fn key_operation_joint_fallback_then_same_frame_loss_invalidates_once() {
    fallback_history_then_later_loss(false);
}

#[test]
fn key_operation_s1only_history_next_frame_loss_invalidates_once() {
    fallback_history_then_later_loss(true);
}

/// A genuine S1Only C may have an exact successful key claim without a Joint
/// birth grant. Its negative must consume only that original and must not
/// strand the healthy, disjoint A/B targets or retire their live objects.
#[test]
fn key_operation_s1only_own_claim_disposes_disjoint_raw() {
    let mut fixture = CanonicalFanoutScene::prior_sealed();
    let before_model = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    let child_c = OwnedStoppedChild::new();
    let caller = fixture.scene.real.bind(
        child_c.id(),
        ImageIdentity {
            task_cookie: 73,
            exec_id: 0,
        },
        0,
    );
    for (sequence, name) in ["C_SignInit", "C_SignUpdate", "C_SignFinal"]
        .into_iter()
        .enumerate()
    {
        fixture
            .scene
            .push(child_c.id(), 0, name, sequence as u64 + 1);
    }
    let raw = fixture.scene.collect_with_fault(&BirthFault);
    fixture.scene.real.h0.0.borrow_mut().collected = Some(raw);
    let batch = fixture.scene.real.tick();
    fixture.scene.admit_providers(child_c.id(), caller, &[0]);
    fixture.scene.prepare_batch(batch, 3);
    let raw = fixture
        .scene
        .real
        .h0
        .0
        .borrow_mut()
        .collected
        .take()
        .unwrap();
    let mut ingested = raw
        .ingest(
            fixture
                .scene
                .real
                .scene
                .coordinator
                .joint_capture_mut()
                .adapter_mut(),
            &fixture.scene.producers,
            &fixture.grant,
        )
        .unwrap_or_else(|(_, reason)| panic!("original C raw: {reason:?}"));
    let coordinator = &mut fixture.scene.real.scene.coordinator;
    let mut claims = Vec::new();
    while let Some((position, proof)) = coordinator
        .claim_next_prepared_admission(&fixture.scene.producers, &ingested)
        .unwrap()
    {
        assert!(
            proof.is_ok(),
            "successful real C claims are not a Joint feed grant"
        );
        claims.push(position);
    }
    assert_eq!(claims, [3, 4, 5]);
    let original_claims = coordinator
        .joint_capture()
        .adapter()
        .invocation_claims_for_test();
    let starts = coordinator
        .joint_capture()
        .adapter()
        .retained_starts_for_test();
    let roles = coordinator.joint_capture().ledger().roles_for_test();
    assert_eq!(roles[..4], [0, 3, 0, 0]);
    let mut staged = 0;
    while coordinator
        .stage_next_prepared_admission_with_disposition(&fixture.scene.producers, &mut ingested)
        .unwrap_or_else(|reason| {
            panic!("exact own S1Only claim must retain negative disposition, not stall: {reason:?}")
        })
    {
        staged += 1;
    }
    assert_eq!(staged, 3);
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .invocation_claims_for_test(),
        original_claims
    );
    assert_eq!(
        coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test(),
        starts
    );
    assert_eq!(coordinator.joint_capture().ledger().roles_for_test(), roles);
    assert!(coordinator.finish_prepared_semantic_batch(&fixture.scene.real.lane));
    coordinator
        .commit_batch_with_semantics(false, Some(&mut fixture.scene.real.lane))
        .unwrap();
    let c = coordinator
        .registry()
        .instance_semantic_edges()
        .find(|record| record.caller == caller)
        .unwrap()
        .id;
    assert_eq!(
        coordinator.registry().feed_mode_for_test(c),
        Some(crate::semantics_key_use::FeedMode::S1Only)
    );
    assert_eq!(fixture.s1_counts(c), (3, 1, 1, 0, 0));
    let mut frame = acquire(&mut fixture.scene, ingested, &fixture.attached, &BirthFault);
    assert_eq!(
        frame.failure_for_test().unwrap().gap,
        crate::semantics_objects::journal::JournalGap::ImageTainted
    );
    assert!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .adapter()
            .retained_starts_for_test()
            .is_empty()
    );
    fixture.scene.assert_claims(&[]);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_capture()
            .ledger()
            .roles_for_test()[..4],
        [0, 0, 0, 0]
    );
    {
        let ports = fixture
            .scene
            .real
            .scene
            .coordinator
            .joint_frame_ports(&fixture.scene.producers)
            .unwrap();
        frame.bind_targets(&ports).unwrap();
    }
    fixture.finish_bounded_batch(frame, false);
    assert_eq!(fixture.s1_counts(c), (3, 1, 1, 0, 0));
    let after_model = fixture
        .scene
        .real
        .scene
        .coordinator
        .joint_capture()
        .model()
        .project();
    for object in &before_model.objects {
        assert_eq!(
            after_model.object(object.id).unwrap().lifetime,
            Lifetime::Live
        );
    }
    assert!(
        fixture
            .feeds()
            .iter()
            .all(|feed| feed.staged == 0 && !feed.degraded && !feed.fallback)
    );
}

/// Scripted discovery service for the progress tests: no Engine and no
/// transport. Every credit reports a pending backlog with zero records
/// and counts the call; the first `progressed_for` credits report Engine
/// progress, later ones report none.
struct DiscoveryScriptIo<'a> {
    producers: &'a SessionDrainProducers,
    discovery: &'a crate::events::DiscoveryDomain,
    calls: Cell<usize>,
    progressed_for: usize,
}

impl crate::inventory_semantics::JointMachineIo for DiscoveryScriptIo<'_> {
    fn producers(&self) -> &SessionDrainProducers {
        self.producers
    }

    fn finish_discovery_domain(&self) -> Result<&crate::events::DiscoveryDomain, SemanticRefusal> {
        Ok(self.discovery)
    }

    fn service_finish_discovery(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _coordinator: &mut InventoryCoordinator<OsProcessSource>,
        _q: &crate::attach::CollectedFinishQ,
        _work: usize,
    ) -> Result<crate::inventory_semantics::LaneDrainOutcome, SemanticRefusal> {
        self.calls.set(self.calls.get() + 1);
        Ok(crate::inventory_semantics::LaneDrainOutcome {
            records: 0,
            post_q: false,
            backlog: true,
            failed: false,
        })
    }

    fn finish_discovery_progressed(
        &self,
        _coordinator: &InventoryCoordinator<OsProcessSource>,
    ) -> bool {
        self.calls.get() <= self.progressed_for
    }

    fn collect_raw(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _adapter: &mut JournalAdapter,
        _reserve: &crate::semantics_edge::resources::SemanticResourceReserver,
        _capacity: usize,
        _work: usize,
    ) -> Result<(RawJointQuantum, Option<crate::events::DispatchPoll>), RawQuantumRefusal> {
        unreachable!("discovery-script IO never collects");
    }

    fn continue_raw(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _raw: &mut RawJointQuantum,
        _adapter: &mut JournalAdapter,
        _work: usize,
    ) -> Result<crate::events::DispatchPoll, RawQuantumRefusal> {
        unreachable!("discovery-script IO never continues a Raw");
    }

    fn tick_collected(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _bindings: &[SemanticCallerBinding],
        _raw: &mut RawJointQuantum,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        unreachable!("discovery-script IO never ticks");
    }

    fn prepare_publication(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _coordinator: &mut InventoryCoordinator<OsProcessSource>,
        _raw: &mut RawJointQuantum,
        _engine_changed: bool,
    ) -> anyhow::Result<()> {
        unreachable!("discovery-script IO never prepares a publication");
    }

    #[allow(clippy::too_many_arguments)]
    fn consume_birth(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _candidate: H0BirthCandidate,
        _absence: Option<CommittedAbsenceBirth>,
        _input: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
        _binding: &SemanticCallerBinding,
        _proof: &JournalDomainProof,
        _adapter: &JournalAdapter,
    ) -> Result<RetainedBirthWitness, BirthObservationRefusal> {
        unreachable!("discovery-script IO never consumes births");
    }

    fn acquire_absence(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _binding: &SemanticCallerBinding,
        _slot: u32,
        _adapter: &mut JournalAdapter,
    ) -> Result<CommittedAbsenceBirth, BirthObservationRefusal> {
        unreachable!("discovery-script IO never acquires absences");
    }

    fn absence_query_storage_bytes(
        &self,
        _lane: &AttestedSemanticLane,
        _object: PinnedObjectId,
        _target_copy: usize,
    ) -> Option<usize> {
        unreachable!("discovery-script IO never sizes absence queries");
    }

    fn with_native<R>(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _witnesses: &crate::inventory_semantics::RetainedJointBirths,
        _inspect: impl for<'io> FnOnce(crate::inventory_semantics::JointCommitIo<'io>) -> R,
    ) -> Result<R, SemanticRefusal> {
        unreachable!("discovery-script IO never touches native handles");
    }
}

/// Poll Finish one discovery credit from a deeper stack frame with a
/// large local, so a stack-resident Q address cannot match a direct
/// poll's address.
fn poll_finish_from_deeper_frame(
    scene: &mut MachineScene,
) -> Result<crate::discovery::engine::inventory_coordinator::JointCommitProgress, SemanticRefusal> {
    let pad = std::hint::black_box([0u8; 4096]);
    let result = scene.poll_finish(1);
    std::hint::black_box(pad);
    result
}

/// The Q the discovery IO sees keeps one heap address across call
/// depths and machine moves: it is boxed once at observation.
#[test]
fn joint_machine_finish_q_address_is_stable_across_moves() {
    use crate::inventory_semantics::LiveJointMachine;
    let child = OwnedStoppedChild::new();
    let exited_pid = child.id();
    drop(child);
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(vec![
        finish_discovery_bytes(exited_pid, 100),
        finish_discovery_bytes(exited_pid, 101),
        finish_discovery_bytes(exited_pid, 102),
    ]);
    fixture.begin_finish().unwrap();
    // The first poll observes Q and returns before discovery.
    fixture.poll_finish(1).unwrap();
    assert!(fixture.machine.retained_finish_q_for_test().is_some());
    fixture.poll_finish(1).unwrap();
    let direct = LiveJointMachine::finish_q_addr_for_test();
    assert_ne!(direct, 0, "discovery service must observe the Q address");
    poll_finish_from_deeper_frame(&mut fixture).unwrap();
    let deep = LiveJointMachine::finish_q_addr_for_test();
    let mut other = MachineScene::new(1);
    std::mem::swap(&mut fixture.machine, &mut other.machine);
    std::mem::swap(&mut fixture.machine, &mut other.machine);
    fixture.poll_finish(1).unwrap();
    let moved = LiveJointMachine::finish_q_addr_for_test();
    assert_eq!(
        direct, deep,
        "the Q address must not depend on caller stack depth"
    );
    assert_eq!(direct, moved, "the Q address must survive machine moves");
}

/// A Q that no longer matches its discovery owner latches the Finish
/// disposition at once; the latched first reason is kept.
#[test]
fn joint_machine_finish_q_mismatch_latches_disposition() {
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    fixture.begin_finish().unwrap();
    fixture.poll_finish(1).unwrap();
    assert!(fixture.machine.retained_finish_q_for_test().is_some());
    assert!(!fixture.machine.finish_disposition_required());
    // Present another owning DISCOVERY allocation at the native I/O
    // boundary; the retained Q cannot match it.
    let original_finish = fixture.finish.take().unwrap();
    fixture.enable_finish_fixture(Vec::new());
    assert_eq!(fixture.poll_finish(1), Err(SemanticRefusal::Unavailable));
    assert!(
        fixture.machine.finish_disposition_required(),
        "a Q mismatch must latch the Finish disposition"
    );
    fixture.finish = Some(original_finish);
    assert_eq!(
        fixture.poll_finish(1),
        Err(SemanticRefusal::Unavailable),
        "the first latched reason is kept after the owner is restored"
    );
    assert!(fixture.machine.finish_disposition_required());
}

/// Retryable `ProviderStorage` refusals count over the whole Finish
/// without reset; the 100th latches the disposition.
#[test]
fn joint_machine_finish_storage_retry_is_bounded() {
    use crate::inventory_semantics::JOINT_FINISH_STORAGE_RETRIES;
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    fixture.begin_finish().unwrap();
    fixture.reach_finish_stop_ready();
    let bytes = fixture.finish_storage_bytes();
    assert!(bytes > 0);
    let resource = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let _hold = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(resource.limit_bytes - resource.charged_bytes - (bytes - 1))
        .unwrap();
    for n in 1..JOINT_FINISH_STORAGE_RETRIES {
        assert_eq!(
            fixture.poll_finish(1),
            Err(SemanticRefusal::ProviderStorage),
            "refusal {n}"
        );
        assert!(
            !fixture.machine.finish_disposition_required(),
            "refusal {n} must not latch yet"
        );
    }
    assert_eq!(
        fixture.poll_finish(1),
        Err(SemanticRefusal::ProviderStorage)
    );
    assert!(
        fixture.machine.finish_disposition_required(),
        "the 100th storage refusal latches the disposition"
    );
    assert_eq!(
        fixture.poll_finish(1),
        Err(SemanticRefusal::ProviderStorage),
        "the first latched reason is kept"
    );
}

/// One Finish poll spends discovery credits up to its budget: 8 queued
/// single-credit records drain in one budgeted poll, one per credit.
#[test]
fn joint_machine_finish_discovery_spends_budget_in_one_poll() {
    let child = OwnedStoppedChild::new();
    let exited_pid = child.id();
    drop(child);
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(
        (100u64..108)
            .map(|at| finish_discovery_bytes(exited_pid, at))
            .collect(),
    );
    fixture.begin_finish().unwrap();
    fixture.poll_finish(1).unwrap();
    fixture.poll_finish(1024).unwrap();
    assert_eq!(
        fixture
            .finish
            .as_ref()
            .unwrap()
            .observer
            .discovery_remaining(),
        0,
        "one budgeted poll consumes all 8 queued records"
    );
    assert_eq!(fixture.finish.as_ref().unwrap().staged.len(), 0);
    assert_eq!(
        fixture
            .scene
            .real
            .scene
            .coordinator
            .reference_collected_finish_discovery_backlog(0),
        (0, false)
    );
    // Twin: a one-action budget consumes exactly one record.
    let child = OwnedStoppedChild::new();
    let exited_pid = child.id();
    drop(child);
    let mut twin = MachineScene::new(1);
    twin.prime(1);
    twin.enable_finish_fixture(
        (100u64..108)
            .map(|at| finish_discovery_bytes(exited_pid, at))
            .collect(),
    );
    twin.begin_finish().unwrap();
    twin.poll_finish(1).unwrap();
    twin.poll_finish(1).unwrap();
    assert_eq!(
        twin.finish.as_ref().unwrap().observer.discovery_remaining(),
        7,
        "a one-action budget consumes exactly one record"
    );
}

/// An owner-validation refusal inside Finish latches the disposition.
#[test]
fn joint_machine_finish_latches_validate_owner_error() {
    use crate::inventory_semantics::FinishSite;
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    fixture.begin_finish().unwrap();
    fixture
        .machine
        .inject_finish_site_for_test(FinishSite::ValidateOwner);
    assert_eq!(fixture.poll_finish(1), Err(SemanticRefusal::Unavailable));
    assert!(fixture.machine.finish_disposition_required());
    assert_eq!(
        fixture.poll_finish(1),
        Err(SemanticRefusal::Unavailable),
        "the first latched reason is kept"
    );
}

/// A discovery-domain refusal inside Finish latches the disposition.
#[test]
fn joint_machine_finish_latches_discovery_domain_error() {
    use crate::inventory_semantics::FinishSite;
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    fixture.begin_finish().unwrap();
    fixture.poll_finish(1).unwrap();
    fixture
        .machine
        .inject_finish_site_for_test(FinishSite::DiscoveryDomain);
    assert_eq!(fixture.poll_finish(1), Err(SemanticRefusal::Unavailable));
    assert!(fixture.machine.finish_disposition_required());
    assert_eq!(
        fixture.poll_finish(1),
        Err(SemanticRefusal::Unavailable),
        "the first latched reason is kept"
    );
}

/// A completion refusal at publication latches the disposition and
/// publishes nothing.
#[test]
fn joint_machine_finish_latches_complete_finish_error() {
    use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
    use crate::inventory_semantics::FinishSite;
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    fixture.begin_finish().unwrap();
    fixture
        .machine
        .inject_finish_site_for_test(FinishSite::CompleteFinish);
    let mut refused = false;
    for _ in 0..512 {
        match fixture.poll_finish(1) {
            Err(reason) => {
                assert_eq!(reason, SemanticRefusal::Unavailable);
                refused = true;
                break;
            }
            Ok(JointCommitProgress::Published(_)) => {
                panic!("an injected completion refusal must not publish")
            }
            Ok(JointCommitProgress::Pending) => {}
        }
    }
    assert!(
        refused,
        "the publish branch must surface the injected refusal"
    );
    assert!(fixture.machine.finish_disposition_required());
    assert!(
        !fixture.scene.real.lane.is_finished(),
        "a refused completion publishes nothing"
    );
    assert_eq!(
        fixture.poll_finish(1),
        Err(SemanticRefusal::Unavailable),
        "the first latched reason is kept"
    );
}

/// A missing publication receipt after completion latches: the lane is
/// finished, but the Finish disposition is still required.
#[test]
fn joint_machine_finish_latches_missing_receipt_error() {
    use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
    use crate::inventory_semantics::FinishSite;
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    fixture.begin_finish().unwrap();
    fixture
        .machine
        .inject_finish_site_for_test(FinishSite::MissingReceipt);
    let mut refused = false;
    for _ in 0..512 {
        match fixture.poll_finish(1) {
            Err(reason) => {
                assert_eq!(reason, SemanticRefusal::Unavailable);
                refused = true;
                break;
            }
            Ok(JointCommitProgress::Published(_)) => {
                panic!("a missing receipt must not publish")
            }
            Ok(JointCommitProgress::Pending) => {}
        }
    }
    assert!(
        refused,
        "the publish branch must surface the missing receipt"
    );
    assert!(
        fixture.scene.real.lane.is_finished(),
        "completion ran before the missing receipt"
    );
    assert!(
        fixture.machine.finish_disposition_required(),
        "the missing receipt latches the disposition"
    );
    assert_eq!(
        fixture.poll_finish(1),
        Err(SemanticRefusal::Unavailable),
        "the first latched reason is kept"
    );
}

/// A pending-report validation refusal latches the disposition.
#[test]
fn joint_machine_finish_latches_pending_report_error() {
    use crate::inventory_semantics::FinishSite;
    let (mut fixture, observer, _foreign) = pending_h0_finish_fixture(false);
    let q = observe_pending_finish_q(&fixture, &observer);
    // Resolve once: AwaitH0 becomes a retained PendingQ report.
    fixture
        .resolve_pending_q(&q, observer.discovery_domain(), 1)
        .unwrap();
    assert!(
        fixture
            .machine
            .retained_pending_q_report_for_test()
            .is_some()
    );
    fixture
        .machine
        .inject_finish_site_for_test(FinishSite::PendingReport);
    assert_eq!(
        fixture.resolve_pending_q(&q, observer.discovery_domain(), 1),
        Err(SemanticRefusal::Unavailable)
    );
    assert!(
        fixture.machine.finish_disposition_required(),
        "the pending-report refusal latches the disposition"
    );
    assert_eq!(
        fixture.poll_finish(1),
        Err(SemanticRefusal::Unavailable),
        "the next poll keeps the first latched reason"
    );
}

/// A pending-phase refusal latches the disposition.
#[test]
fn joint_machine_finish_latches_pending_phase_error() {
    use crate::inventory_semantics::FinishSite;
    let (mut fixture, observer, _foreign) = pending_h0_finish_fixture(false);
    let q = observe_pending_finish_q(&fixture, &observer);
    // Resolve once: AwaitH0 becomes a retained PendingQ report.
    fixture
        .resolve_pending_q(&q, observer.discovery_domain(), 1)
        .unwrap();
    assert!(
        fixture
            .machine
            .retained_pending_q_report_for_test()
            .is_some()
    );
    fixture
        .machine
        .inject_finish_site_for_test(FinishSite::PendingPhase);
    assert_eq!(
        fixture.resolve_pending_q(&q, observer.discovery_domain(), 1),
        Err(SemanticRefusal::Unavailable)
    );
    assert!(
        fixture.machine.finish_disposition_required(),
        "the pending-phase refusal latches the disposition"
    );
    assert_eq!(
        fixture.poll_finish(1),
        Err(SemanticRefusal::Unavailable),
        "the next poll keeps the first latched reason"
    );
}

/// A refused Q-box reservation latches at once; no Finish starts.
#[test]
fn joint_machine_finish_q_box_refusal_latches() {
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    // One byte short of the Q box: the reservation must refuse.
    let need = size_of::<crate::attach::CollectedFinishQ>()
        + crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING;
    let resource = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot();
    let _hold = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .reserve_semantic_storage(resource.limit_bytes - resource.charged_bytes - (need - 1))
        .unwrap();
    assert_eq!(
        fixture.begin_finish(),
        Err(SemanticRefusal::ProviderStorage)
    );
    assert!(
        fixture.machine.finish_disposition_required(),
        "the Q-box refusal latches at once"
    );
    assert!(
        !fixture.machine.finish_begun(),
        "no Finish starts without its Q box"
    );
}

/// A duplicate begin refuses without latching; the Finish continues.
#[test]
fn joint_machine_finish_duplicate_begin_does_not_latch() {
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    fixture.begin_finish().unwrap();
    assert_eq!(fixture.begin_finish(), Err(SemanticRefusal::Unavailable));
    assert!(
        !fixture.machine.finish_disposition_required(),
        "a duplicate begin latches nothing"
    );
    fixture.finish_published();
}

/// A pre-machine refusal latches the lane flag; a finished lane's
/// refusal leaves it clear.
#[test]
fn joint_lane_finish_wrapper_error_latches_lane_flag() {
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    fixture
        .scene
        .real
        .lane
        .set_inject_pre_machine_for_test(true);
    let mut budget = crate::inventory_semantics::JointWorkBudget {
        remaining_actions: 1,
        deadline: Instant::now() + Duration::from_secs(10),
    };
    assert!(
        fixture
            .scene
            .real
            .lane
            .poll_joint_finish(&mut fixture.scene.real.scene.coordinator, &mut budget)
            .is_err()
    );
    assert!(
        fixture.scene.real.lane.joint_finish_disposition_required(),
        "a pre-machine refusal latches the lane flag"
    );
    // Twin: a finished lane's refusal leaves the flag clear.
    let mut finished = MachineScene::new(1);
    finished.prime(1);
    finished.enable_finish_fixture(Vec::new());
    finished.begin_finish().unwrap();
    finished.finish_published();
    assert!(finished.scene.real.lane.is_finished());
    let mut budget = crate::inventory_semantics::JointWorkBudget {
        remaining_actions: 1,
        deadline: Instant::now() + Duration::from_secs(10),
    };
    assert!(
        finished
            .scene
            .real
            .lane
            .poll_joint_finish(&mut finished.scene.real.scene.coordinator, &mut budget)
            .is_err()
    );
    assert!(
        !finished.scene.real.lane.joint_finish_disposition_required(),
        "a finished lane's refusal latches nothing"
    );
}

/// Progress without records is not capped: 500 progressed credits with
/// zero records are all spent, while idle credits yield after 64.
#[test]
fn joint_machine_finish_progress_without_records_is_not_capped() {
    use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    fixture.begin_finish().unwrap();
    fixture.poll_finish(1).unwrap();
    assert!(
        !fixture
            .scene
            .real
            .scene
            .coordinator
            .collected_finish_progressed(),
        "no discovery service ran yet"
    );
    let (result, calls) = fixture.poll_finish_discovery_scripted(1024, 500);
    assert!(matches!(result, Ok(JointCommitProgress::Pending)));
    assert!(
        calls >= 500,
        "progressed credits are not capped, got {calls}"
    );
    // Twin: without progress the poll yields after exactly 64 credits.
    let mut idle = MachineScene::new(1);
    idle.prime(1);
    idle.enable_finish_fixture(Vec::new());
    idle.begin_finish().unwrap();
    idle.poll_finish(1).unwrap();
    let (result, calls) = idle.poll_finish_discovery_scripted(1024, 0);
    assert!(matches!(result, Ok(JointCommitProgress::Pending)));
    assert_eq!(calls, 64, "idle credits yield after exactly 64");
}

/// With a grant-less Q, the machine's own Raw-minted grant is
/// admissible and a foreign scene's grant is refused.
#[test]
fn joint_machine_finish_grant_predicate_refuses_foreign_producers() {
    use crate::inventory_semantics::finish_grant_admissible;
    use crate::semantics_objects::journal::SessionDrainGrant;
    let mut scene_a = MachineScene::new(1);
    scene_a
        .scene
        .push(std::process::id(), 0, "C_CreateObject", 1);
    scene_a.reach_phase("BindingKeys");
    let grant_a = SessionDrainGrant::observe(
        &scene_a.scene.producers,
        scene_a
            .scene
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .next()
            .unwrap(),
    )
    .unwrap();
    let mut scene_b = MachineScene::new(1);
    scene_b
        .scene
        .push(std::process::id(), 0, "C_CreateObject", 1);
    scene_b.reach_phase("BindingKeys");
    let grant_b = SessionDrainGrant::observe(
        &scene_b.scene.producers,
        scene_b
            .scene
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
            .unwrap()
            .admissions()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_ne!(
        grant_a, grant_b,
        "the two scenes mint distinct drain grants"
    );
    // A's grant-less Q: observed before any admission.
    let observer_a = crate::attach::CollectedFinishQObserverForTest::with_discovery_bytes(
        &scene_a.scene.producers,
        Vec::new(),
    );
    observer_a.request_stop();
    let q_a = observer_a
        .observe(&scene_a.scene.producers, None, &scene_a.scene.drain)
        .unwrap()
        .unwrap();
    assert!(q_a.observed_without_grant());
    assert!(
        finish_grant_admissible(&q_a, &grant_a, &scene_a.scene.producers),
        "the own Raw-minted grant stays admissible without a retained grant"
    );
    assert!(
        !finish_grant_admissible(&q_a, &grant_b, &scene_a.scene.producers),
        "a foreign scene's grant is refused"
    );
}

#[path = "joint_cells_machine.rs"]
mod cells;

/// A promotion Finish drains to Q without entering the Engine
/// (OD-11): three exit records and one birth before Q are counted
/// and dropped, the engine's collected-finish entry is never
/// called, and the Finish still publishes. The twin without the
/// flag enters the engine. Engine facts have no test reader, so
/// the zero-call count (the only engine entry on this path) plus
/// the twin control carry the untouched-engine claim.
#[test]
fn joint_machine_promotion_finish_never_enters_engine() {
    use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
    for promotion in [true, false] {
        let child = OwnedStoppedChild::new();
        let exited_pid = child.id();
        drop(child);
        let mut fixture = MachineScene::new(1);
        fixture.prime(1);
        fixture.enable_finish_fixture(vec![
            finish_discovery_bytes(exited_pid, 100),
            finish_discovery_bytes(exited_pid, 101),
            finish_discovery_bytes(exited_pid, 102),
            finish_exec_bytes(exited_pid, 103),
        ]);
        if promotion {
            fixture
                .scene
                .real
                .scene
                .coordinator
                .set_promotion_finish(true);
        }
        fixture.begin_finish().unwrap();
        let mut published = 0;
        for _ in 0..512 {
            match fixture.poll_finish(64) {
                Ok(JointCommitProgress::Published(_)) => {
                    published += 1;
                    break;
                }
                Ok(JointCommitProgress::Pending) => {}
                Err(reason) => {
                    assert!(!promotion, "promotion must publish, not refuse: {reason:?}");
                }
            }
        }
        let coordinator = &fixture.scene.real.scene.coordinator;
        if promotion {
            assert_eq!(published, 1, "promotion publishes");
            assert_eq!(
                coordinator.engine_collected_finish_calls(),
                0,
                "promotion never enters the engine"
            );
            assert_eq!(
                coordinator.promotion_records_discarded(),
                4,
                "3 exits + 1 birth counted and dropped"
            );
        } else {
            assert!(
                coordinator.engine_collected_finish_calls() > 0,
                "the twin without the flag enters the engine"
            );
        }
    }
}

/// Promotion ignores shared engine backlog (N2): seeded engine
/// work stays outstanding and untouched while the promotion
/// publishes past it.
#[test]
fn joint_machine_promotion_finish_ignores_shared_engine_backlog() {
    use crate::discovery::engine::inventory_coordinator::JointCommitProgress;
    let mut fixture = MachineScene::new(1);
    fixture.prime(1);
    fixture.enable_finish_fixture(Vec::new());
    fixture
        .scene
        .real
        .scene
        .coordinator
        .seed_collected_finish_work_for_test(crate::process::ProcessViewId(4243));
    let (held_before, outstanding_before) = fixture
        .scene
        .real
        .scene
        .coordinator
        .reference_collected_finish_discovery_backlog(0);
    assert!(
        outstanding_before,
        "the seeded work is outstanding before the finish"
    );
    fixture
        .scene
        .real
        .scene
        .coordinator
        .set_promotion_finish(true);
    fixture.begin_finish().unwrap();
    let mut published = 0;
    for _ in 0..512 {
        match fixture
            .poll_finish(64)
            .expect("promotion polls must succeed")
        {
            JointCommitProgress::Published(_) => {
                published += 1;
                break;
            }
            JointCommitProgress::Pending => {}
        }
    }
    assert_eq!(published, 1, "promotion publishes past the backlog");
    let coordinator = &fixture.scene.real.scene.coordinator;
    assert_eq!(
        coordinator.engine_collected_finish_calls(),
        0,
        "promotion never enters the engine"
    );
    let (held_after, outstanding_after) =
        coordinator.reference_collected_finish_discovery_backlog(0);
    assert!(
        outstanding_after,
        "the seeded work is still outstanding: ignored and untouched"
    );
    assert_eq!(
        held_after, held_before,
        "the seeded intent and pending exit are unchanged afterwards"
    );
    assert!(
        !fixture.machine.finish_disposition_required(),
        "finish_disposition_required() stays false past the backlog"
    );
    assert_eq!(
        coordinator.promotion_records_discarded(),
        0,
        "the empty discovery drains nothing"
    );
}
/// The Binding reservation arithmetic pins: exact element sizes the pool
/// charges multiply, the pool limit, and the pinned-toolchain `collect`
/// growth law the per-receipt instance charge relies on. Any layout or
/// toolchain drift must re-audit the reservation, never silently squeeze it.
#[test]
fn joint_machine_receipt_model_sizes_and_collect_growth() {
    use std::mem::size_of;
    assert_eq!(size_of::<crate::discovery::instances::InstanceId>(), 8);
    assert_eq!(
        size_of::<crate::semantic_capture::CurrentPartitionReceipt>(),
        488
    );
    assert_eq!(size_of::<crate::semantic_capture::TickOutcome>(), 784);
    assert_eq!(size_of::<crate::inventory_semantics::LaneNegative>(), 16);
    assert_eq!(size_of::<crate::inventory_semantics::SemanticBatch>(), 128);
    assert_eq!(size_of::<crate::semantic_capture::Endpoint>(), 16);
    assert_eq!(
        size_of::<crate::semantics_edge::resources::ResourceLease>(),
        16
    );
    assert_eq!(
        crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING,
        32
    );
    assert_eq!(
        crate::semantics_edge::resources::SEMANTIC_RESOURCE_LIMIT,
        64 * 1024 * 1024
    );
    assert_eq!(crate::discovery::instances::MAX_INSTANCES, 4_096);
    assert_eq!(crate::discovery::instances::MAX_PENDING, 1_024);
    assert_eq!(crate::inventory_semantics::MAX_LANE_NEGATIVES, 64);
    // The exact `collect` shape `InstanceRouter::current_instances` uses to
    // build a receipt's id list: filter_map over partition pairs. Capacity
    // stays within twice the length plus one minimal allocation.
    for len in 0..=4_096usize {
        let partitions: Vec<(u64, Option<u64>)> =
            (0..len as u64).map(|base| (base, Some(base))).collect();
        let ids: Vec<u64> = partitions.iter().filter_map(|(_, id)| *id).collect();
        assert_eq!(ids.len(), len);
        assert!(
            ids.capacity() <= 2 * len + 4,
            "len={len} cap={} exceeds the pinned growth law",
            ids.capacity()
        );
    }
}

/// A full H0 transaction at the widest system-scale spread must bind: 1,024
/// pending call records (the most the collector holds) over 1,024 distinct
/// caller partitions across five callers publish through the real collected
/// machine within the shared 64 MiB semantic pool. Receipts are minted per
/// partition, never per record, so this is the most receipts one Binding
/// pass can accumulate.
#[test]
fn joint_machine_full_transaction_binds_at_system_partition_spread() {
    const PARTITIONS: usize = crate::discovery::instances::MAX_PENDING;
    let children = [
        OwnedStoppedChild::new(),
        OwnedStoppedChild::new(),
        OwnedStoppedChild::new(),
        OwnedStoppedChild::new(),
    ];
    let mut fixture = MachineScene::new(1);
    let pid = std::process::id();
    let mut pids = vec![pid];
    for (offset, child) in children.iter().enumerate() {
        let caller_pid = child.id();
        fixture.scene.real.bind(
            caller_pid,
            ImageIdentity {
                task_cookie: 100 + offset as u64,
                exec_id: 0,
            },
            0,
        );
        pids.push(caller_pid);
    }
    // One transaction holds at most RAW_CAPACITY wire pulls; the scripted
    // ring reports a 4,096-byte window, so at most 511 wire records may be
    // queued at any consumption cut. Feed the ring while the collector is
    // backlogged, exactly as producers refill a live ring during a pass.
    fixture.scene.drain.source_mut().bound = 4_096;
    let mut pushed_calls = 0usize;
    let push_call = |fixture: &mut MachineScene, index: usize| {
        // One fresh caller image per record, round-robin over the callers:
        // distinct (cookie, exec, slot) partitions, the widest spread one
        // transaction can carry.
        let record_pid = pids[index % pids.len()];
        fixture
            .scene
            .real
            .h0
            .0
            .borrow_mut()
            .io
            .targets
            .get_mut(&record_pid)
            .unwrap()
            .1 = ImageIdentity {
            task_cookie: 1_000 + index as u64,
            exec_id: 0,
        };
        fixture
            .scene
            .push(record_pid, 0, "C_CreateObject", index as u64 + 1);
    };
    for index in 0..255 {
        push_call(&mut fixture, index);
        pushed_calls += 1;
    }
    assert_eq!(fixture.scene.drain.source_mut().remaining(), 510);
    let limit = crate::semantics_edge::resources::SEMANTIC_RESOURCE_LIMIT;
    let mut peak_charged = 0usize;
    let mut max_current = 0usize;
    let mut max_entries = 0usize;
    let mut all_receipts_named = true;
    let mut services = 0usize;
    let mut pulls = 0usize;
    let mut published = false;
    for _ in 0..8192 {
        let charged = fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes;
        peak_charged = peak_charged.max(charged);
        if let Some(prepared) = fixture
            .scene
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
        {
            // Births consume the prepared receipts as they install, so the
            // first prepared view holds the complete accumulated set.
            max_current = max_current.max(prepared.current_receipts().len());
            max_entries = max_entries.max(prepared.entry_count());
            all_receipts_named &= prepared
                .current_receipts()
                .iter()
                .all(|receipt| !receipt.instances().is_empty());
        }
        // Single-wire pulls while collecting keep the backlog true so all
        // 1,024 calls accumulate into one transaction; wider budgets after.
        let collecting = matches!(
            fixture.machine.diagnostic_snapshot_for_test().0,
            "Idle" | "Collecting"
        );
        let work = if collecting { 1 } else { 1024 };
        match fixture.service(work) {
            Ok(crate::inventory_semantics::JointServiceProgress::Published) => {
                services += 1;
                published = true;
                break;
            }
            Ok(crate::inventory_semantics::JointServiceProgress::Pending) => {
                services += 1;
                if collecting {
                    pulls += 1;
                    if pulls % 2 == 1 && pushed_calls < PARTITIONS {
                        push_call(&mut fixture, pushed_calls);
                        pushed_calls += 1;
                    }
                }
            }
            Err(reason) => {
                panic!(
                    "a full 1,024-partition transaction must bind within the semantic pool: \
                     refused {reason:?} at {:?} after {services} services, peak_charged={peak_charged}",
                    fixture.machine.diagnostic_snapshot_for_test(),
                );
            }
        }
    }
    assert_eq!(
        pushed_calls, PARTITIONS,
        "all 1,024 calls fed into the single transaction"
    );
    assert!(published, "the full transaction must publish");
    let charged = fixture
        .scene
        .real
        .scene
        .coordinator
        .registry()
        .semantic_resource_snapshot()
        .charged_bytes;
    peak_charged = peak_charged.max(charged);
    eprintln!(
        "machine_scale partitions={PARTITIONS} callers={} services={services} \
         max_current={max_current} max_entries={max_entries} peak_charged={peak_charged} limit={limit}",
        pids.len(),
    );
    assert!(
        peak_charged < limit,
        "peak {peak_charged} must stay under the shared semantic pool {limit}"
    );
    assert_eq!(
        max_current, PARTITIONS,
        "one current-partition receipt per distinct input partition"
    );
    assert_eq!(max_entries, PARTITIONS, "one admission per completed call");
    assert!(
        all_receipts_named,
        "every minted receipt names its partition's instances"
    );
    assert_eq!(fixture.scene.drain.source_mut().remaining(), 0);
}

/// A genuinely exhausted pool still refuses at Binding with the named storage
/// reason before any watched text is copied or custody moves. The
/// partition-sized bound must never turn this into unbounded allocation.
#[test]
fn joint_machine_binding_precharge_still_refuses_an_exhausted_pool() {
    let mut fixture = MachineScene::new(1);
    fixture
        .scene
        .push(std::process::id(), 0, "C_CreateObject", 1);
    for _ in 0..16 {
        fixture.service(1).unwrap();
        if fixture.machine.report_preparation_pending_for_test() {
            break;
        }
    }
    assert!(fixture.machine.report_preparation_pending_for_test());
    let identity = fixture
        .machine
        .retained_raw_for_test()
        .unwrap()
        .h0_identity();
    let coordinator = &fixture.scene.real.scene.coordinator;
    let snapshot = coordinator.registry().semantic_resource_snapshot();
    let reserve = coordinator.registry().semantic_storage_reserver();
    let hold = reserve
        .reserve(snapshot.limit_bytes - snapshot.charged_bytes)
        .unwrap();
    let (result, allocations, _) = crate::test_alloc::count_allocs_during(|| fixture.service(1));
    assert_eq!(result, Err(SemanticRefusal::ProviderStorage));
    assert_eq!(
        allocations, 0,
        "the exhausted real pool refuses before any watched Entry copy"
    );
    assert!(
        fixture
            .machine
            .retained_raw_for_test()
            .unwrap()
            .h0_identity()
            == identity
    );
    assert_eq!(
        fixture.machine.diagnostic_snapshot_for_test().0,
        "Binding",
        "the refused original stays in Binding for disposal, never half-bound"
    );
    // The latch holds: a retry without disposal refuses identically.
    assert_eq!(fixture.service(1), Err(SemanticRefusal::ProviderStorage));
    drop(hold);
}

/// The common spread: 1,024 records sharing 64 caller partitions still mint
/// one receipt per partition, not per record. The reservation must size by
/// the 64 partitions; the records-times bound refuses this shape too.
#[test]
fn joint_machine_shared_partitions_mint_one_receipt_each() {
    const RECORDS: usize = 1_024;
    const PARTITIONS: usize = 64;
    let children = [OwnedStoppedChild::new(), OwnedStoppedChild::new()];
    let mut fixture = MachineScene::new(1);
    let pid = std::process::id();
    let mut pids = vec![pid];
    for (offset, child) in children.iter().enumerate() {
        let caller_pid = child.id();
        fixture.scene.real.bind(
            caller_pid,
            ImageIdentity {
                task_cookie: 100 + offset as u64,
                exec_id: 0,
            },
            0,
        );
        pids.push(caller_pid);
    }
    fixture.scene.drain.source_mut().bound = 4_096;
    let mut pushed_calls = 0usize;
    let push_call = |fixture: &mut MachineScene, index: usize| {
        // Sixteen records share each caller image; the image stays with
        // one caller so no exec churn retires anything mid-pass.
        let partition = index % PARTITIONS;
        let record_pid = pids[partition % pids.len()];
        fixture
            .scene
            .real
            .h0
            .0
            .borrow_mut()
            .io
            .targets
            .get_mut(&record_pid)
            .unwrap()
            .1 = ImageIdentity {
            task_cookie: 1_000 + partition as u64,
            exec_id: 0,
        };
        fixture
            .scene
            .push(record_pid, 0, "C_CreateObject", index as u64 + 1);
    };
    for index in 0..255 {
        push_call(&mut fixture, index);
        pushed_calls += 1;
    }
    let limit = crate::semantics_edge::resources::SEMANTIC_RESOURCE_LIMIT;
    let mut peak_charged = 0usize;
    let mut max_current = 0usize;
    let mut pulls = 0usize;
    let mut published = false;
    for _ in 0..8192 {
        let charged = fixture
            .scene
            .real
            .scene
            .coordinator
            .registry()
            .semantic_resource_snapshot()
            .charged_bytes;
        peak_charged = peak_charged.max(charged);
        if let Some(prepared) = fixture
            .scene
            .real
            .scene
            .coordinator
            .prepared_semantic_batch()
        {
            max_current = max_current.max(prepared.current_receipts().len());
        }
        let collecting = matches!(
            fixture.machine.diagnostic_snapshot_for_test().0,
            "Idle" | "Collecting"
        );
        let work = if collecting { 1 } else { 1024 };
        match fixture.service(work) {
            Ok(crate::inventory_semantics::JointServiceProgress::Published) => {
                published = true;
                break;
            }
            Ok(crate::inventory_semantics::JointServiceProgress::Pending) => {
                if collecting {
                    pulls += 1;
                    if pulls % 2 == 1 && pushed_calls < RECORDS {
                        push_call(&mut fixture, pushed_calls);
                        pushed_calls += 1;
                    }
                }
            }
            Err(reason) => {
                panic!(
                    "1,024 records over 64 partitions must bind: refused {reason:?} at {:?}",
                    fixture.machine.diagnostic_snapshot_for_test(),
                );
            }
        }
    }
    assert_eq!(pushed_calls, RECORDS);
    assert!(published, "the shared-partition transaction must publish");
    eprintln!(
        "machine_shared records={RECORDS} partitions={PARTITIONS} max_current={max_current} \
         peak_charged={peak_charged} limit={limit}"
    );
    assert!(
        peak_charged < limit,
        "peak {peak_charged} must stay under the shared semantic pool {limit}"
    );
    assert_eq!(
        max_current, PARTITIONS,
        "one receipt per distinct partition, not per record"
    );
    assert_eq!(fixture.scene.drain.source_mut().remaining(), 0);
}
