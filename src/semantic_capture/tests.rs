//! SPDX-License-Identifier: GPL-3.0-or-later
//! Tests of the actual capture transport and joint custody.

use super::*;
use crate::attach::image_query::{CompleteEpochs, acquire_test_scan};
use crate::discovery::instances::MapRange;
use p11scope_ebpf_common::{InstanceStamp, instance};

mod current_receipts_tests {
    //! SPDX-License-Identifier: GPL-3.0-or-later
    //! Shared production orchestration with substituted I/O, never proof decisions.
    use super::*;

    fn initial_pair(capture: &mut SemanticCapture, io: &mut ScriptIo) -> TickReport {
        io.semantic_call("C_SignInit", 0, 0);
        io.semantic_call("C_Sign", 0, 0);
        let report = capture.tick_with(io).unwrap();
        assert_eq!(report.calls().count(), 2);
        assert!(
            report
                .calls()
                .all(|call| matches!(call.route(), Route::Joined(_)))
        );
        assert!(
            report
                .outcomes()
                .iter()
                .all(|item| !matches!(item, TickOutcome::Invalidation(_)))
        );
        assert_eq!(capture.router.ranges_retained(), 2);
        report
    }

    fn id(route: Route) -> InstanceId {
        let Route::Joined(id) = route else {
            panic!("nonempty supported join required")
        };
        id
    }

    fn gap(capture: &SemanticCapture) -> PhysicalSemanticGap {
        let binding = &capture.bindings[&1];
        PhysicalSemanticGap::test_episode(binding.domain, binding.image, binding.pin.clone())
    }

    fn barrier(report: &TickReport) -> &Invalidation {
        report
            .outcomes()
            .iter()
            .find_map(|outcome| match outcome {
                TickOutcome::Invalidation(value)
                    if matches!(value.scope(), InvalidationScope::FaultEra) =>
                {
                    Some(value)
                }
                _ => None,
            })
            .expect("one producer-visible fault barrier")
    }

    #[test]
    fn native_semantic_current_receipt_requires_original_pin_and_accepted_scan() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = super::capture(&io);
        let mut report = initial_pair(&mut capture, &mut io);
        let joined = id(report.calls().next().unwrap().route());
        assert_eq!(
            report.current.len(),
            1,
            "accepted complete first scan must yield registration authority"
        );
        let mut receipt = report.current.pop().unwrap();
        assert_eq!(receipt.domain(), io.domain);
        assert_eq!(receipt.image(), io.current_image);
        assert_eq!(receipt.instances(), &[joined]);
        assert!(receipt.endpoint() == io.endpoint(0).unwrap());
        assert!(Arc::ptr_eq(receipt.original_pin(), &io.pin));
        assert!(Arc::ptr_eq(
            &receipt.watched.retirement_lease(),
            &io.watched[0].retirement_lease()
        ));
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Ok(())
        );

        io.fail_file = Some(0);
        io.semantic_call("C_Sign", 0, 0);
        let cached = capture.tick_with(&mut io).unwrap();
        assert_eq!(
            cached.calls().next().unwrap().route(),
            Route::Joined(joined)
        );
        assert!(
            cached.current().is_empty(),
            "a refused fresh scan cannot grant a cached Joined call currency"
        );
        assert_eq!(cached.scan_refusals, vec![ImageQueryRefusal::Unstable]);
        let (owned_cached, no_receipts) = cached.into_parts();
        assert_eq!(owned_cached.len(), 1);
        assert!(no_receipts.is_empty());
        io.fail_file = None;
        let refresh = capture
            .refresh_with(&mut io, receipt.pin.clone(), 0)
            .unwrap();
        assert_eq!(refresh.collected_calls, 0);
        assert_eq!(refresh.current.len(), 1, "fresh no-call scan can register");

        let original_domain = receipt.domain;
        receipt.domain = NativeDomainId::mint();
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Domain)
        );
        receipt.domain = original_domain;
        let original_pin = receipt.pin.clone();
        receipt.pin = Arc::new(PidPin::open(original_pin.pid()).unwrap());
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Custody)
        );
        receipt.pin = original_pin;
        receipt.image.exec_id += 1;
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Custody)
        );
        receipt.image.exec_id -= 1;
        receipt.endpoint.file_slot = 1;
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Attachment)
        );
        assert_eq!(capture.router.instances_minted(), 1);
        assert_eq!(io.raises, 0);
        receipt.endpoint.file_slot = 0;
        capture.stop();
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Stopped)
        );
    }

    #[test]
    fn joined_refresh_rotates_after_refusal_with_one_shared_scan_slot() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = super::capture(&io);
        for file in [0, 1] {
            io.semantic_call("C_SignInit", file, 0);
            io.semantic_call("C_Sign", file, 0);
        }
        let initial = capture.tick_with(&mut io).unwrap();
        assert_eq!(initial.current().len(), 2);
        let original = [0, 1].map(|file| {
            id(initial
                .calls()
                .find(|call| call.endpoint().unwrap().file_slot == file)
                .unwrap()
                .route())
        });
        assert_ne!(original[0], original[1]);
        assert_eq!(capture.router.instances_minted(), 2);
        capture.limits.scans = 1;

        for (refused_file, selected_file) in [(Some(0), 0), (None, 1), (None, 0)] {
            io.fail_file = refused_file;
            let prior_attempts = io.attempted_files.len();
            let next_token = capture.next_token;
            for file in [0, 1] {
                io.semantic_call("C_SignInit", file, 0);
                io.semantic_call("C_Sign", file, 0);
            }
            let mut report = capture.tick_with(&mut io).unwrap();
            assert_eq!(report.scans, 1, "Pending and Joined share the scan cap");
            assert_eq!(&io.attempted_files[prior_attempts..], &[selected_file]);
            assert_eq!(report.calls().count(), 4);
            for call in report.calls() {
                let file = call.endpoint().unwrap().file_slot as usize;
                assert_eq!(call.route(), Route::Joined(original[file]));
            }
            assert_eq!(capture.next_token, next_token + 4);
            assert!(capture.awaiting.is_empty());
            assert!(capture.jobs.is_empty());
            assert_eq!(capture.router.pending_len(), 0);
            assert_eq!(capture.router.instances_minted(), 2);
            if refused_file.is_some() {
                assert_eq!(report.scan_refusals, vec![ImageQueryRefusal::Unstable]);
                assert!(report.current().is_empty());
            } else {
                assert!(report.scan_refusals.is_empty());
                assert_eq!(report.current().len(), 1);
                let receipt = report.current.pop().unwrap();
                assert_eq!(receipt.endpoint().file_slot, selected_file);
                assert_eq!(receipt.instances(), &[original[selected_file as usize]]);
                assert_eq!(
                    capture.validate_current_with(&mut io, &receipt, &mut report),
                    Ok(())
                );
            }
        }
    }

    #[test]
    fn pending_scan_keeps_its_deadline_and_precedes_joined_refresh() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = super::capture(&io);
        let initial = initial_pair(&mut capture, &mut io);
        let joined = id(initial.calls().next().unwrap().route());

        capture.limits.scans = 1;
        io.fail_file = Some(1);
        io.semantic_call("C_SignInit", 1, 0);
        let pending = capture.tick_with(&mut io).unwrap();
        assert_eq!(pending.scans, 1);
        assert!(pending.calls().next().is_none());
        assert_eq!(capture.awaiting.len(), 1);
        let original_deadline = capture.jobs[0].deadline;
        let original_token = *capture.awaiting.keys().next().unwrap();

        capture.limits.scans = 2;
        let prior_attempts = io.attempted_files.len();
        io.semantic_call("C_Sign", 0, 0);
        let mut later = capture.tick_with(&mut io).unwrap();
        assert_eq!(
            later.scans, 2,
            "one Pending and one Joined scan share the cap"
        );
        assert_eq!(&io.attempted_files[prior_attempts..], &[1, 0]);
        assert_eq!(later.scan_refusals, vec![ImageQueryRefusal::Unstable]);
        assert_eq!(later.calls().count(), 1);
        assert_eq!(later.calls().next().unwrap().route(), Route::Joined(joined));
        assert_eq!(later.current().len(), 1);
        let receipt = later.current.pop().unwrap();
        assert_eq!(receipt.endpoint().file_slot, 0);
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut later),
            Ok(())
        );
        assert_eq!(capture.jobs.len(), 1);
        assert_eq!(capture.jobs[0].deadline, original_deadline);
        assert_eq!(
            capture.awaiting.keys().copied().collect::<Vec<_>>(),
            vec![original_token]
        );
    }

    #[test]
    fn native_semantic_receipt_expires_before_finalization() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = super::capture(&io);
        let mut report = initial_pair(&mut capture, &mut io);
        let held_route = report.calls().next().unwrap().route();
        let receipt = report.current.pop().expect("accepted original receipt");
        let now = io.now;
        io.now = receipt.deadline;
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Deadline)
        );
        io.now = now;
        io.local = 1; // Actual epoch I/O changes before any subsequent observation.
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Epoch)
        );
        let original_pin = io.pin.clone();
        let mut newer = capture.refresh_with(&mut io, original_pin, 0).unwrap();
        assert_eq!(newer.current.len(), 1);
        let new_receipt = newer.current.pop().unwrap();
        assert_ne!(new_receipt.instances(), receipt.instances());
        assert_eq!(
            capture.validate_current_with(&mut io, &new_receipt, &mut newer),
            Ok(())
        );
        assert_eq!(
            report.calls().next().unwrap().route(),
            held_route,
            "owned history is not restamped"
        );
        assert!(newer.outcomes().iter().any(|item| matches!(item,
                TickOutcome::Invalidation(value) if matches!(value.scope(), InvalidationScope::InstancesRetired { ids, .. } if ids == receipt.instances()))));

        io.local = 0;
        let original_pin = io.pin.clone();
        let historical = capture.refresh_with(&mut io, original_pin, 0).unwrap();
        assert_eq!(historical.observations, vec![ObserveOutcome::Continued]);
        assert!(
            historical.current.is_empty(),
            "a retained historical epoch cannot mint current authority"
        );
        io.semantic_call("C_Sign", 0, 0);
        let late = capture.tick_with(&mut io).unwrap();
        assert_eq!(late.calls().next().unwrap().route(), held_route);
        assert!(late.current.is_empty());
        for epoch in 2..=5 {
            io.local = epoch;
            let pin = io.pin.clone();
            assert_eq!(
                capture.refresh_with(&mut io, pin, 0).unwrap().current.len(),
                1
            );
        }
        io.local = 0;
        io.semantic_call("C_Sign", 0, 0);
        assert_eq!(
            capture
                .tick_with(&mut io)
                .unwrap()
                .calls()
                .next()
                .unwrap()
                .route(),
            Route::Unknown(UnknownReason::Evicted)
        );
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Partition)
        );
        capture.router.retire_image(receipt.image);
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Partition)
        );
    }

    #[test]
    fn refresh_receipt_survives_realistic_pass_interval_into_next_tick() {
        use crate::inventory_semantics::{
            RefreshReceiptStash, merge_stash_into_report, stash_refresh_report,
        };

        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        let pin = io.pin.clone();
        let minted_at = io.now;
        let mut refresh = capture.refresh_with(&mut io, pin, 0).unwrap();
        assert_eq!(
            refresh.current().len(),
            1,
            "the accepted refresh mints one receipt"
        );
        // The quiet provider's proof waits the normal pass interval
        // for the next tick batch (1s passes; the scan slice is only
        // 50ms), carried by the real lane stash through the shared
        // production round-trip.
        let mut stash = RefreshReceiptStash::new();
        let (images, shed) = stash_refresh_report(&mut stash, &mut refresh);
        assert_eq!(shed, 0);
        assert_eq!(images.len(), 1);
        io.now += Duration::from_secs(1);
        let mut tick = capture.tick_with(&mut io).unwrap();
        assert!(
            tick.calls().next().is_none(),
            "the quiet tick routes no calls"
        );
        assert_eq!(merge_stash_into_report(&mut stash, &mut tick), 0);
        assert_eq!(tick.current().len(), 1);
        assert_eq!(
            tick.current()[0].deadline,
            minted_at + capture.limits.pending_for,
            "a refresh receipt stays provable across the normal pass interval"
        );
        let mut scratch = TickReport::default();
        assert_eq!(
            capture.validate_current_with(&mut io, &tick.current()[0], &mut scratch),
            Ok(()),
            "the stashed quiet proof validates at the next tick"
        );
    }

    #[test]
    fn refresh_outcomes_reach_next_tick_instead_of_dropping() {
        use crate::inventory_semantics::{
            RefreshReceiptStash, merge_stash_into_report, stash_refresh_report,
        };

        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        let pin = io.pin.clone();
        // The second refresh supersedes the first image on the same
        // pin: H0 retires the prior image with an invalidation.
        let first = capture.refresh_with(&mut io, pin.clone(), 0).unwrap();
        assert_eq!(first.current().len(), 1);
        io.output_image = Some(ImageIdentity {
            task_cookie: 2,
            exec_id: 1,
        });
        let mut second = capture.refresh_with(&mut io, pin, 0).unwrap();
        assert_eq!(second.current().len(), 1);
        assert!(
            second.outcomes().iter().any(|item| matches!(
                item,
                TickOutcome::Invalidation(value)
                    if matches!(value.scope(), InvalidationScope::ImageRetired(_))
            )),
            "the superseding refresh must carry its invalidation: {:?}",
            second.outcomes()
        );
        // The shared round-trip preserves the outcomes beside the
        // receipts into the next tick batch.
        let mut stash = RefreshReceiptStash::new();
        let (images, shed) = stash_refresh_report(&mut stash, &mut second);
        assert_eq!(shed, 0);
        assert_eq!(images.len(), 1);
        let mut tick = capture.tick_with(&mut io).unwrap();
        assert_eq!(merge_stash_into_report(&mut stash, &mut tick), 0);
        assert_eq!(tick.current().len(), 1);
        assert!(
            tick.outcomes().iter().any(|item| matches!(
                item,
                TickOutcome::Invalidation(value)
                    if matches!(value.scope(), InvalidationScope::ImageRetired(_))
            )),
            "the stashed invalidation must reach the tick batch: {:?}",
            tick.outcomes()
        );
    }

    #[test]
    fn drained_receipt_expires_inside_quiescence_wait_but_validates_promptly() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        io.call_image(1, 1, 0);
        let tick = capture.tick_with(&mut io).unwrap();
        assert_eq!(
            tick.current().len(),
            1,
            "the drained call mints its receipt"
        );
        let receipt = &tick.current()[0];
        let mut scratch = TickReport::default();
        // A prompt terminal commit (inside `on_batch` during the
        // drain) validates while the receipt is fresh.
        assert_eq!(
            capture.validate_current_with(&mut io, receipt, &mut scratch),
            Ok(())
        );
        // Buffered through a full quiescence wait, the 2s pending
        // window expires inside the 5s stop budget.
        io.now += Duration::from_secs(5);
        assert_eq!(
            capture.validate_current_with(&mut io, receipt, &mut scratch),
            Err(CurrentReceiptRefusal::Deadline)
        );
    }

    #[test]
    fn native_semantic_receipt_revalidates_readback_and_postscan_health() {
        // Exercise the actual Session readback decision, alongside the shared
        // capture's I/O-failure paths; no injected boolean may seal a receipt.
        use crate::attach::{CapturePolicy, semantic_receipt_readback_test};
        let descriptors = crate::kinds::DESCRIPTORS.to_vec();
        assert_eq!(
            semantic_receipt_readback_test(CapturePolicy::Allowlisted, Ok(descriptors.clone())),
            Ok(())
        );
        assert_eq!(
            semantic_receipt_readback_test(CapturePolicy::AggregateOnly, Ok(descriptors.clone())),
            Err(CurrentReceiptRefusal::Attachment)
        );
        assert_eq!(
            semantic_receipt_readback_test(
                CapturePolicy::Allowlisted,
                Err(anyhow::anyhow!("readback I/O"))
            ),
            Err(CurrentReceiptRefusal::Attachment)
        );
        let mut truncated = descriptors.clone();
        truncated.pop();
        assert_eq!(
            semantic_receipt_readback_test(CapturePolicy::Allowlisted, Ok(truncated)),
            Err(CurrentReceiptRefusal::Attachment)
        );
        let mut changed = descriptors;
        let positive = changed
            .iter()
            .position(|descriptor| *descriptor != p11scope_ebpf_common::SlotSemantics::COUNT_ONLY)
            .expect("nonempty non-count descriptor inventory");
        changed[positive] = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
        assert_eq!(
            semantic_receipt_readback_test(CapturePolicy::Allowlisted, Ok(changed)),
            Err(CurrentReceiptRefusal::Attachment)
        );
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = super::capture(&io);
        let mut report = initial_pair(&mut capture, &mut io);
        let receipt = report.current.pop().expect("accepted original receipt");
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Ok(())
        );
        for (query_refusal, refusal) in [
            (ImageQueryRefusal::Unknown, CurrentReceiptRefusal::Epoch),
            (ImageQueryRefusal::Unstable, CurrentReceiptRefusal::Epoch),
            (ImageQueryRefusal::Deadline, CurrentReceiptRefusal::Deadline),
            (ImageQueryRefusal::Custody, CurrentReceiptRefusal::Custody),
        ] {
            let classified = crate::attach::semantic_receipt_query_refusal_test(query_refusal);
            assert_eq!(
                classified, refusal,
                "temporary current-proof refusal is not missed coverage"
            );
            io.receipt_refusal = Some(classified);
            io.health.extend([Ok(io.last_health), Ok(io.last_health)]);
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(refusal)
            );
            assert!(
                io.health.is_empty(),
                "post-read audit still runs after finite refusal"
            );
            assert!(!capture.image_failed && !capture.exhausted);
            io.receipt_refusal = None;
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Ok(())
            );
        }
        for query_refusal in [ImageQueryRefusal::Coverage, ImageQueryRefusal::Stream] {
            let classified = crate::attach::semantic_receipt_query_refusal_test(query_refusal);
            assert_eq!(classified, CurrentReceiptRefusal::Audit);
            let mut failed_io = ScriptIo::new(NativeDomainId::mint());
            let mut failed_capture = super::capture(&failed_io);
            let mut failed_report = initial_pair(&mut failed_capture, &mut failed_io);
            let failed_receipt = failed_report.current.pop().unwrap();
            failed_io.receipt_refusal = Some(classified);
            failed_io
                .health
                .extend([Ok(failed_io.last_health), Ok(failed_io.last_health)]);
            assert_eq!(
                failed_capture.validate_current_with(
                    &mut failed_io,
                    &failed_receipt,
                    &mut failed_report
                ),
                Err(CurrentReceiptRefusal::Audit)
            );
            assert!(
                failed_io.health.is_empty(),
                "both surrounding audits succeed"
            );
            assert!(
                failed_capture.image_failed,
                "actual receipt read failure stays permanent"
            );
            failed_io.receipt_refusal = None;
            assert_eq!(
                failed_capture.validate_current_with(
                    &mut failed_io,
                    &failed_receipt,
                    &mut failed_report
                ),
                Err(CurrentReceiptRefusal::Audit)
            );
            let fault = u32::try_from(failed_io.last_health.fault).unwrap();
            failed_io.semantic_call("C_SignInit", 0, fault);
            let retry = failed_capture.tick_with(&mut failed_io).unwrap();
            assert!(retry.current.is_empty());
            assert_eq!(
                retry.calls().next().unwrap().route(),
                Route::Unknown(UnknownReason::CoverageFault)
            );
            assert_eq!(failed_capture.router.instances_minted(), 1);
        }
        io.current_image.exec_id += 1;
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Epoch)
        );
        io.current_image.exec_id -= 1;
        for epochs in [
            CompleteEpochs {
                local: 1,
                ..receipt.epochs
            },
            CompleteEpochs {
                global: 1,
                ..receipt.epochs
            },
            CompleteEpochs {
                fault: 1,
                ..receipt.epochs
            },
            CompleteEpochs {
                sticky: 1,
                ..receipt.epochs
            },
            CompleteEpochs {
                record_flags: 1,
                ..receipt.epochs
            },
        ] {
            io.receipt_epochs = Some(epochs);
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Epoch)
            );
        }
        io.receipt_epochs = None;
        io.attachment_refusal = Some(CurrentReceiptRefusal::Attachment);
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Attachment)
        );
        io.attachment_refusal = None;
        io.receipt_refusal = Some(CurrentReceiptRefusal::Epoch);
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Epoch)
        );
        io.receipt_refusal = None;
        io.health.extend([Ok(io.last_health), Err(())]);
        assert_eq!(
            capture.validate_current_with(&mut io, &receipt, &mut report),
            Err(CurrentReceiptRefusal::Audit)
        );
        assert!(capture.image_failed, "post-read health loss is permanent");
        io.last_health.fault += 1;
        let original_pin = io.pin.clone();
        let retry = capture.refresh_with(&mut io, original_pin, 0).unwrap();
        assert!(retry.current.is_empty());
        assert_eq!(capture.router.instances_minted(), 1);

        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = super::capture(&io);
        io.health.extend([Ok(io.last_health), Err(())]);
        io.semantic_call("C_SignInit", 0, 0);
        let failed = capture.tick_with(&mut io).unwrap();
        assert!(failed.current.is_empty());
        assert_eq!(
            failed.calls().next().unwrap().route(),
            Route::Unknown(UnknownReason::CoverageFault)
        );
        assert_eq!(capture.router.instances_minted(), 0);
    }

    #[test]
    fn native_semantic_physical_cut_fences_unread_and_inflight() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = super::capture(&io);
        let history = initial_pair(&mut capture, &mut io);
        let old_id = id(history.calls().next().unwrap().route());
        let last_position = history
            .calls()
            .filter_map(RoutedCall::position)
            .max()
            .unwrap();
        io.semantic_call("C_SignInit", 0, 0); // Completed, still unread EVENTS record.
        io.semantic_call("C_SignInit", 0, 0); // Entry was before the cut, return after it.
        io.records
            .back_mut()
            .unwrap()
            .base
            .continuity
            .return_stamp
            .fault = 1;
        let queued = io.records.len();
        let episode = gap(&capture);
        let cut = capture
            .apply_physical_gaps_with(&mut io, vec![episode])
            .unwrap();
        assert_eq!(
            io.raises, 1,
            "genuine physical gap must reach producer fault cell"
        );
        assert_eq!(capture.continuity_cuts(), 1);
        assert_eq!(barrier(&cut).domain(), io.domain);
        assert!(barrier(&cut).position().unwrap() > last_position);
        assert_eq!(cut.calls().count(), 0);
        assert_eq!(
            io.records.len(),
            queued,
            "cut neither drains EVENTS nor changes completed physical records"
        );
        assert_eq!(
            history.calls().next().unwrap().route(),
            Route::Joined(old_id)
        );
        let old = capture.tick_with(&mut io).unwrap();
        let routes: Vec<_> = old.calls().map(RoutedCall::route).collect();
        assert_eq!(
            routes,
            vec![
                Route::Unknown(UnknownReason::FaultEra),
                Route::Unknown(UnknownReason::Straddle)
            ]
        );
        assert_eq!(capture.router.instances_minted(), 1);
        io.semantic_call("C_SignInit", 0, 1);
        io.semantic_call("C_Sign", 0, 1);
        let fresh = capture.tick_with(&mut io).unwrap();
        assert_eq!(fresh.calls().count(), 2);
        assert!(
            fresh
                .calls()
                .all(|call| matches!(call.route(), Route::Joined(new) if new != old_id))
        );
        assert_eq!(capture.router.instances_minted(), 2);
    }

    #[test]
    fn native_semantic_physical_cut_coalesces_and_exhausts() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = super::capture(&io);
        initial_pair(&mut capture, &mut io);
        let first = gap(&capture);
        let repeat = first.test_repeat();
        let another_episode = gap(&capture);
        let other_repeat = another_episode.test_repeat();
        let cut = capture
            .apply_physical_gaps_with(&mut io, vec![first, another_episode])
            .unwrap();
        assert_eq!(
            io.raises, 1,
            "distinct new gaps in one publication coalesce"
        );
        assert_eq!(
            cut.outcomes()
                .iter()
                .filter(|item| matches!(item, TickOutcome::Invalidation(_)))
                .count(),
            1
        );
        assert_eq!(capture.continuity_cuts(), 1);
        let repeated = capture
            .apply_physical_gaps_with(&mut io, vec![repeat.test_repeat(), other_repeat])
            .unwrap();
        assert!(repeated.outcomes().is_empty());
        assert_eq!(io.raises, 1);
        io.semantic_call("C_SignInit", 0, 1);
        let healthy = capture.tick_with(&mut io).unwrap();
        assert!(matches!(
            healthy.calls().next().unwrap().route(),
            Route::Joined(_)
        ));
        capture
            .apply_physical_gaps_with(&mut io, vec![repeat])
            .unwrap();
        assert_eq!(
            io.raises, 1,
            "H0 scan alone cannot reset physical uncertainty"
        );
        // Only Task3's completed physical recovery can mint this successor episode.
        let successor = gap(&capture);
        capture
            .apply_physical_gaps_with(&mut io, vec![successor])
            .unwrap();
        assert_eq!(io.raises, 2);
        assert_eq!(capture.continuity_cuts(), 2);
    }

    #[test]
    fn native_semantic_physical_cut_requires_returned_token_readback_and_preserves_cas() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = super::capture(&io);
        initial_pair(&mut capture, &mut io);
        io.concurrent_raise = true;
        let episode = gap(&capture);
        let cut = capture
            .apply_physical_gaps_with(&mut io, vec![episode])
            .unwrap();
        assert_eq!(capture.continuity_cuts(), 1);
        assert_eq!(io.fault_cell.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            capture.fault, 2,
            "readback newer than returned userspace token is another loss"
        );
        assert!(barrier(&cut).position().is_some());
        io.semantic_call("C_SignInit", 0, 2);
        assert!(matches!(
            capture
                .tick_with(&mut io)
                .unwrap()
                .calls()
                .next()
                .unwrap()
                .route(),
            Route::Joined(_)
        ));

        for refusal in 0..3 {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = super::capture(&io);
            initial_pair(&mut capture, &mut io);
            let episode = gap(&capture);
            let repeat = episode.test_repeat();
            match refusal {
                0 => io.raise_fails = true,
                1 => io.health.extend([Ok(io.last_health), Err(())]),
                2 => io.health.extend([Ok(io.last_health), Ok(io.last_health)]), // stale readback below CAS result
                _ => unreachable!(),
            }
            capture
                .apply_physical_gaps_with(&mut io, vec![episode])
                .unwrap();
            assert!(
                capture.image_failed || capture.exhausted,
                "write/read/token failure permanently refuses"
            );
            let raises = io.raises;
            io.raise_fails = false;
            io.last_health.fault = 3;
            capture
                .apply_physical_gaps_with(&mut io, vec![repeat])
                .unwrap();
            assert_eq!(io.raises, raises, "permanent failure never retries the CAS");
            io.semantic_call("C_SignInit", 0, 3);
            let failed = capture.tick_with(&mut io).unwrap();
            assert!(failed.calls().all(|call| matches!(
                call.route(),
                Route::Unknown(UnknownReason::CoverageFault | UnknownReason::AuthorityExhausted)
            )));
            assert_eq!(capture.router.instances_minted(), 1);
        }
    }

    #[test]
    fn native_semantic_physical_cut_counter_and_position_exhaustion_never_reopen() {
        for ordinal in [false, true] {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = super::capture(&io);
            initial_pair(&mut capture, &mut io);
            let episode = gap(&capture);
            if ordinal {
                capture.next_token = u64::MAX;
            } else {
                io.last_health.fault = u64::from(u32::MAX);
            }
            let failed = capture
                .apply_physical_gaps_with(&mut io, vec![episode])
                .unwrap();
            assert!(
                capture.exhausted,
                "unrepresentable cut or negative position is permanent"
            );
            assert!(
                failed
                    .outcomes()
                    .iter()
                    .any(|item| matches!(item, TickOutcome::Invalidation(value)
                    if matches!(value.scope(), InvalidationScope::AuthorityExhausted)))
            );
            if !ordinal {
                assert_eq!(
                    io.fault_cell.load(std::sync::atomic::Ordering::SeqCst),
                    u64::from(u32::MAX) + 1
                );
                assert_eq!(capture.continuity_cuts(), 0);
            }
            let minted = capture.router.instances_minted();
            io.last_health.fault = u64::from(u32::MAX);
            io.semantic_call("C_SignInit", 0, u32::MAX);
            assert_eq!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .next()
                    .unwrap()
                    .route(),
                Route::Unknown(UnknownReason::AuthorityExhausted)
            );
            assert_eq!(capture.router.instances_minted(), minted);
        }
    }

    #[test]
    fn native_semantic_physical_cut_prevalidates_all_gaps_and_costs_healthy_sibling() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = super::capture(&io);
        let first = initial_pair(&mut capture, &mut io);
        let first_id = id(first.calls().next().unwrap().route());
        io.semantic_call("C_SignInit", 1, 0);
        io.semantic_call("C_Sign", 1, 0);
        let sibling = capture.tick_with(&mut io).unwrap();
        let sibling_id = id(sibling.calls().next().unwrap().route());
        assert_ne!(first_id, sibling_id);
        assert_eq!(capture.router.ranges_retained(), 4);
        let valid = gap(&capture);
        let foreign = PhysicalSemanticGap::test_episode(
            NativeDomainId::mint(),
            io.current_image,
            io.pin.clone(),
        );
        assert!(
            capture
                .apply_physical_gaps_with(&mut io, vec![valid, foreign])
                .is_err()
        );
        assert_eq!(
            io.raises, 0,
            "validate entire publication before any mutation"
        );
        let rival = PhysicalSemanticGap::test_episode(
            io.domain,
            io.current_image,
            Arc::new(PidPin::open(io.pin.pid()).unwrap()),
        );
        let valid = gap(&capture);
        assert!(
            capture
                .apply_physical_gaps_with(&mut io, vec![valid, rival])
                .is_err()
        );
        assert_eq!(capture.router.ranges_retained(), 4);
        assert_eq!(capture.router.instances_minted(), 2);
        let episode = gap(&capture);
        let cut = capture
            .apply_physical_gaps_with(&mut io, vec![episode])
            .unwrap();
        assert_eq!(io.raises, 1);
        assert_eq!(barrier(&cut).domain(), io.domain);
        io.semantic_call("C_Sign", 1, 0);
        assert_eq!(
            capture
                .tick_with(&mut io)
                .unwrap()
                .calls()
                .next()
                .unwrap()
                .route(),
            Route::Unknown(UnknownReason::FaultEra)
        );
        io.semantic_call("C_SignInit", 0, 1);
        io.semantic_call("C_Sign", 0, 1);
        io.semantic_call("C_SignInit", 1, 1);
        io.semantic_call("C_Sign", 1, 1);
        let recovery = capture.tick_with(&mut io).unwrap();
        assert_eq!(recovery.calls().count(), 4);
        assert!(recovery.calls().all(
                |call| matches!(call.route(), Route::Joined(new) if new != first_id && new != sibling_id)
            ));
        assert_eq!(capture.router.instances_minted(), 4);
    }
}

struct ScriptIo {
    domain: NativeDomainId,
    now: Instant,
    records: VecDeque<DecodedEventRecord>,
    event_drain: Option<crate::events::EventDrain<crate::events::ScriptedRecords>>,
    health: VecDeque<Result<Health, ()>>,
    last_health: Health,
    pin: Arc<PidPin>,
    fail_cookie: Option<u64>,
    fail_file: Option<u32>,
    attempts: Vec<(u64, Instant)>,
    attempted_files: Vec<u32>,
    raises: usize,
    raise_fails: bool,
    local: u32,
    output_image: Option<ImageIdentity>,
    output_file: Option<u32>,
    scan_advance: Duration,
    receipt_advance: Duration,
    collection_status: CollectionStatus,
    extra_range: bool,
    watched: [RetainedInventoryTarget; 2],
    attachment_refusal: Option<CurrentReceiptRefusal>,
    receipt_refusal: Option<CurrentReceiptRefusal>,
    receipt_epochs: Option<CompleteEpochs>,
    current_image: ImageIdentity,
    endpoints: Option<BTreeMap<u32, Endpoint>>,
    scan_ranges: Option<Vec<MapRange>>,
    fault_cell: Arc<std::sync::atomic::AtomicU64>,
    concurrent_raise: bool,
}
impl ScriptIo {
    fn new(domain: NativeDomainId) -> Self {
        let path = std::env::current_exe().unwrap();
        Self::with_paths(domain, &path, std::path::Path::new("/usr/bin/true"))
    }

    fn small(domain: NativeDomainId) -> Self {
        Self::with_paths(
            domain,
            std::path::Path::new("/usr/bin/true"),
            std::path::Path::new("/usr/bin/false"),
        )
    }

    fn with_paths(
        domain: NativeDomainId,
        path: &std::path::Path,
        sibling_path: &std::path::Path,
    ) -> Self {
        let pins = crate::discovery::identity::test_fixture::real_scan_pin(
            path,
            None,
            1,
            "held-test-image",
        );
        let watched = pins.retain_inventory_target(PinnedObjectId(0)).unwrap();
        let sibling = crate::discovery::identity::test_fixture::real_scan_pin(
            sibling_path,
            None,
            2,
            "held-sibling-image",
        )
        .retain_inventory_target(PinnedObjectId(0))
        .unwrap();
        assert_ne!(
            watched.object_key(),
            sibling.object_key(),
            "sibling must be a distinct physical file"
        );
        Self {
            domain,
            now: Instant::now(),
            records: VecDeque::new(),
            event_drain: None,
            health: VecDeque::new(),
            last_health: Health {
                fault: 0,
                sticky: 0,
            },
            pin: Arc::new(PidPin::open(std::process::id()).unwrap()),
            fail_cookie: None,
            fail_file: None,
            attempts: Vec::new(),
            attempted_files: Vec::new(),
            raises: 0,
            raise_fails: false,
            local: 0,
            output_image: None,
            output_file: None,
            scan_advance: Duration::ZERO,
            receipt_advance: Duration::ZERO,
            collection_status: CollectionStatus::Complete,
            extra_range: false,
            watched: [watched, sibling],
            attachment_refusal: None,
            receipt_refusal: None,
            receipt_epochs: None,
            current_image: ImageIdentity {
                task_cookie: 1,
                exec_id: 1,
            },
            endpoints: None,
            scan_ranges: None,
            fault_cell: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            concurrent_raise: false,
        }
    }
    fn call_image(&mut self, cookie: u64, exec_id: u64, fault: u32) {
        self.call(cookie, fault);
        self.records.back_mut().unwrap().base.event.image.exec_id = exec_id;
    }
    fn call(&mut self, cookie: u64, fault: u32) {
        let stamp = InstanceStamp {
            flags: instance::STAMP_VALID,
            file_slot_plus1: 1,
            fault,
            epoch: self.local,
            global: 0,
        };
        self.records.push_back(DecodedEventRecord {
            joint_resource: None,
            base: EventRecord {
                event: p11scope_ebpf_common::Event {
                    event_type: event_type::CALL,
                    image: ImageIdentity {
                        task_cookie: cookie,
                        exec_id: 1,
                    },
                    pid_tgid: u64::from(self.pin.pid()) << 32,
                    ..Default::default()
                },
                continuity: p11scope_ebpf_common::InstanceContinuity {
                    entry_stamp: stamp,
                    return_stamp: stamp,
                    entry_ip: 0x2200,
                },
            },
            object: None,
        });
    }
    fn semantic_call(&mut self, name: &str, file: u32, fault: u32) {
        self.call(1, fault);
        let record = self.records.back_mut().unwrap();
        // Native function selection belongs to the retained attach slot;
        // target_function is a different, captured API argument.
        let function_slot = match name {
            "C_SignInit" => 0,
            "C_Sign" => 1,
            _ => panic!("fixture endpoint not retained"),
        };
        record.base.event.slot = file * 2 + function_slot;
        record.base.continuity.entry_stamp.file_slot_plus1 = (file + 1) as u16;
        record.base.continuity.return_stamp.file_slot_plus1 = (file + 1) as u16;
        record.base.continuity.entry_ip +=
            u64::from(file) * 0x4000 + u64::from(function_slot) * 0x100;
    }
}
impl ScriptIo {
    /// Advance the scripted capture clock (retention horizons,
    /// deadlines). Wall-clock registration stamps are unaffected.
    pub(crate) fn advance_now(&mut self, by: Duration) {
        self.now += by;
    }
}
impl CaptureIo for ScriptIo {
    fn domain(&self) -> Option<NativeDomainId> {
        Some(self.domain)
    }
    fn now(&self) -> Instant {
        self.now
    }
    fn collect(&mut self, limit: usize) -> Collection {
        if let Some(drain) = self.event_drain.as_mut() {
            return collect_event_prefix(drain, None, limit);
        }
        Collection {
            records: (0..limit)
                .filter_map(|_| self.records.pop_front())
                .collect(),
            status: std::mem::replace(&mut self.collection_status, CollectionStatus::Complete),
        }
    }
    fn health(&mut self) -> Result<Health, ()> {
        let result = self.health.pop_front().unwrap_or(Ok(self.last_health));
        if let Ok(health) = result {
            self.last_health = health;
        }
        result
    }
    fn raise_fault(&mut self) -> Result<u64, ()> {
        self.raises += 1;
        if self.raise_fails {
            return Err(());
        }
        use std::sync::atomic::Ordering;
        self.fault_cell
            .store(self.last_health.fault, Ordering::SeqCst);
        let raised = crate::attach::raise_fault_test_cell(&self.fault_cell).map_err(|_| ())?;
        if self.concurrent_raise {
            let cell = self.fault_cell.clone();
            std::thread::spawn(move || crate::attach::raise_fault_test_cell(&cell).unwrap())
                .join()
                .unwrap();
        }
        self.last_health.fault = self.fault_cell.load(Ordering::SeqCst);
        Ok(raised)
    }
    fn retained_attachment(
        &self,
        slot: u32,
    ) -> Result<RetainedInventoryTarget, CurrentReceiptRefusal> {
        if let Some(refusal) = self.attachment_refusal {
            return Err(refusal);
        }
        let file = self
            .endpoint(slot)
            .ok_or(CurrentReceiptRefusal::Attachment)?
            .file_slot;
        self.watched
            .get(file as usize)
            .map(RetainedInventoryTarget::share)
            .ok_or(CurrentReceiptRefusal::Attachment)
    }
    fn receipt_state(
        &mut self,
        _: &Arc<PidPin>,
        _: ImageIdentity,
        endpoint: Endpoint,
        _: u32,
        _: Instant,
    ) -> Result<ReceiptState, CurrentReceiptRefusal> {
        self.now += self.receipt_advance;
        if let Some(refusal) = self.receipt_refusal {
            return Err(refusal);
        }
        Ok(ReceiptState {
            image: self.current_image,
            epochs: self.receipt_epochs.unwrap_or(CompleteEpochs {
                local: u64::from(self.local),
                global: 0,
                fault: self.last_health.fault,
                sticky: self.last_health.sticky,
                record_flags: 0,
            }),
            watched: self.watched[endpoint.file_slot as usize].share(),
        })
    }
    fn endpoint(&self, slot: u32) -> Option<Endpoint> {
        if let Some(endpoints) = &self.endpoints {
            return endpoints.get(&slot).copied();
        }
        (slot < 4).then_some(Endpoint {
            object: PinnedObjectId(slot / 2),
            file_slot: slot / 2,
            offset: 0x1200 + u64::from(slot % 2) * 0x100,
        })
    }
    fn target(&self, _: u32) -> Option<Arc<PidPin>> {
        Some(self.pin.clone())
    }
    fn scan(
        &mut self,
        job: &ScanJob,
        deadline: Instant,
        fence: u64,
        _: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        self.attempts.push((job.image.task_cookie, deadline));
        self.attempted_files.push(job.endpoint.file_slot);
        self.now += self.scan_advance;
        if self.fail_cookie == Some(job.image.task_cookie)
            || self.fail_file == Some(job.endpoint.file_slot)
        {
            return Err(ImageQueryRefusal::Unstable);
        }
        let base = u64::from(job.endpoint.file_slot) * 0x4000;
        let mut ranges = vec![
            MapRange::new(base + 0x1000, base + 0x2000, 0, false),
            MapRange::new(base + 0x2000, base + 0x3000, 0x1000, true),
        ];
        if let Some(original) = &self.scan_ranges {
            ranges = original.clone();
        }
        if self.extra_range {
            ranges.push(MapRange::new(0x4000, 0x5000, 0, false));
        }
        self.current_image = self.output_image.unwrap_or(job.image);
        acquire_test_scan(
            self.domain,
            self.output_image.unwrap_or(job.image),
            self.output_file.unwrap_or(job.endpoint.file_slot),
            CompleteEpochs {
                local: u64::from(self.local),
                global: 0,
                fault: self.last_health.fault,
                sticky: 0,
                record_flags: 0,
            },
            ranges,
            fence,
        )
    }
    fn scan_selected(
        &mut self,
        pin: &Arc<PidPin>,
        endpoint: Endpoint,
        deadline: Instant,
        fence: u64,
        current: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        let job = ScanJob {
            image: self.output_image.unwrap_or(ImageIdentity {
                task_cookie: 1,
                exec_id: 1,
            }),
            endpoint,
            slot: endpoint.file_slot * 2,
            pin: pin.clone(),
            deadline,
            birth_cut: None,
        };
        self.scan(&job, deadline, fence, current)
    }
}
fn capture(io: &ScriptIo) -> SemanticCapture {
    SemanticCapture::in_domain(io.domain, TickLimits::default()).unwrap()
}

// Only the role-bookkeeping tests use this substituted native I/O. The
// actual collected leaf stamps the report; it grants no admission/birth.
pub(super) fn deliver_collected_raw_for_resource_test(
    raw: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    domain: NativeDomainId,
) -> TickReport {
    let mut io = ScriptIo::small(domain);
    let mut capture = capture(&io);
    let report = capture.tick_collected_with(&mut io, raw).unwrap();
    assert!(report.awaiting_floor().is_none());
    report
}

struct BirthFault;
impl crate::semantics_objects::journal::FaultEpoch for BirthFault {
    fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
        Ok(0)
    }
}

struct JointBirthHarness {
    fixture: crate::semantics_objects::journal::tests::AttestationFixture,
    io: ScriptIo,
    capture: SemanticCapture,
    pool: crate::semantics_edge::resources::SemanticResourcePool,
    adapter: JournalAdapter,
    drain: crate::events::EventDrain<crate::events::ScriptedRecords>,
    producers: crate::attach::SessionDrainProducers,
    caller: Option<crate::discovery::caller_registry::CallerId>,
    rows: [p11scope_ebpf_common::object_wire::ObjectDescriptorWire;
        p11scope_ebpf_common::MAX_DESCRIPTORS as usize],
}
impl JointBirthHarness {
    fn new() -> Self {
        use crate::semantics_objects::journal::{
            JournalLimits, SessionClosureGrant, StagingLedger,
        };
        let image = ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        };
        let fixture =
            crate::semantics_objects::journal::tests::AttestationFixture::new_with_quiet_function(
                image,
            );
        let mut io = ScriptIo::with_paths(
            fixture.domain(),
            &fixture.provider_path(),
            std::path::Path::new("/usr/bin/false"),
        );
        io.pin = fixture.binding().pin();
        io.local = 1;
        io.current_image = image;
        io.output_image = Some(image);
        io.endpoints = Some(
            ["C_CreateObject", "C_GetSessionInfo"]
                .into_iter()
                .map(|name| fixture.endpoint_for(name))
                .collect(),
        );
        io.scan_ranges = Some(vec![MapRange::new(0x7000_0000, 0x7000_6000, 0, true)]);
        let capture = capture(&io);
        let pool = crate::semantics_edge::resources::SemanticResourcePool::default();
        let mut adapter = JournalAdapter::with_ledger(
            JournalLimits::policy(),
            StagingLedger::with_resources(pool.reserver()),
        );
        assert!(adapter.install_closure_grant(&SessionClosureGrant::observe(fixture.attachment())));
        let events = crate::events::EventsDomain::test_standin(0xb101);
        let producers = crate::attach::SessionDrainProducers::test_pair(io.domain, events.clone());
        let drain = crate::events::EventDrain::over_domain(
            crate::events::ScriptedRecords::records([], 64),
            events,
        );
        Self {
            fixture,
            io,
            capture,
            pool,
            adapter,
            drain,
            producers,
            caller: None,
            rows: p11scope_ebpf_common::object_wire::publish_object_descriptors(),
        }
    }
    fn ordinary(&self, child: ImageIdentity) -> EventRecord {
        let (slot, endpoint) = self.fixture.endpoint_for("C_GetSessionInfo");
        let pid = u64::from(self.io.pin.pid());
        let stamp = p11scope_ebpf_common::InstanceStamp {
            flags: p11scope_ebpf_common::instance::STAMP_VALID,
            file_slot_plus1: endpoint.file_slot as u16 + 1,
            epoch: self.io.local,
            global: 0,
            fault: 0,
        };
        EventRecord {
            event: p11scope_ebpf_common::Event {
                event_type: event_type::CALL,
                image: self.io.current_image,
                child_image: child,
                pid_tgid: (pid << 32) | pid,
                ts_ns: 100,
                duration_ns: 10,
                slot,
                session: 1,
                ..Default::default()
            },
            continuity: p11scope_ebpf_common::InstanceContinuity {
                entry_stamp: stamp,
                return_stamp: stamp,
                entry_ip: 0x7000_0000 + endpoint.offset,
            },
        }
    }
    fn push_ordinary(&mut self, child: ImageIdentity) {
        let bytes = crate::events::record_bytes(&self.ordinary(child));
        self.drain.source_mut().push_record(bytes);
    }
    fn push_create(&mut self, sequence: u64) {
        use crate::semantics_objects::journal::tests::{
            ENTRY_NS, begin_bytes, end_bytes, function_id,
        };
        let (slot, endpoint) = self.fixture.endpoint_for("C_CreateObject");
        let thread = if self.caller.is_some() { 2 } else { 1 };
        let mut begin = begin_bytes(thread, sequence, function_id("C_CreateObject"), 0);
        let pid = u64::from(self.io.pin.pid());
        begin[24..32].copy_from_slice(&((pid << 32) | pid).to_le_bytes());
        begin[32..40].copy_from_slice(&self.io.current_image.task_cookie.to_le_bytes());
        begin[40..48].copy_from_slice(&self.io.current_image.exec_id.to_le_bytes());
        begin[56..64].copy_from_slice(&(0x7000_0000 + endpoint.offset).to_le_bytes());
        begin[64..68].copy_from_slice(&self.io.local.to_le_bytes());
        begin[68..76].fill(0);
        begin[76..78].copy_from_slice(&1u16.to_le_bytes());
        begin[104..108].copy_from_slice(&slot.to_le_bytes());
        let end = end_bytes(
            &begin,
            p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE,
            0,
            ENTRY_NS + 100,
        );
        self.drain.source_mut().push_record(begin.to_vec());
        self.drain.source_mut().push_record(end.to_vec());
    }
    fn collect(&mut self) -> crate::semantics_objects::journal::joint_driver::RawJointQuantum {
        crate::semantics_objects::journal::joint_driver::RawJointQuantum::collect_bounded_with_adapter(
                &mut self.drain, &self.rows, 4_096, None, &BirthFault, &self.producers,
                |bytes| self.pool.reserve(bytes), &mut self.adapter,
            ).expect("original bounded collection")
    }
    fn route(
        &mut self,
        raw: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    ) -> (
        TickReport,
        crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
    ) {
        let mut report = self.capture.tick_collected_with(&mut self.io, raw).unwrap();
        let mut calls = report
            .take_outcomes()
            .into_iter()
            .filter_map(|outcome| match outcome {
                TickOutcome::Call(call) => Some(call),
                _ => None,
            });
        let call = calls.next().expect("one actual completed call");
        assert!(calls.next().is_none());
        let admitted = self.fixture.admit_collected_for(call, self.caller);
        (report, admitted)
    }
    fn ingest(
        &mut self,
        raw: crate::semantics_objects::journal::joint_driver::RawJointQuantum,
        admitted: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
    ) -> (
        crate::semantics_objects::journal::JournalCollection,
        JournalDomainProof,
    ) {
        let proof = self
            .adapter
            .bind_admitted_key(admitted)
            .expect("binding does not claim before START ingestion");
        let grant = crate::semantics_objects::journal::SessionDrainGrant::observe(
            &self.producers,
            admitted,
        )
        .unwrap();
        self.adapter.bind_session_drain(&grant).unwrap();
        let collection = raw
            .ingest(&mut self.adapter, &self.producers, &grant)
            .unwrap_or_else(|(_, reason)| panic!("raw ingest: {reason:?}"))
            .into_collection_for_birth_test();
        assert_eq!(
            self.adapter.attest_key(admitted).unwrap(),
            proof,
            "claim follows genuine START ingestion"
        );
        (collection, proof)
    }
    fn absence(&mut self) -> CommittedAbsenceBirth {
        use crate::attach::image_query::acquire_test_absence;
        let (slot, endpoint) = self.fixture.endpoint_for("C_GetSessionInfo");
        let proof = acquire_test_absence(
            self.io.domain,
            self.io.current_image,
            endpoint.file_slot,
            CompleteEpochs {
                local: u64::from(self.io.local),
                global: 0,
                fault: 0,
                sticky: 0,
                record_flags: 0,
            },
            vec![p11scope_manifest::maps::MapEntry {
                start: 0x4000,
                end: 0x5000,
                file_offset: 0,
                permissions: *b"r-xp",
                device: p11scope_manifest::maps::Device { major: 8, minor: 2 },
                inode: 1001,
                raw_path: None,
            }],
            self.fixture.attachment().generation(),
            vec![self.io.watched[0].object_key()],
            crate::discovery::instances::MappedFileIdentity {
                dev: 0x801,
                ino: 999,
            },
            |_, _| panic!("no watched-provider mapping"),
            self.capture.router.fence(),
        )
        .expect("genuine provider-free acquisition before appearance");
        let before = self.drain.consumption_cut().unwrap();
        let after = self.drain.consumption_cut().unwrap();
        self.capture
            .commit_absence_with(
                &mut self.io,
                proof,
                before,
                after,
                self.fixture.binding_for_collected(self.caller),
                self.fixture.attachment(),
                slot,
                &mut self.adapter,
                &self.producers,
            )
            .unwrap()
    }
    fn birth(
        &mut self,
        mut report: TickReport,
        admitted: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
        proof: &JournalDomainProof,
        absence: Option<CommittedAbsenceBirth>,
        rows: &mut impl crate::attach::BirthRowReader,
    ) -> RetainedBirthWitness {
        assert!(report.observations.contains(&ObserveOutcome::New));
        let candidate = report
            .take_current()
            .pop()
            .unwrap()
            .into_birth_candidate()
            .unwrap_or_else(|_| panic!("actual New candidate"));
        self.capture
            .validate_birth_candidate(&mut self.io, &candidate, false)
            .unwrap();
        self.capture
            .finish_birth(
                candidate,
                absence,
                admitted,
                self.fixture.binding_for_collected(self.caller),
                self.fixture.attachment(),
                proof,
                &self.adapter,
                rows,
            )
            .unwrap()
    }
    fn seal(
        &mut self,
        collection: crate::semantics_objects::journal::JournalCollection,
        witness: &RetainedBirthWitness,
        rows: &mut impl crate::attach::BirthRowReader,
        model: &mut crate::semantics_objects::ObjectSemantics,
    ) -> usize {
        use crate::semantics_objects::journal::{
            BirthEvidenceSource, H3DispositionEvidence, JournalAuditReceipt, ScriptedH3Source,
        };
        struct Fresh<'a, R> {
            witness: &'a RetainedBirthWitness,
            io: &'a mut ScriptIo,
            capture: &'a SemanticCapture,
            fixture: &'a crate::semantics_objects::journal::tests::AttestationFixture,
            caller: Option<crate::discovery::caller_registry::CallerId>,
            rows: &'a mut R,
        }
        impl<R: crate::attach::BirthRowReader> BirthEvidenceSource for Fresh<'_, R> {
            fn take_birth_evidence(
                &mut self,
            ) -> Result<
                crate::semantics_objects::journal::SessionBirthEvidence,
                crate::attach::BirthObservationRefusal,
            > {
                self.witness.fresh_evidence_with(
                    self.io,
                    self.rows,
                    self.capture,
                    self.fixture.attachment(),
                    self.fixture.binding_for_collected(self.caller),
                )
            }
        }
        let mut h3 = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(
            collection.h0_allocated_below,
        ));
        let audit = JournalAuditReceipt::collect(
            &collection,
            &mut h3,
            self.fixture.attachment().generation(),
        );
        let frontier = self.adapter.consumed_frontier();
        let mut source = Fresh {
            witness,
            io: &mut self.io,
            capture: &self.capture,
            fixture: &self.fixture,
            caller: self.caller,
            rows,
        };
        self.adapter
            .seal(
                model,
                &audit,
                witness.receipt(),
                frontier,
                &mut source,
                &BirthFault,
            )
            .expect("actual retained birth seals")
            .prefix
            .settled()
            .len()
    }
}

#[test]
fn joint_ingested_raw_keeps_original_frontier_and_admission() {
    use crate::semantics_objects::journal::SessionDrainGrant;
    use crate::semantics_objects::journal::joint_driver::{IngestedRaw, RawQuantumRefusal};

    let mut harness = JointBirthHarness::new();
    harness.push_create(1);
    let mut raw = harness.collect();
    let (_, admitted) = harness.route(&mut raw);
    harness.adapter.bind_admitted_key(&admitted).unwrap();
    let grant = SessionDrainGrant::observe(&harness.producers, &admitted).unwrap();
    harness.adapter.bind_session_drain(&grant).unwrap();
    let ingested: IngestedRaw = raw
        .ingest(&mut harness.adapter, &harness.producers, &grant)
        .unwrap_or_else(|(_, reason)| panic!("actual raw ingest: {reason:?}"));
    let first_frontier = harness.adapter.consumed_frontier();
    assert!(ingested.matches_admission(&admitted));
    assert!(ingested.frontier() == first_frontier);
    assert_eq!(
        ingested.validate_owner(&harness.adapter, &harness.producers),
        Ok(())
    );
    let foreign = crate::attach::SessionDrainProducers::test_pair(
        harness.producers.native_domain(),
        crate::events::EventsDomain::test_standin(harness.producers.events_id()),
    );
    assert_eq!(
        ingested.validate_owner(&harness.adapter, &foreign),
        Err(RawQuantumRefusal::ForeignCapture)
    );

    harness.push_create(2);
    let mut next_raw = harness.collect();
    let (_, next_admitted) = harness.route(&mut next_raw);
    assert!(
        !ingested.matches_admission(&next_admitted),
        "a later original from the same owner cannot borrow the earlier allocation's proof"
    );
    let next_ingested: IngestedRaw = next_raw
        .ingest(&mut harness.adapter, &harness.producers, &grant)
        .unwrap_or_else(|(_, reason)| panic!("next actual raw ingest: {reason:?}"));
    assert!(next_ingested.matches_admission(&next_admitted));
    assert!(ingested.frontier() == first_frontier);
    assert_eq!(
        ingested.validate_owner(&harness.adapter, &harness.producers),
        Err(RawQuantumRefusal::StaleFrontier)
    );
    assert_eq!(
        next_ingested.validate_owner(&harness.adapter, &harness.producers),
        Ok(())
    );
}

#[test]
fn joint_raw_negative_preserves_sealed_domain_loss_effects() {
    use crate::semantics_objects::journal::joint_driver::{JointCaptureOwner, RawDisposeReason};
    use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
    use crate::semantics_objects::journal::{AttestationRefusal, JournalGap};
    use crate::semantics_objects::{Lifetime, ObjectEffect, ObjectGap};

    let mut harness = JointBirthHarness::new();
    harness.push_create(1);
    let mut raw = harness.collect();
    let (report, admitted) = harness.route(&mut raw);
    let (collection, proof) = harness.ingest(raw, &admitted);
    let publisher = NativePublisher::build();
    let (row, control, _) =
        publisher.publish_stamped(&["0", "0"], harness.fixture.attachment().generation());
    let mut rows = NativeBirthRows { row, control };
    let witness = harness.birth(report, &admitted, &proof, None, &mut rows);
    let mut model = crate::semantics_objects::ObjectSemantics::new();
    assert_eq!(harness.seal(collection, &witness, &mut rows, &mut model), 1);
    let domain = witness.receipt().domain();
    let before = model.project();
    assert_eq!(
        before.objects.len(),
        1,
        "the actual CREATE established history"
    );
    let object = before.objects[0].id;
    assert_eq!(before.objects[0].lifetime, Lifetime::Live);
    let settled_census = harness.adapter.ledger().census();

    harness.push_create(2);
    let mut raw = harness.collect();
    let (_, next_admitted) = harness.route(&mut raw);
    let mut owner = JointCaptureOwner::from_existing_parts_for_test(harness.adapter, model);
    let negative = raw
        .dispose_without_ingest(
            &mut owner,
            &harness.producers,
            RawDisposeReason::NoAdmission,
        )
        .unwrap_or_else(|(_, reason)| panic!("original unclaimed disposition: {reason:?}"));
    let failure = negative
        .failure()
        .expect("affecting original requires loss");
    assert_eq!(failure.gap, JournalGap::ImageTainted);
    assert!(failure.affects_domain(domain));
    assert!(
        failure.effects.effects.iter().any(|effect| matches!(
            effect,
            ObjectEffect::Retired { object: affected, reason: ObjectGap::Loss }
                if *affected == object
        )),
        "original model effects remain with the negative receipt"
    );
    assert_eq!(
        owner.model().project().object(object).unwrap().lifetime,
        Lifetime::Retired(ObjectGap::Loss)
    );
    assert_eq!(
        owner.adapter_mut().bind_admitted_key(&next_admitted),
        Err(AttestationRefusal::ImageTainted),
        "discarded object input cannot later acquire the old domain's authority"
    );
    assert_eq!(owner.ledger().census(), settled_census);
}

#[test]
fn joint_unlocalized_raw_loss_retains_all_sealed_domains_and_effects() {
    use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
    use crate::semantics_objects::journal::joint_driver::{
        JointCaptureOwner, RawDisposeReason, RawJointQuantum, RawQuantumRefusal,
    };
    use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
    use crate::semantics_objects::journal::{BirthCutRefusal, JournalGap};
    use crate::semantics_objects::{Lifetime, ObjectEffect, ObjectGap};

    let child = OwnedStoppedChild::new();
    let mut harness = JointBirthHarness::new();
    let mut model = crate::semantics_objects::ObjectSemantics::new();
    let publisher = NativePublisher::build();
    let mut domains = Vec::new();
    for second in [false, true] {
        if second {
            let image = ImageIdentity {
                task_cookie: 72,
                exec_id: 0,
            };
            let caller = harness.fixture.bind_collected_image(child.id(), image);
            harness.caller = Some(caller);
            harness.io.pin = harness.fixture.binding_for_collected(Some(caller)).pin();
            harness.io.current_image = image;
            harness.io.output_image = Some(image);
        }
        harness.push_create(1);
        let mut raw = harness.collect();
        let (report, admitted) = harness.route(&mut raw);
        let (collection, proof) = harness.ingest(raw, &admitted);
        let (row, control, _) =
            publisher.publish_stamped(&["0", "0"], harness.fixture.attachment().generation());
        let mut rows = NativeBirthRows { row, control };
        let witness = harness.birth(report, &admitted, &proof, None, &mut rows);
        domains.push(witness.receipt().domain());
        assert_eq!(harness.seal(collection, &witness, &mut rows, &mut model), 1);
    }
    assert_ne!(domains[0], domains[1]);
    let before = model.project();
    assert_eq!(before.objects.len(), 2);
    assert!(
        before
            .objects
            .iter()
            .all(|object| object.lifetime == Lifetime::Live)
    );
    harness.drain.source_mut().push_record(vec![1, 2, 3]);
    let raw = harness.collect();
    // A genuine later input stays behind the now-unprovable stream.
    harness.push_create(2);
    let cut = harness.drain.consumption_cut().unwrap();
    let mut owner = JointCaptureOwner::from_existing_parts_for_test(harness.adapter, model);
    let negative = raw
        .dispose_without_ingest(
            &mut owner,
            &harness.producers,
            RawDisposeReason::TerminalLoss,
        )
        .unwrap_or_else(|(_, reason)| panic!("actual malformed disposition: {reason:?}"));
    let failure = negative.failure().unwrap();
    assert_eq!(failure.gap, JournalGap::Malformed);
    assert!(domains.iter().all(|domain| failure.affects_domain(*domain)));
    for object in &before.objects {
        assert!(
            failure.effects.effects.iter().any(|effect| matches!(
                effect,
                ObjectEffect::Retired { object: affected, reason: ObjectGap::Loss }
                    if *affected == object.id
            )),
            "every original domain's loss effects survive"
        );
        assert_eq!(
            owner.model().project().object(object.id).unwrap().lifetime,
            Lifetime::Retired(ObjectGap::Loss)
        );
    }
    let effects = failure.effects.effects.len();
    let frontier = negative.frontier();
    let next = RawJointQuantum::collect_bounded_with_adapter(
        &mut harness.drain,
        &harness.rows,
        4_096,
        None,
        &BirthFault,
        &harness.producers,
        |bytes| harness.pool.reserve(bytes),
        owner.adapter_mut(),
    );
    assert!(matches!(
        next,
        Err(RawQuantumRefusal::Cut(BirthCutRefusal::Gap))
    ));
    assert!(
        harness.drain.consumption_cut().unwrap().same_boundary(&cut),
        "refusal cannot consume the queued original or heal the invalid stream"
    );
    assert!(owner.adapter().consumed_frontier() == frontier);
    assert_eq!(failure.effects.effects.len(), effects);
    assert!(
        domains.iter().all(|domain| failure.affects_domain(*domain)),
        "the negative retains its original union across later attempts"
    );
}

#[test]
fn joint_birth_witness_uses_actual_new_once() {
    use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
    let mut harness = JointBirthHarness::new();
    harness.push_create(1);
    let mut raw = harness.collect();
    let (report, admitted) = harness.route(&mut raw);
    assert_eq!(report.observations, vec![ObserveOutcome::New]);
    let (collection, proof) = harness.ingest(raw, &admitted);
    let publisher = NativePublisher::build();
    let (row, control, _) =
        publisher.publish_stamped(&["0", "0"], harness.fixture.attachment().generation());
    let mut rows = NativeBirthRows { row, control };
    let witness = harness.birth(report, &admitted, &proof, None, &mut rows);
    assert!(Arc::ptr_eq(
        &witness.candidate.receipt.pin,
        &harness.fixture.binding().pin()
    ));
    let mut model = crate::semantics_objects::ObjectSemantics::new();
    assert_eq!(harness.seal(collection, &witness, &mut rows, &mut model), 1);
    harness.io.now += Duration::from_secs(3);
    assert!(harness.io.now > witness.candidate.receipt.deadline);
    harness.push_create(2);
    let mut raw = harness.collect();
    let (mut report, admitted) = harness.route(&mut raw);
    assert_eq!(report.observations, vec![ObserveOutcome::Continued]);
    assert!(
        report
            .take_current()
            .pop()
            .unwrap()
            .into_birth_candidate()
            .is_err()
    );
    let (collection, _) = harness.ingest(raw, &admitted);
    assert_eq!(harness.seal(collection, &witness, &mut rows, &mut model), 1);
    assert_eq!(
        harness.capture.router.instances_minted(),
        1,
        "successive seals never observe again"
    );
    let foreign = capture(&harness.io);
    assert!(
        witness
            .fresh_evidence_with(
                &mut harness.io,
                &mut rows,
                &foreign,
                harness.fixture.attachment(),
                harness.fixture.binding()
            )
            .is_err()
    );
    harness.io.receipt_epochs = Some(CompleteEpochs {
        local: 2,
        global: 0,
        fault: 0,
        sticky: 0,
        record_flags: 0,
    });
    assert!(
        witness
            .fresh_evidence_with(
                &mut harness.io,
                &mut rows,
                &harness.capture,
                harness.fixture.attachment(),
                harness.fixture.binding()
            )
            .is_err()
    );
}

#[test]
fn joint_absence_birth_requires_prior_negative_and_quiet_sighting() {
    actual_absence_birth_fixture();
}

#[test]
fn joint_native_freshness_alone_cannot_authorize_absence_birth() {
    use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
    let mut harness = JointBirthHarness::new();
    harness.push_ordinary(ImageIdentity::default());
    let mut quiet = harness.collect();
    let (mut report, admitted) = harness.route(&mut quiet);
    quiet.classify_ordinary(&admitted).unwrap();
    let (_, proof) = harness.ingest(quiet, &admitted);
    let cut = harness
        .adapter
        .resolve_birth_cut(
            &harness.drain.consumption_cut().unwrap(),
            &harness.producers,
        )
        .unwrap();
    assert!(
        harness
            .adapter
            .quiet_sighting_at(harness.io.current_image, &cut)
    );
    // This already-present provider has no committed absence or later
    // appearance. The native probe can return freshness evidence only.
    let publisher = NativePublisher::build();
    let (row, control, _) = publisher.publish(&["0", "0", "0", "0", "1"]);
    let mut rows = NativeBirthRows { row, control };
    let binding = crate::attach::BirthAdmissionBinding::from_admitted(&admitted);
    crate::attach::observe_retained_birth(
        &mut rows,
        harness.fixture.binding(),
        harness.fixture.attachment(),
        &binding,
        BirthKind::AbsenceAppearance,
    )
    .expect("honest native freshness is available without birth authority");
    let candidate = report
        .take_current()
        .pop()
        .unwrap()
        .into_birth_candidate()
        .unwrap_or_else(|_| panic!("actual first H0 New candidate"));
    harness
        .capture
        .validate_birth_candidate(&mut harness.io, &candidate, false)
        .unwrap();
    let birth = harness.capture.finish_birth(
        candidate,
        None,
        &admitted,
        harness.fixture.binding(),
        harness.fixture.attachment(),
        &proof,
        &harness.adapter,
        &mut rows,
    );
    assert!(
        matches!(
            birth,
            Err(crate::attach::BirthObservationRefusal::MarkerNotReady)
        ),
        "native freshness and a quiet stream cut cannot replace a committed absence and actual new appearance"
    );
    harness.push_ordinary(ImageIdentity::default());
    let mut quiet = harness.collect();
    let (mut report, admitted) = harness.route(&mut quiet);
    assert_eq!(report.observations, vec![ObserveOutcome::Continued]);
    assert!(
        report
            .take_current()
            .pop()
            .unwrap()
            .into_birth_candidate()
            .is_err(),
        "an already-present quiet provider cannot renew actual H0 novelty"
    );
    quiet.classify_ordinary(&admitted).unwrap();
    harness.ingest(quiet, &admitted);
}

#[test]
fn joint_exec_marker_birth_without_publication_refuses_closed() {
    use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
    let mut harness = JointBirthHarness::new();
    harness.push_ordinary(ImageIdentity::default());
    let mut quiet = harness.collect();
    let (_report, admitted) = harness.route(&mut quiet);
    quiet.classify_ordinary(&admitted).unwrap();
    let (_, _proof) = harness.ingest(quiet, &admitted);
    // Live marker state: no BPF root publishes (contract-pinned
    // inactive until slice B authorizes the transactions), so the
    // bootstrap word reads Unpublished and the observed-call birth
    // refuses closed. The machine S1-discloses this refusal; slice B
    // flips this pin to a witness assertion (live R16 cells are its
    // acceptance).
    let publisher = NativePublisher::build();
    let (row, control, _) = publisher.publish(&["0", "0", "0", "0", "1"]);
    let mut rows = NativeBirthRows { row, control };
    let binding = crate::attach::BirthAdmissionBinding::from_admitted(&admitted);
    assert!(
        matches!(
            crate::attach::observe_retained_birth(
                &mut rows,
                harness.fixture.binding(),
                harness.fixture.attachment(),
                &binding,
                BirthKind::ExecMarker,
            ),
            Err(crate::attach::BirthObservationRefusal::MarkerNotReady)
        ),
        "an unpublished bootstrap marker cannot authorize an observed-call birth"
    );
}

#[test]
fn joint_refused_exec_marker_row_stays_unready_and_stage1_continues() {
    // 6.05 step 1(c), marker half: a collection-window EXEC the ticket
    // path refused leaves the marker row un-READY-able — every
    // un-READY native row state (unpublished, DIRTY, READY naming
    // another exec) refuses the ExecMarker birth with MarkerNotReady —
    // while the ordinary S1 stream still classifies Continued. The
    // exec half of this twin lives in the inventory_coordinator tests
    // (a_refused_collection_exec_leaves_no_birth_path_and_keeps_stage1_useful):
    // the refused EXEC mints nothing.
    use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
    let mut harness = JointBirthHarness::new();
    harness.push_ordinary(ImageIdentity::default());
    let mut quiet = harness.collect();
    let (_report, admitted) = harness.route(&mut quiet);
    quiet.classify_ordinary(&admitted).unwrap();
    let (_, _proof) = harness.ingest(quiet, &admitted);
    let publisher = NativePublisher::build();
    let binding = crate::attach::BirthAdmissionBinding::from_admitted(&admitted);
    // Every dumped row comes from the real marker leaves; only the argv
    // parameters are injected.
    for (args, what) in [
        (["0", "0", "0", "0", "1"], "unpublished"),
        (["0", "0", "1", "0", "1"], "DIRTY"),
        (["9", "0", "0", "9", "0"], "READY naming another exec"),
    ] {
        let (row, control, _) = publisher.publish(&args);
        let mut rows = NativeBirthRows { row, control };
        assert!(
            matches!(
                crate::attach::observe_retained_birth(
                    &mut rows,
                    harness.fixture.binding(),
                    harness.fixture.attachment(),
                    &binding,
                    BirthKind::ExecMarker,
                ),
                Err(crate::attach::BirthObservationRefusal::MarkerNotReady)
            ),
            "{what}: a refused EXEC leaves no READY-able marker row"
        );
    }
    // The same unpublished row still issues absence freshness: the
    // refusal above is the row state, not a dead harness.
    let (row, control, _) = publisher.publish(&["0", "0", "0", "0", "1"]);
    let mut rows = NativeBirthRows { row, control };
    crate::attach::observe_retained_birth(
        &mut rows,
        harness.fixture.binding(),
        harness.fixture.attachment(),
        &binding,
        BirthKind::AbsenceAppearance,
    )
    .expect("the unpublished row issues absence freshness");
    // S1 intact: the next ordinary observation still continues.
    harness.push_ordinary(ImageIdentity::default());
    let mut next = harness.collect();
    let (report, admitted) = harness.route(&mut next);
    assert_eq!(report.observations, vec![ObserveOutcome::Continued]);
    next.classify_ordinary(&admitted).unwrap();
    harness.ingest(next, &admitted);
}

pub(super) fn actual_absence_birth_fixture() {
    use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
    let mut harness = JointBirthHarness::new();
    harness.push_ordinary(ImageIdentity::default());
    let mut quiet = harness.collect();
    let (quiet_report, admitted) = harness.route(&mut quiet);
    assert!(quiet_report.observations.contains(&ObserveOutcome::New));
    quiet
        .classify_ordinary(&admitted)
        .expect("only real canonical C_GetSessionInfo admission narrows history");
    assert!(
        quiet.classify_ordinary(&admitted).is_err(),
        "classification cannot replay"
    );
    harness.ingest(quiet, &admitted);
    harness.io.local = 2;
    let negative = harness.absence();
    assert!(
        harness
            .adapter
            .quiet_sighting_at(harness.io.current_image, &negative.cut)
    );
    harness.io.local = 3;
    harness.push_create(1);
    let mut raw = harness.collect();
    let (report, admitted) = harness.route(&mut raw);
    let (collection, proof) = harness.ingest(raw, &admitted);
    let publisher = NativePublisher::build();
    let (row, control, _) = publisher.publish(&["0", "0", "0", "0", "1"]);
    let mut rows = NativeBirthRows { row, control };
    let witness = harness.birth(report, &admitted, &proof, Some(negative), &mut rows);
    assert_eq!(
        witness.receipt().birth_cut(),
        1,
        "quiet ordinal <= genuine cut < affecting BEGIN ordinal 2"
    );
    assert_eq!(
        harness.capture.router.instances_minted(),
        2,
        "old quiet incarnation never upgrades"
    );
    assert_eq!(
        harness.seal(
            collection,
            &witness,
            &mut rows,
            &mut crate::semantics_objects::ObjectSemantics::new()
        ),
        1
    );
}

#[test]
fn joint_quiet_classification_rejects_foreign_repeated_and_child_positions() {
    let mut harness = JointBirthHarness::new();
    harness.push_ordinary(ImageIdentity::default());
    let mut first = harness.collect();
    let (_, first_admitted) = harness.route(&mut first);
    // A second real H0 allocator in the same domain restarts at ordinal1;
    // exact allocation provenance still rejects the identical wire bytes.
    let mut foreign_capture = capture(&harness.io);
    let mut foreign_adapter = JournalAdapter::with_ledger(
        crate::semantics_objects::journal::JournalLimits::policy(),
        crate::semantics_objects::journal::StagingLedger::with_resources(harness.pool.reserver()),
    );
    let foreign_events = crate::events::EventsDomain::test_standin(0xb101);
    let foreign_producers =
        crate::attach::SessionDrainProducers::test_pair(harness.io.domain, foreign_events.clone());
    let mut foreign_drain = crate::events::EventDrain::over_domain(
        crate::events::ScriptedRecords::records(
            [crate::events::record_bytes(
                &harness.ordinary(ImageIdentity::default()),
            )],
            1,
        ),
        foreign_events,
    );
    let mut foreign_raw = crate::semantics_objects::journal::joint_driver::RawJointQuantum::collect_bounded_with_adapter(&mut foreign_drain, &harness.rows, 4_096, None, &BirthFault, &foreign_producers, |bytes| harness.pool.reserve(bytes), &mut foreign_adapter).unwrap();
    let mut foreign_report = foreign_capture
        .tick_collected_with(&mut harness.io, &mut foreign_raw)
        .unwrap();
    let call = match foreign_report.take_outcomes().pop().unwrap() {
        TickOutcome::Call(call) => call,
        _ => panic!("call"),
    };
    let foreign_admitted = harness.fixture.admit_collected(call);
    assert_eq!(first_admitted.h0_ordinal(), foreign_admitted.h0_ordinal());
    assert!(first.classify_ordinary(&foreign_admitted).is_err());
    assert!(foreign_raw.classify_ordinary(&first_admitted).is_err());
    first.classify_ordinary(&first_admitted).unwrap();
    harness.ingest(first, &first_admitted);
    let child = ImageIdentity {
        task_cookie: 72,
        exec_id: 0,
    };
    harness.push_ordinary(child);
    let mut second = harness.collect();
    let (_, second_admitted) = harness.route(&mut second);
    assert!(second_admitted.h0_ordinal() > first_admitted.h0_ordinal());
    assert!(
        second.classify_ordinary(&first_admitted).is_err(),
        "consumed same-shaped admission is foreign"
    );
    second.classify_ordinary(&second_admitted).unwrap();
    harness.ingest(second, &second_admitted);
    let cut = harness
        .adapter
        .resolve_birth_cut(
            &harness.drain.consumption_cut().unwrap(),
            &harness.producers,
        )
        .unwrap();
    assert!(
        harness
            .adapter
            .quiet_sighting_at(harness.io.current_image, &cut)
    );
    assert!(
        !harness.adapter.quiet_sighting_at(child, &cut),
        "fork-child sighting always affects"
    );
}

#[test]
fn joint_birth_cut_requires_original_stream_prefix() {
    let mut harness = JointBirthHarness::new();
    let initial = harness.drain.consumption_cut().unwrap();
    let mut raw = harness.collect();
    harness
        .capture
        .tick_collected_with(&mut harness.io, &mut raw)
        .unwrap();
    // Unobserved movement is refused before the next collection consumes.
    harness.push_ordinary(ImageIdentity::default());
    harness.drain.poll(Some(1), |_| ControlFlow::Continue(()));
    let remaining = harness.drain.source().remaining();
    assert!(crate::semantics_objects::journal::joint_driver::RawJointQuantum::collect_bounded_with_adapter(&mut harness.drain, &harness.rows, 4_096, None, &BirthFault, &harness.producers, |bytes| harness.pool.reserve(bytes), &mut harness.adapter).is_err());
    assert_eq!(harness.drain.source().remaining(), remaining);
    let foreign = crate::events::EventDrain::over_domain(
        crate::events::ScriptedRecords::records([], 0),
        crate::events::EventsDomain::test_standin(harness.producers.events_id()),
    );
    assert!(
        harness
            .adapter
            .resolve_birth_cut(&foreign.consumption_cut().unwrap(), &harness.producers)
            .is_err()
    );
    assert!(
        harness
            .adapter
            .resolve_birth_cut(&initial, &harness.producers)
            .is_ok(),
        "original boundary itself remains historical, never remapped to later movement"
    );
}

#[test]
fn joint_birth_witness_refuses_replaced_custody_provider_native_and_fence() {
    use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
    let mut harness = JointBirthHarness::new();
    harness.push_create(1);
    let mut raw = harness.collect();
    let (report, admitted) = harness.route(&mut raw);
    let (_, proof) = harness.ingest(raw, &admitted);
    let publisher = NativePublisher::build();
    let closure = harness.fixture.attachment().generation();
    let (row, control, _) = publisher.publish_stamped(&["0", "0"], closure);
    let mut rows = NativeBirthRows { row, control };
    let witness = harness.birth(report, &admitted, &proof, None, &mut rows);
    let native = harness.io.domain;
    harness.io.domain = NativeDomainId::mint();
    assert!(
        witness
            .fresh_evidence_with(
                &mut harness.io,
                &mut rows,
                &harness.capture,
                harness.fixture.attachment(),
                harness.fixture.binding()
            )
            .is_err()
    );
    harness.io.domain = native;
    let original_pin = harness.capture.bindings.get_mut(&71).unwrap().pin.clone();
    harness.capture.bindings.get_mut(&71).unwrap().pin =
        Arc::new(PidPin::open(original_pin.pid()).unwrap());
    assert!(
        witness
            .fresh_evidence_with(
                &mut harness.io,
                &mut rows,
                &harness.capture,
                harness.fixture.attachment(),
                harness.fixture.binding()
            )
            .is_err(),
        "same PID and scalar identity cannot replace the original Arc"
    );
    harness.capture.bindings.get_mut(&71).unwrap().pin = original_pin;
    let other = harness.io.watched[1].share();
    let original = std::mem::replace(&mut harness.io.watched[0], other);
    assert!(
        witness
            .fresh_evidence_with(
                &mut harness.io,
                &mut rows,
                &harness.capture,
                harness.fixture.attachment(),
                harness.fixture.binding()
            )
            .is_err()
    );
    harness.io.watched[0] = original;
    let (wrong, control, _) = publisher.publish_stamped(&["0", "0"], closure + 1);
    let mut wrong_rows = NativeBirthRows {
        row: wrong,
        control,
    };
    assert_eq!(
        witness.fresh_evidence_with(
            &mut harness.io,
            &mut wrong_rows,
            &harness.capture,
            harness.fixture.attachment(),
            harness.fixture.binding()
        ),
        Err(crate::attach::BirthObservationRefusal::GenerationMismatch)
    );
    // The bounded window is measured on the fixture clock: advance it past
    // the scan slice instead of sleeping on the wall clock.
    harness.io.receipt_advance = harness.capture.limits.scan_slice + Duration::from_millis(1);
    assert!(
        witness
            .fresh_evidence_with(
                &mut harness.io,
                &mut rows,
                &harness.capture,
                harness.fixture.attachment(),
                harness.fixture.binding()
            )
            .is_err(),
        "fresh native reads share one bounded window"
    );
    harness.io.receipt_advance = Duration::ZERO;
    assert!(
        witness
            .fresh_evidence_with(
                &mut harness.io,
                &mut rows,
                &harness.capture,
                harness.fixture.attachment(),
                harness.fixture.binding()
            )
            .is_ok(),
        "a later fresh read retains the original birth, not a renewed New"
    );
    harness.capture.audit_health(
        Health {
            fault: 1,
            sticky: 0,
        },
        &mut TickReport::default(),
    );
    harness.io.last_health.fault = 1;
    assert!(
        witness
            .fresh_evidence_with(
                &mut harness.io,
                &mut rows,
                &harness.capture,
                harness.fixture.attachment(),
                harness.fixture.binding()
            )
            .is_err(),
        "an original fence never follows a fault-era move"
    );
}

#[test]
fn joint_birth_recheck_measures_the_window_on_the_test_clock() {
    use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
    let mut harness = JointBirthHarness::new();
    harness.push_create(1);
    let mut raw = harness.collect();
    let (report, admitted) = harness.route(&mut raw);
    let (_, proof) = harness.ingest(raw, &admitted);
    let publisher = NativePublisher::build();
    let closure = harness.fixture.attachment().generation();
    let (row, control, _) = publisher.publish_stamped(&["0", "0"], closure);
    let mut rows = NativeBirthRows { row, control };
    let witness = harness.birth(report, &admitted, &proof, None, &mut rows);
    // Plant the descheduling a parallel run inflicts: wall time passes
    // mid-recheck while every observed fact stays coherent. The test-only
    // recheck is bounded by the fixture clock, not the wall clock.
    struct StalledRows<'a>(&'a mut NativeBirthRows);
    impl crate::attach::BirthRowReader for StalledRows<'_> {
        fn read_marker_row(
            &mut self,
        ) -> Result<p11scope_ebpf_common::InstanceRecord, crate::attach::BirthRowError> {
            std::thread::sleep(Duration::from_millis(60));
            crate::attach::BirthRowReader::read_marker_row(self.0)
        }
        fn read_admission_control(
            &mut self,
        ) -> Result<p11scope_ebpf_common::JournalAdmissionControl, crate::attach::BirthRowError>
        {
            crate::attach::BirthRowReader::read_admission_control(self.0)
        }
    }
    assert!(
        witness
            .fresh_evidence_with(
                &mut harness.io,
                &mut StalledRows(&mut rows),
                &harness.capture,
                harness.fixture.attachment(),
                harness.fixture.binding()
            )
            .is_ok(),
        "a descheduled-but-coherent recheck succeeds on the frozen test clock"
    );
}

#[test]
fn joint_birth_cut_cannot_bridge_busy_discard_or_malformed_movement() {
    use crate::events::{BoundedRecord, BoundedRecordSource, EventDrain, RecordSource};
    use crate::semantics_objects::journal::joint_driver::RawJointQuantum;
    use std::cell::Cell;
    use std::rc::Rc;
    struct GapSource {
        queue: VecDeque<Vec<u8>>,
        cursor: usize,
        mode: Rc<Cell<u8>>,
        discarded: u64,
    }
    impl RecordSource for GapSource {
        fn next_record(&mut self) -> Option<impl std::ops::Deref<Target = [u8]> + '_> {
            if let Some(record) = self.queue.pop_front() {
                self.cursor += 8;
                return Some(record);
            }
            match self.mode.get() {
                1 => {
                    self.mode.set(0);
                    self.cursor += 8;
                    Some(vec![0])
                }
                2 => {
                    self.mode.set(0);
                    self.cursor += 8;
                    self.discarded += 1;
                    None
                }
                _ => None,
            }
        }
        fn discarded(&self) -> u64 {
            self.discarded
        }
    }
    impl BoundedRecordSource for GapSource {
        fn positions(&self) -> aya::maps::ring_buf::RingBufPositions {
            aya::maps::ring_buf::RingBufPositions {
                consumer: self.cursor,
                producer: self.cursor + 8 * (self.queue.len() + usize::from(self.mode.get() != 0)),
                capacity: 4096,
            }
        }
        fn consumer(&self) -> usize {
            self.cursor
        }
        fn bounded_record(
            &mut self,
            stop: usize,
        ) -> anyhow::Result<BoundedRecord<impl std::ops::Deref<Target = [u8]> + '_>> {
            if self.cursor == stop {
                return Ok(BoundedRecord::Reached);
            }
            let record = self.next_record().map(|record| record.to_vec());
            Ok(match record {
                Some(record) => BoundedRecord::Item(record),
                None if self.cursor == stop => BoundedRecord::Reached,
                None => BoundedRecord::Pending,
            })
        }
    }
    for mode in 1..=3 {
        let mut harness = JointBirthHarness::new();
        let events = harness.drain.consumption_cut().unwrap().events().clone();
        let switch = Rc::new(Cell::new(0));
        let source = GapSource {
            queue: VecDeque::from([crate::events::record_bytes(
                &harness.ordinary(ImageIdentity::default()),
            )]),
            cursor: 0,
            mode: switch.clone(),
            discarded: 0,
        };
        let mut drain = EventDrain::over_domain(source, events);
        let mut quiet = RawJointQuantum::collect_bounded_with_adapter(
            &mut drain,
            &harness.rows,
            4_096,
            None,
            &BirthFault,
            &harness.producers,
            |bytes| harness.pool.reserve(bytes),
            &mut harness.adapter,
        )
        .unwrap();
        let (_, admitted) = harness.route(&mut quiet);
        quiet.classify_ordinary(&admitted).unwrap();
        harness.ingest(quiet, &admitted);
        let original = harness
            .adapter
            .resolve_birth_cut(&drain.consumption_cut().unwrap(), &harness.producers)
            .unwrap();
        switch.set(mode);
        let stop = (mode == 3).then_some(16);
        let mut raw = RawJointQuantum::collect_bounded_with_adapter(
            &mut drain,
            &harness.rows,
            4_096,
            stop,
            &BirthFault,
            &harness.producers,
            |bytes| harness.pool.reserve(bytes),
            &mut harness.adapter,
        )
        .unwrap();
        let report = harness
            .capture
            .tick_collected_with(&mut harness.io, &mut raw)
            .unwrap();
        assert_eq!(report.calls().count(), 0);
        let (audit, _) = harness.ingest(raw, &admitted);
        assert!(audit.counter_error || audit.malformed_delta != 0 || audit.discarded_delta != 0);
        assert!(
            !harness.adapter.accepts_birth_cut(&original),
            "no clean prefix after mode {mode}"
        );
        switch.set(0);
        assert!(
            harness
                .adapter
                .resolve_birth_cut(&drain.consumption_cut().unwrap(), &harness.producers)
                .is_err(),
            "later healthy reads cannot heal the missing stream at mode {mode}"
        );
    }
}

#[test]
fn joint_birth_recheck_keeps_pending_original_for_actual_h0_publication() {
    use crate::semantics_objects::journal::tests::{NativeBirthRows, NativePublisher};
    let mut harness = JointBirthHarness::new();
    harness.push_create(1);
    let mut raw = harness.collect();
    let (report, admitted) = harness.route(&mut raw);
    let (_, proof) = harness.ingest(raw, &admitted);
    let publisher = NativePublisher::build();
    let (row, control, _) =
        publisher.publish_stamped(&["0", "0"], harness.fixture.attachment().generation());
    let mut rows = NativeBirthRows { row, control };
    let witness = harness.birth(report, &admitted, &proof, None, &mut rows);
    let mut pending_record = harness.ordinary(ImageIdentity::default());
    pending_record.event.image.task_cookie = 72;
    harness
        .drain
        .source_mut()
        .push_record(crate::events::record_bytes(&pending_record));
    harness.io.fail_cookie = Some(72);
    let mut pending_raw = harness.collect();
    let pending = harness
        .capture
        .tick_collected_with(&mut harness.io, &mut pending_raw)
        .unwrap();
    let position = pending.awaiting_floor().expect("original pending position");
    assert_eq!(pending.calls().count(), 0);
    assert_eq!(harness.capture.awaiting.len(), 1);
    harness.io.last_health.fault = 1;
    assert!(
        witness
            .fresh_evidence_with(
                &mut harness.io,
                &mut rows,
                &harness.capture,
                harness.fixture.attachment(),
                harness.fixture.binding()
            )
            .is_err()
    );
    assert!(
        harness.capture.awaiting.contains_key(&position),
        "a birth read must not consume pending originals into a temporary report"
    );
    let mut resolved = harness
        .capture
        .tick_collected_with(&mut harness.io, &mut pending_raw)
        .unwrap();
    assert_eq!(
        resolved.calls().count(),
        1,
        "actual H0 publishes the original exactly once"
    );
    let call = resolved.calls().next().unwrap();
    assert_eq!(call.position(), Some(position));
    assert_eq!(
        crate::events::record_bytes(call.record()),
        crate::events::record_bytes(&pending_record)
    );
    assert!(
        resolved
            .take_outcomes()
            .iter()
            .any(TickOutcome::is_invalidation)
    );
    assert!(harness.capture.awaiting.is_empty());
}

/// H7 slice D activation: mixed ordinary/lifecycle/object records flow
/// through the session's single retained cursor; a delayed object CALL
/// keeps its exact validated payload and original position once; a
/// no-call tick resolves it; malformed suffix and partial/extra-length
/// twins disclose loss without positive object facts; bare Event
/// consumers are unchanged; stop drains without duplicating the call.
#[test]
fn object_producer_full_record_mixed_cursor_and_pending() {
    use crate::discovery::caller_registry::instance_input::CallEvidence;
    use crate::events::{
        EventDrain, ScriptedRecords, decode, poll_object_records_to_position, record_bytes,
    };
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_LAYOUT_LP64, ObjectAttributeListWire, ObjectAttributeWire,
        ObjectCallWire, publish_object_descriptors,
    };

    let descriptors = publish_object_descriptors();
    let function = crate::kinds::function_id("C_CreateObject").expect("Create ordinal");
    assert_eq!(function, 20);
    let index = function + 1;
    assert_eq!(descriptors[index as usize].action, OBJECT_ACTION_CREATE);

    // One exact validated Create tail: observed result handle plus a
    // classified request cell, an inspected request list and empty
    // remainder.
    let tail = ObjectCallWire {
        version: 1,
        bytes: 240,
        descriptor_index: index,
        flags: 0,
        layout: OBJECT_LAYOUT_LP64,
        action: OBJECT_ACTION_CREATE,
        entry_derive: 0,
        reserved0: 0,
        input_handles: [0, 0],
        result_handles: [0xA11CE, 0],
        find_handles: [0; 8],
        input_status: [0, 0],
        result_status: [1, 0],
        find_status: [0; 8],
        find_len: 0,
        find_flags: 0,
        find_valid: 0,
        reserved1: 0,
        requested: [
            ObjectAttributeListWire {
                cells: [
                    ObjectAttributeWire {
                        kind: 1,
                        status: 1,
                        value: 3,
                    },
                    ObjectAttributeWire::default(),
                    ObjectAttributeWire::default(),
                    ObjectAttributeWire::default(),
                    ObjectAttributeWire::default(),
                    ObjectAttributeWire::default(),
                    ObjectAttributeWire::default(),
                    ObjectAttributeWire::default(),
                ],
                inspected: 1,
                flags: 1,
                reserved: 0,
            },
            ObjectAttributeListWire::default(),
        ],
        result_attributes: ObjectAttributeListWire::default(),
        reserved2: 0,
    };
    assert_eq!(std::mem::size_of::<ObjectCallWire>(), 240);
    let tail_bytes: [u8; 240] = unsafe { std::mem::transmute(tail) };
    assert!(
        p11scope_ebpf_common::object_wire::validate_object_tail(
            &tail_bytes,
            &descriptors[index as usize]
        ),
        "the scripted tail must validate against its frozen row"
    );

    // Base records reuse the exact routing fixtures; the lifecycle
    // record differs only in its non-CALL type.
    let domain = NativeDomainId::mint();
    let mut io = ScriptIo::new(domain);
    let mut capture = capture(&io);
    io.call(1, 0);
    io.call(1, 0);
    io.call(1, 0);
    let ordinary = io.records.pop_front().expect("ordinary base").base;
    let object_base = io.records.pop_front().expect("object base").base;
    let mut lifecycle = io.records.pop_front().expect("lifecycle base").base;
    lifecycle.event.event_type = p11scope_ebpf_common::event_type::FORK;

    // The single cursor delivers alternating 368/608-byte records in
    // order with no second drain: ordinary, lifecycle, object.
    let mut object_record = record_bytes(&object_base);
    object_record.extend_from_slice(&tail_bytes);
    assert_eq!(object_record.len(), 368 + 240);
    let script = vec![
        record_bytes(&ordinary),
        record_bytes(&lifecycle),
        object_record,
    ];
    let mut drain = EventDrain::over(ScriptedRecords::records(script, 3));
    let mut decoded = Vec::new();
    assert!(
        !drain.poll_object_records(None, &descriptors, |record| {
            decoded.push(record);
            ControlFlow::Continue(())
        }),
        "the scripted source ends after its three records"
    );
    assert_eq!(decoded.len(), 3);
    assert!(decoded[0].object.is_none());
    assert!(decoded[1].object.is_none());
    let carried = decoded[2].object.as_ref().expect("validated object tail");
    assert_eq!(carried.tail_bytes(), &tail_bytes);
    assert_eq!(carried.descriptor_index(), index);
    assert_eq!(drain.malformed(), 0);

    // Malformed suffix (valid prefix, corrupt tail) and
    // partial/extra-length twins disclose loss; nothing decodes.
    let mut bad_suffix = record_bytes(&object_base);
    let mut bad_tail = tail_bytes;
    bad_tail[0] = 2;
    bad_suffix.extend_from_slice(&bad_tail);
    let mut twins = vec![
        bad_suffix,
        vec![9u8; 367],
        vec![9u8; 369],
        vec![9u8; 607],
        vec![9u8; 609],
    ];
    // A truncated valid object record is partial, not a prefix decode.
    twins.push(record_bytes(&object_base)[..367].to_vec());
    let mut spoiled = EventDrain::over(ScriptedRecords::records(twins, 6));
    let mut spoiled_count = 0;
    assert!(
        !spoiled.poll_object_records(None, &descriptors, |_| {
            spoiled_count += 1;
            ControlFlow::Continue(())
        }),
        "the spoiled script ends"
    );
    assert_eq!(spoiled_count, 0);
    assert_eq!(spoiled.malformed(), 6);

    // Bare Event consumers are unchanged: 368 decodes, every other
    // selected form refuses without a tail read.
    assert!(decode(&record_bytes(&ordinary)).is_some());
    let mut full = record_bytes(&object_base);
    full.extend_from_slice(&tail_bytes);
    assert!(decode(&full).is_none());
    assert!(decode(&vec![9u8; 607]).is_none());
    assert!(decode(&vec![9u8; 609]).is_none());

    // The delayed object CALL: a failing scan parks it in Pending
    // with its payload; the no-call tick resolves it exactly once
    // with its original collection position.
    io.records.extend(decoded);
    io.fail_file = Some(0);
    let parked = capture.tick_with(&mut io).unwrap();
    assert_eq!(parked.collected_calls, 2);
    assert_eq!(
        parked.calls().count(),
        0,
        "failing scans park both calls in Pending"
    );
    assert!(
        parked
            .outcomes()
            .iter()
            .any(|item| matches!(item, TickOutcome::Other(_))),
        "the lifecycle record still reports while calls wait"
    );
    assert_eq!(capture.awaiting.len(), 2);
    io.fail_file = None;
    let resolved = capture.tick_with(&mut io).unwrap();
    assert_eq!(
        resolved.collected_calls, 0,
        "the no-call tick collects none"
    );
    let joined: Vec<_> = resolved.calls().collect();
    assert_eq!(joined.len(), 2, "both parked calls resolve once");
    let object = joined
        .iter()
        .find(|call| call.record().event.event_type == event_type::CALL && call.token() == Some(3))
        .expect("the object CALL resolves at its original position");
    assert_eq!(object.token(), Some(3));
    // A quiet tick emits nothing further: no duplicate delivery.
    let quiet = capture.tick_with(&mut io).unwrap();
    assert_eq!(quiet.calls().count(), 0);
    assert!(capture.awaiting.is_empty());

    // The owned H3 routed call converts move-only with its exact
    // validated payload; the position is the original cursor order.
    let owned: Vec<_> = resolved.into_outcomes().into_iter().collect();
    let mut evidence = None;
    for outcome in owned {
        if let TickOutcome::Call(call) = outcome
            && call.token() == Some(3)
        {
            evidence = CallEvidence::from_routed(call);
        }
    }
    let evidence = evidence.expect("object CALL converts to evidence");
    assert_eq!(evidence.token(), 3);
    assert_eq!(
        evidence
            .object_tail()
            .expect("evidence carries the tail")
            .tail_bytes(),
        &tail_bytes
    );

    // A malformed collection discloses loss and forbids positives.
    io.collection_status = CollectionStatus::Malformed;
    io.call(1, 0);
    let failed = capture.tick_with(&mut io).unwrap();
    assert!(
        failed
            .calls()
            .all(|call| !matches!(call.route(), Route::Joined(_))),
        "malformed collection forbids positive routes"
    );

    // Stop drains once: Stopped is disclosed, nothing is duplicated.
    let stopped = capture.stop();
    assert!(
        stopped.outcomes().iter().any(|item| matches!(
            item,
            TickOutcome::Invalidation(value)
                if matches!(value.scope(), InvalidationScope::Stopped)
        )),
        "stop discloses Stopped"
    );
    assert!(capture.awaiting.is_empty());

    // The stop-time bounded cursor delivers the 608-byte form intact.
    let mut terminal = EventDrain::over(ScriptedRecords::records([full], 1));
    let mut terminal_decoded = Vec::new();
    // The Q stop stands after the one record (8 scripted bytes).
    let (post_q, backlog) =
        poll_object_records_to_position(&mut terminal, 8, None, &descriptors, |record| {
            terminal_decoded.push(record);
            ControlFlow::Continue(())
        })
        .expect("bounded stop drain");
    assert!(!post_q && !backlog);
    assert_eq!(terminal_decoded.len(), 1);
    assert_eq!(
        terminal_decoded[0]
            .object
            .as_ref()
            .expect("stop drain keeps the tail")
            .tail_bytes(),
        &tail_bytes
    );
}
fn stash_watched() -> RetainedInventoryTarget {
    let pins = crate::discovery::identity::test_fixture::real_scan_pin(
        &std::env::current_exe().unwrap(),
        None,
        1,
        "held-test-image",
    );
    pins.retain_inventory_target(PinnedObjectId(0)).unwrap()
}
fn merge_receipt(
    domain: NativeDomainId,
    cookie: u64,
    watched: &RetainedInventoryTarget,
) -> CurrentPartitionReceipt {
    CurrentPartitionReceipt::scripted(
        domain,
        ImageIdentity {
            task_cookie: cookie,
            exec_id: 1,
        },
        Arc::new(PidPin::test_proc_only(4321)),
        Endpoint {
            object: PinnedObjectId(0),
            file_slot: 0,
            offset: 0x1200,
        },
        0,
        watched.share(),
        CompleteEpochs {
            local: 0,
            global: 0,
            fault: 0,
            sticky: 0,
            record_flags: 0,
        },
        0,
        Instant::now() + Duration::from_secs(60),
        Vec::new(),
    )
}
#[test]
fn merge_stashed_current_appends_fresh_first() {
    let domain = NativeDomainId::mint();
    let watched = stash_watched();
    let mut report = TickReport::scripted(
        Vec::new(),
        vec![
            merge_receipt(domain, 1, &watched),
            merge_receipt(domain, 2, &watched),
        ],
    );
    let stashed = vec![
        merge_receipt(domain, 3, &watched),
        merge_receipt(domain, 4, &watched),
    ];
    assert_eq!(report.merge_stashed_current(stashed), 0);
    let cookies: Vec<u64> = report
        .current()
        .iter()
        .map(|receipt| receipt.image().task_cookie)
        .collect();
    assert_eq!(
        cookies,
        vec![1, 2, 3, 4],
        "fresh receipts first, stashed appended"
    );
}
#[test]
fn merge_stashed_current_truncates_to_batch_capacity() {
    let domain = NativeDomainId::mint();
    let watched = stash_watched();
    let mut report = TickReport::scripted(Vec::new(), vec![merge_receipt(domain, 0, &watched)]);
    let stashed: Vec<_> = (1..=MAX_INSTANCES as u64)
        .map(|cookie| merge_receipt(domain, cookie, &watched))
        .collect();
    assert_eq!(report.merge_stashed_current(stashed), 1);
    assert_eq!(report.current().len(), MAX_INSTANCES);
    assert_eq!(
        report.current()[0].image().task_cookie,
        0,
        "the fresh receipt survives truncation"
    );
}
#[test]
fn merge_stashed_outcomes_sheds_calls_before_invalidations() {
    let domain = NativeDomainId::mint();
    let call = || {
        let stamp = InstanceStamp::default();
        TickOutcome::Call(RoutedCall::scripted(
            domain,
            DecodedEventRecord {
                joint_resource: None,
                base: event_record_with_routing(
                    p11scope_ebpf_common::Event::default(),
                    stamp,
                    0x2200,
                ),
                object: None,
            },
            Route::Unknown(UnknownReason::PendingCapacity),
            None,
            Some(1),
        ))
    };
    let invalidation = TickOutcome::Invalidation(Invalidation {
        domain,
        scope: InvalidationScope::FaultEra,
        position: Some(1025),
    });
    assert!(invalidation.is_invalidation());
    assert!(!call().is_invalidation());
    let mut report = TickReport::scripted((0..MAX_INSTANCES).map(|_| call()).collect(), Vec::new());
    assert_eq!(report.merge_stashed_outcomes(vec![invalidation]), 1);
    assert_eq!(report.outcomes().len(), MAX_INSTANCES);
    assert!(
        report
            .outcomes()
            .iter()
            .any(|outcome| matches!(outcome, TickOutcome::Invalidation(_))),
        "the merged invalidation survives a full batch: a call sheds instead"
    );
}

#[test]
fn dropped_batch_shed_counts_unjoined_calls_by_route() {
    // A dropped batch sheds its unjoined calls by route: Unknown under
    // their reason label, Pending under `pending`. Joined calls are
    // already counted in joined and must not shed; invalidations carry
    // no calls.
    let domain = NativeDomainId::mint();
    let call = |route, token| {
        let stamp = InstanceStamp::default();
        TickOutcome::Call(RoutedCall::scripted(
            domain,
            DecodedEventRecord {
                joint_resource: None,
                base: event_record_with_routing(
                    p11scope_ebpf_common::Event::default(),
                    stamp,
                    0x2200,
                ),
                object: None,
            },
            route,
            None,
            Some(token),
        ))
    };
    let outcomes = vec![
        call(Route::Joined(InstanceId::from_raw(1)), 1),
        call(Route::Joined(InstanceId::from_raw(1)), 2),
        call(Route::Unknown(UnknownReason::Unobserved), 3),
        call(Route::Unknown(UnknownReason::Unobserved), 4),
        call(Route::Unknown(UnknownReason::Evicted), 5),
        call(Route::Pending, 6),
        TickOutcome::Invalidation(Invalidation {
            domain,
            scope: InvalidationScope::FaultEra,
            position: Some(1025),
        }),
    ];
    assert_eq!(
        unjoined_shed_counts(&outcomes),
        BTreeMap::from([("evicted", 1), ("pending", 1), ("unobserved", 2),]),
        "joined calls and invalidations shed nothing"
    );
    assert!(
        unjoined_shed_counts(&[]).is_empty(),
        "an empty drop sheds nothing"
    );
}

#[test]
fn tick_report_carries_disposition_inputs() {
    // C5: each tick stamps its allocation watermark and
    // route-waiting floor for the finalizer's disposition evidence.
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    io.semantic_call("C_SignInit", 0, 0);
    io.semantic_call("C_Sign", 0, 0);
    let report = capture.tick_with(&mut io).unwrap();
    assert_eq!(report.calls().count(), 2);
    assert_eq!(report.allocated_below(), capture.next_token);
    assert!(capture.next_token > 1);
    assert_eq!(report.awaiting_floor(), None);
    assert_eq!(report.shed_floor(), None);
    assert!(!report.exhausted());
    // A scan-waiting call holds its allocated position in
    // awaiting: the floor names it while the watermark advances
    // past it.
    capture.limits.scans = 1;
    io.fail_file = Some(1);
    io.semantic_call("C_SignInit", 1, 0);
    let pending = capture.tick_with(&mut io).unwrap();
    assert_eq!(capture.awaiting.len(), 1);
    let token = *capture.awaiting.keys().next().unwrap();
    assert_eq!(pending.awaiting_floor(), Some(token));
    assert_eq!(pending.allocated_below(), capture.next_token);
    assert!(capture.next_token > token);
}

#[test]
fn terminal_stop_report_carries_actual_h0_watermark() {
    let mut capture =
        SemanticCapture::in_domain(NativeDomainId::mint(), TickLimits::default()).unwrap();
    let before = capture.next_token;
    let report = capture.stop();
    assert_eq!(report.outcomes().len(), 1);
    assert_eq!(report.outcomes()[0].position(), Some(before));
    assert_eq!(capture.next_token, before + 1);
    assert_eq!(report.allocated_below(), capture.next_token);
    assert_eq!(report.awaiting_floor(), None);
    assert!(!report.exhausted());

    let repeated = capture.stop();
    assert!(repeated.outcomes().is_empty());
    assert_eq!(repeated.allocated_below(), capture.next_token);
    assert_eq!(capture.next_token, before + 1);
}

fn retained_joint_quantum(
    io: &mut ScriptIo,
) -> (
    crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    crate::events::EventDrain<crate::events::ScriptedRecords>,
    crate::semantics_edge::resources::SemanticResourcePool,
) {
    use crate::events::{EventDrain, EventsDomain, ScriptedRecords, record_bytes};
    use crate::semantics_edge::resources::SemanticResourcePool;
    use crate::semantics_objects::journal::joint_driver::RawJointQuantum;
    struct Fault;
    impl crate::semantics_objects::journal::FaultEpoch for Fault {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            Ok(0)
        }
    }
    let records: Vec<_> = io
        .records
        .drain(..)
        .map(|record| record_bytes(&record.base))
        .collect();
    let limit = records.len();
    let events = EventsDomain::test_standin(0xef01);
    let producers = crate::attach::SessionDrainProducers::test_pair(io.domain, events.clone());
    let mut drain = EventDrain::over_domain(
        ScriptedRecords::records(
            records
                .into_iter()
                .chain([crate::events::event_bytes(&Default::default())]),
            limit,
        ),
        events,
    );
    let pool = SemanticResourcePool::default();
    let quantum = RawJointQuantum::collect(
        &mut drain,
        &p11scope_ebpf_common::object_wire::publish_object_descriptors(),
        limit,
        &Fault,
        &producers,
        |bytes| pool.reserve(bytes),
    )
    .unwrap_or_else(|reason| panic!("actual retained ordinary collection: {reason:?}"));
    (quantum, drain, pool)
}

#[test]
fn joint_collected_leaf_lifecycle_preserves_capacity_then_routes_later_call_once() {
    use crate::events::{EventDrain, EventsDomain, RecordSource, record_bytes};
    use crate::semantics_edge::resources::SemanticResourcePool;
    use crate::semantics_objects::journal::joint_driver::{RawJointQuantum, RawQuantumRefusal};
    struct Arriving(std::rc::Rc<std::cell::RefCell<VecDeque<Vec<u8>>>>);
    impl RecordSource for Arriving {
        fn next_record(&mut self) -> Option<impl std::ops::Deref<Target = [u8]> + '_> {
            self.0.borrow_mut().pop_front()
        }
    }
    struct Fault;
    impl crate::semantics_objects::journal::FaultEpoch for Fault {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            Ok(0)
        }
    }
    let mut io = ScriptIo::small(NativeDomainId::mint());
    let mut capture = capture(&io);
    io.semantic_call("C_Sign", 0, 0);
    let call = io.records.pop_front().unwrap();
    let mut lifecycle = call.base;
    lifecycle.event.event_type = event_type::FORK;
    let queue = std::rc::Rc::new(std::cell::RefCell::new(VecDeque::from([record_bytes(
        &lifecycle,
    )])));
    let events = EventsDomain::test_standin(47);
    let producers = crate::attach::SessionDrainProducers::test_pair(io.domain, events.clone());
    let mut drain = EventDrain::over_domain(Arriving(queue.clone()), events);
    let pool = SemanticResourcePool::default();
    let rows = p11scope_ebpf_common::object_wire::publish_object_descriptors();
    let mut quantum =
        RawJointQuantum::collect(&mut drain, &rows, 4_096, &Fault, &producers, |bytes| {
            pool.reserve(bytes)
        })
        .unwrap();
    let capacities = quantum.retained_capacities();
    let charged = pool.snapshot().charged_bytes;
    let first = capture.tick_collected_with(&mut io, &mut quantum).unwrap();
    assert_eq!(first.collected_calls, 0);
    assert!(
        first.outcomes().iter().any(
            |outcome| matches!(outcome, TickOutcome::Other(other) if other.position == Some(1))
        )
    );
    assert_eq!(quantum.pending_h0_records(), 0);
    assert_eq!(quantum.retained_capacities(), capacities);
    // Wait longer than the later H0 pending policy: no provider deadline
    // is created by a lifecycle-only input or empty raw continuation.
    io.now += Duration::from_secs(3);
    assert_eq!(
        quantum
            .continue_collect(&mut drain, &rows, 1_024, &Fault, &producers)
            .unwrap()
            .attempted,
        0
    );
    queue
        .borrow_mut()
        .extend([record_bytes(&call.base), record_bytes(&call.base)]);
    assert_eq!(
        quantum
            .continue_collect(&mut drain, &rows, 1, &Fault, &producers)
            .unwrap()
            .attempted,
        1
    );
    let returned = capture.tick_collected_with(&mut io, &mut quantum).unwrap();
    assert_eq!(returned.collected_calls, 1);
    let routed = returned.calls().next().unwrap();
    assert_eq!(routed.position(), Some(2));
    assert!(matches!(routed.route(), Route::Joined(_)));
    assert_eq!(quantum.retained_capacities(), capacities);
    assert_eq!(pool.snapshot().charged_bytes, charged);
    assert_eq!(
        quantum.continue_collect(&mut drain, &rows, 1, &Fault, &producers),
        Err(RawQuantumRefusal::H0Active)
    );
    assert_eq!(queue.borrow().len(), 1);
    let empty = capture.tick_collected_with(&mut io, &mut quantum).unwrap();
    assert_eq!(empty.collected_calls, 0);
    assert!(empty.calls().next().is_none());
    assert_eq!(queue.borrow().len(), 1);
    assert_eq!(quantum.retained_capacities(), capacities);
    assert_eq!(pool.snapshot().charged_bytes, charged);
}

#[test]
fn joint_collected_leaf_routes_original_records_without_second_collection() {
    let mut io = ScriptIo::small(NativeDomainId::mint());
    let mut capture = capture(&io);
    io.semantic_call("C_SignInit", 0, 0);
    io.semantic_call("C_Sign", 0, 0);
    let (mut quantum, drain, pool) = retained_joint_quantum(&mut io);
    let held = pool.snapshot().charged_bytes;
    // Today's collect leaf would consume this unrelated record. The new
    // leaf must leave it queued and route only the original cursor values.
    io.semantic_call("C_Sign", 1, 0);
    let report = capture.tick_collected_with(&mut io, &mut quantum).unwrap();
    assert_eq!(report.calls().count(), 2);
    assert!(report.calls().all(|call| {
        call.endpoint().unwrap().file_slot == 0 && matches!(call.route(), Route::Joined(_))
    }));
    assert_eq!(
        report.calls().map(RoutedCall::position).collect::<Vec<_>>(),
        vec![Some(1), Some(2)]
    );
    assert_eq!(report.allocated_below(), capture.next_token);
    assert_eq!(io.records.len(), 1);
    assert_eq!(drain.source().remaining(), 1);
    assert_eq!(pool.snapshot().charged_bytes, held);
}

fn joint_collected_pending_case(expire: bool) {
    let mut io = ScriptIo::small(NativeDomainId::mint());
    let mut capture = capture(&io);
    capture.limits.scans = 0;
    io.semantic_call("C_SignInit", 0, 0);
    let (mut quantum, drain, pool) = retained_joint_quantum(&mut io);
    let held = pool.snapshot().charged_bytes;
    let pending = capture.tick_collected_with(&mut io, &mut quantum).unwrap();
    assert_eq!(capture.awaiting.len(), 1);
    assert_eq!(pending.awaiting_floor(), Some(1));
    assert_eq!(pending.allocated_below(), 2);
    assert_eq!(pending.calls().count(), 0);
    capture.limits.scans = 1;
    io.semantic_call("C_Sign", 1, 0);
    if expire {
        io.now += capture.limits.pending_for;
    }
    let resolved = capture.tick_collected_with(&mut io, &mut quantum).unwrap();
    assert!(capture.awaiting.is_empty());
    assert_eq!(resolved.calls().count(), 1);
    let call = resolved.calls().next().unwrap();
    assert_eq!(call.position(), Some(1));
    assert_eq!(call.endpoint().unwrap().file_slot, 0);
    if expire {
        assert_eq!(call.route(), Route::Unknown(UnknownReason::Unobserved));
    } else {
        assert!(matches!(call.route(), Route::Joined(_)));
    }
    assert_eq!(resolved.awaiting_floor(), None);
    assert_eq!(resolved.allocated_below(), 2);
    assert_eq!(io.records.len(), 1);
    assert_eq!(drain.source().remaining(), 1);
    assert_eq!(pool.snapshot().charged_bytes, held);
}

#[test]
fn joint_collected_leaf_pending_success_keeps_original_quantum() {
    joint_collected_pending_case(false);
}

#[test]
fn joint_collected_leaf_pending_timeout_keeps_original_quantum() {
    joint_collected_pending_case(true);
}

#[test]
fn joint_collected_leaf_foreign_quantum_is_nonconsuming() {
    let mut source = ScriptIo::small(NativeDomainId::mint());
    source.semantic_call("C_SignInit", 0, 0);
    let (mut quantum, drain, _pool) = retained_joint_quantum(&mut source);
    let mut foreign_io = ScriptIo::small(NativeDomainId::mint());
    let mut foreign = capture(&foreign_io);
    foreign_io.semantic_call("C_Sign", 1, 0);
    assert!(
        foreign
            .tick_collected_with(&mut foreign_io, &mut quantum)
            .is_err()
    );
    assert_eq!(foreign.next_token, 1);
    assert!(foreign.awaiting.is_empty());
    assert_eq!(foreign_io.records.len(), 1);
    assert_eq!(quantum.pending_h0_records(), 1);
    assert_eq!(drain.source().remaining(), 1);
    let mut actual = capture(&source);
    let report = actual
        .tick_collected_with(&mut source, &mut quantum)
        .unwrap();
    assert_eq!(report.calls().count(), 1);
    assert!(matches!(
        report.calls().next().unwrap().route(),
        Route::Joined(_)
    ));
}

#[test]
fn joint_collected_leaf_pending_fault_preserves_original_call_position() {
    let mut io = ScriptIo::small(NativeDomainId::mint());
    let mut capture = capture(&io);
    capture.limits.scans = 0;
    io.semantic_call("C_SignInit", 0, 0);
    let (mut quantum, drain, pool) = retained_joint_quantum(&mut io);
    let held = pool.snapshot().charged_bytes;
    let pending = capture.tick_collected_with(&mut io, &mut quantum).unwrap();
    assert_eq!(pending.awaiting_floor(), Some(1));
    io.last_health.fault = 1;
    io.semantic_call("C_Sign", 1, 1);
    let lost = capture.tick_collected_with(&mut io, &mut quantum).unwrap();
    assert!(capture.awaiting.is_empty());
    assert_eq!(lost.calls().count(), 1);
    let call = lost.calls().next().unwrap();
    assert_eq!(call.position(), Some(1));
    assert_eq!(call.route(), Route::Unknown(UnknownReason::FaultEra));
    assert_eq!(lost.awaiting_floor(), None);
    assert_eq!(io.records.len(), 1);
    assert_eq!(drain.source().remaining(), 1);
    assert_eq!(pool.snapshot().charged_bytes, held);
}

#[test]
fn collected_transient_discard_fails_its_quantum_then_recovers() {
    use crate::events::{EventDrain, EventsDomain, RecordSource, record_bytes};
    use crate::semantics_edge::resources::SemanticResourcePool;
    use crate::semantics_objects::journal::joint_driver::RawJointQuantum;
    use std::collections::VecDeque;
    use std::ops::Deref;
    /// One lost reservation behind genuine records, like ring pressure:
    /// the drain reports the loss only after the queued bytes.
    struct DiscardingRecords {
        queue: VecDeque<Vec<u8>>,
        discarded: u64,
    }
    impl RecordSource for DiscardingRecords {
        fn next_record(&mut self) -> Option<impl Deref<Target = [u8]> + '_> {
            if let Some(record) = self.queue.pop_front() {
                return Some(record);
            }
            self.discarded = 1;
            None
        }
        fn discarded(&self) -> u64 {
            self.discarded
        }
    }
    struct Fault;
    impl crate::semantics_objects::journal::FaultEpoch for Fault {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            Ok(0)
        }
    }
    let mut io = ScriptIo::small(NativeDomainId::mint());
    let mut capture = capture(&io);
    // Prime: a healthy quantum binds and joins, fault era 0.
    io.semantic_call("C_SignInit", 0, 0);
    io.semantic_call("C_Sign", 0, 0);
    let (mut primed, _, _) = retained_joint_quantum(&mut io);
    let joined = capture.tick_collected_with(&mut io, &mut primed).unwrap();
    assert_eq!(joined.calls().count(), 2);
    assert!(
        joined
            .calls()
            .all(|call| matches!(call.route(), Route::Joined(_)))
    );
    // Failed quantum: one genuine call behind one discarded reservation.
    io.semantic_call("C_Sign", 0, 0);
    let records: Vec<_> = io
        .records
        .drain(..)
        .map(|record| record_bytes(&record.base))
        .collect();
    let events = EventsDomain::test_standin(0xef01);
    let producers = crate::attach::SessionDrainProducers::test_pair(io.domain, events.clone());
    let mut drain = EventDrain::over_domain(
        DiscardingRecords {
            queue: records.into(),
            discarded: 0,
        },
        events,
    );
    let pool = SemanticResourcePool::default();
    let mut failed = RawJointQuantum::collect(
        &mut drain,
        &p11scope_ebpf_common::object_wire::publish_object_descriptors(),
        4_096,
        &Fault,
        &producers,
        |bytes| pool.reserve(bytes),
    )
    .unwrap();
    let shed = capture.tick_collected_with(&mut io, &mut failed).unwrap();
    assert_eq!(shed.calls().count(), 1);
    assert_eq!(
        shed.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    assert!(
        shed.outcomes().iter().any(|outcome| matches!(
            outcome,
            TickOutcome::Invalidation(loss)
                if matches!(loss.scope(), InvalidationScope::CoverageFailed)
        )),
        "the failed quantum discloses its coverage loss"
    );
    // Recovery: the next healthy quantum audits, re-scans, and joins.
    io.semantic_call("C_Sign", 0, 1);
    let (mut healed, _, _) = retained_joint_quantum(&mut io);
    let recovered = capture.tick_collected_with(&mut io, &mut healed).unwrap();
    assert!(
        !capture.image_failed,
        "a bounded per-quantum loss must not latch coverage"
    );
    assert_eq!(recovered.calls().count(), 1);
    assert!(
        matches!(recovered.calls().next().unwrap().route(), Route::Joined(_)),
        "the post-loss quantum joins against a fresh observation"
    );
}

#[test]
fn collected_bounded_loss_with_failed_raise_fails_coverage_permanently() {
    use crate::events::{EventDrain, EventsDomain, RecordSource, record_bytes};
    use crate::semantics_edge::resources::SemanticResourcePool;
    use crate::semantics_objects::journal::joint_driver::RawJointQuantum;
    use std::collections::VecDeque;
    use std::ops::Deref;
    /// One lost reservation behind genuine records, like ring pressure:
    /// the drain reports the loss only after the queued bytes.
    struct DiscardingRecords {
        queue: VecDeque<Vec<u8>>,
        discarded: u64,
    }
    impl RecordSource for DiscardingRecords {
        fn next_record(&mut self) -> Option<impl Deref<Target = [u8]> + '_> {
            if let Some(record) = self.queue.pop_front() {
                return Some(record);
            }
            self.discarded = 1;
            None
        }
        fn discarded(&self) -> u64 {
            self.discarded
        }
    }
    struct Fault;
    impl crate::semantics_objects::journal::FaultEpoch for Fault {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            Ok(0)
        }
    }
    let mut io = ScriptIo::small(NativeDomainId::mint());
    let mut capture = capture(&io);
    // Prime: a healthy quantum binds and joins, fault era 0.
    io.semantic_call("C_SignInit", 0, 0);
    io.semantic_call("C_Sign", 0, 0);
    let (mut primed, _, _) = retained_joint_quantum(&mut io);
    let joined = capture.tick_collected_with(&mut io, &mut primed).unwrap();
    assert_eq!(joined.calls().count(), 2);
    assert!(
        joined
            .calls()
            .all(|call| matches!(call.route(), Route::Joined(_)))
    );
    // Failed quantum: one genuine call behind one discarded reservation,
    // but the scoped fault-era advance cannot land.
    io.raise_fails = true;
    io.semantic_call("C_Sign", 0, 0);
    let records: Vec<_> = io
        .records
        .drain(..)
        .map(|record| record_bytes(&record.base))
        .collect();
    let events = EventsDomain::test_standin(0xef01);
    let producers = crate::attach::SessionDrainProducers::test_pair(io.domain, events.clone());
    let mut drain = EventDrain::over_domain(
        DiscardingRecords {
            queue: records.into(),
            discarded: 0,
        },
        events,
    );
    let pool = SemanticResourcePool::default();
    let mut failed = RawJointQuantum::collect(
        &mut drain,
        &p11scope_ebpf_common::object_wire::publish_object_descriptors(),
        4_096,
        &Fault,
        &producers,
        |bytes| pool.reserve(bytes),
    )
    .unwrap();
    let shed = capture.tick_collected_with(&mut io, &mut failed).unwrap();
    assert_eq!(shed.calls().count(), 1);
    assert_eq!(
        shed.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    assert!(
        shed.outcomes().iter().any(|outcome| matches!(
            outcome,
            TickOutcome::Invalidation(loss)
                if matches!(loss.scope(), InvalidationScope::CoverageFailed)
        )),
        "the failed quantum discloses its coverage loss"
    );
    assert!(
        capture.image_failed,
        "a scoped recovery whose fault-era advance fails must latch coverage: \
         old-era stamps stay routable without it"
    );
    // No recovery: with raises working again the latched capture still
    // sheds, exactly as under permanent coverage failure.
    io.raise_fails = false;
    io.semantic_call("C_Sign", 0, 0);
    let (mut healed, _, _) = retained_joint_quantum(&mut io);
    let refused = capture.tick_collected_with(&mut io, &mut healed).unwrap();
    assert_eq!(refused.calls().count(), 1);
    assert_eq!(
        refused.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::CoverageFault),
        "the post-loss quantum must not join once the failed raise latched coverage"
    );
}

#[test]
fn collected_counter_error_stays_a_permanent_coverage_failure() {
    use crate::events::{EventDrain, EventsDomain, RecordSource, record_bytes};
    use crate::semantics_edge::resources::SemanticResourcePool;
    use crate::semantics_objects::journal::joint_driver::RawJointQuantum;
    use std::collections::VecDeque;
    use std::ops::Deref;
    /// A producer-protocol violation: the reader counter is saturated,
    /// so no lost-history bound can be established from this audit.
    struct SaturatedRecords {
        queue: VecDeque<Vec<u8>>,
    }
    impl RecordSource for SaturatedRecords {
        fn next_record(&mut self) -> Option<impl Deref<Target = [u8]> + '_> {
            self.queue.pop_front()
        }
        fn discarded(&self) -> u64 {
            u64::MAX
        }
    }
    struct Fault;
    impl crate::semantics_objects::journal::FaultEpoch for Fault {
        fn fault_epoch(&self) -> Result<u64, crate::semantics_objects::journal::FaultReadError> {
            Ok(0)
        }
    }
    let mut io = ScriptIo::small(NativeDomainId::mint());
    let mut capture = capture(&io);
    // Prime: a healthy quantum binds and joins, fault era 0.
    io.semantic_call("C_SignInit", 0, 0);
    io.semantic_call("C_Sign", 0, 0);
    let (mut primed, _, _) = retained_joint_quantum(&mut io);
    let joined = capture.tick_collected_with(&mut io, &mut primed).unwrap();
    assert_eq!(joined.calls().count(), 2);
    assert!(
        joined
            .calls()
            .all(|call| matches!(call.route(), Route::Joined(_)))
    );
    // Failed quantum: one genuine call behind a saturated counter.
    io.semantic_call("C_Sign", 0, 0);
    let records: Vec<_> = io
        .records
        .drain(..)
        .map(|record| record_bytes(&record.base))
        .collect();
    let events = EventsDomain::test_standin(0xef01);
    let producers = crate::attach::SessionDrainProducers::test_pair(io.domain, events.clone());
    let mut drain = EventDrain::over_domain(
        SaturatedRecords {
            queue: records.into(),
        },
        events,
    );
    let pool = SemanticResourcePool::default();
    let mut failed = RawJointQuantum::collect(
        &mut drain,
        &p11scope_ebpf_common::object_wire::publish_object_descriptors(),
        4_096,
        &Fault,
        &producers,
        |bytes| pool.reserve(bytes),
    )
    .unwrap();
    let shed = capture.tick_collected_with(&mut io, &mut failed).unwrap();
    assert_eq!(shed.calls().count(), 1);
    assert_eq!(
        shed.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    assert!(
        shed.outcomes().iter().any(|outcome| matches!(
            outcome,
            TickOutcome::Invalidation(loss)
                if matches!(loss.scope(), InvalidationScope::CoverageFailed)
        )),
        "the failed quantum discloses its coverage loss"
    );
    assert!(
        capture.image_failed,
        "an unprovable counter must latch coverage: a producer-protocol \
         violation must not clear after one tick"
    );
    // No recovery: the next healthy quantum still sheds, exactly as
    // under permanent coverage failure.
    io.semantic_call("C_Sign", 0, 1);
    let (mut healed, _, _) = retained_joint_quantum(&mut io);
    let refused = capture.tick_collected_with(&mut io, &mut healed).unwrap();
    assert_eq!(refused.calls().count(), 1);
    assert_eq!(
        refused.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::CoverageFault),
        "the post-loss quantum must not join once the counter error latched coverage"
    );
}

#[test]
fn merge_stash_records_shed_floor_and_exhaustion() {
    // C5: merged-overflow sheds record their minimum position; a
    // shed outcome without a position records exhaustion.
    let domain = NativeDomainId::mint();
    let call = |token: Option<u64>| {
        let stamp = InstanceStamp::default();
        TickOutcome::Call(RoutedCall::scripted(
            domain,
            DecodedEventRecord {
                joint_resource: None,
                base: event_record_with_routing(
                    p11scope_ebpf_common::Event::default(),
                    stamp,
                    0x2200,
                ),
                object: None,
            },
            Route::Unknown(UnknownReason::PendingCapacity),
            None,
            token,
        ))
    };
    let mut report = TickReport::scripted(
        (0..MAX_INSTANCES)
            .map(|n| call(Some(100 + n as u64)))
            .collect(),
        Vec::new(),
    );
    assert_eq!(
        report.merge_stashed_outcomes(vec![call(Some(200)), call(Some(201))]),
        2
    );
    assert_eq!(report.shed_floor(), Some(100));
    assert!(!report.exhausted());
    // A full invalidation batch sheds the stashed positive: an
    // unpositioned shed records exhaustion.
    let invalidation = || {
        TickOutcome::Invalidation(Invalidation {
            domain,
            scope: InvalidationScope::FaultEra,
            position: Some(300),
        })
    };
    let mut report = TickReport::scripted(
        (0..MAX_INSTANCES).map(|_| invalidation()).collect(),
        Vec::new(),
    );
    assert_eq!(report.merge_stashed_outcomes(vec![call(None)]), 1);
    assert!(report.exhausted());
}
fn retain_scripted_event_cursor(io: &mut ScriptIo) {
    let records: Vec<_> = io
        .records
        .drain(..)
        .map(|record| crate::events::record_bytes(&record.base))
        .collect();
    let bound = records.len();
    io.event_drain = Some(crate::events::EventDrain::over(
        crate::events::ScriptedRecords::records(records, bound),
    ));
}

#[test]
fn live_discovery_read_error_is_sticky_until_h0_consumes_the_events_prefix() {
    let mut io = ScriptIo::small(NativeDomainId::mint());
    let mut capture = capture(&io);
    prime(&mut capture, &mut io);
    io.call(1, 0);
    retain_scripted_event_cursor(&mut io);
    capture.service_live_discovery_with(|| anyhow::bail!("owned DISCOVERY unavailable"));
    capture.service_live_discovery_with(|| Ok(None));
    let report = capture.tick_with(&mut io).unwrap();
    assert_eq!(report.calls().count(), 1);
    assert_eq!(
        report.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    assert!(report.outcomes().iter().any(|outcome| matches!(
        outcome,
        TickOutcome::Invalidation(loss) if matches!(loss.scope(), InvalidationScope::CoverageFailed)
    )));
    assert_eq!(io.event_drain.as_ref().unwrap().source().remaining(), 0);
}

#[test]
fn live_discovery_malformed_is_sticky_until_h0_consumes_the_events_prefix() {
    let mut io = ScriptIo::small(NativeDomainId::mint());
    let mut capture = capture(&io);
    prime(&mut capture, &mut io);
    io.call(1, 0);
    retain_scripted_event_cursor(&mut io);
    let mut discovery = crate::events::DiscoveryDrain::over(
        crate::events::ScriptedRecords::records(vec![vec![0]], 1),
    );
    capture.service_live_discovery_with(|| Ok(discovery.dequeue()));
    capture.service_live_discovery_with(|| Ok(None));
    let report = capture.tick_with(&mut io).unwrap();
    assert_eq!(report.calls().count(), 1);
    assert_eq!(
        report.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    assert_eq!(discovery.source().remaining(), 0);
    assert_eq!(io.event_drain.as_ref().unwrap().source().remaining(), 0);
}

fn prime(capture: &mut SemanticCapture, io: &mut ScriptIo) -> Route {
    io.call(1, 0);
    let report = capture.tick_with(io).unwrap();
    assert_eq!(report.calls().count(), 1);
    assert_eq!(capture.router.ranges_retained(), 2);
    assert!(matches!(
        report.calls().next().unwrap().route(),
        Route::Joined(_)
    ));
    report.calls().next().unwrap().route()
}
#[test]
fn healthy_nonempty_tick_and_cached_join_use_one_instance() {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    let joined = prime(&mut capture, &mut io);
    io.call(1, 0);
    let report = capture.tick_with(&mut io).unwrap();
    assert_eq!(report.calls().count(), 1);
    assert_eq!(report.calls().next().unwrap().route(), joined);
    let call = report.calls().next().unwrap();
    assert_eq!(call.position(), call.token());
    assert_eq!(call.domain(), io.domain);
    let endpoint = call.endpoint().expect("retained owned endpoint");
    assert_eq!(endpoint.file_slot, 0);
    assert_eq!(endpoint.offset, 0x1200);
    assert_eq!(capture.router.instances_minted(), 1);
}
#[test]
fn pump_miss_invalidates_before_next_semantic_join_even_when_raise_fails() {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    prime(&mut capture, &mut io);
    io.raise_fails = true;
    io.health.push_back(Err(()));
    io.call(1, 0);
    let report = capture.tick_with(&mut io).unwrap();
    assert_eq!(
        report.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    assert_eq!(io.raises, 1);
    io.last_health.fault = 1;
    io.call(1, 1);
    assert_eq!(
        capture
            .tick_with(&mut io)
            .unwrap()
            .calls()
            .next()
            .unwrap()
            .route(),
        Route::Unknown(UnknownReason::CoverageFault)
    );
}
#[test]
fn postscan_fault_rejects_original_fence_then_fresh_call_succeeds() {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    io.health.extend([
        Ok(Health {
            fault: 0,
            sticky: 0,
        }),
        Ok(Health {
            fault: 1,
            sticky: 0,
        }),
    ]);
    io.call(1, 0);
    let report = capture.tick_with(&mut io).unwrap();
    assert_eq!(
        report.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::FaultEra)
    );
    assert_eq!(capture.router.instances_minted(), 0);
    io.call(1, 1);
    let report = capture.tick_with(&mut io).unwrap();
    assert!(matches!(
        report.calls().next().unwrap().route(),
        Route::Joined(_)
    ));
}
#[test]
fn unstable_job_cannot_starve_a_healthy_peer() {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    io.fail_cookie = Some(1);
    io.call(1, 0);
    io.call(2, 0);
    let report = capture.tick_with(&mut io).unwrap();
    assert!(
        report
            .calls()
            .any(|r| r.image().task_cookie == 2 && matches!(r.route(), Route::Joined(_)))
    );
    assert_eq!(
        io.attempts.iter().map(|a| a.0).collect::<Vec<_>>(),
        vec![1, 2]
    );
}
#[test]
fn original_deadline_expires_on_empty_batch_once() {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    io.fail_cookie = Some(1);
    io.call(1, 0);
    assert!(capture.tick_with(&mut io).unwrap().calls().next().is_none());
    let deadline = capture.jobs[0].deadline;
    io.now = deadline;
    let report = capture.tick_with(&mut io).unwrap();
    assert_eq!(report.calls().count(), 1);
    assert_eq!(
        report.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::Unobserved)
    );
    assert!(capture.tick_with(&mut io).unwrap().calls().next().is_none());
    assert_eq!(capture.router.pending_len(), 0);
}
#[test]
fn token_exhaustion_refuses_without_wrap_or_duplicate_outcome() {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    capture.next_token = u64::MAX;
    io.call(1, 0);
    io.call(2, 0);
    let report = capture.tick_with(&mut io).unwrap();
    assert_eq!(report.calls().count(), 2);
    assert!(
        report
            .calls()
            .all(|r| r.route() == Route::Unknown(UnknownReason::AuthorityExhausted))
    );
    assert_eq!(capture.next_token, u64::MAX);
    assert_eq!(capture.router.instances_minted(), 0);
}
#[test]
fn deadline_overflow_is_ordinary_permanent_refusal() {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    capture.limits.pending_for = Duration::MAX;
    io.call(1, 0);
    let report = capture.tick_with(&mut io).unwrap();
    assert_eq!(
        report.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::AuthorityExhausted)
    );
    assert_eq!(capture.router.instances_minted(), 0);
}
#[test]
fn stop_drains_pending_once_without_late_authority() {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    io.fail_cookie = Some(1);
    io.call(1, 0);
    assert!(capture.tick_with(&mut io).unwrap().calls().next().is_none());
    let stopped = capture.stop();
    assert_eq!(stopped.calls().count(), 1);
    assert_eq!(
        stopped.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::Unobserved)
    );
    assert!(capture.stop().calls().next().is_none());
}
#[test]
fn foreign_session_refuses_before_collection_or_state_mutation() {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    io.domain = NativeDomainId::mint();
    io.call(1, 0);
    assert!(capture.tick_with(&mut io).is_err());
    assert_eq!(io.records.len(), 1);
    assert_eq!(capture.next_token, 1);
    assert_eq!(capture.router.instances_minted(), 0);
}
#[test]
fn refresh_checks_owning_session_and_endpoint_before_scan() {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    let pin = io.pin.clone();
    let owner = io.domain;
    io.domain = NativeDomainId::mint();
    assert!(capture.refresh_with(&mut io, pin.clone(), 0).is_err());
    assert!(io.attempts.is_empty());
    io.domain = owner;
    let refused = capture.refresh_with(&mut io, pin.clone(), 99).unwrap();
    assert_eq!(refused.scan_refusals, vec![ImageQueryRefusal::Coverage]);
    assert!(io.attempts.is_empty());
    let healthy = capture.refresh_with(&mut io, pin, 0).unwrap();
    assert_eq!(healthy.observations, vec![ObserveOutcome::New]);
    assert_eq!(capture.router.instances_minted(), 1);
    assert_eq!(capture.router.ranges_retained(), 2);
    assert!(healthy.outcomes().is_empty());
}
#[test]
fn refresh_requires_pre_and_post_health_and_original_fence() {
    for before in [true, false] {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        let pin = io.pin.clone();
        if before {
            io.health.push_back(Err(()));
        } else {
            io.health.extend([
                Ok(io.last_health),
                Ok(Health {
                    fault: 1,
                    sticky: 0,
                }),
            ]);
        }
        let report = capture.refresh_with(&mut io, pin.clone(), 0).unwrap();
        assert_eq!(report.scans, usize::from(!before));
        assert!(report.observations.is_empty());
        assert!(capture.bindings.is_empty());
        assert_eq!(capture.router.instances_minted(), 0);
        assert!(
            report
                .outcomes()
                .iter()
                .any(|o| matches!(o, TickOutcome::Invalidation(_)))
        );
        if !before {
            let fresh = capture.refresh_with(&mut io, pin, 0).unwrap();
            assert_eq!(fresh.observations, vec![ObserveOutcome::New]);
            assert_eq!(capture.router.ranges_retained(), 2);
        }
    }
}
fn decoded_prefix_survives_failure(status: CollectionStatus) {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    prime(&mut capture, &mut io);
    io.call(1, 0);
    io.records.push_back(DecodedEventRecord {
        joint_resource: None,
        base: EventRecord {
            event: p11scope_ebpf_common::Event {
                event_type: u32::MAX,
                session: 0xfeed_1234_5678_9abc,
                ..Default::default()
            },
            ..Default::default()
        },
        object: None,
    });
    io.collection_status = status;
    let report = capture.tick_with(&mut io).unwrap();
    assert_eq!(report.collected_calls, 1);
    assert_eq!(report.calls().count(), 1);
    let call = report.calls().next().unwrap();
    assert_eq!(call.route(), Route::Unknown(UnknownReason::CoverageFault));
    assert_eq!(call.position(), Some(2));
    let other = report
        .outcomes()
        .iter()
        .find_map(|o| match o {
            TickOutcome::Other(other) => Some(other),
            _ => None,
        })
        .unwrap();
    assert_eq!(other.position(), Some(3));
    assert_eq!(other.record().event.session, 0xfeed_1234_5678_9abc);
    let loss = report
        .outcomes()
        .iter()
        .find_map(|o| match o {
            TickOutcome::Invalidation(loss) => Some(loss),
            _ => None,
        })
        .unwrap();
    assert!(matches!(loss.scope(), InvalidationScope::CoverageFailed));
    assert_eq!(loss.domain(), io.domain);
    assert_eq!(loss.position(), Some(4));
    assert!(matches!(report.outcomes()[0], TickOutcome::Invalidation(_)));
    assert_eq!(report.scans, 0);
    assert_eq!(capture.router.instances_minted(), 1);
    assert!(capture.tick_with(&mut io).unwrap().outcomes().is_empty());
    io.last_health.fault = 1;
    io.call(1, 1);
    let later = capture.tick_with(&mut io).unwrap();
    assert_eq!(later.calls().count(), 1);
    assert_eq!(
        later.calls().next().unwrap().route(),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    assert_eq!(later.scans, 0);
    assert_eq!(capture.router.instances_minted(), 1);
}
#[test]
fn malformed_collection_preserves_decoded_calls_and_other_once() {
    decoded_prefix_survives_failure(CollectionStatus::Malformed);
}
#[test]
fn partial_read_error_preserves_decoded_calls_and_other_once() {
    // Session currently fails to obtain its cursor before reading any
    // prefix. This I/O seam also preserves prefixes of future read errors.
    decoded_prefix_survives_failure(CollectionStatus::ReadError);
}
#[test]
fn unchanged_epoch_range_appearance_emits_exact_owned_file_loss() {
    let mut io = ScriptIo::new(NativeDomainId::mint());
    let mut capture = capture(&io);
    prime(&mut capture, &mut io);
    io.extra_range = true;
    let pin = io.pin.clone();
    let report = capture.refresh_with(&mut io, pin, 0).unwrap();
    assert_eq!(report.observations, vec![ObserveOutcome::CoverageFault]);
    let loss = report
        .outcomes()
        .iter()
        .find_map(|o| match o {
            TickOutcome::Invalidation(loss) => Some(loss),
            _ => None,
        })
        .unwrap();
    assert_eq!(loss.domain(), io.domain);
    assert!(
        matches!(loss.scope(), InvalidationScope::File { image, file_slot }
            if *image == (ImageIdentity { task_cookie: 1, exec_id: 1 }) && *file_slot == 0)
    );
    io.call(1, 0);
    assert_eq!(
        capture
            .tick_with(&mut io)
            .unwrap()
            .calls()
            .next()
            .unwrap()
            .route(),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    assert_eq!(capture.router.instances_minted(), 1);
}
mod authority_controls {
    use super::*;
    struct ChildGuard(std::process::Child);
    impl ChildGuard {
        fn spawn() -> (Self, Arc<PidPin>) {
            let child = Self(
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap(),
            );
            let pin = Arc::new(PidPin::open(child.0.id()).unwrap());
            (child, pin)
        }
        fn end(&mut self) {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[test]
    fn binding_capacity_is_once_only_and_keeps_existing_live_join() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        capture.limits.bindings = 1;
        let joined = prime(&mut capture, &mut io);
        io.call(2, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert_eq!(report.calls().count(), 1);
        assert_eq!(
            report.calls().next().unwrap().route(),
            Route::Unknown(UnknownReason::BindingCapacity)
        );
        assert_eq!(capture.bindings.len(), 1);
        assert_eq!(capture.router.pending_len(), 0);
        assert!(capture.jobs.is_empty());
        assert!(capture.tick_with(&mut io).unwrap().calls().next().is_none());
        io.call(1, 0);
        assert_eq!(
            capture
                .tick_with(&mut io)
                .unwrap()
                .calls()
                .next()
                .unwrap()
                .route(),
            joined
        );
    }
    #[test]
    fn proven_original_death_releases_capacity_after_permanent_retirement() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let (mut child, pin) = ChildGuard::spawn();
        io.pin = pin.clone();
        let mut capture = capture(&io);
        capture.limits.bindings = 1;
        prime(&mut capture, &mut io);
        child.end();
        assert!(pin.wait_ready(Some(Duration::ZERO)).unwrap());
        let report = capture.tick_with(&mut io).unwrap();
        assert!(
            report
                .outcomes()
                .iter()
                .any(|o| matches!(o, TickOutcome::Invalidation(i)
                if matches!(i.scope(), InvalidationScope::TaskRetired(1))))
        );
        assert!(capture.bindings.is_empty());
        io.pin = Arc::new(PidPin::open(std::process::id()).unwrap());
        io.call(2, 0);
        assert!(matches!(
            capture
                .tick_with(&mut io)
                .unwrap()
                .calls()
                .next()
                .unwrap()
                .route(),
            Route::Joined(_)
        ));
        io.call(1, 0);
        assert_eq!(
            capture
                .tick_with(&mut io)
                .unwrap()
                .calls()
                .next()
                .unwrap()
                .route(),
            Route::Unknown(UnknownReason::Retired)
        );
        assert_eq!(capture.bindings.len(), 1);
    }
    #[test]
    fn nonready_binding_preserves_the_original_pin_and_cached_positive() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        let joined = prime(&mut capture, &mut io);
        for _ in 0..3 {
            assert!(capture.tick_with(&mut io).unwrap().outcomes().iter().all(|o|
                    !matches!(o, TickOutcome::Invalidation(i) if matches!(i.scope(), InvalidationScope::TaskRetired(_)))));
        }
        assert!(Arc::ptr_eq(&capture.bindings[&1].pin, &io.pin));
        io.call(1, 0);
        assert_eq!(
            capture
                .tick_with(&mut io)
                .unwrap()
                .calls()
                .next()
                .unwrap()
                .route(),
            joined
        );
    }
    #[test]
    fn terminal_quota_rotates_past_a_live_prefix_on_empty_batches() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        capture.limits.terminal_reads = 1;
        prime(&mut capture, &mut io);
        let (mut child, pin) = ChildGuard::spawn();
        io.pin = pin;
        io.call(2, 0);
        assert!(matches!(
            capture
                .tick_with(&mut io)
                .unwrap()
                .calls()
                .next()
                .unwrap()
                .route(),
            Route::Joined(_)
        ));
        child.end();
        let a = capture.tick_with(&mut io).unwrap();
        let b = capture.tick_with(&mut io).unwrap();
        assert!(
            a.outcomes()
                .iter()
                .chain(b.outcomes())
                .any(|o| matches!(o, TickOutcome::Invalidation(i)
                if matches!(i.scope(), InvalidationScope::TaskRetired(2))))
        );
        assert!(capture.bindings.contains_key(&1));
        assert!(!capture.bindings.contains_key(&2));
    }
    #[test]
    fn live_binding_is_never_replaced_by_a_new_pin() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        prime(&mut capture, &mut io);
        let original = io.pin.clone();
        io.pin = Arc::new(PidPin::open(std::process::id()).unwrap());
        io.local = 1;
        io.call(1, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert!(
            !report
                .calls()
                .any(|r| matches!(r.route(), Route::Joined(_)))
        );
        assert!(Arc::ptr_eq(&capture.bindings[&1].pin, &original));
        assert_eq!(capture.router.instances_minted(), 1);
    }
    #[test]
    fn scan_identity_and_file_mismatch_cannot_mint_or_bind() {
        for file in [false, true] {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            if file {
                io.output_file = Some(1);
            } else {
                io.output_image = Some(ImageIdentity {
                    task_cookie: 2,
                    exec_id: 1,
                });
            }
            io.call(1, 0);
            let report = capture.tick_with(&mut io).unwrap();
            assert!(
                !report
                    .calls()
                    .any(|r| matches!(r.route(), Route::Joined(_)))
            );
            assert_eq!(capture.router.instances_minted(), 0);
            assert!(capture.bindings.is_empty());
        }
    }
    #[test]
    fn scan_slice_is_bounded_and_coalescing_keeps_original_deadline() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        io.fail_cookie = Some(1);
        io.call(1, 0);
        capture.tick_with(&mut io).unwrap();
        let original = capture.jobs[0].deadline;
        assert!(io.attempts[0].1 <= io.now.checked_add(capture.limits.scan_slice).unwrap());
        io.now += Duration::from_millis(1);
        io.call(1, 0);
        capture.tick_with(&mut io).unwrap();
        assert_eq!(capture.jobs.len(), 1);
        assert_eq!(capture.jobs[0].deadline, original);
        assert_eq!(capture.awaiting.len(), 2);
    }
    #[test]
    fn noncall_record_is_preserved_in_the_single_private_stream() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        io.records.push_back(DecodedEventRecord {
            joint_resource: None,
            base: EventRecord {
                event: p11scope_ebpf_common::Event {
                    event_type: u32::MAX,
                    image: ImageIdentity {
                        task_cookie: 9,
                        exec_id: 99,
                    },
                    session: 0xfeed_1234_5678_9abc,
                    ..Default::default()
                },
                ..Default::default()
            },
            object: None,
        });
        let report = capture.tick_with(&mut io).unwrap();
        let other = report
            .outcomes()
            .iter()
            .find_map(|o| match o {
                TickOutcome::Other(r) => Some(r),
                _ => None,
            })
            .expect("one retained noncall");
        assert_eq!(other.domain(), io.domain);
        assert_eq!(other.position(), Some(1));
        assert_eq!(other.record().event.session, 0xfeed_1234_5678_9abc);
        let debug = format!("{report:?}");
        assert!(!debug.contains("feed") && !debug.contains("183693"));
    }
    #[test]
    fn audit_invalidation_precedes_calls_and_keeps_pending_token_original() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        io.fail_cookie = Some(1);
        io.call(1, 0);
        capture.tick_with(&mut io).unwrap();
        let pending_token = *capture.awaiting.keys().next().unwrap();
        io.health.push_back(Err(()));
        io.call(1, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert!(matches!(report.outcomes()[0], TickOutcome::Invalidation(_)));
        let tokens: Vec<_> = report.calls().map(|r| r.token()).collect();
        assert_eq!(tokens, vec![Some(pending_token), Some(pending_token + 1)]);
        assert!(report.calls().all(|r| r.domain() == io.domain
            && r.route() == Route::Unknown(UnknownReason::CoverageFault)));
    }
    #[test]
    fn shared_positions_do_not_alias_invalidations_and_collected_calls() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        prime(&mut capture, &mut io);
        io.health.push_back(Err(()));
        io.call(1, 0);
        let report = capture.tick_with(&mut io).unwrap();
        let invalidation = report
            .outcomes()
            .iter()
            .find_map(|o| match o {
                TickOutcome::Invalidation(i) => Some(i),
                _ => None,
            })
            .unwrap();
        assert_eq!(report.calls().next().unwrap().token(), Some(2));
        assert_eq!(invalidation.position(), Some(3));
        assert_ne!(
            invalidation.position(),
            report.calls().next().unwrap().token()
        );
    }
    #[test]
    fn late_scan_result_cannot_consume_or_bind_after_its_slice() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        io.scan_advance = capture.limits.scan_slice + Duration::from_millis(1);
        io.call(1, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert!(
            !report
                .calls()
                .any(|r| matches!(r.route(), Route::Joined(_)))
        );
        assert_eq!(capture.router.instances_minted(), 0);
        assert!(capture.bindings.is_empty());
        assert_eq!(capture.jobs.len(), 1);
    }

    #[test]
    fn initial_pending_positive_does_not_invent_a_loss_barrier() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        io.call(1, 0);
        io.call(1, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert_eq!(report.calls().count(), 2);
        assert!(
            report
                .calls()
                .all(|call| matches!(call.route(), Route::Joined(_)))
        );
        assert!(
            !report
                .outcomes()
                .iter()
                .any(|o| matches!(o, TickOutcome::Invalidation(_)))
        );
        assert_eq!(capture.router.instances_minted(), 1);
    }
    #[test]
    fn accepted_epoch_change_retires_only_prior_ids_and_keeps_late_history() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        let Route::Joined(old) = prime(&mut capture, &mut io) else {
            unreachable!()
        };
        io.local = 1;
        io.call(1, 0);
        let report = capture.tick_with(&mut io).unwrap();
        let Route::Joined(new) = report.calls().next().unwrap().route() else {
            panic!("new epoch joins")
        };
        assert_ne!(new, old);
        let retired = report
            .outcomes()
            .iter()
            .find_map(|outcome| match outcome {
                TickOutcome::Invalidation(change) => match change.scope() {
                    InvalidationScope::InstancesRetired {
                        image,
                        file_slot,
                        ids,
                    } => Some((*image, *file_slot, ids)),
                    _ => None,
                },
                _ => None,
            })
            .expect("exact previous partitions retired");
        assert_eq!(
            retired.0,
            ImageIdentity {
                task_cookie: 1,
                exec_id: 1
            }
        );
        assert_eq!(retired.1, 0);
        assert_eq!(retired.2, &vec![old]);
        assert!(!retired.2.contains(&new));
        assert!(matches!(report.outcomes()[0], TickOutcome::Invalidation(_)));
        // Delivery after the boundary can still be a historical native call;
        // the explicit ended ID prevents consumers treating it as current.
        io.local = 0;
        io.call(1, 0);
        assert_eq!(
            capture
                .tick_with(&mut io)
                .unwrap()
                .calls()
                .next()
                .unwrap()
                .route(),
            Route::Joined(old)
        );
    }
    #[test]
    fn observation_eviction_emits_exact_old_ids_as_typed_loss() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        capture.router = InstanceRouter::new(
            io.domain,
            RouterLimits {
                observed_keys: 1,
                ..Default::default()
            },
        );
        let Route::Joined(old) = prime(&mut capture, &mut io) else {
            unreachable!()
        };
        io.call(2, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert!(
            report
                .calls()
                .any(|r| matches!(r.route(), Route::Joined(id) if id != old))
        );
        assert!(
            report
                .outcomes()
                .iter()
                .any(|o| matches!(o, TickOutcome::Invalidation(change)
                if matches!(change.scope(), InvalidationScope::InstancesRetired { image, ids, .. }
                    if image.task_cookie == 1 && ids == &vec![old])))
        );
    }

    mod successor_controls {
        use super::*;
        #[test]
        fn same_original_pin_cross_cookie_successor_retires_images_once() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            io.call_image(1, 1_000_000, 0);
            let first = capture.tick_with(&mut io).unwrap();
            let Route::Joined(old) = first.calls().next().unwrap().route() else {
                panic!("old nonempty positive")
            };
            io.local = 1;
            io.fail_cookie = Some(1);
            io.call_image(1, 1_000_000, 0);
            assert!(capture.tick_with(&mut io).unwrap().calls().next().is_none());
            io.local = 0;
            io.call_image(2, 0, 0);
            let report = capture.tick_with(&mut io).unwrap();
            let images: Vec<_> = report
                .outcomes()
                .iter()
                .filter_map(|outcome| match outcome {
                    TickOutcome::Invalidation(i) => match i.scope() {
                        InvalidationScope::ImageRetired(image) => Some(*image),
                        _ => None,
                    },
                    _ => None,
                })
                .collect();
            assert_eq!(
                images,
                vec![ImageIdentity {
                    task_cookie: 1,
                    exec_id: 1_000_000
                }]
            );
            assert!(report.calls().any(|call| call.image().task_cookie == 1
                && call.route() == Route::Unknown(UnknownReason::Retired)));
            assert!(report.calls().any(|call| call.image().task_cookie == 2
                && matches!(call.route(), Route::Joined(id) if id != old)));
            assert!(
                report
                    .outcomes()
                    .iter()
                    .all(|outcome| !matches!(outcome, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::TaskRetired(_))))
            );
            assert_eq!(capture.bindings.len(), 2);
            assert!(Arc::ptr_eq(
                &capture.bindings[&1].pin,
                &capture.bindings[&2].pin
            ));
            io.call_image(2, 0, 0);
            let again = capture.tick_with(&mut io).unwrap();
            assert!(
                again
                    .calls()
                    .any(|call| matches!(call.route(), Route::Joined(_)))
            );
            assert!(
                again
                    .outcomes()
                    .iter()
                    .all(|outcome| !matches!(outcome, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::ImageRetired(_))))
            );
        }
        #[test]
        fn same_cookie_forward_exec_never_rolls_back_to_an_old_proof() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            io.call_image(1, 2, 0);
            assert!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .any(|r| matches!(r.route(), Route::Joined(_)))
            );
            io.call_image(1, 3, 0);
            let forward = capture.tick_with(&mut io).unwrap();
            assert!(forward.outcomes().iter().any(|o| matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::ImageRetired(image) if image.exec_id == 2))));
            assert_eq!(capture.bindings.len(), 1);
            assert_eq!(capture.bindings[&1].image.exec_id, 3);
            io.local = 1;
            io.call_image(1, 2, 0);
            let old = capture.tick_with(&mut io).unwrap();
            assert!(!old.calls().any(|r| matches!(r.route(), Route::Joined(_))));
            assert_eq!(capture.bindings[&1].image.exec_id, 3);
            assert!(old.outcomes().iter().all(|o| !matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::ImageRetired(image) if image.exec_id == 3))));
        }
        #[test]
        fn equal_pid_different_arc_cannot_retire_another_cookie_binding() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            prime(&mut capture, &mut io);
            let original = io.pin.clone();
            io.pin = Arc::new(PidPin::open(original.pid()).unwrap());
            assert!(!Arc::ptr_eq(&original, &io.pin));
            io.call_image(2, 0, 0);
            let report = capture.tick_with(&mut io).unwrap();
            assert!(report.outcomes().iter().all(|o| !matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::ImageRetired(_) | InvalidationScope::TaskRetired(_)))));
            assert!(Arc::ptr_eq(&capture.bindings[&1].pin, &original));
            assert_eq!(
                capture.bindings[&1].image,
                ImageIdentity {
                    task_cookie: 1,
                    exec_id: 1
                }
            );
        }
        #[test]
        fn ready_aliases_consume_only_the_terminal_association_quota() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let (mut child, pin) = ChildGuard::spawn();
            io.pin = pin;
            let mut capture = capture(&io);
            capture.limits.terminal_reads = 1;
            io.call_image(1, 8, 0);
            assert!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .any(|r| matches!(r.route(), Route::Joined(_)))
            );
            io.call_image(2, 0, 0);
            assert!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .any(|r| matches!(r.route(), Route::Joined(_)))
            );
            assert_eq!(capture.bindings.len(), 2);
            child.end();
            let first = capture.tick_with(&mut io).unwrap();
            assert_eq!(
                first
                    .outcomes()
                    .iter()
                    .filter(|o| matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::TaskRetired(_))))
                    .count(),
                1
            );
            assert_eq!(capture.bindings.len(), 1);
            let second = capture.tick_with(&mut io).unwrap();
            assert_eq!(
                second
                    .outcomes()
                    .iter()
                    .filter(|o| matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::TaskRetired(_))))
                    .count(),
                1
            );
            assert!(capture.bindings.is_empty());
            io.pin = Arc::new(PidPin::open(std::process::id()).unwrap());
            io.last_health.fault = 1;
            io.call_image(1, 99, 1);
            io.call_image(2, 99, 1);
            let old = capture.tick_with(&mut io).unwrap();
            assert_eq!(old.calls().count(), 2);
            assert!(
                old.calls()
                    .all(|r| r.route() == Route::Unknown(UnknownReason::Retired))
            );
        }
        #[test]
        fn failed_postscan_health_cannot_promote_or_retire_a_binding() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            prime(&mut capture, &mut io);
            io.health.extend([
                Ok(Health {
                    fault: 0,
                    sticky: 0,
                }),
                Err(()),
            ]);
            io.call_image(2, 0, 0);
            let report = capture.tick_with(&mut io).unwrap();
            assert_eq!(capture.bindings.len(), 1);
            assert_eq!(
                capture.bindings[&1].image,
                ImageIdentity {
                    task_cookie: 1,
                    exec_id: 1
                }
            );
            assert!(
                report
                    .calls()
                    .all(|r| r.route() == Route::Unknown(UnknownReason::CoverageFault))
            );
            assert!(report.outcomes().iter().all(|o| !matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::ImageRetired(_) | InvalidationScope::TaskRetired(_)))));
        }
        #[test]
        fn exec_zero_is_a_nonempty_positive_identity() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            io.call_image(1, 0, 0);
            let report = capture.tick_with(&mut io).unwrap();
            assert!(
                report
                    .calls()
                    .any(|r| matches!(r.route(), Route::Joined(_)))
            );
            assert_eq!(capture.router.ranges_retained(), 2);
            assert_eq!(capture.bindings[&1].image.exec_id, 0);
        }
    }
}

mod custody_chain_tests {
    //! One custody Arc through H0 refresh, coordinator binding, tick and
    //! receipt validation: H0's `ptr_eq` gates refuse any re-duplication.
    use super::*;
    use crate::attach::BackendSelection;
    use crate::attach::Scope;
    use crate::attach::capture::{
        CaptureHealth, CapturePhase, CookieQuery, DiscoveryBatch, DomainCookie, ExecCoverage,
        ExtendReceipt, ScopeCustody, WitnessBatch, WitnessRow,
    };
    use crate::discovery::caller_registry::{
        AdmissionState, CallerId, ImageAuthority, ModuleInfo, ModuleKey, OsProcessSource,
        RegistryLimits, now_ns,
    };
    use crate::discovery::engine::inventory_coordinator::{InventoryCoordinator, NativeBatch};
    use crate::discovery::hooks::HookRegistry;
    use crate::discovery::inventory_attach_set::{AttachObjectId, EndpointId};
    use crate::discovery::native_binding::NativeIdentity;
    use crate::inventory_semantics::{
        AttestedSemanticLane, LaneDrainOutcome, LaneTestIo, RefreshReceiptStash, SemanticBatch,
        SemanticRefusal, effective_refresh_custody, merge_stash_into_report, stash_refresh_report,
    };
    use std::collections::HashMap;

    mod semantic_validation;

    #[derive(Default)]
    struct ChainIdentity {
        answers: HashMap<(u32, NativeDomainId), CookieQuery>,
    }

    impl NativeIdentity<PidPin> for ChainIdentity {
        fn owner_image(&mut self, _pid: u32) -> Option<ImageIdentity> {
            None
        }

        fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
            self.answers
                .get(&(pin.pid(), domain))
                .cloned()
                .unwrap_or(CookieQuery::NoCookie)
        }
    }

    std::thread_local! {
        static SIGHT_NS: std::cell::Cell<u64> = const { std::cell::Cell::new(1_005) };
    }

    fn sight_clock() -> Option<u64> {
        SIGHT_NS.with(|clock| Some(clock.get()))
    }

    struct CustodyScene {
        coordinator: InventoryCoordinator<OsProcessSource>,
        identity: ChainIdentity,
        detailed: NativeDomainId,
        module: ModuleKey,
    }

    impl CustodyScene {
        fn new() -> Self {
            let mut coordinator = InventoryCoordinator::new(
                Scope::Pid(std::process::id()),
                HookRegistry::builtin(),
                Vec::new(),
                OsProcessSource,
                RegistryLimits::default_limits(),
            )
            .unwrap();
            let detailed = NativeDomainId::mint();
            coordinator.note_extend_receipt(&ExtendReceipt {
                activated_roots: true,
                exec_coverage: Some(ExecCoverage::scripted(detailed, 0)),
                ..ExtendReceipt::default()
            });
            coordinator.set_semantic_binding_clock(sight_clock);
            let pins = operation_pins();
            let pin = pins.pinned().next().unwrap();
            let module = ModuleKey::physical(
                pin.key.device.major,
                pin.key.device.minor,
                pin.key.inode,
                Some(pin.sha256.to_owned()),
                pin.path,
            );
            Self {
                coordinator,
                identity: ChainIdentity::default(),
                detailed,
                module,
            }
        }

        fn admit(&mut self, pid: u32, at_ns: u64) -> CallerId {
            self.coordinator
                .adapter_mut()
                .admit(pid, ImageAuthority::ScanPinned, at_ns)
                .unwrap()
        }

        fn map(&mut self, caller: CallerId, pid: u32, at_ns: u64) {
            let info = ModuleInfo {
                path: "/task3/provider.so".into(),
                key: self.module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("task3".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(1),
                admission_reasons: Vec::new(),
            };
            self.coordinator
                .registry_mut()
                .note_mapping(caller, pid, info, at_ns);
            self.coordinator.commit_batch(false).unwrap();
        }

        fn answer(&mut self, pid: u32, domain: NativeDomainId, ticket: u64) {
            self.identity.answers.insert(
                (pid, domain),
                CookieQuery::Cookie(DomainCookie::scripted(domain, ticket)),
            );
        }

        fn witness_read(&mut self, domain: NativeDomainId, rows: Vec<WitnessRow>, at_ns: u64) {
            let batch = WitnessBatch {
                domain,
                phase: CapturePhase::Active,
                rows,
                integrity: Vec::new(),
                integrity_total: 0,
                visited: 0,
                sweep_completed: true,
                sweeps_completed: 1,
                row_bound_reached: false,
                deadline_reached: false,
                read_failures: Vec::new(),
                unrecorded_rows: 0,
                sweep_gaps: false,
                counts: Vec::new(),
                refresh_sweep_completed: true,
                refresh_sweep_gaps: false,
                refresh_deadline_reached: false,
                refresh_sweeps_completed: 1,
                seen_rows: 0,
                pair_limit: 65_536,
                health: CaptureHealth {
                    discovery_counters: Some([0; 5]),
                    ..CaptureHealth::default()
                },
                health_regression: None,
                health_unproven: None,
                health_baseline_ns: 0,
                health_read_ns: at_ns,
                rows_anchor_ns: at_ns + 1,
                rows_read_ns: at_ns + 1,
                counts_read_ns: at_ns + 1,
                changed_objects: Vec::new(),
                custody: ScopeCustody::System,
                custody_proven_ns: None,
                lifecycle_proven_ns: u64::MAX,
                lifecycle_loss: None,
                unsettled: false,
            };
            self.coordinator.stage_native(
                NativeBatch::Witness(Box::new(batch)),
                &mut self.identity,
                at_ns + 2,
            );
        }

        fn drain(&mut self, domain: NativeDomainId, at_ns: u64) {
            let batch = DiscoveryBatch::scripted(domain, Vec::new(), at_ns);
            self.coordinator.stage_native(
                NativeBatch::Lifecycle(batch),
                &mut self.identity,
                at_ns + 1,
            );
        }

        fn bind_image(
            &mut self,
            domain: NativeDomainId,
            rows: Vec<(u64, u64, u32, u64)>,
            at_ns: u64,
        ) {
            let rows = rows
                .into_iter()
                .map(|(ticket, exec, tgid, t0)| {
                    WitnessRow::scripted(
                        domain,
                        ticket,
                        exec,
                        AttachObjectId::scripted(0),
                        EndpointId(0),
                        tgid,
                        t0,
                    )
                })
                .collect();
            self.witness_read(domain, rows, at_ns);
            self.drain(domain, at_ns + 10);
            self.witness_read(domain, Vec::new(), at_ns + 20);
            self.coordinator.commit_batch(false).unwrap();
        }
    }

    fn operation_pins() -> crate::discovery::identity::PinnedObjects {
        static PINS: std::sync::OnceLock<
            std::sync::Mutex<crate::discovery::identity::PinnedObjects>,
        > = std::sync::OnceLock::new();
        PINS.get_or_init(|| {
            std::sync::Mutex::new({
                use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
                let path = std::env::current_exe().unwrap();
                let file = open_object(&path).unwrap();
                let inspected = inspect_file(&file).unwrap();
                let mapping = mapping_file_key(&file).unwrap();
                let key = p11scope_manifest::maps::ObjectKey {
                    device: p11scope_manifest::maps::Device {
                        major: mapping.device_major,
                        minor: mapping.device_minor,
                    },
                    inode: mapping.inode,
                };
                crate::discovery::identity::test_fixture::real_scan_pin(
                    &path,
                    Some(key),
                    mapping.mount_id,
                    inspected.identity.sha256.as_deref().unwrap(),
                )
            })
        })
        .lock()
        .unwrap()
        .clone()
    }

    /// Scripted descriptors over a real held file, aligned
    /// to `ScriptIo::endpoint` so real routed Init/Sign calls convert.
    fn operation_subset()
    -> crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset {
        use crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset;
        use crate::discovery::identity::PinnedObjectId;
        let slot = |index: u32, name: &str, offset: u64| crate::plan::Slot {
            index,
            descriptor_index: crate::kinds::function_id(name).unwrap() + 1,
            object: PinnedObjectId(0),
            object_path: "/operation-probe.so".into(),
            file_offset: offset,
            names: vec![name.into()],
            aliased: false,
            semantics: crate::kinds::descriptor(name).unwrap(),
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: true,
            module_ids: vec![crate::plan::ModuleId(0)],
        };
        let plan = crate::plan::AttachPlan::from_slots(vec![
            slot(0, "C_SignInit", 0x1200),
            slot(1, "C_Sign", 0x1300),
        ]);
        AttestedSubset::scripted(
            plan,
            operation_pins(),
            std::collections::BTreeMap::from([(
                PinnedObjectId(0),
                std::collections::BTreeSet::from([0, 1]),
            )]),
        )
    }

    /// H0 engagement observed through substituted lane I/O:
    /// serviced tick count, deepest `awaiting` occupancy on any
    /// tick, cumulative scan file attempts, and cumulative
    /// FaultEra-routed calls. Shared by handle so a drain test
    /// can prove its fault setup engaged after the lane owns the
    /// I/O. Scalar folds, never per-tick vectors: the instrument
    /// allocates nothing run-length-dependent inside a measured
    /// drain, so prompt-drain no-accumulation equalities still
    /// compare the drain, not the instrument. Recording only; H0
    /// decisions never read it.
    #[derive(Default)]
    struct H0Engagement {
        ticks: usize,
        awaiting_max: usize,
        attempted_files: Vec<u32>,
        faultera_total: usize,
        events_consumer: usize,
        discovery_consumer: usize,
    }

    /// Tests-only substituted H0 I/O behind a lane: the real H0
    /// decisions (refresh/tick/validate/stop) through `ScriptIo`,
    /// with the production stash/merge/batch helpers. Installed
    /// into a shell lane so tests drive the production
    /// stage→finalize→commit path without a live Session.
    struct H0TestIo {
        capture: SemanticCapture,
        io: ScriptIo,
        discovery: Option<crate::events::DiscoveryDrain<crate::events::ScriptedRecords>>,
        stash: RefreshReceiptStash,
        engagement: std::rc::Rc<std::cell::RefCell<H0Engagement>>,
        attempted_drained: usize,
        last_refresh_deadline: Option<Instant>,
        /// Clock advance applied at the start of every tick:
        /// quiescence tests age receipts per serviced quantum.
        tick_advance: Duration,
        /// Merge/stash shed disclosed while driving (the lane owns
        /// this counter in production).
        shed: u64,
        /// Serviced quanta after which the substituted producer
        /// quiesces; each tick counts one.
        quiesce_after: usize,
        serviced: usize,
    }

    impl H0TestIo {
        fn new(domain: NativeDomainId) -> Self {
            let io = ScriptIo::new(domain);
            let capture = capture(&io);
            Self {
                capture,
                io,
                discovery: None,
                stash: RefreshReceiptStash::new(),
                engagement: std::rc::Rc::new(std::cell::RefCell::new(H0Engagement::default())),
                attempted_drained: 0,
                last_refresh_deadline: None,
                tick_advance: Duration::ZERO,
                shed: 0,
                quiesce_after: 0,
                serviced: 0,
            }
        }
    }

    impl LaneTestIo for H0TestIo {
        fn service_live_discovery(&mut self) {
            use crate::events::BoundedRecordSource;
            if let Some(discovery) = self.discovery.as_mut() {
                self.capture
                    .service_live_discovery_with(|| Ok(discovery.dequeue()));
                self.engagement.borrow_mut().discovery_consumer = discovery.source().consumer();
            }
        }

        fn validate_current(
            &mut self,
            receipt: &CurrentPartitionReceipt,
            report: &mut TickReport,
        ) -> Result<(), CurrentReceiptRefusal> {
            self.capture
                .validate_current_with(&mut self.io, receipt, report)
        }

        fn tick(&mut self, domain: NativeDomainId) -> Result<SemanticBatch, SemanticRefusal> {
            self.io.now += self.tick_advance;
            self.serviced += 1;
            let mut report = self
                .capture
                .tick_with(&mut self.io)
                .map_err(|_| SemanticRefusal::Unavailable)?;
            {
                let mut engagement = self.engagement.borrow_mut();
                engagement.ticks += 1;
                if let Some(drain) = self.io.event_drain.as_ref() {
                    use crate::events::BoundedRecordSource;
                    engagement.events_consumer = drain.source().consumer();
                }
                engagement.awaiting_max = engagement.awaiting_max.max(self.capture.awaiting.len());
                engagement.attempted_files.extend(
                    self.io.attempted_files[self.attempted_drained..]
                        .iter()
                        .copied(),
                );
                self.attempted_drained = self.io.attempted_files.len();
                engagement.faultera_total += report
                    .calls()
                    .filter(|call| call.route() == Route::Unknown(UnknownReason::FaultEra))
                    .count();
            }
            self.shed = self
                .shed
                .saturating_add(merge_stash_into_report(&mut self.stash, &mut report));
            SemanticBatch::from_tick_report(domain, report, Vec::new(), now_ns())
        }

        fn refresh(
            &mut self,
            pin: Arc<PidPin>,
            slot: u32,
        ) -> Result<(Vec<ImageIdentity>, Arc<PidPin>), SemanticRefusal> {
            let mut report = self
                .capture
                .refresh_with(&mut self.io, pin.clone(), slot)
                .map_err(|_| SemanticRefusal::Unavailable)?;
            self.last_refresh_deadline = report.current().first().map(|receipt| receipt.deadline);
            let effective = effective_refresh_custody(&report, pin);
            let (images, shed) = stash_refresh_report(&mut self.stash, &mut report);
            self.shed = self.shed.saturating_add(shed);
            Ok((images, effective))
        }

        fn has_pending_evidence(&self) -> bool {
            !self.stash.is_empty()
        }

        fn finish(&mut self, domain: NativeDomainId) -> SemanticBatch {
            let report = self.capture.stop();
            SemanticBatch::from_tick_report(domain, report, Vec::new(), now_ns())
                .expect("H0 stop batches respect lane bounds")
        }

        fn quiescent(&mut self) -> bool {
            self.serviced >= self.quiesce_after
        }

        fn positions(&mut self) -> Option<[(usize, usize); 2]> {
            Some([(0, 0), (0, 0)])
        }

        fn drain_events_to(&mut self, _stop: usize, _quantum: usize) -> LaneDrainOutcome {
            LaneDrainOutcome::default()
        }

        fn drain_discovery_to(&mut self, _stop: usize, _quantum: usize) -> LaneDrainOutcome {
            LaneDrainOutcome::default()
        }
    }

    /// A coordinator scene bound to a lane's own domain: the bind
    /// proof runs in the lane's domain exactly as in production, so
    /// the lane's receipts finalize against the stored binding.
    struct LaneScene {
        scene: CustodyScene,
        lane: AttestedSemanticLane,
    }

    fn bound_lane_scene(image: ImageIdentity) -> LaneScene {
        let lane = AttestedSemanticLane::start(
            operation_subset(),
            &Scope::Pid(std::process::id()),
            BackendSelection::Auto,
        )
        .expect("shell lane starts");
        let domain = lane.domain();
        let mut scene = CustodyScene::new();
        scene.coordinator.note_extend_receipt(&ExtendReceipt {
            activated_roots: true,
            exec_coverage: Some(ExecCoverage::scripted(domain, 0)),
            ..ExtendReceipt::default()
        });
        let pid = std::process::id();
        let caller = scene.admit(pid, 50);
        scene.map(caller, pid, 60);
        scene.answer(pid, domain, image.task_cookie);
        scene.bind_image(
            domain,
            vec![(image.task_cookie, image.exec_id, pid, 100)],
            1_000,
        );
        let pin = Arc::new(
            scene
                .coordinator
                .adapter()
                .live_pin(pid)
                .and_then(|(_, pin)| pin.try_clone().ok())
                .unwrap(),
        );
        scene
            .coordinator
            .bind_semantic_caller_with_pin(
                caller,
                scene.module.clone(),
                domain,
                image,
                &mut scene.identity,
                pin,
            )
            .unwrap();
        LaneScene { scene, lane }
    }

    type HeldBatchFingerprint = (
        NativeDomainId,
        u64,
        usize,
        Vec<(Option<u64>, String, Vec<u8>)>,
        Vec<usize>,
    );

    fn held_batch_fingerprint(batch: &SemanticBatch) -> HeldBatchFingerprint {
        (
            batch.domain(),
            batch.observed_ns(),
            batch.outcomes().as_ptr() as usize,
            batch
                .outcomes()
                .iter()
                .map(|outcome| {
                    let record = match outcome {
                        TickOutcome::Call(call) => crate::events::record_bytes(call.record()),
                        TickOutcome::Other(other) => crate::events::record_bytes(other.record()),
                        TickOutcome::Invalidation(_) => Vec::new(),
                    };
                    (outcome.position(), format!("{outcome:?}"), record)
                })
                .collect(),
            batch
                .current_receipts()
                .iter()
                .map(|receipt| Arc::as_ptr(receipt.original_pin()) as usize)
                .collect(),
        )
    }

    fn discovery_records(
        count: usize,
    ) -> crate::events::DiscoveryDrain<crate::events::ScriptedRecords> {
        let mut record: p11scope_ebpf_common::DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = p11scope_ebpf_common::DISCOVERY_KIND_EXEC;
        record.pid_tgid = (7u64 << 32) | 7;
        record.hook_ts_ns = 1;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&record as *const p11scope_ebpf_common::DiscoveryRecord).cast::<u8>(),
                std::mem::size_of_val(&record),
            )
        }
        .to_vec();
        crate::events::DiscoveryDrain::over(crate::events::ScriptedRecords::records(
            vec![bytes; count],
            count,
        ))
    }

    fn discovery_service_while_batch_is_staged(positive: bool) {
        let image = ImageIdentity {
            task_cookie: 7,
            exec_id: 1,
        };
        let mut fixture = bound_lane_scene(image);
        let domain = fixture.lane.domain();
        let mut h0 = H0TestIo::new(domain);
        h0.capture.limits.records = 1;
        h0.io.output_image = Some(image);
        h0.discovery = Some(discovery_records(600));
        if positive {
            let pin = fixture
                .scene
                .coordinator
                .semantic_bindings()
                .find_by_image(domain, image)
                .unwrap()
                .pin();
            h0.refresh(pin, 0).unwrap();
            h0.io.call_image(7, 1, 0);
            h0.io.call_image(7, 1, 0);
            // Keep the original positive quantum in the production staged slot.
            crate::inventory::fail_next_classic_commit_for_test("retain original positive batch");
        }
        retain_scripted_event_cursor(&mut h0.io);
        let engagement = h0.engagement.clone();
        fixture.lane.install_test_io(Box::new(h0));
        let mut first = None;
        let mut first_consumer = 0;
        let mut ticks = 0;
        fixture.lane = crate::inventory::classic_semantic_ticks_for_test(
            &mut fixture.scene.coordinator,
            fixture.lane,
            2,
            |coordinator, _, staged| {
                assert!(staged, "the original quantum stays staged");
                let batch = coordinator
                    .pending_semantic_batch_for_test()
                    .expect("the actual original collected batch remains owned");
                let fingerprint = held_batch_fingerprint(batch);
                assert_eq!(batch.is_empty(), !positive);
                if positive {
                    assert!(batch.outcomes().iter().any(|outcome| matches!(
                        outcome, TickOutcome::Call(call) if matches!(call.route(), Route::Joined(_))
                    )));
                }
                let observed = engagement.borrow();
                assert_eq!(
                    observed.ticks, 1,
                    "held publication forbids another EVENTS collection"
                );
                assert_eq!(observed.events_consumer, if positive { 8 } else { 0 });
                if let Some(first) = first.as_ref() {
                    assert_eq!(
                        &fingerprint, first,
                        "same positions, records, receipts and allocation"
                    );
                    assert_eq!(
                        observed.discovery_consumer,
                        first_consumer + 2048,
                        "the held-batch hook services another bounded256 discovery records"
                    );
                } else {
                    first = Some(fingerprint);
                    first_consumer = observed.discovery_consumer;
                }
                ticks += 1;
            },
        );
        assert_eq!(ticks, 2);
        fixture
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut fixture.lane))
            .unwrap();
        let returns: u64 = fixture
            .scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .filter_map(|row| row.api_returns)
            .sum();
        assert_eq!(
            returns,
            u64::from(positive),
            "the original call publishes exactly once"
        );
        assert!(
            fixture
                .scene
                .coordinator
                .pending_semantic_batch_for_test()
                .is_none()
        );
    }

    #[test]
    fn live_discovery_progresses_while_positive_batch_is_staged() {
        discovery_service_while_batch_is_staged(true);
    }

    #[test]
    fn live_discovery_progresses_while_empty_batch_is_staged() {
        discovery_service_while_batch_is_staged(false);
    }

    #[test]
    fn live_discovery_service_keeps_joint_gated_and_finished_readers_owned() {
        for state in ["joint", "gated", "finished"] {
            let mut fixture = bound_lane_scene(ImageIdentity {
                task_cookie: 7,
                exec_id: 1,
            });
            let mut h0 = H0TestIo::new(fixture.lane.domain());
            h0.discovery = Some(discovery_records(1));
            h0.io.call_image(7, 1, 0);
            retain_scripted_event_cursor(&mut h0.io);
            let engagement = h0.engagement.clone();
            fixture.lane.install_test_io(Box::new(h0));
            match state {
                "joint" => fixture.lane.set_test_joint_machine(true),
                "gated" => fixture.lane.request_semantic_stop(),
                "finished" => {
                    assert!(fixture.lane.finish_semantic_stop().is_some());
                }
                _ => unreachable!(),
            }
            fixture.lane.service_live_discovery();
            let observed = engagement.borrow();
            assert_eq!(observed.discovery_consumer, 0, "{state}");
            assert_eq!(observed.events_consumer, 0, "{state}");
            assert_eq!(observed.ticks, 0, "{state}");
        }
    }

    /// Published semantic edge rows: (api returns, historical-only
    /// returns, lossy, started, completed).
    fn operation_edge_rows(scene: &CustodyScene) -> Vec<(Option<u64>, u64, bool, u64, u64)> {
        scene
            .coordinator
            .registry()
            .instance_semantic_edges()
            .map(|row| {
                let started = row.semantics.as_ref().map(|s| s.started()).unwrap_or(0);
                let completed = row.semantics.as_ref().map(|s| s.completed()).unwrap_or(0);
                (
                    row.api_returns,
                    row.historical_only_returns,
                    row.lossy,
                    started,
                    completed,
                )
            })
            .collect()
    }

    #[test]
    fn refresh_bind_tick_validate_share_one_custody_arc() {
        let mut scene = CustodyScene::new();
        let pid = std::process::id();
        let caller = scene.admit(pid, 50);
        scene.map(caller, pid, 60);
        let detailed = scene.detailed;
        let module = scene.module.clone();
        let image = ImageIdentity {
            task_cookie: 7,
            exec_id: 1,
        };
        scene.answer(pid, detailed, 7);
        scene.bind_image(detailed, vec![(7, 1, pid, 100)], 1_000);
        // The production refresh pin: one duplication off the live pin,
        // given to H0's refresh (inventory/mod.rs `bind_semantic_callers`).
        let pin: Arc<PidPin> = Arc::new(
            scene
                .coordinator
                .adapter()
                .live_pin(pid)
                .and_then(|(_, pin)| pin.try_clone().ok())
                .unwrap(),
        );
        // H0 serves this pin's targets through the same Arc.
        let mut io = ScriptIo::new(NativeDomainId::mint());
        io.pin = pin.clone();
        let mut capture = capture(&io);
        let refresh = capture.refresh_with(&mut io, pin.clone(), 0).unwrap();
        assert_eq!(
            refresh.current().len(),
            1,
            "the accepted refresh scan mints one receipt"
        );
        let refreshed = refresh.current()[0].original_pin().clone();
        assert!(
            Arc::ptr_eq(&refreshed, &pin),
            "H0 retains the exact refresh Arc"
        );
        // The binding stores the passed Arc, never a re-duplication.
        scene
            .coordinator
            .bind_semantic_caller_with_pin(
                caller,
                module,
                detailed,
                image,
                &mut scene.identity,
                pin.clone(),
            )
            .unwrap();
        let bound = scene
            .coordinator
            .semantic_bindings()
            .get(caller)
            .unwrap()
            .pin();
        assert!(
            Arc::ptr_eq(&bound, &pin),
            "the stored binding shares the refresh Arc"
        );
        // The refresh receipt validates through the retained Arc.
        let mut scratch = TickReport::default();
        assert_eq!(
            capture.validate_current_with(&mut io, &refresh.current()[0], &mut scratch),
            Ok(())
        );
        // A fresh-image tick scans through the binding pin: the minted
        // receipt shares it and validates.
        io.call_image(2, 1, 0);
        let tick = capture.tick_with(&mut io).unwrap();
        assert!(
            tick.calls()
                .any(|call| matches!(call.route(), crate::discovery::instances::Route::Joined(_))),
            "the tick serves the fresh image"
        );
        assert_eq!(tick.current().len(), 1);
        assert!(
            Arc::ptr_eq(tick.current()[0].original_pin(), &bound),
            "the tick receipt shares the binding Arc"
        );
        assert_eq!(
            capture.validate_current_with(&mut io, &tick.current()[0], &mut scratch),
            Ok(())
        );
    }

    #[test]
    fn failed_bind_retry_reuses_h0_retained_arc_through_production_loop() {
        let mut lane = AttestedSemanticLane::start(
            operation_subset(),
            &Scope::Pid(std::process::id()),
            BackendSelection::Auto,
        )
        .expect("shell lane starts");
        let domain = lane.domain();
        let mut scene = CustodyScene::new();
        scene.coordinator.note_extend_receipt(&ExtendReceipt {
            activated_roots: true,
            exec_coverage: Some(ExecCoverage::scripted(domain, 0)),
            ..ExtendReceipt::default()
        });
        let pid = std::process::id();
        let caller = scene.admit(pid, 50);
        scene.map(caller, pid, 60);
        let module = scene.module.clone();
        let image = ImageIdentity {
            task_cookie: 7,
            exec_id: 1,
        };
        // H0 shares the bind domain exactly as a live lane would;
        // the scan proves the same image the coordinator proof
        // expects.
        let mut h0 = H0TestIo::new(domain);
        h0.io.output_image = Some(image);
        lane.install_test_io(Box::new(h0));
        let targets = vec![(caller, pid, 0u32, module)];
        let mut passed: Vec<Arc<PidPin>> = Vec::new();
        let mut minted: Vec<(Vec<ImageIdentity>, Arc<PidPin>)> = Vec::new();
        // The production bind loop over the lane's own refresh: the
        // refresh closure records each pass's offered pin and the
        // images plus effective custody Arc the lane reports.
        macro_rules! drive_pass {
            () => {{
                let mut refresh = |pin: Arc<PidPin>, slot: u32| {
                    passed.push(pin.clone());
                    let report = lane.refresh_candidate_with_custody(pin, slot)?;
                    minted.push((report.0.clone(), report.1.clone()));
                    Ok(report)
                };
                crate::inventory::bind_semantic_candidates(
                    &mut scene.coordinator,
                    domain,
                    &mut scene.identity,
                    &targets,
                    &mut refresh,
                );
            }};
        }
        // Pass N: the refresh accepts (H0 retains Arc A) but the
        // coordinator proof refuses without identity evidence.
        drive_pass!();
        assert!(
            scene.coordinator.semantic_bindings().get(caller).is_none(),
            "pass N binds nothing without identity evidence"
        );
        assert_eq!(passed.len(), 1);
        assert_eq!(minted[0].0, vec![image]);
        assert!(
            Arc::ptr_eq(&minted[0].1, &passed[0]),
            "H0 retains the exact pass-N refresh Arc"
        );
        // Pass N+1: identity evidence arrives; the retry duplicates
        // a fresh Arc B but must bind through H0's retained Arc A.
        scene.answer(pid, domain, 7);
        scene.bind_image(domain, vec![(7, 1, pid, 100)], 1_000);
        drive_pass!();
        assert_eq!(passed.len(), 2);
        assert!(
            !Arc::ptr_eq(&passed[0], &passed[1]),
            "each pass duplicates its pin fresh: the retry really offers Arc B"
        );
        assert_eq!(minted.len(), 2);
        assert_eq!(minted[1].0, vec![image]);
        assert!(
            Arc::ptr_eq(&minted[1].1, &passed[0]),
            "the retry receipt carries the retained Arc"
        );
        let bound = scene
            .coordinator
            .semantic_bindings()
            .get(caller)
            .expect("the retry binds after an accepted-refresh/failed-bind pass")
            .pin();
        assert!(
            Arc::ptr_eq(&bound, &passed[0]),
            "the retry binding shares H0's retained Arc A, not the fresh duplicate"
        );
        // The retry receipt finalizes through the lane: the next
        // tick stages the stashed retry proof and the commit
        // registers it against the retained Arc.
        let batch = {
            let bindings = scene
                .coordinator
                .semantic_bindings_mut()
                .bindings_for_tick();
            lane.tick(bindings).unwrap()
        };
        assert!(
            !batch.is_empty(),
            "the tick batch carries the stashed retry proof"
        );
        scene.coordinator.stage_semantic_batch(batch);
        scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        let gaps: Vec<(String, String)> = scene
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect();
        assert!(
            !gaps.iter().any(|gap| gap.0 == "semantic receipt refused"),
            "the retry proof validates through the retained Arc: {gaps:?}"
        );
        assert_eq!(
            scene.coordinator.registry().instances().count(),
            1,
            "the retry receipt registers one instance at commit"
        );
    }

    /// Stash overflow preserves the fault-era invalidation: with
    /// 1024 pending calls, the next audit emits the FaultEra
    /// invalidation first and resolves all 1024 calls behind it, so
    /// the refresh report holds 1025 outcomes against the 1024-item
    /// stash. The shed outcome must be a call, never the
    /// invalidation: the merged batch finalizes the exact
    /// H0-minted loss boundary through the production commit.
    #[test]
    fn stash_overflow_preserves_fault_era_invalidation_at_1024_pending() {
        let image = ImageIdentity {
            task_cookie: 7,
            exec_id: 1,
        };
        let mut fixture = bound_lane_scene(image);
        let domain = fixture.lane.domain();
        let mut h0 = H0TestIo::new(domain);
        h0.io.output_image = Some(image);
        // Image 7 never scans: every record parks Pending.
        h0.io.fail_cookie = Some(image.task_cookie);
        for _ in 0..MAX_PENDING {
            h0.io.call(image.task_cookie, 0);
        }
        let parked = h0.tick(domain).unwrap();
        assert!(
            parked.is_empty(),
            "all 1024 records park pending with no scan to resolve them"
        );
        // The fault era moves: the next audit invalidates first,
        // then resolves every pending call behind it.
        h0.io.health.push_back(Ok(Health {
            fault: 1,
            sticky: 0,
        }));
        let pin: Arc<PidPin> = Arc::new(
            fixture
                .scene
                .coordinator
                .adapter()
                .live_pin(std::process::id())
                .and_then(|(_, pin)| pin.try_clone().ok())
                .unwrap(),
        );
        let (images, _effective) = h0.refresh(pin, 0).unwrap();
        assert!(images.is_empty());
        assert_eq!(
            h0.shed, 1,
            "1025 outcomes against the 1024-item stash shed exactly one"
        );
        fixture.lane.install_test_io(Box::new(h0));
        // The next lane tick merges the stashed evidence and the
        // pass commit finalizes it: H2 must see the exact
        // H0-minted FaultEra boundary, not a refusal count.
        let batch = {
            let bindings = fixture
                .scene
                .coordinator
                .semantic_bindings_mut()
                .bindings_for_tick();
            fixture.lane.tick(bindings).unwrap()
        };
        assert!(
            !batch.is_empty(),
            "the tick batch carries the stashed overflow evidence"
        );
        fixture.scene.coordinator.stage_semantic_batch(batch);
        fixture
            .scene
            .coordinator
            .commit_batch_with_semantics(false, Some(&mut fixture.lane))
            .unwrap();
        assert_eq!(
            fixture.lane.take_last_conversion_barrier(),
            Some(MAX_PENDING as u64 + 1),
            "the FaultEra invalidation survives the stash: its position fences conversion"
        );
    }

    /// Quiet registration end to end through the production lane
    /// and finalizer: a no-call refresh proves the quiet provider's
    /// partition, the proof waits the normal 1s pass schedule, the
    /// next lane tick stages it, and the pass commit finalizes it
    /// into one registration. Past the receipt window the same
    /// proof refuses through the audited path and registers
    /// nothing.
    #[test]
    fn quiet_refresh_registers_through_next_tick_batch() {
        let image = ImageIdentity {
            task_cookie: 7,
            exec_id: 1,
        };
        for buffered in [false, true] {
            let mut fixture = bound_lane_scene(image);
            let domain = fixture.lane.domain();
            let mut h0 = H0TestIo::new(domain);
            h0.io.output_image = Some(image);
            let pin: Arc<PidPin> = Arc::new(
                fixture
                    .scene
                    .coordinator
                    .adapter()
                    .live_pin(std::process::id())
                    .and_then(|(_, pin)| pin.try_clone().ok())
                    .unwrap(),
            );
            // The production refresh: one accepted no-call scan,
            // stashed for the next tick batch.
            let (images, _effective) = h0.refresh(pin, 0).unwrap();
            assert_eq!(images, vec![image]);
            assert_eq!(h0.shed, 0);
            assert!(h0.has_pending_evidence());
            // The normal pass schedule (1s) or past the receipt
            // window (3s > 2s pending): only timing differs.
            h0.io.now += Duration::from_secs(if buffered { 3 } else { 1 });
            fixture.lane.install_test_io(Box::new(h0));
            // The next tick batch through the lane, finalized by
            // the pass commit beside the physical evidence.
            let batch = {
                let bindings = fixture
                    .scene
                    .coordinator
                    .semantic_bindings_mut()
                    .bindings_for_tick();
                fixture.lane.tick(bindings).unwrap()
            };
            assert!(
                !batch.is_empty(),
                "the tick batch carries the stashed quiet proof"
            );
            fixture.scene.coordinator.stage_semantic_batch(batch);
            fixture
                .scene
                .coordinator
                .commit_batch_with_semantics(false, Some(&mut fixture.lane))
                .unwrap();
            let gaps: Vec<(String, String)> = fixture
                .scene
                .coordinator
                .registry()
                .gaps()
                .iter()
                .map(|gap| (gap.subject.clone(), gap.reason.clone()))
                .collect();
            if buffered {
                assert_eq!(
                    fixture.scene.coordinator.registry().instances().count(),
                    0,
                    "an expired proof registers nothing"
                );
                assert!(
                    gaps.contains(&(
                        "semantic receipt refused".to_string(),
                        "deadline".to_string()
                    )),
                    "the expired proof refuses through the audited path: {gaps:?}"
                );
                continue;
            }
            assert!(
                !gaps.iter().any(|gap| gap.0 == "semantic receipt refused"),
                "the fresh proof validates: {gaps:?}"
            );
            assert_eq!(
                fixture.scene.coordinator.registry().instances().count(),
                1,
                "the quiet proof registers one instance at commit"
            );
        }
    }

    /// Drive a quiet refresh receipt through ClassicDriver using
    /// H0's actual minting, stash merge and receipt validator. The
    /// original proof clock ages before the driver stages it.
    fn classic_tick_with_aged_refresh(remaining: Duration) -> CustodyScene {
        let image = ImageIdentity {
            task_cookie: 7,
            exec_id: 1,
        };
        let mut fixture = bound_lane_scene(image);
        let domain = fixture.lane.domain();
        let pin = fixture
            .scene
            .coordinator
            .semantic_bindings()
            .find_by_image(domain, image)
            .unwrap()
            .pin();
        let mut h0 = H0TestIo::new(domain);
        h0.io.output_image = Some(image);
        h0.capture.limits.pending_for = Duration::from_secs(2);
        let staged_at = Instant::now();
        h0.io.now = staged_at - (Duration::from_secs(2) - remaining);
        let (images, retained) = h0.refresh(pin.clone(), 0).unwrap();
        assert_eq!(images, vec![image]);
        assert!(Arc::ptr_eq(&retained, &pin));
        assert!(h0.has_pending_evidence());
        assert_eq!(
            h0.last_refresh_deadline
                .unwrap()
                .saturating_duration_since(staged_at),
            remaining,
            "the original H0 receipt has the selected lifetime at staging"
        );
        // Aging preserves the minted deadline: no re-proof or new
        // receipt is supplied by this no-call tick.
        h0.io.now = staged_at;
        fixture.lane.install_test_io(Box::new(h0));
        let _lane = crate::inventory::classic_semantic_tick_for_test(
            &mut fixture.scene.coordinator,
            fixture.lane,
        );
        fixture.scene
    }

    #[test]
    fn short_lived_refresh_receipt_commits_through_classic_driver() {
        for (remaining, expected_instances) in
            [(Duration::from_millis(300), 1), (Duration::ZERO, 0)]
        {
            let scene = classic_tick_with_aged_refresh(remaining);
            assert_eq!(
                scene.coordinator.registry().instances().count(),
                expected_instances,
                "original remaining={remaining:?}: registration follows real H0 validation"
            );
            let refusals: Vec<&str> = scene
                .coordinator
                .registry()
                .gaps()
                .iter()
                .filter(|gap| gap.subject == "semantic receipt refused")
                .map(|gap| gap.reason.as_str())
                .collect();
            if remaining.is_zero() {
                assert_eq!(refusals, vec!["deadline"]);
            } else {
                assert!(
                    refusals.is_empty(),
                    "fresh receipt refuses nothing: {refusals:?}"
                );
            }
        }
    }

    #[test]
    fn longer_lived_refresh_receipt_commits_through_classic_driver() {
        // Above the old 1s threshold, publication still must be
        // prompt: later tick scheduling cannot guarantee the
        // remaining original receipt window will survive.
        let scene = classic_tick_with_aged_refresh(Duration::from_millis(1_500));
        assert_eq!(scene.coordinator.registry().instances().count(), 1);
        assert!(
            scene
                .coordinator
                .registry()
                .gaps()
                .iter()
                .all(|gap| gap.subject != "semantic receipt refused")
        );
    }

    /// Terminal drain through production with real H0 receipts
    /// under delayed quiescence: Q arrives after 4 servicing
    /// quanta, each aging H0 1s (4s total, past the 2s receipt
    /// window). Every drained batch commits promptly in its own
    /// quantum through the production drain and receipt finalizer,
    /// so the drained Init/Sign pair validates fresh and completes
    /// one operation. Both orders run: a receipt minted by the
    /// drain itself, and a refresh receipt stashed before the stop
    /// (flushed by the drain's pre-flush).
    #[test]
    fn prompt_drain_commits_complete_operation_under_delayed_quiescence() {
        use crate::discovery::caller_registry::instance_input::InstanceReason;

        for prestashed in [false, true] {
            let image = ImageIdentity {
                task_cookie: 7,
                exec_id: 1,
            };
            let mut fixture = bound_lane_scene(image);
            let domain = fixture.lane.domain();
            let mut h0 = H0TestIo::new(domain);
            h0.io.output_image = Some(image);
            h0.io.semantic_call("C_SignInit", 0, 0);
            h0.io.records.back_mut().unwrap().base.event.image = image;
            h0.io.semantic_call("C_Sign", 0, 0);
            h0.io.records.back_mut().unwrap().base.event.image = image;
            if prestashed {
                // A quiet refresh proves the partition before the
                // stop; its proof waits stashed for the pre-flush.
                let pin: Arc<PidPin> = Arc::new(
                    fixture
                        .scene
                        .coordinator
                        .adapter()
                        .live_pin(std::process::id())
                        .and_then(|(_, pin)| pin.try_clone().ok())
                        .unwrap(),
                );
                let (images, _effective) = h0.refresh(pin, 0).unwrap();
                assert_eq!(images, vec![image]);
                assert!(h0.has_pending_evidence());
            }
            // Delayed quiescence: Q after 4 quanta of the 5s stop
            // budget, each quantum aging H0 1s. The 4s total passes
            // the 2s receipt window: only prompt per-quantum
            // commits validate fresh.
            assert!(
                Duration::from_secs(4) < crate::run::STOP_QUIESCE_BUDGET,
                "the delayed quiescence fits the stop budget"
            );
            h0.tick_advance = Duration::from_secs(1);
            h0.quiesce_after = 4;
            fixture.lane.install_test_io(Box::new(h0));
            let summary = fixture.lane.run_semantic_drain_committing(
                &mut fixture.scene.coordinator,
                &[],
                Instant::now,
            );
            assert!(summary.quiesced, "prestashed={prestashed}: quiesces");
            assert!(
                summary.final_drain,
                "prestashed={prestashed}: drains exactly to Q"
            );
            assert!(
                !summary.semantic_loss,
                "prestashed={prestashed}: no semantic loss"
            );
            assert_eq!(
                summary.drain_batches, 1,
                "prestashed={prestashed}: exactly the Init/Sign quantum commits"
            );
            // H0 stops once, after every drained batch published;
            // the terminal Finish batch commits separately.
            let finish = fixture.lane.finish_semantic_stop().unwrap();
            fixture.scene.coordinator.stage_semantic_batch(finish);
            fixture
                .scene
                .coordinator
                .commit_batch_with_semantics(false, Some(&mut fixture.lane))
                .unwrap();
            let gaps: Vec<(String, String)> = fixture
                .scene
                .coordinator
                .registry()
                .gaps()
                .iter()
                .map(|gap| (gap.subject.clone(), gap.reason.clone()))
                .collect();
            assert!(
                !gaps.iter().any(|gap| gap.0 == "semantic receipt refused"),
                "prestashed={prestashed}: the drained proof validates: {gaps:?}"
            );
            assert_eq!(
                operation_edge_rows(&fixture.scene),
                vec![(Some(2), 0, true, 1, 1)],
                "prestashed={prestashed}: the drained Init/Sign pair completes one operation; \
                     the terminal stop discloses lossy"
            );
            let reasons: Vec<InstanceReason> = fixture
                .scene
                .coordinator
                .registry()
                .instance_semantic_edges()
                .next()
                .unwrap()
                .reasons
                .iter()
                .copied()
                .collect();
            assert_eq!(
                reasons,
                vec![InstanceReason::SemanticLoss, InstanceReason::CaptureStopped],
                "prestashed={prestashed}: only the terminal stop fences the completed \
                     operation (boundary plus cause)"
            );
        }
    }

    /// Prompt commitment retains no batches across quanta: the SAME
    /// 2600-record population drains through the production committing
    /// drain over 4 vs 16 serviced quanta. The population mixes 2400
    /// completing file-0 Init/Sign pairs at zero fault (genuine
    /// completions, so the run is not vacuous), 100 max-stamp-fault
    /// file-0 calls (fault outcomes on the completing path), and 100
    /// max-stamp-fault file-1 calls. Stamp fault routes before scan
    /// queueing, so both fault cohorts resolve as FaultEra outcomes
    /// on the collecting ticks: nothing parks in `awaiting`, and the
    /// configured file-1 scan fault is never attempted. The
    /// engagement asserts pin this disposition (200 FaultEra routes,
    /// completing-path scans only) so the coverage claim stays
    /// honest. At the 1024-record tick limit the population
    /// commits as exactly 3 batches (1024/1024/552) in both runs;
    /// the extra 12 empty quanta retain nothing — live requested
    /// bytes, pool charges and completed operations are identical,
    /// proving serviced quanta never accumulate batches.
    #[test]
    fn prompt_drain_many_quanta_retain_no_batches() {
        struct Run {
            live_bytes: usize,
            peak_bytes: usize,
            cumulative_requested_bytes: usize,
            allocation_requests: usize,
            pool_charged_delta: usize,
            completed: u64,
        }

        let mut runs = Vec::new();
        for quanta in [4usize, 16usize] {
            let image = ImageIdentity {
                task_cookie: 7,
                exec_id: 1,
            };
            let mut fixture = bound_lane_scene(image);
            let domain = fixture.lane.domain();
            let mut h0 = H0TestIo::new(domain);
            h0.io.output_image = Some(image);
            // Held calls: file-1 scans fail, so these stay in
            // `awaiting` across every serviced quantum, at max fault.
            h0.io.fail_file = Some(1);
            for index in 0..100 {
                let name = if index % 2 == 0 {
                    "C_SignInit"
                } else {
                    "C_Sign"
                };
                h0.io.semantic_call(name, 1, u32::MAX);
                h0.io.records.back_mut().unwrap().base.event.image = image;
            }
            // Max-fault outcomes on the completing path.
            for index in 0..100 {
                let name = if index % 2 == 0 {
                    "C_SignInit"
                } else {
                    "C_Sign"
                };
                h0.io.semantic_call(name, 0, u32::MAX);
                h0.io.records.back_mut().unwrap().base.event.image = image;
            }
            // Genuine completions at zero fault: 1200 Init/Sign pairs.
            for index in 0..2400 {
                let name = if index % 2 == 0 {
                    "C_SignInit"
                } else {
                    "C_Sign"
                };
                h0.io.semantic_call(name, 0, 0);
                h0.io.records.back_mut().unwrap().base.event.image = image;
            }
            // 16 quanta age 1.6s: inside the 2s receipt window, so
            // prompt commits validate fresh in both runs.
            h0.tick_advance = Duration::from_millis(100);
            h0.quiesce_after = quanta;
            let engagement = h0.engagement.clone();
            fixture.lane.install_test_io(Box::new(h0));
            let pool_before = fixture
                .scene
                .coordinator
                .registry()
                .semantic_resource_snapshot();
            let (summary, peak, allocs, requested) = crate::test_alloc::counted_peak_during(|| {
                fixture.lane.run_semantic_drain_committing(
                    &mut fixture.scene.coordinator,
                    &[],
                    Instant::now,
                )
            });
            assert!(!peak.incomplete, "quanta={quanta}: peak tracked");
            assert!(summary.quiesced, "quanta={quanta}: quiesces");
            assert_eq!(
                summary.drain_batches, 3,
                "quanta={quanta}: 2600 records commit as 3 batches"
            );
            let pool_after = fixture
                .scene
                .coordinator
                .registry()
                .semantic_resource_snapshot();
            let rows = operation_edge_rows(&fixture.scene);
            assert_eq!(rows.len(), 1, "quanta={quanta}: one edge row");
            let started = rows[0].3;
            let completed = rows[0].4;
            assert!(
                completed > 0,
                "quanta={quanta}: genuine pairs complete; the run is not vacuous"
            );
            // Fault engagement: both max-stamp cohorts
            // fault-route through the real router (200 FaultEra
            // outcomes, all on the collecting ticks), while scans
            // run only on the completing file-0 path (one per
            // collecting tick). Stamp fault routes before scan
            // queueing, so the configured file-1 scan fault is
            // never attempted and nothing parks in `awaiting` —
            // the disposition below pins what the fault setup
            // really covers, not just what it configures.
            let engagement = engagement.borrow();
            println!(
                "H3_MEM_PROMPT_DRAIN_ENGAGEMENT {{\"quanta\": {quanta}, \
                     \"started\": {started}, \"completed\": {completed}, \
                     \"ticks\": {}, \"awaiting_max\": {}, \
                     \"attempted_files\": {:?}, \
                     \"faultera_total\": {}}}",
                engagement.ticks,
                engagement.awaiting_max,
                engagement.attempted_files,
                engagement.faultera_total,
            );
            assert_eq!(
                engagement.faultera_total, 200,
                "quanta={quanta}: both max-stamp cohorts fault-route"
            );
            assert_eq!(
                engagement.attempted_files,
                vec![0, 0, 0],
                "quanta={quanta}: scans run only on the completing path"
            );
            runs.push((
                quanta,
                Run {
                    live_bytes: peak.live_bytes,
                    peak_bytes: peak.peak_bytes,
                    cumulative_requested_bytes: requested,
                    allocation_requests: allocs,
                    pool_charged_delta: pool_after
                        .charged_bytes
                        .saturating_sub(pool_before.charged_bytes),
                    completed,
                },
            ));
        }
        let (short_quanta, short) = &runs[0];
        let (long_quanta, long) = &runs[1];
        assert_eq!(
            (long.live_bytes, long.pool_charged_delta, long.completed),
            (short.live_bytes, short.pool_charged_delta, short.completed),
            "the extra {} serviced quanta retain nothing",
            long_quanta - short_quanta
        );
        assert!(
            long.peak_bytes >= long.live_bytes
                && long.cumulative_requested_bytes >= long.peak_bytes,
            "peak labels order: cumulative >= peak >= live"
        );
        for (quanta, run) in &runs {
            println!(
                "H3_MEM_PROMPT_DRAIN {{\"quanta\": {quanta}, \
                     \"drain_batches\": 3, \
                     \"peak_live_retained_bytes\": {}, \
                     \"peak_transient_bytes\": {}, \
                     \"cumulative_requested_bytes\": {}, \
                     \"allocation_requests\": {}, \
                     \"pool_charged_delta_bytes\": {}, \
                     \"completed\": {}}}",
                run.live_bytes,
                run.peak_bytes - run.live_bytes,
                run.cumulative_requested_bytes,
                run.allocation_requests,
                run.pool_charged_delta,
                run.completed,
            );
        }
    }
}
