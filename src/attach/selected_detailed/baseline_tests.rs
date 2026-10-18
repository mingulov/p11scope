//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private binder fixtures exercise the actual decoder and charged original
//! process custody. They do not claim live kernel acquisition or activation.
use super::*;
use crate::discovery::caller_registry::RegistryLimits;
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use crate::inventory_promotion::{Promoter, ViewRevision};
use crate::semantics_edge::resources::SemanticResourcePool;

fn original(pool: &SemanticResourcePool) -> Arc<PidPin> {
    let mut pin = PidPin::open(std::process::id()).unwrap();
    let charge = crate::process::CustodyCharge::reserve::<PidPin>(&pool.reserver(), 0).unwrap();
    pin.install_shared_custody_charge(charge);
    Arc::new(pin)
}
fn frame(original: &Arc<PidPin>) -> Arc<Presentation> {
    let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
    harness.stage_scale(&ScaleSpec {
        name: "baseline-binder",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 1,
        first_pid: original.pid(),
    });
    harness.commit();
    let mut frame = Presentation::capture(harness.coordinator(), "pid", 1, 2, 1);
    assert_eq!(frame.callers.len(), 1);
    assert_eq!(frame.edges.len(), 1);
    frame.callers[0].start_time = original.start_time();
    frame.callers[0].lifecycle = CallerLifecycle::Mapped;
    frame.callers[0].retired = false;
    Arc::new(frame)
}
fn batch(
    pool: &SemanticResourcePool,
    original: &Arc<PidPin>,
    frame: Arc<Presentation>,
    exec: u64,
) -> Arc<PromotionBaselineBatch> {
    // Reserve before the private fixture's row/Arc allocations, exactly as the
    // production query does. No constructor is available outside this cfg test.
    let storage = pool.reserve(requested_bytes(1).unwrap()).unwrap();
    let mut bytes = Vec::new();
    for (cookie, exec, visits, slot, status) in [(17u64, exec, 1u64, 0u32, 1u32), (0, 0, 2, 1, 2)] {
        for word in [9u64, cookie, exec, visits] {
            bytes.extend_from_slice(&word.to_ne_bytes());
        }
        bytes.extend_from_slice(&slot.to_ne_bytes());
        bytes.extend_from_slice(&status.to_ne_bytes());
    }
    let decoded = super::super::wire::parse_baseline(&bytes, 9, 1, 65536).unwrap();
    let image = decoded.images.into_iter().next().unwrap();
    let caller = &frame.callers[0];
    Arc::new(PromotionBaselineBatch {
        capture: CaptureId::new(11),
        core: KernelBaselineBatch {
            domain: NativeDomainId::mint(),
            generation: 9,
            rows: vec![ImageRow {
                caller: caller.id,
                incarnation: caller.incarnation,
                original: PidPin::downgrade_shared(original).unwrap(),
                cookie: image.cookie,
                exec_id: image.exec_id,
            }],
        },
        presentation: frame,
        _storage: storage,
    })
}
fn request(view: Arc<PromotionView>) -> PromotionRequest {
    let caller = view.presentation().edges[0].caller;
    let provider = view.presentation().edges[0].module;
    let mut promoter = Promoter::new();
    assert!(promoter.enable(view.capture()));
    promoter.request(view, caller, provider).unwrap();
    promoter.take_request().unwrap()
}

#[test]
fn promotion_baseline_exact_view_request_and_full_exec_identity() {
    let pool = SemanticResourcePool::default();
    let pin = original(&pool);
    let frame = frame(&pin);
    for exec in [0, 0x8000_0000_0000_0001] {
        let batch = batch(&pool, &pin, Arc::clone(&frame), exec);
        let view = Arc::new(
            PromotionView::with_baseline(
                CaptureId::new(11),
                ViewRevision::new(1),
                Arc::clone(&frame),
                Arc::clone(&batch),
            )
            .unwrap(),
        );
        let request = request(view);
        let baseline = batch
            .for_request(&request, &pin, frame.callers[0].incarnation)
            .unwrap();
        assert!(baseline.matches_request(&request));
        assert!(baseline.matches_original_and_exec(&pin, exec));
        assert!(!baseline.matches_original_and_exec(&pin, exec ^ 1));
        assert!(!baseline.matches_original_and_exec(&pin, exec ^ (1 << 63)));
        assert!(
            batch
                .for_request(&request, &pin, frame.callers[0].incarnation.wrapping_add(1))
                .is_err()
        );
        assert!(format!("{batch:?}{baseline:?}").contains("<retained>"));
    }
}

#[test]
fn promotion_baseline_old_missing_or_foreign_frame_cannot_be_retrofitted() {
    let pool = SemanticResourcePool::default();
    let pin = original(&pool);
    let frame = frame(&pin);
    let old = request(Arc::new(PromotionView::new(
        CaptureId::new(11),
        ViewRevision::new(1),
        Arc::clone(&frame),
    )));
    let batch = batch(&pool, &pin, Arc::clone(&frame), 0);
    assert!(old.viewed().baseline().is_none());
    assert!(
        batch
            .for_request(&old, &pin, frame.callers[0].incarnation)
            .is_err()
    );
    assert!(
        PromotionView::with_baseline(
            CaptureId::new(12),
            ViewRevision::new(2),
            Arc::clone(&frame),
            Arc::clone(&batch)
        )
        .is_none()
    );
    assert!(
        PromotionView::with_baseline(
            CaptureId::new(11),
            ViewRevision::new(2),
            Arc::new((*frame).clone()),
            Arc::clone(&batch)
        )
        .is_none()
    );
    for revision in [0, ViewRevision::EXHAUSTED] {
        assert!(
            PromotionView::with_baseline(
                CaptureId::new(11),
                ViewRevision::new(revision),
                Arc::clone(&frame),
                Arc::clone(&batch)
            )
            .is_none()
        );
    }
    let fresh = request(Arc::new(
        PromotionView::with_baseline(
            CaptureId::new(11),
            ViewRevision::new(2),
            Arc::clone(&frame),
            Arc::clone(&batch),
        )
        .unwrap(),
    ));
    let baseline = batch
        .for_request(&fresh, &pin, frame.callers[0].incarnation)
        .unwrap();
    assert!(baseline.matches_request(&fresh));
    assert!(!baseline.matches_request(&old));
    assert!(old.viewed().baseline().is_none());
}

#[test]
fn promotion_baseline_replacement_pin_and_different_batch_refuse() {
    let pool = SemanticResourcePool::default();
    let pin = original(&pool);
    let replacement = original(&pool); // Same physical PID, different retained allocation.
    let frame = frame(&pin);
    let first = batch(&pool, &pin, Arc::clone(&frame), 5);
    let second = batch(&pool, &pin, Arc::clone(&frame), 5);
    assert_ne!(first.core.domain, second.core.domain);
    assert_eq!(first.core.rows[0].cookie, second.core.rows[0].cookie);
    let request = request(Arc::new(
        PromotionView::with_baseline(
            CaptureId::new(11),
            ViewRevision::new(1),
            Arc::clone(&frame),
            Arc::clone(&first),
        )
        .unwrap(),
    ));
    assert!(
        second
            .for_request(&request, &pin, frame.callers[0].incarnation)
            .is_err()
    );
    assert!(
        first
            .for_request(&request, &replacement, frame.callers[0].incarnation)
            .is_err()
    );
    let baseline = first
        .for_request(&request, &pin, frame.callers[0].incarnation)
        .unwrap();
    assert!(!baseline.matches_original_and_exec(&replacement, 5));
    drop(pin);
    assert!(!first.core.rows[0].original.matches_original(&replacement));
    assert!(
        first
            .for_request(&request, &replacement, frame.callers[0].incarnation)
            .is_err()
    );
}

#[test]
fn promotion_baseline_storage_follows_batch_and_paired_weak_lifetime() {
    let pool = SemanticResourcePool::default();
    let initial = pool.snapshot().charged_bytes;
    let pin = original(&pool);
    let before = pool.snapshot().charged_bytes;
    assert_eq!(
        before,
        initial + crate::process::CustodyCharge::requested_bytes::<PidPin>(0).unwrap()
    );
    let frame = frame(&pin);
    let batch = batch(&pool, &pin, frame, 0);
    assert_eq!(
        pool.snapshot().charged_bytes,
        before + requested_bytes(1).unwrap()
    );
    drop(pin); // The paired Weak keeps its allocation charge, never the pidfd.
    assert_eq!(
        pool.snapshot().charged_bytes,
        before + requested_bytes(1).unwrap()
    );
    drop(batch);
    assert_eq!(pool.snapshot().charged_bytes, initial);
    let small = SemanticResourcePool::reference_limit(
        crate::semantics_edge::resources::SEMANTIC_TRANSITION_SCRATCH,
    );
    let no_headroom = small.snapshot();
    assert_eq!(no_headroom.charged_bytes, no_headroom.limit_bytes);
    assert!(small.reserve(requested_bytes(1).unwrap()).is_err());
    let refused = small.snapshot();
    assert_eq!(refused.charged_bytes, no_headroom.charged_bytes);
    assert_eq!(refused.peak_charged_bytes, no_headroom.peak_charged_bytes);
    assert_eq!(refused.refused, no_headroom.refused + 1);
}
