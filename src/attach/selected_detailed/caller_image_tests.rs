//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual private observation/decoder controls. These do not claim live native
//! iterator acquisition or turn an observation into caller admission.
use super::*;
use crate::semantics_edge::resources::SemanticResourcePool;
use std::time::{Duration, Instant};

fn original(pool: &SemanticResourcePool) -> Arc<PidPin> {
    let mut pin = PidPin::open(std::process::id()).unwrap();
    let charge = crate::process::CustodyCharge::reserve::<PidPin>(&pool.reserver(), 0).unwrap();
    pin.install_shared_custody_charge(charge);
    Arc::new(pin)
}

fn observation(
    domain: NativeDomainId,
    original: &Arc<PidPin>,
    generation: u64,
    cookie: u64,
    exec_id: u64,
) -> CallerImageObservation {
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
    let image = super::super::super::wire::parse_baseline(&bytes, generation, 1, 65536)
        .unwrap()
        .images
        .pop()
        .unwrap();
    CallerImageObservation {
        domain,
        generation,
        original: Arc::clone(original),
        cookie: image.cookie,
        exec_id: image.exec_id,
    }
}

#[test]
fn caller_image_observation_binds_original_cookie_and_full_exec_including_zero() {
    let pool = SemanticResourcePool::default();
    let pin = original(&pool);
    let domain = NativeDomainId::mint();
    for exec_id in [0, 0x8000_0000_0000_0001] {
        let image = observation(domain, &pin, 1, 17, exec_id);
        assert!(image.matches_original_and_image(&pin, 17, exec_id));
        assert!(!image.matches_original_and_image(&pin, 18, exec_id));
        assert!(!image.matches_original_and_image(&pin, 17, exec_id ^ 1));
        assert!(!image.matches_original_and_image(&pin, 17, exec_id ^ (1 << 63)));
        let later = observation(domain, &pin, 2, 17, exec_id);
        assert!(image.same_image(&later));
        assert!(later.same_image(&image));
        assert_eq!(format!("{image:?}"), "CallerImageObservation(<retained>)");
    }
}

#[test]
fn caller_image_observation_rejects_foreign_domain_original_cookie_and_exec() {
    let pool = SemanticResourcePool::default();
    let pin = original(&pool);
    let replacement = original(&pool);
    assert_eq!(pin.pid(), replacement.pid());
    assert_eq!(pin.start_time(), replacement.start_time());
    let domain = NativeDomainId::mint();
    let image = observation(domain, &pin, 1, 17, 0);
    assert!(!image.matches_original_and_image(&replacement, 17, 0));
    for other in [
        observation(NativeDomainId::mint(), &pin, 2, 17, 0),
        observation(domain, &replacement, 2, 17, 0),
        observation(domain, &pin, 2, 18, 0),
        observation(domain, &pin, 2, 17, 1 << 63),
    ] {
        assert!(!image.same_image(&other));
        assert!(!other.same_image(&image));
    }
}

#[test]
fn caller_image_observation_retains_same_charged_original_without_extra_custody_charge() {
    let pool = SemanticResourcePool::default();
    let initial = pool.snapshot().charged_bytes;
    let pin = original(&pool);
    let before = pool.snapshot().charged_bytes;
    let weak = Arc::downgrade(&pin);
    let image = observation(NativeDomainId::mint(), &pin, 1, 17, 0);
    assert_eq!(pool.snapshot().charged_bytes, before);
    assert_eq!(Arc::strong_count(&pin), 2);
    drop(pin);
    assert!(weak.upgrade().is_some());
    assert_eq!(pool.snapshot().charged_bytes, before);
    drop(image);
    drop(weak);
    assert_eq!(pool.snapshot().charged_bytes, initial);
}

#[test]
fn caller_image_query_window_requires_generation_positive_bounded_rows_and_deadline() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let window = ReadWindow::new(1, deadline).unwrap();
    assert!(super::super::validate_query_window(1, 1, window).is_ok());
    for (generation, count) in [(0, 1), (1, 0), (1, 2)] {
        assert!(super::super::validate_query_window(generation, count, window).is_err());
    }
    let wide = ReadWindow::new(1025, deadline).unwrap();
    assert!(super::super::validate_query_window(1, 1024, wide).is_ok());
    assert!(super::super::validate_query_window(1, 1025, wide).is_err());
    let expired = ReadWindow::new(1, Instant::now() - Duration::from_millis(1)).unwrap();
    assert!(super::super::validate_query_window(1, 1, expired).is_err());
}
