//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

fn mark_used(cell: &AtomicU64) -> bool {
    inventory_mark_used_with(
        || cell.load(Ordering::Relaxed),
        || {
            cell.compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                .unwrap_or_else(|previous| previous)
        },
    )
}

#[test]
fn inventory_policy_accepts_only_one_external_scope_and_no_capture_or_pause_policy() {
    for flags in 0..=255 {
        assert_eq!(
            valid_inventory_config(flags),
            matches!(flags, 0x81 | 0x82 | 0xc0),
            "{flags:#x}"
        );
        if flags & 0x80 != 0 {
            assert!(
                !valid_config(flags),
                "detailed object admitted inventory flags {flags:#x}"
            );
        }
    }
    for scope in [0x81, 0x82, 0xc0] {
        assert!(!valid_inventory_config(scope | (1 << 63)));
    }
}

#[test]
fn inventory_cookie_cannot_alias_detailed_cookie_and_checks_runtime_capacity() {
    for (cookie, capacity, expected) in [
        (0, 1, None),
        (1, 2, None),
        (0x5055_5346_0000_0000, 1, None),
        (0x5055_5347_0000_0000, 0, None),
        (0x5055_5347_0000_0000, 1, Some(0)),
        (0x5055_5347_0000_ffff, 65_536, Some(65_535)),
        (0x5055_5347_0001_0000, 65_536, None),
        (0x5055_5347_ffff_fffe, u32::MAX, Some(u32::MAX - 1)),
        (0x5055_5347_ffff_ffff, u32::MAX, None),
    ] {
        assert_eq!(inventory_cookie_endpoint(cookie, capacity), expected);
    }
}

#[test]
fn inventory_usage_config_rejects_unknown_version_and_empty_capacity() {
    for (version, endpoint_capacity, valid) in [
        (1, 1, true),
        (1, u32::MAX, true),
        (1, 0, false),
        (0, 1, false),
        (2, 1, false),
    ] {
        assert_eq!(
            InventoryUsageConfig {
                version,
                endpoint_capacity
            }
            .is_valid(),
            valid
        );
    }
    assert_eq!(core::mem::size_of::<InventoryUsageConfig>(), 8);
    assert_eq!(
        core::mem::offset_of!(InventoryUsageConfig, endpoint_capacity),
        4
    );
}

#[test]
fn inventory_use_is_monotonic_and_refuses_corrupt_cells() {
    let cell = AtomicU64::new(0);
    for _ in 0..100 {
        assert!(mark_used(&cell));
        assert_eq!(cell.load(Ordering::Relaxed), 1);
    }
    for invalid in [2, u64::MAX] {
        let cell = AtomicU64::new(invalid);
        assert!(!mark_used(&cell));
        assert_eq!(cell.load(Ordering::Relaxed), invalid);
    }
}

#[test]
fn concurrent_inventory_use_preserves_one_without_counting_calls() {
    extern crate std;
    let cell = AtomicU64::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..10_000 {
                    assert!(mark_used(&cell));
                }
            });
        }
    });
    assert_eq!(cell.load(Ordering::Relaxed), 1);
}
