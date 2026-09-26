//! SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-or-later
use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

/// Compare-exchange read of the shared word, as the BPF helper reads it
/// (`CAS(p, 0, 0)`); the admitted/denied decision rides on the stop bit only.
fn gate_read(cell: &AtomicU64) -> u64 {
    cell.compare_exchange(0, 0, Ordering::SeqCst, Ordering::SeqCst)
        .unwrap_or_else(|previous| previous)
}

/// Non-fetch atomic add; the result is never consumed, on either side.
fn gate_add(cell: &AtomicU64, delta: i64) {
    cell.fetch_add(delta as u64, Ordering::SeqCst);
}

fn admit(cell: &AtomicU64) -> bool {
    stop_gate_admit_with(|| gate_read(cell), |delta| gate_add(cell, delta))
}

fn request_stop(cell: &AtomicU64) {
    cell.fetch_or(STOP_GATE_STOP, Ordering::SeqCst);
}

fn quiescent(cell: &AtomicU64) -> bool {
    cell.compare_exchange(
        STOP_GATE_STOP,
        STOP_GATE_STOP,
        Ordering::SeqCst,
        Ordering::SeqCst,
    )
    .is_ok()
}

fn in_flight(cell: &AtomicU64) -> u64 {
    cell.load(Ordering::SeqCst) & STOP_GATE_COUNT_MASK
}

#[test]
fn stop_gate_constants_split_the_word_into_stop_bit_and_count() {
    assert_eq!(STOP_GATE_STOP, 1 << 63);
    assert_eq!(STOP_GATE_COUNT_MASK, (1 << 63) - 1);
    assert_eq!(STOP_GATE_STOP & STOP_GATE_COUNT_MASK, 0);
    assert_eq!(STOP_GATE_STOP | STOP_GATE_COUNT_MASK, u64::MAX);
}

#[test]
fn stop_gate_admitted_body_blocks_quiescence_until_its_decrement() {
    // (a) Admitted before stop, still running.
    let cell = AtomicU64::new(0);
    assert!(admit(&cell));
    assert_eq!(in_flight(&cell), 1);
    request_stop(&cell);
    assert!(!quiescent(&cell));
    assert_eq!(in_flight(&cell), 1);
    gate_add(&cell, -1);
    assert!(quiescent(&cell));
    assert_eq!(in_flight(&cell), 0);
}

#[test]
fn stop_gate_denies_an_admission_paused_across_stop_and_restores_the_count() {
    // (b) Paused between the first read and the increment, then stop: the
    // stale first read admits, the stop lands, and the second read denies,
    // so the count returns to its previous value.
    let cell = AtomicU64::new(1); // one body already admitted and running
    let mut reads = 0;
    let admitted = stop_gate_admit_with(
        || {
            reads += 1;
            if reads == 1 {
                1
            } else {
                gate_read(&cell)
            }
        },
        |delta| {
            if delta == 1 {
                request_stop(&cell);
            }
            gate_add(&cell, delta);
        },
    );
    assert!(!admitted);
    assert_eq!(reads, 2);
    assert_eq!(cell.load(Ordering::SeqCst), STOP_GATE_STOP | 1);
    assert_eq!(in_flight(&cell), 1);
    assert!(!quiescent(&cell));
    gate_add(&cell, -1);
    assert!(quiescent(&cell));
}

#[test]
fn stop_gate_denies_after_stop_without_touching_the_count() {
    // (c) Stop before any read.
    let cell = AtomicU64::new(0);
    request_stop(&cell);
    assert!(!admit(&cell));
    assert_eq!(cell.load(Ordering::SeqCst), STOP_GATE_STOP);
    assert!(!admit(&cell));
    assert_eq!(cell.load(Ordering::SeqCst), STOP_GATE_STOP);
    assert!(quiescent(&cell));
}

#[test]
fn stop_gate_race_between_admissions_and_stop_leaves_no_running_body() {
    // (d) Many concurrent admissions racing one request_stop: after
    // quiescent() no admitted body can still be running, and it stays so.
    extern crate std;
    let cell = &AtomicU64::new(0);
    let running = &AtomicU64::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..20_000 {
                    if admit(cell) {
                        running.fetch_add(1, Ordering::SeqCst);
                        for _ in 0..8 {
                            core::hint::spin_loop();
                        }
                        running.fetch_sub(1, Ordering::SeqCst);
                        gate_add(cell, -1);
                    }
                }
            });
        }
        // Let at least one body get inside before the stop lands; the bound
        // keeps a starved scheduler from spinning forever.
        for _ in 0..1_000_000 {
            if running.load(Ordering::SeqCst) != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        request_stop(cell);
        while !quiescent(cell) {
            core::hint::spin_loop();
        }
        assert_eq!(running.load(Ordering::SeqCst), 0);
    });
    assert_eq!(running.load(Ordering::SeqCst), 0);
    assert_eq!(in_flight(cell), 0);
    assert!(quiescent(cell));
}
