//! SPDX-License-Identifier: GPL-3.0-or-later
//! Userspace side of the Detailed STOP_GATE map: metadata validation plus
//! the `Session`-owned mmap of its single cell.

use super::{BPF_F_MMAPABLE, map_metadata, validate_map_metadata};
use anyhow::{Context as _, Result, bail};
use aya::Ebpf;
use aya::maps::{Map, MapData, MapType};
use p11scope_ebpf_common::{STOP_GATE_COUNT_MASK, STOP_GATE_STOP};
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

/// Borrow the Detailed STOP_GATE map's data, refusing any other variant.
pub(crate) fn stop_gate_map_data(ebpf: &Ebpf) -> Result<&MapData> {
    let map = ebpf.map("STOP_GATE").context("STOP_GATE map")?;
    match map {
        Map::Array(data) => Ok(data),
        other => bail!("refusing unexpected STOP_GATE runtime map variant {other:?}"),
    }
}

/// Require the Detailed STOP_GATE map: `Array<u64>` with one entry and
/// exactly `BPF_F_MMAPABLE`.
pub(crate) fn validate_stop_gate(ebpf: &Ebpf) -> Result<()> {
    validate_map_metadata(
        "STOP_GATE",
        stop_gate_map_data(ebpf)?,
        map_metadata(MapType::Array, 4, 8, 1, BPF_F_MMAPABLE),
    )
}

/// First-stop state (packet 6.13 round-3, re-audit finding 2): "no stop
/// requested" and "stop requested but its instant is unknown" are distinct.
/// A clock failure at the first request latches `Unknown` once — a later
/// request or loop-end sample must never backfill it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirstStop {
    NotRequested,
    Unknown,
    Known(u64),
}

/// Raw `first_stop` encoding of [`FirstStop::Unknown`]: unreachable from
/// `CLOCK_MONOTONIC` (2^64-1ns ≈ 585 years), reserved so the unknown case
/// latches once in the same atomic as the known instant. Zero stays "none";
/// known instants clamp below the sentinel.
const FIRST_STOP_UNKNOWN: u64 = u64::MAX;

/// Mmap of the STOP_GATE cell, owned by the `Session` for its lifetime.
/// Every access is atomic; the mapping unmaps on drop.
pub(crate) struct StopGate {
    cell: NonNull<AtomicU64>,
    len: usize,
    /// First stop-request state (packet 6.13 round-2, F3): latched once at
    /// the first effective STOP, never overwritten, so terminal watch
    /// bounds use the earliest stop instead of a later publication read.
    /// Raw [`FirstStop`] encoding: 0 none, `FIRST_STOP_UNKNOWN` unknown.
    first_stop: AtomicU64,
}

// SAFETY: the mapping is owned exclusively and every access is atomic.
unsafe impl Send for StopGate {}
// SAFETY: the mapping is owned exclusively and every access is atomic.
unsafe impl Sync for StopGate {}

impl StopGate {
    /// Map the gate cell and require its initial value 0: a nonzero cell
    /// means another session's state leaked into this map.
    pub(crate) fn from_map_fd(fd: BorrowedFd<'_>) -> Result<StopGate> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let len = usize::try_from(page).context("querying the STOP_GATE page size")?;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error()).context("mapping the STOP_GATE cell");
        }
        // SAFETY: mmap succeeded, so the first eight bytes are readable and
        // writable; the page-aligned base satisfies AtomicU64 alignment.
        let cell = NonNull::new(base.cast::<AtomicU64>()).context("STOP_GATE mapping is null")?;
        if unsafe { cell.as_ref() }.load(Ordering::SeqCst) != 0 {
            unsafe { libc::munmap(base, len) };
            bail!("STOP_GATE cell is nonzero before first use");
        }
        Ok(StopGate {
            cell,
            len,
            first_stop: AtomicU64::new(0),
        })
    }

    /// Publish the stop request: set the stop bit, keep the count. The
    /// first call also latches its `CLOCK_MONOTONIC` instant (read before
    /// the bit is set, so the stamp is at or before the effective stop),
    /// or `Unknown` when the clock read fails; later calls never move it.
    pub(crate) fn request_stop(&self) {
        self.request_stop_with(super::monotonic_ns());
    }

    /// [`request_stop`] with an injected clock reading, so tests can script
    /// a failed first read. Production always passes the live clock. Both
    /// outcomes latch once: a failed read records `Unknown`, never a
    /// later request's instant.
    pub(crate) fn request_stop_with(&self, now: Option<u64>) {
        let stamped = match now {
            Some(ns) => ns.max(1).min(FIRST_STOP_UNKNOWN - 1),
            None => FIRST_STOP_UNKNOWN,
        };
        let _ = self
            .first_stop
            .compare_exchange(0, stamped, Ordering::SeqCst, Ordering::SeqCst);
        self.word().fetch_or(STOP_GATE_STOP, Ordering::SeqCst);
    }

    /// The first stop-request state: nothing requested yet, requested with
    /// an unknown instant, or the latched known instant.
    pub(crate) fn first_stop(&self) -> FirstStop {
        match self.first_stop.load(Ordering::SeqCst) {
            0 => FirstStop::NotRequested,
            FIRST_STOP_UNKNOWN => FirstStop::Unknown,
            ns => FirstStop::Known(ns),
        }
    }

    pub(crate) fn stop_requested(&self) -> bool {
        self.word().load(Ordering::SeqCst) & STOP_GATE_STOP != 0
    }

    /// True only when the stop bit is set and no body is admitted.
    pub(crate) fn quiescent(&self) -> bool {
        self.word()
            .compare_exchange(
                STOP_GATE_STOP,
                STOP_GATE_STOP,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /// Bodies currently inside a guarded region.
    pub(crate) fn in_flight(&self) -> u64 {
        self.word().load(Ordering::SeqCst) & STOP_GATE_COUNT_MASK
    }

    fn word(&self) -> &AtomicU64 {
        // SAFETY: from_map_fd validated the mapping; Drop unmaps exactly once.
        unsafe { self.cell.as_ref() }
    }
}

impl Drop for StopGate {
    fn drop(&mut self) {
        // SAFETY: from_map_fd mapped exactly this range; StopGate is the
        // exclusive owner and Drop runs once.
        unsafe {
            libc::munmap(self.cell.as_ptr().cast(), self.len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_gate() -> StopGate {
        let len = 4096;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        StopGate {
            cell: NonNull::new(base.cast()).unwrap(),
            len,
            first_stop: AtomicU64::new(0),
        }
    }

    #[test]
    fn pid_continuity_stop_bit_refuses_with_bodies_in_flight() {
        let gate = test_gate();
        gate.word().store(3, Ordering::SeqCst);
        assert!(!gate.stop_requested());
        assert_eq!(gate.first_stop(), FirstStop::NotRequested);
        gate.request_stop();
        assert_eq!(gate.in_flight(), 3);
        assert!(!gate.quiescent());
        assert!(
            gate.stop_requested(),
            "STOP must refuse before admitted bodies become quiescent"
        );
        // The first stop latches its instant; a later request never moves it.
        let FirstStop::Known(first) = gate.first_stop() else {
            panic!("the stop latches its instant");
        };
        assert!(first > 0);
        std::thread::sleep(std::time::Duration::from_millis(2));
        gate.request_stop();
        assert_eq!(gate.first_stop(), FirstStop::Known(first));
    }

    #[test]
    fn first_stop_failure_then_success_stays_unknown() {
        // Packet 6.13 round-3 (re-audit finding 2): a failed clock read at
        // the first request latches "stop requested, instant unknown" once —
        // a later request with a working clock must not backfill it.
        let gate = test_gate();
        assert_eq!(gate.first_stop(), FirstStop::NotRequested);
        gate.request_stop_with(None);
        assert!(gate.stop_requested());
        assert_eq!(gate.first_stop(), FirstStop::Unknown);
        gate.request_stop_with(Some(5000));
        assert_eq!(gate.first_stop(), FirstStop::Unknown);
    }

    #[test]
    fn first_stop_known_instant_latches_once() {
        // Healthy twin: the first known instant latches; later requests —
        // known or clock-failed — never move it.
        let gate = test_gate();
        gate.request_stop_with(Some(1000));
        assert_eq!(gate.first_stop(), FirstStop::Known(1000));
        gate.request_stop_with(Some(5000));
        assert_eq!(gate.first_stop(), FirstStop::Known(1000));
        gate.request_stop_with(None);
        assert_eq!(gate.first_stop(), FirstStop::Known(1000));
    }
}
