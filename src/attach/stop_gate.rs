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

/// Mmap of the STOP_GATE cell, owned by the `Session` for its lifetime.
/// Every access is atomic; the mapping unmaps on drop.
pub(crate) struct StopGate {
    cell: NonNull<AtomicU64>,
    len: usize,
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
        Ok(StopGate { cell, len })
    }

    /// Publish the stop request: set the stop bit, keep the count.
    // A later stop-gate task drives userspace stop.
    #[allow(dead_code)]
    pub(crate) fn request_stop(&self) {
        self.word().fetch_or(STOP_GATE_STOP, Ordering::SeqCst);
    }

    /// True only when the stop bit is set and no body is admitted.
    // A later stop-gate task drives userspace stop.
    #[allow(dead_code)]
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
    // A later stop-gate task drives userspace stop.
    #[allow(dead_code)]
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
