//! SPDX-License-Identifier: GPL-2.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Shared Task 7 INFO record layout and read lists (spec §17).
//!
//! The 176-byte inventory info record is a 48-byte [`InfoHeader`]
//! followed by the 128-byte [`InfoTrailer`]. These structs are the
//! single shared layout: the BPF writer fills the same bytes the
//! userspace decoder validates (the decoder keeps its own offset
//! oracle for the header and indexes the trailer through the shared
//! offsets). Wire order is field order; all integers are
//! little-endian on the wire.
//!
//! The §17.1 read lists live here as checked-in consts (ebpf-common
//! is no_std on the kernel side and cannot depend on cryptoki-sys):
//! full struct spans for the entry guard, exact payload lengths,
//! (offset, length) range tables in struct address order, and probe
//! argument positions. Static asserts below pin every range end
//! inside its per-ABI span; the root-crate LP64 cross-check pins the
//! LP64 consts against the bindgen types, and the byte-exact host
//! twins pin the ia32 literals.

use crate::LinuxLayout;

/// 176-byte inventory info record: 48-byte header + 128-byte trailer.
pub const INFO_RECORD_LEN: usize = 176;
/// Info record header: endpoint/kind/layout, host tgid, caller
/// identity, slot and mechanism words (spec §17.4).
pub const INFO_HEADER_LEN: usize = 48;
/// Info record trailer: [`InfoTrailer`], 8 fixed bytes plus the
/// 120-byte payload window.
pub const INFO_TRAILER_LEN: usize = 128;
/// Payload window inside the trailer; `payload_len` says how many
/// leading bytes carry struct ranges, the rest is zero slack.
pub const INFO_PAYLOAD_MAX: usize = 120;

/// Info trailer version carried in every record.
pub const INFO_VERSION: u16 = 1;
/// Info kinds: `C_GetInfo` / `C_GetTokenInfo` / `C_GetMechanismInfo`.
/// Kind 0 is usage-only (never stashes, never records).
pub const INFO_KIND_PROVIDER: u8 = 1;
pub const INFO_KIND_TOKEN: u8 = 2;
pub const INFO_KIND_MECHANISM: u8 = 3;
/// Layout codes, mirroring the journal wire (`OBJECT_LAYOUT_*`).
pub const INFO_LAYOUT_LP64: u8 = 1;
pub const INFO_LAYOUT_ILP32: u8 = 2;
/// Trailer status: values present (`CKR_OK` + readable bytes) or
/// unavailable (unreadable bytes — joins to nothing).
pub const INFO_STATUS_OK: u8 = 0;
pub const INFO_STATUS_UNAVAILABLE: u8 = 1;

/// 128-byte INFO record trailer: version, kind, status, layout,
/// exact payload length, 2 reserved bytes and the 120-byte payload
/// window. All integers are little-endian on the wire.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InfoTrailer {
    /// Trailer version (`INFO_VERSION`).
    pub version: u16,
    /// Info kind (`INFO_KIND_*`); agrees with the header kind.
    pub kind: u8,
    /// Trailer status (`INFO_STATUS_*`).
    pub status: u8,
    /// Target layout (`INFO_LAYOUT_*`); agrees with the header layout.
    pub layout: u8,
    /// Exact payload bytes for this (kind, layout).
    pub payload_len: u8,
    /// Reserved, always zero.
    pub reserved: [u8; 2],
    /// Struct-range bytes; slack past `payload_len` is zero.
    pub payload: [u8; 120],
}

const _: () = assert!(INFO_HEADER_LEN + INFO_TRAILER_LEN == INFO_RECORD_LEN);
const _: () = assert!(core::mem::size_of::<InfoTrailer>() == INFO_TRAILER_LEN);
const _: () = assert!(core::mem::align_of::<InfoTrailer>() == 2);
const _: () = assert!(core::mem::offset_of!(InfoTrailer, version) == 0);
const _: () = assert!(core::mem::offset_of!(InfoTrailer, kind) == 2);
const _: () = assert!(core::mem::offset_of!(InfoTrailer, status) == 3);
const _: () = assert!(core::mem::offset_of!(InfoTrailer, layout) == 4);
const _: () = assert!(core::mem::offset_of!(InfoTrailer, payload_len) == 5);
const _: () = assert!(core::mem::offset_of!(InfoTrailer, reserved) == 6);
const _: () = assert!(core::mem::offset_of!(InfoTrailer, payload) == 8);
const _: () =
    assert!(core::mem::offset_of!(InfoTrailer, payload) + INFO_PAYLOAD_MAX == INFO_TRAILER_LEN);

// SAFETY: `repr(C)` integers only, no padding; every bit pattern is
// representable. Callers still run the record validator before
// interpreting a trailer.
#[cfg(feature = "user")]
unsafe impl aya::Pod for InfoTrailer {}

/// Full struct bytes per (kind, layout) for the entry full-span
/// guard (spec §17.1: 88/76, 208/160, 24/12). Unknown kinds refuse.
#[inline(always)]
pub const fn info_span_size(kind: u8, layout: LinuxLayout) -> Option<u16> {
    match (kind, layout) {
        (INFO_KIND_PROVIDER, LinuxLayout::Lp64) => Some(88),
        (INFO_KIND_PROVIDER, LinuxLayout::Ilp32) => Some(76),
        (INFO_KIND_TOKEN, LinuxLayout::Lp64) => Some(208),
        (INFO_KIND_TOKEN, LinuxLayout::Ilp32) => Some(160),
        (INFO_KIND_MECHANISM, LinuxLayout::Lp64) => Some(24),
        (INFO_KIND_MECHANISM, LinuxLayout::Ilp32) => Some(12),
        _ => None,
    }
}

/// Exact payload bytes per (kind, layout) (spec §17.1: 76/72, 76/64,
/// 24/12). Unknown kinds refuse.
#[inline(always)]
pub const fn info_payload_len(kind: u8, layout: LinuxLayout) -> Option<u8> {
    match (kind, layout) {
        (INFO_KIND_PROVIDER, LinuxLayout::Lp64) => Some(76),
        (INFO_KIND_PROVIDER, LinuxLayout::Ilp32) => Some(72),
        (INFO_KIND_TOKEN, LinuxLayout::Lp64) => Some(76),
        (INFO_KIND_TOKEN, LinuxLayout::Ilp32) => Some(64),
        (INFO_KIND_MECHANISM, LinuxLayout::Lp64) => Some(24),
        (INFO_KIND_MECHANISM, LinuxLayout::Ilp32) => Some(12),
        _ => None,
    }
}

/// One (kind, layout) read list: up to four (struct offset, length)
/// ranges in struct address order; only the first `count` entries
/// are live, the rest are zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InfoReadList {
    pub ranges: [(u16, u16); 4],
    pub count: u8,
}

/// Read lists per (kind, layout) (spec §17.1). Unknown kinds refuse.
#[inline(always)]
pub const fn info_read_ranges(kind: u8, layout: LinuxLayout) -> Option<InfoReadList> {
    let (ranges, count) = match (kind, layout) {
        (INFO_KIND_PROVIDER, LinuxLayout::Lp64) => ([(0, 34), (40, 42), (0, 0), (0, 0)], 2),
        (INFO_KIND_PROVIDER, LinuxLayout::Ilp32) => ([(0, 34), (36, 38), (0, 0), (0, 0)], 2),
        (INFO_KIND_TOKEN, LinuxLayout::Lp64) => ([(32, 48), (96, 8), (136, 16), (184, 4)], 4),
        (INFO_KIND_TOKEN, LinuxLayout::Ilp32) => ([(32, 48), (96, 4), (116, 8), (140, 4)], 4),
        (INFO_KIND_MECHANISM, LinuxLayout::Lp64) => ([(0, 24), (0, 0), (0, 0), (0, 0)], 1),
        (INFO_KIND_MECHANISM, LinuxLayout::Ilp32) => ([(0, 12), (0, 0), (0, 0), (0, 0)], 1),
        _ => return None,
    };
    Some(InfoReadList { ranges, count })
}

/// The info-pointer probe argument per kind (spec §17.1): arg 0/1/2.
/// Unknown kinds refuse.
#[inline(always)]
pub const fn info_pointer_arg(kind: u8) -> Option<u8> {
    match kind {
        INFO_KIND_PROVIDER => Some(0),
        INFO_KIND_TOKEN => Some(1),
        INFO_KIND_MECHANISM => Some(2),
        _ => None,
    }
}

/// The snapshotted slot-scalar probe argument per kind, if any.
#[inline(always)]
pub const fn info_slot_arg(kind: u8) -> Option<u8> {
    match kind {
        INFO_KIND_TOKEN | INFO_KIND_MECHANISM => Some(0),
        _ => None,
    }
}

/// The snapshotted mechanism-scalar probe argument per kind, if any.
#[inline(always)]
pub const fn info_mechanism_arg(kind: u8) -> Option<u8> {
    match kind {
        INFO_KIND_MECHANISM => Some(1),
        _ => None,
    }
}

/// Whether the entry probe for `kind` may load probe argument `index`
/// (spec §17.1, allowlist-v3 named positions): provider {0}, token
/// {0,1}, mechanism {0,1,2}. Unknown kinds load nothing. The BPF
/// entry wrapper guards every `arg_u64` call with this predicate, so
/// ia32 stack-word reads never touch positions outside the authorized
/// function signature.
#[inline(always)]
pub const fn info_uses_arg(kind: u8, index: u8) -> bool {
    matches!(
        (kind, index),
        (INFO_KIND_PROVIDER, 0)
            | (INFO_KIND_TOKEN, 0)
            | (INFO_KIND_TOKEN, 1)
            | (INFO_KIND_MECHANISM, 0)
            | (INFO_KIND_MECHANISM, 1)
            | (INFO_KIND_MECHANISM, 2)
    )
}

/// Whether `kind` is a published INFO kind (spec §17.4): exactly
/// the three info functions. Kind 0 (usage-only, return-deferred,
/// or revoked) and unknown values authorize nothing. The BPF entry
/// and return wrappers share this single definition: the entry
/// stashes only for valid kinds, and the return enforces the LIVE
/// cell before reading a saved pointer or counting an unmatched
/// call — a revoked endpoint's returns delete silently.
#[inline(always)]
pub const fn info_kind_valid(kind: u8) -> bool {
    matches!(
        kind,
        INFO_KIND_PROVIDER | INFO_KIND_TOKEN | INFO_KIND_MECHANISM
    )
}

/// Attach-side name rule (spec §17.4): exactly the three info
/// function names resolve to kinds; anything else refuses.
#[inline(always)]
pub fn info_kind_for_function(name: &str) -> Option<u8> {
    match name {
        "C_GetInfo" => Some(INFO_KIND_PROVIDER),
        "C_GetTokenInfo" => Some(INFO_KIND_TOKEN),
        "C_GetMechanismInfo" => Some(INFO_KIND_MECHANISM),
        _ => None,
    }
}

const _: () = {
    assert!(INFO_LAYOUT_LP64 == 1);
    assert!(INFO_LAYOUT_ILP32 == 2);
    // Every range end sits inside its per-ABI span, every live range
    // is nonempty with zero trailing ranges, and the byte sums equal
    // the exact payload lengths.
    let lists: [(u8, LinuxLayout); 6] = [
        (INFO_KIND_PROVIDER, LinuxLayout::Lp64),
        (INFO_KIND_PROVIDER, LinuxLayout::Ilp32),
        (INFO_KIND_TOKEN, LinuxLayout::Lp64),
        (INFO_KIND_TOKEN, LinuxLayout::Ilp32),
        (INFO_KIND_MECHANISM, LinuxLayout::Lp64),
        (INFO_KIND_MECHANISM, LinuxLayout::Ilp32),
    ];
    let mut i = 0;
    while i < lists.len() {
        let (kind, layout) = lists[i];
        let span = match info_span_size(kind, layout) {
            Some(span) => span,
            None => panic!("info span"),
        };
        let payload = match info_payload_len(kind, layout) {
            Some(payload) => payload,
            None => panic!("info payload len"),
        };
        let list = match info_read_ranges(kind, layout) {
            Some(list) => list,
            None => panic!("info ranges"),
        };
        assert!(list.count >= 1 && list.count <= 4);
        let mut sum = 0u16;
        let mut r = 0usize;
        while r < 4 {
            let (off, len) = list.ranges[r];
            if r < list.count as usize {
                assert!(len > 0);
                let end = match off.checked_add(len) {
                    Some(end) => end,
                    None => panic!("info range end"),
                };
                assert!(end <= span);
                sum += len;
            } else {
                assert!(off == 0 && len == 0);
            }
            r += 1;
        }
        assert!(sum == payload as u16);
        i += 1;
    }
};

/// 48-byte INFO record header (spec §17.4): endpoint, kind, layout,
/// host thread group, caller identity, slot and mechanism words.
/// All integers are little-endian on the wire.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InfoHeader {
    /// Inventory endpoint id.
    pub endpoint: u32,
    /// Info kind (`INFO_KIND_*`); agrees with the trailer kind.
    pub kind: u8,
    /// Target layout (`INFO_LAYOUT_*`); agrees with the trailer layout.
    pub layout: u8,
    /// Reserved, always zero.
    pub reserved0: u16,
    /// The witness's host thread group.
    pub host_tgid: u32,
    /// Reserved, always zero.
    pub reserved1: u32,
    /// The calling image's task cookie (0 = unavailable).
    pub task_cookie: u64,
    /// The calling image's exec id.
    pub exec_id: u64,
    /// Slot id snapshotted at entry (0 for `C_GetInfo`).
    pub slot: u64,
    /// Mechanism id snapshotted at entry (0 except `C_GetMechanismInfo`).
    pub mechanism: u64,
}

const _: () = assert!(core::mem::size_of::<InfoHeader>() == INFO_HEADER_LEN);
const _: () = assert!(core::mem::align_of::<InfoHeader>() == 8);
const _: () = assert!(core::mem::offset_of!(InfoHeader, endpoint) == 0);
const _: () = assert!(core::mem::offset_of!(InfoHeader, kind) == 4);
const _: () = assert!(core::mem::offset_of!(InfoHeader, layout) == 5);
const _: () = assert!(core::mem::offset_of!(InfoHeader, reserved0) == 6);
const _: () = assert!(core::mem::offset_of!(InfoHeader, host_tgid) == 8);
const _: () = assert!(core::mem::offset_of!(InfoHeader, reserved1) == 12);
const _: () = assert!(core::mem::offset_of!(InfoHeader, task_cookie) == 16);
const _: () = assert!(core::mem::offset_of!(InfoHeader, exec_id) == 24);
const _: () = assert!(core::mem::offset_of!(InfoHeader, slot) == 32);
const _: () = assert!(core::mem::offset_of!(InfoHeader, mechanism) == 40);

/// The 176-byte wire record: the header followed by the shared
/// trailer. The BPF writer fills this shape; the userspace decoder
/// validates the same bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InfoRecordWire {
    pub header: InfoHeader,
    pub trailer: InfoTrailer,
}

const _: () = assert!(core::mem::size_of::<InfoRecordWire>() == INFO_RECORD_LEN);
const _: () = assert!(core::mem::offset_of!(InfoRecordWire, header) == 0);
const _: () = assert!(core::mem::offset_of!(InfoRecordWire, trailer) == INFO_HEADER_LEN);

// SAFETY: `repr(C)` integers only, no padding; every bit pattern is
// representable. Callers still run the record validator before
// interpreting a record.
#[cfg(feature = "user")]
unsafe impl aya::Pod for InfoHeader {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for InfoRecordWire {}

/// Zero the 120-byte payload window. Explicit volatile byte stores:
/// no implicit memset call and no 120-byte temporary on the stack, so
/// the BPF writer inlines this leaf-flat, and no alignment requirement
/// (the window is a bare `[u8; 120]`). Shared by the BPF return path
/// and the host adapters.
#[inline(always)]
pub fn zero_info_payload(payload: &mut [u8; INFO_PAYLOAD_MAX]) {
    let mut i = 0usize;
    while i < INFO_PAYLOAD_MAX {
        // SAFETY: `i` stays inside the exclusively owned window.
        unsafe { payload.as_mut_ptr().add(i).write_volatile(0) };
        i += 1;
    }
}

/// Encode one wire record from a header, a status and a packed
/// payload window: the 48 header bytes, the fixed trailer bytes
/// (version, kind/layout agreement with the header, the exact
/// per-(kind, layout) payload length, zero reserved) and the copied
/// 120-byte window. Returns false and writes nothing when the
/// (kind, layout) pair is unknown: the caller emits no record (fail
/// closed, never a guessed length).
#[inline(always)]
pub fn encode_info_record(
    out: &mut [u8; INFO_RECORD_LEN],
    header: &InfoHeader,
    status: u8,
    payload: &[u8; INFO_PAYLOAD_MAX],
) -> bool {
    let layout = match header.layout {
        INFO_LAYOUT_LP64 => LinuxLayout::Lp64,
        INFO_LAYOUT_ILP32 => LinuxLayout::Ilp32,
        _ => return false,
    };
    let Some(payload_len) = info_payload_len(header.kind, layout) else {
        return false;
    };
    out[0..4].copy_from_slice(&header.endpoint.to_le_bytes());
    out[4] = header.kind;
    out[5] = header.layout;
    out[6..8].copy_from_slice(&[0, 0]);
    out[8..12].copy_from_slice(&header.host_tgid.to_le_bytes());
    out[12..16].copy_from_slice(&[0, 0, 0, 0]);
    out[16..24].copy_from_slice(&header.task_cookie.to_le_bytes());
    out[24..32].copy_from_slice(&header.exec_id.to_le_bytes());
    out[32..40].copy_from_slice(&header.slot.to_le_bytes());
    out[40..48].copy_from_slice(&header.mechanism.to_le_bytes());
    out[48..50].copy_from_slice(&INFO_VERSION.to_le_bytes());
    out[50] = header.kind;
    out[51] = status;
    out[52] = header.layout;
    out[53] = payload_len;
    out[54..56].copy_from_slice(&[0, 0]);
    out[56..176].copy_from_slice(payload);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn info_trailer_layout_matches_the_wire() {
        // Transcribed from spec §17.4, not from the struct above: if
        // the struct drifts, this twin fails.
        assert_eq!(INFO_RECORD_LEN, 176);
        assert_eq!(INFO_HEADER_LEN, 48);
        assert_eq!(INFO_TRAILER_LEN, 128);
        assert_eq!(INFO_PAYLOAD_MAX, 120);
        assert_eq!(size_of::<InfoTrailer>(), 128);
        assert_eq!(align_of::<InfoTrailer>(), 2);
        assert_eq!(offset_of!(InfoTrailer, version), 0);
        assert_eq!(offset_of!(InfoTrailer, kind), 2);
        assert_eq!(offset_of!(InfoTrailer, status), 3);
        assert_eq!(offset_of!(InfoTrailer, layout), 4);
        assert_eq!(offset_of!(InfoTrailer, payload_len), 5);
        assert_eq!(offset_of!(InfoTrailer, reserved), 6);
        assert_eq!(offset_of!(InfoTrailer, payload), 8);
    }

    /// Wire vocabulary (spec §17.4): version, the three info kinds,
    /// the two layout codes and the two statuses. Transcribed
    /// literals: the BPF writer and the userspace decoder share these
    /// consts, and this twin pins their values.
    #[test]
    fn info_codes_pin_the_wire_vocabulary() {
        assert_eq!(INFO_VERSION, 1);
        assert_eq!(INFO_KIND_PROVIDER, 1);
        assert_eq!(INFO_KIND_TOKEN, 2);
        assert_eq!(INFO_KIND_MECHANISM, 3);
        assert_eq!(INFO_LAYOUT_LP64, 1);
        assert_eq!(INFO_LAYOUT_ILP32, 2);
        assert_eq!(INFO_STATUS_OK, 0);
        assert_eq!(INFO_STATUS_UNAVAILABLE, 1);
    }

    /// Full struct spans per (kind, layout) for the entry guard
    /// (spec §17.1: 88/76, 208/160, 24/12). Unknown kinds refuse.
    #[test]
    fn info_span_sizes_pin_the_full_struct_bytes() {
        use crate::LinuxLayout::{Ilp32, Lp64};
        for (kind, layout, span) in [
            (INFO_KIND_PROVIDER, Lp64, 88),
            (INFO_KIND_PROVIDER, Ilp32, 76),
            (INFO_KIND_TOKEN, Lp64, 208),
            (INFO_KIND_TOKEN, Ilp32, 160),
            (INFO_KIND_MECHANISM, Lp64, 24),
            (INFO_KIND_MECHANISM, Ilp32, 12),
        ] {
            assert_eq!(info_span_size(kind, layout), Some(span), "kind {kind}");
        }
        assert_eq!(info_span_size(0, Lp64), None);
        assert_eq!(info_span_size(9, Lp64), None);
    }

    /// Exact payload bytes per (kind, layout) (spec §17.1: 76/72,
    /// 76/64, 24/12). Unknown kinds refuse.
    #[test]
    fn info_payload_lens_pin_the_exact_range_bytes() {
        use crate::LinuxLayout::{Ilp32, Lp64};
        for (kind, layout, len) in [
            (INFO_KIND_PROVIDER, Lp64, 76),
            (INFO_KIND_PROVIDER, Ilp32, 72),
            (INFO_KIND_TOKEN, Lp64, 76),
            (INFO_KIND_TOKEN, Ilp32, 64),
            (INFO_KIND_MECHANISM, Lp64, 24),
            (INFO_KIND_MECHANISM, Ilp32, 12),
        ] {
            assert_eq!(info_payload_len(kind, layout), Some(len), "kind {kind}");
        }
        assert_eq!(info_payload_len(0, Lp64), None);
        assert_eq!(info_payload_len(9, Ilp32), None);
    }

    /// Read lists per (kind, layout) as (struct offset, length)
    /// ranges in struct address order (spec §17.1). Unknown kinds
    /// refuse.
    #[test]
    fn info_read_ranges_pin_the_section_17_1_lists() {
        use crate::LinuxLayout::{Ilp32, Lp64};
        type RangeCase = (u8, crate::LinuxLayout, [(u16, u16); 4], u8);
        let lists: [RangeCase; 6] = [
            (
                INFO_KIND_PROVIDER,
                Lp64,
                [(0, 34), (40, 42), (0, 0), (0, 0)],
                2,
            ),
            (
                INFO_KIND_PROVIDER,
                Ilp32,
                [(0, 34), (36, 38), (0, 0), (0, 0)],
                2,
            ),
            (
                INFO_KIND_TOKEN,
                Lp64,
                [(32, 48), (96, 8), (136, 16), (184, 4)],
                4,
            ),
            (
                INFO_KIND_TOKEN,
                Ilp32,
                [(32, 48), (96, 4), (116, 8), (140, 4)],
                4,
            ),
            (
                INFO_KIND_MECHANISM,
                Lp64,
                [(0, 24), (0, 0), (0, 0), (0, 0)],
                1,
            ),
            (
                INFO_KIND_MECHANISM,
                Ilp32,
                [(0, 12), (0, 0), (0, 0), (0, 0)],
                1,
            ),
        ];
        for (kind, layout, ranges, count) in lists {
            let list = info_read_ranges(kind, layout).expect("known kind");
            assert_eq!(list.ranges, ranges, "kind {kind} ranges");
            assert_eq!(list.count, count, "kind {kind} count");
        }
        assert!(info_read_ranges(0, Lp64).is_none());
        assert!(info_read_ranges(9, Ilp32).is_none());
    }

    /// Read-list hygiene per (kind, layout): ranges are ordered and
    /// disjoint, every range end sits inside the full span, the byte
    /// sum equals the exact payload length, and every pad interval
    /// from the §17.1 tables stays outside the read ranges (pads are
    /// never fetched, not read-and-scrubbed).
    #[test]
    fn info_read_ranges_exclude_every_pad_and_span_end() {
        use crate::LinuxLayout::{Ilp32, Lp64};
        // (kind, layout, pad intervals).
        type PadCase<'a> = (u8, crate::LinuxLayout, &'a [(u16, u16)]);
        let pads: [PadCase<'_>; 6] = [
            (INFO_KIND_PROVIDER, Lp64, &[(34, 6), (82, 6)]),
            (INFO_KIND_PROVIDER, Ilp32, &[(34, 2), (74, 2)]),
            (INFO_KIND_TOKEN, Lp64, &[(204, 4)]),
            (INFO_KIND_TOKEN, Ilp32, &[]),
            (INFO_KIND_MECHANISM, Lp64, &[]),
            (INFO_KIND_MECHANISM, Ilp32, &[]),
        ];
        for (kind, layout, pad_list) in pads {
            let span = info_span_size(kind, layout).expect("span");
            let payload = info_payload_len(kind, layout).expect("payload len");
            let list = info_read_ranges(kind, layout).expect("ranges");
            let live = &list.ranges[..usize::from(list.count)];
            let mut end = 0u16;
            let mut sum = 0u16;
            for (off, len) in live {
                assert!(*off >= end, "kind {kind}: ranges ordered and disjoint");
                assert!(*len > 0, "kind {kind}: live ranges are nonempty");
                end = off.saturating_add(*len);
                assert!(end <= span, "kind {kind}: range end inside the span");
                sum = sum.saturating_add(*len);
            }
            assert_eq!(sum, u16::from(payload), "kind {kind}: bytes sum");
            for (pad_off, pad_len) in pad_list {
                let pad_end = pad_off.saturating_add(*pad_len);
                for (off, len) in live {
                    let range_end = off.saturating_add(*len);
                    assert!(
                        range_end <= *pad_off || *off >= pad_end,
                        "kind {kind}: pad [{pad_off}..{pad_end}) outside reads"
                    );
                }
            }
            for (off, len) in &list.ranges[usize::from(list.count)..] {
                assert_eq!(
                    (*off, *len),
                    (0, 0),
                    "kind {kind}: trailing ranges are zero"
                );
            }
        }
    }

    /// Probe argument positions per kind (spec §17.1): the info
    /// pointer plus the snapshotted slot/mechanism scalars. Every
    /// index is ≤ 2 and unknown kinds refuse.
    #[test]
    fn info_argument_positions_pin_the_probe_slots() {
        assert_eq!(info_pointer_arg(INFO_KIND_PROVIDER), Some(0));
        assert_eq!(info_pointer_arg(INFO_KIND_TOKEN), Some(1));
        assert_eq!(info_pointer_arg(INFO_KIND_MECHANISM), Some(2));
        assert_eq!(info_pointer_arg(0), None);
        assert_eq!(info_pointer_arg(9), None);
        assert_eq!(info_slot_arg(INFO_KIND_PROVIDER), None);
        assert_eq!(info_slot_arg(INFO_KIND_TOKEN), Some(0));
        assert_eq!(info_slot_arg(INFO_KIND_MECHANISM), Some(0));
        assert_eq!(info_slot_arg(0), None);
        assert_eq!(info_mechanism_arg(INFO_KIND_PROVIDER), None);
        assert_eq!(info_mechanism_arg(INFO_KIND_TOKEN), None);
        assert_eq!(info_mechanism_arg(INFO_KIND_MECHANISM), Some(1));
        assert_eq!(info_mechanism_arg(9), None);
        for kind in [INFO_KIND_PROVIDER, INFO_KIND_TOKEN, INFO_KIND_MECHANISM] {
            for arg in [
                info_pointer_arg(kind),
                info_slot_arg(kind),
                info_mechanism_arg(kind),
            ]
            .into_iter()
            .flatten()
            {
                assert!(arg <= 2, "kind {kind}: index {arg} within args");
            }
        }
    }

    /// Attach-side name rule (spec §17.4): exactly the three info
    /// function names resolve to kinds; anything else refuses.
    #[test]
    fn info_function_names_pin_the_three_endpoints() {
        assert_eq!(
            info_kind_for_function("C_GetInfo"),
            Some(INFO_KIND_PROVIDER)
        );
        assert_eq!(
            info_kind_for_function("C_GetTokenInfo"),
            Some(INFO_KIND_TOKEN)
        );
        assert_eq!(
            info_kind_for_function("C_GetMechanismInfo"),
            Some(INFO_KIND_MECHANISM)
        );
        for other in ["", "C_Sign", "c_getinfo", "C_GetInfoX", "C_GetSlotInfo"] {
            assert_eq!(info_kind_for_function(other), None, "{other}");
        }
    }

    /// Shared 48-byte record header (spec §17.4): endpoint, kind,
    /// layout, host tgid, caller identity, slot and mechanism words.
    /// Transcribed literals: the BPF writer fills this struct and the
    /// userspace decoder keeps its own offset oracle.
    #[test]
    fn info_header_layout_matches_the_wire() {
        assert_eq!(size_of::<InfoHeader>(), 48);
        assert_eq!(align_of::<InfoHeader>(), 8);
        assert_eq!(offset_of!(InfoHeader, endpoint), 0);
        assert_eq!(offset_of!(InfoHeader, kind), 4);
        assert_eq!(offset_of!(InfoHeader, layout), 5);
        assert_eq!(offset_of!(InfoHeader, reserved0), 6);
        assert_eq!(offset_of!(InfoHeader, host_tgid), 8);
        assert_eq!(offset_of!(InfoHeader, reserved1), 12);
        assert_eq!(offset_of!(InfoHeader, task_cookie), 16);
        assert_eq!(offset_of!(InfoHeader, exec_id), 24);
        assert_eq!(offset_of!(InfoHeader, slot), 32);
        assert_eq!(offset_of!(InfoHeader, mechanism), 40);
    }

    /// The wire record is the header followed by the shared trailer:
    /// 176 bytes with the trailer at 48.
    #[test]
    fn info_record_wire_is_header_plus_trailer() {
        assert_eq!(size_of::<InfoRecordWire>(), INFO_RECORD_LEN);
        assert_eq!(offset_of!(InfoRecordWire, header), 0);
        assert_eq!(offset_of!(InfoRecordWire, trailer), INFO_HEADER_LEN);
    }

    /// The payload-window zeroing the writer runs on every record:
    /// 0xA5 bytes become zero.
    #[test]
    fn zero_info_payload_clears_the_window() {
        let mut payload = [0xA5u8; INFO_PAYLOAD_MAX];
        zero_info_payload(&mut payload);
        assert_eq!(payload, [0u8; INFO_PAYLOAD_MAX]);
    }

    /// The shared encoder packs one header, the fixed trailer bytes
    /// (version, kind/layout agreement, exact payload length, zero
    /// reserved) and the 120-byte payload window at the wire offsets.
    /// Byte-exact against transcribed literals.
    #[test]
    fn encode_info_record_packs_header_status_and_payload() {
        let header = InfoHeader {
            endpoint: 0x0102_0304,
            kind: INFO_KIND_TOKEN,
            layout: INFO_LAYOUT_ILP32,
            reserved0: 0,
            host_tgid: 0x0506_0708,
            reserved1: 0,
            task_cookie: 0x090A_0B0C_0D0E_0F10,
            exec_id: 0x1112_1314_1516_1718,
            slot: 9,
            mechanism: 0,
        };
        let mut payload = [0u8; INFO_PAYLOAD_MAX];
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let mut out = [0xCCu8; INFO_RECORD_LEN];
        assert!(encode_info_record(
            &mut out,
            &header,
            INFO_STATUS_OK,
            &payload
        ));
        assert_eq!(
            u32::from_le_bytes(out[0..4].try_into().unwrap()),
            0x0102_0304
        );
        assert_eq!(out[4], INFO_KIND_TOKEN);
        assert_eq!(out[5], INFO_LAYOUT_ILP32);
        assert_eq!(&out[6..8], &[0, 0]);
        assert_eq!(
            u32::from_le_bytes(out[8..12].try_into().unwrap()),
            0x0506_0708
        );
        assert_eq!(&out[12..16], &[0, 0, 0, 0]);
        assert_eq!(
            u64::from_le_bytes(out[16..24].try_into().unwrap()),
            0x090A_0B0C_0D0E_0F10
        );
        assert_eq!(
            u64::from_le_bytes(out[24..32].try_into().unwrap()),
            0x1112_1314_1516_1718
        );
        assert_eq!(u64::from_le_bytes(out[32..40].try_into().unwrap()), 9);
        assert_eq!(u64::from_le_bytes(out[40..48].try_into().unwrap()), 0);
        assert_eq!(
            u16::from_le_bytes(out[48..50].try_into().unwrap()),
            INFO_VERSION
        );
        assert_eq!(out[50], INFO_KIND_TOKEN);
        assert_eq!(out[51], INFO_STATUS_OK);
        assert_eq!(out[52], INFO_LAYOUT_ILP32);
        assert_eq!(out[53], 64, "token ia32 exact payload length");
        assert_eq!(&out[54..56], &[0, 0]);
        assert_eq!(&out[56..176], &payload[..]);
    }

    /// Kind validity (spec §17.4): exactly the three info kinds
    /// authorize capture — 0 (usage-only, return-deferred, revoked)
    /// and every unknown value authorize nothing, on the full byte.
    #[test]
    fn info_kind_valid_authorizes_exactly_the_three_kinds() {
        use super::{info_kind_valid, INFO_KIND_MECHANISM, INFO_KIND_PROVIDER, INFO_KIND_TOKEN};
        for kind in 0..=255u8 {
            assert_eq!(
                info_kind_valid(kind),
                matches!(
                    kind,
                    INFO_KIND_PROVIDER | INFO_KIND_TOKEN | INFO_KIND_MECHANISM
                ),
                "kind {kind}"
            );
        }
    }

    /// The encoder refuses unknown kinds and writes nothing: the
    /// caller emits no record (fail closed, never a guessed length).
    #[test]
    fn encode_info_record_refuses_unknown_kind() {
        let header = InfoHeader {
            endpoint: 1,
            kind: 9,
            layout: INFO_LAYOUT_LP64,
            reserved0: 0,
            host_tgid: 2,
            reserved1: 0,
            task_cookie: 3,
            exec_id: 4,
            slot: 0,
            mechanism: 0,
        };
        let payload = [0xA5u8; INFO_PAYLOAD_MAX];
        let mut out = [0xCCu8; INFO_RECORD_LEN];
        assert!(!encode_info_record(
            &mut out,
            &header,
            INFO_STATUS_OK,
            &payload
        ));
        assert_eq!(out, [0xCCu8; INFO_RECORD_LEN]);
    }
}
