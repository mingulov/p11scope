//! SPDX-License-Identifier: GPL-2.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Shared Task 7 INFO record trailer layout (spec §17.4).
//!
//! The 176-byte inventory info record is a 48-byte header followed by
//! the 128-byte [`InfoTrailer`]. This struct is the single shared
//! layout: the userspace decoder indexes trailer fields through its
//! offsets and the BPF writer fills the same bytes. Wire order is
//! field order; there is no padding.

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
}
