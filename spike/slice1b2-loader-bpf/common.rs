// Shared record/protocol definitions for the loader artifact (corrective design
// §5.2/§5.3/§7.3). This is the loader artifact's OWN copy: the frozen A/B
// artifact's spike/slice1b2-kernel files are never touched (Task 5 freeze
// boundary); both loader crates include this single file.

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DiscoveryRecord {
    pub hook_ts_ns: u64,
    pub pid_tgid: u64,
    pub table_ptr: u64,
    pub interface_flags: u64,
    pub pointers: [u64; 104],
    pub kind: u8,
    pub case_id: u8,
    pub interface_index: u8,
    pub name_class: u8,
    pub status_flags: u8,
    pub usable_n: u8,
    pub pointers_attempted: u8,
    pub completed_prefix: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub reserved_zero: [u8; 2],
    pub symbol_id: u32,
    pub announced_count: u32,
    pub reserved_tail_zero: [u8; 12],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SignalRecord {
    pub hook_ts_ns: u64,
    pub pid_tgid: u64,
    pub send_signal_rc: i64,
    pub case_id: u8,
    pub reserved_zero: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StateKey {
    pub pid_tgid: u64,
    pub attach_cookie: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StartState {
    pub arg0: u64,
    pub arg1: u64,
}

// §5.2/§5.3 pause-owner protocol constants (no record layout change).
pub const PAUSE_ARMED: u64 = 1;
pub const PAUSE_REQUESTED: u64 = 2;
pub const COALESCED_NO_HELPER: i64 = i64::MIN;
/// UAPI `BPF_NOEXIST` map-update flag (aya does not export it host-side).
pub const BPF_NOEXIST_FLAG: u64 = 1;

// §7.3 loader attach cookie layout: bits 0..7 = context_id - 1, bit 8 =
// state_present, bits 9..63 = payload (sentinel 1 when state is absent, else a
// signed 55-bit two's-complement delta).
pub const COOKIE_ID_MASK: u64 = 0xff;
pub const COOKIE_STATE_PRESENT: u64 = 1 << 8;
pub const COOKIE_PAYLOAD_SHIFT: u32 = 9;
pub const COOKIE_DELTA_MASK: u64 = (1 << 55) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CookieError {
    Zero,
    InvalidAbsentPayload,
}

pub fn cookie_encode(context_id: u16, delta: Option<i64>) -> u64 {
    let id_bits = u64::from(context_id - 1) & COOKIE_ID_MASK;
    match delta {
        None => id_bits | (1 << COOKIE_PAYLOAD_SHIFT), // sentinel payload 1
        Some(d) => {
            id_bits
                | COOKIE_STATE_PRESENT
                | (((d as u64) & COOKIE_DELTA_MASK) << COOKIE_PAYLOAD_SHIFT)
        }
    }
}

pub fn cookie_decode(cookie: u64) -> Result<(u16, Option<i64>), CookieError> {
    if cookie == 0 {
        return Err(CookieError::Zero);
    }
    let id = (cookie & COOKIE_ID_MASK) as u16 + 1;
    if cookie & COOKIE_STATE_PRESENT == 0 {
        if cookie >> COOKIE_PAYLOAD_SHIFT != 1 {
            return Err(CookieError::InvalidAbsentPayload);
        }
        Ok((id, None))
    } else {
        Ok((id, Some((cookie as i64) >> COOKIE_PAYLOAD_SHIFT))) // signed 55-bit delta
    }
}
