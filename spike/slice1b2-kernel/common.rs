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
pub const SIGNAL_COOKIE_A: u64 = 1;
pub const SIGNAL_COOKIE_B: u64 = 2;
/// UAPI `BPF_NOEXIST` map-update flag (aya does not export it host-side).
pub const BPF_NOEXIST_FLAG: u64 = 1;
