//! SPDX-License-Identifier: GPL-2.0-or-later
//! Executable object-adapter sequencing: the production adapter bodies shared
//! by the BPF programs and host regression tests.
//!
//! The BPF adapters used to reimplement these protocols inline while host
//! tests executed copies, so production mutations (a neutered continuity
//! gate, an unconditional arg-5 fetch) still passed the suite. The functions
//! here ARE the adapter bodies: the BPF wrappers in `p11scope-ebpf` do only
//! BPF-local work (probe-register reads, map lookups, ring/tail pointers)
//! and call here with injected readers; host tests call the same functions
//! with instrumented readers and assert exact read sets. Every branch below
//! executes in both. All shared functions are `#[inline(always)]` so the BPF
//! call-chain frames stay identical (pinned by
//! `object_producer_compiled_frames_are_bounded`).
//!
//! Conventions (same as `object_capture`): every target-memory access goes
//! through caller-supplied `FnMut` readers; ownership/phase/continuity arrive
//! as data (`joined`, side rows, RV); span arithmetic is checked before any
//! access. `core`-only: this module compiles for BPF and host alike.

use crate::event_type;
use crate::instance;
use crate::object_capture::{
    authorize_derive_return, classify_derive_mechanism, find_flag, handle_status, object_flag,
    return_accepts_get_results, spans_overlap, validate_target_span, DeriveEntry, GetEntryVerdict,
    ReturnAuthority,
};
use crate::object_policy::ScalarDeriveMechanism;
use crate::object_wire::{
    ObjectAttributeListWire, ObjectCallWire, ObjectDescriptorWire, ObjectStart,
    OBJECT_ACTION_DERIVE, OBJECT_ACTION_FIND, OBJECT_ACTION_GET, OBJECT_ACTION_MAX,
    OBJECT_ACTION_NONE, OBJECT_ATTR_LIST_UNINSPECTED, OBJECT_DERIVE_UNAVAILABLE, OBJECT_FLAGS_MASK,
    OBJECT_GUARD_NONE, OBJECT_GUARD_SCALAR_DERIVE,
};
use crate::{
    target_word_end, CallStart, Event, ImageIdentity, InstanceContinuity, LinuxLayout, ARG_NONE,
};

/// Already captured scalar return facts for the in-place Event writer.
/// This pure constructor grants no read or semantic authority.
pub struct ReturnEventFacts {
    pub ts_ns: u64,
    pub duration_ns: u64,
    pub rv: u64,
    pub mechanism: u64,
    pub session: u64,
    pub async_value: u64,
    pub capture_flags: u32,
    pub pid_tgid: u64,
    pub cgroup_id: u64,
    pub root_affiliation: u64,
}

/// Initialize every Event byte from retained entry facts and captured scalars.
/// # Safety
/// `out` must point to an exclusively writable, aligned Event reservation;
/// it must not alias `start` or `facts`. `start` must remain valid and
/// immutable through this call: an ordinary return may use its owned snapshot
/// after retirement. For a map-backed START, the caller retains ownership
/// and ends the borrow before any helper mutates or retires that row.
#[inline(always)]
pub unsafe fn fill_call_event(
    out: *mut Event,
    start: &CallStart,
    slot: u32,
    facts: &ReturnEventFacts,
) {
    // Every Event field is initialized directly in the exclusive reservation.
    // No Event aggregate is materialized on the BPF stack.
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!((*out).ts_ns), facts.ts_ns);
        core::ptr::write(
            core::ptr::addr_of_mut!((*out).duration_ns),
            facts.duration_ns,
        );
        core::ptr::write(core::ptr::addr_of_mut!((*out).pid_tgid), facts.pid_tgid);
        core::ptr::write(core::ptr::addr_of_mut!((*out).cgroup_id), facts.cgroup_id);
        core::ptr::write(core::ptr::addr_of_mut!((*out).session), facts.session);
        core::ptr::write(core::ptr::addr_of_mut!((*out).slot_id), start.slot_id);
        core::ptr::write(core::ptr::addr_of_mut!((*out).mechanism), facts.mechanism);
        core::ptr::write(core::ptr::addr_of_mut!((*out).flags), start.flags);
        core::ptr::write(core::ptr::addr_of_mut!((*out).rv), facts.rv);
        core::ptr::write(core::ptr::addr_of_mut!((*out).p0), start.p0);
        core::ptr::write(core::ptr::addr_of_mut!((*out).p1), start.p1);
        core::ptr::write(core::ptr::addr_of_mut!((*out).p2), start.p2);
        core::ptr::write(
            core::ptr::addr_of_mut!((*out).async_value),
            facts.async_value,
        );
        core::ptr::write(core::ptr::addr_of_mut!((*out).slot), slot);
        core::ptr::write(
            core::ptr::addr_of_mut!((*out).target_function),
            start.target_function,
        );
        core::ptr::write(core::ptr::addr_of_mut!((*out).user_type), start.user_type);
        core::ptr::write(core::ptr::addr_of_mut!((*out).shape), start.shape);
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(start.attr_types),
            core::ptr::addr_of_mut!((*out).attr_types),
            1,
        );
        core::ptr::write(core::ptr::addr_of_mut!((*out).attr_count), start.attr_count);
        core::ptr::write(core::ptr::addr_of_mut!((*out).attr_total), start.attr_total);
        core::ptr::write(core::ptr::addr_of_mut!((*out).attr_bools), start.attr_bools);
        core::ptr::write(
            core::ptr::addr_of_mut!((*out).attr_bools_seen),
            start.attr_bools_seen,
        );
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(start.attr_types1),
            core::ptr::addr_of_mut!((*out).attr_types1),
            1,
        );
        core::ptr::write(
            core::ptr::addr_of_mut!((*out).attr_count1),
            start.attr_count1,
        );
        core::ptr::write(
            core::ptr::addr_of_mut!((*out).attr_total1),
            start.attr_total1,
        );
        core::ptr::write(
            core::ptr::addr_of_mut!((*out).attr_bools1),
            start.attr_bools1,
        );
        core::ptr::write(
            core::ptr::addr_of_mut!((*out).attr_bools_seen1),
            start.attr_bools_seen1,
        );
        core::ptr::write(core::ptr::addr_of_mut!((*out).capture), facts.capture_flags);
        core::ptr::write(core::ptr::addr_of_mut!((*out).event_type), event_type::CALL);
        core::ptr::write(core::ptr::addr_of_mut!((*out).image), start.image);
        core::ptr::write(
            core::ptr::addr_of_mut!((*out).child_image),
            ImageIdentity::default(),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!((*out).root_affiliation),
            facts.root_affiliation,
        );
    }
}

/// Finite metadata for outlined return wrappers. The layout uses bits0–1
/// (1 LP64, 2 ia32), bit2 is the actual root continuity verdict. Full-width
/// RV, mechanism status and mechanism remain separate scalar arguments.
pub const RETURN_GATE_LAYOUT_MASK: u32 = 3;
pub const RETURN_GATE_JOINED: u32 = 4;
pub const RETURN_GATE_MASK: u32 = RETURN_GATE_LAYOUT_MASK | RETURN_GATE_JOINED;

#[inline(always)]
pub fn encode_return_gate(layout: LinuxLayout, joined: bool) -> u32 {
    let layout = match layout {
        LinuxLayout::Lp64 => 1,
        LinuxLayout::Ilp32 => 2,
    };
    layout | if joined { RETURN_GATE_JOINED } else { 0 }
}

#[inline(always)]
pub fn decode_return_gate(gate: u32) -> Option<(LinuxLayout, bool)> {
    if gate & !RETURN_GATE_MASK != 0 {
        return None;
    }
    let layout = match gate & RETURN_GATE_LAYOUT_MASK {
        1 => LinuxLayout::Lp64,
        2 => LinuxLayout::Ilp32,
        _ => return None,
    };
    Some((layout, gate & RETURN_GATE_JOINED != 0))
}

/// Actual controlled fill body, shared with host read spies. Invalid
/// metadata refuses before reaching the existing custody/continuity gates.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn adapter_fill_return_control(
    side: Option<&mut ObjectStart>,
    descriptor: u32,
    row: Option<&ObjectDescriptorWire>,
    rv: u64,
    mech_status: u32,
    mech: u64,
    gate: u32,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> bool {
    let Some((layout, joined)) = decode_return_gate(gate) else {
        return false;
    };
    adapter_fill_return(
        side,
        descriptor,
        row,
        rv,
        layout,
        mech_status,
        mech,
        joined,
        read_word,
    )
}

/// Actual controlled Find body.
/// # Safety
/// `tail` must satisfy the exclusive writable tail contract of `adapter_emit_find`.
#[inline(always)]
pub unsafe fn adapter_emit_find_control(
    tail: *mut ObjectCallWire,
    side: Option<&ObjectStart>,
    descriptor: u32,
    row: Option<&ObjectDescriptorWire>,
    rv: u64,
    gate: u32,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> bool {
    let Some((layout, joined)) = decode_return_gate(gate) else {
        return false;
    };
    unsafe { adapter_emit_find(tail, side, descriptor, row, layout, rv, joined, read_word) }
}

/// Actual controlled Get body.
/// # Safety
/// `tail` must satisfy the exclusive writable tail contract of `adapter_emit_get_attributes`.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn adapter_emit_get_control(
    tail: *mut ObjectCallWire,
    side: Option<&ObjectStart>,
    descriptor: u32,
    row: Option<&ObjectDescriptorWire>,
    rv: u64,
    gate: u32,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
    read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> bool {
    let Some((layout, joined)) = decode_return_gate(gate) else {
        return false;
    };
    unsafe {
        adapter_emit_get_attributes(
            tail, side, descriptor, row, layout, rv, joined, read_word, read_bytes,
        )
    }
}

/// Production return-arm continuity gate: the reserved record's entry and
/// return stamps join. The BPF return root and host tests execute this same
/// field selection plus predicate; substituting one stamp for the other
/// flips the asymmetric refusal cases.
#[inline(always)]
pub fn continuity_joins(continuity: &InstanceContinuity) -> bool {
    instance::stamp_joinable(continuity.entry_stamp, continuity.return_stamp)
}

/// Production Derive entry adapter body (H7-E3): fetch the arg-1 mechanism
/// pointer, classify through the shared guard, then acquire arg 5 ONLY on
/// membership. Refused mechanisms never fetch arg 5. `fetch_arg` supplies
/// entry arguments (probe registers/stack on BPF, a spy on host);
/// `read_word` reads one target word. Returns false only on custody/row
/// failure, never on a refused mechanism.
#[inline(always)]
pub fn adapter_derive_entry(
    side: Option<&mut ObjectStart>,
    descriptor: u32,
    row: Option<&ObjectDescriptorWire>,
    layout: LinuxLayout,
    fetch_arg: &mut impl FnMut(u8) -> Option<u64>,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> bool {
    let Some(side) = side else {
        return false;
    };
    let Some(row) = row else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1)
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    if row.action != OBJECT_ACTION_DERIVE {
        return true;
    }
    // C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey):
    // mechanism at arg 1, result pointer at arg 5. The ordinals below
    // duplicate the Derive row; refuse loudly if the frozen row disagrees
    // rather than reading the wrong arguments. Unreadable arguments retain
    // zero, which the return core maps to unreadable.
    if row.result_args != [5, ARG_NONE] {
        return false;
    }
    // H7-E3: membership before acquisition. The mechanism word is read
    // and classified first; the arg-5 result pointer is acquired only for
    // the accepted mechanisms, so refused calls never read arg 5 (on
    // ia32, never read its stack word).
    let mechanism_ptr = fetch_arg(1).unwrap_or(0);
    let derive = classify_derive_mechanism(mechanism_ptr, layout, read_word);
    let retained = match derive {
        DeriveEntry::Accepted(_) => fetch_arg(5),
        DeriveEntry::Unavailable => None,
    };
    // SAFETY: a validated live map row on BPF (a caller-owned row on host);
    // these fields are ours.
    unsafe {
        core::ptr::addr_of_mut!(side.derive).write(derive.code());
        core::ptr::addr_of_mut!(side.result_ptrs[0]).write(retained.unwrap_or(0));
        core::ptr::addr_of_mut!(side.result_ptrs[1]).write(0);
    }
    true
}

/// H7-E4 shipping gate, now build-selected: the default build wires
/// FULL attribute capture; only the `stub-object-attributes` BPF build
/// (the v0.4 P0 fallback object) shuts it. While false, entry acquires
/// no template arguments and Get emission reads nothing.
pub const ATTRIBUTE_CAPTURE_WIRED: bool = !cfg!(feature = "stub-object-attributes");

/// Production entry attribute adapter body (H7-E4): inspect authorized
/// creation-template pairs into the side row's request lists, or retain
/// Get entry headers into the side row's Get fields. Returns false only
/// on custody/row failure; refused or unsupported templates are silent
/// outcomes, never failures. `fetch_arg` supplies entry arguments (probe
/// registers/stack on BPF, a spy on host).
///
/// Dispatch mirrors `authorize_entry_templates`: the Get family retains
/// pair zero through the Get entry seam (never request-inspected);
/// other families inspect each present pair through the request seam,
/// with the pair-zero scalars as pair one's alias peer; Derive
/// additionally requires accepted entry evidence (`side.derive`, set by
/// the Derive adapter earlier in the entry chain), and refused Derive
/// marks its present pairs uninspected without fetching or reading.
/// Absent pairs stay untouched. Inspection flag contributions merge
/// into the side flags.
///
/// The entry store lives HERE: the seams populate production side state
/// directly, so host tests observe wiring through this function — no
/// caller hand-writes the inspected outcomes. Acquisition is exact:
/// every `fetch_arg` call below is a probe register/stack read on BPF,
/// pinned by the drivers' fetch counts.
#[inline(always)]
// Closure plus scalar parameters map to the BPF wrapper's register-passed
// arguments; bundling them into a struct would risk wrapper stack the
// 512-byte entry chain does not have.
#[allow(clippy::too_many_arguments)]
pub fn adapter_attributes_entry(
    side: Option<&mut ObjectStart>,
    descriptor: u32,
    row: Option<&ObjectDescriptorWire>,
    layout: LinuxLayout,
    fetch_arg: &mut impl FnMut(u8) -> Option<u64>,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
    mut read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> bool {
    let Some(side) = side else {
        return false;
    };
    let Some(row) = row else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1)
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    if row.action == OBJECT_ACTION_GET {
        capture_get_template(side, row, layout, fetch_arg, &mut read_word);
        return true;
    }
    capture_request_pairs(
        side,
        row,
        layout,
        fetch_arg,
        &mut read_word,
        &mut read_bytes,
    );
    true
}

#[inline(always)]
pub(crate) fn capture_get_template(
    side: &mut ObjectStart,
    row: &ObjectDescriptorWire,
    layout: LinuxLayout,
    fetch_arg: &mut impl FnMut(u8) -> Option<u64>,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
) {
    let (ptr_arg, count_arg) = (row.template_args[0], row.template_args[1]);
    if ptr_arg == ARG_NONE || count_arg == ARG_NONE {
        return;
    }
    let ptr = fetch_arg(ptr_arg);
    let count = fetch_arg(count_arg);
    match (ptr, count) {
        (Some(ptr), Some(count)) => {
            let _ = production_capture_get_entry(ptr, count, layout, side, &mut read_word);
        }
        _ => {
            // Clear every retained field/slot before marking acquisition
            // unavailable, including host reuse or a future retry path.
            let _ = production_capture_get_entry(0, 0, layout, side, &mut read_word);
            side.flags |=
                object_flag::ARG_READ_FAILURE as u16 | crate::object_wire::GET_ENTRY_UNINSPECTED;
        }
    }
}

// The actual scalar request-pair body, separate so host spies exercise its
// acquisition and alias sequencing directly. It is called only after
// descriptor/custody validation.
#[inline(always)]
pub(crate) fn capture_request_pairs(
    side: &mut ObjectStart,
    row: &ObjectDescriptorWire,
    layout: LinuxLayout,
    fetch_arg: &mut impl FnMut(u8) -> Option<u64>,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
    mut read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) {
    let present0 = row.template_args[0] != ARG_NONE && row.template_args[1] != ARG_NONE;
    let present1 = row.template_args[2] != ARG_NONE && row.template_args[3] != ARG_NONE;
    // Derive requires accepted entry evidence before any template access
    // (the same finite guard as result-pointer retention). A refused
    // Derive authorizes no template access at all, so its present pairs
    // keep the honest never-inspected marking instead of a fake
    // inspected-empty list the row presence would contradict. No fetch,
    // no read and no flag: the marking plus the unavailable derive code
    // already tell the refusal story.
    if row.action == OBJECT_ACTION_DERIVE && side.derive == OBJECT_DERIVE_UNAVAILABLE {
        if present0 {
            side.requested[0].flags = OBJECT_ATTR_LIST_UNINSPECTED;
        }
        if present1 {
            side.requested[1].flags = OBJECT_ATTR_LIST_UNINSPECTED;
        }
        return;
    }
    // Both actual pairs precede either inspection. Keep failed acquisition
    // distinct from an absent pair and from a successfully acquired count0.
    let pair0 = if present0 {
        let ptr = fetch_arg(row.template_args[0]);
        let count = fetch_arg(row.template_args[1]);
        ptr.zip(count)
    } else {
        None
    };
    let pair1 = if present1 {
        let ptr = fetch_arg(row.template_args[2]);
        let count = fetch_arg(row.template_args[3]);
        ptr.zip(count)
    } else {
        None
    };
    if (present0 && pair0.is_none()) || (present1 && pair1.is_none()) {
        // An unavailable peer has no proven span. Refuse all present lists
        // before any target read instead of silently granting the other pair.
        if present0 {
            side.requested[0].flags = OBJECT_ATTR_LIST_UNINSPECTED;
        }
        if present1 {
            side.requested[1].flags = OBJECT_ATTR_LIST_UNINSPECTED;
        }
        side.flags |= object_flag::ARG_READ_FAILURE as u16;
        return;
    }
    let mut accumulated = 0;
    if let Some((ptr, count)) = pair0 {
        accumulated |= production_inspect_request_template(
            ptr,
            count,
            pair1,
            layout,
            &mut side.requested[0],
            &mut read_word,
            &mut read_bytes,
        );
    }
    if let Some((ptr, count)) = pair1 {
        accumulated |= production_inspect_request_template(
            ptr,
            count,
            pair0,
            layout,
            &mut side.requested[1],
            &mut read_word,
            &mut read_bytes,
        );
    }
    side.flags |= accumulated as u16;
}

// Per-slot return gates for the unrolled fill below. Always inlined
// with value semantics: taking `&mut` of the slot scalars would pin
// them to stack addresses and spill past the 64-byte helper frame.
#[inline(always)]
fn slot_gate(arg: u8, action: u8, derive_ok: bool) -> (bool, u8) {
    if arg == ARG_NONE {
        (false, handle_status::ABSENT)
    } else if action == OBJECT_ACTION_DERIVE && !derive_ok {
        (false, handle_status::PROTOCOL_UNAVAILABLE)
    } else {
        (true, handle_status::ABSENT)
    }
}

#[inline(always)]
fn slot_span(ptr: u64, layout: LinuxLayout) -> (bool, u8) {
    if ptr == 0 {
        (false, handle_status::UNREADABLE)
    } else if target_word_end(ptr, layout).is_none() {
        (false, handle_status::INVALID_SPAN)
    } else {
        (true, handle_status::ABSENT)
    }
}

#[inline(always)]
fn slot_word(
    ptr: u64,
    layout: LinuxLayout,
    read_word: &mut impl FnMut(u64) -> Result<u64, ()>,
) -> (u8, u64) {
    match read_word(ptr) {
        Err(()) => (handle_status::UNREADABLE, 0),
        Ok(0) => (handle_status::INVALID_ZERO, 0),
        Ok(observed) => {
            if layout == LinuxLayout::Ilp32 && observed > u64::from(u32::MAX) {
                (handle_status::INVALID_SPAN, 0)
            } else {
                (handle_status::VALUE, observed)
            }
        }
    }
}

/// Production return-fill adapter body (H7-E1): refuse before any read
/// unless continuity joined, then read both result handles at their
/// retained pointers and advance READY to RETURNING, mirroring
/// `capture_return_handles`. Find carries its facts in the Find section
/// (emission reads the retained array base, never a handle) and skips
/// here; families without results keep absent cells. `rv` is the
/// normalized return value, `mech_status`/`mech` the S1 return-time
/// mechanism evidence. Slot-0 VALUE is pre-cross-check until the pair
/// alias/duplicate/partial rules below recompute both slots from the
/// retained pointers; emission never trusts slot-0 as final.
#[inline(always)]
// This semantic body stays inlined into the checked five-register wrapper;
// no local context aggregate crosses the tightly bounded return chain.
#[allow(clippy::too_many_arguments)]
pub fn adapter_fill_return(
    side: Option<&mut ObjectStart>,
    descriptor: u32,
    row: Option<&ObjectDescriptorWire>,
    rv: u64,
    layout: LinuxLayout,
    mech_status: u32,
    mech: u64,
    joined: bool,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> bool {
    // H7-E1 enforcement inside the executed flow: refused continuity reads
    // nothing, however the adapter was reached.
    if !joined {
        return false;
    }
    let Some(side) = side else {
        return false;
    };
    if side.phase != 2 {
        return false;
    }
    let Some(row) = row else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1)
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    if row.action != OBJECT_ACTION_FIND {
        // Derive return authorization is the full S1 match: accepted
        // entry evidence, CKR_OK, and existing MECHANISM_VALUE return
        // evidence exactly equal to the entry code. Entry-nonzero alone
        // never authorizes the phKey read.
        let derive_entry = match side.derive {
            1 => DeriveEntry::Accepted(ScalarDeriveMechanism::DhPkcs),
            2 => DeriveEntry::Accepted(ScalarDeriveMechanism::Sha256),
            3 => DeriveEntry::Accepted(ScalarDeriveMechanism::Ecdh1),
            4 => DeriveEntry::Accepted(ScalarDeriveMechanism::Ecdh1Cofactor),
            _ => DeriveEntry::Unavailable,
        };
        let derive_ok = row.action != OBJECT_ACTION_DERIVE
            || authorize_derive_return(derive_entry, rv, mech_status, mech);
        // Unrolled two-slot protocol: arrays and loop-carried indices
        // spill past the 64-byte helper frame, while straight-line
        // scalars stay in registers. Both retained pointers are
        // validated before either read; the alias rule consumes them
        // before the observed words overwrite them below.
        let mut flags = 0u32;
        let (gated0, mut status0) = slot_gate(row.result_args[0], row.action, derive_ok);
        if row.action == OBJECT_ACTION_DERIVE && !derive_ok && row.result_args[0] != ARG_NONE {
            flags |= object_flag::UNAVAILABLE_RESULT;
        }
        let (gated1, mut status1) = slot_gate(row.result_args[1], row.action, derive_ok);
        if row.action == OBJECT_ACTION_DERIVE && !derive_ok && row.result_args[1] != ARG_NONE {
            flags |= object_flag::UNAVAILABLE_RESULT;
        }
        let (mut word0, mut word1) = (0u64, 0u64);
        if gated0 || gated1 {
            if rv != 0 {
                if gated0 {
                    status0 = handle_status::PROTOCOL_UNAVAILABLE;
                }
                if gated1 {
                    status1 = handle_status::PROTOCOL_UNAVAILABLE;
                }
            } else {
                let ptr0 = side.result_ptrs[0];
                let ptr1 = side.result_ptrs[1];
                let mut readable0 = false;
                let mut readable1 = false;
                if gated0 {
                    let (ok, span) = slot_span(ptr0, layout);
                    readable0 = ok;
                    if !ok {
                        status0 = span;
                    }
                }
                if gated1 {
                    let (ok, span) = slot_span(ptr1, layout);
                    readable1 = ok;
                    if !ok {
                        status1 = span;
                    }
                }
                let w = layout.word_bytes() as u64;
                if readable0 && readable1 && spans_overlap(ptr0, w, ptr1, w) {
                    status0 = handle_status::ALIAS;
                    status1 = handle_status::ALIAS;
                    flags |= object_flag::ALIAS;
                } else {
                    if readable0 {
                        let (status, word) = slot_word(ptr0, layout, &mut read_word);
                        status0 = status;
                        word0 = word;
                    }
                    if readable1 {
                        let (status, word) = slot_word(ptr1, layout, &mut read_word);
                        status1 = status;
                        word1 = word;
                    }
                    if status0 == handle_status::VALUE
                        && status1 == handle_status::VALUE
                        && word0 == word1
                    {
                        status0 = handle_status::DUPLICATE;
                        status1 = handle_status::DUPLICATE;
                        word0 = 0;
                        word1 = 0;
                        flags |= object_flag::DUPLICATE_RESULT;
                    }
                    if gated0
                        && gated1
                        && u32::from(status0 == handle_status::VALUE)
                            + u32::from(status1 == handle_status::VALUE)
                            == 1
                    {
                        flags |= object_flag::PARTIAL_RESULT;
                    }
                }
            }
        }
        // SAFETY: a validated live map row on BPF (a caller-owned row on
        // host); these fields are ours. The retained pointers are
        // overwritten with the observed handle words (zero for non-value
        // statuses), which emission reads; the cross-checks above already
        // consumed the retained pointers.
        unsafe {
            core::ptr::addr_of_mut!(side.result_ptrs).write([word0, word1]);
            core::ptr::addr_of_mut!(side.result_statuses).write([status0, status1]);
            let old = core::ptr::addr_of!(side.flags).read();
            core::ptr::addr_of_mut!(side.flags).write(old | flags as u16);
        }
    }
    // SAFETY: a validated live map row on BPF (a caller-owned row on host);
    // the phase byte is ours.
    unsafe {
        core::ptr::addr_of_mut!(side.phase).write(3);
    }
    true
}

/// Production emission adapter body: fill the reserved 240-byte object
/// tail in place from the RETURNING side row. Zeroes the whole tail first
/// (every reserved word, the Find section and the result list stay zero
/// unless their family helper fills them), then copies header, handles and
/// statuses and marks never-inspected request lists honestly. False only on
/// custody failure, never on a finite per-field status. Performs no target
/// reads (hence no reader and no continuity gate: it runs only after a
/// joined fill).
///
/// # Safety
///
/// `tail` must be an exclusively owned writable tail (the reserved ring
/// tail on BPF, a caller-owned row on host).
#[inline(always)]
pub unsafe fn adapter_tail_fill(
    tail: *mut ObjectCallWire,
    side: Option<&ObjectStart>,
    descriptor: u32,
    row: Option<&ObjectDescriptorWire>,
) -> bool {
    if tail.is_null() {
        return false;
    }
    let Some(side) = side else {
        return false;
    };
    if side.phase != 3 || side.descriptor_index != descriptor {
        return false;
    }
    let Some(row) = row else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1)
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    // SAFETY: `tail` is the exclusively owned reserved tail; `side` is a
    // validated live map row whose fields are ours to read.
    //
    // Unrolled volatile stores on purpose: any optimizable zeroing
    // sequence (a loop, or even straight-line stores) lowers to memset
    // calls, and the kernel floors every subprogram on the call path at
    // 32 bytes (check_max_stack_depth), so each call level costs budget
    // this helper does not have. Volatile keeps it leaf-flat.
    unsafe {
        let words = tail.cast::<u64>();
        words.add(0).write_volatile(0);
        words.add(1).write_volatile(0);
        words.add(2).write_volatile(0);
        words.add(3).write_volatile(0);
        words.add(4).write_volatile(0);
        words.add(5).write_volatile(0);
        words.add(6).write_volatile(0);
        words.add(7).write_volatile(0);
        words.add(8).write_volatile(0);
        words.add(9).write_volatile(0);
        words.add(10).write_volatile(0);
        words.add(11).write_volatile(0);
        words.add(12).write_volatile(0);
        words.add(13).write_volatile(0);
        words.add(14).write_volatile(0);
        words.add(15).write_volatile(0);
        words.add(16).write_volatile(0);
        words.add(17).write_volatile(0);
        words.add(18).write_volatile(0);
        words.add(19).write_volatile(0);
        words.add(20).write_volatile(0);
        words.add(21).write_volatile(0);
        words.add(22).write_volatile(0);
        words.add(23).write_volatile(0);
        words.add(24).write_volatile(0);
        words.add(25).write_volatile(0);
        words.add(26).write_volatile(0);
        words.add(27).write_volatile(0);
        words.add(28).write_volatile(0);
        words.add(29).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).version).write(1);
        core::ptr::addr_of_mut!((*tail).bytes).write(240);
        core::ptr::addr_of_mut!((*tail).descriptor_index).write(descriptor);
        core::ptr::addr_of_mut!((*tail).flags).write(u32::from(side.flags) & OBJECT_FLAGS_MASK);
        core::ptr::addr_of_mut!((*tail).layout).write(side.layout);
        core::ptr::addr_of_mut!((*tail).action).write(row.action);
        core::ptr::addr_of_mut!((*tail).entry_derive).write(side.derive);
        core::ptr::addr_of_mut!((*tail).input_handles).write(side.inputs);
        core::ptr::addr_of_mut!((*tail).input_status).write(side.input_statuses);
        if row.action == OBJECT_ACTION_FIND {
            // Precondition (b): Find result_ptrs[0] holds the array base,
            // never a handle. The single-handle result cell is pinned to
            // the constant unavailable cell; Find facts live in the Find
            // section that the Find adapter fills next.
            core::ptr::addr_of_mut!((*tail).result_handles).write([0, 0]);
            core::ptr::addr_of_mut!((*tail).result_status)
                .write([handle_status::PROTOCOL_UNAVAILABLE, handle_status::ABSENT]);
        } else {
            core::ptr::addr_of_mut!((*tail).result_handles).write(side.result_ptrs);
            core::ptr::addr_of_mut!((*tail).result_status).write(side.result_statuses);
        }
    }
    // Entry's inspected lists pass through; refused pairs already
    // carry their honest uninspected marking from the entry store.
    // Absent pairs stay all-zero.
    let mut p = 0;
    while p < 2 {
        let present =
            row.template_args[2 * p] != ARG_NONE && row.template_args[2 * p + 1] != ARG_NONE;
        if present {
            // SAFETY: `tail` is ours; `side` is a validated live map row.
            unsafe {
                let dst = core::ptr::addr_of_mut!((*tail).requested[p]);
                dst.write(side.requested[p]);
            }
        }
        p += 1;
    }
    // Get result lists are return-inspected only, so a Get tail marks
    // its result list uninspected until the Get emission establishes
    // inspected results (or keeps the marking on a refused return).
    if row.action == OBJECT_ACTION_GET {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            let dst = core::ptr::addr_of_mut!((*tail).result_attributes);
            core::ptr::addr_of_mut!((*dst).flags).write(OBJECT_ATTR_LIST_UNINSPECTED);
        }
    }
    true
}

// Zero the streamed Find cells after a late refusal (changed count or
// address overflow): the section keeps only its flag byte. Always
// inlined: it must not cost the return chain another level.
#[inline(always)]
unsafe fn zero_find_cells(tail: *mut ObjectCallWire) {
    // SAFETY: the caller holds the exclusively owned reserved tail.
    //
    // Unrolled volatile stores like the tail zeroing above: any
    // optimizable zeroing here lowers to memset calls that cost the
    // return call chain a 32-byte level each, and this helper's caller
    // has no budget for it.
    unsafe {
        core::ptr::addr_of_mut!((*tail).find_handles[0]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[1]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[2]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[3]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[4]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[5]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[6]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[7]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[0]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[1]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[2]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[3]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[4]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[5]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[6]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[7]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_len).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_valid).write_volatile(0);
    }
}

/// Production Find emission adapter body: refuse before any read unless
/// continuity joined, then stream the bounded Find protocol straight into
/// the reserved tail, mirroring `capture_find_return` without its 8-word
/// stack array. Non-Find families succeed trivially. Every refusal
/// leaves the zeroed section with only its flag byte set; a changed
/// count re-zeroes the streamed cells.
///
/// # Safety
///
/// `tail` must be an exclusively owned writable tail (the reserved ring
/// tail on BPF, a caller-owned row on host).
#[inline(always)]
// Eight scalar parameters map 1:1 to the BPF wrapper's register-passed
// arguments; bundling them into a struct would risk wrapper stack the
// 512-byte return chain does not have.
#[allow(clippy::too_many_arguments)]
pub unsafe fn adapter_emit_find(
    tail: *mut ObjectCallWire,
    side: Option<&ObjectStart>,
    descriptor: u32,
    row: Option<&ObjectDescriptorWire>,
    layout: LinuxLayout,
    rv: u64,
    joined: bool,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> bool {
    // H7-E1 enforcement inside the executed flow: refused continuity reads
    // nothing, however the adapter was reached.
    if !joined {
        return false;
    }
    if tail.is_null() {
        return false;
    }
    let Some(side) = side else {
        return false;
    };
    if side.phase != 3 || side.descriptor_index != descriptor {
        return false;
    }
    let Some(row) = row else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1) {
        return false;
    }
    if row.action != OBJECT_ACTION_FIND {
        return true;
    }
    if rv != 0 {
        return true;
    }
    let count_ptr = side.find_count_ptr;
    if count_ptr == 0 || target_word_end(count_ptr, layout).is_none() {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_COUNT);
        }
        return true;
    }
    let count = match read_word(count_ptr) {
        Ok(count) => count,
        Err(()) => {
            // SAFETY: `tail` is the exclusively owned reserved tail.
            unsafe {
                core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_COUNT);
            }
            return true;
        }
    };
    if layout == LinuxLayout::Ilp32 && count > u64::from(u32::MAX) {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_COUNT);
        }
        return true;
    }
    if count > side.find_capacity {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_COUNT);
        }
        return true;
    }
    // `count * W` with overflow refusal. A checked 64-bit multiply
    // lowers to a widening multiply BPF cannot link (`__multi3`), so
    // shift: the target word is 8 (LP64) or 4 (ILP32) bytes wide.
    let shift: u32 = match layout {
        LinuxLayout::Lp64 => 3,
        LinuxLayout::Ilp32 => 2,
    };
    let array_ptr = side.result_ptrs[0];
    if count > (u64::MAX >> shift) {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_SPAN);
        }
        return true;
    }
    let array_len = count << shift;
    if validate_target_span(array_ptr, array_len, layout).is_none() {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_SPAN);
        }
        return true;
    }
    if spans_overlap(array_ptr, array_len, count_ptr, 1u64 << shift) {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::COUNT_ALIAS);
        }
        return true;
    }
    let take = if count > 8 { 8u64 } else { count };
    let mut flags = 0u8;
    if count > 8 {
        flags |= find_flag::TRUNCATED;
    }
    let mut i = 0u64;
    while i < take {
        let Some(addr) = array_ptr.checked_add(i << shift) else {
            // SAFETY: `tail` is ours; zero the streamed prefix, keep flags.
            unsafe {
                zero_find_cells(tail);
                core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_SPAN);
            }
            return true;
        };
        // SAFETY: `tail` is the exclusively owned reserved tail; `i` is
        // bounded by `take <= 8`.
        unsafe {
            match read_word(addr) {
                Err(()) => {
                    core::ptr::addr_of_mut!((*tail).find_status[i as usize])
                        .write(handle_status::UNREADABLE);
                    flags |= find_flag::UNREADABLE_ELEMENT;
                }
                Ok(0) => {
                    core::ptr::addr_of_mut!((*tail).find_status[i as usize])
                        .write(handle_status::INVALID_ZERO);
                }
                Ok(word) => {
                    if layout == LinuxLayout::Ilp32 && word > u64::from(u32::MAX) {
                        core::ptr::addr_of_mut!((*tail).find_status[i as usize])
                            .write(handle_status::INVALID_SPAN);
                    } else {
                        core::ptr::addr_of_mut!((*tail).find_status[i as usize])
                            .write(handle_status::VALUE);
                        core::ptr::addr_of_mut!((*tail).find_handles[i as usize]).write(word);
                    }
                }
            }
        }
        i += 1;
    }
    match read_word(count_ptr) {
        Ok(stable) if stable == count => (),
        _ => {
            // SAFETY: `tail` is ours; the changed count discards the batch.
            unsafe {
                zero_find_cells(tail);
                core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::CHANGED_COUNT);
            }
            return true;
        }
    }
    // SAFETY: `tail` is the exclusively owned reserved tail.
    unsafe {
        core::ptr::addr_of_mut!((*tail).find_len).write(take as u8);
        core::ptr::addr_of_mut!((*tail).find_flags).write(flags);
        core::ptr::addr_of_mut!((*tail).find_valid).write(1);
    }
    true
}

/// Production Get emission adapter body (H7-E4): establish inspected Get
/// results from the side row's retained entry state and stream them into
/// the reserved tail's result list. Mirrors `adapter_emit_find`: refuse
/// before any read unless continuity joined, then emit. Non-Get families
/// succeed trivially (their result list stays zero); return values
/// outside the Get acceptance set keep the tail's UNINSPECTED marking.
/// The seam writes the list; its flag contributions merge into the tail
/// flags.
///
/// # Safety
///
/// `tail` must be an exclusively owned writable tail (the reserved ring
/// tail on BPF, a caller-owned row on host).
#[inline(always)]
// Closure plus scalar parameters map 1:1 to the BPF wrapper's
// register-passed arguments (see `adapter_emit_find`).
#[allow(clippy::too_many_arguments)]
pub unsafe fn adapter_emit_get_attributes(
    tail: *mut ObjectCallWire,
    side: Option<&ObjectStart>,
    descriptor: u32,
    row: Option<&ObjectDescriptorWire>,
    layout: LinuxLayout,
    rv: u64,
    joined: bool,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
    mut read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> bool {
    // H7-E1 enforcement inside the executed flow: refused continuity reads
    // nothing, however the adapter was reached.
    if !joined {
        return false;
    }
    if tail.is_null() {
        return false;
    }
    let Some(side) = side else {
        return false;
    };
    if side.phase != 3 || side.descriptor_index != descriptor {
        return false;
    }
    let Some(row) = row else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1)
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    if row.action != OBJECT_ACTION_GET {
        return true;
    }
    if !return_accepts_get_results(rv) {
        return true;
    }
    // Authority from the adapter's own custody plus the threaded verdict:
    // the side row is live, the fill advanced it to RETURNING, and the
    // root joined continuity — the same trust the fill adapter places in
    // `joined`.
    let contributed = production_capture_get_return(
        side,
        rv,
        ReturnAuthority::AUTHORIZED,
        layout,
        // SAFETY: `tail` is the exclusively owned reserved tail; the
        // result list is ours (zeroed by the tail fill, marked for Get).
        unsafe { &mut (*tail).result_attributes },
        &mut read_word,
        &mut read_bytes,
    );
    if contributed != 0 {
        // SAFETY: `tail` is ours.
        unsafe {
            let old = core::ptr::addr_of!((*tail).flags).read();
            core::ptr::addr_of_mut!((*tail).flags).write(old | contributed);
        }
    }
    true
}

/// Production emission-finalize verdict: the reserved record submits
/// only when emission succeeded AND the retirement settled; any failure
/// discards and faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmissionOutcome {
    pub submitted: bool,
    pub faulted: bool,
}

/// Production emission cleanup decision (H7-E2): the retirement runs
/// INDEPENDENTLY of emission success — a failed fill/emission still
/// retires owned state — and the record submits only when both hold.
/// `remove` performs the checked ownership removal (true = retired).
/// The BPF return root is a thin caller; the host G03 suite executes
/// this same function with an instrumented removal. `#[inline(always)]`
/// keeps the return call-chain frames identical (pinned by
/// `object_producer_compiled_frames_are_bounded`).
#[inline(always)]
pub fn emission_finalize(emitted: bool, remove: impl FnOnce() -> bool) -> EmissionOutcome {
    // H7-E2 enforcement inside the executed flow: no short-circuit past
    // the removal. `emitted && remove()` would skip cleanup on emission
    // failure; the G03 decision test fails that mutant (zero attempts on
    // the emitted=false cells).
    let retired = remove();
    if !emitted || !retired {
        EmissionOutcome {
            submitted: false,
            faulted: true,
        }
    } else {
        EmissionOutcome {
            submitted: true,
            faulted: false,
        }
    }
}

/// Production entry attribute-inspection path (H7-E4 seam).
///
/// Inspects one authorized creation-template pair and populates `out`
/// with the inspected list. Called by `adapter_attributes_entry`, which
/// passes the side row's pair list, so the inspected outcome lands in
/// production entry state — never hand-written by callers. The list is
/// written in place (no 40-byte outcome crosses the BPF entry stack).
/// Returns the inspection's `object_flag` contributions for the adapter
/// to merge into the side flags.
///
/// Uses bounded selector-first header rescans for all stated-span alias
/// checks, followed by one value read and a stable header recheck.
#[inline(always)]
pub fn production_inspect_request_template(
    template_ptr: u64,
    count: u64,
    peer: Option<(u64, u64)>,
    layout: LinuxLayout,
    out: &mut ObjectAttributeListWire,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
    read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> u32 {
    crate::object_capture::inspect_request_template_into(
        template_ptr,
        count,
        peer,
        layout,
        out,
        read_word,
        read_bytes,
    )
}

/// Production GetAttributeValue entry path (H7-E4 seam).
///
/// Retains selected entry-header facts directly into the side row
/// (`get_template_base`, `inspected_header_end`, `slots`,
/// `get_inspected`). Called by `adapter_attributes_entry` for the Get
/// family. Retention writes go straight to the side row: the 216-byte
/// `GetEntryState` never materializes on the BPF entry path (it cannot
/// fit the 512 B chain), so the seam takes the side row itself. Host
/// oracles keep using `GetEntryState`; the G05 sim bridges it.
///
/// Retained slots pack densely; the return path derives their count from
/// the leading selected-slot prefix. The four entry-list flags occupy
/// private side bits8–11 and are masked out of every public tail copy.
#[inline(always)]
pub fn production_capture_get_entry(
    template_ptr: u64,
    count: u64,
    layout: LinuxLayout,
    side: &mut ObjectStart,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> GetEntryVerdict {
    crate::object_capture::capture_get_entry_into(template_ptr, count, layout, side, read_word)
}

/// Production GetAttributeValue return path (H7-E4 seam).
///
/// Establishes inspected Get results from the side row's retained entry
/// state and populates the emitted result list `out` (the reserved
/// tail's list, via `adapter_emit_get_attributes`). The side row arrives
/// by reference: no capture state is rebuilt on BPF. Returns the
/// inspection's `object_flag` contributions for the adapter to merge
/// into the tail flags.
///
/// Reads the side row immutably, checks every retained entry capacity for
/// aliases, then classifies one approved value and rechecks its header.
/// Failed acquisition keeps the tail fill's marked-only list.
#[inline(always)]
pub fn production_capture_get_return(
    side: &ObjectStart,
    rv: u64,
    authority: ReturnAuthority,
    layout: LinuxLayout,
    out: &mut ObjectAttributeListWire,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
    read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> u32 {
    crate::object_capture::capture_get_return_into(
        side, rv, authority, layout, out, read_word, read_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P0-degrade ship vehicle: the default build wires FULL object
    /// attribute capture. Only the `stub-object-attributes` BPF build
    /// shuts the gate; its qualification is the P0 artifact contract
    /// plus the live 1M-kernel load, never this host suite.
    #[test]
    fn default_build_wires_attribute_capture() {
        assert!(
            ATTRIBUTE_CAPTURE_WIRED,
            "default build must wire FULL attribute capture"
        );
        assert!(
            !cfg!(feature = "stub-object-attributes"),
            "host tests never run stubbed"
        );
    }
}
