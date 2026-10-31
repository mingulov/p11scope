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
    attribute_table_span, authorize_derive_return, classify_derive_mechanism, find_flag,
    handle_status, object_flag, return_accepts_get_results, spans_overlap, validate_target_span,
    DeriveEntry, GetEntryVerdict, ReturnAuthority,
};
use crate::object_policy::ScalarDeriveMechanism;
use crate::object_wire::{
    object_result_arg7_address, ObjectAttributeListWire, ObjectCallWire, ObjectDescriptorWire,
    ObjectStart, OBJECT_ACTION_DECAPSULATE, OBJECT_ACTION_DERIVE, OBJECT_ACTION_ENCAPSULATE,
    OBJECT_ACTION_FIND, OBJECT_ACTION_GET, OBJECT_ACTION_MAX, OBJECT_ACTION_NONE,
    OBJECT_ATTR_LIST_UNINSPECTED, OBJECT_DERIVE_UNAVAILABLE, OBJECT_FLAGS_MASK, OBJECT_GUARD_NONE,
    OBJECT_GUARD_SCALAR_DERIVE,
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
/// (the v0.4.0 P0-only object) shuts it. While false, entry acquires
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
/// pinned by the drivers' fetch counts. Under the `stub-object-attributes`
/// build the gate below returns first and every fetch evaporates.
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
    // Closed shipping gate: acquire nothing. Every `fetch_arg` below
    // this line evaporates while the switch is false (the BPF wrapper
    // keeps only its descriptor lookup); the side keeps its
    // allocated-zero attribute state.
    if !ATTRIBUTE_CAPTURE_WIRED {
        return true;
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

/// Build flavor for T0 KEM capture: false only in the
/// `stub-object-attributes` (P0) BPF build. The KEM entry wrapper
/// passes this constant; the shared adapter takes it as a runtime
/// parameter so both branches run in the host suite.
pub const KEM_CAPTURE_WIRED: bool = !cfg!(feature = "stub-object-attributes");

/// Production KEM entry adapter body (T0): acquire the key input
/// (arg 2) and retain the scalar result pointer (arg 7) for exactly
/// the two KEM actions. Any other action returns true untouched.
/// False only on custody/row failure or a wrapping arg-7 stack
/// address (loud abandon, mirroring pair/unwrap); every other
/// refusal retains zero, which the return core maps to unreadable
/// with zero reads. Every KEM true return stores READY (phase 2):
/// the generic fill skips KEM, so this adapter advances the native
/// ENTRY binding itself; loud false returns keep ENTRY for cleanup.
///
/// `kem_wired` is the build FULL gate (P0 refuses before any
/// fetch); `output_non_null` is the owned call's validated S1
/// entry output-pointer verdict (encapsulation query shapes retain
/// no result); `null_cancel` mirrors the entry core's suppression.
/// `fetch_arg` supplies entry argument scalars (registers/stack);
/// `read_word` reads exactly one target word: the arg-7 stack slot.
/// Template headers/values, ciphertext and length values are never
/// read; args 3/4/5/6 scalars only bound span guards. Performs no
/// read for slot 1 (always absent).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn adapter_kem_entry(
    side: Option<&mut ObjectStart>,
    descriptor: u32,
    row: Option<&ObjectDescriptorWire>,
    layout: LinuxLayout,
    stack_pointer: u64,
    kem_wired: bool,
    output_non_null: bool,
    null_cancel: bool,
    fetch_arg: &mut impl FnMut(u8) -> Option<u64>,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
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
    let encapsulate = row.action == OBJECT_ACTION_ENCAPSULATE;
    if !encapsulate && row.action != OBJECT_ACTION_DECAPSULATE {
        return true;
    }
    // The ordinals below duplicate the KEM rows; refuse loudly if
    // the frozen row disagrees rather than reading the wrong args.
    if row.input_args != [2, ARG_NONE]
        || row.result_args != [7, ARG_NONE]
        || row.template_args != [ARG_NONE, ARG_NONE, ARG_NONE, ARG_NONE]
        || row.find_capacity_arg != ARG_NONE
        || row.find_count_arg != ARG_NONE
    {
        return false;
    }
    // FULL-only reads: P0 refuses before either the input or the
    // result-pointer acquisition, fetching nothing.
    if !kem_wired {
        side.inputs = [0, 0];
        side.input_statuses = [handle_status::PROTOCOL_UNAVAILABLE, handle_status::ABSENT];
        side.result_ptrs = [0, 0];
        side.phase = 2;
        return true;
    }
    // Slot-0 input rules mirror the entry core exactly.
    let mut flags = 0u32;
    let (status, word) = match fetch_arg(2) {
        None => {
            flags |= object_flag::ARG_READ_FAILURE;
            (handle_status::UNREADABLE, 0)
        }
        Some(0) => (handle_status::INVALID_ZERO, 0),
        Some(candidate) => {
            if layout == LinuxLayout::Ilp32 && candidate > u64::from(u32::MAX) {
                (handle_status::INVALID_SPAN, 0)
            } else {
                (handle_status::VALUE, candidate)
            }
        }
    };
    let (status, word) = if null_cancel && status == handle_status::VALUE {
        flags |= object_flag::NULL_MECHANISM_CANCEL;
        (handle_status::SUPPRESSED, 0)
    } else {
        (status, word)
    };
    side.inputs = [word, 0];
    side.input_statuses = [status, handle_status::ABSENT];
    side.flags = flags as u16;
    // Encapsulation query shapes retain no result pointer: only a
    // positively non-null entry ciphertext pointer authorizes the
    // output. The input scalar above stays acquired.
    if encapsulate && !output_non_null {
        side.result_ptrs = [0, 0];
        side.phase = 2;
        return true;
    }
    // The arg-7 stack address must compute before any target read;
    // a wrapping address abandons loudly like pair/unwrap.
    let Some(arg7) = object_result_arg7_address(row, stack_pointer, layout) else {
        return false;
    };
    let Ok(cell) = read_word(arg7) else {
        side.result_ptrs = [0, 0];
        side.phase = 2;
        return true;
    };
    // An invalid result-cell span retains the pointer: return marks
    // INVALID_SPAN (never reads). Overlap guards need a valid cell.
    let word_len = layout.word_bytes() as u64;
    if target_word_end(cell, layout).is_none() {
        side.result_ptrs = [cell, 0];
        side.phase = 2;
        return true;
    }
    // Template-header guard from pointer/count scalars alone: no
    // template memory is read. Unavailable bounds withhold output.
    let (Some(template_ptr), Some(template_count)) = (fetch_arg(3), fetch_arg(4)) else {
        side.result_ptrs = [0, 0];
        side.phase = 2;
        return true;
    };
    let template_len = attribute_table_span(template_count, layout).unwrap_or(0);
    if template_count != 0 {
        if template_len == 0 || validate_target_span(template_ptr, template_len, layout).is_none() {
            side.result_ptrs = [0, 0];
            side.phase = 2;
            return true;
        }
        if spans_overlap(cell, word_len, template_ptr, template_len) {
            side.result_ptrs = [0, 0];
            side.phase = 2;
            return true;
        }
    }
    // Encapsulation length-cell guard: the arg-6 address bounds one
    // word; its value is never read. A null cell has no span.
    // Decapsulation arg 6 is a scalar length, never consulted.
    if encapsulate {
        let Some(length_cell) = fetch_arg(6) else {
            side.result_ptrs = [0, 0];
            side.phase = 2;
            return true;
        };
        if length_cell != 0
            && (target_word_end(length_cell, layout).is_none()
                || spans_overlap(cell, word_len, length_cell, word_len))
        {
            side.result_ptrs = [0, 0];
            side.phase = 2;
            return true;
        }
    }
    // Ciphertext guard from the arg-5 register word alone: no
    // ciphertext byte is read, and no length is consulted (D1: the
    // encapsulation length value is unreadable by policy, and the
    // decapsulation scalar length is not an authorized bound). With
    // no authorized extent, only a result cell wholly below the
    // known buffer base is provably disjoint. Unavailable bounds
    // withhold output; the qualified input above is preserved.
    let Some(ciphertext) = fetch_arg(5) else {
        side.result_ptrs = [0, 0];
        side.phase = 2;
        return true;
    };
    if ciphertext == 0 {
        if encapsulate {
            // Contradicts the non-null S1 verdict that authorized
            // this path: the required bound is unavailable.
            side.result_ptrs = [0, 0];
            side.phase = 2;
            return true;
        }
    } else if cell
        .checked_add(word_len)
        .is_none_or(|end| end > ciphertext)
    {
        // Equality, interior overlap from below, at-or-above the
        // base with unknown extent, or an overflowing exclusive
        // end (saturation would hide the top-edge overlap):
        // disjointness unprovable.
        side.result_ptrs = [0, 0];
        side.phase = 2;
        return true;
    }
    side.result_ptrs = [cell, 0];
    side.phase = 2;
    true
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
    // Absent pairs stay all-zero. Under the stub build entry stored
    // nothing, so present pairs are marked uninspected here rather
    // than passing allocated-zero lists through as inspected.
    let mut p = 0;
    while p < 2 {
        let present =
            row.template_args[2 * p] != ARG_NONE && row.template_args[2 * p + 1] != ARG_NONE;
        if present {
            // SAFETY: `tail` is ours; `side` is a validated live map row.
            unsafe {
                let dst = core::ptr::addr_of_mut!((*tail).requested[p]);
                dst.write(side.requested[p]);
                if !ATTRIBUTE_CAPTURE_WIRED {
                    core::ptr::addr_of_mut!((*dst).flags).write(OBJECT_ATTR_LIST_UNINSPECTED);
                }
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
    // Shut gate: the stub build establishes no Get results; the tail
    // keeps the UNINSPECTED marking the fill wrote. Direct seam tests
    // execute the decoder itself.
    if !ATTRIBUTE_CAPTURE_WIRED {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            (*tail).result_attributes.flags = OBJECT_ATTR_LIST_UNINSPECTED;
        }
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

/// Outcome of retaining an ordinary return after its object join refused.
/// This is a private producer decision, not a wire value or a join grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedBaseOutcome {
    RetirementFailed,
    OutputFailed,
    Emitted,
}

/// Retire the START exactly once and fault object continuity before copying
/// the already initialized ordinary base. A failed retirement cannot emit a
/// duplicate-capable return. The caller still owns its object reservation
/// through this call and must discard it afterwards on every outcome.
#[inline(always)]
pub fn preserve_refused_base(
    remove: impl FnOnce() -> bool,
    fault: impl FnOnce(),
    output_base: impl FnOnce() -> bool,
) -> RefusedBaseOutcome {
    let retired = remove();
    fault();
    if !retired {
        RefusedBaseOutcome::RetirementFailed
    } else if output_base() {
        RefusedBaseOutcome::Emitted
    } else {
        RefusedBaseOutcome::OutputFailed
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
    extern crate alloc;
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn refused_base_requires_retirement_and_fault_before_output() {
        use core::cell::Cell;
        for (retired, output_ok, expected) in [
            (true, true, RefusedBaseOutcome::Emitted),
            (true, false, RefusedBaseOutcome::OutputFailed),
            (false, true, RefusedBaseOutcome::RetirementFailed),
            (false, false, RefusedBaseOutcome::RetirementFailed),
        ] {
            let stage = Cell::new(0);
            let outcome = preserve_refused_base(
                || {
                    assert_eq!(stage.replace(1), 0);
                    retired
                },
                || assert_eq!(stage.replace(2), 1),
                || {
                    assert_eq!(stage.replace(3), 2);
                    output_ok
                },
            );
            assert_eq!(outcome, expected);
            assert_eq!(stage.get(), if retired { 3 } else { 2 });
        }
    }

    /// One scripted entry-argument table plus fetch/read spies for the
    /// KEM entry adapter. Register fetches resolve from `args`;
    /// `reads` logs every target-word address in order.
    struct KemSpy {
        args: [(u8, Option<u64>); 7],
        fetches: Vec<u8>,
        reads: Vec<u64>,
        cell: Result<u64, ()>,
    }

    impl KemSpy {
        fn new(args: [(u8, Option<u64>); 7], cell: Result<u64, ()>) -> Self {
            Self {
                args,
                fetches: Vec::new(),
                reads: Vec::new(),
                cell,
            }
        }

        /// Run the entry adapter with fetch/read closures over
        /// disjoint spy fields, so the two `FnMut` borrows coexist.
        #[allow(clippy::too_many_arguments)]
        fn run(
            &mut self,
            side: Option<&mut ObjectStart>,
            descriptor: u32,
            row: Option<&ObjectDescriptorWire>,
            layout: LinuxLayout,
            stack_pointer: u64,
            kem_wired: bool,
            output_non_null: bool,
            null_cancel: bool,
        ) -> bool {
            let args = &self.args;
            let cell = self.cell;
            let fetches = &mut self.fetches;
            let reads = &mut self.reads;
            let mut fetch = |index: u8| {
                fetches.push(index);
                args.iter()
                    .find(|(slot, _)| *slot == index)
                    .and_then(|(_, value)| *value)
            };
            let read = |address: u64| {
                reads.push(address);
                cell
            };
            adapter_kem_entry(
                side,
                descriptor,
                row,
                layout,
                stack_pointer,
                kem_wired,
                output_non_null,
                null_cancel,
                &mut fetch,
                read,
            )
        }
    }

    fn kem_row(encapsulate: bool) -> ObjectDescriptorWire {
        crate::object_wire::canonical_object_wire(if encapsulate { 92 } else { 93 })
    }

    fn kem_descriptor(encapsulate: bool) -> u32 {
        if encapsulate {
            93
        } else {
            94
        }
    }

    // Mutation caught: a KEM input/result acquisition outside FULL, a
    // template-pointee read, or a retained result on a refused path.
    #[test]
    fn kem_entry_acquires_input_and_result_on_healthy_full_call() {
        use crate::object_capture::handle_status as hst;
        for encapsulate in [true, false] {
            for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
                let w = layout.word_bytes() as u64;
                let sp = 0x1000u64;
                let arg7 = if layout == LinuxLayout::Lp64 {
                    sp + 16
                } else {
                    sp + 32
                };
                // Disjoint guard spans: template header at 0x5000 (2
                // slots), length cell at 0x6000, result cell at 0x7000.
                let template = 0x5000u64;
                let length_cell = 0x6000u64;
                let cell = 0x7000u64;
                let mut spy = KemSpy::new(
                    [
                        (2, Some(0x1111)),
                        (3, Some(template)),
                        (4, Some(2)),
                        (5, Some(0x8000)),
                        (6, Some(length_cell)),
                        (7, None),
                        (0, None),
                    ],
                    Ok(cell),
                );
                let mut side = ObjectStart::default();
                let row = kem_row(encapsulate);
                assert!(spy.run(
                    Some(&mut side),
                    kem_descriptor(encapsulate),
                    Some(&row),
                    layout,
                    sp,
                    true,
                    true,
                    false,
                ));
                assert_eq!(side.inputs, [0x1111, 0]);
                assert_eq!(side.input_statuses, [hst::VALUE, hst::ABSENT]);
                assert_eq!(side.result_ptrs, [cell, 0]);
                assert_eq!(side.flags, 0);
                // Decap never fetches the scalar arg 6; encap fetches
                // the length-cell address as span-guard evidence only.
                // Both fetch the ciphertext base as the final guard.
                if encapsulate {
                    assert_eq!(spy.fetches, vec![2, 3, 4, 6, 5]);
                } else {
                    assert_eq!(spy.fetches, vec![2, 3, 4, 5]);
                }
                // Exactly one target read: the arg-7 stack slot. No
                // template header/value, ciphertext or length value.
                assert_eq!(spy.reads, vec![arg7]);
                assert_eq!(w, if layout == LinuxLayout::Lp64 { 8 } else { 4 });
            }
        }
    }

    // Mutation caught: a P0 KEM input or result-pointer acquisition.
    // The gate is a runtime parameter so both branches run here; the
    // BPF wrapper passes the build's KEM_CAPTURE_WIRED constant.
    #[test]
    fn kem_entry_p0_gate_refuses_before_any_fetch() {
        use crate::object_capture::handle_status as hst;
        for encapsulate in [true, false] {
            for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
                let mut spy = KemSpy::new(
                    [
                        (2, Some(0x1111)),
                        (3, Some(0x5000)),
                        (4, Some(2)),
                        (5, Some(0x8000)),
                        (6, Some(0x6000)),
                        (7, None),
                        (0, None),
                    ],
                    Ok(0x7000),
                );
                let mut side = ObjectStart::default();
                let row = kem_row(encapsulate);
                assert!(spy.run(
                    Some(&mut side),
                    kem_descriptor(encapsulate),
                    Some(&row),
                    layout,
                    0x1000,
                    false,
                    true,
                    false,
                ));
                assert!(spy.fetches.is_empty());
                assert!(spy.reads.is_empty());
                assert_eq!(side.inputs, [0, 0]);
                assert_eq!(
                    side.input_statuses,
                    [hst::PROTOCOL_UNAVAILABLE, hst::ABSENT]
                );
                assert_eq!(side.result_ptrs, [0, 0]);
            }
        }
    }

    // Mutation caught: a retained result pointer (or an arg-7 read)
    // on an encapsulation query shape. The input scalar stays
    // acquired; output authority alone is refused.
    #[test]
    fn kem_entry_query_shape_retains_no_result_pointer() {
        use crate::object_capture::handle_status as hst;
        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let mut spy = KemSpy::new(
                [
                    (2, Some(0x1111)),
                    (3, Some(0x5000)),
                    (4, Some(2)),
                    (5, Some(0)),
                    (6, Some(0x6000)),
                    (7, None),
                    (0, None),
                ],
                Ok(0x7000),
            );
            let mut side = ObjectStart::default();
            let row = kem_row(true);
            assert!(spy.run(
                Some(&mut side),
                kem_descriptor(true),
                Some(&row),
                layout,
                0x1000,
                true,
                false,
                false,
            ));
            assert_eq!(side.inputs, [0x1111, 0]);
            assert_eq!(side.input_statuses, [hst::VALUE, hst::ABSENT]);
            assert_eq!(side.result_ptrs, [0, 0]);
            assert_eq!(spy.fetches, vec![2]);
            assert!(spy.reads.is_empty());
            // Decap has no query shape: a negative output verdict
            // still retains (the scalar arg 6 is never consulted).
            let mut spy = KemSpy::new(
                [
                    (2, Some(0x1111)),
                    (3, Some(0x5000)),
                    (4, Some(2)),
                    (5, Some(0x8000)),
                    (6, Some(9)),
                    (7, None),
                    (0, None),
                ],
                Ok(0x7000),
            );
            let mut side = ObjectStart::default();
            let row = kem_row(false);
            assert!(spy.run(
                Some(&mut side),
                kem_descriptor(false),
                Some(&row),
                layout,
                0x1000,
                true,
                false,
                false,
            ));
            assert_eq!(side.result_ptrs, [0x7000, 0]);
            assert_eq!(spy.fetches, vec![2, 3, 4, 5]);
        }
    }

    // Mutation caught: a retained result on an overlapping template
    // header or length cell, on unavailable guard bounds, or on an
    // unreadable arg-7 stack word.
    #[test]
    fn kem_entry_span_and_cell_refusals_withhold_output() {
        use crate::object_capture::handle_status as hst;
        // (template ptr, count, length cell, stack cell, retain?)
        // Result cell at 0x7000 (LP64 words); template header two
        // slots (48 bytes) unless noted.
        for (variant, (template, count, length_cell, stack_cell, retain, reads)) in [
            // Template header overlap withholds.
            (
                Some(0x6FF0u64),
                Some(2u64),
                Some(0x6000u64),
                Ok(0x7000u64),
                false,
                1usize,
            ),
            // Template count overflow withholds (bound unavailable).
            (
                Some(0x5000u64),
                Some(u64::MAX),
                Some(0x6000u64),
                Ok(0x7000u64),
                false,
                1,
            ),
            // Unreadable template words withhold (bound unavailable).
            (None, Some(2u64), Some(0x6000u64), Ok(0x7000u64), false, 1),
            (
                Some(0x5000u64),
                None,
                Some(0x6000u64),
                Ok(0x7000u64),
                false,
                1,
            ),
            // Length-cell overlap withholds.
            (
                Some(0x5000u64),
                Some(2u64),
                Some(0x7004u64),
                Ok(0x7000u64),
                false,
                1,
            ),
            // Unreadable length-cell address withholds.
            (Some(0x5000u64), Some(2u64), None, Ok(0x7000u64), false, 1),
            // NULL length cell has no span: healthy retention.
            (
                Some(0x5000u64),
                Some(2u64),
                Some(0u64),
                Ok(0x7000u64),
                true,
                1,
            ),
            // Empty template authorizes no span: healthy retention.
            (
                Some(0x5000u64),
                Some(0u64),
                Some(0x6000u64),
                Ok(0x7000u64),
                true,
                1,
            ),
            // Over-cap template count still guards by arithmetic alone:
            // no reads, healthy retention when disjoint.
            (
                Some(0x5000u64),
                Some(9u64),
                Some(0x6000u64),
                Ok(0x7000u64),
                true,
                1,
            ),
            // Malformed template span (null base, nonzero count)
            // withholds: the required bound is unusable.
            (
                Some(0u64),
                Some(2u64),
                Some(0x6000u64),
                Ok(0x7000u64),
                false,
                1,
            ),
            // Unreadable arg-7 stack word retains nothing.
            (
                Some(0x5000u64),
                Some(2u64),
                Some(0x6000u64),
                Err(()),
                false,
                1,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let mut spy = KemSpy::new(
                [
                    (2, Some(0x1111)),
                    (3, template),
                    (4, count),
                    (5, Some(0x8000)),
                    (6, length_cell),
                    (7, None),
                    (0, None),
                ],
                stack_cell,
            );
            let mut side = ObjectStart::default();
            let row = kem_row(true);
            assert!(
                spy.run(
                    Some(&mut side),
                    kem_descriptor(true),
                    Some(&row),
                    LinuxLayout::Lp64,
                    0x1000,
                    true,
                    true,
                    false,
                ),
                "variant {variant}"
            );
            assert_eq!(side.inputs, [0x1111, 0], "variant {variant}");
            assert_eq!(
                side.input_statuses,
                [hst::VALUE, hst::ABSENT],
                "variant {variant}"
            );
            assert_eq!(
                side.result_ptrs,
                if retain { [0x7000, 0] } else { [0, 0] },
                "variant {variant}"
            );
            // The only target read is the arg-7 stack slot itself.
            assert_eq!(spy.reads.len(), reads, "variant {variant}");
            assert!(
                spy.reads.iter().all(|address| *address == 0x1010),
                "variant {variant}"
            );
        }
        // An invalid result-cell span retains the pointer: return
        // marks INVALID_SPAN (never reads); overlap checks need a
        // valid cell first.
        let mut spy = KemSpy::new(
            [
                (2, Some(0x1111)),
                (3, Some(0x5000)),
                (4, Some(2)),
                (5, Some(0x8000)),
                (6, Some(0x6000)),
                (7, None),
                (0, None),
            ],
            Ok(u64::MAX),
        );
        let mut side = ObjectStart::default();
        let row = kem_row(true);
        assert!(spy.run(
            Some(&mut side),
            kem_descriptor(true),
            Some(&row),
            LinuxLayout::Lp64,
            0x1000,
            true,
            true,
            false,
        ));
        assert_eq!(side.result_ptrs, [u64::MAX, 0]);
        assert_eq!(spy.reads, vec![0x1010]);
        // A wrapping arg-7 stack address refuses loudly (mirrors
        // pair/unwrap retention): the invocation abandons, no read.
        let mut spy = KemSpy::new(
            [
                (2, Some(0x1111)),
                (3, Some(0x5000)),
                (4, Some(2)),
                (5, Some(0x8000)),
                (6, Some(0x6000)),
                (7, None),
                (0, None),
            ],
            Ok(0x7000),
        );
        let mut side = ObjectStart::default();
        let row = kem_row(true);
        assert!(!spy.run(
            Some(&mut side),
            kem_descriptor(true),
            Some(&row),
            LinuxLayout::Lp64,
            u64::MAX - 15,
            true,
            true,
            false,
        ));
        assert!(spy.reads.is_empty());
    }

    // Mutation caught: KEM input rules drifting from the entry core
    // (unreadable/zero/width/null-cancel), or a touched slot 1.
    #[test]
    fn kem_entry_inputs_mirror_the_entry_core() {
        use crate::object_capture::handle_status as hst;
        use crate::object_capture::object_flag as ofl;
        for (input, layout, status, word, flags) in [
            (
                None,
                LinuxLayout::Lp64,
                hst::UNREADABLE,
                0,
                ofl::ARG_READ_FAILURE,
            ),
            (Some(0), LinuxLayout::Lp64, hst::INVALID_ZERO, 0, 0),
            (
                Some(0x1_0000_0001),
                LinuxLayout::Ilp32,
                hst::INVALID_SPAN,
                0,
                0,
            ),
            (
                Some(u32::MAX as u64),
                LinuxLayout::Ilp32,
                hst::VALUE,
                u32::MAX as u64,
                0,
            ),
        ] {
            let mut spy = KemSpy::new(
                [
                    (2, input),
                    (3, Some(0x5000)),
                    (4, Some(2)),
                    (5, Some(0x8000)),
                    (6, Some(0x6000)),
                    (7, None),
                    (0, None),
                ],
                Ok(0x7000),
            );
            let mut side = ObjectStart::default();
            let row = kem_row(true);
            assert!(spy.run(
                Some(&mut side),
                kem_descriptor(true),
                Some(&row),
                layout,
                0x1000,
                true,
                true,
                false,
            ));
            assert_eq!(side.inputs, [word, 0]);
            assert_eq!(side.input_statuses, [status, hst::ABSENT]);
            assert_eq!(side.flags, flags as u16);
        }
        // Null-mechanism cancellation suppresses a value input in place.
        let mut spy = KemSpy::new(
            [
                (2, Some(0x1111)),
                (3, Some(0x5000)),
                (4, Some(2)),
                (5, Some(0x8000)),
                (6, Some(0x6000)),
                (7, None),
                (0, None),
            ],
            Ok(0x7000),
        );
        let mut side = ObjectStart::default();
        let row = kem_row(false);
        assert!(spy.run(
            Some(&mut side),
            kem_descriptor(false),
            Some(&row),
            LinuxLayout::Lp64,
            0x1000,
            true,
            true,
            true,
        ));
        assert_eq!(side.inputs, [0, 0]);
        assert_eq!(side.input_statuses, [hst::SUPPRESSED, hst::ABSENT]);
        assert_eq!(side.flags, ofl::NULL_MECHANISM_CANCEL as u16);
        assert_eq!(side.result_ptrs, [0x7000, 0]);
    }

    // Mutation caught: KEM handling leaking onto another family, or a
    // silently accepted row/descriptor mismatch.
    #[test]
    fn kem_entry_ignores_other_families_and_mismatches() {
        let create = crate::object_wire::canonical_object_wire(20);
        let mut spy = KemSpy::new(
            [
                (2, Some(0x1111)),
                (3, Some(0x5000)),
                (4, Some(2)),
                (5, Some(0x8000)),
                (6, Some(0x6000)),
                (7, None),
                (0, None),
            ],
            Ok(0x7000),
        );
        let mut side = ObjectStart {
            inputs: [0xAAAA, 0xBBBB],
            ..ObjectStart::default()
        };
        assert!(spy.run(
            Some(&mut side),
            21,
            Some(&create),
            LinuxLayout::Lp64,
            0x1000,
            true,
            true,
            false,
        ));
        assert!(spy.fetches.is_empty());
        assert!(spy.reads.is_empty());
        assert_eq!(side.inputs, [0xAAAA, 0xBBBB]);
        assert_eq!(side.result_ptrs, [0, 0]);
        // Custody/row failures refuse loudly without touching memory.
        let row = kem_row(true);
        for (side_none, row_none, descriptor) in
            [(true, false, 93u32), (false, true, 93), (false, false, 94)]
        {
            let mut spy = KemSpy::new(
                [
                    (2, Some(0x1111)),
                    (3, Some(0x5000)),
                    (4, Some(2)),
                    (5, Some(0x8000)),
                    (6, Some(0x6000)),
                    (7, None),
                    (0, None),
                ],
                Ok(0x7000),
            );
            let mut side = ObjectStart::default();
            let side_ref = (!side_none).then_some(&mut side);
            let row_ref = (!row_none).then_some(&row);
            assert!(!spy.run(
                side_ref,
                descriptor,
                row_ref,
                LinuxLayout::Lp64,
                0x1000,
                true,
                true,
                false,
            ));
            assert!(spy.fetches.is_empty());
            assert!(spy.reads.is_empty());
        }
        // A KEM action with a non-KEM row shape refuses loudly.
        let mut bad = row;
        bad.result_args = [6, crate::ARG_NONE];
        let mut spy = KemSpy::new(
            [
                (2, Some(0x1111)),
                (3, Some(0x5000)),
                (4, Some(2)),
                (5, Some(0x8000)),
                (6, Some(0x6000)),
                (7, None),
                (0, None),
            ],
            Ok(0x7000),
        );
        let mut side = ObjectStart::default();
        assert!(!spy.run(
            Some(&mut side),
            93,
            Some(&bad),
            LinuxLayout::Lp64,
            0x1000,
            true,
            true,
            false,
        ));
        assert!(spy.fetches.is_empty());
        assert!(spy.reads.is_empty());
    }

    // Mutation caught: a KEM result-cell read on a refused path, a
    // pair/duplicate/partial rule firing with slot 1 absent, or a
    // bypass of the joined-continuity gate.
    #[test]
    fn kem_return_uses_single_result_protocol() {
        use crate::object_capture::handle_status as hst;
        use crate::object_capture::object_flag as ofl;
        for encapsulate in [true, false] {
            for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
                let row = kem_row(encapsulate);
                let descriptor = kem_descriptor(encapsulate);
                // Healthy CKR_OK: exactly one read at the retained
                // pointer; slot 1 stays absent; no pair flags.
                for (cell, status) in [(0x777u64, hst::VALUE), (0, hst::INVALID_ZERO)] {
                    let mut side = ObjectStart {
                        descriptor_index: descriptor,
                        phase: 2,
                        result_ptrs: [0x7000, 0],
                        ..ObjectStart::default()
                    };
                    let reads = core::cell::Cell::new(0u32);
                    let ok = adapter_fill_return(
                        Some(&mut side),
                        descriptor,
                        Some(&row),
                        0,
                        layout,
                        0,
                        0,
                        true,
                        |address| {
                            reads.set(reads.get() + 1);
                            assert_eq!(address, 0x7000);
                            Ok(cell)
                        },
                    );
                    assert!(ok);
                    assert_eq!(reads.get(), 1);
                    assert_eq!(side.result_statuses, [status, hst::ABSENT]);
                    assert_eq!(
                        side.result_ptrs,
                        [if status == hst::VALUE { cell } else { 0 }, 0]
                    );
                    assert_eq!(
                        side.flags
                            & (ofl::ALIAS | ofl::DUPLICATE_RESULT | ofl::PARTIAL_RESULT) as u16,
                        0
                    );
                    assert_eq!(side.phase, 3);
                }
                // Unreadable cell: finite status, never a value.
                let mut side = ObjectStart {
                    descriptor_index: descriptor,
                    phase: 2,
                    result_ptrs: [0x7000, 0],
                    ..ObjectStart::default()
                };
                assert!(adapter_fill_return(
                    Some(&mut side),
                    descriptor,
                    Some(&row),
                    0,
                    layout,
                    0,
                    0,
                    true,
                    |_| Err(()),
                ));
                assert_eq!(side.result_statuses, [hst::UNREADABLE, hst::ABSENT]);
                assert_eq!(side.result_ptrs, [0, 0]);
                // Every refused path reads nothing: non-OK RV, denied
                // continuity, null and invalid-span pointers.
                for (rv, joined, ptr) in [
                    (0x150u64, true, 0x7000u64),
                    (516u64, true, 0x7000u64),
                    (0u64, false, 0x7000u64),
                    (0u64, true, 0u64),
                    (0u64, true, u64::MAX),
                ] {
                    let mut side = ObjectStart {
                        descriptor_index: descriptor,
                        phase: 2,
                        result_ptrs: [ptr, 0],
                        ..ObjectStart::default()
                    };
                    let reads = core::cell::Cell::new(0u32);
                    let ok = adapter_fill_return(
                        Some(&mut side),
                        descriptor,
                        Some(&row),
                        rv,
                        layout,
                        0,
                        0,
                        joined,
                        |_| {
                            reads.set(reads.get() + 1);
                            Ok(0x777)
                        },
                    );
                    assert_eq!(reads.get(), 0, "rv {rv:#x} joined {joined} ptr {ptr:#x}");
                    if !joined {
                        assert!(!ok);
                    } else {
                        assert!(ok);
                        let expected = if rv != 0 {
                            hst::PROTOCOL_UNAVAILABLE
                        } else if ptr == 0 {
                            hst::UNREADABLE
                        } else {
                            hst::INVALID_SPAN
                        };
                        assert_eq!(side.result_statuses, [expected, hst::ABSENT]);
                        assert_eq!(side.result_ptrs, [0, 0]);
                    }
                }
            }
        }
    }

    // Mutation caught (M01): a KEM entry that never reaches READY
    // through the production transaction. Real native ENTRY binding
    // -> actual entry adapter -> required-side query predicate ->
    // production return -> RETURNING, for the healthy call and every
    // finite no-read refusal. The harness never repairs phase: it is
    // asserted, never written, between the two production adapters.
    // Loud failures keep ENTRY for the caller's loud cleanup.
    #[test]
    fn kem_entry_to_return_preserves_native_phase() {
        use crate::object_capture::handle_status as hst;
        // Exact native ENTRY writes (task_owner.c): descriptor,
        // action, image pair, entry stamp, OBJECT_PHASE_ENTRY.
        fn native_entry_side(descriptor: u32, action: u8) -> ObjectStart {
            ObjectStart {
                image: ImageIdentity {
                    task_cookie: 0xC0FF_EE00_C0FF_EE00,
                    exec_id: 0xE9EC_1D00_E9EC_1D00,
                },
                entry_ns: 0x1111_2222_3333_4444,
                descriptor_index: descriptor,
                action,
                phase: 1,
                ..ObjectStart::default()
            }
        }
        // Exact native phase predicate on the required-side query
        // path (task_owner.c): ENTRY/READY/RETURNING pass the range
        // check; a required query additionally demands READY.
        fn required_side_admits(side: &ObjectStart) -> bool {
            matches!(side.phase, 1..=3) && side.phase == 2
        }
        // (encapsulate, layout, template ptr, template count, arg 6,
        // stack cell, kem wired, output non-null, retained result,
        // return reads, return status)
        for (
            variant,
            (
                encapsulate,
                layout,
                template,
                count,
                arg6,
                stack_cell,
                kem_wired,
                output_non_null,
                retained,
                return_reads,
                return_status,
            ),
        ) in [
            // Healthy FULL calls retain the result cell.
            (
                true,
                LinuxLayout::Lp64,
                Some(0x5000u64),
                Some(2u64),
                Some(0x6000u64),
                Ok(0x7000u64),
                true,
                true,
                0x7000u64,
                1u32,
                hst::VALUE,
            ),
            (
                true,
                LinuxLayout::Ilp32,
                Some(0x5000u64),
                Some(2u64),
                Some(0x6000u64),
                Ok(0x7000u64),
                true,
                true,
                0x7000u64,
                1,
                hst::VALUE,
            ),
            (
                false,
                LinuxLayout::Lp64,
                Some(0x5000u64),
                Some(2u64),
                Some(9u64),
                Ok(0x7000u64),
                true,
                true,
                0x7000u64,
                1,
                hst::VALUE,
            ),
            (
                false,
                LinuxLayout::Ilp32,
                Some(0x5000u64),
                Some(2u64),
                Some(9u64),
                Ok(0x7000u64),
                true,
                true,
                0x7000u64,
                1,
                hst::VALUE,
            ),
            // P0 finite refusals read nothing.
            (
                true,
                LinuxLayout::Lp64,
                Some(0x5000u64),
                Some(2u64),
                Some(0x6000u64),
                Ok(0x7000u64),
                false,
                true,
                0u64,
                0,
                hst::UNREADABLE,
            ),
            (
                false,
                LinuxLayout::Ilp32,
                Some(0x5000u64),
                Some(2u64),
                Some(9u64),
                Ok(0x7000u64),
                false,
                true,
                0,
                0,
                hst::UNREADABLE,
            ),
            // Encapsulation query shapes keep the input only.
            (
                true,
                LinuxLayout::Lp64,
                Some(0x5000u64),
                Some(2u64),
                Some(0x6000u64),
                Ok(0x7000u64),
                true,
                false,
                0,
                0,
                hst::UNREADABLE,
            ),
            (
                true,
                LinuxLayout::Ilp32,
                Some(0x5000u64),
                Some(2u64),
                Some(0x6000u64),
                Ok(0x7000u64),
                true,
                false,
                0,
                0,
                hst::UNREADABLE,
            ),
            // Template-header overlap withholds output.
            (
                true,
                LinuxLayout::Lp64,
                Some(0x6FF0u64),
                Some(2u64),
                Some(0x6000u64),
                Ok(0x7000u64),
                true,
                true,
                0,
                0,
                hst::UNREADABLE,
            ),
            // Length-cell overlap withholds output.
            (
                true,
                LinuxLayout::Lp64,
                Some(0x5000u64),
                Some(2u64),
                Some(0x7004u64),
                Ok(0x7000u64),
                true,
                true,
                0,
                0,
                hst::UNREADABLE,
            ),
            // An unreadable arg-7 stack word retains nothing.
            (
                false,
                LinuxLayout::Lp64,
                Some(0x5000u64),
                Some(2u64),
                Some(9u64),
                Err(()),
                true,
                true,
                0,
                0,
                hst::UNREADABLE,
            ),
            // An invalid result-cell span retains the pointer;
            // return marks INVALID_SPAN without reading.
            (
                true,
                LinuxLayout::Lp64,
                Some(0x5000u64),
                Some(2u64),
                Some(0x6000u64),
                Ok(u64::MAX),
                true,
                true,
                u64::MAX,
                0,
                hst::INVALID_SPAN,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let row = kem_row(encapsulate);
            let descriptor = kem_descriptor(encapsulate);
            let mut spy = KemSpy::new(
                [
                    (2, Some(0x1111)),
                    (3, template),
                    (4, count),
                    (5, Some(0x8000)),
                    (6, arg6),
                    (7, None),
                    (0, None),
                ],
                stack_cell,
            );
            let mut side = native_entry_side(descriptor, row.action);
            assert!(
                spy.run(
                    Some(&mut side),
                    descriptor,
                    Some(&row),
                    layout,
                    0x1000,
                    kem_wired,
                    output_non_null,
                    false,
                ),
                "variant {variant}"
            );
            // The production entry transaction advances ENTRY to
            // READY; the native binding survives the adapter.
            assert_eq!(side.phase, 2, "variant {variant}");
            assert!(required_side_admits(&side), "variant {variant}");
            assert_eq!(side.descriptor_index, descriptor, "variant {variant}");
            assert_eq!(side.action, row.action, "variant {variant}");
            assert_eq!(
                side.image.task_cookie, 0xC0FF_EE00_C0FF_EE00,
                "variant {variant}"
            );
            assert_eq!(
                side.image.exec_id, 0xE9EC_1D00_E9EC_1D00,
                "variant {variant}"
            );
            assert_eq!(side.entry_ns, 0x1111_2222_3333_4444, "variant {variant}");
            assert_eq!(side.result_ptrs, [retained, 0], "variant {variant}");
            // The same row flows into the production return: one
            // result read on the healthy path, zero on every
            // finite refusal, then RETURNING.
            let reads = core::cell::Cell::new(0u32);
            assert!(
                adapter_fill_return(
                    Some(&mut side),
                    descriptor,
                    Some(&row),
                    0,
                    layout,
                    0,
                    0,
                    true,
                    |address| {
                        reads.set(reads.get() + 1);
                        assert_eq!(address, 0x7000, "variant {variant}");
                        Ok(0x777)
                    },
                ),
                "variant {variant}"
            );
            assert_eq!(reads.get(), return_reads, "variant {variant}");
            assert_eq!(
                side.result_statuses,
                [return_status, hst::ABSENT],
                "variant {variant}"
            );
            assert_eq!(
                side.result_ptrs,
                [
                    if return_status == hst::VALUE {
                        0x777
                    } else {
                        0
                    },
                    0
                ],
                "variant {variant}"
            );
            assert_eq!(side.phase, 3, "variant {variant}");
        }
        // A wrapping arg-7 stack address refuses loudly: ENTRY is
        // kept for the caller's loud cleanup, never READY.
        let row = kem_row(true);
        let descriptor = kem_descriptor(true);
        let mut spy = KemSpy::new(
            [
                (2, Some(0x1111)),
                (3, Some(0x5000)),
                (4, Some(2)),
                (5, Some(0x8000)),
                (6, Some(0x6000)),
                (7, None),
                (0, None),
            ],
            Ok(0x7000),
        );
        let mut side = native_entry_side(descriptor, row.action);
        assert!(!spy.run(
            Some(&mut side),
            descriptor,
            Some(&row),
            LinuxLayout::Lp64,
            u64::MAX - 15,
            true,
            true,
            false,
        ));
        assert!(spy.reads.is_empty());
        assert_eq!(side.phase, 1);
        assert!(!required_side_admits(&side));
        // Other families pass through untouched: no phase store
        // leaks onto a row the generic fill owns.
        let mut other = kem_row(true);
        other.action = OBJECT_ACTION_DERIVE;
        let mut spy = KemSpy::new(
            [
                (2, Some(0x1111)),
                (3, Some(0x5000)),
                (4, Some(2)),
                (5, Some(0x8000)),
                (6, Some(0x6000)),
                (7, None),
                (0, None),
            ],
            Ok(0x7000),
        );
        let mut side = native_entry_side(descriptor, other.action);
        assert!(spy.run(
            Some(&mut side),
            descriptor,
            Some(&other),
            LinuxLayout::Lp64,
            0x1000,
            true,
            true,
            false,
        ));
        assert_eq!(side.phase, 1);
        assert_eq!(side.inputs, [0, 0]);
        assert_eq!(side.result_ptrs, [0, 0]);
        assert!(spy.fetches.is_empty());
        assert!(spy.reads.is_empty());
    }

    // Mutation caught (M02): a retained result on a detectable
    // ciphertext/result alias, or on an unavailable ciphertext
    // bound. Equality, interior overlap, at-or-above-base geometry
    // with unknown extent, unreadable arg 5 and a null
    // contradicting the non-null S1 verdict all withhold output;
    // only a result cell wholly below the known buffer base (or a
    // null decapsulation input, which has no span) retains. The
    // only target read in every leg is the arg-7 stack slot: no
    // ciphertext byte, length value, mechanism or template read.
    // The qualified input survives every output-only refusal.
    #[test]
    fn kem_entry_ciphertext_span_refusals_withhold_output() {
        use crate::object_capture::handle_status as hst;
        // Exact native ENTRY writes (task_owner.c): descriptor,
        // action, image pair, entry stamp, OBJECT_PHASE_ENTRY.
        fn native_entry_side(descriptor: u32, action: u8) -> ObjectStart {
            ObjectStart {
                image: ImageIdentity {
                    task_cookie: 0xC0FF_EE00_C0FF_EE00,
                    exec_id: 0xE9EC_1D00_E9EC_1D00,
                },
                entry_ns: 0x1111_2222_3333_4444,
                descriptor_index: descriptor,
                action,
                phase: 1,
                ..ObjectStart::default()
            }
        }
        // (encapsulate, layout, arg 5, stack cell, retain?)
        // Withhold legs first: variant 0 is the named RED
        // assertion pre-fix. Template header (0x5000, two slots)
        // and length cell (0x6000) stay disjoint in every leg, so
        // only the ciphertext guard fires.
        for (variant, (encapsulate, layout, arg5, stack_cell, retain)) in [
            // Equality: phKey == pCiphertext withholds.
            (true, LinuxLayout::Lp64, Some(0x7000u64), 0x7000u64, false),
            (false, LinuxLayout::Ilp32, Some(0x7000u64), 0x7000u64, false),
            // Interior overlap from below withholds.
            (true, LinuxLayout::Lp64, Some(0x7004u64), 0x7000u64, false),
            (false, LinuxLayout::Lp64, Some(0x7007u64), 0x7000u64, false),
            // At or above the base with unknown extent withholds.
            (true, LinuxLayout::Lp64, Some(0x6800u64), 0x7000u64, false),
            (false, LinuxLayout::Ilp32, Some(0x6800u64), 0x7000u64, false),
            // An unavailable ciphertext bound withholds.
            (true, LinuxLayout::Lp64, None, 0x7000u64, false),
            (false, LinuxLayout::Ilp32, None, 0x7000u64, false),
            // A null contradicting the non-null S1 verdict
            // withholds: the required bound is unavailable.
            (true, LinuxLayout::Lp64, Some(0u64), 0x7000u64, false),
            // Top-edge interior overlap withholds.
            (
                true,
                LinuxLayout::Lp64,
                Some(u64::MAX - 3),
                u64::MAX - 7,
                false,
            ),
            // Healthy disjoint input/output retains, both
            // functions and ABIs.
            (true, LinuxLayout::Lp64, Some(0x8000u64), 0x7000u64, true),
            (true, LinuxLayout::Ilp32, Some(0x8000u64), 0x7000u64, true),
            (false, LinuxLayout::Lp64, Some(0x8000u64), 0x7000u64, true),
            (false, LinuxLayout::Ilp32, Some(0x8000u64), 0x7000u64, true),
            // Touching the base is disjoint: the cell ends where
            // the buffer begins.
            (true, LinuxLayout::Lp64, Some(0x7008u64), 0x7000u64, true),
            (false, LinuxLayout::Ilp32, Some(0x7004u64), 0x7000u64, true),
            // Top-edge saturated overlap withholds: the cell's
            // inclusive last byte is the ciphertext's first byte,
            // and the overflowing exclusive end refuses.
            (true, LinuxLayout::Lp64, Some(u64::MAX), u64::MAX - 7, false),
            // Top-edge cell wholly below the base retains.
            (true, LinuxLayout::Lp64, Some(u64::MAX), u64::MAX - 8, true),
            // A null decapsulation input has no span: retains.
            (false, LinuxLayout::Lp64, Some(0u64), 0x7000u64, true),
        ]
        .into_iter()
        .enumerate()
        {
            let row = kem_row(encapsulate);
            let descriptor = kem_descriptor(encapsulate);
            let arg7 = if layout == LinuxLayout::Lp64 {
                0x1010u64
            } else {
                0x1020u64
            };
            let mut spy = KemSpy::new(
                [
                    (2, Some(0x1111)),
                    (3, Some(0x5000)),
                    (4, Some(2)),
                    (5, arg5),
                    (6, if encapsulate { Some(0x6000) } else { Some(9) }),
                    (7, None),
                    (0, None),
                ],
                Ok(stack_cell),
            );
            let mut side = native_entry_side(descriptor, row.action);
            assert!(
                spy.run(
                    Some(&mut side),
                    descriptor,
                    Some(&row),
                    layout,
                    0x1000,
                    true,
                    true,
                    false,
                ),
                "variant {variant}"
            );
            // The ciphertext guard withholds the result pointer
            // while the qualified input and READY survive.
            assert_eq!(
                side.result_ptrs,
                if retain { [stack_cell, 0] } else { [0, 0] },
                "variant {variant}"
            );
            assert_eq!(side.phase, 2, "variant {variant}");
            assert_eq!(side.inputs, [0x1111, 0], "variant {variant}");
            assert_eq!(
                side.input_statuses,
                [hst::VALUE, hst::ABSENT],
                "variant {variant}"
            );
            // Approved guard evidence only: input, template
            // scalars, the encapsulation length-cell address, and
            // the ciphertext base. The arg-7 stack slot is the one
            // target read: no ciphertext, length-value, mechanism
            // or template read anywhere.
            assert_eq!(
                spy.fetches,
                if encapsulate {
                    alloc::vec![2, 3, 4, 6, 5]
                } else {
                    alloc::vec![2, 3, 4, 5]
                },
                "variant {variant}"
            );
            assert_eq!(spy.reads, alloc::vec![arg7], "variant {variant}");
            // The same row flows into the production return: one
            // result read on the disjoint path, zero on every
            // withheld path, then RETURNING.
            let reads = core::cell::Cell::new(0u32);
            assert!(
                adapter_fill_return(
                    Some(&mut side),
                    descriptor,
                    Some(&row),
                    0,
                    layout,
                    0,
                    0,
                    true,
                    |address| {
                        reads.set(reads.get() + 1);
                        assert_eq!(address, stack_cell, "variant {variant}");
                        Ok(0x777)
                    },
                ),
                "variant {variant}"
            );
            assert_eq!(reads.get(), u32::from(retain), "variant {variant}");
            assert_eq!(
                side.result_statuses,
                [
                    if retain { hst::VALUE } else { hst::UNREADABLE },
                    hst::ABSENT
                ],
                "variant {variant}"
            );
            assert_eq!(side.phase, 3, "variant {variant}");
        }
    }

    // The build flavor gates acquisition through the actual
    // KEM_CAPTURE_WIRED constant, never a literal: FULL builds
    // acquire exactly; P0 builds acquire nothing. Runs in both
    // configurations (the P0 cell runs this selector plus the
    // finite controls, never the FULL positives).
    #[test]
    fn kem_build_flavor_precedes_acquisition() {
        let p0 = cfg!(feature = "stub-object-attributes");
        assert_eq!(KEM_CAPTURE_WIRED, !p0, "flavor constant matches the build");
        for (encapsulate, layout) in [
            (true, LinuxLayout::Lp64),
            (true, LinuxLayout::Ilp32),
            (false, LinuxLayout::Lp64),
            (false, LinuxLayout::Ilp32),
        ] {
            let row = kem_row(encapsulate);
            let descriptor = kem_descriptor(encapsulate);
            let mut spy = KemSpy::new(
                [
                    (2, Some(0x1111)),
                    (3, Some(0x5000)),
                    (4, Some(2)),
                    (5, Some(0x8000)),
                    (6, if encapsulate { Some(0x6000) } else { Some(9) }),
                    (7, None),
                    (0, None),
                ],
                Ok(0x7000),
            );
            let mut side = ObjectStart {
                phase: 1,
                ..ObjectStart::default()
            };
            assert!(spy.run(
                Some(&mut side),
                descriptor,
                Some(&row),
                layout,
                0x1000,
                KEM_CAPTURE_WIRED,
                true,
                false,
            ));
            // Both flavors advance ENTRY to READY through the
            // production adapter; only FULL acquires.
            assert_eq!(side.phase, 2);
            if p0 {
                assert!(spy.fetches.is_empty(), "P0 fetches nothing");
                assert!(spy.reads.is_empty(), "P0 reads nothing");
                assert_eq!(side.inputs, [0, 0]);
                assert_eq!(side.result_ptrs, [0, 0]);
            } else {
                assert_eq!(
                    spy.fetches,
                    if encapsulate {
                        alloc::vec![2, 3, 4, 6, 5]
                    } else {
                        alloc::vec![2, 3, 4, 5]
                    }
                );
                assert_eq!(side.inputs, [0x1111, 0]);
                assert_eq!(side.result_ptrs, [0x7000, 0]);
            }
        }
    }

    // Duplicate, stale and lost KEM returns refuse with zero
    // reads: a consumed (RETURNING) row, an unadvanced (ENTRY)
    // row, a lost side, a mismatched descriptor and a foreign
    // phase never reach the result reader. No read precedes any
    // refusal.
    #[test]
    fn kem_return_duplicate_stale_and_custody_zero_reads() {
        use crate::object_capture::handle_status as hst;
        let row = kem_row(true);
        let descriptor = kem_descriptor(true);
        // The healthy route first: ENTRY -> READY -> one result
        // read -> RETURNING.
        let mut spy = KemSpy::new(
            [
                (2, Some(0x1111)),
                (3, Some(0x5000)),
                (4, Some(2)),
                (5, Some(0x8000)),
                (6, Some(0x6000)),
                (7, None),
                (0, None),
            ],
            Ok(0x7000),
        );
        let mut side = ObjectStart {
            phase: 1,
            ..ObjectStart::default()
        };
        assert!(spy.run(
            Some(&mut side),
            descriptor,
            Some(&row),
            LinuxLayout::Lp64,
            0x1000,
            true,
            true,
            false,
        ));
        assert_eq!(side.phase, 2);
        let reads = core::cell::Cell::new(0u32);
        let read = |address: u64| {
            reads.set(reads.get() + 1);
            assert_eq!(address, 0x7000);
            Ok(0x777)
        };
        assert!(adapter_fill_return(
            Some(&mut side),
            descriptor,
            Some(&row),
            0,
            LinuxLayout::Lp64,
            0,
            0,
            true,
            read,
        ));
        assert_eq!(reads.get(), 1);
        assert_eq!(side.result_statuses, [hst::VALUE, hst::ABSENT]);
        assert_eq!(side.phase, 3);
        // A duplicate return on the consumed row refuses.
        let read = |address: u64| {
            reads.set(reads.get() + 1);
            assert_eq!(address, 0x7000);
            Ok(0x777)
        };
        assert!(!adapter_fill_return(
            Some(&mut side),
            descriptor,
            Some(&row),
            0,
            LinuxLayout::Lp64,
            0,
            0,
            true,
            read,
        ));
        assert_eq!(reads.get(), 1, "duplicate return reads nothing");
        assert_eq!(side.phase, 3);
        // A stale return on an unadvanced ENTRY row refuses: the
        // row never reached READY (finding 1's pre-fix state).
        let mut stale = ObjectStart {
            phase: 1,
            ..ObjectStart::default()
        };
        stale.result_ptrs = [0x7000, 0];
        let read = |address: u64| {
            reads.set(reads.get() + 1);
            assert_eq!(address, 0x7000);
            Ok(0x777)
        };
        assert!(!adapter_fill_return(
            Some(&mut stale),
            descriptor,
            Some(&row),
            0,
            LinuxLayout::Lp64,
            0,
            0,
            true,
            read,
        ));
        assert_eq!(reads.get(), 1, "stale return reads nothing");
        // A lost side refuses.
        let read = |_: u64| {
            reads.set(reads.get() + 1);
            Ok(0x777)
        };
        assert!(!adapter_fill_return(
            None,
            descriptor,
            Some(&row),
            0,
            LinuxLayout::Lp64,
            0,
            0,
            true,
            read,
        ));
        assert_eq!(reads.get(), 1, "lost side reads nothing");
        // A mismatched descriptor refuses without reading.
        let mut side = ObjectStart {
            phase: 2,
            ..ObjectStart::default()
        };
        side.result_ptrs = [0x7000, 0];
        let read = |_: u64| {
            reads.set(reads.get() + 1);
            Ok(0x777)
        };
        assert!(!adapter_fill_return(
            Some(&mut side),
            descriptor,
            Some(&kem_row(false)),
            0,
            LinuxLayout::Lp64,
            0,
            0,
            true,
            read,
        ));
        assert_eq!(reads.get(), 1, "custody mismatch reads nothing");
        // A foreign phase refuses without reading.
        let mut side = ObjectStart {
            phase: 9,
            ..ObjectStart::default()
        };
        side.result_ptrs = [0x7000, 0];
        let read = |_: u64| {
            reads.set(reads.get() + 1);
            Ok(0x777)
        };
        assert!(!adapter_fill_return(
            Some(&mut side),
            descriptor,
            Some(&row),
            0,
            LinuxLayout::Lp64,
            0,
            0,
            true,
            read,
        ));
        assert_eq!(reads.get(), 1, "foreign phase reads nothing");
        // An unjoined return on a live READY row refuses before any
        // read: loss of continuity never advances the row. Both
        // families; the S1 verdict is irrelevant to the gate.
        for encapsulate in [true, false] {
            let lrow = kem_row(encapsulate);
            let ldescriptor = kem_descriptor(encapsulate);
            let mut lspy = KemSpy::new(
                [
                    (2, Some(0x1111)),
                    (3, Some(0x5000)),
                    (4, Some(2)),
                    (5, Some(0x8000)),
                    (6, Some(0x6000)),
                    (7, None),
                    (0, None),
                ],
                Ok(0x7000),
            );
            let mut lside = ObjectStart {
                phase: 1,
                ..ObjectStart::default()
            };
            assert!(lspy.run(
                Some(&mut lside),
                ldescriptor,
                Some(&lrow),
                LinuxLayout::Lp64,
                0x1000,
                true,
                true,
                false,
            ));
            assert_eq!(lside.phase, 2);
            let lreads = core::cell::Cell::new(0u32);
            assert!(!adapter_fill_return(
                Some(&mut lside),
                ldescriptor,
                Some(&lrow),
                0,
                LinuxLayout::Lp64,
                0,
                0,
                false,
                |_: u64| {
                    lreads.set(lreads.get() + 1);
                    Ok(0x777)
                },
            ));
            assert_eq!(lreads.get(), 0, "unjoined loss reads nothing");
            assert_eq!(lside.phase, 2, "unjoined loss advances nothing");
        }
        // Full-width boundary twins: the return read preserves full
        // words exactly (no truncation, no masking); over-wide words
        // on Ilp32 mark INVALID_SPAN with a zero word. The read itself
        // is attempted once in every leg.
        for (encapsulate, layout, word, status) in [
            (
                true,
                LinuxLayout::Lp64,
                0xFFFF_FFFF_FFFF_FFFFu64,
                hst::VALUE,
            ),
            (
                true,
                LinuxLayout::Lp64,
                0x8000_0000_0000_0000u64,
                hst::VALUE,
            ),
            (
                false,
                LinuxLayout::Lp64,
                0xFFFF_FFFF_FFFF_FFFFu64,
                hst::VALUE,
            ),
            (
                false,
                LinuxLayout::Lp64,
                0x8000_0000_0000_0000u64,
                hst::VALUE,
            ),
            (true, LinuxLayout::Ilp32, 0xFFFF_FFFFu64, hst::VALUE),
            (
                true,
                LinuxLayout::Ilp32,
                0x1_0000_0000u64,
                hst::INVALID_SPAN,
            ),
            (false, LinuxLayout::Ilp32, 0xFFFF_FFFFu64, hst::VALUE),
            (
                false,
                LinuxLayout::Ilp32,
                0x1_0000_0000u64,
                hst::INVALID_SPAN,
            ),
        ] {
            let brow = kem_row(encapsulate);
            let bdescriptor = kem_descriptor(encapsulate);
            let mut bspy = KemSpy::new(
                [
                    (2, Some(0x1111)),
                    (3, Some(0x5000)),
                    (4, Some(2)),
                    (5, Some(0x8000)),
                    (6, Some(0x6000)),
                    (7, None),
                    (0, None),
                ],
                Ok(0x7000),
            );
            let mut bside = ObjectStart {
                phase: 1,
                ..ObjectStart::default()
            };
            assert!(bspy.run(
                Some(&mut bside),
                bdescriptor,
                Some(&brow),
                layout,
                0x1000,
                true,
                true,
                false,
            ));
            assert_eq!(bside.phase, 2);
            let breads = core::cell::Cell::new(0u32);
            assert!(adapter_fill_return(
                Some(&mut bside),
                bdescriptor,
                Some(&brow),
                0,
                layout,
                0,
                0,
                true,
                |address: u64| {
                    breads.set(breads.get() + 1);
                    assert_eq!(address, 0x7000);
                    Ok(word)
                },
            ));
            assert_eq!(breads.get(), 1, "boundary word read once");
            assert_eq!(
                bside.result_statuses,
                [status, hst::ABSENT],
                "boundary status"
            );
            assert_eq!(
                bside.result_ptrs,
                [if status == hst::VALUE { word } else { 0 }, 0],
                "boundary word preserved or zeroed"
            );
            assert_eq!(bside.phase, 3);
        }
    }

    /// Emission-tail custody gate: malformed custody refuses without
    /// touching the tail; field values pass through verbatim for
    /// downstream validation. Both KEM families; the tail carries no
    /// find/requested sections for KEM rows.
    #[test]
    fn kem_tail_fill_refuses_malformed_custody() {
        use crate::object_capture::handle_status as hst;
        use crate::object_wire::ObjectCallWire;
        for encapsulate in [true, false] {
            let row = kem_row(encapsulate);
            let descriptor = kem_descriptor(encapsulate);
            let mut side = ObjectStart {
                phase: 3,
                descriptor_index: descriptor,
                layout: crate::object_wire::OBJECT_LAYOUT_LP64,
                action: row.action,
                inputs: [0x1111, 0],
                input_statuses: [hst::VALUE, hst::ABSENT],
                result_ptrs: [0x42, 0],
                result_statuses: [hst::VALUE, hst::ABSENT],
                ..ObjectStart::default()
            };
            // Healthy RETURNING side fills: header, handles and
            // statuses carried verbatim; KEM sections stay zero.
            let mut tail = ObjectCallWire::default();
            assert!(unsafe {
                adapter_tail_fill(&mut tail as *mut _, Some(&side), descriptor, Some(&row))
            });
            assert_eq!((tail.version, tail.bytes), (1, 240));
            assert_eq!(tail.descriptor_index, descriptor);
            assert_eq!(tail.action, row.action);
            assert_eq!(tail.input_handles, [0x1111, 0]);
            assert_eq!(tail.input_status, [hst::VALUE, hst::ABSENT]);
            assert_eq!(tail.result_handles, [0x42, 0]);
            assert_eq!(tail.result_status, [hst::VALUE, hst::ABSENT]);
            assert_eq!(tail.find_handles, [0; 8]);
            assert_eq!(tail.find_len, 0);
            // Malformed custody refuses; the tail stays untouched.
            for phase in [1u8, 2, 9] {
                side.phase = phase;
                let mut refused = ObjectCallWire::default();
                assert!(!unsafe {
                    adapter_tail_fill(&mut refused as *mut _, Some(&side), descriptor, Some(&row))
                });
                assert_eq!(refused.version, 0, "phase {phase} writes nothing");
            }
            side.phase = 3;
            let mut refused = ObjectCallWire::default();
            assert!(!unsafe {
                adapter_tail_fill(&mut refused as *mut _, None, descriptor, Some(&row))
            });
            assert_eq!(refused.version, 0, "lost side writes nothing");
            assert!(!unsafe {
                adapter_tail_fill(core::ptr::null_mut(), Some(&side), descriptor, Some(&row))
            });
            let mut refused = ObjectCallWire::default();
            assert!(!unsafe {
                adapter_tail_fill(
                    &mut refused as *mut _,
                    Some(&side),
                    descriptor + 1,
                    Some(&row),
                )
            });
            assert_eq!(refused.version, 0, "descriptor mismatch writes nothing");
            let mut refused = ObjectCallWire::default();
            assert!(!unsafe {
                adapter_tail_fill(&mut refused as *mut _, Some(&side), descriptor, None)
            });
            assert_eq!(refused.version, 0, "missing row writes nothing");
            let mut refused = ObjectCallWire::default();
            assert!(!unsafe {
                adapter_tail_fill(
                    &mut refused as *mut _,
                    Some(&side),
                    descriptor,
                    Some(&kem_row(!encapsulate)),
                )
            });
            assert_eq!(refused.version, 0, "sibling-family row writes nothing");
        }
    }

    /// P0-only ship vehicle: the default build wires FULL object
    /// attribute capture. Only the `stub-object-attributes` BPF build
    /// shuts the gate; its qualification is the P0 artifact contract
    /// plus the live 1M-kernel load, never this host suite. Gated
    /// out of P0 builds so the feature-selected cell compiles and
    /// runs its actual-constant and finite controls.
    #[test]
    #[cfg(not(feature = "stub-object-attributes"))]
    fn default_build_wires_attribute_capture() {
        const {
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
}
