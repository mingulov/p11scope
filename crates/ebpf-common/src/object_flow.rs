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

use crate::instance;
use crate::object_capture::{
    authorize_derive_return, classify_derive_mechanism, find_flag, handle_status, object_flag,
    spans_overlap, validate_target_span, AttributeListOutcome, DeriveEntry, GetEntryState,
    GetEntryVerdict, ReturnAuthority,
};
use crate::object_policy::ScalarDeriveMechanism;
use crate::object_wire::{
    ObjectCallWire, ObjectDescriptorWire, ObjectStart, OBJECT_ACTION_DERIVE, OBJECT_ACTION_FIND,
    OBJECT_ACTION_GET, OBJECT_ACTION_MAX, OBJECT_ACTION_NONE, OBJECT_ATTR_LIST_UNINSPECTED,
    OBJECT_GUARD_NONE, OBJECT_GUARD_SCALAR_DERIVE,
};
use crate::{target_word_end, InstanceContinuity, LinuxLayout, ARG_NONE};

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
// Nine scalar parameters map 1:1 to the BPF wrapper's register-passed
// arguments; bundling them into a struct would risk wrapper stack the
// 512-byte return chain does not have.
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
        core::ptr::addr_of_mut!((*tail).flags).write(u32::from(side.flags));
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
    // Requested lists: BPF performs no entry template inspection (no
    // chain budget for it), so present pairs carry the honest
    // uninspected marker; absent pairs stay all-zero.
    let mut p = 0;
    while p < 2 {
        let present =
            row.template_args[2 * p] != ARG_NONE && row.template_args[2 * p + 1] != ARG_NONE;
        if present {
            // SAFETY: `tail` is ours; `side` is a validated live map row.
            unsafe {
                let dst = core::ptr::addr_of_mut!((*tail).requested[p]);
                dst.write(side.requested[p]);
                core::ptr::addr_of_mut!((*dst).flags).write(OBJECT_ATTR_LIST_UNINSPECTED);
            }
        }
        p += 1;
    }
    // Get result lists are return-inspected only; slice D runs no Get
    // protocol in BPF, so a Get tail marks its result list uninspected
    // rather than claiming an inspected-empty result.
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
/// TODAY (E4 unwired): inspects nothing — performs zero reads and returns
/// the zero outcome. Present pairs then carry the UNINSPECTED marking (see
/// `adapter_tail_fill`). A budgeted E4 implements the approved bounded
/// in-place inspection HERE with this exact signature (same vectors, same
/// readers); G05 passes unmodified when it does. G05 additionally
/// requires production-tail emission of the outcome and a production
/// call edge to this seam (forwarding alone stays RED).
pub fn production_inspect_request_template(
    template_ptr: u64,
    count: u64,
    peer: Option<(u64, u64)>,
    layout: LinuxLayout,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
    read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> AttributeListOutcome {
    let _ = (template_ptr, count, peer, layout);
    let _ = (read_word, read_bytes);
    AttributeListOutcome::default()
}

/// Production GetAttributeValue entry path (H7-E4 seam).
///
/// TODAY (E4 unwired): retains nothing — performs zero reads, leaves
/// `state` untouched and returns the zero verdict. A budgeted E4 retains
/// selected headers HERE with this exact signature; G05 passes
/// unmodified when it does. G05 additionally requires a production call
/// edge to this seam (forwarding alone stays RED).
pub fn production_capture_get_entry(
    template_ptr: u64,
    count: u64,
    layout: LinuxLayout,
    state: &mut GetEntryState,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> GetEntryVerdict {
    let _ = (template_ptr, count, layout);
    let _ = state;
    let _ = read_word;
    GetEntryVerdict::default()
}

/// Production GetAttributeValue return path (H7-E4 seam).
///
/// TODAY (E4 unwired): establishes nothing — performs zero reads and
/// returns the zero outcome. A budgeted E4 establishes inspected results
/// HERE with this exact signature (same retained state, same readers);
/// G05 passes unmodified when it does. G05 additionally requires a
/// production call edge to this seam (forwarding alone stays RED).
pub fn production_capture_get_return(
    state: &GetEntryState,
    rv: u64,
    authority: ReturnAuthority,
    layout: LinuxLayout,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
    read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> AttributeListOutcome {
    let _ = (state, rv, authority, layout);
    let _ = (read_word, read_bytes);
    AttributeListOutcome::default()
}
