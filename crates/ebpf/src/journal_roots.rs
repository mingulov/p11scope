//! SPDX-License-Identifier: GPL-2.0-only
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Distinct journal roots. This module is absent from every non-journal BPF
//! object; proof and production journal selections link the same roots.
//! The host proof includes its scalar policy and in-place wire writers only.

use p11scope_ebpf_common::object_journal::{
    JOURNAL_END_FULL_BYTES, JOURNAL_END_LENGTH_BYTES, JOURNAL_END_TAIL_ABSENT,
    JOURNAL_END_UNJOURNALED, JOURNAL_KIND_END, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
    JOURNAL_VERSION, JournalEndFull, JournalEndLength, LengthTrailer,
};
use p11scope_ebpf_common::{Event, LinuxLayout, MAX_DESCRIPTORS};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EntryContext {
    pub descriptor: u32,
    pub class_bits: u32,
    pub layout: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct ReturnWords {
    pub thread: u64,
    pub sequence: u64,
    pub flags: u32,
    pub pad: u32,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoutingWord {
    PidTgid = 0,
    Cgroup = 1,
    RootAffiliation = 2,
}

/// Sample and immediately initialize each non-target routing word in owned
/// storage. No routing scalar must survive the next sampler or reservation.
///
/// # Safety
/// `event` is the exclusively owned, aligned Event in the live reservation.
#[inline(always)]
pub(crate) unsafe fn fill_routing(event: *mut Event, mut sample: impl FnMut(RoutingWord) -> u64) {
    unsafe {
        core::ptr::addr_of_mut!((*event).pid_tgid).write(sample(RoutingWord::PidTgid));
        core::ptr::addr_of_mut!((*event).cgroup_id).write(sample(RoutingWord::Cgroup));
        core::ptr::addr_of_mut!((*event).root_affiliation)
            .write(sample(RoutingWord::RootAffiliation));
    }
}

const _: () = {
    assert!(core::mem::size_of::<EntryContext>() == 16);
    assert!(core::mem::size_of::<ReturnWords>() == 24);
    assert!(core::mem::offset_of!(ReturnWords, flags) == 16);
    assert!(core::mem::offset_of!(ReturnWords, pad) == 20);
};

/// The private frozen array uses zero for UNKNOWN, deliberately distinct from
/// native class zero (proved irrelevant). No raw semantic flag enters here.
#[inline(always)]
pub(crate) fn entry_context(
    descriptor: u32,
    configured_class: u32,
    layout: LinuxLayout,
) -> Option<EntryContext> {
    if descriptor == 0 || descriptor >= MAX_DESCRIPTORS {
        return None;
    }
    let class_bits = match configured_class {
        1 => 0,
        2 => 1,
        3 => 2,
        _ => return None,
    };
    Some(EntryContext {
        descriptor,
        class_bits,
        layout: match layout {
            LinuxLayout::Lp64 => 1,
            LinuxLayout::Ilp32 => 2,
        },
        reserved: 0,
    })
}

/// Pure BEGIN custody decision shared by the BPF root and the host proof.
/// Every valid context calls the native BEGIN function, including
/// proved-irrelevant class zero; the native function's own validation
/// decides. The narrowed (switched-slot) arm lives in
/// [`begin_action`], never here: this frozen decision keeps mapping
/// descriptor 0 to Gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BeginDecision {
    Call(EntryContext),
    Gap,
}

#[inline(always)]
pub(crate) fn begin_decision(
    descriptor: u32,
    configured_class: u32,
    layout: LinuxLayout,
) -> BeginDecision {
    match entry_context(descriptor, configured_class, layout) {
        Some(context) => BeginDecision::Call(context),
        None => BeginDecision::Gap,
    }
}

/// BEGIN custody action shared by the BPF root and the host proof:
/// the frozen [`begin_decision`] plus the in-place downgrade (A′)
/// narrowed arm. A switched slot skips silently only for a
/// proved-irrelevant configured class; an affecting (or unknown)
/// class gaps without semantic-capture-failure evidence, since an
/// intended narrowing is not a capture failure but its history is
/// honestly incomplete. Anything unswitched — including a planned
/// descriptor 0, and a descriptor 0 seen with the bit set (a planned
/// slot over a stale switch) — keeps the frozen decision, Gap with
/// evidence included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BeginAction {
    Skip,
    Call(EntryContext),
    Gap { evidence: bool },
}

#[inline(always)]
pub(crate) fn begin_action(
    switched: bool,
    descriptor: u32,
    configured_class: u32,
    layout: LinuxLayout,
) -> BeginAction {
    // Only a downgraded cookie descriptor narrows: a set bit with
    // descriptor 0 is a planned slot, never a downgrade (a downgrade
    // keeps its nonzero link cookie), so it keeps today's Gap path.
    if switched && descriptor != 0 {
        return match configured_class {
            1 => BeginAction::Skip,
            _ => BeginAction::Gap { evidence: false },
        };
    }
    match begin_decision(descriptor, configured_class, layout) {
        BeginDecision::Call(context) => BeginAction::Call(context),
        BeginDecision::Gap => BeginAction::Gap { evidence: true },
    }
}

/// Pure completion-reason decision shared by the BPF root and the host
/// proof. A refused phase already reported its actual loss; a named reason
/// avoids reason-zero's second loss on an unsettled row.
#[inline(always)]
pub(crate) fn completion_reason(words: &ReturnWords) -> u32 {
    if words.flags & u32::from(JOURNAL_END_UNJOURNALED) != 0 {
        JOURNAL_REASON_SYNC_RETURN_RESULT_LOST
    } else {
        0
    }
}

/// Checked END flag conversion: only the finite Rust-validated END bits
/// survive into the header byte. Any unknown bit — including any bit at
/// or above 0x100 from a future native leaf — refuses instead of
/// truncating, so the writer can only emit validatable headers.
#[inline(always)]
fn end_flags_byte(flags: u32, absent_tail: bool) -> Option<u8> {
    if flags & !(u32::from(JOURNAL_END_TAIL_ABSENT | JOURNAL_END_UNJOURNALED)) != 0 {
        return None;
    }
    let narrowed = u8::try_from(flags).ok()?;
    Some(
        narrowed
            | if absent_tail {
                JOURNAL_END_TAIL_ABSENT
            } else {
                0
            },
    )
}

/// Initialize the exact header in reserved storage. Native returning supplies
/// both identity words and its finite flags, including zero UNJOURNALED words.
/// No PID/current-owner value can substitute for them. Returns false without
/// writing any byte when the flag conversion refuses; the caller must treat
/// the reservation as uninitialized and refuse the record.
///
/// # Safety
/// `record` is an aligned, exclusively owned 632-byte reservation; `words`
/// is the fully initialized output of the native returning function.
#[inline(always)]
pub(crate) unsafe fn initialize_end(
    record: *mut JournalEndFull,
    words: &ReturnWords,
    absent_tail: bool,
) -> bool {
    let Some(flags) = end_flags_byte(words.flags, absent_tail) else {
        return false;
    };
    unsafe {
        core::ptr::addr_of_mut!((*record).header.version).write(JOURNAL_VERSION);
        core::ptr::addr_of_mut!((*record).header.length).write(JOURNAL_END_FULL_BYTES as u16);
        core::ptr::addr_of_mut!((*record).header.kind).write(JOURNAL_KIND_END);
        core::ptr::addr_of_mut!((*record).header.flags).write(flags);
        core::ptr::addr_of_mut!((*record).header.reserved).write(0);
        core::ptr::addr_of_mut!((*record).header.thread).write(words.thread);
        core::ptr::addr_of_mut!((*record).header.sequence).write(words.sequence);
        if absent_tail {
            // Volatile stores stay leaf-flat, like adapter_tail_fill: no
            // implicit memset call and no 240-byte temporary on the stack.
            let tail = core::ptr::addr_of_mut!((*record).payload.object).cast::<u64>();
            macro_rules! zero {
                ($($word:expr),+ $(,)?) => { $(tail.add($word).write_volatile(0);)+ };
            }
            zero!(
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29
            );
        }
    }
    true
}

/// Initialize the exact 648-byte header + trailer in reserved storage:
/// the shared [`initialize_end`] writes the 632-byte prefix (the two
/// forms share the header layout and the absent-tail rule), then the
/// length field is corrected and the carried trailer stored. Returns
/// false without writing any byte when the flag conversion refuses;
/// the caller must treat the reservation as uninitialized and refuse
/// the record.
///
/// # Safety
/// `record` is an aligned, exclusively owned 648-byte reservation;
/// `words` is the fully initialized output of the native returning
/// function; `trailer` is the resolved length trailer.
#[cfg_attr(feature = "stub-object-attributes", allow(dead_code))]
#[inline(always)]
pub(crate) unsafe fn initialize_end_length(
    record: *mut JournalEndLength,
    words: &ReturnWords,
    absent_tail: bool,
    trailer: &LengthTrailer,
) -> bool {
    if !unsafe { initialize_end(record.cast(), words, absent_tail) } {
        return false;
    }
    unsafe {
        core::ptr::addr_of_mut!((*record).header.length).write(JOURNAL_END_LENGTH_BYTES as u16);
        core::ptr::addr_of_mut!((*record).trailer).write(*trailer);
    }
    true
}

#[cfg(target_arch = "bpf")]
pub(super) mod program {
    use super::{
        BeginAction, EntryContext, ReturnWords, RoutingWord, begin_action, completion_reason,
        initialize_end, initialize_end_length,
    };
    use crate::*;
    use p11scope_ebpf_common::object_flow::join_refusal_bump;
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_REASON_IDENTITY_REFUSED, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, JournalEndFull,
        LengthTrailer,
    };

    #[map]
    static JOURNAL_CLASSES: Array<u32> =
        Array::with_max_entries(MAX_DESCRIPTORS, BPF_F_RDONLY_PROG);

    unsafe extern "C" {
        fn p11_journal_begin(key: *const StartKey, context: *const EntryContext) -> u32;
        fn p11_journal_returning(key: *const StartKey, out: *mut ReturnWords) -> u32;
        fn p11_owner_start_remove_reason(key: *const StartKey, required: u32, reason: u32) -> i64;
    }

    #[uprobe]
    pub fn p11_entry_journal(ctx: ProbeContext) -> u32 {
        keep_endpoint_stack(&ctx);
        if !stop_gate_enter() {
            return 0;
        }
        let mut completed = CompletedEntry::default();
        capture_entry(ctx, &mut completed);
        if completed.completed == 1 && completed.reserved == 0 {
            let layout = match completed.layout {
                1 => LinuxLayout::Lp64,
                2 => LinuxLayout::Ilp32,
                _ => {
                    gap();
                    bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
                    stop_gate_leave();
                    return 0;
                }
            };
            begin(
                &completed.key,
                completed.descriptor,
                layout,
                completed.switched != 0,
            );
        }
        stop_gate_leave();
        0
    }

    // The capture frame has returned before BEGIN reserves or constructs its
    // own native facts. The token is actual construction success, never a
    // lookup of an older START under the same numeric key.
    #[inline(never)]
    fn capture_entry(ctx: ProbeContext, completed: *mut CompletedEntry) {
        let _ = p11_entry_impl::<0, ENTRY_ABI_MIXED, true>(ctx, completed);
    }

    #[uretprobe]
    pub fn p11_return_journal(ctx: RetProbeContext) -> u32 {
        keep_endpoint_stack(&ctx);
        if !stop_gate_enter() {
            return 0;
        }
        let rc = p11_return_impl::<true, false>(ctx);
        stop_gate_leave();
        rc
    }

    #[inline(always)]
    pub(crate) fn gap() {
        unsafe { p11_instance_scope_gap() };
    }

    #[inline(never)]
    pub(crate) fn begin(key: &StartKey, descriptor: u32, layout: LinuxLayout, switched: bool) {
        // In-place downgrade (A′): the skip consults the slot's
        // switch bit, never the descriptor alone. A switched slot
        // skips BEGIN silently only for a proved-irrelevant class;
        // an affecting class gaps without evidence (an intended
        // narrowing is not a capture failure, but its history is
        // honestly incomplete). A planned descriptor 0 keeps today's
        // Gap path with evidence. Counts stay exact through STATS in
        // every arm, and a never-begun call completes as an
        // UNJOURNALED END, the pre-existing shape for count-only
        // slots. Controller rulings 2026-11-16 07:43 (REPLACE-INPLACE
        // B1b) and 14:57 (t3 B2/I1).
        let configured = JOURNAL_CLASSES.get(descriptor).copied().unwrap_or(0);
        // Irrelevant is configured explicitly and still takes the native
        // call; the native function's own validation decides. Unknown never
        // takes the Call arm.
        match begin_action(switched, descriptor, configured, layout) {
            BeginAction::Skip => {}
            BeginAction::Call(context) => {
                unsafe { p11_journal_begin(key, &context) };
            }
            BeginAction::Gap { evidence } => {
                gap();
                if evidence {
                    bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
                }
            }
        }
    }

    #[inline(always)]
    pub(crate) fn remove(key: &StartKey, required: bool, reason: u32) -> i64 {
        unsafe { p11_owner_start_remove_reason(key, u32::from(required), reason) }
    }

    #[inline(always)]
    pub(crate) unsafe fn route(event: *mut Event) {
        unsafe {
            super::fill_routing(event, |word| match word {
                RoutingWord::PidTgid => helpers::bpf_get_current_pid_tgid(),
                RoutingWord::Cgroup => helpers::bpf_get_current_cgroup_id(),
                RoutingWord::RootAffiliation => p11_root_current_tag(),
            });
        }
    }

    impl ReturnPayload for JournalEndFull {
        const LENGTH: bool = false;
        #[inline(always)]
        unsafe fn payload(record: *mut Self) -> *mut ObjectEventRecord {
            unsafe { core::ptr::addr_of_mut!((*record).payload) }
        }
    }

    #[inline(always)]
    pub(crate) unsafe fn complete(
        record: *mut JournalEndFull,
        key: &StartKey,
        absent: bool,
    ) -> Option<u32> {
        let mut words = ReturnWords::default();
        unsafe { p11_journal_returning(key, &mut words) };
        if unsafe { initialize_end(record, &words, absent) } {
            Some(completion_reason(&words))
        } else {
            None
        }
    }

    #[inline(never)]
    pub(crate) fn ordinary_return<Record: ReturnPayload>(
        ctx: RetProbeContext,
        key: &StartKey,
        start: *const CallStart,
        flags: u64,
        layout: LinuxLayout,
    ) -> u32 {
        let key = *key;
        let accounting = account_return(&ctx, key.slot, unsafe { (*start).ts_ns }, layout);
        if flags & FLAG_POLICY_AGGREGATE != 0 {
            if remove(&key, true, 0) != 0 {
                unsafe { p11_object_fault() };
                bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            }
            // Every return path deletes the stash row (journal
            // sessions never run aggregate today; this keeps the
            // branch consistent for the day one does).
            if Record::LENGTH {
                length_return_abandon(&key);
            }
            return 0;
        }
        let mut image = ImageIdentity::default();
        if unsafe { p11_link_current_identity(&mut image) } != 1
            || !image_pair_matches(unsafe { (*start).image }, image)
        {
            if remove(&key, true, JOURNAL_REASON_IDENTITY_REFUSED) != 0 {
                unsafe { p11_object_fault() };
                bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            }
            gap();
            bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
            if Record::LENGTH {
                length_return_abandon(&key);
            }
            return 0;
        }
        let facts =
            unsafe { capture_return_facts::<true>(&ctx, &*start, flags, layout, accounting) };
        let Some(mut entry) = EVENTS.reserve::<Record>(0) else {
            if remove(&key, true, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST) != 0 {
                unsafe { p11_object_fault() };
                bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            }
            gap();
            bump_evidence(EVIDENCE_RING_LOSS);
            if Record::LENGTH {
                length_return_abandon(&key);
            }
            return 0;
        };
        let record = entry.as_mut_ptr();
        let raw = unsafe { core::ptr::addr_of_mut!((*Record::payload(record)).base) };
        unsafe {
            fill_call_event(
                core::ptr::addr_of_mut!((*raw).event),
                &*start,
                key.slot,
                &facts,
            );
            route(core::ptr::addr_of_mut!((*raw).event));
            let _ = p11_instance_return(&key, core::ptr::addr_of_mut!((*raw).continuity));
        }
        if Record::LENGTH {
            // Sync START rows leave target_function FUNCTION_NONE, but
            // the trailer validator matches the kind against the
            // function-addressed evidence row: stamp the
            // cookie-derived ordinal so the 648 decodes. The root's
            // length dispatch guarantees a valid length descriptor
            // (misrouted and narrowed endpoints degrade to the base
            // flow before this runs), so descriptor - 1 is in range.
            let descriptor = cookie_descriptor(cookie_of(&ctx));
            unsafe {
                core::ptr::addr_of_mut!((*raw).event.target_function).write(descriptor - 1);
            }
        }
        let joined = unsafe { continuity_joins(&(*raw).continuity) };
        if !joined {
            // Decide accounting before the discard below invalidates
            // `raw`: both reads are pure (reservation bytes, cell).
            let bump = join_refusal_bump(unsafe { &(*raw).continuity }, unsafe {
                p11_instance_coverage_cell()
            });
            let outcome = preserve_refused_base(
                || remove(&key, true, JOURNAL_REASON_IDENTITY_REFUSED) == 0,
                || unsafe { p11_object_fault() },
                || {
                    let ok = EVENTS.output::<EventRecord>(unsafe { &*raw }, 0).is_ok();
                    if ok {
                        bump_produced(PRODUCED_EVENTS);
                    }
                    ok
                },
            );
            entry.discard(0);
            if outcome == RefusedBaseOutcome::OutputFailed {
                bump_evidence(EVIDENCE_RING_LOSS);
            }
            gap();
            // Retired starts are matched (their base was emitted above):
            // only a failed retirement is a return without a recorded
            // start. The coverage gate silences retired joins when
            // continuity was never active; a failed retirement still
            // reports unmatched on every coverage state.
            let (unmatched, semantic) = refused_join_accounting(outcome, bump);
            if unmatched {
                bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            }
            if semantic {
                bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
            }
            if Record::LENGTH {
                length_return_abandon(&key);
            }
            return 0;
        }
        // Length trailer (spec §8.2/§8.3): resolve the retained
        // evidence now that the join gate passed (no target read
        // before the join), and complete the matching END form. Base
        // records fold the dummy trailer away unused.
        let trailer = if Record::LENGTH {
            length_trailer_for_return(&key, &ctx, accounting.rv, layout, joined)
        } else {
            LengthTrailer {
                version: 0,
                kind: 0,
                status: 0,
                reserved: [0; 4],
                value: 0,
            }
        };
        let completed = if Record::LENGTH {
            unsafe { complete_length(record.cast(), &key, true, &trailer) }
        } else {
            unsafe { complete(record.cast(), &key, true) }
        };
        let Some(reason) = completed else {
            // The flag conversion refused: the reservation holds no
            // header, so it can never submit. Retire the call like a
            // lost result, then gap, mirroring the reserve-failure arm.
            if remove(&key, true, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST) != 0 {
                unsafe { p11_object_fault() };
                bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            }
            entry.discard(0);
            gap();
            bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
            return 0;
        };
        if remove(&key, true, reason) != 0 {
            unsafe { p11_object_fault() };
            entry.discard(0);
            bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            return 0;
        }
        entry.submit(0);
        bump_produced(PRODUCED_EVENTS);
        0
    }

    // Length programs (v0.8.0 keymeta Task 2, spec §8.6): the same
    // journal BEGIN/END protocol as the base pair, plus the §8.2 length
    // adapters into EVIDENCE_START and the 648 END+length form. Loaded
    // and linked only with --key-sizes (attach-time routing); the P0
    // journal flavor omits them, so without the flag the length code is
    // never even verified. Everything length-specific lives below this
    // marker: the base region above references no adapter or stash
    // (pinned by the Task 2 contracts case).
    #[cfg(not(feature = "stub-object-attributes"))]
    use core::ffi::c_void;
    use p11scope_ebpf_common::acquire_length_entry_args;
    #[cfg(not(feature = "stub-object-attributes"))]
    use p11scope_ebpf_common::evidence_table::length_entry_descriptor;
    use p11scope_ebpf_common::evidence_table::{
        LENGTH_KIND_SCELL, length_entry_fetch_mask, length_kind_for_descriptor,
    };
    use p11scope_ebpf_common::object_flow::{
        EvidenceStart, LengthReturnVerdict, adapter_length_entry, adapter_length_return,
    };
    use p11scope_ebpf_common::object_journal::{JournalEndLength, length_trailer_for_verdict};
    use p11scope_ebpf_common::{EVIDENCE_LENGTH_INSERT_FAILURES, EVIDENCE_LENGTH_STASH_MISMATCHES};

    #[cfg_attr(feature = "stub-object-attributes", allow(dead_code))]
    impl ReturnPayload for JournalEndLength {
        const LENGTH: bool = true;
        #[inline(always)]
        unsafe fn payload(record: *mut Self) -> *mut ObjectEventRecord {
            unsafe { core::ptr::addr_of_mut!((*record).payload) }
        }
    }

    #[cfg(not(feature = "stub-object-attributes"))]
    #[uprobe]
    pub fn p11_entry_journal_length(ctx: ProbeContext) -> u32 {
        keep_endpoint_stack(&ctx);
        if !stop_gate_enter() {
            return 0;
        }
        // Rebuilt below for argument fetch after the shared entry
        // consumes `ctx` (ProbeContext is move-only): the regs pointer
        // stays valid for the whole probe invocation.
        let regs = ctx.regs as *mut c_void;
        let mut completed = CompletedEntry::default();
        capture_entry(ctx, &mut completed);
        if completed.completed == 1 && completed.reserved == 0 {
            let layout = match completed.layout {
                1 => LinuxLayout::Lp64,
                2 => LinuxLayout::Ilp32,
                _ => {
                    gap();
                    bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
                    stop_gate_leave();
                    return 0;
                }
            };
            begin(
                &completed.key,
                completed.descriptor,
                layout,
                completed.switched != 0,
            );
            let ctx = ProbeContext::new(regs);
            // Narrowed slots keep the link but lose semantic capture:
            // the stash resolves descriptor 0, so the adapter refuses
            // and the call still counts without length evidence.
            let descriptor = length_entry_descriptor(completed.descriptor, completed.switched != 0);
            stash_length_entry(&ctx, &completed.key, descriptor, layout);
        }
        stop_gate_leave();
        0
    }

    /// Run the length entry adapter and bind the stash row: insert on
    /// retention (overwrite), delete on unavailable (a stale row is
    /// never trusted), count full-map insert failures. The START
    /// timestamp binds the return (fix9 R4); a missing row binds zero,
    /// which the return mismatches (fail closed). Outlined (not
    /// inlined): the 32-byte row, the fetched argument array and
    /// the adapter spills stay out of the root frame, keeping the
    /// entry call chain inside the unmodified 512-byte bound.
    ///
    /// Acquisition is bounded by the row's entry-fetch mask: a zero
    /// mask (count-only, narrowed, unlisted, corrupt, info) deletes
    /// any stale row and returns before the first fetch, and every
    /// fetch runs through the shared `acquire_length_entry_args`
    /// with a compile-time-constant literal index guarded by its
    /// mask bit. Index 0 is never an approved length position and
    /// is never fetched.
    #[cfg_attr(feature = "stub-object-attributes", allow(dead_code))]
    #[inline(never)]
    fn stash_length_entry(
        ctx: &ProbeContext,
        key: &StartKey,
        descriptor: u32,
        layout: LinuxLayout,
    ) {
        // Refuse before any acquisition: the mask names exactly the
        // approved argument words for this descriptor, and zero
        // deletes any stale row without touching target memory.
        let mask = length_entry_fetch_mask(descriptor);
        if mask == 0 {
            let _ = EVIDENCE_START.remove(key);
            return;
        }
        let start_ts_ns = unsafe { p11_owner_start_get(key, 0).as_ref() }.map(|start| start.ts_ns);
        let mut row = EvidenceStart::default();
        // One shared guarded fetch expression: each masked position
        // arrives with a compile-time-constant literal index (a
        // dynamic index into `arg_u64` becomes register-offset
        // pt_regs arithmetic, `ctx += reg`, which the verifier
        // rejects with "dereference of modified ctx ptr" on
        // 6.6/6.12/7.0). Slots 1..=5 are the LP64 registers; 6 is
        // the SP+8 stack slot (spec §8.2). Words start zeroed
        // beside a validity mask: a `None` payload is undef, and
        // LLVM spills the stale R0 as that payload, which the
        // verifier rejects (`R0 !read_ok`). The fetch closure only
        // indexes these arrays, never `arg_u64`.
        let mut words = [0u64; 7];
        let mut present: u8 = 0;
        acquire_length_entry_args!(arg_u64, ctx, layout, mask, words, present);
        let mut fetch = |index: u8| {
            if index < 7 && present & (1 << index) != 0 {
                Some(words[index as usize])
            } else {
                None
            }
        };
        if !adapter_length_entry(
            &mut row,
            descriptor,
            layout,
            start_ts_ns.unwrap_or(0),
            &mut fetch,
            BpfReader,
        ) {
            let _ = EVIDENCE_START.remove(key);
            return;
        }
        if EVIDENCE_START.insert(key, &row, 0).is_err() {
            bump_evidence(EVIDENCE_LENGTH_INSERT_FAILURES);
        }
    }

    #[cfg(not(feature = "stub-object-attributes"))]
    #[uretprobe]
    pub fn p11_return_journal_length(ctx: RetProbeContext) -> u32 {
        keep_endpoint_stack(&ctx);
        if !stop_gate_enter() {
            return 0;
        }
        // Length dispatch: only length endpoints take the length path; a
        // misrouted endpoint degrades to the base flow with a valid base
        // END instead of losing the completion.
        let descriptor = cookie_descriptor(cookie_of(&ctx));
        if length_kind_for_descriptor(descriptor).is_none() {
            let rc = p11_return_impl::<true, false>(ctx);
            stop_gate_leave();
            return rc;
        }
        let rc = p11_return_impl::<true, true>(ctx);
        stop_gate_leave();
        rc
    }

    /// Resolve the length trailer for one return: copy the stash row and
    /// delete it unconditionally (every emission deletes), then resolve
    /// the START stamp and feed the return adapter (RV + owned
    /// lifetime). A missing row resolves unavailable with zero reads
    /// and never consults the stamp; a refused join resolves
    /// unavailable the same way the adapter would; a stamp/layout
    /// mismatch bumps its own counter. The kind re-derives from the
    /// same cookie the root dispatched on, so the fallback below is
    /// dead (kept fail-closed: a wrong kind refuses at validation).
    /// Called only after the join gate passed.
    #[cfg_attr(feature = "stub-object-attributes", allow(dead_code))]
    #[inline(always)]
    pub(crate) fn length_trailer_for_return(
        key: &StartKey,
        ctx: &RetProbeContext,
        rv: u64,
        layout: LinuxLayout,
        joined: bool,
    ) -> LengthTrailer {
        let stash = EVIDENCE_START.get_ptr(key).map(|row| unsafe { *row });
        let _ = EVIDENCE_START.remove(key);
        let descriptor = cookie_descriptor(cookie_of(ctx));
        let kind = length_kind_for_descriptor(descriptor).unwrap_or(LENGTH_KIND_SCELL);
        let Some(stash) = stash else {
            return length_trailer_for_verdict(kind, LengthReturnVerdict::Unavailable);
        };
        if !joined {
            return length_trailer_for_verdict(kind, LengthReturnVerdict::Unavailable);
        }
        // An explicit null branch, never an as_ref().map chain: LLVM
        // merges the chained null check with the adapter's downstream
        // flag arithmetic into a bitwise OR on the map pointer
        // itself, which the verifier rejects. The bump (a map
        // helper) keeps this a real branch. A missing START stamp
        // mismatches (fail closed), exactly as the adapter's None
        // arm would.
        let start = unsafe { p11_owner_start_get(key, 0) };
        if start.is_null() {
            bump_evidence(EVIDENCE_LENGTH_STASH_MISMATCHES);
            return length_trailer_for_verdict(kind, LengthReturnVerdict::StashMismatch);
        }
        let verdict = adapter_length_return(
            &stash,
            Some(unsafe { (*start).ts_ns }),
            rv,
            layout,
            joined,
            BpfReader,
        );
        if verdict == LengthReturnVerdict::StashMismatch {
            bump_evidence(EVIDENCE_LENGTH_STASH_MISMATCHES);
        }
        length_trailer_for_verdict(kind, verdict)
    }

    #[cfg_attr(feature = "stub-object-attributes", allow(dead_code))]
    #[inline(always)]
    pub(crate) unsafe fn complete_length(
        record: *mut JournalEndLength,
        key: &StartKey,
        absent: bool,
        trailer: &LengthTrailer,
    ) -> Option<u32> {
        let mut words = ReturnWords::default();
        unsafe { p11_journal_returning(key, &mut words) };
        if unsafe { initialize_end_length(record, &words, absent, trailer) } {
            Some(completion_reason(&words))
        } else {
            None
        }
    }
}
