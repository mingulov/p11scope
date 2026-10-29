//! SPDX-License-Identifier: GPL-2.0-only
//! Private proof roots. This module is absent from every ordinary BPF object.
//! The host proof includes its scalar policy and in-place wire writers only.

use p11scope_ebpf_common::object_journal::{
    JOURNAL_END_FULL_BYTES, JOURNAL_END_TAIL_ABSENT, JOURNAL_END_UNJOURNALED, JOURNAL_KIND_END,
    JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, JOURNAL_VERSION, JournalEndFull,
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
/// decides. There is no skip arm.
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

/// Initialize the exact header in reserved storage. Native returning supplies
/// both identity words and its finite flags, including zero UNJOURNALED words.
/// No PID/current-owner value can substitute for them.
///
/// # Safety
/// `record` is an aligned, exclusively owned 632-byte reservation; `words`
/// is the fully initialized output of the native returning function.
#[inline(always)]
pub(crate) unsafe fn initialize_end(
    record: *mut JournalEndFull,
    words: &ReturnWords,
    absent_tail: bool,
) {
    unsafe {
        core::ptr::addr_of_mut!((*record).header.version).write(JOURNAL_VERSION);
        core::ptr::addr_of_mut!((*record).header.length).write(JOURNAL_END_FULL_BYTES as u16);
        core::ptr::addr_of_mut!((*record).header.kind).write(JOURNAL_KIND_END);
        core::ptr::addr_of_mut!((*record).header.flags).write(
            words.flags as u8
                | if absent_tail {
                    JOURNAL_END_TAIL_ABSENT
                } else {
                    0
                },
        );
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
}

#[cfg(target_arch = "bpf")]
pub(super) mod program {
    use super::{
        BeginDecision, EntryContext, ReturnWords, RoutingWord, begin_decision, completion_reason,
        initialize_end,
    };
    use crate::*;
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_REASON_IDENTITY_REFUSED, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, JournalEndFull,
    };

    #[map]
    static JOURNAL_CLASSES: Array<u32> =
        Array::with_max_entries(MAX_DESCRIPTORS, BPF_F_RDONLY_PROG);

    unsafe extern "C" {
        fn p11_journal_begin(key: *const StartKey, context: *const EntryContext);
        fn p11_journal_returning(key: *const StartKey, out: *mut ReturnWords);
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
            begin(&completed.key, completed.descriptor, layout);
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
        let rc = p11_return_impl::<true>(ctx);
        stop_gate_leave();
        rc
    }

    #[inline(always)]
    pub(crate) fn gap() {
        unsafe { p11_instance_scope_gap() };
    }

    #[inline(never)]
    pub(crate) fn begin(key: &StartKey, descriptor: u32, layout: LinuxLayout) {
        let configured = JOURNAL_CLASSES.get(descriptor).copied().unwrap_or(0);
        // Irrelevant is configured explicitly and still takes the native
        // call; the native function's own validation decides. Unknown never
        // takes the Call arm.
        match begin_decision(descriptor, configured, layout) {
            BeginDecision::Call(context) => unsafe { p11_journal_begin(key, &context) },
            BeginDecision::Gap => {
                gap();
                bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
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
    ) -> u32 {
        let mut words = ReturnWords::default();
        unsafe { p11_journal_returning(key, &mut words) };
        unsafe { initialize_end(record, &words, absent) };
        completion_reason(&words)
    }

    #[inline(never)]
    pub(crate) fn ordinary_return(
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
            return 0;
        }
        let facts =
            unsafe { capture_return_facts::<true>(&ctx, &*start, flags, layout, accounting) };
        let Some(mut entry) = EVENTS.reserve::<JournalEndFull>(0) else {
            if remove(&key, true, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST) != 0 {
                unsafe { p11_object_fault() };
                bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            }
            gap();
            bump_evidence(EVIDENCE_RING_LOSS);
            return 0;
        };
        let record = entry.as_mut_ptr();
        let raw = unsafe { core::ptr::addr_of_mut!((*record).payload.base) };
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
        if !unsafe { continuity_joins(&(*raw).continuity) } {
            let outcome = preserve_refused_base(
                || remove(&key, true, JOURNAL_REASON_IDENTITY_REFUSED) == 0,
                || unsafe { p11_object_fault() },
                || EVENTS.output::<EventRecord>(unsafe { &*raw }, 0).is_ok(),
            );
            entry.discard(0);
            if outcome == RefusedBaseOutcome::OutputFailed {
                bump_evidence(EVIDENCE_RING_LOSS);
            }
            gap();
            bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            return 0;
        }
        let reason = unsafe { complete(record, &key, true) };
        if remove(&key, true, reason) != 0 {
            unsafe { p11_object_fault() };
            entry.discard(0);
            bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            return 0;
        }
        entry.submit(0);
        0
    }
}
