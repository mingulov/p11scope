//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private host proof of native custody plus the actual root wire writers.
//! No Session/loader path imports this child or its fixture library.

use super::{EndpointClass, end_agrees_with_begin, endpoint_class};
use p11scope_ebpf_common::object_capture::handle_status;
use p11scope_ebpf_common::object_flow::{
    RefusedBaseOutcome, ReturnEventFacts, adapter_emit_find_control, adapter_emit_get_control,
    adapter_fill_return_control, adapter_tail_fill, continuity_joins, emission_finalize,
    encode_return_gate, fill_call_event, preserve_refused_base,
};
use p11scope_ebpf_common::object_journal::{
    JOURNAL_END_FULL_BYTES, JOURNAL_END_UNJOURNALED, JOURNAL_REASON_IDENTITY_REFUSED,
    JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, JournalEndFull, JournalRecord, decode_journal_record,
};
use p11scope_ebpf_common::object_wire::{
    ObjectCallWire, ObjectDescriptorWire, ObjectStart, publish_object_descriptors,
};
use p11scope_ebpf_common::{
    ARG_NONE, CallStart, EventRecord, LinuxLayout, MAX_DESCRIPTORS, StartKey, capture,
};
use std::{cell::Cell, ffi::CStr, process::Command};

#[path = "../../../crates/ebpf/src/journal_roots.rs"]
mod root_writers;

/// Construct once, then expose only immutable descriptor lookups. The values
/// come from the actual private userspace classifier, never a copied census.
struct FrozenClasses([u32; MAX_DESCRIPTORS as usize]);

impl FrozenClasses {
    fn new() -> Self {
        Self(std::array::from_fn(|descriptor| {
            if descriptor == 0 {
                return 0;
            }
            match endpoint_class(descriptor as u32 - 1) {
                Some(EndpointClass::ProvedIrrelevant) => 1,
                Some(EndpointClass::ModeledAffecting) => 2,
                Some(EndpointClass::NegativeOnlyAffecting) => 3,
                None => 0,
            }
        }))
    }

    fn get(&self, descriptor: u32) -> u32 {
        self.0.get(descriptor as usize).copied().unwrap_or(0)
    }
}

#[test]
fn private_root_class_array_uses_the_frozen_endpoint_classifier() {
    let classes = FrozenClasses::new();
    let mut counts = [0usize; 4];
    for descriptor in 1..MAX_DESCRIPTORS {
        let class = classes.get(descriptor);
        counts[class as usize] += 1;
        assert!(root_writers::entry_context(descriptor, class, LinuxLayout::Lp64).is_some());
    }
    assert_eq!(counts, [0, 19, 76, 9]);
    for descriptor in [0, MAX_DESCRIPTORS, u32::MAX] {
        assert_eq!(classes.get(descriptor), 0);
        assert!(root_writers::entry_context(descriptor, 0, LinuxLayout::Lp64).is_none());
    }
}

struct Bridge {
    _temporary: tempfile::TempDir,
    handle: *mut libc::c_void,
    setup: unsafe extern "C" fn(u32, u32, u32, u32, u32),
    row: unsafe extern "C" fn(u32) -> *mut libc::c_void,
    object_descriptor: unsafe extern "C" fn(*const ObjectDescriptorWire),
    begin: unsafe extern "C" fn(*const root_writers::EntryContext),
    returning: unsafe extern "C" fn(*mut root_writers::ReturnWords),
    remove: unsafe extern "C" fn(u32) -> libc::c_long,
    cleanup: unsafe extern "C" fn() -> u32,
    aggregate: unsafe extern "C" fn(),
    fail: unsafe extern "C" fn(u32),
    loss: unsafe extern "C" fn(u32),
    reserve: unsafe extern "C" fn(u32) -> *mut JournalEndFull,
    submit: unsafe extern "C" fn(*mut JournalEndFull),
    discard: unsafe extern "C" fn(*mut JournalEndFull),
    continuity: unsafe extern "C" fn(*mut p11scope_ebpf_common::InstanceContinuity, u32),
    routing: unsafe extern "C" fn(u32) -> u64,
    record: unsafe extern "C" fn(u32, *mut u32) -> *const u8,
    status: unsafe extern "C" fn(*mut u64),
}

impl Bridge {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let library = temporary.path().join("bridge.so");
        let output = Command::new("clang-18")
            .args([
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
                "-fPIC",
                "-shared",
                "-Wl,-z,defs",
                "-DP11SCOPE_OBJECT_JOURNAL",
                "-I",
                "crates/ebpf/native",
                "tests/fixtures/object-journal/journal_roots_bridge.c",
                "-o",
            ])
            .arg(&library)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let path = std::ffi::CString::new(library.as_os_str().as_encoded_bytes()).unwrap();
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        assert!(!handle.is_null(), "load compiled native fixture adapter");
        unsafe fn symbol<T: Copy>(handle: *mut libc::c_void, name: &CStr) -> T {
            let pointer = unsafe { libc::dlsym(handle, name.as_ptr()) };
            assert!(!pointer.is_null(), "missing fixture interface {name:?}");
            assert_eq!(std::mem::size_of::<T>(), std::mem::size_of_val(&pointer));
            unsafe { std::mem::transmute_copy(&pointer) }
        }
        unsafe {
            Self {
                _temporary: temporary,
                handle,
                setup: symbol(handle, c"roots_setup"),
                row: symbol(handle, c"roots_row"),
                object_descriptor: symbol(handle, c"roots_object_descriptor"),
                begin: symbol(handle, c"roots_begin"),
                returning: symbol(handle, c"roots_returning"),
                remove: symbol(handle, c"roots_remove"),
                cleanup: symbol(handle, c"roots_cleanup"),
                aggregate: symbol(handle, c"roots_aggregate"),
                fail: symbol(handle, c"roots_fail"),
                loss: symbol(handle, c"roots_loss"),
                reserve: symbol(handle, c"roots_reserve"),
                submit: symbol(handle, c"roots_submit"),
                discard: symbol(handle, c"roots_discard"),
                continuity: symbol(handle, c"roots_continuity"),
                routing: symbol(handle, c"roots_routing"),
                record: symbol(handle, c"roots_record"),
                status: symbol(handle, c"roots_status"),
            }
        }
    }

    fn status(&self) -> [u64; 15] {
        let mut words = [u64::MAX; 15];
        unsafe { (self.status)(words.as_mut_ptr()) };
        assert_eq!(words[10], 0, "native submission-order assertions");
        words
    }

    fn records(&self) -> Vec<Vec<u8>> {
        (0..self.status()[5] as u32)
            .map(|index| {
                let mut length = 0;
                let pointer = unsafe { (self.record)(index, &mut length) };
                assert!(!pointer.is_null());
                assert!([64, 224, 632].contains(&length));
                unsafe { std::slice::from_raw_parts(pointer, length as usize) }.to_vec()
            })
            .collect()
    }

    fn setup(
        &self,
        function: &str,
        class: u32,
        layout: LinuxLayout,
        object: bool,
        descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
    ) -> u32 {
        let descriptor = crate::kinds::function_id(function).unwrap() + 1;
        let semantics = crate::kinds::descriptor(function).unwrap();
        unsafe {
            (self.setup)(
                descriptor,
                class,
                if layout == LinuxLayout::Lp64 { 1 } else { 2 },
                u32::from(object),
                u32::from(semantics.session_arg),
            );
            let start = &mut *(self.row)(0).cast::<CallStart>();
            start.target_function = p11scope_ebpf_common::FUNCTION_NONE;
            start.capture = capture::MECHANISM_NONE | capture::OUTPUT_NONE;
            if semantics.lifecycle == p11scope_ebpf_common::lifecycle::OPEN_SESSION {
                start.out_ptr = 0x5000;
                start.capture = capture::MECHANISM_NONE | capture::OUTPUT_NON_NULL;
            }
            if semantics.mechanism_arg != ARG_NONE {
                start.mechanism_ptr = 0x6000;
            }
            if layout == LinuxLayout::Ilp32 && semantics.session_arg != ARG_NONE {
                start.session = 0x8000_0001;
            }
            if object {
                (self.object_descriptor)(&descriptors[descriptor as usize]);
                let side = &mut *(self.row)(1).cast::<ObjectStart>();
                side.action = descriptors[descriptor as usize].action;
                for (index, arg) in descriptors[descriptor as usize]
                    .result_args
                    .iter()
                    .enumerate()
                {
                    if *arg != ARG_NONE {
                        side.result_ptrs[index] = 0x1000 + 0x100 * index as u64;
                    }
                }
            }
        }
        descriptor
    }

    fn begin(&self, descriptor: u32, configured: u32, layout: LinuxLayout) {
        if let Some(context) = root_writers::entry_context(descriptor, configured, layout) {
            if context.class_bits != 0 {
                unsafe { (self.begin)(&context) };
            }
        } else {
            unsafe { (self.loss)(5) };
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::dlclose(self.handle) }, 0);
    }
}

/// Executes the actual shared writers with independent retained native rows.
/// Kernel identity/S1 return facts are controlled inputs, exactly as in the
/// existing adapter tests; the compiled-root test pins the real BPF readers.
fn completed(
    bridge: &Bridge,
    descriptor: u32,
    layout: LinuxLayout,
    object: bool,
    joined: bool,
    fill_ok: bool,
    descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
) -> (usize, Option<Vec<u8>>) {
    let start = unsafe { &*(bridge.row)(0).cast::<CallStart>() };
    let key = unsafe { *(bridge.row)(3).cast::<StartKey>() };
    let mut facts = ReturnEventFacts {
        ts_ns: start.ts_ns + 100,
        duration_ns: 100,
        rv: 0,
        mechanism: start.mechanism,
        session: start.session,
        async_value: start.async_value,
        capture_flags: start.capture,
        pid_tgid: 0,
        cgroup_id: 0,
        root_affiliation: 0,
    };
    let name = pkcs11_module::function_name((descriptor - 1) as usize).unwrap();
    let semantics = crate::kinds::descriptor(name).unwrap();
    if semantics.lifecycle == p11scope_ebpf_common::lifecycle::OPEN_SESSION && start.out_ptr != 0 {
        facts.session = 0x9090;
    }
    if start.mechanism_ptr != 0 {
        facts.mechanism = 0x250;
        facts.capture_flags =
            (facts.capture_flags & !capture::MECHANISM_MASK) | capture::MECHANISM_VALUE;
    }
    let record = unsafe { (bridge.reserve)(JOURNAL_END_FULL_BYTES as u32) };
    if record.is_null() {
        unsafe { (bridge.remove)(JOURNAL_REASON_SYNC_RETURN_RESULT_LOST) };
        unsafe { (bridge.loss)(0) };
        assert_eq!(&bridge.status()[12..15], &[0; 3]);
        return (0, None);
    }
    unsafe {
        record
            .cast::<u8>()
            .write_bytes(0xa5, JOURNAL_END_FULL_BYTES)
    };
    let base = unsafe { &mut (*record).payload.base };
    unsafe {
        fill_call_event(&mut base.event, start, key.slot, &facts);
        root_writers::fill_routing(&mut base.event, |word| (bridge.routing)(word as u32));
        (bridge.continuity)(&mut base.continuity, u32::from(joined));
    }
    assert_eq!(
        &bridge.status()[12..15],
        &[1; 3],
        "routing sampled exactly once after reserve"
    );
    let joined = continuity_joins(&base.continuity);
    let reads = Cell::new(0usize);
    if !joined {
        let mut fallback = None;
        let outcome = preserve_refused_base(
            || unsafe { (bridge.remove)(JOURNAL_REASON_IDENTITY_REFUSED) == 0 },
            || unsafe { (bridge.loss)(2) },
            || {
                fallback = Some(
                    unsafe {
                        std::slice::from_raw_parts(
                            (base as *const EventRecord).cast::<u8>(),
                            std::mem::size_of::<EventRecord>(),
                        )
                    }
                    .to_vec(),
                );
                true
            },
        );
        unsafe { (bridge.discard)(record) };
        assert_eq!(outcome, RefusedBaseOutcome::Emitted);
        return (reads.get(), fallback);
    }
    let emitted = if object {
        let side = unsafe { &mut *(bridge.row)(1).cast::<ObjectStart>() };
        if !fill_ok {
            side.phase = 1;
        }
        let row = &descriptors[descriptor as usize];
        let gate = encode_return_gate(layout, joined);
        let filled = adapter_fill_return_control(
            Some(side),
            descriptor,
            Some(row),
            facts.rv,
            facts.capture_flags & capture::MECHANISM_MASK,
            facts.mechanism,
            gate,
            |_| {
                reads.set(reads.get() + 1);
                Ok(if layout == LinuxLayout::Ilp32 {
                    0x8000_1234
                } else {
                    0x1_8000_1234
                })
            },
        );
        let side = unsafe { &*(bridge.row)(1).cast::<ObjectStart>() };
        let tail = unsafe { &mut (*record).payload.object };
        filled
            && unsafe { adapter_tail_fill(tail, Some(side), descriptor, Some(row)) }
            && unsafe {
                adapter_emit_find_control(
                    tail,
                    Some(side),
                    descriptor,
                    Some(row),
                    facts.rv,
                    gate,
                    |_| {
                        reads.set(reads.get() + 1);
                        Ok(0)
                    },
                )
            }
            && unsafe {
                adapter_emit_get_control(
                    tail,
                    Some(side),
                    descriptor,
                    Some(row),
                    facts.rv,
                    gate,
                    |_| {
                        reads.set(reads.get() + 1);
                        Ok(0)
                    },
                    |_, _| {
                        reads.set(reads.get() + 1);
                        Ok(())
                    },
                )
            }
    } else {
        fill_ok
    };
    if !emitted {
        unsafe { (bridge.loss)(5) };
    }
    let mut reason = JOURNAL_REASON_SYNC_RETURN_RESULT_LOST;
    if emitted {
        let mut words = root_writers::ReturnWords::default();
        unsafe { (bridge.returning)(&mut words) };
        unsafe { root_writers::initialize_end(record, &words, !object) };
        if words.flags & u32::from(JOURNAL_END_UNJOURNALED) == 0 {
            reason = 0;
        }
    }
    let outcome = emission_finalize(emitted, || unsafe { (bridge.remove)(reason) == 0 });
    if outcome.submitted {
        unsafe { (bridge.submit)(record) };
    } else {
        unsafe { (bridge.discard)(record) };
    }
    (reads.get(), None)
}

#[test]
fn private_root_native_records_keep_real_results_and_terminal_custody() {
    let bridge = Bridge::new();
    let classes = FrozenClasses::new();
    let descriptors = publish_object_descriptors();
    let mut cells = 0;
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        for (function, object) in [
            ("C_CreateObject", true),
            ("C_Digest", false),
            ("C_OpenSession", false),
            ("C_DigestInit", false),
        ] {
            let descriptor = bridge.setup(function, 1, layout, object, &descriptors);
            assert_eq!(classes.get(descriptor), 2);
            bridge.begin(descriptor, classes.get(descriptor), layout);
            assert_eq!(&bridge.status()[..5], &[1, u64::from(object), 1, 1, 1]);
            let (reads, fallback) = completed(
                &bridge,
                descriptor,
                layout,
                object,
                true,
                true,
                &descriptors,
            );
            assert_eq!(reads, usize::from(object));
            assert!(fallback.is_none());
            let records = bridge.records();
            assert_eq!(records.len(), 2);
            let JournalRecord::Begin(begin) =
                decode_journal_record(&records[0], &descriptors).unwrap()
            else {
                panic!("native BEGIN")
            };
            let JournalRecord::End(end) = decode_journal_record(&records[1], &descriptors).unwrap()
            else {
                panic!("632-byte END")
            };
            assert!(end_agrees_with_begin(&begin, &end));
            if object {
                let tail = end.payload_tail();
                let tail =
                    unsafe { std::ptr::read_unaligned(tail.as_ptr().cast::<ObjectCallWire>()) };
                assert_eq!(tail.result_status[0], handle_status::VALUE);
                assert_eq!(
                    tail.result_handles[0],
                    if layout == LinuxLayout::Ilp32 {
                        0x8000_1234
                    } else {
                        0x1_8000_1234
                    }
                );
            }
            if function == "C_OpenSession" {
                assert_eq!(end.payload_base().event.session, 0x9090);
            }
            if function == "C_DigestInit" {
                assert_eq!(end.payload_base().event.mechanism, 0x250);
            }
            assert_eq!(&bridge.status()[..5], &[0; 5]);
            assert_eq!(bridge.status()[11], 1);
            assert_eq!(&bridge.status()[7..10], &[0; 3]);
            cells += 1;
        }
        for (function, configured, expected_begin) in [
            ("C_GetInfo", 1, false),
            ("C_AsyncComplete", 3, true),
            ("C_Digest", 0, false),
            ("C_Digest", 4, false),
        ] {
            let descriptor = bridge.setup(function, 0, layout, false, &descriptors);
            if configured == 1 || configured == 3 {
                assert_eq!(classes.get(descriptor), configured);
            }
            bridge.begin(descriptor, configured, layout);
            completed(&bridge, descriptor, layout, false, true, true, &descriptors);
            let records = bridge.records();
            assert_eq!(records.len(), 1 + usize::from(expected_begin));
            if expected_begin {
                let JournalRecord::Begin(begin) =
                    decode_journal_record(&records[0], &descriptors).unwrap()
                else {
                    panic!("NO_END BEGIN")
                };
                assert!(begin.no_end());
            }
            let JournalRecord::End(end) =
                decode_journal_record(records.last().unwrap(), &descriptors).unwrap()
            else {
                panic!("useful ordinary result")
            };
            assert!(end.unjournaled());
            assert_eq!((end.thread(), end.sequence()), (0, 0));
            assert_eq!(&bridge.status()[..5], &[0; 5]);
            assert_eq!(
                bridge.status()[7],
                u64::from(configured == 0 || configured == 4)
            );
            cells += 1;
        }
        for object in [false, true] {
            let function = if object { "C_CreateObject" } else { "C_Digest" };
            let descriptor = bridge.setup(function, 1, layout, object, &descriptors);
            bridge.begin(descriptor, 2, layout);
            let original =
                unsafe { *(bridge.row)(2).cast::<p11scope_ebpf_common::InstanceEntry>() };
            let (reads, fallback) = completed(
                &bridge,
                descriptor,
                layout,
                object,
                false,
                true,
                &descriptors,
            );
            assert_eq!(reads, 0);
            let fallback = fallback.unwrap();
            assert_eq!(fallback.len(), 368);
            let base = unsafe { std::ptr::read_unaligned(fallback.as_ptr().cast::<EventRecord>()) };
            assert!(base.continuity.entry_ip == original.entry_ip);
            assert!(base.continuity.entry_stamp == original.entry_stamp);
            assert!(!continuity_joins(&base.continuity));
            let records = bridge.records();
            assert_eq!(records.len(), 2);
            let JournalRecord::Abandon(abandon) =
                decode_journal_record(&records[1], &descriptors).unwrap()
            else {
                panic!("refused continuity retires BEGIN")
            };
            assert_eq!(abandon.reason(), JOURNAL_REASON_IDENTITY_REFUSED);
            assert_eq!(&bridge.status()[..5], &[0; 5]);
            assert_eq!(bridge.status()[6], 1);
            assert_eq!(bridge.status()[11], 1);
            cells += 1;
        }
    }
    let mut failure_cells = 0;
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        // Failed BEGIN leaves real START useful. Neither missing identity nor
        // a NO_END/unknown class is permission to discard a completed call.
        for failure in [1, 32] {
            let descriptor = bridge.setup("C_CreateObject", 1, layout, true, &descriptors);
            unsafe { (bridge.fail)(failure) };
            bridge.begin(descriptor, 2, layout);
            assert_eq!(bridge.status()[5], 0);
            assert_eq!(bridge.status()[7], 1);
            unsafe { (bridge.fail)(0) };
            let (reads, fallback) =
                completed(&bridge, descriptor, layout, true, true, true, &descriptors);
            assert_eq!(reads, 1);
            assert!(fallback.is_none());
            let records = bridge.records();
            assert_eq!(records.len(), 1);
            let JournalRecord::End(end) = decode_journal_record(&records[0], &descriptors).unwrap()
            else {
                panic!("failed BEGIN keeps ordinary result")
            };
            assert!(end.unjournaled());
            assert_eq!(&bridge.status()[..5], &[0; 5]);
            assert_eq!(bridge.status()[7], 1, "no invented loss for missing key");
            failure_cells += 1;
        }
        // Successful provider return with a failed output settles its BEGIN
        // by reason9. A failed END reservation performs no object read.
        for reserve_failure in [false, true] {
            let descriptor = bridge.setup("C_CreateObject", 1, layout, true, &descriptors);
            bridge.begin(descriptor, 2, layout);
            if reserve_failure {
                unsafe { (bridge.fail)(64) };
            }
            let (reads, fallback) = completed(
                &bridge,
                descriptor,
                layout,
                true,
                true,
                reserve_failure,
                &descriptors,
            );
            assert_eq!(reads, 0);
            assert!(fallback.is_none());
            let records = bridge.records();
            assert_eq!(records.len(), 2);
            let JournalRecord::Abandon(abandon) =
                decode_journal_record(&records[1], &descriptors).unwrap()
            else {
                panic!("lost synchronous result")
            };
            assert_eq!(abandon.reason(), JOURNAL_REASON_SYNC_RETURN_RESULT_LOST);
            assert_eq!(&bridge.status()[..5], &[0; 5]);
            assert_eq!(bridge.status()[7], 1);
            assert_eq!(bridge.status()[8], u64::from(reserve_failure));
            assert_eq!(bridge.status()[9], u64::from(!reserve_failure));
            failure_cells += 1;
        }
        for failure in [2, 4, 8] {
            let descriptor = bridge.setup("C_CreateObject", 1, layout, true, &descriptors);
            bridge.begin(descriptor, 2, layout);
            unsafe { (bridge.fail)(failure) };
            completed(&bridge, descriptor, layout, true, true, true, &descriptors);
            assert_eq!(
                bridge.records().len(),
                1,
                "no terminal before physical commit"
            );
            assert_eq!(bridge.status()[0], 1);
            assert_eq!(bridge.status()[3], 1, "failed cleanup retains owner lease");
            assert_eq!(bridge.status()[2], u64::from(failure == 2));
            assert_eq!(bridge.status()[7], 1);
            assert_eq!(bridge.status()[9], 1);
            unsafe { (bridge.fail)(0) };
            if failure == 2 {
                // Journal deletion blocked before any physical disposal. A
                // healed retry retires the exact original identity once.
                assert_eq!(
                    unsafe { (bridge.remove)(JOURNAL_REASON_SYNC_RETURN_RESULT_LOST) },
                    0
                );
                assert_eq!(bridge.records().len(), 2);
                let records = bridge.records();
                let JournalRecord::Abandon(abandon) =
                    decode_journal_record(&records[1], &descriptors).unwrap()
                else {
                    panic!("healed blocked retry")
                };
                assert_eq!(abandon.reason(), JOURNAL_REASON_SYNC_RETURN_RESULT_LOST);
            }
            let before = bridge.records().len();
            unsafe { (bridge.cleanup)() };
            assert_eq!(
                bridge.records().len(),
                before,
                "cleanup cannot duplicate a terminal"
            );
            assert_eq!(&bridge.status()[..5], &[0; 5]);
            failure_cells += 1;
        }
        // The non-object path also retires late: a failed journal or START
        // deletion must withhold END and preserve the same retry custody.
        for failure in [2, 8] {
            let descriptor = bridge.setup("C_Digest", 1, layout, false, &descriptors);
            bridge.begin(descriptor, 2, layout);
            unsafe { (bridge.fail)(failure) };
            completed(&bridge, descriptor, layout, false, true, true, &descriptors);
            assert_eq!(bridge.records().len(), 1);
            assert_eq!(
                &bridge.status()[..5],
                &[1, 0, u64::from(failure == 2), 1, 1]
            );
            assert_eq!(&bridge.status()[7..10], &[1, 0, 1]);
            unsafe { (bridge.fail)(0) };
            if failure == 2 {
                assert_eq!(
                    unsafe { (bridge.remove)(JOURNAL_REASON_SYNC_RETURN_RESULT_LOST) },
                    0
                );
                assert_eq!(bridge.records().len(), 2);
            }
            unsafe { (bridge.cleanup)() };
            assert_eq!(&bridge.status()[..5], &[0; 5]);
            failure_cells += 1;
        }
        // A phase update failure preserves the output as UNJOURNALED and
        // explicitly abandons the still-unsettled BEGIN. Exactly one loss.
        let descriptor = bridge.setup("C_CreateObject", 1, layout, true, &descriptors);
        bridge.begin(descriptor, 2, layout);
        unsafe { (bridge.fail)(16) };
        completed(&bridge, descriptor, layout, true, true, true, &descriptors);
        let records = bridge.records();
        assert_eq!(records.len(), 3);
        assert!(matches!(
            decode_journal_record(&records[1], &descriptors),
            Some(JournalRecord::Abandon(_))
        ));
        let JournalRecord::End(end) = decode_journal_record(&records[2], &descriptors).unwrap()
        else {
            panic!("phase failure retains result")
        };
        assert!(end.unjournaled());
        assert_eq!(&bridge.status()[..5], &[0; 5]);
        assert_eq!(&bridge.status()[7..10], &[1, 0, 1]);
        failure_cells += 1;
        for session in [
            0,
            if layout == LinuxLayout::Ilp32 {
                u64::from(u32::MAX)
            } else {
                u64::MAX
            },
        ] {
            let descriptor = bridge.setup("C_Digest", 1, layout, false, &descriptors);
            unsafe { (*(bridge.row)(0).cast::<CallStart>()).session = session };
            bridge.begin(descriptor, 2, layout);
            completed(&bridge, descriptor, layout, false, true, true, &descriptors);
            let records = bridge.records();
            let JournalRecord::Begin(begin) =
                decode_journal_record(&records[0], &descriptors).unwrap()
            else {
                panic!("exact zero/sentinel native BEGIN")
            };
            let JournalRecord::End(end) = decode_journal_record(&records[1], &descriptors).unwrap()
            else {
                panic!("exact zero/sentinel shared END")
            };
            assert!(end_agrees_with_begin(&begin, &end));
            assert_eq!(end.payload_base().event.session, session);
            assert_eq!(&bridge.status()[7..10], &[0; 3]);
            cells += 1;
        }
    }
    assert_eq!(failure_cells, 20);
    unsafe { (bridge.aggregate)() };
    assert_eq!(&bridge.status()[..5], &[1, 0, 0, 1, 1]);
    assert_eq!(bridge.status()[5], 0);
    assert_eq!(&bridge.status()[12..15], &[0; 3]);
    let start = unsafe { &*(bridge.row)(0).cast::<CallStart>() };
    assert_eq!(start.object_required, 0);
    assert_eq!(start.ts_ns, 123);
    unsafe { assert_eq!((bridge.remove)(0), 0) };
    assert_eq!(&bridge.status()[..5], &[0; 5]);
    assert_eq!(cells, 24);
}
