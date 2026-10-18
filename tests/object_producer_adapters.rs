//! SPDX-License-Identifier: GPL-3.0-or-later
//! H7 adapters tail: wire the read-protocol core to object storage.
//!
//! Entry-fill runs after the ABI record (dispatch on the frozen descriptor
//! via `object_capture`, write verdicts into the side row, advance ENTRY to
//! READY, fault plus abandon on refusal). Return-fill runs after the
//! required=1 ready query (return-phase reads, write side fields, advance
//! READY to RETURNING, fault plus drain on refusal). No tail is constructed:
//! production publication stays gated for slice D. These tests pin the
//! adapter call sites, ordering and ELF presence; the existing
//! `object_producer_compiled_frames_are_bounded` test enforces the 512-byte
//! root call-chain budget over the new levels.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/object_adapter.rs"]
mod adapter;

#[path = "support/object_owner_fixture.rs"]
mod owner_fixture;

fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("missing source marker {start:?}"));
    let rest = &source[from + start.len()..];
    let until = rest
        .find(end)
        .unwrap_or_else(|| panic!("missing source marker {end:?}"));
    &rest[..until]
}

fn embedded_object(directory: &Path) -> PathBuf {
    let object = directory.join("p11scope-ebpf");
    std::fs::write(&object, p11scope::EBPF_OBJECT).expect("write actual embedded BPF object");
    object
}

fn nm_text_symbols(object: &Path) -> String {
    let output = Command::new("nm")
        .arg("--defined-only")
        .arg(object)
        .output()
        .expect("run nm on embedded object");
    assert!(
        output.status.success(),
        "nm failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn object_producer_adapters_entry_fill_shape() {
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF entry root");
    // Adapter helpers are outlined like the marker/ABI helpers: one
    // rounding quantum per level, never inlined into the hot root frame.
    for helper in [
        "fn object_fill_entry",
        "fn object_entry_derive",
        "fn object_entry_results",
        "fn object_entry_find",
        "fn object_fill_return",
    ] {
        assert!(source.contains(helper), "missing adapter helper {helper}");
        let marker = source.find(helper).expect("adapter helper");
        let window = &source[marker.saturating_sub(400)..marker];
        assert!(
            window.contains("#[inline(never)]"),
            "{helper} must be #[inline(never)]"
        );
    }

    // The two slice-D emission levels are outlined like the adapters:
    // one rounding quantum each, never inlined into the hot root frame.
    for helper in ["fn object_tail_fill", "fn object_emit_find"] {
        assert!(source.contains(helper), "missing emission helper {helper}");
        let marker = source.find(helper).expect("emission helper");
        let window = &source[marker.saturating_sub(400)..marker];
        assert!(
            window.contains("#[inline(never)]"),
            "{helper} must be #[inline(never)]"
        );
    }

    // Entry: ABI record, then fill, then abandon on refusal.
    let entry = source_between(
        &source,
        "fn p11_entry_impl<const TEMPLATE_MODE: u8, const ENTRY_ABI: u8>(ctx: ProbeContext) -> u32 {",
        "fn rv_count_add(key: &RvKey) -> bool {",
    );
    let abi = entry
        .find("object_record_entry_abi(&key,")
        .expect("entry must record the ABI before filling");
    let fill = entry
        .find("object_fill_entry(")
        .expect("entry must fill the side row after the ABI record");
    assert!(abi < fill, "entry fill must run after the ABI record");
    // Refusal abandons through the ordinary removal plus the fault leaf.
    let abandon = entry[fill..]
        .find("owned_start_remove(&key, true)")
        .expect("entry fill refusal must abandon through the ordinary removal");
    let fault = entry[fill..]
        .find("p11_object_fault()")
        .expect("entry fill refusal must fault");
    // Both abandon sites (ABI record + fill) retire through the same removal.
    assert!(
        entry.matches("owned_start_remove(&key, true)").count() >= 2,
        "entry keeps ABI-record and fill abandon arms"
    );
    let _ = (abandon, fault);

    // Slice D lifts the gate on the return path only: entry fills
    // side storage and never constructs a tail.
    assert!(
        !entry.contains("ObjectCallWire")
            && !entry.contains("ObjectEventRecord")
            && !entry.contains("object_tail_fill")
            && !entry.contains("object_emit_find"),
        "entry must not construct an object tail"
    );
}

#[test]
fn object_producer_adapters_return_fill_shape() {
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF return root");
    let returned = source_between(
        &source,
        "fn p11_return_impl(ctx: RetProbeContext) -> u32 {",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    // Return (slice D): ready/agreement queries, then the complete
    // 608-byte reservation, then fill, tail and Find emission, then the
    // drain retire, then submit (discard plus fault on failure). The
    // reservation precedes every object read; the retire precedes the
    // submit. (Slice C retired before reading; slice D lifts the gate
    // and the side row must stay alive through emission.)
    let ready = returned
        .find("p11_object_side_get(&key, descriptor, 1)")
        .expect("return fill must query ready with required=1");
    let reserve = returned
        .find("reserve::<ObjectEventRecord>")
        .expect("emission must reserve the complete object record");
    let fill = returned
        .find("object_fill_return(")
        .expect("return must fill after reserving");
    let tail = returned
        .find("object_tail_fill(")
        .expect("return must fill the tail after filling results");
    let find = returned
        .find("object_emit_find(")
        .expect("return must emit the Find section after the tail");
    let drain = returned
        .rfind("owned_start_remove(&key, true)")
        .expect("emission arm retires");
    assert!(
        ready < reserve && reserve < fill && fill < tail && tail < find && find < drain,
        "return must query ready, reserve, fill, tail, find, then retire"
    );
    let submit = returned.find("entry.submit(0)").expect("emission submits");
    let discards: Vec<_> = returned.match_indices("entry.discard(0)").collect();
    assert_eq!(
        discards.len(),
        2,
        "the continuity-gate arm and the failed-emission arm each discard"
    );
    assert!(
        discards[0].0 < fill,
        "the gate arm must discard before any object read"
    );
    assert!(
        drain < submit && drain < discards[1].0,
        "the drain retire must precede submit and the emission discard"
    );
    // The drain still queries (required=0, all sane phases) and the
    // failed settle still faults; emission reads stay outlined.
    let query = returned
        .find("p11_object_side_get(&key, descriptor, 0)")
        .expect("drain must query the side row before retiring");
    assert!(
        query < reserve,
        "the agreement query must precede the object reservation"
    );
    let fault = returned
        .find("p11_object_fault()")
        .expect("failed settle must fault");
    let _ = fault;
    // Slice D emits behind the required-object marker: exactly the two
    // record forms are reserved.
    assert_eq!(
        returned.matches("EVENTS.reserve").count(),
        2,
        "return reserves exactly the ordinary and the object record forms"
    );
}

#[test]
fn object_producer_adapters_helpers_in_elf() {
    let directory = tempfile::tempdir().expect("temporary adapter ELF check");
    let object = embedded_object(directory.path());
    let symbols = nm_text_symbols(&object);
    // Helpers are private like the marker/ABI levels, so their symbols are
    // local text (`t`), not global (`T`). Either proves the outline survived.
    for helper in [
        "object_fill_entry",
        "object_entry_derive",
        "object_entry_results",
        "object_entry_find",
        "object_fill_return",
    ] {
        let hits: Vec<&str> = symbols
            .lines()
            .filter(|line| line.contains(helper) && (line.contains(" T ") || line.contains(" t ")))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "expected one .text {helper}, saw {}: {hits:?}",
            hits.len()
        );
        println!("{}", hits[0]);
    }
    // Still no tail construction symbol and no monolithic drain.
    assert!(
        !symbols.contains("p11_object_return_remove"),
        "no monolithic native drain"
    );
}

/// Spy for entry-argument acquisition. LP64 serves programmed register
/// values with no target read; ia32 serves through the REAL shared
/// `read_ia32_arg_with` address computation plus an instrumented
/// four-byte stack read, so a forbidden arg5 fetch is a logged stack
/// read, not just a counter.
struct ArgSpy<'a> {
    reads: Vec<u8>,
    registers: [Option<u64>; 7],
    stack_pointer: u64,
    layout: p11scope_ebpf_common::LinuxLayout,
    target: Option<&'a std::cell::RefCell<adapter::FakeTarget>>,
}

impl<'a> ArgSpy<'a> {
    fn lp64(registers: [Option<u64>; 7]) -> Self {
        Self {
            reads: Vec::new(),
            registers,
            stack_pointer: 0,
            layout: p11scope_ebpf_common::LinuxLayout::Lp64,
            target: None,
        }
    }

    fn ia32(target: &'a std::cell::RefCell<adapter::FakeTarget>, stack_pointer: u64) -> Self {
        Self {
            reads: Vec::new(),
            registers: [None; 7],
            stack_pointer,
            layout: p11scope_ebpf_common::LinuxLayout::Ilp32,
            target: Some(target),
        }
    }

    /// Mirror of BPF `arg_u64`: LP64 register file, ia32 stack through
    /// the shared reader. Returns the fetched word or `None` on refusal.
    fn fetch(&mut self, index: u8) -> Option<u64> {
        self.reads.push(index);
        if self.layout == p11scope_ebpf_common::LinuxLayout::Ilp32 {
            let target = self.target.expect("ia32 spy needs its target");
            let value = p11scope_ebpf_common::read_ia32_arg_with(
                self.stack_pointer,
                u32::from(index),
                |addr| target.borrow_mut().read_u32(addr),
            );
            return (value <= u64::from(u32::MAX)).then_some(value);
        }
        if index > 6 {
            return None;
        }
        self.registers[usize::from(index)]
    }

    fn fetches_of(&self, index: u8) -> usize {
        self.reads.iter().filter(|i| **i == index).count()
    }
}

/// H7-E3 Derive entry harness. Executes the REAL production adapter body
/// (`object_flow::adapter_derive_entry` — the same function the BPF wrapper
/// calls) with the argument spy as its fetcher and the instrumented target
/// as its reader. Returns the adapter verdict; the caller-owned side row
/// carries retention. Refused mechanisms fetch arg5 zero times (on ia32,
/// zero stack word reads through the real `read_ia32_arg_with` address).
fn run_production_derive_entry(
    args: &mut ArgSpy<'_>,
    target: &std::cell::RefCell<adapter::FakeTarget>,
    layout: p11scope_ebpf_common::LinuxLayout,
    side: &mut p11scope_ebpf_common::object_wire::ObjectStart,
    row: &p11scope_ebpf_common::object_wire::ObjectDescriptorWire,
) -> bool {
    use p11scope_ebpf_common::object_flow::adapter_derive_entry;
    let descriptor = side.descriptor_index;
    let (reader, _) = adapter::readers(target);
    let mut fetch = |index: u8| args.fetch(index);
    adapter_derive_entry(
        Some(side),
        descriptor,
        Some(row),
        layout,
        &mut fetch,
        reader,
    )
}

/// A Derive harness pair: ENTRY-phase side row plus the frozen Derive row
/// (descriptor 23, function 22, result arg 5, valid guard).
fn derive_harness() -> (
    p11scope_ebpf_common::object_wire::ObjectStart,
    p11scope_ebpf_common::object_wire::ObjectDescriptorWire,
) {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_DERIVE, OBJECT_GUARD_NAMED, ObjectDescriptorWire, ObjectStart,
    };
    let side = ObjectStart {
        descriptor_index: 23,
        phase: 1,
        ..Default::default()
    };
    let row = ObjectDescriptorWire {
        function: 22,
        input_args: [ARG_NONE; 2],
        result_args: [5, ARG_NONE],
        template_args: [ARG_NONE; 4],
        find_capacity_arg: ARG_NONE,
        find_count_arg: ARG_NONE,
        action: OBJECT_ACTION_DERIVE,
        guard: OBJECT_GUARD_NAMED,
    };
    (side, row)
}

fn pin_derive_guard_precedes_arg5() {
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF entry root");
    // Delegation: the BPF wrapper binds readers and calls the shared
    // adapter the harness executes — no second inline copy.
    let wrapper = source_between(
        &source,
        "fn object_entry_derive(",
        "fn object_entry_results(",
    );
    assert_eq!(
        wrapper.matches("adapter_derive_entry(").count(),
        1,
        "the BPF wrapper must delegate to exactly one shared adapter_derive_entry"
    );
    assert!(
        !wrapper.contains("classify_derive_mechanism"),
        "the wrapper must not inline a second mechanism guard"
    );
    // Executed order: inside the shared adapter, membership
    // classification precedes the single arg-5 fetch.
    let flow = std::fs::read_to_string("crates/ebpf-common/src/object_flow.rs")
        .expect("read shared adapter flow");
    let derive = source_between(&flow, "pub fn adapter_derive_entry(", "fn slot_gate(");
    let guard = derive
        .find("classify_derive_mechanism")
        .expect("derive entry must classify the mechanism before acquiring arg5");
    let arg5 = derive
        .find("fetch_arg(5)")
        .expect("derive entry acquires arg5");
    assert!(
        guard < arg5,
        "the derive mechanism guard must precede the arg-5 fetch"
    );
    assert_eq!(
        derive.matches("fetch_arg(5)").count(),
        1,
        "derive entry fetches arg5 exactly once, after the guard"
    );
}

/// G04/E3: ia32 Derive membership precedes the arg-5 stack read. Exactly
/// the four mechanism words 0x21, 0x393, 0x1050, 0x1051 authorize the
/// arg-5 fetch on each ABI; null, unreadable, unsupported and high-bit
/// mechanisms fetch arg5 zero times, retain nothing and authorize no
/// template access. A matching CKR_OK return reads phKey once;
/// changed/missing S1 return evidence reads it zero times. Entry and
/// return both run through the production adapters, so an unconditional
/// production arg-5 fetch fails this test.
#[test]
fn object_ia32_derive_membership_precedes_arg5_read() {
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::capture;
    use p11scope_ebpf_common::object_capture::{
        DeriveEntry, authorize_derive_return, authorize_entry_templates, derive_mechanism_code,
        handle_status,
    };
    use p11scope_ebpf_common::object_flow::adapter_fill_return;
    use p11scope_ebpf_common::object_policy::ScalarDeriveMechanism;
    let derive_fn: u32 = pkcs11_module::FUNCTION_NAMES
        .iter()
        .position(|name| *name == "C_DeriveKey")
        .expect("C_DeriveKey exists") as u32;
    let accepted = [
        (0x21u64, ScalarDeriveMechanism::DhPkcs),
        (0x393u64, ScalarDeriveMechanism::Sha256),
        (0x1050u64, ScalarDeriveMechanism::Ecdh1),
        (0x1051u64, ScalarDeriveMechanism::Ecdh1Cofactor),
    ];
    for mechanism in accepted {
        assert_eq!(derive_mechanism_code(mechanism.1), mechanism.0);
    }
    // LP64 positives: each accepted mechanism fetches arg5 exactly once
    // and retains it; templates stay authorized through the entry.
    for (code, expected) in accepted {
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(8));
        target.borrow_mut().set_word(0x30000, code);
        let mut args = ArgSpy::lp64([None, Some(0x30000), None, None, None, Some(0x40000), None]);
        let (mut side, row) = derive_harness();
        let ok =
            run_production_derive_entry(&mut args, &target, LinuxLayout::Lp64, &mut side, &row);
        let entry = DeriveEntry::Accepted(expected);
        assert!(ok, "LP64 {code:#x} accepts");
        assert_eq!(side.derive, entry.code());
        assert_eq!(side.result_ptrs, [0x40000, 0]);
        assert_eq!(args.fetches_of(5), 1, "LP64 {code:#x} fetches arg5 once");
        assert_eq!(
            target.borrow().log(),
            &[(adapter::READ_WORD, 0x30000, 8)],
            "LP64 {code:#x} reads only the mechanism word"
        );
        let templates = authorize_entry_templates(derive_fn, [(0x50000, 2), (0, 0)], entry);
        assert!(
            templates[0].is_some(),
            "LP64 {code:#x} authorizes its template pair"
        );
    }
    // ia32 positives: arg5 is a stack word through the shared address.
    for (code, expected) in accepted {
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(4));
        let sp = 0x8000_0000u64;
        // Stack: return address at sp, args 0..=6 above it.
        let mut stack = [0u32; 8];
        stack[1] = 0x30000;
        stack[5] = 0x40000;
        for (i, word) in stack.iter().enumerate() {
            target
                .borrow_mut()
                .set_bytes(sp + 4 + i as u64 * 4, &word.to_le_bytes());
        }
        target.borrow_mut().set_word(0x30000, code);
        let mut args = ArgSpy::ia32(&target, sp);
        let (mut side, row) = derive_harness();
        let ok =
            run_production_derive_entry(&mut args, &target, LinuxLayout::Ilp32, &mut side, &row);
        let entry = DeriveEntry::Accepted(expected);
        assert!(ok, "ia32 {code:#x} accepts");
        assert_eq!(side.derive, entry.code());
        assert_eq!(side.result_ptrs, [0x40000, 0]);
        assert_eq!(args.fetches_of(5), 1, "ia32 {code:#x} fetches arg5 once");
        let arg5_addr = p11scope_ebpf_common::ia32_arg_address(sp, 5).expect("arg5 stack address");
        assert_eq!(
            target.borrow().reads_of(arg5_addr),
            1,
            "ia32 {code:#x} reads the arg-5 stack word once"
        );
        // Matching CKR_OK return reads phKey exactly once through the
        // production fill.
        let phkey = std::cell::RefCell::new(adapter::FakeTarget::new(4));
        phkey.borrow_mut().set_word(0x40000, 0x77);
        assert!(authorize_derive_return(
            entry,
            adapter::rv_ok(),
            capture::MECHANISM_VALUE,
            code
        ));
        let mut return_side = p11scope_ebpf_common::object_wire::ObjectStart {
            descriptor_index: 23,
            phase: 2,
            derive: entry.code(),
            result_ptrs: [0x40000, 0],
            ..Default::default()
        };
        let (reader, _) = adapter::readers(&phkey);
        let filled = adapter_fill_return(
            Some(&mut return_side),
            23,
            Some(&row),
            adapter::rv_ok(),
            LinuxLayout::Ilp32,
            capture::MECHANISM_VALUE,
            code,
            true,
            reader,
        );
        assert!(filled, "ia32 {code:#x} matching return fills");
        assert_eq!(return_side.result_statuses[0], handle_status::VALUE);
        assert_eq!(return_side.result_ptrs[0], 0x77);
        assert_eq!(
            phkey.borrow().log(),
            &[(adapter::READ_WORD, 0x40000, 4)],
            "matching return reads phKey once"
        );
    }
    // Refusals on both ABIs: no arg5 fetch, no retention, no template
    // authorization, no phKey dereference.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // (name, mechanism pointer, programmed mechanism word or None for
        // an unreadable word, expected arg5 fetches).
        let refusals: [(&str, u64, Option<u64>); 5] = [
            ("null mechanism", 0, None),
            ("unreadable mechanism", 0x30000, None),
            ("unsupported mechanism", 0x30000, Some(0x1082)),
            ("ignored-phKey standard", 0x30000, Some(0x1041)),
            ("high-bit contamination", 0x30000, Some(0x1_0000_0021)),
        ];
        for (name, mech_ptr, programmed) in refusals {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            if layout == LinuxLayout::Ilp32 {
                // ia32 serves args from the stack; high-bit contamination
                // cannot arrive through a four-byte read, so program the
                // low word the hardware would deliver.
                let sp = 0x8000_0000u64;
                let mut stack = [0u32; 8];
                stack[1] = mech_ptr as u32;
                stack[5] = 0x40000;
                for (i, word) in stack.iter().enumerate() {
                    target
                        .borrow_mut()
                        .set_bytes(sp + 4 + i as u64 * 4, &word.to_le_bytes());
                }
                // ia32 words are four bytes: bit-31 contamination is the
                // representable high-bit refusal (the LP64-only 1<<32 case
                // is covered on LP64).
                let programmed = if name == "high-bit contamination" {
                    Some(0x8000_0021u64)
                } else {
                    programmed
                };
                if let Some(word) = programmed {
                    target.borrow_mut().set_word(0x30000, word & 0xffff_ffff);
                } else if mech_ptr != 0 {
                    target.borrow_mut().set_fail(0x30000);
                }
                // The high-bit LP64-only refusal is covered on LP64; on
                // ia32 the masked word is either unsupported or refused.
                let mut args = ArgSpy::ia32(&target, sp);
                let (mut side, row) = derive_harness();
                let ok = run_production_derive_entry(&mut args, &target, layout, &mut side, &row);
                assert!(ok, "{name} refuses without custody failure");
                assert_eq!(side.derive, DeriveEntry::Unavailable.code(), "{name}");
                assert_eq!(side.result_ptrs, [0, 0], "{name} retains nothing");
                assert_eq!(
                    args.fetches_of(5),
                    0,
                    "ia32 {name} performs zero arg-5 stack fetches"
                );
                let arg5_addr =
                    p11scope_ebpf_common::ia32_arg_address(sp, 5).expect("arg5 stack address");
                assert_eq!(
                    target.borrow().reads_of(arg5_addr),
                    0,
                    "ia32 {name} reads the arg-5 stack word zero times"
                );
                let templates = authorize_entry_templates(
                    derive_fn,
                    [(0x50000, 2), (0, 0)],
                    DeriveEntry::Unavailable,
                );
                assert_eq!(templates, [None, None], "{name} authorizes no template");
            } else {
                if let Some(word) = programmed {
                    target.borrow_mut().set_word(0x30000, word);
                } else if mech_ptr != 0 {
                    target.borrow_mut().set_fail(0x30000);
                }
                let mut args =
                    ArgSpy::lp64([None, Some(mech_ptr), None, None, None, Some(0x40000), None]);
                let (mut side, row) = derive_harness();
                let ok = run_production_derive_entry(&mut args, &target, layout, &mut side, &row);
                assert!(ok, "{name} refuses without custody failure");
                assert_eq!(side.derive, DeriveEntry::Unavailable.code(), "{name}");
                assert_eq!(side.result_ptrs, [0, 0], "{name} retains nothing");
                assert_eq!(
                    args.fetches_of(5),
                    0,
                    "LP64 {name} performs zero arg-5 fetches"
                );
                let templates = authorize_entry_templates(
                    derive_fn,
                    [(0x50000, 2), (0, 0)],
                    DeriveEntry::Unavailable,
                );
                assert_eq!(templates, [None, None], "{name} authorizes no template");
            }
        }
        // Changed/missing S1 return evidence reads phKey zero times
        // through the production fill.
        let (_, derive_row) = derive_harness();
        for (name, status, mechanism) in [
            ("changed evidence", capture::MECHANISM_VALUE, 0x393u64),
            ("missing evidence", capture::MECHANISM_UNREADABLE, 0x21u64),
            ("non-OK RV guard", capture::MECHANISM_VALUE, 0x21u64),
        ] {
            let entry = DeriveEntry::Accepted(ScalarDeriveMechanism::DhPkcs);
            let rv = if name == "non-OK RV guard" {
                7
            } else {
                adapter::rv_ok()
            };
            assert!(
                !authorize_derive_return(entry, rv, status, mechanism),
                "{layout:?} {name} authorizes no phKey read"
            );
            let phkey = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            phkey.borrow_mut().set_word(0x40000, 0x77);
            let mut return_side = p11scope_ebpf_common::object_wire::ObjectStart {
                descriptor_index: 23,
                phase: 2,
                derive: entry.code(),
                result_ptrs: [0x40000, 0],
                ..Default::default()
            };
            let (reader, _) = adapter::readers(&phkey);
            let filled = adapter_fill_return(
                Some(&mut return_side),
                23,
                Some(&derive_row),
                rv,
                layout,
                status,
                mechanism,
                true,
                reader,
            );
            assert!(
                filled,
                "{layout:?} {name}: the finite refusal still completes"
            );
            assert_eq!(
                return_side.result_statuses,
                [handle_status::PROTOCOL_UNAVAILABLE, handle_status::ABSENT]
            );
            adapter::assert_no_target_reads(&phkey, &format!("{layout:?} phKey on {name}"));
        }
        // Arithmetic overflow: the arg-1 slot itself is readable here
        // (sp+8) but unprogrammed, so entry is unavailable after exactly
        // that one failed stack read. The arg-5 slot address overflows,
        // so no arg-5 stack read can land.
        if layout == LinuxLayout::Ilp32 {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            target.borrow_mut().set_word(0x30000, 0x21);
            let sp = 0xffff_fff0u64;
            let mut args = ArgSpy::ia32(&target, sp);
            let (mut side, row) = derive_harness();
            let ok = run_production_derive_entry(&mut args, &target, layout, &mut side, &row);
            assert!(ok, "overflow refuses without custody failure");
            assert_eq!(side.derive, DeriveEntry::Unavailable.code());
            assert_eq!(side.result_ptrs, [0, 0]);
            assert_eq!(
                target.borrow().log(),
                &[(adapter::READ_BYTES, sp + 8, 4)],
                "only the failed arg-1 slot is read"
            );
            assert_eq!(
                p11scope_ebpf_common::ia32_arg_address(sp, 5),
                None,
                "the arg-5 slot address overflows"
            );
        }
    }
    pin_derive_guard_precedes_arg5();
}

/// Fix round 1 mutation control for the G04 probe: the production
/// acquisition order is load-bearing. Fetching arg5 unconditionally (or
/// before classification) in the shared adapter fails this test
/// (verified by manual mutant during the fix round). Non-Derive families
/// and custody failures exercise the remaining adapter branches.
#[test]
fn object_derive_acquisition_guards_arg5_fetch() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::object_flow::adapter_derive_entry;
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_DERIVE_UNAVAILABLE, ObjectDescriptorWire,
    };
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // A refused mechanism performs zero arg-5 fetches through the
        // production adapter and retains the zero pointer.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        target.borrow_mut().set_word(0x30000, 0x1082);
        let mut args = if layout == LinuxLayout::Lp64 {
            ArgSpy::lp64([None, Some(0x30000), None, None, None, Some(0x40000), None])
        } else {
            let sp = 0x8000_0000u64;
            target
                .borrow_mut()
                .set_bytes(sp + 8, &0x30000u32.to_le_bytes());
            target
                .borrow_mut()
                .set_bytes(sp + 24, &0x40000u32.to_le_bytes());
            ArgSpy::ia32(&target, sp)
        };
        let (mut side, row) = derive_harness();
        let ok = run_production_derive_entry(&mut args, &target, layout, &mut side, &row);
        assert!(ok, "{layout:?} refusal is not custody failure");
        assert_eq!(side.derive, OBJECT_DERIVE_UNAVAILABLE);
        assert_eq!(side.result_ptrs, [0, 0]);
        assert_eq!(args.fetches_of(5), 0, "{layout:?} refused fetch count");
        // A non-Derive family succeeds trivially with zero reads.
        let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
        let mut create_row = row;
        create_row.action = OBJECT_ACTION_CREATE;
        let (reader, _) = adapter::readers(&target);
        let mut fetch = |_: u8| -> Option<u64> { panic!("no fetch on the trivial path") };
        assert!(
            adapter_derive_entry(
                Some(&mut side),
                23,
                Some(&create_row),
                layout,
                &mut fetch,
                reader,
            ),
            "{layout:?} non-Derive succeeds trivially"
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} trivial path"));
        // Custody failures refuse: missing side, missing row, a row that
        // disagrees on the result ordinals.
        let (reader, _) = adapter::readers(&target);
        let mut fetch = |_: u8| None;
        assert!(
            !adapter_derive_entry(None, 23, Some(&row), layout, &mut fetch, reader),
            "{layout:?} missing side refuses"
        );
        let (reader, _) = adapter::readers(&target);
        let mut fetch = |_: u8| None;
        assert!(
            !adapter_derive_entry(Some(&mut side), 23, None, layout, &mut fetch, reader),
            "{layout:?} missing row refuses"
        );
        let bad_row = ObjectDescriptorWire {
            function: 22,
            input_args: [ARG_NONE; 2],
            result_args: [6, ARG_NONE],
            template_args: [ARG_NONE; 4],
            find_capacity_arg: ARG_NONE,
            find_count_arg: ARG_NONE,
            action: row.action,
            guard: row.guard,
        };
        let (reader, _) = adapter::readers(&target);
        let mut fetch = |_: u8| None;
        assert!(
            !adapter_derive_entry(
                Some(&mut side),
                23,
                Some(&bad_row),
                layout,
                &mut fetch,
                reader
            ),
            "{layout:?} disagreeing row refuses"
        );
        adapter::assert_no_target_reads(&target, &format!("{layout:?} Derive custody"));
    }
}

/// The extracted production fill agrees with the reviewed shared core on
/// a joined battery: identical statuses, words and flags, identical read
/// sets. (Refused continuity is intentionally excluded: the core returns
/// an unavailable verdict while the adapter refuses with `false`; G02
/// covers the refused half through the production path.)
#[test]
fn object_return_fill_matches_shared_core() {
    use p11scope_ebpf_common::ARG_NONE;
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::capture;
    use p11scope_ebpf_common::object_capture::{DeriveEntry, capture_return_handles};
    use p11scope_ebpf_common::object_flow::adapter_fill_return;
    use p11scope_ebpf_common::object_policy::ScalarDeriveMechanism;
    use p11scope_ebpf_common::object_wire::{OBJECT_ACTION_CREATE, OBJECT_ACTION_DERIVE};
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // (result args, pointers, words-or-None-per-slot, rv, action,
        // derive code, S1 status, S1 mechanism).
        type FillVector = ([u8; 2], [u64; 2], [Option<u64>; 2], u64, u8, u8, u32, u64);
        let vectors: [FillVector; 8] = [
            (
                [5, ARG_NONE],
                [0x10000, 0],
                [Some(0x42), None],
                0,
                OBJECT_ACTION_CREATE,
                0,
                capture::MECHANISM_VALUE,
                0,
            ),
            (
                [5, 6],
                [0x10000, 0x10008],
                [Some(0x42), Some(0x43)],
                0,
                OBJECT_ACTION_CREATE,
                0,
                capture::MECHANISM_VALUE,
                0,
            ),
            // Alias: overlapping spans refuse both slots.
            (
                [5, 6],
                [0x10000, 0x10000],
                [Some(0x42), Some(0x42)],
                0,
                OBJECT_ACTION_CREATE,
                0,
                capture::MECHANISM_VALUE,
                0,
            ),
            // Duplicate: equal words invalidate both slots.
            (
                [5, 6],
                [0x10000, 0x10100],
                [Some(0x42), Some(0x42)],
                0,
                OBJECT_ACTION_CREATE,
                0,
                capture::MECHANISM_VALUE,
                0,
            ),
            // Partial: one value, one unreadable.
            (
                [5, 6],
                [0x10000, 0x10100],
                [Some(0x42), None],
                0,
                OBJECT_ACTION_CREATE,
                0,
                capture::MECHANISM_VALUE,
                0,
            ),
            // Non-OK RV: unavailable cells, no reads.
            (
                [5, 6],
                [0x10000, 0x10100],
                [Some(0x42), Some(0x43)],
                7,
                OBJECT_ACTION_CREATE,
                0,
                capture::MECHANISM_VALUE,
                0,
            ),
            // Derive match: accepted entry plus exact S1 reads phKey.
            (
                [5, ARG_NONE],
                [0x10000, 0],
                [Some(0x77), None],
                0,
                OBJECT_ACTION_DERIVE,
                1,
                capture::MECHANISM_VALUE,
                0x21,
            ),
            // Derive mismatch: S1 disagreement reads nothing.
            (
                [5, ARG_NONE],
                [0x10000, 0],
                [Some(0x77), None],
                0,
                OBJECT_ACTION_DERIVE,
                1,
                capture::MECHANISM_VALUE,
                0x393,
            ),
        ];
        for (case, vector) in vectors.iter().enumerate() {
            let (result_args, ptrs, words, rv, action, derive, status, mechanism) = *vector;
            let program = |target: &std::cell::RefCell<adapter::FakeTarget>| {
                for (slot, word) in words.iter().enumerate() {
                    match word {
                        Some(word) => target.borrow_mut().set_word(ptrs[slot], *word),
                        None if ptrs[slot] != 0 => target.borrow_mut().set_fail(ptrs[slot]),
                        None => {}
                    }
                }
            };
            // Shared-core oracle.
            let core_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            program(&core_target);
            let present = [result_args[0] != ARG_NONE, result_args[1] != ARG_NONE];
            let derive_entry = match derive {
                1 => DeriveEntry::Accepted(ScalarDeriveMechanism::DhPkcs),
                _ => DeriveEntry::Unavailable,
            };
            let authorized = if action == OBJECT_ACTION_DERIVE {
                let ok = p11scope_ebpf_common::object_capture::authorize_derive_return(
                    derive_entry,
                    rv,
                    status,
                    mechanism,
                );
                [ok, ok]
            } else {
                [true, true]
            };
            let (reader, _) = adapter::readers(&core_target);
            let (verdict, core_words) = capture_return_handles(
                present,
                authorized,
                ptrs,
                rv,
                adapter::owner_ready_authority(),
                layout,
                reader,
            );
            // Production adapter on the identical vector.
            let prod_target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            program(&prod_target);
            let (_, mut row) = derive_harness();
            row.action = action;
            row.result_args = result_args;
            let mut side = p11scope_ebpf_common::object_wire::ObjectStart {
                descriptor_index: 23,
                phase: 2,
                derive,
                result_ptrs: ptrs,
                ..Default::default()
            };
            let (reader, _) = adapter::readers(&prod_target);
            let filled = adapter_fill_return(
                Some(&mut side),
                23,
                Some(&row),
                rv,
                layout,
                status,
                mechanism,
                true,
                reader,
            );
            assert!(
                filled,
                "{layout:?} case {case}: joined battery always fills"
            );
            assert_eq!(
                side.result_statuses, verdict.statuses,
                "{layout:?} case {case}: statuses match the core"
            );
            assert_eq!(
                side.result_ptrs, core_words,
                "{layout:?} case {case}: words match the core"
            );
            assert_eq!(
                u32::from(side.flags),
                verdict.object_flags,
                "{layout:?} case {case}: flags match the core"
            );
            assert_eq!(
                prod_target.borrow().log(),
                core_target.borrow().log(),
                "{layout:?} case {case}: read sets match the core"
            );
        }
    }
}

/// G03/E2: the production emission cleanup decision retires before
/// gating. `emission_finalize` — the shared production function the BPF
/// return root calls — attempts the injected removal on ALL four
/// (emitted x retired) cells, never short-circuited by emission
/// failure; it submits only when both hold and faults otherwise. The
/// `emitted && remove()` mutant (skipped cleanup on emission failure)
/// fails here: the emitted=false cells observe zero attempts.
#[test]
fn object_emission_finalize_always_attempts_removal() {
    use p11scope_ebpf_common::object_flow::emission_finalize;
    for emitted in [false, true] {
        for retired in [false, true] {
            let mut attempts = 0;
            let outcome = emission_finalize(emitted, || {
                attempts += 1;
                retired
            });
            assert_eq!(
                attempts, 1,
                "emitted={emitted} retired={retired}: the removal is attempted exactly once"
            );
            assert_eq!(
                outcome.submitted,
                emitted && retired,
                "emitted={emitted} retired={retired}: submit only on both"
            );
            assert_eq!(
                outcome.faulted,
                !(emitted && retired),
                "emitted={emitted} retired={retired}: fault on either failure"
            );
        }
    }
}

fn pin_root_refusals_retire() {
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF return root");
    let returned = source_between(
        &source,
        "fn p11_return_impl(ctx: RetProbeContext) -> u32 {",
        "pub extern \"C\" fn p11_link_fork_allowed",
    );
    // Ready/agreement refusal arms retire ownership before returning.
    for arm in ["if ready.is_none() {", "if !agreed {"] {
        let at = returned
            .find(arm)
            .unwrap_or_else(|| panic!("return must keep its {arm} refusal arm"));
        let end = returned[at..]
            .find("\n    }\n")
            .expect("refusal arm closes");
        let body = &returned[at..at + end];
        assert!(
            body.contains("owned_start_remove(&key, true)"),
            "{arm} must retire ownership"
        );
        assert!(
            body.contains("p11_object_fault()"),
            "{arm} must fault visibly"
        );
    }
    // The object branch alone owns late retirement; ordinary returns
    // already retired before accounting and cannot delete twice.
    let object = &returned[returned.find("fn object_return(").expect("object branch")..];
    let image_at = object
        .find("image_pair_matches(unsafe { (*start).image }, image)")
        .expect("object return must retain its live START image refusal");
    let image_end = object[image_at..]
        .find("EVIDENCE_SEMANTIC_CAPTURE_FAILURES")
        .expect("image arm books its loss");
    let image_body = &object[image_at..image_at + image_end];
    for marker in ["owned_start_remove(&key, true)", "p11_object_fault()"] {
        assert!(
            image_body.contains(marker),
            "object image refusal must {marker}"
        );
    }
    let ordinary = source_between(returned, "fn ordinary_return(", "fn object_return(");
    assert_eq!(
        ordinary.matches("owned_start_remove(&key, true)").count(),
        1,
        "ordinary retirement happens once before accounting"
    );
    // Emission cleanup is the shared production decision: the root
    // calls `emission_finalize` exactly once with the checked removal,
    // then gates on its verdict. No inline retirement may remain for a
    // mutant to short-circuit, and no read may run after a failed
    // emission.
    assert_eq!(
        returned.matches("emission_finalize(").count(),
        1,
        "emission must delegate its cleanup decision to the shared production function"
    );
    assert!(
        !returned.contains("let retired = "),
        "no inline retirement may bypass the shared decision"
    );
    let finalize = returned
        .find("emission_finalize(emitted")
        .expect("emission delegates with its chained stage result");
    let stmt_end = returned[finalize..]
        .find(';')
        .expect("delegated call terminates");
    let stmt = &returned[finalize..finalize + stmt_end];
    assert!(
        stmt.contains("owned_start_remove(&key, true)"),
        "the delegated decision must carry the checked removal"
    );
    let gate = returned
        .find("if !outcome.submitted")
        .expect("emission keeps its success gate");
    assert!(
        finalize < gate,
        "the delegated decision must precede the emission gate"
    );
    let discard = returned
        .rfind("entry.discard(0)")
        .expect("failed emission discards");
    let tail_region = &returned[finalize..discard];
    for forbidden in [
        "p11_object_side_get",
        "object_fill_return(",
        "object_emit_find(",
        "read_word(",
    ] {
        assert!(
            !tail_region.contains(forbidden),
            "no {forbidden} may run after a failed emission"
        );
    }
}

/// G03/E2: every root-level return refusal attempts owned cleanup through
/// the checked owner path. Missing/non-ready side, attached-descriptor
/// and ABI mismatch, image refusal and failed fill/emission each scrub
/// and remove identifiable owned state, settle or explicitly fail the
/// lease, emit no successful tail and fault before returning; unproved
/// ownership never authorizes forced deletion. The native fixture drives
/// the real owner transactions; the emission cleanup decision itself is
/// the shared production `emission_finalize` (executed by
/// `object_emission_finalize_always_attempts_removal`, with the
/// `emitted && remove()` mutant failing there); the pins bind the root
/// arms and the single delegation call.
#[test]
fn object_root_refusal_always_attempts_owned_cleanup() {
    owner_fixture::run_object_subcommand(
        "object_producer_return_refusals_retire_owned_state",
        "object custody return refusals passed",
    );
    pin_root_refusals_retire();
}
