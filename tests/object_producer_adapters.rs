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
    let discard = returned
        .find("entry.discard(0)")
        .expect("failed emission discards");
    assert!(
        drain < submit && drain < discard,
        "the drain retire must precede submit and discard"
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

/// H7-E3 Derive entry mirror. Replicates the CURRENT `object_entry_derive`
/// acquisition order (main.rs `object_entry_derive` at f8f7a7a7): fetch
/// the arg-1 mechanism pointer AND the arg-5 result pointer first, then
/// classify through the REAL shared `capture_derive_entry`. RED state:
/// refused mechanisms still fetch arg5 (on ia32 a stack word read
/// through the real `read_ia32_arg_with` address). The E3 fix classifies
/// the mechanism word first and fetches arg5 only on membership, in both
/// the adapter and this mirror; the order pin below binds them.
fn run_derive_entry_mirror(
    args: &mut ArgSpy<'_>,
    target: &std::cell::RefCell<adapter::FakeTarget>,
    layout: p11scope_ebpf_common::LinuxLayout,
) -> (
    p11scope_ebpf_common::object_capture::DeriveEntry,
    Option<u64>,
) {
    use p11scope_ebpf_common::object_capture::capture_derive_entry;
    // Steps 1-2 (mirror of the two `arg_u64` fetches): both arguments
    // are acquired before any membership check.
    let mechanism_ptr = args.fetch(1).unwrap_or(0);
    let out5_ptr = args.fetch(5).unwrap_or(0);
    // Step 3: the real shared guard classifies and retains.
    let (reader, _) = adapter::readers(target);
    capture_derive_entry(mechanism_ptr, out5_ptr, layout, reader)
}

fn pin_derive_guard_precedes_arg5() {
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF entry root");
    let derive = source_between(
        &source,
        "fn object_entry_derive(",
        "fn object_entry_results(",
    );
    // Membership classification precedes the arg-5 acquisition: the only
    // arg-5 fetch in the adapter runs after the guard.
    let guard = derive
        .find("classify_derive_mechanism")
        .expect("derive entry must classify the mechanism before acquiring arg5");
    let arg5 = derive
        .find("arg_u64(ctx, 5, layout)")
        .expect("derive entry acquires arg5");
    assert!(
        guard < arg5,
        "the derive mechanism guard must precede the arg-5 fetch"
    );
    assert_eq!(
        derive.matches("arg_u64(ctx, 5, layout)").count(),
        1,
        "derive entry fetches arg5 exactly once, after the guard"
    );
}

/// G04/E3: ia32 Derive membership precedes the arg-5 stack read. Exactly
/// the four mechanism words 0x21, 0x393, 0x1050, 0x1051 authorize the
/// arg-5 fetch on each ABI; null, unreadable, unsupported and high-bit
/// mechanisms fetch arg5 zero times, retain nothing and authorize no
/// template access. A matching CKR_OK return reads phKey once;
/// changed/missing S1 return evidence reads it zero times.
#[test]
#[ignore = "RED: H7-E3 derive guard pending"]
fn object_ia32_derive_membership_precedes_arg5_read() {
    use p11scope_ebpf_common::LinuxLayout;
    use p11scope_ebpf_common::capture;
    use p11scope_ebpf_common::object_capture::{
        DeriveEntry, authorize_derive_return, authorize_entry_templates, capture_return_handles,
        derive_mechanism_code, handle_status,
    };
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
        let (entry, retained) = run_derive_entry_mirror(&mut args, &target, LinuxLayout::Lp64);
        assert_eq!(entry, DeriveEntry::Accepted(expected));
        assert_eq!(retained, Some(0x40000));
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
        let (entry, retained) = run_derive_entry_mirror(&mut args, &target, LinuxLayout::Ilp32);
        assert_eq!(entry, DeriveEntry::Accepted(expected));
        assert_eq!(retained, Some(0x40000));
        assert_eq!(args.fetches_of(5), 1, "ia32 {code:#x} fetches arg5 once");
        let arg5_addr = p11scope_ebpf_common::ia32_arg_address(sp, 5).expect("arg5 stack address");
        assert_eq!(
            target.borrow().reads_of(arg5_addr),
            1,
            "ia32 {code:#x} reads the arg-5 stack word once"
        );
        // Matching CKR_OK return reads phKey exactly once.
        let phkey = std::cell::RefCell::new(adapter::FakeTarget::new(4));
        phkey.borrow_mut().set_word(0x40000, 0x77);
        assert!(authorize_derive_return(
            entry,
            adapter::rv_ok(),
            capture::MECHANISM_VALUE,
            code
        ));
        let (reader, _) = adapter::readers(&phkey);
        let (verdict, words) = capture_return_handles(
            [true, false],
            [true, false],
            [0x40000, 0],
            adapter::rv_ok(),
            adapter::owner_ready_authority(),
            LinuxLayout::Ilp32,
            reader,
        );
        assert_eq!(verdict.statuses[0], handle_status::VALUE);
        assert_eq!(words[0], 0x77);
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
                let (entry, retained) = run_derive_entry_mirror(&mut args, &target, layout);
                assert_eq!(entry, DeriveEntry::Unavailable, "{name}");
                assert_eq!(retained, None, "{name} retains nothing");
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
                let templates = authorize_entry_templates(derive_fn, [(0x50000, 2), (0, 0)], entry);
                assert_eq!(templates, [None, None], "{name} authorizes no template");
            } else {
                if let Some(word) = programmed {
                    target.borrow_mut().set_word(0x30000, word);
                } else if mech_ptr != 0 {
                    target.borrow_mut().set_fail(0x30000);
                }
                let mut args =
                    ArgSpy::lp64([None, Some(mech_ptr), None, None, None, Some(0x40000), None]);
                let (entry, retained) = run_derive_entry_mirror(&mut args, &target, layout);
                assert_eq!(entry, DeriveEntry::Unavailable, "{name}");
                assert_eq!(retained, None, "{name} retains nothing");
                assert_eq!(
                    args.fetches_of(5),
                    0,
                    "LP64 {name} performs zero arg-5 fetches"
                );
                let templates = authorize_entry_templates(derive_fn, [(0x50000, 2), (0, 0)], entry);
                assert_eq!(templates, [None, None], "{name} authorizes no template");
            }
        }
        // Changed/missing S1 return evidence reads phKey zero times.
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
            let (reader, _) = adapter::readers(&phkey);
            let (verdict, _) = capture_return_handles(
                [true, false],
                [false, false],
                [0x40000, 0],
                adapter::rv_ok(),
                adapter::owner_ready_authority(),
                layout,
                reader,
            );
            assert_eq!(verdict.statuses[0], handle_status::PROTOCOL_UNAVAILABLE);
            adapter::assert_no_target_reads(&phkey, &format!("{layout:?} phKey on {name}"));
        }
        // Arithmetic overflow: a valid mechanism with an overflowing
        // ia32 stack performs zero stack reads.
        if layout == LinuxLayout::Ilp32 {
            let target = std::cell::RefCell::new(adapter::FakeTarget::new(w));
            target.borrow_mut().set_word(0x30000, 0x21);
            let sp = 0xffff_fff0u64;
            let mut args = ArgSpy::ia32(&target, sp);
            // The mechanism pointer itself is unreadable here (its stack
            // slot overflows too), so entry is unavailable without any
            // stack read landing.
            let (entry, retained) = run_derive_entry_mirror(&mut args, &target, layout);
            assert_eq!(entry, DeriveEntry::Unavailable);
            assert_eq!(retained, None);
            adapter::assert_no_target_reads(&target, "overflowing ia32 stack");
        }
    }
    pin_derive_guard_precedes_arg5();
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
    // Image refusal retires object calls with a fault; ordinary calls
    // keep their existing accounting-only refusal.
    let image_at = returned
        .find("image_pair_matches(start.image, image)")
        .expect("return must keep its image refusal");
    let image_end = returned[image_at..]
        .find("EVIDENCE_SEMANTIC_CAPTURE_FAILURES")
        .expect("image arm books its loss");
    let image_body = &returned[image_at..image_at + image_end];
    for marker in [
        "start.object_required != 0",
        "owned_start_remove(&key, true)",
        "p11_object_fault()",
    ] {
        assert!(
            image_body.contains(marker),
            "the image arm must retire object calls: missing {marker}"
        );
    }
    // Emission retirement is independent of emission success: no
    // short-circuit past the removal, and no read after a failed
    // emission.
    assert!(
        !returned.contains("!emitted || owned_start_remove"),
        "emission cleanup must not short-circuit past the removal"
    );
    let retire = returned
        .find("owned_start_remove(&key, true).is_ok()")
        .expect("emission must evaluate its retirement independently");
    let gate = returned
        .find("if !emitted")
        .expect("emission keeps its success gate");
    assert!(
        retire < gate,
        "the independent retirement must precede the emission gate"
    );
    let discard = returned
        .find("entry.discard(0)")
        .expect("failed emission discards");
    let tail_region = &returned[retire..discard];
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
/// the real owner transactions; the pins bind the root arms line for line.
#[test]
#[ignore = "RED: H7-E2 refusal retirement pending"]
fn object_root_refusal_always_attempts_owned_cleanup() {
    owner_fixture::run_object_subcommand(
        "object_producer_return_refusals_retire_owned_state",
        "object custody return refusals passed",
    );
    pin_root_refusals_retire();
}
