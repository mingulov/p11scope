//! SPDX-License-Identifier: GPL-2.0-or-later
//! H7 slice-C protocol tests: host executions of the production core with
//! injected read spies. Every test asserts exact read sets (addresses and
//! sizes) and proves forbidden fields unread via the read log.

use super::*;
use crate::object_policy::{self, ScalarDeriveMechanism};
use crate::{ARG_NONE, LinuxLayout};
use core::cell::RefCell;

extern crate std;

// Boxed constructors: each fake target is tens of KiB and debug builds keep
// every sequential local alive in the frame, so heap allocation keeps test
// stacks small. The harness itself stays `core`-only.
fn fresh(word_len: u64) -> std::boxed::Box<RefCell<FakeTarget>> {
    std::boxed::Box::new(RefCell::new(FakeTarget::new(word_len)))
}

fn fresh_lp64() -> std::boxed::Box<RefCell<FakeTarget>> {
    fresh(8)
}

fn fresh_ia32() -> std::boxed::Box<RefCell<FakeTarget>> {
    fresh(4)
}

const READ_WORD: u8 = 0;
const READ_BYTES: u8 = 1;

const LOG_MAX: usize = 1024;
const WORDS_MAX: usize = 256;
const BYTES_MAX: usize = 512;
const FAIL_MAX: usize = 32;
const SCRIPT_MAX: usize = 8;

const ERR_FUNCTION_FAILED: u64 = 6;
const ERR_ARGUMENTS_BAD: u64 = 7;

fn fid(name: &str) -> u32 {
    pkcs11_module::FUNCTION_NAMES
        .iter()
        .position(|candidate| *candidate == name)
        .unwrap() as u32
}

/// Fake target memory with an exact read log. Unprogrammed addresses fail:
/// every successful read is explicit test setup, and the log proves which
/// addresses (and byte lengths) the production protocol touched.
struct FakeTarget {
    word_len: u64,
    words: [(u64, u64); WORDS_MAX],
    words_len: usize,
    bytes: [(u64, u8); BYTES_MAX],
    bytes_len: usize,
    failing: [u64; FAIL_MAX],
    failing_len: usize,
    /// Scripted races: on word-read number `at` (0-based among word reads),
    /// `addr` reads as `value` instead of programmed memory.
    script: [(usize, u64, u64); SCRIPT_MAX],
    script_len: usize,
    /// Scripted failures: on word-read number `at`, `addr` fails.
    fail_script: [(usize, u64); SCRIPT_MAX],
    fail_script_len: usize,
    word_read_count: usize,
    log: [(u8, u64, u64); LOG_MAX],
    log_len: usize,
}

impl FakeTarget {
    fn new(word_len: u64) -> Self {
        Self {
            word_len,
            words: [(0, 0); WORDS_MAX],
            words_len: 0,
            bytes: [(0, 0); BYTES_MAX],
            bytes_len: 0,
            failing: [0; FAIL_MAX],
            failing_len: 0,
            script: [(0, 0, 0); SCRIPT_MAX],
            script_len: 0,
            fail_script: [(0, 0); SCRIPT_MAX],
            fail_script_len: 0,
            word_read_count: 0,
            log: [(0, 0, 0); LOG_MAX],
            log_len: 0,
        }
    }

    fn set_word(&mut self, addr: u64, value: u64) {
        assert!(self.words_len < WORDS_MAX, "fake word memory full");
        self.words[self.words_len] = (addr, value);
        self.words_len += 1;
    }

    fn set_bytes(&mut self, addr: u64, data: &[u8]) {
        for (i, byte) in data.iter().enumerate() {
            assert!(self.bytes_len < BYTES_MAX, "fake byte memory full");
            self.bytes[self.bytes_len] = (addr + i as u64, *byte);
            self.bytes_len += 1;
        }
    }

    fn set_fail(&mut self, addr: u64) {
        assert!(self.failing_len < FAIL_MAX, "fake failure list full");
        self.failing[self.failing_len] = addr;
        self.failing_len += 1;
    }

    fn script_word(&mut self, at: usize, addr: u64, value: u64) {
        assert!(self.script_len < SCRIPT_MAX, "fake script full");
        self.script[self.script_len] = (at, addr, value);
        self.script_len += 1;
    }

    fn script_fail(&mut self, at: usize, addr: u64) {
        assert!(self.fail_script_len < SCRIPT_MAX, "fake fail script full");
        self.fail_script[self.fail_script_len] = (at, addr);
        self.fail_script_len += 1;
    }

    fn lookup_word(&self, addr: u64) -> Option<u64> {
        for i in (0..self.words_len).rev() {
            if self.words[i].0 == addr {
                return Some(self.words[i].1);
            }
        }
        None
    }

    fn lookup_byte(&self, addr: u64) -> Option<u8> {
        for i in (0..self.bytes_len).rev() {
            if self.bytes[i].0 == addr {
                return Some(self.bytes[i].1);
            }
        }
        None
    }

    fn read_word(&mut self, addr: u64) -> Result<u64, ()> {
        assert!(self.log_len < LOG_MAX, "read log overflow");
        self.log[self.log_len] = (READ_WORD, addr, self.word_len);
        self.log_len += 1;
        let index = self.word_read_count;
        self.word_read_count += 1;
        for i in 0..self.script_len {
            let (at, script_addr, value) = self.script[i];
            if at == index && script_addr == addr {
                return Ok(value);
            }
        }
        for i in 0..self.fail_script_len {
            let (at, script_addr) = self.fail_script[i];
            if at == index && script_addr == addr {
                return Err(());
            }
        }
        if self.failing[..self.failing_len].contains(&addr) {
            return Err(());
        }
        self.lookup_word(addr).ok_or(())
    }

    fn read_bytes(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), ()> {
        assert!(self.log_len < LOG_MAX, "read log overflow");
        self.log[self.log_len] = (READ_BYTES, addr, buf.len() as u64);
        self.log_len += 1;
        if self.failing[..self.failing_len].contains(&addr) {
            return Err(());
        }
        for (i, slot) in buf.iter_mut().enumerate() {
            let byte_addr = addr.checked_add(i as u64).ok_or(())?;
            *slot = self.lookup_byte(byte_addr).ok_or(())?;
        }
        Ok(())
    }

    fn log(&self) -> &[(u8, u64, u64)] {
        &self.log[..self.log_len]
    }
}

fn word_reader(target: &RefCell<FakeTarget>) -> impl FnMut(u64) -> Result<u64, ()> + '_ {
    |addr: u64| target.borrow_mut().read_word(addr)
}

#[allow(clippy::type_complexity)]
fn readers(
    target: &RefCell<FakeTarget>,
) -> (
    impl FnMut(u64) -> Result<u64, ()> + '_,
    impl FnMut(u64, &mut [u8]) -> Result<(), ()> + '_,
) {
    (
        |addr: u64| target.borrow_mut().read_word(addr),
        |addr: u64, buf: &mut [u8]| target.borrow_mut().read_bytes(addr, buf),
    )
}

fn assert_log(target: &RefCell<FakeTarget>, expected: &[(u8, u64, u64)]) {
    assert_eq!(target.borrow().log(), expected);
}

fn assert_no_read_of(target: &RefCell<FakeTarget>, addr: u64) {
    for entry in target.borrow().log() {
        assert_ne!(entry.1, addr, "forbidden read of {addr:#x}");
    }
}

fn assert_no_bytes_reads(target: &RefCell<FakeTarget>) {
    for entry in target.borrow().log() {
        assert_ne!(entry.0, READ_BYTES, "unexpected value-byte read");
    }
}

/// Program one header's `{type, pValue, ulValueLen}` words. Setup
/// convenience only; every oracle below asserts literal addresses.
fn prog_attr(
    target: &RefCell<FakeTarget>,
    base: u64,
    index: u64,
    w: u64,
    selector: u64,
    ptr: u64,
    len: u64,
) {
    let slot = base + index * 3 * w;
    let mut mem = target.borrow_mut();
    mem.set_word(slot, selector);
    mem.set_word(slot + w, ptr);
    mem.set_word(slot + 2 * w, len);
}

const SEL_CLASS: u64 = 0x0000;
const SEL_TOKEN: u64 = 0x0001;
const SEL_KEYTYPE: u64 = 0x0100;
const SEL_MODBITS: u64 = 0x0121;
const SEL_VALUELEN: u64 = 0x0161;
const SEL_ECPARAMS: u64 = 0x0180;

const EC_P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const EC_P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const EC_P521: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

use attr_kind as ak;
use attr_list_flag as alf;
use attr_status as ast;
use find_flag as ff;
use handle_status as hst;
use object_flag as ofl;

/// Approved named families and their input-handle presence. Cross-checked
/// against the frozen policy below so the table cannot drift silently.
const INPUT_MATRIX: &[(&str, [bool; 2])] = &[
    ("C_CreateObject", [false, false]),
    ("C_CopyObject", [true, false]),
    ("C_GenerateKey", [false, false]),
    ("C_GenerateKeyPair", [false, false]),
    ("C_DeriveKey", [true, false]),
    ("C_UnwrapKey", [true, false]),
    ("C_DestroyObject", [true, false]),
    ("C_GetObjectSize", [true, false]),
    ("C_GetAttributeValue", [true, false]),
    ("C_SetAttributeValue", [true, false]),
    ("C_EncryptInit", [true, false]),
    ("C_DecryptInit", [true, false]),
    ("C_SignInit", [true, false]),
    ("C_SignRecoverInit", [true, false]),
    ("C_VerifyInit", [true, false]),
    ("C_VerifyRecoverInit", [true, false]),
    ("C_MessageEncryptInit", [true, false]),
    ("C_MessageDecryptInit", [true, false]),
    ("C_MessageSignInit", [true, false]),
    ("C_MessageVerifyInit", [true, false]),
    ("C_VerifySignatureInit", [true, false]),
    ("C_DigestKey", [true, false]),
    ("C_WrapKey", [true, true]),
    ("C_SetOperationState", [true, true]),
    ("C_FindObjects", [false, false]),
];

const UNSUPPORTED_NAMES: &[&str] = &[
    "C_UnwrapKeyAuthenticated",
    "C_EncapsulateKey",
    "C_FindObjectsInit",
    "C_DecapsulateKey",
    "C_WrapKeyAuthenticated",
    "C_AsyncComplete",
];

const ERROR_RVS: &[u64] = &[
    ERR_FUNCTION_FAILED,
    ERR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    0x8000_0000,
    u64::MAX,
];

// Mutation caught: any wrong input position, zero/import rule, RV gate,
// pair-overlap/duplicate/partial rule, span check or template authorization.
#[test]
fn object_producer_object_family_matrix() {
    assert_eq!(INPUT_MATRIX.len(), 25);
    assert_eq!(pkcs11_module::FUNCTION_NAMES.len(), 104);
    for (name, present) in INPUT_MATRIX {
        let descriptor = object_policy::object_descriptor(fid(name)).unwrap();
        assert_eq!(
            [
                descriptor.input_args[0] != ARG_NONE,
                descriptor.input_args[1] != ARG_NONE
            ],
            *present,
            "{name}: input presence drifted from policy"
        );
    }

    // (a) Scalar entry inputs across every approved family.
    for (name, present) in INPUT_MATRIX {
        let function = fid(name);
        let (verdict, words) =
            capture_entry_inputs(function, [Some(0x1111), Some(0x2222)], LinuxLayout::Lp64);
        assert!(verdict.supported, "{name}");
        assert_eq!(verdict.object_flags, 0, "{name}");
        for i in 0..2 {
            let expected = if present[i] {
                (hst::VALUE, if i == 0 { 0x1111 } else { 0x2222 })
            } else {
                (hst::ABSENT, 0)
            };
            assert_eq!(verdict.statuses[i], expected.0, "{name}[{i}] status");
            assert_eq!(words[i], expected.1, "{name}[{i}] word");
        }
        // Full-width LP64 handles pass through.
        let (verdict, words) = capture_entry_inputs(
            function,
            [Some(u64::MAX), Some(0x1_0000_0001)],
            LinuxLayout::Lp64,
        );
        for i in 0..2 {
            assert_eq!(
                verdict.statuses[i],
                if present[i] { hst::VALUE } else { hst::ABSENT },
                "{name}[{i}] wide"
            );
            assert_eq!(
                words[i],
                if present[i] {
                    if i == 0 { u64::MAX } else { 0x1_0000_0001 }
                } else {
                    0
                },
                "{name}[{i}] wide word"
            );
        }
        // Zero is invalid except optional absent import keys.
        let (verdict, words) =
            capture_entry_inputs(function, [Some(0), Some(0)], LinuxLayout::Lp64);
        assert!(verdict.supported, "{name}");
        assert_eq!(verdict.object_flags, 0, "{name}");
        for i in 0..2 {
            let expected = if !present[i] || *name == "C_SetOperationState" {
                hst::ABSENT
            } else {
                hst::INVALID_ZERO
            };
            assert_eq!(verdict.statuses[i], expected, "{name} zero[{i}]");
            assert_eq!(words[i], 0, "{name} zero[{i}] word");
        }
        // Unreadable arguments cannot join and raise the failure flag.
        let (verdict, words) = capture_entry_inputs(function, [None, None], LinuxLayout::Lp64);
        let any_present = present[0] || present[1];
        assert_eq!(
            verdict.object_flags,
            if any_present {
                ofl::ARG_READ_FAILURE
            } else {
                0
            },
            "{name} unreadable flags"
        );
        for i in 0..2 {
            assert_eq!(
                verdict.statuses[i],
                if present[i] {
                    hst::UNREADABLE
                } else {
                    hst::ABSENT
                },
                "{name} unreadable[{i}]"
            );
            assert_eq!(words[i], 0, "{name} unreadable[{i}] word");
        }
        // ia32 rejects words with high bits; u32::MAX stays valid.
        let (verdict, words) = capture_entry_inputs(
            function,
            [Some(0x1_0000_0001), Some(u32::MAX as u64)],
            LinuxLayout::Ilp32,
        );
        assert_eq!(
            verdict.statuses[0],
            if present[0] {
                hst::INVALID_SPAN
            } else {
                hst::ABSENT
            },
            "{name} ia32 high[{i}]",
            i = 0
        );
        assert_eq!(words[0], 0, "{name} ia32 high word");
        assert_eq!(
            verdict.statuses[1],
            if present[1] { hst::VALUE } else { hst::ABSENT },
            "{name} ia32 max[{i}]",
            i = 1
        );
    }
    // Import keys are independently optional.
    let import = fid("C_SetOperationState");
    for (args, statuses, words) in [
        ([Some(0x51), Some(0)], [hst::VALUE, hst::ABSENT], [0x51, 0]),
        ([Some(0), Some(0x52)], [hst::ABSENT, hst::VALUE], [0, 0x52]),
        ([None, Some(0x53)], [hst::UNREADABLE, hst::VALUE], [0, 0x53]),
    ] {
        let (verdict, got_words) = capture_entry_inputs(import, args, LinuxLayout::Lp64);
        assert!(verdict.supported);
        assert_eq!(verdict.statuses, statuses);
        assert_eq!(got_words, words);
    }
    let (verdict, _) = capture_entry_inputs(import, [None, Some(0)], LinuxLayout::Lp64);
    assert_eq!(verdict.object_flags, ofl::ARG_READ_FAILURE);

    // (b) Unsupported neighbors and unknown ordinals observe nothing.
    for name in UNSUPPORTED_NAMES {
        let (verdict, words) =
            capture_entry_inputs(fid(name), [Some(0x1111), Some(0x2222)], LinuxLayout::Lp64);
        assert!(!verdict.supported, "{name}");
        assert_eq!(verdict.statuses, [hst::ABSENT, hst::ABSENT], "{name}");
        assert_eq!(verdict.object_flags, 0, "{name}");
        assert_eq!(words, [0, 0], "{name}");
    }
    for ordinal in [104u32, 105, 0x8000_0000, u32::MAX] {
        let (verdict, words) =
            capture_entry_inputs(ordinal, [Some(0x1111), Some(0x2222)], LinuxLayout::Lp64);
        assert!(!verdict.supported, "ordinal {ordinal}");
        assert_eq!(verdict.statuses, [hst::ABSENT, hst::ABSENT]);
        assert_eq!(words, [0, 0]);
    }

    // (c) Single-result returns: CKR_OK reads exactly one word; every other
    // RV, denied authority and refused authorization read nothing.
    for (name, ptr) in [
        ("C_CreateObject", 0xC000u64),
        ("C_CopyObject", 0xC100u64),
        ("C_GenerateKey", 0xC200u64),
        ("C_DeriveKey", 0xC400u64),
        ("C_UnwrapKey", 0xC300u64),
    ] {
        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let w = layout.word_bytes() as u64;
            let target = fresh(w);
            target.borrow_mut().set_word(ptr, 0x777);
            let (verdict, words) = capture_return_handles(
                [true, false],
                [true, false],
                [ptr, 0],
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert_eq!(
                verdict.statuses,
                [hst::VALUE, hst::ABSENT],
                "{name} {layout:?}"
            );
            assert_eq!(words, [0x777, 0], "{name} {layout:?}");
            assert_eq!(verdict.object_flags, 0, "{name} {layout:?}");
            assert_log(&target, &[(READ_WORD, ptr, w)]);

            // Zero and unreadable cells carry finite statuses, never values.
            let target = fresh(w);
            target.borrow_mut().set_word(ptr, 0);
            let (verdict, words) = capture_return_handles(
                [true, false],
                [true, false],
                [ptr, 0],
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert_eq!(verdict.statuses[0], hst::INVALID_ZERO, "{name} {layout:?}");
            assert_eq!(words[0], 0, "{name} {layout:?}");

            let target = fresh(w);
            target.borrow_mut().set_fail(ptr);
            let (verdict, words) = capture_return_handles(
                [true, false],
                [true, false],
                [ptr, 0],
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert_eq!(verdict.statuses[0], hst::UNREADABLE, "{name} {layout:?}");
            assert_eq!(words[0], 0);
            assert_eq!(verdict.object_flags, 0, "single results never partial");

            // Null pointers are not dereferenced.
            let target = fresh(w);
            let (verdict, words) = capture_return_handles(
                [true, false],
                [true, false],
                [0, 0],
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert_eq!(verdict.statuses[0], hst::UNREADABLE, "{name} null");
            assert_eq!(words[0], 0);
            assert_log(&target, &[]);

            // Every non-OK RV refuses without reading.
            for rv in ERROR_RVS
                .iter()
                .copied()
                .chain(core::iter::once(CKR_PENDING))
            {
                let target = fresh(w);
                target.borrow_mut().set_word(ptr, 0x777);
                let (verdict, words) = capture_return_handles(
                    [true, false],
                    [true, false],
                    [ptr, 0],
                    rv,
                    ReturnAuthority::AUTHORIZED,
                    layout,
                    word_reader(&target),
                );
                assert_eq!(
                    verdict.statuses,
                    [hst::PROTOCOL_UNAVAILABLE, hst::ABSENT],
                    "{name} rv {rv:#x}"
                );
                assert_eq!(words, [0, 0], "{name} rv {rv:#x}");
                assert_log(&target, &[]);
            }
            // Denied ownership/phase reads nothing. Continuity stays
            // joined here: these cases deny on owner/phase only.
            for authority in [
                ReturnAuthority {
                    owner_live: false,
                    phase_ready: true,
                    continuity_joined: true,
                },
                ReturnAuthority {
                    owner_live: true,
                    phase_ready: false,
                    continuity_joined: true,
                },
                ReturnAuthority {
                    owner_live: false,
                    phase_ready: false,
                    continuity_joined: true,
                },
            ] {
                let target = fresh(w);
                target.borrow_mut().set_word(ptr, 0x777);
                let (verdict, _) = capture_return_handles(
                    [true, false],
                    [true, false],
                    [ptr, 0],
                    CKR_OK,
                    authority,
                    layout,
                    word_reader(&target),
                );
                assert_eq!(
                    verdict.statuses,
                    [hst::PROTOCOL_UNAVAILABLE, hst::ABSENT],
                    "{name} teardown"
                );
                assert_log(&target, &[]);
            }
            // Refused authorization (Derive guard detail in its own test)
            // reads nothing and flags the unavailable protocol.
            let target = fresh(w);
            target.borrow_mut().set_word(ptr, 0x777);
            let (verdict, words) = capture_return_handles(
                [true, false],
                [false, false],
                [ptr, 0],
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert_eq!(
                verdict.statuses,
                [hst::PROTOCOL_UNAVAILABLE, hst::ABSENT],
                "{name} refused"
            );
            assert_eq!(words, [0, 0]);
            assert_eq!(verdict.object_flags, ofl::UNAVAILABLE_RESULT);
            assert_log(&target, &[]);
        }
    }
    // Families without results never read, whatever scalars arrive.
    for name in [
        "C_DestroyObject",
        "C_GetObjectSize",
        "C_GetAttributeValue",
        "C_SetAttributeValue",
        "C_EncryptInit",
        "C_WrapKey",
        "C_SetOperationState",
        "C_DigestKey",
    ] {
        let target = fresh_lp64();
        let (verdict, words) = capture_return_handles(
            [false, false],
            [false, false],
            [0xC000, 0xC008],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            LinuxLayout::Lp64,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses, [hst::ABSENT, hst::ABSENT], "{name}");
        assert_eq!(words, [0, 0], "{name}");
        assert_eq!(verdict.object_flags, 0, "{name}");
        assert_log(&target, &[]);
    }

    // (d) GenerateKeyPair: independence is proven before either read.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // Distinct values from disjoint spans: two reads, in order.
        let (r0, r1) = (0xC500u64, 0xC600u64);
        let target = fresh(w);
        target.borrow_mut().set_word(r0, 0x101);
        target.borrow_mut().set_word(r1, 0x202);
        let (verdict, words) = capture_return_handles(
            [true, true],
            [true, true],
            [r0, r1],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses, [hst::VALUE, hst::VALUE], "{layout:?}");
        assert_eq!(words, [0x101, 0x202], "{layout:?}");
        assert_eq!(verdict.object_flags, 0, "{layout:?}");
        assert_log(&target, &[(READ_WORD, r0, w), (READ_WORD, r1, w)]);

        // Adjacent spans are disjoint and valid.
        let target = fresh(w);
        target.borrow_mut().set_word(r0, 0x101);
        target.borrow_mut().set_word(r0 + w, 0x202);
        let (verdict, words) = capture_return_handles(
            [true, true],
            [true, true],
            [r0, r0 + w],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses, [hst::VALUE, hst::VALUE], "adjacent");
        assert_eq!(words, [0x101, 0x202]);

        // Equal nonzero handles invalidate both (reads happened first).
        let target = fresh(w);
        target.borrow_mut().set_word(r0, 0x303);
        target.borrow_mut().set_word(r1, 0x303);
        let (verdict, words) = capture_return_handles(
            [true, true],
            [true, true],
            [r0, r1],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert_eq!(
            verdict.statuses,
            [hst::DUPLICATE, hst::DUPLICATE],
            "{layout:?} duplicate"
        );
        assert_eq!(words, [0, 0]);
        assert_eq!(verdict.object_flags, ofl::DUPLICATE_RESULT);
        assert_log(&target, &[(READ_WORD, r0, w), (READ_WORD, r1, w)]);

        // Overlapping spans invalidate both before either read.
        for delta in [0u64, 1, w - 1] {
            let target = fresh(w);
            target.borrow_mut().set_word(r0, 0x101);
            target.borrow_mut().set_word(r0 + delta, 0x202);
            let (verdict, words) = capture_return_handles(
                [true, true],
                [true, true],
                [r0, r0 + delta],
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert_eq!(
                verdict.statuses,
                [hst::ALIAS, hst::ALIAS],
                "{layout:?} overlap +{delta}"
            );
            assert_eq!(words, [0, 0]);
            assert_eq!(verdict.object_flags, ofl::ALIAS);
            assert_log(&target, &[]);
        }
        // Disjoint neighbors stay independent.
        for delta in [w, w + 1] {
            let target = fresh(w);
            target.borrow_mut().set_word(r0, 0x101);
            target.borrow_mut().set_word(r0 + delta, 0x202);
            let (verdict, words) = capture_return_handles(
                [true, true],
                [true, true],
                [r0, r0 + delta],
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert_eq!(
                verdict.statuses,
                [hst::VALUE, hst::VALUE],
                "{layout:?} disjoint +{delta}"
            );
            assert_eq!(words, [0x101, 0x202]);
        }

        // One readable member yields an explicitly partial result.
        let target = fresh(w);
        target.borrow_mut().set_word(r0, 0x101);
        target.borrow_mut().set_fail(r1);
        let (verdict, words) = capture_return_handles(
            [true, true],
            [true, true],
            [r0, r1],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses, [hst::VALUE, hst::UNREADABLE]);
        assert_eq!(words, [0x101, 0]);
        assert_eq!(verdict.object_flags, ofl::PARTIAL_RESULT);

        let target = fresh(w);
        target.borrow_mut().set_fail(r0);
        target.borrow_mut().set_word(r1, 0x202);
        let (verdict, words) = capture_return_handles(
            [true, true],
            [true, true],
            [r0, r1],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses, [hst::UNREADABLE, hst::VALUE]);
        assert_eq!(words, [0, 0x202]);
        assert_eq!(verdict.object_flags, ofl::PARTIAL_RESULT);

        // Zero and null siblings are partial, never invented.
        let target = fresh(w);
        target.borrow_mut().set_word(r0, 0x101);
        target.borrow_mut().set_word(r1, 0);
        let (verdict, _) = capture_return_handles(
            [true, true],
            [true, true],
            [r0, r1],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses, [hst::VALUE, hst::INVALID_ZERO]);
        assert_eq!(verdict.object_flags, ofl::PARTIAL_RESULT);

        let target = fresh(w);
        target.borrow_mut().set_word(r0, 0x101);
        let (verdict, words) = capture_return_handles(
            [true, true],
            [true, true],
            [r0, 0],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses, [hst::VALUE, hst::UNREADABLE]);
        assert_eq!(words, [0x101, 0]);
        assert_eq!(verdict.object_flags, ofl::PARTIAL_RESULT);
        assert_log(&target, &[(READ_WORD, r0, w)]);

        // Both null: unreadable pair, and no partial without a value.
        let target = fresh(w);
        let (verdict, _) = capture_return_handles(
            [true, true],
            [true, true],
            [0, 0],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses, [hst::UNREADABLE, hst::UNREADABLE]);
        assert_eq!(verdict.object_flags, 0);
        assert_log(&target, &[]);

        // Pair RV/authority/authorization gates read nothing.
        for rv in ERROR_RVS
            .iter()
            .copied()
            .chain(core::iter::once(CKR_PENDING))
        {
            let target = fresh(w);
            target.borrow_mut().set_word(r0, 0x101);
            target.borrow_mut().set_word(r1, 0x202);
            let (verdict, words) = capture_return_handles(
                [true, true],
                [true, true],
                [r0, r1],
                rv,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert_eq!(
                verdict.statuses,
                [hst::PROTOCOL_UNAVAILABLE, hst::PROTOCOL_UNAVAILABLE],
                "pair rv {rv:#x}"
            );
            assert_eq!(words, [0, 0]);
            assert_log(&target, &[]);
        }
        let target = fresh(w);
        target.borrow_mut().set_word(r0, 0x101);
        target.borrow_mut().set_word(r1, 0x202);
        let (verdict, _) = capture_return_handles(
            [true, true],
            [true, true],
            [r0, r1],
            CKR_OK,
            ReturnAuthority {
                owner_live: false,
                phase_ready: true,
                continuity_joined: true,
            },
            layout,
            word_reader(&target),
        );
        assert_eq!(
            verdict.statuses,
            [hst::PROTOCOL_UNAVAILABLE, hst::PROTOCOL_UNAVAILABLE]
        );
        assert_log(&target, &[]);
    }

    // (e) Result-span edges: inclusive last byte, no wrap, ia32 range.
    let target = fresh_lp64();
    target.borrow_mut().set_word(u64::MAX - 7, 0x909);
    let (verdict, words) = capture_return_handles(
        [true, false],
        [true, false],
        [u64::MAX - 7, 0],
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        word_reader(&target),
    );
    assert_eq!(verdict.statuses[0], hst::VALUE);
    assert_eq!(words[0], 0x909);
    for bad in [u64::MAX - 6, u64::MAX - 1, u64::MAX] {
        let target = fresh_lp64();
        let (verdict, words) = capture_return_handles(
            [true, false],
            [true, false],
            [bad, 0],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            LinuxLayout::Lp64,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses[0], hst::INVALID_SPAN, "ptr {bad:#x}");
        assert_eq!(words[0], 0);
        assert_log(&target, &[]);
    }
    let target = fresh_ia32();
    target.borrow_mut().set_word(0xFFFF_FFFC, 0x909);
    let (verdict, words) = capture_return_handles(
        [true, false],
        [true, false],
        [0xFFFF_FFFC, 0],
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Ilp32,
        word_reader(&target),
    );
    assert_eq!(verdict.statuses[0], hst::VALUE);
    assert_eq!(words[0], 0x909);
    for bad in [0xFFFF_FFFDu64, 0xFFFF_FFFE, 0xFFFF_FFFF, 0x1_0000_0000] {
        let target = fresh_ia32();
        let (verdict, _) = capture_return_handles(
            [true, false],
            [true, false],
            [bad, 0],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            LinuxLayout::Ilp32,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses[0], hst::INVALID_SPAN, "ptr {bad:#x}");
        assert_log(&target, &[]);
    }
    // A high-bit word where ia32 allows none is refused, never emitted.
    let target = fresh_ia32();
    target.borrow_mut().set_word(0xC000, 0x1_0000_0007);
    let (verdict, words) = capture_return_handles(
        [true, false],
        [true, false],
        [0xC000, 0],
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Ilp32,
        word_reader(&target),
    );
    assert_eq!(verdict.statuses[0], hst::INVALID_SPAN);
    assert_eq!(words[0], 0);

    // (f) Entry template authorization by family and Derive guard.
    let accepted = DeriveEntry::Accepted(ScalarDeriveMechanism::DhPkcs);
    let scalars = [(0x1000u64, 3u64), (0x2000u64, 4u64)];
    for name in [
        "C_CreateObject",
        "C_CopyObject",
        "C_GenerateKey",
        "C_UnwrapKey",
        "C_GetAttributeValue",
    ] {
        assert_eq!(
            authorize_entry_templates(fid(name), scalars, DeriveEntry::Unavailable),
            [Some(scalars[0]), None],
            "{name}"
        );
    }
    assert_eq!(
        authorize_entry_templates(fid("C_GenerateKeyPair"), scalars, DeriveEntry::Unavailable),
        [Some(scalars[0]), Some(scalars[1])]
    );
    assert_eq!(
        authorize_entry_templates(fid("C_DeriveKey"), scalars, accepted),
        [Some(scalars[0]), None]
    );
    assert_eq!(
        authorize_entry_templates(fid("C_DeriveKey"), scalars, DeriveEntry::Unavailable),
        [None, None]
    );
    for name in [
        "C_DestroyObject",
        "C_GetObjectSize",
        "C_SetAttributeValue",
        "C_EncryptInit",
        "C_DecryptInit",
        "C_SignInit",
        "C_SignRecoverInit",
        "C_VerifyInit",
        "C_VerifyRecoverInit",
        "C_MessageEncryptInit",
        "C_MessageDecryptInit",
        "C_MessageSignInit",
        "C_MessageVerifyInit",
        "C_VerifySignatureInit",
        "C_DigestKey",
        "C_WrapKey",
        "C_SetOperationState",
        "C_FindObjects",
    ] {
        assert_eq!(
            authorize_entry_templates(fid(name), scalars, accepted),
            [None, None],
            "{name} reads no template"
        );
    }
    for name in UNSUPPORTED_NAMES {
        assert_eq!(
            authorize_entry_templates(fid(name), scalars, accepted),
            [None, None],
            "{name}"
        );
    }
    for ordinal in [104u32, 105, u32::MAX] {
        assert_eq!(
            authorize_entry_templates(ordinal, scalars, accepted),
            [None, None]
        );
    }
}

// Mutation caught: a cancelled unrelated key leaking an object/access/key-use
// fact, or cancellation suppressing inputs it must not touch.
#[test]
fn object_producer_null_cancel_suppresses_key() {
    const KEY: u64 = 0x9E17_9E17;
    const INITS: &[&str] = &[
        "C_EncryptInit",
        "C_DecryptInit",
        "C_SignInit",
        "C_SignRecoverInit",
        "C_VerifyInit",
        "C_VerifyRecoverInit",
        "C_MessageEncryptInit",
        "C_MessageDecryptInit",
        "C_MessageSignInit",
        "C_MessageVerifyInit",
        "C_VerifySignatureInit",
    ];
    assert_eq!(INITS.len(), 11);
    for name in INITS {
        let function = fid(name);
        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let (entry, words) = capture_entry_inputs(function, [Some(KEY), Some(0xBEEF)], layout);
            assert!(entry.supported, "{name}");
            assert_eq!(entry.statuses, [hst::VALUE, hst::ABSENT], "{name}");
            assert_eq!(words, [KEY, 0], "{name}");

            // Successful cancellation suppresses the unrelated key fact.
            let (cancelled, cancelled_words) =
                apply_null_mechanism_cancel(true, true, entry, words);
            assert_eq!(
                cancelled.statuses,
                [hst::SUPPRESSED, hst::ABSENT],
                "{name} {layout:?}"
            );
            assert_eq!(cancelled_words, [0, 0], "{name} {layout:?}");
            assert_eq!(
                cancelled.object_flags,
                ofl::NULL_MECHANISM_CANCEL,
                "{name} {layout:?}"
            );

            // Without eligibility or observation the key fact survives.
            for (eligible, observed) in [(true, false), (false, true), (false, false)] {
                let (kept, kept_words) =
                    apply_null_mechanism_cancel(eligible, observed, entry, words);
                assert_eq!(kept, entry, "{name} {eligible}/{observed}");
                assert_eq!(kept_words, words, "{name} {eligible}/{observed}");
            }
        }
    }
    // Eligibility is S1's flag as data: ineligible families ignore even an
    // observed transition, and non-value inputs have no key fact to suppress.
    for name in [
        "C_DestroyObject",
        "C_GetObjectSize",
        "C_DigestKey",
        "C_WrapKey",
        "C_SetOperationState",
    ] {
        let (entry, words) =
            capture_entry_inputs(fid(name), [Some(KEY), Some(KEY)], LinuxLayout::Lp64);
        let (kept, kept_words) = apply_null_mechanism_cancel(false, true, entry, words);
        assert_eq!(kept, entry, "{name}");
        assert_eq!(kept_words, words, "{name}");
    }
    let function = fid("C_EncryptInit");
    let (entry, words) = capture_entry_inputs(function, [None, None], LinuxLayout::Lp64);
    let (cancelled, cancelled_words) = apply_null_mechanism_cancel(true, true, entry, words);
    assert_eq!(cancelled.statuses, [hst::UNREADABLE, hst::ABSENT]);
    assert_eq!(cancelled_words, [0, 0]);
    assert_eq!(
        cancelled.object_flags,
        ofl::ARG_READ_FAILURE | ofl::NULL_MECHANISM_CANCEL
    );
    let (entry, words) = capture_entry_inputs(function, [Some(0), None], LinuxLayout::Lp64);
    let (cancelled, _) = apply_null_mechanism_cancel(true, true, entry, words);
    assert_eq!(cancelled.statuses, [hst::INVALID_ZERO, hst::ABSENT]);
    // Cancellation is idempotent and preserves unrelated flags.
    let (entry, words) = capture_entry_inputs(function, [Some(KEY), None], LinuxLayout::Lp64);
    let (once, once_words) = apply_null_mechanism_cancel(true, true, entry, words);
    let (twice, twice_words) = apply_null_mechanism_cancel(true, true, once, once_words);
    assert_eq!(twice, once);
    assert_eq!(twice_words, once_words);
    assert_eq!(twice.statuses[0], hst::SUPPRESSED);
}

const DERIVE_POSITIVES: &[(u64, ScalarDeriveMechanism, u8)] = &[
    (0x21, ScalarDeriveMechanism::DhPkcs, 1),
    (0x393, ScalarDeriveMechanism::Sha256, 2),
    (0x1050, ScalarDeriveMechanism::Ecdh1, 3),
    (0x1051, ScalarDeriveMechanism::Ecdh1Cofactor, 4),
];

/// Successful ignored-`phKey` standards (SSL3/TLS12/WTLS key-material or PRF
/// results outside `phKey`) plus unknown/unrepresentable mechanisms.
const DERIVE_IGNORED: &[u64] = &[
    0x372,
    0x3e1,
    0x3d3,
    0x3d4,
    0x3d5,
    0,
    0x20,
    0x22,
    0x392,
    0x394,
    0x104F,
    0x1052,
    0x8000_0000,
    u32::MAX as u64,
    u64::MAX,
];

// Mutation caught: any `phKey`/template/no-read bypass of the Derive guard:
// a positively identified scalar-result mechanism is required at entry and
// re-proven from existing return evidence, with no extra mechanism read.
#[test]
fn object_producer_derive_guard_precedes_all_reads() {
    use capture::{MECHANISM_NONE, MECHANISM_NULL, MECHANISM_UNREADABLE, MECHANISM_VALUE};
    const MECH: u64 = 0xD000;
    const OUT5: u64 = 0xC400;
    const PHKEY_SENTINEL: u64 = 0xDEAD_BEEF;
    let derive = fid("C_DeriveKey");

    // (a) All four positives on both layouts: exactly one entry word read
    // (nested parameter canaries untouched), retention, template access,
    // matching return evidence and one `phKey` read.
    for (mechanism, expected, code) in DERIVE_POSITIVES {
        assert_eq!(derive_mechanism_code(*expected), *mechanism);
        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let w = layout.word_bytes() as u64;
            let target = fresh(w);
            target.borrow_mut().set_word(MECH, *mechanism);
            target.borrow_mut().set_word(MECH + w, 0xCA1A_CAFE);
            target.borrow_mut().set_word(MECH + 2 * w, 0xCA2A_CAFE);
            let (entry, retained) = capture_derive_entry(MECH, OUT5, layout, word_reader(&target));
            assert_eq!(entry, DeriveEntry::Accepted(*expected), "{layout:?}");
            assert_eq!(entry.code(), *code);
            assert_eq!(retained, Some(OUT5));
            assert_log(&target, &[(READ_WORD, MECH, w)]);
            assert_no_read_of(&target, MECH + w);
            assert_no_read_of(&target, MECH + 2 * w);

            let scalars = [(0x1000u64, 2u64), (0u64, 0u64)];
            assert_eq!(
                authorize_entry_templates(derive, scalars, entry),
                [Some(scalars[0]), None],
                "accepted entry authorizes the request template"
            );

            assert!(
                authorize_derive_return(entry, CKR_OK, MECHANISM_VALUE, *mechanism),
                "{mechanism:#x} {layout:?}"
            );
            let target = fresh(w);
            target.borrow_mut().set_word(OUT5, 0xD817);
            let (verdict, words) = capture_return_handles(
                [true, false],
                [true, false],
                [OUT5, 0],
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert_eq!(verdict.statuses, [hst::VALUE, hst::ABSENT]);
            assert_eq!(words, [0xD817, 0]);
            assert_eq!(verdict.object_flags, 0);
            // The return log holds only the `phKey` read: authorization took
            // existing evidence as data, with no extra mechanism read.
            assert_log(&target, &[(READ_WORD, OUT5, w)]);
        }
    }
    assert_eq!(DeriveEntry::Unavailable.code(), 0);

    // (b) Ignored standards and unknowns: one guard read, then nothing. A
    // readable nonzero `phKey` sentinel gets no exception.
    for mechanism in DERIVE_IGNORED {
        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let w = layout.word_bytes() as u64;
            let target = fresh(w);
            target.borrow_mut().set_word(MECH, *mechanism);
            let (entry, retained) = capture_derive_entry(MECH, OUT5, layout, word_reader(&target));
            assert_eq!(entry, DeriveEntry::Unavailable, "{mechanism:#x} {layout:?}");
            assert_eq!(retained, None, "{mechanism:#x} {layout:?}");
            assert_log(&target, &[(READ_WORD, MECH, w)]);
            let scalars = [(0x1000u64, 2u64), (0u64, 0u64)];
            assert_eq!(
                authorize_entry_templates(derive, scalars, entry),
                [None, None],
                "{mechanism:#x}: entry refusal authorizes no template access"
            );
            assert!(
                !authorize_derive_return(entry, CKR_OK, MECHANISM_VALUE, *mechanism),
                "{mechanism:#x}"
            );
            let target = fresh(w);
            target.borrow_mut().set_word(OUT5, PHKEY_SENTINEL);
            let (verdict, words) = capture_return_handles(
                [true, false],
                [false, false],
                [OUT5, 0],
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert_eq!(verdict.statuses[0], hst::PROTOCOL_UNAVAILABLE);
            assert_eq!(words[0], 0);
            assert_eq!(verdict.object_flags, ofl::UNAVAILABLE_RESULT);
            assert_log(&target, &[]);
            assert_no_read_of(&target, OUT5);
        }
    }

    // (c) High-bit mechanism IDs are not the named mechanisms.
    for (mechanism, _, _) in DERIVE_POSITIVES {
        for high in [1u64 << 16, 1u64 << 32] {
            for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
                let w = layout.word_bytes() as u64;
                let target = fresh(w);
                target.borrow_mut().set_word(MECH, mechanism | high);
                let (entry, retained) =
                    capture_derive_entry(MECH, OUT5, layout, word_reader(&target));
                assert_eq!(
                    entry,
                    DeriveEntry::Unavailable,
                    "{mechanism:#x} | {high:#x} {layout:?}"
                );
                assert_eq!(retained, None);
                assert_log(&target, &[(READ_WORD, MECH, w)]);
                // A matching high-bit return scalar is still not a match.
                let accepted = DeriveEntry::Accepted(derive_entry_mechanism(*mechanism).unwrap());
                assert!(!authorize_derive_return(
                    accepted,
                    CKR_OK,
                    MECHANISM_VALUE,
                    mechanism | high
                ));
            }
        }
    }

    // (d) Null, unreadable and out-of-span mechanism evidence.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let target = fresh(w);
        let (entry, retained) = capture_derive_entry(0, OUT5, layout, word_reader(&target));
        assert_eq!(entry, DeriveEntry::Unavailable, "null {layout:?}");
        assert_eq!(retained, None);
        assert_log(&target, &[]);

        let target = fresh(w);
        target.borrow_mut().set_fail(MECH);
        let (entry, retained) = capture_derive_entry(MECH, OUT5, layout, word_reader(&target));
        assert_eq!(entry, DeriveEntry::Unavailable, "unreadable {layout:?}");
        assert_eq!(retained, None);
        assert_log(&target, &[(READ_WORD, MECH, w)]);
    }
    for bad in [u64::MAX - 6, u64::MAX] {
        let target = fresh_lp64();
        let (entry, retained) =
            capture_derive_entry(bad, OUT5, LinuxLayout::Lp64, word_reader(&target));
        assert_eq!(entry, DeriveEntry::Unavailable, "span {bad:#x}");
        assert_eq!(retained, None);
        assert_log(&target, &[]);
    }
    for bad in [0xFFFF_FFFDu64, 0x1_0000_0000] {
        let target = fresh_ia32();
        let (entry, retained) =
            capture_derive_entry(bad, OUT5, LinuxLayout::Ilp32, word_reader(&target));
        assert_eq!(entry, DeriveEntry::Unavailable, "ia32 span {bad:#x}");
        assert_eq!(retained, None);
        assert_log(&target, &[]);
    }
    // A null arg-5 scalar is retained (not read) on acceptance, then maps to
    // an unreadable result without a dereference.
    let target = fresh_lp64();
    target.borrow_mut().set_word(MECH, 0x21);
    let (entry, retained) = capture_derive_entry(MECH, 0, LinuxLayout::Lp64, word_reader(&target));
    assert!(matches!(entry, DeriveEntry::Accepted(_)));
    assert_eq!(retained, Some(0));
    let target = fresh_lp64();
    let (verdict, _) = capture_return_handles(
        [true, false],
        [true, false],
        [0, 0],
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        word_reader(&target),
    );
    assert_eq!(verdict.statuses[0], hst::UNREADABLE);
    assert_log(&target, &[]);

    // (e) Changed or missing return evidence discards the association
    // without reading `phKey`; non-OK RVs never authorize.
    let accepted = DeriveEntry::Accepted(ScalarDeriveMechanism::Ecdh1);
    for (status, scalar, label) in [
        (MECHANISM_VALUE, 0x1051u64, "changed mechanism"),
        (MECHANISM_VALUE, 0x1050 | (1 << 16), "high-bit return"),
        (MECHANISM_VALUE, 0u64, "zero return"),
        (MECHANISM_NONE, 0x1050u64, "missing evidence"),
        (MECHANISM_NULL, 0x1050u64, "null evidence"),
        (MECHANISM_UNREADABLE, 0x1050u64, "unreadable evidence"),
        (0xFFu32, 0x1050u64, "unknown status"),
    ] {
        assert!(
            !authorize_derive_return(accepted, CKR_OK, status, scalar),
            "{label}"
        );
        let target = fresh_lp64();
        target.borrow_mut().set_word(OUT5, PHKEY_SENTINEL);
        let (verdict, words) = capture_return_handles(
            [true, false],
            [false, false],
            [OUT5, 0],
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            LinuxLayout::Lp64,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses[0], hst::PROTOCOL_UNAVAILABLE, "{label}");
        assert_eq!(words[0], 0, "{label}");
        assert_log(&target, &[]);
    }
    for rv in ERROR_RVS
        .iter()
        .copied()
        .chain(core::iter::once(CKR_PENDING))
    {
        assert!(
            !authorize_derive_return(accepted, rv, MECHANISM_VALUE, 0x1050),
            "rv {rv:#x}"
        );
    }
    assert!(!authorize_derive_return(
        DeriveEntry::Unavailable,
        CKR_OK,
        MECHANISM_VALUE,
        0x1050
    ));
}

/// Test-only inversion of `derive_mechanism_code` over the closed set.
fn derive_entry_mechanism(code: u64) -> Option<ScalarDeriveMechanism> {
    for (mechanism, expected, _) in DERIVE_POSITIVES {
        if *mechanism == code {
            return Some(*expected);
        }
    }
    None
}

// Mutation caught: any unbounded Find read, skipped count/capacity/span
// check, missed count-array alias, silent truncation or lost count race.
#[test]
fn object_producer_find_zero_eight_nine_and_races() {
    const ARRAY: u64 = 0xA000;
    const COUNT: u64 = 0xB000;
    const HANDLES: [u64; 9] = [
        0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007, 0x1008, 0x1009,
    ];

    // (a) Zero reads no array (count read plus its stability reread); eight
    // fills the batch; nine truncates to eight without touching the ninth.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let target = fresh(w);
        target.borrow_mut().set_word(COUNT, 0);
        let (verdict, words) = capture_find_return(
            ARRAY,
            8,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(verdict.valid, "zero {layout:?}");
        assert_eq!(verdict.len, 0);
        assert_eq!(verdict.flags, 0);
        assert_eq!(verdict.statuses, [hst::ABSENT; 8]);
        assert_eq!(words, [0; 8]);
        assert_log(&target, &[(READ_WORD, COUNT, w), (READ_WORD, COUNT, w)]);

        // Zero stays zero even with a null array pointer.
        let target = fresh(w);
        target.borrow_mut().set_word(COUNT, 0);
        let (verdict, _) = capture_find_return(
            0,
            0,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(verdict.valid, "null zero {layout:?}");
        assert_eq!(verdict.len, 0);
        assert_log(&target, &[(READ_WORD, COUNT, w), (READ_WORD, COUNT, w)]);

        // Eight: literal element addresses on both layouts.
        let target = fresh(w);
        target.borrow_mut().set_word(COUNT, 8);
        for (i, handle) in HANDLES[..8].iter().enumerate() {
            target.borrow_mut().set_word(ARRAY + i as u64 * w, *handle);
        }
        let (verdict, words) = capture_find_return(
            ARRAY,
            8,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(verdict.valid, "eight {layout:?}");
        assert_eq!(verdict.len, 8);
        assert_eq!(verdict.flags, 0);
        assert_eq!(verdict.statuses, [hst::VALUE; 8]);
        assert_eq!(words, HANDLES[..8], "eight {layout:?}");
        let mut expected = [(0u8, 0u64, 0u64); 10];
        expected[0] = (READ_WORD, COUNT, w);
        for i in 0..8 {
            expected[1 + i] = (READ_WORD, ARRAY + i as u64 * w, w);
        }
        expected[9] = (READ_WORD, COUNT, w);
        assert_log(&target, &expected);
        // The oracle pins the stride independently of production arithmetic.
        let literal: &[(u8, u64, u64)] = match layout {
            LinuxLayout::Lp64 => &[
                (READ_WORD, COUNT, 8),
                (READ_WORD, 0xA000, 8),
                (READ_WORD, 0xA008, 8),
                (READ_WORD, 0xA010, 8),
                (READ_WORD, 0xA018, 8),
                (READ_WORD, 0xA020, 8),
                (READ_WORD, 0xA028, 8),
                (READ_WORD, 0xA030, 8),
                (READ_WORD, 0xA038, 8),
                (READ_WORD, COUNT, 8),
            ],
            LinuxLayout::Ilp32 => &[
                (READ_WORD, COUNT, 4),
                (READ_WORD, 0xA000, 4),
                (READ_WORD, 0xA004, 4),
                (READ_WORD, 0xA008, 4),
                (READ_WORD, 0xA00C, 4),
                (READ_WORD, 0xA010, 4),
                (READ_WORD, 0xA014, 4),
                (READ_WORD, 0xA018, 4),
                (READ_WORD, 0xA01C, 4),
                (READ_WORD, COUNT, 4),
            ],
        };
        assert_log(&target, literal);

        // Nine: eight words, truncation flag, ninth element never read.
        let target = fresh(w);
        target.borrow_mut().set_word(COUNT, 9);
        for (i, handle) in HANDLES.iter().enumerate() {
            target.borrow_mut().set_word(ARRAY + i as u64 * w, *handle);
        }
        let (verdict, words) = capture_find_return(
            ARRAY,
            9,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(verdict.valid, "nine {layout:?}");
        assert_eq!(verdict.len, 8);
        assert_eq!(verdict.flags, ff::TRUNCATED);
        assert_eq!(verdict.statuses, [hst::VALUE; 8]);
        assert_eq!(words, HANDLES[..8]);
        assert_eq!(target.borrow().log().len(), 10, "nine reads are bounded");
        assert_no_read_of(&target, ARRAY + 8 * w);
    }

    // (b) Count above capacity permits no array read; huge counts refuse.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for (count, capacity) in [(9u64, 8u64), (1, 0), (8, 7), (u64::MAX, 8)] {
            let target = fresh(w);
            target.borrow_mut().set_word(COUNT, count);
            let (verdict, words) = capture_find_return(
                ARRAY,
                capacity,
                COUNT,
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert!(!verdict.valid, "count {count} cap {capacity} {layout:?}");
            assert_eq!(verdict.len, 0);
            assert_eq!(verdict.flags, ff::INVALID_COUNT);
            assert_eq!(verdict.statuses, [hst::ABSENT; 8]);
            assert_eq!(words, [0; 8]);
            assert_log(&target, &[(READ_WORD, COUNT, w)]);
        }
        // A huge count within a huge capacity still refuses: LP64 fails
        // span validation, while ia32 rejects the unrepresentable count.
        let target = fresh(w);
        target.borrow_mut().set_word(COUNT, u64::MAX);
        let (verdict, _) = capture_find_return(
            ARRAY,
            u64::MAX,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(!verdict.valid, "huge span {layout:?}");
        let expected = match layout {
            LinuxLayout::Lp64 => ff::INVALID_SPAN,
            LinuxLayout::Ilp32 => ff::INVALID_COUNT,
        };
        assert_eq!(verdict.flags, expected, "huge span {layout:?}");
        assert_log(&target, &[(READ_WORD, COUNT, w)]);
    }
    // An ia32 count above the 32-bit range is not a count.
    let target = fresh_ia32();
    target.borrow_mut().set_word(COUNT, 0x1_0000_0008);
    let (verdict, _) = capture_find_return(
        ARRAY,
        u64::MAX,
        COUNT,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Ilp32,
        word_reader(&target),
    );
    assert!(!verdict.valid);
    assert_eq!(verdict.flags, ff::INVALID_COUNT);
    assert_log(&target, &[(READ_WORD, COUNT, 4)]);

    // (c) Inclusive last byte: exact-fit spans read, wrap/range violations
    // refuse before any array access.
    let target = fresh_lp64();
    target.borrow_mut().set_word(COUNT, 1);
    target.borrow_mut().set_word(u64::MAX - 7, 0xE1);
    let (verdict, words) = capture_find_return(
        u64::MAX - 7,
        1,
        COUNT,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        word_reader(&target),
    );
    assert!(verdict.valid);
    assert_eq!(verdict.len, 1);
    assert_eq!(words[0], 0xE1);
    for (array, count) in [(u64::MAX - 6, 1u64), (u64::MAX - 15, 3), (0x1000, u64::MAX)] {
        let target = fresh_lp64();
        target.borrow_mut().set_word(COUNT, count);
        let (verdict, _) = capture_find_return(
            array,
            u64::MAX,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            LinuxLayout::Lp64,
            word_reader(&target),
        );
        assert!(!verdict.valid, "array {array:#x} count {count}");
        assert_eq!(verdict.flags, ff::INVALID_SPAN);
        assert_log(&target, &[(READ_WORD, COUNT, 8)]);
    }
    let target = fresh_ia32();
    target.borrow_mut().set_word(COUNT, 2);
    target.borrow_mut().set_word(0xFFFF_FFF8, 0xE1);
    target.borrow_mut().set_word(0xFFFF_FFFC, 0xE2);
    let (verdict, words) = capture_find_return(
        0xFFFF_FFF8,
        2,
        COUNT,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Ilp32,
        word_reader(&target),
    );
    assert!(verdict.valid, "ia32 exact fit");
    assert_eq!(words[..2], [0xE1, 0xE2]);
    for (array, count) in [(0xFFFF_FFFCu64, 2u64), (0x1_0000_0000, 1)] {
        let target = fresh_ia32();
        target.borrow_mut().set_word(COUNT, count);
        let (verdict, _) = capture_find_return(
            array,
            8,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            LinuxLayout::Ilp32,
            word_reader(&target),
        );
        assert!(!verdict.valid, "ia32 array {array:#x}");
        assert_eq!(verdict.flags, ff::INVALID_SPAN);
        assert_log(&target, &[(READ_WORD, COUNT, 4)]);
    }

    // (d) Null count/array and count-array alias refuse; disjoint and zero
    // twins stay valid.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let target = fresh(w);
        let (verdict, _) = capture_find_return(
            ARRAY,
            8,
            0,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(!verdict.valid, "null count {layout:?}");
        assert_eq!(verdict.flags, ff::INVALID_COUNT);
        assert_log(&target, &[]);

        let target = fresh(w);
        target.borrow_mut().set_word(COUNT, 3);
        let (verdict, _) = capture_find_return(
            0,
            8,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(!verdict.valid, "null array {layout:?}");
        assert_eq!(verdict.flags, ff::INVALID_SPAN);
        assert_log(&target, &[(READ_WORD, COUNT, w)]);

        // The count word inside (or at the last byte of) the claimed array.
        for count_ptr in [ARRAY, ARRAY + w, ARRAY + 3 * w - 1] {
            let target = fresh(w);
            for i in 0..3u64 {
                target.borrow_mut().set_word(ARRAY + i * w, 0xF0 + i);
            }
            // Last write wins: the aliased count word reads 3 even where
            // it shares an address with a claimed element.
            target.borrow_mut().set_word(count_ptr, 3);
            let (verdict, words) = capture_find_return(
                ARRAY,
                8,
                count_ptr,
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert!(!verdict.valid, "alias {count_ptr:#x} {layout:?}");
            assert_eq!(verdict.flags, ff::COUNT_ALIAS);
            assert_eq!(words, [0; 8]);
            assert_log(&target, &[(READ_WORD, count_ptr, w)]);
        }
        // First byte past the array is disjoint.
        let target = fresh(w);
        let past = ARRAY + 3 * w;
        target.borrow_mut().set_word(past, 3);
        for i in 0..3u64 {
            target.borrow_mut().set_word(ARRAY + i * w, 0xF0 + i);
        }
        let (verdict, words) = capture_find_return(
            ARRAY,
            8,
            past,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(verdict.valid, "disjoint past-end {layout:?}");
        assert_eq!(verdict.len, 3);
        assert_eq!(words[..3], [0xF0, 0xF1, 0xF2]);
        // An empty claimed span cannot alias the count word.
        let target = fresh(w);
        target.borrow_mut().set_word(ARRAY, 0);
        let (verdict, _) = capture_find_return(
            ARRAY,
            8,
            ARRAY,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(verdict.valid, "zero self-alias {layout:?}");
        assert_eq!(verdict.len, 0);
    }
    // An unreadable count-word span is an invalid count, never a read.
    for (layout, bad) in [
        (LinuxLayout::Lp64, u64::MAX - 6),
        (LinuxLayout::Ilp32, 0xFFFF_FFFD),
    ] {
        let w = layout.word_bytes() as u64;
        let target = fresh(w);
        let (verdict, _) = capture_find_return(
            ARRAY,
            8,
            bad,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(!verdict.valid);
        assert_eq!(verdict.flags, ff::INVALID_COUNT);
        assert_log(&target, &[]);
    }

    // (e) Per-element failure is unknown; neighbors stay usable.
    let target = fresh_lp64();
    target.borrow_mut().set_word(COUNT, 4);
    target.borrow_mut().set_word(ARRAY, 0x2001);
    target.borrow_mut().set_fail(ARRAY + 8);
    target.borrow_mut().set_word(ARRAY + 16, 0);
    target.borrow_mut().set_word(ARRAY + 24, 0x2004);
    let (verdict, words) = capture_find_return(
        ARRAY,
        8,
        COUNT,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        word_reader(&target),
    );
    assert!(verdict.valid, "partial batch stays valid");
    assert_eq!(verdict.len, 4);
    assert_eq!(verdict.flags, ff::UNREADABLE_ELEMENT);
    assert_eq!(
        verdict.statuses,
        [
            hst::VALUE,
            hst::UNREADABLE,
            hst::INVALID_ZERO,
            hst::VALUE,
            hst::ABSENT,
            hst::ABSENT,
            hst::ABSENT,
            hst::ABSENT
        ]
    );
    assert_eq!(words[..4], [0x2001, 0, 0, 0x2004]);
    assert_eq!(verdict.result_cell, (hst::PROTOCOL_UNAVAILABLE, 0));

    // (f) Changed counts discard the whole batch with only the changed flag.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // Stable counts validate; scripted index 4 is the reread after
        // three element reads (0, 1, 2, 3, then reread).
        let target = fresh(w);
        target.borrow_mut().set_word(COUNT, 3);
        for i in 0..3u64 {
            target.borrow_mut().set_word(ARRAY + i * w, 0x300 + i);
        }
        target.borrow_mut().script_word(4, COUNT, 5);
        let (verdict, words) = capture_find_return(
            ARRAY,
            8,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(!verdict.valid, "changed 3->5 {layout:?}");
        assert_eq!(verdict.len, 0);
        assert_eq!(verdict.flags, ff::CHANGED_COUNT);
        assert_eq!(verdict.statuses, [hst::ABSENT; 8]);
        assert_eq!(words, [0; 8]);

        // A changed count suppresses truncation: the validator forbids a
        // truncation flag with zero length.
        let target = fresh(w);
        target.borrow_mut().set_word(COUNT, 9);
        for i in 0..8u64 {
            target.borrow_mut().set_word(ARRAY + i * w, 0x300 + i);
        }
        target.borrow_mut().script_word(9, COUNT, 8);
        let (verdict, _) = capture_find_return(
            ARRAY,
            9,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(!verdict.valid, "changed 9->8 {layout:?}");
        assert_eq!(verdict.flags, ff::CHANGED_COUNT);
        assert_eq!(verdict.flags & ff::TRUNCATED, 0);

        // A failed reread cannot prove stability: discard as changed.
        // Word reads are 0 (count), 1, 2 (elements), 3 (reread): only the
        // reread fails.
        let target = fresh(w);
        target.borrow_mut().set_word(COUNT, 2);
        target.borrow_mut().set_word(ARRAY, 0x301);
        target.borrow_mut().set_word(ARRAY + w, 0x302);
        target.borrow_mut().script_fail(3, COUNT);
        let (verdict, _) = capture_find_return(
            ARRAY,
            8,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(!verdict.valid, "reread failure {layout:?}");
        assert_eq!(verdict.flags, ff::CHANGED_COUNT);

        // Zero racing to nonzero discards the empty batch.
        let target = fresh(w);
        target.borrow_mut().set_word(COUNT, 0);
        target.borrow_mut().script_word(1, COUNT, 5);
        let (verdict, _) = capture_find_return(
            ARRAY,
            8,
            COUNT,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            word_reader(&target),
        );
        assert!(!verdict.valid, "zero race {layout:?}");
        assert_eq!(verdict.flags, ff::CHANGED_COUNT);
    }

    // (g) Non-OK RVs and denied authority read nothing, with no flags.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for rv in ERROR_RVS
            .iter()
            .copied()
            .chain(core::iter::once(CKR_PENDING))
        {
            let target = fresh(w);
            target.borrow_mut().set_word(COUNT, 8);
            let (verdict, words) = capture_find_return(
                ARRAY,
                8,
                COUNT,
                rv,
                ReturnAuthority::AUTHORIZED,
                layout,
                word_reader(&target),
            );
            assert!(!verdict.valid, "rv {rv:#x} {layout:?}");
            assert_eq!(verdict.len, 0);
            assert_eq!(verdict.flags, 0);
            assert_eq!(words, [0; 8]);
            assert_log(&target, &[]);
        }
        let target = fresh(w);
        target.borrow_mut().set_word(COUNT, 8);
        let (verdict, _) = capture_find_return(
            ARRAY,
            8,
            COUNT,
            CKR_OK,
            ReturnAuthority {
                owner_live: true,
                phase_ready: false,
                continuity_joined: true,
            },
            layout,
            word_reader(&target),
        );
        assert!(!verdict.valid);
        assert_log(&target, &[]);
    }

    // (h) Find carries no single-handle result: the constant unavailable cell.
    let target = fresh_lp64();
    target.borrow_mut().set_word(COUNT, 1);
    target.borrow_mut().set_word(ARRAY, 0x777);
    let (verdict, _) = capture_find_return(
        ARRAY,
        8,
        COUNT,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        word_reader(&target),
    );
    assert!(verdict.valid);
    assert_eq!(verdict.result_cell, (hst::PROTOCOL_UNAVAILABLE, 0));
}

// Mutation caught: any narrowed comparison, skipped full-width check,
// unauthorized pointer/length read, missing span/alias/recheck rule or
// wrong finite value on the creation-request path.
#[test]
fn object_producer_attributes_full_width_and_no_read() {
    // (a) Span and address helpers against literal oracles.
    assert_eq!(
        attribute_table_span(0, LinuxLayout::Lp64),
        Some(0),
        "empty LP64"
    );
    assert_eq!(attribute_table_span(1, LinuxLayout::Lp64), Some(24));
    assert_eq!(attribute_table_span(8, LinuxLayout::Lp64), Some(192));
    assert_eq!(attribute_table_span(1, LinuxLayout::Ilp32), Some(12));
    assert_eq!(attribute_table_span(8, LinuxLayout::Ilp32), Some(96));
    assert_eq!(attribute_table_span(u64::MAX, LinuxLayout::Lp64), None);
    assert_eq!(
        attribute_table_span(u64::MAX / 24 + 1, LinuxLayout::Lp64),
        None
    );
    assert_eq!(
        validate_target_span(0x1000, 24, LinuxLayout::Lp64),
        Some(0x1018)
    );
    assert_eq!(validate_target_span(0, 0, LinuxLayout::Lp64), Some(0));
    assert_eq!(validate_target_span(0, 1, LinuxLayout::Lp64), None);
    assert_eq!(
        validate_target_span(u64::MAX - 7, 8, LinuxLayout::Lp64),
        Some(u64::MAX)
    );
    assert_eq!(
        validate_target_span(u64::MAX - 6, 8, LinuxLayout::Lp64),
        None
    );
    assert_eq!(
        validate_target_span(0xFFFF_FFFC, 4, LinuxLayout::Ilp32),
        Some(0x1_0000_0000)
    );
    assert_eq!(
        validate_target_span(0xFFFF_FFFD, 4, LinuxLayout::Ilp32),
        None
    );
    assert_eq!(
        validate_target_span(0x1_0000_0000, 1, LinuxLayout::Ilp32),
        None
    );
    assert_eq!(
        attribute_header_addresses(0x5000, 0, LinuxLayout::Lp64),
        Some((0x5000, 0x5008, 0x5010))
    );
    assert_eq!(
        attribute_header_addresses(0x5000, 1, LinuxLayout::Lp64),
        Some((0x5018, 0x5020, 0x5028))
    );
    assert_eq!(
        attribute_header_addresses(0x5000, 7, LinuxLayout::Lp64),
        Some((0x50A8, 0x50B0, 0x50B8))
    );
    assert_eq!(
        attribute_header_addresses(0x5000, 0, LinuxLayout::Ilp32),
        Some((0x5000, 0x5004, 0x5008))
    );
    assert_eq!(
        attribute_header_addresses(0x5000, 1, LinuxLayout::Ilp32),
        Some((0x500C, 0x5010, 0x5014))
    );
    assert_eq!(
        attribute_header_addresses(u64::MAX - 23, 1, LinuxLayout::Lp64),
        None
    );
    assert!(!spans_overlap(0x1000, 8, 0x1008, 8), "adjacent");
    assert!(spans_overlap(0x1000, 8, 0x1007, 8), "last byte");
    assert!(spans_overlap(0x1000, 8, 0x1000, 8), "identical");
    assert!(!spans_overlap(0x1000, 0, 0x1000, 8), "empty left");
    assert!(!spans_overlap(0x1000, 8, 0x2000, 0), "empty right");
    assert_eq!(unavailable_len(LinuxLayout::Lp64), u64::MAX);
    assert_eq!(unavailable_len(LinuxLayout::Ilp32), u32::MAX as u64);

    // (b) Every finite scalar value classifies on both layouts with an exact
    // seven-read log: selector, pointer, length, value, then the three-word
    // header recheck.
    const SCALARS: &[(u64, u8, &[u64])] = &[
        (SEL_CLASS, ak::CLASS, &[0, 1, 2, 3, 4]),
        (
            SEL_KEYTYPE,
            ak::KEY_TYPE,
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x10, 0x1f, 0x3a, 0x3b],
        ),
        (SEL_TOKEN, ak::TOKEN, &[0, 1]),
        (SEL_VALUELEN, ak::VALUE_LEN, &[16, 24, 32]),
        (
            SEL_MODBITS,
            ak::MODULUS_BITS,
            &[1024, 2048, 3072, 4096, 8192],
        ),
    ];
    for (selector, kind, values) in SCALARS {
        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let w = layout.word_bytes() as u64;
            // Literal slot-0 header addresses pin the stride per layout.
            let (sel_addr, ptr_addr, len_addr) = match layout {
                LinuxLayout::Lp64 => (0x5000u64, 0x5008u64, 0x5010u64),
                LinuxLayout::Ilp32 => (0x5000u64, 0x5004u64, 0x5008u64),
            };
            for value in *values {
                let target = fresh(w);
                const BASE: u64 = 0x5000;
                const VAL: u64 = 0x9000;
                let len = if *kind == ak::TOKEN { 1 } else { w };
                prog_attr(&target, BASE, 0, w, *selector, VAL, len);
                if *kind == ak::TOKEN {
                    target.borrow_mut().set_bytes(VAL, &[*value as u8]);
                } else {
                    target.borrow_mut().set_word(VAL, *value);
                }
                let (mut read_word, mut read_bytes) = readers(&target);
                let outcome = inspect_request_template(
                    BASE,
                    1,
                    None,
                    layout,
                    &mut read_word,
                    &mut read_bytes,
                );
                assert_eq!(outcome.inspected, 1, "{selector:#x}={value}");
                assert_eq!(outcome.flags, alf::PRESENT, "{selector:#x}={value}");
                assert_eq!(outcome.object_flags, 0);
                assert_eq!(
                    outcome.cells[0],
                    AttrCell {
                        kind: *kind,
                        status: ast::VALUE,
                        value: *value as u16,
                    },
                    "{selector:#x}={value} {layout:?}"
                );
                assert_eq!(
                    outcome.cells[1],
                    AttrCell {
                        kind: 0,
                        status: 0,
                        value: 0
                    }
                );
                let value_read = if *kind == ak::TOKEN {
                    (READ_BYTES, VAL, 1)
                } else {
                    (READ_WORD, VAL, w)
                };
                assert_log(
                    &target,
                    &[
                        (READ_WORD, sel_addr, w),
                        (READ_WORD, ptr_addr, w),
                        (READ_WORD, len_addr, w),
                        value_read,
                        (READ_WORD, sel_addr, w),
                        (READ_WORD, ptr_addr, w),
                        (READ_WORD, len_addr, w),
                    ],
                );
            }
        }
    }
    // Scalar zero is a value by status, not by word: class/token/keytype 0.
    for (selector, kind) in [
        (SEL_CLASS, ak::CLASS),
        (SEL_TOKEN, ak::TOKEN),
        (SEL_KEYTYPE, ak::KEY_TYPE),
    ] {
        let target = fresh_lp64();
        let w = 8u64;
        let len = if kind == ak::TOKEN { 1 } else { w };
        prog_attr(&target, 0x5000, 0, w, selector, 0x9000, len);
        if kind == ak::TOKEN {
            target.borrow_mut().set_bytes(0x9000, &[0]);
        } else {
            target.borrow_mut().set_word(0x9000, 0);
        }
        let (mut read_word, mut read_bytes) = readers(&target);
        let outcome = inspect_request_template(
            0x5000,
            1,
            None,
            LinuxLayout::Lp64,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(
            outcome.cells[0],
            AttrCell {
                kind,
                status: ast::VALUE,
                value: 0
            },
            "scalar zero {selector:#x}"
        );
    }
    // Accepted neighbors stay unsupported after a full read and recheck.
    for (selector, bad) in [
        (SEL_CLASS, 5u64),
        (SEL_CLASS, u64::MAX),
        (SEL_KEYTYPE, 0x05),
        (SEL_KEYTYPE, 0x11),
        (SEL_TOKEN, 2),
        (SEL_VALUELEN, 8),
        (SEL_VALUELEN, 64),
        (SEL_MODBITS, 512),
        (SEL_MODBITS, 1025),
    ] {
        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let w = layout.word_bytes() as u64;
            let target = fresh(w);
            let kind = match selector {
                SEL_CLASS => ak::CLASS,
                SEL_KEYTYPE => ak::KEY_TYPE,
                SEL_TOKEN => ak::TOKEN,
                SEL_VALUELEN => ak::VALUE_LEN,
                _ => ak::MODULUS_BITS,
            };
            let len = if kind == ak::TOKEN { 1 } else { w };
            prog_attr(&target, 0x5000, 0, w, selector, 0x9000, len);
            if kind == ak::TOKEN {
                target.borrow_mut().set_bytes(0x9000, &[bad as u8]);
            } else {
                target.borrow_mut().set_word(0x9000, bad);
            }
            let (mut read_word, mut read_bytes) = readers(&target);
            let outcome =
                inspect_request_template(0x5000, 1, None, layout, &mut read_word, &mut read_bytes);
            assert_eq!(
                outcome.cells[0].status,
                ast::UNSUPPORTED,
                "{selector:#x}={bad:#x} {layout:?}"
            );
            assert_eq!(outcome.cells[0].kind, kind);
            assert_eq!(outcome.cells[0].value, 0);
            assert_eq!(target.borrow().log().len(), 7, "full read + recheck");
        }
    }

    // (c) Curves: exact bytes only, lengths 7/10, nothing else.
    for (bytes, curve) in [(EC_P256, 1u16), (EC_P384, 2), (EC_P521, 3)] {
        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let w = layout.word_bytes() as u64;
            let target = fresh(w);
            prog_attr(
                &target,
                0x5000,
                0,
                w,
                SEL_ECPARAMS,
                0x9000,
                bytes.len() as u64,
            );
            target.borrow_mut().set_bytes(0x9000, bytes);
            let (mut read_word, mut read_bytes) = readers(&target);
            let outcome =
                inspect_request_template(0x5000, 1, None, layout, &mut read_word, &mut read_bytes);
            assert_eq!(
                outcome.cells[0],
                AttrCell {
                    kind: ak::EC_PARAMS,
                    status: ast::VALUE,
                    value: curve,
                },
                "curve {curve} {layout:?}"
            );
            // The value read carries the exact bounded length, nothing more.
            let value_entry = target.borrow().log()[3];
            assert_eq!(value_entry, (READ_BYTES, 0x9000, bytes.len() as u64));
        }
    }
    // Mutated encodings and wrong lengths classify nothing.
    let mut bad_p256 = [0u8; 10];
    bad_p256.copy_from_slice(EC_P256);
    bad_p256[9] ^= 0x01;
    for len in [7u64, 10] {
        let target = fresh_lp64();
        prog_attr(&target, 0x5000, 0, 8, SEL_ECPARAMS, 0x9000, len);
        let bytes: &[u8] = if len == 10 { &bad_p256 } else { EC_P384 };
        let mut mutated = [0u8; 10];
        mutated[..bytes.len()].copy_from_slice(bytes);
        mutated[0] ^= 0x80;
        target
            .borrow_mut()
            .set_bytes(0x9000, &mutated[..bytes.len()]);
        let (mut read_word, mut read_bytes) = readers(&target);
        let outcome = inspect_request_template(
            0x5000,
            1,
            None,
            LinuxLayout::Lp64,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(outcome.cells[0].status, ast::UNSUPPORTED, "len {len}");
        assert_eq!(outcome.cells[0].value, 0);
    }
    for len in [0u64, 1, 6, 8, 9, 11, 16] {
        let target = fresh_lp64();
        prog_attr(&target, 0x5000, 0, 8, SEL_ECPARAMS, 0x9000, len);
        let (mut read_word, mut read_bytes) = readers(&target);
        let outcome = inspect_request_template(
            0x5000,
            1,
            None,
            LinuxLayout::Lp64,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(outcome.cells[0].status, ast::INVALID_LENGTH, "len {len}");
        assert_no_bytes_reads(&target);
    }

    // (d) Token reads are exactly one byte; word-sized token lengths refuse.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let target = fresh(w);
        prog_attr(&target, 0x5000, 0, w, SEL_TOKEN, 0x9000, 1);
        target.borrow_mut().set_bytes(0x9000, &[1]);
        target.borrow_mut().set_bytes(0x9001, &[0xBB]);
        let (mut read_word, mut read_bytes) = readers(&target);
        let outcome =
            inspect_request_template(0x5000, 1, None, layout, &mut read_word, &mut read_bytes);
        assert_eq!(outcome.cells[0].status, ast::VALUE);
        assert_eq!(outcome.cells[0].value, 1);
        let value_entry = target.borrow().log()[3];
        assert_eq!(value_entry, (READ_BYTES, 0x9000, 1), "{layout:?} one byte");
        assert_no_read_of(&target, 0x9001);
        for len in [0u64, 2, w, 8] {
            if len == 1 {
                continue;
            }
            let target = fresh(w);
            prog_attr(&target, 0x5000, 0, w, SEL_TOKEN, 0x9000, len);
            let (mut read_word, mut read_bytes) = readers(&target);
            let outcome =
                inspect_request_template(0x5000, 1, None, layout, &mut read_word, &mut read_bytes);
            assert_eq!(
                outcome.cells[0].status,
                ast::INVALID_LENGTH,
                "token len {len} {layout:?}"
            );
            assert_no_bytes_reads(&target);
        }
    }

    // (e) Unknown and excluded selectors: all-zero cell, selector read only.
    // No pointer or length field is touched.
    for selector in [0x0002u64, 0x0102, 0x0103, 0x0160, 0x0181, 0x9999, u64::MAX] {
        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let w = layout.word_bytes() as u64;
            let target = fresh(w);
            prog_attr(&target, 0x5000, 0, w, selector, 0x9000, w);
            target.borrow_mut().set_word(0x9000, 0x1234);
            let (mut read_word, mut read_bytes) = readers(&target);
            let outcome =
                inspect_request_template(0x5000, 1, None, layout, &mut read_word, &mut read_bytes);
            assert_eq!(
                outcome.cells[0],
                AttrCell {
                    kind: 0,
                    status: 0,
                    value: 0
                },
                "selector {selector:#x} {layout:?}"
            );
            assert_eq!(outcome.inspected, 1);
            assert_eq!(outcome.flags, alf::PRESENT);
            assert_log(&target, &[(READ_WORD, 0x5000, w)]);
        }
    }
    // Full-width selector equality: ORed high bits are unknown selectors.
    for (selector, _, _) in SCALARS {
        for high in [1u64 << 16, 1u64 << 32] {
            for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
                let w = layout.word_bytes() as u64;
                let target = fresh(w);
                prog_attr(&target, 0x5000, 0, w, selector | high, 0x9000, w);
                let (mut read_word, mut read_bytes) = readers(&target);
                let outcome = inspect_request_template(
                    0x5000,
                    1,
                    None,
                    layout,
                    &mut read_word,
                    &mut read_bytes,
                );
                assert_eq!(
                    outcome.cells[0],
                    AttrCell {
                        kind: 0,
                        status: 0,
                        value: 0
                    },
                    "{selector:#x}|{high:#x} {layout:?}"
                );
                assert_log(&target, &[(READ_WORD, 0x5000, w)]);
            }
        }
    }
    // High-bit values are read, then rejected; high-bit lengths refuse
    // before any value read.
    for high in [1u64 << 16, 1u64 << 32] {
        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let w = layout.word_bytes() as u64;
            let target = fresh(w);
            prog_attr(&target, 0x5000, 0, w, SEL_CLASS, 0x9000, w);
            target.borrow_mut().set_word(0x9000, 2 | high);
            let (mut read_word, mut read_bytes) = readers(&target);
            let outcome =
                inspect_request_template(0x5000, 1, None, layout, &mut read_word, &mut read_bytes);
            assert_eq!(outcome.cells[0].status, ast::UNSUPPORTED, "{high:#x}");
            assert_eq!(target.borrow().log().len(), 7);

            let target = fresh(w);
            prog_attr(&target, 0x5000, 0, w, SEL_CLASS, 0x9000, w | high);
            target.borrow_mut().set_word(0x9000, 2);
            let (mut read_word, mut read_bytes) = readers(&target);
            let outcome =
                inspect_request_template(0x5000, 1, None, layout, &mut read_word, &mut read_bytes);
            assert_eq!(outcome.cells[0].status, ast::INVALID_LENGTH, "{high:#x}");
            assert_eq!(target.borrow().log().len(), 3, "no value read");
            assert_no_read_of(&target, 0x9000);
        }
    }

    // (f) Null, wrong-length and out-of-span values are never read.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let target = fresh(w);
        prog_attr(&target, 0x5000, 0, w, SEL_CLASS, 0, w);
        let (mut read_word, mut read_bytes) = readers(&target);
        let outcome =
            inspect_request_template(0x5000, 1, None, layout, &mut read_word, &mut read_bytes);
        assert_eq!(outcome.cells[0].status, ast::UNAVAILABLE, "{layout:?} null");
        assert_eq!(outcome.cells[0].kind, ak::CLASS);
        assert_eq!(target.borrow().log().len(), 3);

        for len in [0u64, 1, w - 1, w + 1] {
            let target = fresh(w);
            prog_attr(&target, 0x5000, 0, w, SEL_MODBITS, 0x9000, len);
            target.borrow_mut().set_word(0x9000, 2048);
            let (mut read_word, mut read_bytes) = readers(&target);
            let outcome =
                inspect_request_template(0x5000, 1, None, layout, &mut read_word, &mut read_bytes);
            assert_eq!(
                outcome.cells[0].status,
                ast::INVALID_LENGTH,
                "len {len} {layout:?}"
            );
            assert_no_read_of(&target, 0x9000);
        }
    }
    let target = fresh_lp64();
    prog_attr(&target, 0x5000, 0, 8, SEL_CLASS, u64::MAX - 6, 8);
    let (mut read_word, mut read_bytes) = readers(&target);
    let outcome = inspect_request_template(
        0x5000,
        1,
        None,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::INVALID_SPAN);
    assert_no_read_of(&target, u64::MAX - 6);
    let target = fresh_ia32();
    prog_attr(&target, 0x5000, 0, 4, SEL_CLASS, 0xFFFF_FFFD, 4);
    let (mut read_word, mut read_bytes) = readers(&target);
    let outcome = inspect_request_template(
        0x5000,
        1,
        None,
        LinuxLayout::Ilp32,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::INVALID_SPAN);

    // (g) Selected values overlapping inspected headers or each other are
    // aliases; adjacent spans stay valid. Neighbors stay usable.
    let target = fresh_lp64();
    prog_attr(&target, 0x5000, 0, 8, SEL_CLASS, 0x5008, 8);
    let (mut read_word, mut read_bytes) = readers(&target);
    let outcome = inspect_request_template(
        0x5000,
        1,
        None,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::ALIAS, "value in headers");
    assert_eq!(outcome.object_flags, ofl::ALIAS);
    // 0x5008 is legitimately read as the header pointer word; the exact
    // three-read log proves no separate value read happened there.
    assert_log(
        &target,
        &[
            (READ_WORD, 0x5000, 8),
            (READ_WORD, 0x5008, 8),
            (READ_WORD, 0x5010, 8),
        ],
    );

    let target = fresh_lp64();
    prog_attr(&target, 0x5000, 0, 8, SEL_CLASS, 0x4FF8, 8);
    target.borrow_mut().set_word(0x4FF8, 3);
    let (mut read_word, mut read_bytes) = readers(&target);
    let outcome = inspect_request_template(
        0x5000,
        1,
        None,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::VALUE, "adjacent below valid");

    let target = fresh_lp64();
    prog_attr(&target, 0x5000, 0, 8, SEL_CLASS, 0x9000, 8);
    prog_attr(&target, 0x5000, 1, 8, SEL_TOKEN, 0x9000, 1);
    target.borrow_mut().set_word(0x9000, 2);
    target.borrow_mut().set_bytes(0x9000, &[1]);
    prog_attr(&target, 0x5000, 2, 8, SEL_VALUELEN, 0x9010, 8);
    target.borrow_mut().set_word(0x9010, 24);
    let (mut read_word, mut read_bytes) = readers(&target);
    let outcome = inspect_request_template(
        0x5000,
        3,
        None,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.inspected, 3);
    assert_eq!(outcome.cells[0].status, ast::ALIAS, "shared buffer left");
    assert_eq!(outcome.cells[1].status, ast::ALIAS, "shared buffer right");
    assert_eq!(outcome.cells[2].status, ast::VALUE, "neighbor usable");
    assert_eq!(outcome.cells[2].value, 24);
    assert_eq!(outcome.object_flags, ofl::ALIAS);
    assert_no_read_of(&target, 0x9000);

    let target = fresh_lp64();
    prog_attr(&target, 0x5000, 0, 8, SEL_CLASS, 0x9000, 8);
    prog_attr(&target, 0x5000, 1, 8, SEL_CLASS, 0x9008, 8);
    target.borrow_mut().set_word(0x9000, 1);
    target.borrow_mut().set_word(0x9008, 2);
    let (mut read_word, mut read_bytes) = readers(&target);
    let outcome = inspect_request_template(
        0x5000,
        2,
        None,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::VALUE, "adjacent values left");
    assert_eq!(outcome.cells[1].status, ast::VALUE, "adjacent values right");
    assert_eq!(outcome.object_flags, 0);

    // (h) Post-read header rechecks discard races; header failures keep
    // neighbors. Word reads are T0 P0 L0 V0 T0' P0' L0' (indices 0..7).
    for (index, addr, value, label) in [
        (4u64, 0x5000u64, SEL_KEYTYPE, "selector flip"),
        (5, 0x5008, 0x9800, "pointer flip"),
        (6, 0x5010, 4, "length flip"),
    ] {
        let target = fresh_lp64();
        prog_attr(&target, 0x5000, 0, 8, SEL_CLASS, 0x9000, 8);
        target.borrow_mut().set_word(0x9000, 2);
        target.borrow_mut().script_word(index as usize, addr, value);
        let (mut read_word, mut read_bytes) = readers(&target);
        let outcome = inspect_request_template(
            0x5000,
            1,
            None,
            LinuxLayout::Lp64,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(outcome.cells[0].status, ast::CHANGED, "{label}");
        assert_eq!(outcome.cells[0].value, 0);
        assert_eq!(outcome.object_flags, ofl::CHANGED_METADATA, "{label}");
    }
    let target = fresh_lp64();
    prog_attr(&target, 0x5000, 0, 8, SEL_CLASS, 0x9000, 8);
    target.borrow_mut().set_word(0x9000, 2);
    target.borrow_mut().script_fail(4, 0x5000);
    let (mut read_word, mut read_bytes) = readers(&target);
    let outcome = inspect_request_template(
        0x5000,
        1,
        None,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::UNREADABLE, "recheck failure");

    let target = fresh_lp64();
    target.borrow_mut().set_fail(0x5000);
    prog_attr(&target, 0x5000, 1, 8, SEL_CLASS, 0x9000, 8);
    target.borrow_mut().set_word(0x9000, 4);
    let (mut read_word, mut read_bytes) = readers(&target);
    let outcome = inspect_request_template(
        0x5000,
        2,
        None,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.inspected, 2);
    assert_eq!(
        outcome.cells[0],
        AttrCell {
            kind: 0,
            status: 0,
            value: 0
        }
    );
    assert_eq!(outcome.cells[1].status, ast::VALUE);
    assert_eq!(outcome.flags, alf::PRESENT | alf::HEADER_READ_FAILURE);

    let target = fresh_lp64();
    prog_attr(&target, 0x5000, 0, 8, SEL_TOKEN, 0x9000, 1);
    target.borrow_mut().set_fail(0x5008);
    let (mut read_word, mut read_bytes) = readers(&target);
    let outcome = inspect_request_template(
        0x5000,
        1,
        None,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].kind, ak::TOKEN);
    assert_eq!(outcome.cells[0].status, ast::UNREADABLE);
    assert_eq!(outcome.flags, alf::PRESENT | alf::HEADER_READ_FAILURE);

    // (i) Count edges: empty, full, truncated, huge and null templates.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for base in [0x5000u64, 0] {
            let target = fresh(w);
            let (mut read_word, mut read_bytes) = readers(&target);
            let outcome =
                inspect_request_template(base, 0, None, layout, &mut read_word, &mut read_bytes);
            assert_eq!(outcome.inspected, 0, "empty {base:#x} {layout:?}");
            assert_eq!(outcome.flags, 0);
            assert_log(&target, &[]);
        }
        let target = fresh(w);
        for i in 0..8u64 {
            prog_attr(&target, 0x5000, i, w, SEL_CLASS, 0x9000 + i * 8, w);
            target.borrow_mut().set_word(0x9000 + i * 8, i % 5);
        }
        let (mut read_word, mut read_bytes) = readers(&target);
        let outcome =
            inspect_request_template(0x5000, 8, None, layout, &mut read_word, &mut read_bytes);
        assert_eq!(outcome.inspected, 8, "{layout:?}");
        assert_eq!(outcome.flags, alf::PRESENT, "eight is not truncated");

        let target = fresh(w);
        for i in 0..8u64 {
            prog_attr(&target, 0x5000, i, w, SEL_CLASS, 0x9000 + i * 8, w);
            target.borrow_mut().set_word(0x9000 + i * 8, i % 5);
        }
        let (mut read_word, mut read_bytes) = readers(&target);
        let outcome =
            inspect_request_template(0x5000, 9, None, layout, &mut read_word, &mut read_bytes);
        assert_eq!(outcome.inspected, 8, "nine {layout:?}");
        assert_eq!(outcome.flags, alf::PRESENT | alf::TRUNCATED);
        assert_no_read_of(&target, 0x5000 + 8 * 3 * w);

        let target = fresh(w);
        let (mut read_word, mut read_bytes) = readers(&target);
        let outcome = inspect_request_template(
            0x5000,
            u64::MAX,
            None,
            layout,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(outcome.inspected, 0, "huge {layout:?}");
        assert_eq!(outcome.flags, alf::INVALID_SPAN);
        assert_log(&target, &[]);

        let target = fresh(w);
        let (mut read_word, mut read_bytes) = readers(&target);
        let outcome = inspect_request_template(0, 3, None, layout, &mut read_word, &mut read_bytes);
        assert_eq!(outcome.inspected, 0, "null {layout:?}");
        assert_eq!(outcome.flags, alf::INVALID_SPAN);
        assert_log(&target, &[]);
    }

    // (j) Adapter encodings carry the exact classified bytes, zero-padded.
    let cell = AttrCell {
        kind: ak::KEY_TYPE,
        status: ast::VALUE,
        value: 0x1f,
    };
    let wire = cell.to_wire();
    assert_eq!(wire.kind, ak::KEY_TYPE);
    assert_eq!(wire.status, ast::VALUE);
    assert_eq!(wire.value, 0x1f);
    let outcome = AttributeListOutcome {
        cells: [cell; 8],
        inspected: 3,
        flags: alf::PRESENT,
        object_flags: 0,
    };
    let list = outcome.to_wire();
    assert_eq!(list.cells[0].kind, ak::KEY_TYPE);
    assert_eq!(list.cells[7].value, 0x1f);
    assert_eq!(list.inspected, 3);
    assert_eq!(list.flags, alf::PRESENT);
    assert_eq!(list.reserved, 0);

    // (k) Mixed two-slot template: exact eight-read log in phase order.
    let target = fresh_lp64();
    prog_attr(&target, 0x5000, 0, 8, SEL_CLASS, 0x9000, 8);
    target.borrow_mut().set_word(0x9000, 2);
    prog_attr(&target, 0x5000, 1, 8, 0x0102, 0x9100, 8);
    target.borrow_mut().set_word(0x9100, 0xCAFE);
    let (mut read_word, mut read_bytes) = readers(&target);
    let outcome = inspect_request_template(
        0x5000,
        2,
        None,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.inspected, 2);
    assert_eq!(outcome.flags, alf::PRESENT);
    assert_eq!(outcome.cells[0].status, ast::VALUE);
    assert_eq!(outcome.cells[0].value, 2);
    assert_eq!(
        outcome.cells[1],
        AttrCell {
            kind: 0,
            status: 0,
            value: 0
        }
    );
    assert_log(
        &target,
        &[
            (READ_WORD, 0x5000, 8),
            (READ_WORD, 0x5008, 8),
            (READ_WORD, 0x5010, 8),
            (READ_WORD, 0x5018, 8),
            (READ_WORD, 0x9000, 8),
            (READ_WORD, 0x5000, 8),
            (READ_WORD, 0x5008, 8),
            (READ_WORD, 0x5010, 8),
        ],
    );
    assert_no_read_of(&target, 0x5020);
    assert_no_read_of(&target, 0x5028);
    assert_no_read_of(&target, 0x9100);
}

// Mutation caught: any retained unselected pointer, missed header/length/
// span/alias check, lost partial-RV neighbor, dropped duplicate, pair
// cross-talk or stale-retry reuse on the GetAttribute and pair paths.
#[test]
fn object_producer_attributes_partial_alias_retry() {
    const BASE: u64 = 0x5000;
    const PEER_BASE: u64 = 0x6000;

    // (a) Get entry retains only selected header facts; unknown selectors
    // authorize no pointer/length reads.
    let target = fresh_lp64();
    prog_attr(&target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    prog_attr(&target, BASE, 1, 8, 0x0102, 0x9100, 8);
    prog_attr(&target, BASE, 2, 8, SEL_TOKEN, 0, 1);
    prog_attr(&target, BASE, 3, 8, SEL_ECPARAMS, 0x9020, 10);
    let mut state = GetEntryState::default();
    let verdict = capture_get_entry(BASE, 4, LinuxLayout::Lp64, &mut state, word_reader(&target));
    assert_eq!(verdict.inspected, 4);
    assert_eq!(verdict.slot_count, 3);
    assert_eq!(verdict.entry_flags, 0);
    assert_eq!(state.slot_count, 3);
    assert_eq!(state.inspected, 4);
    assert_eq!(state.template_base, BASE);
    assert_eq!(state.header_end, BASE + 4 * 24);
    assert_eq!(state.slots[0].kind, ak::CLASS);
    assert_eq!(state.slots[0].slot_index, 0);
    assert_eq!(state.slots[0].value_ptr, 0x9000);
    assert_eq!(state.slots[0].entry_capacity, 8);
    assert_eq!(state.slots[1].kind, ak::TOKEN);
    assert_eq!(state.slots[1].slot_index, 2);
    assert_eq!(state.slots[1].value_ptr, 0);
    assert_eq!(state.slots[2].kind, ak::EC_PARAMS);
    assert_eq!(state.slots[2].slot_index, 3);
    assert_eq!(state.slots[2].entry_capacity, 10);
    assert_log(
        &target,
        &[
            (READ_WORD, 0x5000, 8),
            (READ_WORD, 0x5008, 8),
            (READ_WORD, 0x5010, 8),
            (READ_WORD, 0x5018, 8),
            (READ_WORD, 0x5030, 8),
            (READ_WORD, 0x5038, 8),
            (READ_WORD, 0x5040, 8),
            (READ_WORD, 0x5048, 8),
            (READ_WORD, 0x5050, 8),
            (READ_WORD, 0x5058, 8),
        ],
    );
    assert_no_read_of(&target, 0x5020);
    assert_no_read_of(&target, 0x5028);

    // Entry truncation, header failure and invalid spans record flags.
    let target = fresh_lp64();
    for i in 0..8u64 {
        prog_attr(&target, BASE, i, 8, SEL_CLASS, 0x9000 + i * 8, 8);
    }
    let mut state = GetEntryState::default();
    let verdict = capture_get_entry(BASE, 9, LinuxLayout::Lp64, &mut state, word_reader(&target));
    assert_eq!(verdict.inspected, 8);
    assert_eq!(verdict.slot_count, 8);
    assert_eq!(verdict.entry_flags, alf::TRUNCATED);
    assert_no_read_of(&target, BASE + 8 * 24);

    let target = fresh_lp64();
    prog_attr(&target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    target.borrow_mut().set_fail(BASE + 24);
    let mut state = GetEntryState::default();
    let verdict = capture_get_entry(BASE, 2, LinuxLayout::Lp64, &mut state, word_reader(&target));
    assert_eq!(verdict.slot_count, 1);
    assert_eq!(verdict.entry_flags, alf::HEADER_READ_FAILURE);

    for (base, count) in [(0u64, 3u64), (BASE, u64::MAX)] {
        let target = fresh_lp64();
        let mut state = GetEntryState::default();
        let verdict = capture_get_entry(
            base,
            count,
            LinuxLayout::Lp64,
            &mut state,
            word_reader(&target),
        );
        assert_eq!(verdict.inspected, 0);
        assert_eq!(verdict.slot_count, 0);
        assert_eq!(verdict.entry_flags, alf::INVALID_SPAN);
        assert_log(&target, &[]);
    }
    let target = fresh_lp64();
    let mut state = GetEntryState::default();
    let verdict = capture_get_entry(0, 0, LinuxLayout::Lp64, &mut state, word_reader(&target));
    assert_eq!(verdict.inspected, 0);
    assert_eq!(verdict.entry_flags, 0);
    assert_log(&target, &[]);

    // (b) Get return happy path: two slots, exact fourteen-read log in
    // phase order (all headers, then per-slot value plus recheck).
    let entry_target = fresh_lp64();
    prog_attr(&entry_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    prog_attr(&entry_target, BASE, 1, 8, SEL_TOKEN, 0x9010, 2);
    let mut state = GetEntryState::default();
    let entry_verdict = capture_get_entry(
        BASE,
        2,
        LinuxLayout::Lp64,
        &mut state,
        word_reader(&entry_target),
    );
    assert_eq!(entry_verdict.slot_count, 2);
    let return_target = fresh_lp64();
    prog_attr(&return_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    return_target.borrow_mut().set_word(0x9000, 3);
    prog_attr(&return_target, BASE, 1, 8, SEL_TOKEN, 0x9010, 1);
    return_target.borrow_mut().set_bytes(0x9010, &[1]);
    let (mut read_word, mut read_bytes) = readers(&return_target);
    let outcome = capture_get_return(
        &state,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.inspected, 2);
    assert_eq!(outcome.flags, alf::PRESENT);
    assert_eq!(outcome.object_flags, 0);
    assert_eq!(
        outcome.cells[0],
        AttrCell {
            kind: ak::CLASS,
            status: ast::VALUE,
            value: 3
        }
    );
    assert_eq!(
        outcome.cells[1],
        AttrCell {
            kind: ak::TOKEN,
            status: ast::VALUE,
            value: 1
        }
    );
    assert_log(
        &return_target,
        &[
            (READ_WORD, 0x5000, 8),
            (READ_WORD, 0x5008, 8),
            (READ_WORD, 0x5010, 8),
            (READ_WORD, 0x5018, 8),
            (READ_WORD, 0x5020, 8),
            (READ_WORD, 0x5028, 8),
            (READ_WORD, 0x9000, 8),
            (READ_WORD, 0x5000, 8),
            (READ_WORD, 0x5008, 8),
            (READ_WORD, 0x5010, 8),
            (READ_BYTES, 0x9010, 1),
            (READ_WORD, 0x5018, 8),
            (READ_WORD, 0x5020, 8),
            (READ_WORD, 0x5028, 8),
        ],
    );

    // Accepted partial RVs process normally; every other RV refuses.
    assert!(return_accepts_get_results(CKR_OK));
    assert!(return_accepts_get_results(CKR_ATTRIBUTE_SENSITIVE));
    assert!(return_accepts_get_results(CKR_ATTRIBUTE_TYPE_INVALID));
    assert!(return_accepts_get_results(CKR_BUFFER_TOO_SMALL));
    for rv in [
        ERR_FUNCTION_FAILED,
        ERR_ARGUMENTS_BAD,
        CKR_PENDING,
        0x8000_0000,
        u64::MAX,
    ] {
        assert!(!return_accepts_get_results(rv), "rv {rv:#x}");
    }
    for rv in [
        CKR_ATTRIBUTE_SENSITIVE,
        CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_BUFFER_TOO_SMALL,
    ] {
        let return_target = fresh_lp64();
        prog_attr(&return_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
        return_target.borrow_mut().set_word(0x9000, 2);
        prog_attr(&return_target, BASE, 1, 8, SEL_TOKEN, 0x9010, 1);
        return_target.borrow_mut().set_bytes(0x9010, &[0]);
        let (mut read_word, mut read_bytes) = readers(&return_target);
        let outcome = capture_get_return(
            &state,
            rv,
            ReturnAuthority::AUTHORIZED,
            LinuxLayout::Lp64,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(outcome.cells[0].status, ast::VALUE, "partial rv {rv:#x}");
        assert_eq!(outcome.cells[1].status, ast::VALUE, "partial rv {rv:#x}");
    }
    for rv in [ERR_FUNCTION_FAILED, ERR_ARGUMENTS_BAD, CKR_PENDING] {
        let return_target = fresh_lp64();
        let (mut read_word, mut read_bytes) = readers(&return_target);
        let outcome = capture_get_return(
            &state,
            rv,
            ReturnAuthority::AUTHORIZED,
            LinuxLayout::Lp64,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(outcome.inspected, 0, "refused rv {rv:#x}");
        assert_eq!(outcome.flags, 0);
        assert_eq!(
            outcome.cells[0],
            AttrCell {
                kind: 0,
                status: 0,
                value: 0
            }
        );
        assert_log(&return_target, &[]);
    }
    let return_target = fresh_lp64();
    let (mut read_word, mut read_bytes) = readers(&return_target);
    let outcome = capture_get_return(
        &state,
        CKR_OK,
        ReturnAuthority {
            owner_live: false,
            phase_ready: true,
            continuity_joined: true,
        },
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.inspected, 0, "denied authority");
    assert_log(&return_target, &[]);
    // Entry flags merge into the result list even when the entry outcome
    // carried them alone.
    let entry_target = fresh_lp64();
    for i in 0..8u64 {
        prog_attr(&entry_target, BASE, i, 8, SEL_CLASS, 0x9000 + i * 8, 8);
    }
    let mut trunc_state = GetEntryState::default();
    let entry_verdict = capture_get_entry(
        BASE,
        9,
        LinuxLayout::Lp64,
        &mut trunc_state,
        word_reader(&entry_target),
    );
    assert_eq!(entry_verdict.entry_flags, alf::TRUNCATED);
    let return_target = fresh_lp64();
    for i in 0..8u64 {
        prog_attr(&return_target, BASE, i, 8, SEL_CLASS, 0x9000 + i * 8, 8);
        return_target.borrow_mut().set_word(0x9000 + i * 8, i % 5);
    }
    let (mut read_word, mut read_bytes) = readers(&return_target);
    let outcome = capture_get_return(
        &trunc_state,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.inspected, 8);
    assert_eq!(outcome.flags, alf::PRESENT | alf::TRUNCATED);
    assert!(outcome.cells.iter().all(|cell| cell.status == ast::VALUE));

    // (c) Width-correct unavailable sentinel; growing and inexact lengths.
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // All-ones at the target width is unavailable, without a value read.
        let entry_target = fresh(w);
        prog_attr(&entry_target, BASE, 0, w, SEL_MODBITS, 0x9000, w);
        let mut one = GetEntryState::default();
        capture_get_entry(BASE, 1, layout, &mut one, word_reader(&entry_target));
        let return_target = fresh(w);
        prog_attr(
            &return_target,
            BASE,
            0,
            w,
            SEL_MODBITS,
            0x9000,
            unavailable_len(layout),
        );
        let (mut read_word, mut read_bytes) = readers(&return_target);
        let outcome = capture_get_return(
            &one,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(outcome.cells[0].status, ast::UNAVAILABLE, "{layout:?}");
        assert_eq!(outcome.cells[0].kind, ak::MODULUS_BITS);
        assert_no_bytes_reads(&return_target);
        assert_eq!(return_target.borrow().log().len(), 3, "header only");

        // Width-incorrect all-ones is an invalid length, never unavailable.
        let wrong = if layout == LinuxLayout::Lp64 {
            u32::MAX as u64
        } else {
            u64::MAX
        };
        let return_target = fresh(w);
        prog_attr(&return_target, BASE, 0, w, SEL_MODBITS, 0x9000, wrong);
        let (mut read_word, mut read_bytes) = readers(&return_target);
        let outcome = capture_get_return(
            &one,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(outcome.cells[0].status, ast::INVALID_LENGTH, "{layout:?}");

        // Entry capacity below the exact shape is insufficient capacity.
        let entry_target = fresh(w);
        prog_attr(&entry_target, BASE, 0, w, SEL_CLASS, 0x9000, w - 1);
        let mut small = GetEntryState::default();
        capture_get_entry(BASE, 1, layout, &mut small, word_reader(&entry_target));
        let return_target = fresh(w);
        prog_attr(&return_target, BASE, 0, w, SEL_CLASS, 0x9000, w - 1);
        return_target.borrow_mut().set_word(0x9000, 2);
        let (mut read_word, mut read_bytes) = readers(&return_target);
        let outcome = capture_get_return(
            &small,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(
            outcome.cells[0].status,
            ast::INSUFFICIENT_CAPACITY,
            "{layout:?}"
        );
        assert_no_read_of(&return_target, 0x9000);

        // A returned length above capacity (growing) or merely inexact is
        // invalid, without a value read.
        for (capacity, returned) in [(w, w - 1), (w, w + 1), (w, 0), (2 * w, 3 * w)] {
            let entry_target = fresh(w);
            prog_attr(&entry_target, BASE, 0, w, SEL_CLASS, 0x9000, capacity);
            let mut grown = GetEntryState::default();
            capture_get_entry(BASE, 1, layout, &mut grown, word_reader(&entry_target));
            let return_target = fresh(w);
            prog_attr(&return_target, BASE, 0, w, SEL_CLASS, 0x9000, returned);
            return_target.borrow_mut().set_word(0x9000, 2);
            let (mut read_word, mut read_bytes) = readers(&return_target);
            let outcome = capture_get_return(
                &grown,
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                &mut read_word,
                &mut read_bytes,
            );
            assert_eq!(
                outcome.cells[0].status,
                ast::INVALID_LENGTH,
                "cap {capacity} ret {returned} {layout:?}"
            );
            assert_no_read_of(&return_target, 0x9000);
        }
        // A larger entry capacity with an exact returned length is valid.
        let entry_target = fresh(w);
        prog_attr(&entry_target, BASE, 0, w, SEL_TOKEN, 0x9000, 4);
        let mut roomy = GetEntryState::default();
        capture_get_entry(BASE, 1, layout, &mut roomy, word_reader(&entry_target));
        let return_target = fresh(w);
        prog_attr(&return_target, BASE, 0, w, SEL_TOKEN, 0x9000, 1);
        return_target.borrow_mut().set_bytes(0x9000, &[1]);
        let (mut read_word, mut read_bytes) = readers(&return_target);
        let outcome = capture_get_return(
            &roomy,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(outcome.cells[0].status, ast::VALUE, "{layout:?} roomy");
        let value_entry = return_target.borrow().log()[3];
        assert_eq!(value_entry, (READ_BYTES, 0x9000, 1));
    }

    // (d) Null entry pointers stay size-only even when the return header
    // changes the pointer; other header changes discard the attribute.
    let entry_target = fresh_lp64();
    prog_attr(&entry_target, BASE, 0, 8, SEL_TOKEN, 0, 8);
    let mut null_entry = GetEntryState::default();
    capture_get_entry(
        BASE,
        1,
        LinuxLayout::Lp64,
        &mut null_entry,
        word_reader(&entry_target),
    );
    for return_ptr in [0u64, 0x9000] {
        let return_target = fresh_lp64();
        prog_attr(&return_target, BASE, 0, 8, SEL_TOKEN, return_ptr, 1);
        return_target.borrow_mut().set_bytes(0x9000, &[1]);
        let (mut read_word, mut read_bytes) = readers(&return_target);
        let outcome = capture_get_return(
            &null_entry,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            LinuxLayout::Lp64,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(
            outcome.cells[0],
            AttrCell {
                kind: ak::TOKEN,
                status: ast::SIZE_ONLY,
                value: 0
            },
            "null entry, return ptr {return_ptr:#x}"
        );
        assert_no_read_of(&return_target, 0x9000);
    }
    // Non-null entries require the unchanged selector and pointer; the
    // length legitimately narrows from capacity to exact size.
    let entry_target = fresh_lp64();
    prog_attr(&entry_target, BASE, 0, 8, SEL_CLASS, 0x9000, 16);
    let mut narrow = GetEntryState::default();
    capture_get_entry(
        BASE,
        1,
        LinuxLayout::Lp64,
        &mut narrow,
        word_reader(&entry_target),
    );
    let return_target = fresh_lp64();
    prog_attr(&return_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    return_target.borrow_mut().set_word(0x9000, 4);
    let (mut read_word, mut read_bytes) = readers(&return_target);
    let outcome = capture_get_return(
        &narrow,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::VALUE, "capacity narrows");
    for (selector, ptr, label) in [
        (SEL_KEYTYPE, 0x9000u64, "selector flip"),
        (SEL_CLASS, 0x9010u64, "pointer flip"),
        (SEL_CLASS, 0u64, "pointer nulled"),
    ] {
        let return_target = fresh_lp64();
        prog_attr(&return_target, BASE, 0, 8, selector, ptr, 8);
        return_target.borrow_mut().set_word(0x9000, 4);
        return_target.borrow_mut().set_word(0x9010, 4);
        let (mut read_word, mut read_bytes) = readers(&return_target);
        let outcome = capture_get_return(
            &narrow,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            LinuxLayout::Lp64,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(outcome.cells[0].status, ast::CHANGED, "{label}");
        assert_eq!(outcome.object_flags, ofl::CHANGED_METADATA, "{label}");
    }
    // Post-read recheck races discard the value just read.
    let return_target = fresh_lp64();
    prog_attr(&return_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    return_target.borrow_mut().set_word(0x9000, 4);
    return_target.borrow_mut().script_word(4, BASE, SEL_TOKEN);
    let (mut read_word, mut read_bytes) = readers(&return_target);
    let outcome = capture_get_return(
        &narrow,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::CHANGED, "recheck flip");
    let return_target = fresh_lp64();
    prog_attr(&return_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    return_target.borrow_mut().set_word(0x9000, 4);
    return_target.borrow_mut().script_fail(5, BASE + 8);
    let (mut read_word, mut read_bytes) = readers(&return_target);
    let outcome = capture_get_return(
        &narrow,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::UNREADABLE, "recheck failure");

    // (e) Return rereads only retained slots; unknown selector pointers
    // stay unread across both phases.
    let entry_target = fresh_lp64();
    prog_attr(&entry_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    prog_attr(&entry_target, BASE, 1, 8, 0x0102, 0x9100, 8);
    prog_attr(&entry_target, BASE, 2, 8, SEL_TOKEN, 0x9020, 1);
    let mut sparse = GetEntryState::default();
    let entry_verdict = capture_get_entry(
        BASE,
        3,
        LinuxLayout::Lp64,
        &mut sparse,
        word_reader(&entry_target),
    );
    assert_eq!(entry_verdict.slot_count, 2);
    assert_no_read_of(&entry_target, 0x9100);
    let return_target = fresh_lp64();
    prog_attr(&return_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    return_target.borrow_mut().set_word(0x9000, 1);
    prog_attr(&return_target, BASE, 2, 8, SEL_TOKEN, 0x9020, 1);
    return_target.borrow_mut().set_bytes(0x9020, &[1]);
    let (mut read_word, mut read_bytes) = readers(&return_target);
    let outcome = capture_get_return(
        &sparse,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    // The result list mirrors template slots: the unretained middle slot
    // stays a zero cell while its neighbors classify.
    assert_eq!(outcome.inspected, 3);
    assert_eq!(outcome.cells[0].status, ast::VALUE);
    assert_eq!(
        outcome.cells[1],
        AttrCell {
            kind: 0,
            status: 0,
            value: 0
        }
    );
    assert_eq!(outcome.cells[2].status, ast::VALUE);
    assert_eq!(outcome.cells[2].kind, ak::TOKEN);
    for addr in [0x5018u64, 0x5020, 0x5028, 0x9100] {
        assert_no_read_of(&return_target, addr);
    }

    // (f) Get span aliasing mirrors requests; adjacent spans stay valid.
    let entry_target = fresh_lp64();
    prog_attr(&entry_target, BASE, 0, 8, SEL_CLASS, 0x5010, 8);
    let mut headed = GetEntryState::default();
    capture_get_entry(
        BASE,
        1,
        LinuxLayout::Lp64,
        &mut headed,
        word_reader(&entry_target),
    );
    let return_target = fresh_lp64();
    prog_attr(&return_target, BASE, 0, 8, SEL_CLASS, 0x5010, 8);
    let (mut read_word, mut read_bytes) = readers(&return_target);
    let outcome = capture_get_return(
        &headed,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::ALIAS, "value in headers");
    assert_eq!(outcome.object_flags, ofl::ALIAS);
    // 0x5010 is legitimately reread as the header length word; the exact
    // three-read log proves no separate value read happened there.
    assert_log(
        &return_target,
        &[
            (READ_WORD, 0x5000, 8),
            (READ_WORD, 0x5008, 8),
            (READ_WORD, 0x5010, 8),
        ],
    );

    let entry_target = fresh_lp64();
    prog_attr(&entry_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    prog_attr(&entry_target, BASE, 1, 8, SEL_CLASS, 0x9004, 8);
    prog_attr(&entry_target, BASE, 2, 8, SEL_CLASS, 0x9010, 8);
    let mut crossed = GetEntryState::default();
    capture_get_entry(
        BASE,
        3,
        LinuxLayout::Lp64,
        &mut crossed,
        word_reader(&entry_target),
    );
    let return_target = fresh_lp64();
    for (i, ptr) in [0x9000u64, 0x9004, 0x9010].iter().enumerate() {
        prog_attr(&return_target, BASE, i as u64, 8, SEL_CLASS, *ptr, 8);
        return_target.borrow_mut().set_word(*ptr, 1);
    }
    let (mut read_word, mut read_bytes) = readers(&return_target);
    let outcome = capture_get_return(
        &crossed,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::ALIAS, "overlap left");
    assert_eq!(outcome.cells[1].status, ast::ALIAS, "overlap right");
    assert_eq!(outcome.cells[2].status, ast::VALUE, "neighbor usable");

    // (g) Duplicates with disjoint spans persist as separate cells: equal
    // values for downstream coalescing, conflicting values for Conflict.
    for (left, right) in [(2u64, 2u64), (1, 3)] {
        let entry_target = fresh_lp64();
        prog_attr(&entry_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
        prog_attr(&entry_target, BASE, 1, 8, SEL_CLASS, 0x9010, 8);
        let mut dup = GetEntryState::default();
        capture_get_entry(
            BASE,
            2,
            LinuxLayout::Lp64,
            &mut dup,
            word_reader(&entry_target),
        );
        let return_target = fresh_lp64();
        prog_attr(&return_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
        prog_attr(&return_target, BASE, 1, 8, SEL_CLASS, 0x9010, 8);
        return_target.borrow_mut().set_word(0x9000, left);
        return_target.borrow_mut().set_word(0x9010, right);
        let (mut read_word, mut read_bytes) = readers(&return_target);
        let outcome = capture_get_return(
            &dup,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            LinuxLayout::Lp64,
            &mut read_word,
            &mut read_bytes,
        );
        assert_eq!(outcome.inspected, 2, "dup {left}/{right}");
        assert_eq!(outcome.cells[0].status, ast::VALUE);
        assert_eq!(outcome.cells[1].status, ast::VALUE);
        assert_eq!(outcome.cells[0].value, left as u16);
        assert_eq!(outcome.cells[1].value, right as u16);
    }
    // One shared buffer is an alias, not a duplicate: duplicates require
    // disjoint spans.
    let entry_target = fresh_lp64();
    prog_attr(&entry_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    prog_attr(&entry_target, BASE, 1, 8, SEL_CLASS, 0x9000, 8);
    let mut shared = GetEntryState::default();
    capture_get_entry(
        BASE,
        2,
        LinuxLayout::Lp64,
        &mut shared,
        word_reader(&entry_target),
    );
    let return_target = fresh_lp64();
    prog_attr(&return_target, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    prog_attr(&return_target, BASE, 1, 8, SEL_CLASS, 0x9000, 8);
    return_target.borrow_mut().set_word(0x9000, 2);
    let (mut read_word, mut read_bytes) = readers(&return_target);
    let outcome = capture_get_return(
        &shared,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].status, ast::ALIAS);
    assert_eq!(outcome.cells[1].status, ast::ALIAS);
    assert_no_read_of(&return_target, 0x9000);

    // (h) Retries are fresh calls: two entries from different memories stay
    // independent, with no pointer or capacity reuse.
    let first_entry = fresh_lp64();
    prog_attr(&first_entry, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    let mut first = GetEntryState::default();
    capture_get_entry(
        BASE,
        1,
        LinuxLayout::Lp64,
        &mut first,
        word_reader(&first_entry),
    );
    let second_entry = fresh_lp64();
    prog_attr(&second_entry, BASE, 0, 8, SEL_CLASS, 0x9100, 16);
    let mut second = GetEntryState::default();
    capture_get_entry(
        BASE,
        1,
        LinuxLayout::Lp64,
        &mut second,
        word_reader(&second_entry),
    );
    assert_eq!(first.slots[0].value_ptr, 0x9000);
    assert_eq!(first.slots[0].entry_capacity, 8);
    assert_eq!(second.slots[0].value_ptr, 0x9100);
    assert_eq!(second.slots[0].entry_capacity, 16);
    let first_return = fresh_lp64();
    prog_attr(&first_return, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    first_return.borrow_mut().set_word(0x9000, 1);
    let (mut read_word, mut read_bytes) = readers(&first_return);
    let outcome = capture_get_return(
        &first,
        CKR_OK,
        ReturnAuthority::AUTHORIZED,
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome.cells[0].value, 1);
    assert_no_read_of(&first_return, 0x9100);

    // (i) Pair members stay separated, with cross-template aliasing through
    // bounded peer header re-reads (peer values are never read).
    let both = fresh_lp64();
    prog_attr(&both, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    both.borrow_mut().set_word(0x9000, 2);
    prog_attr(&both, PEER_BASE, 0, 8, SEL_TOKEN, 0x9010, 1);
    both.borrow_mut().set_bytes(0x9010, &[1]);
    let (mut read_word, mut read_bytes) = readers(&both);
    let outcome_a = inspect_request_template(
        BASE,
        1,
        Some((PEER_BASE, 1)),
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome_a.cells[0].status, ast::VALUE);
    assert_eq!(outcome_a.cells[0].value, 2);
    assert_log(
        &both,
        &[
            (READ_WORD, 0x5000, 8),
            (READ_WORD, 0x5008, 8),
            (READ_WORD, 0x5010, 8),
            (READ_WORD, 0x6000, 8),
            (READ_WORD, 0x6008, 8),
            (READ_WORD, 0x6010, 8),
            (READ_WORD, 0x9000, 8),
            (READ_WORD, 0x5000, 8),
            (READ_WORD, 0x5008, 8),
            (READ_WORD, 0x5010, 8),
        ],
    );
    assert_no_read_of(&both, 0x9010);

    let both = fresh_lp64();
    prog_attr(&both, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    both.borrow_mut().set_word(0x9000, 2);
    prog_attr(&both, PEER_BASE, 0, 8, SEL_TOKEN, 0x9010, 1);
    both.borrow_mut().set_bytes(0x9010, &[1]);
    let (mut read_word, mut read_bytes) = readers(&both);
    let outcome_b = inspect_request_template(
        PEER_BASE,
        1,
        Some((BASE, 1)),
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome_b.cells[0].status, ast::VALUE);
    assert_eq!(outcome_b.cells[0].value, 1);
    assert_eq!(outcome_b.cells[0].kind, ak::TOKEN);
    assert_no_read_of(&both, 0x9000);

    // A value inside the peer's inspected headers aliases that member only.
    let both = fresh_lp64();
    prog_attr(&both, BASE, 0, 8, SEL_CLASS, 0x6008, 8);
    prog_attr(&both, PEER_BASE, 0, 8, SEL_TOKEN, 0x9010, 1);
    both.borrow_mut().set_bytes(0x9010, &[1]);
    let (mut read_word, mut read_bytes) = readers(&both);
    let outcome_a = inspect_request_template(
        BASE,
        1,
        Some((PEER_BASE, 1)),
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome_a.cells[0].status, ast::ALIAS, "peer-header alias");
    assert_eq!(outcome_a.object_flags, ofl::ALIAS);
    let (mut read_word, mut read_bytes) = readers(&both);
    let outcome_b = inspect_request_template(
        PEER_BASE,
        1,
        Some((BASE, 1)),
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome_b.cells[0].status, ast::VALUE, "peer unaffected");

    // A value shared across members aliases both members.
    let both = fresh_lp64();
    prog_attr(&both, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    both.borrow_mut().set_word(0x9000, 2);
    prog_attr(&both, PEER_BASE, 0, 8, SEL_TOKEN, 0x9000, 1);
    let (mut read_word, mut read_bytes) = readers(&both);
    let outcome_a = inspect_request_template(
        BASE,
        1,
        Some((PEER_BASE, 1)),
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome_a.cells[0].status, ast::ALIAS, "shared left");
    let (mut read_word, mut read_bytes) = readers(&both);
    let outcome_b = inspect_request_template(
        PEER_BASE,
        1,
        Some((BASE, 1)),
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome_b.cells[0].status, ast::ALIAS, "shared right");

    // Unknown peer selectors re-read only their selector word: no peer
    // pointer/length/value access, and no peer value span to alias.
    let both = fresh_lp64();
    prog_attr(&both, BASE, 0, 8, SEL_CLASS, 0x9000, 8);
    both.borrow_mut().set_word(0x9000, 2);
    prog_attr(&both, PEER_BASE, 0, 8, 0x0102, 0x9000, 8);
    let (mut read_word, mut read_bytes) = readers(&both);
    let outcome_a = inspect_request_template(
        BASE,
        1,
        Some((PEER_BASE, 1)),
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(outcome_a.cells[0].status, ast::VALUE);
    assert_no_read_of(&both, 0x6008);
    assert_no_read_of(&both, 0x6010);

    // Overlap is checked against inspected headers: a value starting
    // exactly where the peer's inspected window ends stays valid.
    let both = fresh_lp64();
    prog_attr(&both, BASE, 0, 8, SEL_CLASS, PEER_BASE + 24, 8);
    both.borrow_mut().set_word(PEER_BASE + 24, 4);
    prog_attr(&both, PEER_BASE, 0, 8, SEL_TOKEN, 0x9010, 1);
    let (mut read_word, mut read_bytes) = readers(&both);
    let outcome_a = inspect_request_template(
        BASE,
        1,
        Some((PEER_BASE, 1)),
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert_eq!(
        outcome_a.cells[0].status,
        ast::VALUE,
        "adjacent peer window"
    );

    // Full pair windows stay fixed-bounded: 8+8 headers plus values and
    // rechecks never exceed 80 reads.
    let both = fresh_lp64();
    for i in 0..8u64 {
        prog_attr(&both, BASE, i, 8, SEL_CLASS, 0x9000 + i * 8, 8);
        both.borrow_mut().set_word(0x9000 + i * 8, i % 5);
        prog_attr(&both, PEER_BASE, i, 8, SEL_TOKEN, 0x9100 + i, 1);
        both.borrow_mut().set_bytes(0x9100 + i, &[(i % 2) as u8]);
    }
    let (mut read_word, mut read_bytes) = readers(&both);
    let outcome_a = inspect_request_template(
        BASE,
        8,
        Some((PEER_BASE, 8)),
        LinuxLayout::Lp64,
        &mut read_word,
        &mut read_bytes,
    );
    assert!(outcome_a.cells.iter().all(|cell| cell.status == ast::VALUE));
    assert!(
        both.borrow().log().len() <= 80,
        "pair reads bounded: {}",
        both.borrow().log().len()
    );
}

// H7-E1: unjoined continuity denies every return read directly in the
// shared core (no adapter mirror): result handles, Find and Get each
// read zero words under `ReturnAuthority::for_return` with straddled,
// absent or flagged stamps, while joined stamps authorize. This pins the
// guarantee the return adapter's gate relies on.
#[test]
fn object_producer_continuity_denied_authority_reads_nothing() {
    use crate::InstanceStamp;
    let clean = InstanceStamp {
        epoch: 7,
        global: 9,
        fault: 11,
        file_slot_plus1: 3,
        flags: crate::instance::STAMP_VALID,
    };
    let zero = InstanceStamp::default();
    let mut moved = clean;
    moved.epoch = moved.epoch.wrapping_add(1);
    let mut flagged = clean;
    flagged.flags |= crate::instance::STAMP_LOCAL_FAULT;
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        // Joined control: the same vectors read.
        let target = fresh(w);
        target.borrow_mut().set_word(0x10000, 0x42);
        let (verdict, words) = capture_return_handles(
            [true, false],
            [true, false],
            [0x10000, 0],
            CKR_OK,
            ReturnAuthority::for_return(true, true, clean, clean),
            layout,
            word_reader(&target),
        );
        assert_eq!(verdict.statuses[0], hst::VALUE);
        assert_eq!(words[0], 0x42);
        assert_eq!(target.borrow().log().len(), 1);
        for (name, entry, ret) in [
            ("absent", zero, clean),
            ("straddled", clean, moved),
            ("flagged", flagged, flagged),
        ] {
            let authority = ReturnAuthority::for_return(true, true, entry, ret);
            assert!(!authority.is_authorized(), "{name} denies");
            let target = fresh(w);
            target.borrow_mut().set_word(0x10000, 0x42);
            let (verdict, words) = capture_return_handles(
                [true, false],
                [true, false],
                [0x10000, 0],
                CKR_OK,
                authority,
                layout,
                word_reader(&target),
            );
            assert_eq!(verdict.statuses[0], hst::PROTOCOL_UNAVAILABLE, "{name}");
            assert_eq!(words, [0, 0]);
            assert_log(&target, &[]);
            let target = fresh(w);
            target.borrow_mut().set_word(0x21000, 2);
            target.borrow_mut().set_word(0x20000, 0x51);
            let (verdict, _) = capture_find_return(
                0x20000,
                8,
                0x21000,
                CKR_OK,
                authority,
                layout,
                word_reader(&target),
            );
            assert!(!verdict.valid, "{name}");
            assert_log(&target, &[]);
            let target = fresh(w);
            let retained = GetSlot {
                value_ptr: 0x50000,
                entry_capacity: w,
                kind: ak::CLASS,
                slot_index: 0,
            };
            let mut slots = [GetSlot::default(); 8];
            slots[0] = retained;
            let state = GetEntryState {
                template_base: 0x40000,
                header_end: 0x40000 + 3 * w,
                inspected: 1,
                slot_count: 1,
                slots,
                ..Default::default()
            };
            prog_attr(&target, 0x40000, 0, w, SEL_CLASS, 0x50000, w);
            target.borrow_mut().set_word(0x50000, 3);
            let (mut read_word, mut read_bytes) = readers(&target);
            let outcome = capture_get_return(
                &state,
                CKR_OK,
                authority,
                layout,
                &mut read_word,
                &mut read_bytes,
            );
            assert_eq!(outcome.inspected, 0, "{name}");
            assert_log(&target, &[]);
        }
    }
}

// E4 executes the actual in-place production seams. The array implementation
// above remains an independent reference; neither driver copies its outcome
// into production state.
fn streamed_program_six(target: &RefCell<FakeTarget>, layout: LinuxLayout) {
    let w = layout.word_bytes() as u64;
    for (i, (selector, len, value)) in [
        (SEL_CLASS, w, 4),
        (SEL_KEYTYPE, w, 0x1f),
        (SEL_TOKEN, 1, 1),
        (SEL_VALUELEN, w, 32),
        (SEL_MODBITS, w, 4096),
        (SEL_ECPARAMS, 10, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let ptr = 0x8000 + i as u64 * 32;
        prog_attr(target, 0x4000, i as u64, w, selector, ptr, len);
        if selector == SEL_TOKEN {
            target.borrow_mut().set_bytes(ptr, &[1]);
        } else if selector == SEL_ECPARAMS {
            target.borrow_mut().set_bytes(ptr, EC_P256);
        } else {
            target.borrow_mut().set_word(ptr, value);
        }
    }
    // Unknown/private selectors must never authorize pointer/length reads.
    target.borrow_mut().set_word(0x4000 + 6 * 3 * w, 0x0011);
    target.borrow_mut().set_word(0x4000 + 7 * 3 * w, 0x0102);
}

fn streamed_assert_list(
    out: &crate::object_wire::ObjectAttributeListWire,
    oracle: AttributeListOutcome,
) {
    assert_eq!(out.inspected, oracle.inspected);
    assert_eq!(out.flags, oracle.flags);
    assert_eq!(out.reserved, 0);
    for i in 0..8 {
        assert_eq!(
            (out.cells[i].kind, out.cells[i].status, out.cells[i].value),
            (
                oracle.cells[i].kind,
                oracle.cells[i].status,
                oracle.cells[i].value
            ),
            "slot {i}"
        );
    }
}

#[test]
fn streamed_request_six_fields_match_reference_and_privacy() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let target = fresh(layout.word_bytes() as u64);
        streamed_program_six(&target, layout);
        let (r, b) = readers(&target);
        let oracle = inspect_request_template(0x4000, 8, None, layout, r, b);
        target.borrow_mut().log_len = 0;
        let mut out = crate::object_wire::ObjectAttributeListWire::default();
        let (r, b) = readers(&target);
        let flags = crate::object_flow::production_inspect_request_template(
            0x4000, 8, None, layout, &mut out, r, b,
        );
        streamed_assert_list(&out, oracle);
        assert_eq!(flags, oracle.object_flags);
        assert_eq!(
            out.cells[..6]
                .iter()
                .filter(|c| c.status == ast::VALUE)
                .count(),
            6
        );
        for i in 0..6 {
            assert_eq!(
                target
                    .borrow()
                    .log()
                    .iter()
                    .filter(|entry| entry.1 == 0x8000 + i * 32)
                    .count(),
                1,
                "one authorized value read per slot"
            );
        }
        let w = layout.word_bytes() as u64;
        for i in 6..8 {
            assert_no_read_of(&target, 0x4000 + i * 3 * w + w);
            assert_no_read_of(&target, 0x4000 + i * 3 * w + 2 * w);
        }
    }
}

#[test]
fn streamed_request_alias_inexact_neighbor_and_peer_never_read_values() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for peer in [false, true] {
            let target = fresh(w);
            prog_attr(&target, 0x4000, 0, w, SEL_CLASS, 0x8000, w);
            prog_attr(
                &target,
                if peer { 0x6000 } else { 0x4000 },
                if peer { 0 } else { 1 },
                w,
                SEL_TOKEN,
                0x8000,
                2,
            );
            let mut out = crate::object_wire::ObjectAttributeListWire::default();
            let (r, b) = readers(&target);
            let flags = crate::object_flow::production_inspect_request_template(
                0x4000,
                if peer { 1 } else { 2 },
                if peer { Some((0x6000, 1)) } else { None },
                layout,
                &mut out,
                r,
                b,
            );
            assert_eq!(out.cells[0].status, ast::ALIAS);
            assert_ne!(flags & ofl::ALIAS, 0);
            assert_no_read_of(&target, 0x8000);
            assert_no_bytes_reads(&target);
        }
    }
}

#[test]
fn streamed_request_header_recheck_discards_classified_value() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let target = fresh(w);
        prog_attr(&target, 0x4000, 0, w, SEL_CLASS, 0x8000, w);
        target.borrow_mut().set_word(0x8000, 3);
        let seen = core::cell::Cell::new(false);
        let mut out = crate::object_wire::ObjectAttributeListWire::default();
        let flags = crate::object_flow::production_inspect_request_template(
            0x4000,
            1,
            None,
            layout,
            &mut out,
            |addr| {
                if addr == 0x8000 {
                    seen.set(true);
                }
                if addr == 0x4000 && seen.get() {
                    Ok(SEL_KEYTYPE)
                } else {
                    target.borrow_mut().read_word(addr)
                }
            },
            |addr, buf| target.borrow_mut().read_bytes(addr, buf),
        );
        assert!(seen.get());
        assert_eq!(out.cells[0].status, ast::CHANGED);
        assert_eq!(out.cells[0].value, 0);
        assert_ne!(flags & ofl::CHANGED_METADATA, 0);
    }
}

#[test]
fn streamed_get_entry_retains_selected_headers_and_failure_flags() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let target = fresh(w);
        streamed_program_six(&target, layout);
        target.borrow_mut().set_fail(0x4000 + w);
        let mut reference = GetEntryState::default();
        let expected = capture_get_entry(0x4000, 9, layout, &mut reference, word_reader(&target));
        target.borrow_mut().log_len = 0;
        let mut side = crate::object_wire::ObjectStart {
            flags: ofl::PARTIAL_RESULT as u16,
            ..Default::default()
        };
        let actual = crate::object_flow::production_capture_get_entry(
            0x4000,
            9,
            layout,
            &mut side,
            word_reader(&target),
        );
        assert_eq!(actual, expected);
        assert_eq!(side.get_inspected, 8);
        assert_eq!(side.get_template_base, reference.template_base);
        assert_eq!(side.inspected_header_end, reference.header_end);
        assert_eq!(side.flags & 0xff, ofl::PARTIAL_RESULT as u16);
        assert_eq!((side.flags >> 8) & 15, u16::from(expected.entry_flags));
        for i in 0..usize::from(expected.slot_count) {
            let a = &side.slots[i];
            let b = &reference.slots[i];
            assert_eq!(
                (a.kind, a.slot_index, a.value_ptr, a.entry_capacity),
                (b.kind, b.slot_index, b.value_ptr, b.entry_capacity)
            );
            assert_eq!(a.returned_len, 0);
            assert_eq!(a.status, 0);
            assert_eq!(a.reserved, [0; 5]);
        }
        for i in 6..8 {
            assert_no_read_of(&target, 0x4000 + i * 3 * w + w);
            assert_no_read_of(&target, 0x4000 + i * 3 * w + 2 * w);
        }
        for i in 0..6 {
            assert_no_read_of(&target, 0x8000 + i * 32);
        }
    }
}

#[test]
fn streamed_get_return_six_fields_and_authority_twins() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let target = fresh(layout.word_bytes() as u64);
        streamed_program_six(&target, layout);
        let mut side = crate::object_wire::ObjectStart::default();
        crate::object_flow::production_capture_get_entry(
            0x4000,
            8,
            layout,
            &mut side,
            word_reader(&target),
        );
        let mut reference = GetEntryState::default();
        capture_get_entry(0x4000, 8, layout, &mut reference, word_reader(&target));
        let (r, b) = readers(&target);
        let oracle = capture_get_return(
            &reference,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            r,
            b,
        );
        let mut out = crate::object_wire::ObjectAttributeListWire::default();
        let (r, b) = readers(&target);
        let flags = crate::object_flow::production_capture_get_return(
            &side,
            CKR_OK,
            ReturnAuthority::AUTHORIZED,
            layout,
            &mut out,
            r,
            b,
        );
        streamed_assert_list(&out, oracle);
        assert_eq!(flags, oracle.object_flags);
        for (rv, authority) in [
            (CKR_PENDING, ReturnAuthority::AUTHORIZED),
            (6, ReturnAuthority::AUTHORIZED),
            (
                CKR_OK,
                ReturnAuthority {
                    owner_live: false,
                    phase_ready: true,
                    continuity_joined: true,
                },
            ),
            (
                CKR_OK,
                ReturnAuthority {
                    owner_live: true,
                    phase_ready: false,
                    continuity_joined: true,
                },
            ),
            (
                CKR_OK,
                ReturnAuthority {
                    owner_live: true,
                    phase_ready: true,
                    continuity_joined: false,
                },
            ),
        ] {
            target.borrow_mut().log_len = 0;
            let mut out = crate::object_wire::ObjectAttributeListWire::default();
            let (r, b) = readers(&target);
            crate::object_flow::production_capture_get_return(
                &side, rv, authority, layout, &mut out, r, b,
            );
            assert_eq!(target.borrow().log_len, 0);
            assert!(out == crate::object_wire::ObjectAttributeListWire::default());
        }
    }
}

#[test]
fn streamed_get_return_entry_capacity_alias_and_race_controls() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for mode in 0..5 {
            let target = fresh(w);
            prog_attr(
                &target,
                0x4000,
                0,
                w,
                SEL_CLASS,
                0x8000,
                if mode == 0 { w - 1 } else { w },
            );
            if mode == 1 {
                prog_attr(&target, 0x4000, 1, w, SEL_TOKEN, 0x8000, 2);
            }
            target.borrow_mut().set_word(0x8000, 3);
            let mut side = crate::object_wire::ObjectStart::default();
            crate::object_flow::production_capture_get_entry(
                0x4000,
                if mode == 1 { 2 } else { 1 },
                layout,
                &mut side,
                word_reader(&target),
            );
            if mode == 0 {
                target.borrow_mut().set_word(0x4000 + 2 * w, w);
            }
            if mode == 2 {
                target
                    .borrow_mut()
                    .set_word(0x4000 + 2 * w, unavailable_len(layout));
            }
            if mode == 3 {
                target.borrow_mut().set_word(0x4000 + w, 0x9000);
            }
            target.borrow_mut().log_len = 0;
            let seen = core::cell::Cell::new(false);
            let mut out = crate::object_wire::ObjectAttributeListWire::default();
            crate::object_flow::production_capture_get_return(
                &side,
                CKR_ATTRIBUTE_SENSITIVE,
                ReturnAuthority::AUTHORIZED,
                layout,
                &mut out,
                |addr| {
                    if addr == 0x8000 {
                        seen.set(true);
                    }
                    if mode == 4 && addr == 0x4000 && seen.get() {
                        Ok(SEL_KEYTYPE)
                    } else {
                        target.borrow_mut().read_word(addr)
                    }
                },
                |addr, buf| target.borrow_mut().read_bytes(addr, buf),
            );
            assert_eq!(
                out.cells[0].status,
                [
                    ast::INSUFFICIENT_CAPACITY,
                    ast::ALIAS,
                    ast::UNAVAILABLE,
                    ast::CHANGED,
                    ast::CHANGED
                ][mode]
            );
            assert_eq!(out.cells[0].value, 0);
            if mode < 4 {
                assert_no_read_of(&target, 0x8000);
            } else {
                assert!(seen.get());
            }
        }
    }
}

#[test]
fn streamed_request_policy_and_span_corpus_matches_reference() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for selector in [
            SEL_CLASS,
            SEL_KEYTYPE,
            SEL_TOKEN,
            SEL_VALUELEN,
            SEL_MODBITS,
            SEL_ECPARAMS,
            0x11,
        ] {
            for mode in 0..11 {
                let target = fresh(w);
                let len = if selector == SEL_TOKEN {
                    1
                } else if selector == SEL_ECPARAMS {
                    10
                } else {
                    w
                };
                let ptr = if mode == 1 {
                    0
                } else if mode == 2 {
                    u64::MAX - 1
                } else {
                    0x8000
                };
                prog_attr(
                    &target,
                    0x4000,
                    0,
                    w,
                    selector,
                    ptr,
                    if mode == 3 { len + 1 } else { len },
                );
                let value = match selector {
                    SEL_KEYTYPE => 0x1f,
                    SEL_TOKEN => 1,
                    SEL_VALUELEN => 32,
                    SEL_MODBITS => 4096,
                    _ => 3,
                };
                target
                    .borrow_mut()
                    .set_word(0x8000, if mode == 4 { u64::MAX } else { value });
                target.borrow_mut().set_bytes(
                    0x8000,
                    if selector == SEL_ECPARAMS {
                        EC_P256
                    } else {
                        &[1]
                    },
                );
                if mode == 5 {
                    target.borrow_mut().set_fail(0x4000);
                }
                if mode == 6 {
                    target.borrow_mut().set_fail(0x4000 + w);
                }
                if mode == 7 {
                    target.borrow_mut().set_fail(0x4000 + 2 * w);
                }
                if mode == 8 {
                    target.borrow_mut().set_fail(ptr);
                }
                if mode == 9 {
                    target.borrow_mut().set_bytes(0x8000, &[0xff; 10]);
                }
                if mode == 10 {
                    prog_attr(&target, 0x4000, 1, w, SEL_TOKEN, 0x8000, 2);
                }
                let count = if mode == 10 { 2 } else { 1 };
                let (r, b) = readers(&target);
                let expected = inspect_request_template(0x4000, count, None, layout, r, b);
                target.borrow_mut().log_len = 0;
                let mut out = crate::object_wire::ObjectAttributeListWire::default();
                let (r, b) = readers(&target);
                let flags = crate::object_flow::production_inspect_request_template(
                    0x4000, count, None, layout, &mut out, r, b,
                );
                streamed_assert_list(&out, expected);
                assert_eq!(flags, expected.object_flags);
                if selector == 0x11 {
                    assert_no_read_of(&target, 0x4000 + w);
                    assert_no_read_of(&target, 0x4000 + 2 * w);
                }
                if [ast::UNAVAILABLE, ast::INVALID_LENGTH, ast::INVALID_SPAN]
                    .contains(&out.cells[0].status)
                {
                    assert_no_read_of(&target, ptr);
                }
            }
        }
    }
}

#[test]
fn streamed_empty_and_overflow_templates_read_nothing_including_peer() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        for (base, count) in [(0, 0), (0x4000, u64::MAX), (u64::MAX - 23, 1), (0, 1)] {
            let target = fresh(layout.word_bytes() as u64);
            let mut out = crate::object_wire::ObjectAttributeListWire::default();
            let (r, b) = readers(&target);
            crate::object_flow::production_inspect_request_template(
                base,
                count,
                Some((0x8000, 8)),
                layout,
                &mut out,
                r,
                b,
            );
            assert_eq!(target.borrow().log_len, 0);
            assert_eq!(out.inspected, 0);
            assert_eq!(out.flags, if count == 0 { 0 } else { alf::INVALID_SPAN });
        }
    }
}

#[test]
fn streamed_get_private_flags_never_enter_public_tail() {
    use crate::object_wire::{
        GET_ENTRY_FLAGS_MASK, ObjectCallWire, ObjectStart, canonical_object_wire,
    };
    let function = fid("C_GetAttributeValue");
    let row = canonical_object_wire(function);
    let side = ObjectStart {
        phase: 3,
        descriptor_index: function + 1,
        flags: GET_ENTRY_FLAGS_MASK | ofl::PARTIAL_RESULT as u16,
        ..Default::default()
    };
    let mut tail = ObjectCallWire::default();
    assert!(unsafe {
        crate::object_flow::adapter_tail_fill(&mut tail, Some(&side), function + 1, Some(&row))
    });
    assert_eq!(tail.flags, ofl::PARTIAL_RESULT);
}

#[test]
fn streamed_get_partial_result_corpus_matches_reference() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for rv in [
            CKR_OK,
            CKR_ATTRIBUTE_SENSITIVE,
            CKR_ATTRIBUTE_TYPE_INVALID,
            CKR_BUFFER_TOO_SMALL,
        ] {
            for mode in 0..13 {
                let target = fresh(w);
                streamed_program_six(&target, layout);
                if mode == 1 {
                    target.borrow_mut().set_word(0x4000 + w, 0);
                }
                if mode == 2 {
                    target.borrow_mut().set_word(0x4000 + 2 * w, w - 1);
                }
                if mode == 9 {
                    target.borrow_mut().set_word(0x4000 + w, u64::MAX - 1);
                }
                if mode == 10 {
                    prog_attr(&target, 0x4000, 1, w, SEL_TOKEN, 0x8000, 2);
                }
                if mode == 12 {
                    target.borrow_mut().set_word(0x4000, 0x11);
                }
                let mut reference = GetEntryState::default();
                capture_get_entry(0x4000, 9, layout, &mut reference, word_reader(&target));
                let mut side = crate::object_wire::ObjectStart::default();
                crate::object_flow::production_capture_get_entry(
                    0x4000,
                    9,
                    layout,
                    &mut side,
                    word_reader(&target),
                );
                match mode {
                    1 | 4 => target.borrow_mut().set_word(0x4000 + w, 0x9000),
                    2 => target.borrow_mut().set_word(0x4000 + 2 * w, w),
                    3 => target
                        .borrow_mut()
                        .set_word(0x4000 + 2 * w, unavailable_len(layout)),
                    5 => target.borrow_mut().set_word(0x4000, SEL_KEYTYPE),
                    6 => target.borrow_mut().set_word(0x4000 + 2 * w, w + 1),
                    7 => target.borrow_mut().set_fail(0x8000),
                    8 => target.borrow_mut().set_fail(0x4000),
                    11 => target.borrow_mut().set_word(0x8000, u64::MAX),
                    _ => {}
                }
                let (r, b) = readers(&target);
                let expected =
                    capture_get_return(&reference, rv, ReturnAuthority::AUTHORIZED, layout, r, b);
                target.borrow_mut().log_len = 0;
                let mut out = crate::object_wire::ObjectAttributeListWire::default();
                let (r, b) = readers(&target);
                let flags = crate::object_flow::production_capture_get_return(
                    &side,
                    rv,
                    ReturnAuthority::AUTHORIZED,
                    layout,
                    &mut out,
                    r,
                    b,
                );
                streamed_assert_list(&out, expected);
                assert_eq!(flags, expected.object_flags);
                if [
                    ast::SIZE_ONLY,
                    ast::UNAVAILABLE,
                    ast::INVALID_LENGTH,
                    ast::CHANGED,
                    ast::ALIAS,
                    ast::INVALID_SPAN,
                    ast::INSUFFICIENT_CAPACITY,
                ]
                .contains(&out.cells[0].status)
                {
                    assert_no_read_of(&target, 0x8000);
                }
                if mode == 12 {
                    assert_no_read_of(&target, 0x4000 + w);
                    assert_no_read_of(&target, 0x4000 + 2 * w);
                }
            }
        }
    }
}

#[test]
fn streamed_actual_pair_body_checks_peer_before_either_value_read() {
    use crate::object_wire::{ObjectStart, canonical_object_wire};
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for mode in 0..4 {
            let target = fresh(w);
            // Mode0 checks shared values; mode1 aliases pair1's value with
            // pair0's header; mode2 makes
            // pair1's length inexact; mode3 aliases pair0's value with pair1's
            // inspected header (use Token for a distinguishable byte read).
            prog_attr(
                &target,
                0x4000,
                0,
                w,
                if mode == 3 { SEL_TOKEN } else { SEL_CLASS },
                if mode == 3 { 0x6000 } else { 0x8000 },
                if mode == 3 { 1 } else { w },
            );
            prog_attr(
                &target,
                0x6000,
                0,
                w,
                if mode == 1 { SEL_TOKEN } else { SEL_CLASS },
                if mode == 1 { 0x4000 } else { 0x8000 },
                if mode == 1 {
                    1
                } else if mode == 2 {
                    w + 1
                } else {
                    w
                },
            );
            target.borrow_mut().set_word(0x8000, 3);
            target.borrow_mut().set_bytes(0x6000, &[1]);
            let row = canonical_object_wire(fid("C_GenerateKeyPair"));
            let mut side = ObjectStart::default();
            let mut fetches = std::vec::Vec::new();
            let mut fetch = |arg| {
                fetches.push(arg);
                Some(if arg == row.template_args[0] {
                    0x4000
                } else if arg == row.template_args[2] {
                    0x6000
                } else {
                    1
                })
            };
            let (r, b) = readers(&target);
            crate::object_flow::capture_request_pairs(&mut side, &row, layout, &mut fetch, r, b);
            assert_eq!(fetches, row.template_args);
            assert_eq!(
                side.requested[0].cells[0].status,
                if mode == 1 { ast::VALUE } else { ast::ALIAS }
            );
            if mode < 2 {
                assert_eq!(side.requested[1].cells[0].status, ast::ALIAS);
            }
            if mode == 2 {
                assert_eq!(side.requested[1].cells[0].status, ast::INVALID_LENGTH);
            }
            if mode < 3 && mode != 1 {
                assert_no_read_of(&target, 0x8000);
            } else {
                assert_no_bytes_reads(&target);
            }
        }
    }
}

#[test]
fn streamed_actual_pair_body_distinguishes_failed_argument_from_empty() {
    use crate::object_wire::{ObjectStart, canonical_object_wire};
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let row = canonical_object_wire(fid("C_GenerateKeyPair"));
        for failed in row.template_args {
            let target = fresh(w);
            prog_attr(&target, 0x4000, 0, w, SEL_CLASS, 0x8000, w);
            prog_attr(&target, 0x6000, 0, w, SEL_CLASS, 0x9000, w);
            target.borrow_mut().set_word(0x8000, 3);
            target.borrow_mut().set_word(0x9000, 3);
            let mut side = ObjectStart::default();
            let mut fetch = |arg| {
                if arg == failed {
                    None
                } else {
                    Some(if arg == row.template_args[0] {
                        0x4000
                    } else if arg == row.template_args[2] {
                        0x6000
                    } else {
                        1
                    })
                }
            };
            let (r, b) = readers(&target);
            crate::object_flow::capture_request_pairs(&mut side, &row, layout, &mut fetch, r, b);
            assert_eq!(
                target.borrow().log_len,
                0,
                "unknown peer span cannot authorize any value"
            );
            assert_ne!(side.flags & ofl::ARG_READ_FAILURE as u16, 0);
            for out in side.requested {
                assert_eq!(out.flags, alf::UNINSPECTED);
                assert_eq!(out.inspected, 0);
            }
        }
        let target = fresh(w);
        let mut side = ObjectStart::default();
        let mut fetch = |arg| {
            Some(if arg == row.template_args[0] {
                0x4000
            } else if arg == row.template_args[2] {
                0x6000
            } else {
                0
            })
        };
        let (r, b) = readers(&target);
        crate::object_flow::capture_request_pairs(&mut side, &row, layout, &mut fetch, r, b);
        assert_eq!(side.flags, 0);
        assert_eq!(target.borrow().log_len, 0);
        for out in side.requested {
            assert_eq!(out.flags, 0);
            assert_eq!(out.inspected, 0);
        }
    }
}

#[test]
fn streamed_actual_pair_body_disjoint_and_refused_derives_are_unchanged() {
    use crate::object_wire::{OBJECT_DERIVE_UNAVAILABLE, ObjectStart, canonical_object_wire};
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        let target = fresh(w);
        prog_attr(&target, 0x4000, 0, w, SEL_CLASS, 0x8000, w);
        prog_attr(&target, 0x6000, 0, w, SEL_CLASS, 0x9000, w);
        target.borrow_mut().set_word(0x8000, 3);
        target.borrow_mut().set_word(0x9000, 4);
        target.borrow_mut().set_word(0x4000 + 3 * w, 0x11);
        let row = canonical_object_wire(fid("C_GenerateKeyPair"));
        let mut side = ObjectStart::default();
        let mut fetch = |arg| {
            Some(if arg == row.template_args[0] {
                0x4000
            } else if arg == row.template_args[2] {
                0x6000
            } else if arg == row.template_args[1] {
                2
            } else {
                1
            })
        };
        let (r, b) = readers(&target);
        crate::object_flow::capture_request_pairs(&mut side, &row, layout, &mut fetch, r, b);
        assert_eq!(side.requested[0].cells[0].status, ast::VALUE);
        assert_eq!(side.requested[0].cells[0].value, 3);
        assert_eq!(side.requested[1].cells[0].status, ast::VALUE);
        assert_eq!(side.requested[1].cells[0].value, 4);
        assert_no_read_of(&target, 0x4000 + 4 * w);
        assert_no_read_of(&target, 0x4000 + 5 * w);
        for name in ["C_DeriveKey", "C_SetAttributeValue"] {
            let target = fresh(w);
            let row = canonical_object_wire(fid(name));
            let mut side = ObjectStart {
                derive: OBJECT_DERIVE_UNAVAILABLE,
                ..Default::default()
            };
            let mut acquired = 0;
            let (r, b) = readers(&target);
            crate::object_flow::capture_request_pairs(
                &mut side,
                &row,
                layout,
                &mut |_| {
                    acquired += 1;
                    Some(0x4000)
                },
                r,
                b,
            );
            assert_eq!(acquired, 0);
            assert_eq!(target.borrow().log_len, 0);
        }
    }
}

#[test]
fn return_gate_exact_finite_roundtrip_and_all_unknown_bits_refuse() {
    use crate::object_flow::{decode_return_gate, encode_return_gate};
    for (layout, code) in [(LinuxLayout::Lp64, 1), (LinuxLayout::Ilp32, 2)] {
        for joined in [false, true] {
            let gate = code | if joined { 4 } else { 0 };
            assert_eq!(encode_return_gate(layout, joined), gate);
            assert_eq!(decode_return_gate(gate), Some((layout, joined)));
        }
        for bit in 3..32 {
            assert_eq!(decode_return_gate(code | 4 | (1 << bit)), None);
        }
    }
    for gate in [0, 3, 4, 7, u32::MAX] {
        assert_eq!(decode_return_gate(gate), None);
    }
}

#[test]
fn return_gate_actual_fill_keeps_full_width_and_continuity_authority() {
    use crate::object_flow::adapter_fill_return_control;
    use crate::object_wire::{ObjectStart, canonical_object_wire};
    let row = canonical_object_wire(fid("C_DeriveKey"));
    let descriptor = row.function + 1;
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let good_gate = if layout == LinuxLayout::Lp64 { 5 } else { 6 };
        for gate in [0, 3, 4, 7]
            .into_iter()
            .chain((3..32).map(|bit| good_gate | (1 << bit)))
        {
            let target = fresh(layout.word_bytes() as u64);
            let mut side = ObjectStart {
                phase: 2,
                descriptor_index: descriptor,
                derive: 1,
                result_ptrs: [0x8000, 0],
                ..Default::default()
            };
            assert!(!adapter_fill_return_control(
                Some(&mut side),
                descriptor,
                Some(&row),
                0,
                capture::MECHANISM_VALUE,
                0x21,
                gate,
                word_reader(&target)
            ));
            assert_eq!(target.borrow().log_len, 0);
            assert_eq!(side.phase, 2);
        }
        for (gate, rv, status, mech, filled, reads) in [
            (good_gate, 0, capture::MECHANISM_VALUE, 0x21, true, 1),
            (good_gate & !4, 0, capture::MECHANISM_VALUE, 0x21, false, 0),
            (good_gate | 8, 0, capture::MECHANISM_VALUE, 0x21, false, 0),
            (
                good_gate,
                1u64 << 32,
                capture::MECHANISM_VALUE,
                0x21,
                true,
                0,
            ),
            (
                good_gate,
                0,
                capture::MECHANISM_VALUE,
                (1u64 << 32) | 0x21,
                true,
                0,
            ),
            (
                good_gate,
                0,
                (1u32 << 16) | capture::MECHANISM_VALUE,
                0x21,
                true,
                0,
            ),
        ] {
            let target = fresh(layout.word_bytes() as u64);
            target.borrow_mut().set_word(0x8000, 0x1234);
            let mut side = ObjectStart {
                phase: 2,
                descriptor_index: descriptor,
                derive: 1,
                result_ptrs: [0x8000, 0],
                ..Default::default()
            };
            assert_eq!(
                adapter_fill_return_control(
                    Some(&mut side),
                    descriptor,
                    Some(&row),
                    rv,
                    status,
                    mech,
                    gate,
                    word_reader(&target)
                ),
                filled
            );
            assert_eq!(target.borrow().log_len, reads);
            assert_eq!(side.phase, if filled { 3 } else { 2 });
            if reads == 1 {
                assert_eq!(side.result_ptrs[0], 0x1234);
                assert_eq!(side.result_statuses[0], hst::VALUE);
            }
        }
    }
}

#[test]
fn return_gate_actual_emitters_refuse_unknown_bits_and_unjoined_without_reads() {
    use crate::object_flow::{adapter_emit_find_control, adapter_emit_get_control};
    use crate::object_wire::{ObjectCallWire, ObjectStart, canonical_object_wire};
    for name in ["C_FindObjects", "C_GetAttributeValue"] {
        let row = canonical_object_wire(fid(name));
        let descriptor = row.function + 1;
        let side = ObjectStart {
            phase: 3,
            descriptor_index: descriptor,
            find_capacity: 1,
            find_count_ptr: 0x9000,
            result_ptrs: [0x8000, 0],
            ..Default::default()
        };
        let mut invalid = std::vec![1, 2, 0, 3, 4, 7, u32::MAX];
        for bit in 3..32 {
            invalid.push(5 | (1 << bit));
            invalid.push(6 | (1 << bit));
        }
        for gate in invalid {
            let target = fresh_lp64();
            let (r, b) = readers(&target);
            let mut tail = ObjectCallWire::default();
            let ok = unsafe {
                if name == "C_FindObjects" {
                    adapter_emit_find_control(
                        &mut tail,
                        Some(&side),
                        descriptor,
                        Some(&row),
                        0,
                        gate,
                        r,
                    )
                } else {
                    adapter_emit_get_control(
                        &mut tail,
                        Some(&side),
                        descriptor,
                        Some(&row),
                        0,
                        gate,
                        r,
                        b,
                    )
                }
            };
            assert!(!ok);
            assert_eq!(target.borrow().log_len, 0);
        }
        let target = fresh_lp64();
        target.borrow_mut().set_word(0x9000, 1);
        target.borrow_mut().set_word(0x8000, 0x1234);
        let (r, b) = readers(&target);
        let mut tail = ObjectCallWire::default();
        assert!(unsafe {
            if name == "C_FindObjects" {
                adapter_emit_find_control(&mut tail, Some(&side), descriptor, Some(&row), 0, 5, r)
            } else {
                adapter_emit_get_control(&mut tail, Some(&side), descriptor, Some(&row), 0, 5, r, b)
            }
        });
        if name == "C_FindObjects" {
            assert_eq!(tail.find_handles[0], 0x1234);
            assert_eq!(tail.find_len, 1);
        }
    }
}

#[test]
fn streamed_actual_get_arguments_missing_is_uninspected_and_zero_is_empty() {
    use crate::object_flow::{capture_get_template, production_capture_get_return};
    use crate::object_wire::{ObjectAttributeListWire, ObjectStart, canonical_object_wire};
    let row = canonical_object_wire(fid("C_GetAttributeValue"));
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for missing in [Some(row.template_args[0]), Some(row.template_args[1]), None] {
            let target = fresh(w);
            prog_attr(&target, 0x4000, 0, w, SEL_CLASS, 0x8000, w);
            let mut side = ObjectStart::default();
            // Reuse must clear stale retained pointers before marking failed args.
            side.slots[0].kind = ak::CLASS;
            side.slots[0].value_ptr = 0xdead;
            side.get_inspected = 1;
            let mut fetch = |arg| {
                if missing == Some(arg) {
                    None
                } else {
                    Some(if arg == row.template_args[0] {
                        0x4000
                    } else if missing.is_none() {
                        0
                    } else {
                        1
                    })
                }
            };
            capture_get_template(&mut side, &row, layout, &mut fetch, word_reader(&target));
            assert_eq!(target.borrow().log_len, 0);
            assert_eq!(side.get_inspected, 0);
            assert_eq!(side.slots[0].value_ptr, 0);
            let mut out = ObjectAttributeListWire::default();
            let (r, b) = readers(&target);
            production_capture_get_return(
                &side,
                0,
                ReturnAuthority::AUTHORIZED,
                layout,
                &mut out,
                r,
                b,
            );
            assert_eq!(
                out.flags,
                if missing.is_some() {
                    alf::UNINSPECTED
                } else {
                    0
                }
            );
            assert_eq!(out.inspected, 0);
            assert_eq!(target.borrow().log_len, 0);
            assert_eq!(
                side.flags & ofl::ARG_READ_FAILURE as u16,
                if missing.is_some() {
                    ofl::ARG_READ_FAILURE as u16
                } else {
                    0
                }
            );
        }
    }
}

#[test]
fn streamed_attribute_stride_matches_wide_arithmetic_at_overflow_boundaries() {
    for (layout, stride) in [(LinuxLayout::Lp64, 24u64), (LinuxLayout::Ilp32, 12u64)] {
        let limit = u64::MAX / stride;
        for count in [0, 1, 7, 8, 9, limit - 1, limit, limit + 1, u64::MAX] {
            // Independent widened arithmetic stays host-test-only. Production
            // must preserve this result without generating a wide BPF multiply.
            let expected = u128::from(count) * u128::from(stride);
            let expected = if expected <= u128::from(u64::MAX) {
                Some(expected as u64)
            } else {
                None
            };
            assert_eq!(attribute_table_span(count, layout), expected);
            for base in [0, 1, 0x4000, u64::MAX - 23, u64::MAX] {
                let wide = u128::from(base) + u128::from(count) * u128::from(stride);
                let last = wide + u128::from(stride) - 1;
                let max = if layout == LinuxLayout::Lp64 {
                    u128::from(u64::MAX)
                } else {
                    u128::from(u32::MAX)
                };
                let expected = if wide != 0 && last <= max {
                    let slot = wide as u64;
                    let w = layout.word_bytes() as u64;
                    Some((slot, slot + w, slot + 2 * w))
                } else {
                    None
                };
                assert_eq!(attribute_header_addresses(base, count, layout), expected);
            }
        }
    }
}

#[test]
fn streamed_get_retained_index_boundary_refuses_before_target_reads() {
    use crate::object_wire::{ObjectAttributeListWire, ObjectStart};
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for index in [0u8, 8, 255] {
            let target = fresh(w);
            prog_attr(&target, 0x4000, 0, w, SEL_CLASS, 0x8000, w);
            target.borrow_mut().set_word(0x8000, 3);
            let mut side = ObjectStart {
                get_template_base: 0x4000,
                inspected_header_end: 0x4000 + 8 * 3 * w,
                get_inspected: 255,
                ..Default::default()
            };
            side.slots[0].kind = ak::CLASS;
            side.slots[0].slot_index = index;
            side.slots[0].value_ptr = 0x8000;
            side.slots[0].entry_capacity = w;
            let mut out = ObjectAttributeListWire::default();
            let (r, b) = readers(&target);
            crate::object_flow::production_capture_get_return(
                &side,
                CKR_OK,
                ReturnAuthority::AUTHORIZED,
                layout,
                &mut out,
                r,
                b,
            );
            assert_eq!(out.inspected, 8);
            if index == 0 {
                assert_eq!(out.cells[0].status, ast::VALUE);
                assert_eq!(out.cells[0].value, 3);
            } else {
                assert_eq!(target.borrow().log_len, 0);
                assert!(out.cells == [ObjectAttributeWire::default(); 8]);
            }
        }
    }
}

#[test]
fn completed_event_in_place_initializes_all_bytes_from_owned_facts() {
    use crate::object_flow::{ReturnEventFacts, fill_call_event};
    use crate::{CallStart, Event, ImageIdentity};
    let start = CallStart {
        ts_ns: 900,
        session: 2,
        slot_id: 3,
        mechanism: 4,
        mechanism_ptr: u64::MAX,
        flags: 5,
        out_ptr: u64::MAX - 1,
        user_type: 6,
        shape: 7,
        p0: 8,
        p1: 9,
        p2: 10,
        async_value: 11,
        attr_types: [12, 13, 14, 15, 16, 17, 18, 19],
        attr_count: 20,
        attr_total: 21,
        attr_bools: 22,
        attr_bools_seen: 23,
        attr_types1: [24, 25, 26, 27, 28, 29, 30, 31],
        attr_count1: 32,
        attr_total1: 33,
        attr_bools1: 34,
        attr_bools_seen1: 35,
        capture: 36,
        target_function: 37,
        object_required: u64::MAX - 2,
        image: ImageIdentity {
            task_cookie: 38,
            exec_id: 39,
        },
    };
    for word in [0, 0x1_0000_0001, u64::MAX] {
        let facts = ReturnEventFacts {
            ts_ns: word,
            duration_ns: word.wrapping_sub(1),
            rv: word.wrapping_sub(2),
            mechanism: word.wrapping_sub(3),
            session: word.wrapping_sub(4),
            async_value: word.wrapping_sub(5),
            capture_flags: 0x8000_0041,
            pid_tgid: word.wrapping_sub(6),
            cgroup_id: word.wrapping_sub(7),
            root_affiliation: word.wrapping_sub(8),
        };
        let expected = Event {
            ts_ns: facts.ts_ns,
            duration_ns: facts.duration_ns,
            pid_tgid: facts.pid_tgid,
            cgroup_id: facts.cgroup_id,
            session: facts.session,
            slot_id: 3,
            mechanism: facts.mechanism,
            flags: 5,
            rv: facts.rv,
            p0: 8,
            p1: 9,
            p2: 10,
            async_value: facts.async_value,
            slot: 40,
            target_function: 37,
            user_type: 6,
            shape: 7,
            attr_types: [12, 13, 14, 15, 16, 17, 18, 19],
            attr_count: 20,
            attr_total: 21,
            attr_bools: 22,
            attr_bools_seen: 23,
            attr_types1: [24, 25, 26, 27, 28, 29, 30, 31],
            attr_count1: 32,
            attr_total1: 33,
            attr_bools1: 34,
            attr_bools_seen1: 35,
            capture: facts.capture_flags,
            event_type: crate::event_type::CALL,
            image: ImageIdentity {
                task_cookie: 38,
                exec_id: 39,
            },
            child_image: ImageIdentity {
                task_cookie: 0,
                exec_id: 0,
            },
            root_affiliation: facts.root_affiliation,
        };
        for poison in [0xA5, 0x5A] {
            let mut actual = core::mem::MaybeUninit::<Event>::uninit();
            // All Event fields are integer scalars/arrays. The frozen Event
            // has no padding; compare all328 bytes, including zero child image.
            unsafe {
                core::ptr::write_bytes(
                    actual.as_mut_ptr().cast::<u8>(),
                    poison,
                    core::mem::size_of::<Event>(),
                );
                fill_call_event(actual.as_mut_ptr(), &start, 40, &facts);
                let actual = core::slice::from_raw_parts(
                    actual.as_ptr().cast::<u8>(),
                    core::mem::size_of::<Event>(),
                );
                let expected = core::slice::from_raw_parts(
                    (&expected as *const Event).cast::<u8>(),
                    core::mem::size_of::<Event>(),
                );
                assert_eq!(actual.len(), 328);
                assert_eq!(actual, expected, "word={word} poison={poison}");
            }
        }
    }
}

#[test]
fn streamed_stable_recheck_preserves_read_order_and_failure_priority() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for failed in 0u8..8 {
            for changed in 0u8..8 {
                let target = fresh(w);
                prog_attr(&target, 0x4000, 0, w, SEL_CLASS, 0x8000, w);
                target.borrow_mut().set_word(0x8000, 3);
                let mut out = crate::object_wire::ObjectAttributeWire::default();
                let flags = stable_attribute_cell(
                    0x4000,
                    0,
                    object_policy::SafeAttributeKind::Class,
                    0x8000,
                    w,
                    layout,
                    &mut out,
                    &mut |addr| {
                        let original = target.borrow_mut().read_word(addr);
                        let Some(index) = [0x4000, 0x4000 + w, 0x4000 + 2 * w]
                            .iter()
                            .position(|candidate| *candidate == addr)
                        else {
                            return original;
                        };
                        if failed & (1 << index) != 0 {
                            Err(())
                        } else if changed & (1 << index) != 0 {
                            Ok([SEL_KEYTYPE, 0x9000, w + 1][index])
                        } else {
                            original
                        }
                    },
                    &mut |addr, bytes| target.borrow_mut().read_bytes(addr, bytes),
                );
                let expected = if failed != 0 {
                    ast::UNREADABLE
                } else if changed != 0 {
                    ast::CHANGED
                } else {
                    ast::VALUE
                };
                assert_eq!(out.status, expected, "failed={failed} changed={changed}");
                assert_eq!(out.value, if expected == ast::VALUE { 3 } else { 0 });
                assert_eq!(
                    flags,
                    if expected == ast::CHANGED {
                        ofl::CHANGED_METADATA
                    } else {
                        0
                    }
                );
                assert_eq!(
                    target.borrow().log(),
                    &[
                        (READ_WORD, 0x8000, w),
                        (READ_WORD, 0x4000, w),
                        (READ_WORD, 0x4000 + w, w),
                        (READ_WORD, 0x4000 + 2 * w, w),
                    ]
                );
            }
        }
    }
}

#[test]
fn request_cell_pack_preserves_widths_and_refuses_unknown_bits() {
    for kind in 0..=6 {
        for status in 0..=10 {
            for list_flags in [0, alf::HEADER_READ_FAILURE] {
                for object_flags in [
                    0,
                    ofl::ALIAS,
                    ofl::CHANGED_METADATA,
                    ofl::ALIAS | ofl::CHANGED_METADATA,
                ] {
                    for value in [0, 1, u16::MAX] {
                        if value != 0 && (kind == 0 || status != ast::VALUE) {
                            continue;
                        }
                        let facts = RequestCellFacts {
                            kind,
                            status,
                            value,
                            list_flags,
                            object_flags,
                        };
                        let packed =
                            pack_request_cell(facts).expect("finite facts fit without truncation");
                        assert_eq!(packed >> 48, 0);
                        assert_eq!(unpack_request_cell(packed), Some(facts));
                    }
                }
            }
        }
    }
    let good = RequestCellFacts {
        kind: 1,
        status: ast::VALUE,
        value: 0xabcd,
        list_flags: alf::HEADER_READ_FAILURE,
        object_flags: ofl::CHANGED_METADATA,
    };
    assert_eq!(pack_request_cell(good), Some(0x1004_abcd_0101));
    for bad in [
        RequestCellFacts { kind: 7, ..good },
        RequestCellFacts {
            kind: u8::MAX,
            ..good
        },
        RequestCellFacts { status: 11, ..good },
        RequestCellFacts {
            status: u8::MAX,
            ..good
        },
        RequestCellFacts { kind: 0, ..good },
        RequestCellFacts {
            status: ast::CHANGED,
            ..good
        },
        RequestCellFacts {
            list_flags: alf::PRESENT,
            ..good
        },
        RequestCellFacts {
            list_flags: alf::TRUNCATED,
            ..good
        },
        RequestCellFacts {
            list_flags: alf::INVALID_SPAN,
            ..good
        },
        RequestCellFacts {
            list_flags: alf::UNINSPECTED,
            ..good
        },
        RequestCellFacts {
            object_flags: ofl::ARG_READ_FAILURE,
            ..good
        },
        RequestCellFacts {
            object_flags: 1 << 8,
            ..good
        },
        RequestCellFacts {
            object_flags: 1 << 31,
            ..good
        },
    ] {
        assert!(pack_request_cell(bad).is_none(), "bad={bad:?}");
    }
    for bit in (48..64).chain([32, 33, 35, 36, 37, 38, 39, 40, 41, 43, 45, 46, 47]) {
        assert!(unpack_request_cell(1 << bit).is_none(), "unknown bit {bit}");
    }
    for bad in [7, 0xff, 11 << 8, 0xff << 8, 1 << 16] {
        assert!(unpack_request_cell(bad).is_none(), "bad={bad:#x}");
    }
    assert_eq!(
        unpack_request_cell(request_cell_poison()),
        Some(RequestCellFacts {
            list_flags: alf::HEADER_READ_FAILURE,
            ..RequestCellFacts::default()
        })
    );
}

#[test]
fn request_cell_poison_arguments_never_read_target_memory() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let good = encode_request_cell_tag(0, layout, true).unwrap();
        assert_eq!(decode_request_cell_tag(good), Some((0, layout, true)));
        for index in [8, 0x100, u64::MAX] {
            assert!(encode_request_cell_tag(index, layout, false).is_none());
        }
        let high = if layout == LinuxLayout::Ilp32 {
            1 << 32
        } else {
            u64::MAX - 8
        };
        for (base, count, tag) in [
            (0x4000, 1, good | 8),
            (0x4000, 1, good | (1 << 10)),
            (0x4000, 1, good | (1 << 63)),
            (0x4000, 1, encode_request_cell_tag(7, layout, true).unwrap()),
            (0x4000, 0, good),
            (0, 1, good),
            (high, 1, good),
            (0x4000, u64::MAX, good),
        ] {
            let target = fresh(layout.word_bytes() as u64);
            let (mut r, mut b) = readers(&target);
            assert_eq!(
                request_cell_packed(base, count, tag, 0x6000, 1, &mut r, &mut b),
                request_cell_poison(),
                "base={base:#x} count={count} tag={tag:#x}"
            );
            assert_log(&target, &[]);
        }
        for index in 0..8 {
            for peer in [false, true] {
                let tag = encode_request_cell_tag(index, layout, peer).unwrap();
                assert_eq!(decode_request_cell_tag(tag), Some((index, layout, peer)));
            }
        }
    }
}

#[test]
fn request_cell_preserves_ordered_reads_and_failure_priority() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for mode in 0..11 {
            let target = fresh(w);
            prog_attr(
                &target,
                0x4000,
                0,
                w,
                if mode == 2 {
                    0x11
                } else if mode == 10 {
                    (1 << 32) | SEL_CLASS
                } else {
                    SEL_CLASS
                },
                0x8000,
                w,
            );
            target.borrow_mut().set_word(0x8000, 3);
            let failed = match mode {
                1 => Some(0x4000),
                3 => Some(0x4000 + w),
                4 => Some(0x4000 + 2 * w),
                5 => Some(0x8000),
                _ => None,
            };
            if let Some(address) = failed {
                target.borrow_mut().set_fail(address);
            }
            if mode == 6 {
                target.borrow_mut().script_word(4, 0x4000, SEL_KEYTYPE);
            }
            if (7..=9).contains(&mode) {
                prog_attr(
                    &target,
                    0x6000,
                    0,
                    w,
                    SEL_TOKEN,
                    if mode == 7 { 0x8000 } else { 0x9000 },
                    2,
                );
            }
            if mode == 9 {
                target.borrow_mut().set_fail(0x6000 + w);
            }
            let (mut r, mut b) = readers(&target);
            let facts = unpack_request_cell(request_cell_packed(
                0x4000,
                1,
                encode_request_cell_tag(0, layout, (7..=9).contains(&mode)).unwrap(),
                0x6000,
                1,
                &mut r,
                &mut b,
            ))
            .unwrap();
            let expected = match mode {
                1 => (0, 0, 0, alf::HEADER_READ_FAILURE, 0),
                2 | 10 => (0, 0, 0, 0, 0),
                3 | 4 => (1, ast::UNREADABLE, 0, alf::HEADER_READ_FAILURE, 0),
                5 => (1, ast::UNREADABLE, 0, 0, 0),
                6 => (1, ast::CHANGED, 0, 0, ofl::CHANGED_METADATA),
                7 => (1, ast::ALIAS, 0, 0, ofl::ALIAS),
                9 => (1, ast::VALUE, 3, alf::HEADER_READ_FAILURE, 0),
                _ => (1, ast::VALUE, 3, 0, 0),
            };
            assert_eq!(
                (
                    facts.kind,
                    facts.status,
                    facts.value,
                    facts.list_flags,
                    facts.object_flags
                ),
                expected,
                "mode={mode} layout={layout:?}"
            );
            let mut expected_reads = std::vec![(READ_WORD, 0x4000, w)];
            if ![1, 2, 10].contains(&mode) {
                expected_reads.push((READ_WORD, 0x4000 + w, w));
            }
            if ![1, 2, 3, 10].contains(&mode) {
                expected_reads.push((READ_WORD, 0x4000 + 2 * w, w));
            }
            if (7..=9).contains(&mode) {
                expected_reads.extend([
                    (READ_WORD, 0x6000, w),
                    (READ_WORD, 0x6000 + w, w),
                    (READ_WORD, 0x6000 + 2 * w, w),
                ]);
            }
            if ![1, 2, 3, 4, 7, 10].contains(&mode) {
                expected_reads.push((READ_WORD, 0x8000, w));
                if mode != 5 {
                    expected_reads.extend([
                        (READ_WORD, 0x4000, w),
                        (READ_WORD, 0x4000 + w, w),
                        (READ_WORD, 0x4000 + 2 * w, w),
                    ]);
                }
            }
            assert_log(&target, &expected_reads);
        }
    }
}

#[test]
fn stable_cell_pack_roundtrips() {
    for status in [0u8, 1, 5, 0xFF] {
        for value in [0u16, 1, 0x1234, 0xFFFF] {
            for write_value in [false, true] {
                for contrib in [0u32, ofl::CHANGED_METADATA, u32::MAX] {
                    let (s, v, w, c) =
                        unpack_stable_cell(pack_stable_cell(status, value, write_value, contrib));
                    assert_eq!((s, v, w, c), (status, value, write_value, contrib));
                }
            }
        }
    }
}

#[test]
fn stable_cell_kind_layout_codec_roundtrips() {
    use object_policy::SafeAttributeKind as Kind;
    for kind in [
        Kind::Class,
        Kind::KeyType,
        Kind::Token,
        Kind::ValueLen,
        Kind::ModulusBits,
        Kind::EcParams,
    ] {
        for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
            let code = encode_stable_kind_layout(kind, layout);
            assert_eq!(decode_stable_kind_layout(code), Some((kind, layout)));
        }
    }
    // Unused code 0, above-range codes, bad layout tags, high garbage.
    for bad in [0u64, 7, 0xFF, 0x200, 0x201, 1 << 16, u64::MAX] {
        assert_eq!(decode_stable_kind_layout(bad), None, "bad={bad:#x}");
    }
}

#[test]
fn stable_cell_poison_inputs_publish_nothing() {
    for bad in [0u64, 7, 0xFF, 0x200, u64::MAX] {
        let reads = core::cell::Cell::new(0u32);
        let packed = stable_cell_packed(
            0x4000,
            0,
            bad,
            0x8000,
            8,
            &mut |_| {
                reads.set(reads.get() + 1);
                Ok(0)
            },
            &mut |_, _| {
                reads.set(reads.get() + 1);
                Ok(())
            },
        );
        assert_eq!(packed, stable_cell_poison(), "bad={bad:#x}");
        assert_eq!(reads.get(), 0, "bad={bad:#x}");
        assert_eq!(unpack_stable_cell(packed), (ast::UNREADABLE, 0, false, 0));
    }
}

/// E1a boundary equivalence: the packed global form publishes exactly what the
/// direct wrapper publishes, with identical reads, across every kind, layout,
/// and recheck fault combination (plus invalid spans and unreadable values).
#[test]
fn stable_cell_packed_matches_direct() {
    use object_policy::SafeAttributeKind as Kind;
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for (kind, selector, len) in [
            (Kind::Class, SEL_CLASS, w),
            (Kind::KeyType, SEL_KEYTYPE, w),
            (Kind::Token, SEL_TOKEN, 1),
            (Kind::ValueLen, SEL_VALUELEN, w),
            (Kind::ModulusBits, SEL_MODBITS, w),
            (Kind::EcParams, SEL_ECPARAMS, 10),
        ] {
            for failed in 0u8..8 {
                for changed in 0u8..8 {
                    for value_case in 0..3 {
                        let run = |packed: bool| {
                            let target = fresh(w);
                            prog_attr(&target, 0x4000, 0, w, selector, 0x8000, len);
                            match (kind, value_case) {
                                (Kind::Token, 0) => {
                                    target.borrow_mut().set_bytes(0x8000, &[1]);
                                }
                                (Kind::Token, 1) => {
                                    target.borrow_mut().set_bytes(0x8000, &[9]);
                                }
                                (Kind::EcParams, 0) => {
                                    target.borrow_mut().set_bytes(0x8000, EC_P256);
                                }
                                (Kind::EcParams, 1) => {
                                    target.borrow_mut().set_bytes(0x8000, &[9; 10]);
                                }
                                (_, 0) => {
                                    let scalar = match kind {
                                        Kind::Class => 3,
                                        Kind::KeyType => 0x10,
                                        Kind::ValueLen => 32,
                                        Kind::ModulusBits => 2048,
                                        _ => unreachable!(),
                                    };
                                    target.borrow_mut().set_word(0x8000, scalar);
                                }
                                (_, 1) => {
                                    target.borrow_mut().set_word(0x8000, 0xFFFF);
                                }
                                // value_case 2 leaves the value unreadable.
                                _ => {}
                            }
                            let mut read_word = |addr: u64| {
                                let original = target.borrow_mut().read_word(addr);
                                let Some(index) = [0x4000, 0x4000 + w, 0x4000 + 2 * w]
                                    .iter()
                                    .position(|candidate| *candidate == addr)
                                else {
                                    return original;
                                };
                                if failed & (1 << index) != 0 {
                                    Err(())
                                } else if changed & (1 << index) != 0 {
                                    Ok([SEL_KEYTYPE, 0x9000, len + 1][index])
                                } else {
                                    original
                                }
                            };
                            let mut read_bytes = |addr: u64, bytes: &mut [u8]| {
                                target.borrow_mut().read_bytes(addr, bytes)
                            };
                            let mut out = crate::object_wire::ObjectAttributeWire::default();
                            let flags = if packed {
                                let encoded = encode_stable_kind_layout(kind, layout);
                                let (status, value, write_value, contrib) =
                                    unpack_stable_cell(stable_cell_packed(
                                        0x4000,
                                        0,
                                        encoded,
                                        0x8000,
                                        len,
                                        &mut read_word,
                                        &mut read_bytes,
                                    ));
                                out.status = status;
                                if write_value {
                                    out.value = value;
                                }
                                contrib
                            } else {
                                stable_attribute_cell(
                                    0x4000,
                                    0,
                                    kind,
                                    0x8000,
                                    len,
                                    layout,
                                    &mut out,
                                    &mut read_word,
                                    &mut read_bytes,
                                )
                            };
                            let outcome =
                                (out.status, out.value, flags, target.borrow().log().to_vec());
                            outcome
                        };
                        let direct = run(false);
                        let packed = run(true);
                        assert_eq!(
                            packed, direct,
                            "kind={kind:?} failed={failed} changed={changed} value_case={value_case}"
                        );
                    }
                }
            }
            // Invalid header span: the value classifies, then the header
            // addresses refuse; exactly one read (the value) on either path.
            for packed in [false, true] {
                let target = fresh(w);
                match kind {
                    Kind::Token => target.borrow_mut().set_bytes(0x8000, &[1]),
                    Kind::EcParams => target.borrow_mut().set_bytes(0x8000, EC_P256),
                    Kind::Class => target.borrow_mut().set_word(0x8000, 3),
                    Kind::KeyType => target.borrow_mut().set_word(0x8000, 0x10),
                    Kind::ValueLen => target.borrow_mut().set_word(0x8000, 32),
                    Kind::ModulusBits => target.borrow_mut().set_word(0x8000, 2048),
                }
                let (mut rw, mut rb) = readers(&target);
                let mut out = crate::object_wire::ObjectAttributeWire::default();
                let flags = if packed {
                    let encoded = encode_stable_kind_layout(kind, layout);
                    let (status, value, write_value, contrib) = unpack_stable_cell(
                        stable_cell_packed(u64::MAX - 8, 0, encoded, 0x8000, len, &mut rw, &mut rb),
                    );
                    out.status = status;
                    if write_value {
                        out.value = value;
                    }
                    contrib
                } else {
                    stable_attribute_cell(
                        u64::MAX - 8,
                        0,
                        kind,
                        0x8000,
                        len,
                        layout,
                        &mut out,
                        &mut rw,
                        &mut rb,
                    )
                };
                assert_eq!(
                    (out.status, out.value, flags, target.borrow().log().len()),
                    (ast::INVALID_SPAN, 0, 0, 1),
                    "kind={kind:?} packed={packed}"
                );
            }
        }
    }
}

#[test]
fn streamed_alias_header_failures_keep_all_selected_reads() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for (other_ptr, other_len, overlaps) in [
            (0x8000, 16, true),
            (0, 16, false),
            (0x9000, 16, false),
            (u64::MAX, 16, false),
            (0x8000, 0, false),
            (0x7ff8, 9, true),
        ] {
            for failed in 0..4 {
                let target = fresh(w);
                prog_attr(&target, 0x4000, 0, w, SEL_TOKEN, other_ptr, other_len);
                if failed & 1 != 0 {
                    target.borrow_mut().set_fail(0x4000 + w);
                }
                if failed & 2 != 0 {
                    target.borrow_mut().set_fail(0x4000 + 2 * w);
                }
                let (alias, flags) = request_alias_scan(
                    0x4000,
                    1,
                    u64::MAX,
                    0x8000,
                    8,
                    layout,
                    &mut word_reader(&target),
                );
                assert_eq!(alias, failed == 0 && overlaps);
                assert_eq!(
                    flags,
                    if failed == 0 {
                        0
                    } else {
                        alf::HEADER_READ_FAILURE
                    }
                );
                assert_eq!(
                    target.borrow().log(),
                    &[
                        (READ_WORD, 0x4000, w),
                        (READ_WORD, 0x4000 + w, w),
                        (READ_WORD, 0x4000 + 2 * w, w),
                    ]
                );
            }
        }
    }
}

#[test]
fn alias_scan_pack_roundtrips() {
    for alias in [false, true] {
        for flags in [0u8, 1, 0xFF] {
            assert_eq!(
                unpack_alias_scan(pack_alias_scan(alias, flags)),
                (alias, flags)
            );
        }
    }
}

#[test]
fn alias_skip_layout_codec_roundtrips() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        // Every skip the roots produce: per-index skips decode exactly.
        for skip in 0..8u64 {
            assert_eq!(
                decode_alias_skip_layout(encode_alias_skip_layout(skip, layout)),
                (skip, layout)
            );
        }
        // No-skip decodes to a below-`u64::MAX` value that still skips
        // nothing: the scan only compares `j != skip` with `j < 8`.
        let (skip, decoded) = decode_alias_skip_layout(encode_alias_skip_layout(u64::MAX, layout));
        assert_eq!(decoded, layout);
        for j in 0..8u64 {
            assert_ne!(j, skip);
        }
    }
}

/// E1b boundary equivalence: the packed global form returns exactly what the
/// direct wrapper returns, with identical reads, across overlap shapes,
/// header faults, skip values, and one multi-neighbor layout.
#[test]
fn alias_scan_packed_matches_direct() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        let w = layout.word_bytes() as u64;
        for (other_ptr, other_len) in [
            (0x8000, 16),
            (0, 16),
            (0x9000, 16),
            (u64::MAX, 16),
            (0x8000, 0),
            (0x7ff8, 9),
        ] {
            for failed in 0..4 {
                for skip in [0u64, 1, u64::MAX] {
                    let run = |packed: bool| {
                        let target = fresh(w);
                        prog_attr(&target, 0x4000, 0, w, SEL_TOKEN, other_ptr, other_len);
                        if failed & 1 != 0 {
                            target.borrow_mut().set_fail(0x4000 + w);
                        }
                        if failed & 2 != 0 {
                            target.borrow_mut().set_fail(0x4000 + 2 * w);
                        }
                        let outcome = if packed {
                            let encoded = encode_alias_skip_layout(skip, layout);
                            unpack_alias_scan(alias_scan_packed(
                                0x4000,
                                1,
                                encoded,
                                0x8000,
                                8,
                                &mut word_reader(&target),
                            ))
                        } else {
                            request_alias_scan(
                                0x4000,
                                1,
                                skip,
                                0x8000,
                                8,
                                layout,
                                &mut word_reader(&target),
                            )
                        };
                        let logged = target.borrow().log().to_vec();
                        (outcome.0, outcome.1, logged)
                    };
                    let direct = run(false);
                    let packed = run(true);
                    assert_eq!(
                        packed, direct,
                        "other=({other_ptr:#x},{other_len}) failed={failed} skip={skip:#x}"
                    );
                }
            }
        }
        // Multi-neighbor: two overlapping selected headers, one skipped.
        for skip in [3u64, u64::MAX] {
            let run = |packed: bool| {
                let target = fresh(w);
                prog_attr(&target, 0x4000, 3, w, SEL_TOKEN, 0x8000, 16);
                prog_attr(&target, 0x4000, 5, w, SEL_KEYTYPE, 0x8000, 16);
                let outcome = if packed {
                    let encoded = encode_alias_skip_layout(skip, layout);
                    unpack_alias_scan(alias_scan_packed(
                        0x4000,
                        8,
                        encoded,
                        0x8000,
                        8,
                        &mut word_reader(&target),
                    ))
                } else {
                    request_alias_scan(
                        0x4000,
                        8,
                        skip,
                        0x8000,
                        8,
                        layout,
                        &mut word_reader(&target),
                    )
                };
                let logged = target.borrow().log().to_vec();
                (outcome.0, outcome.1, logged)
            };
            let direct = run(false);
            let packed = run(true);
            assert!(direct.0, "skip={skip:#x}");
            assert_eq!(packed, direct, "skip={skip:#x}");
        }
    }
}

/// E1c boundary equivalence: the packed global form agrees with the direct
/// core on every address/capacity edge, both layouts, and poison widths.
#[test]
fn alias_capacity_packed_matches_direct() {
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        for (ptr, len) in [
            (0u64, 0u64),
            (0x8000, 8),
            (0x7ff8, 9),
            (u64::MAX - 8, 16),
            (u64::MAX, 1),
        ] {
            for (other_ptr, other_cap) in [
                (0u64, 0u64),
                (0, 16),
                (0x8000, 0),
                (0x8000, 16),
                (0x9000, 16),
                (0x7ff8, 9),
                (u64::MAX, 16),
                (u64::MAX - 8, 16),
            ] {
                let direct = alias_capacity_core(ptr, len, other_ptr, other_cap, layout);
                let wb = layout.word_bytes() as u64;
                assert_eq!(
                    alias_capacity_packed(ptr, len, other_ptr, other_cap, wb),
                    u64::from(direct),
                    "ptr={ptr:#x} len={len} other=({other_ptr:#x},{other_cap})"
                );
                // Spot-anchor the verdict (not just equivalence): disjoint and
                // zero spans never alias; identical spans always do.
                if ptr == 0x8000 && len == 8 {
                    let expected = (other_ptr, other_cap) == (0x8000, 16)
                        || (other_ptr, other_cap) == (0x7ff8, 9);
                    assert_eq!(direct, expected, "other=({other_ptr:#x},{other_cap})");
                }
            }
        }
        // Poison widths publish "no alias" without a layout.
        for wb in [0u64, 3, 5, 7, 9, u64::MAX] {
            assert_eq!(decode_alias_capacity_layout(wb), None);
            assert_eq!(
                alias_capacity_packed(0x8000, 8, 0x8000, 16, wb),
                0,
                "wb={wb}"
            );
        }
    }
}

#[test]
fn slot_kind_codes_stay_consecutive_from_class() {
    // `slot_kind_selected` subtracts CLASS and range-checks; any renumber
    // must update it together with this pin.
    assert_eq!(
        [
            attr_kind::CLASS,
            attr_kind::KEY_TYPE,
            attr_kind::TOKEN,
            attr_kind::VALUE_LEN,
            attr_kind::MODULUS_BITS,
            attr_kind::EC_PARAMS,
        ],
        [1, 2, 3, 4, 5, 6]
    );
    for code in 0u8..=u8::MAX {
        assert_eq!(
            slot_kind_selected(code),
            kind_from_code(code).is_some(),
            "code {code}"
        );
    }
}

#[test]
fn selector_for_kind_inverts_policy_mapping() {
    use object_policy::SafeAttributeKind;
    for kind in [
        SafeAttributeKind::Class,
        SafeAttributeKind::KeyType,
        SafeAttributeKind::Token,
        SafeAttributeKind::ValueLen,
        SafeAttributeKind::ModulusBits,
        SafeAttributeKind::EcParams,
    ] {
        assert_eq!(
            object_policy::safe_attribute_kind(selector_for_kind(kind)),
            Some(kind),
            "{kind:?}"
        );
    }
}
