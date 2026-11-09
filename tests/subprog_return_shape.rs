//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Kernels since 7.4 treat a static subprogram whose BTF return type is
//! 9..=16 bytes as returning a register pair (R0, R2) and refuse the load
//! when either register holds a stack pointer at subprogram exit
//! (`prepare_func_exit`: "cannot return stack pointer to the caller").
//! Our toolchain lowers such wide returns through a caller-stack
//! out-pointer, so R2 regularly still holds an incoming caller-stack
//! argument at exit. No embedded object may keep a subprogram in that
//! BTF return size window: return at most 8 bytes (`bool` plus a
//! caller-owned slot) instead.
//!
//! Entry programs (subprog 0) are exempt in the kernel, but every entry
//! here returns a small integer, so this test holds all FUNCs to the
//! same bound and any future wide entry return trips it loudly.

use p11scope::attach::identity_iter::IDENTITY_OBJECT;

fn le_u16_at(data: &[u8], at: usize, what: &str) -> u16 {
    let bytes: [u8; 2] = data
        .get(at..at + 2)
        .unwrap_or_else(|| panic!("{what} out of bounds at {at}"))
        .try_into()
        .expect("u16 slice");
    u16::from_le_bytes(bytes)
}

fn le_u32_at(data: &[u8], at: usize, what: &str) -> u32 {
    let bytes: [u8; 4] = data
        .get(at..at + 4)
        .unwrap_or_else(|| panic!("{what} out of bounds at {at}"))
        .try_into()
        .expect("u32 slice");
    u32::from_le_bytes(bytes)
}

fn le_u64_at(data: &[u8], at: usize, what: &str) -> u64 {
    let bytes: [u8; 8] = data
        .get(at..at + 8)
        .unwrap_or_else(|| panic!("{what} out of bounds at {at}"))
        .try_into()
        .expect("u64 slice");
    u64::from_le_bytes(bytes)
}

fn btf_section<'a>(object: &'a [u8], label: &str) -> &'a [u8] {
    assert!(
        object.len() >= 64,
        "{label}: object smaller than an ELF header"
    );
    assert_eq!(&object[0..4], b"\x7fELF", "{label}: not an ELF object");
    assert_eq!(object[4], 2, "{label}: not a 64-bit object");
    assert_eq!(object[5], 1, "{label}: not little-endian");
    let shoff = usize::try_from(le_u64_at(object, 0x28, "e_shoff")).expect("e_shoff fits");
    let shentsize = usize::from(le_u16_at(object, 0x3a, "e_shentsize"));
    let shnum = usize::from(le_u16_at(object, 0x3c, "e_shnum"));
    let shstrndx = usize::from(le_u16_at(object, 0x3e, "e_shstrndx"));
    assert_eq!(shentsize, 64, "{label}: unexpected section header size");
    assert!(shnum > 0, "{label}: object has no sections");
    assert!(
        shstrndx < shnum,
        "{label}: section-name index out of bounds"
    );
    let header_at = |index: usize| {
        let at = shoff
            .checked_add(index.checked_mul(shentsize).expect("section table fits"))
            .expect("section table fits");
        assert!(
            object.len() >= at + 64,
            "{label}: section header {index} out of bounds"
        );
        at
    };
    let names_at = header_at(shstrndx);
    let names_off =
        usize::try_from(le_u64_at(object, names_at + 24, "shstrtab offset")).expect("offset fits");
    let names_len =
        usize::try_from(le_u64_at(object, names_at + 32, "shstrtab size")).expect("size fits");
    let names = object
        .get(names_off..names_off.checked_add(names_len).expect("names fit"))
        .unwrap_or_else(|| panic!("{label}: section names out of bounds"));
    let name_at = |off: usize| {
        let tail = names
            .get(off..)
            .unwrap_or_else(|| panic!("{label}: section name offset {off} out of bounds"));
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or_else(|| panic!("{label}: unterminated section name"));
        &tail[..end]
    };
    for index in 0..shnum {
        let at = header_at(index);
        if name_at(le_u32_at(object, at, "sh_name") as usize) == b".BTF" {
            let off =
                usize::try_from(le_u64_at(object, at + 24, ".BTF offset")).expect("offset fits");
            let len = usize::try_from(le_u64_at(object, at + 32, ".BTF size")).expect("size fits");
            return object
                .get(off..off.checked_add(len).expect(".BTF fits"))
                .unwrap_or_else(|| panic!("{label}: .BTF contents out of bounds"));
        }
    }
    panic!("{label}: non-empty object without a .BTF section");
}

struct BtfType {
    kind: u32,
    name: String,
    value: u32,
    extra: Vec<u32>,
}

fn btf_string(strings: &[u8], off: u32, label: &str) -> String {
    let tail = strings
        .get(off as usize..)
        .unwrap_or_else(|| panic!("{label}: BTF string offset {off} out of bounds"));
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or_else(|| panic!("{label}: unterminated BTF string"));
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

fn parse_btf(section: &[u8], label: &str) -> Vec<BtfType> {
    assert!(section.len() >= 24, "{label}: .BTF smaller than its header");
    assert_eq!(
        le_u16_at(section, 0, "BTF magic"),
        0xeb9f,
        "{label}: bad BTF magic"
    );
    assert_eq!(section[2], 1, "{label}: unexpected BTF version");
    assert_eq!(section[3], 0, "{label}: unexpected BTF flags");
    assert_eq!(
        le_u32_at(section, 4, "BTF hdr_len"),
        24,
        "{label}: unexpected BTF header length"
    );
    assert_eq!(
        le_u32_at(section, 8, "BTF type_off"),
        0,
        "{label}: unexpected BTF type offset"
    );
    let type_len = le_u32_at(section, 12, "BTF type_len") as usize;
    let str_off = le_u32_at(section, 16, "BTF str_off") as usize;
    let str_len = le_u32_at(section, 20, "BTF str_len") as usize;
    assert_eq!(str_off, type_len, "{label}: unexpected BTF string offset");
    assert_eq!(
        24 + str_off + str_len,
        section.len(),
        "{label}: inconsistent BTF section lengths"
    );
    let raw = &section[24..24 + type_len];
    let strings = &section[24 + str_off..];
    assert!(
        !strings.is_empty() && strings[0] == 0,
        "{label}: bad BTF strings"
    );
    let mut types = Vec::new();
    let mut pos = 0;
    while pos < raw.len() {
        let name_off = le_u32_at(raw, pos, "BTF type name");
        let info = le_u32_at(raw, pos + 4, "BTF type info");
        let value = le_u32_at(raw, pos + 8, "BTF type value");
        let kind = (info >> 24) & 31;
        let vlen = info & 0xffff;
        assert_eq!(info & 0x60ff0000, 0, "{label}: invalid BTF type info");
        let payload: usize = match kind {
            1 | 14 | 17 => 4,
            2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
            3 => 12,
            4 | 5 => (vlen as usize).checked_mul(12).expect("members fit"),
            6 => (vlen as usize).checked_mul(8).expect("values fit"),
            13 => (vlen as usize).checked_mul(8).expect("params fit"),
            15 => (vlen as usize).checked_mul(12).expect("vars fit"),
            19 => (vlen as usize).checked_mul(12).expect("values fit"),
            _ => panic!("{label}: unsupported BTF kind {kind}"),
        };
        let mut extra = Vec::with_capacity(payload / 4);
        for at in (pos + 12..pos + 12 + payload).step_by(4) {
            extra.push(le_u32_at(raw, at, "BTF payload"));
        }
        types.push(BtfType {
            kind,
            name: btf_string(strings, name_off, label),
            value,
            extra,
        });
        pos += 12 + payload;
    }
    types
}

fn resolve_size(types: &[BtfType], mut id: u32, label: &str, func: &str) -> u32 {
    if id == 0 {
        return 0;
    }
    for _ in 0..32 {
        let slot = usize::try_from(id).expect("type id fits");
        assert!(
            slot >= 1 && slot <= types.len(),
            "{label}: {func}: return type id {id} out of bounds"
        );
        let ty = &types[slot - 1];
        match ty.kind {
            1 | 4 | 5 | 6 | 16 | 19 => return ty.value,
            2 => return 8,
            3 => {
                assert_eq!(ty.extra.len(), 3, "{label}: {func}: bad ARRAY payload");
                let elem = resolve_size(types, ty.extra[0], label, func);
                return elem.checked_mul(ty.extra[2]).expect("array size fits");
            }
            8 | 9 | 10 | 11 | 17 | 18 => id = ty.value,
            _ => panic!("{label}: {func}: cannot size BTF kind {} return", ty.kind),
        }
    }
    panic!("{label}: {func}: BTF return type chain too deep");
}

fn wide_returns(label: &str, object: &[u8]) -> Vec<(String, u32)> {
    if object.is_empty() {
        return Vec::new();
    }
    let types = parse_btf(btf_section(object, label), label);
    let mut offenders = Vec::new();
    let mut funcs = 0;
    for ty in &types {
        if ty.kind != 12 {
            continue;
        }
        funcs += 1;
        let slot = usize::try_from(ty.value).expect("proto id fits");
        assert!(
            slot >= 1 && slot <= types.len(),
            "{label}: {}: proto id {} out of bounds",
            ty.name,
            ty.value
        );
        let proto = &types[slot - 1];
        assert_eq!(
            proto.kind, 13,
            "{label}: {}: type {} is not a FUNC_PROTO",
            ty.name, ty.value
        );
        let size = resolve_size(&types, proto.value, label, &ty.name);
        if (9..=16).contains(&size) {
            offenders.push((ty.name.clone(), size));
        }
    }
    assert!(funcs > 0, "{label}: no BTF FUNCs found; parser saw nothing");
    offenders
}

#[test]
fn no_subprogram_returns_nine_to_sixteen_bytes() {
    let objects = [
        ("detailed", p11scope::EBPF_OBJECT),
        ("inventory", p11scope::EBPF_INVENTORY_OBJECT),
        ("inventory-callers", p11scope::EBPF_INVENTORY_CALLERS_OBJECT),
        ("counter-counts", p11scope::EBPF_COUNTER_COUNTS_OBJECT),
        (
            "counter-timestamps",
            p11scope::EBPF_COUNTER_TIMESTAMPS_OBJECT,
        ),
        ("counter-latency", p11scope::EBPF_COUNTER_LATENCY_OBJECT),
        ("journal", p11scope::EBPF_JOURNAL_OBJECT),
        ("identity", IDENTITY_OBJECT),
    ];
    let mut offenders = Vec::new();
    for (label, object) in objects {
        for (name, size) in wide_returns(label, object) {
            offenders.push(format!("{label}: {name} returns {size} bytes"));
        }
    }
    assert!(
        offenders.is_empty(),
        "subprograms in the 7.4 register-pair return window (9..=16 BTF bytes):\n{}",
        offenders.join("\n")
    );
}
