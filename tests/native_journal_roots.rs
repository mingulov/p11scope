//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual private journal roots and their emitted native call graph.

use std::{fs, path::Path, process::Command};

#[path = "../crates/ebpf/src/journal_roots.rs"]
mod root_writers;

#[test]
fn frozen_class_context_never_promotes_unknown_and_preserves_target_abi() {
    use p11scope_ebpf_common::{LinuxLayout, MAX_DESCRIPTORS};
    for (layout, code) in [(LinuxLayout::Lp64, 1), (LinuxLayout::Ilp32, 2)] {
        for (configured, normalized) in [(1, 0), (2, 1), (3, 2)] {
            let context = root_writers::entry_context(21, configured, layout).unwrap();
            assert_eq!(context.descriptor, 21);
            assert_eq!(context.class_bits, normalized);
            assert_eq!(context.layout, code);
            assert_eq!(context.reserved, 0);
        }
        for unknown in [0, 4, u32::MAX] {
            assert!(root_writers::entry_context(21, unknown, layout).is_none());
        }
        for descriptor in [0, MAX_DESCRIPTORS, u32::MAX] {
            assert!(root_writers::entry_context(descriptor, 2, layout).is_none());
        }
    }
}

#[test]
fn begin_decision_calls_every_valid_context_and_gaps_the_rest() {
    use p11scope_ebpf_common::{LinuxLayout, MAX_DESCRIPTORS};
    use root_writers::BeginDecision;
    for (layout, code) in [(LinuxLayout::Lp64, 1), (LinuxLayout::Ilp32, 2)] {
        for (configured, normalized) in [(1, 0), (2, 1), (3, 2)] {
            let BeginDecision::Call(context) = root_writers::begin_decision(21, configured, layout)
            else {
                panic!("configured {configured} must decide Call");
            };
            assert_eq!(context.descriptor, 21);
            assert_eq!(context.class_bits, normalized);
            assert_eq!(context.layout, code);
            assert_eq!(context.reserved, 0);
        }
        for unknown in [0, 4, u32::MAX] {
            assert!(matches!(
                root_writers::begin_decision(21, unknown, layout),
                BeginDecision::Gap
            ));
        }
        for descriptor in [0, MAX_DESCRIPTORS, u32::MAX] {
            assert!(matches!(
                root_writers::begin_decision(descriptor, 2, layout),
                BeginDecision::Gap
            ));
        }
    }
}

#[test]
fn completion_reason_names_result_lost_only_on_unjournaled() {
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_END_TAIL_ABSENT, JOURNAL_END_UNJOURNALED, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
    };
    for (flags, expected) in [
        (0, 0),
        (u32::from(JOURNAL_END_TAIL_ABSENT), 0),
        (
            u32::from(JOURNAL_END_UNJOURNALED),
            JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
        ),
        (
            u32::from(JOURNAL_END_TAIL_ABSENT | JOURNAL_END_UNJOURNALED),
            JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
        ),
    ] {
        let words = root_writers::ReturnWords {
            flags,
            ..root_writers::ReturnWords::default()
        };
        assert_eq!(root_writers::completion_reason(&words), expected);
    }
}

#[test]
fn end_header_and_absent_tail_initialize_every_byte_in_poisoned_storage() {
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_END_FULL_BYTES, JOURNAL_END_TAIL_ABSENT, JOURNAL_END_UNJOURNALED, JOURNAL_KIND_END,
        JOURNAL_VERSION, JournalEndFull,
    };
    for absent in [false, true] {
        for tracked in [false, true] {
            let mut storage = std::mem::MaybeUninit::<JournalEndFull>::uninit();
            unsafe {
                storage
                    .as_mut_ptr()
                    .cast::<u8>()
                    .write_bytes(0xa5, JOURNAL_END_FULL_BYTES)
            };
            let words = root_writers::ReturnWords {
                thread: if tracked { 41 } else { 0 },
                sequence: if tracked { 7 } else { 0 },
                flags: if tracked {
                    0
                } else {
                    u32::from(JOURNAL_END_UNJOURNALED)
                },
                pad: 0,
            };
            unsafe { root_writers::initialize_end(storage.as_mut_ptr(), &words, absent) };
            let bytes = unsafe {
                std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), JOURNAL_END_FULL_BYTES)
            };
            let mut expected = [0u8; 24];
            expected[..2].copy_from_slice(&JOURNAL_VERSION.to_ne_bytes());
            expected[2..4].copy_from_slice(&(JOURNAL_END_FULL_BYTES as u16).to_ne_bytes());
            expected[4] = JOURNAL_KIND_END;
            expected[5] = words.flags as u8 | if absent { JOURNAL_END_TAIL_ABSENT } else { 0 };
            expected[8..16].copy_from_slice(&words.thread.to_ne_bytes());
            expected[16..24].copy_from_slice(&words.sequence.to_ne_bytes());
            assert_eq!(&bytes[..24], &expected);
            assert!(bytes[24..392].iter().all(|byte| *byte == 0xa5));
            assert!(
                bytes[392..]
                    .iter()
                    .all(|byte| *byte == if absent { 0 } else { 0xa5 })
            );
        }
    }
}

#[test]
fn routing_words_are_sampled_once_and_stored_before_the_next_sampler() {
    use p11scope_ebpf_common::Event;
    use root_writers::RoutingWord;
    let mut storage = std::mem::MaybeUninit::<Event>::uninit();
    let raw = storage.as_mut_ptr();
    unsafe {
        raw.cast::<u8>()
            .write_bytes(0xa5, std::mem::size_of::<Event>())
    };
    let mut order = Vec::new();
    unsafe {
        root_writers::fill_routing(raw, |word| {
            order.push(word);
            match word {
                RoutingWord::PidTgid => 11,
                RoutingWord::Cgroup => {
                    assert_eq!((*raw).pid_tgid, 11);
                    22
                }
                RoutingWord::RootAffiliation => {
                    assert_eq!((*raw).pid_tgid, 11);
                    assert_eq!((*raw).cgroup_id, 22);
                    1
                }
            }
        });
    }
    assert_eq!(
        order,
        [
            RoutingWord::PidTgid,
            RoutingWord::Cgroup,
            RoutingWord::RootAffiliation
        ]
    );
    let bytes =
        unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), std::mem::size_of::<Event>()) };
    let mut expected = vec![0xa5; std::mem::size_of::<Event>()];
    for (offset, value) in [
        (std::mem::offset_of!(Event, pid_tgid), 11u64),
        (std::mem::offset_of!(Event, cgroup_id), 22),
        (std::mem::offset_of!(Event, root_affiliation), 1),
    ] {
        expected[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }
    assert_eq!(bytes, expected);
}

#[test]
fn native_prepare_initializes_retained_bytes_and_preserves_blocked_retry() {
    let temporary = tempfile::tempdir().unwrap();
    let source = fs::read_to_string("crates/ebpf/native/object_journal.c").unwrap();
    for (index, mutant) in [
        None,
        Some((
            "txn_copy(out->record + 56, (const unsigned char *)start, 8);",
            "txn_copy(out->record + 56, (const unsigned char *)start + 8, 8);",
        )),
        Some((
            "__builtin_memset(out, 0, sizeof(*out));",
            "__builtin_memset(out, 0, sizeof(*out) - 4);",
        )),
        Some((
            "out->state = JOURNAL_SETTLE_BLOCKED;",
            "out->state = JOURNAL_SETTLE_EMPTY;",
        )),
        Some((
            "if (!journal_header_valid(bytes, kind, flags, 0, thread, sequence))",
            "if (0)",
        )),
    ]
    .into_iter()
    .enumerate()
    {
        let directory = temporary.path().join(index.to_string());
        fs::create_dir(&directory).unwrap();
        for file in ["task_owner.c", "task_owner.h", "object_journal.h"] {
            fs::copy(
                Path::new("crates/ebpf/native").join(file),
                directory.join(file),
            )
            .unwrap();
        }
        let native = if let Some((before, after)) = mutant {
            assert_eq!(source.matches(before).count(), 1, "native mutation anchor");
            source.replace(before, after)
        } else {
            source.clone()
        };
        fs::write(directory.join("object_journal.c"), native).unwrap();
        let binary = directory.join("prepare");
        let output = Command::new("clang-18")
            .args([
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
                "-DP11SCOPE_OBJECT_JOURNAL",
                "-DP11_JOURNAL_ROOTS_PREPARE_TEST",
                "-I",
            ])
            .arg(&directory)
            .arg("tests/fixtures/object-journal/journal_roots_bridge.c")
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(binary)
            .current_dir(&directory)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            mutant.is_none(),
            "native control {index}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if mutant.is_none() {
            assert!(String::from_utf8_lossy(&output.stdout).contains("52 native prepare"));
        }
    }
}

#[test]
fn private_journal_roots_reach_the_real_producer_with_bounded_stack() {
    if option_env!("P11SCOPE_JOURNAL_PROOF_ENABLED") != Some("1") {
        assert_eq!(option_env!("P11SCOPE_JOURNAL_PROOF_ENABLED"), Some("0"));
        return;
    }
    let object = Path::new(env!("OUT_DIR")).join("journal-proof-v1/p11scope-ebpf-journal-proof-v1");
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "-c", ROOT_CHECKER])
        .arg(&object)
        .output()
        .expect("inspect actual private roots");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));

    let temporary = tempfile::tempdir().unwrap();
    let (reader, _) = ROOT_CHECKER
        .split_once("\nfor name, required in {")
        .unwrap();
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "-c", &format!("{reader}\n{ROOT_MUTATIONS}")])
        .arg(&object)
        .arg(temporary.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for (name, diagnostic) in [
        ("no-begin", "missing native/shared path"),
        ("no-returning", "missing native/shared path"),
        ("excess-stack", "lacks >=5% headroom"),
    ] {
        let output = Command::new("python3")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(["-I", "-c", ROOT_CHECKER])
            .arg(temporary.path().join(name))
            .output()
            .unwrap();
        assert!(!output.status.success(), "actual ELF mutant {name} passed");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(diagnostic),
            "wrong mutant refusal: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn private_roots_reach_no_void_global_callee() {
    if option_env!("P11SCOPE_JOURNAL_PROOF_ENABLED") != Some("1") {
        assert_eq!(option_env!("P11SCOPE_JOURNAL_PROOF_ENABLED"), Some("0"));
        return;
    }
    let object = Path::new(env!("OUT_DIR")).join("journal-proof-v1/p11scope-ebpf-journal-proof-v1");
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "-c", VOID_CALLEE_CHECKER])
        .arg(&object)
        .output()
        .expect("inspect actual private callees");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

const ROOT_CHECKER: &str = r#"
from pathlib import Path
import struct
import sys
sys.path.insert(0, str(Path('scripts').resolve()))
from _loader import load_path
reader = load_path(Path('scripts/check-bpf-map-defs.py'), 'journal_root_elf')
elf = reader.Elf(Path(sys.argv[1]).read_bytes())
bodies = {(s[3], s[4]): s for s in elf.symbols if s[1] & 15 == 2 and s[3] and s[5]}
raws = {elf.indices[name]: raw for name, (_, raw) in elf.sections.items()}
relocations = {}
for row, raw in elf.sections.values():
    if row[1] == 9:
        for at in range(0, len(raw), 16):
            address, info = struct.unpack_from('<QQ', raw, at)
            relocations[row[7], address] = (info & 0xffffffff, elf.symbols[info >> 32])

# Associate Rust's mangled ELF symbols with their actual BTF FUNC names at
# the same section/offset. Substring presence is not call reachability.
btf = reader.Btf(elf.sections['.BTF'][1])
ext = elf.sections['.BTF.ext'][1]
magic, version, flags, hlen, off, length = struct.unpack_from('<HBBIII', ext)
assert (magic, version, flags, hlen) == (0xeb9f, 1, 0, 32)
raw = ext[hlen + off:hlen + off + length]
stride, = struct.unpack_from('<I', raw)
assert stride == 8
names, pos = {}, 4
while pos < len(raw):
    section_name, count = struct.unpack_from('<II', raw, pos)
    section = elf.indices[reader.string_at(btf.strings, section_name)]
    pos += 8
    for _ in range(count):
        offset, ident = struct.unpack_from('<II', raw, pos)
        pos += stride
        assert btf.types[ident][0] == 12 and (section, offset) in bodies
        names[section, offset] = btf.types[ident][1]

def only(name):
    matches = [key for key, symbol in bodies.items() if symbol[0] == name]
    assert len(matches) == 1, f'expected one actual {name}, saw {len(matches)}'
    return matches[0]

def instructions(key):
    symbol = bodies[key]
    raw = raws[key[0]][key[1]:key[1] + symbol[5]]
    return [struct.unpack_from('<BBhi', raw, at) for at in range(0, len(raw), 8)]

def calls(key):
    found = []
    for index, (op, reg, _, immediate) in enumerate(instructions(key)):
        if op != 0x85 or reg >> 4 != 1:
            continue
        relocation = relocations.get((key[0], key[1] + index * 8))
        if relocation:
            kind, target = relocation
            assert kind == 10, f'unknown call relocation in {bodies[key][0]}'
            child = (target[3], target[4] + (immediate + 1) * 8)
        else:
            child = (key[0], key[1] + index * 8 + (immediate + 1) * 8)
        assert child in bodies, f'unresolved call in {bodies[key][0]}'
        found.append((index, child))
    return found

def children(key):
    return [target for _, target in calls(key)]

def closure(root):
    seen, pending = set(), [root]
    while pending:
        key = pending.pop()
        if key not in seen:
            seen.add(key)
            pending.extend(children(key))
    return seen

def reachable(root):
    return {names.get(key, bodies[key][0]) for key in closure(root)}

def frame(key):
    depth = 0
    insns = instructions(key)
    for index, (op, reg, offset, immediate) in enumerate(insns):
        if ((op & 7 in (2, 3) and reg & 15 == 10)
                or (op & 7 == 1 and reg >> 4 == 10)) and offset < 0:
            depth = max(depth, -offset)
        if (index and op == 0x07 and immediate < 0
                and insns[index - 1][:2] == (0xbf, 0xa0 | (reg & 15))):
            depth = max(depth, -immediate)
    return ((max(depth, 1) + 31) // 32) * 32

def chain(key, path=()):
    assert key not in path, 'recursive journal BPF graph'
    paths = [chain(child, path + (key,)) for child in children(key)]
    cost, subpath = max(paths, default=(0, ()))
    return frame(key) + cost, (names.get(key, bodies[key][0]),) + subpath

for name, required in {
    'p11_entry_journal': {'p11_journal_begin', 'p11_owner_start_begin', 'p11_instance_entry'},
    'p11_return_journal': {'p11_journal_returning', 'p11_owner_start_remove_reason',
                           'p11_instance_return', 'object_fill_return',
                           'object_emit_find', 'object_emit_get_attributes'},
}.items():
    root = only(name)
    expected_section = 'uprobe' if name == 'p11_entry_journal' else 'uretprobe'
    assert root[0] == elf.indices[expected_section], f'{name} is not an actual probe root'
    assert required <= reachable(root), f'{name} missing native/shared path: {required - reachable(root)}'
    cost, path = chain(root)
    assert cost <= 480, f'{name} stack chain {cost} lacks >=5% headroom: {" > ".join(path)}'
    assert len(path) <= 8, f'{name} exceeds eight call frames: {path}'
    print(f'{name}: stack-chain={cost}/512, path={" > ".join(path)}')
for name in ('p11_entry', 'p11_return'):
    assert not any(symbol[0] == name for symbol in bodies.values()), \
        f'private ELF retained the inapplicable duplicate ordinary root {name}'
programs = [key for key in bodies if key[0] != elf.indices['.text']]
assert len(programs) >= 20, 'missing ordinary discovery/lifecycle/identity program inventory'
for root in programs:
    cost, path = chain(root)
    assert cost <= 480, f'exported {bodies[root][0]} chain {cost} lacks >=5% headroom: {" > ".join(path)}'
    assert len(path) <= 8, f'exported {bodies[root][0]} exceeds eight call frames'
print(f'all {len(programs)} exported private-ELF program chains <=480/512 and <=8 frames')
functions = [node for node in btf.types[1:] if node[0] == 12]
assert functions
for function in functions:
    proto = btf.types[function[2]]
    assert proto[0] == 13 and proto[3] <= 5, f'{function[1]} exceeds five-register BPF ABI'
assert not any(symbol[0] == 'journal_header_write' for symbol in bodies.values()), \
    'six-scalar source core must be fully inlined, never an emitted function'
print(f'all {len(functions)} emitted function ABIs <=5 arguments')
"#;

const ROOT_MUTATIONS: &str = r#"
data = Path(sys.argv[1]).read_bytes()
output = Path(sys.argv[2])
section_offsets = {elf.indices[name]: row[4] for name, (row, _) in elf.sections.items()}
for label, root_name, removed_name, replacement_name in (
    ('no-begin', 'p11_entry_journal', 'p11_journal_begin', 'p11_journal_returning'),
    ('no-returning', 'p11_return_journal', 'p11_journal_returning', 'p11_journal_begin'),
):
    removed, replacement = only(removed_name), only(replacement_name)
    found = [(caller, index) for caller in closure(only(root_name))
             for index, target in calls(caller) if target == removed]
    assert found, 'actual native call mutation has no site'
    changed = bytearray(data)
    for caller, index in found:
        address = caller[1] + index * 8
        relocation = relocations.get((caller[0], address))
        if relocation:
            assert relocation[0] == 10 and relocation[1][3] == replacement[0]
            immediate = (replacement[1] - relocation[1][4]) // 8 - 1
        else:
            assert caller[0] == replacement[0]
            immediate = (replacement[1] - address) // 8 - 1
        struct.pack_into('<i', changed, section_offsets[caller[0]] + address + 4, immediate)
    (output / label).write_bytes(changed)
root = only('p11_entry_journal')
sites = [index for index, (op, reg, offset, _) in enumerate(instructions(root))
         if offset < 0 and ((op & 7 in (2, 3) and reg & 15 == 10)
                            or (op & 7 == 1 and reg >> 4 == 10))]
assert sites, 'actual entry stack mutation has no site'
changed = bytearray(data)
struct.pack_into('<h', changed, section_offsets[root[0]] + root[1] + sites[0] * 8 + 2, -488)
(output / 'excess-stack').write_bytes(changed)
"#;

const VOID_CALLEE_CHECKER: &str = r#"
from pathlib import Path
import struct
import sys
sys.path.insert(0, str(Path('scripts').resolve()))
from _loader import load_path
reader = load_path(Path('scripts/check-bpf-map-defs.py'), 'journal_void_guard')
elf = reader.Elf(Path(sys.argv[1]).read_bytes())
bodies = {(s[3], s[4]): s for s in elf.symbols if s[1] & 15 == 2 and s[3] and s[5]}
raws = {elf.indices[name]: raw for name, (_, raw) in elf.sections.items()}
relocations = {}
for row, raw in elf.sections.values():
    if row[1] == 9:
        for at in range(0, len(raw), 16):
            address, info = struct.unpack_from('<QQ', raw, at)
            relocations[row[7], address] = (info & 0xffffffff, elf.symbols[info >> 32])

# Associate Rust's mangled ELF symbols with their actual BTF FUNC names at
# the same section/offset. Substring presence is not call reachability.
btf = reader.Btf(elf.sections['.BTF'][1])
ext = elf.sections['.BTF.ext'][1]
magic, version, flags, hlen, off, length = struct.unpack_from('<HBBIII', ext)
assert (magic, version, flags, hlen) == (0xeb9f, 1, 0, 32)
raw = ext[hlen + off:hlen + off + length]
stride, = struct.unpack_from('<I', raw)
assert stride == 8
names, pos = {}, 4
while pos < len(raw):
    section_name, count = struct.unpack_from('<II', raw, pos)
    section = elf.indices[reader.string_at(btf.strings, section_name)]
    pos += 8
    for _ in range(count):
        offset, ident = struct.unpack_from('<II', raw, pos)
        pos += stride
        assert btf.types[ident][0] == 12 and (section, offset) in bodies
        names[section, offset] = btf.types[ident][1]

def instructions(key):
    symbol = bodies[key]
    raw = raws[key[0]][key[1]:key[1] + symbol[5]]
    return [struct.unpack_from('<BBhi', raw, at) for at in range(0, len(raw), 8)]

def children(key):
    found = []
    for index, (op, reg, _, immediate) in enumerate(instructions(key)):
        if op != 0x85 or reg >> 4 != 1:
            continue
        relocation = relocations.get((key[0], key[1] + index * 8))
        if relocation:
            kind, target = relocation
            assert kind == 10, f'unknown call relocation in {bodies[key][0]}'
            child = (target[3], target[4] + (immediate + 1) * 8)
        else:
            child = (key[0], key[1] + index * 8 + (immediate + 1) * 8)
        assert child in bodies, f'unresolved call in {bodies[key][0]}'
        found.append(child)
    return found

def closure(root):
    seen, pending = set(), [root]
    while pending:
        key = pending.pop()
        if key not in seen:
            seen.add(key)
            pending.extend(children(key))
    return seen

def reachable(root):
    return {names.get(key, bodies[key][0]) for key in closure(root)}

# The kernel verifier requires every GLOBAL BPF callee to return a scalar;
# a void global reachable from a program is refused at BPF_PROG_LOAD. The
# three compiler builtins are empirically exempt (loaded programs reach
# memset); every other void global must be unreachable from every program.
void_globals = set()
for node in btf.types[1:]:
    if node[0] == 12 and node[3] == 1:
        proto = btf.types[node[2]]
        assert proto[0] == 13, 'global BTF function without a prototype'
        if proto[2] == 0:
            void_globals.add(node[1])
builtins = {'memcpy', 'memmove', 'memset'}
assert builtins <= void_globals, \
    f'builtin carve-out is not all void globals: {builtins - void_globals}'
for name in ('p11_journal_begin', 'p11_journal_returning',
             'p11_journal_settle_prepare', 'p11_journal_settle_finish'):
    functions = [node for node in btf.types[1:] if node[0] == 12 and node[1] == name]
    assert len(functions) == 1 and functions[0][3] == 1, name + ' must stay a global BTF function'
    proto = btf.types[functions[0][2]]
    assert proto[0] == 13 and proto[2] != 0, name + ' must return a scalar for the verifier'
programs = [key for key in bodies if key[0] != elf.indices['.text']]
assert len(programs) >= 20, 'missing ordinary discovery/lifecycle/identity program inventory'
for key in programs:
    bad = sorted((reachable(key) & void_globals) - builtins)
    assert not bad, f'{bodies[key][0]} reaches void GLOBAL FUNCs the verifier refuses: {bad}'
print(f'all {len(programs)} programs reach no void GLOBAL callee outside the 3 builtins')
"#;
