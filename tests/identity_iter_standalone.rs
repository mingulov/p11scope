//! SPDX-License-Identifier: GPL-3.0-or-later
//! W3-1 (Stage 3 Wave D, D2a+b) standalone harness for the task_vma identity
//! object and its loader/parser.
//!
//! TEMPORARY wiring (constraint: only `build.rs` may change among existing
//! files, so `src/attach.rs` cannot declare the new module yet): the module
//! under test is included by path. Its inline `#[cfg(test)]` unit tests
//! (parser tables, byte-flip, reader, uapi offsets, I6 grep) therefore run
//! inside this integration-test binary. W3-2 deletes the `#[path]` include
//! below and switches these tests to `p11scope::attach::identity_iter` once
//! the module is wired into `attach.rs`; the object-level tests in this file
//! stay valid unchanged.

#[path = "../src/attach/identity_iter.rs"]
mod identity_iter;

use identity_iter as ii;

/// The clang-built identity object out of this package's `OUT_DIR`. This is
/// the same artifact [`ii::IDENTITY_OBJECT`] embeds; reading it separately
/// here keeps the object-contract tests independent of the loader path.
static OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/p11scope-ebpf-identity"));

/// D2a gate: exactly 2 `iter/task_vma` programs and 4 maps with the expected
/// types, sizes and flags (`WRONLY` on the two anchor maps, `MMAPABLE` on the
/// scope bitmap). Kills the D2a mutations: a dropped `WRONLY` flag or a third
/// program fails here.
#[test]
fn identity_object_has_two_iter_programs_and_four_maps() {
    let object = aya_obj::Object::parse(OBJECT).expect("parse identity object");
    assert_eq!(object.programs.len(), 2, "exactly two programs");
    for name in ["p11_anchor_vma", "p11_identity_vma"] {
        let program = object.programs.get(name).unwrap_or_else(|| {
            panic!(
                "program {name} missing; have {:?}",
                object.programs.keys().collect::<Vec<_>>()
            )
        });
        assert!(
            matches!(
                program.section,
                aya_obj::ProgramSection::Iter { sleepable: false }
            ),
            "{name} must live in iter/task_vma, got {:?}",
            program.section
        );
    }
    assert_eq!(object.maps.len(), 4, "exactly four maps");
    // (name, type, key_size, value_size, max_entries, flags)
    for (name, map_type, key_size, value_size, max_entries, flags) in [
        ("anchors", 1u32, 8u32, 16u32, 1024u32, 16u32), // HASH, WRONLY
        ("anchor_slots", 2u32, 4u32, 8u32, 1024u32, 16u32), // ARRAY, WRONLY
        ("config", 2u32, 4u32, 32u32, 1u32, 0u32),      // ARRAY
        ("scope_bitmap", 2u32, 4u32, 8u32, 65_536u32, 1024u32), // ARRAY, MMAPABLE
    ] {
        let map = object.maps.get(name).unwrap_or_else(|| {
            panic!(
                "map {name} missing; have {:?}",
                object.maps.keys().collect::<Vec<_>>()
            )
        });
        assert_eq!(map.map_type(), map_type, "{name} type");
        assert_eq!(map.key_size(), key_size, "{name} key size");
        assert_eq!(map.value_size(), value_size, "{name} value size");
        assert_eq!(map.max_entries(), max_entries, "{name} max entries");
        assert_eq!(map.map_flags(), flags, "{name} flags");
    }
    assert_eq!(object.license.to_str().expect("license utf8"), "GPL");
}

/// Aya's map relocation runs over the identity object with sentinel fds, as it
/// does for the embedded Detailed object: parsing plus relocation without any
/// kernel syscall.
#[test]
fn identity_object_relocates_without_syscalls() {
    let mut object = aya_obj::Object::parse(OBJECT).expect("parse identity object");
    let maps = object.maps.clone();
    let mut names: Vec<_> = maps.keys().collect();
    names.sort();
    let descriptors: std::collections::BTreeMap<_, _> = names
        .into_iter()
        .enumerate()
        .map(|(index, name)| (name.as_str(), 1000 + index as i32))
        .collect();
    let code_sections = object
        .functions
        .keys()
        .map(|(section, _)| *section)
        .collect();
    object
        .relocate_maps(
            maps.iter()
                .map(|(name, map)| (name.as_str(), descriptors[name.as_str()], map)),
            &code_sections,
        )
        .expect("relocate every identity map reference");
    let referenced: std::collections::BTreeSet<_> = object
        .functions
        .values()
        .flat_map(|function| &function.instructions)
        .filter(|instruction| instruction.code == 0x18 && instruction.src_reg() == 1)
        .map(|instruction| instruction.imm)
        .collect();
    for name in ["anchors", "anchor_slots", "config", "scope_bitmap"] {
        assert!(
            referenced.contains(&descriptors[name]),
            "map {name} must retain its own descriptor after relocation"
        );
    }
}

/// CO-RE relocations in the clang object resolve against the host vmlinux BTF
/// and rewrite at least one instruction (so the check is live, not a no-op).
/// This proves the anonymous-union descent for `vm_start`/`vm_end`/`vm_flags`
/// and the `FIELD_EXISTS` guard evaluate on a real 7.x BTF. Unprivileged: pure
/// userspace BTF matching, no syscalls. Loudly skipped only where host BTF is
/// absent (the multi-kernel matrix itself is W3-2's vng job).
#[test]
fn identity_core_relocations_resolve_against_host_btf() {
    let btf = match aya::Btf::from_sys_fs() {
        Ok(btf) => btf,
        Err(error) => {
            eprintln!("W3-1 CO-RE test NEEDS_CONTEXT: host BTF unreadable ({error:#}); skipping");
            return;
        }
    };
    let pristine = aya_obj::Object::parse(OBJECT).expect("parse identity object");
    assert!(
        pristine.has_btf_relocations(),
        "object must carry CO-RE relocations"
    );
    let mut relocated = pristine.clone();
    relocated
        .relocate_btf(&btf)
        .expect("CO-RE must resolve against host BTF");
    let before: Vec<_> = pristine
        .functions
        .values()
        .flat_map(|function| {
            function
                .instructions
                .iter()
                .map(|ins| (ins.code, ins.imm, ins.off))
        })
        .collect();
    let after: Vec<_> = relocated
        .functions
        .values()
        .flat_map(|function| {
            function
                .instructions
                .iter()
                .map(|ins| (ins.code, ins.imm, ins.off))
        })
        .collect();
    assert_eq!(
        before.len(),
        after.len(),
        "relocation must not add/remove instructions"
    );
    assert_ne!(
        before, after,
        "relocation must rewrite at least one instruction"
    );
    // The pristine object keeps its local offsets; relocation is what adapts it.
    drop(pristine);
}

/// D2a byte-identity gate: the three default objects are unchanged by the new
/// flavor. Digests pinned at BASE `cd6ad51` in this toolchain; small-ring and
/// diagnostic features legitimately change the objects, so the pin applies
/// only to the default build.
#[test]
fn default_objects_byte_identical_to_base() {
    if cfg!(feature = "unsafe-unvalidated-metadata")
        || cfg!(feature = "wide-detailed-2112")
        || cfg!(p11scope_small_discovery_ring)
        || std::env::var("P11SCOPE_SMALL_RING").is_ok_and(|v| v == "1" || v == "true")
        || std::env::var("P11SCOPE_SMALL_STATE_MAPS").is_ok_and(|v| v == "1" || v == "true")
        || std::env::var("P11SCOPE_SMALL_DISCOVERY_RING").is_ok_and(|v| v == "1" || v == "true")
    {
        eprintln!("byte-identity pin applies to default builds only; skipping");
        return;
    }
    use sha2::Digest as _;
    for (name, bytes, pinned) in [
        (
            "p11scope-ebpf",
            p11scope::EBPF_OBJECT,
            "b62b40541cad83d211cbd80031c4e2bbea60edd20f5a040af35f1f890efb9f08",
        ),
        (
            "p11scope-ebpf-inventory",
            p11scope::EBPF_INVENTORY_OBJECT,
            "a8b93b30813b666ef63a868f0615cfa2b7da8822d0bfa297f35b6f680759bc77",
        ),
        (
            "p11scope-ebpf-inventory-callers",
            p11scope::EBPF_INVENTORY_CALLERS_OBJECT,
            "bc77210dbd74ecf2ec8dbac9bb73553c37f0939512e7d1a71c65df35300be480",
        ),
    ] {
        let digest = sha2::Sha256::digest(bytes);
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, pinned, "{name} must stay byte-identical to BASE");
    }
}

/// Extract the kernel errno from a loader failure's syscall-carrying variants.
/// Object-side variants (parse, relocation) yield `None`: they never touched
/// the kernel, so they must fail the gate rather than pass as unprivileged.
fn map_errno(error: &aya::maps::MapError) -> Option<i32> {
    match error {
        aya::maps::MapError::CreateError { io_error, .. } => io_error.raw_os_error(),
        aya::maps::MapError::IoError(io_error) => io_error.raw_os_error(),
        aya::maps::MapError::SyscallError(sys) => sys.io_error.raw_os_error(),
        _ => None,
    }
}

fn prog_errno(error: &aya::programs::ProgramError) -> Option<i32> {
    match error {
        aya::programs::ProgramError::LoadError { io_error, .. } => io_error.raw_os_error(),
        aya::programs::ProgramError::SyscallError(sys) => sys.io_error.raw_os_error(),
        aya::programs::ProgramError::MapError(error) => map_errno(error),
        _ => None,
    }
}

fn syscall_errno(error: &aya::EbpfError) -> Option<i32> {
    match error {
        aya::EbpfError::MapError(error) => map_errno(error),
        aya::EbpfError::ProgramError(error) => prog_errno(error),
        aya::EbpfError::BtfError(aya::BtfError::LoadError { io_error, .. }) => {
            io_error.raw_os_error()
        }
        _ => None,
    }
}

/// D2a loader gate: aya takes the clang object through parse, relocation,
/// and map creation to program verification. Privileged runners verify both
/// programs outright; unprivileged runners must fail only with a permission
/// errno from a syscall, never with an object-side (parse/relocation) error.
#[test]
fn identity_loader_reaches_syscall_or_loads() {
    let btf = aya::Btf::from_sys_fs().ok();
    match ii::load_identity_object(btf.as_ref()) {
        Ok(_) => eprintln!("W3-1 loader gate: identity object LOADED (privileged run)"),
        Err(ii::LoadError::MissingProgram(name)) => {
            panic!("program {name} missing from identity object");
        }
        Err(ii::LoadError::Program(error))
            if matches!(prog_errno(&error), Some(libc::EPERM) | Some(libc::EACCES)) =>
        {
            eprintln!(
                "W3-1 loader gate NEEDS_CONTEXT for full load: unprivileged program load; parse+relocation proven above"
            );
        }
        Err(ii::LoadError::Program(error)) => {
            panic!("program verification failure: {error:#?}");
        }
        Err(ii::LoadError::Ebpf(aya::EbpfError::ParseError(_)))
        | Err(ii::LoadError::Ebpf(aya::EbpfError::BtfRelocationError(_)))
        | Err(ii::LoadError::Ebpf(aya::EbpfError::RelocationError(_)))
        | Err(ii::LoadError::Ebpf(aya::EbpfError::NoBTF))
        | Err(ii::LoadError::Ebpf(aya::EbpfError::UnexpectedPinningType { .. }))
        | Err(ii::LoadError::Ebpf(aya::EbpfError::FileError { .. })) => {
            panic!("object-side loader failure");
        }
        Err(ii::LoadError::Ebpf(aya::EbpfError::BtfError(not_load)))
            if !matches!(not_load, aya::BtfError::LoadError { .. }) =>
        {
            panic!("BTF-side loader failure: {not_load}");
        }
        Err(ii::LoadError::Ebpf(other))
            if matches!(
                syscall_errno(&other),
                Some(libc::EPERM) | Some(libc::EACCES)
            ) =>
        {
            eprintln!(
                "W3-1 loader gate NEEDS_CONTEXT for full load: unprivileged ({other:#}); parse+relocation proven above"
            );
        }
        Err(other) => panic!("unexpected loader failure (not a permission errno): {other:#?}"),
    }
}

/// F6 uapi constants cross-checked against aya's generated bindings, an
/// independent copy of `linux/bpf.h`.
#[test]
fn identity_uapi_constants_match_aya_bindings() {
    use aya_obj::generated::bpf_cmd;
    assert_eq!(ii::BPF_LINK_CREATE, bpf_cmd::BPF_LINK_CREATE as u32);
    assert_eq!(ii::BPF_ITER_CREATE, bpf_cmd::BPF_ITER_CREATE as u32);
    assert_eq!(ii::BPF_MAP_UPDATE_ELEM, bpf_cmd::BPF_MAP_UPDATE_ELEM as u32);
    assert_eq!(ii::BPF_MAP_DELETE_ELEM, bpf_cmd::BPF_MAP_DELETE_ELEM as u32);
}
