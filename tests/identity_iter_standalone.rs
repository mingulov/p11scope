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

/// D2a gate: exactly 2 `iter/task_vma` programs and 5 maps with the expected
/// types, sizes and flags (`WRONLY` on the three kernel-only anchor maps,
/// `MMAPABLE` on the scope bitmap). Kills the D2a mutations: a dropped
/// `WRONLY` flag or a third program fails here.
#[test]
fn identity_object_has_two_iter_programs_and_five_maps() {
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
    assert_eq!(object.maps.len(), 5, "exactly five maps");
    // (name, type, key_size, value_size, max_entries, flags)
    for (name, map_type, key_size, value_size, max_entries, flags) in [
        ("anchors", 1u32, 8u32, 16u32, 1024u32, 16u32), // HASH, WRONLY
        ("anchor_slots", 2u32, 4u32, 8u32, 1024u32, 16u32), // ARRAY, WRONLY
        ("anchor_observed", 2u32, 4u32, 8u32, 1024u32, 16u32), // ARRAY, WRONLY
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
    for name in [
        "anchors",
        "anchor_slots",
        "anchor_observed",
        "config",
        "scope_bitmap",
    ] {
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
    // The identity object has no feature variants: its pin (below) applies
    // to every build, while these three skip under small-ring/diagnostic
    // features.
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

/// Digest pin for the identity object itself (F-build): any source or
/// toolchain drift changes these bytes, and the pin fails loudly. Pinned
/// at the arena-containment commit in this toolchain (round 1:
/// `000caca5…`; round 2 adds the fifth map plus the end-containment
/// check); the build-info test below binds the pin to the compiler
/// digest and CPU baseline it was recorded with.
#[test]
fn identity_object_digest_pinned() {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(OBJECT);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex, "f48ecf91965f7432444b39da088f0ec281c5f7db0d17ffeee951bc50ab9b30d4",
        "p11scope-ebpf-identity must stay byte-identical to the arena-containment pin"
    );
}

/// Qualification binding (F-build): the build records the resolved
/// compiler digest, the explicit CPU baseline, and the object digest in
/// `p11scope-identity-build-info.txt`; this test pins that record's shape
/// and its agreement with the object under test. Ordinary builds still
/// trust their tool environment (PATH `clang-18`, system headers) — the
/// record makes qualification reproducible, not the build hermetic.
#[test]
fn identity_build_info_binds_compiler_and_baseline() {
    let info = std::fs::read_to_string(concat!(
        env!("OUT_DIR"),
        "/p11scope-identity-build-info.txt"
    ))
    .expect("build must record identity build info");
    let field = |name: &str| -> String {
        info.lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("build info lacks {name}"))
            .to_string()
    };
    let compiler = field("compiler_sha256");
    assert_eq!(compiler.len(), 64, "compiler digest must be sha256 hex");
    assert!(
        compiler.chars().all(|c| c.is_ascii_hexdigit()),
        "compiler digest must be hex"
    );
    assert!(
        ["bpfel", "bpfeb"].contains(&field("target").as_str()),
        "target must be a BPF endian flavor"
    );
    assert_eq!(field("mcpu"), "v1", "CPU baseline must be explicit v1");
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(OBJECT);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        field("object_sha256"),
        hex,
        "recorded object digest must match the object under test"
    );
    assert!(
        field("compiler_path").contains("clang-18"),
        "compiler path must name the resolved clang-18"
    );
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

/// D2a STRICT loader gate (mandatory, privileged): aya takes the clang
/// object through parse, CO-RE relocation against READABLE host BTF, map
/// creation, and verification of BOTH programs. Every program-load error
/// fails this gate — no permission-errno acceptance here, because
/// verifier rejections arrive as `EACCES` and must never pass as
/// "unprivileged". Run as root with `--ignored`. Records the kernel
/// release, the BTF identity (path, size, sha256), and both verified
/// program fds; on failure the kernel verifier log is printed.
#[test]
#[ignore = "privileged: verifies both identity programs through the kernel verifier"]
fn identity_loader_strict_gate_requires_btf_and_both_programs() {
    let btf = aya::Btf::from_sys_fs().expect("strict gate requires readable host BTF");
    let loaded = match ii::load_identity_object_strict(&btf) {
        Ok(loaded) => loaded,
        Err(error) => {
            if let Some(log) = ii::verifier_log_of(&error) {
                eprintln!("W3-1 strict gate verifier log:\n{log}");
            }
            panic!("strict gate: identity object failed to verify: {error:#}");
        }
    };
    // The strict constructor required both program fds; prove they are
    // open and distinct here, and that the receipt's object still carries
    // both verified programs.
    assert!(
        loaded.ebpf.program(ii::ANCHOR_PROGRAM).is_some(),
        "receipt object carries the anchor program"
    );
    assert!(
        loaded.ebpf.program(ii::TARGET_PROGRAM).is_some(),
        "receipt object carries the target program"
    );
    use std::os::fd::AsRawFd as _;
    let anchor = loaded.anchor_fd.as_raw_fd();
    let target = loaded.target_fd.as_raw_fd();
    assert_ne!(anchor, target, "both programs must hold distinct fds");
    for (name, fd) in [("anchor", anchor), ("target", target)] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "{name} program fd {fd} must be open");
    }
    // BTF identity: the exact bytes relocation consumed.
    let btf_bytes = std::fs::read("/sys/kernel/btf/vmlinux").expect("read host BTF for identity");
    let mut release = [0 as libc::c_char; 65];
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::uname(&mut uts) }, 0, "uname");
    for (slot, byte) in release.iter_mut().zip(uts.release.iter()) {
        *slot = *byte;
    }
    let release = unsafe { std::ffi::CStr::from_ptr(release.as_ptr()) }.to_string_lossy();
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(&btf_bytes);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    eprintln!(
        "W3-1 strict gate LOADED: kernel {release}, BTF /sys/kernel/btf/vmlinux ({} bytes, sha256 {hex}), anchor fd {anchor}, target fd {target}",
        btf_bytes.len()
    );
}

/// Explicitly-unprivileged smoke: the clang object parses, relocates, and
/// reaches map-creation syscalls. Accepts ONLY a permission errno from a
/// syscall (an unprivileged runner) or a full unverified load (a
/// privileged context); object-side failures panic. Makes NO verification
/// claim — programs are never loaded on this path (pinned by
/// `none_btf_load_never_verifies_programs` below).
#[test]
fn identity_loader_unprivileged_smoke() {
    match ii::load_identity_object_unverified(None) {
        Ok(_) => eprintln!(
            "W3-1 loader smoke: object parsed, maps created (privileged context); programs NOT verified here"
        ),
        Err(ii::LoadError::Ebpf(other))
            if matches!(
                syscall_errno(&other),
                Some(libc::EPERM) | Some(libc::EACCES)
            ) =>
        {
            eprintln!(
                "W3-1 loader smoke NEEDS_CONTEXT for verification: permission errno ({other:#}); parse+relocation proven above"
            );
        }
        Err(other) => panic!("smoke: object-side or unexpected loader failure: {other:#?}"),
    }
}

/// The unverified path must never yield loaded programs: with `None` BTF
/// a privileged load creates maps but loads nothing, and an unprivileged
/// load fails at map creation. Either way no program verifies here.
#[test]
fn none_btf_load_never_verifies_programs() {
    if let Ok(ebpf) = ii::load_identity_object_unverified(None) {
        for name in [ii::ANCHOR_PROGRAM, ii::TARGET_PROGRAM] {
            let program = ebpf
                .program(name)
                .unwrap_or_else(|| panic!("{name} missing from loaded object"));
            assert!(
                program.fd().is_err(),
                "{name} must stay unloaded without BTF-backed verification"
            );
        }
    }
}

/// F6 uapi surface cross-checked against aya's generated bindings, an
/// independent copy of `linux/bpf.h`: every command number, the attach
/// type, map types, map flags, and the attr layouts bindgen exposes as
/// plain structs. (The `link_create` prefix with `iter_info`, the
/// `bpf_iter_link_info` task member, and the `bpf_map_info` prefix are
/// asserted against the host headers by the build-time C check instead:
/// bindgen nests those in anonymous unions awkward for `offset_of!`.)
#[test]
fn identity_uapi_constants_match_aya_bindings() {
    use aya_obj::generated::{
        BPF_F_MMAPABLE as GEN_MMAPABLE, BPF_F_WRONLY as GEN_WRONLY, bpf_attach_type, bpf_cmd,
        bpf_map_type,
    };
    assert_eq!(ii::BPF_LINK_CREATE, bpf_cmd::BPF_LINK_CREATE as u32);
    assert_eq!(ii::BPF_ITER_CREATE, bpf_cmd::BPF_ITER_CREATE as u32);
    assert_eq!(ii::BPF_MAP_CREATE, bpf_cmd::BPF_MAP_CREATE as u32);
    assert_eq!(ii::BPF_MAP_UPDATE_ELEM, bpf_cmd::BPF_MAP_UPDATE_ELEM as u32);
    assert_eq!(ii::BPF_MAP_DELETE_ELEM, bpf_cmd::BPF_MAP_DELETE_ELEM as u32);
    assert_eq!(
        ii::BPF_OBJ_GET_INFO_BY_FD,
        bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as u32
    );
    assert_eq!(ii::BPF_TRACE_ITER, bpf_attach_type::BPF_TRACE_ITER as u32);
    assert_eq!(
        ii::BPF_MAP_TYPE_HASH,
        bpf_map_type::BPF_MAP_TYPE_HASH as u32
    );
    assert_eq!(
        ii::BPF_MAP_TYPE_ARRAY,
        bpf_map_type::BPF_MAP_TYPE_ARRAY as u32
    );
    assert_eq!(ii::BPF_F_WRONLY, GEN_WRONLY);
    assert_eq!(ii::BPF_F_MMAPABLE, GEN_MMAPABLE);
    // Attr layouts bindgen exposes as plain structs.
    use aya_obj::generated::{
        bpf_attr__bindgen_ty_2 as gen_map_elem, bpf_attr__bindgen_ty_9 as gen_obj_info,
        bpf_attr__bindgen_ty_18 as gen_iter_create,
    };
    use std::mem::offset_of;
    assert_eq!(
        size_of::<ii::IterCreateAttr>(),
        size_of::<gen_iter_create>()
    );
    assert_eq!(
        offset_of!(ii::IterCreateAttr, link_fd),
        offset_of!(gen_iter_create, link_fd)
    );
    assert_eq!(
        offset_of!(ii::IterCreateAttr, flags),
        offset_of!(gen_iter_create, flags)
    );
    assert_eq!(size_of::<ii::ObjGetInfoAttr>(), size_of::<gen_obj_info>());
    assert_eq!(
        offset_of!(ii::ObjGetInfoAttr, bpf_fd),
        offset_of!(gen_obj_info, bpf_fd)
    );
    assert_eq!(
        offset_of!(ii::ObjGetInfoAttr, info_len),
        offset_of!(gen_obj_info, info_len)
    );
    assert_eq!(
        offset_of!(ii::ObjGetInfoAttr, info),
        offset_of!(gen_obj_info, info)
    );
    // The map-elem member carries `value`/`next_key` as a union at 16;
    // our attr fixes the update shape (`value`), same size and offsets.
    assert_eq!(size_of::<ii::MapElemAttr>(), size_of::<gen_map_elem>());
    assert_eq!(
        offset_of!(ii::MapElemAttr, map_fd),
        offset_of!(gen_map_elem, map_fd)
    );
    assert_eq!(
        offset_of!(ii::MapElemAttr, key),
        offset_of!(gen_map_elem, key)
    );
    assert_eq!(
        offset_of!(ii::MapElemAttr, flags),
        offset_of!(gen_map_elem, flags)
    );
}
