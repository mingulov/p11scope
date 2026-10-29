//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private native linkage only: no kernel load or journal-root acceptance.

use std::{
    collections::BTreeSet, ffi::OsStr, fs, os::unix::fs::PermissionsExt, path::Path,
    process::Command,
};

const OUTPUT: &str = "journal-proof-v1/p11scope-ebpf-journal-proof-v1";
const PRODUCERS: [&str; 6] = [
    "p11_journal_begin",
    "p11_journal_returning",
    "p11_journal_settle_prepare",
    "p11_journal_settle_finish",
    "p11_owner_start_remove_reason",
    "p11_instance_scope_gap",
];

fn selected() -> bool {
    match option_env!("P11SCOPE_JOURNAL_PROOF_ENABLED") {
        Some("0") => false,
        Some("1") => true,
        other => panic!("private journal build-selection interface unavailable: {other:?}"),
    }
}

#[test]
fn journal_proof_output_matches_this_build_selection() {
    let requested = option_env!("P11SCOPE_JOURNAL_PROOF") == Some("1");
    let path = Path::new(env!("OUT_DIR")).join(OUTPUT);
    if requested {
        assert!(
            path.is_file(),
            "requested private journal ELF is absent: build-selection interface gap: {}",
            path.display()
        );
    }
    assert_eq!(selected(), requested);
    assert_eq!(
        option_env!("P11SCOPE_JOURNAL_PROOF_OUTPUTS"),
        Some(if requested { "journal-proof-v1" } else { "" })
    );
    assert_eq!(env!("P11SCOPE_BIRTH_MARKER_ENABLED"), "0");
    if requested {
        assert!(
            fs::read(path).unwrap().as_slice() != p11scope::EBPF_OBJECT,
            "private journal ELF aliases ordinary Detailed bytes"
        );
    }
}

fn preflight(
    value: Option<&OsStr>,
    settings: &[(&str, &str)],
) -> (std::process::Output, bool, Vec<String>) {
    let root = tempfile::tempdir().unwrap();
    let out = root.path().join("out");
    let tools = root.path().join("tools");
    fs::create_dir(&out).unwrap();
    fs::create_dir(&tools).unwrap();
    fs::write(out.join("preserved"), b"keep").unwrap();
    let trace = root.path().join("compiler-reached");
    for name in ["rustc", "cargo", "clang-18"] {
        let tool = tools.join(name);
        fs::write(
            &tool,
            "#!/bin/sh\nprintf '%s\\n' reached > \"$P11_JOURNAL_TEST_TRACE\"\nexit 97\n",
        )
        .unwrap();
        fs::set_permissions(tool, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut command = Command::new(env!("P11SCOPE_JOURNAL_PROOF_BUILD_SCRIPT"));
    command
        .env_clear()
        .env("PATH", &tools)
        .env("RUSTC", tools.join("rustc"))
        .env("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR"))
        .env("CARGO_CFG_TARGET_ENDIAN", "little")
        .env("OUT_DIR", &out)
        .env("P11_JOURNAL_TEST_TRACE", &trace);
    if let Some(value) = value {
        command.env("P11SCOPE_JOURNAL_PROOF", value);
    }
    for (key, value) in settings {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    assert!(
        !output.status.success(),
        "the compiler tripwire always stops valid preflight"
    );
    assert_eq!(fs::read(out.join("preserved")).unwrap(), b"keep");
    let mut entries: Vec<_> = fs::read_dir(&out)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    entries.sort();
    (output, trace.exists(), entries)
}

#[test]
fn journal_proof_switch_refuses_before_tools_or_outputs() {
    use std::os::unix::ffi::OsStringExt;
    let mut values: Vec<_> = ["", "2", "true", "false", "01", "-1", "1 ", " 1", "\n1"]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect();
    values.push(std::ffi::OsString::from_vec(vec![0xff]));
    for value in values {
        let (output, reached, entries) = preflight(Some(&value), &[]);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("P11SCOPE_JOURNAL_PROOF must be unset, 0 or 1"),
            "{value:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!reached, "invalid request reached a compiler");
        assert_eq!(entries, ["preserved"]);
    }
    for setting in [
        ("CARGO_FEATURE_STUB_OBJECT_ATTRIBUTES", "1"),
        ("CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA", "1"),
        ("CARGO_FEATURE_WIDE_DETAILED_2112", "1"),
        ("P11SCOPE_SMALL_RING", "1"),
        ("P11SCOPE_SMALL_RING", "true"),
        ("P11SCOPE_SMALL_STATE_MAPS", "1"),
        ("P11SCOPE_SMALL_STATE_MAPS", "true"),
        ("P11SCOPE_SMALL_DISCOVERY_RING", "1"),
        ("P11SCOPE_SMALL_DISCOVERY_RING", "true"),
        ("P11SCOPE_IMAGE_BANK_PROOF", "1"),
        ("P11SCOPE_COUNTER_ARTIFACTS", "1"),
    ] {
        let (output, reached, entries) = preflight(Some(OsStr::new("1")), &[setting]);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("private journal proof"),
            "{setting:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!reached, "{setting:?} reached a compiler");
        assert_eq!(entries, ["preserved"]);
    }
}

#[test]
fn journal_proof_permits_existing_independent_counter_selection() {
    for value in [None, Some(OsStr::new("0")), Some(OsStr::new("1"))] {
        for counter in [None, Some("0"), Some("1")] {
            let settings: Vec<_> = counter
                .map(|value| ("P11SCOPE_COUNTER_OBJECTS", value))
                .into_iter()
                .collect();
            let (output, reached, entries) = preflight(value, &settings);
            assert!(
                reached,
                "valid journal/counter preflight refused: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains(&format!(
                "cargo:rustc-env=P11SCOPE_JOURNAL_PROOF_COUNTER_OBJECTS={}\n",
                u8::from(counter != Some("0"))
            )));
            assert_eq!(entries, ["preserved"]);
        }
    }
}

#[test]
fn journal_proof_private_elf_retains_real_producer_and_loss_dependencies() {
    if !selected() {
        assert_eq!(option_env!("P11SCOPE_JOURNAL_PROOF_OUTPUTS"), Some(""));
        return; // The opt-in configuration supplies the actual linkage positive.
    }
    let path = Path::new(env!("OUT_DIR")).join(OUTPUT);
    let bytes = fs::read(&path).unwrap();
    let object = aya_obj::Object::parse(&bytes).unwrap();
    let ordinary = aya_obj::Object::parse(p11scope::EBPF_OBJECT).unwrap();
    let mut expected_programs: BTreeSet<_> = ordinary.programs.keys().map(String::as_str).collect();
    assert!(expected_programs.remove("p11_entry"));
    assert!(expected_programs.remove("p11_return"));
    expected_programs.extend(["p11_entry_journal", "p11_return_journal"]);
    assert_eq!(
        object
            .programs
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected_programs
    );
    let mut expected_maps: BTreeSet<_> = ordinary.maps.keys().map(String::as_str).collect();
    expected_maps.extend([
        "JOURNAL_START",
        "JOURNAL_CTL",
        "JOURNAL_MARKER_CTL",
        "JOURNAL_CLASSES",
    ]);
    assert_eq!(
        object
            .maps
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected_maps,
        "private map inventory must be ordinary Detailed plus the four journal maps"
    );
    for (name, baseline) in &ordinary.maps {
        let map = &object.maps[name];
        let shape = |map: &aya_obj::Map| {
            (
                map.map_type(),
                map.key_size(),
                map.value_size(),
                map.max_entries(),
                map.map_flags(),
            )
        };
        assert_eq!(
            shape(map),
            shape(baseline),
            "existing private map shape: {name}"
        );
    }
    let functions: BTreeSet<_> = object
        .functions
        .values()
        .map(|function| function.name.as_str())
        .collect();
    for name in PRODUCERS {
        assert!(functions.contains(name), "missing real native {name}");
    }
    for forbidden in [
        "p11_instance_exec_birth",
        "p11_journal_marker_publish",
        "p11_journal_combined_entry",
        "p11_journal_combined_return",
        "p11_journal_combined_remove",
    ] {
        assert!(
            !functions.contains(forbidden),
            "unexpected private ELF body {forbidden}"
        );
    }
    let undefined = Command::new("llvm-nm")
        .arg("--undefined-only")
        .arg(&path)
        .output()
        .unwrap();
    assert!(undefined.status.success());
    assert!(
        undefined.stdout.is_empty(),
        "unresolved native dependencies: {}",
        String::from_utf8_lossy(&undefined.stdout)
    );
    for (name, shape) in [
        ("JOURNAL_START", (1, 16, 24, 16_384, 0)),
        ("JOURNAL_CTL", (2, 4, 24, 1, 0)),
        ("JOURNAL_MARKER_CTL", (2, 4, 16, 1, 0)),
        ("JOURNAL_CLASSES", (2, 4, 4, 105, 128)),
        ("THREAD_OWNER", (29, 4, 560, 0, 1)),
        ("START", (1, 16, 288, 16_384, 0)),
        ("OBJECT_START", (1, 16, 432, 16_384, 0)),
        ("INSTANCE_START", (9, 16, 24, 16_384, 0)),
        ("DESCRIPTORS", (2, 4, 18, 105, 128)),
        ("EVENTS", (27, 0, 0, 4 * 1024 * 1024, 0)),
        ("EVIDENCE", (6, 4, 8, 9, 0)),
    ] {
        let map = object
            .maps
            .get(name)
            .unwrap_or_else(|| panic!("missing dependency {name}"));
        assert_eq!(
            (
                map.map_type(),
                map.key_size(),
                map.value_size(),
                map.max_entries(),
                map.map_flags()
            ),
            shape,
            "{name}"
        );
    }
    let abi = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-I",
            "-c",
            r#"
from pathlib import Path
import sys
sys.path.insert(0, str(Path('scripts').resolve()))
from _loader import load_path
reader = load_path(Path('scripts/check-bpf-map-defs.py'), 'journal_link_btf')
elf = reader.Elf(Path(sys.argv[1]).read_bytes())
btf = reader.Btf(elf.sections['.BTF'][1])
expected = {
    'p11_journal_begin': (4, (('ptr', 16), ('ptr', 16))),
    'p11_journal_returning': (4, (('ptr', 16), ('ptr', 24))),
    'p11_journal_settle_prepare': (4, (('ptr', 16), ('int', 4), ('ptr', 72))),
    'p11_journal_settle_finish': (4, (('ptr', 72), ('int', 4))),
    'p11_owner_start_remove_reason': (8, (('ptr', 16), ('int', 4), ('int', 4))),
    'p11_instance_scope_gap': (4, ()),
}
for name, (result_size, arguments) in expected.items():
    functions = [node for node in btf.types[1:] if node[0] == 12 and node[1] == name]
    assert len(functions) == 1 and functions[0][3] == 1, name + ' global BTF function'
    proto = btf.types[functions[0][2]]
    assert proto[0] == 13 and proto[3] == len(arguments), name + ' argument count'
    assert result_size != 0, name + ' must declare a scalar BTF result for the verifier'
    result = btf.resolve(proto[2])
    assert result[0] == 1 and result[2] == result_size, name + ' scalar result'
    for ref, (kind, size) in zip(proto[5][1::2], arguments, strict=True):
        node = btf.resolve(ref)
        if kind == 'ptr':
            assert node[0] == 2, name + ' sized pointer argument'
            assert btf.resolve(node[2])[0] == 4 and btf.size(node[2]) == size, name + ' pointee'
        else:
            assert node[0] == 1 and node[2] == size, name + ' scalar argument'
print('six actual native producer/loss BTF signatures verified')
"#,
        ])
        .arg(&path)
        .output()
        .expect("check actual linked native pointer ABIs");
    assert!(
        abi.status.success(),
        "{}{}",
        String::from_utf8_lossy(&abi.stdout),
        String::from_utf8_lossy(&abi.stderr)
    );
    let Some(flags) = option_env!("P11SCOPE_BPF_RUSTFLAGS_JOURNAL_PROOF") else {
        panic!("selected private journal proof has no flags receipt");
    };
    assert!(!flags.contains("--cfg=p11scope_birth_marker"));
    assert!(!flags.contains("image-bank-proof"));
}

#[test]
fn journal_proof_never_enters_ordinary_objects_or_loader_sources() {
    let mut bodies: Vec<&[u8]> = vec![
        p11scope::EBPF_OBJECT,
        p11scope::EBPF_INVENTORY_OBJECT,
        p11scope::EBPF_INVENTORY_CALLERS_OBJECT,
    ];
    for bytes in [
        p11scope::EBPF_COUNTER_COUNTS_OBJECT,
        p11scope::EBPF_COUNTER_TIMESTAMPS_OBJECT,
        p11scope::EBPF_COUNTER_LATENCY_OBJECT,
    ] {
        if !bytes.is_empty() {
            bodies.push(bytes);
        }
    }
    for bytes in bodies {
        let object = aya_obj::Object::parse(bytes).unwrap();
        for name in ["p11_entry_journal", "p11_return_journal"] {
            assert!(
                !object.programs.contains_key(name),
                "ordinary object selected {name}"
            );
        }
        for name in [
            "JOURNAL_START",
            "JOURNAL_CTL",
            "JOURNAL_MARKER_CTL",
            "JOURNAL_CLASSES",
        ] {
            assert!(!object.maps.contains_key(name));
        }
        assert!(
            !object
                .functions
                .values()
                .any(|function| PRODUCERS.contains(&function.name.as_str()))
        );
    }
    let mut pending = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = fs::read_to_string(&path).unwrap();
                assert!(
                    !source.contains("p11scope-ebpf-journal-proof-v1"),
                    "{} embeds private ELF",
                    path.display()
                );
                assert!(
                    !source.contains("P11SCOPE_JOURNAL_PROOF"),
                    "{} selects private proof",
                    path.display()
                );
            }
        }
    }
}

const JOURNAL_OUTPUT: &str = "journal-v1/p11scope-ebpf-journal-v1";

fn journal_selected() -> bool {
    match option_env!("P11SCOPE_JOURNAL_ENABLED") {
        Some("0") => false,
        Some("1") => true,
        other => panic!("production journal build-selection interface unavailable: {other:?}"),
    }
}

/// Production-switch preflight: the same tripwire discipline as the proof
/// switch, generalized over the switch name. The proof `preflight` above
/// stays frozen; this helper serves only the production selection tests.
fn preflight_switch(
    switch: &str,
    value: Option<&OsStr>,
    settings: &[(&str, &str)],
) -> (std::process::Output, bool, Vec<String>) {
    let root = tempfile::tempdir().unwrap();
    let out = root.path().join("out");
    let tools = root.path().join("tools");
    fs::create_dir(&out).unwrap();
    fs::create_dir(&tools).unwrap();
    fs::write(out.join("preserved"), b"keep").unwrap();
    let trace = root.path().join("compiler-reached");
    for name in ["rustc", "cargo", "clang-18"] {
        let tool = tools.join(name);
        fs::write(
            &tool,
            "#!/bin/sh\nprintf '%s\\n' reached > \"$P11_JOURNAL_TEST_TRACE\"\nexit 97\n",
        )
        .unwrap();
        fs::set_permissions(tool, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut command = Command::new(env!("P11SCOPE_JOURNAL_PROOF_BUILD_SCRIPT"));
    command
        .env_clear()
        .env("PATH", &tools)
        .env("RUSTC", tools.join("rustc"))
        .env("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR"))
        .env("CARGO_CFG_TARGET_ENDIAN", "little")
        .env("OUT_DIR", &out)
        .env("P11_JOURNAL_TEST_TRACE", &trace);
    if let Some(value) = value {
        command.env(switch, value);
    }
    for (key, value) in settings {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    assert!(
        !output.status.success(),
        "the compiler tripwire always stops valid preflight"
    );
    assert_eq!(fs::read(out.join("preserved")).unwrap(), b"keep");
    let mut entries: Vec<_> = fs::read_dir(&out)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    entries.sort();
    (output, trace.exists(), entries)
}

#[test]
fn journal_switch_refuses_before_tools_or_outputs() {
    use std::os::unix::ffi::OsStringExt;
    let mut values: Vec<_> = ["", "2", "true", "false", "01", "-1", "1 ", " 1", "\n1"]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect();
    values.push(std::ffi::OsString::from_vec(vec![0xff]));
    for value in values {
        let (output, reached, entries) = preflight_switch("P11SCOPE_JOURNAL", Some(&value), &[]);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("P11SCOPE_JOURNAL must be unset, 0 or 1"),
            "{value:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!reached, "invalid request reached a compiler");
        assert_eq!(entries, ["preserved"]);
    }
    for setting in [
        ("CARGO_FEATURE_STUB_OBJECT_ATTRIBUTES", "1"),
        ("CARGO_FEATURE_UNSAFE_UNVALIDATED_METADATA", "1"),
        ("CARGO_FEATURE_WIDE_DETAILED_2112", "1"),
        ("P11SCOPE_SMALL_RING", "1"),
        ("P11SCOPE_SMALL_RING", "true"),
        ("P11SCOPE_SMALL_STATE_MAPS", "1"),
        ("P11SCOPE_SMALL_STATE_MAPS", "true"),
        ("P11SCOPE_SMALL_DISCOVERY_RING", "1"),
        ("P11SCOPE_SMALL_DISCOVERY_RING", "true"),
        ("P11SCOPE_IMAGE_BANK_PROOF", "1"),
        ("P11SCOPE_COUNTER_ARTIFACTS", "1"),
    ] {
        let (output, reached, entries) =
            preflight_switch("P11SCOPE_JOURNAL", Some(OsStr::new("1")), &[setting]);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("production journal"),
            "{setting:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!reached, "{setting:?} reached a compiler");
        assert_eq!(entries, ["preserved"]);
    }
}

#[test]
fn journal_permits_existing_independent_counter_selection() {
    for value in [None, Some(OsStr::new("0")), Some(OsStr::new("1"))] {
        for counter in [None, Some("0"), Some("1")] {
            let settings: Vec<_> = counter
                .map(|value| ("P11SCOPE_COUNTER_OBJECTS", value))
                .into_iter()
                .collect();
            let (output, reached, entries) = preflight_switch("P11SCOPE_JOURNAL", value, &settings);
            assert!(
                reached,
                "valid journal/counter preflight refused: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(entries, ["preserved"]);
        }
    }
}

#[test]
fn journal_output_matches_this_build_selection() {
    let requested = option_env!("P11SCOPE_JOURNAL") == Some("1");
    let path = Path::new(env!("OUT_DIR")).join(JOURNAL_OUTPUT);
    if requested {
        assert!(
            path.is_file(),
            "requested production journal ELF is absent: build-selection interface gap: {}",
            path.display()
        );
        assert!(
            fs::read(&path).unwrap().as_slice() != p11scope::EBPF_OBJECT,
            "production journal ELF aliases ordinary Detailed bytes"
        );
    }
    assert_eq!(journal_selected(), requested);
    assert_eq!(
        option_env!("P11SCOPE_JOURNAL_OUTPUTS"),
        Some(if requested { "journal-v1" } else { "" })
    );
}

#[test]
fn journal_production_elf_replaces_pair_and_retains_shapes() {
    if !journal_selected() {
        assert_eq!(option_env!("P11SCOPE_JOURNAL_OUTPUTS"), Some(""));
        return; // The opt-in configuration supplies the actual production positive.
    }
    let path = Path::new(env!("OUT_DIR")).join(JOURNAL_OUTPUT);
    let bytes = fs::read(&path).unwrap();
    let object = aya_obj::Object::parse(&bytes).unwrap();
    let ordinary = aya_obj::Object::parse(p11scope::EBPF_OBJECT).unwrap();
    let mut expected_programs: BTreeSet<_> = ordinary.programs.keys().map(String::as_str).collect();
    assert!(expected_programs.remove("p11_entry"));
    assert!(expected_programs.remove("p11_return"));
    expected_programs.extend(["p11_entry_journal", "p11_return_journal"]);
    assert_eq!(
        object
            .programs
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected_programs
    );
    let mut expected_maps: BTreeSet<_> = ordinary.maps.keys().map(String::as_str).collect();
    expected_maps.extend([
        "JOURNAL_START",
        "JOURNAL_CTL",
        "JOURNAL_MARKER_CTL",
        "JOURNAL_CLASSES",
    ]);
    assert_eq!(
        object
            .maps
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected_maps,
        "production map inventory must be ordinary Detailed plus the four journal maps"
    );
    for (name, baseline) in &ordinary.maps {
        let map = &object.maps[name];
        let shape = |map: &aya_obj::Map| {
            (
                map.map_type(),
                map.key_size(),
                map.value_size(),
                map.max_entries(),
                map.map_flags(),
            )
        };
        assert_eq!(
            shape(map),
            shape(baseline),
            "existing production map shape: {name}"
        );
    }
    let functions: BTreeSet<_> = object
        .functions
        .values()
        .map(|function| function.name.as_str())
        .collect();
    for name in PRODUCERS {
        assert!(functions.contains(name), "missing real native {name}");
    }
    for forbidden in [
        "p11_instance_exec_birth",
        "p11_journal_marker_publish",
        "p11_journal_combined_entry",
        "p11_journal_combined_return",
        "p11_journal_combined_remove",
    ] {
        assert!(
            !functions.contains(forbidden),
            "unexpected production ELF body {forbidden}"
        );
    }
    let undefined = Command::new("llvm-nm")
        .arg("--undefined-only")
        .arg(&path)
        .output()
        .unwrap();
    assert!(undefined.status.success());
    assert!(
        undefined.stdout.is_empty(),
        "unresolved native dependencies: {}",
        String::from_utf8_lossy(&undefined.stdout)
    );
    for (name, shape) in [
        ("JOURNAL_START", (1, 16, 24, 16_384, 0)),
        ("JOURNAL_CTL", (2, 4, 24, 1, 0)),
        ("JOURNAL_MARKER_CTL", (2, 4, 16, 1, 0)),
        ("JOURNAL_CLASSES", (2, 4, 4, 105, 128)),
        ("THREAD_OWNER", (29, 4, 560, 0, 1)),
        ("START", (1, 16, 288, 16_384, 0)),
        ("OBJECT_START", (1, 16, 432, 16_384, 0)),
        ("INSTANCE_START", (9, 16, 24, 16_384, 0)),
        ("DESCRIPTORS", (2, 4, 18, 105, 128)),
        ("EVENTS", (27, 0, 0, 4 * 1024 * 1024, 0)),
        ("EVIDENCE", (6, 4, 8, 9, 0)),
    ] {
        let map = object
            .maps
            .get(name)
            .unwrap_or_else(|| panic!("missing dependency {name}"));
        assert_eq!(
            (
                map.map_type(),
                map.key_size(),
                map.value_size(),
                map.max_entries(),
                map.map_flags()
            ),
            shape,
            "{name}"
        );
    }
    let Some(flags) = option_env!("P11SCOPE_BPF_RUSTFLAGS_JOURNAL") else {
        panic!("selected production journal has no flags receipt");
    };
    assert!(flags.contains("--cfg=p11scope_journal_roots"));
    assert!(!flags.contains("--cfg=p11scope_birth_marker"));
    assert!(!flags.contains("image-bank-proof"));
}
