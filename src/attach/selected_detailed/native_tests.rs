//! SPDX-License-Identifier: GPL-3.0-or-later
//! Can run directly with rustc --test; no Cargo/BPF build or kernel loading.
use std::path::PathBuf;
use std::process::Command;
#[test]
fn actual_selected_native_gate_and_irreversible_state() {
    let root = PathBuf::from(option_env!("CARGO_MANIFEST_DIR").unwrap_or(env!("PWD")));
    assert!(
        root.join("crates/ebpf/native/selected_detailed.c")
            .is_file(),
        "selected native gate is not implemented"
    );
    let binary =
        std::env::temp_dir().join(format!("p11scope-selected-host-{}", std::process::id()));
    let output = Command::new("clang-18")
        .args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-attributes",
        ])
        .args(
            ["native_tests.c", "identity_fixture.c", "query_fixture.c"]
                .map(|name| root.join("src/attach/selected_detailed").join(name)),
        )
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_file(binary);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("29 controls passed"));
}

#[test]
fn actual_selected_bootstrap_uses_real_allocator_and_continuity() {
    let root = PathBuf::from(option_env!("CARGO_MANIFEST_DIR").unwrap_or(env!("PWD")));
    let binary = std::env::temp_dir().join(format!(
        "p11scope-selected-bootstrap-{}",
        std::process::id()
    ));
    let output = Command::new("clang-18")
        .args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-attributes",
        ])
        .args(
            ["bootstrap_tests.c", "identity_fixture.c", "query_fixture.c"]
                .map(|name| root.join("src/attach/selected_detailed").join(name)),
        )
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_file(binary);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("9 controls passed"));
}

#[test]
fn actual_inventory_baseline_uses_identity_only_allocator() {
    let root = PathBuf::from(option_env!("CARGO_MANIFEST_DIR").unwrap_or(env!("PWD")));
    assert!(
        root.join("crates/ebpf/native/selected_detailed_baseline.c")
            .is_file(),
        "Inventory-side baseline is not implemented"
    );
    let binary = std::env::temp_dir().join(format!(
        "p11scope-inventory-baseline-{}",
        std::process::id()
    ));
    let output = Command::new("clang-18")
        .args([
            "-std=gnu11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-attributes",
        ])
        .args(
            ["baseline_tests.c", "identity_fixture.c"]
                .map(|name| root.join("src/attach/selected_detailed").join(name)),
        )
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_file(binary);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("7 controls passed"));
}

#[test]
fn actual_selected_leaf_object_contract_and_causal_mutations() {
    let root = PathBuf::from(option_env!("CARGO_MANIFEST_DIR").unwrap_or(env!("PWD")));
    let object =
        std::env::temp_dir().join(format!("p11scope-selected-leaf-{}.o", std::process::id()));
    let output = Command::new("clang-18")
        .args([
            "-target", "bpfel", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-c",
        ])
        .arg(root.join("crates/ebpf/native/selected_detailed.c"))
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("python3").args(["-I", "-c", r#"
import runpy, struct, sys
from pathlib import Path
checker=runpy.run_path(str(Path(sys.argv[1])/'scripts/check-bpf-map-defs.py'))
raw=Path(sys.argv[2]).read_bytes(); Elf=checker['Elf']; check=checker['validate_selected_leaf']
elf=Elf(raw); report=check(elf); assert report['frame'] == 32
symbol=next(s for s in elf.symbols if s[0]=='p11_selected_current_allowed')
section=elf.sections['.text'][0]
base=section[4]+symbol[4]
body=raw[base:base+symbol[5]]
call=next(i for i in range(0,len(body),8) if body[i]==0x85 and body[i+1]==0)
stack=next(i for i in range(0,len(body),8) if body[i]&7 in (1,2,3) and struct.unpack_from('<h',body,i+2)[0]==-32)
for label,offset,value in [('user-read',call+4,struct.pack('<i',113)), ('nested-call',call+1,b'\x10'), ('frame-overflow',stack+2,struct.pack('<h',-40))]:
    changed=bytearray(raw); changed[base+offset:base+offset+len(value)]=value
    try: check(Elf(bytes(changed)))
    except RuntimeError: pass
    else: raise AssertionError(label+' accepted')
string=elf.sections['.strtab']; at=string[0][4]+string[1].index(b'TASK_COOKIE\0')
changed=bytearray(raw); changed[at:at+11]=b'EVIL_COOKIE'
try: check(Elf(bytes(changed)))
except RuntimeError: pass
else: raise AssertionError('foreign map accepted')
print('actual selected leaf: own32 and four causal negatives passed')
"#]).arg(&root).arg(&object).output().unwrap();
    let _ = std::fs::remove_file(object);
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
