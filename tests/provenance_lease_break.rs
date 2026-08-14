use p11scope_manifest::manifest::*;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

#[test]
fn same_inode_write_during_fresh_discovery_is_refused_before_bpf() {
    let dir = tempfile::tempdir().unwrap();
    let observer = dir.path().join("p11scope");
    let helper = dir.path().join("p11scope-discover");
    let object = dir.path().join("provider.so");
    let manifest_path = dir.path().join("manifest.json");
    std::fs::copy(env!("CARGO_BIN_EXE_p11scope"), &observer).unwrap();
    std::fs::copy("/bin/true", &object).unwrap();
    std::fs::set_permissions(&observer, std::fs::Permissions::from_mode(0o755)).unwrap();

    let object_file = p11scope_manifest::identity::open_object(&object).unwrap();
    let object_key = p11scope_manifest::identity::mapping_file_key(&object_file).unwrap();
    let object_identity = p11scope_manifest::identity::inspect_file(&object_file)
        .unwrap()
        .identity;

    let manifest = Manifest {
        schema: SCHEMA.into(),
        module_path: object.display().to_string(),
        objects: vec![ObjectRecord {
            id: 0,
            path: object.display().to_string(),
            identity: object_identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path: object.display().to_string(),
            device_major: object_key.device_major,
            device_minor: object_key.device_minor,
            inode: object_key.inode,
            identity: object_identity,
        }],
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Absent,
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: vec![],
        }],
        vendor_interfaces: vec![],
        alias_groups: vec![],
    };
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

    let source = dir.path().join("oracle.c");
    std::fs::write(
        &source,
        format!(
            r#"#include <fcntl.h>
#include <stdio.h>
int main(int argc, char **argv) {{
  if (argc < 3 || open(argv[2], O_WRONLY | O_NONBLOCK) >= 0) return 90;
  FILE *in = fopen({:?}, "r");
  if (!in) return 91;
  int ch;
  while ((ch = fgetc(in)) != EOF) putchar(ch);
  return 0;
}}
"#,
            manifest_path.display().to_string()
        ),
    )
    .unwrap();
    assert!(
        Command::new("gcc")
            .args(["-o"])
            .arg(&helper)
            .arg(&source)
            .status()
            .unwrap()
            .success()
    );
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new(&observer)
        .args(["profile", "--manifest"])
        .arg(&manifest_path)
        .args(["--provenance-module"])
        .arg(&object)
        .args([
            "--pid",
            &std::process::id().to_string(),
            "--trusted-workload",
            "--duration",
            "1",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(p11scope::verify::OBJECT_CHANGED_EXIT)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("loading BPF object"), "{stderr}");
}
