use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
use p11scope_manifest::manifest::*;
use std::path::PathBuf;
use std::process::Command;

fn tmpdir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Build a .so with a caller-chosen build-id so two builds differ.
fn cc_so(dir: &PathBuf, name: &str, body: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, body).unwrap();
    let so = dir.join(format!("{name}.so"));
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-Wl,--build-id=sha1", "-o"])
            .arg(&so)
            .arg(&src)
            .status()
            .unwrap()
            .success()
    );
    so
}

fn manifest_for(path: &PathBuf) -> Manifest {
    let id = p11scope_manifest::identity::identify(path);
    Manifest {
        schema: SCHEMA.to_string(),
        module_path: path.display().to_string(),
        objects: vec![ObjectRecord { id: 0, path: path.display().to_string(), identity: id }],
        interface_list: Acquisition::Absent,
        surfaces: vec![],
        vendor_interfaces: vec![],
        alias_groups: vec![],
    }
}

#[test]
fn matching_identity_is_accepted() {
    let d = tmpdir("reuse_ok");
    let so = cc_so(&d, "same", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    assert!(p11scope::verify::check_reuse(&m).is_ok());
}

#[test]
fn changed_object_is_refused_naming_the_file() {
    let d = tmpdir("reuse_bad");
    let so = cc_so(&d, "changed", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    // Rebuild with different content → different build-id, same path.
    let _ = cc_so(&d, "changed", "int f(void){return 2;} int g(void){return 3;}\n");
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("changed.so"), "{err:?}");
    assert!(err[0].contains("build") || err[0].contains("identity"), "{err:?}");
}

#[test]
fn vanished_object_is_refused() {
    let d = tmpdir("reuse_gone");
    let so = cc_so(&d, "gone", "int f(void){return 1;}\n");
    let m = manifest_for(&so);
    std::fs::remove_file(&so).unwrap();
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert_eq!(err.len(), 1);
}

#[test]
fn non_reusable_identity_is_refused_even_if_unchanged() {
    let d = tmpdir("reuse_unreusable");
    let so = cc_so(&d, "unreusable", "int f(void){return 1;}\n");
    let mut m = manifest_for(&so);
    m.objects[0].identity = ObjectIdentity {
        kind: IdentityKind::Unavailable,
        value: None,
        reusable: false,
        note: Some("read failed".into()),
    };
    let err = p11scope::verify::check_reuse(&m).unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("not reusable"), "{err:?}");
}
