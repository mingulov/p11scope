use p11scope_manifest::manifest::*;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn manifest_for(object: &Path) -> Manifest {
    let file = p11scope_manifest::identity::open_object(object).unwrap();
    let key = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
    let identity = p11scope_manifest::identity::inspect_file(&file)
        .unwrap()
        .identity;
    Manifest {
        schema: SCHEMA.into(),
        module_path: object.display().to_string(),
        objects: vec![ObjectRecord {
            id: 0,
            path: object.display().to_string(),
            identity: identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path: object.display().to_string(),
            device_major: key.device_major,
            device_minor: key.device_minor,
            inode: key.inode,
            identity,
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
    }
}

#[test]
fn lease_holder_child() {
    if std::env::var_os("P11SCOPE_LEASE_CHILD").is_none() {
        return;
    }
    let object = PathBuf::from(std::env::var_os("P11SCOPE_TEST_OBJECT").unwrap());
    let ready = PathBuf::from(std::env::var_os("P11SCOPE_TEST_READY").unwrap());
    let _verified = p11scope::verify::check_reuse(&manifest_for(&object)).unwrap();
    std::fs::write(ready, b"ready").unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[test]
fn a_write_attempt_terminates_the_observer_before_the_writer_proceeds() {
    let dir = tempfile::tempdir().unwrap();
    let object = dir.path().join("leased.so");
    let ready = dir.path().join("ready");
    std::fs::copy("/bin/true", &object).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["lease_holder_child", "--exact"])
        .env("P11SCOPE_LEASE_CHILD", "1")
        .env("P11SCOPE_TEST_OBJECT", &object)
        .env("P11SCOPE_TEST_READY", &ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    while !ready.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "lease holder exited early"
        );
        assert!(
            Instant::now() < deadline,
            "lease holder did not become ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let _writer = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&object);
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("observer survived an object lease break");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(p11scope::verify::OBJECT_CHANGED_EXIT));
}
