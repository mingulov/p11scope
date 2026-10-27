//! SPDX-License-Identifier: GPL-3.0-or-later
//! An unrelated executable mapping must not erase useful provider observations.

#[allow(dead_code)]
#[path = "../../../src/manifest_input.rs"]
mod manifest_input;

use p11scope_discover::manifest::{Manifest, Resolution, SurfaceSource};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_p11scope-discover");
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    provider: PathBuf,
}

impl Fixture {
    fn build(mode: u8) -> Self {
        let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "provenance-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let provider = directory.join("provider.so");
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture/provenance_provider.c");
        if matches!(mode, 3 | 5) {
            let backend = directory.join("backend.c");
            std::fs::write(
                &backend,
                "unsigned long provenance_backend(void) { return 0; }\n",
            )
            .unwrap();
            compile(&backend, &directory.join("backend.so"), None);
        }
        compile(&source, &provider, Some(mode));
        Self {
            directory,
            provider,
        }
    }

    fn discover(&self) -> Output {
        Command::new(BIN)
            .arg("--module")
            .arg(&self.provider)
            .output()
            .unwrap()
    }

    fn manifest(&self) -> (Manifest, String) {
        let output = self.discover();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            output.status.success(),
            "a usable provider must yield its manifest: {stderr}"
        );
        let manifest: Manifest = serde_json::from_slice(&output.stdout).unwrap();
        let problems = manifest_input::validate_structure(&manifest);
        assert!(problems.is_empty(), "invalid helper manifest: {problems:?}");
        for object in &manifest.objects {
            assert!(object.identity.reusable, "unusable object: {object:?}");
            assert!(manifest.provenance_objects.iter().any(|provenance| {
                provenance.identity.sha256 == object.identity.sha256 && provenance.identity.reusable
            }));
        }
        let legacy = manifest
            .surfaces
            .iter()
            .find(|surface| matches!(surface.source, SurfaceSource::LegacyFunctionList))
            .unwrap();
        assert_eq!(legacy.functions.len(), 68);
        assert_eq!(legacy.functions[0].name, "C_Initialize");
        assert!(matches!(
            legacy.functions[0].resolution,
            Resolution::Resolved { object: 0, .. }
        ));
        (manifest, stderr)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn compile(source: &Path, output: &Path, mode: Option<u8>) {
    let mut command = Command::new("gcc");
    command
        .arg(format!("-m{}", usize::BITS))
        .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(output)
        .arg(source)
        .arg("-ldl");
    if let Some(mode) = mode {
        command.arg(format!("-DPROVENANCE_MODE={mode}"));
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn healthy_provider_has_usable_required_provenance() {
    let fixture = Fixture::build(0);
    fixture.manifest();
}

#[test]
fn unrelated_deleted_executable_mapping_preserves_provider_manifest() {
    let fixture = Fixture::build(1);
    let (manifest, stderr) = fixture.manifest();
    assert_eq!(manifest.objects.len(), 1);
    assert!(
        stderr.contains("optional executable provenance"),
        "an omitted optional mapping must be diagnosed: {stderr}"
    );
    assert!(
        manifest
            .provenance_objects
            .iter()
            .all(|object| !object.path.contains(".scratch-"))
    );
}

#[test]
fn deleted_mapping_target_stays_unusable_while_healthy_target_survives() {
    let fixture = Fixture::build(2);
    let (manifest, _) = fixture.manifest();
    let legacy = &manifest.surfaces[0];
    assert_eq!(legacy.functions[1].name, "C_Finalize");
    assert!(matches!(
        &legacy.functions[1].resolution,
        Resolution::UnusableFile { reason, .. } if reason.contains("deleted")
    ));
    assert_eq!(manifest.objects.len(), 1);
}

#[test]
fn resolved_required_target_deleted_before_provenance_is_refused() {
    let fixture = Fixture::build(3);
    let output = fixture.discover();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("backend.so") || stderr.contains("6261636b656e642e736f"),
        "required backend failure must identify the affected object: {stderr}"
    );
    assert!(
        stderr.contains("deleted") || stderr.contains("cannot open"),
        "required target identity failure must be explicit: {stderr}"
    );
}

#[test]
fn required_module_deleted_before_provenance_is_refused() {
    let fixture = Fixture::build(4);
    let output = fixture.discover();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("provider.so"), "{stderr}");
    assert!(stderr.contains("cannot open"), "{stderr}");
}

#[test]
fn required_target_whole_file_identity_change_is_refused() {
    let fixture = Fixture::build(5);
    let output = fixture.discover();
    assert!(
        !output.status.success(),
        "helper must refuse changed required target bytes before publishing a manifest"
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("identity"), "{stderr}");
}
