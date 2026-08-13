use p11scope_discover::discover::discover;
use p11scope_discover::manifest::{Resolution, SurfaceSource, WalkOutcome};
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn acquisition_loaded_backend_keeps_its_own_object_identity() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("lazy-dependency");
    std::fs::create_dir_all(&dir).unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let backend = dir.join("lazy-backend.so");
    let wrapper = dir.join("lazy-wrapper.so");

    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-Wl,-soname,lazy-backend.so", "-o"])
            .arg(&backend)
            .arg(source.join("lazy_backend.c"))
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&wrapper)
            .arg(source.join("lazy_wrapper.c"))
            .arg("-ldl")
            .arg("-Wl,-rpath,$ORIGIN")
            .status()
            .unwrap()
            .success()
    );

    let dynamic = Command::new("readelf")
        .args(["-d"])
        .arg(&wrapper)
        .output()
        .unwrap();
    assert!(dynamic.status.success());
    assert!(
        !String::from_utf8_lossy(&dynamic.stdout).contains("lazy-backend"),
        "backend must be acquired lazily, not through DT_NEEDED"
    );

    let manifest = discover(&wrapper).unwrap();
    let legacy = manifest
        .surfaces
        .iter()
        .find(|surface| matches!(surface.source, SurfaceSource::LegacyFunctionList))
        .unwrap();
    assert!(matches!(&legacy.walk, WalkOutcome::Full));
    assert_eq!(legacy.functions.len(), 68);
    let backend_object = manifest
        .objects
        .iter()
        .find(|object| object.path.ends_with("lazy-backend.so"))
        .expect("lazy backend must get its own object identity");
    assert!(backend_object.identity.reusable);
    assert!(legacy.functions.iter().all(|function| {
        matches!(
            function.resolution,
            Resolution::Resolved { object, .. } if object == backend_object.id
        )
    }));
}
