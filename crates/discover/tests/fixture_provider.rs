use p11scope_discover::discover::discover;
use p11scope_discover::manifest::*;
use std::path::{Path, PathBuf};
use std::process::Command;

fn build_fixture() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fixture");
    std::fs::create_dir_all(&dir).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let helper = dir.join("helper.so");
    let provider = dir.join("provider.so");
    let ok = Command::new("gcc")
        .args(["-shared", "-fPIC", "-Wl,-soname,helper.so", "-o"])
        .arg(&helper)
        .arg(src.join("helper.c"))
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc helper.so failed");
    let ok = Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&provider)
        .arg(src.join("provider.c"))
        .arg(&helper)
        .arg(format!("-Wl,-rpath,{}", dir.display()))
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc provider.so failed");
    provider
}

fn resolution<'a>(s: &'a SurfaceRecord, name: &str) -> &'a Resolution {
    &s.functions.iter().find(|f| f.name == name).unwrap().resolution
}

#[test]
fn fixture_covers_3x_vendor_null_alias_cross_object() {
    let provider = build_fixture();
    let m = discover(&provider).unwrap();

    // Legacy surface walked in full; NULL entry preserved as evidence.
    let legacy = &m.surfaces[0];
    assert!(matches!(legacy.walk, WalkOutcome::Full));
    assert_eq!(legacy.functions.len(), 68);
    assert!(matches!(resolution(legacy, "C_GetFunctionStatus"), Resolution::NullPointer));

    // Cross-object: C_GenerateRandom resolves into helper.so, which gets
    // its own object record with its own identity.
    let Resolution::Resolved { object: helper_obj, .. } = *resolution(legacy, "C_GenerateRandom")
    else { panic!("C_GenerateRandom did not resolve") };
    let Resolution::Resolved { object: main_obj, .. } = *resolution(legacy, "C_Initialize")
    else { panic!("C_Initialize did not resolve") };
    assert_ne!(helper_obj, main_obj);
    assert!(m.objects[helper_obj as usize].path.ends_with("helper.so"));
    assert!(m.objects[helper_obj as usize].identity.reusable);

    // Interface enumeration succeeded; the standard 3.0 surface is walked
    // in full: 68 base + 24 extra entries.
    assert!(matches!(m.interface_list, Acquisition::Ok));
    let std30 = m
        .surfaces
        .iter()
        .find(|s| s.version == Some(Version { major: 3, minor: 0 }))
        .expect("3.0 standard surface");
    assert!(matches!(std30.walk, WalkOutcome::Full));
    assert_eq!(std30.functions.len(), 92);

    // "PKCS 11" with a NULL function list: recorded, never walked.
    let nullfl = m
        .surfaces
        .iter()
        .find(|s| matches!(s.source, SurfaceSource::Interface { index: 2, .. }))
        .expect("NULL-func-list surface");
    assert!(matches!(nullfl.walk, WalkOutcome::NotWalked));
    assert!(nullfl.functions.is_empty());

    // Vendor interface: present-but-undecoded, lossless name.
    assert_eq!(m.vendor_interfaces.len(), 1);
    assert_eq!(m.vendor_interfaces[0].name_lossy.as_deref(), Some("Vendor NetHSM-Ext"));
    assert!(!m.vendor_interfaces[0].func_list_null);

    // Alias: C_CancelFunction and C_WaitForSlotEvent share one target.
    let g = m
        .alias_groups
        .iter()
        .find(|g| g.entries.iter().any(|e| e.name == "C_CancelFunction"))
        .expect("alias group");
    assert!(g.entries.iter().any(|e| e.name == "C_WaitForSlotEvent"));
}
