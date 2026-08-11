use p11scope_discover::discover::discover;
use p11scope_discover::identity::IdentityKind;
use p11scope_discover::manifest::*;
use std::path::Path;

const SOFTHSM: &str = "/usr/lib/softhsm/libsofthsm2.so";

#[test]
fn softhsm2_legacy_table_fully_resolved() {
    if !Path::new(SOFTHSM).exists() {
        eprintln!("SKIP: {SOFTHSM} not present");
        return;
    }
    let m = discover(Path::new(SOFTHSM)).unwrap();
    assert_eq!(m.schema, SCHEMA);

    // Legacy surface: 68/68, names exactly FUNCTION_LIST_FIELDS, in order.
    let legacy = &m.surfaces[0];
    assert!(matches!(legacy.source, SurfaceSource::LegacyFunctionList));
    assert!(matches!(legacy.acquisition, Acquisition::Ok));
    assert!(matches!(legacy.walk, WalkOutcome::Full));
    let expected: Vec<&str> = pkcs11_module::FUNCTION_LIST_FIELDS.iter().map(|f| f.name).collect();
    let got: Vec<&str> = legacy.functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(got, expected);
    assert_eq!(legacy.functions.len(), 68);

    // Every entry resolves into a softhsm object file.
    for f in &legacy.functions {
        match f.resolution {
            Resolution::Resolved { object, .. } => {
                assert!(m.objects[object as usize].path.contains("softhsm"), "{}", f.name);
            }
            ref other => panic!("{} did not resolve: {other:?}", f.name),
        }
    }

    // SoftHSM2 2.6 is 2.40-only: no C_GetInterfaceList export.
    assert!(matches!(m.interface_list, Acquisition::Absent));
    assert!(m.surfaces.len() == 1);
    assert!(m.vendor_interfaces.is_empty());

    // Distro .so carries a GNU build-id.
    assert_eq!(m.objects[0].identity.kind, IdentityKind::GnuBuildId);
    assert!(m.objects[0].identity.reusable);
}
