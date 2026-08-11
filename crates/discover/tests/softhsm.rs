use p11scope_discover::discover::discover;
use p11scope_discover::identity::IdentityKind;
use p11scope_discover::manifest::*;
use std::path::Path;

const SOFTHSM: &str = "/usr/lib/softhsm/libsofthsm2.so";
/// A magic /proc/<pid>/root/... path is exactly how a Docker/Knative
/// capture points discover at a container's provider (see
/// scripts/matrix/verify-knative.sh); `/proc/self/root` reaches the same
/// file the plain `SOFTHSM` path does, without needing a container, so
/// this exercises the same "resolved path != --module argument" hazard
/// discover.rs's `module_anchor` fixes.
const SOFTHSM_MAGIC: &str = "/proc/self/root/usr/lib/softhsm/libsofthsm2.so";

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

/// Regression for the discover identity bug the Knative row found
/// (docs/notes/phase4-matrix.md): a magic `/proc/<pid>/root/...` module
/// path crosses into another mount namespace, so `/proc/self/maps` can
/// report the loaded module's own mapping under a path string that
/// differs from `--module` — sometimes one unreachable from this process
/// at all. The module's object must still be recorded against the
/// argument path, not that resolved one, so a later `p11scope profile`/
/// `verify::check_reuse` re-identifying against `module_path` (the only
/// path guaranteed to stay valid) finds a matching, reusable object.
#[test]
fn magic_proc_path_records_identity_against_the_module_path_argument() {
    if !Path::new(SOFTHSM).exists() {
        eprintln!("SKIP: {SOFTHSM} not present");
        return;
    }
    let m = discover(Path::new(SOFTHSM_MAGIC)).unwrap();
    assert_eq!(m.module_path, SOFTHSM_MAGIC);

    let obj = m.objects.iter().find(|o| o.path == SOFTHSM_MAGIC).expect(
        "the module's object must be recorded under the --module argument path, \
         not whatever path /proc/self/maps resolved for the same file",
    );
    assert_eq!(obj.identity.kind, IdentityKind::GnuBuildId);
    assert!(obj.identity.reusable);

    // Reproduces verify::check_reuse's per-object comparison directly:
    // re-identify against the recorded path and confirm it still matches
    // — the manifest passes the reuse gate end to end, no manual patching
    // (the workaround verify-knative.sh had to fall back to) needed.
    let current = p11scope_discover::identity::identify(Path::new(&obj.path));
    assert_eq!(current.kind, obj.identity.kind);
    assert_eq!(current.value, obj.identity.value);
    assert!(current.reusable);
}
