use p11scope_discover::discover::discover;
use p11scope_discover::manifest::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

static FIXTURE_ID: AtomicUsize = AtomicUsize::new(0);
static DISCOVER_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
enum FixtureMode {
    Normal,
    Conflict,
    PostFailure,
    Absent,
    UnknownFlags,
    ShortTable,
    Outside,
}

fn build_fixture(mode: FixtureMode) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "fixture-{}",
        FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture");
    let helper = dir.join("helper.so");
    let provider = dir.join("provider.so");
    let outside = dir.join("outside.c");
    if matches!(mode, FixtureMode::Outside) {
        std::fs::write(
            &outside,
            "typedef unsigned long CK_RV; typedef unsigned long CK_FLAGS; typedef struct { unsigned char major; unsigned char minor; } CK_VERSION; CK_RV C_GetInterface(void *n, void *v, void **o, CK_FLAGS f) { (void)n; (void)v; (void)o; (void)f; __builtin_trap(); }\n",
        )
        .unwrap();
    }
    let mut helper_cmd = Command::new("gcc");
    helper_cmd
        .args(["-shared", "-fPIC", "-Wl,-soname,helper.so", "-o"])
        .arg(&helper)
        .arg(src.join("helper.c"));
    if matches!(mode, FixtureMode::Outside) {
        helper_cmd.arg(&outside);
    }
    let ok = helper_cmd.status().unwrap().success();
    assert!(ok, "gcc helper.so failed");
    let mut provider_cmd = Command::new("gcc");
    provider_cmd
        .args(["-shared", "-fPIC", "-o"])
        .arg(&provider)
        .arg(src.join("provider.c"))
        .arg(&helper);
    if matches!(mode, FixtureMode::Conflict) {
        provider_cmd.arg("-DCONFLICT_FIXTURE=1");
    }
    if matches!(mode, FixtureMode::PostFailure) {
        provider_cmd.arg("-DPOST_FAILURE_FIXTURE=1");
    }
    if matches!(mode, FixtureMode::Absent | FixtureMode::Outside) {
        provider_cmd.arg("-DNO_GET_INTERFACE=1");
    }
    if matches!(mode, FixtureMode::UnknownFlags) {
        provider_cmd.arg("-DUNKNOWN_FLAGS_FIXTURE=1");
    }
    if matches!(mode, FixtureMode::ShortTable) {
        provider_cmd.arg("-DSHORT_TABLE_FIXTURE=1");
    }
    let ok = provider_cmd
        .arg(format!("-Wl,-rpath,{}", dir.display()))
        .status()
        .unwrap()
        .success();
    assert!(ok, "gcc provider.so failed");
    provider
}

fn resolution<'a>(s: &'a SurfaceRecord, name: &str) -> &'a Resolution {
    &s.functions
        .iter()
        .find(|f| f.name == name)
        .unwrap()
        .resolution
}

#[test]
fn fixture_covers_3x_vendor_null_alias_cross_object() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let provider = build_fixture(FixtureMode::Normal);
    let m = discover(&provider).unwrap();

    // Legacy surface walked in full; NULL entry preserved as evidence.
    let legacy = &m.surfaces[0];
    assert!(matches!(legacy.walk, WalkOutcome::Full));
    assert_eq!(legacy.functions.len(), 68);
    assert!(matches!(
        resolution(legacy, "C_GetFunctionStatus"),
        Resolution::NullPointer
    ));

    // Cross-object: C_GenerateRandom resolves into helper.so, which gets
    // its own object record with its own identity.
    let Resolution::Resolved {
        object: helper_obj, ..
    } = *resolution(legacy, "C_GenerateRandom")
    else {
        panic!("C_GenerateRandom did not resolve")
    };
    let Resolution::Resolved {
        object: main_obj, ..
    } = *resolution(legacy, "C_Initialize")
    else {
        panic!("C_Initialize did not resolve")
    };
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
    assert_eq!(
        m.vendor_interfaces[0].name_lossy.as_deref(),
        Some("Vendor NetHSM-Ext")
    );
    assert!(!m.vendor_interfaces[0].func_list_null);

    // Alias: C_CancelFunction and C_WaitForSlotEvent share one target.
    let g = m
        .alias_groups
        .iter()
        .find(|g| g.entries.iter().any(|e| e.name == "C_CancelFunction"))
        .expect("alias group");
    assert!(g.entries.iter().any(|e| e.name == "C_WaitForSlotEvent"));
}

#[test]
fn selection_helper_makes_exactly_ten_queries() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let provider = build_fixture(FixtureMode::Normal);
    let m = discover(&provider).unwrap();
    let json = serde_json::to_value(&m).unwrap();
    assert_eq!(json["schema"], "p11scope-manifest/5");
    assert_eq!(json["selection_evidence"]["acquisition"], "queried");
    assert_eq!(
        json["selection_evidence"]["queries"]
            .as_array()
            .unwrap()
            .len(),
        10
    );
    let evidence = &m.selection_evidence;
    for (position, query) in evidence.queries.iter().enumerate() {
        assert_eq!(query.selector, (position / 2) as u8);
        assert_eq!(query.request.flags, (position % 2) as u64);
        assert_eq!(
            query.rv,
            if position == 1 {
                cryptoki_sys::CKR_ARGUMENTS_BAD
            } else {
                cryptoki_sys::CKR_OK
            }
        );
        if position >= 4 {
            assert_eq!(
                query.result.as_ref().map(|result| result.version),
                Some(SelectionVersionClass::V3_0)
            );
        }
    }
    assert_eq!(evidence.queries[1].rv, cryptoki_sys::CKR_ARGUMENTS_BAD);
    assert!(evidence.queries[1].result.is_none());
}

#[test]
fn selection_helper_conflicting_semantic_pair_is_truncated() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let provider = build_fixture(FixtureMode::Conflict);
    let m = discover(&provider).unwrap();
    assert!(m.selection_evidence.selection_truncated);
    assert_eq!(m.selection_evidence.tables.len(), 1);
    assert!(m.selection_evidence.queries[2].selection_table.is_some());
    assert!(m.selection_evidence.queries[3].selection_table.is_none());
    assert_eq!(
        m.selection_evidence.queries[3].authority,
        SelectionAuthority::None
    );
    assert!(m.selection_evidence.queries[3].helper_failure.is_none());
}

#[test]
fn selection_helper_records_post_success_helper_failure() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let provider = build_fixture(FixtureMode::PostFailure);
    let m = discover(&provider).unwrap();
    let query = &m.selection_evidence.queries[2];
    assert_eq!(query.rv, cryptoki_sys::CKR_OK);
    assert!(query.result.is_some());
    assert_eq!(
        query.helper_failure,
        Some(SelectionFailure::UnresolvedFunction)
    );
    assert_eq!(query.authority, SelectionAuthority::None);
    assert!(query.selection_table.is_none());
}

#[test]
fn selection_helper_export_absent_makes_zero_queries() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let provider = build_fixture(FixtureMode::Absent);
    let m = discover(&provider).unwrap();
    assert_eq!(
        m.selection_evidence.acquisition,
        SelectionAcquisition::ExportAbsent
    );
    assert!(m.selection_evidence.queries.is_empty());
    assert!(m.selection_evidence.tables.is_empty());
}

#[test]
fn selection_helper_export_outside_module_makes_zero_queries() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let provider = build_fixture(FixtureMode::Outside);
    let m = discover(&provider).unwrap();
    assert_eq!(
        m.selection_evidence.acquisition,
        SelectionAcquisition::ExportOutsideModule
    );
    assert!(m.selection_evidence.queries.is_empty());
    assert!(m.selection_evidence.tables.is_empty());
}

#[test]
fn selection_helper_preserves_unknown_returned_flags() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let provider = build_fixture(FixtureMode::UnknownFlags);
    let m = discover(&provider).unwrap();
    assert_eq!(
        m.selection_evidence.queries[2]
            .result
            .as_ref()
            .unwrap()
            .flags,
        1u64 << 63
    );
}

#[test]
fn selection_helper_rejects_short_known_table_without_authority() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let provider = build_fixture(FixtureMode::ShortTable);
    let m = discover(&provider).unwrap();
    let query = &m.selection_evidence.queries[4];
    assert_eq!(
        query.helper_failure,
        Some(SelectionFailure::UnreadableTable)
    );
    assert_eq!(query.authority, SelectionAuthority::None);
    assert!(query.selection_table.is_none());
}

#[test]
fn selection_helper_matches_pointer_and_compares_agreement_fields() {
    let _guard = DISCOVER_LOCK.lock().unwrap();
    let provider = build_fixture(FixtureMode::Normal);
    let m = discover(&provider).unwrap();
    let matches = &m.selection_evidence.queries[2].inventory_matches;
    assert!(!matches.is_empty());
    assert!(
        matches
            .windows(2)
            .all(|pair| pair[0].surface < pair[1].surface)
    );
    assert!(
        matches
            .iter()
            .any(|found| found.name_agrees && found.version_agrees)
    );

    let provider = build_fixture(FixtureMode::Conflict);
    let m = discover(&provider).unwrap();
    assert!(m.selection_evidence.queries[2].inventory_matches.is_empty());
    assert!(m.selection_evidence.queries[2].selection_table.is_some());
}
