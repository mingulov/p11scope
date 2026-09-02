use p11scope::attach::Scope;
use p11scope::cli::{CaptureArgs, Kind, ScopeArg};
use p11scope::discovery::engine::Engine;
use p11scope::discovery::hooks::HookRegistry;
use p11scope::process::{ProcessView, ProcessViewId};
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("live-discovery-initial-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build_and_load_fixture(dir: &Path) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/discover/tests/fixture/version_matrix.c");
    let library = dir.join("initial-provider.so");
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-DMATRIX_INTERFACES=0", "-o"])
            .arg(&library)
            .arg(source)
            .status()
            .unwrap()
            .success()
    );

    let path = std::ffi::CString::new(library.to_str().unwrap()).unwrap();
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen {}", library.display());
    let symbol = std::ffi::CString::new("C_GetFunctionList").unwrap();
    let entry = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
    assert!(!entry.is_null());
    let entry: extern "C" fn(*mut *mut std::ffi::c_void) -> u64 =
        unsafe { std::mem::transmute(entry) };
    let mut table = std::ptr::null_mut();
    assert_eq!(entry(&mut table), 0);
    assert!(!table.is_null());
    library
}

#[test]
fn engine_initial_discovery_preserves_plan() {
    let provider = build_and_load_fixture(&fixture_dir());
    let pid = std::process::id();
    let args = CaptureArgs {
        kind: Kind::Profile,
        modules: vec![provider],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: ScopeArg::Pid(pid),
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        unsafe_requested: false,
    };
    let scope = Scope::Pid(pid);
    let view = ProcessView::open(ProcessViewId(0), pid).unwrap();

    let engine = Engine::discover(&args, &scope, Some(view)).unwrap();

    assert_eq!(engine.plan().modules.len(), 1);
    assert!(engine.plan().slots.len() >= 60);
    assert!(
        engine
            .plan()
            .slots
            .iter()
            .all(|slot| !slot.semantic_authorized),
        "scan-only initial discovery remains count-only"
    );
    assert_eq!(engine.discovery().modules.len(), 1);
    assert_eq!(engine.loader_failures(), (0, 0));
}
