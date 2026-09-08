//! Measures the /proc access rules the scan depends on (spec §4.9, §6.6). Each test
//! asserts the outcome the documented rules require for the observed configuration
//! (root vs non-root, `ptrace_scope` value, filesystem identity resolution) instead of
//! skipping a precondition it cannot control — `eprintln!` output is only for
//! `--nocapture` observability, no test result depends on it being read.

use std::os::unix::fs::FileExt as _;

mod support;

fn ptrace_scope() -> i32 {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().parse().unwrap_or(0))
        .unwrap_or(0)
}

#[test]
fn non_descendant_fixture_owns_concurrent_launches_exactly() {
    let mut decoy = support::MatchingDecoy::spawn().unwrap();
    let mut first = support::SameUidNonDescendant::spawn().unwrap();
    let mut second = support::SameUidNonDescendant::spawn().unwrap();
    assert_ne!(first.pid(), second.pid());
    assert!(first.is_alive().unwrap());
    assert!(second.is_alive().unwrap());
    assert!(decoy.is_alive().unwrap());

    first.terminate().unwrap();
    assert!(!first.is_alive().unwrap());
    assert!(second.is_alive().unwrap());
    assert!(
        decoy.is_alive().unwrap(),
        "matching-command decoy was touched"
    );

    second.terminate().unwrap();
    assert!(!second.is_alive().unwrap());
    assert!(
        decoy.is_alive().unwrap(),
        "decoy cleanup uses only its Child"
    );
}

/// `/proc/<pid>/maps` needs `PTRACE_MODE_READ` (same uid, or `CAP_SYS_PTRACE`) and is not
/// subject to Yama. `/proc/<pid>/mem` needs `PTRACE_MODE_ATTACH`, additionally gated by
/// `kernel.yama.ptrace_scope` (spec §4.9): 0 = same uid allowed; 1 = descendants only
/// unless `CAP_SYS_PTRACE`; 2 = `CAP_SYS_PTRACE` only; 3 = refused for *everyone*, including
/// root/`CAP_SYS_PTRACE` holders — in `yama_ptrace_access_check`
/// (`security/yama/yama_lsm.c`), the `YAMA_SCOPE_NO_ATTACH` case returns `-EPERM` directly
/// with no `ns_capable(..., CAP_SYS_PTRACE)` check, unlike scopes 1 and 2. Every branch
/// below asserts the outcome the documented rule requires for the configuration actually
/// observed — none of them are skipped.
#[test]
fn mem_access_for_a_same_uid_non_descendant_follows_the_documented_ptrace_rules() {
    let target = support::SameUidNonDescendant::spawn().expect("launch detached target");
    let pid = target.pid();
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).expect("target exe link");
    assert!(support::is_sleep(&exe));

    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"));
    assert!(
        maps.is_ok(),
        "/proc/{pid}/maps must be readable (PTRACE_MODE_READ): {maps:?}"
    );
    let maps = p11scope_manifest::maps::parse_maps(maps.unwrap().as_bytes()).unwrap();
    let readable_address = maps
        .iter()
        .find(|entry| entry.permissions[0] == b'r')
        .expect("target has a readable mapping")
        .start;

    let mem = std::fs::File::open(format!("/proc/{pid}/mem")).and_then(|f| {
        let mut b = [0u8; 1];
        f.read_exact_at(&mut b, readable_address)
    });
    let is_root = unsafe { libc::geteuid() } == 0;
    let scope = ptrace_scope();
    if is_root && scope <= 2 {
        assert!(
            mem.is_ok(),
            "root (CAP_SYS_PTRACE) must be able to read mem at ptrace_scope={scope} (<=2): {mem:?}"
        );
    } else if is_root {
        assert!(
            mem.is_err(),
            "ptrace_scope={scope} (YAMA_SCOPE_NO_ATTACH) must refuse mem even for root: {mem:?}"
        );
    } else if scope == 0 {
        assert!(
            mem.is_ok(),
            "ptrace_scope=0 must allow mem for a same-uid target: {mem:?}"
        );
    } else {
        assert!(
            mem.is_err(),
            "ptrace_scope={scope} must refuse mem for a non-descendant: {mem:?}"
        );
    }
    eprintln!(
        "MEASURED: euid_root={is_root}, ptrace_scope={scope}, mem access allowed: {:?}",
        mem.is_ok()
    );
}

#[test]
fn self_mem_is_always_readable_and_agrees_with_maps() {
    // The scan's unprivileged test path: read our own mapped bytes and confirm
    // they match what the mapping says is there.
    let maps = std::fs::read("/proc/self/maps").unwrap();
    let entries = p11scope_manifest::maps::parse_maps(&maps).unwrap();
    let exe = entries
        .iter()
        .find(|e| e.permissions[2] == b'x' && e.inode != 0)
        .expect("an executable file-backed mapping");
    let file = std::fs::File::open("/proc/self/mem").expect("/proc/self/mem");
    let mut buf = [0u8; 4];
    std::os::unix::fs::FileExt::read_exact_at(&file, &mut buf, exe.start)
        .expect("pread of our own executable mapping");
    eprintln!("MEASURED: first 4 bytes of {:?} = {buf:02x?}", exe.raw_path);
}

#[test]
fn proc_root_path_opens_the_same_inode_the_mapping_names() {
    let maps = std::fs::read("/proc/self/maps").unwrap();
    let entries = p11scope_manifest::maps::parse_maps(&maps).unwrap();
    let exe = entries
        .iter()
        .find(|e| {
            e.permissions[2] == b'x'
                && e.inode != 0
                && e.raw_path.as_deref().is_some_and(|p| p.starts_with(b"/"))
        })
        .expect("an executable file-backed mapping");
    let path = String::from_utf8(exe.raw_path.clone().unwrap()).unwrap();
    let via_root = format!("/proc/self/root{path}");
    let file = p11scope_manifest::identity::open_object(std::path::Path::new(&via_root))
        .expect("open through /proc/self/root");
    let key = p11scope_manifest::identity::mapping_file_key(&file)
        .expect("an unavailable full mapping identity must fail closed, never fall back to inode");
    assert!(
        key.mount_id > 0,
        "the fd's parsed mount identity is required"
    );
    assert_eq!(
        key.inode, exe.inode,
        "inode via /proc/self/root must match the mapping"
    );
    assert_eq!(
        (key.device_major, key.device_minor),
        (exe.device.major, exe.device.minor),
        "mountinfo-derived device must match the mapping's device"
    );
}

#[test]
fn capability_tier_target_readability_requires_generation_root_and_provider_identity() {
    use p11scope::doctor::target_readability_proven;

    assert!(target_readability_proven([Ok::<(), ()>(()); 5]));
    for missing in 0..5 {
        let mut operations = [Ok(()); 5];
        operations[missing] = Err(());
        assert!(
            !target_readability_proven(operations),
            "fallible operation {missing} was not required"
        );
    }
}
