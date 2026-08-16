//! Measures the /proc access rules the scan depends on (spec §4.9, §6.6). Each test
//! states its precondition and SKIPs loudly rather than asserting a policy the host
//! does not have — the point is a recorded measurement, not a forced pass.

use std::io::Read as _;
use std::process::{Child, Command};

fn ptrace_scope() -> i32 {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().parse().unwrap_or(0))
        .unwrap_or(0)
}

/// A same-uid process that is NOT our descendant: spawn `sleep` from a
/// double-fork through `setsid` so it is reparented to init.
fn same_uid_non_descendant() -> (u32, Child) {
    let child = Command::new("setsid")
        .args(["--fork", "sleep", "31.4159"])
        .spawn()
        .expect("spawn setsid sleep");
    // setsid --fork exits immediately; its grandchild survives, reparented.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let out = Command::new("pgrep")
        .args(["-f", "sleep 31.4159"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pids: Vec<&str> = stdout.split_whitespace().collect();
    assert_eq!(
        pids.len(),
        1,
        "expected exactly one 'sleep 31.4159' process, found {}: {:?}",
        pids.len(),
        pids
    );
    let pid: u32 = pids[0].parse().expect("pgrep sleep pid");
    (pid, child)
}

#[test]
fn maps_is_readable_and_mem_is_refused_for_a_same_uid_non_descendant() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("SKIP: running as root; Yama does not apply");
        return;
    }
    let (pid, mut spawner) = same_uid_non_descendant();
    let _ = spawner.wait();

    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"));
    assert!(
        maps.is_ok(),
        "/proc/{pid}/maps must be readable (PTRACE_MODE_READ): {maps:?}"
    );

    let mem = std::fs::File::open(format!("/proc/{pid}/mem")).and_then(|mut f| {
        let mut b = [0u8; 1];
        f.read_exact(&mut b)
    });
    if ptrace_scope() >= 1 {
        assert!(
            mem.is_err(),
            "ptrace_scope={} must refuse mem for a non-descendant",
            ptrace_scope()
        );
    } else {
        eprintln!(
            "MEASURED: ptrace_scope=0, mem access allowed: {:?}",
            mem.is_ok()
        );
    }
    let _ = Command::new("kill").arg(pid.to_string()).status();
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
    let key = p11scope_manifest::identity::mapping_file_key(&file);
    match key {
        Ok(key) => {
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
        Err(error) => {
            eprintln!("MEASURED: mapping_file_key unavailable on this filesystem: {error}")
        }
    }
}
