//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! A pid-scope trace names its target on stderr beside the readiness line
//! (`docs/usage.md`): `p11scope: target: pid <N> exe <path>`. Without it a
//! pid-scope trace never names its target anywhere — the trace rows label
//! early events `Unknown executable` and trace publishes no JSON report
//! carrying the caller identity. Regression test: `capture_trace` omitted
//! the unconditional target line that `capture_profile` prints.
//!
//! Privileged: the target line prints from a real BPF attach session. Run
//! as root: `cargo test --test trace_pid_target -- --ignored
//! --test-threads=1`.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::DieWithParent as _;

#[allow(dead_code)]
mod support;

/// The observer under test: the `P11SCOPE_E2E_OBSERVER` override when the
/// runner stages a prebuilt binary elsewhere, else the binary Cargo built
/// beside this test target.
fn bin() -> String {
    std::env::var("P11SCOPE_E2E_OBSERVER")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_p11scope").to_string())
}

/// Probe SoftHSM (Debian then Fedora paths); panic loudly when absent —
/// this cell needs the real provider, never a skip.
fn softhsm_path() -> String {
    for candidate in [
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
    ] {
        if std::path::Path::new(candidate).is_file() {
            return candidate.to_string();
        }
    }
    panic!("SoftHSM not installed (probed Debian and Fedora paths)");
}

/// ctypes fixture (stdlib only): materialize the provider function table
/// with `C_GetFunctionList`, issue three harmless info calls, print READY,
/// then hold the mapping open. No token, PIN, key or login is needed or
/// used; return values are ignored.
const FIXTURE_PY: &str = r#"
import ctypes
import sys
import time

lib = ctypes.CDLL(sys.argv[1])
lib.C_GetFunctionList.argtypes = [ctypes.c_void_p]
lib.C_GetFunctionList.restype = ctypes.c_ulong
lib.C_Initialize.argtypes = [ctypes.c_void_p]
lib.C_Initialize.restype = ctypes.c_ulong
lib.C_GetInfo.argtypes = [ctypes.c_void_p]
lib.C_GetInfo.restype = ctypes.c_ulong
lib.C_GetSlotList.argtypes = [ctypes.c_ubyte, ctypes.c_void_p, ctypes.c_void_p]
lib.C_GetSlotList.restype = ctypes.c_ulong

table = ctypes.c_void_p()
lib.C_GetFunctionList(ctypes.byref(table))
lib.C_Initialize(None)
info = (ctypes.c_ubyte * 256)()
lib.C_GetInfo(info)
count = ctypes.c_ulong(0)
lib.C_GetSlotList(0, None, ctypes.byref(count))
print("READY", flush=True)
time.sleep(120)
"#;

struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Poll a growing file for a needle without forking (a forking wait would
/// admit newcomer processes mid-capture). Panics past the deadline.
fn wait_for(path: &std::path::Path, needle: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(path)
            && String::from_utf8_lossy(&bytes).contains(needle)
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "timed out after {timeout:?} waiting for {needle:?} in {}",
        path.display()
    );
}

#[test]
#[ignore = "privileged: loads BPF; run as root with --ignored --test-threads=1"]
fn privileged_trace_pid_names_target_on_stderr() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run as root: the target line needs a real attach session"
    );
    let dir = tempfile::tempdir().unwrap();
    let fixture = dir.path().join("fixture.py");
    std::fs::write(&fixture, FIXTURE_PY).unwrap();
    let ready_path = dir.path().join("fixture.log");
    let ready_file = std::fs::File::create(&ready_path).unwrap();
    let target = Owned(
        Command::new("python3")
            .arg("-I")
            .arg(&fixture)
            .arg(softhsm_path())
            .stdin(Stdio::null())
            .stdout(ready_file)
            .stderr(Stdio::null())
            .die_with_parent()
            .spawn()
            .expect("spawn SoftHSM fixture"),
    );
    let pid = target.0.id().to_string();
    wait_for(&ready_path, "READY", Duration::from_secs(60));

    let stderr_path = dir.path().join("stderr");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();
    let mut observer = Owned(
        Command::new(bin())
            .args(["trace", "--pid", &pid, "--duration", "3"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr_file)
            .die_with_parent()
            .spawn()
            .expect("spawn p11scope trace"),
    );
    let deadline = Instant::now() + Duration::from_secs(180);
    let status = loop {
        if let Some(status) = observer.0.try_wait().expect("wait for observer") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = observer.0.kill();
            let _ = observer.0.wait();
            panic!("observer still running 180s after start");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let diagnostics = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    assert_eq!(status.code(), Some(0), "trace exit:\n{diagnostics}");
    assert!(
        diagnostics.contains("p11scope: capturing:"),
        "observer never reached capture:\n{diagnostics}"
    );
    assert!(
        diagnostics.contains(&format!("p11scope: target: pid {pid} exe ")),
        "pid-scope trace must name its target beside the readiness line:\n{diagnostics}"
    );
    drop(target);
}
