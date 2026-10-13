//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::io::{Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

// A separate socket holds the actual provider constructor inside dlopen.
// The command pipe stays available for the runner's readiness request.
const HELD_TABLED_CONSTRUCTOR_C: &str = r#"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
__attribute__((constructor)) static void held_tabled_constructor(void) {
    const char *path = getenv("P11S_TEST_CONSTRUCTOR_GATE");
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (path == NULL || strlen(path) >= sizeof(address.sun_path)) _exit(20);
    strcpy(address.sun_path, path);
    int gate = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (gate < 0 || connect(gate, (struct sockaddr *)&address, sizeof(address)) != 0)
        _exit(21);
    if (write(gate, "G", 1) != 1) _exit(22);
    char release;
    ssize_t got;
    do { got = read(gate, &release, 1); } while (got < 0 && errno == EINTR);
    if (got != 1 || release != 'g') _exit(23);
    close(gate);
}
"#;

fn held_constructor_fixture() -> (TabledSeedProvider, PathBuf, UnixStream) {
    let dir = tempfile::tempdir().unwrap();
    let gate_path = dir.path().join("constructor.sock");
    let listener = UnixListener::bind(&gate_path).unwrap();
    let source = dir.path().join("tabled-provider.c");
    let library = dir.path().join("tabled-provider.so");
    std::fs::write(
        &source,
        format!("{TABLED_PROVIDER_C}\n{HELD_TABLED_CONSTRUCTOR_C}"),
    )
    .unwrap();
    assert!(
        std::process::Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&library)
            .arg(&source)
            .status()
            .unwrap()
            .success()
    );
    let runner = compile_tabled_runner(dir.path());
    let child = std::process::Command::new(runner)
        .arg(&library)
        .arg(dir.path().join("unused-replacement.so"))
        .env("P11S_TEST_CONSTRUCTOR_GATE", &gate_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let fixture = TabledSeedProvider {
        child,
        peers: Vec::new(),
        dir,
    };
    listener.set_nonblocking(true).unwrap();
    assert!(system_scope_poll_fd(listener.as_raw_fd(), Duration::from_secs(5)).unwrap());
    let (mut gate, _) = listener.accept().unwrap();
    gate.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    gate.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut held = [0];
    gate.read_exact(&mut held).unwrap();
    assert_eq!(held, *b"G", "the real constructor has reached its hold");
    wait_tabled_mapping(fixture.child.id(), &library);
    (fixture, library, gate)
}

#[test]
fn tabled_readiness_waits_for_the_real_constructor_after_mapping() {
    let (mut fixture, library, mut gate) = held_constructor_fixture();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = wait_tabled_ready(&mut fixture.child, &library);
        ready_tx.send(result).unwrap();
        fixture
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let premature = ready_rx.recv_timeout(Duration::from_millis(100));
    gate.write_all(b"g").unwrap();
    let premature_return = premature.is_ok();
    let result = match premature {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap()
        }
        Err(error) => panic!("the owned readiness waiter ended: {error}"),
    };
    let mut fixture = waiter.join().unwrap();
    assert!(
        !premature_return,
        "mapping alone must not release readiness while the constructor is held"
    );
    result.unwrap();
    // Keep cleanup explicit as well as guarded on every assertion/error path.
    fixture.child.kill().unwrap();
    assert!(!fixture.child.wait().unwrap().success());
}

#[test]
fn tabled_readiness_refuses_a_runner_that_exits_before_loading() {
    let dir = tempfile::tempdir().unwrap();
    let runner = compile_tabled_runner(dir.path());
    let library = dir.path().join("missing-provider.so");
    let child = std::process::Command::new(runner)
        .arg(&library)
        .arg(&library)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut fixture = TabledSeedProvider {
        child,
        peers: Vec::new(),
        dir,
    };
    assert!(wait_tabled_ready(&mut fixture.child, &library).is_err());
    assert_eq!(fixture.child.wait().unwrap().code(), Some(3));
}
