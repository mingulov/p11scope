use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_p11scope-discover");
const PACKET_TIMEOUT_MS: i32 = 2_000;
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    dir: PathBuf,
    provider: PathBuf,
    marker: PathBuf,
    fd_marker: PathBuf,
}

impl Fixture {
    fn build() -> Self {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "control-protocol-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let provider = dir.join("provider.so");
        let marker_dir = dir.join("markers");
        std::fs::create_dir(&marker_dir).unwrap();
        std::fs::set_permissions(&marker_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let marker = marker_dir.join("constructor-marker");
        let fd_marker = marker_dir.join("fd-marker");
        let constructor = dir.join("constructor.c");
        std::fs::write(
            &constructor,
            r#"#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

static int one_read_only_self_memory_fd(void) {
    struct stat memory;
    if (stat("/proc/self/mem", &memory) != 0) return 0;
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return 0;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long fd = strtol(entry->d_name, &end, 10);
        if (!entry->d_name[0] || !end || *end || fd < 0) continue;
        struct stat opened;
        if (fstat((int)fd, &opened) != 0) continue;
        if (opened.st_dev == memory.st_dev && opened.st_ino == memory.st_ino &&
            (opened.st_mode & S_IFMT) == (memory.st_mode & S_IFMT)) {
            int flags = fcntl((int)fd, F_GETFL);
            if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY) {
                closedir(directory);
                return 0;
            }
            count++;
        }
    }
    closedir(directory);
    return count == 1;
}

__attribute__((constructor)) static void mark_constructor(void) {
    const char *state =
        prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0 &&
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1
            ? "secure\n" : "insecure\n";
    int fd = open(MARKER_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
        (void)write(fd, state, strlen(state));
        (void)close(fd);
    }
    const char *fd_state = one_read_only_self_memory_fd()
        ? "one-read-only-self-memory\n" : "invalid-self-memory-fds\n";
    fd = open(FD_MARKER_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
        (void)write(fd, fd_state, strlen(fd_state));
        (void)close(fd);
    }
}
"#,
        )
        .unwrap();
        let matrix = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture/version_matrix.c");
        let status = Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&provider)
            .arg(&matrix)
            .arg(&constructor)
            .arg(format!("-DMARKER_PATH=\"{}\"", marker.display()))
            .arg(format!("-DFD_MARKER_PATH=\"{}\"", fd_marker.display()))
            .status()
            .unwrap();
        assert!(status.success(), "gcc failed to build the barrier provider");
        std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o555)).unwrap();
        Self {
            dir,
            provider,
            marker,
            fd_marker,
        }
    }

    fn reset_marker(&self) {
        let _ = std::fs::remove_file(&self.marker);
    }

    fn assert_not_loaded(&self) {
        assert!(
            !self.marker.exists() && !self.fd_marker.exists(),
            "provider constructor ran before authorization"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct ControlledChild {
    child: Option<Child>,
    control: Option<OwnedFd>,
}

impl ControlledChild {
    fn packet(&self) -> Vec<u8> {
        recv_packet(self.control.as_ref().unwrap())
    }

    fn send(&self, packet: &[u8]) {
        send_packet(self.control.as_ref().unwrap(), packet);
    }

    fn close_control(&mut self) {
        self.control.take();
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    fn is_running(&mut self) -> bool {
        self.child.as_mut().unwrap().try_wait().unwrap().is_none()
    }

    fn output(mut self) -> Output {
        self.control.take();
        self.child.take().unwrap().wait_with_output().unwrap()
    }

    fn failed_output(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.child.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "helper did not reject control input"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        self.control.take();
        self.child.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for ControlledChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    assert_eq!(result, 0, "socketpair: {}", std::io::Error::last_os_error());
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn stream_pair() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    assert_eq!(result, 0, "socketpair: {}", std::io::Error::last_os_error());
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn pipe_pair() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(result, 0, "pipe2: {}", std::io::Error::last_os_error());
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn spawn_with_control_fd(provider: &Path, inherited: OwnedFd, control: OwnedFd) -> ControlledChild {
    let raw = inherited.as_raw_fd();
    let mut command = Command::new(BIN);
    command
        .arg("--module")
        .arg(provider)
        .arg("--control-fd")
        .arg(raw.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(raw, libc::F_GETFD);
            if flags == -1 || libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(inherited);
    ControlledChild {
        child: Some(child),
        control: Some(control),
    }
}

fn spawn_controlled(provider: &Path) -> ControlledChild {
    let (parent, child) = seqpacket_pair();
    spawn_with_control_fd(provider, child, parent)
}

fn recv_packet(fd: &OwnedFd) -> Vec<u8> {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&mut pollfd, 1, PACKET_TIMEOUT_MS) };
        if ready == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        assert_eq!(ready, 1, "timed out waiting for helper control packet");
        break;
    }
    let mut packet = [0u8; 32];
    let length = loop {
        let length = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
                libc::MSG_TRUNC,
            )
        };
        if length == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        break length;
    };
    assert!(length > 0, "helper control channel closed before a packet");
    let length = usize::try_from(length).unwrap();
    assert!(length <= packet.len(), "oversized helper control packet");
    packet[..length].to_vec()
}

fn send_packet(fd: &OwnedFd, packet: &[u8]) {
    let sent = loop {
        let sent = unsafe {
            libc::send(
                fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        break sent;
    };
    assert_eq!(sent, packet.len() as isize, "sending helper control packet");
}

fn assert_dropped_status(pid: u32) {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    for prefix in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap();
        assert_eq!(
            u64::from_str_radix(value.trim(), 16).unwrap(),
            0,
            "{prefix}"
        );
    }
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    if unsafe { libc::geteuid() } == 0 {
        assert_eq!(
            status
                .lines()
                .find_map(|line| line.strip_prefix("Groups:"))
                .unwrap()
                .trim(),
            ""
        );
    }
    for prefix in ["Uid:", "Gid:"] {
        let ids: Vec<u32> = status
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap()
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(ids.len(), 4);
        assert!(ids.iter().all(|value| *value == ids[0]));
        assert_ne!(ids[0], 0);
    }
}

#[test]
fn provider_load_waits_for_go() {
    let fixture = Fixture::build();
    let child = spawn_controlled(&fixture.provider);

    assert_eq!(child.packet(), b"PREPARED");
    fixture.assert_not_loaded();
    let mut retained_maps = File::open(format!("/proc/{}/maps", child.pid())).unwrap();
    child.send(b"DROP");

    assert_eq!(child.packet(), b"READY");
    fixture.assert_not_loaded();
    assert_dropped_status(child.pid());
    let mut maps = String::new();
    retained_maps.read_to_string(&mut maps).unwrap();
    assert!(!maps.contains(fixture.provider.to_str().unwrap()));

    child.send(b"GO");
    let output = child.output();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.marker).unwrap(),
        "secure\n"
    );
    let manifest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(manifest["schema"], "p11scope-manifest/4");
}

#[test]
fn controlled_helper_opens_one_read_only_self_memory_fd_after_drop() {
    let fixture = Fixture::build();
    let child = spawn_controlled(&fixture.provider);

    assert_eq!(child.packet(), b"PREPARED");
    fixture.assert_not_loaded();
    child.send(b"DROP");
    assert_eq!(child.packet(), b"READY");
    fixture.assert_not_loaded();
    child.send(b"GO");
    let output = child.output();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.fd_marker).unwrap(),
        "one-read-only-self-memory\n"
    );
}

#[test]
fn malformed_or_abandoned_barrier_never_loads_provider() {
    let fixture = Fixture::build();

    let child = spawn_controlled(&fixture.provider);
    assert_eq!(child.packet(), b"PREPARED");
    child.send(b"DROP-TOO-LONG");
    assert!(!child.failed_output().status.success());
    fixture.assert_not_loaded();

    let mut child = spawn_controlled(&fixture.provider);
    assert_eq!(child.packet(), b"PREPARED");
    child.close_control();
    assert!(!child.failed_output().status.success());
    fixture.assert_not_loaded();

    let mut child = spawn_controlled(&fixture.provider);
    assert_eq!(child.packet(), b"PREPARED");
    std::thread::sleep(Duration::from_millis(50));
    assert!(child.is_running(), "helper did not wait for DROP");
    fixture.assert_not_loaded();
    drop(child);

    let mut child = spawn_controlled(&fixture.provider);
    child.close_control();
    assert!(!child.failed_output().status.success());
    fixture.assert_not_loaded();

    let child = spawn_controlled(&fixture.provider);
    assert_eq!(child.packet(), b"PREPARED");
    child.send(b"DROP");
    assert_eq!(child.packet(), b"READY");
    child.send(b"NOT-GO");
    assert!(!child.failed_output().status.success());
    fixture.assert_not_loaded();

    let mut child = spawn_controlled(&fixture.provider);
    assert_eq!(child.packet(), b"PREPARED");
    child.send(b"DROP");
    assert_eq!(child.packet(), b"READY");
    child.close_control();
    assert!(!child.failed_output().status.success());
    fixture.assert_not_loaded();

    let (reader, writer) = pipe_pair();
    let child = spawn_with_control_fd(&fixture.provider, reader, writer);
    assert!(!child.failed_output().status.success());
    fixture.assert_not_loaded();

    let (parent, child_fd) = stream_pair();
    let child = spawn_with_control_fd(&fixture.provider, child_fd, parent);
    assert!(!child.failed_output().status.success());
    fixture.assert_not_loaded();
}

#[test]
fn standalone_helper_is_nondumpable() {
    let fixture = Fixture::build();
    fixture.reset_marker();
    let output = Command::new(BIN)
        .arg("--module")
        .arg(&fixture.provider)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.marker).unwrap(),
        "secure\n"
    );
}
