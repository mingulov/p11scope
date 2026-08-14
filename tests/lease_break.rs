use p11scope_manifest::manifest::*;
use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static FORK_TEST: Mutex<()> = Mutex::new(());

fn protected_tempdir() -> tempfile::TempDir {
    let directory = tempfile::Builder::new().tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn spawn_single_threaded(run: impl FnOnce() -> i32) -> libc::pid_t {
    // SAFETY: the child performs the test protocol and terminates with _exit;
    // the parent only receives its pid and waits below.
    let pid = unsafe { libc::fork() };
    assert_ne!(pid, -1, "fork failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        let code = run();
        unsafe { libc::_exit(code) }
    }
    pid
}

fn wait_status(pid: libc::pid_t) -> libc::c_int {
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            return status;
        }
        assert_eq!(waited, -1);
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::Interrupted
        );
    }
}

fn wait_status_bounded(pid: libc::pid_t) -> libc::c_int {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return status;
        }
        assert_eq!(
            waited,
            0,
            "waitpid failed: {}",
            std::io::Error::last_os_error()
        );
        if Instant::now() >= deadline {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let _ = wait_status(pid);
            panic!("process {pid} exceeded the supervisor test deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} was not created",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_stopped_process(pid: libc::pid_t) {
    let status = format!("/proc/{pid}/status");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if std::fs::read_to_string(&status)
            .is_ok_and(|text| text.lines().any(|line| line.starts_with("State:\tT")))
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "process {pid} did not enter stopped state"
        );
        std::thread::yield_now();
    }
}

fn profile_temp_path(directory: &Path) -> std::path::PathBuf {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .contains("p11scope")
        })
        .expect("same-directory profile temp")
}

fn wait_for_child(parent: libc::pid_t) -> libc::pid_t {
    let children = format!("/proc/{parent}/task/{parent}/children");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(text) = std::fs::read_to_string(&children)
            && let Some(child) = text.split_whitespace().next()
        {
            return child.parse().unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "parent {parent} never forked a worker"
        );
        std::thread::yield_now();
    }
}

fn pidfd_open(pid: libc::pid_t) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as libc::c_int;
    assert_ne!(
        fd,
        -1,
        "pidfd_open failed: {}",
        std::io::Error::last_os_error()
    );
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn pidfd_exited(pidfd: &OwnedFd, timeout_ms: libc::c_int) -> bool {
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_ne!(
        unsafe { libc::poll(&mut pollfd, 1, timeout_ms) },
        -1,
        "pidfd poll failed: {}",
        std::io::Error::last_os_error()
    );
    pollfd.revents & libc::POLLIN != 0
}

fn send_worker_control(packet: u8) -> Result<(), String> {
    for entry in std::fs::read_dir("/proc/self/fd").map_err(|error| error.to_string())? {
        let fd: libc::c_int = match entry
            .map_err(|error| error.to_string())?
            .file_name()
            .to_string_lossy()
            .parse()
        {
            Ok(fd) if fd > libc::STDERR_FILENO => fd,
            _ => continue,
        };
        let mut socket_type = 0;
        let mut length = std::mem::size_of_val(&socket_type) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut socket_type as *mut libc::c_int).cast(),
                &mut length,
            )
        } == 0
            && socket_type == libc::SOCK_SEQPACKET
            && unsafe { libc::send(fd, (&packet as *const u8).cast(), 1, 0) } == 1
        {
            return Ok(());
        }
    }
    Err("capture worker control socket was not found".into())
}

fn full_pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0,
        "pipe2 failed: {}",
        std::io::Error::last_os_error()
    );
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    let bytes = [0u8; 4096];
    loop {
        let written = unsafe { libc::write(write.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if written >= 0 {
            continue;
        }
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let flags = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1);
        assert_ne!(
            unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) },
            -1
        );
        return (read, write);
    }
}

fn build_cli_fixture(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let provider = dir.join("provider.so");
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&provider)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("crates/discover/tests/fixture/version_matrix.c"),
            )
            .status()
            .unwrap()
            .success()
    );
    let mut manifest = p11scope_discover::discover::discover(&provider).unwrap();
    let provider_sha = manifest.objects[0].identity.sha256.as_deref().unwrap();
    manifest
        .provenance_objects
        .retain(|object| object.identity.sha256.as_deref() == Some(provider_sha));
    let manifest_path = dir.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

    let observer = dir.join("p11scope");
    std::fs::copy(env!("CARGO_BIN_EXE_p11scope"), &observer).unwrap();
    std::fs::set_permissions(&observer, std::fs::Permissions::from_mode(0o755)).unwrap();
    let oracle_source = dir.join("oracle.c");
    let oracle_ran = dir.join("oracle-ran");
    std::fs::write(
        &oracle_source,
        format!(
            "#include <stdio.h>\nint main(void) {{ FILE *m=fopen({:?},\"wb\"); if(!m)return 3; fclose(m); FILE *f=fopen({:?},\"rb\"); int c; if(!f)return 2; while((c=fgetc(f))!=EOF)fputc(c,stdout); return ferror(f)||ferror(stdout); }}\n",
            oracle_ran.display().to_string(),
            manifest_path.display().to_string(),
        ),
    )
    .unwrap();
    let oracle = dir.join("p11scope-discover");
    assert!(
        Command::new("gcc")
            .args(["-o"])
            .arg(&oracle)
            .arg(&oracle_source)
            .status()
            .unwrap()
            .success()
    );
    std::fs::set_permissions(&oracle, std::fs::Permissions::from_mode(0o755)).unwrap();
    (provider, manifest_path, oracle_ran)
}

fn finish(outcome: p11scope::verify::SupervisorOutcome) -> ! {
    match outcome {
        p11scope::verify::SupervisorOutcome::Exited(code) => unsafe { libc::_exit(code) },
        p11scope::verify::SupervisorOutcome::LeaseBroken => unsafe {
            libc::_exit(p11scope::verify::OBJECT_CHANGED_EXIT)
        },
        p11scope::verify::SupervisorOutcome::Signaled(signal) => {
            p11scope::verify::mirror_worker_signal(signal)
        }
    }
}

fn manifest_for(object: &Path) -> Manifest {
    let file = p11scope_manifest::identity::open_object(object).unwrap();
    let key = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
    let identity = p11scope_manifest::identity::inspect_file(&file)
        .unwrap()
        .identity;
    Manifest {
        schema: SCHEMA.into(),
        module_path: object.display().to_string(),
        objects: vec![ObjectRecord {
            id: 0,
            path: object.display().to_string(),
            identity: identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path: object.display().to_string(),
            device_major: key.device_major,
            device_minor: key.device_minor,
            inode: key.inode,
            identity,
        }],
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Absent,
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: vec![],
        }],
        vendor_interfaces: vec![],
        alias_groups: vec![],
    }
}

#[test]
fn supervisor_refuses_to_fork_a_multithreaded_process() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let pid = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::trace(
            None,
            p11scope::attach::CapturePolicy::Allowlisted,
        )
        .unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || wait.recv().unwrap());
        let error = p11scope::verify::supervise_capture(signals, objects, output, |_| Ok(()))
            .expect_err("forking with another live thread must be refused");
        release.send(()).unwrap();
        thread.join().unwrap();
        i32::from(!error.contains("single-threaded"))
    });

    let status = wait_status_bounded(pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

#[test]
fn trace_abort_sink_must_be_a_regular_file() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let sink = dir.path().join("sink");
    std::os::unix::fs::symlink("/dev/null", &sink).unwrap();

    let error = match p11scope::verify::SupervisorOutput::trace(
        Some(sink),
        p11scope::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
    ) {
        Ok(_) => panic!("mandatory trace abort delivery requires a regular-file sink"),
        Err(error) => error,
    };

    assert!(error.contains("regular file"), "{error}");
}

#[test]
fn real_cli_refuses_preexisting_threads_before_lease_acquisition() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let (provider, manifest, oracle_ran) = build_cli_fixture(dir.path());
    let preload_source = dir.path().join("thread.c");
    let preload = dir.path().join("thread.so");
    std::fs::write(
        &preload_source,
        "#include <pthread.h>\n#include <unistd.h>\nstatic void *hold(void *p){(void)p;for(;;)pause();}\n__attribute__((constructor))static void start(void){pthread_t t;pthread_create(&t,0,hold,0);}\n",
    )
    .unwrap();
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-pthread", "-o"])
            .arg(&preload)
            .arg(&preload_source)
            .status()
            .unwrap()
            .success()
    );

    let output = Command::new(dir.path().join("p11scope"))
        .args(["profile", "--manifest"])
        .arg(manifest)
        .arg("--provenance-module")
        .arg(provider)
        .args([
            "--pid",
            &std::process::id().to_string(),
            "--trusted-workload",
            "--duration",
            "0",
        ])
        .env("LD_PRELOAD", preload)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("single-threaded process"), "{stderr}");
    assert!(!stderr.contains("loading BPF object"), "{stderr}");
    assert!(
        !oracle_ran.exists(),
        "discovery/lease work began before multithreaded refusal"
    );
}

#[test]
fn lease_signal_owner_is_the_supervisor_not_the_worker() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();

    let pid = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let manifest = manifest_for(&child_object);
        let objects = p11scope::verify::check_reuse(&manifest).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(None).unwrap();
        let outcome = p11scope::verify::supervise_capture(signals, objects, output, |worker| {
            let fd: libc::c_int = worker
                .objects()
                .attach_path(&manifest.module_path)?
                .file_name()
                .unwrap()
                .to_string_lossy()
                .parse()
                .map_err(|error| format!("parsing inherited object fd: {error}"))?;
            let owner = unsafe { libc::fcntl(fd, libc::F_GETOWN) };
            if owner != unsafe { libc::getppid() } {
                return Err(format!(
                    "lease signal owner {owner} is not supervisor {}",
                    unsafe { libc::getppid() }
                ));
            }
            Ok(())
        })
        .unwrap();
        finish(outcome)
    });

    let status = wait_status_bounded(pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

#[test]
fn normal_completion_atomically_publishes_profile_output() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let profile = dir.path().join("profile.json");
    let worker_pid_path = dir.path().join("worker.pid");
    let release = dir.path().join("release");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_profile = profile.clone();
    let child_worker_pid_path = worker_pid_path.clone();
    let child_release = release.clone();

    let pid = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(Some(child_profile)).unwrap();
        let outcome = p11scope::verify::supervise_capture(signals, objects, output, |worker| {
            worker
                .output()
                .unwrap()
                .write_all(br#"{"complete":true}"#)
                .map_err(|error| error.to_string())?;
            std::fs::write(child_worker_pid_path, std::process::id().to_string())
                .map_err(|error| error.to_string())?;
            while !child_release.exists() {
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        })
        .unwrap();
        finish(outcome)
    });

    wait_for_file(&worker_pid_path);
    assert!(
        !profile.exists(),
        "profile was visible before normal completion"
    );
    assert!(
        std::fs::read_dir(dir.path()).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("p11scope")),
        "same-directory temporary profile was not prepared"
    );
    assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
    let mut stopped = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut stopped, libc::WUNTRACED) },
        pid
    );
    assert!(libc::WIFSTOPPED(stopped));
    let worker: libc::pid_t = std::fs::read_to_string(&worker_pid_path)
        .unwrap()
        .parse()
        .unwrap();
    let worker_pidfd = pidfd_open(worker);
    std::fs::write(release, b"go").unwrap();
    assert!(pidfd_exited(&worker_pidfd, 1_000));
    assert!(
        !profile.exists(),
        "profile was published before pidfd-confirmed exit"
    );
    assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
    let status = wait_status(pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(profile).unwrap()).unwrap(),
        serde_json::json!({"complete": true})
    );
}

#[test]
fn substituted_profile_temp_is_never_published_or_removed_as_cleanup() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let profile = dir.path().join("profile.json");
    let worker_pid_path = dir.path().join("worker.pid");
    let supervisor_error = dir.path().join("supervisor.error");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_profile = profile.clone();
    let child_worker_pid_path = worker_pid_path.clone();
    let child_supervisor_error = supervisor_error.clone();

    let supervisor = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(Some(child_profile)).unwrap();
        let result = p11scope::verify::supervise_capture(signals, objects, output, |worker| {
            worker
                .output()
                .unwrap()
                .write_all(br#"{"trusted":true}"#)
                .map_err(|error| error.to_string())?;
            std::fs::write(child_worker_pid_path, std::process::id().to_string())
                .map_err(|error| error.to_string())?;
            unsafe { libc::raise(libc::SIGSTOP) };
            Ok(())
        });
        match result {
            Err(error) => {
                std::fs::write(child_supervisor_error, &error).unwrap();
                i32::from(!error.contains("identity"))
            }
            Ok(outcome) => finish(outcome),
        }
    });

    wait_for_file(&worker_pid_path);
    let worker: libc::pid_t = std::fs::read_to_string(&worker_pid_path)
        .unwrap()
        .parse()
        .unwrap();
    wait_for_stopped_process(worker);
    let temp = profile_temp_path(dir.path());
    std::fs::remove_file(&temp).unwrap();
    std::fs::write(&temp, br#"{"attacker":true}"#).unwrap();
    assert_eq!(unsafe { libc::kill(worker, libc::SIGCONT) }, 0);

    let status = wait_status_bounded(supervisor);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert!(
        !profile.exists(),
        "replacement reached the final profile name"
    );
    assert_eq!(
        std::fs::read(&temp).unwrap(),
        br#"{"attacker":true}"#,
        "cleanup removed or changed the substituted entry"
    );
    assert!(
        std::fs::read_to_string(supervisor_error)
            .unwrap()
            .contains("identity")
    );
}

#[test]
fn abnormal_completion_removes_the_profile_temp_and_preserves_exit_status() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let profile = dir.path().join("profile.json");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_profile = profile.clone();

    let pid = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(Some(child_profile)).unwrap();
        let outcome = p11scope::verify::supervise_capture(signals, objects, output, |worker| {
            worker
                .output()
                .unwrap()
                .write_all(b"partial")
                .map_err(|error| error.to_string())?;
            Err("capture failed".into())
        })
        .unwrap();
        finish(outcome)
    });

    let status = wait_status_bounded(pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 1);
    assert!(!profile.exists());
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("p11scope")
    }));
}

#[test]
fn worker_panic_removes_the_profile_temp_and_exits_101() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let profile = dir.path().join("profile.json");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_profile = profile.clone();

    let pid = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(Some(child_profile)).unwrap();
        let outcome = p11scope::verify::supervise_capture(signals, objects, output, |_| {
            panic!("capture panicked")
        })
        .unwrap();
        finish(outcome)
    });

    let status = wait_status_bounded(pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 101);
    assert!(!profile.exists());
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("p11scope")
    }));
}

#[test]
fn failed_record_allows_a_delayed_nonzero_exit_status() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let profile = dir.path().join("profile.json");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_profile = profile.clone();

    let pid = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(Some(child_profile)).unwrap();
        let outcome = p11scope::verify::supervise_capture(signals, objects, output, |worker| {
            worker
                .output()
                .unwrap()
                .write_all(b"partial")
                .map_err(|error| error.to_string())?;
            send_worker_control(b'F')?;
            std::thread::sleep(Duration::from_millis(50));
            unsafe { libc::_exit(23) }
        })
        .unwrap();
        finish(outcome)
    });

    let status = wait_status_bounded(pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 23);
    assert!(!profile.exists());
}

#[test]
fn failed_record_followed_by_zero_is_a_protocol_error() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let profile = dir.path().join("profile.json");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_profile = profile.clone();

    let pid = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(Some(child_profile)).unwrap();
        match p11scope::verify::supervise_capture(signals, objects, output, |worker| {
            worker
                .output()
                .unwrap()
                .write_all(b"partial")
                .map_err(|error| error.to_string())?;
            send_worker_control(b'F')?;
            std::thread::sleep(Duration::from_millis(50));
            unsafe { libc::_exit(0) }
        }) {
            Err(error) if error.contains("reported failure") => 0,
            _ => 1,
        }
    });

    let status = wait_status_bounded(pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert!(!profile.exists());
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("p11scope")
    }));
}

#[test]
fn externally_killed_worker_releases_lease_cleans_profile_and_mirrors_sigkill() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let profile = dir.path().join("profile.json");
    let worker_pid_path = dir.path().join("worker.pid");
    let writer_result = dir.path().join("writer.result");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_profile = profile.clone();
    let child_worker_pid_path = worker_pid_path.clone();

    let supervisor = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(Some(child_profile)).unwrap();
        let outcome =
            p11scope::verify::supervise_capture(signals, objects, output, move |worker| {
                worker
                    .output()
                    .unwrap()
                    .write_all(b"partial")
                    .map_err(|error| error.to_string())?;
                std::fs::write(child_worker_pid_path, std::process::id().to_string())
                    .map_err(|error| error.to_string())?;
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            })
            .unwrap();
        finish(outcome)
    });

    wait_for_file(&worker_pid_path);
    let worker: libc::pid_t = std::fs::read_to_string(&worker_pid_path)
        .unwrap()
        .parse()
        .unwrap();
    let worker_pidfd = pidfd_open(worker);
    assert_eq!(unsafe { libc::kill(supervisor, libc::SIGSTOP) }, 0);
    let mut stopped = 0;
    assert_eq!(
        unsafe { libc::waitpid(supervisor, &mut stopped, libc::WUNTRACED) },
        supervisor
    );
    assert!(libc::WIFSTOPPED(stopped));
    assert_eq!(unsafe { libc::kill(worker, libc::SIGKILL) }, 0);
    assert!(pidfd_exited(&worker_pidfd, 1_000));
    assert!(!profile.exists());
    assert_eq!(unsafe { libc::kill(supervisor, libc::SIGCONT) }, 0);
    let supervisor_status = wait_status_bounded(supervisor);
    assert!(libc::WIFSIGNALED(supervisor_status));
    assert_eq!(libc::WTERMSIG(supervisor_status), libc::SIGKILL);

    let writer_object = object.clone();
    let writer_result_path = writer_result.clone();
    let writer = spawn_single_threaded(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .open(writer_object)
            .unwrap();
        let worker_is_gone = unsafe { libc::kill(worker, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        std::fs::write(
            writer_result_path,
            if worker_is_gone {
                &b"gone"[..]
            } else {
                &b"alive"[..]
            },
        )
        .unwrap();
        i32::from(!worker_is_gone)
    });
    let writer_status = wait_status_bounded(writer);
    assert!(libc::WIFEXITED(writer_status));
    assert_eq!(libc::WEXITSTATUS(writer_status), 0);
    assert_eq!(std::fs::read(writer_result).unwrap(), b"gone");
    assert!(!profile.exists());
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("p11scope")
    }));
}

#[test]
fn failed_worker_that_stops_is_killed_before_leases_are_released() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let profile = dir.path().join("profile.json");
    let worker_pid_path = dir.path().join("worker.pid");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_profile = profile.clone();
    let child_worker_pid_path = worker_pid_path.clone();

    let supervisor = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(Some(child_profile)).unwrap();
        let outcome =
            p11scope::verify::supervise_capture(signals, objects, output, move |worker| {
                worker
                    .output()
                    .unwrap()
                    .write_all(b"partial")
                    .map_err(|error| error.to_string())?;
                std::fs::write(child_worker_pid_path, std::process::id().to_string())
                    .map_err(|error| error.to_string())?;
                send_worker_control(b'F')?;
                unsafe { libc::raise(libc::SIGSTOP) };
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            })
            .unwrap();
        finish(outcome)
    });

    wait_for_file(&worker_pid_path);
    let worker: libc::pid_t = std::fs::read_to_string(&worker_pid_path)
        .unwrap()
        .parse()
        .unwrap();
    let supervisor_status = wait_status_bounded(supervisor);
    assert!(libc::WIFSIGNALED(supervisor_status));
    assert_eq!(libc::WTERMSIG(supervisor_status), libc::SIGKILL);
    assert_eq!(unsafe { libc::kill(worker, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    assert!(!profile.exists());
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("p11scope")
    }));
    std::fs::OpenOptions::new()
        .write(true)
        .open(object)
        .expect("writer must proceed only after the stopped worker is gone");
}

#[test]
fn lease_break_kills_a_stopped_worker_before_the_writer_and_records_abort() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let worker_pid_path = dir.path().join("worker.pid");
    let writer_result = dir.path().join("writer.result");
    let trace = dir.path().join("trace.log");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_worker_pid_path = worker_pid_path.clone();
    let child_trace = trace.clone();
    let (_full_stdout_read, full_stdout_write) = full_pipe();

    let supervisor = spawn_single_threaded(move || {
        assert_ne!(
            unsafe { libc::dup2(full_stdout_write.as_raw_fd(), libc::STDOUT_FILENO) },
            -1
        );
        drop(full_stdout_write);
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::trace(
            Some(child_trace),
            p11scope::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        )
        .unwrap();
        let outcome = p11scope::verify::supervise_capture(signals, objects, output, move |_| {
            std::fs::write(&child_worker_pid_path, std::process::id().to_string())
                .map_err(|error| error.to_string())?;
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        })
        .unwrap();
        finish(outcome)
    });

    wait_for_file(&worker_pid_path);
    let worker: libc::pid_t = std::fs::read_to_string(&worker_pid_path)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(unsafe { libc::kill(worker, libc::SIGSTOP) }, 0);
    let writer_object = object.clone();
    let writer_result_path = writer_result.clone();
    let started = Instant::now();
    let writer = spawn_single_threaded(move || {
        let _file = std::fs::OpenOptions::new()
            .write(true)
            .open(writer_object)
            .unwrap();
        let gone = unsafe { libc::kill(worker, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        std::fs::write(
            writer_result_path,
            if gone { &b"gone"[..] } else { &b"alive"[..] },
        )
        .unwrap();
        i32::from(!gone)
    });

    let supervisor_status = wait_status_bounded(supervisor);
    let writer_status = wait_status_bounded(writer);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "blocked stdout delayed lease release/exit for {:?}",
        started.elapsed()
    );
    assert!(libc::WIFEXITED(supervisor_status));
    assert_eq!(
        libc::WEXITSTATUS(supervisor_status),
        p11scope::verify::OBJECT_CHANGED_EXIT
    );
    assert!(libc::WIFEXITED(writer_status));
    assert_eq!(libc::WEXITSTATUS(writer_status), 0);
    assert_eq!(std::fs::read(writer_result).unwrap(), b"gone");
    let trace = std::fs::read_to_string(trace).unwrap();
    assert!(trace.starts_with("\nEVIDENCE "), "{trace:?}");
    assert!(trace.contains(r#""capture_aborted":"object_lease_break""#));
    assert!(trace.contains(r#""event_loss":null"#));
    assert!(!trace.contains("LOST"));
}

#[test]
fn pending_break_at_start_barrier_never_enters_capture_worker() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let leased = dir.path().join("leased");
    let worker_started = dir.path().join("worker-started");
    let trace = dir.path().join("trace.log");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_leased = leased.clone();
    let child_worker_started = worker_started.clone();
    let child_trace = trace.clone();

    let supervisor = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::trace(
            Some(child_trace),
            p11scope::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        )
        .unwrap();
        std::fs::write(child_leased, b"ready").unwrap();
        assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
        let outcome = p11scope::verify::supervise_capture(signals, objects, output, move |_| {
            std::fs::write(child_worker_started, b"started").map_err(|error| error.to_string())?;
            Ok(())
        })
        .unwrap();
        finish(outcome)
    });

    wait_for_file(&leased);
    let mut stopped = 0;
    assert_eq!(
        unsafe { libc::waitpid(supervisor, &mut stopped, libc::WUNTRACED) },
        supervisor
    );
    assert!(libc::WIFSTOPPED(stopped));
    let writer_object = object.clone();
    let writer = spawn_single_threaded(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .open(writer_object)
            .unwrap();
        0
    });
    assert_eq!(unsafe { libc::kill(supervisor, libc::SIGCONT) }, 0);

    let supervisor_status = wait_status_bounded(supervisor);
    let writer_status = wait_status_bounded(writer);
    assert!(libc::WIFEXITED(supervisor_status));
    assert_eq!(
        libc::WEXITSTATUS(supervisor_status),
        p11scope::verify::OBJECT_CHANGED_EXIT
    );
    assert!(libc::WIFEXITED(writer_status));
    assert_eq!(libc::WEXITSTATUS(writer_status), 0);
    assert!(!worker_started.exists());
    assert!(
        std::fs::read_to_string(trace)
            .unwrap()
            .contains(r#""capture_aborted":"object_lease_break""#)
    );
}

#[test]
fn supervisor_death_kills_a_worker_blocked_in_output_and_releases_its_lease() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let worker_pid_path = dir.path().join("worker.pid");
    let trace = dir.path().join("trace.log");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_worker_pid_path = worker_pid_path.clone();
    let child_trace = trace.clone();
    let (_full_stdout_read, full_stdout_write) = full_pipe();

    let supervisor = spawn_single_threaded(move || {
        assert_ne!(
            unsafe { libc::dup2(full_stdout_write.as_raw_fd(), libc::STDOUT_FILENO) },
            -1
        );
        drop(full_stdout_write);
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::trace(
            Some(child_trace),
            p11scope::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        )
        .unwrap();
        let outcome =
            p11scope::verify::supervise_capture(signals, objects, output, move |worker| {
                std::fs::write(child_worker_pid_path, std::process::id().to_string())
                    .map_err(|error| error.to_string())?;
                worker
                    .stdout()
                    .write_all(b"blocked")
                    .map_err(|error| error.to_string())
            })
            .unwrap();
        finish(outcome)
    });

    wait_for_file(&worker_pid_path);
    let worker: libc::pid_t = std::fs::read_to_string(&worker_pid_path)
        .unwrap()
        .parse()
        .unwrap();
    let worker_pidfd = pidfd_open(worker);
    let writer_object = object.clone();
    let writer = spawn_single_threaded(move || {
        std::fs::OpenOptions::new()
            .write(true)
            .open(writer_object)
            .unwrap();
        0
    });
    assert_eq!(unsafe { libc::kill(supervisor, libc::SIGKILL) }, 0);
    let supervisor_status = wait_status_bounded(supervisor);
    let worker_exited = pidfd_exited(&worker_pidfd, 1_000);
    if !worker_exited {
        unsafe { libc::kill(worker, libc::SIGKILL) };
    }
    let writer_status = wait_status_bounded(writer);

    assert!(libc::WIFSIGNALED(supervisor_status));
    assert_eq!(libc::WTERMSIG(supervisor_status), libc::SIGKILL);
    assert!(
        worker_exited,
        "PDEATHSIG did not terminate the blocked worker"
    );
    assert!(libc::WIFEXITED(writer_status));
    assert_eq!(libc::WEXITSTATUS(writer_status), 0);
}

#[test]
fn parent_death_setup_race_cannot_leave_an_orphan_worker() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    std::fs::copy("/bin/true", &object).unwrap();

    for _ in 0..32 {
        let child_object = object.clone();
        let supervisor = spawn_single_threaded(move || {
            let signals = p11scope::verify::CaptureSignals::block().unwrap();
            let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
            let output = p11scope::verify::SupervisorOutput::profile(None).unwrap();
            let outcome = p11scope::verify::supervise_capture(signals, objects, output, |_| {
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            })
            .unwrap();
            finish(outcome)
        });
        let worker = wait_for_child(supervisor);
        let worker_pidfd = pidfd_open(worker);
        assert_eq!(unsafe { libc::kill(supervisor, libc::SIGKILL) }, 0);
        let status = wait_status_bounded(supervisor);
        assert!(libc::WIFSIGNALED(status));
        let exited = pidfd_exited(&worker_pidfd, 1_000);
        if !exited {
            unsafe { libc::kill(worker, libc::SIGKILL) };
        }
        assert!(
            exited,
            "worker {worker} survived the parent-death setup race"
        );
    }
}

#[test]
fn sigint_stops_the_worker_cleanly_and_preserves_normal_status() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let ready = dir.path().join("ready");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_ready = ready.clone();

    let supervisor = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(None).unwrap();
        let outcome =
            p11scope::verify::supervise_capture(signals, objects, output, move |worker| {
                let interrupted = Arc::new(AtomicBool::new(false));
                signal_hook::flag::register(libc::SIGINT, Arc::clone(&interrupted)).unwrap();
                worker.unblock_operator_signals()?;
                std::fs::write(child_ready, b"ready").map_err(|error| error.to_string())?;
                while !interrupted.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(())
            })
            .unwrap();
        finish(outcome)
    });

    wait_for_file(&ready);
    assert_eq!(unsafe { libc::kill(supervisor, libc::SIGINT) }, 0);
    let status = wait_status_bounded(supervisor);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

#[test]
fn sigterm_preserves_terminating_signal_status() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let ready = dir.path().join("ready");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_ready = ready.clone();

    let supervisor = spawn_single_threaded(move || {
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(None).unwrap();
        let outcome =
            p11scope::verify::supervise_capture(signals, objects, output, move |worker| {
                worker.unblock_operator_signals()?;
                std::fs::write(child_ready, b"ready").map_err(|error| error.to_string())?;
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            })
            .unwrap();
        finish(outcome)
    });

    wait_for_file(&ready);
    assert_eq!(unsafe { libc::kill(supervisor, libc::SIGTERM) }, 0);
    let status = wait_status_bounded(supervisor);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGTERM);
}

#[test]
fn sigterm_ignored_by_the_original_process_is_reset_for_the_worker() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let ready = dir.path().join("ready");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_ready = ready.clone();

    let supervisor = spawn_single_threaded(move || {
        unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(None).unwrap();
        let outcome =
            p11scope::verify::supervise_capture(signals, objects, output, move |worker| {
                worker.unblock_operator_signals()?;
                std::fs::write(child_ready, b"ready").map_err(|error| error.to_string())?;
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            })
            .unwrap();
        finish(outcome)
    });

    wait_for_file(&ready);
    assert_eq!(unsafe { libc::kill(supervisor, libc::SIGTERM) }, 0);
    let status = wait_status_bounded(supervisor);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGTERM);
}

#[test]
fn sigterm_blocked_by_the_original_process_is_unblocked_when_mirrored() {
    let _serial = FORK_TEST.lock().unwrap();
    let dir = protected_tempdir();
    let object = dir.path().join("leased.so");
    let ready = dir.path().join("ready");
    std::fs::copy("/bin/true", &object).unwrap();
    let child_object = object.clone();
    let child_ready = ready.clone();

    let supervisor = spawn_single_threaded(move || {
        unsafe {
            let mut blocked = std::mem::zeroed();
            assert_eq!(libc::sigemptyset(&mut blocked), 0);
            assert_eq!(libc::sigaddset(&mut blocked, libc::SIGTERM), 0);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut()),
                0
            );
        }
        let signals = p11scope::verify::CaptureSignals::block().unwrap();
        let objects = p11scope::verify::check_reuse(&manifest_for(&child_object)).unwrap();
        let output = p11scope::verify::SupervisorOutput::profile(None).unwrap();
        let outcome =
            p11scope::verify::supervise_capture(signals, objects, output, move |worker| {
                worker.unblock_operator_signals()?;
                std::fs::write(child_ready, b"ready").map_err(|error| error.to_string())?;
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            })
            .unwrap();
        finish(outcome)
    });

    wait_for_file(&ready);
    assert_eq!(unsafe { libc::kill(supervisor, libc::SIGTERM) }, 0);
    let status = wait_status_bounded(supervisor);
    assert!(libc::WIFSIGNALED(status), "wait status {status:#x}");
    assert_eq!(libc::WTERMSIG(status), libc::SIGTERM);
}
