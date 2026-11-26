//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Subprocess `-o` recovery diagnostics: ENOSPC saves produce exactly one
//! recovery line and exit 1, even when stderr itself is a closed pipe.

use std::collections::BTreeSet;
use std::os::fd::FromRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use support::DieWithParent as _;

#[path = "support/multi_host.rs"]
mod multi_host;

#[allow(dead_code)]
mod support;

fn bin() -> String {
    std::env::var("P11SCOPE_E2E_OBSERVER")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_p11scope").to_string())
}

fn capture_available() -> bool {
    p11scope::doctor::verdict(&p11scope::doctor::probe(None, None)) == 0
}

fn require_capture_positive(test: &str) {
    if std::env::var("P11SCOPE_REQUIRE_CAPTURE").as_deref() == Ok("1") {
        panic!("P11SCOPE_REQUIRE_CAPTURE=1 requires the positive branch ({test})");
    }
}

/// The production recovery dir this subprocess uses. The test removes only
/// files that appeared during its own injection run; a pre-existing dir or
/// unrelated file is never touched.
fn recovery_dir() -> PathBuf {
    PathBuf::from(format!("/var/tmp/p11scope-recovered-{}", unsafe {
        libc::geteuid()
    }))
}

fn recovery_files(dir: &Path) -> BTreeSet<PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect()
        })
        .unwrap_or_default()
}

struct RecoveryGuard {
    dir: PathBuf,
    before: BTreeSet<PathBuf>,
    dir_existed: bool,
}

impl RecoveryGuard {
    fn start() -> Self {
        let dir = recovery_dir();
        Self {
            before: recovery_files(&dir),
            dir_existed: dir.exists(),
            dir,
        }
    }

    fn new_files(&self) -> Vec<PathBuf> {
        recovery_files(&self.dir)
            .difference(&self.before)
            .cloned()
            .collect()
    }
}

impl Drop for RecoveryGuard {
    fn drop(&mut self) {
        for path in self.new_files() {
            let _ = std::fs::remove_file(path);
        }
        if !self.dir_existed {
            let _ = std::fs::remove_dir(&self.dir);
        }
    }
}

fn compile_injector(dir: &Path) -> PathBuf {
    let source = dir.join("enospc_inject.c");
    let library = dir.join("enospc_inject.so");
    std::fs::write(
        &source,
        r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

static ssize_t (*real_write_fn)(int, const void *, size_t);
static ssize_t (*real_writev_fn)(int, const struct iovec *, int);
static int (*real_fsync_fn)(int);
static int (*real_fdatasync_fn)(int);
static int sync_seen;

static int injected_fd(int fd) {
    const char *prefix = getenv("P11SCOPE_ENOSPC_PREFIX");
    char link[64];
    char target[PATH_MAX];
    ssize_t len;
    if (!prefix || !*prefix) return 0;
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    len = readlink(link, target, sizeof(target) - 1);
    if (len < 0) return 0;
    target[len] = '\0';
    return strncmp(target, prefix, strlen(prefix)) == 0;
}

static int write_mode(void) {
    const char *mode = getenv("P11SCOPE_ENOSPC_MODE");
    return mode && strcmp(mode, "write") == 0;
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (!real_write_fn) real_write_fn = dlsym(RTLD_NEXT, "write");
    if (write_mode() && injected_fd(fd)) {
        errno = ENOSPC;
        return -1;
    }
    return real_write_fn(fd, buf, count);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    if (!real_writev_fn) real_writev_fn = dlsym(RTLD_NEXT, "writev");
    if (write_mode() && injected_fd(fd)) {
        errno = ENOSPC;
        return -1;
    }
    return real_writev_fn(fd, iov, iovcnt);
}

static int inject_sync(int fd) {
    const char *mode = getenv("P11SCOPE_ENOSPC_MODE");
    if (!mode || strcmp(mode, "sync-after-first") != 0 || !injected_fd(fd)) return 0;
    /* The report writer's first sync proves the bytes reached the kernel.
       Every later commit/retry sync is the delayed ENOSPC. */
    if (__sync_fetch_and_add(&sync_seen, 1) == 0) return 0;
    errno = ENOSPC;
    return 1;
}

int fsync(int fd) {
    if (!real_fsync_fn) real_fsync_fn = dlsym(RTLD_NEXT, "fsync");
    if (inject_sync(fd)) return -1;
    return real_fsync_fn(fd);
}

int fdatasync(int fd) {
    if (!real_fdatasync_fn) real_fdatasync_fn = dlsym(RTLD_NEXT, "fdatasync");
    if (inject_sync(fd)) return -1;
    return real_fdatasync_fn(fd);
}
"#,
    )
    .unwrap();
    let status = Command::new("gcc")
        .args(["-shared", "-fPIC", "-O2", "-o"])
        .arg(&library)
        .arg(&source)
        .args(["-ldl"])
        .status()
        .expect("gcc builds the ENOSPC injector");
    assert!(status.success(), "gcc builds the ENOSPC injector");
    library
}

fn run_injected(
    args: &[String],
    inject_dir: &Path,
    injector: &Path,
    mode: &str,
    closed_stderr: bool,
) -> (Output, RecoveryGuard) {
    let guard = RecoveryGuard::start();
    let mut command = Command::new(bin());
    command
        .args(args)
        .stdin(Stdio::null())
        .env("LD_PRELOAD", injector)
        .env("P11SCOPE_ENOSPC_PREFIX", inject_dir)
        .env("P11SCOPE_ENOSPC_MODE", mode);
    let output = if closed_stderr {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        assert_eq!(unsafe { libc::close(fds[0]) }, 0);
        let writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        let child = command
            .stdout(Stdio::null())
            .stderr(writer)
            .die_with_parent()
            .spawn()
            .expect("spawn injected observer");
        child
            .wait_with_output()
            .expect("wait for injected observer")
    } else {
        command.output().expect("run injected observer")
    };
    (output, guard)
}

struct SleepTarget {
    child: std::process::Child,
}

impl SleepTarget {
    fn spawn() -> Self {
        let child = Command::new("sleep")
            .arg("287.4139")
            .die_with_parent()
            .spawn()
            .expect("spawn sleep target");
        Self { child }
    }

    fn pid(&self) -> String {
        self.child.id().to_string()
    }
}

impl Drop for SleepTarget {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn private_output_dir(path: &Path) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn cases(root: &Path, target: Option<&SleepTarget>) -> Vec<(String, Vec<String>, &'static str)> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/inventory-diff/scan-current.json");
    let mut cases = Vec::new();
    if let Some(target) = target {
        let out = root.join("profile-out");
        private_output_dir(&out);
        cases.push((
            "profile".to_string(),
            vec![
                "profile".into(),
                "--pid".into(),
                target.pid(),
                "--duration".into(),
                "1".into(),
                "-o".into(),
                out.join("profile.json").display().to_string(),
            ],
            "sync-after-first",
        ));
    }
    let cbom_out = root.join("cbom-out");
    private_output_dir(&cbom_out);
    cases.push((
        "cbom".to_string(),
        vec![
            "inventory".into(),
            "cbom".into(),
            fixture.display().to_string(),
            "--quiet".into(),
            "-o".into(),
            cbom_out.join("cbom.json").display().to_string(),
        ],
        "write",
    ));
    let inventory_out = root.join("inventory-out");
    private_output_dir(&inventory_out);
    cases.push((
        "inventory".to_string(),
        vec![
            "inventory".into(),
            "--system".into(),
            "--capture".into(),
            "scan".into(),
            "--identity-backend".into(),
            "userspace".into(),
            "--max-scan-pids".into(),
            "1".into(),
            "--quiet".into(),
            "-o".into(),
            inventory_out.join("inventory.json").display().to_string(),
        ],
        "write",
    ));
    cases
}

#[test]
fn enospc_recovery_is_one_stderr_line_and_closed_stderr_still_exits_one() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        temp.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let injector = compile_injector(temp.path());
    let capture = capture_available();
    if !capture {
        require_capture_positive("profile ENOSPC recovery");
    }
    let target = capture.then(SleepTarget::spawn);
    let cases = cases(temp.path(), target.as_ref());
    assert_eq!(
        cases.len(),
        if capture { 3 } else { 2 },
        "profile, cbom and inventory legs (profile needs a capture-capable host)"
    );

    for (name, args, mode) in &cases {
        let inject_dir = PathBuf::from(args.last().unwrap())
            .parent()
            .unwrap()
            .to_path_buf();
        let (output, guard) = run_injected(args, &inject_dir, &injector, mode, false);
        let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
        assert_eq!(
            output.status.code(),
            Some(1),
            "{name} must fail the requested -o: {stderr}"
        );
        assert_eq!(
            stderr.matches("capture saved to").count(),
            1,
            "{name} must print the recovery fact exactly once: {stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("rescued_after_output_failure"),
            "{name} must not duplicate a recovered report through the stdout rescue"
        );
        let recovered = guard.new_files();
        assert_eq!(recovered.len(), 1, "{name} leaves one recovery file");
        let bytes = std::fs::read(&recovered[0]).unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap_or_else(|error| panic!("{name} recovery is not complete JSON: {error}"));
    }

    for (name, args, mode) in &cases {
        let inject_dir = PathBuf::from(args.last().unwrap())
            .parent()
            .unwrap()
            .to_path_buf();
        let (output, _guard) = run_injected(args, &inject_dir, &injector, mode, true);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{name} with closed stderr must exit 1, not panic with 101"
        );
    }
}
