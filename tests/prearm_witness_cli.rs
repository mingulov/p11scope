//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! P2-8 CLI cells: `--prearm-module` exactness through the real command
//! line against SoftHSM. A GO-gated workload maps SoftHSM and issues a
//! scripted call sequence only after the capture prints its ready line;
//! the profile must then show `unobserved_windows: []` with per-function
//! call counts exactly equal to the workload LEDGER. A twin runs the
//! workload before the capture and expects the exact `pre_attach` window.
//! The workload C is runtime-generated (P2-7 `TARGET_C` precedent), so no
//! committed fixture and no license row.

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const READY_LINE: &str = "p11scope: capturing:";
const TIMEOUT: Duration = Duration::from_secs(60);
const ITERS: u32 = 5;

/// Probe SoftHSM (Debian then Fedora paths); panic loudly when absent —
/// these cells need the real provider, never a skip.
fn softhsm_path() -> PathBuf {
    for candidate in [
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
    ] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return path;
        }
    }
    panic!("SoftHSM not installed (probed Debian and Fedora paths)");
}

/// Which provider file a positive cell drives.
enum ModuleSource {
    /// The shared system SoftHSM path (pid/cgroup positives and the
    /// shared-provider twin, unchanged).
    Shared,
    /// A unique provider copy (the `--system` exact-count cells: no
    /// ambient process maps that inode, so ambient same-inode mappings
    /// cannot enter the ground truth).
    Isolated,
}

/// Brand-new provider file for the isolated `--system` cells
/// (learned-cell precedent): a copy at a cell-private path with a
/// per-copy trailing nonce, so inode and sha256 are unique to the cell
/// and counts for its sha can only come from the cell's workload. The
/// counter (plus pid) keeps the sha strictly unique per copy even
/// under parallel test execution, where the pid alone repeats within
/// one process.
fn unique_provider_copy(dir: &Path) -> PathBuf {
    static COPY_NONCE: AtomicU64 = AtomicU64::new(0);
    let copy = dir.join(format!("libisolated-{}-p28.so", std::process::id()));
    std::fs::copy(softhsm_path(), &copy).expect("copy provider");
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&copy)
            .expect("open copy for append");
        let mut trailer = [0u8; 256];
        let nonce = COPY_NONCE.fetch_add(1, Ordering::Relaxed);
        trailer[..8].copy_from_slice(&nonce.to_le_bytes());
        trailer[8..12].copy_from_slice(&std::process::id().to_le_bytes());
        file.write_all(&trailer).expect("append unseen bytes");
    }
    copy
}

/// Private token dir + config + one initialized token (bench-overhead
/// precedent); returns the config path. The caller exports it as
/// `SOFTHSM2_CONF` for the workload child only.
fn init_token(dir: &Path) -> PathBuf {
    let tokens = dir.join("tokens");
    std::fs::create_dir_all(&tokens).expect("token dir");
    let conf = dir.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\nslots.mechanisms = ALL\nlibrary.reset_on_fork = false\n",
            tokens.display()
        ),
    )
    .expect("token conf");
    let status = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            "p28",
            "--so-pin",
            "1234",
            "--pin",
            "1234",
        ])
        .env("SOFTHSM2_CONF", &conf)
        .status()
        .expect("spawn softhsm2-util");
    assert!(status.success(), "init one token");
    conf
}

/// GO-gated SoftHSM workload. Usage:
/// `workload MODULE GO_FILE LEDGER_FILE ITERATIONS [HOLD]`.
/// Prints `WAITING pid=N`, blocks until `GO_FILE` appears, then dlopens
/// the module and issues the scripted sequence (counter-softhsm-workload
/// pattern), writing one `LEDGER name=count ...` line to the ledger file
/// and stdout. With `HOLD`, sleeps 300 s afterwards (twin); otherwise
/// exits 0 (3 on any call-count drift or setup failure).
const WORKLOAD_C: &str = r#"
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long ck_ulong_t;
typedef ck_ulong_t ck_rv_t;
typedef ck_ulong_t ck_slot_id_t;
typedef ck_ulong_t ck_mechanism_type_t;

typedef ck_rv_t (*c_initialize_t)(void *);
typedef ck_rv_t (*c_finalize_t)(void *);
typedef ck_rv_t (*c_get_info_t)(unsigned char *);
typedef ck_rv_t (*c_get_slot_list_t)(unsigned char, ck_slot_id_t *, ck_ulong_t *);
typedef ck_rv_t (*c_get_slot_info_t)(ck_slot_id_t, unsigned char *);
typedef ck_rv_t (*c_get_token_info_t)(ck_slot_id_t, unsigned char *);
typedef ck_rv_t (*c_get_mechanism_list_t)(ck_slot_id_t, ck_mechanism_type_t *, ck_ulong_t *);
typedef ck_rv_t (*c_get_mechanism_info_t)(ck_slot_id_t, ck_mechanism_type_t, unsigned char *);

static void *need_symbol(void *handle, const char *name)
{
    dlerror();
    void *symbol = dlsym(handle, name);
    const char *error = dlerror();
    if (error != NULL || symbol == NULL) {
        fprintf(stderr, "workload: missing %s\n", name);
        exit(3);
    }
    return symbol;
}

int main(int argc, char **argv)
{
    if (sizeof(unsigned long) != 8 || sizeof(void *) != 8) {
        fprintf(stderr, "workload: LP64 only\n");
        return 3;
    }
    if (argc < 5 || argc > 6) {
        fprintf(stderr, "usage: %s MODULE GO_FILE LEDGER_FILE ITERATIONS [HOLD]\n", argv[0]);
        return 2;
    }
    const char *module = argv[1];
    const char *go_file = argv[2];
    const char *ledger_file = argv[3];
    long iterations = strtol(argv[4], NULL, 10);
    int hold = argc == 6 && strcmp(argv[5], "HOLD") == 0;
    if (iterations < 1 || iterations > 1000) {
        fprintf(stderr, "workload: bad iteration count\n");
        return 2;
    }
    printf("WAITING pid=%d\n", (int)getpid());
    fflush(stdout);
    {
        struct timespec wait5ms = { 0, 5000000 };
        while (access(go_file, F_OK) != 0)
            nanosleep(&wait5ms, NULL);
    }
    void *handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "workload: cannot open %s: %s\n", module, dlerror());
        return 3;
    }
    c_initialize_t c_initialize = need_symbol(handle, "C_Initialize");
    c_finalize_t c_finalize = need_symbol(handle, "C_Finalize");
    c_get_info_t c_get_info = need_symbol(handle, "C_GetInfo");
    c_get_slot_list_t c_get_slot_list = need_symbol(handle, "C_GetSlotList");
    c_get_slot_info_t c_get_slot_info = need_symbol(handle, "C_GetSlotInfo");
    c_get_token_info_t c_get_token_info = need_symbol(handle, "C_GetTokenInfo");
    c_get_mechanism_list_t c_get_mechanism_list = need_symbol(handle, "C_GetMechanismList");
    c_get_mechanism_info_t c_get_mechanism_info = need_symbol(handle, "C_GetMechanismInfo");
    ck_rv_t rv = c_initialize(NULL);
    if (rv != 0) {
        fprintf(stderr, "workload: C_Initialize failed: 0x%lx\n", rv);
        return 3;
    }
    unsigned char info[256];
    unsigned char slot_info[256];
    unsigned char token_info[512];
    unsigned char mechanism_info[256];
    ck_slot_id_t slots[64];
    ck_mechanism_type_t mechanisms[256];
    long get_info = 0, get_slot_list = 0, get_slot_info = 0, get_token_info = 0;
    long get_mechanism_list = 0, get_mechanism_info = 0;
    for (long i = 0; i < iterations; i++) {
        memset(info, 0, sizeof info);
        c_get_info(info);
        get_info++;
        ck_ulong_t count = 0;
        c_get_slot_list(0, NULL, &count);
        get_slot_list++;
        if (count > 64)
            count = 64;
        if (count > 0) {
            ck_ulong_t have = count;
            c_get_slot_list(0, slots, &have);
            get_slot_list++;
            if (have > count)
                have = count;
            for (ck_ulong_t s = 0; s < have; s++) {
                memset(slot_info, 0, sizeof slot_info);
                c_get_slot_info(slots[s], slot_info);
                get_slot_info++;
                memset(token_info, 0, sizeof token_info);
                c_get_token_info(slots[s], token_info);
                get_token_info++;
                ck_ulong_t mechanisms_count = 0;
                c_get_mechanism_list(slots[s], NULL, &mechanisms_count);
                get_mechanism_list++;
                if (mechanisms_count > 256)
                    mechanisms_count = 256;
                if (mechanisms_count > 0) {
                    ck_ulong_t got = mechanisms_count;
                    c_get_mechanism_list(slots[s], mechanisms, &got);
                    get_mechanism_list++;
                    if (got > mechanisms_count)
                        got = mechanisms_count;
                    if (got > 0) {
                        memset(mechanism_info, 0, sizeof mechanism_info);
                        c_get_mechanism_info(slots[s], mechanisms[0], mechanism_info);
                        get_mechanism_info++;
                    }
                }
            }
        }
    }
    rv = c_finalize(NULL);
    if (rv != 0) {
        fprintf(stderr, "workload: C_Finalize failed: 0x%lx\n", rv);
        return 3;
    }
    FILE *ledger = fopen(ledger_file, "w");
    if (!ledger) {
        fprintf(stderr, "workload: cannot write ledger\n");
        return 3;
    }
    fprintf(ledger,
            "LEDGER C_Initialize=1 C_Finalize=1 C_GetInfo=%ld C_GetSlotList=%ld "
            "C_GetSlotInfo=%ld C_GetTokenInfo=%ld C_GetMechanismList=%ld "
            "C_GetMechanismInfo=%ld\n",
            get_info, get_slot_list, get_slot_info, get_token_info,
            get_mechanism_list, get_mechanism_info);
    fclose(ledger);
    printf("LEDGER C_Initialize=1 C_Finalize=1 C_GetInfo=%ld C_GetSlotList=%ld "
           "C_GetSlotInfo=%ld C_GetTokenInfo=%ld C_GetMechanismList=%ld "
           "C_GetMechanismInfo=%ld\n",
           get_info, get_slot_list, get_slot_info, get_token_info,
           get_mechanism_list, get_mechanism_info);
    fflush(stdout);
    if (get_info != iterations || get_slot_list < iterations) {
        fprintf(stderr, "workload: hot counts drifted\n");
        return 3;
    }
    if (hold)
        sleep(300);
    return 0;
}
"#;

/// Compiles the workload with the system compiler.
fn build_workload(dir: &Path) -> PathBuf {
    let src = dir.join("p28-workload.c");
    std::fs::write(&src, WORKLOAD_C).expect("write workload source");
    let out = dir.join("p28-workload");
    let compile = Command::new("gcc")
        .args(["-O2", "-o"])
        .arg(&out)
        .arg(&src)
        .arg("-ldl")
        .output()
        .expect("execute gcc for the workload");
    assert!(
        compile.status.success(),
        "workload compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    out
}

/// Minimal steady provider stub for the fixture-stability twins: one
/// slot, one mechanism, every fill matching its count.
const STABLE_STUB_C: &str = r#"
#include <stddef.h>
typedef unsigned long ck_ulong_t;
typedef ck_ulong_t ck_rv_t;
typedef ck_ulong_t ck_slot_id_t;
typedef ck_ulong_t ck_mechanism_type_t;
ck_rv_t C_Initialize(void *p) { (void)p; return 0; }
ck_rv_t C_Finalize(void *p) { (void)p; return 0; }
ck_rv_t C_GetInfo(unsigned char *info) { (void)info; return 0; }
ck_rv_t C_GetSlotList(unsigned char token, ck_slot_id_t *slots, ck_ulong_t *count) {
    (void)token;
    if (slots == NULL) { *count = 1; return 0; }
    if (*count > 0) { slots[0] = 1; *count = 1; }
    return 0;
}
ck_rv_t C_GetSlotInfo(ck_slot_id_t slot, unsigned char *info) { (void)slot; (void)info; return 0; }
ck_rv_t C_GetTokenInfo(ck_slot_id_t slot, unsigned char *info) { (void)slot; (void)info; return 0; }
ck_rv_t C_GetMechanismList(ck_slot_id_t slot, ck_mechanism_type_t *mechs, ck_ulong_t *count) {
    (void)slot;
    if (mechs == NULL) { *count = 1; return 0; }
    if (*count > 0) { mechs[0] = 0; *count = 1; }
    return 0;
}
ck_rv_t C_GetMechanismInfo(ck_slot_id_t slot, ck_mechanism_type_t mech, unsigned char *info) {
    (void)slot; (void)mech; (void)info; return 0;
}
"#;

/// Mechanism-drift stub: the count query reports one mechanism but the
/// fill returns zero, so a second mechanism-list attempt yields no
/// mechanism info.
const DRIFT_MECH_STUB_C: &str = r#"
#include <stddef.h>
typedef unsigned long ck_ulong_t;
typedef ck_ulong_t ck_rv_t;
typedef ck_ulong_t ck_slot_id_t;
typedef ck_ulong_t ck_mechanism_type_t;
ck_rv_t C_Initialize(void *p) { (void)p; return 0; }
ck_rv_t C_Finalize(void *p) { (void)p; return 0; }
ck_rv_t C_GetInfo(unsigned char *info) { (void)info; return 0; }
ck_rv_t C_GetSlotList(unsigned char token, ck_slot_id_t *slots, ck_ulong_t *count) {
    (void)token;
    if (slots == NULL) { *count = 1; return 0; }
    if (*count > 0) { slots[0] = 1; *count = 1; }
    return 0;
}
ck_rv_t C_GetSlotInfo(ck_slot_id_t slot, unsigned char *info) { (void)slot; (void)info; return 0; }
ck_rv_t C_GetTokenInfo(ck_slot_id_t slot, unsigned char *info) { (void)slot; (void)info; return 0; }
ck_rv_t C_GetMechanismList(ck_slot_id_t slot, ck_mechanism_type_t *mechs, ck_ulong_t *count) {
    (void)slot;
    if (mechs == NULL) { *count = 1; return 0; }
    *count = 0;
    return 0;
}
ck_rv_t C_GetMechanismInfo(ck_slot_id_t slot, ck_mechanism_type_t mech, unsigned char *info) {
    (void)slot; (void)mech; (void)info; return 0;
}
"#;

/// Slot-drift stub: the count query reports one slot but the fill
/// returns zero, so a second slot-list attempt yields no listed slot.
const DRIFT_SLOT_STUB_C: &str = r#"
#include <stddef.h>
typedef unsigned long ck_ulong_t;
typedef ck_ulong_t ck_rv_t;
typedef ck_ulong_t ck_slot_id_t;
typedef ck_ulong_t ck_mechanism_type_t;
ck_rv_t C_Initialize(void *p) { (void)p; return 0; }
ck_rv_t C_Finalize(void *p) { (void)p; return 0; }
ck_rv_t C_GetInfo(unsigned char *info) { (void)info; return 0; }
ck_rv_t C_GetSlotList(unsigned char token, ck_slot_id_t *slots, ck_ulong_t *count) {
    (void)token;
    if (slots == NULL) { *count = 1; return 0; }
    *count = 0;
    return 0;
}
ck_rv_t C_GetSlotInfo(ck_slot_id_t slot, unsigned char *info) { (void)slot; (void)info; return 0; }
ck_rv_t C_GetTokenInfo(ck_slot_id_t slot, unsigned char *info) { (void)slot; (void)info; return 0; }
ck_rv_t C_GetMechanismList(ck_slot_id_t slot, ck_mechanism_type_t *mechs, ck_ulong_t *count) {
    (void)slot;
    if (mechs == NULL) { *count = 1; return 0; }
    if (*count > 0) { mechs[0] = 0; *count = 1; }
    return 0;
}
ck_rv_t C_GetMechanismInfo(ck_slot_id_t slot, ck_mechanism_type_t mech, unsigned char *info) {
    (void)slot; (void)mech; (void)info; return 0;
}
"#;

/// Compiles a stub provider with the system compiler.
fn build_stub(dir: &Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).expect("write stub source");
    let out = dir.join(format!("{name}.so"));
    let compile = Command::new("gcc")
        .args(["-O2", "-shared", "-fPIC", "-o"])
        .arg(&out)
        .arg(&src)
        .output()
        .expect("execute gcc for the stub");
    assert!(
        compile.status.success(),
        "stub compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    out
}

/// A child with a poll-bounded line reader on one piped stream and
/// kill-on-drop (never hangs, only fails loudly).
struct GuardedChild {
    child: Child,
    fd: std::os::fd::OwnedFd,
    buf: Vec<u8>,
}

impl GuardedChild {
    fn new(child: Child, stream: impl std::os::unix::io::IntoRawFd) -> Self {
        use std::os::unix::io::FromRawFd as _;
        let raw = stream.into_raw_fd();
        // SAFETY: flag juggling on our own pipe end.
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        assert!(flags >= 0, "getfl child stream");
        assert_eq!(
            unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0,
            "nonblock child stream"
        );
        // SAFETY: sole owner of the converted fd.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        Self {
            child,
            fd,
            buf: Vec::new(),
        }
    }

    /// Next full line before the deadline; panics on timeout or EOF.
    fn next_line(&mut self, what: &str) -> String {
        let deadline = Instant::now() + TIMEOUT;
        let mut byte = [0u8; 1];
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                let line = self.buf.drain(..=pos).collect::<Vec<_>>();
                return String::from_utf8(line).expect("child speaks UTF-8");
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll on our own pipe end.
            let ready = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis() as i32) };
            assert!(ready > 0, "{what} silent for {}s", TIMEOUT.as_secs());
            if pfd.revents & libc::POLLIN != 0 {
                // SAFETY: single-byte read into a stack slot.
                let got = unsafe { libc::read(self.fd.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
                if got == 0 {
                    panic!("{what}: EOF (child status: {:?})", self.try_wait());
                }
                if got < 0 {
                    assert_eq!(
                        std::io::Error::last_os_error().kind(),
                        std::io::ErrorKind::WouldBlock,
                        "{what} read"
                    );
                    continue;
                }
                self.buf.push(byte[0]);
            } else {
                panic!("{what}: pipe hung up");
            }
        }
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().expect("try_wait")
    }

    fn wait_expect(&mut self, what: &str) -> std::process::ExitStatus {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.try_wait() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "{what} would not exit within {}s",
                TIMEOUT.as_secs()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for GuardedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Parses one `LEDGER name=count ...` line into per-function counts.
fn parse_ledger(line: &str) -> BTreeMap<String, u64> {
    let body = line
        .strip_prefix("LEDGER ")
        .unwrap_or_else(|| panic!("not a ledger line: {line:?}"));
    body.split_whitespace()
        .map(|pair| {
            let (name, count) = pair
                .split_once('=')
                .unwrap_or_else(|| panic!("bad ledger pair: {pair:?}"));
            (
                name.to_string(),
                count.parse::<u64>().expect("ledger count"),
            )
        })
        .collect()
}

/// A cell cgroup (created for the `--cgroup` cell; removed on drop).
struct CellCgroup {
    path: PathBuf,
}

impl CellCgroup {
    fn create(name: &str) -> Self {
        let path = PathBuf::from("/sys/fs/cgroup").join(name);
        std::fs::create_dir(&path).expect("create cell cgroup");
        Self { path }
    }

    fn place(&self, pid: u32) {
        std::fs::write(self.path.join("cgroup.procs"), pid.to_string())
            .expect("place workload in cgroup");
    }
}

impl Drop for CellCgroup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_p11scope"))
}

/// Spawns the workload (GO absent unless `go_ready`), waits for its
/// `WAITING` line, and returns the guarded child plus its pid.
fn spawn_workload(
    workload: &Path,
    module: &Path,
    go: &Path,
    ledger: &Path,
    conf: &Path,
    hold: bool,
    go_ready: bool,
) -> (GuardedChild, u32) {
    if go_ready {
        std::fs::write(go, b"go\n").expect("pre-create GO");
    }
    let mut command = Command::new(workload);
    command
        .arg(module)
        .arg(go)
        .arg(ledger)
        .arg(ITERS.to_string());
    if hold {
        command.arg("HOLD");
    }
    command
        .env("SOFTHSM2_CONF", conf)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().expect("spawn workload");
    let pid = child.id();
    let stdout = child.stdout.take().expect("workload stdout");
    let mut guarded = GuardedChild::new(child, stdout);
    let waiting = guarded.next_line("workload WAITING");
    assert!(
        waiting.starts_with("WAITING pid="),
        "workload waits: {waiting:?}"
    );
    (guarded, pid)
}

/// Runs the workload against a stub provider with GO pre-created and
/// returns its exit status plus the ledger path (for the steady
/// control to validate; drift refusals emit no ledger).
fn run_workload_against_stub(
    workload: &Path,
    stub: &Path,
    dir: &Path,
) -> (std::process::ExitStatus, PathBuf) {
    let go = dir.join("stub-go");
    let ledger = dir.join("stub-ledger.txt");
    let conf = dir.join("stub.conf");
    std::fs::write(&conf, "").expect("dummy stub conf");
    let (mut child, _pid) = spawn_workload(workload, stub, &go, &ledger, &conf, false, true);
    let status = child.wait_expect("stub workload exit");
    (status, ledger)
}

/// Spawns a capture with stderr piped; returns the guarded child.
fn spawn_capture(args: &[String]) -> GuardedChild {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn capture");
    let stderr = child.stderr.take().expect("capture stderr");
    GuardedChild::new(child, stderr)
}

/// Drains capture stderr until the ready line.
fn wait_ready(capture: &mut GuardedChild) {
    loop {
        let line = capture.next_line("capture ready");
        if line.contains(READY_LINE) {
            return;
        }
    }
}

/// Reads the LEDGER file (written by the workload on completion) and
/// validates its known eight-counter shape: every exact cell inherits
/// the guard, so silence or impossible counts fail here instead of
/// passing a count comparison against nothing observed.
fn read_ledger_file(ledger: &Path) -> BTreeMap<String, u64> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Ok(text) = std::fs::read_to_string(ledger)
            && let Some(line) = text.lines().find(|l| l.starts_with("LEDGER "))
        {
            let counts = parse_ledger(line);
            assert!(
                validate_workload_ledger(&counts),
                "the workload ledger must have its known eight-counter shape: {counts:?}"
            );
            return counts;
        }
        assert!(Instant::now() < deadline, "workload never wrote its ledger");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Waits for a non-hold workload and asserts its clean exit: the
/// ledger proves the fixture reached its write, the exit proves it
/// passed its own drift check. Hold workloads are killed by design
/// and never pass through here.
fn wait_workload_success(workload: &mut GuardedChild) {
    let status = workload.wait_expect("workload exit");
    assert!(status.success(), "workload exits clean");
}

/// The ledger producer validates shape: an impossible ledger file
/// (zero slot-list attempts, which the fixture cannot emit) never
/// yields counts — every exact cell inherits the guard.
#[test]
fn ledger_file_reader_rejects_an_impossible_ledger() {
    let dir = tempfile::tempdir().expect("cell dir");
    let ledger = dir.path().join("ledger.txt");
    std::fs::write(
        &ledger,
        format!(
            "LEDGER C_Initialize=1 C_Finalize=1 C_GetInfo={} C_GetSlotList=0 \
             C_GetSlotInfo=0 C_GetTokenInfo=0 C_GetMechanismList=0 C_GetMechanismInfo=0\n",
            u64::from(ITERS)
        ),
    )
    .expect("write impossible ledger");
    let rejected =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| read_ledger_file(&ledger)));
    assert!(
        rejected.is_err(),
        "an impossible ledger must not yield counts"
    );
}

/// A healthy ledger file still yields its counts through the same
/// validating producer.
#[test]
fn ledger_file_reader_accepts_a_healthy_ledger() {
    let dir = tempfile::tempdir().expect("cell dir");
    let ledger = dir.path().join("ledger.txt");
    let iters = u64::from(ITERS);
    std::fs::write(
        &ledger,
        format!(
            "LEDGER C_Initialize=1 C_Finalize=1 C_GetInfo={iters} C_GetSlotList={} \
             C_GetSlotInfo={iters} C_GetTokenInfo={iters} C_GetMechanismList={} \
             C_GetMechanismInfo={iters}\n",
            2 * iters,
            2 * iters,
        ),
    )
    .expect("write healthy ledger");
    let counts = read_ledger_file(&ledger);
    assert_eq!(counts.len(), 8);
    assert!(validate_workload_ledger(&counts));
}

/// The workload-exit gate fails loudly on a nonzero exit and passes
/// on a clean one (negative control for the gate every exact cell
/// applies to its non-hold workload).
#[test]
fn workload_exit_gate_fails_a_nonzero_exit() {
    fn guarded(argv0: &str) -> GuardedChild {
        let mut child = Command::new(argv0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gate control");
        let stdout = child.stdout.take().expect("control stdout");
        GuardedChild::new(child, stdout)
    }
    wait_workload_success(&mut guarded("true"));
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_workload_success(&mut guarded("false"))
    }));
    assert!(
        failed.is_err(),
        "a nonzero workload exit must fail the gate"
    );
}

/// A ledger line repeating a counter name never yields counts: the
/// producer refuses duplicate keys before map insertion instead of
/// letting last-wins collapse a conflict into healthy counts.
#[test]
fn ledger_file_reader_rejects_a_duplicate_counter() {
    let dir = tempfile::tempdir().expect("cell dir");
    let ledger = dir.path().join("ledger.txt");
    let iters = u64::from(ITERS);
    std::fs::write(
        &ledger,
        format!(
            "LEDGER C_Initialize=0 C_Initialize=1 C_Finalize=1 C_GetInfo={iters} C_GetSlotList={} \
             C_GetSlotInfo={iters} C_GetTokenInfo={iters} C_GetMechanismList={} \
             C_GetMechanismInfo={iters}\n",
            2 * iters,
            2 * iters,
        ),
    )
    .expect("write duplicate-key ledger");
    let rejected =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| read_ledger_file(&ledger)));
    assert!(
        rejected.is_err(),
        "a conflicting repeated counter must not yield counts"
    );
}

/// A ledger file holding two records never yields counts: the
/// producer requires exactly one complete record instead of taking
/// the first matching line.
#[test]
fn ledger_file_reader_rejects_a_duplicate_record() {
    let dir = tempfile::tempdir().expect("cell dir");
    let ledger = dir.path().join("ledger.txt");
    let iters = u64::from(ITERS);
    let line = format!(
        "LEDGER C_Initialize=1 C_Finalize=1 C_GetInfo={iters} C_GetSlotList={} \
         C_GetSlotInfo={iters} C_GetTokenInfo={iters} C_GetMechanismList={} \
         C_GetMechanismInfo={iters}\n",
        2 * iters,
        2 * iters,
    );
    std::fs::write(&ledger, format!("{line}{line}")).expect("write duplicate-record ledger");
    let rejected =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| read_ledger_file(&ledger)));
    assert!(
        rejected.is_err(),
        "a repeated ledger record must not yield counts"
    );
}

/// Finds the module record for `module` in a profile/metrics JSON
/// document: the full `DiscoveredModule` lives at `evidence.discovery[]`
/// (`capture.modules[]` is an identity-only projection).
fn module_record<'a>(profile: &'a serde_json::Value, module: &Path) -> &'a serde_json::Value {
    let want = module.to_str().expect("utf8 module path");
    let modules = profile
        .get("evidence")
        .and_then(|evidence| evidence.get("discovery"))
        .and_then(|discovery| discovery.as_array())
        .unwrap_or_else(|| {
            panic!(
                "no evidence.discovery; top-level keys: {:?}",
                profile
                    .as_object()
                    .map(|object| object.keys().collect::<Vec<_>>())
            )
        });
    modules
        .iter()
        .find(|record| record.get("path").and_then(|p| p.as_str()) == Some(want))
        .unwrap_or_else(|| {
            panic!(
                "no module record for {want}; modules present: {:?}",
                modules
                    .iter()
                    .map(|record| record.get("path"))
                    .collect::<Vec<_>>()
            )
        })
}

/// Per-function completed-call counts for the module with `sha256` from
/// the profile's `functions` rows. Rows name functions via `names[]` and
/// carry the module as an identity object; the match is on `sha256`,
/// which is stable across the fd/maps device domains (btrfs splits
/// `st_dev` from the maps device for the same file).
fn function_calls(profile: &serde_json::Value, sha256: &str) -> BTreeMap<String, u64> {
    let rows = profile
        .get("functions")
        .and_then(|functions| functions.as_array())
        .unwrap_or_else(|| {
            panic!(
                "no functions array; top-level keys: {:?}",
                profile
                    .as_object()
                    .map(|object| object.keys().collect::<Vec<_>>())
            )
        });
    let mut counts = BTreeMap::new();
    for row in rows {
        let row_sha = row
            .get("module")
            .and_then(|module| module.get("sha256"))
            .and_then(|sha| sha.as_str());
        if row_sha != Some(sha256) {
            continue;
        }
        let names = row
            .get("names")
            .and_then(|names| names.as_array())
            .expect("function names");
        let calls = row.get("calls").and_then(|c| c.as_u64()).unwrap_or(0);
        for name in names {
            let name = name.as_str().expect("function name");
            *counts.entry(name.to_string()).or_insert(0) += calls;
        }
    }
    counts
}

/// The record's `sha256` (row-join key).
fn record_sha256(record: &serde_json::Value) -> &str {
    record
        .get("sha256")
        .and_then(|sha| sha.as_str())
        .expect("record sha256")
}

/// Exact counts in both directions: every ledger function observed
/// exactly its count, and no calls outside the ledger at all.
fn assert_exact_counts(observed: &BTreeMap<String, u64>, ledger: &BTreeMap<String, u64>) {
    for (name, want) in ledger {
        assert_eq!(
            observed.get(name).copied().unwrap_or(0),
            *want,
            "exact count for {name}"
        );
    }
    let spurious: u64 = observed
        .iter()
        .filter(|(name, _)| !ledger.contains_key(*name))
        .map(|(_, calls)| calls)
        .sum();
    assert_eq!(spurious, 0, "no calls outside the ledger: {observed:?}");
}

/// Runs one positive: the workload starts on the ready line, so the
/// module shows `unobserved_windows: []` and exact ledger counts.
/// `scope_args` selects `--pid`/`--cgroup`/`--system`; `extra` carries
/// mode flags (`--mode metrics`) or stays empty. Returns the ledger,
/// the profile, and the driven module path (a unique copy for
/// `Isolated`, for the record lookup).
fn run_positive(
    scope: &str,
    extra: &[&str],
    source: ModuleSource,
) -> (BTreeMap<String, u64>, serde_json::Value, PathBuf) {
    let dir = tempfile::tempdir().expect("cell dir");
    let module = match source {
        ModuleSource::Shared => softhsm_path(),
        ModuleSource::Isolated => unique_provider_copy(dir.path()),
    };
    let conf = init_token(dir.path());
    let workload = build_workload(dir.path());
    let go = dir.path().join("go");
    let ledger = dir.path().join("ledger.txt");
    let out = dir.path().join("out.json");
    let (mut workload, pid) = spawn_workload(&workload, &module, &go, &ledger, &conf, false, false);
    // Held to the end of the capture (dropped after the output is read).
    let mut _cgroup: Option<CellCgroup> = None;
    let mut args = vec!["profile".to_string(), format!("--{scope}")];
    if scope == "pid" {
        args.push(pid.to_string());
    } else if scope == "cgroup" {
        let cgroup = CellCgroup::create(&format!("p11pw-p28-{pid}"));
        cgroup.place(pid);
        args.push(cgroup.path.to_str().expect("utf8 cgroup").to_string());
        _cgroup = Some(cgroup);
    }
    args.extend([
        "--module".to_string(),
        module.to_str().expect("utf8 module").to_string(),
        "--prearm-module".to_string(),
        module.to_str().expect("utf8 module").to_string(),
        "--duration".to_string(),
        "8".to_string(),
        "-o".to_string(),
        out.to_str().expect("utf8 out").to_string(),
    ]);
    for flag in extra {
        args.push(flag.to_string());
    }
    let mut capture = spawn_capture(&args);
    wait_ready(&mut capture);
    std::fs::write(&go, b"go\n").expect("release the workload");
    let ledger_counts = read_ledger_file(&ledger);
    wait_workload_success(&mut workload);
    let status = capture.wait_expect("capture");
    assert!(status.success(), "capture exits clean");
    let text = std::fs::read_to_string(&out).expect("read profile");
    let profile: serde_json::Value = serde_json::from_str(&text).expect("profile is JSON");
    (ledger_counts, profile, module)
}

#[test]
#[ignore = "privileged: witness P2-8 profile --pid positive cell"]
fn privileged_profile_pid_prearm_clean_exact_counts() {
    let (ledger, profile, module) = run_positive("pid", &[], ModuleSource::Shared);
    let record = module_record(&profile, &module);
    assert_eq!(
        record.get("unobserved_windows"),
        Some(&serde_json::Value::Array(vec![])),
        "windows empty: {}",
        serde_json::to_string_pretty(record).unwrap_or_default()
    );
    assert_exact_counts(&function_calls(&profile, record_sha256(record)), &ledger);
}

#[test]
#[ignore = "privileged: witness P2-8 profile --cgroup positive cell"]
fn privileged_profile_cgroup_prearm_clean_exact_counts() {
    let (ledger, profile, module) = run_positive("cgroup", &[], ModuleSource::Shared);
    let record = module_record(&profile, &module);
    assert_eq!(
        record.get("unobserved_windows"),
        Some(&serde_json::Value::Array(vec![])),
        "windows empty: {}",
        serde_json::to_string_pretty(record).unwrap_or_default()
    );
    assert_exact_counts(&function_calls(&profile, record_sha256(record)), &ledger);
}

#[test]
#[ignore = "privileged: witness P2-8 profile --system positive cell"]
fn privileged_profile_system_prearm_clean_exact_counts() {
    let (ledger, profile, module) = run_positive("system", &[], ModuleSource::Isolated);
    let record = module_record(&profile, &module);
    assert_eq!(
        record.get("unobserved_windows"),
        Some(&serde_json::Value::Array(vec![])),
        "windows empty: {}",
        serde_json::to_string_pretty(record).unwrap_or_default()
    );
    assert_exact_counts(&function_calls(&profile, record_sha256(record)), &ledger);
}

#[test]
#[ignore = "privileged: witness P2-8 profile --mode metrics positive cell"]
fn privileged_profile_metrics_system_prearm_clean_exact_counts() {
    let (ledger, profile, module) =
        run_positive("system", &["--mode", "metrics"], ModuleSource::Isolated);
    let record = module_record(&profile, &module);
    assert_eq!(
        record.get("unobserved_windows"),
        Some(&serde_json::Value::Array(vec![])),
        "windows empty: {}",
        serde_json::to_string_pretty(record).unwrap_or_default()
    );
    assert_exact_counts(&function_calls(&profile, record_sha256(record)), &ledger);
}

/// Twin: the workload maps and calls SoftHSM *before* the capture
/// starts (and holds the mapping), so the module keeps the exact
/// `pre_attach` window over `[scope_start, attached_at]` and observes
/// zero calls.
#[test]
#[ignore = "privileged: witness P2-8 profile --pid early-workload twin cell"]
fn privileged_profile_pid_prearm_twin_exact_window() {
    let dir = tempfile::tempdir().expect("cell dir");
    let module = softhsm_path();
    let conf = init_token(dir.path());
    let workload = build_workload(dir.path());
    let go = dir.path().join("go");
    let ledger = dir.path().join("ledger.txt");
    let out = dir.path().join("out.json");
    // GO pre-created: the workload runs to completion (and holds F)
    // before the capture exists.
    let (_workload, pid) = spawn_workload(&workload, &module, &go, &ledger, &conf, true, true);
    // Hold workload: killed on drop by design, so no exit gate (its
    // ledger proves its pre-attach calls).
    let ledger_counts = read_ledger_file(&ledger);
    assert!(
        ledger_counts.values().sum::<u64>() > 0,
        "twin workload made calls"
    );
    let args = vec![
        "profile".to_string(),
        "--pid".to_string(),
        pid.to_string(),
        "--module".to_string(),
        module.to_str().expect("utf8 module").to_string(),
        "--prearm-module".to_string(),
        module.to_str().expect("utf8 module").to_string(),
        "--duration".to_string(),
        "6".to_string(),
        "-o".to_string(),
        out.to_str().expect("utf8 out").to_string(),
    ];
    let mut capture = spawn_capture(&args);
    wait_ready(&mut capture);
    let status = capture.wait_expect("capture");
    assert!(status.success(), "capture exits clean");
    let text = std::fs::read_to_string(&out).expect("read profile");
    let profile: serde_json::Value = serde_json::from_str(&text).expect("profile is JSON");
    let record = module_record(&profile, &module);
    let windows = record.get("unobserved_windows").unwrap_or_else(|| {
        panic!(
            "twin module has no windows: {}",
            serde_json::to_string_pretty(record).unwrap_or_default()
        )
    });
    let windows = windows.as_array().expect("windows is a list");
    assert_eq!(windows.len(), 1, "exactly one window: {windows:?}");
    let window = &windows[0];
    assert_eq!(
        window.get("reason").and_then(|r| r.as_str()),
        Some("pre_attach"),
        "twin window reason: {window:?}"
    );
    // Exact end: the record's own attach instant. (The scope start that
    // opens the window is not rendered anywhere in the profile, so the
    // start asserts ordering only; exact `[50, 900]` arithmetic is pinned
    // by the engine twins. Rendering `scope_start_ns` is a product RFE,
    // not this task.)
    let attached_at = record.get("attached_at_ns").unwrap_or_else(|| {
        panic!(
            "no attached_at_ns on twin record: {}",
            serde_json::to_string_pretty(record).unwrap_or_default()
        )
    });
    let start_ns = window
        .get("start_ns")
        .and_then(|s| s.as_u64())
        .expect("window start_ns");
    let end_ns = window
        .get("end_ns")
        .and_then(|e| e.as_u64())
        .expect("window end_ns");
    assert_eq!(window.get("end_ns"), Some(attached_at));
    assert!(
        0 < start_ns && start_ns < end_ns,
        "window opens before attach: {window:?}"
    );
    // Every twin call predates attach: zero observed.
    let observed = function_calls(&profile, record_sha256(record));
    assert_eq!(
        observed.values().sum::<u64>(),
        0,
        "twin observes no calls: {observed:?}"
    );
}

/// Trace positive: `trace --system` with the workload on the ready
/// line shows `[]` and per-function event counts equal to the LEDGER.
#[test]
#[ignore = "privileged: witness P2-8 trace --system positive cell"]
fn privileged_trace_system_prearm_clean_exact_counts() {
    let dir = tempfile::tempdir().expect("cell dir");
    let module = unique_provider_copy(dir.path());
    let conf = init_token(dir.path());
    let workload = build_workload(dir.path());
    let go = dir.path().join("go");
    let ledger = dir.path().join("ledger.txt");
    let out = dir.path().join("out.jsonl");
    let (mut workload, _pid) =
        spawn_workload(&workload, &module, &go, &ledger, &conf, false, false);
    let args = vec![
        "trace".to_string(),
        "--system".to_string(),
        "--module".to_string(),
        module.to_str().expect("utf8 module").to_string(),
        "--prearm-module".to_string(),
        module.to_str().expect("utf8 module").to_string(),
        "--duration".to_string(),
        "8".to_string(),
        "--max-events".to_string(),
        "100000".to_string(),
        "-o".to_string(),
        out.to_str().expect("utf8 out").to_string(),
    ];
    let mut capture = spawn_capture(&args);
    wait_ready(&mut capture);
    std::fs::write(&go, b"go\n").expect("release the workload");
    let ledger_counts = read_ledger_file(&ledger);
    wait_workload_success(&mut workload);
    let status = capture.wait_expect("capture");
    assert!(status.success(), "capture exits clean");
    let text = std::fs::read_to_string(&out).expect("read trace");
    // Trace shape: a text preamble, one text event line per completed
    // call (`... (PID n, TID m) FUNC [...] → ...`), then a
    // `COUNT_EVIDENCE {...}` line and an `EVIDENCE {...}` terminal
    // object carrying the module records.
    let mut events: BTreeMap<String, u64> = BTreeMap::new();
    let mut count_evidence: Option<serde_json::Value> = None;
    let mut evidence: Option<serde_json::Value> = None;
    for line in text.lines() {
        if let Some(body) = line.strip_prefix("COUNT_EVIDENCE ") {
            count_evidence = Some(serde_json::from_str(body).expect("count evidence JSON"));
            continue;
        }
        if let Some(body) = line.strip_prefix("EVIDENCE ") {
            evidence = Some(serde_json::from_str(body).expect("terminal evidence JSON"));
            continue;
        }
        // Event line: the token after `(PID n, TID m)` is the function.
        let Some(paren) = line.find("(PID ") else {
            continue;
        };
        let Some(close) = line[paren..].find(") ") else {
            continue;
        };
        let name = line[paren + close + 2..]
            .split_whitespace()
            .next()
            .expect("event function");
        assert!(
            name.starts_with("C_"),
            "event names a PKCS#11 function: {line:?}"
        );
        *events.entry(name.to_string()).or_insert(0) += 1;
    }
    // Per-function event counts are exactly the ledger.
    for (name, want) in &ledger_counts {
        assert_eq!(
            events.get(name).copied().unwrap_or(0),
            *want,
            "exact trace count for {name}"
        );
    }
    let ledger_total: u64 = ledger_counts.values().sum();
    let event_total: u64 = events.values().sum();
    assert_eq!(event_total, ledger_total, "trace event total");
    // The counter evidence agrees too.
    let count_evidence = count_evidence.expect("COUNT_EVIDENCE line");
    assert_eq!(
        count_evidence.get("stats_entered").and_then(|v| v.as_u64()),
        Some(ledger_total),
        "count evidence entered"
    );
    assert_eq!(
        count_evidence
            .get("stats_returned")
            .and_then(|v| v.as_u64()),
        Some(ledger_total),
        "count evidence returned"
    );
    // The terminal evidence carries the module windows: empty.
    let evidence = evidence.expect("EVIDENCE line");
    let modules = evidence
        .get("discovery")
        .and_then(|discovery| discovery.as_array())
        .expect("terminal discovery records");
    let want = module.to_str().expect("utf8 module path");
    let record = modules
        .iter()
        .find(|record| record.get("path").and_then(|p| p.as_str()) == Some(want))
        .expect("trace module record");
    assert_eq!(
        record.get("unobserved_windows"),
        Some(&serde_json::Value::Array(vec![])),
        "trace windows empty: {}",
        serde_json::to_string_pretty(record).unwrap_or_default()
    );
}

/// Parses one trace event line into (pid, function), across both
/// executable-label shapes: `Unknown executable (PID n, TID m) FUNC`
/// and `"base" (PID n, TID m) exe="..." [sess#k] FUNC`. Returns None
/// for non-event lines (preamble, COUNT_EVIDENCE, EVIDENCE, and the
/// per-process `(PID n)` summary lines, which carry no TID).
fn parse_trace_event(line: &str) -> Option<(u32, String)> {
    let after_pid = line.find("(PID ")? + "(PID ".len();
    let rest = &line[after_pid..];
    let comma = rest.find(", TID ")?;
    let pid: u32 = rest[..comma].parse().ok()?;
    let after_tid = &rest[comma + ", TID ".len()..];
    let close = after_tid.find(") ")?;
    let _: u32 = after_tid[..close].parse().ok()?;
    let tail = &after_tid[close + ") ".len()..];
    tail.split_whitespace().find_map(|token| {
        let name = token.strip_prefix("C_")?;
        if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            Some((pid, token.to_string()))
        } else {
            None
        }
    })
}

/// Shared-twin verdict (factored out so its accept/reject table runs
/// unprivileged): the main workload's per-pid event counts are exactly
/// its ledger, the pre-attach holder contributed zero counted calls,
/// and the module carries at least one well-formed named window with
/// a `pre_attach` window ending exactly at attach.
fn shared_twin_accepts(
    main_exact: bool,
    holder_counted: u64,
    window_count: usize,
    windows_wellformed_named: bool,
    pre_attach_ends_at_attach: bool,
) -> bool {
    main_exact
        && holder_counted == 0
        && window_count >= 1
        && windows_wellformed_named
        && pre_attach_ends_at_attach
}

/// The parser reads both event shapes and rejects every non-event
/// line, including the TID-less per-process summary lines.
#[test]
fn shared_twin_parser_reads_both_event_shapes() {
    assert_eq!(
        parse_trace_event(
            "00:00:00.000000 Unknown executable (PID 123, TID 456) C_GetInfo -> CKR_OK 3.0us"
        ),
        Some((123, "C_GetInfo".to_string()))
    );
    assert_eq!(
        parse_trace_event(
            "12:00:01.123456 \"p28-workload\" (PID 12345, TID 12401) exe=\"/tmp/x/p28-workload\" sess#7 C_SignInit -> CKR_OK 3.0us"
        ),
        Some((12345, "C_SignInit".to_string()))
    );
    assert_eq!(
        parse_trace_event(
            "00:00:00.000000 \"pkcs11-tool\" (PID 100, TID 1) exe=\"/usr/bin/pkcs11-tool\" C_Initialize -> CKR_OK 1.0us"
        ),
        Some((100, "C_Initialize".to_string()))
    );
    assert_eq!(
        parse_trace_event("COUNT_EVIDENCE {\"stats_entered\": 3}"),
        None
    );
    assert_eq!(parse_trace_event("EVIDENCE {\"discovery\": []}"), None);
    assert_eq!(
        parse_trace_event(
            "\"firefox\" (PID 100) exe=\"/usr/bin/firefox\": C_OpenSession: CKR_OK x2"
        ),
        None
    );
    assert_eq!(parse_trace_event("p11scope: capturing: system"), None);
}

/// Negative controls for the verdict above: only complete honest
/// accounting may pass. Each term is load-bearing on its own.
#[test]
fn shared_twin_oracle_requires_every_honest_accounting_term() {
    assert!(shared_twin_accepts(true, 0, 1, true, true));
    assert!(
        !shared_twin_accepts(false, 0, 1, true, true),
        "main counts must be exact"
    );
    assert!(
        !shared_twin_accepts(true, 1, 1, true, true),
        "holder calls stay in the gap"
    );
    assert!(
        !shared_twin_accepts(true, 0, 0, true, true),
        "a window must exist"
    );
    assert!(
        !shared_twin_accepts(true, 0, 2, false, true),
        "every window well-formed and named"
    );
    assert!(
        !shared_twin_accepts(true, 0, 1, true, false),
        "pre_attach ends at attach"
    );
}

/// Nonce control for the isolated provider copies: two copies made in
/// one process (separate cell dirs, as the cells use) must carry
/// distinct trailing bytes, so their sha256 differ even under parallel
/// test execution, where the pid alone repeats within one process.
#[test]
fn unique_provider_copies_carry_distinct_trailing_bytes() {
    let left_dir = tempfile::tempdir().expect("left cell dir");
    let right_dir = tempfile::tempdir().expect("right cell dir");
    let left = unique_provider_copy(left_dir.path());
    let right = unique_provider_copy(right_dir.path());
    let tail = |path: &Path| {
        let bytes = std::fs::read(path).expect("read provider copy");
        bytes[bytes.len() - 256..].to_vec()
    };
    assert_ne!(tail(&left), tail(&right));
}

/// Shared-provider twin: `trace --system` against the SHARED system
/// SoftHSM while a holder workload maps it across the whole pre-attach
/// interval (the busy-home-PC case, deterministic on any host). The
/// held mapping voids the exactness proof, so the cell asserts honest
/// accounting instead of emptiness: every main-workload call is
/// counted and attributed to its pid, the holder's pre-attach calls
/// are counted zero times (they sit in the named gap), the counters
/// agree with the parsed events, and every window is well-formed and
/// named with a `pre_attach` window ending exactly at attach. Never a
/// skip: it runs unconditionally and fails loudly on any dishonest
/// accounting.
#[test]
#[ignore = "privileged: witness P2-8 trace --system shared-provider honest-accounting twin cell"]
fn privileged_trace_system_prearm_shared_provider_honest_accounting() {
    let dir = tempfile::tempdir().expect("cell dir");
    let module = softhsm_path();
    let conf = init_token(dir.path());
    let workload = build_workload(dir.path());
    // The holder maps and calls the shared module BEFORE the capture
    // exists and holds the mapping: its calls complete pre-scope (the
    // ledger wait proves it) and its mapping voids the proof.
    let holder_go = dir.path().join("holder-go");
    let holder_ledger = dir.path().join("holder-ledger.txt");
    let (_holder, holder_pid) = spawn_workload(
        &workload,
        &module,
        &holder_go,
        &holder_ledger,
        &conf,
        true,
        true,
    );
    // Hold workload: killed on drop by design, so no exit gate (its
    // ledger proves its pre-attach calls).
    let holder_counts = read_ledger_file(&holder_ledger);
    assert!(
        holder_counts.values().sum::<u64>() > 0,
        "holder made pre-attach calls"
    );
    // The main workload starts on the ready line: every one of its
    // calls is post-attach and must be counted under its pid.
    let go = dir.path().join("go");
    let ledger = dir.path().join("ledger.txt");
    let out = dir.path().join("out.jsonl");
    let (mut main, main_pid) =
        spawn_workload(&workload, &module, &go, &ledger, &conf, false, false);
    let args = vec![
        "trace".to_string(),
        "--system".to_string(),
        "--module".to_string(),
        module.to_str().expect("utf8 module").to_string(),
        "--prearm-module".to_string(),
        module.to_str().expect("utf8 module").to_string(),
        "--duration".to_string(),
        "8".to_string(),
        "--max-events".to_string(),
        "100000".to_string(),
        "-o".to_string(),
        out.to_str().expect("utf8 out").to_string(),
    ];
    let mut capture = spawn_capture(&args);
    wait_ready(&mut capture);
    std::fs::write(&go, b"go\n").expect("release the workload");
    let ledger_counts = read_ledger_file(&ledger);
    wait_workload_success(&mut main);
    let status = capture.wait_expect("capture");
    assert!(status.success(), "capture exits clean");
    let text = std::fs::read_to_string(&out).expect("read trace");
    let mut main_events: BTreeMap<String, u64> = BTreeMap::new();
    let mut holder_total: u64 = 0;
    let mut event_total: u64 = 0;
    let mut count_evidence: Option<serde_json::Value> = None;
    let mut evidence: Option<serde_json::Value> = None;
    for line in text.lines() {
        if let Some(body) = line.strip_prefix("COUNT_EVIDENCE ") {
            count_evidence = Some(serde_json::from_str(body).expect("count evidence JSON"));
            continue;
        }
        if let Some(body) = line.strip_prefix("EVIDENCE ") {
            evidence = Some(serde_json::from_str(body).expect("terminal evidence JSON"));
            continue;
        }
        let Some((pid, name)) = parse_trace_event(line) else {
            continue;
        };
        event_total += 1;
        if pid == main_pid {
            *main_events.entry(name).or_insert(0) += 1;
        } else if pid == holder_pid {
            holder_total += 1;
        }
    }
    // Every main call counted, attributed to the main pid, nothing
    // else under it.
    let main_exact = main_events == ledger_counts;
    // The counter evidence agrees with the parsed events.
    let count_evidence = count_evidence.expect("COUNT_EVIDENCE line");
    assert_eq!(
        count_evidence.get("stats_entered").and_then(|v| v.as_u64()),
        Some(event_total),
        "count evidence entered"
    );
    assert_eq!(
        count_evidence
            .get("stats_returned")
            .and_then(|v| v.as_u64()),
        Some(event_total),
        "count evidence returned"
    );
    // Every window well-formed and named; a pre_attach window ends
    // exactly at attach.
    let evidence = evidence.expect("EVIDENCE line");
    let modules = evidence
        .get("discovery")
        .and_then(|discovery| discovery.as_array())
        .expect("terminal discovery records");
    let want = module.to_str().expect("utf8 module path");
    let record = modules
        .iter()
        .find(|record| record.get("path").and_then(|p| p.as_str()) == Some(want))
        .expect("trace module record");
    let windows = record
        .get("unobserved_windows")
        .and_then(|windows| windows.as_array())
        .expect("windows list");
    let attached_at = record.get("attached_at_ns").expect("attached_at_ns");
    const KNOWN_REASONS: [&str; 5] = [
        "pre_attach",
        "late_discovery",
        "mapped_unattached",
        "health_loss",
        "scope_uncertain",
    ];
    let mut wellformed_named = true;
    let mut pre_attach_ends_at_attach = false;
    for window in windows {
        let start_ns = window.get("start_ns").and_then(|s| s.as_u64());
        let end_ns = window.get("end_ns").and_then(|e| e.as_u64());
        let reason = window.get("reason").and_then(|r| r.as_str());
        let wellformed = start_ns.is_some_and(|start| start > 0)
            && end_ns.is_some_and(|end| start_ns.is_some_and(|start| start < end))
            && reason.is_some_and(|reason| KNOWN_REASONS.contains(&reason));
        wellformed_named &= wellformed;
        if reason == Some("pre_attach") && window.get("end_ns") == Some(attached_at) {
            pre_attach_ends_at_attach = true;
        }
    }
    assert!(
        shared_twin_accepts(
            main_exact,
            holder_total,
            windows.len(),
            wellformed_named,
            pre_attach_ends_at_attach
        ),
        "honest accounting: main {main_pid} events {main_events:?} vs ledger {ledger_counts:?}; \
         holder {holder_pid} counted {holder_total} (its ledger {holder_counts:?} sits in the gap); \
         windows {windows:?} attached_at {attached_at}"
    );
}

/// The two-round cell's verdict, factored out so its negative
/// controls run unprivileged: the counted `C_Initialize` total for
/// the copy's sha, the record's opens-before-staging tally, and the
/// staged learned-file count.
fn learned_second_round_accepts(
    caught: u64,
    pre_attach_loads: Option<u64>,
    staged: Option<u64>,
) -> bool {
    caught == 20 && pre_attach_loads == Some(1) && staged.is_some_and(|staged| staged >= 1)
}

/// Negative controls for the verdict above: only a complete second
/// round may pass. In particular the combined total 19 — reachable
/// as one first-round call counted after a mid-run attach plus only
/// 18 of 20 second-round calls — must be rejected, as must every
/// schedule that misses even one second-round call.
#[test]
fn learned_second_round_oracle_requires_every_second_round_call() {
    assert!(learned_second_round_accepts(20, Some(1), Some(1)));
    assert!(
        !learned_second_round_accepts(19, Some(1), Some(1)),
        "first=1 plus second=18 must not pass"
    );
    assert!(!learned_second_round_accepts(18, Some(1), Some(1)));
    assert!(!learned_second_round_accepts(21, Some(1), Some(1)));
    assert!(!learned_second_round_accepts(20, Some(0), Some(1)));
    assert!(!learned_second_round_accepts(20, Some(2), Some(1)));
    assert!(!learned_second_round_accepts(20, None, Some(1)));
    assert!(!learned_second_round_accepts(20, Some(1), Some(0)));
    assert!(!learned_second_round_accepts(20, Some(1), None));
}

/// Two-round kernel learning (owner acceptance): a brand-new provider
/// file at a random path, held by no live process and named by no
/// `--module`/`--prearm-module`/`--manifest`, under one
/// `profile --system` capture. Round 1 is one one-shot tool run: its
/// calls may be missed, but the run must be shown as a named miss
/// (provider path + loading program). Round 2 is twenty identical
/// one-shot runs in the same capture: every one must be counted.
///
/// The rounds are isolated by construction, not by arithmetic on the
/// combined total: only the observer is stopped (SIGSTOP) after its
/// ready line — group and marks already exist, so opens queue in the
/// kernel — round 1 then runs to completion and exits while no probe
/// for this file can possibly exist yet, and the resumed observer
/// drains its real fanotify queue, stages the file, and attaches it
/// with the round-1 process already dead. Every counted call is
/// therefore a round-2 call, and the verdict requires all twenty
/// (see `learned_second_round_accepts` and its negative controls).
/// The opens-before-staging tally (`pre_attach_loads == 1`, exactly
/// the round-1 loader; nothing else opens this unique-sha copy) and
/// the staging event observed between the rounds pin that round 1
/// was learned from, not scan-covered: a scan-caught round 1 would
/// stage nothing. The tally alone would not prove round-1 calls were
/// missed — it counts opens before *staging*, not calls before
/// *attachment* — which is why the stopped-observer round, not the
/// tally, carries the isolation.
#[test]
#[ignore = "privileged: learned provider second round catches one-shot tools (root, BPF, SoftHSM, pkcs11-tool)"]
fn privileged_profile_system_learned_provider_second_round_catches_oneshots() {
    let tool = ["/usr/bin/pkcs11-tool", "/usr/local/bin/pkcs11-tool"]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("a pkcs11-tool binary must be installed for the cell");
    let dir = tempfile::tempdir().expect("cell dir");
    let conf = init_token(dir.path());
    // Brand-new provider file: random path, new inode, and a sha256 no
    // ambient system user shares (trailing bytes), so counts for its
    // sha can only come from this cell's tool runs.
    let copy = dir.path().join(format!(
        "libbrandnew-{}-{}.so",
        std::process::id(),
        "x7learn"
    ));
    std::fs::copy(softhsm_path(), &copy).expect("copy provider");
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&copy)
            .expect("open copy for append");
        file.write_all(&[0u8; 256]).expect("append unseen bytes");
    }
    let run_tool = |what: &str| {
        let status = Command::new(&tool)
            .args(["--module", &copy.to_string_lossy(), "-L"])
            .env("SOFTHSM2_CONF", &conf)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn pkcs11-tool");
        assert!(status.success(), "{what}: pkcs11-tool run must succeed");
    };
    // The copy really loads (outside the capture: teaches nothing).
    run_tool("pre-capture dlopen check");

    // This cell's waits are load-tolerant by construction: a loaded
    // host's system scan alone can exceed the shared 60 s harness
    // deadlines, so the capture is spawned and read locally with
    // chunked reads and explicit long deadlines, diagnostics (not
    // verbose text) name the staging event, and an operator SIGINT
    // ends the capture once round 2 is done instead of a fixed
    // duration racing the arm latency. Every wait still fails loud.
    fn next_line_within(capture: &mut GuardedChild, what: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            if let Some(pos) = capture.buf.iter().position(|b| *b == b'\n') {
                let line = capture.buf.drain(..=pos).collect::<Vec<_>>();
                return String::from_utf8(line).expect("child speaks UTF-8");
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "{what} silent for {within:?}");
            let mut pfd = libc::pollfd {
                fd: capture.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll on our own pipe end.
            let ready = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis() as i32) };
            assert!(ready > 0, "{what} silent for {within:?}");
            if pfd.revents & libc::POLLIN == 0 {
                panic!("{what}: pipe hung up");
            }
            let mut chunk = [0u8; 8192];
            // SAFETY: chunked read into a stack buffer.
            let got =
                unsafe { libc::read(capture.fd.as_raw_fd(), chunk.as_mut_ptr().cast(), 8192) };
            if got == 0 {
                panic!("{what}: EOF (child status: {:?})", capture.try_wait());
            }
            if got < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::WouldBlock,
                    "{what} read"
                );
                continue;
            }
            capture.buf.extend_from_slice(&chunk[..got as usize]);
        }
    }
    fn wait_line(capture: &mut GuardedChild, what: &str, needle: &str) {
        loop {
            let line = next_line_within(capture, what, Duration::from_secs(300));
            if line.contains(needle) {
                return;
            }
        }
    }
    fn wait_pred(capture: &mut GuardedChild, what: &str, mut pred: impl FnMut(&str) -> bool) {
        loop {
            let line = next_line_within(capture, what, Duration::from_secs(300));
            if pred(&line) {
                return;
            }
        }
    }

    let out = dir.path().join("out.json");
    let mut child = Command::new(bin())
        .args([
            "profile",
            "--system",
            "--duration",
            "600",
            "-o",
            out.to_str().expect("utf8 out"),
        ])
        .env("P11SCOPE_CAPTURE_DIAGNOSTICS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn capture");
    let stderr = child.stderr.take().expect("capture stderr");
    let mut capture = GuardedChild::new(child, stderr);
    wait_line(&mut capture, "capture ready", READY_LINE);
    // Stop only the observer (its fanotify group and marks exist, so
    // opens queue in the kernel) and run round 1 to completion: no
    // probe for this file can exist while the observer is stopped,
    // so no round-1 call can be counted, whatever the expedited
    // attach would otherwise have raced. Resuming drains the real
    // queued open through staging and attach with the round-1
    // process already exited, isolating the round-2 count exactly.
    // SAFETY: signalling our own capture child.
    assert_eq!(
        unsafe { libc::kill(capture.child.id() as i32, libc::SIGSTOP) },
        0,
        "stop capture for round 1"
    );
    // Round 1: the first-ever run against this file in the capture.
    run_tool("round 1");
    // SAFETY: signalling our own capture child.
    assert_eq!(
        unsafe { libc::kill(capture.child.id() as i32, libc::SIGCONT) },
        0,
        "resume capture after round 1"
    );
    // Wait for the learning event itself (the diagnostics staging line
    // names the copy), then a few ordinary frames for the expedited
    // attach, so the rate below measures steady-state catching, not
    // arm latency on a small or loaded host.
    let copy_name = copy
        .file_name()
        .expect("copy file name")
        .to_string_lossy()
        .into_owned();
    wait_pred(&mut capture, "learned staging", |line| {
        is_fresh_staging_line_for(line, &copy_name)
    });
    std::thread::sleep(Duration::from_secs(10));
    // Round 2: twenty one-shot runs, no retry masking the rate.
    for index in 0..20 {
        run_tool(&format!("round 2 run {index}"));
        std::thread::sleep(Duration::from_millis(50));
    }
    // Operator stop: the report must still be written (data-always).
    // SAFETY: signalling our own capture child.
    assert_eq!(
        unsafe { libc::kill(capture.child.id() as i32, libc::SIGINT) },
        0,
        "signal capture"
    );
    let deadline = Instant::now() + Duration::from_secs(300);
    let status = loop {
        if let Some(status) = capture.try_wait() {
            break status;
        }
        assert!(Instant::now() < deadline, "capture would not exit");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        status.success() || status.code() == Some(130),
        "capture exits clean or as an operator interrupt: {status}"
    );
    let text = std::fs::read_to_string(&out).expect("read profile");
    let profile: serde_json::Value = serde_json::from_str(&text).expect("profile is JSON");

    let record = module_record(&profile, &copy);
    let calls = function_calls(&profile, record_sha256(record));
    let caught = calls.get("C_Initialize").copied().unwrap_or(0);
    // The provider is listed with the program that first loaded it.
    let first = record
        .get("first_loaded_by")
        .unwrap_or_else(|| panic!("learned module names its first loader: {record}"));
    let exe = first.get("exe").and_then(|exe| exe.as_str());
    let unknown = first
        .get("exe_unknown_reason")
        .and_then(|reason| reason.as_str());
    assert!(
        exe.is_some_and(|exe| exe.ends_with("pkcs11-tool"))
            || unknown == Some("loader exe link unreadable"),
        "first loader named or finitely unknown: {first}"
    );
    let pre_attach_loads = first
        .get("pre_attach_loads")
        .and_then(|loads| loads.as_u64());
    let staged = profile["evidence"]["learned_staged_files"].as_u64();
    assert!(
        learned_second_round_accepts(caught, pre_attach_loads, staged),
        "every round-2 call must be counted and round 1 stays a named \
         miss; C_Initialize for the copy = {caught} (all calls: \
         {calls:?}), pre_attach_loads = {pre_attach_loads:?}, staged = \
         {staged:?} (evidence: {})",
        profile["evidence"]
    );
    // The first run is a named miss, not silent.
    assert!(
        has_first_use_gap_record(&profile),
        "first run must be a named gap"
    );
}

/// Private-mount-namespace file holder. Usage: `holder PATH`. Opens
/// the file (no mapping: scans cannot see an unmapped open) and
/// sleeps, so the private namespace and its mount table stay alive
/// for the whole capture. Prints `READY pid=N` and exits 3 on any
/// setup failure.
const MNT_HOLDER_C: &str = r#"
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s PATH\n", argv[0]);
        return 2;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "holder: cannot open %s\n", argv[1]);
        return 3;
    }
    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    sleep(300);
    return 0;
}
"#;

/// Compiles the holder with the system compiler.
fn build_mnt_holder(dir: &Path) -> PathBuf {
    let src = dir.join("p28-mnt-holder.c");
    std::fs::write(&src, MNT_HOLDER_C).expect("write holder source");
    let out = dir.join("p28-mnt-holder");
    let compile = Command::new("gcc")
        .args(["-O2", "-o"])
        .arg(&out)
        .arg(&src)
        .output()
        .expect("execute gcc for the holder");
    assert!(
        compile.status.success(),
        "holder compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    out
}

/// A tmpfs mount that unmounts on drop, before the cell tempdir goes
/// (declared after the tempdir, so it drops first).
struct TmpfsMount {
    path: PathBuf,
}

impl TmpfsMount {
    fn mount(path: &Path) -> Self {
        std::fs::create_dir_all(path).expect("private mnt dir");
        let status = Command::new("mount")
            .args(["-t", "tmpfs", "tmpfs"])
            .arg(path)
            .status()
            .expect("spawn mount");
        assert!(status.success(), "mount tmpfs at {}", path.display());
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl Drop for TmpfsMount {
    fn drop(&mut self) {
        let status = Command::new("umount").arg(&self.path).status();
        if !status.as_ref().is_ok_and(|status| status.success()) {
            // A red-run holder may still hold the mount busy: detach
            // lazily so the tmpfs cannot leak over the deleted tempdir
            // path, and say so — the leak would otherwise be silent.
            let _ = Command::new("umount").args(["-l"]).arg(&self.path).status();
            eprintln!(
                "p11scope test: umount {} failed ({status:?}); retried with -l",
                self.path.display()
            );
        }
    }
}

/// The private-mount verdict, factored out so its negative controls
/// run unprivileged: the learned staging markers (the record names
/// its first loader, exactly one pre-attach load, at least one file
/// staged, the named first-use gap) plus ledger-exact counts with no
/// calls outside the ledger.
fn learned_private_mount_accepts(
    loader_named: bool,
    pre_attach_loads: Option<u64>,
    staged: Option<u64>,
    first_use_gap: bool,
    counts_exact: bool,
    spurious: u64,
) -> bool {
    loader_named
        && pre_attach_loads == Some(1)
        && staged.is_some_and(|staged| staged >= 1)
        && first_use_gap
        && counts_exact
        && spurious == 0
}

/// Negative controls for the verdict above: only the complete
/// private-mount round may pass.
#[test]
fn learned_private_mount_oracle_requires_the_full_round() {
    assert!(learned_private_mount_accepts(
        true,
        Some(1),
        Some(1),
        true,
        true,
        0
    ));
    assert!(!learned_private_mount_accepts(
        false,
        Some(1),
        Some(1),
        true,
        true,
        0
    ));
    assert!(!learned_private_mount_accepts(
        true,
        Some(0),
        Some(1),
        true,
        true,
        0
    ));
    assert!(!learned_private_mount_accepts(
        true,
        Some(2),
        Some(1),
        true,
        true,
        0
    ));
    assert!(!learned_private_mount_accepts(
        true,
        None,
        Some(1),
        true,
        true,
        0
    ));
    assert!(!learned_private_mount_accepts(
        true,
        Some(1),
        Some(0),
        true,
        true,
        0
    ));
    assert!(!learned_private_mount_accepts(
        true,
        Some(1),
        None,
        true,
        true,
        0
    ));
    assert!(!learned_private_mount_accepts(
        true,
        Some(1),
        Some(1),
        false,
        true,
        0
    ));
    assert!(!learned_private_mount_accepts(
        true,
        Some(1),
        Some(1),
        true,
        false,
        0
    ));
    assert!(!learned_private_mount_accepts(
        true,
        Some(1),
        Some(1),
        true,
        true,
        1
    ));
}

/// Whether a capture-diagnostics line is the fresh-staging record for
/// the exact `file_name`: the engine emits
/// `p11scope: learned provider {display} (first loaded by {loader}):
/// {loads} earlier loads missed; attached for later runs` exactly once
/// per newly staged file. Another copy, an `already staged` note, an
/// `already scan-covered; not staged` refusal, or gap prose never
/// match: the name is boundary-pinned (`/name (`), the shape is exact.
fn is_fresh_staging_line_for(line: &str, file_name: &str) -> bool {
    // The engine emits `p11scope: learned provider {display} (first
    // loaded by {loader}): {loads} earlier loads missed; attached for
    // later runs` exactly once per newly staged file. Only the display
    // field names the file: the basename must end the display at a
    // slash boundary, and the loader segment must keep its own
    // "<loader>): <loads>" shape, so loader free text can never match.
    const PREFIX: &str = "p11scope: learned provider ";
    const MID: &str = " (first loaded by ";
    const SUFFIX: &str = " earlier loads missed; attached for later runs";
    let line = line.trim_end();
    let Some(rest) = line.strip_prefix(PREFIX) else {
        return false;
    };
    let Some(rest) = rest.strip_suffix(SUFFIX) else {
        return false;
    };
    let Some(split) = rest.find(MID) else {
        return false;
    };
    let (display, after) = rest.split_at(split);
    let loader = &after[MID.len()..];
    display
        .strip_suffix(file_name)
        .is_some_and(|prefix| prefix.ends_with('/'))
        && loader.contains("): ")
        && !loader.contains(MID)
}

/// Negative controls for the staging gate above: only the fresh
/// staging record for the exact file may release the workload.
#[test]
fn fresh_staging_line_names_the_exact_file_and_shape() {
    let file_name = "libprivatemnt-123-p28.so";
    assert!(is_fresh_staging_line_for(
        "p11scope: learned provider /tmp/cell/mnt/libprivatemnt-123-p28.so (first loaded by /tmp/cell/p28-mnt-holder): 1 earlier loads missed; attached for later runs\n",
        file_name,
    ));
    // Another copy's fresh staging is foreign evidence.
    assert!(!is_fresh_staging_line_for(
        "p11scope: learned provider /tmp/cell/mnt/libprivatemnt-456-p28.so (first loaded by /tmp/cell/p28-mnt-holder): 1 earlier loads missed; attached for later runs\n",
        file_name,
    ));
    // A refusal in place of staging, for the same file.
    assert!(!is_fresh_staging_line_for(
        "p11scope: learned provider /tmp/cell/mnt/libprivatemnt-123-p28.so already staged; loader note added\n",
        file_name,
    ));
    assert!(!is_fresh_staging_line_for(
        "p11scope: learned provider /tmp/cell/mnt/libprivatemnt-123-p28.so already scan-covered; not staged\n",
        file_name,
    ));
    // Gap prose without the staging shape.
    assert!(!is_fresh_staging_line_for(
        "note: learned provider file libprivatemnt-123-p28.so learned after its first use\n",
        file_name,
    ));
    // A substring trap: a longer name sharing the file name as a prefix.
    assert!(!is_fresh_staging_line_for(
        "p11scope: learned provider /tmp/cell/mnt/libprivatemnt-123-p28.so.evil (first loaded by /tmp/cell/p28-mnt-holder): 1 earlier loads missed; attached for later runs\n",
        file_name,
    ));
}

/// The requested basename inside the free-text loader field is foreign
/// evidence: only the display field names the staged file. A line
/// staging `/tmp/other.so` whose loader text carries the requested
/// basename must never release the workload.
#[test]
fn fresh_staging_line_rejects_loader_field_injection() {
    let file_name = "libprivatemnt-123-p28.so";
    assert!(!is_fresh_staging_line_for(
        "p11scope: learned provider /tmp/other.so (first loaded by /tmp/cell/libprivatemnt-123-p28.so (first loaded by /tmp/x): 1 earlier loads missed; attached for later runs\n",
        file_name,
    ));
}

/// Only the exact staging shape for the exact display basename gates
/// the workload: leading space, trailing junk, a loader segment
/// without its "<loader>): <loads>" shape, or the basename without
/// its slash boundary never match.
#[test]
fn fresh_staging_line_rejects_malformed_staging_lines() {
    let file_name = "libprivatemnt-123-p28.so";
    // Leading space before the diagnostics tag.
    assert!(!is_fresh_staging_line_for(
        "  p11scope: learned provider /tmp/cell/mnt/libprivatemnt-123-p28.so (first loaded by /tmp/cell/p28-mnt-holder): 1 earlier loads missed; attached for later runs\n",
        file_name,
    ));
    // Trailing junk past the exact shape.
    assert!(!is_fresh_staging_line_for(
        "p11scope: learned provider /tmp/cell/mnt/libprivatemnt-123-p28.so (first loaded by /tmp/cell/p28-mnt-holder): 1 earlier loads missed; attached for later runs; retried\n",
        file_name,
    ));
    // Loader segment without the "<loader>): <loads>" shape.
    assert!(!is_fresh_staging_line_for(
        "p11scope: learned provider /tmp/cell/mnt/libprivatemnt-123-p28.so (first loaded by 1 earlier loads missed; attached for later runs\n",
        file_name,
    ));
    // Basename as a suffix without its slash boundary.
    assert!(!is_fresh_staging_line_for(
        "p11scope: learned provider /tmp/cell/mnt/prefixlibprivatemnt-123-p28.so (first loaded by /tmp/cell/p28-mnt-holder): 1 earlier loads missed; attached for later runs\n",
        file_name,
    ));
    // A display path carrying its own loader separator: the split
    // would land inside the display, so the loader side must reject.
    assert!(!is_fresh_staging_line_for(
        "p11scope: learned provider /tmp/cell/mnt/libprivatemnt-123-p28.so (first loaded by impostor) (first loaded by /tmp/cell/p28-mnt-holder): 1 earlier loads missed; attached for later runs\n",
        file_name,
    ));
}

/// Whether the profile carries the learned first-use gap as a
/// structured skip row for the exact subject and reason: only an
/// `evidence.skipped[]` entry with render's `SkippedOut` name/reason
/// proves the gap — the same phrases anywhere else in the document
/// (a note, a path, another row's text) prove nothing.
fn has_first_use_gap_record(profile: &serde_json::Value) -> bool {
    // Keep beside render::LEARNED_SKIP_SUBJECT / LEARNED_FIRST_RUN_REASON.
    const SUBJECT: &str = "learned provider file";
    const REASON: &str =
        "a provider file was learned after its first use; its earlier calls were not observed";
    profile["evidence"]["skipped"]
        .as_array()
        .is_some_and(|skipped| {
            skipped.iter().any(|skip| {
                skip["name"].as_str() == Some(SUBJECT) && skip["reason"].as_str() == Some(REASON)
            })
        })
}

/// Negative controls for the gap record above: only the structured
/// skip row counts.
#[test]
fn first_use_gap_record_requires_the_structured_skip() {
    let row = serde_json::json!({
        "name": "learned provider file",
        "reason": "a provider file was learned after its first use; its earlier calls were not observed",
    });
    assert!(has_first_use_gap_record(
        &serde_json::json!({"evidence": {"skipped": [row]}})
    ));
    // The same phrases outside any skip row.
    assert!(!has_first_use_gap_record(&serde_json::json!({
        "evidence": {
            "skipped": [],
            "note": "learned provider file x learned after its first use",
        }
    })));
    // The right subject with the wrong reason.
    assert!(!has_first_use_gap_record(&serde_json::json!({
        "evidence": {"skipped": [{
            "name": "learned provider file",
            "reason": "file-learning events were lost; some provider files may not have been learned",
        }]}
    })));
    // No evidence section at all.
    assert!(!has_first_use_gap_record(&serde_json::json!({})));
}

/// The workload ledger as one typed result: exactly the eight
/// counters the C fixture emits, with the counts its loop dictates.
/// Per iteration the fixture issues one `C_GetInfo`, one unconditional
/// `C_GetSlotList` plus one more when the slot set is non-empty, one
/// `C_GetSlotInfo`/`C_GetTokenInfo` per listed slot (at most 64 per
/// iteration), and per listed slot one `C_GetMechanismList` plus one
/// more — with one `C_GetMechanismInfo` — when the slot has
/// mechanisms. An empty, partial, or impossible ledger never
/// validates — comparing exact counts against silence, or against
/// counts the fixture cannot emit, would pass on nothing observed.
struct WorkloadLedger {
    initialize: u64,
    finalize: u64,
    get_info: u64,
    get_slot_list: u64,
    get_slot_info: u64,
    get_token_info: u64,
    get_mechanism_list: u64,
    get_mechanism_info: u64,
}

impl WorkloadLedger {
    fn parse(ledger: &BTreeMap<String, u64>) -> Option<Self> {
        const NAMES: [&str; 8] = [
            "C_Initialize",
            "C_Finalize",
            "C_GetInfo",
            "C_GetSlotList",
            "C_GetSlotInfo",
            "C_GetTokenInfo",
            "C_GetMechanismList",
            "C_GetMechanismInfo",
        ];
        if ledger.len() != NAMES.len() || NAMES.iter().any(|name| !ledger.contains_key(*name)) {
            return None;
        }
        let get = |name: &str| ledger.get(name).copied().unwrap_or(0);
        Some(Self {
            initialize: get("C_Initialize"),
            finalize: get("C_Finalize"),
            get_info: get("C_GetInfo"),
            get_slot_list: get("C_GetSlotList"),
            get_slot_info: get("C_GetSlotInfo"),
            get_token_info: get("C_GetTokenInfo"),
            get_mechanism_list: get("C_GetMechanismList"),
            get_mechanism_info: get("C_GetMechanismInfo"),
        })
    }

    fn validates(&self) -> bool {
        let iters = u64::from(ITERS);
        if self.initialize != 1 || self.finalize != 1 || self.get_info != iters {
            return false;
        }
        // One unconditional slot-list query per iteration, plus one per
        // iteration with a non-empty slot set.
        if !(iters..=2 * iters).contains(&self.get_slot_list) {
            return false;
        }
        // Slot info and token info share one loop over the listed slots.
        if self.get_slot_info != self.get_token_info {
            return false;
        }
        let iters_with_slots = self.get_slot_list.saturating_sub(iters);
        // Every iteration with slots lists 1..=64 of them.
        if self.get_slot_info < iters_with_slots
            || self.get_slot_info > iters_with_slots.saturating_mul(64)
        {
            return false;
        }
        // One mechanism-list query per listed slot, plus one per slot
        // with mechanisms; mechanism info runs at most once per slot.
        // (Saturating: absurd counts already fail the slot bounds above.)
        let mech_want = self.get_slot_info.saturating_add(self.get_mechanism_info);
        if self.get_mechanism_list != mech_want || self.get_mechanism_info > self.get_slot_info {
            return false;
        }
        true
    }
}

/// Whether the workload ledger has the known shape the C fixture
/// emits, validated as one typed result (see [`WorkloadLedger`]).
fn validate_workload_ledger(ledger: &BTreeMap<String, u64>) -> bool {
    WorkloadLedger::parse(ledger).is_some_and(|typed| typed.validates())
}

/// Negative controls for the ledger shape above: only the known
/// eight-counter ledger validates.
#[test]
fn workload_ledger_validator_requires_the_known_shape() {
    fn ledger(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs
            .iter()
            .map(|(name, count)| ((*name).to_string(), *count))
            .collect()
    }
    let good = ledger(&[
        ("C_Initialize", 1),
        ("C_Finalize", 1),
        ("C_GetInfo", u64::from(ITERS)),
        ("C_GetSlotList", 10),
        ("C_GetSlotInfo", 5),
        ("C_GetTokenInfo", 5),
        ("C_GetMechanismList", 10),
        ("C_GetMechanismInfo", 5),
    ]);
    assert!(validate_workload_ledger(&good));
    // Silence never validates.
    assert!(!validate_workload_ledger(&BTreeMap::new()));
    // A missing counter never validates.
    let mut missing = good.clone();
    missing.remove("C_GetInfo");
    assert!(!validate_workload_ledger(&missing));
    // A cold Initialize (the workload never ran) never validates.
    let mut cold = good.clone();
    cold.insert("C_Initialize".to_string(), 0);
    assert!(!validate_workload_ledger(&cold));
    // A drifted hot count never validates.
    let mut drifted = good.clone();
    drifted.insert("C_GetInfo".to_string(), u64::from(ITERS) + 1);
    assert!(!validate_workload_ledger(&drifted));
    // An unexpected ninth counter never validates.
    let mut extra = good.clone();
    extra.insert("C_Extra".to_string(), 1);
    assert!(!validate_workload_ledger(&extra));
}

/// Key presence is load-bearing: a zero `C_GetMechanismInfo` is valid
/// (slots without mechanisms), so only the name check — not the
/// length or value checks — refuses a ledger that swaps the
/// mechanism-info counter for an unknown key.
#[test]
fn workload_ledger_validator_requires_every_counter_by_name() {
    fn ledger(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs
            .iter()
            .map(|(name, count)| ((*name).to_string(), *count))
            .collect()
    }
    // Valid zero-mechanism ledger: every listed slot answered its
    // mechanism list with an empty set, so no mechanism info ran.
    let good = ledger(&[
        ("C_Initialize", 1),
        ("C_Finalize", 1),
        ("C_GetInfo", u64::from(ITERS)),
        ("C_GetSlotList", 2 * u64::from(ITERS)),
        ("C_GetSlotInfo", u64::from(ITERS)),
        ("C_GetTokenInfo", u64::from(ITERS)),
        ("C_GetMechanismList", u64::from(ITERS)),
        ("C_GetMechanismInfo", 0),
    ]);
    assert!(validate_workload_ledger(&good));
    // The same counts with the zero mechanism-info counter swapped
    // for an unknown key: length and relationships still hold, but
    // the required name is gone.
    let mut swapped = good.clone();
    swapped.remove("C_GetMechanismInfo");
    swapped.insert("C_Extra".to_string(), 1);
    assert!(
        !validate_workload_ledger(&swapped),
        "a swapped-out counter name never validates"
    );
}

/// The C fixture attempts one `C_GetSlotList` per iteration
/// unconditionally, plus one more per iteration that lists a
/// non-empty slot set — so the count is always within
/// `ITERS..=2 * ITERS`. Zero slot-list attempts on a successful run
/// are impossible and never validate.
#[test]
fn workload_ledger_validator_rejects_impossible_slot_list_counts() {
    fn ledger(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs
            .iter()
            .map(|(name, count)| ((*name).to_string(), *count))
            .collect()
    }
    let good = ledger(&[
        ("C_Initialize", 1),
        ("C_Finalize", 1),
        ("C_GetInfo", u64::from(ITERS)),
        ("C_GetSlotList", 2 * u64::from(ITERS)),
        ("C_GetSlotInfo", u64::from(ITERS)),
        ("C_GetTokenInfo", u64::from(ITERS)),
        ("C_GetMechanismList", 2 * u64::from(ITERS)),
        ("C_GetMechanismInfo", u64::from(ITERS)),
    ]);
    assert!(validate_workload_ledger(&good));
    // Zero slot-list attempts are impossible on a successful run.
    let mut silent_slots = good.clone();
    silent_slots.insert("C_GetSlotList".to_string(), 0);
    silent_slots.insert("C_GetSlotInfo".to_string(), 0);
    silent_slots.insert("C_GetTokenInfo".to_string(), 0);
    silent_slots.insert("C_GetMechanismList".to_string(), 0);
    silent_slots.insert("C_GetMechanismInfo".to_string(), 0);
    assert!(
        !validate_workload_ledger(&silent_slots),
        "zero slot-list attempts cannot come from this fixture"
    );
    // Below the unconditional floor, and above the two-per-iteration cap.
    for bad in [u64::from(ITERS) - 1, 2 * u64::from(ITERS) + 1] {
        let mut out_of_range = good.clone();
        out_of_range.insert("C_GetSlotList".to_string(), bad);
        assert!(
            !validate_workload_ledger(&out_of_range),
            "C_GetSlotList = {bad} is outside ITERS..=2*ITERS"
        );
    }
    // Isolated bound violations: silent slots below the floor fail
    // only the lower bound, and consistent slot counters above the cap
    // fail only the upper bound.
    let mut below_floor = good.clone();
    below_floor.insert("C_GetSlotList".to_string(), u64::from(ITERS) - 1);
    below_floor.insert("C_GetSlotInfo".to_string(), 0);
    below_floor.insert("C_GetTokenInfo".to_string(), 0);
    below_floor.insert("C_GetMechanismList".to_string(), 0);
    below_floor.insert("C_GetMechanismInfo".to_string(), 0);
    assert!(!validate_workload_ledger(&below_floor));
    let mut above_cap = good.clone();
    above_cap.insert("C_GetSlotList".to_string(), 2 * u64::from(ITERS) + 1);
    above_cap.insert("C_GetSlotInfo".to_string(), u64::from(ITERS) + 1);
    above_cap.insert("C_GetTokenInfo".to_string(), u64::from(ITERS) + 1);
    above_cap.insert("C_GetMechanismList".to_string(), 2 * (u64::from(ITERS) + 1));
    above_cap.insert("C_GetMechanismInfo".to_string(), u64::from(ITERS) + 1);
    assert!(!validate_workload_ledger(&above_cap));
}

/// The C loop dictates the slot/mechanism relationships: slot info and
/// token info run once per listed slot, the mechanism list runs once
/// per slot plus once per slot with mechanisms, and mechanism info
/// runs at most once per slot. Ledgers breaking these shapes never
/// validate.
#[test]
fn workload_ledger_validator_requires_slot_mechanism_relationships() {
    fn ledger(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs
            .iter()
            .map(|(name, count)| ((*name).to_string(), *count))
            .collect()
    }
    let good = ledger(&[
        ("C_Initialize", 1),
        ("C_Finalize", 1),
        ("C_GetInfo", u64::from(ITERS)),
        ("C_GetSlotList", 2 * u64::from(ITERS)),
        ("C_GetSlotInfo", u64::from(ITERS)),
        ("C_GetTokenInfo", u64::from(ITERS)),
        ("C_GetMechanismList", 2 * u64::from(ITERS)),
        ("C_GetMechanismInfo", u64::from(ITERS)),
    ]);
    assert!(validate_workload_ledger(&good));
    // Slot info and token info share one loop over the listed slots.
    let mut split_slots = good.clone();
    split_slots.insert("C_GetTokenInfo".to_string(), u64::from(ITERS) - 1);
    assert!(!validate_workload_ledger(&split_slots));
    // The mechanism list is one per slot plus one per slot with mechanisms.
    let mut drifted_mech_list = good.clone();
    drifted_mech_list.insert("C_GetMechanismList".to_string(), 2 * u64::from(ITERS) + 1);
    assert!(!validate_workload_ledger(&drifted_mech_list));
    // Mechanism info runs at most once per listed slot.
    let mut extra_mech_info = good.clone();
    extra_mech_info.insert("C_GetMechanismInfo".to_string(), u64::from(ITERS) + 1);
    assert!(!validate_workload_ledger(&extra_mech_info));
    // Listed slots without the second slot-list query are impossible:
    // every iteration that lists slots issues both queries.
    let mut slots_without_query = good.clone();
    slots_without_query.insert("C_GetSlotList".to_string(), u64::from(ITERS));
    assert!(!validate_workload_ledger(&slots_without_query));
    // Fewer listed slots than iterations with slots: every such
    // iteration lists at least one slot.
    let mut thin_slots = good.clone();
    thin_slots.insert("C_GetSlotInfo".to_string(), u64::from(ITERS) - 1);
    thin_slots.insert("C_GetTokenInfo".to_string(), u64::from(ITERS) - 1);
    thin_slots.insert("C_GetMechanismList".to_string(), 2 * (u64::from(ITERS) - 1));
    thin_slots.insert("C_GetMechanismInfo".to_string(), u64::from(ITERS) - 1);
    assert!(!validate_workload_ledger(&thin_slots));
    // More listed slots than the per-iteration 64-slot cap allows.
    let mut over_cap_slots = good.clone();
    over_cap_slots.insert("C_GetSlotList".to_string(), u64::from(ITERS) + 1);
    over_cap_slots.insert("C_GetSlotInfo".to_string(), 65);
    over_cap_slots.insert("C_GetTokenInfo".to_string(), 65);
    over_cap_slots.insert("C_GetMechanismList".to_string(), 65);
    over_cap_slots.insert("C_GetMechanismInfo".to_string(), 0);
    assert!(!validate_workload_ledger(&over_cap_slots));
    // Mechanism info for more slots than were listed, with a
    // consistent mechanism-list total: info still runs at most once
    // per listed slot.
    let mut over_mech_info = good.clone();
    over_mech_info.insert("C_GetMechanismInfo".to_string(), u64::from(ITERS) + 1);
    over_mech_info.insert("C_GetMechanismList".to_string(), 2 * u64::from(ITERS) + 1);
    assert!(!validate_workload_ledger(&over_mech_info));
}

/// A cold Finalize (the workload never finished) never validates.
#[test]
fn workload_ledger_validator_requires_hot_finalize() {
    fn ledger(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs
            .iter()
            .map(|(name, count)| ((*name).to_string(), *count))
            .collect()
    }
    let good = ledger(&[
        ("C_Initialize", 1),
        ("C_Finalize", 1),
        ("C_GetInfo", u64::from(ITERS)),
        ("C_GetSlotList", 2 * u64::from(ITERS)),
        ("C_GetSlotInfo", u64::from(ITERS)),
        ("C_GetTokenInfo", u64::from(ITERS)),
        ("C_GetMechanismList", 2 * u64::from(ITERS)),
        ("C_GetMechanismInfo", u64::from(ITERS)),
    ]);
    assert!(validate_workload_ledger(&good));
    let mut cold = good.clone();
    cold.insert("C_Finalize".to_string(), 0);
    assert!(!validate_workload_ledger(&cold));
}

/// A shrinking list never validates: five listed slots with ten
/// mechanism-list attempts and zero mechanism-info calls means every
/// fill returned empty after a non-empty count, and ten slot-list
/// attempts with zero listed slots means every fill returned empty
/// after a non-empty count. The fixture refuses both shapes with
/// exit 3 (see the drift-stub twins), so a successful run never
/// emits them; the validator still refuses them if they appear.
#[test]
fn workload_ledger_validator_rejects_a_shrinking_list() {
    fn ledger(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs
            .iter()
            .map(|(name, count)| ((*name).to_string(), *count))
            .collect()
    }
    let mech_drifted = ledger(&[
        ("C_Initialize", 1),
        ("C_Finalize", 1),
        ("C_GetInfo", u64::from(ITERS)),
        ("C_GetSlotList", 2 * u64::from(ITERS)),
        ("C_GetSlotInfo", u64::from(ITERS)),
        ("C_GetTokenInfo", u64::from(ITERS)),
        ("C_GetMechanismList", 2 * u64::from(ITERS)),
        ("C_GetMechanismInfo", 0),
    ]);
    assert!(
        !validate_workload_ledger(&mech_drifted),
        "a mechanism list that shrinks to zero never validates"
    );
    let slot_drifted = ledger(&[
        ("C_Initialize", 1),
        ("C_Finalize", 1),
        ("C_GetInfo", u64::from(ITERS)),
        ("C_GetSlotList", 2 * u64::from(ITERS)),
        ("C_GetSlotInfo", 0),
        ("C_GetTokenInfo", 0),
        ("C_GetMechanismList", 0),
        ("C_GetMechanismInfo", 0),
    ]);
    assert!(
        !validate_workload_ledger(&slot_drifted),
        "a slot list that shrinks to zero never validates"
    );
}

/// Steady control: the fixture exits clean against a stable stub and
/// its ledger validates through the shared producer.
#[test]
fn workload_fixture_accepts_a_stable_stub_ledger() {
    let dir = tempfile::tempdir().expect("cell dir");
    let workload = build_workload(dir.path());
    let stub = build_stub(dir.path(), "stable-stub", STABLE_STUB_C);
    let (status, ledger) = run_workload_against_stub(&workload, &stub, dir.path());
    assert!(status.success(), "a stable stub must exit clean: {status}");
    let counts = read_ledger_file(&ledger);
    assert!(
        validate_workload_ledger(&counts),
        "the stable stub ledger validates: {counts:?}"
    );
}

/// A mechanism list that reports one mechanism and fills zero fails
/// the fixture with exit 3 instead of emitting a ledger the
/// validator must refuse.
#[test]
fn workload_fixture_rejects_a_shrinking_mechanism_list() {
    let dir = tempfile::tempdir().expect("cell dir");
    let workload = build_workload(dir.path());
    let stub = build_stub(dir.path(), "drift-mech-stub", DRIFT_MECH_STUB_C);
    let (status, ledger) = run_workload_against_stub(&workload, &stub, dir.path());
    assert_eq!(
        status.code(),
        Some(3),
        "a shrinking mechanism list fails the fixture"
    );
    assert!(
        !ledger.is_file(),
        "no ledger is emitted on a fixture refusal"
    );
}

/// A slot list that reports one slot and fills zero fails the
/// fixture with exit 3 instead of emitting a ledger the validator
/// must refuse.
#[test]
fn workload_fixture_rejects_a_shrinking_slot_list() {
    let dir = tempfile::tempdir().expect("cell dir");
    let workload = build_workload(dir.path());
    let stub = build_stub(dir.path(), "drift-slot-stub", DRIFT_SLOT_STUB_C);
    let (status, ledger) = run_workload_against_stub(&workload, &stub, dir.path());
    assert_eq!(
        status.code(),
        Some(3),
        "a shrinking slot list fails the fixture"
    );
    assert!(
        !ledger.is_file(),
        "no ledger is emitted on a fixture refusal"
    );
}

/// Whether the exact module record names the private-mount holder as
/// its first loader: the holder lives for the whole capture, so its
/// executable is always readable at learn time and the finite unknown
/// is not accepted here (one-shot loaders in other cells keep their
/// allowance).
fn private_mount_loader_named(first_loaded_by: &serde_json::Value) -> bool {
    first_loaded_by
        .get("exe")
        .and_then(|exe| exe.as_str())
        .is_some_and(|exe| exe.ends_with("p28-mnt-holder"))
}

/// Negative controls for the loader naming above: only the holder's
/// executable counts.
#[test]
fn private_mount_loader_naming_requires_the_holder_exe() {
    assert!(private_mount_loader_named(&serde_json::json!({
        "exe": "/tmp/cell/p28-mnt-holder",
    })));
    // The finite unknown is refused here: the holder is always alive.
    assert!(!private_mount_loader_named(&serde_json::json!({
        "exe_unknown_reason": "loader exe link unreadable",
    })));
    // Another program's executable is foreign evidence.
    assert!(!private_mount_loader_named(&serde_json::json!({
        "exe": "/usr/bin/pkcs11-tool",
    })));
    // A missing loader record names nothing.
    assert!(!private_mount_loader_named(&serde_json::json!({})));
}

/// Exact counts in both directions against a validated ledger: every
/// ledger function observed exactly its count, and the total outside
/// the ledger. Silence passes this comparison — that is why the cell
/// validates the ledger shape first.
fn ledger_counts_match(
    observed: &BTreeMap<String, u64>,
    ledger: &BTreeMap<String, u64>,
) -> (bool, u64) {
    let mut exact = true;
    for (name, want) in ledger {
        if observed.get(name).copied().unwrap_or(0) != *want {
            exact = false;
        }
    }
    let spurious: u64 = observed
        .iter()
        .filter(|(name, _)| !ledger.contains_key(*name))
        .map(|(_, count)| count)
        .sum();
    (exact, spurious)
}

/// The count comparison, including its documented hole: silence
/// passes, so the ledger validator must gate it.
#[test]
fn ledger_counts_comparison_needs_the_validated_ledger() {
    let ledger: BTreeMap<String, u64> = [("C_Initialize".to_string(), 1)].into_iter().collect();
    let same = ledger.clone();
    assert_eq!(ledger_counts_match(&same, &ledger), (true, 0));
    let short: BTreeMap<String, u64> = BTreeMap::new();
    assert_eq!(ledger_counts_match(&short, &ledger), (false, 0));
    let mut noisy = ledger.clone();
    noisy.insert("C_Noisy".to_string(), 2);
    assert_eq!(ledger_counts_match(&noisy, &ledger), (true, 2));
    // The hole the validator closes: silence against silence.
    assert_eq!(
        ledger_counts_match(&BTreeMap::new(), &BTreeMap::new()),
        (true, 0)
    );
}

/// A provider learned from a private mount namespace (owner
/// acceptance): a tmpfs the observer sees is mounted before the
/// capture, so its superblock is marked at startup; a holder in a
/// private namespace (`unshare -m`) opens the provider copy there,
/// so its mount table carries the clone mount with an ID the
/// observer's table never holds. The learned staging must resolve
/// that ID through the loading process's mount table — through the
/// observer's table it reads "fd mount N is missing from the mount
/// table" and the file is lost.
///
/// The opener never maps the file, so no scan can cover it before
/// staging: learning wins deterministically (no scan/learn race).
/// Once staged, an ordinary workload maps the same copy from the
/// observer's namespace and its ledger-exact calls prove the staged
/// file counts. The capture is `profile --system` with no `--module`:
/// learning alone must find the file.
#[test]
#[ignore = "privileged: learned provider from a private mount namespace is learned and counted (root, BPF, SoftHSM, unshare, mount)"]
fn privileged_profile_system_learned_provider_private_mount_is_learned_and_counted() {
    fn next_line_within(capture: &mut GuardedChild, what: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            if let Some(pos) = capture.buf.iter().position(|b| *b == b'\n') {
                let line = capture.buf.drain(..=pos).collect::<Vec<_>>();
                return String::from_utf8(line).expect("child speaks UTF-8");
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "{what} silent for {within:?}");
            let mut pfd = libc::pollfd {
                fd: capture.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll on our own pipe end.
            let ready = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis() as i32) };
            assert!(ready > 0, "{what} silent for {within:?}");
            if pfd.revents & libc::POLLIN == 0 {
                panic!("{what}: pipe hung up");
            }
            let mut chunk = [0u8; 8192];
            // SAFETY: chunked read into a stack buffer.
            let got =
                unsafe { libc::read(capture.fd.as_raw_fd(), chunk.as_mut_ptr().cast(), 8192) };
            if got == 0 {
                panic!("{what}: EOF (child status: {:?})", capture.try_wait());
            }
            if got < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::WouldBlock,
                    "{what} read"
                );
                continue;
            }
            capture.buf.extend_from_slice(&chunk[..got as usize]);
        }
    }
    fn wait_line(capture: &mut GuardedChild, what: &str, needle: &str) {
        loop {
            let line = next_line_within(capture, what, Duration::from_secs(300));
            if line.contains(needle) {
                return;
            }
        }
    }
    /// Waits up to `budget` for a line selected by `pred`, consuming
    /// lines; false on timeout (the caller fails on the verdict, with
    /// the report).
    fn wait_pred_within(
        capture: &mut GuardedChild,
        what: &str,
        budget: Duration,
        mut pred: impl FnMut(&str) -> bool,
    ) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            if Instant::now() >= deadline {
                return false;
            }
            let line = next_line_within(capture, what, Duration::from_secs(60));
            if pred(&line) {
                return true;
            }
        }
    }

    let dir = tempfile::tempdir().expect("cell dir");
    let conf = init_token(dir.path());
    // Tmpfs mounted before the capture: the observer marks its
    // superblock at startup. The holder's private namespace clones
    // the mount with a new ID on the same superblock, so opens
    // still queue events while the ID stays foreign.
    let mnt = dir.path().join("mnt");
    let _tmpfs = TmpfsMount::mount(&mnt);
    // Brand-new provider file with a per-copy trailing nonce, so
    // inode and sha256 are unique to the cell and counts for its sha
    // can only come from this cell's workload.
    let copy = mnt.join(format!("libprivatemnt-{}-p28.so", std::process::id()));
    std::fs::copy(softhsm_path(), &copy).expect("copy provider to tmpfs");
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&copy)
            .expect("open copy for append");
        let mut trailer = [0u8; 256];
        trailer[..8].copy_from_slice(&0x51u64.to_le_bytes());
        trailer[8..12].copy_from_slice(&std::process::id().to_le_bytes());
        file.write_all(&trailer).expect("append unseen bytes");
    }
    let holder = build_mnt_holder(dir.path());
    let workload = build_workload(dir.path());
    let go = dir.path().join("GO");
    let ledger = dir.path().join("ledger");

    let out = dir.path().join("out.json");
    let mut child = Command::new(bin())
        .args([
            "profile",
            "--system",
            "--duration",
            "600",
            "-o",
            out.to_str().expect("utf8 out"),
        ])
        .env("P11SCOPE_CAPTURE_DIAGNOSTICS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn capture");
    let stderr = child.stderr.take().expect("capture stderr");
    let mut capture = GuardedChild::new(child, stderr);
    wait_line(&mut capture, "capture ready", READY_LINE);

    // The holder opens the copy in a private mount namespace and
    // never maps it: no fork, so the child pid is the holder pid
    // and kill-on-drop reaches it.
    let mut holder_child = Command::new("unshare")
        .args(["-m"])
        .arg(&holder)
        .arg(&copy)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn private-namespace holder");
    let holder_pid = holder_child.id();
    let holder_stdout = holder_child.stdout.take().expect("holder stdout");
    let mut holder_guarded = GuardedChild::new(holder_child, holder_stdout);
    let ready = holder_guarded.next_line("holder READY");
    let ready_pid: u32 = ready
        .strip_prefix("READY pid=")
        .unwrap_or_else(|| panic!("holder ready: {ready:?}"))
        .trim()
        .parse()
        .expect("holder ready pid");
    assert_eq!(
        ready_pid, holder_pid,
        "unshare must exec the holder without forking"
    );
    // Twin preconditions, proved while the holder is still alive: it
    // sits in another mount namespace, its tmpfs mount ID is absent
    // from the observer's table (the red shape) but present in its
    // own (the fix's resolution source), and it maps nothing (no
    // scan can cover the file before staging).
    let observer_ns = std::fs::read_link("/proc/self/ns/mnt").expect("observer mount ns");
    let holder_ns =
        std::fs::read_link(format!("/proc/{holder_pid}/ns/mnt")).expect("holder mount ns");
    assert_ne!(
        observer_ns, holder_ns,
        "the holder needs its own mount namespace"
    );
    let mnt_spelling = mnt.to_str().expect("utf8 mnt");
    let holder_mounts =
        std::fs::read_to_string(format!("/proc/{holder_pid}/mountinfo")).expect("holder mounts");
    let holder_row = holder_mounts
        .lines()
        .find(|line| line.split_whitespace().nth(4) == Some(mnt_spelling))
        .unwrap_or_else(|| panic!("holder mounts its tmpfs at {mnt_spelling}"));
    let holder_mnt_id = holder_row
        .split_whitespace()
        .next()
        .expect("holder mount id");
    let observer_mounts = std::fs::read_to_string("/proc/self/mountinfo").expect("observer mounts");
    assert!(
        !observer_mounts
            .lines()
            .any(|line| line.split_whitespace().next() == Some(holder_mnt_id)),
        "the holder mount ID must be foreign to the observer: {holder_mnt_id}"
    );
    let holder_maps =
        std::fs::read_to_string(format!("/proc/{holder_pid}/maps")).expect("holder maps");
    assert!(
        !holder_maps.contains("libprivatemnt-"),
        "the holder must map nothing of the copy"
    );

    // The learning event itself (the fresh-staging record for the
    // exact copy): bounded, so an unlearned file fails on the verdict
    // below instead of hanging. Then a few ordinary frames for the
    // expedited attach, so the workload measures steady-state
    // catching, not arm latency.
    let copy_name = copy
        .file_name()
        .expect("copy file name")
        .to_string_lossy()
        .into_owned();
    let staged_seen = wait_pred_within(
        &mut capture,
        "learned staging",
        Duration::from_secs(300),
        |line| is_fresh_staging_line_for(line, &copy_name),
    );
    std::thread::sleep(Duration::from_secs(10));
    // The workload maps the same copy from the observer's namespace
    // and issues its ledger-exact sequence after staging.
    let (mut driven, _workload_pid) =
        spawn_workload(&workload, &copy, &go, &ledger, &conf, false, false);
    std::fs::write(&go, b"go\n").expect("release the workload");
    let workload_status = driven.wait_expect("workload exit");
    assert!(workload_status.success(), "workload exits clean");
    let ledger_counts = read_ledger_file(&ledger);
    assert!(
        validate_workload_ledger(&ledger_counts),
        "the workload ledger must have its known eight-counter shape: {ledger_counts:?}"
    );
    // Operator stop: the report must still be written (data-always).
    // SAFETY: signalling our own capture child.
    assert_eq!(
        unsafe { libc::kill(capture.child.id() as i32, libc::SIGINT) },
        0,
        "signal capture"
    );
    let deadline = Instant::now() + Duration::from_secs(300);
    let status = loop {
        if let Some(status) = capture.try_wait() {
            break status;
        }
        assert!(Instant::now() < deadline, "capture would not exit");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        status.success() || status.code() == Some(130),
        "capture exits clean or as an operator interrupt: {status}"
    );
    let text = std::fs::read_to_string(&out).expect("read profile");
    let profile: serde_json::Value = serde_json::from_str(&text).expect("profile is JSON");

    let record = module_record(&profile, &copy);
    let observed = function_calls(&profile, record_sha256(record));
    let (counts_exact, spurious) = ledger_counts_match(&observed, &ledger_counts);
    // The provider is listed with the program that first loaded it.
    let first = record.get("first_loaded_by");
    let loader_named = first.is_some_and(private_mount_loader_named);
    let pre_attach_loads = first
        .and_then(|first| first.get("pre_attach_loads"))
        .and_then(|loads| loads.as_u64());
    let staged = profile["evidence"]["learned_staged_files"].as_u64();
    let first_use_gap = has_first_use_gap_record(&profile);
    assert!(
        staged_seen,
        "the learned staging line must name the copy (the file was not learned)"
    );
    assert!(
        learned_private_mount_accepts(
            loader_named,
            pre_attach_loads,
            staged,
            first_use_gap,
            counts_exact,
            spurious
        ),
        "the private-mount file must be learned and counted; loader named = \
         {loader_named} ({first:?}), pre_attach_loads = {pre_attach_loads:?}, staged = \
         {staged:?}, first-use gap = {first_use_gap}, counts exact = {counts_exact} \
         (observed: {observed:?}, ledger: {ledger_counts:?}), spurious = {spurious} \
         (evidence: {})",
        profile["evidence"]
    );
}
