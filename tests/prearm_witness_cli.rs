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

/// Reads the LEDGER file (written by the workload on completion).
fn read_ledger_file(ledger: &Path) -> BTreeMap<String, u64> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Ok(text) = std::fs::read_to_string(ledger)
            && let Some(line) = text.lines().find(|l| l.starts_with("LEDGER "))
        {
            return parse_ledger(line);
        }
        assert!(Instant::now() < deadline, "workload never wrote its ledger");
        std::thread::sleep(Duration::from_millis(50));
    }
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
/// mode flags (`--mode metrics`) or stays empty.
fn run_positive(scope: &str, extra: &[&str]) -> (BTreeMap<String, u64>, serde_json::Value) {
    let dir = tempfile::tempdir().expect("cell dir");
    let module = softhsm_path();
    let conf = init_token(dir.path());
    let workload = build_workload(dir.path());
    let go = dir.path().join("go");
    let ledger = dir.path().join("ledger.txt");
    let out = dir.path().join("out.json");
    let (_workload, pid) = spawn_workload(&workload, &module, &go, &ledger, &conf, false, false);
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
    let status = capture.wait_expect("capture");
    assert!(status.success(), "capture exits clean");
    let text = std::fs::read_to_string(&out).expect("read profile");
    let profile: serde_json::Value = serde_json::from_str(&text).expect("profile is JSON");
    (ledger_counts, profile)
}

#[test]
#[ignore = "privileged: witness P2-8 profile --pid positive cell"]
fn privileged_profile_pid_prearm_clean_exact_counts() {
    let (ledger, profile) = run_positive("pid", &[]);
    let module = softhsm_path();
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
    let (ledger, profile) = run_positive("cgroup", &[]);
    let module = softhsm_path();
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
    let (ledger, profile) = run_positive("system", &[]);
    let module = softhsm_path();
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
    let (ledger, profile) = run_positive("system", &["--mode", "metrics"]);
    let module = softhsm_path();
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
    let module = softhsm_path();
    let conf = init_token(dir.path());
    let workload = build_workload(dir.path());
    let go = dir.path().join("go");
    let ledger = dir.path().join("ledger.txt");
    let out = dir.path().join("out.jsonl");
    let (_workload, _pid) = spawn_workload(&workload, &module, &go, &ledger, &conf, false, false);
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

/// The two-round cell's verdict, factored out so its negative
/// controls run unprivileged: the counted `C_Initialize` total for
/// the copy's sha, the record's opens-before-staging tally, and the
/// staged learned-file count.
fn learned_second_round_accepts(
    caught: u64,
    pre_attach_loads: Option<u64>,
    staged: Option<u64>,
) -> bool {
    (19..=20).contains(&caught)
        && pre_attach_loads == Some(1)
        && staged.is_some_and(|staged| staged >= 1)
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
/// one-shot runs in the same capture: at least 19 must be counted.
///
/// The round boundary is causal, not arithmetic: the staging event is
/// observed on the capture's stderr *after* the round-1 run and
/// *before* any round-2 run, and the final record must show
/// `learned_staged_files >= 1` with `pre_attach_loads == 1` (exactly
/// the round-1 loader tallied before staging; nothing else opens this
/// unique-sha copy). A round-1 run caught by ordinary discovery would
/// be scan-covered and stage nothing. So round 1 is *proven* missed,
/// and a combined `C_Initialize` of 19..=20 over 21 in-capture runs
/// isolates round 2 at >=19/20: one caught round-1 run plus 18
/// round-2 runs cannot satisfy the conjunction.
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
    // Round 1: the first-ever run against this file in the capture.
    run_tool("round 1");
    // Wait for the learning event itself (the diagnostics staging line
    // names the copy), then a few ordinary frames for the expedited
    // attach, so the rate below measures steady-state catching, not
    // arm latency on a small or loaded host.
    wait_line(&mut capture, "learned staging", "libbrandnew-");
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
    let pre_attach_loads = first.get("pre_attach_loads").and_then(|loads| loads.as_u64());
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
        text.contains("learned provider file") && text.contains("learned after its first use"),
        "first run must be a named gap"
    );
}
