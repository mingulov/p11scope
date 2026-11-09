//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Run-tree CLI cells: `p11scope run` follows the command's process
//! tree (v0.7.0). Each cell runs a shell wrapper or a fork/daemonize
//! fixture under `run` against SoftHSM and asserts the descendants'
//! calls land in the profile with ledger-exact counts. The direct
//! child never maps the provider itself, so every observed provider
//! call proves a descendant was followed. All cells pre-arm SoftHSM:
//! unprearmed cold-grandchild exactness is frame-racy by design (the
//! documented short-lived limitation), so committed cells pin the
//! deterministic shape and the operator-shaped unprearmed runs stay
//! manual live proofs. Workloads are runtime-generated C (P2-7
//! `TARGET_C` precedent), so no committed fixtures and no license row.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(120);

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

/// Private token dir + config + one initialized token (P2-8
/// precedent); returns the config path. The caller exports it as
/// `SOFTHSM2_CONF` on the capture, which the command inherits.
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
            "rt",
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

/// A private output dir for the capture's `-o` report: the report
/// trust check refuses world-writable ancestors, so outputs stay out
/// of the opened cell dir. The tempdir is held to the cell's end.
fn out_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("output dir");
    let out = dir.path().join("out.json");
    (dir, out)
}

/// Opens the cell dir for the dropped command: the cell runs as root
/// but `run` drops its child to the invoker, so ledgers, pid files,
/// the token store and the fixtures must be usable by that user.
fn open_cell_dir(dir: &Path) {
    let status = Command::new("chmod")
        .args(["-R", "a+rwX"])
        .arg(dir)
        .status()
        .expect("chmod the cell dir");
    assert!(status.success(), "cell dir opens");
}

/// Compiles one runtime-generated workload with the system compiler.
fn build_c(dir: &Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).expect("write workload source");
    let out = dir.join(name);
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

/// A child with kill-on-drop and bounded waits (never hangs, only
/// fails loudly).
struct GuardedChild {
    child: Child,
}

impl GuardedChild {
    fn wait_expect(&mut self, what: &str) -> std::process::ExitStatus {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
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

/// The observer under test: the `P11SCOPE_E2E_OBSERVER` override when the
/// runner stages a prebuilt binary elsewhere (Fedora delivery), else the
/// binary Cargo built beside this test target.
fn bin() -> PathBuf {
    PathBuf::from(
        std::env::var("P11SCOPE_E2E_OBSERVER")
            .unwrap_or_else(|_| env!("CARGO_BIN_EXE_p11scope").to_string()),
    )
}

/// Static guard: the staged-binary override `bin()` reads is the dedicated
/// `P11SCOPE_E2E_OBSERVER` variable. A stray matrix export must not silently
/// switch the binary in an ordinary `cargo test`, so `bin()` must not read
/// that variable. (The needle is spelled in two halves so this guard does
/// not match its own source.)
#[test]
fn observer_override_uses_the_dedicated_variable() {
    let path = format!("{}/tests/run_tree.rs", env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(&path).unwrap();
    assert!(
        source.contains(r#"std::env::var("P11SCOPE_E2E_OBSERVER")"#),
        "bin() must read P11SCOPE_E2E_OBSERVER in {path}"
    );
    assert!(
        !source.contains(&["P11SCOPE", "BIN"].join("_")),
        "bin() must not read the matrix override variable in {path}"
    );
}

/// Spawns `p11scope run` with stderr inherited (diagnostics stay
/// visible) and returns the guarded capture.
fn spawn_run(args: &[String], conf: &Path) -> GuardedChild {
    let child = Command::new(bin())
        .args(args)
        .env("SOFTHSM2_CONF", conf)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn run");
    GuardedChild { child }
}

/// Reads one `LEDGER name=count ...` file (written by a workload on
/// completion).
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

/// Sums ledger files into per-function counts.
fn sum_ledgers(ledgers: &[PathBuf]) -> BTreeMap<String, u64> {
    let mut total = BTreeMap::new();
    for ledger in ledgers {
        for (name, count) in read_ledger_file(ledger) {
            *total.entry(name).or_insert(0) += count;
        }
    }
    total
}

/// Per-function completed-call counts for the module with `sha256` from
/// the profile's `functions` rows (P2-8 join: rows carry the module as
/// an identity object; `sha256` is stable across device domains).
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

/// The `evidence.discovery[]` record's `sha256` for `module`.
fn record_sha256(profile: &serde_json::Value, module: &Path) -> String {
    let want = module.to_str().expect("utf8 module path");
    let modules = profile
        .get("evidence")
        .and_then(|evidence| evidence.get("discovery"))
        .and_then(|discovery| discovery.as_array())
        .expect("evidence.discovery");
    modules
        .iter()
        .find(|record| record.get("path").and_then(|p| p.as_str()) == Some(want))
        .unwrap_or_else(|| panic!("no module record for {want}"))
        .get("sha256")
        .and_then(|sha| sha.as_str())
        .expect("record sha256")
        .to_string()
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

/// Reads a finished capture's JSON profile.
fn read_profile(out: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(out).expect("read profile");
    serde_json::from_str(&text).expect("profile is JSON")
}

/// The profile's coverage verdict (`COMPLETE`/`PARTIAL`).
fn verdict(profile: &serde_json::Value) -> &str {
    profile
        .get("evidence")
        .and_then(|evidence| evidence.get("completeness"))
        .and_then(|completeness| completeness.as_str())
        .unwrap_or_else(|| panic!("no completeness verdict: {profile}"))
}

/// The honest run-tree verdict for descendants that retired between
/// admission passes: PARTIAL with exactly one descendant gap per
/// never-admitted generation, zero event loss, the run cgroup scope,
/// a measured zero handed back, and no run-scope refusal (no
/// `run process tree` gap entry).
fn assert_honest_tree_gaps(profile: &serde_json::Value, descendant_gaps: u64) {
    assert_eq!(verdict(profile), "PARTIAL", "{profile}");
    let evidence = profile.get("evidence").expect("evidence");
    assert_eq!(
        evidence.get("pid_descendant_gaps"),
        Some(&serde_json::Value::from(descendant_gaps)),
        "{profile}"
    );
    assert_eq!(
        evidence.get("run_tree_handed_back"),
        Some(&serde_json::Value::from(0)),
        "{profile}"
    );
    assert_eq!(
        evidence.get("event_loss"),
        Some(&serde_json::Value::from(0)),
        "{profile}"
    );
    assert_eq!(
        evidence.get("discovery_ring_loss"),
        Some(&serde_json::Value::from(0)),
        "{profile}"
    );
    assert_eq!(
        profile
            .get("capture")
            .and_then(|capture| capture.get("scope")),
        Some(&serde_json::Value::from("cgroup")),
        "{profile}"
    );
    let labels: Vec<&str> = profile
        .get("cgroups")
        .and_then(|cgroups| cgroups.as_array())
        .expect("cgroups")
        .iter()
        .filter_map(|cgroup| cgroup.get("label").and_then(|label| label.as_str()))
        .collect();
    assert!(
        labels
            .iter()
            .any(|label| { label.starts_with("p11scope-run-") && !label.contains('/') }),
        "the run cgroup scope is retained as its leaf name only, not degraded: {labels:?}"
    );
    let skipped = evidence
        .get("skipped")
        .and_then(|skipped| skipped.as_array())
        .expect("evidence.skipped");
    assert!(
        skipped.iter().all(|entry| {
            entry
                .get("name")
                .and_then(|name| name.as_str())
                .is_some_and(|name| name != "run process tree")
        }),
        "no run-scope refusal gap: {skipped:?}"
    );
}

/// SoftHSM call-sequence workload. Usage:
/// `workload MODULE LEDGER_FILE ITERATIONS [SLEEP_SECS]`.
/// Dlopens the module and issues the scripted sequence (P2-8 call
/// pattern), writes one `LEDGER name=count ...` line, checks its own
/// hot counts, then sleeps `SLEEP_SECS` when given (the outliving
/// leaf) and exits 0 (3 on any call-count drift or setup failure).
const WORKLOAD_C: &str = r#"
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    if (argc < 4 || argc > 5) {
        fprintf(stderr, "usage: %s MODULE LEDGER_FILE ITERATIONS [SLEEP_SECS]\n", argv[0]);
        return 2;
    }
    const char *module = argv[1];
    const char *ledger_file = argv[2];
    long iterations = strtol(argv[3], NULL, 10);
    long sleep_secs = argc == 5 ? strtol(argv[4], NULL, 10) : 0;
    if (iterations < 1 || iterations > 1000 || sleep_secs < 0 || sleep_secs > 300) {
        fprintf(stderr, "workload: bad counts\n");
        return 2;
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
    ck_rv_t rv = c_initialize(NULL);
    if (rv != 0) {
        fprintf(stderr, "workload: C_Initialize failed: 0x%lx\n", rv);
        return 3;
    }
    unsigned char info[256];
    unsigned char slot_info[256];
    unsigned char token_info[512];
    ck_slot_id_t slots[64];
    long get_info = 0, get_slot_list = 0, get_slot_info = 0, get_token_info = 0;
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
            "C_GetSlotInfo=%ld C_GetTokenInfo=%ld\n",
            get_info, get_slot_list, get_slot_info, get_token_info);
    fclose(ledger);
    if (get_info != iterations || get_slot_list < iterations) {
        fprintf(stderr, "workload: hot counts drifted\n");
        return 3;
    }
    if (sleep_secs > 0)
        sleep((unsigned)sleep_secs);
    return 0;
}
"#;

/// Double-fork fixture. Usage:
/// `doublefork WORKLOAD MODULE LEDGER_FILE PID_FILE`.
/// The middle generation forks the leaf, records its pid, and exits
/// immediately, so the leaf reparents away from this tree and then
/// execs the workload (2 iterations). The direct child waits for the
/// middle, then for the LEDGER (the leaf's calls all happened), then
/// for the leaf pid to be gone, and exits 0. A PPID-walk follower
/// loses the reparented leaf; the run cgroup keeps it.
const DOUBLEFORK_C: &str = r#"
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void wait_for_file(const char *path)
{
    struct timespec wait50ms = { 0, 50000000 };
    for (int i = 0; i < 1200; i++) {
        if (access(path, F_OK) == 0)
            return;
        nanosleep(&wait50ms, NULL);
    }
    fprintf(stderr, "doublefork: timed out waiting for %s\n", path);
    exit(3);
}

static void wait_pid_gone(pid_t pid)
{
    struct timespec wait50ms = { 0, 50000000 };
    for (int i = 0; i < 1200; i++) {
        if (kill(pid, 0) != 0 && errno == ESRCH)
            return;
        nanosleep(&wait50ms, NULL);
    }
    fprintf(stderr, "doublefork: leaf %d never exited\n", (int)pid);
    exit(3);
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s WORKLOAD MODULE LEDGER_FILE PID_FILE\n", argv[0]);
        return 2;
    }
    pid_t mid = fork();
    if (mid < 0) {
        perror("doublefork: fork middle");
        return 3;
    }
    if (mid > 0) {
        int status = 0;
        if (waitpid(mid, &status, 0) < 0) {
            perror("doublefork: wait middle");
            return 3;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "doublefork: middle failed\n");
            return 3;
        }
        wait_for_file(argv[3]);
        FILE *pidfile = fopen(argv[4], "r");
        if (!pidfile) {
            perror("doublefork: pid file");
            return 3;
        }
        long leaf = 0;
        if (fscanf(pidfile, "%ld", &leaf) != 1 || leaf <= 0) {
            fprintf(stderr, "doublefork: bad leaf pid\n");
            return 3;
        }
        fclose(pidfile);
        wait_pid_gone((pid_t)leaf);
        return 0;
    }
    pid_t leaf = fork();
    if (leaf < 0) {
        perror("doublefork: fork leaf");
        _exit(3);
    }
    if (leaf > 0) {
        FILE *pidfile = fopen(argv[4], "w");
        if (!pidfile) {
            perror("doublefork: pid file");
            _exit(3);
        }
        fprintf(pidfile, "%d\n", (int)leaf);
        fclose(pidfile);
        _exit(0);
    }
    execl(argv[1], argv[1], argv[2], argv[3], "2", (char *)NULL);
    perror("doublefork: exec workload");
    _exit(3);
}
"#;

/// Outliving-child fixture. Usage:
/// `outlive WORKLOAD MODULE LEDGER_FILE PID_FILE SLEEP_SECS`.
/// Forks the leaf, which execs the workload (3 iterations, then
/// sleeps); writes the leaf pid to `PID_FILE` for the cell's cleanup;
/// waits for the LEDGER (the leaf's calls all happened), then exits 0
/// at once — while the leaf still sleeps. The run ends with this
/// process's status; the leaf is handed back and disclosed.
const OUTLIVE_C: &str = r#"
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static void wait_for_file(const char *path)
{
    struct timespec wait50ms = { 0, 50000000 };
    for (int i = 0; i < 1200; i++) {
        if (access(path, F_OK) == 0)
            return;
        nanosleep(&wait50ms, NULL);
    }
    fprintf(stderr, "outlive: timed out waiting for %s\n", path);
    exit(3);
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: %s WORKLOAD MODULE LEDGER_FILE PID_FILE SLEEP_SECS\n", argv[0]);
        return 2;
    }
    pid_t leaf = fork();
    if (leaf < 0) {
        perror("outlive: fork");
        return 3;
    }
    if (leaf > 0) {
        FILE *pidfile = fopen(argv[4], "w");
        if (!pidfile) {
            perror("outlive: pid file");
            return 3;
        }
        fprintf(pidfile, "%d\n", (int)leaf);
        fclose(pidfile);
        wait_for_file(argv[3]);
        return 0;
    }
    execl(argv[1], argv[1], argv[2], argv[3], "3", argv[5], (char *)NULL);
    perror("outlive: exec workload");
    _exit(3);
}
"#;

/// The cgroup v2 path of `pid` relative to the cgroup root, from
/// `/proc/<pid>/cgroup` (empty for the root cgroup).
fn cgroup_v2_relative(pid: u32) -> String {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .unwrap_or_else(|error| panic!("reading the cgroup of {pid}: {error}"));
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|path| path.trim_start_matches('/').to_string())
        .unwrap_or_else(|| panic!("no cgroup v2 line for {pid}: {text:?}"))
}

/// Waits (bounded) for a fixture's pid file and parses it.
fn wait_for_pid_file(path: &Path) -> i32 {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(pid) = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse::<i32>().ok())
            .filter(|pid| *pid > 0)
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "{} never named a pid",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Common `run` prefix: pre-armed SoftHSM, scan filter, JSON output.
fn run_prefix(module: &Path, out: &Path) -> Vec<String> {
    ["run"]
        .into_iter()
        .map(str::to_string)
        .chain(
            [
                "--module",
                module.to_str().expect("utf8 module"),
                "--prearm-module",
                module.to_str().expect("utf8 module"),
                "-o",
                out.to_str().expect("utf8 out"),
                "--",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .collect()
}

/// Shell wrapper: `sh -c` runs the workload twice sequentially. The
/// shell never maps the provider, so every observed call is a
/// grandchild's; both grandchildren land ledger-exact. Both retire
/// between admission passes, so the verdict is honestly PARTIAL with
/// two descendant gaps and zero loss.
#[test]
#[ignore = "privileged: run-tree shell-wrapper cell (root BPF capture, runtime SoftHSM workload + token)"]
fn privileged_run_tree_shell_wrapper_shows_grandchild_calls() {
    let dir = tempfile::tempdir().expect("cell dir");
    let module = softhsm_path();
    let conf = init_token(dir.path());
    let workload = build_c(dir.path(), "rt-workload", WORKLOAD_C);
    open_cell_dir(dir.path());
    let (ledger1, ledger2) = (dir.path().join("l1"), dir.path().join("l2"));
    let (_outdir, out) = out_dir();
    // Drain settle: the shell holds the loop open two seconds after the
    // last grandchild so its exit record lands before the terminal drain
    // fixes its read position; without the settle the last exit strands
    // past it on some hosts (Fedora) and the gap counts via the
    // fail-closed sweep instead of the exit ledger.
    // `exec` keeps the direct-child PID: no new process, no new exit.
    let script = format!(
        "{} {} {} 3; {} {} {} 3; exec sleep 2",
        workload.display(),
        module.display(),
        ledger1.display(),
        workload.display(),
        module.display(),
        ledger2.display()
    );
    let mut args = run_prefix(&module, &out);
    args.extend(["sh".to_string(), "-c".to_string(), script]);
    let mut capture = spawn_run(&args, &conf);
    let status = capture.wait_expect("run");
    assert!(status.success(), "run exits with the shell's status");
    let profile = read_profile(&out);
    assert_honest_tree_gaps(&profile, 2);
    let want = sum_ledgers(&[ledger1, ledger2]);
    let sha = record_sha256(&profile, &module);
    assert_exact_counts(&function_calls(&profile, &sha), &want);
}

/// Double fork: the middle generation exits before the reparented
/// leaf issues its calls. The leaf's ledger lands exact; the middle
/// and the leaf both retire between admission passes (the direct
/// child waits for both and exits last), so two descendant gaps stay.
#[test]
#[ignore = "privileged: run-tree double-fork cell (root BPF capture, runtime SoftHSM workload + token)"]
fn privileged_run_tree_double_fork_shows_reparented_calls() {
    let dir = tempfile::tempdir().expect("cell dir");
    let module = softhsm_path();
    let conf = init_token(dir.path());
    let workload = build_c(dir.path(), "rt-workload", WORKLOAD_C);
    let doublefork = build_c(dir.path(), "rt-doublefork", DOUBLEFORK_C);
    open_cell_dir(dir.path());
    let (ledger, pidfile) = (dir.path().join("l"), dir.path().join("leaf.pid"));
    let (_outdir, out) = out_dir();
    let mut args = run_prefix(&module, &out);
    for arg in [&doublefork, &workload] {
        args.push(arg.to_str().expect("utf8 arg").to_string());
    }
    args.push(module.to_str().expect("utf8 module").to_string());
    args.push(ledger.to_str().expect("utf8 ledger").to_string());
    args.push(pidfile.to_str().expect("utf8 pidfile").to_string());
    let mut capture = spawn_run(&args, &conf);
    let status = capture.wait_expect("run");
    assert!(status.success(), "run exits with the fixture's status");
    let profile = read_profile(&out);
    assert_honest_tree_gaps(&profile, 2);
    let want = sum_ledgers(&[ledger]);
    let sha = record_sha256(&profile, &module);
    assert_exact_counts(&function_calls(&profile, &sha), &want);
}

/// Outliving child: the direct child exits while its leaf still
/// sleeps. The run ends with the direct child's status, the leaf's
/// pre-exit calls land exact, and the handed-back leaf is disclosed
/// by the named gap (PARTIAL). The cell reaps the leaf afterwards:
/// nothing it started may outlive it.
#[test]
#[ignore = "privileged: run-tree outliving-child cell (root BPF capture, runtime SoftHSM workload + token)"]
fn privileged_run_tree_outliving_child_is_disclosed() {
    let dir = tempfile::tempdir().expect("cell dir");
    let module = softhsm_path();
    let conf = init_token(dir.path());
    let workload = build_c(dir.path(), "rt-workload", WORKLOAD_C);
    let outlive = build_c(dir.path(), "rt-outlive", OUTLIVE_C);
    open_cell_dir(dir.path());
    let (ledger, pidfile) = (dir.path().join("l"), dir.path().join("leaf.pid"));
    let (_outdir, out) = out_dir();
    let mut args = run_prefix(&module, &out);
    for arg in [&outlive, &workload] {
        args.push(arg.to_str().expect("utf8 arg").to_string());
    }
    args.push(module.to_str().expect("utf8 module").to_string());
    args.push(ledger.to_str().expect("utf8 ledger").to_string());
    args.push(pidfile.to_str().expect("utf8 pidfile").to_string());
    args.push("60".to_string());
    let mut capture = spawn_run(&args, &conf);
    // Placement, from the outside while the command runs: the leaf's
    // cgroup is a `p11scope-run-*` directory directly under the
    // observer's own cgroup (the root only when the observer runs there).
    let observer_base = cgroup_v2_relative(capture.child.id());
    let leaf = wait_for_pid_file(&pidfile);
    let leaf_cgroup = PathBuf::from(cgroup_v2_relative(leaf as u32));
    let run_leaf = leaf_cgroup
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the leaf cgroup has a name")
        .to_string();
    assert!(
        run_leaf.starts_with("p11scope-run-"),
        "the leaf runs in the run cgroup: {}",
        leaf_cgroup.display()
    );
    assert_eq!(
        leaf_cgroup.parent(),
        Some(Path::new(&observer_base)),
        "the run cgroup is directly under the observer's cgroup {observer_base:?}"
    );
    let base_dir = Path::new("/sys/fs/cgroup").join(&observer_base);
    let listed = std::fs::read_dir(&base_dir)
        .expect("the observer cgroup lists")
        .flatten()
        .any(|entry| entry.file_name().to_str() == Some(&run_leaf) && entry.path().is_dir());
    assert!(
        listed,
        "{run_leaf} is a directory under {}",
        base_dir.display()
    );
    let status = capture.wait_expect("run");
    assert!(status.success(), "run exits with the direct child's status");
    // The leaf must still be alive: it proves the run ended first.
    let alive = unsafe { libc::kill(leaf, 0) } == 0;
    assert!(alive, "the leaf outlives the run");
    let profile = read_profile(&out);
    let want = sum_ledgers(&[ledger]);
    let sha = record_sha256(&profile, &module);
    assert_exact_counts(&function_calls(&profile, &sha), &want);
    assert_eq!(verdict(&profile), "PARTIAL", "{profile}");
    let labels: Vec<&str> = profile
        .get("cgroups")
        .and_then(|cgroups| cgroups.as_array())
        .expect("cgroups")
        .iter()
        .filter_map(|cgroup| cgroup.get("label").and_then(|label| label.as_str()))
        .collect();
    assert!(
        labels.contains(&run_leaf.as_str()),
        "the published label is the run cgroup's leaf {run_leaf}: {labels:?}"
    );
    let evidence = profile.get("evidence").expect("evidence");
    assert_eq!(
        evidence.get("run_tree_handed_back"),
        Some(&serde_json::Value::from(1)),
        "{profile}"
    );
    let skipped = evidence
        .get("skipped")
        .and_then(|skipped| skipped.as_array())
        .expect("evidence.skipped");
    assert!(
        skipped.iter().any(|entry| entry
            .get("name")
            .and_then(|name| name.as_str())
            .is_some_and(|name| name == "run process tree")
            && entry
                .get("reason")
                .and_then(|reason| reason.as_str())
                .is_some_and(|reason| reason
                    == "process-tree members were still present when the command exited; \
                        their calls after the run end are out of scope")),
        "the handed-back leaf is disclosed: {skipped:?}"
    );
    // Cleanup: nothing this cell started may outlive it.
    assert_eq!(
        unsafe { libc::kill(leaf, libc::SIGKILL) },
        0,
        "kill the leaf"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let gone = unsafe { libc::kill(leaf, 0) } != 0;
        if gone {
            break;
        }
        assert!(Instant::now() < deadline, "the leaf would not die");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Many children: 32 sequential grandchildren through one shell loop
/// land ledger-exact in one profile, with one descendant gap each:
/// every grandchild retires between admission passes.
#[test]
#[ignore = "privileged: run-tree many-children cell (root BPF capture, runtime SoftHSM workload + token)"]
fn privileged_run_tree_many_children_land_exact() {
    const CHILDREN: u32 = 32;
    let dir = tempfile::tempdir().expect("cell dir");
    let module = softhsm_path();
    let conf = init_token(dir.path());
    let workload = build_c(dir.path(), "rt-workload", WORKLOAD_C);
    open_cell_dir(dir.path());
    let (_outdir, out) = out_dir();
    let mut ledgers = Vec::new();
    let mut script = String::new();
    for i in 0..CHILDREN {
        let ledger = dir.path().join(format!("l{i}"));
        script.push_str(&format!(
            "{} {} {} 1; ",
            workload.display(),
            module.display(),
            ledger.display()
        ));
        ledgers.push(ledger);
    }
    // Drain settle (see the shell-wrapper cell): two seconds between the
    // last grandchild and loop end, same PID via `exec`.
    script.push_str("exec sleep 2");
    let mut args = run_prefix(&module, &out);
    args.extend(["sh".to_string(), "-c".to_string(), script]);
    let mut capture = spawn_run(&args, &conf);
    let status = capture.wait_expect("run");
    assert!(status.success(), "run exits with the shell's status");
    let profile = read_profile(&out);
    assert_honest_tree_gaps(&profile, 32);
    let want = sum_ledgers(&ledgers);
    let sha = record_sha256(&profile, &module);
    assert_exact_counts(&function_calls(&profile, &sha), &want);
}
