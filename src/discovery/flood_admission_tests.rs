//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Controller addendum test (d): privileged `--system` flood cell.
//!
//! A short `--system` profile floods SIGKILL children (256 MiB paced
//! mappers with a per-minute K signature, SIGKILLed near scan time)
//! plus a zero-call dlopen churn loop against an isolated provider
//! copy, with a zero-call anchor mapped pre-capture and held to the
//! end. The profile must count every driven call exactly, with no
//! spurious calls, no event loss, no ambiguity rows, and every slot
//! active; the K signature attributes any stall to its minute (an
//! exact prefix plus a missing suffix is the stall shape). On the
//! pre-fix code the flood retires the proven slots mid-capture
//! (ambiguous identity, zero active slots) and late windows go
//! missing; on the fixed code counting continues for the whole
//! capture. Sized from the flood repro at 1/4 the mapper bytes so six
//! concurrent children fit a small runner.
//!
//! Per-window oracle: the profile carries aggregate per-endpoint
//! totals with no timestamps, so a missing call in one window could
//! cancel an extra call in another under a totals-only check. Each
//! window (minute) therefore drives a window-exclusive call mix —
//! mix 0 rounds call GetInfo plus a slot list, mix 1 rounds call
//! GetSlotInfo, mix 2 rounds call GetTokenInfo, cycling by
//! `(K - 10) % 3` — and the oracle asserts each mix's observed
//! endpoint totals against the driver ledger for those windows. For
//! captures under ~3 minutes each mix is exactly one window, so the
//! check is per-window exact; longer captures alias same-mix
//! windows 3 minutes apart (documented residual: per-child-once
//! setup calls also span windows by construction).
//!
//! Split-domain shape: half the children map the provider through a
//! bind-mounted alias path, so the same file is observed through two
//! mount views (distinct mount IDs, one kernel file) even on
//! single-domain filesystems — the addendum-(d) ext4 shape. The two
//! raws merge by same-open-file proof on the fixed code (no
//! ambiguity); the pre-fix teardown races reject the group. The
//! profile joins counts by sha256 across both paths. RED on the old
//! code needs a privileged run (hosted CI runs this cell); the
//! oracle's discrimination itself is pinned unprivileged below by
//! the cancellation twins.
//!
//! Tuning (no rebuild needed): `P11SCOPE_FLOOD_DUR_S` (capture seconds,
//! default 120), `P11SCOPE_FLOOD_NWAY` (concurrent children, default
//! 6), `P11SCOPE_FLOOD_HOLD_MS` (hold before SIGKILL, default 200),
//! `P11SCOPE_FLOOD_CHURN_US` (churn sleep microseconds, default 100),
//! `P11SCOPE_FLOOD_EXT4_LOOP=1` (the provider copy lives on a private
//! ext4 loop mount while the bind alias stays in the cell dir, so the
//! alias is a cross-filesystem bind that reproduces the ext4 domain
//! split; needs root with `mkfs.ext4` and `mount`, like the v072
//! regress-071 cell d vehicle this reuses).
//! The observer is `P11SCOPE_E2E_OBSERVER` or the `p11scope` sibling of
//! this test binary's directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const READY_LINE: &str = "p11scope: capturing:";

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_flag(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1" | "true" | "yes"))
}

/// Probe SoftHSM (Debian then Fedora paths); panic loudly when absent —
/// this cell needs the real provider, never a skip.
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

/// Brand-new provider file: a copy at a cell-private path with a
/// per-copy trailing nonce, so inode and sha256 are unique to the cell
/// and counts for its sha can only come from the cell's workload.
fn unique_provider_copy(dir: &Path) -> PathBuf {
    static COPY_NONCE: AtomicU64 = AtomicU64::new(0);
    let copy = dir.join(format!("libflood-{}-isolated.so", std::process::id()));
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

/// Private token dir + config + one initialized token; returns the
/// config path. The caller exports it as `SOFTHSM2_CONF` for the
/// workload children and the observer.
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
            "flood",
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

/// A bind-mounted alias of the provider file, unmounted on every exit
/// path (Drop still detaches on panic paths, like `GuardedChild`).
struct BindMount {
    target: PathBuf,
}

impl Drop for BindMount {
    fn drop(&mut self) {
        use std::os::unix::ffi::OsStrExt as _;
        let target = std::ffi::CString::new(self.target.as_os_str().as_bytes())
            .expect("bind target is not NUL-free");
        // SAFETY: detaching our own alias; the path is NUL-free.
        let detached = unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
        if detached != 0 {
            eprintln!(
                "flood cell: detach of {} failed: {}",
                self.target.display(),
                std::io::Error::last_os_error()
            );
        }
    }
}

/// A private ext4 filesystem on a loop device (mounted with `mount -o
/// loop`, released on drop with a lazy fallback), reusing the v072
/// regress-071 cell d vehicle. The provider copy lives here when
/// `P11SCOPE_FLOOD_EXT4_LOOP=1` so the alias bind below crosses
/// filesystems and reproduces the ext4 domain split. Root only; every
/// stage fails the cell naming itself (never a skip).
struct Ext4Loop {
    mount: PathBuf,
}

impl Ext4Loop {
    fn create(dir: &Path) -> Self {
        let image = dir.join("flood-ext4.img");
        std::fs::File::create(&image)
            .expect("create the ext4 image")
            .set_len(64 << 20)
            .expect("size the ext4 image");
        let mount = dir.join("flood-ext4");
        std::fs::create_dir(&mount).expect("create the ext4 mountpoint");
        let run = |program: &str, args: &[&std::ffi::OsStr]| {
            let status = std::process::Command::new(program)
                .args(args)
                .status()
                .unwrap_or_else(|error| panic!("{program} is required: {error}"));
            assert!(status.success(), "{program} {args:?} failed with {status}");
        };
        run(
            "mkfs.ext4",
            &["-q".as_ref(), "-F".as_ref(), image.as_os_str()],
        );
        run(
            "mount",
            &[
                "-o".as_ref(),
                "loop".as_ref(),
                image.as_os_str(),
                mount.as_os_str(),
            ],
        );
        eprintln!(
            "flood cell: ext4 loop mounted: {} on {}",
            image.display(),
            mount.display()
        );
        Self { mount }
    }

    fn is_mounted(&self) -> bool {
        let target = self.mount.display().to_string();
        std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|table| {
            table.lines().any(|line| {
                let fields: Vec<&str> = line.split_ascii_whitespace().collect();
                fields.get(4) == Some(&target.as_str())
            })
        })
    }

    fn unmount(&self) {
        let status = std::process::Command::new("umount")
            .arg(&self.mount)
            .status()
            .expect("umount is required");
        assert!(
            status.success(),
            "umount {} failed with {status}",
            self.mount.display()
        );
    }
}

impl Drop for Ext4Loop {
    fn drop(&mut self) {
        let unmounted = std::process::Command::new("umount")
            .arg(&self.mount)
            .status()
            .is_ok_and(|status| status.success());
        if !unmounted {
            let _ = std::process::Command::new("umount")
                .arg("-l")
                .arg(&self.mount)
                .status();
        }
    }
}

/// Prove the provider sits on ext4 (statfs magic), so an ext4-loop
/// run that silently landed elsewhere cannot pass as the vehicle.
fn assert_fstype_ext4(path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    const EXT4_SUPER_MAGIC: i64 = 0xEF53;
    let target =
        std::ffi::CString::new(path.as_os_str().as_bytes()).expect("mount path is not NUL-free");
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: statfs on our own mountpoint with a valid out-pointer.
    let rc = unsafe { libc::statfs(target.as_ptr(), &mut stat) };
    assert_eq!(
        rc,
        0,
        "statfs {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    assert_eq!(
        stat.f_type,
        EXT4_SUPER_MAGIC,
        "the provider mount is not ext4: {} has f_type {:x}",
        path.display(),
        stat.f_type
    );
}

/// Bind-mount `source` at a cell-private alias path and prove the
/// split-domain shape: both paths name one kernel file (equal
/// device and inode) while the alias is its own mount view. Panics
/// loudly when the mount is unavailable — the cell needs the shape,
/// never a skip.
fn bind_provider_alias(dir: &Path, source: &Path) -> (BindMount, PathBuf) {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    let target = dir.join(format!("libflood-{}-alias.so", std::process::id()));
    std::fs::write(&target, []).expect("create the bind target");
    let c_source = std::ffi::CString::new(source.as_os_str().as_bytes()).expect("source path");
    let c_target = std::ffi::CString::new(target.as_os_str().as_bytes()).expect("target path");
    // SAFETY: bind-mounting our own provider copy at our own alias;
    // both paths are NUL-free.
    let mounted = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    assert_eq!(
        mounted,
        0,
        "bind-mount the provider alias: {}",
        std::io::Error::last_os_error()
    );
    let guard = BindMount {
        target: target.clone(),
    };
    let (source_meta, target_meta) = (
        std::fs::metadata(source).expect("stat the provider"),
        std::fs::metadata(&target).expect("stat the alias"),
    );
    assert_eq!(
        (source_meta.dev(), source_meta.ino()),
        (target_meta.dev(), target_meta.ino()),
        "the alias names the same kernel file"
    );
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
    let want = target.to_str().unwrap_or("");
    assert!(
        mounts
            .lines()
            .any(|line| line.split_whitespace().nth(4).is_some_and(|mount| {
                // Mountinfo escapes spaces, so match both spellings.
                mount == want || mount == want.replace(' ', "\\040")
            })),
        "the alias is its own mount view: {}",
        target.display()
    );
    (guard, target)
}

/// Flood child: map the provider, `C_Initialize`, one slot list,
/// grow to 256 MiB RSS (4-way touch, like the flood repro's paced
/// mapper at 1/4 the bytes so six fit a small CI runner), do K
/// counted call rounds in this window's exclusive mix, print
/// `COUNTS`, then sleep until the driver SIGKILLs it. The SIGKILL
/// lands near scan time so teardown races trigger; the pre-fix code
/// retires the proven slots on those races and stalls, the fixed
/// code counts every child exactly.
///
/// The mix is `(K - 10) % 3`: mix 0 rounds call GetInfo plus a slot
/// list, mix 1 rounds call GetSlotInfo, mix 2 rounds call
/// GetTokenInfo. Undriven counters print zero, so the `COUNTS` shape
/// is unchanged and each mix's endpoints are attributable to their
/// windows from the aggregate profile totals.
///
/// Usage: `child PROVIDER K`. Stdout: `READY pid=%d`, then
/// `COUNTS init=.. gfl=.. slotlist=.. getinfo=.. getslotinfo=..
/// gettokeninfo=.. failed=..`. Exit 1 on any setup/call failure,
/// 3 on NOMEM.
const CHILD_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID;
typedef struct { void *c, *d, *l, *u; unsigned long flags; void *r; } INITARGS;
#define F(i, t) ((t)fns[i])
static void **fns;

struct touch_quad { char *base; size_t len; };

static void *touch_quad(void *arg)
{
    struct touch_quad *q = arg;
    for (size_t i = 0; i < q->len; i += 4096)
        q->base[i] = 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s PROVIDER K\n", argv[0]);
        return 2;
    }
    int K = atoi(argv[2]);
    if (K < 1 || K > 100000) {
        fprintf(stderr, "bad K\n");
        return 2;
    }
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }
    unsigned long (*g)(void **);
    *(void **)&g = dlsym(h, "C_GetFunctionList");
    if (!g) {
        fprintf(stderr, "no C_GetFunctionList\n");
        return 1;
    }
    void *l;
    if (g(&l)) {
        fprintf(stderr, "gfl\n");
        return 1;
    }
    fns = (void **)((char *)l + 8);
    INITARGS a;
    memset(&a, 0, sizeof a);
    a.flags = 2;
    if (F(0, CK_RV(*)(void *))(&a)) {
        fprintf(stderr, "init\n");
        return 1;
    }
    CK_SLOT_ID slots[16];
    CK_ULONG ns = 16;
    if (F(4, CK_RV(*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(0, slots, &ns) || ns < 1) {
        fprintf(stderr, "slots\n");
        return 1;
    }
    size_t n = (size_t)1 << 28;
    char *p = mmap(0, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "NOMEM\n");
        return 3;
    }
    pthread_t th[4];
    struct touch_quad q[4];
    for (int t = 0; t < 4; t++) {
        q[t].base = p + (size_t)t * (n / 4);
        q[t].len = n / 4;
        if (pthread_create(&th[t], 0, touch_quad, &q[t])) {
            fprintf(stderr, "thread\n");
            return 1;
        }
    }
    for (int t = 0; t < 4; t++)
        pthread_join(th[t], 0);
    printf("READY pid=%d\n", getpid());
    fflush(stdout);
    static unsigned char info[512];
    unsigned long gi = 0, sl = 1, gsi = 0, gti = 0, failed = 0;
    int mix = ((K - 10) % 3 + 3) % 3;
    for (int k = 0; k < K; k++) {
        if (mix == 0) {
            if (F(2, CK_RV(*)(void *))(info))
                failed++;
            else
                gi++;
            ns = 16;
            if (F(4, CK_RV(*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(0, slots, &ns))
                failed++;
            else
                sl++;
        } else if (mix == 1) {
            if (F(5, CK_RV(*)(CK_SLOT_ID, void *))(slots[0], info))
                failed++;
            else
                gsi++;
        } else {
            if (F(6, CK_RV(*)(CK_SLOT_ID, void *))(slots[0], info))
                failed++;
            else
                gti++;
        }
    }
    printf("COUNTS init=1 gfl=1 slotlist=%lu getinfo=%lu getslotinfo=%lu gettokeninfo=%lu failed=%lu\n",
           sl, gi, gsi, gti, failed);
    fflush(stdout);
    for (;;)
        pause();
    return 0;
}
"#;

/// Anchor: map the provider once and sleep, zero PKCS#11 calls. Mapped
/// before the capture starts so the initial scan learns the provider
/// and attach settles before counted children; held to capture end so
/// its slots stay active (the pre-fix code retires them mid-capture).
/// Usage: `anchor PROVIDER`. Stdout: `ANCHOR pid=%d`.
const ANCHOR_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }
    printf("ANCHOR pid=%d\n", getpid());
    fflush(stdout);
    for (;;)
        pause();
    return 0;
}
"#;

/// Churn: loader churn with zero PKCS#11 calls
/// (dlopen/dlsym-resolve/dlclose). Usage: `churn PROVIDER [SLEEP_US]`.
const CHURN_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    long su = argc > 2 ? atol(argv[2]) : 100;
    unsigned long it = 0, fail = 0;
    printf("CHURN pid=%d\n", getpid());
    fflush(stdout);
    time_t last = time(0);
    for (;;) {
        void *h = dlopen(argv[1], RTLD_NOW);
        if (!h) {
            fail++;
        } else {
            volatile void *s = dlsym(h, "C_GetFunctionList");
            (void)s;
            dlclose(h);
        }
        it++;
        if (su > 0)
            usleep((useconds_t)su);
        time_t now = time(0);
        if (now - last >= 30) {
            printf("CHURN_ALIVE iters=%lu fails=%lu\n", it, fail);
            fflush(stdout);
            last = now;
        }
    }
    return 0;
}
"#;

/// Compile one runtime-generated C source with the system compiler.
fn build_c(dir: &Path, stem: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{stem}.c"));
    std::fs::write(&src, source).expect("write C source");
    let out = dir.join(stem);
    let compile = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(&out)
        .arg(&src)
        .args(["-ldl", "-pthread"])
        .output()
        .expect("execute cc");
    assert!(
        compile.status.success(),
        "{stem} compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    out
}

/// Run one flood child to completion: spawn, wait for its `COUNTS`
/// line (it pauses after printing), hold, SIGKILL, reap. Returns
/// `None` when the child misbehaves (no `COUNTS`, NOMEM, signal
/// failure); the caller counts a warning. Blocking reads are bounded
/// by the runner's cell timeout; a healthy child answers in ~1 s.
fn run_child(
    child_bin: &Path,
    provider: &Path,
    conf: &Path,
    k: u64,
    hold: Duration,
    t_ms: u64,
) -> Option<DrivenChild> {
    use crate::fixture_guard::DieWithParent as _;
    use std::io::BufRead as _;
    let mut child = Command::new(child_bin)
        .arg(provider)
        .arg(k.to_string())
        .env("SOFTHSM2_CONF", conf)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .die_with_parent()
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let mut reader = std::io::BufReader::new(stdout);
    let mut counts = None;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if line.starts_with("COUNTS ") {
                    counts = Some(line);
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let counts = counts?;
    std::thread::sleep(hold);
    child.kill().ok()?;
    child.wait().ok()?;
    Some(DrivenChild {
        t_ms,
        k,
        provider: provider.display().to_string(),
        counts: parse_counts(counts.trim_end()),
    })
}

/// The observer under test: an explicit `P11SCOPE_E2E_OBSERVER` binary
/// or the `p11scope` sibling of this test binary's directory.
fn observer_binary() -> PathBuf {
    if let Ok(path) = std::env::var("P11SCOPE_E2E_OBSERVER") {
        let path = PathBuf::from(path);
        assert!(path.exists(), "P11SCOPE_E2E_OBSERVER is missing");
        return path;
    }
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent()?.parent().map(|dir| dir.join("p11scope")));
    if let Some(sibling) = sibling.filter(|path| path.exists()) {
        return sibling;
    }
    panic!(
        "no observer binary: set P11SCOPE_E2E_OBSERVER or build the p11scope binary beside this test binary"
    );
}

/// A child reaped on every exit path: the runner kills the cell on
/// timeout, and Drop still reaps a live child on panic paths.
struct GuardedChild(Child);

impl Drop for GuardedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One driven child's ground truth: wall time, K, the provider path
/// it mapped (direct copy or bind alias), and per-function completed
/// counts parsed from its `COUNTS` line.
struct DrivenChild {
    t_ms: u64,
    k: u64,
    provider: String,
    counts: BTreeMap<String, u64>,
}

/// Parse `COUNTS` `name=value` pairs (skips `failed`, which must be
/// zero separately).
fn parse_counts(line: &str) -> BTreeMap<String, u64> {
    let body = line
        .split_once(' ')
        .unwrap_or_else(|| panic!("not a counts line: {line:?}"))
        .1;
    body.split_whitespace()
        .filter_map(|pair| {
            let (name, count) = pair.split_once('=').expect("counts pair");
            if name == "failed" {
                assert_eq!(count, "0", "child reports failed calls: {line:?}");
                return None;
            }
            Some((
                name.to_string(),
                count.parse::<u64>().expect("counts number"),
            ))
        })
        .collect()
}

/// Per-function completed-call counts for the module with `sha256`
/// from the profile's `functions` rows. The match is on `sha256`,
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

/// The module record's `sha256` row-join key from
/// `evidence.discovery[]`, matched by exact provider path.
/// The module record's `sha256` row-join key, trying each provider
/// path in turn: the direct copy first, then its bind-mounted alias.
/// Both name one kernel file (one sha); the fallback only tolerates
/// the plan merging the two mount views under either spelling.
fn record_sha256_any(profile: &serde_json::Value, modules: &[&Path]) -> String {
    let discovery = profile
        .get("evidence")
        .and_then(|evidence| evidence.get("discovery"))
        .and_then(|discovery| discovery.as_array())
        .expect("evidence.discovery array");
    for module in modules {
        let want = module.to_str().expect("utf8 module path");
        if let Some(sha) = discovery
            .iter()
            .find(|record| record.get("path").and_then(|p| p.as_str()) == Some(want))
            .and_then(|record| record.get("sha256"))
            .and_then(|sha| sha.as_str())
        {
            return sha.to_string();
        }
    }
    panic!(
        "no module record for any of {:?}",
        modules
            .iter()
            .map(|module| module.display().to_string())
            .collect::<Vec<_>>()
    );
}

/// Wait for the observer's ready line on its piped stderr (bounded);
/// panics with the stderr tail when the observer exits first or the
/// wait times out.
fn wait_ready(child: &mut Child, stderr: &mut std::process::ChildStderr) {
    use std::io::Read as _;
    use std::os::unix::io::AsRawFd as _;
    // SAFETY: flag juggling on our own pipe end.
    let fd = stderr.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(flags >= 0, "getfl observer stderr");
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0,
        "nonblock observer stderr"
    );
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(status) = child.try_wait().expect("poll the observer") {
            let tail = String::from_utf8_lossy(&buf);
            let tail: String = tail
                .chars()
                .rev()
                .take(2000)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            panic!("the observer exited {status} before ready: {tail}");
        }
        match stderr.read(&mut chunk) {
            Ok(0) => {}
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if String::from_utf8_lossy(&buf).contains(READY_LINE) {
                    return;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("observer stderr read: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "the observer never printed its ready line"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Bounded wait for a child; kills it instead of hanging the campaign
/// lane forever. Returns `None` on timeout.
fn wait_bounded(child: &mut Child, seconds: u64) -> Option<std::process::ExitStatus> {
    for _ in 0..seconds * 10 {
        if let Some(status) = child.try_wait().expect("poll child") {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// K-signature break diagnosis: the largest time-ordered prefix of
/// driven children whose `C_GetInfo` sum does not exceed the observed
/// total, plus where the next child starts. An exact run matches every
/// child; a stall shows as an exact prefix plus a missing suffix with
/// the break minute.
fn break_prefix(children: &[DrivenChild], observed_getinfo: u64) -> (usize, u64, u64) {
    break_prefix_for(children, "getinfo", observed_getinfo)
}

/// The break-prefix diagnosis for one ledger endpoint: the largest
/// time-ordered prefix of driven children whose `name` sum does not
/// exceed the observed total, plus where the next child starts. Each
/// mix owns distinct endpoints, so the per-endpoint breaks attribute
/// a stall to its mix (and, for short captures, its minute).
fn break_prefix_for(children: &[DrivenChild], name: &str, observed: u64) -> (usize, u64, u64) {
    let mut sum = 0u64;
    let mut matched = 0usize;
    for child in children {
        let count = child.counts.get(name).copied().unwrap_or(0);
        if sum.saturating_add(count) > observed {
            break;
        }
        sum += count;
        matched += 1;
    }
    let (break_t_ms, break_k) = children
        .get(matched)
        .map(|child| (child.t_ms, child.k))
        .unwrap_or((u64::MAX, u64::MAX));
    (matched, break_t_ms, break_k)
}

/// The window-exclusive call mix for driver minute `K - 10`: mix 0
/// rounds drive GetInfo plus a slot list, mix 1 rounds drive
/// GetSlotInfo, mix 2 rounds drive GetTokenInfo. Mirrors the flood
/// child's mix selection exactly.
fn window_mix(k: u64) -> usize {
    (k.saturating_sub(10) % 3) as usize
}

/// The per-mix oracle: each mix's observed endpoint totals must equal
/// the driver ledger for that mix's windows. `observed` maps profile
/// function names to aggregate calls. Returns the first mismatch.
///
/// Mix 0 owns GetInfo and the round slot lists, mix 1 owns
/// GetSlotInfo, mix 2 owns GetTokenInfo; anything driven outside its
/// owner's mix fails the ledger contract (a window cannot miss what
/// it never drives, so cross-mix same-endpoint cancellation is
/// structurally impossible). Slot lists add one per-child setup call
/// on top of the mix-0 rounds. `C_Initialize`, `C_GetFunctionList`
/// and the setup slot list span windows by construction and stay
/// aggregate checks in the cell.
fn check_mix_exclusive(
    children: &[DrivenChild],
    observed: &BTreeMap<String, u64>,
) -> Result<(), String> {
    let mut mix_sums: [BTreeMap<String, u64>; 3] = Default::default();
    let mut mix_kids = [0u64; 3];
    for child in children {
        let mix = window_mix(child.k);
        mix_kids[mix] += 1;
        for (name, count) in &child.counts {
            *mix_sums[mix].entry(name.clone()).or_insert(0) += count;
        }
    }
    let driven = |mix: usize, name: &str| -> u64 { mix_sums[mix].get(name).copied().unwrap_or(0) };
    let seen = |function: &str| -> u64 { observed.get(function).copied().unwrap_or(0) };
    for (mix, ledger, function) in [
        (0usize, "getinfo", "C_GetInfo"),
        (1usize, "getslotinfo", "C_GetSlotInfo"),
        (2usize, "gettokeninfo", "C_GetTokenInfo"),
    ] {
        let elsewhere: u64 = (0..3)
            .filter(|candidate| *candidate != mix)
            .map(|candidate| driven(candidate, ledger))
            .sum();
        if elsewhere != 0 {
            return Err(format!(
                "{ledger} is not mix-{mix}-exclusive in the ledger: {elsewhere} driven outside mix {mix}"
            ));
        }
        let want = driven(mix, ledger);
        if seen(function) != want {
            return Err(format!(
                "{function}: observed {} != mix-{mix} driver {want}",
                seen(function)
            ));
        }
    }
    for mix in [1usize, 2usize] {
        let sum = driven(mix, "slotlist");
        if sum != mix_kids[mix] {
            return Err(format!(
                "mix-{mix} slot lists are not setup-only: {sum} driven for {} children",
                mix_kids[mix]
            ));
        }
    }
    let rounds = driven(0, "slotlist").saturating_sub(mix_kids[0]);
    let want_slotlist = children.len() as u64 + rounds;
    if seen("C_GetSlotList") != want_slotlist {
        return Err(format!(
            "C_GetSlotList: observed {} != driver {want_slotlist} ({} setup + {rounds} mix-0 rounds)",
            seen("C_GetSlotList"),
            children.len(),
        ));
    }
    Ok(())
}

/// The per-window oracle accepts exact windows: each mix's observed
/// endpoint totals equal the driver ledger for that mix's windows,
/// including an empty mix asserting zero.
#[test]
fn mix_oracle_accepts_exact_windows() {
    let child = |t_ms: u64, k: u64, counts: &[(&str, u64)]| DrivenChild {
        t_ms,
        k,
        provider: String::new(),
        counts: counts
            .iter()
            .map(|(name, count)| (name.to_string(), *count))
            .collect(),
    };
    // Window 0 (mix 0): two children, 10 rounds each.
    // Window 1 (mix 1): one child, 11 rounds. Window 2 (mix 2): none.
    let children = vec![
        child(1000, 10, &[("slotlist", 11), ("getinfo", 10)]),
        child(2000, 10, &[("slotlist", 11), ("getinfo", 10)]),
        child(61_000, 11, &[("slotlist", 1), ("getslotinfo", 11)]),
    ];
    let observed = BTreeMap::from([
        ("C_GetInfo".to_string(), 20),
        ("C_GetSlotList".to_string(), 3 + 20),
        ("C_GetSlotInfo".to_string(), 11),
        ("C_GetTokenInfo".to_string(), 0),
    ]);
    assert_eq!(check_mix_exclusive(&children, &observed), Ok(()));
}

/// The per-window oracle rejects a stall and names its mix: mix 1's
/// window loses 4 GetSlotInfo calls (a missing suffix), so the mix-1
/// equation fails while the mix-0 equation still holds.
#[test]
fn mix_oracle_rejects_a_stall_and_names_its_mix() {
    let child = |t_ms: u64, k: u64, counts: &[(&str, u64)]| DrivenChild {
        t_ms,
        k,
        provider: String::new(),
        counts: counts
            .iter()
            .map(|(name, count)| (name.to_string(), *count))
            .collect(),
    };
    let children = vec![
        child(1000, 10, &[("slotlist", 11), ("getinfo", 10)]),
        child(61_000, 11, &[("slotlist", 1), ("getslotinfo", 11)]),
    ];
    let observed = BTreeMap::from([
        ("C_GetInfo".to_string(), 10),
        ("C_GetSlotList".to_string(), 2 + 10),
        ("C_GetSlotInfo".to_string(), 7),
        ("C_GetTokenInfo".to_string(), 0),
    ]);
    let error = check_mix_exclusive(&children, &observed).expect_err("the stall must fail");
    assert!(
        error.contains("C_GetSlotInfo") && error.contains("mix-1"),
        "the failure names the stalled mix: {error}"
    );
}

/// The per-window oracle enforces the mix contract the totals-only
/// oracle cannot see: the review's cancellation shape (GetInfo 30/33
/// restated as 31/32, total 63 preserved) keeps the aggregate total
/// exact, but the restated ledger drives GetInfo outside mix 0, so
/// the mix check fails while the totals recomputation passes.
#[test]
fn mix_oracle_rejects_cancellation_the_totals_oracle_misses() {
    let child = |t_ms: u64, k: u64, counts: &[(&str, u64)]| DrivenChild {
        t_ms,
        k,
        provider: String::new(),
        counts: counts
            .iter()
            .map(|(name, count)| (name.to_string(), *count))
            .collect(),
    };
    // Window A is mix 0, window B is mix 1; the restated ledger moves
    // one GetInfo call from B to A.
    let children = vec![
        child(1000, 10, &[("slotlist", 32), ("getinfo", 31)]),
        child(61_000, 11, &[("slotlist", 1), ("getinfo", 32)]),
    ];
    let observed = BTreeMap::from([
        ("C_GetInfo".to_string(), 63),
        ("C_GetSlotList".to_string(), 2 + 31),
        ("C_GetSlotInfo".to_string(), 0),
        ("C_GetTokenInfo".to_string(), 0),
    ]);
    // Totals-only: 31 + 32 == 63, blind to the restatement.
    let total: u64 = children
        .iter()
        .map(|child| child.counts.get("getinfo").copied().unwrap_or(0))
        .sum();
    assert_eq!(total, observed["C_GetInfo"]);
    // Per-mix: window B must not drive GetInfo at all.
    let error = check_mix_exclusive(&children, &observed).expect_err("the restatement must fail");
    assert!(
        error.contains("not mix-0-exclusive"),
        "the failure names the contract breach: {error}"
    );
}

/// Coverage the flood cell requires of its driver ledger: nonzero
/// calls in at least two distinct per-minute windows and through both
/// provider paths (direct copy and bind-mounted alias). Long runs
/// reuse mixes every third minute; the per-mix oracle already
/// qualifies each mix total, so the guard counts distinct windows,
/// not distinct mixes. Returns the first coverage gap.
fn check_flood_coverage(
    children: &[DrivenChild],
    direct: &std::path::Path,
    alias: &std::path::Path,
) -> Result<(), String> {
    let mut windows = std::collections::BTreeSet::new();
    let mut direct_calls = 0u64;
    let mut alias_calls = 0u64;
    for child in children {
        let calls: u64 = child.counts.values().sum();
        if calls == 0 {
            continue;
        }
        windows.insert(child.k);
        if std::path::Path::new(&child.provider) == direct {
            direct_calls += calls;
        } else if std::path::Path::new(&child.provider) == alias {
            alias_calls += calls;
        }
    }
    if windows.len() < 2 {
        return Err(format!(
            "flood coverage: {} driven window(s) with calls, need at least two",
            windows.len()
        ));
    }
    if direct_calls == 0 || alias_calls == 0 {
        return Err(format!(
            "flood coverage: {direct_calls} direct-path calls and {alias_calls} alias-path calls, need nonzero on both aliases"
        ));
    }
    Ok(())
}

/// Characterization of the coverage gap the flood-coverage guard
/// closes: a ledger driving a single window passes the per-mix
/// oracle — the undriven mixes assert zero and hold. This passing
/// test pins today's oracle behavior; the guard above (wired into
/// the cell, not the oracle) is what rejects a one-window run.
#[test]
fn mix_oracle_accepts_a_single_window_ledger_without_coverage() {
    let child = |t_ms: u64, k: u64, counts: &[(&str, u64)]| DrivenChild {
        t_ms,
        k,
        provider: String::new(),
        counts: counts
            .iter()
            .map(|(name, count)| (name.to_string(), *count))
            .collect(),
    };
    // One window (mix 0): two children, 10 rounds each. Nothing else.
    let children = vec![
        child(1000, 10, &[("slotlist", 11), ("getinfo", 10)]),
        child(2000, 10, &[("slotlist", 11), ("getinfo", 10)]),
    ];
    let observed = BTreeMap::from([
        ("C_GetInfo".to_string(), 20),
        ("C_GetSlotList".to_string(), 2 + 20),
        ("C_GetSlotInfo".to_string(), 0),
        ("C_GetTokenInfo".to_string(), 0),
    ]);
    assert_eq!(
        check_mix_exclusive(&children, &observed),
        Ok(()),
        "one window passes the mix oracle: the coverage guard must reject it instead"
    );
}

/// The coverage guard accepts two driven windows across both paths.
#[test]
fn flood_coverage_accepts_two_windows_across_both_paths() {
    let direct = std::path::Path::new("/cell/libflood.so");
    let alias = std::path::Path::new("/cell/libflood-alias.so");
    let child = |t_ms: u64, k: u64, provider: &std::path::Path| DrivenChild {
        t_ms,
        k,
        provider: provider.display().to_string(),
        counts: BTreeMap::from([
            ("init".to_string(), 1),
            ("slotlist".to_string(), 2),
            ("getinfo".to_string(), 1),
        ]),
    };
    let children = vec![
        child(1000, 10, direct),
        child(2000, 10, alias),
        child(61_000, 11, direct),
        child(62_000, 11, alias),
    ];
    assert_eq!(check_flood_coverage(&children, direct, alias), Ok(()));
}

/// The coverage guard rejects a single driven window, however many
/// children it ran and on however many paths.
#[test]
fn flood_coverage_rejects_a_single_window() {
    let direct = std::path::Path::new("/cell/libflood.so");
    let alias = std::path::Path::new("/cell/libflood-alias.so");
    let child = |t_ms: u64, provider: &std::path::Path| DrivenChild {
        t_ms,
        k: 10,
        provider: provider.display().to_string(),
        counts: BTreeMap::from([("init".to_string(), 1), ("getinfo".to_string(), 5)]),
    };
    let children = vec![child(1000, direct), child(2000, alias), child(3000, direct)];
    let error = check_flood_coverage(&children, direct, alias).expect_err("one window must fail");
    assert!(
        error.contains("window"),
        "the failure names the missing window: {error}"
    );
}

/// The coverage guard rejects two windows driven through one path
/// only: the split-domain shape needs both aliases.
#[test]
fn flood_coverage_rejects_a_single_path() {
    let direct = std::path::Path::new("/cell/libflood.so");
    let alias = std::path::Path::new("/cell/libflood-alias.so");
    let child = |t_ms: u64, k: u64| DrivenChild {
        t_ms,
        k,
        provider: direct.display().to_string(),
        counts: BTreeMap::from([("init".to_string(), 1), ("getinfo".to_string(), 5)]),
    };
    let children = vec![child(1000, 10), child(61_000, 11)];
    let error = check_flood_coverage(&children, direct, alias).expect_err("one path must fail");
    assert!(
        error.contains("alias") || error.contains("path"),
        "the failure names the missing path: {error}"
    );
}

/// The coverage guard accepts long runs whose mixes repeat: four
/// driven windows across both paths qualify however the mixes alias.
#[test]
fn flood_coverage_accepts_repeated_mixes_on_long_runs() {
    let direct = std::path::Path::new("/cell/libflood.so");
    let alias = std::path::Path::new("/cell/libflood-alias.so");
    let child = |t_ms: u64, k: u64, provider: &std::path::Path| DrivenChild {
        t_ms,
        k,
        provider: provider.display().to_string(),
        counts: BTreeMap::from([("init".to_string(), 1), ("getinfo".to_string(), 3)]),
    };
    // K = 10..13 reuses mix 0 in the fourth window; coverage counts
    // windows, while the per-mix oracle qualifies each mix total.
    let children = vec![
        child(1000, 10, direct),
        child(61_000, 11, alias),
        child(121_000, 12, direct),
        child(181_000, 13, alias),
    ];
    assert_eq!(check_flood_coverage(&children, direct, alias), Ok(()));
}

#[test]
#[ignore = "privileged: flood-admission --system short-lived exact-count cell"]
fn privileged_profile_system_flood_shortlived_exact_per_window() {
    use crate::fixture_guard::DieWithParent as _;
    // SAFETY: reading the effective uid has no preconditions.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run as root via scripts/run-privileged-lib-tests.sh"
    );
    let dur_s = env_usize("P11SCOPE_FLOOD_DUR_S", 120) as u64;
    let nway = env_usize("P11SCOPE_FLOOD_NWAY", 6);
    let hold_ms = env_usize("P11SCOPE_FLOOD_HOLD_MS", 200) as u64;
    let churn_us = env_usize("P11SCOPE_FLOOD_CHURN_US", 100).to_string();
    assert!(
        dur_s >= 120,
        "the cell floods for at least 120 s to drive two per-minute windows"
    );
    assert!((1..=32).contains(&nway), "sane flood concurrency");

    let dir = tempfile::tempdir().expect("cell dir");
    // Ext4-loop vehicle: the provider copy lives on a private ext4
    // mount while the alias below lands in the cell dir, so the alias
    // bind crosses filesystems. Default runs keep both in the cell dir.
    let ext4: Option<(tempfile::TempDir, Ext4Loop)> = if env_flag("P11SCOPE_FLOOD_EXT4_LOOP") {
        let backing = tempfile::tempdir().expect("ext4 backing dir");
        let mounted = Ext4Loop::create(backing.path());
        assert_fstype_ext4(&mounted.mount);
        Some((backing, mounted))
    } else {
        None
    };
    let provider_dir: &Path = ext4
        .as_ref()
        .map(|(_, mounted)| mounted.mount.as_path())
        .unwrap_or(dir.path());
    let provider = unique_provider_copy(provider_dir);
    let conf = init_token(dir.path());
    // Split-domain shape (addendum d): a bind-mounted alias of the
    // same file, so half the children map the provider through a
    // second mount view even on single-domain filesystems. Held for
    // the whole cell; the anchor and churn stay on the direct path.
    let (_alias_guard, alias) = bind_provider_alias(dir.path(), &provider);
    let child_bin = build_c(dir.path(), "flood-child", CHILD_C);
    let anchor_bin = build_c(dir.path(), "flood-anchor", ANCHOR_C);
    let churn_bin = build_c(dir.path(), "flood-churn", CHURN_C);

    // Apparatus check: one child must report COUNTS through the full
    // run-kill-reap cycle (it never exits by itself).
    assert!(
        run_child(&child_bin, &provider, &conf, 2, Duration::ZERO, 0).is_some(),
        "apparatus child reports COUNTS"
    );

    // Anchor first: mapped before the capture starts so the initial
    // scan learns the provider and attach settles before counted
    // children. Held to capture end so its slots stay active.
    let mut anchor = GuardedChild(
        Command::new(&anchor_bin)
            .arg(&provider)
            .env("SOFTHSM2_CONF", &conf)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .die_with_parent()
            .spawn()
            .expect("spawn the anchor"),
    );
    {
        use std::io::BufRead as _;
        let stdout = anchor.0.stdout.take().expect("anchor stdout");
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("anchor prints its mapping");
        assert!(
            line.starts_with("ANCHOR pid="),
            "anchor mapped pre-capture: {line:?}"
        );
    }

    // Observer + churn. The driver deadline is measured from the
    // OBSERVER start: ready wait and settle consume capture time, so
    // a driver-relative margin would overrun the capture tail.
    let out = dir.path().join("out.json");
    let obs_start = Instant::now();
    let mut observer = Command::new(observer_binary())
        .env("SOFTHSM2_CONF", &conf)
        .args([
            "profile",
            "--system",
            "--module",
            provider.to_str().expect("utf8 module"),
            "--duration",
            &format!("{dur_s}s"),
            "-v",
            "-o",
        ])
        .arg(&out)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .die_with_parent()
        .spawn()
        .expect("spawn the observer");
    let mut observer_stderr = observer.stderr.take().expect("observer stderr");
    wait_ready(&mut observer, &mut observer_stderr);
    std::thread::sleep(Duration::from_secs(5));
    let churn = GuardedChild(
        Command::new(&churn_bin)
            .arg(&provider)
            .arg(&churn_us)
            .env("SOFTHSM2_CONF", &conf)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .die_with_parent()
            .spawn()
            .expect("spawn churn"),
    );

    // Driver: NWAY worker threads spawn SIGKILL children with a
    // per-minute K signature until the deadline margin (12 s before
    // capture end, measured from the observer start). Each worker
    // loops spawn-wait-hold-kill-reap; panics propagate through joins.
    // Children alternate between the direct provider path and its
    // bind-mounted alias, so both mount views churn together.
    let start = Instant::now();
    let end = obs_start + Duration::from_secs(dur_s.saturating_sub(12));
    let hold = Duration::from_millis(hold_ms);
    let (ledger_tx, ledger_rx) = std::sync::mpsc::channel::<Option<DrivenChild>>();
    let child_bin = &child_bin;
    let provider = &provider;
    let alias = &alias;
    let conf = &conf;
    let child_seq = std::sync::atomic::AtomicU64::new(0);
    std::thread::scope(|scope| {
        for _ in 0..nway {
            let ledger_tx = ledger_tx.clone();
            let child_seq = &child_seq;
            scope.spawn(move || {
                while Instant::now() < end {
                    let k = 10 + start.elapsed().as_secs() / 60;
                    let t_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let seq = child_seq.fetch_add(1, Ordering::Relaxed);
                    let path = if seq.is_multiple_of(2) {
                        provider
                    } else {
                        alias
                    };
                    let driven = run_child(child_bin, path, conf, k, hold, t_ms);
                    ledger_tx
                        .send(driven)
                        .expect("the ledger receiver outlives workers");
                }
            });
        }
        drop(ledger_tx);
    });
    let mut children: Vec<DrivenChild> = Vec::new();
    let mut warns = 0u64;
    for driven in ledger_rx {
        match driven {
            Some(child) => children.push(child),
            None => warns += 1,
        }
    }
    assert_eq!(warns, 0, "{warns} flood children failed");
    assert!(
        !children.is_empty(),
        "the driver ran no children in {dur_s}s"
    );
    children.sort_by_key(|child| child.t_ms);
    eprintln!("flood cell: drove {} children", children.len());
    // Coverage gate: two driven windows across both aliases, or the
    // per-window oracle below could pass vacuously — a short or
    // slow-start run drives a single mix whose empty siblings assert
    // zero. Fail loudly here instead of weakening the oracle.
    check_flood_coverage(&children, provider, alias).unwrap_or_else(|gap| {
        panic!(
            "flood cell coverage: {gap} ({} children drove)",
            children.len()
        )
    });
    drop(churn);

    let status = wait_bounded(&mut observer, dur_s + 120).expect("the observer exits");
    assert_eq!(status.code(), Some(0), "profile exits 0");
    drop(anchor);
    // The profile is written and every child reaped: release the ext4
    // loop mount explicitly and prove it is gone (Drop still detaches
    // on panic paths, like `BindMount`).
    if let Some((_, ext4loop)) = &ext4 {
        ext4loop.unmount();
        assert!(
            !ext4loop.is_mounted(),
            "the ext4 loop mount at {} leaked; umount it by hand",
            ext4loop.mount.display()
        );
        eprintln!("flood cell: ext4 loop mount released");
    }
    let capture_end_ms = obs_start.elapsed().as_millis() as u64;
    let driver_start_ms = u64::try_from(start.duration_since(obs_start).as_millis()).unwrap();
    // Persist the profile and ledgers beside the runner's per-test
    // evidence dir when provided, so failures keep their artifacts
    // after the cell tempdir is reaped.
    if let Ok(evidence) = std::env::var("P11SCOPE_TASK4_EVIDENCE_DIR") {
        let evidence = PathBuf::from(evidence);
        let _ = std::fs::copy(&out, evidence.join("flood-profile.json"));
        let mut ledger = format!(
            "children={} driver_start_ms={driver_start_ms} capture_end_ms={capture_end_ms}\n",
            children.len(),
        );
        for child in &children {
            ledger.push_str(&format!(
                "CHILD t_ms={} k={} mix={} via={} getinfo={} slotlist={} getslotinfo={} gettokeninfo={}\n",
                child.t_ms,
                child.k,
                window_mix(child.k),
                child.provider,
                child.counts.get("getinfo").copied().unwrap_or(0),
                child.counts.get("slotlist").copied().unwrap_or(0),
                child.counts.get("getslotinfo").copied().unwrap_or(0),
                child.counts.get("gettokeninfo").copied().unwrap_or(0),
            ));
        }
        let _ = std::fs::write(evidence.join("flood-driver.log"), ledger);
    }
    let profile: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("profile exists"))
            .expect("the profile parses");

    // Ground truth: the flood children (the anchor makes zero calls).
    let mut expected: BTreeMap<String, u64> = BTreeMap::new();
    for child in &children {
        for (name, count) in &child.counts {
            *expected.entry(name.clone()).or_insert(0) += count;
        }
    }
    // Driver ledger names vs profile function names.
    let rename = |name: &str| match name {
        "init" => "C_Initialize",
        "gfl" => "C_GetFunctionList",
        "slotlist" => "C_GetSlotList",
        "getinfo" => "C_GetInfo",
        "getslotinfo" => "C_GetSlotInfo",
        "gettokeninfo" => "C_GetTokenInfo",
        other => panic!("unknown ledger name: {other}"),
    };
    let sha = record_sha256_any(&profile, &[provider.as_path(), alias.as_path()]);
    let observed = function_calls(&profile, &sha);
    let observed_getinfo = observed.get("C_GetInfo").copied().unwrap_or(0);
    let (matched, break_t_ms, break_k) = break_prefix(&children, observed_getinfo);
    let diagnosis = format!(
        "children={} driver_start_ms={driver_start_ms} \
         capture_end_ms={capture_end_ms} observed_getinfo={observed_getinfo} \
         matched_prefix={matched}/{} break_t_ms={break_t_ms} break_k={break_k}",
        children.len(),
        children.len(),
    );
    eprintln!("flood cell: {diagnosis}");
    for (name, want) in &expected {
        let function = rename(name);
        eprintln!(
            "flood cell: {function} expected={want} observed={}",
            observed.get(function).copied().unwrap_or(0)
        );
    }
    // Per-endpoint break attribution: each mix owns distinct
    // endpoints, so a stall's missing suffix names its mix (and, for
    // short captures, its minute) here.
    for (name, function) in [
        ("getinfo", "C_GetInfo"),
        ("slotlist", "C_GetSlotList"),
        ("getslotinfo", "C_GetSlotInfo"),
        ("gettokeninfo", "C_GetTokenInfo"),
    ] {
        let (at, at_t_ms, at_k) = break_prefix_for(
            &children,
            name,
            observed.get(function).copied().unwrap_or(0),
        );
        eprintln!(
            "flood cell: {function} break matched_prefix={at}/{} break_t_ms={at_t_ms} break_k={at_k}",
            children.len()
        );
    }
    // Per-window oracle: each mix's observed endpoint totals against
    // the driver ledger for that mix's windows. A missing call in one
    // window cannot cancel an extra call in another mix's window —
    // the other mix never drives that endpoint.
    check_mix_exclusive(&children, &observed)
        .unwrap_or_else(|mismatch| panic!("per-window exact counts ({diagnosis}): {mismatch}"));
    // Inits first: whole missing callers (stall/overrun shape) vs
    // partial call loss read differently in the diagnosis above.
    assert_eq!(
        observed.get("C_Initialize").copied().unwrap_or(0),
        expected.get("init").copied().unwrap_or(0),
        "exact count for C_Initialize ({diagnosis})"
    );
    for (name, want) in &expected {
        let function = rename(name);
        assert_eq!(
            observed.get(function).copied().unwrap_or(0),
            *want,
            "exact count for {function} ({diagnosis})"
        );
    }
    let ledger_names: BTreeMap<String, u64> = expected
        .iter()
        .map(|(name, count)| (rename(name).to_string(), *count))
        .collect();
    let spurious: u64 = observed
        .iter()
        .filter(|(name, _)| !ledger_names.contains_key(*name))
        .map(|(_, calls)| calls)
        .sum();
    assert_eq!(spurious, 0, "no calls outside the ledger: {observed:?}");
    assert_eq!(
        profile
            .get("evidence")
            .and_then(|evidence| evidence.get("event_loss"))
            .and_then(|loss| loss.as_u64()),
        Some(0),
        "no event loss"
    );
    // Stall fingerprint: our provider copy's key is unique to this
    // cell, so any ambiguity row is our group rejected mid-capture
    // (the pre-fix stall shape: ambiguous identity, retired slots).
    let ambiguous = profile
        .get("evidence")
        .and_then(|evidence| evidence.get("skipped"))
        .and_then(|skipped| skipped.as_array())
        .map(|skipped| {
            skipped
                .iter()
                .filter(|skip| {
                    skip.get("reason")
                        .and_then(|reason| reason.as_str())
                        .is_some_and(|reason| reason.contains("physical identity is ambiguous"))
                })
                .count()
        })
        .unwrap_or(0);
    assert_eq!(ambiguous, 0, "no ambiguity rows on the fixed code");
    // The anchor is held to capture end: no slot is retired. Every
    // slot is either active or never semantically verified (functions
    // the workload never calls); the pre-fix code retires them all
    // mid-capture (active 0) when the flood's teardown races reject
    // the proven group.
    let evidence = profile.get("evidence").expect("evidence");
    let slots = evidence.get("slots").and_then(|slots| slots.as_u64());
    let active = evidence
        .get("active_slots")
        .and_then(|slots| slots.as_u64());
    let unverified = evidence
        .get("semantic_unverified_slots")
        .and_then(|slots| slots.as_u64());
    let slots = slots.expect("evidence.slots");
    let active = active.expect("evidence.active_slots");
    let unverified = unverified.expect("evidence.semantic_unverified_slots");
    assert_eq!(
        active + unverified,
        slots,
        "no slot retired: every slot is active or never verified"
    );
}
