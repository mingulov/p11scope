# Release Hardening Wave 1 — Security Findings Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all eight open findings from static security scan `3e10be9` (six MEDIUM, two LOW) with focused local tests, repair the Stage 3A3 evidence-custody gap, and drive independent review→fix cycles until zero findings remain — so the basic product is issue-free and fully covered by the local test framework.

**Architecture:** One TDD task per finding, at its cited code site, using the scanner record preserved in the private `p11scope-ws` custody tree plus a fresh code-level implementation brief as the design authority. The current verified execution base is `main` `5d251b76b33b14839a7147e14b5ccd1348855587`; reviewed `b86d4d5` and `556f7cf` anchors remain historical evidence, not execution bases. Two findings turned out to be more than the scan said (Lane 14 receipt mis-binding is a live bug; `-o` is currently broken under old Docker seccomp). Work lands on branch `hardening/findings-wave1`; the wave closes with full canonical gates and iterated review cycles, then merges to `main`.

**Tech Stack:** Rust 1.88 (edition 2024), aya eBPF, `libc` 0.2.189 (only syscall dep — no new deps), bash release driver, existing `tests/` + in-module `mod tests` framework.

**Spec:** `docs/superpowers/specs/2026-09-01-release-requirements-and-goal.md` §3/§5 (the owner authority; it supersedes the consolidation-status "Next order" list). Scanner detail is the hash-pinned record migrated to `p11scope-ws/preserved/security-scan-3e10be9/findings.json`; the old `.local/state` path is source history only and is not a durable plan dependency.

**Plan review 2026-09-01:** every cited anchor was verified against historical HEAD `556f7cf`/`b86d4d5` by three independent read-only verifiers (Tasks 1-3, 4-6, 7-9); those reviewed bases remain historical. The current execution anchor is verified `main` `5d251b76b33b14839a7147e14b5ccd1348855587` (origin gap 239). All accepted corrections are folded in below. Largest: Task 6 gained part (f) — the `/proc/<pid>/maps` read itself was still unbudgeted (spec §3.1 / research #3); Task 5's original test destroyed the directory behind the retained fd and could green a broken fix; Task 4's ancestry rule as first drafted refused this repo's own 775 working tree. The "brief A/B in the scratchpad" pointers were dead (session-local, gone) and were replaced with self-contained instructions.

## Global Constraints

- Rust 1.88, edition 2024, Linux x86-64-first (CLAUDE.md). `std::env::remove_var` and other formerly-safe fns are `unsafe` in edition 2024 — wrap in `unsafe {}` where noted.
- **All four canonical gates green after every task**: `cargo +1.88 fmt --all -- --check`, `cargo +1.88 check --locked --workspace --all-targets`, `cargo +1.88 test --locked --workspace --all-targets`, `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings`.
- Preserve `docs/privacy/allowlist-v1.md`; never broaden capture implicitly. Target-controlled bytes must not leak into the capture document (subjects stay operator-path/label form, never `/proc/self/fd/N`).
- No new dependencies. `libc` 0.2.189 already exports `open_how` (`#[non_exhaustive]` — construct via `mem::zeroed()` + field assignment only), `RESOLVE_NO_SYMLINKS`, `SYS_close_range` (verified for both gnu and musl x86-64); use the raw `libc::syscall` for `close_range` (the wrapper fn is gnu-only and the release also builds a musl helper).
- Do not track generated output. Wave-1 tasks must be verifiable unprivileged; a privileged-only assertion follows the repo convention — assert the outcome the observed configuration requires (`tests/proc_access.rs:1-5`), reserve `eprintln!("SKIP: …")` for a genuinely absent resource only.
- Kernel floor 5.15. `openat2`(5.6)/`close_range`(5.9) exist on every supported kernel, but keep the `ENOSYS`/`EPERM` fallback where specified — seccomp (Docker) is the real reason, not the kernel.
- Branch `hardening/findings-wave1` off verified `main` `5d251b76b33b14839a7147e14b5ccd1348855587` (origin gap 239). `556f7cf` and `b86d4d5` are retained as historical reviewed bases only. Frequent commits (one per task). Merge only after Task 11 review cycles reach zero accepted findings.

---

### Task 0: Stage 3A3 evidence-custody rescue (before product Task 1)

**Files:**
- Modify: `docs/superpowers/reports/2026-08-31-productization-evidence-index.md:66-70`, root `.gitignore`, and `/home/user/src/m/p11scope-ws/.gitignore`
- Restore only into: `/home/user/src/m/p11scope-ws/preserved/sdd/2026-08-27-task4-receipt-closure/` (durable home per spec §4)
- Never recreate the private SDD trove under the public repository; public files may contain only a pointer/fence.

- [ ] **Step 1 — install both ignore fences first:** create/verify the public root `.gitignore` fence for `.superpowers/sdd/` and the private sibling `/home/user/src/m/p11scope-ws/.gitignore` fence for `incoming/`, `vm-bases/`, `preserved/evidence-roots/`, `preserved/portable/`, `*.tar.zst`, `*.qcow2`, and `*.img`. Do not recreate the private SDD trove under the public repository.
- [ ] **Step 2 — no-clobber preflight and source choice:** use the complete source under `/home/user/.local/state/p11scope/retired-generated-slice1b2-finish/.superpowers/sdd/2026-08-27-task4-receipt-closure/` only as input. The destination `/home/user/src/m/p11scope-ws/preserved/sdd/2026-08-27-task4-receipt-closure/` must be absent, or already have complete exact manifest equality; in either case do not copy. Otherwise copy only to a private sibling temporary directory under `p11scope-ws`, never to a public path.
- [ ] **Step 3 — verify and classify:** hash every source file before copying and every temporary/destination file after it with a sorted, path-stable manifest; record exact before/after SHA-256 values and the manifest hash. Verify the two named reports are non-empty and match the tarball cross-check byte-for-byte. Run a private-data/privacy scan and classify PID, address, and raw-capture content as private-only; classify any such content, forbidden paths, or a public SDD recreation as forbidden in the public diff.
- [ ] **Step 4 — publish without replacement:** publish the verified temporary tree with `mv -T --no-clobber` (or an equally minimal native no-replace operation), then assert the destination's exact file set and hashes and that no existing destination was overwritten. Update the evidence index to point to `p11scope-ws/preserved/sdd/2026-08-27-task4-receipt-closure/` and state that no public SDD copy exists; the portable package may hold only the explicitly approved three-file `stage3a3/` subset.
- [ ] **Step 5 — mirror the scanner record privately:** copy `findings.json` only into `/home/user/src/m/p11scope-ws/preserved/security-scan-3e10be9/findings.json` under the same no-clobber, exact-hash, deterministic-manifest, and private-data scan rules. Never copy it into public `.superpowers/sdd/` or another public evidence path.
- [ ] **Step 6 — explicit staging and separate reviews:** stage only an explicit path list (never `git add -A` or a broad glob): public pointer/fence paths in the public repository, and durable private text/manifests in `p11scope-ws`; never stage raw captures or ignored binaries. Review and commit the public pointer/fence separately from the private custody commit, with exact before/after hashes in each review record.
- [ ] **Step 7 — gates and privacy fence:** verify that a fresh public clone cannot stage the private trove, scan both repositories' diffs for PIDs, addresses, raw captures, and forbidden paths, and run the public repository's non-Cargo markdown/source checks. Privileged/container rows remain UNRUN without separate approval and do not block the W1 unprivileged exit.

---

### Task 1: Helper file-descriptor and environment confinement (csf_f5953ae, MEDIUM)

**Files:**
- Modify: `crates/discover/src/main.rs` (top of `drop_privileges_and_open_self_memory`, before the `/proc/self/mem` open at :142)
- Create: `crates/discover/tests/fixture/fd_env_canary.c`
- Test: `crates/discover/tests/cli.rs` (add one test; reuses `BIN` at :4)

**Interfaces:**
- Produces: `close_inherited_descriptors() -> Result<()>` (fail closed if neither `close_range` nor a verified `/proc/self/fd` fallback establishes closure), `ensure_loader_env_sanitized()` with a private re-exec marker, and a `LOADER_SENSITIVE_ENV: &[&str]` const, all private to `crates/discover/src/main.rs`; the `Result<File, String>` caller maps both helper errors to its existing string error contract.
- The fix MUST live in `main.rs` only — never in `discover.rs`, whose `discover()` is called in-process by four test binaries (`fixture_provider.rs`, `version_matrix.rs`, `lazy_dependency.rs`, `softhsm.rs`); a `close_range` there would shred the libtest harness fds.

- [ ] **Step 1: Write the failing test.** New fixture `crates/discover/tests/fixture/fd_env_canary.c` (constructor reports on stderr, so it needs no env of its own):

```c
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#define PLANTED_FD 17
typedef unsigned long CK_RV;
#ifdef DEPENDENCY
int fd_env_loader_marker(void) { return 1; }
#else
__attribute__((constructor)) static void ctor(void) {
    ssize_t n = write(PLANTED_FD, "LEAK", 4);
    fprintf(stderr, "CANARY_FD=%s\n", (n < 0 && errno == EBADF) ? "closed" : "OPEN");
    void *dep = dlopen("fd-env-dependency.so", RTLD_NOW | RTLD_LOCAL);
    void *preload = dlsym(RTLD_DEFAULT, "fd_env_loader_marker");
    fprintf(stderr, "CANARY_SEARCH=%s\n", dep ? "present" : "absent");
    fprintf(stderr, "CANARY_PRELOAD=%s\n", preload ? "present" : "absent");
    fflush(stderr);
}
CK_RV C_GetFunctionList(void **pp) { *pp = 0; return 5UL; /* CKR_GENERAL_ERROR */ }
#endif
```

Add to `crates/discover/tests/cli.rs` (compile the fixture twice with the `gcc -shared -fPIC` idiom from `lazy_dependency.rs:16-34`, once with `-DDEPENDENCY` as `fd-env-dependency.so`; use `std::io::pipe` (stable 1.87) + `pre_exec` `dup2(raw,17)` to plant an inheritable fd — `dup2` clears `FD_CLOEXEC` on the copy). Launch with `LD_LIBRARY_PATH` pointing at the dependency and `LD_PRELOAD` set to that valid dependency, then assert the provider constructor reports both loader effects absent after the self-reexec; this exercises loader search/preload behavior, not only `getenv`. Assert on stderr not exit status, since the fixture's `C_GetFunctionList` errors → helper exits 1):

```rust
#[test]
fn constructor_sees_no_planted_fd_or_loader_env() {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fd-canary");
    std::fs::create_dir_all(&dir).unwrap();
    let provider = dir.join("fd-env-canary.so");
    let dependency = dir.join("fd-env-dependency.so");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture/fd_env_canary.c");
    assert!(Command::new("gcc").args(["-shared", "-fPIC", "-o"]).arg(&provider).arg(&src)
        .status().unwrap().success());
    assert!(Command::new("gcc").args(["-shared", "-fPIC", "-DDEPENDENCY", "-o"]).arg(&dependency).arg(&src)
        .status().unwrap().success());
    let (mut reader, writer) = std::io::pipe().unwrap();
    let raw = writer.as_raw_fd();
    let mut cmd = Command::new(BIN);
    cmd.arg("--module").arg(&provider)
        .env("LD_LIBRARY_PATH", &dir)
        .env("LD_PRELOAD", &dependency)
        .stderr(std::process::Stdio::piped());
    unsafe { cmd.pre_exec(move || { if libc::dup2(raw, 17) < 0 { return Err(std::io::Error::last_os_error()); } Ok(()) }); }
    let out = cmd.output().unwrap();
    drop(writer);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("CANARY_FD=closed"), "planted fd survived: {stderr}");
    assert!(stderr.contains("CANARY_SEARCH=absent"), "LD_LIBRARY_PATH survived: {stderr}");
    assert!(stderr.contains("CANARY_PRELOAD=absent"), "LD_PRELOAD survived: {stderr}");
    let mut leaked = Vec::new();
    reader.read_to_end(&mut leaked).unwrap();
    assert!(leaked.is_empty(), "constructor wrote through planted fd: {leaked:?}");
}
```

- [ ] **Step 2: Run it, verify FAIL** (`CANARY_FD=OPEN`, `CANARY_SEARCH=present`, or `CANARY_PRELOAD=present` before the fix): `cargo +1.88 test -p p11scope-discover --test cli constructor_sees_no_planted_fd -- --nocapture`. Add `close_range_failure_uses_verified_proc_fallback` (inject `close_range` → `EPERM`, then assert the planted fd is closed) and `unreadable_proc_fallback_fails_closed` (inject `close_range` → `EPERM` plus `read_dir` → `PermissionDenied`, then assert a hard error and no provider load). Run all three before implementation and observe failure. Add a second invocation with a forged marker plus one sensitive variable and assert a hard refusal; the marker must never bypass sanitization.
- [ ] **Step 3: Implement.** In `crates/discover/src/main.rs`, add the closure helper, sanitized re-exec helper, and denylist const, and call them at the very top of `drop_privileges_and_open_self_memory` (before `File::open("/proc/self/mem")` at :142 — self-mem fd then lands at 3, outside the closed range; no `dup2` renumber needed):

```rust
fn close_inherited_descriptors() -> std::io::Result<()> {
    // SYS_close_range present on both shipped targets; the libc::close_range wrapper
    // is gnu-only (libc 0.2.189 declares it under linux/gnu only) and build-release.sh
    // also builds a musl helper — use the raw syscall.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0) } == 0 { return Ok(()); }
    // Fallback: seccomp ENOSYS/EPERM. `collect_proc_fd_snapshot` uses read_dir, propagates
    // every entry error, records the enumeration dirfd, collects the complete snapshot while
    // this code is single-threaded, and drops ReadDir before returning. If even /proc/self/fd
    // is unreadable (masked /proc, e.g. the musl container lane,
    // verify-discover-containers.sh:239-245), return the error. A closure failure is
    // security-relevant: fail closed rather than continue.
    let (enumeration_fd, mut fds) = collect_proc_fd_snapshot("/proc/self/fd")?;
    fds.sort_unstable();
    for fd in fds {
        let rc = unsafe { libc::close(fd) };
        let error = std::io::Error::last_os_error();
        if rc < 0 && !(fd == enumeration_fd && error.raw_os_error() == Some(libc::EBADF)) {
            return Err(error);
        }
    }
    Ok(())
}

// glibc unsecvars.h set: the loader-sensitive vars a provider constructor might read.
const LOADER_SENSITIVE_ENV: &[&str] = &[
    "GCONV_PATH","GETCONF_DIR","GLIBC_TUNABLES","HOSTALIASES","LD_AUDIT","LD_BIND_NOT",
    "LD_BIND_NOW","LD_DEBUG","LD_DEBUG_OUTPUT","LD_DYNAMIC_WEAK","LD_HWCAP_MASK",
    "LD_LIBRARY_PATH","LD_ORIGIN_PATH","LD_PRELOAD","LD_PROFILE","LD_PROFILE_OUTPUT",
    "LD_SHOW_AUXV","LD_USE_LOAD_BIAS","LOCALDOMAIN","LOCPATH","MALLOC_ARENA_MAX",
    "MALLOC_ARENA_TEST","MALLOC_CHECK_","MALLOC_MMAP_MAX_","MALLOC_MMAP_THRESHOLD_",
    "MALLOC_PERTURB_","MALLOC_TOP_PAD_","MALLOC_TRACE","NIS_PATH","NLSPATH",
    "RESOLV_HOST_CONF","RES_OPTIONS","TMPDIR","TZDIR",
];

const SANITIZED_ENV_MARKER: &str = "P11SCOPE_LOADER_ENV_SANITIZED";

fn ensure_loader_env_sanitized() -> std::io::Result<()> {
    let present = LOADER_SENSITIVE_ENV.iter().any(|name| std::env::var_os(name).is_some());
    let marked = std::env::var_os(SANITIZED_ENV_MARKER).is_some();
    if marked && present { return Err(std::io::Error::other("sanitized marker with loader-sensitive environment")); }
    if !present { return Ok(()); } // a forged marker is safe only when every sensitive var is absent
    let exe = "/proc/self/exe";
    let mut cmd = std::process::Command::new(exe);
    cmd.args(std::env::args_os().skip(1)).env(SANITIZED_ENV_MARKER, "1");
    for name in LOADER_SENSITIVE_ENV { cmd.env_remove(name); }
    Err(std::os::unix::process::CommandExt::exec(&mut cmd))
}
```

`collect_proc_fd_snapshot` is a private raw-fd-backed `read_dir` adapter: it
returns the enumeration fd plus every parsed fd greater than 2, propagates
every `read_dir` entry error, collects while single-threaded, and drops
`ReadDir` before the close loop. The fallback permits `EBADF` only for that
enumeration fd's stale entry; every other `EBADF` or close error fails closed.
The close-range seam is injectable so the two fallback tests above exercise
both successful proc fallback and fail-closed unreadable `/proc` behavior.

At the call site (denylist, not allowlist — `SOFTHSM2_CONF` and other provider config must survive; `verify-attach-e2e.sh:149` threads it):

```rust
    close_inherited_descriptors()
        .map_err(|e| format!("inherited descriptor closure failed: {e}"))?;
    // Re-exec before discover.rs:53 can dlopen the provider. The second process
    // starts with all loader-sensitive vars absent, while SOFTHSM2_CONF and other
    // provider configuration stays intact. A marker is trusted only with no
    // sensitive variable present; marker+variable is a hard failure.
    ensure_loader_env_sanitized()
        .map_err(|e| format!("loader environment sanitization failed: {e}"))?;
```

Note: `prepare_drop()` at `main.rs:253` reads `SUDO_UID`/`SUDO_GID` (`target_id`, `:37-43`) before this point — the denylist deliberately excludes them, so provider configuration and privilege-selection inputs survive the re-exec. Keep the closure and re-exec at the top of `drop_privileges_and_open_self_memory`, before any provider load.

- [ ] **Step 4: Run test, verify PASS.** Then full workspace test to confirm the four in-process fixture binaries are untouched.
- [ ] **Step 5: Add a `CHANGELOG.md` line** noting the helper now closes inherited fds and strips loader env (behavior: providers whose subprocesses relied on inherited `LD_LIBRARY_PATH` no longer see it). Commit `security: confine discovery helper descriptors and loader environment (csf_f5953ae)`.

**Regression watch (must stay green):** all 8 `crates/discover/tests/cli.rs` tests, especially the `-o` cases (outfile written via `std::fs::write` at `main.rs:277`, after the close — fine) and `control_fd_flag_is_gone:85` (no protocol fd exists). `lazy_dependency.rs:48-49` opens a `File` in-process and passes `/proc/self/fd/{}` as the module path — untouched only because the fix lives in `main.rs`, never `discover.rs`. Shell e2e sites pass no extra fds; `build-release.sh:447`'s fd 3 is for the observer, not the helper.

---

### Task 2: Trace output cumulative bound (csf_ad79ebb, MEDIUM)

**Files:**
- Modify: `src/cli.rs` (`Common` struct, `capture_option`, profile-refusal, USAGE :103), `src/run.rs` (`CaptureEnd` enum :922, `capture_trace` :2071, `drain_trace_events` :2292, a `DEFAULT_TRACE_MAX_EVENTS` const), `src/trace.rs` (`evidence_line` :177, new `truncated_line` :166)
- Test: `src/cli.rs` mod tests (:590 area), `src/trace.rs` mod tests (:436 area), one `scripts/bench-overhead.sh` assertion

**Interfaces:**
- Produces: `Common.max_events: Option<u64>`; `CaptureEnd::LimitReached`; `trace::truncated_line(limit: u64) -> String`; `trace::evidence_line(ev, policy, truncated: bool)` (added 3rd param).
- Consumes: existing `render::Evidence`, `CapturePolicy`, `trace::lost_line`.

- [ ] **Step 1: Write every failing test before implementation.** In `src/cli.rs` mod tests (shape of `trace_rejects_mode_and_accepts_the_rest:590`):

```rust
#[test]
fn trace_takes_a_max_events_bound_and_profile_refuses_it() {
    let a = parse_capture(Kind::Trace, args(&["--pid","1","--max-events","1"])).unwrap();
    assert_eq!(a.max_events, Some(1));
    assert!(matches!(parse_capture(Kind::Profile, args(&["--pid","1","--max-events","1"])),
        Err(CliError::Usage(m)) if m.contains("--max-events is a trace option")));
    assert!(matches!(parse_capture(Kind::Trace, args(&["--pid","1","--max-events","x"])),
        Err(CliError::Usage(m)) if m.contains("invalid number")));
    assert!(matches!(parse_capture(Kind::Trace, args(&["--pid","1","--max-events","0"])),
        Err(CliError::Usage(m)) if m.contains("must be greater than zero")));
}
```

Also add these RED integration tests before touching the parser or capture loop: `default_trace_bound_applies_to_stdout` (an omitted `--max-events` still emits at most the documented default and then `TRUNCATED` plus one partial evidence record), `bounded_file_trace_is_cumulative` (the same bound applies across `-o` rather than separately per sink), and `owned_child_limit_reaches_settlement_and_reap` (a `--max-events 1` owned run reaches terminal drain, emits truncation/evidence, and verifies the child has been reaped). Keep the test fixtures deterministic and assert the event count and terminal records, not merely process success.

Write the failing evidence assertion shown in Step 4 now as part of this same RED set; do not defer writing any test until after a production edit.

- [ ] **Step 2: Run every RED test and record the failures before implementation.** Run the CLI parser test, the evidence test below, `default_trace_bound_applies_to_stdout`, `bounded_file_trace_is_cumulative`, and `owned_child_limit_reaches_settlement_and_reap` in one focused command (or equivalent individually); each must fail for the missing behavior before any production edit.

- [ ] **Step 3: Implement the flag.** In `src/cli.rs`: add `max_events: Option<u64>` to `Common` (:173-182); in `capture_option` parse a positive integer and reject `0` with `"--max-events must be greater than zero"`; in `parse_capture`/`parse_run` add `if kind == Kind::Profile && common.max_events.is_some() { return Err(usage_err("--max-events is a trace option; profile publishes one aggregate document")); }`; extend the trace USAGE line (:103) with `[--max-events <n>]`. There is no unlimited mode: an omitted value uses the documented default cumulative bound.

- [ ] **Step 4: Keep the already-written evidence assertion in `src/trace.rs` mod tests** (reuse the `Evidence` literal from `final_evidence_line_is_machine_readable_and_never_claims_a_proven_drain:436`; it was run RED with the other tests in Step 2):

```rust
#[test]
fn a_truncated_trace_says_so_in_its_terminal_record() {
    assert_eq!(truncated_line(1), "TRUNCATED at 1 events (--max-events)");
    let evidence = /* same literal as trace.rs:437-493 */;
    let line = evidence_line(&evidence, CapturePolicy::Allowlisted, true);
    let v: serde_json::Value = serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
    assert_eq!(v["trace_truncated"], true);
    assert_eq!(v["completeness"], "PARTIAL");
}
```

- [ ] **Step 5: Implement termination + evidence.** In `src/run.rs`: `const DEFAULT_TRACE_MAX_EVENTS: u64 = 10_000_000;` (10M, so `bench-overhead.sh`'s default 1M workload is not truncated; an operator raising `N_CALLS` past 10M sees the visible `TRUNCATED` line — documented behavior). Add `CaptureEnd::LimitReached` to :923 (NOT in `allows_handoff` :931 — an owned child must not be handed back on truncation). In `capture_trace`, use one `remaining` counter initialized from the positive CLI value or the default **before** borrowing `out_sink`; the default applies cumulatively to stdout and file trace. Pass `remaining: &mut Option<u64>` into both regular and terminal `drain_trace_events` calls, appending the arg after `session` so the pinned source text survives. Inside `drain.poll`, when `remaining == Some(0)` still call `state.observe_process(process,&ev)` but do not emit; otherwise emit and decrement. After the drain, `if remaining == Some(0) { break Ok(CaptureEnd::LimitReached); }` goes between drain and `retire_exited`. Thread `max_events` through `run_loop` (:1117, already `#[allow(clippy::too_many_arguments)]`; call sites :1063, :1580). `LimitReached` must flow through terminal drain, emit one `TRUNCATED` line and `trace_truncated: true` evidence with `PARTIAL`, then settle and reap the owned child before returning; it must not be converted into a normal handoff. In `src/trace.rs`, add `truncated_line(limit: u64) -> String`, add the boolean to `evidence_line`, and update all four callers. Compile churn: every exhaustive `Common` literal gains `max_events: None`.
- [ ] **Step 6: Run focused tests and verify PASS.** Run parsing, evidence, default stdout, bounded file trace, and the owned run. The default path must be bounded on stdout as well as `-o`, and `CaptureEnd::LimitReached` must still produce terminal evidence and a reaped child.
- [ ] **Step 7:** Add a `--max-events 1` assertion to `scripts/bench-overhead.sh` trace lane (or a small verify step): output file has the `CAPTURE` line, ≤1 event line, a `TRUNCATED` line, one `EVIDENCE …"trace_truncated":true`, process exits 0. Commit `security: bound trace output by event count with truncation evidence (csf_ad79ebb)`.

**Regression watch:** `tests/artifact_contracts.rs::both_capture_loops_keep_the_one_frozen_per_tick_ordering:3628` slices `capture_trace` source and requires literal substrings incl. `"    loop {\n        let elapsed = clock.elapsed();"`, `"drain_trace_events(\n            session,"`, `"report_trace_loss("`, `"    finish_capture_loop("` — preserve formatting exactly. Also `usage_documents_every_subcommand…:3440` (keep `p11scope trace` on its USAGE line), `tests/pause.rs:160`, `src/cli.rs` parser tests, `src/trace.rs::final_evidence_line_…:436` (signature change).

---

### Task 3: Terminal control-byte escaping (csf_b8067e3, LOW)

**Files:**
- Modify: `src/render.rs` (new `escape_controls`, `heading()` :136-142), `src/inspect.rs` (:74, :68, :143), `src/discovery/engine.rs` (:2263-2267 eprintln)
- Test: `src/render.rs` mod tests (:3341 area), `src/inspect.rs` mod tests (:452 area)

**Interfaces:**
- Produces: `pub(crate) fn render::escape_controls(s: &str) -> std::borrow::Cow<'_, str>` — escapes C0/DEL/C1 only, leaves legitimate non-ASCII intact; JSON paths keep original bytes (serde escapes on the wire).

- [ ] **Step 1: Write failing tests.** In `src/inspect.rs` mod tests (beside `text_escapes_interface_name_quotes_and_ascii_controls:452`):

```rust
#[test]
fn text_escapes_module_path_controls_while_json_preserves_them() {
    const HOSTILE: &str = "/opt/p\u{1b}[2Jevil\r.so";
    let mut outcome = sample();
    let ScanOutcome::Scanned { modules, .. } = &mut outcome else { unreachable!() };
    modules[0].path = HOSTILE.into();
    let text = render_text(4242, &outcome, &PinnedObjects::empty());
    assert!(!text.contains('\u{1b}') && !text.contains('\r'), "raw controls reached text: {text:?}");
    assert!(text.contains(r"\u{1b}[2Jevil\r"), "{text:?}");
    let json = render_json(4242, &outcome, &PinnedObjects::empty());
    assert_eq!(json["modules"][0]["path"], HOSTILE, "JSON keeps original bytes");
    assert!(serde_json::to_string(&json).unwrap().contains(r"\u001b"), "serde escapes on the wire");
}
```

And in `src/render.rs` mod tests (beside `the_live_heading_names_capture_facts…:3341`): a hostile `path = "/opt/p\u{1b}[2Jevil\r.so"`, assert `heading()` contains no raw `\u{1b}`/`\r` but contains `\u{1b}`/`\r` escaped, and the `live(...)` frame contains no `\u{1b}[2J` beyond the caller's own clear-screen prefix. Before implementing either renderer, add the two target-controlled `engine.rs` error-detail sink tests at the `:2263-2267` scan/pin eprintln and `:2782` diagnostic eprintln: inject hostile detail into each and assert emitted stderr has escaped controls and no raw ESC/CR. Run all four RED tests and observe their failures before the implementation step.

- [ ] **Step 2: Run, verify FAIL** (raw controls present).
- [ ] **Step 3: Implement** in `src/render.rs`:

```rust
/// Target-controlled bytes reach a terminal here. Only control characters — C0,
/// DEL, C1 (incl. CSI U+009B) — are rewritten; a legitimate non-ASCII pathname
/// still renders as itself. JSON is unaffected (serde escapes controls itself).
pub(crate) fn escape_controls(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(char::is_control) { return std::borrow::Cow::Borrowed(s); }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c.is_control() { out.extend(c.escape_default()); } else { out.push(c); }
    }
    std::borrow::Cow::Owned(out)
}
```

Apply inside `heading()` (:136-142: `escape_controls(&only.path).into_owned()`, and `format!("{} (+{} more)", escape_controls(&first.path), rest.len())`), and at `inspect.rs:74`, `:68` (both `subject` and `reason`), `:143`, `engine.rs:2263-2267`, **and `engine.rs:2782`** — its `{detail}` is an anyhow chain from the scan/pin path that transitively carries maps-derived, target-controlled text (cf. `engine.rs:4875`); escape `detail` at that eprintln. Leave `run.rs:1055` (operator scope) alone. Already clean, verified — no sites to add: `module.exports` (hook-registry names only, `scan.rs:883-898`), `table.null_entries` (`&'static str`), `attribution::note` (test-only). The stdlib `escape_default` at `inspect.rs:111` stays for interface names; `escape_controls` is earned only because paths must NOT get the quote/`\u{…}`-everything treatment (`tests/discovery_scan.rs:866` asserts the literal `inspected.so`).

- [ ] **Step 4: Run tests + workspace, verify PASS.** Commit `security: escape terminal control bytes in module-path headings (csf_b8067e3)`.

**Regression watch:** `inspect.rs::text_escapes_interface_name_quotes…:452`, `render.rs::the_live_heading…:3341` (asserts `heading()=="/opt/p11.so"` at :3349, `"/opt/p11.so (+1 more)"` at :3375 — all unchanged via the `Cow::Borrowed` fast path), `tests/discovery_scan.rs:866-867` (literal `inspected.so`/`2.40` in text output), and `tests/artifact_contracts.rs:4041-4045` which asserts `run.matches(".heading()").count() == 2` — escape inside `heading()`, never by adding/removing `.heading()` calls in `run.rs`. (`scripts/verify-inspect-doctor.sh` checks paths only on the JSON document, which this task leaves byte-identical — not at risk.)

---

### Task 4: Output ancestry hardening (csf_c94c662, MEDIUM)

**Files:**
- Modify: `src/output.rs` (`open_output_directory` :277-304, delete local `OpenHow` :270-275, extend `create_private_stream` :203)
- Test: `src/output.rs` mod tests (:391-527)

**Interfaces:**
- Produces: `fn open_directory_nofollow_walk(path: &Path) -> std::io::Result<std::fs::File>` (component-wise `O_NOFOLLOW|O_DIRECTORY` walk); a trusted-ancestor boundary check reused by both sinks.
- Note: HEAD already has `openat2 RESOLVE_NO_SYMLINKS` (commits 7487377/fef8ab3), and per `openat2(2)` `RESOLVE_NO_SYMLINKS` is a **superset** of `RESOLVE_NO_MAGICLINKS` — so magiclinks are already blocked; do not claim otherwise. This task closes the residual gaps: no seccomp fallback (`-o` hard-fails today when `openat2` is blocked — `output.rs:296-302` maps every `fd == -1` to a plain error), no ancestry trust rule, `create_private_stream` unnormalized.

- [ ] **Step 1: Write failing tests** in `src/output.rs` mod tests, `tempfile::tempdir()` + `std::os::unix::fs::PermissionsExt` (the dead "brief B" pointer is gone — the assertions here are the spec): `output_refuses_a_symlinked_intermediate_ancestor` (symlink is an ancestor, not the parent; both `AtomicFile::create` and `create_private_stream` refuse; protected bytes untouched); `output_refuses_a_group_or_world_writable_ancestor` (chmod an ancestor 0775 or 0707 non-sticky → refused with the ancestor named + "untrusted"; chmod 0700 → accepted; chmod 1707 → accepted only for the mandatory sticky carve-out; test fixtures and gates use private output directories); `root_owner_is_accepted_but_unrelated_owner_is_rejected` (root-owned and, when euid is root, validated `SUDO_UID`-owned private fixture are accepted; no ownership case waives the mode rule); `the_nofollow_walk_fallback_matches_openat2_and_refuses_the_same_symlinks` (direct `open_directory_nofollow_walk` on a real dir returns the same dev+ino as `open_output_directory`; on a symlinked component and on `/proc/self/fd/1` it errors). Inject the `openat2` syscall result so both `EPERM` and `ENOSYS` fallback cases run automatically without privileged e2e. Test and gate setup names the private fixture/output directories explicitly; no trusted-group directory is invented.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** in `src/output.rs`: delete the local `OpenHow` in favor of `libc::open_how` (construct via zeroed value plus field assignment because it is `#[non_exhaustive]`); keep `RESOLVE_NO_SYMLINKS`; extract the component-wise `O_NOFOLLOW|O_DIRECTORY` walk and fall back on `ENOSYS`/`EPERM` only, never `ELOOP`. Enforce every component from `/` to the output parent as owned by euid or root, accepting a validated existing `SUDO_UID` owner only for the root-running fixture path, and always reject non-sticky `(mode & 0o022) != 0`; there is no trusted-group exception and ownership never waives the mode rule. Normalize `create_private_stream` before opening. Keep the fallback syscall injectable so unprivileged tests cover both seccomp errors without a privileged run.
- [ ] **Step 4: Run focused output tests and workspace checks, verify PASS.** Prepare private test/gate directories; the privileged e2e lane is explicitly UNRUN without separate owner approval and does not block the W1 unprivileged exit. Add the existing `CHANGELOG.md` note and commit the scoped fix.

**Regression watch:** 9 `src/output.rs` mod tests (:397,:408,:422,:432,:453,:474,:488,:506 + `src/run.rs:3580`'s use of `AtomicFile::create`) — all write under `tempfile::tempdir()`, NOT `CARGO_TARGET_TMPDIR`; private fixture directories are required. `tests/run_lifecycle.rs:179` and every gate output root must be prepared without group/world write. The privileged e2e lane is UNRUN without separate approval and does not block W1's unprivileged exit. (`tests/live_discovery.rs` sets `out: None` — not a target.)

---

### Task 5: Cgroup descriptor retention (csf_6f180d5, MEDIUM)

**Files:**
- Modify: `src/attach.rs` (`Scope::Cgroup` :277-286), `src/scope.rs` (new `cgroup()` constructor, `publish` :94-134 simplification), `src/discovery/engine.rs` (`scope_pids` :2141-2209), `src/run.rs:1037`, ~8 test construction sites
- Test: `src/discovery/engine.rs` mod tests (:17653 area)

**Interfaces:**
- Produces: `Scope::Cgroup { id: u64, path: PathBuf, dir: std::sync::Arc<std::fs::File> }`; `pub fn scope::cgroup(path: &Path) -> Result<Scope>` (opens once, ino from the fd).
- The retained fd is the one object both the userspace walk and the kernel publish route through — one guard fixes every caller.
- Keep publication testable without BPF through one private seam used by the real publish path: `publish_cgroup_fd_with(dir: &File, set: impl FnOnce(File) -> Result<()>)`, where `publish` passes `dir.try_clone()?` to the closure and the production closure performs the existing groups publish. This is a test seam, not a new public abstraction or dependency.

- [ ] **Step 1: Write the failing test** in `src/discovery/engine.rs` mod tests (calls private `scope_pids` like :17659):

```rust
#[test]
fn cgroup_walk_follows_the_retained_directory_not_a_replaced_path() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("target.scope");
    let impostor = root.path().join("impostor.scope");
    std::fs::create_dir_all(real.join("leaf.scope")).unwrap();
    std::fs::create_dir(&impostor).unwrap();
    std::fs::write(real.join("cgroup.procs"), "11\n").unwrap();
    std::fs::write(real.join("leaf.scope/cgroup.procs"), "22\n").unwrap();
    std::fs::write(impostor.join("cgroup.procs"), "99\n").unwrap();
    let scope = crate::scope::cgroup(&real).unwrap();     // opens + pins
    // Move the live dir ASIDE — never remove_dir_all it: deleting the directory the
    // fd holds makes every read through the fd ENOENT, so a correct fix would return
    // pids == [] and the test could green a broken one (!contains(99) also holds then).
    let stash = root.path().join("moved.scope");
    std::fs::rename(&real, &stash).unwrap();               // the retained fd follows the dir
    std::fs::rename(&impostor, &real).unwrap();            // pathname now the impostor
    let (pids, lost) = scope_pids(&scope);
    assert_eq!(pids, vec![11, 22], "the retained fd's descendants, not 99");
    assert!(!pids.contains(&99));
    assert_eq!(lost, vec![]);
    assert!(!format!("{lost:?}").contains("/proc/self/fd"), "subject must be the operator path");
}
```

Plus `cgroup_walk_reports_losses_under_the_operator_path_not_a_proc_fd_path` (mode-000 leaf, like :17694; assert `lost[0].subject.starts_with(root.path())`). Add `publish_uses_the_retained_cgroup_fd` using the private `publish_cgroup_fd_with` seam: rename the live directory aside, replace its pathname with the impostor, pass a clone of the retained fd to a closure that compares `MetadataExt::ino()` to the original retained inode, and assert the selected inode is the live/stashed cgroup without starting BPF. The production `publish` must call the same seam, proving the retained fd is used for publication as well as traversal.

- [ ] **Step 2: Run, verify FAIL** (walk currently follows the pathname → sees 99).
- [ ] **Step 3: Implement.** `Scope::Cgroup` gains `dir: Arc<File>` (keeps `#[derive(Debug, Clone)]` — the only derives on `Scope`; nothing derives `PartialEq`). Compile churn the field forces: `scope.rs:94` matches `Scope::Cgroup { id, path }` exhaustively — bind or elide the new field there; every other pattern already uses `..` (`scope.rs:73`, `attach.rs:367/1081/1115`, `engine.rs:2144/2217/7873`). New `scope::cgroup(path)` opens the dir, reads `ino()` from the fd, returns the variant (used at `run.rs:1038`) — and KEEPS the `"reading cgroup path {}"` error context (`scope.rs:191`'s `missing_cgroup_path_errors_loudly` asserts that string). In `scope_pids`, the I/O root is `/proc/self/fd/{}` of the retained fd (repo idiom: `crates/manifest/src/identity.rs:154-168`, `src/discovery/identity.rs:367`) and the stack carries **relative suffixes**; the label root is the operator path — `Skipped.subject` MUST use the label (privacy: no `/proc/self/fd/N` in the capture doc; note `readlink` on the fd reports the moved path, another reason the stored operator path is the only valid subject). `scope::publish` simplifies: drop `File::open` + inode re-check (:96-111) since the fd is the checked object, keep `groups.set(0, dir.try_clone()?, 0)` (:114), delete `drop(cgroup_file)` (:134). Non-goals (one-line comment each): `scope::label` (:34) and `doctor::cgroup_check` (:447) stay path-based (trusted fixed root, label/diagnostic only).
- [ ] **Step 4: Fix the ~8 construction sites** (compile churn): `engine.rs:11020,:11301,:11332,:11653,:17659,:17671,:17696`, `attach.rs:2487` — switch literal `/sys/fs/cgroup*` paths to `tempfile::tempdir()` (matching :11016); `id:0` becomes the real inode (nothing compares `Scope.id` outside `publish`).
- [ ] **Step 5: Run tests + workspace, verify PASS.** Commit `security: walk cgroup descendants through a retained descriptor (csf_6f180d5)`.

**Regression watch:** `engine.rs:17653` (subject `ends_with("container.scope")`), `engine.rs:11852` — a SOURCE-TEXT test slicing between `"fn scope_pids("` and `"fn scope_label("`, requiring literal `"membership absence is not authoritative"` and forbidding **both** `entries.flatten()` **and** `file_type().is_ok_and` (:11864) — the fd-based rewrite must not reach for either; preserve the literals verbatim. `scope.rs:175` (`cgroup_id_is_the_directory_inode` — the id must remain the directory inode), `:189-191` (`missing_cgroup_path_errors_loudly` — keep the `"reading cgroup path"` context in the new constructor).

---

### Task 6: Discovery scan computation budget + pause deadline (csf_ce5962b, MEDIUM)

**Files:**
- Modify: `crates/manifest/src/maps.rs` (new `MapIndex`, extract `resolved_for`), `src/discovery/scan.rs` (`CaptureWorkBudget` :49-149, the maps read :778, `detect_tables` :424, `decode_candidate` :308, `scan_interfaces` :478, `scan_process_view` :763, reason consts), `src/discovery/engine.rs` (`apply_discovery_batch(_with)` :8296/:8307 — thread `deadline`), `src/discovery/pause.rs:2076`
- Test: `src/discovery/scan.rs` mod tests (:1134 area), one `tests/discovery_scan.rs` PARTIAL-wiring assertion

**Interfaces:**
- Produces: `manifest::maps::MapIndex<'a>` (with `new`, `resolve` — sorted-interval `partition_point` lookup; unsorted input is rejected fail-closed); `CaptureWorkBudget::charge(units: u64) -> bool`, `set_deadline(Option<u64>)`, `WORK_CEILING_REASON`, `SCAN_DEADLINE_REASON`, `MAPS_CEILING_REASON`, and `MAPS_ENTRY_CEILING_REASON`.
- Consumes: `attach::monotonic_ns()` (verified: `attach.rs:711`, `pub(crate)` — deadline tests must live in `src/` mod tests; `SessionPauseIo::now_ns` at `pause.rs:1997-1999` is literally the same fn, so the clocks match); the existing `Skipped{subject,reason}` → `capture_skipped_out` → `modules_skipped` → PARTIAL path (no renderer/evidence change).

- [ ] **Step 1: Write failing tests** in `src/discovery/scan.rs` mod tests (model on `dense_candidates_and_interfaces_stop_at_capture_caps:1134`; use an injectable maps-reader seam): `adversarial_near_misses_and_a_512_table_tail_stop_at_the_computation_ceiling` (4096 candidates each a full-104-field near miss rejected at the last field; assert `tables.is_empty()` and `skipped == vec![WORK_CEILING_REASON]`); `maps_reader_crosses_64_mib_without_a_per_object_ceiling` (one maps snapshot crossing 64 MiB still reads until the total budget or `MAX_MAPS_BYTES`, proving no `per_object_bytes` allowance); `maps_exact_cap_is_not_truncated` (reader returns exactly `MAX_MAPS_BYTES`, assert no maps-ceiling reason); `maps_cap_plus_one_is_truncated_at_the_last_newline` (reader returns `MAX_MAPS_BYTES + 1`, assert only complete lines before the cut, `MAPS_CEILING_REASON`, and no hard error); `maps_entry_ceiling_truncates_at_complete_line` (more than `MAX_MAP_ENTRIES`, assert truncation at the `MAX_MAP_ENTRIES`th complete newline, `MAPS_ENTRY_CEILING_REASON`, and PARTIAL without changing the generic parser); `maps_total_byte_exhaustion_is_partial` (exhaust `total_bytes` during the injected maps read, assert `IO_CEILING_REASON` and the existing PARTIAL path); `deadline_interrupts_between_64k_chunks` (deadline becomes expired after a chunk, assert `SCAN_DEADLINE_REASON`); `deadline_is_cleared_after_error_and_success` (subsequent scan has no stale deadline); and `unsorted_maps_fail_closed` (construct reversed intervals, assert the scan refuses instead of using a linear fallback).
- [ ] **Step 2: Run, verify FAIL** (scan currently completes / near misses cost zero budget / the maps read is uncapped).
- [ ] **Step 3: Implement (a) `MapIndex`** in `maps.rs`: extract `:204-222` into `resolved_for`; build a sorted-interval `partition_point` index once after `parse_maps`, and reject unsorted intervals immediately (delete the unsorted linear fallback). **(b)** HashMap `by_address` in `scan_interfaces` replacing the linear `position`. **(c)** add an independent work counter with `const DEFAULT_WORK_CEILING: u64 = 16 * 1024 * 1024`; it is test-overridable and never derived from `total_bytes` (there is no `per_object_bytes` allowance). Charge at each window and inside `decode_candidate`'s field loop before `resolve`; on exhaustion return `WORK_CEILING_REASON`. A `charge(1)` against the O(log n) index is the unit definition. **(d)** add `deadline_ns: Option<u64>` + `set_deadline`; check immediately on entry to each scan, then every 4096 windows via `attach::monotonic_ns()`. For the maps reader, read in bounded 64 KiB chunks through `Read::take(MAX_MAPS_BYTES + 1)`, check the deadline between chunks, and charge every returned byte against the total I/O budget. On total exhaustion return `IO_CEILING_REASON`; do not reset or split that charge per object. Reading `MAX_MAPS_BYTES + 1` distinguishes exact EOF from cap-plus-one. If the extra byte exists, truncate before generic parse at the `MAX_MAP_ENTRIES`th complete newline (or the last complete newline for the byte cap), emit `MAPS_ENTRY_CEILING_REASON` or `MAPS_CEILING_REASON`, and continue with PARTIAL evidence. **(e)** thread `deadline` through `apply_discovery_batch(_with)` and set it on entry. Clear it on every exit, including all early returns (a guard/finally closure is acceptable); `pause.rs:2076` passes the held deadline already. **(f)** push all reason constants through the existing `Vec<String>` returns. There is no weaker deadline fallback.
- [ ] **Step 4: Run tests, verify PASS.** Add a `tests/discovery_scan.rs` assertion that `render::capture_skipped_out(&Skipped{subject:"/lib/x.so".into(), reason: WORK_CEILING_REASON.into()}).reason == "discovery unavailable"` (pins PARTIAL wiring).
- [ ] **Step 5: Measure the honest path** — `p11scope inspect --pid <softhsm-loaded pid>` before/after, compare `scan.scan_ms` from the JSON; `MapIndex` should make it faster (log n vs n). If `DEFAULT_WORK_CEILING` ever trips on a real provider, raise the const (the calibration knob — noted in a `ponytail:` comment). Commit `security: bound discovery scan computation, the maps read, and honor the pause deadline (csf_ce5962b)`.

**Regression watch / signature churn:** `scan.rs` tests :1082,:1106,:1134,:1280 call `detect_tables(&snapshot, base, &maps, &mut budget)` and :1190 calls `scan_interfaces(…, &maps, …)` — the `&MapIndex` parameter is a **compile-breaking edit at all five sites**; :1190 additionally guards independent work-vs-I/O ceilings. `maps.rs` tests :266,:293,:302 (plus :238,:326 unaffected); `tests/discovery_scan.rs` budget tests :554,:600,:644,:685; `CaptureWorkBudget` uses in `tests/manifest_pinning.rs` and `engine.rs:12603,:14057,:15076,:16627,:16939,:17394` plus six defaults. `tests/artifact_contracts.rs:409` pins the literal `".apply_discovery_batch_with("` in pause.rs — an appended parameter preserves it. There is no weaker relative-deadline fallback: the immediate check, periodic checks, and unconditional clear are the contract.

---

### Task 7: Release driver input-trust hardening (csf_014eb65, MEDIUM)

**Files:**
- Modify: `scripts/build-release.sh` (`task4_receipt_run` :285-296, `task4_finalize` :231, official build :335-336, self-test `lane` heredoc :105-122)
- Test: `tests/artifact_contracts.rs` (`LANE14_CASES` :2429, static asserts :709/:734, a real-process refusal test)

**Interfaces:**
- "Integrate the preflight" does NOT mean invoking BS2b (`scripts/task4-build-subject.py:3461-3462` exits 77 by construction, review-gated; `tests/task4_build_subjects.rs:417` pins candidate-only). It means enforcing the ratified input-trust rules (`docs/superpowers/reports/2026-08-28-task4-receipt-architecture-decision.md:83-91`, `docs/superpowers/reports/2026-08-28-task4-build-subject-decision.md:107-112` — note: `reports/`, not `plans/`) in the shell driver. Every recorded tool must be invoked by the resolved absolute non-symlink path recorded in the receipt, not merely hashed via `command -v`.
- Context on A1: `:285` already refuses a dirty TRACKED tree (`git diff --quiet && git diff --cached --quiet`, twin inside `task4_finalize` at :231; the fn itself starts :220) and `task4_snapshot:202` hashes `git ls-files` only — **untracked files are invisible to every existing gate**, which is exactly how an untracked `.cargo/config.toml` steers Cargo unnoticed. The porcelain replacement is what closes that.

The preflight is self-contained and exact: **A1** requires full `git status --porcelain=v1 --untracked-files=all` cleanliness (tracked, staged, and untracked); **A2** searches the exact repository-ancestor sequence from the worktree to `/` for each `.cargo/config.toml` and `.cargo/config`, then the effective `CARGO_HOME/config.toml` and `CARGO_HOME/config`, refusing any untracked or unexpected config input; **A3** records and rejects changes to exactly these ten inherited variables: `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_TARGET_DIR`, `CARGO_BUILD_TARGET`, `CARGO_HOME`, `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`, `RUSTC_WRAPPER`, `CC`, and `CFLAGS`; **A4** records the exact nine tools `cargo`, `docker`, `file`, `jq`, `python3`, `rustup`, `setpriv`, `sudo`, and `sha256sum`, plus the `rustup`-reported `cargo`/`rustc` toolchain binaries, and every invocation uses its resolved absolute non-symlink path; **A5** permits host build execution only with `--offline` (container/privileged commands retain their separate owner gates). Initial and final repository/tool/environment hashes must match; PATH replacement or mismatch is refusal, never a warning.

- [ ] **Step 1: Write failing tests.** (a) Real-process refusal in `tests/artifact_contracts.rs` (pattern of :811, PATH tripwires from :2512-2543): tempdir `CARGO_HOME` with a planted `config.toml`, run `build-release.sh <absent_root>` → `exit 77`, stderr contains `"untracked cargo config"`, tripwire log absent (never reached cargo/sudo/rm). (b) Self-test model rows: add `untracked-build-input-rejected-status-77-no-touch-before-body` to `LANE14_CASES` (:2429) AND the `lane` heredoc (:105-122); modeled on `root-preflight-blocks-body-cargo-runtime` (:62). (c) Add refusal rows for replacing one recorded tool between preflight and finalization, and for a PATH change that resolves a different binary; both must fail closed. (d) Static assert: extend `official_build_is_safe_only:709` for `--offline`.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** in `task4_receipt_run`, all before `command -v`(:295)/`sudo -n`(:296)/`release_body`(:305), refusal `exit 77` (POSIX sh; `sh -n` gate at :2267): implement self-contained A1–A5 exactly as listed above, resolve each recorded tool to an absolute non-symlink path and invoke those exact paths (including the rustup-selected cargo/rustc binaries), and record `task4_fact` path/hash rows. At finalization, rehash every recorded tool path and refuse publication on any mismatch or replacement; a PATH change that resolves a different binary is a refusal, not a warning. Add `--offline` to the host build only (:335-336). New receipt fields remain additive TSV rows.
- [ ] **Step 4: Run focused artifact-contract tests and workspace checks, including tool replacement/PATH-mismatch refusal tests, verify PASS** (update the byte-exact cargo block literal in :709 in the SAME commit as `--offline`). Commit the scoped fix.

**Regression watch:** `artifact_contracts.rs:709` (byte-exact cargo block — update literal), `:734` (literal path relationships, `trap … EXIT` count ==1, `release_body_cleanup` ==2, poisoned-env exit 2 — keep `WORK=`/invocation strings byte-identical), `:2339`/`:2650` (uncontracted self-test rows fail; `build-release.sh:161` enforces row-count equality), `:2267` (POSIX `sh -n` — no bashisms), `tests/task4_build_subjects.rs:417,:196` (don't touch the .py). `facts.log` has no parser today → new rows safe.

---

### Task 8: Lane 14 receipt literal capture binding (csf_19fb2f, LOW — LIVE BUG)

**Files:**
- Modify: `scripts/build-release.sh` (`task4_receipt_run` :313-316, `release_body` checker :490-491, self-test heredoc :105-122)
- Test: `tests/artifact_contracts.rs` (`:734` static asserts, `LANE14_CASES` :2429)

**Interfaces:**
- **Hard dependency:** Task 8 runs only after Task 7 has established exact
  tool/input layout and final rehashing. Its checker assertion parses and
  validates the framed `argv`/stdout-stderr/status structure; non-empty output
  alone is insufficient.
- Consumes the layout from Task 7. **Live bug (verified against the script flow):** `:313 find "$TASK4_ROOT/work" … -name '*observed*.json' | sort | head -n 1` always selects `observed-scan.json` — ASCII sort: `-` < `.`, then `c` < `t` — an attach-e2e file (`verify-attach-e2e.sh:191,198` leave `observed-scan.json`/`observed.json` in the same `$WORK`; its `$WORK` IS `$TASK4_ROOT/work` via `P11SCOPE_TASK4_WORK="$ATTACH_WORK"` and `ATTACH_WORK=$WORK` at :302, and attach-e2e always completes inside `release_body` before the receipt step runs). It NEVER selects the release's own `observed-static-smoke.json`, which is written via the profile's `-o` flag at `:478` (landing root-owned, reclaimed at `:488`; `:446` is only the `rm -f` prep line). Every existing Lane 14 receipt `capture.json` is mis-bound; `:316` copies whole body stdout as `checker.log`. Both mechanisms are literally forbidden by the ratified decision (`…receipt-architecture-decision.md:90`: "No glob, `find | head`, basename, stdout-as-capture, or path-order authority is permitted").

- [ ] **Step 1: Write failing tests.** Static asserts in `artifact_contracts.rs:734`: `release.contains("cp \"$WORK/observed-static-smoke.json\" \"$TASK4_ROOT/artifacts/capture.json\"")`, `!release.contains("head -n 1")`, `!release.contains("cp \"$TASK4_ROOT/stdout.log\" \"$TASK4_ROOT/artifacts/checker.log\"")`. Self-test model rows `literal-static-smoke-capture-path-exact-accepted`, `decoy-observed-json-under-work-rejected`, `aggregate-stdout-as-checker-evidence-rejected` in both the heredoc and `LANE14_CASES` (the decoy row plants a 4th `*observed*.json` in the model `work/` and asserts rejection).
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement.** **B1** replace :313-315 with `cp "$WORK/observed-static-smoke.json" "$TASK4_ROOT/artifacts/capture.json"`. **B2** keep `find` only as a guard asserting the exact 3-name set (`observed-scan.json\nobserved-static-smoke.json\nobserved.json`) else `exit 1`. **B3** in `release_body` replace :490-491 with a framed capture into `$WORK/checker.log` (`argv` line + checker stdout/stderr + `status` line — the frame keeps it non-empty since the checker is silent on success, and `finalize:237` requires `-s`), then `:316` becomes `cp "$WORK/checker.log" "$TASK4_ROOT/artifacts/checker.log"` plus facts `checker_argv`/`checker_status`/`checker_log_sha256`.
- [ ] **Step 4: Run focused artifact-contract tests and workspace checks, verify PASS. The checker test must parse and validate the framed `argv`/stdout-stderr/status structure and reject an unframed aggregate stdout log, not merely assert non-empty files.** Commit the scoped fix.

**Regression watch:** as Task 7 (`:734`, `:2339`/`:2650`, `:2267`, `:161`). The framed checker record is parsed for `argv`, captured streams, and `status`; an aggregate/non-framed log is rejected. The closeout report (Task 12) MUST record that prior receipts' `capture.json` were mis-bound.

---

### Task 10: Full-gate verification

- [ ] **Step 1:** All four canonical gates on the branch tip, clean.
- [ ] **Step 2:** Run the unprivileged portions of `scripts/verify-canaries.sh` / privacy suite as far as unprivileged allows; record any privileged lane as UNRUN explicitly (never claim a root lane ran).
- [ ] **Step 3:** Commit any fallout fixes.

---

### Task 11: Independent review → fix cycles (repeat until clean)

- [ ] **Step 1:** Dispatch two independent Opus review agents over both repositories: (a) adversarial security/correctness review of the public `git diff main...hardening/findings-wave1` plus the private `p11scope-ws` custody diff, including each finding's root closure and all sibling callers; (b) test-quality + regression review of both diffs (tests fail without the fix, assertions are meaningful, no weakened existing test, no private data crossed the public boundary).
- [ ] **Step 2:** Triage (Fable adjudicates — accept/reject each with reasoning). Fix every accepted finding TDD-style; rerun gates.
- [ ] **Step 3:** Repeat Step 1 with fresh agents until a full cycle reports zero accepted findings.
- **Exit condition:** Task 11 is review-to-zero only. It performs no integration, packaging, or finishing workflow; those occur exactly once in Task 12 after the closeout is committed and reviewed.

---

### Task 12: Wave-1 closeout

- [ ] **Step 1:** Write `docs/superpowers/reports/2026-09-01-wave1-findings-closure.md`: per-finding closure evidence (test name + commit), the two upgraded findings called out honestly (Lane 14 receipt was a live mis-binding affecting all prior receipts; `-o` was broken under old Docker seccomp), review-cycle count, private-custody hashes, and every UNRUN privileged confirmation listed plainly.
- [ ] **Step 2:** Commit the closeout report on the W1 branch. Run the exact branch-tip gates and perform the final public-plus-`p11scope-ws` review before any integration choice; accepted findings require fixes and a fresh gate/review cycle.
- [ ] **Step 3:** After the closeout is written, committed, gated, and reviewed on the branch, invoke `superpowers:finishing-a-development-branch` exactly once for the owner's integration choice. After a merge, rerun all gates on the merged tip; package the portable bundle/evidence archive only after those merged-tip gates pass. Never package from an unmerged branch tip.
- [ ] **Step 4:** Memory update is conditional: only an explicit contemporaneous owner request may create a platform-permitted ad-hoc note under `/home/user/.codex/memories/extensions/ad_hoc/notes/`; otherwise record `SKIPPED` in the closeout. When requested, name W2 storage consolidation next and **W3 priority one** as the `C_GetInterface` compatibility closure; W3 then handles tracepoint offsets, opened-file identity, capability breadth, and `uprobe_multi` according to the ROADMAP/charter. Allowlist/schema wording remains owner-gated.

## Self-Review

- **Spec coverage:** all 8 findings (Tasks 1-8) + research #3 (Task 6f) + custody rescue (Task 0) + gates/review/closeout (10-12). Task 6 now specifies `DEFAULT_WORK_CEILING=16*1024*1024`, `MAX_MAP_ENTRIES=1_048_576`, cap-plus-one maps reads, exact EOF/truncation tests, injected readers, fail-closed ordering, immediate/periodic deadlines, and unconditional deadline clearing. W3 priority one is the `C_GetInterface` compatibility closure, with tracepoint offsets and opened-file identity following it.
- **Placeholder scan:** every code step carries real code or an exact edit locus; the `/* same literal as … */` markers point at existing test fixtures the executor copies, not invented content; no scratchpad/brief pointers remain.
- **Type consistency:** `Scope::Cgroup{id,path,dir}`, `scope::cgroup()`, `MapIndex`, `CaptureWorkBudget::charge/set_deadline`, `CaptureEnd::LimitReached`, `trace::truncated_line -> String`/`evidence_line(…, truncated)`, `render::escape_controls` — names used consistently across tasks.
- **2026-09-01 verification pass (three independent read-only verifiers over historical HEAD 556f7cf):** all cited line anchors were confirmed or corrected in place; the current execution base is verified `main` `5d251b76b33b14839a7147e14b5ccd1348855587`, origin gap 239. The three blocking defects found (Task 6 maps-read gap, Task 5 test destroying the fd's directory, Task 4 ancestry rule vs 775 checkouts + sudo inversion) and both compile-breaks (Task 2 `out_sink` borrow, Task 4 `open_how` non_exhaustive) remain recorded as historical review context.
