# Release Hardening Wave 1 — Security Findings Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all eight open findings from static security scan `3e10be9` (six MEDIUM, two LOW) with focused local tests, repair the Stage 3A3 evidence-custody gap, and drive independent review→fix cycles until zero findings remain — so the basic product is issue-free and fully covered by the local test framework.

**Architecture:** One TDD task per finding, at its cited code site, using the scanner's own `remediation` text (durable at `/home/user/.local/state/p11scope/security-scan-3e10be9/findings.json`) plus a fresh code-level implementation brief as the design authority. Each brief was produced by an independent read-only analysis of HEAD `b86d4d5`; two findings turned out to be more than the scan said (Lane 14 receipt mis-binding is a live bug; `-o` is currently broken under old Docker seccomp). Work lands on branch `hardening/findings-wave1`; the wave closes with full canonical gates and iterated Opus review cycles, then merges to `main`.

**Tech Stack:** Rust 1.88 (edition 2024), aya eBPF, `libc` 0.2.189 (only syscall dep — no new deps), bash release driver, existing `tests/` + in-module `mod tests` framework.

**Spec:** `/home/user/.local/state/p11scope/security-scan-3e10be9/findings.json` (hash-pinned in `docs/superpowers/reports/2026-08-31-productization-evidence-index.md` §"Static security closeout") and the "Next order" list in `docs/superpowers/reports/2026-08-31-consolidation-status.md`.

## Global Constraints

- Rust 1.88, edition 2024, Linux x86-64-first (CLAUDE.md). `std::env::remove_var` and other formerly-safe fns are `unsafe` in edition 2024 — wrap in `unsafe {}` where noted.
- **All four canonical gates green after every task**: `cargo +1.88 fmt --all -- --check`, `cargo +1.88 check --locked --workspace --all-targets`, `cargo +1.88 test --locked --workspace --all-targets`, `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings`.
- Preserve `docs/privacy/allowlist-v1.md`; never broaden capture implicitly. Target-controlled bytes must not leak into the capture document (subjects stay operator-path/label form, never `/proc/self/fd/N`).
- No new dependencies. `libc` 0.2.189 already exports `open_how`, `RESOLVE_NO_MAGICLINKS`, `SYS_close_range` (both gnu+musl targets); use the raw `libc::syscall` for `close_range` (the wrapper fn is gnu-only and the release also builds a musl helper).
- Do not track generated output. Wave-1 tasks must be verifiable unprivileged; a privileged-only assertion follows the repo convention — assert the outcome the observed configuration requires (`tests/proc_access.rs:1-5`), reserve `eprintln!("SKIP: …")` for a genuinely absent resource only.
- Kernel floor 5.15. `openat2`(5.6)/`close_range`(5.9) exist on every supported kernel, but keep the `ENOSYS`/`EPERM` fallback where specified — seccomp (Docker) is the real reason, not the kernel.
- Branch `hardening/findings-wave1` off `main` b86d4d5. Frequent commits (one per task). Merge only after Task 11 review cycles reach zero accepted findings.

---

### Task 1: Helper file-descriptor and environment confinement (csf_f5953ae, MEDIUM)

**Files:**
- Modify: `crates/discover/src/main.rs` (top of `drop_privileges_and_open_self_memory`, before the `/proc/self/mem` open at :142)
- Create: `crates/discover/tests/fixture/fd_env_canary.c`
- Test: `crates/discover/tests/cli.rs` (add one test; reuses `BIN` at :4)

**Interfaces:**
- Produces: `close_inherited_descriptors() -> Result<(), String>` and a `LOADER_SENSITIVE_ENV: &[&str]` const, both private to `crates/discover/src/main.rs`.
- The fix MUST live in `main.rs` only — never in `discover.rs`, whose `discover()` is called in-process by four test binaries (`fixture_provider.rs`, `version_matrix.rs`, `lazy_dependency.rs`, `softhsm.rs`); a `close_range` there would shred the libtest harness fds.

- [ ] **Step 1: Write the failing test.** New fixture `crates/discover/tests/fixture/fd_env_canary.c` (constructor reports on stderr, so it needs no env of its own):

```c
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define PLANTED_FD 17
typedef unsigned long CK_RV;
__attribute__((constructor)) static void ctor(void) {
    ssize_t n = write(PLANTED_FD, "LEAK", 4);
    fprintf(stderr, "CANARY_FD=%s\n", (n < 0 && errno == EBADF) ? "closed" : "OPEN");
    fprintf(stderr, "CANARY_ENV=%s\n", getenv("LD_PRELOAD") ? "present" : "absent");
    fflush(stderr);
}
CK_RV C_GetFunctionList(void **pp) { *pp = 0; return 5UL; /* CKR_GENERAL_ERROR */ }
```

Add to `crates/discover/tests/cli.rs` (compile the fixture with the `gcc -shared -fPIC` idiom from `lazy_dependency.rs:16-34`; use `std::io::pipe` (stable 1.87) + `pre_exec` `dup2(raw,17)` to plant an inheritable fd — `dup2` clears `FD_CLOEXEC` on the copy; assert on stderr not exit status, since the fixture's `C_GetFunctionList` errors → helper exits 1):

```rust
#[test]
fn constructor_sees_no_planted_fd_or_loader_env() {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fd-canary");
    std::fs::create_dir_all(&dir).unwrap();
    let provider = dir.join("fd-env-canary.so");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture/fd_env_canary.c");
    assert!(Command::new("gcc").args(["-shared", "-fPIC", "-o"]).arg(&provider).arg(&src)
        .status().unwrap().success());
    let (mut reader, writer) = std::io::pipe().unwrap();
    let raw = writer.as_raw_fd();
    let mut cmd = Command::new(BIN);
    cmd.arg("--module").arg(&provider).env("LD_PRELOAD", "/nonexistent-canary.so")
        .stderr(std::process::Stdio::piped());
    unsafe { cmd.pre_exec(move || { if libc::dup2(raw, 17) < 0 { return Err(std::io::Error::last_os_error()); } Ok(()) }); }
    let out = cmd.output().unwrap();
    drop(writer);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("CANARY_FD=closed"), "planted fd survived: {stderr}");
    assert!(stderr.contains("CANARY_ENV=absent"), "LD_PRELOAD survived: {stderr}");
    let mut leaked = Vec::new();
    reader.read_to_end(&mut leaked).unwrap();
    assert!(leaked.is_empty(), "constructor wrote through planted fd: {leaked:?}");
}
```

- [ ] **Step 2: Run it, verify FAIL** (`CANARY_FD=OPEN` / `CANARY_ENV=present`): `cargo +1.88 test -p p11scope-discover --test cli constructor_sees_no_planted_fd -- --nocapture`
- [ ] **Step 3: Implement.** In `crates/discover/src/main.rs`, add the two items and call them at the very top of `drop_privileges_and_open_self_memory` (before `File::open("/proc/self/mem")` at :142 — self-mem fd then lands at 3, outside the closed range; no `dup2` renumber needed):

```rust
fn close_inherited_descriptors() -> Result<(), String> {
    // SYS_close_range present on both shipped targets; the libc::close_range wrapper
    // is gnu-only and build-release.sh also builds a musl helper — use the raw syscall.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0) } == 0 { return Ok(()); }
    // Fallback: pre-5.9 kernels / seccomp return ENOSYS or EPERM. Collect first, then
    // close — closing the DirFd mid-iteration invalidates it.
    let dir = std::fs::read_dir("/proc/self/fd").map_err(|e| format!("/proc/self/fd: {e}"))?;
    let mut fds: Vec<i32> = dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| *fd > 2).collect();
    fds.sort_unstable();
    for fd in fds { unsafe { libc::close(fd) }; }
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
```

At the call site (denylist, not allowlist — `SOFTHSM2_CONF` and other provider config must survive; `verify-attach-e2e.sh:149` threads it):

```rust
    close_inherited_descriptors()?;
    // ponytail: glibc caches LD_LIBRARY_PATH/PRELOAD/AUDIT at startup, so this
    // protects constructor getenv + any child the provider spawns, not the dlopen
    // search itself; full closure needs a self re-exec with sanitized environ.
    for name in LOADER_SENSITIVE_ENV { unsafe { std::env::remove_var(name) }; }
```

- [ ] **Step 4: Run test, verify PASS.** Then full workspace test to confirm the four in-process fixture binaries are untouched.
- [ ] **Step 5: Add a `CHANGELOG.md` line** noting the helper now closes inherited fds and strips loader env (behavior: providers whose subprocesses relied on inherited `LD_LIBRARY_PATH` no longer see it). Commit `security: confine discovery helper descriptors and loader environment (csf_f5953ae)`.

**Regression watch (must stay green):** all 8 `crates/discover/tests/cli.rs` tests, especially the `-o` cases (outfile opened at `main.rs:277`, after the close — fine) and `control_fd_flag_is_gone:83` (no protocol fd exists). Shell e2e sites pass no extra fds; `build-release.sh:447`'s fd 3 is for the observer, not the helper.

---

### Task 2: Trace output cumulative bound (csf_ad79ebb, MEDIUM)

**Files:**
- Modify: `src/cli.rs` (`Common` struct, `capture_option`, profile-refusal, USAGE :103), `src/run.rs` (`CaptureEnd` enum :922, `capture_trace` :2071, `drain_trace_events` :2292, a `DEFAULT_TRACE_MAX_EVENTS` const), `src/trace.rs` (`evidence_line` :177, new `truncated_line` :166)
- Test: `src/cli.rs` mod tests (:590 area), `src/trace.rs` mod tests (:436 area), one `scripts/bench-overhead.sh` assertion

**Interfaces:**
- Produces: `Common.max_events: Option<u64>`; `CaptureEnd::LimitReached`; `trace::truncated_line(limit: u64) -> Option<String>`; `trace::evidence_line(ev, policy, truncated: bool)` (added 3rd param).
- Consumes: existing `render::Evidence`, `CapturePolicy`, `trace::lost_line`.

- [ ] **Step 1: Write the failing CLI test** in `src/cli.rs` mod tests (shape of `trace_rejects_mode_and_accepts_the_rest:590`):

```rust
#[test]
fn trace_takes_a_max_events_bound_and_profile_refuses_it() {
    let a = parse_capture(Kind::Trace, args(&["--pid","1","--max-events","1"])).unwrap();
    assert_eq!(a.max_events, Some(1));
    assert!(matches!(parse_capture(Kind::Profile, args(&["--pid","1","--max-events","1"])),
        Err(CliError::Usage(m)) if m.contains("--max-events is a trace option")));
    assert!(matches!(parse_capture(Kind::Trace, args(&["--pid","1","--max-events","x"])),
        Err(CliError::Usage(m)) if m.contains("invalid number")));
}
```

- [ ] **Step 2: Run, verify FAIL** (field/parse missing).
- [ ] **Step 3: Implement the flag.** In `src/cli.rs`: add `max_events: Option<u64>` to `Common` (:173-182); in `capture_option` add `"--max-events" => { let v = require_value(args,"--max-events")?; common.max_events = Some(v.parse().map_err(|_| usage_err(format!("--max-events: invalid number {v:?}")))?); }`; in `parse_capture`/`parse_run` add `if kind == Kind::Profile && common.max_events.is_some() { return Err(usage_err("--max-events is a trace option; profile publishes one aggregate document")); }`; extend the trace USAGE line (:103) with `[--max-events <n>]`. `0` = unlimited.
- [ ] **Step 4: Run CLI test, verify PASS.**
- [ ] **Step 5: Write the failing evidence test** in `src/trace.rs` mod tests (reuse the `Evidence` literal from `final_evidence_line_is_machine_readable_and_never_claims_a_proven_drain:436`):

```rust
#[test]
fn a_truncated_trace_says_so_in_its_terminal_record() {
    assert_eq!(truncated_line(1).unwrap(), "TRUNCATED at 1 events (--max-events)");
    let evidence = /* same literal as trace.rs:437-493 */;
    let line = evidence_line(&evidence, CapturePolicy::Allowlisted, true);
    let v: serde_json::Value = serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
    assert_eq!(v["trace_truncated"], true);
    assert_eq!(v["completeness"], "PARTIAL");
}
```

- [ ] **Step 6: Implement termination + evidence.** In `src/run.rs`: `const DEFAULT_TRACE_MAX_EVENTS: u64 = 10_000_000;` (10M, so `bench-overhead.sh`'s 1M workload is not truncated). Add `CaptureEnd::LimitReached` to :922 (NOT in `allows_handoff` :930 — an owned child must not be handed back on truncation). In `capture_trace`: `let mut remaining = match max_events { Some(0) => None, Some(n) => Some(n), None => out_sink.is_some().then_some(DEFAULT_TRACE_MAX_EVENTS) };` (bounded only when writing a file; a terminal stream stays unbounded). Pass `remaining: &mut Option<u64>` into `drain_trace_events`; inside `drain.poll`, when `remaining == Some(0)` still call `state.observe_process(process,&ev)` but do not emit; else emit and decrement. After the drain step, `if remaining == Some(0) { break Ok(CaptureEnd::LimitReached); }`. Preserve the exact per-tick loop formatting (see regression note). In `src/trace.rs`: `evidence_line` gains `truncated: bool` and inserts `object.insert("trace_truncated".into(), Value::Bool(truncated));` beside :192; add `pub fn truncated_line(limit: u64) -> Option<String> { Some(format!("TRUNCATED at {limit} events (--max-events)")) }`; emit it once from `capture_trace` right before the EVIDENCE line when truncated.
- [ ] **Step 7: Run both tests + full workspace tests, verify PASS.**
- [ ] **Step 8:** Add a `--max-events 1` assertion to `scripts/bench-overhead.sh` trace lane (or a small verify step): output file has the `CAPTURE` line, ≤1 event line, a `TRUNCATED` line, one `EVIDENCE …"trace_truncated":true`, process exits 0. Commit `security: bound trace output by event count with truncation evidence (csf_ad79ebb)`.

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
    assert!(serde_json::to_string(&json).unwrap().contains(r""), "serde escapes on the wire");
}
```

And in `src/render.rs` mod tests (beside `the_live_heading_names_capture_facts…:3341`): a hostile `path = "/opt/p\u{1b}[2Jevil\r.so"`, assert `heading()` contains no raw `\u{1b}`/`\r` but contains `\u{1b}`/`\r` escaped, and the `live(...)` frame contains no `\u{1b}[2J` beyond the caller's own clear-screen prefix.

- [ ] **Step 2: Run, verify FAIL** (raw controls present).
- [ ] **Step 3: Implement** in `src/render.rs`:

```rust
/// Target-controlled bytes reach a terminal here. Only control characters — C0,
/// DEL, C1 (incl. CSI U+009B) — are rewritten; a legitimate non-ASCII pathname
/// still renders as itself. JSON is unaffected (serde escapes controls itself).
pub(crate) fn escape_controls(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(char::is_control) { return std::borrow::Cow::Borrowed(s); }
    std::borrow::Cow::Owned(
        s.chars().map(|c| if c.is_control() { c.escape_default().to_string() } else { c.to_string() }).collect())
}
```

Apply inside `heading()` (:136-142: `escape_controls(&only.path).into_owned()`, and `format!("{} (+{} more)", escape_controls(&first.path), rest.len())`), and at `inspect.rs:74`, `:68` (both `subject` and `reason`), `:143`, and `engine.rs:2263-2267`. Leave `engine.rs:2782` (pid-only) and `run.rs:1055` (operator scope) alone.

- [ ] **Step 4: Run tests + workspace, verify PASS.** Commit `security: escape terminal control bytes in module-path headings (csf_b8067e3)`.

**Regression watch:** `inspect.rs::text_escapes_interface_name_quotes…:452`, `render.rs::the_live_heading…:3341` (asserts `heading()=="/opt/p11.so"` — unchanged via `Cow::Borrowed` fast path), `tests/discovery_scan.rs:844` and inspect render tests asserting literal paths, `scripts/verify-inspect-doctor.sh`.

---

### Task 4: Output ancestry hardening (csf_c94c662, MEDIUM)

**Files:**
- Modify: `src/output.rs` (`open_output_directory` :277-304, delete local `OpenHow` :270-275, extend `create_private_stream` :203)
- Test: `src/output.rs` mod tests (:391-527)

**Interfaces:**
- Produces: `fn open_directory_nofollow_walk(path: &Path) -> std::io::Result<std::fs::File>` (component-wise `O_NOFOLLOW|O_DIRECTORY` walk); a trusted-ancestor boundary check reused by both sinks.
- Note: HEAD already has `openat2 RESOLVE_NO_SYMLINKS` (commits 7487377/fef8ab3). This task closes the four residual gaps.

- [ ] **Step 1: Write failing tests** in `src/output.rs` mod tests: `output_refuses_a_symlinked_intermediate_ancestor` (symlink is an ancestor, not the parent; both `AtomicFile::create` and `create_private_stream` refuse; protected bytes untouched); `output_refuses_a_world_writable_ancestor` (0777 non-sticky ancestor refused with the ancestor named + "untrusted"; then set 1777 and assert it is accepted — the sticky carve-out); `the_nofollow_walk_fallback_matches_openat2_and_refuses_the_same_symlinks` (direct `open_directory_nofollow_walk` on a real dir returns the same inode; on a symlink and on `/proc/self/fd/1` it errors). Code sketches: see brief B in the scratchpad; use `tempfile::tempdir()` + `PermissionsExt`.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** in `src/output.rs`: (G1) delete local `OpenHow`, use `let mut how: libc::open_how = unsafe { std::mem::zeroed() };` with `resolve: libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS`. (G2) extract `open_directory_nofollow_walk` (each component opened `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` relative to the previous; refuse `..`/prefixes; fall back to it from `open_output_directory` on `ENOSYS`/`EPERM` **only**, never `ELOOP`). (G3) trusted-ancestor rule on every component from `/` to the output parent: trusted iff `st_uid == geteuid() || st_uid == 0`, **and** `st_mode & 0o022 == 0` **unless** `S_ISVTX` sticky (the `/tmp` 1777 carve-out is MANDATORY — the whole output suite builds under `CARGO_TARGET_TMPDIR`); error names the offending ancestor. (G4) call `normalize_output_path` first in `create_private_stream` (:203), matching `AtomicFile::create:55`.
- [ ] **Step 4: Run tests + workspace, verify PASS.** Add a `CHANGELOG.md` line: `-o` now refuses untrusted-ancestor output dirs and works under seccomp profiles that block `openat2`. Commit `security: enforce no-symlink no-magiclink output ancestry with trusted-parent boundary (csf_c94c662)`.

**Regression watch:** 8 `src/output.rs` tests (:397,:408,:422,:432,:453,:474,:488,:506) + `src/run.rs:3580`. Assert the *rule* not unconditional `is_ok()` in tests writing to `CARGO_TARGET_TMPDIR` (`tests/run_lifecycle.rs:19`, `tests/live_discovery.rs:11`) — a non-sticky group-writable TMPDIR is correctly refused. No root gating (uid==0 trusted symmetrically).

---

### Task 5: Cgroup descriptor retention (csf_6f180d5, MEDIUM)

**Files:**
- Modify: `src/attach.rs` (`Scope::Cgroup` :277-286), `src/scope.rs` (new `cgroup()` constructor, `publish` :94-134 simplification), `src/discovery/engine.rs` (`scope_pids` :2141-2209), `src/run.rs:1037`, ~8 test construction sites
- Test: `src/discovery/engine.rs` mod tests (:17653 area)

**Interfaces:**
- Produces: `Scope::Cgroup { id: u64, path: PathBuf, dir: std::sync::Arc<std::fs::File> }`; `pub fn scope::cgroup(path: &Path) -> Result<Scope>` (opens once, ino from the fd).
- The retained fd is the one object both the userspace walk and the kernel publish route through — one guard fixes every caller.

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
    std::fs::remove_dir_all(&real).unwrap();
    std::fs::rename(&impostor, &real).unwrap();            // pathname now the impostor
    let (pids, lost) = scope_pids(&scope);
    assert_eq!(pids, vec![11, 22], "the retained fd's descendants, not 99");
    assert!(!pids.contains(&99));
    assert_eq!(lost, vec![]);
    assert!(!format!("{lost:?}").contains("/proc/self/fd"), "subject must be the operator path");
}
```

Plus `cgroup_walk_reports_losses_under_the_operator_path_not_a_proc_fd_path` (mode-000 leaf, like :17694; assert `lost[0].subject.starts_with(root.path())`).

- [ ] **Step 2: Run, verify FAIL** (walk currently follows the pathname → sees 99).
- [ ] **Step 3: Implement.** `Scope::Cgroup` gains `dir: Arc<File>` (keeps `#[derive(Debug, Clone)]`). New `scope::cgroup(path)` opens the dir, reads `ino()` from the fd, returns the variant (used at `run.rs:1037`). In `scope_pids`, the I/O root is `/proc/self/fd/{}` of the retained fd (repo idiom: `crates/manifest/src/identity.rs:156-168`, `src/discovery/identity.rs:367`) and the stack carries **relative suffixes**; the label root is the operator path — `Skipped.subject` MUST use the label (privacy: no `/proc/self/fd/N` in the capture doc). `scope::publish` simplifies: drop `File::open` + inode re-check (:96-111) since the fd is the checked object, keep `groups.set(0, dir.try_clone()?, 0)` (:114), delete `drop(cgroup_file)` (:134). Non-goals (one-line comment each): `scope::label` (:34) and `doctor::cgroup_check` (:447) stay path-based (trusted fixed root, label/diagnostic only).
- [ ] **Step 4: Fix the ~8 construction sites** (compile churn): `engine.rs:11020,:11301,:11332,:11653,:17659,:17671,:17696`, `attach.rs:2487` — switch literal `/sys/fs/cgroup*` paths to `tempfile::tempdir()` (matching :11016); `id:0` becomes the real inode (nothing compares `Scope.id` outside `publish`).
- [ ] **Step 5: Run tests + workspace, verify PASS.** Commit `security: walk cgroup descendants through a retained descriptor (csf_6f180d5)`.

**Regression watch:** `engine.rs:17653` (subject `ends_with("container.scope")`), `engine.rs:11852` — a SOURCE-TEXT test slicing between `"fn scope_pids("` and `"fn scope_label("`, requiring literal `"membership absence is not authoritative"` and forbidding `entries.flatten()`; preserve those literals verbatim. `scope.rs:175` (keep `"reading cgroup path"` context or move the assertion to the new constructor), `:189`.

---

### Task 6: Discovery scan computation budget + pause deadline (csf_ce5962b, MEDIUM)

**Files:**
- Modify: `crates/manifest/src/maps.rs` (new `MapIndex`, extract `resolved_for`), `src/discovery/scan.rs` (`CaptureWorkBudget` :49-149, `detect_tables` :424, `decode_candidate` :308, `scan_interfaces` :478, `scan_process_view` :763, two reason consts), `src/discovery/engine.rs` (`apply_discovery_batch(_with)` :8296/:8307 — thread `deadline`), `src/discovery/pause.rs:2076`
- Test: `src/discovery/scan.rs` mod tests (:1134 area), one `tests/discovery_scan.rs` PARTIAL-wiring assertion

**Interfaces:**
- Produces: `manifest::maps::MapIndex<'a>` (with `new`, `resolve` — sorted-interval `partition_point` lookup with an unsorted fallback); `CaptureWorkBudget::charge(units: u64) -> bool`, `set_deadline(Option<u64>)`, `WORK_CEILING_REASON`, `SCAN_DEADLINE_REASON`.
- Consumes: `attach::monotonic_ns()` (same clock as `PauseIo::now_ns`); the existing `Skipped{subject,reason}` → `capture_skipped_out` → `modules_skipped` → PARTIAL path (no renderer/evidence change).

- [ ] **Step 1: Write failing tests** in `src/discovery/scan.rs` mod tests (model on `dense_candidates_and_interfaces_stop_at_capture_caps:1134`; synthetic `parse_maps(b"…")` + hand-built `Vec<u8>`): `adversarial_near_misses_and_a_512_table_tail_stop_at_the_computation_ceiling` (4096 candidates each a full-104-field near miss rejected at the last field; assert `tables.is_empty()` and `skipped == vec![WORK_CEILING_REASON]`); `a_crossed_deadline_stops_the_scan_and_reports_it` (`budget.set_deadline(Some(monotonic_ns().saturating_sub(1)))`; assert `skipped == vec![SCAN_DEADLINE_REASON]`). Full sketches in scratchpad brief A.
- [ ] **Step 2: Run, verify FAIL** (scan currently completes / near misses cost zero budget).
- [ ] **Step 3: Implement (a) `MapIndex`** in `maps.rs`: extract `:205-221` body into `fn resolved_for(entry: Option<&MapEntry>, vaddr) -> Resolved`; free `resolve` (:203) calls it (all existing callers untouched); add `MapIndex` with `partition_point` lookup + unsorted-fallback and a one-time sorted check. Build it once in `scan_process_view` after `parse_maps` (:776), pass `&MapIndex` to the three scan fns; delete the now-redundant `mapped` prefilter (`scan.rs:431-434`). **(b)** HashMap `by_address` in `scan_interfaces` replacing the linear `position` (:513). **(c)** one `work` counter on `CaptureWorkBudget` with `WORK_PER_WORD=8`, ceiling `total_bytes/WORD*8`, charged `charge(1)` at the top of each of the three window loops **and inside** `decode_candidate`'s field loop (before the `resolve` — this is what makes a near miss cost budget); on exhaustion return the existing `Err(())` + `WORK_CEILING_REASON`. **(d)** `deadline_ns: Option<u64>` + `set_deadline`; check every 4096 windows via `attach::monotonic_ns()`; thread a `deadline: Option<u64>` param through `apply_discovery_batch(_with)` (engine.rs:8296/:8307) → `budget.set_deadline` on entry, `None` on exit; `pause.rs:2076` passes the deadline it already holds. **(e)** the two reason consts beside `IO_CEILING_REASON:29`, pushed through the existing `Vec<String>` returns.
- [ ] **Step 4: Run tests, verify PASS.** Add a `tests/discovery_scan.rs` assertion that `render::capture_skipped_out(&Skipped{subject:"/lib/x.so".into(), reason: WORK_CEILING_REASON.into()}).reason == "discovery unavailable"` (pins PARTIAL wiring).
- [ ] **Step 5: Measure the honest path** — `p11scope inspect --pid <softhsm-loaded pid>` before/after, compare `scan.scan_ms` from the JSON; `MapIndex` should make it faster (log n vs n). If `WORK_PER_WORD=8` ever trips on a real provider, raise the const (the calibration knob — noted in a `ponytail:` comment). Commit `security: bound discovery scan computation and honor the pause deadline (csf_ce5962b)`.

**Regression watch:** `scan.rs` tests :1082,:1106,:1134,:1190,:1280; `maps.rs` tests :266,:293,:302; `tests/discovery_scan.rs` budget tests :554,:600,:644,:685; `CaptureWorkBudget` uses in `tests/manifest_pinning.rs` and `engine.rs:12603,:14057,:15076,:16627,:16939,:17394`. Fallback if the deadline thread proves invasive: a self-imposed relative cap from `Instant::now()` (bounds the SIGSTOP but not to policy) — record it as a known ceiling.

---

### Task 7: Release driver input-trust hardening (csf_014eb65, MEDIUM)

**Files:**
- Modify: `scripts/build-release.sh` (`task4_receipt_run` :285-296, `task4_finalize` :231, official build :335-336, self-test `lane` heredoc :105-122)
- Test: `tests/artifact_contracts.rs` (`LANE14_CASES` :2429, static asserts :709/:734, a real-process refusal test)

**Interfaces:**
- "Integrate the preflight" does NOT mean invoking BS2b (`scripts/task4-build-subject.py` exits 77 by construction, review-gated; `tests/task4_build_subjects.rs:417` pins candidate-only). It means enforcing the ratified input-trust rules (`2026-08-28-task4-receipt-architecture-decision.md:83-91`, `-build-subject-decision.md:107-112`) in the shell driver.

- [ ] **Step 1: Write failing tests.** (a) Real-process refusal in `tests/artifact_contracts.rs` (pattern of :811, PATH tripwires from :2512-2543): tempdir `CARGO_HOME` with a planted `config.toml`, run `build-release.sh <absent_root>` → `exit 77`, stderr contains `"untracked cargo config"`, tripwire log absent (never reached cargo/sudo/rm). (b) Self-test model rows: add `untracked-build-input-rejected-status-77-no-touch-before-body` to `LANE14_CASES` (:2429) AND the `lane` heredoc (:105-122); modeled on `root-preflight-blocks-body-cargo-runtime` (:62). (c) Static assert: extend `official_build_is_safe_only:709` for `--offline`.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** in `task4_receipt_run`, all before `command -v`(:295)/`sudo -n`(:296)/`release_body`(:305), refusal `exit 77` (POSIX sh; `sh -n` gate at :2267): **A1** replace :285 with `[ -z "$(git status --porcelain=v1 2>/dev/null)" ] || { echo "worktree has untracked or modified entries" >&2; exit 77; }`, mirror at :231. **A2** walk up to `/` and check `CARGO_HOME` for `.cargo/config.toml`/`config` (`-e`/`-L`) → `"untracked cargo config: $p"` exit 77. **A3** refuse-inherited-then-set (lane16.sh:346-350 verbatim: `RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTC_WRAPPER CC CFLAGS`). **A4** rewrite :295 to resolve each of the 9 tools absolute + non-symlink + `task4_fact tool_path_*`/`tool_sha256_*`, plus `rustup which --toolchain 1.88 cargo|rustc` → `toolchain_*` facts (command -v gives the shim). **A5** add `--offline` to the host build (:335-336) ONLY — leave the container-lane builds alone. New receipt fields are additive `task4_fact` TSV rows (no new artifact file, validator :246 untouched).
- [ ] **Step 4: Run tests + workspace, verify PASS** (update the byte-exact cargo block literal in `:709` in the SAME commit as `--offline`). Commit `security: reject untracked build inputs and inherited tool resolution in the release receipt (csf_014eb65)`.

**Regression watch:** `artifact_contracts.rs:709` (byte-exact cargo block — update literal), `:734` (literal path relationships, `trap … EXIT` count ==1, `release_body_cleanup` ==2, poisoned-env exit 2 — keep `WORK=`/invocation strings byte-identical), `:2339`/`:2650` (uncontracted self-test rows fail; `build-release.sh:161` enforces row-count equality), `:2267` (POSIX `sh -n` — no bashisms), `tests/task4_build_subjects.rs:417,:196` (don't touch the .py). `facts.log` has no parser today → new rows safe.

---

### Task 8: Lane 14 receipt literal capture binding (csf_19fb2f, LOW — LIVE BUG)

**Files:**
- Modify: `scripts/build-release.sh` (`task4_receipt_run` :313-316, `release_body` checker :490-491, self-test heredoc :105-122)
- Test: `tests/artifact_contracts.rs` (`:734` static asserts, `LANE14_CASES` :2429)

**Interfaces:**
- Consumes the layout from Task 7. **Live bug:** `:313 find … -name '*observed*.json' | sort | head -n 1` always selects the attach-e2e capture (`verify-attach-e2e.sh:191,198` leave `observed.json`/`observed-scan.json` in the same `$WORK`), NEVER the release's `observed-static-smoke.json` (:446). Every existing Lane 14 receipt `capture.json` is mis-bound; `:316` copies whole body stdout as `checker.log`.

- [ ] **Step 1: Write failing tests.** Static asserts in `artifact_contracts.rs:734`: `release.contains("cp \"$WORK/observed-static-smoke.json\" \"$TASK4_ROOT/artifacts/capture.json\"")`, `!release.contains("head -n 1")`, `!release.contains("cp \"$TASK4_ROOT/stdout.log\" \"$TASK4_ROOT/artifacts/checker.log\"")`. Self-test model rows `literal-static-smoke-capture-path-exact-accepted`, `decoy-observed-json-under-work-rejected`, `aggregate-stdout-as-checker-evidence-rejected` in both the heredoc and `LANE14_CASES` (the decoy row plants a 4th `*observed*.json` in the model `work/` and asserts rejection).
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement.** **B1** replace :313-315 with `cp "$WORK/observed-static-smoke.json" "$TASK4_ROOT/artifacts/capture.json"`. **B2** keep `find` only as a guard asserting the exact 3-name set (`observed-scan.json\nobserved-static-smoke.json\nobserved.json`) else `exit 1`. **B3** in `release_body` replace :490-491 with a framed capture into `$WORK/checker.log` (`argv` line + checker stdout/stderr + `status` line — the frame keeps it non-empty since the checker is silent on success, and `finalize:237` requires `-s`), then `:316` becomes `cp "$WORK/checker.log" "$TASK4_ROOT/artifacts/checker.log"` plus facts `checker_argv`/`checker_status`/`checker_log_sha256`.
- [ ] **Step 4: Run tests + workspace, verify PASS.** Commit `security: bind the Lane 14 receipt to the literal release capture and exact checker output (csf_19fb2f)`.

**Regression watch:** as Task 7 (`:734`, `:2339`/`:2650`, `:2267`, `:161`). `capture.json`/`checker.log` are non-emptiness-checked only (no parser), so the content change is mechanically safe — but the closeout report (Task 12) MUST record that prior receipts' `capture.json` were mis-bound.

---

### Task 9: Stage 3A3 evidence-custody repair

**Files:**
- Modify: `docs/superpowers/reports/2026-08-31-productization-evidence-index.md:66-70`
- Restore into: `.superpowers/sdd/2026-08-27-task4-receipt-closure/` (gitignored local evidence)

- [ ] **Step 1:** The evidence index points Stage 3A3 records at `.claude/worktrees/slice1b2-finish/.superpowers/sdd/2026-08-27-task4-receipt-closure/`, now an empty local dir. The durable copies live in the portable package. Extract exactly `portable-b86d4d5/stage3a3/{stage3a3-green6-report.md,stage3a3-green6-final-review.md,progress.md}` from `/home/user/.local/state/p11scope/pkcs11-scope-portable-b86d4d5.tar.zst` into `.superpowers/sdd/2026-08-27-task4-receipt-closure/` (strip the prefix).
- [ ] **Step 2:** Verify the two named reports exist and are non-empty; record their sha256.
- [ ] **Step 3:** Edit index :66-70 to repoint at `.superpowers/sdd/2026-08-27-task4-receipt-closure/` and add one sentence: the portable package holds the durable copy under `stage3a3/`.
- [ ] **Step 4:** `chmod 0700 /home/user/p11scope-vm-bases` (closes the world-readable parent of an SSH private key; non-destructive, no repo effect).
- [ ] **Step 5:** Run all four gates (docs-only, still run), commit `docs: repoint Stage 3A3 evidence to the canonical sdd copy`.

---

### Task 10: Full-gate verification

- [ ] **Step 1:** All four canonical gates on the branch tip, clean.
- [ ] **Step 2:** Run the unprivileged portions of `scripts/verify-canaries.sh` / privacy suite as far as unprivileged allows; record any privileged lane as UNRUN explicitly (never claim a root lane ran).
- [ ] **Step 3:** Commit any fallout fixes.

---

### Task 11: Independent review → fix cycles (repeat until clean)

- [ ] **Step 1:** Dispatch two independent Opus review agents over `git diff main...hardening/findings-wave1`: (a) adversarial security/correctness review incl. each finding's closure claim and whether the fix is complete at the root (all sibling callers, not just the cited line); (b) test-quality + regression review (do the tests actually fail without the fix? are the assertions meaningful? any weakened existing test?).
- [ ] **Step 2:** Triage (Fable adjudicates — accept/reject each with reasoning). Fix every accepted finding TDD-style; rerun gates.
- [ ] **Step 3:** Repeat Step 1 with fresh agents until a full cycle reports zero accepted findings.
- [ ] **Step 4:** Merge `hardening/findings-wave1` → `main` (repo convention: fast-forward if linear, else a merge commit); rerun all four gates on `main`.

---

### Task 12: Wave-1 closeout

- [ ] **Step 1:** Write `docs/superpowers/reports/2026-09-01-wave1-findings-closure.md`: per-finding closure evidence (test name + commit), the two upgraded findings called out honestly (Lane 14 receipt was a live mis-binding affecting all prior receipts; `-o` was broken under old Docker seccomp), review-cycle count, and every UNRUN privileged confirmation listed plainly.
- [ ] **Step 2:** Refresh the portable package at the new `main` tip, including `.superpowers/sdd/` and — in the evidence-archive side, NOT tracked in git (privacy rule §48 bars PIDs/addresses from tracked files) — the rescued unique `p11scope-ws` text (the 22 `analyses/*.md`, the Task 6D handoff, the Gate B controller review, the codex SDD).
- [ ] **Step 3:** Update memory: mark wave 1 closed, record the new tip and package hash, note waves 2+ (CI, containers, multi-distro, 32-bit) still pending and gated on the eBPF-pitfalls research report.

## Self-Review

- **Spec coverage:** all 8 findings (Tasks 1-8) + the custody gap the audit surfaced (Task 9) + gates/review/closeout (10-12). Every finding's `remediation` maps to a task.
- **Placeholder scan:** every code step carries real code or an exact edit locus from a brief; the `/* same literal as … */` markers point at existing test fixtures the executor copies, not invented content.
- **Type consistency:** `Scope::Cgroup{id,path,dir}`, `scope::cgroup()`, `MapIndex`, `CaptureWorkBudget::charge/set_deadline`, `CaptureEnd::LimitReached`, `trace::truncated_line`/`evidence_line(…, truncated)`, `render::escape_controls` — names used consistently across tasks.
