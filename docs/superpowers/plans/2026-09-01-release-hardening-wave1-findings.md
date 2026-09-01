# Release Hardening Wave 1 — Security Findings Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all eight open findings from static security scan `3e10be9` (six MEDIUM, two LOW) with focused local tests, repair the Stage 3A3 evidence-custody gap, and drive independent review→fix cycles until zero findings remain — so the basic product is issue-free and fully covered by the local test framework.

**Architecture:** One TDD task per finding, at its cited code site, using the scanner's own `remediation` text (`/home/user/.local/state/p11scope/security-scan-3e10be9/findings.json` — NON-durable location; Task 9 mirrors it into `p11scope-ws`) plus a fresh code-level implementation brief as the design authority. Each brief was produced by an independent read-only analysis of HEAD `b86d4d5`; two findings turned out to be more than the scan said (Lane 14 receipt mis-binding is a live bug; `-o` is currently broken under old Docker seccomp). Work lands on branch `hardening/findings-wave1`; the wave closes with full canonical gates and iterated Opus review cycles, then merges to `main`.

**Tech Stack:** Rust 1.88 (edition 2024), aya eBPF, `libc` 0.2.189 (only syscall dep — no new deps), bash release driver, existing `tests/` + in-module `mod tests` framework.

**Spec:** `docs/superpowers/specs/2026-09-01-release-requirements-and-goal.md` §3/§5 (the owner authority; it supersedes the consolidation-status "Next order" list). Scanner detail: `/home/user/.local/state/p11scope/security-scan-3e10be9/findings.json` (hash-pinned in `docs/superpowers/reports/2026-08-31-productization-evidence-index.md` §"Static security closeout") — a non-durable location per spec §4; Task 9 mirrors it into `p11scope-ws`.

**Plan review 2026-09-01:** every cited anchor was verified against HEAD 556f7cf by three independent read-only verifiers (Tasks 1-3, 4-6, 7-9); all accepted corrections are folded in below. Largest: Task 6 gained part (f) — the `/proc/<pid>/maps` read itself was still unbudgeted (spec §3.1 / research #3); Task 5's original test destroyed the directory behind the retained fd and could green a broken fix; Task 4's ancestry rule as first drafted refused this repo's own 775 working tree. The "brief A/B in the scratchpad" pointers were dead (session-local, gone) and were replaced with self-contained instructions.

## Global Constraints

- Rust 1.88, edition 2024, Linux x86-64-first (CLAUDE.md). `std::env::remove_var` and other formerly-safe fns are `unsafe` in edition 2024 — wrap in `unsafe {}` where noted.
- **All four canonical gates green after every task**: `cargo +1.88 fmt --all -- --check`, `cargo +1.88 check --locked --workspace --all-targets`, `cargo +1.88 test --locked --workspace --all-targets`, `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings`.
- Preserve `docs/privacy/allowlist-v1.md`; never broaden capture implicitly. Target-controlled bytes must not leak into the capture document (subjects stay operator-path/label form, never `/proc/self/fd/N`).
- No new dependencies. `libc` 0.2.189 already exports `open_how` (`#[non_exhaustive]` — construct via `mem::zeroed()` + field assignment only), `RESOLVE_NO_SYMLINKS`, `SYS_close_range` (verified for both gnu and musl x86-64); use the raw `libc::syscall` for `close_range` (the wrapper fn is gnu-only and the release also builds a musl helper).
- Do not track generated output. Wave-1 tasks must be verifiable unprivileged; a privileged-only assertion follows the repo convention — assert the outcome the observed configuration requires (`tests/proc_access.rs:1-5`), reserve `eprintln!("SKIP: …")` for a genuinely absent resource only.
- Kernel floor 5.15. `openat2`(5.6)/`close_range`(5.9) exist on every supported kernel, but keep the `ENOSYS`/`EPERM` fallback where specified — seccomp (Docker) is the real reason, not the kernel.
- Branch `hardening/findings-wave1` off the `main` tip (556f7cf; code identical to b86d4d5 — the top commit is docs-only). Frequent commits (one per task). Merge only after Task 11 review cycles reach zero accepted findings.

---

### Task 1: Helper file-descriptor and environment confinement (csf_f5953ae, MEDIUM)

**Files:**
- Modify: `crates/discover/src/main.rs` (top of `drop_privileges_and_open_self_memory`, before the `/proc/self/mem` open at :142)
- Create: `crates/discover/tests/fixture/fd_env_canary.c`
- Test: `crates/discover/tests/cli.rs` (add one test; reuses `BIN` at :4)

**Interfaces:**
- Produces: `close_inherited_descriptors()` (infallible — warn-and-continue on an unreadable `/proc/self/fd`) and a `LOADER_SENSITIVE_ENV: &[&str]` const, both private to `crates/discover/src/main.rs`.
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
fn close_inherited_descriptors() {
    // SYS_close_range present on both shipped targets; the libc::close_range wrapper
    // is gnu-only (libc 0.2.189 declares it under linux/gnu only) and build-release.sh
    // also builds a musl helper — use the raw syscall.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0) } == 0 { return; }
    // Fallback: seccomp ENOSYS/EPERM. Collect first — the ReadDir is consumed by the
    // collect, so its own dirfd is closed before the loop; the stale list entry for it
    // draws one harmless EBADF close (single-threaded here). If even /proc/self/fd is
    // unreadable (masked /proc, e.g. the musl container lane,
    // verify-discover-containers.sh:239-245), warn and continue: a hardening step must
    // not turn a working capture into a hard failure.
    let entries = match std::fs::read_dir("/proc/self/fd") {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("p11scope-discover: cannot enumerate inherited fds, leaving them open: {e}");
            return;
        }
    };
    let mut fds: Vec<i32> = entries.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| *fd > 2).collect();
    fds.sort_unstable();
    for fd in fds { unsafe { libc::close(fd) }; }
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
    close_inherited_descriptors();
    // SAFETY: the helper is single-threaded here — before the dlopen at discover.rs:53;
    // provider constructors may spawn threads, so this must never move after it
    // (remove_var is UB with concurrent env access in edition 2024).
    // ponytail: glibc caches LD_LIBRARY_PATH/PRELOAD/AUDIT at startup, so this
    // protects constructor getenv + any child the provider spawns, not the dlopen
    // search itself; full closure needs a self re-exec with sanitized environ.
    for name in LOADER_SENSITIVE_ENV { unsafe { std::env::remove_var(name) }; }
```

Note: `prepare_drop()` at `main.rs:253` reads `SUDO_UID`/`SUDO_GID` (`target_id`, `:37-43`) before this point — the denylist above deliberately excludes them, so ordering is safe either way, but keep the confinement at the top of `drop_privileges_and_open_self_memory` as specified.

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
    assert_eq!(truncated_line(1), "TRUNCATED at 1 events (--max-events)");
    let evidence = /* same literal as trace.rs:437-493 */;
    let line = evidence_line(&evidence, CapturePolicy::Allowlisted, true);
    let v: serde_json::Value = serde_json::from_str(line.strip_prefix("EVIDENCE ").unwrap()).unwrap();
    assert_eq!(v["trace_truncated"], true);
    assert_eq!(v["completeness"], "PARTIAL");
}
```

- [ ] **Step 6: Implement termination + evidence.** In `src/run.rs`: `const DEFAULT_TRACE_MAX_EVENTS: u64 = 10_000_000;` (10M, so `bench-overhead.sh`'s default 1M workload is not truncated; an operator raising `N_CALLS` past 10M sees the visible `TRUNCATED` line — documented behavior). Add `CaptureEnd::LimitReached` to :923 (NOT in `allows_handoff` :931 — an owned child must not be handed back on truncation). In `capture_trace`: compute `let mut remaining = match max_events { Some(0) => None, Some(n) => Some(n), None => out.is_some().then_some(DEFAULT_TRACE_MAX_EVENTS) };` **from the `out` parameter, BEFORE `:2082`** — `:2083` is `let out_file = &mut out_sink;`, a mutable borrow live for the rest of the fn, so `out_sink.is_some()` later is E0502 — and place the `let` ABOVE `loop {` (a `let` between `loop {` and `let elapsed` breaks the pinned literal at `artifact_contracts.rs:3649`). Pass `remaining: &mut Option<u64>` into `drain_trace_events`, appending the arg AFTER `session` so the pinned `"drain_trace_events(\n            session,"` survives (the closure at :2120 is `#[rustfmt::skip]` — indentation is hand-maintained), **and into the terminal drain at :2186 as well** — otherwise the final drain empties the whole ring past the limit and the file overshoots by a full ring, defeating the flag exactly where it matters. Inside `drain.poll`, when `remaining == Some(0)` still call `state.observe_process(process,&ev)` but do not emit (reuse the shape of the existing `write_error.is_none()` skip-emit branch at :2308-2318 — do not write a second mechanism); else emit and decrement. After the drain step, `if remaining == Some(0) { break Ok(CaptureEnd::LimitReached); }` placed between the drain and `retire_exited` (order the source-text test allows). Thread `max_events` through `run_loop` (:1117, already `#[allow(clippy::too_many_arguments)]`; call sites :1063, :1580). In `src/trace.rs`: `evidence_line` gains `truncated: bool` and inserts `object.insert("trace_truncated".into(), Value::Bool(truncated));` beside :192 — its four call sites `trace.rs:495`, `render.rs:2967`, `run.rs:2228`, `engine.rs:16890` all take the new arg; add `pub fn truncated_line(limit: u64) -> String { format!("TRUNCATED at {limit} events (--max-events)") }` (plain `String` — `lost_line:166`'s `Option` is earned by its `n > 0` guard; an always-`Some` has none); emit it once from `capture_trace` right before the EVIDENCE line when truncated. Compile churn: `Common` is built by exhaustive literal inside `CaptureArgs`/`RunArgs` constructions at `cli.rs:337`, `cli.rs:403`, `run.rs:1496`, `run.rs:3309`, `engine.rs:11290`, `tests/live_discovery.rs:49`, `tests/run_lifecycle.rs:27`, `tests/pause.rs:21` — every site gains `max_events: None`.
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
    assert!(serde_json::to_string(&json).unwrap().contains(r"\u001b"), "serde escapes on the wire");
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

- [ ] **Step 1: Write failing tests** in `src/output.rs` mod tests, `tempfile::tempdir()` + `std::os::unix::fs::PermissionsExt` (the dead "brief B" pointer is gone — the assertions here are the spec): `output_refuses_a_symlinked_intermediate_ancestor` (symlink is an ancestor, not the parent; both `AtomicFile::create` and `create_private_stream` refuse; protected bytes untouched); `output_refuses_a_world_writable_ancestor` (chmod an ancestor 0707 non-sticky → refused with the ancestor named + "untrusted"; chmod 1707 → accepted — the sticky carve-out; chmod 0775 euid-owned → accepted — group-writable is allowed, see G3); `the_nofollow_walk_fallback_matches_openat2_and_refuses_the_same_symlinks` (direct `open_directory_nofollow_walk` on a real dir returns the same dev+ino as `open_output_directory`; on a symlinked component and on `/proc/self/fd/1` it errors).
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** in `src/output.rs`: (G1) delete the local `OpenHow` (:270-275) in favor of `libc::open_how` — it is `#[non_exhaustive]`, so `let mut how: libc::open_how = unsafe { std::mem::zeroed() };` plus field assignment is the ONLY form that compiles (a struct literal will not); keep `resolve: libc::RESOLVE_NO_SYMLINKS` (adding `RESOLVE_NO_MAGICLINKS` is a no-op — superset, above). (G2) extract `open_directory_nofollow_walk` (each component opened `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` relative to the previous; refuse `..`/prefixes; fall back to it from `open_output_directory` on `ENOSYS`/`EPERM` **only**, never `ELOOP`). (G3) trusted-ancestor rule on every component from `/` to the output parent: trusted iff `st_uid ∈ {geteuid(), 0}` — plus, **when euid==0, the invoking `SUDO_UID` if set** (the e2e gates run `sudo … -o target/e2e/…` from a uid-1000 checkout; without this clause every root-invoked `-o` under a user home is refused) — **and** `st_mode & 0o002 == 0` **unless** `S_ISVTX` sticky. Other-write only, NOT `0o022`: this host's `~/src`→`target` chain is 775 non-sticky, so a group-write refusal kills the repo's own gates and most dev checkouts (`ponytail:` comment in code — group-writable ancestors accepted; tighten to 0o022 behind a flag if multi-user groups ever matter). The sticky carve-out stays MANDATORY — the nine existing output tests build under `tempfile::tempdir()` → `/tmp` (1777 root: saved by uid-0 ownership + sticky). Error names the offending ancestor. (G4) call `normalize_output_path` first in `create_private_stream` (:203), matching `AtomicFile::create:55` (today `-o ../../x/trace.log` is accepted for the trace sink and refused for the profile sink — this unifies them).
- [ ] **Step 4: Run tests + workspace, verify PASS.** Add a `CHANGELOG.md` line: `-o` now refuses untrusted-ancestor output dirs and works under seccomp profiles that block `openat2`. Commit `security: enforce output ancestry trust and a seccomp fallback for the no-symlink walk (csf_c94c662)`.

**Regression watch:** 9 `src/output.rs` mod tests (:397,:408,:422,:432,:453,:474,:488,:506 + `src/run.rs:3580`'s use of `AtomicFile::create`) — all write under `tempfile::tempdir()`, NOT `CARGO_TARGET_TMPDIR`. `tests/run_lifecycle.rs:179` writes `<CARGO_TARGET_TMPDIR>/…/run.json` unprivileged — the group-write allowance is what keeps it green. `scripts/verify-attach-e2e.sh:173-176` and `scripts/verify-induced-gaps.sh:855,890,946,956,976,985,1007` pass `-o "$WORK/…"` with `WORK=target/e2e` **under sudo** — the SUDO_UID clause is what keeps them green; neither script may be left out of the post-task check. (`tests/live_discovery.rs` sets `out: None` — not a target.)

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

Plus `cgroup_walk_reports_losses_under_the_operator_path_not_a_proc_fd_path` (mode-000 leaf, like :17694; assert `lost[0].subject.starts_with(root.path())`).

- [ ] **Step 2: Run, verify FAIL** (walk currently follows the pathname → sees 99).
- [ ] **Step 3: Implement.** `Scope::Cgroup` gains `dir: Arc<File>` (keeps `#[derive(Debug, Clone)]` — the only derives on `Scope`; nothing derives `PartialEq`). Compile churn the field forces: `scope.rs:94` matches `Scope::Cgroup { id, path }` exhaustively — bind or elide the new field there; every other pattern already uses `..` (`scope.rs:73`, `attach.rs:367/1081/1115`, `engine.rs:2144/2217/7873`). New `scope::cgroup(path)` opens the dir, reads `ino()` from the fd, returns the variant (used at `run.rs:1038`) — and KEEPS the `"reading cgroup path {}"` error context (`scope.rs:191`'s `missing_cgroup_path_errors_loudly` asserts that string). In `scope_pids`, the I/O root is `/proc/self/fd/{}` of the retained fd (repo idiom: `crates/manifest/src/identity.rs:154-168`, `src/discovery/identity.rs:367`) and the stack carries **relative suffixes**; the label root is the operator path — `Skipped.subject` MUST use the label (privacy: no `/proc/self/fd/N` in the capture doc; note `readlink` on the fd reports the moved path, another reason the stored operator path is the only valid subject). `scope::publish` simplifies: drop `File::open` + inode re-check (:96-111) since the fd is the checked object, keep `groups.set(0, dir.try_clone()?, 0)` (:114), delete `drop(cgroup_file)` (:134). Non-goals (one-line comment each): `scope::label` (:34) and `doctor::cgroup_check` (:447) stay path-based (trusted fixed root, label/diagnostic only).
- [ ] **Step 4: Fix the ~8 construction sites** (compile churn): `engine.rs:11020,:11301,:11332,:11653,:17659,:17671,:17696`, `attach.rs:2487` — switch literal `/sys/fs/cgroup*` paths to `tempfile::tempdir()` (matching :11016); `id:0` becomes the real inode (nothing compares `Scope.id` outside `publish`).
- [ ] **Step 5: Run tests + workspace, verify PASS.** Commit `security: walk cgroup descendants through a retained descriptor (csf_6f180d5)`.

**Regression watch:** `engine.rs:17653` (subject `ends_with("container.scope")`), `engine.rs:11852` — a SOURCE-TEXT test slicing between `"fn scope_pids("` and `"fn scope_label("`, requiring literal `"membership absence is not authoritative"` and forbidding **both** `entries.flatten()` **and** `file_type().is_ok_and` (:11864) — the fd-based rewrite must not reach for either; preserve the literals verbatim. `scope.rs:175` (`cgroup_id_is_the_directory_inode` — the id must remain the directory inode), `:189-191` (`missing_cgroup_path_errors_loudly` — keep the `"reading cgroup path"` context in the new constructor).

---

### Task 6: Discovery scan computation budget + pause deadline (csf_ce5962b, MEDIUM)

**Files:**
- Modify: `crates/manifest/src/maps.rs` (new `MapIndex`, extract `resolved_for`, entry-count ceiling in `parse_maps`), `src/discovery/scan.rs` (`CaptureWorkBudget` :49-149, the maps read :778, `detect_tables` :424, `decode_candidate` :308, `scan_interfaces` :478, `scan_process_view` :763, three reason consts), `src/discovery/engine.rs` (`apply_discovery_batch(_with)` :8296/:8307 — thread `deadline`), `src/discovery/pause.rs:2076`
- Test: `src/discovery/scan.rs` mod tests (:1134 area), one `tests/discovery_scan.rs` PARTIAL-wiring assertion

**Interfaces:**
- Produces: `manifest::maps::MapIndex<'a>` (with `new`, `resolve` — sorted-interval `partition_point` lookup with an unsorted fallback); `CaptureWorkBudget::charge(units: u64) -> bool`, `set_deadline(Option<u64>)`, `WORK_CEILING_REASON`, `SCAN_DEADLINE_REASON`, `MAPS_CEILING_REASON`.
- Consumes: `attach::monotonic_ns()` (verified: `attach.rs:711`, `pub(crate)` — deadline tests must live in `src/` mod tests; `SessionPauseIo::now_ns` at `pause.rs:1997-1999` is literally the same fn, so the clocks match); the existing `Skipped{subject,reason}` → `capture_skipped_out` → `modules_skipped` → PARTIAL path (no renderer/evidence change).

- [ ] **Step 1: Write failing tests** in `src/discovery/scan.rs` mod tests (model on `dense_candidates_and_interfaces_stop_at_capture_caps:1134`; synthetic `parse_maps(b"…")` + hand-built `Vec<u8>` — the dead "brief A" pointer is gone, the assertions here are the spec): `adversarial_near_misses_and_a_512_table_tail_stop_at_the_computation_ceiling` (4096 candidates each a full-104-field near miss rejected at the last field; assert `tables.is_empty()` and `skipped == vec![WORK_CEILING_REASON]`); `a_crossed_deadline_stops_the_scan_and_reports_it` (`budget.set_deadline(Some(monotonic_ns().saturating_sub(1)))`; assert `skipped == vec![SCAN_DEADLINE_REASON]`); `an_oversized_maps_snapshot_truncates_at_a_newline_and_reports_partial` (feed the capped read path a synthetic maps text larger than the cap whose cut lands mid-line; assert the entries parsed are exactly those before the last full newline, `skipped` contains `MAPS_CEILING_REASON`, and there is NO hard error — `parse_maps` rejects the whole snapshot on any malformed line at `maps.rs:55-65`, so an untrimmed cut would turn a big target into a scan failure instead of a partial).
- [ ] **Step 2: Run, verify FAIL** (scan currently completes / near misses cost zero budget / the maps read is uncapped).
- [ ] **Step 3: Implement (a) `MapIndex`** in `maps.rs`: extract `:204-222` body into `fn resolved_for(entry: Option<&MapEntry>, vaddr) -> Resolved`; free `resolve` (:203) calls it (all existing callers untouched); add `MapIndex` with `partition_point` lookup + unsorted-fallback and a one-time sortedness check (O(n), charge it — `/proc` maps are kernel-ordered, so the fallback is unreachable from a real target but must exist for synthetic input). Build it once in `scan_process_view` after `parse_maps` (:776), pass `&MapIndex` to the three scan fns; delete the now-redundant `mapped` prefilter (`scan.rs:431-434`). **(b)** HashMap `by_address` in `scan_interfaces` replacing the linear `position` (:513). **(c)** one `work` counter on `CaptureWorkBudget` with its OWN ceiling — `work_ceiling` initialized from a new `DEFAULT_WORK_CEILING` const, test-overridable alongside the existing limits. It must NOT be derived from `total_bytes`: `scan.rs:1190` runs with `ScanLimits { per_object_bytes: 64, total_bytes: 1 }` and asserts `IO_CEILING_REASON` — a `total_bytes`-derived compute ceiling of 1 would flip that test to `WORK_CEILING_REASON`, and it silently couples compute headroom to I/O headroom for every future caller. Charge `charge(1)` at the top of each of the three window loops **and inside** `decode_candidate`'s field loop (before the `resolve` at :360 — it runs before `admit_table:377`, so today a candidate rejected at its last field costs up to 104 × O(n) comparisons and charges zero; this is what makes a near miss cost budget); on exhaustion return the existing `Err(())` + `WORK_CEILING_REASON`. **(a) and (c) are one indivisible commit**: a `charge(1)` against an O(n) linear `resolve` understates real cost by ~6 orders of magnitude at n=1M — the unit price is only honest once `MapIndex` makes `resolve` O(log n). **(d)** `deadline_ns: Option<u64>` + `set_deadline`; check every 4096 windows via `attach::monotonic_ns()`; thread a `deadline: Option<u64>` param through `apply_discovery_batch(_with)` (engine.rs:8296/:8307; other callers to touch: engine.rs:8303,:12342,:13254) → `budget.set_deadline` on entry, `None` on exit; `pause.rs:2076` passes the deadline `apply_batch:2039-2042` already holds. **(e)** the three reason consts beside `IO_CEILING_REASON:29`, pushed through the existing `Vec<String>` returns. **(f) Bound and charge the maps read itself (spec §3.1 / research #3 — without this the task does not close its finding).** `scan.rs:778`'s bare `std::fs::read("/proc/{pid}/maps")` is the ONLY read in scan.rs outside `allowed_io`/`record_io`, and `vm.max_map_count` now defaults to 1048576 (≈70-100 MB of maps text, re-read per view per refresh, on the pause path while the target is SIGSTOP'd — the deadline in (d) cannot fire until AFTER this read completes, so (d) alone does not bound it). Replace with `File::open` + `Read::take(MAX_MAPS_BYTES)` and spend the bytes through `allowed_io`/`record_io` — charging the existing `total_bytes` budget is what bounds the per-view × per-refresh multiplicity. On hitting the cap: truncate at the LAST NEWLINE before handing to `parse_maps` (see the Step 1 test), push a `MAPS_CEILING_REASON` `Skipped` (a truncated map is real loss — every mapping past the cut is a provider never inventoried → PARTIAL). `const MAX_MAPS_BYTES: u64 = 128 * 1024 * 1024;` — `ponytail:` knob comment: legit JVM/ES nodes genuinely reach ~100 MB; only adversarial scale gets cut; lower it if measurement says so. Add an entry-count ceiling in `parse_maps` (one heap alloc per named line today — 1M lines is 1M allocations).
- [ ] **Step 4: Run tests, verify PASS.** Add a `tests/discovery_scan.rs` assertion that `render::capture_skipped_out(&Skipped{subject:"/lib/x.so".into(), reason: WORK_CEILING_REASON.into()}).reason == "discovery unavailable"` (pins PARTIAL wiring).
- [ ] **Step 5: Measure the honest path** — `p11scope inspect --pid <softhsm-loaded pid>` before/after, compare `scan.scan_ms` from the JSON; `MapIndex` should make it faster (log n vs n). If `DEFAULT_WORK_CEILING` ever trips on a real provider, raise the const (the calibration knob — noted in a `ponytail:` comment). Commit `security: bound discovery scan computation, the maps read, and honor the pause deadline (csf_ce5962b)`.

**Regression watch / signature churn:** `scan.rs` tests :1082,:1106,:1134,:1280 call `detect_tables(&snapshot, base, &maps, &mut budget)` and :1190 calls `scan_interfaces(…, &maps, …)` — the `&MapIndex` parameter is a **compile-breaking edit at all five sites**, not a passive watch; :1190 additionally guards the `work_ceiling` decoupling above. `maps.rs` tests :266,:293,:302 (plus :238,:326 unaffected); `tests/discovery_scan.rs` budget tests :554,:600,:644,:685; `CaptureWorkBudget` uses in `tests/manifest_pinning.rs` and `engine.rs:12603,:14057,:15076,:16627,:16939,:17394` plus six `CaptureWorkBudget::default()` at `engine.rs:15439,:15827,:15884,:16211,:16661,:17310`. `tests/artifact_contracts.rs:409` pins the literal `".apply_discovery_batch_with("` in pause.rs — an appended parameter preserves it. Fallback if the deadline thread proves invasive: a self-imposed relative cap from `Instant::now()` (bounds the SIGSTOP but not to policy) — record it as a known ceiling.

---

### Task 7: Release driver input-trust hardening (csf_014eb65, MEDIUM)

**Files:**
- Modify: `scripts/build-release.sh` (`task4_receipt_run` :285-296, `task4_finalize` :231, official build :335-336, self-test `lane` heredoc :105-122)
- Test: `tests/artifact_contracts.rs` (`LANE14_CASES` :2429, static asserts :709/:734, a real-process refusal test)

**Interfaces:**
- "Integrate the preflight" does NOT mean invoking BS2b (`scripts/task4-build-subject.py:3461-3462` exits 77 by construction, review-gated; `tests/task4_build_subjects.rs:417` pins candidate-only). It means enforcing the ratified input-trust rules (`docs/superpowers/reports/2026-08-28-task4-receipt-architecture-decision.md:83-91`, `docs/superpowers/reports/2026-08-28-task4-build-subject-decision.md:107-112` — note: `reports/`, not `plans/`) in the shell driver.
- Context on A1: `:285` already refuses a dirty TRACKED tree (`git diff --quiet && git diff --cached --quiet`, twin inside `task4_finalize` at :231; the fn itself starts :220) and `task4_snapshot:202` hashes `git ls-files` only — **untracked files are invisible to every existing gate**, which is exactly how an untracked `.cargo/config.toml` steers Cargo unnoticed. The porcelain replacement is what closes that.

- [ ] **Step 1: Write failing tests.** (a) Real-process refusal in `tests/artifact_contracts.rs` (pattern of :811, PATH tripwires from :2512-2543): tempdir `CARGO_HOME` with a planted `config.toml`, run `build-release.sh <absent_root>` → `exit 77`, stderr contains `"untracked cargo config"`, tripwire log absent (never reached cargo/sudo/rm). (b) Self-test model rows: add `untracked-build-input-rejected-status-77-no-touch-before-body` to `LANE14_CASES` (:2429) AND the `lane` heredoc (:105-122); modeled on `root-preflight-blocks-body-cargo-runtime` (:62). (c) Static assert: extend `official_build_is_safe_only:709` for `--offline`.
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement** in `task4_receipt_run`, all before `command -v`(:295)/`sudo -n`(:296)/`release_body`(:305), refusal `exit 77` (POSIX sh; `sh -n` gate at :2267): **A1** replace :285 with `[ -z "$(git status --porcelain=v1 2>/dev/null)" ] || { echo "worktree has untracked or modified entries" >&2; exit 77; }`, mirror at :231. **A2** walk up to `/` and check `CARGO_HOME` for `.cargo/config.toml`/`config` (`-e`/`-L`) → `"untracked cargo config: $p"` exit 77. **A3** refuse-inherited-then-set (`scripts/verify-task4-lane16.sh:346-350` verbatim — all 10 vars: `RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTC_WRAPPER CC CFLAGS`). **A4** rewrite :295 to resolve each of the 9 tools absolute + non-symlink + `task4_fact tool_path_*`/`tool_sha256_*`, plus `rustup which --toolchain 1.88 cargo|rustc` → `toolchain_*` facts (command -v gives the shim). **A5** add `--offline` to the host build (:335-336) ONLY — leave the container-lane builds alone. New receipt fields are additive `task4_fact` TSV rows (no new artifact file, validator :246 untouched).
- [ ] **Step 4: Run tests + workspace, verify PASS** (update the byte-exact cargo block literal in `:709` in the SAME commit as `--offline`). Commit `security: reject untracked build inputs and inherited tool resolution in the release receipt (csf_014eb65)`.

**Regression watch:** `artifact_contracts.rs:709` (byte-exact cargo block — update literal), `:734` (literal path relationships, `trap … EXIT` count ==1, `release_body_cleanup` ==2, poisoned-env exit 2 — keep `WORK=`/invocation strings byte-identical), `:2339`/`:2650` (uncontracted self-test rows fail; `build-release.sh:161` enforces row-count equality), `:2267` (POSIX `sh -n` — no bashisms), `tests/task4_build_subjects.rs:417,:196` (don't touch the .py). `facts.log` has no parser today → new rows safe.

---

### Task 8: Lane 14 receipt literal capture binding (csf_19fb2f, LOW — LIVE BUG)

**Files:**
- Modify: `scripts/build-release.sh` (`task4_receipt_run` :313-316, `release_body` checker :490-491, self-test heredoc :105-122)
- Test: `tests/artifact_contracts.rs` (`:734` static asserts, `LANE14_CASES` :2429)

**Interfaces:**
- Consumes the layout from Task 7. **Live bug (verified against the script flow):** `:313 find "$TASK4_ROOT/work" … -name '*observed*.json' | sort | head -n 1` always selects `observed-scan.json` — ASCII sort: `-` < `.`, then `c` < `t` — an attach-e2e file (`verify-attach-e2e.sh:191,198` leave `observed-scan.json`/`observed.json` in the same `$WORK`; its `$WORK` IS `$TASK4_ROOT/work` via `P11SCOPE_TASK4_WORK="$ATTACH_WORK"` and `ATTACH_WORK=$WORK` at :302, and attach-e2e always completes inside `release_body` before the receipt step runs). It NEVER selects the release's own `observed-static-smoke.json`, which is written via the profile's `-o` flag at `:478` (landing root-owned, reclaimed at `:488`; `:446` is only the `rm -f` prep line). Every existing Lane 14 receipt `capture.json` is mis-bound; `:316` copies whole body stdout as `checker.log`. Both mechanisms are literally forbidden by the ratified decision (`…receipt-architecture-decision.md:90`: "No glob, `find | head`, basename, stdout-as-capture, or path-order authority is permitted").

- [ ] **Step 1: Write failing tests.** Static asserts in `artifact_contracts.rs:734`: `release.contains("cp \"$WORK/observed-static-smoke.json\" \"$TASK4_ROOT/artifacts/capture.json\"")`, `!release.contains("head -n 1")`, `!release.contains("cp \"$TASK4_ROOT/stdout.log\" \"$TASK4_ROOT/artifacts/checker.log\"")`. Self-test model rows `literal-static-smoke-capture-path-exact-accepted`, `decoy-observed-json-under-work-rejected`, `aggregate-stdout-as-checker-evidence-rejected` in both the heredoc and `LANE14_CASES` (the decoy row plants a 4th `*observed*.json` in the model `work/` and asserts rejection).
- [ ] **Step 2: Run, verify FAIL.**
- [ ] **Step 3: Implement.** **B1** replace :313-315 with `cp "$WORK/observed-static-smoke.json" "$TASK4_ROOT/artifacts/capture.json"`. **B2** keep `find` only as a guard asserting the exact 3-name set (`observed-scan.json\nobserved-static-smoke.json\nobserved.json`) else `exit 1`. **B3** in `release_body` replace :490-491 with a framed capture into `$WORK/checker.log` (`argv` line + checker stdout/stderr + `status` line — the frame keeps it non-empty since the checker is silent on success, and `finalize:237` requires `-s`), then `:316` becomes `cp "$WORK/checker.log" "$TASK4_ROOT/artifacts/checker.log"` plus facts `checker_argv`/`checker_status`/`checker_log_sha256`.
- [ ] **Step 4: Run tests + workspace, verify PASS.** Commit `security: bind the Lane 14 receipt to the literal release capture and exact checker output (csf_19fb2f)`.

**Regression watch:** as Task 7 (`:734`, `:2339`/`:2650`, `:2267`, `:161`). `capture.json`/`checker.log` are non-emptiness-checked only (no parser), so the content change is mechanically safe — but the closeout report (Task 12) MUST record that prior receipts' `capture.json` were mis-bound.

---

### Task 9: Stage 3A3 evidence-custody repair

**Files:**
- Modify: `docs/superpowers/reports/2026-08-31-productization-evidence-index.md:66-70`, root `.gitignore`
- Restore into: `.superpowers/sdd/2026-08-27-task4-receipt-closure/` (gitignored local evidence) and `/home/user/src/m/p11scope-ws/preserved/` (durable home per spec §4)

- [ ] **Step 1:** The evidence index points Stage 3A3 records at `.claude/worktrees/slice1b2-finish/.superpowers/sdd/2026-08-27-task4-receipt-closure/` — a dead pointer (`git worktree list` shows no such worktree; the dir is an empty stub, and the repo's own `.superpowers/sdd/2026-08-27-task4-receipt-closure/` is also empty). The ONLY complete copy (~140 files, including the review diffs) survives at `/home/user/.local/state/p11scope/retired-generated-slice1b2-finish/.superpowers/sdd/2026-08-27-task4-receipt-closure/` — a non-durable location per spec §4. Copy the FULL directory into the repo's `.superpowers/sdd/2026-08-27-task4-receipt-closure/` AND mirror it into `/home/user/src/m/p11scope-ws/preserved/sdd/2026-08-27-task4-receipt-closure/` (the durable home). The 3-file `stage3a3/` subset inside `/home/user/.local/state/p11scope/pkcs11-scope-portable-b86d4d5.tar.zst` (verified present: `stage3a3-green6-report.md` 2134 B, `stage3a3-green6-final-review.md` 1006 B, `progress.md` 137536 B) serves as the integrity cross-check, not the source.
- [ ] **Step 2:** Verify the two named reports exist, are non-empty, and match the tarball copies byte-for-byte; record sha256 of all three.
- [ ] **Step 3:** Edit index :66-70 to repoint at `.superpowers/sdd/2026-08-27-task4-receipt-closure/` and add one sentence: the durable copy lives in `p11scope-ws/preserved/`, with the portable package holding the 3-file `stage3a3/` subset.
- [ ] **Step 4:** Mirror the wave's design authority into the durable root too: copy `/home/user/.local/state/p11scope/security-scan-3e10be9/findings.json` to `p11scope-ws/preserved/security-scan-3e10be9/findings.json` (this plan's Spec pointer must survive a machine move).
- [ ] **Step 5:** Make the initial commit in `/home/user/src/m/p11scope-ws` (the repo is git-initialized but has ZERO commits — `evidence/`, `preserved/`, `incoming/` are all untracked; "custody" with no git history is one `rm -rf` from unrecoverable). **FIRST create `p11scope-ws/.gitignore`** covering `incoming/`, `vm-bases/`, `preserved/evidence-roots/`, `preserved/portable/`, `*.tar.zst`, `*.qcow2`, `*.img` — `incoming/` alone is 9.6 GB of capture roots and must NEVER enter the git object store. Then commit: the `.gitignore`, `README.md`, `preserved/` text (the sdd trove and loose .md files), and the Step 1/4 mirrors' text + a `MANIFEST.sha256` for anything the ignore rules exclude. Text and manifests in git; large binaries manifested, never committed (W2 extends this).
- [ ] **Step 6:** Permissions: `chmod 0700 /home/user/p11scope-vm-bases` (currently 0755; mitigation only — the parent `/home/user` is 0750 so exposure is group-scoped, and the audit's key-rotation item stays open under the spec §4 migration wave, this does not un-leak anything) and `chmod 0600 /home/user/.local/state/p11scope/pkcs11-scope-portable-b86d4d5.tar.zst` (currently 0664; its siblings and its own extracted contents are 0600).
- [ ] **Step 7:** Track the privacy fence: the rule ignoring `.superpowers/sdd/` lives only in an UNTRACKED nested `.superpowers/sdd/.gitignore` (`*`) — a fresh clone would happily `git add -A` private evidence. Add `.superpowers/sdd/` to the tracked root `.gitignore`.
- [ ] **Step 8:** Run all four gates (docs-only in the public repo, still run), commit `docs: repoint Stage 3A3 evidence to the canonical sdd copy and fence private evidence`.

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
- [ ] **Step 3:** Update memory: mark wave 1 closed, record the new tip and package hash. The authority for what comes next is the **ROADMAP §"Release program" wave table (W2–W8)** — do not re-derive a next-wave list here; note only that W2 (storage consolidation) is next and that research #1 (tracepoint offsets — literals at `crates/ebpf/src/main.rs:1704,1707`) and #2 (opened-file inode identity) land in W3.

## Self-Review

- **Spec coverage:** all 8 findings (Tasks 1-8) + research #3 (Task 6f) + the custody gap the audit surfaced (Task 9) + gates/review/closeout (10-12). Every finding's `remediation` maps to a task. Research #1 (tracepoint offsets) and #2 (opened-file vs maps-inode identity) are explicitly DEFERRED to the next wave and recorded in Task 12 Step 3 — spec §6's definition of done still requires them before release.
- **Placeholder scan:** every code step carries real code or an exact edit locus; the `/* same literal as … */` markers point at existing test fixtures the executor copies, not invented content; no scratchpad/brief pointers remain.
- **Type consistency:** `Scope::Cgroup{id,path,dir}`, `scope::cgroup()`, `MapIndex`, `CaptureWorkBudget::charge/set_deadline`, `CaptureEnd::LimitReached`, `trace::truncated_line -> String`/`evidence_line(…, truncated)`, `render::escape_controls` — names used consistently across tasks.
- **2026-09-01 verification pass (three independent read-only verifiers over HEAD 556f7cf):** all cited line anchors confirmed or corrected in place; the three blocking defects found (Task 6 maps-read gap, Task 5 test destroying the fd's directory, Task 4 ancestry rule vs 775 checkouts + sudo inversion) and both compile-breaks (Task 2 `out_sink` borrow, Task 4 `open_how` non_exhaustive) are fixed above.
