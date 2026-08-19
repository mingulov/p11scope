# Slice 1b-2 Open Issues — Research and Improvement Plan (rev 3, after two reviews)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is **input to the worker already running on `codex/slice1b-1-recovery`**; it proposes, it does not override the owner-approved corrective design. Where it deviates, the deviation is named and needs an owner decision (§ Owner decisions).

**Goal:** Turn the open Slice 1b-2 gates (A verifier, revised B pause, C loader timing, ptrace-free loader events) from `TIMEOUT / INCOMPLETE / UNRUN` into finite results that satisfy the approved corrective design, using the cheapest evidence lanes that still satisfy it, and decide with an experiment how much of the loader-timing machinery the product needs.

**Architecture:** Keep the existing spike (`spike/slice1b2-kernel`: four maps, six programs, frozen A/B oracle) and the loader witness harness. Change what the retained evidence proves wrong (memset-shaped initializer; a sample loop that never waited; VERBOSE-log retry storms; TCG-only VMs), finish the parts of revised Gate B the spike does not have yet (single owner `ARMED → REQUESTED`, coalesced records, drain-to-empty, frozen attach set), add the mandatory product-shaped ptrace-free loader event program, and run the released-glibc / DT_NEEDED precontrols before any qualification matrix. One experiment (Task 8) bounds what "attach-first" protection can and cannot replace.

**Tech Stack:** Rust 1.88 host runner (`aya 0.14.0`), `aya-ebpf 0.2.1` nightly BPF object, QEMU 8.2.2 (KVM optional, TCG retained), Ubuntu 22.04 (5.15.0-187) / 24.04 (6.8.0-137) guests, Docker (glibc/musl containers), GDB witness scripts (Python 3), bash gate scripts, `llvm-objdump` from the nightly `llvm-tools`.

**Spec:** `docs/superpowers/specs/2026-08-18-slice1b2-corrective-live-discovery-design.md` (on `codex/slice1b-1-recovery`, approved at `fd3a0e1`; section numbers below refer to it) and the note `docs/notes/slice1b2-open-issues-and-consequences.md` (issue register I1–I9, packages P1–P5). This plan covers P1, P2, P3 and research questions 1–5. P4/P5 are out of scope (P5 is in progress on the recovery branch; P4 follows 1b-1 landing).

**Execution status (2026-08-19):** Tasks 0–8 and 10 are complete at the
`a227dab` evidence identity plus this documentation handoff. D3 is **no**.
Task 9 is an optional private diagnostic and remains `UNRUN`; it requires a
new, explicit owner activation. The unchecked boxes below are the preserved
execution recipe, not current pending-work indicators.

## Review log

Rev 1 (621 lines) was reviewed 2026-08-18 and returned "useful, not safe to execute". Changes in rev 2, by blocker: (1) Gate A wording — the *incompleteness/ENOSPC* is a logging+speed artifact, the rejection is real; (2) Task 0 curates < 1 MB of harness + canonical finite evidence, tracks no analyses with raw addresses/paths, copies no run/provision/qcow2 directories; (3) the object guard is now path-scoped, base-register-agnostic, alias/spill-tracking, and ignores unrelated `memset` (§4.2); (4) Task 4 implements the whole revised Gate B (§5.2–§5.3, §6.1–§6.2) and fixes the deadline stamping bug; the campaign moved to Task 5 on one final frozen A/B object; (5) the ptrace-free loader event program is mandatory (Task 7) with the approved nonzero-sentinel cookie (§7.3); only relocation-witness/catalog lanes are conditional (Task 9); (6) the attach-first experiment (Task 8) tests hidden-table providers and claims only what it measures. Order follows the reviewer's shortest order.

Rev 2 review (2026-08-18) returned NEEDS FIXES with seven items; rev 3 resolves them: (1) the evidence manifest is generated outside the tree and excludes itself, globs are asserted unique; (2) the guard is sound by construction — after the reserve and its single null-check the region must be straight-line (any branch/jump/call before the 112th store is FAIL), duplicates are FAIL, spills/reloads must be u64 — re-tested RED/GREEN; (3) `AtomicU64::compare_exchange` does not exist on `bpfel-unknown-none` (`target_has_atomic_load_store="64"` only) — verified; the plan now uses `core::intrinsics::atomic_cxchg`, verified to emit `cmpxchg_64` with the frozen nightly, and the `target-cpu=v3` fallback is gone; (4) the pause owner is removed immediately after the one successful resume, an RAII owner guard covers every failure path with failure-injection tests, and the second record wait shares the causal 100 ms deadline; (5) all loader host/common/BPF code lives in its own artifact so the A/B artifact frozen in Task 5 is never touched again; (6) the loader program uses the existing 896-byte `DiscoveryRecord` + status flags with the same initializer guard, declares its full map/program inventory incl. the `START` pause owner key, and is proved on Jammy 5.15 and Noble 6.8; (7) the `initial_set` precontrol classifies the first hit at which the exact target DSO mapping exists, and Task 9 uses exactly one fixed-glibc candidate (four controls). Smaller corrections applied (≈2.8 MiB curated set; commits are after 2.40 and before 2.41; `apt-get source` unpacks; separate `cargo test` invocations; Task 10 keeps retained TIMEOUT/INCOMPLETE; privileged approval split per lane).

## What this plan adds to the note (facts established 2026-08-18)

1. **The spike VMs run under pure TCG.** `spike/slice1b2-kernel/run.sh:605` uses `-accel tcg,thread=multi -cpu max`; `/dev/kvm` exists on this host (AMD-V, `kvm_amd` loaded, QEMU 8.2.2 lists `kvm`), but the user is not in group `kvm`. Verifier *verdicts* are deterministic per kernel; their duration is TCG-inflated. Gate A's fourth program is genuinely rejected (Jammy: rejection after ≈202 s with a 16.7 MB log; Noble: no verdict inside 600 s) — what is an artifact is that the tracked result is `TIMEOUT / INCOMPLETE` instead of a canonical verdict, and that the initial errno is unknown. Gate B's Jammy variance has TCG scheduling as a named amplifier (`slice1b2-gateb-variance-analysis.md`, hypothesis 2).
2. **Aya's load path re-verifies a failing program up to 11 times.** `aya-0.14.0/src/sys/bpf.rs:1404-1434`: attempt 1 with no log, then 10 KiB → 100 KiB → 1 MiB → 10 MiB → 16,777,215 B (clamped), then repeats at the clamp until 10 retries; the runner asks for `VERBOSE | STATS` (`spike/slice1b2-kernel/src/main.rs:1908,2403`). That is where the 16,777,679-byte `ENOSPC` and the *discarded initial errno* (I1/I2) come from. A single load with `VerifierLogLevel::STATS` only prints the failure reason plus `processed N insns (limit 1000000) … peak_states …` in a few hundred bytes — the "bounded finite failure facts" I2 asks for. This is diagnostic evidence, never the tracked gate.
3. **Both glibc bug-31986 commits are in glibc 2.41.** Verified via the GitHub mirror compare API: `43db5e2c` (2024-10-25, "elf: Signal RT_CONSISTENT after relocation processing in dlopen (bug 31986)") and `ac73067c` (2024-10-25, "elf: Fix map_complete Systemtap probe in dl_open_worker") are 263/264 commits *after* the `glibc-2.40` tag and ancestors of `glibc-2.41` (i.e. first released in 2.41) (released 2025-01-30, <https://sourceware.org/pipermail/libc-announce/2025/000045.html>). Debian 13 ships libc6 2.41 (<https://packages.debian.org/trixie/libc6>); an official `ubuntu:26.04` image exists (<https://hub.docker.com/_/ubuntu/tags>). "≥ 2.41" is not authority (§7.2): it selects which lanes to run; package source provenance plus the runtime witness classify. The commit message also states initial startup (`elf/rtld.c`, end of `dl_main`) already signalled `RT_CONSISTENT` after relocation → the DT_NEEDED/initial-set lane is expected positive even on 2.35/2.39.
4. **The loader witness harness lives only in `/tmp`** (`/tmp/p11scope-slice1b2-loader-spikes/round2/`, 8 files, 457 lines) with the analyses the design pins by SHA-256. The raw spike directories total ≈16 GB (provision runs, qcow2 overlays); the curated canonical set is ≈2.8 MiB (the retained runner/fixture/BPF bundle alone is 2.3 MiB; the loader harness + transcripts < 1 MB).

## Global Constraints

- Rust 1.88, edition 2024, Linux x86-64-first; the spike BPF object builds with the frozen nightly (`rustc 1.97.0-nightly (e50aa6fba 2026-05-19)`, `-Z build-std=core`, `bpfel-unknown-none`); no new dependencies.
- **Do not work inside `/home/user/src/m/pkcs11-scope-codex-slice1b-1`** — a worker commits there live (`906753a` landed during this analysis). Base: `codex/slice1b-1-recovery` at execution-time tip; this plan touches only `spike/`, `docs/notes/slice1b2*`, and `docs/superpowers/plans/ROADMAP.md` (status line). Second executor: worktree `.claude/worktrees/slice1b2-gates`, branch `spike/slice1b2-gates`; the recovery-branch worker: its own branch.
- All four repo checks stay green at every commit (`cargo +1.88 fmt --all -- --check`, `check --locked`, `test --locked`, `clippy --locked -- -D warnings`); also `cargo test` and `cargo clippy -- -D warnings` inside `spike/slice1b2-kernel` after every runner change; `bash -n spike/slice1b2-kernel/run.sh` after every script change.
- **Privileged experiments need explicit owner approval, split by concrete lane** (`CLAUDE.md`): (a) VM lanes with `sudo` inside the retained guests — Tasks 2, 3, 5, 7; (b) diagnostic root runs on the host kernel `7.0.0-28-generic` (not an endpoint) — Tasks 2, 7, 8; (c) Docker lanes with `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined` — Task 6; (d) the one-time KVM enablement — Task 1; (e) Task 8's `loader-protect` runs (host root + guests); Task 9 asks separately when its steps are written. Record UNRUN for any lane not approved.
- Frozen-gate discipline (§3, §4.3, §6.2): the tracked Gate A/B oracles, 120 s inner bound, 8 MiB/16 MiB caps, `VERBOSE | STATS`, literal `< 104` / `< 16`, four maps, `BPF_NOEXIST`, submit-after-init do **not** change. Diagnostic lanes are labelled diagnostic and are never promoted; a PASS is claimed only from the unchanged frozen gate on the final frozen A/B bytes (Task 5). Any A/B BPF/runner/fixture/validator change creates a new campaign identity.
- Privacy: no raw verifier log, PID/TID, task set, runtime address, cookie, delta, context ID or guest path in tracked files; raw evidence stays outside git under `~/src/m/pkcs11-scope-evidence/slice1b2/` (mode 0700) with a SHA-256 manifest; tracked docs carry digests and finite facts only. Do not track generated output (BPF objects, binaries, qcow2, tarballs, transcripts).
- §5, §7 invariants: hooks never call provider/loader code; a BPF read failure is finite evidence, never a silent procfs fallback; only the observer's owned `run` child is ever stopped; reservation precedes authorization consumption; one original-pidfd resume.

---

## Order and effort

| # | Task | Depends on | Effort | Closes / informs |
| --- | --- | --- | --- | --- |
| 0 | Curate harness + canonical finite evidence (≈2.8 MiB) | — | 1 h | reproducibility, evidence pointers |
| 1 | KVM lane (optional speed; owner approval) | approval | 1–2 h | A/B/C lane duration, Q4 diagnostic |
| 2 | `gate-a-diag` STATS-only verdict lane (diagnostic) | — | 3 h | I1, I2, Q1 |
| 3 | Gate A initializer (112 flat volatile stores) + §4.2-compliant semantic guard | 2 | 4–6 h | P1 |
| 4 | Revised Gate B in full: owner protocol, coalescing, drain closure, real 100 ms timeline | 3 | 1.5–2 d | P2, I7 |
| 5 | Final A/B campaign on one frozen object: Gate A ×2 kernels, Gate B 3 boots × 20 × 2 | 3, 4 | 1 d (VM time) | P1/P2 tracked results, Q4, Q5 |
| 6 | Released-glibc (2.41+) and DT_NEEDED precontrols in containers | 0 | 4 h | Q2, Q3, P3 inputs |
| 7 | Mandatory minimal ptrace-free loader event program (§7.3 cookie, every-hit record) | 3 | 1–2 d | I6, P3/P4 prerequisite |
| 8 | Attach-first experiment (hidden-table fixture) + memo | 4, 6, 7 | 1–2 d | design scope of P3/P4 (D3) |
| 9 | Dormant private relocation-witness diagnostic (§8, 12 rows) | 7, 8, new approval | 2–3 d | optional comparison only |
| 10 | Update the note, ROADMAP status, hand-off | all | 1 h | — |

Task 6 (containers) runs in parallel with 2–5 (VMs). Do not add kernels (note § "Do we need more kernels?" stands).

---

### Task 0: Curate the loader harness and the canonical finite evidence

**Files:**
- Create: `spike/slice1b2-loader/{dso.c,fixture.c,rdebug-layout.c,elf_meta.py,gdb-direct-witness.py,inside.sh,run-lanes.sh,CANONICAL-EVIDENCE.md}` (tracked; ≈460 lines, no evidence)
- Create: `docs/notes/slice1b2/README.md` (tracked; digests, pointers, finite facts only)
- Create outside git: `~/src/m/pkcs11-scope-evidence/slice1b2/{analyses,gate-a,gate-b,loader,bundles}/…` + `MANIFEST.sha256`
- Modify: `docs/notes/slice1b2-open-issues-and-consequences.md` § "Authoritative evidence pointers"

**Interfaces:**
- Produces: `spike/slice1b2-loader/run-lanes.sh [LANE_FILTER]` with `P11SCOPE_LOADER_EVIDENCE` (Task 6 extends it); the evidence root + manifest (Tasks 2–9 append to it).

- [ ] **Step 1: Verify the design's pinned inputs before moving them (never edit them)**

```bash
sha256sum /tmp/slice1b2-gatea-corrective-analysis.md /tmp/slice1b2-gateb-variance-analysis.md \
  /tmp/slice1b2-loader-corrective-analysis.md /tmp/slice1b2-corrective-design-cross-review.md
# expected (§2): a8578527… 2abc938c… 89ed5bf3… 31ca2a2f…
```

- [ ] **Step 2: Copy only the small, canonical items — no run/provision directories, no qcow2, no analyses into git**

```bash
E=~/src/m/pkcs11-scope-evidence/slice1b2; install -d -m 0700 "$E"/{analyses,gate-a,gate-b,loader,bundles}
cp /tmp/slice1b2-*.md "$E/analyses/"                                    # analyses: outside git (raw addresses/paths)
cp -a /tmp/p11scope-slice1b2-task2-fd98a02-gatea-*-evidence* "$E/gate-a/" # six-file inventories + .sha256 (16 KiB each)
cp -a /tmp/p11scope-slice1b2-task2-fd98a02-diagnostic-*-evidence* "$E/gate-a/" 2>/dev/null || true
cp -a /tmp/p11scope-slice1b2-task4-37c5b41.*/bundle "$E/bundles/task4-37c5b41-bundle"   # frozen runner/fixture/BPF, few MB
cp -a /tmp/p11scope-slice1b2-loader-spikes/round2 "$E/loader/round2"       # sources, canonical transcripts, artifacts (< 1 MB)
mkdir -p spike/slice1b2-loader
cp /tmp/p11scope-slice1b2-loader-spikes/round2/{dso.c,fixture.c,rdebug-layout.c,elf_meta.py,gdb-direct-witness.py,inside.sh,run-lanes.sh,CANONICAL-EVIDENCE.md} spike/slice1b2-loader/
for g in /tmp/p11scope-slice1b2-task2-fd98a02-gatea-*-evidence /tmp/p11scope-slice1b2-task4-37c5b41.*/bundle; do set -- $g; [ $# -eq 1 ] || { echo "glob $g resolved $# times"; exit 64; }; done   # each source glob exactly once
tmp=$(mktemp -p /tmp/claude-1000 manifest.XXXXXX)   # generate outside $E; the manifest never hashes itself
(cd "$E" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum) >"$tmp" && install -m 0600 "$tmp" "$E/MANIFEST.sha256" && rm -f "$tmp"
du -sh "$E"   # expected: ≈2.8 MiB (bundle 2.3 MiB)
grep -nE '0x[0-9a-f]{8,}|/tmp/p11scope|known_hosts|ssh-' spike/slice1b2-loader/* && echo 'scrub before commit' || echo clean
```
Task 2/4 Gate B raw exports (`signal-timing.jsonl` etc.) are private spike bundles (§9.4): copy the `*-evidence*` export directories only if they exist under `/tmp` at curation time, else record their retained digests from the task reports.

- [ ] **Step 3: Make `run-lanes.sh` repo-relative and lane-filterable**

Replace the two hard-coded paths at the top of `spike/slice1b2-loader/run-lanes.sh`:

```bash
repo=$(cd "$(dirname "$0")/../.." && pwd)
root=$(cd "$(dirname "$0")" && pwd)
evidence=${P11SCOPE_LOADER_EVIDENCE:-$HOME/src/m/pkcs11-scope-evidence/slice1b2/loader}
install -d -m 0700 "$evidence/round2/artifacts"
cp "$root"/{dso.c,fixture.c,rdebug-layout.c,elf_meta.py,gdb-direct-witness.py,inside.sh} "$evidence/round2/"
filter=${1:-}   # empty = all lanes; otherwise a lane-name substring
```
change every `-v /tmp/p11scope-slice1b2-loader-spikes:/evidence` to `-v "$evidence":/evidence`, transcript paths to `"$evidence/${lane}-transcript.log"`, and guard each `run_lane` call with `[[ -z $filter || $lane == *$filter* ]] || return 0` semantics (skip, not fail).

- [ ] **Step 4: Write `docs/notes/slice1b2/README.md`, repoint the note, commit**

README content: the four pinned digests, the evidence root layout, `MANIFEST.sha256` digest, and a two-line status per gate (copied from the note). In the note § "Authoritative evidence pointers", replace `/tmp/...` paths with `~/src/m/pkcs11-scope-evidence/slice1b2/<dir>` and add `spike/slice1b2-loader/` for the harness.

```bash
git add spike/slice1b2-loader docs/notes/slice1b2 docs/notes/slice1b2-open-issues-and-consequences.md
git commit -m "spike/docs: track the slice 1b-2 loader witness harness; curated evidence root + manifest outside git; repoint the note"
```

---

### Task 1: KVM acceleration for the spike VMs (optional; owner approval)

**Files:**
- Modify: `spike/slice1b2-kernel/run.sh:605-609` (QEMU command), `gate_lane` (guest `virt.txt`), usage line `:1344`

**Interfaces:**
- Produces: env `P11SCOPE_SPIKE_ACCEL=kvm|tcg` (default **`tcg`** — the frozen behaviour — unless the owner sets `kvm`); `$run_dir/host-accel.txt`; guest `virt.txt` (`systemd-detect-virt`: `kvm` vs `qemu`) in every lane run dir. Tasks 2–5 record `accel` in their evidence; TCG and KVM lanes are different campaign identities and are never mixed inside one campaign.

- [ ] **Step 1: One-time host change (owner approval), then verify**

Persistent: `sudo usermod -aG kvm user`, run lanes via `sg kvm -c '…'` (no re-login). Non-persistent alternative: `sudo setfacl -m u:user:rw /dev/kvm`. Verify: `test -w /dev/kvm && echo ok`.

- [ ] **Step 2: Select the accelerator in `private_start_lane`**

Replace the `qemu-system-x86_64 -accel tcg,thread=multi -cpu max …` line with:

```bash
    local accel_name=${P11SCOPE_SPIKE_ACCEL:-tcg}
    local -a accel
    case "$accel_name" in
        kvm) [[ -w /dev/kvm ]] || return 64; accel=(-accel kvm -cpu host) ;;
        tcg) accel=(-accel tcg,thread=multi -cpu max) ;;
        *) return 64 ;;
    esac
    printf 'accel=%s\n' "$accel_name" >"$run_dir/host-accel.txt" || return 64
    qemu-system-x86_64 "${accel[@]}" -machine q35 -m 1024 -smp 2 \
```
(the identity check at `run.sh:656-658` compares only the binary basename and the drive argument, so it keeps working).

- [ ] **Step 3: Record the guest's view of virtualization**

Right after the bundle-hash `cmp` in `gate_lane` (and in `diag_lane`, Task 2):

```bash
    strict_ssh "$PRIVATE_KNOWN_HOSTS" "$PRIVATE_PORT" 'systemd-detect-virt; uname -r' >"$run_dir/virt.txt" 2>&1 || gate_rc=64
```
Expected content: `kvm` (KVM lanes) or `qemu` (TCG lanes) + kernel string.

- [ ] **Step 4: Verify both guests boot under KVM and time it; commit**

Run one `diag-lane` (Task 2) per guest with `P11SCOPE_SPIKE_ACCEL=kvm`; record `virt.txt` and boot-to-SSH wall time next to the TCG figure in `docs/notes/slice1b2/README.md`. Expected: `virt.txt` = `kvm`, boot-to-SSH < 60 s.

```bash
git commit -am "spike: optional KVM lane (P11SCOPE_SPIKE_ACCEL=kvm; default stays tcg); guest virt.txt"
```

---

### Task 2: Gate A canonical verdict lane (`gate-a-diag`, STATS-only, diagnostic)

**Files:**
- Modify: `spike/slice1b2-kernel/src/main.rs` (`main` dispatch `:2508-2513`, new `diag_line`, `run_gate_a_diag`)
- Modify: `spike/slice1b2-kernel/run.sh` (new `diag_lane`, usage)
- Test: `spike/slice1b2-kernel/src/main.rs` unit test `gate_a_diag_line_has_finite_fields`

**Interfaces:**
- Produces: `slice1b2-runner gate-a-diag BPF_PATH OUT_DIR` → `OUT_DIR/diag.jsonl`, one object per program: `{program, accepted, duration_ms, errno|null, verified_insns|null, log_bytes, log_tail}`; `run.sh diag-lane LANE BUNDLE NEW_RUN_DIR`. Task 3 reruns it on the fixed object; Task 10 quotes it. **Diagnostic only** (D2): it never replaces the frozen `gate-a-lane` result.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn gate_a_diag_line_has_finite_fields() {
    let line = diag_line("interface_list_return", Err((Some(7), "processed 1000001 insns (limit 1000000) max_states_per_insn 4 total_states 25000 peak_states 2000 mark_read 90".to_string())), 1234);
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["program"], "interface_list_return");
    assert_eq!(v["accepted"], false);
    assert_eq!(v["errno"], 7);
    assert_eq!(v["duration_ms"], 1234);
    assert!(v["log_tail"].as_str().unwrap().contains("processed 1000001 insns"));
    assert!(v["log_bytes"].as_u64().unwrap() < 4096);
}
```
Run: `cd spike/slice1b2-kernel && cargo test gate_a_diag_line_has_finite_fields` → FAIL (`diag_line` undefined).

- [ ] **Step 2: Implement `diag_line` and `run_gate_a_diag`**

```rust
/// One finite JSON line per program: no raw verifier text beyond a 2 KiB tail.
fn diag_line(program: &str, outcome: Result<Option<u32>, (Option<i32>, String)>, duration_ms: u128) -> String {
    let mut v = serde_json::Map::new();
    v.insert("program".into(), program.into());
    v.insert("duration_ms".into(), u64::try_from(duration_ms).unwrap_or(u64::MAX).into());
    match outcome {
        Ok(insns) => {
            v.insert("accepted".into(), true.into());
            v.insert("verified_insns".into(), insns.into()); // None on 5.15 (bpf_prog_info field added in 5.16)
        }
        Err((errno, log)) => {
            v.insert("accepted".into(), false.into());
            v.insert("errno".into(), errno.into());
            v.insert("log_bytes".into(), (log.len() as u64).into());
            let tail: String = log.chars().rev().take(2048).collect::<Vec<_>>().into_iter().rev().collect();
            v.insert("log_tail".into(), tail.into());
        }
    }
    serde_json::Value::Object(v).to_string()
}

fn run_gate_a_diag(bpf_path: &str, out_dir: &str) -> Result<bool, &'static str> {
    std::fs::create_dir_all(out_dir).map_err(|_| "out dir")?;
    let bytes = std::fs::read(bpf_path).map_err(|_| "bpf read")?;
    let mut sink = std::fs::File::create(format!("{out_dir}/diag.jsonl")).map_err(|_| "diag file")?;
    let mut loader = aya::EbpfLoader::new();
    loader.verifier_log_level(aya::VerifierLogLevel::STATS); // no per-insn text; failure reason + stats only
    let mut ebpf = loader.load(&bytes).map_err(|_| "object load")?;
    let mut all = true;
    for name in GATE_A_PROGRAMS {
        let started = Instant::now();
        let outcome: Result<Option<u32>, (Option<i32>, String)> = match ebpf.program_mut(name) {
            None => Err((None, "program missing".into())),
            Some(program) => match <&mut aya::programs::UProbe>::try_from(program) {
                Err(error) => Err((None, error.to_string())),
                Ok(program) => match program.load() {
                    Ok(()) => Ok(program.info().ok().and_then(|info| info.verified_instruction_count())),
                    Err(aya::programs::ProgramError::LoadError { io_error, verifier_log }) => {
                        Err((io_error.raw_os_error(), verifier_log.to_string()))
                    }
                    Err(other) => Err((None, other.to_string())),
                },
            },
        };
        all &= outcome.is_ok();
        writeln!(sink, "{}", diag_line(name, outcome, started.elapsed().as_millis())).map_err(|_| "diag write")?;
    }
    Ok(all)
}
```
Dispatch: `Some("gate-a-diag") if args.len() == 4 => run_gate_a_diag(&args[2], &args[3]),`. Exit code 0 = all accepted, 1 = some rejected, 64 = runner error.

- [ ] **Step 3: Unit test + clippy green; commit the runner**

- [ ] **Step 4: Add `diag_lane` to `run.sh`**

Model on `gate_lane` (`run.sh:847-949`) without the six-file export/validator: `validate_execution_bundle`, flock, `private_arm_lane_traps`, `private_start_lane`, scp `slice1b2-kernel-ebpf` + `slice1b2-runner`, host/guest sha256 `cmp`, `virt.txt`, then

```bash
        remote_command="sudo -n timeout --signal=TERM --kill-after=5s 600s $remote/slice1b2-runner gate-a-diag $remote/slice1b2-kernel-ebpf /var/tmp/p11scope-slice1b2/diag"
        if timeout 660s "${ssh[@]}" p11scope@127.0.0.1 "$remote_command" >"$run_dir/diag.stdout" 2>"$run_dir/diag.stderr"; then rc=0; else rc=$?; fi
        printf '%s\n' "$rc" >"$run_dir/diag.status"
        timeout 120s "${scp[@]}" "p11scope@127.0.0.1:/var/tmp/p11scope-slice1b2/diag/diag.jsonl" "$run_dir/diag.jsonl" || rc=64
```
One cleanup path (`private_cleanup_lane`, `private_disarm_lane_traps`) on every return; the 600 s inner bound is deliberately generous — this lane must *finish*. Add `diag-lane) diag_lane "$2" "$3" "$4" ;;` to dispatch and usage; `bash -n run.sh`.

- [ ] **Step 5: Run it on the retained final object (and optionally the host kernel)**

```bash
# bundle = the retained Task 4 bundle (BPF d405edee…) re-frozen with the new runner via `run.sh freeze-execution …`
run.sh diag-lane jammy "$BUNDLE" ~/src/m/pkcs11-scope-evidence/slice1b2/gate-a/diag-jammy-$(date +%Y%m%dT%H%M%S)
run.sh diag-lane noble "$BUNDLE" ~/src/m/pkcs11-scope-evidence/slice1b2/gate-a/diag-noble-$(date +%Y%m%dT%H%M%S)
# host 7.0.0-28 (not an endpoint; approval): sudo target/release/slice1b2-runner gate-a-diag "$BUNDLE/slice1b2-kernel-ebpf" …/gate-a/diag-host
```
Expected: three `accepted=true` lines with `verified_insns` (6.8/7.0; `null` on 5.15) and one line for `interface_list_return` with a real `errno` (likely `7`/E2BIG "BPF program is too large. Processed 1000001 insn", or `13`/EACCES with a specific complaint) and a `log_tail` ≤ 2 KiB — in seconds under KVM, minutes under TCG. Append to the manifest; quote errno / insns / peak_states in `docs/notes/slice1b2/README.md` under "diagnostic". Commit script.

Why: `verified_insns` of `function_list_return` (one 896-byte init + one ≤104 read loop) is the per-fan-out cost; ×16 predicts *before* Task 5's VM runs whether the flat initializer alone brings `interface_list_return` under the 1 M-insn limit (research question 1).

*Already observed on the host kernel 7.0.0-28 (diagnostic, not an endpoint) while validating the aya fix below:* the retained object's `interface_list_return` is rejected with **errno 7 (E2BIG)** — "BPF program is too large. Processed 1000001 insn", `max_states_per_insn 41 total_states 10774 peak_states 1004`, ~99 s per verification pass at `VERBOSE` — while `function_list_return` is accepted in 28 ms. So the canonical verdict on this kernel is the complexity limit, not an invalid access; the flat initializer removes the dominant 896×16 byte-loop cost, and Task 2's per-program `verified_insns` on 5.15/6.8 will show how much headroom remains.

*Upstream aya fix (prepared 2026-08-18, branch `verifier-log-retry`, commit `be68256` in the local clone):* the retry loop now returns the log-less first attempt's error (the verdict) instead of `ENOSPC`, stops at the maximum buffer instead of re-verifying at 16 MiB six more times, and sizes the retry from `log_true_size` on kernels ≥ 6.4 — three verifications instead of eleven on the same object. Once merged and released, the spike may pin that aya version at a **new** campaign identity; until then D2's STATS lane stands.

---

### Task 3: Gate A initializer (112 flat volatile stores) + §4.2-compliant semantic guard (P1)

**Files:**
- Modify: `spike/slice1b2-kernel/ebpf/src/main.rs:101-106` (zero-init loop in `emit_discovery`)
- Create: `spike/slice1b2-kernel/check-init-shape.py`
- Modify: `spike/slice1b2-kernel/src/main.rs:4569-4650` (text guard `ebpf_source_freezes_six_program_four_map_signal_contract`)
- Modify: `spike/slice1b2-kernel/run.sh` `build_bpf` (run the guard after the build)

**Interfaces:**
- Consumes: `run.sh diag-lane` (Task 2).
- Produces: `check-init-shape.py OBJ [LLVM_OBJDUMP]` exit 0/1; a new (intermediate) BPF object digest — the *final* A/B object is frozen in Task 5 after Task 4.

- [ ] **Step 1: RED — write the path-scoped guard and prove it FAILs on the retained object**

Contract (§4.2), made sound by construction: on the reservation-to-use path of the 896-byte record inside `emit_discovery`, (1) **exactly** 112 aligned u64 zero stores (no duplicates) cover record offsets {0, 8, …, 888}, tracked through **every** register that aliases the reserved pointer (any base register, copies, constant adjustments, u64 stack spills/reloads); (2) after the reserve and its single null-check branch the region is **straight-line** — any branch, jump or call before the 112th store is FAIL — so every path that reaches a record use executed all 112 stores; no record load or non-zero record store before completion; (3) no `memset` relocation inside the region. Unrelated `memset` or back edges elsewhere in the ELF are not checked; no instruction spelling or store order is required.

```python
#!/usr/bin/env python3
"""Semantic initializer guard for the 896-byte DiscoveryRecord (corrective design §4.2).
Scope: emit_discovery, from `call bpf_ringbuf_reserve` (helper 131, r2 == 896) until exactly 112
distinct aligned u64 zero stores have covered record offsets 0..888. Sound because the region must be
straight-line: after the reserve and its single null-check branch, any branch, jump or call before
the 112th store is FAIL, so every path that reaches a record use ran all 112 stores. Duplicate stores
are FAIL. Base-register agnostic (aliases, +=, u64 spills/reloads). Unrelated memset/back edges
elsewhere in the ELF are not checked. Exit 0 PASS, 1 FAIL."""
import re, subprocess, sys

obj = sys.argv[1]
objdump = sys.argv[2] if len(sys.argv) > 2 else "llvm-objdump"
out = subprocess.run([objdump, "-dr", "--no-show-raw-insn", obj], capture_output=True, text=True, check=True).stdout
m = re.search(r"^[0-9a-f]+ <\S*emit_discovery>:\n", out, re.M)      # symbol may be mangled
if not m:
    sys.exit("FAIL: emit_discovery not found")
lines = out[m.end():].split("\n\n", 1)[0].splitlines()

RELOC = re.compile(r"^\s*[0-9a-f]{16}:\s+R_BPF_\S+\s+(\S+)")
NUM = r"(?:0x[0-9a-f]+|-?\d+)"
STORE = re.compile(rf"\*\((u8|u16|u32|u64) \*\)\((r\d+) ([+-]) ({NUM})\) = (r\d+|{NUM})$")
LOAD = re.compile(rf"(r\d+) = \*\((u8|u16|u32|u64) \*\)\((r\d+) ([+-]) ({NUM})\)$")
NEEDED = set(range(0, 896, 8))
val = lambda s: int(s, 0)
off = lambda sign, n: val(n) if sign == "+" else -val(n)


def fail(msg):
    sys.exit(f"FAIL: {msg}")


regs, spills, zero, done = {}, {}, set(), set()   # reg->record offset; stack slot->record offset; zero regs; zeroed offsets
stores, null_check_seen = 0, False
in_region, pending_r2 = False, None
for i, line in enumerate(lines):
    if (r := RELOC.match(line)):
        if in_region and r.group(1) == "memset":
            fail("memset relocation inside the initializer region")
        continue
    ins = line.split(":", 1)[1].strip() if ":" in line else line.strip()
    ins = re.sub(r" <\S+>$", "", ins)                                # strip branch target symbol
    if not in_region:                                                # before the reserve: only track zero registers
        if (m := re.fullmatch(rf"r2 = ({NUM})", ins)):
            pending_r2 = val(m.group(1))
        if re.fullmatch(r"call (0x83|131)", ins) and pending_r2 == 896:  # bpf_ringbuf_reserve of the 896-byte record
            in_region, regs, spills, done, stores, null_check_seen = True, {"r0": 0}, {}, set(), 0, False
            zero -= {"r0", "r1", "r2", "r3", "r4", "r5"}                  # caller-saved; r6-r9 facts survive the call
            continue
        if (m := re.fullmatch(r"(r\d+) = (0x0|0)( ll)?", ins)):
            zero.add(m.group(1))
        elif ins.startswith("call"):
            zero -= {"r0", "r1", "r2", "r3", "r4", "r5"}
        elif (m := re.match(r"(r\d+) ", ins)) and not ins.startswith("if "):
            zero.discard(m.group(1))
        continue
    if (m := re.fullmatch(r"(r\d+) = (r\d+)", ins)) and m.group(2) in regs:
        regs[m.group(1)] = regs[m.group(2)]; zero.discard(m.group(1)); continue
    if (m := re.fullmatch(rf"(r\d+) \+= ({NUM})", ins)) and m.group(1) in regs:
        regs[m.group(1)] += val(m.group(2)); continue
    if (m := re.fullmatch(r"(r\d+) = (0x0|0)( ll)?", ins)):
        zero.add(m.group(1)); regs.pop(m.group(1), None); continue
    if (m := STORE.fullmatch(ins)):
        width, base, sign, n, v = m.groups()
        if base == "r10" and v in regs:
            if width != "u64":
                fail(f"narrow spill of a record alias: {ins}")
            spills[off(sign, n)] = regs[v]; continue                # u64 spill of an alias
        if base in regs:
            o = regs[base] + off(sign, n)
            if width == "u64" and (v in zero or (not v.startswith("r") and val(v) == 0)):
                if o in done:
                    fail(f"duplicate zero store at record offset {o}: {ins}")
                done.add(o); stores += 1
            else:
                fail(f"non-zero or narrow record store before initialization complete: {ins}")
            if done >= NEEDED and stores == 112:
                break                                              # region complete: exactly 112 distinct stores
        continue
    if (m := LOAD.fullmatch(ins)):
        dst, width, base, sign, n = m.groups()
        if base == "r10" and off(sign, n) in spills:
            if width != "u64":
                fail(f"narrow reload of a record alias: {ins}")
            regs[dst] = spills[off(sign, n)]; zero.discard(dst); continue
        if base in regs:
            fail(f"record load before initialization complete: {ins}")
        regs.pop(dst, None); zero.discard(dst); continue
    if ins.startswith("call"):
        target = lines[i + 1] if i + 1 < len(lines) else ""
        rr = RELOC.match(target)
        if rr and rr.group(1) == "memset":
            fail("memset relocation inside the initializer region")
        fail(f"call before the initializer completed: {ins}")
    if (m := re.fullmatch(r"if (r\d+) == (0x0|0) goto \+\S+", ins)) and m.group(1) in regs and not null_check_seen and not done:
        null_check_seen = True; continue                           # the single reserve-failure branch
    if ins.startswith("if ") or ins.startswith("goto"):
        fail(f"branch inside the initializer region (region must be straight-line): {ins}")
    if (m := re.match(r"(r\d+) ", ins)):                            # any other definition kills the alias/zero fact
        regs.pop(m.group(1), None); zero.discard(m.group(1))
else:
    if in_region:
        fail(f"initializer incomplete: {len(done)}/112 offsets; missing {sorted(NEEDED - done)[:6]}…")
    fail("no 896-byte bpf_ringbuf_reserve found in emit_discovery")
print("PASS: 112 aligned u64 zero stores at record offsets 0..888 before any record use; no memset / back edge in the region")
```
Run on the retained final object:
```bash
rustup component add llvm-tools --toolchain nightly
OBJDUMP=$(rustc +nightly --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objdump
python3 spike/slice1b2-kernel/check-init-shape.py ~/src/m/pkcs11-scope-evidence/slice1b2/bundles/task4-37c5b41-bundle/slice1b2-kernel-ebpf "$OBJDUMP"
```
Expected: `FAIL: memset relocation inside the initializer region` (retained disassembly: insns 10-13 `call -0x1` + `R_BPF_64_32 memset` right after `call 0x83`).

*Already verified while writing this plan (scratch, unprivileged, not evidence):* the script above (this exact rev-3 version: straight-line, duplicate-rejecting) returns exactly that FAIL on the retained object `d405edee…` (Ubuntu `llvm-objdump` 18.1.3 output format: mangled `<…14emit_discovery>:` symbol, hex immediates, `call 0x83` for helper 131) — and returns PASS on a scratch build of the Step 2 change with the frozen nightly `e50aa6fba`, which emitted `r8 = 0x0` **before** the reserve and 112 straight-line `*(u64 *)(r6 + 0x0..0x378) = r8` stores. Both objects also contain one *unrelated* 20-byte `memset` relocation in `function_list_return` (a program that already loads on both kernels), which is why the guard must be path-scoped and must not assert object-wide `memset` absence. If the tracker loses the alias for a reason the disassembly shows, extend the tracker — do not weaken a predicate.

- [ ] **Step 2: Replace the loop with 112 flat volatile stores (§4.1)**

In `ebpf/src/main.rs`, above `fn emit_discovery`:

```rust
/// Corrective design §4.1: exactly 112 straight-line `write_volatile(words.add(K), 0u64)` calls,
/// K = 0..=111, each once. Volatile keeps LLVM from re-folding them into `memset`, whose BPF
/// lowering is an 896-iteration byte loop that exhausts the verifier under the 16-interface fan-out.
macro_rules! zero_words {
    ($words:expr; $($k:literal),* $(,)?) => { $( core::ptr::write_volatile($words.add($k), 0u64); )* };
}
```
and inside the existing `unsafe` block replace `while word < 112 { … }` with

```rust
        zero_words!(words;
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
            80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
            96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
        );
```
Nothing else in `emit_discovery` changes (record layout, `< 104`, fail-closed `usable_n`, submit outside the block).

- [ ] **Step 3: Update the source text guard to assert the exact index set**

In `ebpf_source_freezes_six_program_four_map_signal_contract` replace the `while word < 112` assertion with:

```rust
    let invocation = ebpf.split("zero_words!(words;").nth(1).expect("zero_words! invocation").split(')').next().unwrap();
    let mut indexes: Vec<usize> = invocation.split(',').map(str::trim).filter(|s| !s.is_empty()).map(|s| s.parse().unwrap()).collect();
    let raw_len = indexes.len();
    indexes.sort_unstable();
    indexes.dedup();
    assert_eq!(raw_len, 112, "each index exactly once");
    assert_eq!(indexes, (0..112).collect::<Vec<_>>(), "complete index set 0..=111");
    assert!(ebpf.contains("core::ptr::write_volatile($words.add($k), 0u64)"));
    assert!(!ebpf.contains("while word < 112"));
```
Run `cargo test` in the spike crate → PASS.

- [ ] **Step 4: Rebuild, run the guard, then the diag lane on both kernels; commit**

```bash
run.sh build-bpf "$NEW_OUT"           # build_bpf gains: python3 "$here/check-init-shape.py" "$object" "$OBJDUMP" || return 64
sha256sum "$NEW_OUT/slice1b2-kernel-ebpf"   # intermediate object digest (final bytes come after Task 4)
run.sh freeze-execution … "$NEW_BUNDLE"; run.sh diag-lane jammy "$NEW_BUNDLE" …; run.sh diag-lane noble "$NEW_BUNDLE" …
```
Expected: guard PASS; `diag.jsonl` shows four `accepted=true` lines on both kernels. If `interface_list_return` is still rejected: record errno / `processed insns` / `peak_states`, **stop**, open D5 — do not touch the 16/104 ceilings, timeouts or caps. Do **not** run the frozen `gate-a-lane` yet: Task 4 changes `signal_return` and the fixture, and §3 requires the exact Gate A oracle on the *final* A/B bytes (Task 5).

```bash
git commit -am "spike(gate A): 112 flat volatile zero stores replace the memset-shaped initializer; path-scoped semantic guard check-init-shape.py; index-set source guard"
```

---

### Task 4: Revised Gate B in full — owner protocol, coalescing, drain closure, real 100 ms timeline (P2)

**Files:**
- Modify: `spike/slice1b2-kernel/ebpf/src/main.rs:324-360` (`signal_return`), `common.rs` (constants only)
- Modify: `spike/slice1b2-kernel/fixture.c:54-60, 186-236` (second hook, second late target, two-thread barrier, second marker)
- Modify: `spike/slice1b2-kernel/src/main.rs` — facts `:191-223`, oracle `:225-260`, `StopSnapshot`/`stop_snapshot` `:1581-1594`, `run_gate_b_case` `:2159-2363`, facts serializer `:2122`, `parse_gate_b_args` `:1088-1095` (unchanged: literal `--runs 20`)
- Modify: `spike/slice1b2-kernel/run.sh:277-410` (Gate B Python validator)
- Test: unit tests `confirmation_requires_two_all_t_samples_1ms_apart_before_deadline`, `signal_oracle_requires_one_winner_one_coalesced_and_closed_drain`

**Interfaces:**
- Consumes: Task 3 source (final object is built once more here).
- Produces: `signal-timing.jsonl` per child gains `samples[]` (≤ 101 × `{elapsed_us, task_count, exact_expected_task_set, state_counts:{R,S,D,T,t,Z,X,I,other}}`), `confirmation_sample_indexes: [i,j]|null`, `stop_wait_ceiling_us: 100000`, `winner_records`, `coalesced_records`, `signal_helper_calls`, `required_attach_keys`, `attached_while_stopped`, `drain_empty`, `queue_empty_before_resume`, `resume_attempts`, `owner_removed`, `final_start_entries`, `markers_after_resume`; `stopped_snapshot_{1,2}_*` keep their names (filled from the two confirming samples, or the last two samples when unconfirmed). BPF `START` gains the disjoint group key `StateKey { pid_tgid: tgid << 32, attach_cookie: u64::MAX }` with `StartState { arg0: 1 (ARMED) | 2 (REQUESTED), arg1: 0 }` (§5.2). `SignalRecord.send_signal_rc == i64::MIN` means exactly `coalesced_no_helper` (§5.3). No new map, no record layout change.

- [ ] **Step 1: RED — pure-function tests**

```rust
#[test]
fn confirmation_requires_two_all_t_samples_1ms_apart_before_deadline() {
    let s = |elapsed_us: u64, ok: bool| StopSnapshot { elapsed_us, count: 2, exact_expected_task_set: ok, all_tasks_stopped: ok, state_counts: [0; 9] };
    assert_eq!(confirm(&[s(1000, false), s(2000, false)]), None);                 // the old runner's world
    assert_eq!(confirm(&[s(1000, false), s(2100, true), s(3200, true)]), Some((1, 2)));
    assert_eq!(confirm(&[s(1000, true), s(1500, true)]), None);                    // < 1 ms apart
    assert_eq!(confirm(&[s(99_000, true), s(100_500, true)]), None);              // second past the 100 ms deadline
    assert_eq!(confirm(&[s(1000, true), s(2000, false), s(3000, true), s(4100, true)]), Some((2, 3))); // consecutive only
}

#[test]
fn signal_oracle_requires_one_winner_one_coalesced_and_closed_drain() {
    let mut facts = passing_facts();                       // helper: a fully green SignalTimingFacts fixture used by the existing oracle tests
    assert!(signal_oracle_pass(&facts));
    facts.coalesced_records = 0; assert!(!signal_oracle_pass(&facts)); facts.coalesced_records = 1;
    facts.winner_records = 2;    assert!(!signal_oracle_pass(&facts)); facts.winner_records = 1;
    facts.drain_empty = false;   assert!(!signal_oracle_pass(&facts)); facts.drain_empty = true;
    facts.attached_while_stopped = 1; assert!(!signal_oracle_pass(&facts)); facts.attached_while_stopped = 2;
    facts.final_start_entries = 1; assert!(!signal_oracle_pass(&facts));
}
```
Run: `cargo test confirmation_requires` and `cargo test signal_oracle_requires` → both FAIL (fields/functions undefined).

- [ ] **Step 2: BPF — reserve, then `ARMED → REQUESTED`, then one signal (§5.3 order)**

Replace `signal_return` (`ebpf/src/main.rs:324-360`) with:

```rust
const PAUSE_ARMED: u64 = 1;
const PAUSE_REQUESTED: u64 = 2;
const COALESCED_NO_HELPER: i64 = i64::MIN;

/// Group key: tgid in the high half, zero low half (a real thread key always has a nonzero TID),
/// cookie u64::MAX. Namespace-disjoint from every entry/return key (§5.2).
fn pause_owner_key() -> StateKey {
    StateKey { pid_tgid: (helpers::bpf_get_current_pid_tgid() >> 32) << 32, attach_cookie: u64::MAX }
}

#[uretprobe]
pub fn signal_return(ctx: RetProbeContext) -> u32 {
    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    // SAFETY: the probe context is the kernel-provided context for this attachment.
    let case_id = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) } as u8;
    // 2. reserve before any authorization is consumed; loss sends no signal and leaves ARMED intact
    let Some(mut entry) = DISCOVERY.reserve::<SignalRecord>(0) else {
        increment_counter(RING_LOSS);
        return 0;
    };
    let raw = entry.as_mut_ptr();
    let words = raw.cast::<u64>();
    // 3. helper-independent initialization (four zero words)
    // SAFETY: reserve owns one writable 32-byte entry; four volatile u64 writes initialize every byte.
    unsafe {
        core::ptr::write_volatile(words.add(0), 0u64);
        core::ptr::write_volatile(words.add(1), 0u64);
        core::ptr::write_volatile(words.add(2), 0u64);
        core::ptr::write_volatile(words.add(3), 0u64);
    }
    // 4. atomically ARMED -> REQUESTED; only the winner may call the signal helper.
    //    `core::sync::atomic::AtomicU64::compare_exchange` does not exist on bpfel-unknown-none
    //    (the target has atomic load/store only); the core intrinsic lowers to BPF_CMPXCHG.
    let won = match START.get_ptr_mut(&pause_owner_key()) {
        // SAFETY: the pointer addresses a live map value; this CAS is the only BPF writer of arg0.
        Some(state) => unsafe {
            core::intrinsics::atomic_cxchg::<u64, { core::intrinsics::AtomicOrdering::AcqRel }, { core::intrinsics::AtomicOrdering::Acquire }>(
                core::ptr::addr_of_mut!((*state).arg0), PAUSE_ARMED, PAUSE_REQUESTED,
            ).1
        },
        None => false,
    };
    // 5. winner: timestamp immediately before the single SIGSTOP request; nonwinner: causal timestamp + coalesced status
    // SAFETY: these helpers take no pointers, and SIGSTOP is a valid scalar signal.
    let (hook_ts_ns, send_signal_rc) = unsafe {
        if won { (helpers::bpf_ktime_get_ns(), helpers::bpf_send_signal(19) as i64) }
        else { (helpers::bpf_ktime_get_ns(), COALESCED_NO_HELPER) }
    };
    // 6. finish initialization, submit
    // SAFETY: same reserved entry; all fields written after the zero words.
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!((*raw).hook_ts_ns), hook_ts_ns);
        core::ptr::write(core::ptr::addr_of_mut!((*raw).pid_tgid), pid_tgid);
        core::ptr::write(core::ptr::addr_of_mut!((*raw).send_signal_rc), send_signal_rc);
        core::ptr::write(core::ptr::addr_of_mut!((*raw).case_id), case_id);
    }
    entry.submit(0);
    0
}
```
The ebpf crate adds `#![feature(core_intrinsics)]` and `#![allow(internal_features)]` (it is nightly-only already). **Do not use `atomic_xadd`'s return value and do not set `-C target-cpu=v3`:** verified 2026-08-18 with the same toolchain (rustc-LLVM 22.1.4, bpf-linker 0.10.4) — at the default cpu a used fetch-add fails to link ("Invalid usage of the XADD return value"), and with `-C target-cpu=v3` it links but silently emits a plain `lock *(u64 *)(rX + 0) += rY` (imm 0, no `BPF_FETCH`) and returns the addend, i.e. a miscompile; `atomic_cxchg` is correct at both (`cmpxchg_64`, imm `0xf1`). To be reported upstream (aya #1268 / bpf-linker) with the minimal repro. *Verified in scratch with the frozen nightly `e50aa6fba`:* `rustc --print cfg --target bpfel-unknown-none` lists only `target_has_atomic_load_store="64"`, so `compare_exchange` is absent (E0599); the intrinsic above compiles and `signal_return` disassembles to `r0 = cmpxchg_64(r1 + 0x0, r0, r3)` — the kernel `BPF_ATOMIC | BPF_CMPXCHG` instruction (≥ 5.12; both endpoints qualify). Add to `build_bpf` a disassembly assertion (`llvm-objdump -d … | sed -n '/<signal_return>:/,/^$/p' | grep -c cmpxchg_64` == 1) and to the source text guard: `reserve::<SignalRecord>` precedes `atomic_cxchg`, and `bpf_send_signal` appears exactly once, after it. There is no fallback mechanism: if the CAS ever fails to lower, stop.

- [ ] **Step 3: Fixture — two threads reach two distinct hooks concurrently (§6.2)**

In `fixture.c`: add `PROBE_TARGET void spike_stop_hook_b(void)` and `PROBE_TARGET void spike_late_target_b(void)` (same empty-asm bodies as `spike_stop_hook`/`spike_late_target`), a `static pthread_barrier_t hook_barrier;` initialised for 2 parties in `run_signal_case`, and:

```c
static void *worker_main(void *opaque) {
    struct worker_args *args = opaque;
    write_byte(args->ready, 'W');
    /* wait for release exactly as today (poll on args->release, read_byte) */
    …
    pthread_barrier_wait(&hook_barrier);
    spike_stop_hook_b();            /* attach key B */
    write_byte(args->marker, 'N');  /* worker marker */
    spike_late_target_b();
    return NULL;
}
/* main thread, after read_byte(release_fd): */
    pthread_barrier_wait(&hook_barrier);
    spike_stop_hook();              /* attach key A */
    write_byte(marker_fd, 'M');
    spike_late_target();
```
(`worker_args` gains `int marker`; the worker no longer waits for a second release byte — the barrier replaces it.) Two distinct hook offsets are hit within microseconds of each other; only one CAS can win.

- [ ] **Step 4: Runner — arm, observe with the real deadline, drain, freeze, attach both, resume once, close**

In `run_gate_b_case`, in this order:

```rust
        // arm: insert ARMED under the group key before releasing the child (userspace inserts only after preflight)
        let owner_key = StateKey { pid_tgid: u64::from(guard.pid()) << 32, attach_cookie: u64::MAX };
        start_map.insert(owner_key, StartState { arg0: 1, arg1: 0 }, aya::maps::MapFlags::BPF_NOEXIST as u64 /* NOEXIST */)?;
        let owner = PauseOwnerGuard::new(&mut start_map, owner_key);   // RAII: removes the group-key entry on every exit path (see below)
        // attach signal_return at BOTH stop hooks (cookies 1 = A, 2 = B), then release; then read exactly two records.
        // The second record must arrive inside the same causal window: deadline = earliest hook_ts of the two + 100 ms.
        let rec_a = wait_signal_record(ring, cancellation)?;                                  // existing 5 s bound = ring liveness only
        let rec_b = wait_signal_record_until(ring, cancellation, rec_a.hook_ts_ns.checked_add(STOP_WAIT_CEILING_US * 1_000).ok_or("deadline overflow")?)?;
        if rec_b.hook_ts_ns.min(rec_a.hook_ts_ns) + STOP_WAIT_CEILING_US * 1_000 < monotonic_ns()? { facts.drain_empty = false; /* late second record: attempt is unconfirmed, retained */ }
        let winner = [rec_a, rec_b].into_iter().filter(|r| r.send_signal_rc != i64::MIN).count();
        let coalesced = [rec_a, rec_b].into_iter().filter(|r| r.send_signal_rc == i64::MIN).count();
        facts.winner_records = winner as u64; facts.coalesced_records = coalesced as u64; facts.signal_helper_calls = winner as u64;
        let win = if rec_a.send_signal_rc != i64::MIN { rec_a } else { rec_b };
        facts.hook_ts_ns = win.hook_ts_ns; facts.send_signal_rc = win.send_signal_rc; facts.stop_request_accepted = win.send_signal_rc == 0;
        // observe: >= 1 ms cadence, absolute deadline hook_ts + 100 ms, sample stamped AFTER its /proc reads complete
        let deadline_ns = facts.hook_ts_ns.checked_add(STOP_WAIT_CEILING_US * 1_000).ok_or("deadline overflow")?;
        let mut samples: Vec<StopSnapshot> = Vec::with_capacity(101);
        loop {
            cancellation_failure(cancellation)?;
            if monotonic_ns()? > deadline_ns || samples.len() >= 101 { break; }
            let mut snap = stop_snapshot(guard.pid(), &expected)?;
            let done = monotonic_ns()?;                          // a slow snapshot is stamped when it finished
            snap.elapsed_us = done.checked_sub(facts.hook_ts_ns).ok_or("clock reversal")? / 1_000;
            samples.push(snap);
            if confirm(&samples).is_some() { break; }
            std::thread::sleep(Duration::from_millis(1));
        }
        let confirmed = confirm(&samples);
        // drain-to-empty: with all tasks stopped there is no exact-child producer left; anything beyond the two records is a failure
        facts.drain_empty = drain_signal_ring_to_empty(ring)? == 0;
        // freeze the required attach set from the two case IDs, attach BOTH late targets while stopped
        facts.required_attach_keys = 2;
        // … attach late_hit at spike_late_target (cookie 1) and spike_late_target_b (cookie 2); facts.attached_while_stopped = number accepted …
        // third exact-set/all-T snapshot, no marker yet, queue still empty, then exactly one original-pidfd resume (existing code)
        facts.queue_empty_before_resume = drain_signal_ring_to_empty(ring)? == 0;
        // §5.2: REQUESTED is removed immediately after the one successful original-pidfd resume — before waiting for markers/exit
        guard.resume_once()?;                                    // existing single resume through the original pidfd
        facts.owner_removed = owner.close_after_resume()?;       // removes the entry now; guard becomes inert
        // after resume: both markers 'M' and 'N' (any order), LATE_HITS == 2, child exit 0, reap
        facts.final_start_entries = start_map.keys().count() as u64;   // must be 0: namespace separation + closure
```
`PauseOwnerGuard` holds the map handle and key; `close_after_resume()` removes the entry and marks the guard inert; `Drop` removes the entry when still armed **and** no stop was accepted or the child was already resumed/reaped — i.e. on `?`, cancellation, timeout, attach failure, and the unconfirmed-attempt path. `Drop` never resumes a child by itself (resume stays with `ChildGuard`); the case runner orders `ChildGuard` cleanup before `PauseOwnerGuard` drop so a stopped child is resumed exactly once first. Failure-injection unit tests: (i) attach failure after arming → entry removed, no signal record consumed; (ii) cancellation during observation → child resumed once, entry removed; (iii) late second record → attempt unconfirmed, entry removed after cleanup; (iv) happy path → entry removed before markers are read. `wait_signal_record_until(ring, cancellation, deadline_ns)` is `wait_signal_record` with an absolute monotonic deadline. `confirm`, `StopSnapshot { elapsed_us, count, exact_expected_task_set, all_tasks_stopped, state_counts: [u32; 9] }`, `sample_value` and `STOP_WAIT_CEILING_US` are the pure helpers from Step 1's test; `stop_snapshot` fills `state_counts` via `b"RSDTtZXI".iter().position(|c| *c == state).unwrap_or(8)`. `stopped_snapshot_{1,2}_*` are filled from `samples[i]`/`samples[j]` (confirmed) or the last two samples (unconfirmed → oracle fails, record retained). Every failure path still resumes exactly once through the original pidfd and reaps (existing `ChildGuard`).

- [ ] **Step 5: Oracle + serializer + validator**

`signal_oracle_pass` adds: `winner_records == 1 && coalesced_records == 1 && signal_helper_calls == 1 && confirmation_sample_indexes.is_some() && drain_empty && required_attach_keys == 2 && attached_while_stopped == 2 && queue_empty_before_resume && late_hits == 2 && markers_after_resume == 2 && owner_removed && final_start_entries == 0` (owner removal ordered before marker/exit facts). The serializer (`:2122`) emits the new fields (`samples` via `sample_value`; counts only). The `run.sh` Python validator recomputes: `samples` ≤ 101, `elapsed_us` strictly increasing, `state_counts` sums to `task_count`; `confirmation_sample_indexes` null or `[i, i+1]` with both samples exact-set/all-T, ≥ 1000 µs apart, both ≤ 100000; every new boolean/count predicate above; and — new — the record-closure rule (exactly two records: one `rc != i64::MIN`, one `== i64::MIN`, distinct case IDs 1 and 2). It still ignores any serialized `pass`.

- [ ] **Step 6: Local unprivileged proof, then commit**

`cargo test` (both new tests + existing), `cargo clippy -- -D warnings`, `bash -n run.sh`, `run.sh build-bpf` (guard PASS on the rebuilt object — Task 3's guard runs on every build). Commit:

```bash
git commit -am "spike(gate B): single pause owner (ARMED->REQUESTED CAS in START), coalesced no-helper records, two-hook concurrent fixture, real 100 ms observation timeline, drain-to-empty and frozen attach-set closure, validator"
```

---

### Task 5: Final A/B campaign on one frozen object

**Files:** none (evidence only) + `docs/notes/slice1b2/README.md`

**Interfaces:**
- Consumes: Task 3 + Task 4 source at one commit; `run.sh freeze-execution` → one bundle (BPF, runner, fixture, validator digests recorded).
- Produces: tracked Gate A result ×2 kernels; tracked revised Gate B result 120 children; campaign identity (bundle digests + `accel`).
- **Freeze boundary:** after this task no file under `spike/slice1b2-kernel/` (`common.rs`, `src/`, `ebpf/`, `fixture.c`, `run.sh`, validator) is modified by Tasks 6–9. All loader work lives in its own artifact (`spike/slice1b2-loader-bpf/`, `spike/slice1b2-loader-host/`) with its own copy of the shared record definitions; Task 8's runner reads the frozen A/B object bytes without changing them. Any later change to `spike/slice1b2-kernel/` reopens Task 5 (new campaign identity).

- [ ] **Step 1: Freeze one bundle; record its digests in the README** (`run.sh build-bpf`, `build-fixture`, `freeze-execution`; guard PASS is part of `build_bpf`).
- [ ] **Step 2: Diagnostic first (cheap): `diag-lane` on both kernels** — all four programs accepted, else stop (D5).
- [ ] **Step 3: Frozen Gate A, unchanged oracle:** `run.sh gate-a-lane jammy "$BUNDLE" …` and `… noble …`. Expected `PASS` (four accepted verifier records, five cases, four maps, exact records/counters, empty final `START`, canonical validation, export within caps). Retain FAIL/TIMEOUT verbatim.
- [ ] **Step 4: Revised Gate B, six lanes:** three fresh boots per kernel × `gate-b-lane … --runs 20` (the arg parser still accepts only literal `--runs 20`), all under one accelerator (state which; TCG is the frozen default, KVM if D1 approved). Expected 120/120 semantic PASS with `confirmation_sample_indexes` non-null; report the confirming `elapsed_us` min/median/max per kernel. All predeclared lanes run regardless of an earlier FAIL; no replacement lanes; no rerun-until-green.
- [ ] **Step 5 (diagnostic, optional): one extra Jammy lane under the *other* accelerator** and report whether any child shows the Task 3 signature (early non-`T` samples that converge inside 100 ms). Labelled diagnostic; not part of the 120.
- [ ] **Step 6: Record results + digests in the README; append exports to the evidence manifest.**

---

### Task 6: Released-glibc (2.41+) and DT_NEEDED precontrols in containers (Q2, Q3; inputs to P3)

**Files:**
- Modify: `spike/slice1b2-loader/run-lanes.sh` (lanes), `inside.sh` (provenance, load kind), `gdb-direct-witness.py` (`initial_set` mode)
- Create: `spike/slice1b2-loader/fixture-needed.c`, `docs/notes/slice1b2/glibc-31986-provenance.md`

**Interfaces:**
- Consumes: Task 0 layout.
- Produces: transcripts `<lane>-<dlopen|initial_set>-transcript.log` for `glibc-241-debian13`, `glibc-24x-ubuntu2604`, `glibc-235-ubuntu2204`, `glibc-239-ubuntu2404`, `musl-alpine3241`; env `SPIKE_LOAD_KIND`. Debian 13 is the **fixed-glibc candidate** for Task 9 (§8.1 has exactly four controls: fixed, 2.35, 2.39, musl); Ubuntu 26.04 is a precontrol/spare only. These are **precontrols** (GDB/`/proc/<pid>/mem` witness): they select expectations for the product-shaped Gate C rows (§7.2 last paragraph) and never populate a catalog.

- [ ] **Step 1: Pin the two fixed-glibc images; record source provenance, not just versions**

```bash
docker pull debian:13 && docker image inspect debian:13 --format '{{index .RepoDigests 0}}'
docker pull ubuntu:26.04 && docker image inspect ubuntu:26.04 --format '{{index .RepoDigests 0}}'
```
`glibc-31986-provenance.md`: the two commit SHAs + dates + titles; containment proof (`git -C <glibc clone> merge-base --is-ancestor 43db5e2c glibc-2.41` → 0, or the GitHub compare output already obtained: 263/264 behind 2.40, ancestors of 2.41); image digests; and — filled in Step 4 from inside each container — `dpkg-query -W -f '${Version}' libc6`, `apt-get source glibc` (enable `deb-src`) → confirm `elf/dl-open.c` in the unpacked source carries the post-fix ordering (the `RT_CONSISTENT`/`_dl_debug_state` call after relocation processing) and that no `debian/patches/*` reverts it (`grep -l dl-open.c debian/patches/*`); loader/libc SHA-256 + build IDs. State explicitly: version selects lanes; source provenance + runtime witness classify.

- [ ] **Step 2: Add lanes and libc provenance capture**

In `run-lanes.sh` after the existing three lanes:

```bash
run_lane glibc-241-debian13 glibc "debian@sha256:<pinned>" p11scope-slice1b2-r3-glibc241
run_lane glibc-24x-ubuntu2604 glibc "ubuntu@sha256:<pinned>" p11scope-slice1b2-r3-glibc24x
```
`inside.sh` (glibc family, `environment` step): `dpkg-query -W -f 'LIBC6_VERSION=${Version}\n' libc6; echo "GNU_LIBC_VERSION=$(getconf GNU_LIBC_VERSION)"`; new step `source_provenance` (glibc family): `sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/*.sources 2>/dev/null; apt-get update -qq; apt-get install -y -qq dpkg-dev; (cd /work && apt-get source -qq glibc)` (fetches **and unpacks**) then print the `dl_open_worker`/`_dl_debug_state` neighbourhood of `elf/dl-open.c` between `PROVENANCE_DL_OPEN_BEGIN/END`, plus `sha256sum` of the `.dsc`. Run the two `dlopen` lanes:

```bash
spike/slice1b2-loader/run-lanes.sh glibc-241; spike/slice1b2-loader/run-lanes.sh glibc-24x
```
Expected: `GDB_FINAL_CLASSIFICATION=PASS` — first post-`RT_ADD` `RT_CONSISTENT` witness `PASS_EQUAL` **before** `GDB_CTOR`. A FAIL is a first-class finding (fix absent/reverted) and goes into the note.

- [ ] **Step 3: Add the DT_NEEDED (`initial_set`) load kind**

`fixture-needed.c` (no `dlopen`):
```c
#include <stdio.h>
extern void *fixture_relocated_puts;
int main(void) { puts("LAUNCHER_MAIN"); return fixture_relocated_puts == (void *)puts ? 0 : 121; }
```
`inside.sh` compile step adds `gcc -g -Wl,--build-id -o fixture-needed fixture-needed.c -L. -lfixture -Wl,-rpath,'$ORIGIN'` and runs the GDB witness for the kind selected by `SPIKE_LOAD_KIND` (`./fixture` for `dlopen`, `./fixture-needed` for `initial_set`). In `gdb-direct-witness.py`, when `SPIKE_LOAD_KIND == "initial_set"` the decisive hit is the **first qualifying `RT_CONSISTENT` hit at which the exact target DSO mapping (path + dev + inode) exists** (startup, before `main`); every earlier hit is retained in the transcript as `PRE_MAPPING` (r_state + witness `BLOCKED`), and the classification rules are unchanged (`PASS_EQUAL` before ctor → PASS; `FAIL_ZERO`/`FAIL_UNEQUAL` → FAIL; ctor before a decisive hit → BLOCKED). `run-lanes.sh` passes `-e SPIKE_LOAD_KIND="${SPIKE_LOAD_KIND:-dlopen}"` and names transcripts `"$evidence/${lane}-${SPIKE_LOAD_KIND:-dlopen}-transcript.log"`.

- [ ] **Step 4: Run all five loaders in `initial_set` mode; fill the provenance note; commit**

```bash
SPIKE_LOAD_KIND=initial_set spike/slice1b2-loader/run-lanes.sh
```
Expected: PASS on 2.35, 2.39, 2.41+, musl. Any FAIL/BLOCKED retained as-is. Append transcripts to the evidence manifest.

```bash
git commit -am "spike(loader): released fixed-glibc controls (Debian 13, Ubuntu 26.04) with source provenance, DT_NEEDED load kind"
```

---

### Task 7: Mandatory minimal ptrace-free loader event program (§7.3; I6)

**Files:**
- Create: `spike/slice1b2-loader-bpf/` (own aya-ebpf crate; own `common.rs` copy of `DiscoveryRecord`, `StateKey`, `StartState`, `SignalRecord` + the cookie constants — the A/B artifact's files are never touched after Task 5)
- Create: `spike/slice1b2-loader-host/` (own Rust 1.88 crate: cookie encode/decode, 256-entry registry, `loader-hit` and, in Task 8, `loader-protect`; unit tests)
- Modify: `spike/slice1b2-kernel/run.sh` is **not** modified; the loader artifact gets its own `spike/slice1b2-loader-host/run.sh` (VM lane functions copied from the A/B script, own bundle inventory)

**Interfaces:**
- Produces: the loader BPF object with its complete declared inventory — maps `DISCOVERY` (ring, 65,536 B), `START` (hash, 64; used at the §5.2 group key for the pause owner and nothing else), `COUNTERS` (array, six entries: `RING_LOSS`, `STATE_FAILURES`, `LOADER_HITS`, `STATE_READ_FAILURES`, `COOKIE_ZERO_HITS`, `FUNC_IP_ZERO_HITS`); program `dl_debug_state` (`#[uprobe]`), which emits the **existing 896-byte `DiscoveryRecord`** (`kind = LOADER = 3`, `case_id = context_id - 1`, `status_flags` bit `0x04 = loader_context_invalid`, `announced_count = r_state`, `table_ptr = hook_ip` — private, never serialized) initialized with the same 112 flat volatile stores and checked by the same `check-init-shape.py` (§4.4: every emitter of the 896-byte record passes the guard). The hook also runs the §5.3 pause path (reserve → `ARMED → REQUESTED` CAS → single `bpf_send_signal` for the winner) so Task 8 can pause at loader hits; `SignalRecord` is not used here — the winner/coalesced status goes into `status_flags` bit `0x02 = coalesced_no_helper` exactly as §5.3 specifies for the product record. Host: `cookie_encode(context_id: u16, delta: Option<i64>) -> u64`, `cookie_decode(u64) -> Result<(u16, Option<i64>), CookieError>`, `slice1b2-loader-host loader-hit CHILD_ARGV…`. Task 8 and Task 9 attach this program.
- Endpoints: proved on **Jammy 5.15 and Noble 6.8** (both), host 7.0 optional diagnostic.

- [ ] **Step 1: RED — cookie round-trip tests exactly as the §8.1 preflight**

```rust
#[test]
fn cookie_round_trip_covers_all_contexts_and_bounds() {
    for id in 1..=256u16 {
        assert_eq!(cookie_decode(cookie_encode(id, None)).unwrap(), (id, None));
        for delta in [0i64, -(1 << 54), (1 << 54) - 1] {
            assert_eq!(cookie_decode(cookie_encode(id, Some(delta))).unwrap(), (id, Some(delta)));
        }
    }
    assert_eq!(cookie_encode(1, None), 512);        // absent state: id_bits | (1 << 9), never zero
    assert_eq!(cookie_encode(1, Some(0)), 256);     // present state, zero delta: id_bits | (1 << 8)
    assert!(cookie_decode(0).is_err());             // zero cookie rejected before any lookup
    assert!(cookie_decode(2 << 9).is_err());        // absent state with payload != 1 rejected
}
```

- [ ] **Step 2: Implement encode/decode (host and BPF share the bit layout via `common.rs`)**

```rust
pub const COOKIE_ID_MASK: u64 = 0xff;
pub const COOKIE_STATE_PRESENT: u64 = 1 << 8;
pub const COOKIE_PAYLOAD_SHIFT: u32 = 9;
pub const COOKIE_DELTA_MASK: u64 = (1 << 55) - 1;
pub fn cookie_encode(context_id: u16, delta: Option<i64>) -> u64 {
    let id_bits = u64::from(context_id - 1) & COOKIE_ID_MASK;
    match delta {
        None => id_bits | (1 << COOKIE_PAYLOAD_SHIFT),                                       // sentinel payload 1
        Some(d) => id_bits | COOKIE_STATE_PRESENT | (((d as u64) & COOKIE_DELTA_MASK) << COOKIE_PAYLOAD_SHIFT),
    }
}
pub fn cookie_decode(cookie: u64) -> Result<(u16, Option<i64>), CookieError> {
    if cookie == 0 { return Err(CookieError::Zero); }
    let id = (cookie & COOKIE_ID_MASK) as u16 + 1;
    if cookie & COOKIE_STATE_PRESENT == 0 {
        if cookie >> COOKIE_PAYLOAD_SHIFT != 1 { return Err(CookieError::InvalidAbsentPayload); }
        Ok((id, None))
    } else {
        Ok((id, Some((cookie as i64) >> COOKIE_PAYLOAD_SHIFT)))                               // signed 55-bit delta
    }
}
```
BPF `dl_debug_state` (`#[uprobe]`): scope check (pid); `LOADER_HITS += 1` before reservation; reserve `DiscoveryRecord`, 112 flat volatile zero stores (guarded); `bpf_get_attach_cookie`; zero cookie or absent-state payload ≠ 1 → `status_flags |= 0x04`, submit, return (no lookup, no IP/delta arithmetic, no state read); valid → `hook_ip = bpf_get_func_ip(ctx)` (reject zero → submit with flag), `case_id = cookie & 0xff`; if state present: `_r_debug = hook_ip.checked_add_signed(delta)`, `r_state = bpf_probe_read_user(_r_debug + 24)` as one 4-byte read — failure increments `STATE_READ_FAILURES`, record still submitted. Every hit is submitted (§7.1); the hook calls no loader/provider code.

- [ ] **Step 3: Host side — 256-entry monotonic registry (payload vs registration shell), pre-exec pin, one-process attach**

Implement §7.3 minimally: `LoaderContext { generation, loader_identity: (dev, ino, sha256), hook_vaddr, hook_file_offset, r_debug_vaddr: Option<u64>, delta: Option<i64> }` in a `Vec` indexed by `context_id - 1`, capacity 256, IDs never reused; shell `Prepared | Attached(link) | Tombstoned`. `loader-hit CHILD_ARGV…`: fork with a barrier, resolve `PT_INTERP` of the executable through the child's root, pin/hash the loader, read `_dl_debug_state` and optional `_r_debug` from its ELF (`p11scope-manifest` ELF helpers already in the spike's deps), compute `delta = _r_debug_vaddr - hook_vaddr` (checked), insert `Prepared`, attach by file offset + pid, mark `Attached`, release the barrier, drain records, print finite facts (`hits`, `state_read_failures`, per-hit `r_state`, `hook_ip == load_bias + hook_vaddr` check, `loader_context_invalid` count). Add the §8.1 preflight negative: attach once with Aya's no-cookie form → exactly one `loader_context_invalid` record, no state op.

- [ ] **Step 4: Run on Jammy 5.15 and Noble 6.8 (VM lanes; host 7.0 optional) against the loader artifact's fixture; commit**

Expected on both kernels: the program loads (record verifier acceptance with the STATS diagnostic form as in Task 2), 2 startup hits (`RT_ADD`, `RT_CONSISTENT`) with the `hook_ip == load_bias + hook_vaddr` formula holding on glibc 2.35 and 2.39; zero `state_read_failures`; the no-cookie negative behaves as specified; `START` empty at exit. This is the minimal event source every later lane and P4 build on.

```bash
git commit -am "spike(loader): own artifact — product-shaped ptrace-free _dl_debug_state program on the 896-byte DiscoveryRecord with §7.3 cookie/registry and §5.3 pause path; preflight round-trip and no-cookie negative; Jammy+Noble"
```

---

### Task 8: Attach-first experiment (hidden-table fixture) + memo — what protection can and cannot replace

**Files:**
- Create: `spike/slice1b2-loader-host/fixture-provider.c` (two builds: `exported` — table functions in dynsym; `hidden` — only `C_GetFunctionList` exported, table functions `static`)
- Modify: `spike/slice1b2-loader-host/src/main.rs` (`loader-protect` subcommand; loads the loader object **and** the frozen A/B object bytes read-only for `function_list_return`)
- Create: `docs/notes/slice1b2/attach-first-vs-timing-catalog.md` (≤ 1 page + results table)

**Interfaces:**
- Consumes: Task 4 pause protocol (owner CAS, `confirm` — copied into the loader-host crate, not shared source), Task 7 loader program (its `dl_debug_state` carries the pause winner path), `function_list_return` from the frozen A/B object (bytes unchanged).
- Produces: owner decision input D3.

**What is measured** (not assumed): with the child stopped at a `_dl_debug_state` hit for the new mapping on a *negative-timing* loader (host glibc 2.39; Jammy 2.35 in the guest), userspace reads `/proc/<pid>/maps` (owned child), pins the new DSO, and attaches (a) `function_list_return` at its `C_GetFunctionList` file offset, (b) for the `exported` build, entry probes at each exported `C_*` symbol; then resumes once. Recorded per attempt: `attach_gap_ms`; whether the export return record arrived with 104 relocated non-zero pointers **before** `PROVIDER_CTOR_INIT`; whether the constructor's immediate `C_Initialize` was observed (`exported`: symbol probe; `hidden`: only if a table-slot probe was attached in time — measure the export-return → slot-attach window and whether the call escaped); a variant with a **second** owned pause requested from the export-return hook (allowed: a fresh `ARMED` after the first owner closed, §5.2) that attaches the table slots while stopped.

- [ ] **Step 1: Fixture** — `C_GetFunctionList` returns a static `CK_FUNCTION_LIST` (relocated pointers = the witness); constructor calls it and then the table's `C_Initialize`, printing `PROVIDER_CTOR_INIT`; harness `dlopen`s, then calls the export + `C_Initialize` post-return (`LAUNCHER_POST_RETURN`). Build both variants (`-fvisibility=hidden` + explicit visibility on `C_GetFunctionList`).
- [ ] **Step 2: Runner** — `loader-protect {exported|hidden} [--second-pause]`, 20 attempts per configuration on the host and on the Noble guest (Jammy optional), retained as private JSONL (finite facts only).
- [ ] **Step 3: Memo** with the results table and these bounded conclusions:
  - proven if measured: on negative loaders, offset-based **export** attachment at the loader hit + confirmed pause guarantees the export return (and hence a relocated table read) is observed before any post-return application call — independent of relocation timing;
  - proven if measured: `exported` providers additionally get constructor-time coverage from dynsym entry probes;
  - **not** proven by attach-first alone: constructor-time calls into hidden table functions between `C_GetFunctionList` return and dynamic slot attachment — report the measured window and whether the `--second-pause` variant closes it;
  - what the timing catalog would add on top (a trustworthy *scan* at the loader hit, which needs `/proc/<pid>/mem`), and for which provider class (hidden tables, constructor calls) it is the only ptrace-dependent alternative to a second pause.
  Recommendation for D3 written from the numbers, not from the thesis.

---

### Task 9 (dormant; D3 = no): private relocation-witness diagnostic (§8, 12 rows)

**Status:** `UNRUN`. Task 8 selected attach-first protection, so this task is
off the product and release critical paths. Run it only after a new owner
request explicitly names these lanes. Its result cannot create a capability
catalog entry, change product policy, clear `PARTIAL`, satisfy Gate C, or
satisfy corrective-design §11 step 2.

**Activation boundary:** before implementation, commit an amendment that
freezes the exact Task-9-only categorical record ABI and independent validator;
the complete map/program inventory; per-attempt and per-lane deadlines;
verifier-log, per-file, and total-output byte caps; private evidence root; and
the exact source/toolchain/fixture/control identities. Do not inherit the
frozen Gate A/B 120-second or 8/16-MiB caps. Without that amendment and separate
privileged-lane approval, this task stays `UNRUN`.

**Artifact boundary:** derive a separate diagnostic object from the frozen
Task 7 loader artifact; never modify or relabel the Task 5 A/B object or the
Task 7 evidence object. Freeze maps `DISCOVERY` (65,536-byte ring), `START`
(64-entry hash, including the §5.2 pause-owner group key), `COUNTERS` (the six
actual entries `RING_LOSS`, `STATE_FAILURES`, `LOADER_HITS`,
`STATE_READ_FAILURES`, `COOKIE_ZERO_HITS`, `FUNC_IP_ZERO_HITS`), and one
single-entry bounded witness-config array. That entry has exactly two
length-prefixed raw-byte selectors, `fixture_suffix` and `libc_suffix`, each
1–32 bytes, not NUL-terminated, with an all-zero unused tail, plus the two
ELF-relative offsets `witness_vaddr` and `puts_vaddr`; its byte layout is frozen
by the activation amendment. Program inventory is only `dl_debug_state`. The
new record contains only finite categories needed by the oracle. Raw path/name,
runtime address/pointer, PID/TID, cookie, context ID, and delta data stay in the
private run and are never serialized. Do not overload `DiscoveryRecord` fields
with Task 9 meanings.

- [ ] **Step 1: Implement the bounded witness and structural guards.** Preserve
  Task 7 ordering: first validate a nonzero cookie, resolve its attached context,
  validate the hook IP, and obtain present `_r_debug` state. Only that valid
  path may read the witness config, walk at most 64 x86-64 `link_map` entries,
  and read `l_addr @+0`, `l_name @+8`, `l_ld @+16`, and `l_next @+24`.
  Invalid-cookie, absent-state, or failed-context/IP paths submit their finite
  Task 7 status and return without a config read, walk, or witness
  classification. Match only the two configured suffixes. Compare the target
  fixture's `l_addr + witness_vaddr` value with libc's
  `l_addr + puts_vaddr`. Emit only `zero|equal|unequal|unreadable`. Unit tests
  mutate every bound/category; disassembly/source guards prove the bounded walk,
  the existing nonzero-cookie rules, and the unchanged pause-owner protocol.

- [ ] **Step 2: Freeze one diagnostic bundle per control.** Controls are exactly
  Debian 13 glibc 2.41 (the sole fixed-glibc candidate), Ubuntu 22.04 glibc
  2.35, Ubuntu 24.04 glibc 2.39, and Alpine 3.24.1 musl. Record exact commit and
  clean tree, source/file manifest, Rust/nightly/LLVM identities, BPF/host/
  fixture/validator hashes, loader/libc/interpreter digests and build IDs,
  program/map/ABI inventory, caps/deadlines, oracle version, parent campaign,
  and the private evidence-manifest digest. The same control bundle bytes run
  unchanged on Jammy 5.15 and Noble 6.8.

- [ ] **Step 3: Run eight no-cookie preflights.** Before counted attempts, attach
  the same diagnostic program once per control/kernel pair with Aya's no-cookie
  form. Require one `loader_context_invalid` record and no context lookup,
  runtime-IP/state operation, derived classification, or stale `START` owner;
  require `discovery_truncated += 1`, `initial_set_capture = none`, and clean
  teardown. A mismatch is `DIAGNOSTIC FAIL`. These 4 × 2 = **8** preflights are
  mandatory for `DIAGNOSTIC PASS` but are not part of the counted matrix.

- [ ] **Step 4: Run the full 12-row matrix.** Run 20 fresh attempts for each of
  four controls × three load kinds (`dlopen`, `initial_set`, forced
  `dlopen_return`) × two kernels: **480 counted attempts**. Preserve every
  attempt. Continue safe predeclared rows after a finite diagnostic failure;
  stop the campaign after lifecycle or host-safety failure. Each row's
  classification must be identical across all 20 attempts and both kernels;
  mixed attempts or kernels are `DIAGNOSTIC FAIL`.

  Every counted attempt must have exact bundle/loader/libc/fixture/interpreter/
  hook provenance; a valid §7.3 cookie and hook-IP formula; verifier-accepted
  programs; complete records; and zero unexpected helper, ring, stale-context,
  identity, privacy, timeout, cleanup, or lifecycle errors. Explicit pause
  attempts also satisfy the revised pause oracle. An operational/oracle error is
  `DIAGNOSTIC FAIL`, never a capability `unproven` result.

  A valid primary attempt yields exactly one timing category:
  `qualified_pre_constructor` means an equal nonzero witness before constructor
  with every row-order predicate satisfied; `known_pre_relocation` means the
  predeclared event had a zero/unequal witness before constructor; `unproven`
  means a complete attempt had no conclusive qualified event; `none` is reserved
  for forced `dlopen_return` and unavailable strategies. Mapping/export is
  `protected` only when the exact mapping was pinned, its export was attached
  while the causal owner was confirmed stopped, and the constructor's first
  fixture `C_Initialize` was observed. A clean absence is `unproven`; any attach,
  marker, record, or lifecycle error is `DIAGNOSTIC FAIL`. Mapping/export never
  upgrades timing.

  | Control | Load kind | Required timing result | Independent mapping/export result |
  | --- | --- | --- | --- |
  | Debian 13 glibc 2.41 | `dlopen` | `qualified_pre_constructor`: `RT_ADD`, first following `RT_CONSISTENT`, equal witness before constructor. | `protected|unproven` |
  | glibc 2.35 | `dlopen` | `known_pre_relocation`: first post-`RT_ADD` `RT_CONSISTENT` witness remains zero. | `protected|unproven` |
  | glibc 2.39 | `dlopen` | `known_pre_relocation`: first post-`RT_ADD` `RT_CONSISTENT` witness remains zero. | `protected|unproven` |
  | Alpine 3.24.1 musl | `dlopen` | `qualified_pre_constructor`: at least one post-load equal witness before constructor; earlier empty hits allowed. | `protected|unproven` |
  | Debian 13 glibc 2.41 | `initial_set` | Stable `qualified_pre_constructor|known_pre_relocation|unproven`; positive satisfies all five §8.2 initial-set predicates. | `protected|unproven` independently |
  | glibc 2.35 | `initial_set` | Stable `qualified_pre_constructor|known_pre_relocation|unproven`; positive satisfies all five §8.2 predicates; no zero-at-consistent expectation. | `protected|unproven` independently |
  | glibc 2.39 | `initial_set` | Stable `qualified_pre_constructor|known_pre_relocation|unproven`; positive satisfies all five §8.2 predicates; no zero-at-consistent expectation. | `protected|unproven` independently |
  | Alpine 3.24.1 musl | `initial_set` | Stable `qualified_pre_constructor|known_pre_relocation|unproven`; positive is pre-constructor equal and satisfies all five §8.2 predicates. | `protected|unproven` independently |
  | Debian 13 glibc 2.41 | forced `dlopen_return` | Timing `none`; constructor and DT_NEEDED blind; observe only the exact post-return call. | Fallback ordering oracle |
  | glibc 2.35 | forced `dlopen_return` | Timing `none`; constructor and DT_NEEDED blind; observe only the exact post-return call. | Fallback ordering oracle |
  | glibc 2.39 | forced `dlopen_return` | Timing `none`; constructor and DT_NEEDED blind; observe only the exact post-return call. | Fallback ordering oracle |
  | Alpine 3.24.1 musl | forced `dlopen_return` | Timing `none`; constructor and DT_NEEDED blind; observe only the exact post-return call. | Fallback ordering oracle |

  For `initial_set`, a positive requires exactly the five non-circular §8.2
  facts: pre-exec loader pin/hash/hook/cookie before release; qualifying hit
  before constructor for the exact context/process generation; event-time
  loader and companion-libc identity; cookie/IP/state/witness/order validity;
  and no relevant loss or operational error. Mapping/export protection is
  classified separately and never upgrades timing. For forced
  `dlopen_return`, all 20 attempts per pair must prove no constructor/DT_NEEDED
  coverage and then observe the explicit post-return
  `C_GetFunctionList`/`C_Initialize` call.

- [ ] **Step 5: Independently recompute and report.** Run the repository's four
  Rust gates; loader-host `fmt`, locked `check`, `test`, and Clippy; the locked
  frozen-nightly loader-BPF build; `check-init-shape.py`; and `bash -n` on the
  loader run script. Require both-kernel verifier acceptance, exact
  ABI/inventory/cap checks, the independent eight-preflight plus 480-attempt
  oracle, and a privacy canary covering every live observer map. All eight
  preflights and all 480 complete attempts matching the frozen predicates yield
  `DIAGNOSTIC PASS` only. Any operational,
  provenance, privacy, validator, or row-predicate error is `DIAGNOSTIC FAIL`;
  an expired finite bound is `TIMEOUT/INCOMPLETE`; no activation is `UNRUN`.

---

### Task 10: Update the note, the ROADMAP status, and hand off

**Files:**
- Modify: `docs/notes/slice1b2-open-issues-and-consequences.md` (status table, I1/I2/I3/I6/I7 "Next evidence" → results, evidence pointers), `docs/notes/slice1b2/README.md`
- Modify: `docs/superpowers/plans/ROADMAP.md` Slice 1b-2 bullet (gate status line only)

- [ ] **Step 1: Rewrite the status table with finite results** — Gate A: frozen `PASS` on both kernels, canonical `FAIL`, or a retained `TIMEOUT/INCOMPLETE` if that is what the frozen lane produced (diagnostic errno/`processed`/`peak_states` figures labelled as such next to it, never replacing it); revised Gate B: `n/120` with campaign identity, accelerator, confirming-latency range per kernel; loader: precontrol results per loader and load kind (incl. 2.41+), Task 7 event-path facts, D3 outcome. Every historical negative stays in the ledger; the "6.8.0-71" report typo stays labelled as a known artifact defect.
- [ ] **Step 2: Hand-off list for P4/P5** — P5 is on the recovery branch (`906753a`); P4 (`discovery::Engine`, dynamic slots, `run`, pause coordinator, loader every-hit runtime) is written only after 1b-1 lands. D3 is no: catalog promotion and §8.3 timing qualification stay diagnostic-only unless a later approved design changes that boundary.
- [ ] **Step 3: Commit** `docs: slice 1b-2 open issues — results of the research plan; gate status; hand-off`.

---

## Owner decisions — recorded 2026-08-18

- **D1 — approved for the completed local test lanes** ("approving everything for tests — whatever is useful"): VM lanes with guest `sudo`, one-time KVM enablement, Docker `SYS_PTRACE`/seccomp-unconfined lanes, host-root diagnostics on `7.0.0-28`, and Task 8's `loader-protect`. Dormant Task 9 is excluded and asks separately.
- **D2 — STATS-only diagnostic lane: proceed** (the owner asked what "without patching Aya" means and is open to contributions — see the note under D2 below). The lane itself needs no Aya change.
- **D4 — released packages** (Debian 13 candidate; Ubuntu 26.04 precontrol/spare) with source provenance + runtime witness.
- **Executor:** the isolated `spike/slice1b2-gates` worker. D3 is **no** after
  Task 8; D5 was not triggered because the flat-store object passes both
  required kernels.

### Decision texts (as put to the owner)

- **D1 — privileged lanes, decided per lane:** (a) VM lanes with guest `sudo` (Tasks 2, 3, 5, 7); (b) diagnostic root runs on the host kernel (Tasks 2, 7, 8); (c) Docker `SYS_PTRACE`/seccomp-unconfined lanes (Task 6); (d) one-time KVM enablement (`usermod -aG kvm user` recommended; Task 1); (e) Task 8 `loader-protect` runs. Anything not approved is recorded UNRUN; Task 9 asks separately.
- **D2 — STATS-only diagnostic lane.** Accept `gate-a-diag` output (errno, `processed insns`, `peak_states`, ≤ 2 KiB tail) as I2's "bounded finite failure facts", clearly labelled diagnostic; the frozen gate keeps `VERBOSE | STATS`. Recommended: yes — it is the only way to learn the initial errno without patching Aya.
  *What "without patching Aya" means:* Aya 0.14's `retry_with_verifier_logs` (`src/sys/bpf.rs:1404-1434`) tries once with no log, then retries with growing `VERBOSE` buffers up to 16 MiB and returns only the *last* attempt's errno — the first-attempt errno (the real verdict) is lost and the log can only be capped by choosing a smaller log level. Choosing `STATS` (this lane) needs no library change. An **upstream Aya contribution** would make the frozen `VERBOSE | STATS` gate itself yield bounded facts: (i) keep the first-attempt `io_error` in `ProgramError::LoadError` (or a `first_errno` field) instead of the ENOSPC of the last retry; (ii) an `EbpfLoader::verifier_log_max_bytes(n)` cap so the retry loop stops growing at the caller's bound (the gate's 8 MiB) instead of the hard-coded `u32::MAX >> 8`; (iii) optionally, on kernels ≥ 6.4, request the rotating log so the *tail* (failure reason + stats) is retained within a small buffer. Each is a small, self-contained PR (`aya-obj`/`aya` `sys/bpf.rs`, `programs/mod.rs`) with unit tests against a fake syscall; the owner is open to contributing it. It is **optional and off the critical path** — Task 2 works with the released 0.14 — and if merged, the spike would pin the new Aya version only at a new campaign identity (D-boundary in Task 5).
- **D3 — no.** Task 8 selected attach-first protection. Task 9 remains an optional private diagnostic and does not run without a new explicit request.
- **D4 — fixed-glibc controls from released packages instead of a source build.** §7.2 says "reproducible exact tuple built from source containing `43db5e2c`"; Debian 13 / Ubuntu 26.04 packages with recorded source provenance (`apt-get source`, `dl-open.c` ordering, no reverting patch), loader/libc digests, build IDs, and the same runtime witness preserve the "exact tuple + witness" rule. Recommended: yes.
- **D5 — fork if Task 3's flat-store object still fails the verifier.** The options the design rejected stay rejected (chunked records, tail calls, per-interface programs, smaller ceilings). Remaining in-contract option: keep `interface_list_return` as the *enumerator* (16 interface descriptors — name class, flags, table pointer — no 104-pointer loop) and read a table at the **`C_GetInterface` return** hook — one table per hit, the same verifier shape as `function_list_return`, and the hook whose result the application actually uses. The 16-interface and 104-pointer ceilings stay literal; only *which* hook reads the table changes, so it needs a short design amendment (program inventory, oracle cases) and owner sign-off before any VM run.

## Research questions → where they are answered

| Q (note § "Suggested external research questions") | Task |
| --- | --- |
| 1. Which code paths dominate verifier states; minimal codegen change | 2 (`verified_insns` per program, failing errno) + 3 (flat stores) |
| 2. Fixed glibc gives a usable pre-constructor `dlopen` hit | 6 (precontrol); 9 only if the dormant diagnostic is separately activated |
| 3. Which released packages contain the fix, by provenance | 6 Step 1 (containment proof + source provenance + digests) |
| 4. Why Jammy Gate B failed once and passed later; is 100 ms stable | 4 (real wait + timeline) + 5 (campaign; accelerator diagnostic) |
| 5. Do the frozen A/B/C artifacts pass unchanged on both kernels | 5 (A/B); 9 is optional diagnostic C evidence only |

## Self-review notes

- Spec coverage: P1 → Task 3 (+ Task 5 rerun); P2 → Task 4 (§5.2 owner key/CAS, §5.3 order and predicates 1–9, §6.1 fields, §6.2 six lanes and 120/120) + Task 5; P3 → Tasks 6, 7, 9 (§7.2 controls, §7.3 cookie/registry/no-cookie negative, §8.1 fixture incl. DT_NEEDED and `dlopen`-return harness in Task 9); I2 → Task 2; I6 → Task 7; I5/I8/I9 → out of scope (P4), listed in Task 10.
- Deviations from the approved design are only D2, D4, and D5, all labelled; D3 is no and Task 9 is dormant. Nothing changes frozen oracle semantics silently; the A/B object is frozen once (Task 5) after Tasks 3+4.
- Names used across tasks: `StopSnapshot` (extended), `confirm`, `sample_value`, `STOP_WAIT_CEILING_US`, `pause_owner_key`, `PAUSE_ARMED/REQUESTED`, `COALESCED_NO_HELPER` (Task 4; reused by 8); `diag_line`/`run_gate_a_diag`/`diag-lane` (Task 2; reused by 3, 5); `cookie_encode/decode`, `LOADER_HITS`, `STATE_READ_FAILURES`, `PauseOwnerGuard`, `wait_signal_record_until` (Tasks 4/7; reused by 8, 9); `SPIKE_LOAD_KIND` (Task 6; reused by 9); `P11SCOPE_SPIKE_ACCEL` (Task 1; recorded by 2–5).
