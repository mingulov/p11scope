# Task-storage Canary Oracle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the release canary's complete raw-byte scan of observer-owned task-storage maps on every required kernel and ABI row.

**Architecture:** Preserve Python as the isolated orchestration and evidence layer. Add a standalone read-only `iter/task` C helper with a small libbpf loader that reuses exact observer map FDs, then integrate a stable stopped-task snapshot protocol and fail-closed population checks.

**Tech Stack:** Python 3 standard library, POSIX shell, C, clang-18 eBPF target, libbpf, bpftool, Linux BPF iterators.

**Spec:** `docs/superpowers/specs/2026-09-09-task-storage-canary-oracle-design.md`

## Global Constraints

- Preserve Rust 1.88, edition 2024, Linux x86-64-first, native64 and ia32 support.
- Preserve `docs/privacy/allowlist-v1.md`; never broaden capture implicitly.
- Keep native Python, shell, C, and eBPF test code in native files; Cargo bridges remain thin.
- The helper is test-only and read-only, imports exact map FDs, creates no replacement task-storage map, and leaves no pins or processes.
- One Cargo-heavy command may run at a time in the shared checkout.

---

### Task 1: Truthful map dispatch and scan-surface contract

**Files:**
- Modify: `scripts/dump-owned-bpf-maps.py`
- Modify: `scripts/check-canary-evidence.py`
- Modify: `tests/python/test_canary_evidence.py`

**Interfaces:**
- Consumes: live bpftool map metadata and `SAFE_MAPS` definitions.
- Produces: `map_oracle(item)` returning `mmap`, `dump`, or `task-storage`; manifests preserve the real `task_storage` type and require a file for every non-ring scan surface.

- [ ] Write native Python tests with real `task_storage` inventory items for all three maps; require `task-storage` dispatch and reject a missing surface.
- [ ] Run `python3 -I scripts/dump-owned-bpf-maps.py --self-test` and `python3 -I tests/python/test_canary_evidence.py -v`; verify the new assertions fail because task storage routes to `dump` or `hash`.
- [ ] Implement the minimal type-based dispatch, preserve real types in synthetic manifests, improve bounded dump diagnostics with map identity, and make an unavailable task-storage reader fail explicitly.
- [ ] Re-run both native Python commands and `git diff --check`; require PASS.
- [ ] Commit only these three files and the approved spec/plan with an incremental local commit.

### Task 2: Exact-map read-only iterator

**Files:**
- Create: `scripts/native/dump-task-storage.bpf.c`
- Create: `scripts/native/dump-task-storage.c`
- Create: `scripts/build-task-storage-reader.sh`
- Modify: `scripts/dump-owned-bpf-maps.py`
- Modify: `scripts/verify-canaries.sh`
- Modify: `scripts/verify-induced-gaps.sh`
- Modify: `tests/python/test_canary_evidence.py`
- Modify: `tests/artifact_contracts.rs`

**Interfaces:**
- Consumes: observer PID, explicit prebuilt reader/object paths, exact task-storage map IDs/FDs, expected map metadata, output directory, record/byte/time bounds.
- Produces: fixed framed raw records keyed by task identity and map identity plus terminal EOF; Python publishes one 0600 scan surface per imported map only after complete validation.

- [ ] Add mutation/contract tests for exact FD reuse, rejection of replacement maps, full 544-byte output, late-offset sentinel visibility, malformed/duplicate/truncated/overflow/timeout refusal, and cleanup.
- [ ] Run the focused native Python and Cargo artifact tests; verify expected RED failures before adding either native source.
- [ ] Implement the minimal iterator and loader. Use `bpf_map__reuse_fd()` before load, non-creating `bpf_task_storage_get(..., 0)`, direct `bpf_seq_write()`, bounded verifier logs, no bpffs pins, and cleanup on every exit.
- [ ] Compile the loader with the system C compiler and `-ldl`, compile the iterator with `clang-18`, and pass both explicit absolute paths from every dumper caller. Do not compile under sudo or depend on untracked ambient headers.
- [ ] Integrate invocation without ambient `PYTHONPATH`; validate IDs/type/key/value/max/flags before and after load and redact raw values from errors.
- [ ] Re-run focused tests, helper compilation, both embedded-object inventories, format, and `git diff --check`; require PASS.
- [ ] Obtain independent spec and quality review to zero, then create one incremental local commit.

### Task 3: Stable multithreaded snapshot and live qualification

**Files:**
- Modify: `scripts/verify-canaries.sh`
- Modify: `scripts/dump-owned-bpf-maps.py`
- Modify: `scripts/fixtures/canary_workload.c`
- Modify: `scripts/check-canary-evidence.py`
- Modify: `tests/python/test_canary_evidence.py`
- Modify: `tests/artifact_contracts.rs`

**Interfaces:**
- Consumes: expected workload task roster, stopped-state evidence, healthy owner/control-map populations, and iterator output.
- Produces: stable before/after roster receipts, complete task-storage population evidence, and ordinary canary manifests consumed by the unchanged sentinel scanner.

- [ ] Add failure-first tests for missing/non-stopped workers, clone/exit roster changes, ambiguous NULL lookup, population mismatch, unexpected owners, acquisition failures, and resume/cleanup behavior.
- [ ] Add positive fixture states for non-leader `THREAD_OWNER`, `TASK_COOKIE`, and owned `ROOT_AFFILIATION`, including a sentinel beyond byte 512 of the owner value.
- [ ] Run the focused native Python/Cargo cases and verify every new case fails for the intended missing behavior.
- [ ] Implement the smallest full-task stop/roster protocol and population reconciliation, keeping observer stop ordering and existing lane semantics.
- [ ] Re-run focused tests, direct language suites, exact Rust gates, both embedded BPF inventories, and independent review to zero; create one incremental local commit.
- [ ] Run the full native64 and ia32 canary matrix on the host, then Jammy 5.15 and Noble 6.8; retain exact-tip identities, bounded receipts, and clean-resource evidence.

### Task 4: W6 portability carry-forward

**Files:**
- Modify only qualification receipts and final release documentation selected by the W6/W8 plans; do not track generated evidence.

**Interfaces:**
- Consumes: reviewed Task 3 exact tip and each required kernel environment.
- Produces: per-kernel native64/ia32 task-storage oracle results or an exact separately classified incompatibility.

- [ ] Run the affected default/diagnostic canary lanes on the required W6 kernel matrix, including CentOS Stream 9 `5.14.0-741.el9` and the selected early/current 5.15 rows.
- [ ] Verify positive cells, non-leader coverage, complete raw lengths, refusal controls, EOF, cleanup, and absence of unintended BPF resources for each row.
- [ ] Record unsupported prerequisites as UNRUN or incompatibility; never convert refusal into positive qualification.
- [ ] Feed the exact results into W8 architecture review, documentation truth pass, and final-candidate qualification.
