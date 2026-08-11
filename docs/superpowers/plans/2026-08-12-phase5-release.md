# Phase 5 — `trace` mode, overhead benchmark, docs, v0.1 release — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the v1 feature set (`trace`), measure the tool's real overhead instead of claiming it, write docs whose every claim maps to a measurement, and cut v0.1.

## Global Constraints

- **Claim nothing unmeasured.** Every number in the README and the docs must trace to a script in this repo that produced it. If a claim cannot be backed by a run, delete the claim — do not soften it.
- Privacy guarantees are unchanged and non-negotiable: `trace` emits per-call *events*, never buffers. Same allowlist, same canary suite. `verify-canaries.sh` must still pass, and the canary workload should be run under `trace` too, since a per-event renderer is a new output path where a secret could surface.
- Event loss counters are **mandatory** in trace output — the design spec says a trace never silently pretends completeness. A trace that dropped events says so, on its own line.
- Kernel floor stays ≥5.15; the docs state it and the tool must fail with a clear message (not a panic or a verifier dump) on an unsupported kernel.
- All existing verification scripts keep passing: `verify-attach-e2e.sh`, `verify-induced-gaps.sh`, `verify-canaries.sh`, and everything under `scripts/matrix/`.
- `set -eu` as an explicit line in every script body.
- Commit style: short prefix + imperative.

## Inherited facts (verified)

- Phase 4 HEAD `41012fb`; 97 tests green; all 7 matrix rows green; G4 criteria met.
- `p11scope profile --mode profile|metrics` exists; **`trace` does not exist yet** despite being in the design spec's v1 scope and referenced by this phase's benchmark.
- The ring buffer, event drain (`events::Drain`, with `malformed()`), loss counter (`metrics::lost_events`), and semantic state machine already exist — `trace` is a renderer plus CLI wiring, not new kernel work.
- Measured privileges (Phase 4, real): host = `CAP_SYS_ADMIN` alone; Docker/kind = `CAP_SYS_PTRACE` + `CAP_SYS_ADMIN`. Neither needs full root. There is also a host-specific `perf_event_paranoid` finding in `docs/notes/phase4-privileges.md`.
- Schema is at `pkcs11-scope/observed-profile/v1.2` (`docs/schema/observed-profile-v1.md`), with per-cgroup breakdown.
- **Known UX gap**: no SIGINT handler — Ctrl-C aborts without writing output, and `--duration` is the only clean exit. For a long-running observer that is a release-quality problem (Task 2).
- The design spec's trace format (`docs/superpowers/specs/2026-08-10-pkcs11-scope-outputs.md`, "Trace mode" section) is the target: one line per completed call with timestamp, pid, tid, session pseudonym, function, mechanism + safe params, key pseudonym, CK_RV, duration; and `LOST n events` when the ring dropped any.

---

### Task 1: `trace` subcommand

**Files:** `src/main.rs` (subcommand + CLI), `src/trace.rs` (new renderer), `docs/schema/` or the outputs doc as needed.

`p11scope trace --manifest M (--pid N | --cgroup P) [--duration S] [-o FILE]`.

Per the design spec, `trace` is a **separate subcommand** rather than a `--mode`, because its transport and time-bounding differ: it streams per-call lines as events arrive instead of aggregating.

Output: one line per completed call, in arrival order, matching the spec's shape:
```
12:00:01.123456 pid 12345 tid 12401 sess#7 C_SignInit CKM_RSA_PKCS_PSS(hash=SHA256 mgf=MGF1_SHA256 salt=32) → CKR_OK 18µs
```
Use the existing pseudonym machinery — `sess#N`, never a raw handle. Mechanism and parameter rendering reuses whatever `render.rs` already does for the profile, so the allowlist is enforced by construction rather than re-implemented. Unknown mechanisms render as `0x…` verbatim.

**Loss reporting is mandatory**: at exit (and periodically for long runs), emit `LOST n events` when the counter is non-zero. A trace that lost events must never end silently.

`--duration` is effectively required for trace (it is time-bounded by design); if omitted, say so in `--help` and stream until interrupted (Task 2 makes interruption clean).

Tests: the line formatter is a pure function — test it directly (a known event renders to a known line; a vendor mechanism renders as hex; an errored call shows its CK_RV). Test that a non-zero loss counter produces the `LOST` line.

Commit: `scope: trace subcommand for per-call investigation`

---

### Task 2: Clean interruption

**Files:** `src/main.rs`, possibly `Cargo.toml`.

Today Ctrl-C aborts without writing output. For a tool whose primary use is "attach to a production process and watch for a while", that means an operator's capture is lost whenever they stop it — and `--duration` requires guessing the window in advance.

Install a SIGINT handler so Ctrl-C ends the capture *cleanly*: stop polling, print the final frame, and write the `-o` JSON. The existing no-new-dependency constraint from Phase 1b was a Phase-1b judgment; for a release this is worth a dependency if one is needed. Prefer the smallest option (e.g. `signal-hook`, or a small `libc`-based handler setting an `AtomicBool`) and justify the choice.

Both `profile` and `trace` must honor it. Update the `--help` note that currently documents the limitation.

Tests: a test that the interrupt flag path writes output (you can exercise the shutdown path directly without sending a real signal); plus a manual check documented in the report — start a capture, Ctrl-C it, confirm the JSON exists and is valid.

Commit: `scope: clean shutdown on SIGINT`

---

### Task 3: Overhead benchmark

**Files:** `scripts/bench-overhead.sh`, `docs/notes/phase5-overhead.md`.

Measure, on SoftHSM2 — deliberately the **worst case**, since its operations are µs-scale software crypto where probe overhead is proportionally largest (a network HSM's ms-scale calls would flatter the numbers):

| Condition | What |
| --- | --- |
| unobserved | workload alone, no probes attached |
| `profile --mode metrics` | maps-only aggregation |
| `profile --mode profile` | maps + event stream + state machine |
| `trace` | per-call event rendering |

Method requirements:
- A workload with enough calls that per-call cost is resolvable (the `hammer.c` fixture from the induced-gaps suite is a good base).
- **Multiple runs per condition** (≥5) reporting median and spread, not a single number — a single timing on a shared machine is noise.
- Report both wall-clock and per-call overhead in ns.
- Record the machine's kernel and CPU so the numbers are interpretable.

Publish the real numbers. If overhead is high, that is the finding — report it. Do not tune the benchmark to produce a flattering result.

Commit: `bench: measured overhead across capture modes`

---

### Task 4: Unsupported-environment behavior

**Files:** `src/main.rs` or `src/attach.rs`, `docs/notes/phase5-unsupported.md`.

The docs will state a kernel floor of 5.15 and describe behavior under lockdown. Both claims need to be true and verified rather than asserted.

- On a kernel or configuration where BPF loading is unavailable (lockdown, missing `CAP_BPF`/`CAP_SYS_ADMIN`, `perf_event_paranoid` restrictions, no BTF), the tool must fail with a **clear, actionable message** naming what is missing — not a raw verifier dump, not a panic, not a silent zero-count capture.
- Verify what actually happens today for each case you can induce (dropping capabilities is easy; raising `perf_event_paranoid` is easy; simulating an old kernel is not — say so rather than faking it).
- Improve the error messages where they are unclear.

Record the real observed messages in the notes file — those are what the docs will quote.

Commit: `scope: actionable errors for unsupported environments`

---

### Task 5: User documentation

**Files:** `README.md`, `docs/usage.md` (or similar).

Write the docs a first-time operator needs:
- What the tool does and, equally, **what it does not do** — the design spec's "What you will NOT see" list belongs here verbatim in spirit: no PINs, no key material, no plaintext, no raw handles.
- Quickstart: discover → profile → read the report.
- Privileges per environment, quoting Phase 4's **measured** values (`docs/notes/phase4-privileges.md`), not guesses.
- Kernel floor and unsupported-environment behavior, quoting Task 4's real messages.
- Overhead, quoting Task 3's real numbers with the caveat that SoftHSM2 is the worst case.
- The evidence/completeness model: what COMPLETE and PARTIAL mean, and why a PARTIAL report is still useful.
- An **honest-claims section**: what this tool proves and what it cannot. It observes a window; absence of a call means "not observed in this window", never "the application cannot do it". Aliased entries are ambiguous by construction. Requested attributes are not effective policy.
- Pointers to the privacy allowlist (`docs/privacy/allowlist-v1.md`) and the schema doc.

**Every quantitative claim must cite the script that measured it.** A reviewer will check.

Commit: `docs: user documentation for v0.1`

---

### Task 6: Release engineering

**Files:** `Cargo.toml` (version), `scripts/build-release.sh`, `CHANGELOG.md`.

- Set the workspace version to `0.1.0` (it is `0.0.0` today).
- A release build script producing the two artifacts the design calls for: the **fully static musl `p11scope`** (the observer never dlopens) and the **dynamic glibc + musl `p11scope-discover`** builds (a static helper cannot dlopen). Phase 1a's `scripts/verify-discover-containers.sh` already builds the discover variants — reuse that machinery rather than duplicating it.
- Verify each artifact: `file` output, `ldd` where applicable, and a smoke run.
- `CHANGELOG.md` for 0.1.0 summarizing the phases in user-facing terms.
- Confirm the schema doc is versioned and referenced from the README.

Commit: `release: v0.1.0 build script and changelog`

---

### Task 7: Gate G5 bookkeeping and final honesty pass

**Files:** `docs/superpowers/plans/ROADMAP.md`, plus corrections anywhere the pass finds them.

Gate G5 is: full-repo review, security review of the privileged tool as a whole, README claims cross-checked against measured reality, canary suite still green.

1. **Re-run every verification script** and record the results: `verify-attach-e2e.sh`, `verify-induced-gaps.sh`, `verify-canaries.sh`, all of `scripts/matrix/`, and `bench-overhead.sh`. Any failure is a release blocker.
2. **Cross-check the README against reality**: for each quantitative or behavioral claim, confirm the citation exists and says what the README says it says. Fix any drift. This is the criterion most likely to catch an overstatement.
3. Update the ROADMAP: map each G5 criterion to evidence; state the human-triggered items (`/code-review`, `/security-review`) as outstanding rather than claiming them.
4. Check `docs/notes/phase4-matrix.md`'s limitations section for anything now stale (e.g. `cgroup_id` was listed as unconsumed before Phase 4 Task 6 gave it a consumer).

Commit: `plan: record phase 5 status against gate G5 criteria`
