<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Production provider usage implementation plan

**Goal:** identify all used PKCS#11 providers in the supported observation
envelope, with positive execution evidence, late discovery and sound lifecycle
handling. Preserve detailed metrics/profile/trace and improve their scale and
overhead separately. Reporting only the successfully observed subset without
disclosing omissions does not satisfy the goal.

**Status:** authorized full-system campaign, implementation in progress. Source
baseline 7dee8b3; reviewed findings and live baseline are in
`audit-notes/perf/2026-09-22-production-review.md`. No release qualification or
numeric performance success is claimed by this plan.

## Controlling decisions

- A physical endpoint is the validated pinned object plus file offset. Equal
  paths or bytes do not merge different physical attachment identities.
- Compact inventory uses an atomic u64 constrained to 0/1 per endpoint. Only
  an in-scope entry probe may change 0 to 1. Mapping and publication cannot.
  It reads no ordinary arguments, emits no per-call events, and promises no
  return, success, latency, cryptographic-operation or exact call-count fact.
- The capture-local endpoint ID is immutable and not serialized. Positive use
  survives unload, retirement, attribution changes and resource cleanup. No
  reuse or automatic detail promotion until a separate lifecycle proof exists.
- Inventory admits all generically validated physical targets within explicit
  resource bounds. K4/K1 selection and fixture-specific pool names cannot be
  the production coverage policy. Every omitted required addition is a gap.
- Scope filtering precedes the first update. Shared physical execution cannot
  credit every possible logical publisher. No per-process attribution map or
  raw PID/instance/address output is required for the brief inventory contract.
- Detailed-mode behavior remains unchanged until its separate reviewed changes.
  Optional filtered detail does not substitute for broad detailed-mode scaling.
- Never equate entry-only ordinary probes with return-free discovery. Interface
  publication still needs a bounded output-pointer/table path and safety rules.

## Execution order and ownership

One Cargo-heavy command and one privileged BPF experiment at a time. No Cargo
or VM setup during performance comparisons. Independent reviewers inspect only
stopped patches. Worktrees isolate H qualification, oracle repair, performance
changes and the inventory implementation. Preserve unrelated main-tree changes.

### M: Repair independent measurement

Files: `scripts/system-scope-{measure.sh,measure.py,workload.c,receipt.py}` and
focused Python tests. Use a private provider copy, a live endpoint-to-map_files
receipt, PID birth checks and hash-bound observer provenance. All named and
unnamed system decisions must use receipt-matched rows. Missing trace ownership
cannot be replaced with a global total. Timeout/signal/nonzero observer outcomes
invalidate qualification. Publish handshake files atomically; bound collection
and cleanup. Test the actual parser/runner, not only constructed record objects.

Gate: raw-artifact foreign-traffic/failure regressions; privileged real-child
pin with no policy skip; bounded live PID-late and system-early cells. Keep
measurement generation distinct from capture acceptance in the exit contract.

### R: Retain DISCOVERY's consumer

Files: `src/attach.rs`, `src/events.rs`, focused runtime tests. Own one exact-map
reader and cursor per Session, like EVENTS. Preserve decoder, malformed record,
terminal and cancellation semantics. This is independent of scan scheduling.

Gate: repeated valid/malformed/empty/backlog behavior, real kernel map identity
and ownership test, independent review, then baseline/candidate syscall and
functional measurements. Do not infer a coverage fix or speedup from unit tests.

### I1: Carry inventory admission policy through every planner path

Files: `src/plan.rs`, `src/capacity.rs`, relevant tests. Introduce immutable
mode-specific admission policy and validated endpoint budget, keeping existing
detailed defaults. Cover bootstrap, rebuild, selection updates, extensions and
retirement. Inventory takes the full validated union without giving heuristic
tables semantic authority. Do not activate inventory through the experimental
environment variable or fixture symbol reconstruction.

Gate: 64 heuristic tables with zero publications and activity only in the last
table; mixed published/heuristic/forwarded/aliased targets; duplicate views;
equal-byte distinct objects; exact/over budget; append-only retirement. Existing
detailed tests must retain their meaning and behavior.

### I2: Compile and load the compact BPF variant

Files: `build.rs`, eBPF crates/native ownership, `src/lib.rs`, preparation in
`src/attach.rs`. Prefer a dedicated embedded object sharing discovery code.
Omit ordinary STATS/START/RV/EVENTS, decoders and return programs. Keep exactly
the scope, usage, discovery and lifecycle state that this mode needs. Inventory
native ownership must have no ordinary START references or 512-key exit sweep.

Gate: exact map/program/native ABI manifests, wrong-shape mutation rejection,
actual atomics/verifier load, concurrent first touches, scope exclusion and ABI
refusal before updates. Prove ordinary inventory creates no START state, return
links or events, and measure actual kernel map memory. Existing detailed object
and schema gates remain required.

### I3: Add entry-only attachment and publication discovery

Files: attach/run/safety and shared bounded discovery implementation. Singles
and multi need genuine entry-only static attachment and retirement. Scope and
capacity maps are fixed before attachment. Safe static entry attachment can
continue when return probes are unsafe, while unsafe discovery return hooks
remain refused and their coverage gaps are recorded.

Do not reuse AggregateOnly unchanged: it suppresses interface entry/return.
Provide publication-only C_GetInterface discovery for heap tables, retaining
source/context/output/table validation without selector strings or new public
selection metadata. Qualify NSS Interface hooks before changing their defaults.

Gate: return-hazard refusal, both static backends, actual interface-only late
heap table, hostile selector buffers, attach failure, and privacy canaries.

### I4: Make discovery progress renewable and fair

Files: discovery scan/scheduler/engine/identity. Separate renewable per-window
work/I/O/deadlines from bounded retained proofs and sticky lifetime evidence.
Separate expensive active scan views from compact generation-bound mapping
claims so a provider-bearing process cannot permanently occupy the only path
to a newly arriving provider. Losing a scan lease is not proof of unload.

Bound scan/attach work units, drain between them, and reconcile after lost
hints. Reconciliation must also revisit provider-bearing views. Preserve
physical pins and pending-work ownership while settling or cancelling work.

Gate: more than 256 provider-bearing processes then a unique new provider;
exhausted window followed by progress; more than 512 sequential table candidates;
lost/overflowed hints; oversized batch's final provider; cancellation. Evidence
must remain sticky when work allowance renews.

### I5: Integrate history, lifecycle, CLI and closed reporting

Files: `src/inventory.rs`, cli/run, dedicated renderer/schema and privacy tests.
Command: `p11scope inventory --system --duration ...`, with other supported
scopes using the same scope rules. Reject detailed-only decoder/event flags.
Use a separate provider-usage schema; never fabricate metric zeros.

Separate discovered/published, observed execution, current mapping presence,
attribution ambiguity and coverage gaps. Only existing allowlisted provider
identity fields and finite classifications enter public rows. No raw process,
generation, endpoint ID, pointer, interface name, loader identity or raw error.

Initially retain admitted entry links/cells through the bounded capture to
avoid rapid-reload attachment gaps. Unload releases its mapping/work/context
claim; another mapper retains observation. Incomplete reconciliation means
unknown liveness. Historical positive use remains. Read usage at reporting
cadence and termination, preserving the existing terminal uncertainty.

Gate: late load/use/unload/reload including a newly used endpoint after reload;
two sharers; pathname replacement; delayed callbacks; closed-schema/canary
mutations; real browser and multi-tenant provider workloads with independent
physical receipts. Missing supported exercised providers fail acceptance.

### D: Scale the detailed modes without changing their meanings

Compare actual dense/sparse memory and update costs including possible CPUs,
preallocation, first-touch failure and snapshot copying. Repair the misleading
sparse model before using it as evidence. Make task cleanup proportional to
owned active START state rather than the endpoint universe. Treat START, RV,
history, links and discovery limits independently. Cell reuse is a separately
reviewed generation/quiescence protocol, not a constant increase.

Gate: existing metrics/profile/trace oracles plus real broad provider admission,
concurrent invocation, exit cleanup, lifetime churn and terminal-loss accounting.

### H: Complete remaining qualification on final bytes

Repair the E16 runner's eight independent-review findings and its missing mixed
system/foreign-traffic cell. Then run the plan's kernel/backend, privacy,
multi-user/provider, performance, soak and recurring-CI gates on the final
integrated binary. A short fixture run does not satisfy long soak durations.
No push/publication is authorized. Commit verified work and preserve full state.

## Resource and measurement decisions

Endpoint capacity and eight-byte payload budget are checked with overflow-safe
arithmetic; actual map memory is measured separately. Static/dynamic links,
live objects, mapping claims, scan views, pending work, ring storage and scan
window budgets are independent bounds with explicit exhaustion evidence.
Reserve room for later arrivals because an array cannot grow in place. Defaults
must be justified by measured host/VM envelopes, not an unexplained new number.

Compare baseline/candidate application CPU and wall time, tracer CPU/RSS,
kernel map memory, links/FDs, discovery-to-attachment delay and teardown. Use
repeated paired runs on quiet lanes. Proposed SLOs must be stated before final
qualification and tested on representative workloads; none is inferred from
this plan or from Claude's unmeasured suggested thresholds.
