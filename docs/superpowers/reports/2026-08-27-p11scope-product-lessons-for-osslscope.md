# p11scope product lessons for osslscope

**Date:** 2026-08-27
**p11scope tree reviewed:** through `416d11fd6463b31cfe00d9917bf7fedf65513600`
**Purpose:** planning ledger, not a p11scope release verdict or an osslscope implementation plan
**Method:** independent static review plus focused tests, canonical workspace checks, and retained privileged Lane 02 evidence. No container or network experiment was run for this report.

## Executive verdict

The reusable core is narrower than “copy p11scope”: retained file identity, ELF file-offset attachment, one physical probe per `{object, offset}`, task scope before reads, bounded private discovery records, monotonic `PARTIAL`, and authenticated cleanup/evidence. The expensive part was repeatedly the lifecycle around those primitives: closing first-use races, distinguishing process and object generations, preserving terminal records through concurrent retirement, and proving that a gate measured the tree and process it claimed.

For osslscope, the smallest viable design is an owned-`run`, dynamic-provider-only, aggregate count/latency proof. It must observe `OSSL_provider_init`, `provider_query_operation`, and one digest implementation without private `ossl_*` layouts. It should not inherit p11scope's PKCS#11 table semantics, offline provider-loading helper, schema, or historical lease/oracle machinery. This is a **conditional GO** for that bounded spike and a **NO-GO** for universal already-initialized, built-in, static/LTO, ENGINE, or FIPS-compliance claims. See [the feasibility report](2026-08-26-openssl-scope-feasibility.md).

Status vocabulary:

- **CONFIRMED**: established by current code, retained local evidence, or an accepted historical result whose scope is explicit.
- **INFERRED**: supported by multiple code/evidence facts but not directly exercised for osslscope.
- **HISTORICAL/CLOSED**: materially affected p11scope and has a repository resolution; it remains a regression lesson, not a current defect claim.
- **CURRENT BLOCKER**: prevents the current Slice 1b-2 acceptance sequence or the corresponding strong product claim.
- **OPEN/UNVERIFIED**: proposed, stale, missing fresh authority, or lacking durable evidence.

## Shared observer-architecture lessons

### S01 — first-call assurance is a separate product mode — **IMPLEMENTED; GATE BLOCKED**

**Symptom/root cause.** Lane 02 r4 counted no bootstrap `C_GetFunctionList` in `dlopen/always`, and `auto` rows remained pause-partial. Discovery entry/return uprobes discover the table but do not update normal metrics; attaching normal probes only after the discovery return is too late for the bootstrap call. `marker_never_seen()` in `src/run.rs` is fixed false, so it cannot prove that an arbitrary protected application marker did not race attachment. **Non-causes:** successful SIGSTOP/SIGCONT, 68 slots, and 136/136 final probes do not prove the first call was observed.

**Impact/cost/status.** This invalidated the strong first-call claim despite clean teardown. Commit `878c3b9` installs one exact pinned, descriptor-zero, count-only `C_GetFunctionList` slot before resume and later merges real table evidence without duplicate cells or invented table authority. Commit `416d11f` corrects the verifier's former `/usr/bin/env LD_PRELOAD=...` exec chain by using a direct ELF with the exact provider forced into `DT_NEEDED`; all prior initial-set rows produced through the wrapper are non-promotable. A fresh direct-fixture campaign counted `C_GetFunctionList == 1` in every completed row, but Lane 02 remains unaccepted because rows 02/03/06 did not close the pause epoch.

**osslscope lesson/gate.** Treat “observe first provider call” as an explicit owned-run assurance contract, not a side effect of fast attachment. Before any broad surface, prove `provider_init -> query -> first digest call` with a protected pre-resume seed and an exact independent count oracle.

### S02 — signal request acceptance is not a stopped task group — **HISTORICAL/CLOSED**

**Symptom/root cause.** `bpf_send_signal(SIGSTOP) == 0` only means the request was accepted. Early Gate B work conflated acceptance with stop completion, used a winner-side busy wait, or used a later userspace timestamp to judge an earlier kernel hook. Scheduler/TCG timing then produced apparent variance and false FAILs. **Non-causes:** no kernel bisection or larger timeout was needed; direct task-state and dequeue ordering exposed the oracle defects.

**Impact/cost/status.** Two 120/120 campaigns were initially non-promotable; later amended campaigns, multiple cold VM boots, and lifecycle review were required. The production contract now requires an owned child generation, original pidfd, two exact all-`T` snapshots separated by at least 1 ms within 100 ms, drained/coalesced records, attachment, a third stopped snapshot, and exactly one resume. The history and measured attach delays are in [open issues](../../notes/slice1b2-open-issues-and-consequences.md), [the no-busy-wait amendment](../specs/2026-08-19-slice1b2-no-busy-wait-pause-amendment.md), and [the attach-first catalog](../../notes/slice1b2/attach-first-vs-timing-catalog.md).

**osslscope lesson/gate.** Freeze the finite state machine and oracle before runtime. Never busy-wait in BPF or make a later clock sample prove an earlier event; gate stop confirmation, one resume authority, child exit/reap, and empty pause maps.

### S03 — terminal teardown needs one authority and lossless handoff — **HISTORICAL/CLOSED**

**Symptom/root cause.** Live retirement, terminal drain, pause cleanup, and ordinary child exit could all try to consume or retire the same generation. Earlier implementations lost dequeued records, dropped post-dequeue generation/validation context, replayed retirement too broadly, or kept `fail_owned_prearm_attachment` outside the terminal journal. Focused green tests did not cover the reachable integration path.

**Impact/cost/status.** This was a long multi-commit repair (`6fa7fb3`, `78edc7f`, `89bc259`, `f960f99`, `57809a2`, `5e292d6`, `0627c6a`). It affected whether a child could remain stopped, whether records survived terminal handoff, and whether loss was falsely published. Commit `0627c6a` establishes owned terminal discovery cleanup; r4 reports no child residue, but does not close S01. Core symbols are `TerminalJournal`, `TerminalBatch`, `SessionPauseIo`, and terminal settlement in `src/discovery/pause.rs`, `src/discovery/engine.rs`, and `src/run.rs`.

**osslscope lesson/gate.** One terminal owner must preserve each dequeued record and its generation until authority-specific continuation finishes. Add one integration test that races provider unload/child exit with a queued discovery record and proves one cleanup, one retirement, no residue, and no invented loss.

### S04 — dynamic attachment is a transaction, not “append a link” — **CONFIRMED**

**Symptom/root cause.** Live discovery required additive slots, attach-cookie-selected descriptors, one discovery-ring reader, exact candidate/preflight/attachment rollback, alias-safe aggregate ownership, and retirement of links/views only after terminal records drain. A loader event alone is only a hint; it cannot publish a table or semantic claim.

**Impact/cost/status.** The work spans commits `35a69ab`, `0ce5cc2`, `f15aadd`, `eca3df9`, `4848b7a`, `2dfcc0c`, `886f632`, and many later lifecycle corrections. Internal support exists, but fresh Tasks 9.2d–9.4 and exact-tip CI remain open. The contract is in [the production plan](../plans/2026-08-19-slice1b2-production.md), especially Tasks 6–10.

**osslscope lesson/gate.** Use one bounded discovery ring and one transaction that binds process generation, provider generation, pinned object, dispatch ID, offset, attach cookie, aggregate owner, and rollback. Prove same-offset aliases produce one physical probe and one count cell before adding more operations.

### S05 — dynamic-loader callbacks are build-qualified hints — **CONFIRMED**

**Symptom/root cause.** On Ubuntu glibc 2.35/2.39, the first post-`RT_ADD` `RT_CONSISTENT` callback during `dlopen` preceded an ordinary relocation; the witness was still zero. Debian glibc 2.41 and Ubuntu 2.43 carried bug 31986's corrected ordering, while startup `initial_set` was positive on all tested glibc builds and musl 1.2.6 was only an exact-build positive. `dlopen` return is later and constructor-blind. **Non-causes:** `RTLD_NOW`, distro age, or a “new enough” version comparison do not establish ordering.

**Impact/cost/status.** This drove source-provenance research, five userland lanes, separate startup/dlopen controls, and the two-pause attach-first campaign. Exact evidence is in [glibc provenance](../../notes/slice1b2/glibc-31986-provenance.md) and [open issues I3–I5](../../notes/slice1b2-open-issues-and-consequences.md). p11scope avoided making a timing catalog critical by using an owned second pause for hidden tables.

**osslscope lesson/gate.** Treat `_dl_debug_state` as a rescan trigger. Key any timing capability by architecture plus exact loader and companion-libc SHA-256, not version text; test startup and `dlopen` separately with constructor markers.

### S06 — loader allocation IDs are not stable classification identity — **CURRENT BLOCKER**

**Symptom/root cause.** Lane 02 r4 saw three loader strategies where the oracle expected two. Replacement attachments for the same opened loader tuple received different `LoaderContextId` allocation/cookie identities, so public aggregation split one stable strategy. Commit `d175627` adds stable-identity deduplication. Two fresh post-fix campaigns no longer reproduced the three-strategy split in successful rows; the conservative unkeyed fallback still lacks a dedicated live negative control.

**Impact/cost/status.** The defect invalidated two initial-set rows after all 136 probes attached. [Lane 02 r4](2026-08-27-lane02-r4-findings-and-decisions.md) selects `Unbound`, `Bound(PinnedTimingKey)`, and privacy-safe `BoundUnkeyed(LoaderContextId)`; internal IDs never render.

**osslscope lesson/gate.** Separate lifecycle handles from stable evidence keys. Test replacement/re-arm of one exact provider object and require one public strategy, while an unprovable key stays conservatively unique and forces one bounded `PARTIAL` loss.

### S07 — Aya tracepoint attachment adds a tracefs DAC dependency — **OPEN/UNVERIFIED**

**Symptom/root cause.** Aya's classic `sched_process_exec`/`sched_process_exit` path reads `events/sched/*/id` from tracefs. An observer can have enough BPF/uprobe capability yet lack tracefs read permission. External PID sessions now degrade to named `PARTIAL`; owned `run` refuses before barrier release because it needs lifecycle proof. Commit `d6ae6e5` introduced the tier and `scripts/verify-capability-tier.sh`.

**Impact/cost/status.** This is a privilege-portability gap separate from uprobe permission. The current workaround is a tracefs mount readable by a dedicated group; raw-tracepoint lifecycle is explicitly post-v1 in [ROADMAP](../plans/ROADMAP.md). Branch `research/raw-tracepoint-lifecycle` points only to WIP configuration commit `24af620`; no product raw-tracepoint implementation or gate evidence exists.

**osslscope lesson/gate.** Decide early whether exec/exit proof is mandatory. Run the capability tier on the target distro before designing around Aya tracepoints; use raw tracepoints only if a focused prototype proves they remove tracefs DAC dependence without losing lifecycle semantics.

### S08 — capabilities differ by environment and kernel policy — **CURRENT BLOCKER**

**Symptom/root cause.** On the measured Ubuntu host with `perf_event_paranoid=4`, `CAP_BPF+CAP_PERFMON` created maps but attached 0/136 uprobes; `CAP_SYS_ADMIN` attached 136. Same-UID non-descendant memory scan additionally needed `CAP_SYS_PTRACE` under Yama or descendant ownership. Docker/kind cross-UID `/proc/<pid>/root` historically required `CAP_SYS_PTRACE+CAP_SYS_ADMIN`. Knative adds node/cgroup/topology and tracefs constraints. **Non-cause:** ordinary DAC read capability did not replace ptrace access to another UID's proc root.

**Impact/cost/status.** “Works with modern fine-grained caps” was not portable. Current host rows are measured, but the broader live-discovery Docker/kind matrix is still pending; historical rows must not be promoted. Sources: [privilege note](../../notes/phase4-privileges.md), [Slice 1b-1 proc facts](../../notes/2026-08-16-slice1b-1-spikes.md), [environment matrix](../../notes/phase4-matrix.md), and commits `d6ae6e5`/`2494fa9`/`a1774d6`.

**osslscope lesson/gate.** Publish a measured tier matrix, not one minimum. Gate same-UID owned run, host external PID, Docker-host, kind-host, and unsupported ordinary-container lanes separately; never infer container capability from host success.

### S09 — stored manifests, pathnames, and digests cannot authorize live attachment — **HISTORICAL/CLOSED**

**Symptom/root cause.** Earlier discovery could bind identity to an argv/path rather than the resolved mapping, accept a decoy, or use content identity where a path could be retargeted to a byte-identical inode. The first hardening response grew into fresh rediscovery, complete runtime-closure leases, a supervisor, and pre-main loader staging; this was correct for that contract but too expensive for the default product.

**Impact/cost/status.** The maximum review's B2/B3 findings and the later `$ORIGIN`/lazy-dependency/lease-break review drove a 12k-line hardening commit (`cdebf09`) plus follow-ups, then Productization Slice 1a deliberately removed more than 10k lines in `3a3ec28`. Current default authority is opened inode + fstat + SHA-256 + recheck/provider-changed, with exact retained process views. Sources: [maximum review](../../notes/2026-08-12-code-review-max.md), [metadata/provenance review](../../notes/2026-08-13-metadata-and-provenance-review.md), and [architecture decision A5–A7](../../notes/2026-08-15-architecture-and-gap-analysis.md).

**osslscope lesson/gate.** Keep pathname discovery separate from attachment authority. Start with retained regular-file fd, exact mapping relation, SHA-256, dev/inode/size/ctime snapshots, and sticky change evidence. Do not create an offline provider-loading or lease-supervisor lane unless a measured threat model requires it.

### S10 — process generation must survive scan, attach, exec, and exit — **HISTORICAL/CLOSED**

**Symptom/root cause.** PID reuse, exec replacement, cgroup-member exit, and terminal scan could make a once-valid identity stale. Earlier code counted proven exec/exit or a later successful scan as discovery loss, retained stale contributions, or allowed retirement of one owner to remove another owner's shared target.

**Impact/cost/status.** These were correctness and cleanup failures fixed through retained `ProcessView` ownership and a long series including `2a004f3`, `161ee1b`, `4cdb836`, `fae1d7f`, `fee8e0e`, `fe97439`, `f2c1d83`, `14ae5ff`, and `1bd16e0`. Core code is `src/process.rs` plus generation-bound paths in `src/discovery/engine.rs`.

**osslscope lesson/gate.** Key private state by process start-time generation, not PID, and provider state by a separate generation. The smallest regression is exec/unload/exit between discovery dequeue and attach, followed by PID reuse; no old record may authorize the new process.

### S11 — overlay identity is useful but not globally provable — **CONFIRMED**

**Symptom/root cause.** The same lower-layer inode can appear under different overlay device numbers. Comparing full `dev:ino` falsely rejected real shared-layer captures; comparing only inode can falsely collapse byte-identical objects from distinct overlay instances.

**Impact/cost/status.** The validated common case attaches once and observes exact calls from two containers, but the collapse remains explicit uncertainty and forces `PARTIAL`. Commits `f9dbc6b`, `9b9792d`, `e10cb7c`, the [matrix](../../notes/phase4-matrix.md), and [ROADMAP topology qualification](../plans/ROADMAP.md) preserve both the win and the limit.

**osslscope lesson/gate.** Log full identities, collapse only under a named overlay policy, and independently prove each workload's exact count. Do not use equal inode or equal bytes alone as physical-identity proof.

### S12 — ELF offsets and executable inspection need independent bounds — **HISTORICAL/CLOSED**

**Symptom/root cause.** SoftHSM2 had equal `p_offset`/`p_vaddr`, so the feasibility spike could not distinguish Aya's offset contract. A separate non-PIE control proved `UProbeAttachLocation::AbsoluteOffset` is the ELF file byte offset. Later, malformed non-overflowing PT_LOAD ranges past EOF were accepted until `8f669eb`. Pre-exec loader arming also hashed the entire application executable merely to read `PT_INTERP`, consuming the shared discovery budget and making very large executables operationally expensive; `a2fd9ee` replaced that with bounded ELF-header/program-header/`PT_INTERP` preads and snapshot rechecks.

**Impact/cost/status.** Wrong offset semantics silently probes the wrong instruction; unbounded hashing delays or prevents first-use protection. Sources: [Aya offset pin](../../notes/aya-offset-semantics.md), `crates/manifest/src/elf.rs::ElfSnapshot::read`, `src/discovery/engine.rs::read_bounded_interpreter`, and commits `3831273`, `8f669eb`, `a2fd9ee`. Commit `a2fd9ee` includes `two_gib_dynamic_executable_arms_without_hashing_the_executable`, which extends a real dynamic executable to exactly 2 GiB + 11 MiB and proves loader arming without hashing that executable. The exact test passed again on 2026-08-27 in the current worktree. This proves the bounded `PT_INTERP`/loader-arm path, not every large-provider or malformed-ELF path.

**osslscope lesson/gate.** Keep offsets as checked `u64`, validate executable segments against file length, and read only bounded ELF structures when locating an interpreter. Add sparse >1 GiB and near-2 GiB ELF fixtures early, asserting bounded bytes read and unchanged offset resolution without hashing the executable.

### S13 — fixture markers and diagnostic evidence can race or disappear — **CURRENT BLOCKER**

**Symptom/root cause.** A log marker can be emitted after one discovery iteration drained but before its frame rendered; `verify-task4-lane02.sh::wait_mapped_and_drained` therefore needs two later frames. Production's fixed-false marker is not a real negative oracle. Lane 02 row 05 also discarded the internal reason for its exact auto failure, leaving no retained category to separate authorization, task-state, queue, attach, marker, resume, or lifecycle failure.

**Impact/cost/status.** Timing-only logs caused false evidence and prolonged root-cause work. The gate now guards several rendering races, but a real private marker probe and finite failure-category diagnostic remain missing. See [Lane 02 r4](2026-08-27-lane02-r4-findings-and-decisions.md), `src/run.rs::marker_never_seen`, and `scripts/verify-task4-lane02.sh::wait_mapped_and_drained`.

**osslscope lesson/gate.** Evidence needed for an assurance claim must be captured at the event boundary, not inferred from asynchronously rendered text. Retain finite privacy-safe categories and test one deliberately interleaved marker/frame sequence.

### S14 — container gates must authenticate owned process cleanup — **HISTORICAL/CLOSED**

**Symptom/root cause.** Gate scripts could kill or validate a process by a shell-level command string without proving PID generation, session membership, executable bytes, and exact argv. Snap's `/snap/bin/kubectl` wrapper execs revisioned `/snap/kubectl/<rev>/kubectl`, so expecting argv0 `kubectl` was false. Release URLs, generated eBPF identity, process groups, and cleanup receipts also drifted or were under-bound.

**Impact/cost/status.** A gate could report clean while signaling the wrong process or consuming changed infrastructure. Commits `34357b5`, `99abb31`, `516f00b`, `a98cca3`, and `fd3d08a` bind input bytes, release ownership, generated ELF identity, starttime/SID/argv/exe hash, cleanup, and quiescence. The exact Snap shape is retained in the non-portable local attempt-6 evidence referenced by [ROADMAP](../plans/ROADMAP.md); no private payload is needed here.

**osslscope lesson/gate.** Every external helper must have an authenticated launch and teardown receipt. Snapshot `{pid,starttime,sid,exe hash,argv}`, reject unexpected descendants, and prove the cluster/container/session is absent after cleanup.

### S15 — privacy gates can be green while observing nothing — **HISTORICAL/CLOSED**

**Symptom/root cause.** The first canary gate dumped maps after workload exit, when START state was empty; ring buffers could not be dumped by the chosen path, and stale/raw-pointer allowlist citations drifted. A clean scan was therefore partly vacuous. Safe metadata also initially placed a transient raw `pMechanism` pointer in START without an explicit allowlist row.

**Impact/cost/status.** This undermined the project's strongest security claim and caused a full safe/unsafe policy redesign. The current gate samples live observer-owned maps, has a positive control, hostile pointer-alias cases, finite equality oracles, frozen policy maps, and a default release with unsafe decoders absent. Sources: [maximum review D1](../../notes/2026-08-12-code-review-max.md), [metadata review G8](../../notes/2026-08-13-metadata-and-provenance-review.md), README privacy contract, `scripts/verify-canaries.sh`, and `scripts/dump-owned-bpf-maps.py`.

**osslscope lesson/gate.** Start aggregate-only. Never emit provider/property strings, pointers, contexts, `OSSL_PARAM` values, or call buffers. Require a live-map and output canary with a positive control before adding any metadata.

### S16 — terminal completeness and event transport are structurally limited — **CONFIRMED**

**Symptom/root cause.** Detaching perf links stops new invocations but cannot prove callbacks already running on another CPU have drained. A small ring and coarse polling also lose most per-call events under a 1M-call/s hammer, although aggregate maps remain exact. Earlier docs/gates called terminal results `COMPLETE` and some scripts retained that impossible assertion.

**Impact/cost/status.** Current terminal profiles are always `PARTIAL`; “clean” means concrete gap counters are zero, not a proven final drain. Induced loss remains explicit, and aggregate maps are count authority. Resolution commits include `57a8766`, `edbe1c5`, `7774bf6`; see [README honest claims](../../../README.md), [usage overhead/evidence](../../usage.md), and `scripts/check-capture-evidence.py::terminal_capture_is_clean`.

**osslscope lesson/gate.** Separate discovery-ring loss, call-event loss, in-flight overwrite/recursion, and unproven terminal drain. Exact count acceptance must come from aggregate maps; traces are diagnostic and lossy.

### S17 — evidence campaigns fail from oracle and diagnostic defects too — **CONFIRMED**

**Symptom/root cause.** Gate A produced a 16.8 MB verifier log and 331k lines, exceeded evidence caps, and timed out under TCG; the root cause was verifier state explosion from an 896-byte memset-shaped initializer under interface fan-out, not disk space. Straight-line constant-offset stores fixed it. Later Gate B rows failed because the oracle compared a successor kernel hook to a later userspace resume sample. Historical matrix records also lacked enough topology identity to serve as unchanged controls.

**Impact/cost/status.** Substantial effort went into bounded STATS diagnostics, KVM versus TCG classification, immutable campaigns, corrected oracles, and negative controls. Current Lane 02 still lacks one failure-category diagnostic, and fresh r3/9.2d evidence is pending. Sources: [open issues I1–I2/I7](../../notes/slice1b2-open-issues-and-consequences.md), [Gate A/B plan](../plans/2026-08-18-slice1b2-open-issues-research-plan.md), and [next gates](../plans/2026-08-25-slice1b2-next-gates.md).

**osslscope lesson/gate.** Bound logs and time separately from verdicts; `TIMEOUT/INCOMPLETE`, `FAIL`, and `UNRUN` are distinct. Mutation-test the oracle and retain enough input identity to reproduce a row before spending on a large matrix.

### S18 — local green checks do not supply runtime or CI authority — **CURRENT BLOCKER**

**Symptom/root cause.** Current Slice 1b-2 production and focused tests are extensive, but privileged host/container/VM lanes, fresh r3/9.2d/9.3/9.4, and exact-tip CI require separate authority and infrastructure. Missing KVM, sudo, base hashes, harness, or push/workflow authority is `UNRUN/blocked`, never PASS.

**Impact/cost/status.** README remains unreleased; Lane 02/r3/9.2d are locked. [ROADMAP](../plans/ROADMAP.md), [production Tasks 9–10](../plans/2026-08-19-slice1b2-production.md), and [gate closure Tasks 6–9](../plans/2026-08-25-slice1b2-next-gates.md) name the missing evidence.

**osslscope lesson/gate.** Design a cheap unprivileged ABI/object/checker lane first, then request one narrowly frozen privileged dynamic-provider lane. Do not design a full deployment matrix before the smallest provider proof passes.

### S19 — output and embedded-artifact reliability need behavioral gates — **HISTORICAL/CLOSED**

**Symptom/root cause.** Earlier trace sinks discarded write/flush errors and could panic on EPIPE before final loss reporting; release builds could embed a stale eBPF object because build freshness checks were too weak. Output paths also needed symlink/FIFO/foreign-owner refusal and atomic publication.

**Impact/cost/status.** Disk-full or broken-pipe could silently truncate evidence; a stale object could make source and runtime behavior diverge. Corrective work introduced result-propagating sinks, private regular-file creation, identity-safe temp/fsync/rename, BPF capacity/object guards, and generated-object receipts. Sources: [maximum review D2/F2](../../notes/2026-08-12-code-review-max.md), commits `99ddcf3`, `97bcc32`, `97ec8d6`, `2be35e8`, `cdebf09`, and Lane 13 generated-BPF tests in `tests/artifact_contracts.rs`.

**osslscope lesson/gate.** Make the embedded BPF object's bytes and map/program inventory part of every evidence receipt. Induce disk-full/broken-pipe and stale-object mutations in one unprivileged artifact-contract lane.

### S20 — one fixed pause epoch spans variable-cost synchronous work — **CURRENT BLOCKER**

**Symptom/root cause.** The approved pause coordinator derives one absolute deadline at `hook_ts + 100 ms`. That causal epoch remains in force across synchronous discovery processing, but `apply_discovery_batch_with` is not deadline-parameterized or generally checkpointed: scan/pin/ELF work, planning, and probe attachment can consume or overrun the epoch, and expiry is normally detected only at the next stopped/dequeue/resume boundary. In the first fresh direct-`DT_NEEDED` campaign, initial-set/never measured a 187 ms attach gap, initial-set/auto later reached 136/136 and the exact bootstrap count but retained an unconfirmed partial pause, and initial-set/always failed closed with required-attachment and deadline-boundary errors. The same campaign's `dlopen/always` row crossed the pause-confirmation deadline. These results prove deadline sensitivity but do not yet isolate which stage consumed row 02 or whether row 03 first became incomplete before or after expiry.

**Impact/cost/status.** A fixed-budget/workload mismatch is the leading hypothesis, not a selected product diagnosis. The direct fixture is valid, and public `initial_set_capture.none` plus `initial_set_timing.unproven` remain intentional for the unqualified glibc tuple. A later predeclared diagnostic classified bounded pause phases across four identical 100 ms campaigns; its target result was `PASS/PASS/FAIL/PASS`, so it selected no timeout or product change. That campaign is closed. Any further diagnostic requires a new reviewed plan and fresh roots.

**osslscope lesson/gate.** Budget the whole protected window, not only signal delivery. Measure scan, pin, ELF, attach, and scheduler tails independently before freezing one absolute pause ceiling; never reset the deadline per stage or claim first-call assurance from a later exact count.

## PKCS#11-specific problems: do not generalize blindly

### P01 — PKCS#11 semantic state was initially wrong — **HISTORICAL/CLOSED**

**Symptom/root cause.** Stale operation bindings inflated unrelated calls; `C_FindObjectsFinal` cleared crypto binding; `C_CloseAllSessions` used the wrong argument; sessions were not retired; failed logins counted as success. Later multi-module/async work also exposed process/module/handle ownership errors.

**Impact/cost/status.** Profiles could be numerically wrong while attachment was perfect. [Maximum review A1–A5](../../notes/2026-08-12-code-review-max.md) drove the corrective semantic model and regressions; later commits `418c74b`, `64571c2`, `33f451c`, `377b951`, and `50f9a35` fixed multi-module/async ownership.

**osslscope lesson/gate.** Do not copy session/mechanism/handle logic. Start with stateless aggregate function IDs; add context semantics only after an operation-specific OpenSSL fixture proves ownership and recursion behavior.

### P02 — positional table walking created wrong-object and out-of-bounds probes — **HISTORICAL/CLOSED**

**Symptom/root cause.** Resolver scope could attribute a dependency's function to a wrapper, manifest identity could come from the requested path rather than the pointer's mapping, and short legacy tables were read past their ABI boundary, producing offsets into unrelated code such as libc. **Non-cause:** stripped symbols were not the problem; pointer-to-mapping resolution was.

**Impact/cost/status.** The observer could attach to the wrong object/instruction. Corrective tests cover dependency identity, decoys, version boundaries, short-table refusal, and exact pointer mapping; see [maximum review B2–B4](../../notes/2026-08-12-code-review-max.md), `cdebf09`, and the shared `pkcs11-module::tables_for()` contract in [ROADMAP Phase 1](../plans/ROADMAP.md).

**osslscope lesson/gate.** OpenSSL dispatch is ID-tagged rather than positional/version-prefix. Decode bounded `{function_id,function}` entries and resolve every pointer independently to its executable mapping; never infer object identity from the provider DSO named by the operator.

### P03 — scan discovery is not semantic authority — **CONFIRMED**

**Symptom/root cause.** Memory scans can identify table-shaped pointers but cannot prove a canonical PKCS#11 role/name. Manifest and scan sources can corroborate, conflict, be revoked, or disappear across generations. Earlier arithmetic let revoked corroboration or duplicate occurrences affect authority.

**Impact/cost/status.** Exact counts may still be useful, but semantic joins can become deceptive. Current scan-only slots are count-only/PARTIAL; exact manifest claims apply only to their pinned object/offset/name; conflicts remain ineligible. Sources: [semantic-authority contract](../specs/2026-08-18-slice1b1-semantic-authority-contract.md) and commits `906753a`, `389c485`, `0467be0`, `298b626`, `a7d4cc6`, `778f43a`.

**osslscope lesson/gate.** Public OpenSSL IDs are stronger than PKCS#11 scan heuristics, but a dispatch pointer still needs observed init/query provenance. A static catalog names IDs; it does not authorize a runtime pointer or provider selection.

### P04 — fixed slot capacity and proxy closure force honest partial coverage — **CONFIRMED**

**Symptom/root cause.** A 512-slot attach ceiling is capture-wide. p11-kit's fixed closure can exceed it; shared offsets and aliases complicate capacity and aggregate ownership. Earlier planning considered capacity per fragment instead of the complete module union.

**Impact/cost/status.** p11-kit may be refused whole while a later-fitting SoftHSM backend attaches, with `PARTIAL`, not silent truncation. Fixes include `fdde185`, `faba69f`, and later dynamic-capacity/alias work. See [README honest claims](../../../README.md) and `src/plan.rs`.

**osslscope lesson/gate.** Set caps per provider, operation, algorithm, dispatch entries, and total physical probes. Reject or explicitly truncate before partial attachment can create a misleading semantic subset.

### P05 — one-shot discovery misses late modules — **CURRENT BLOCKER**

**Symptom/root cause.** Slice 1b-1 scans only mapped providers at attach. A later `dlopen` of a previously unknown inode/table is missed; a manifest cannot retroactively repair the capture window. Shared-inode preattachment only helps when the inode is already known.

**Impact/cost/status.** Current public late-provider coverage remains unsupported until Tasks 6E–10 and fresh gates complete. See README status, [open issues I8–I9](../../notes/slice1b2-open-issues-and-consequences.md), and [ROADMAP](../plans/ROADMAP.md).

**osslscope lesson/gate.** Dynamic OpenSSL providers make this the MVP path, not a later feature. The first osslscope proof should start before provider init; external already-running capture must remain explicitly partial/unsupported.

### P06 — an offline helper can execute the thing being observed — **HISTORICAL/CLOSED**

**Symptom/root cause.** `p11scope-discover` loads a provider to obtain tables. That simplified first-attach races but introduced provider execution, `$ORIGIN`/lazy-dependency behavior, helper/runtime ABI matching, pre-main provenance, leases, and supervisor teardown. Productization later made memory scan the default and kept the helper optional.

**Impact/cost/status.** This was the largest avoidable complexity detour: hardening commit `cdebf09` and follow-ups were later reduced by `3a3ec28`. The rationale is recorded in [architecture Q&A A1/A5/A7](../../notes/2026-08-15-architecture-and-gap-analysis.md).

**osslscope lesson/gate.** Do not make an offline helper initialize an OpenSSL provider: it may run self-tests or touch hardware and cannot prove the target's fetch state. Observe the target's public provider ABI or stop at inventory-only.

### P07 — cgroup/task scope is separate from inode scope — **HISTORICAL/CLOSED**

**Symptom/root cause.** Early cgroup descendant matching used the wrong level model; an inode-wide uprobe sees every task using that inode unless the BPF program filters the task first. PID scope also does not automatically follow forks.

**Impact/cost/status.** Under-scoping could count another container using the same shared provider inode. Native cgroup membership and fork lifecycle fixed the accepted cgroup path; shared-layer gates prove A-only and B-only exact counts. Sources: [maximum review B1](../../notes/2026-08-12-code-review-max.md), commits `af38efb`/`71049d2`, and [matrix shared-layer proof](../../notes/phase4-matrix.md).

**osslscope lesson/gate.** Authorize PID/cgroup before every target-memory read and aggregate update. Include two concurrent containers on one libcrypto/provider inode as a negative scoping control.

## OpenSSL-specific unknowns: p11scope history does not answer these

### O01 — already-initialized and built-in providers are opaque — **OPEN/UNVERIFIED**

If `OSSL_provider_init` and query returns were missed, provider dispatch is already inside opaque libcrypto state; built-in providers need not expose a generic dynamic-init symbol. Stable public APIs do not recover that state. This is the feasibility report's decisive unsupported path, not a p11scope implementation defect. **Gate:** require owned-run dynamic-provider success and keep external, built-in default-provider, and already-initialized cases `PARTIAL`/unsupported. Reject the architecture if success needs private `ossl_*` layouts.

### O02 — query tables can change or expire — **OPEN/UNVERIFIED**

`provider_query_operation`, `no_store`, `provider_unquery_operation`, unload/reload, secondary DSOs, and shared implementation pointers mean a captured `OSSL_ALGORITHM`/`OSSL_DISPATCH` table is not a permanent manifest. **Gate:** one fixture with `no_store=0/1`, changed results, unload/reload, same-offset aliases, and an in-flight unload; require explicit generations, one physical probe per offset, no stale attribution, and sticky loss.

### O03 — OpenSSL 3/4, ENGINE, static/LTO, and FIPS are different products — **OPEN/UNVERIFIED**

OpenSSL 4 is a new major; separate catalogs and build validation are required. ENGINE is a different 3.x architecture and removed from OpenSSL 4 shared libraries. Static/LTO may erase the dynamic boundary. Uprobes change timing, and no reviewed source establishes FIPS validation neutrality. **Gate:** separate 3.x/4.x header-derived catalogs; explicit negative fixtures; default FIPS posture audit-only outside provider code. Defer ENGINE, static/LTO, and any FIPS-compliance claim.

### O04 — concurrency and causality are not solved by exact offsets — **OPEN/UNVERIFIED**

Independent `OSSL_LIB_CTX`, threads, OpenSSL ASYNC, recursion, aliases, fetch caching, and implicit fetch can share provider functions. Exact provider-call counts do not prove which public EVP call or provider selection caused them. **Gate:** task+attach-cookie entry state, overwrite/recursion/missing-return counters, multithread/ASYNC fixtures, and explicit rejection of exact EVP-to-provider causality in the MVP.

## Prioritized osslscope risk register

| Priority | Risk | Evidence level | Impact | Earliest decisive gate |
| --- | --- | --- | --- | --- |
| 1 | Missed init/query/first provider call | p11scope current blocker + OpenSSL confirmed boundary | Product's core count claim false | Owned-run dynamic digest fixture; protected init/query/first call exact counts |
| 2 | Stale provider/process generation or wrong mapped object | Repeated p11scope historical defects | Wrong code probed or calls misattributed | Exec/unload/reload/PID-reuse and secondary-DSO fixture with retained fds |
| 3 | Dynamic table lifetime, aliases, recursion | OpenSSL open | Double counts, stale links, corrupt latency | `no_store`, unquery, shared-pointer, ASYNC and unload-in-flight fixture |
| 4 | Privilege/tracefs portability | p11scope confirmed/current blocker | Owned run refuses or external capture silently degrades | Host capability+tracefs preflight before any container matrix |
| 5 | Evidence/cleanup authenticity | p11scope repeated gate failures | False PASS, residue, or wrong process signaled | Content-addressed receipt plus PID/starttime/SID/argv/exe and quiescence |
| 6 | Privacy leak from strings/pointers/params | p11scope historical critical gate defect | Key/config/provider data exposure | Aggregate-only live-map/output canaries with positive control |
| 7 | Ring/terminal loss hidden as completeness | p11scope confirmed structural limit | Overconfident negative evidence | Induced discovery/call loss and terminal PARTIAL assertions |
| 8 | Built-in/static/FIPS scope pressure | OpenSSL confirmed/open | Unachievable universal claim | Predeclared negative lanes; NO-GO if MVP requires private internals |
| 9 | Overlay/cgroup cross-attribution | p11scope confirmed | Another workload's calls counted | Two workloads sharing inode, exact per-scope counts |
| 10 | Large/malformed ELF behavior | p11scope 2 GiB + 11 MiB loader-arm regression confirmed; broader provider shapes open | Startup delay, budget exhaustion, wrong offset | Reuse the exact large-executable control; add large provider and malformed-range bounded-read tests |

## Do first / defer

### Do first

1. Freeze a tiny C dynamic provider and EVP digest oracle: init, one query, `{NEWCTX, INIT, UPDATE, FINAL, FREECTX}`, two digest operations.
2. Build only an owned-run pre-exec lifecycle: retained process generation, exact PT_INTERP/loader, observed provider init/query, protected first call, one resume authority.
3. Resolve every dispatch pointer to a retained file-backed executable mapping and checked ELF file offset; one physical probe/cell per `{object, offset}`, explicit aliases.
4. Add monotonic loss evidence and aggregate-only privacy before broadening operations: discovery loss, entry overwrite/recursion, missing return, attach/detach failure, identity change, terminal drain.
5. Run the smallest gates in order: malformed ABI/object self-tests; owned dynamic-provider exact counts on OpenSSL 3.5 and 4.0; canaries; capability/tracefs preflight; only then Docker/kind.
6. Keep a separate osslscope schema and repository. Extract shared p11scope code only after this second consumer proves the boundary.

### Defer

- external PID/cgroup completeness and already-initialized recovery;
- built-in default-provider dispatch, static/LTO, ENGINE, and exact EVP-to-provider causality;
- provider strings, properties, `OSSL_PARAM`, buffers, return payloads, provider-to-core upcalls, and operation-specific semantic decoding;
- FIPS provider-function probing or compliance language without deployment-owner/vendor/lab guidance;
- raw-tracepoint migration unless the measured tracefs tier blocks the supported owned-run environment;
- cluster operator/DaemonSet, AArch64, Windows/macOS, long version matrices, and a generic observability framework.

## Validation and quality verdict

**Remaining p11scope acceptance gap:** the completed campaigns did not isolate a consistent timing stage or authorize a production bound. Any further timing experiment requires a new reviewed plan and fresh roots. Only a separately selected and measured production change could precede a promotable fresh six-row run. The exact bootstrap count is proven; the pause epoch and generic private-marker claims remain separate.

**Smallest decisive osslscope test:** one owned dynamic provider digest whose init/query and first implementation call are all observed and counted exactly on stripped/PIE builds without private OpenSSL internals, duplicate alias counts, leaked canaries, or stale state after unload.

**Quality verdict:** p11scope provides strong reusable invariants and unusually candid evidence semantics, but its history is a warning against beginning with broad lifecycle, metadata, deployment, or universal-coverage claims. osslscope should proceed only with the narrow dynamic-provider owned-run proof above. The repository evidence is insufficient to claim fresh Slice 1b-2 acceptance, portable non-root/container operation, raw-tracepoint readiness, exact-tip CI, or broad large-provider coverage; the narrower 2 GiB + 11 MiB executable loader-arm path is confirmed.

## Source gaps and non-portable evidence

- Lane 02 r4's private evidence root is named in [its report](2026-08-27-lane02-r4-findings-and-decisions.md). It is local/non-portable and was not copied or quoted here.
- Lane 13 attempt-6's private local root/hash is named in [ROADMAP](../plans/ROADMAP.md). Only its public process-shape lesson is used here.
- The committed `a2fd9ee` regression records and reproduces an exact 2 GiB + 11 MiB executable loader-arm experiment. It does not cover a provider DSO of that size, every sparse layout, or every malformed large ELF.
- The raw-tracepoint branch contains no product implementation at its current tip; only the tracefs degradation and post-v1 roadmap are current evidence.
- Two post-`878c3b9` wrapper-based Lane 02 campaigns exist at private local roots `lane02-20260827-bootstrap-gu7qTY/evidence` and `lane02-20260827-repeat-Sl5FTh/evidence`; their initial-set rows are non-promotable because the wrapper added an unhandshaked second exec. The first corrected direct-fixture campaign is retained at `lane02-20260827-direct-416d11f/evidence`; rows 01/04/05 pass and rows 02/03/06 preserve the pause-deadline failure. Fresh r3/9.2d/9.3/9.4, broader live capability-matrix, and exact-tip CI results remain unavailable.

## 2026-08-27 pause-phase campaign lesson

### Confirmed

Four predeclared 100 ms campaigns were identity-comparable and cleanup-safe,
yet the protected target was PASS/PASS/FAIL/PASS. The sole failure retained
`later_pause_boundary`, not a phase-selecting Engine token. Cleanup truth and
functional truth were correctly kept separate: all 24 rows cleaned up while
several rows still failed their oracle.

### Contradicted

The phase classifier did not yield a consistent target category and did not
authorize a timeout or code-path optimization. A clean process exit,
stable hashes, and complete cleanup cannot be promoted into a functional PASS.

### Missing

The roots retain bounded row logs and tokens but no exact diagnostic-diff hash;
their caller-owned files are mutable and unsealed. The ancestry also carried an
unrelated repair even though the diagnostic commit itself was isolated.

### Decision for osslscope

Every experiment receipt should pin the exact source diff as well as the
commit/tree, and the gate should verify the allowed changed-path set before
runtime. Preserve finite stage tokens and row logs after cleanup. Predeclare
contradictions so a PASS/FAIL mixture stops product changes instead of inviting
post-hoc timeout tuning. This result selects no p11scope fix and no osslscope
timing design and authorizes no replacement or repeat run; a future experiment
needs a new reviewed plan and fresh roots.
