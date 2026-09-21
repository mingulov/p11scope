<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Synthesized Audit Findings: p11scope @ feat/system-scale

## Revalidation and system review — 2026-09-21

**Current reviewed production revision:**
`885ed651f1c549162a0537642b1c78ffc61a83e3` (`feat/system-scale`). The original
`cb6337d` synthesis is retained below as historical evidence; its severity
counts, “confirmed” labels and recommended actions are not a fresh verdict
on every finding. This section supersedes conflicting claims there.

Scope: recheck the supplied audit and performance reports, investigate
provider-independent `--system` coverage, and prepare proposals and experiments.
Three bounded read-only reviewers investigated existing findings, discovery
and performance; the primary checked material claims, ran host tests and
integrated the results. This is not an exhaustive new repository security
scan or a claim that every historical hypothesis has been reproduced.

Validation rubric applied to each promoted/corrected claim:

- [x] Identify the current source path and affected input/operating condition.
- [x] Trace the actual control/producer/consumer, not merely an adjacent path.
- [x] Check mitigating controls and distinguish security, correctness,
  coverage, maintainability and release-qualification impacts.
- [x] Record direct test evidence where obtained; retain the exact proof gap
  where no reproduction was obtained.
- [x] Attach a next experiment/acceptance condition to unresolved mechanisms.

### Fresh verification and the system result

The fresh release binary's SHA256 is
`26f262476beca8a25bd3c5494223c537eee72cc975f6b3e4ffcbfcac26420771`.
Build succeeded on Rust 1.88. The focused system-scope/map/task-owner tests
passed **10/10**; the library suite passed **1,201**, failed **0**, ignored
**4** (162.25 s). Formatting, workspace/all-targets check and clippy with
denied warnings passed; the full workspace/all-targets test command was
not run. These tests do not replace live BPF qualification.

With the user's explicit authorization, three repetitions of PID/system ×
metrics/profile ran on kernel `7.0.0-31-generic` using the existing gated
SoftHSM workload. **All six PID cells captured their 20,006 expected calls;
all six system cells captured zero of 20,002 post-GO calls.** All returned
exit 0 and PARTIAL, with zero CALL-ring loss. The system cells also lost
2,344–4,456 discovery records and initially refused additional 68-slot
providers after allocating 478 of 512 slots. Matching a pathname on another
physical object is not proof of workload admission.

This reproduces the practical impact of F-23 and establishes a failed system
coverage baseline. It does not identify one exclusive cause for every missing
process/object; E05/E06 distinguish scan-cap selection from physical admission.
System spawn-to-GO was 61.97–68.67 s, wall time 81.12–86.06 s and sampled peak RSS
664.45–726.32 MiB. These are loaded-host observations, not SLOs. Details,
profiling, measurement caveats and artifact locations:
[perf/REPORT.md](perf/REPORT.md).

### Existing findings: corrected dispositions

| ID | Current disposition and evidence |
|---|---|
| F-01 | **Confirmed safety gap, narrowed.** Unknown kernel + unknown target proceeds (`uretprobe_hazard.rs:105`); wide scope supplies no target (`:184`). This host's owned self-probe was clean. `run` lacks that preflight, but a child can install seccomp after attachment (`run.rs:2305`), so a startup check alone is not a complete fix. No destructive confined-target experiment was performed. |
| F-02 | **Confirmed conservative qualification limit.** Both terminal paths mark drain unproven (`run.rs:3394,3843`; `render.rs:792`). Do not remove PARTIAL to make automation pass; expose useful coverage dimensions and prove settlement first. |
| F-03 | **Confirmed, narrower CI defect.** Root Cargo selects p2 (`Cargo.toml:47`); standalone vendored tests use p1 (`ci.yml:81–103`). Workspace tests still compile p2. The missing evidence is the shipped dependency's standalone regression tests, not complete absence of p2 compilation/testing. |
| F-04/F-28 | **Confirmed recurring qualification gaps.** CI explicitly lists real privileged/release bodies UNRUN (`ci.yml:29–65`). This review's live host cells do not create recurring CI or qualify release artifacts. |
| F-05/F-06/F-07 | **Architecture/test debt; no vulnerability demonstrated.** Large coupled modules and privileged parsers deserve work, but module size or missing fuzz coverage alone does not establish High exploit severity. Source-wide size counts and every parser body were not reaudited. |
| F-08/F-12 | **Serialization split confirmed; impacts conditional.** Metrics embeds `ev`, profile uses `versioned_evidence` (`render.rs:1099–1127`); selection-blind metrics verdict differs by contract, but terminal PARTIAL currently masks the proposed clean-final-verdict difference. High severity needs a concrete acceptance/consumer failure. |
| F-09 | **Reproduced.** Live doctor prints successful `uprobe attach (own libc)` and then T0 offline. Classifier expects `(self)` (`doctor.rs:531,542,1103`). Fix the producer/classifier contract and test their composition. |
| F-10 | **Narrow to release provenance risk.** Off-default compiled feature AND explicit runtime flag are required; metrics refuses it (`attach.rs:688–700,2505`). Safe-object policy inventory is checked (`:488–497`); release checks include feature/map inventory and flag refusal (`build-release.sh:679–713`). A misbuild alone does not silently enable unsafe decoding. |
| F-11 | **Source-confirmed target-interference mechanism.** Duplicated stdout shares O_NONBLOCK (`sink.rs:60–90`); the previously spawned child inherits the same description (`run.rs:2125,2157`). Backpressure/child-output reproduction remains E17. |
| F-13 | **Confirmed producer/oracle mismatch.** Producer emits physical-identity ambiguity (`render.rs:644–645`); importing the actual validator showed the exact string absent from both accepted reason sets (`check-capture-evidence.py:249–254,971`). This check compared the real constant/sets; no full malformed capture document was manufactured. |
| F-14 | **Version boundary confirmed, wording narrowed.** `scan.rs:887` rejects newer minors. A provider with no accepted tables can receive a generic no-table/heap skip (`:2352`); an additional unsupported table beside an accepted table has no specific version omission. No current future-version vendor survey was done. |
| F-15 | **CLI limitation confirmed, narrower.** CLI maps live handoff to exit 0 (`main.rs:34–37`), while the library returns `child_pid` (`run.rs:1644,2293`). Do not claim the API drops the identity. |
| F-16 | **Silent-history claim refuted on current production path.** Admission rejection calls `State::reject_history` (`run.rs:2431–2439`), increments `semantic_history_drops` (`semantics.rs:1864`) and gates completeness (`render.rs:757`). Capture uses `Tracker::for_producer`, not the old `identify` fallback; discovery's PidPin independently fails closed. Lifetime capacity still needs E20. |
| F-17/F-18/F-19 | **Source mechanisms confirmed.** Trace has a 10M default (`run.rs:2851`); both entry points install global signal handlers (`:1447,1508,2079`); public argument structs can bypass CLI-only combination validation (`cli.rs:24`; `run.rs:1542`). No embedding-runtime reproduction in this review. |
| F-20 | **Retain: scan/pin error branch still prints non-JSON.** `inspect.rs:307–310` uses `println!` and returns before the JSON branch. Invalid-PID hard errors instead go to stderr through `main.rs:16`; the fresh binary reproduced that countercontrol with empty stdout. Four short exit-race attempts all failed during ProcessView opening, so they did NOT reproduce or refute the separate scan/pin branch. A review limited to main.rs would incorrectly dismiss this finding. |
| F-23 | **System miss reproduced; qualify aggregate exactness.** Counts are ring-independent but still depend on admission, START pairing, RV capacity, scope and terminal boundaries. Same-target nested entry invalidates an ambiguous START record (`task_owner.c:271–290`; `crates/ebpf/src/main.rs:2179,2444`), so returned totals are not unconditionally exact. |
| F-24 | **Mitigated race; residual not reproduced.** Complete maps-B/dependency/final-generation checks exist (`scan.rs:2379–2429`, `identity.rs:1639`). Equal-snapshot ABA/content mutation remains a proof gap; ordinary PID reuse was not established as a current bypass. |
| F-25 | **Historical occurrence, not freshly reproduced.** The pause wedge remains documented (`usage.md:333`); this review did not rerun the NSS pause case. Preserve it for an owned watchdog/cancel test. |
| F-26 | **Confirmed experiment-only breadth switch.** Exact-value environment check remains (`engine.rs:3884`); fixed-pool recognition also depends on fixture symbol `p11scope_fixed` (`:3496`). This does not establish generic broad-provider coverage. |
| F-27 | **CI advisory-check gap, not a discovered CVE.** No audit/deny gate found in inspected current Cargo/CI. “CVE knowledge is zero” is unsupported; no new dependency-advisory campaign was run. |
| F-30 | **Mixed.** Usage omits current backend/version flags; help excerpt equality IS tested (`cli.rs:1296–1325`). The old 145-commit CHANGELOG age was not reverified. |
| F-31/F-32 | **Retain scoped proof gaps.** Current completeness predicate was read, historical mutation results not rerun. No recurring forced-single/multi exact-count gate was found in CI/scripts/tests; previous one-off backend results remain historical. |
| F-34/F-35 | **Several formerly unopened controls now traced.** BPF `scope_auth` checks owner health and valid scope config; `store_start` uses native owner transactions (`ebpf/main.rs:244,2179`), covered by the native owner suite. `attach_path_for` uses a retained FD (`identity.rs:378`); manifest identity compares kind/value/SHA256 with metadata bracketing (`:1265,1324`). These close those particular uncertainty claims, not every loader/task-cookie/unsafe-decoder question. |
| F-37 | **Source-confirmed and newly sampled performance cost.** History cloning/merging (`engine.rs:1095,1322`) appears prominently in the live system-startup CPU profile. See O-13 in perf/REPORT.md. |
| F-38 | **Refuted as the alleged per-call hotspot.** Repeated cited calls are in `corrective_tests`; production caches the function id in SlotMeta (`semantics.rs:1629,2383`). Setup lookup remains linear, but that is a different claim. |
| F-40/F-41 | **Narrow coverage claims.** No integrated coverage/property/fuzz gate found. Three cargo-fuzz targets and seeds DO exist under untracked `audit-notes/fuzz-harnesses`; their coverage-guided execution was not performed here. Historical RNG campaigns and the 1,604-test count are not current validation. |
| F-42 | **Design risk, not a proven wrong consumer.** History rejection is a counterexample to generic silent-loss wording. Preserve the requirement that every future consumer handles independent loss authorities. |
| F-44 | **Narrow dead-path confirmation.** `Tracker::identify` has test callers but no production call found. Other claimed speculative/dead-code facets were not exhaustively checked. |
| F-64 | **Partly stale.** Task 3.2's `DiscoveryNoiseAggregator` now summarizes repeated discovery messages (`noise.rs:152`; `engine.rs:13846`). Levels/timestamps/quiet are separate possible improvements; the old 31-write count was not recounted. |

F-21/F-22/F-29/F-33/F-36/F-39/F-43, F-45–F-63 and F-65–F-69 retain their
historical evidence except for the explicitly discussed overlapping facets.
They were not individually revalidated in full. R-01–R-05 also retain that
qualification. In particular, this review does not convert accepted design
limits or “body not opened” questions into confirmed exploitable defects.

### R-06 update — external standard grounding resolved for catalog size

The official [OASIS PKCS #11 3.2 standard](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.pdf)
and its [normative function header](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/include/pkcs11-v3.2/pkcs11f.h)
were retrieved. The header contains 104 unique function entries, in exactly
the same order as the pinned `pkcs11-components` `d0a47c7` ABI catalog.
Header SHA256:
`3a205ff9a12247108193d124571fac88e38b59f1273e462baa1b5e00cd182fa0`.
The alleged six missing catalog functions are not established. This closes
the document-availability/catalog comparison gap only; complete per-function
ABI and semantic conformance remains E22.

### New findings

#### F-70 — A full retained-view cap prevents eventual exploration of new providers

**Medium; source-confirmed coverage limitation; no new live fixture reproduction.**
Successful provider-free scans still retain views (`engine.rs:3992–4001`).
Ordinary and reconciliation selection admit only into
`max_scan_pids - views.len()` (`:12795,12816,12902`). Long-lived occupants can
therefore prevent a later unique provider receiving a deep scan or publication
hooks indefinitely. The existing reconciliation test explicitly expects zero
new candidates at a full cap (`engine_tests.rs:4847–4853`).

Counterevidence: already attached shared-inode endpoints can capture later
processes; exits release views; cap omissions are disclosed. This finding
concerns new physical endpoints/process-local publication, not every new PID.
**Next:** E06, with provider-free incumbents and an independently identified
new provider. Separate exploratory capacity from authoritative ownership.

#### F-71 — Table-budget exhaustion can retire already covered endpoints on rescan

**Medium; source-confirmed conditional control path; dedicated reproduction required.**
`scan_tables_with_clock` stops at the table/entry cap before attempting decode
(`scan.rs:1200`), bypassing the repeat exemption in `decode_candidate`
(`:1070`). A full loader rescan replaces that view's previous modules with
its newly found set (`engine.rs:9302–9309`); rebuilding retires absent exact
targets (`plan.rs:719–725`) and `apply_candidate` detaches them (`engine.rs:8485`).
Budget-limited absence can thus erase valid coverage instead of only refusing
new work.

Counterevidence: metadata-only scans preserve tables; other views/manifests or
independent claims can retain endpoints; genuine identity invalidation must
still retire. **Next:** E07, 512 candidate tables sharing few endpoints, then
an unchanged full rescan. Require explicit incomplete-versus-absent results
and revalidation before retaining old coverage.

#### F-72 — `C_GetInterface` lacks equivalent heap/forwarded/default-request admission

**Medium; source-confirmed unsupported coverage shapes, not an authorization bypass.**
Interface returns route exclusively to selection (`engine.rs:12440`);
generic heap lowering rejects that record kind (`:5699`). New selection
admission requires exact-standard request AND result names (`:10108`), table
and all endpoints in the publishing provider (`:10158`), and a table file
offset (`:9714`). An otherwise valid supported table published only via a
NULL-name request, heap table or forwarded endpoints cannot use the generic
count-only publication route when matching scan inventory is absent.

Counterevidence: matching scan inventory, exact-standard same-object tables,
FunctionList and interface-list lowering cover other shapes. Existing guards
protect semantic and ownership boundaries and must not simply be removed.
**Next:** E08/E13; share a bounded ownership-validated count-only lowering
contract, keeping first-call latency and semantic authority explicit.

#### F-73 — Stable interface rescans consume lifetime cardinality

**Medium; source-confirmed accounting/coverage limitation; saturation fixture pending.**
Every matching interface triple calls `admit_interface` (`scan.rs:1348`),
which increments the capture-wide count without repeat identity (`:609–617`).
At 512, future scanning stops (`:1329`). Repeated stable surfaces can lose
interface linkage or block new linkage despite few distinct endpoints.

Counterevidence: the cap is explicit; independent I/O/work limits may exhaust
first; live-return/manifest evidence may supply linkage. **Next:** E09. Keep
attempted work bounded while distinguishing distinct-surface retention from
repeated inspection; include address and process/view-generation reuse.

#### F-74 — Measurement harness invents a duration-collapse cause from setup time

**Medium; confirmed source contradiction and emitted live warning.**
`derive_phases` (`system-scope-measure.py:708–718`) says the loop expired during
setup whenever spawn-to-GO exceeds requested duration. `capture_profile`
creates its clock after the attach session (`run.rs:1509–1513,3054`). The
condition cannot establish expiry. The warning was emitted in all six system
cells; their independent zero-call result remains a real failed coverage cell.

Related oracle weaknesses: the first generic discovery log prefix can be a
per-class summary, FD-plateau boundaries are estimated, pathname equality is
not physical identity, and a derived delivered count is not a separate
consumer oracle. **Next:** E03; direct phase boundaries and exact workload
identity, with synthetic long-setup/short-capture and early-exit countercontrols.

#### F-75 — Independent processes can collide in detached async semantic state

**Medium; source-confirmed conditional reducer path; dedicated replay/live
provider reproduction pending.** The user's multi-process requirement led
to a bounded follow-up review. Detached state is keyed by module, PKCS#11
slot, target function, async ID and `process.domain` (`semantics.rs:1600,2333`).
That domain is the retained EVENTS map ID (`events.rs:20–41`), shared by
processes in a capture; it is not a provider-instance namespace.

If independent processes sharing these fields issue the same ID, the second
`C_AsyncGetID` replaces the first pending record (`semantics.rs:2332–2349`).
A later successful `C_AsyncJoin` uses that tuple without checking the original
process or collision ambiguity and transfers the surviving record (`:2358–2371`).
Completion applies its saved event under the joining process (`:2304–2312`).
With different pending initialization mechanisms, that path can attribute
one process's mechanism to another. The exact provider/standard identifier
namespace and successful-join premise need E20 fixture validation; no claim
that every provider allocates colliding IDs is made.

Counterevidence: replacement increments `async_duplicates` and forces PARTIAL
(`render.rs:753`); count-only slots bypass semantics (`semantics.rs:1900`).
Ordinary cancel/finalize/retirement uses process ownership, and intentional
cross-process join is explicitly tested (`semantics.rs:738`). Those controls
do not quarantine a collided key. The similarly named loaded-object-domain
test (`history_tests.rs:617`) uses different EVENTS domains, so it does not
cover independent processes sharing this capture domain.

**Next:** E20 with one domain, distinct task cookies, the same module/slot/ID,
different mechanisms and opposite join/completion order. Require independent
state or conservative ambiguity refusal, while retaining proven legitimate
transfers. Consider bounded collision tombstones before a richer validated
provider-instance namespace; blindly adding PID would break existing transfer
semantics. This is an early correctness gate in Package E0, before performance
changes to semantic keys or indexes.

### Recommended next work and retained evidence

First address F-01's unsafe unknown verdict and F-11's shared-stdout
interference, with owned safety reproductions and explicit acceptance gates.
Fix trust/oracle vocabulary and F-71's incomplete-rescan contract; specify
and test F-70/F-73 fairness/lifetime behavior. Coverage-breaking scale limits
and F-75's multi-process async isolation belong in this correctness stage.
Treat O-13 history rebuilding
and O-1 persistent consumption as distinct startup/steady-state performance
work. Broader factory handling and capacity redesign require exact physical
identity, privacy and lifecycle acceptance gates. Do not raise one map limit
or add operator filters and call the system-coverage problem solved.
Lower-impact historical cleanup can proceed separately; it need not delay
performance changes that pass their own correctness gates.

The [delivery plan](perf/SYSTEM-PLAN.md) compares three approaches and assigns
owned packages. The [experiment backlog](perf/SYSTEM-EXPERIMENTS.md) provides
workloads, measurements, pass criteria and execution order. Raw logs, hashes,
profiles, command receipts and runtime reports remain under
`/var/tmp/p11scope-ws-tmp/review-20260921-system/` and
`/var/tmp/p11scope-review-20260921-r{1,2,3}/`, outside Git. BPF sets after the
12-cell campaign matched their initial sets exactly (70 programs, 7 maps;
no new IDs), and no p11scope process remained at that check.

## Historical synthesis — `cb6337d`, 2026-09-20

Final synthesis per the runbook final-synthesis step. Read-only on production
code; three top-severity claims spot-verified by direct source read (noted
`[direct-read]`). No subagents used.

- Project: `/home/user/src/m/p11scope-ws/p11scope` (Rust profiler CLI, unreleased)
- Branch: `feat/system-scale` @ `cb6337d`
- Date: 2026-09-20
- Method: dedup + rank of all 14 inputs; `vulnerability-triage-brocards`
  applied for severity/status judgment; `fp-check` verdicts recorded for
  every suspected false positive (never silently dropped); SARIF parsed
  per `sarif-parsing` (severity resolved result→rule→default: all 12
  results level `note` via rule defaults).

## Severity scale (normalized)

No Critical: pre-release, single-node, operator-trusted, no remote attack
surface. The adversarial review's "Critical Risks" are carried as High
safety/architectural findings with rationale. `Significant` (architecture
review) maps to Medium. Adjustments from source severities are flagged
with `TRIAGE:` and a brocard/evidence reason.

## Status taxonomy

- **confirmed** — mechanism verified by code read (by source report; `+direct-read`
  where re-verified here); impact may still be conditional (noted).
- **suspected** — plausible but evidence incomplete (body unopened, unmeasured,
  or future-conditional); needs follow-up, not dismissal.
- **mitigated** — real mechanism with an in-place control; kept as regression guard.
- **accepted** — real but explicitly plan-accepted / documented limitation; info only.
- **refuted** — fp-check verdict FALSE POSITIVE (or non-finding); kept with reason.
- **undecidable** — cannot be judged from repo evidence (external spec absent).

## Ranked finding list

69 active findings: 8 High, 36 Medium, 25 Low. Refuted/mitigated/accepted
records follow separately (R-01..R-06) and are NOT counted as active.

### HIGH (8)

#### F-01 — Uretprobe-vs-seccomp fail-open corners (High, confirmed +direct-read)

Two facets of one hazard: (a) `decide()` returns `Proceed` on
`(KernelVerdict::Unknown, None)` (`src/uretprobe_hazard.rs:105` +direct-read),
and `target=None` is by construction for `--cgroup`/`--system` — widest blast
radius under weakest protection; (b) the `run` lane never runs the uretprobe
preflight at all, so default refusal does not exist there and
`--allow-uretprobe-on-confined-target` is silently meaningless on `run`.
Override is not recorded durably in report evidence.

- Sources: `audit-notes/adversarial-review.md` §Synthesis Risk 1(a);
  `audit-notes/stride-threat-model.md` §3.5 D1;
  `audit-notes/sharp-edges.md` §SE-03.
- TRIAGE: insecure-defaults classifies `decide` L105 as safety-interlock, not
  security control — agreed, kept as High *safety* finding (target integrity
  is a Critical asset in the STRIDE model). Brocard 1 passes: operator
  capturing confined fleet workloads on an unknown kernel kills targets.

#### F-02 — `completeness` is always PARTIAL; core trust signal uninformative (High, confirmed)

Both terminal paths unconditionally call `mark_terminal_drain_unproven()`;
trace EVIDENCE forces PARTIAL + `final_drain:false`. Clean runs and 99%-loss
runs share a verdict; gating on COMPLETE deadlocks automation, ignoring it
discards the only gap signal. Trains consumers to stop reading the field.

- Sources: `audit-notes/sharp-edges.md` §SE-19;
  `audit-notes/adversarial-review.md` §Synthesis Concern 5.

#### F-03 — CI validates stale `-p1` vendored trees while the build ships `-p2` (High, confirmed)

`Cargo.toml` patches aya/aya-obj to `third-party/src/*-p2` but
`ci.yml:81,82,102,103` fetches/tests `-p1`; shipped ring-reader/map-relocation
patches run untested in CI; both trees untracked so drift is invisible.

- Sources: `.full-review/05-final-report.md` §High (S-H1);
  `.full-review/02-security-performance.md` §Security/High.

#### F-04 — No hosted end-to-end capture in CI; BPF path never exercised (High, confirmed)

Every privileged lane runs only `--self-test` oracles; regressions in real
capture/attach surface only in manual runs. Honestly disclosed (pinned UNRUN
list) but still a release-qualification hole.

- Sources: `.full-review/05-final-report.md` §High (T-H1);
  `.full-review/03-testing-documentation.md` §Test Coverage/High.

#### F-05 — Node-root observer parses untrusted bytes; parser surface has no fuzz/property coverage (High, confirmed architecture / suspected bugs)

Observer runs with CAP_SYS_ADMIN-class privilege while parsing manifest JSON,
ELF structures, /proc text, hook specs. No `cargo-fuzz` targets, no
proptest/quickcheck anywhere; scan glue is `pub(crate)` so external harnesses
cannot reach it; 17.5M offline RNG iterations found 0 crashes (weak oracle:
no coverage feedback, no sanitizer).

- Sources: `audit-notes/adversarial-review.md` §Synthesis Risk 2;
  `.full-review/03-testing-documentation.md` §T-M3;
  `audit-notes/fuzzing.md` §F2/F3 + offline-validation limits;
  `audit-notes/property-based-testing.md` §Verdict (zero PBT coverage).
- TRIAGE: no parser bug demonstrated (fuzzing §Verified-safe list is genuine
  evidence) — High is for *unmeasured* privileged attack surface, not a known vuln.

#### F-06 — Discovery Engine god object / mega-modules (High, confirmed)

`engine.rs` 14.3k lines / 56-field `Engine` (~248-320 methods); run 9.1k,
attach 6.6k, pause 6.3k. Every discovery change lands in one module; branch
already rations it with file-disjoint parallel rules.

- Sources: `audit-notes/architecture-review.md` §Risk Assessment (AR-1);
  `.full-review/01-quality-architecture.md` §Q-H1, §A-H2;
  `audit-notes/adversarial-review.md` §Synthesis Concern 9.

#### F-07 — run/attach/engine bidirectional coupling; run.rs mixes three lifecycles (High, confirmed)

No layering direction (`attach ⇄ run ⇄ engine`;
`impl EngineSession for Session` inverts layering); 400-line+ functions
(`refresh_inventory` ~559, `merge_current` ~514, `capture_profile` ~436…);
indirection-heavy shared tick skeleton.

- Sources: `audit-notes/architecture-review.md` §AR-2;
  `.full-review/01-quality-architecture.md` §A-H1, §Q-H2.

#### F-08 — Output contract validated outside the producer; evidence constructor unenforced (High, confirmed)

`profile_json` builds untyped `Value`; closed-shape enforcement lives in a
Python oracle + contract tests (drift silently between runs); `render::json`
embeds `ev` directly instead of `versioned_evidence(ev)` — call-site
discipline, unenforced; `render.rs` fan-in couples evidence model to presentation.

- Sources: `audit-notes/architecture-review.md` §AR-3;
  `.full-review/01-quality-architecture.md` §A-M1;
  `audit-notes/stride-threat-model.md` §3.3 R1.

### MEDIUM (36)

#### F-09 — `doctor` tier readout wrong in every real run: always T0 (Medium, confirmed +direct-read)

Emitted row is `"uprobe attach (own libc)"` (doctor.rs:531,542) but the tier
classifier looks up `"uprobe attach (self)"` (:1103); unit tests use `(self)`
and pass while real runs misreport. Fails safe (under-claims) but breaks
preflight trust and tier-gated automation.

- Sources: `audit-notes/adversarial-review.md` §Perspective 1 + Concern 4.

#### F-10 — Privacy boundary rests on a build-pipeline single point of failure (Medium, confirmed mechanism)

Unsafe pointer-following decoders ship in source; only the
`--no-default-features` release build + packaging check keeps them out. A
misbuilt artifact silently widens the privacy boundary of a root observer.

- Sources: `audit-notes/adversarial-review.md` §Synthesis Risk 3;
  `audit-notes/architecture-review.md` §AR-12.
- TRIAGE: downgraded from adversarial-Critical: safe-only behavioral gate
  exists (build-release.sh:690-711), attach re-checks fail-closed (SE-15
  verified), double-gate verified (insecure-defaults #2). Residual is
  defense-in-depth (no object-level absence assertion), hence Medium.

#### F-11 — Shared-stdout O_NONBLOCK leaks into owned `run` children, never restored (Medium, confirmed +direct-read)

`stdout_sink()` dups fd 1 and sets O_NONBLOCK on the shared description
(sink.rs:68,90 +direct-read); no `Drop` restores flags (verified: no Drop
impl). Owned child (fds 0/1/2 inherited, only ≥3 closed) gets EAGAIN instead
of blocking under pipe backpressure; libc stdio does not retry → lost output
or write errors. Observer perturbs the observed.

- Sources: `audit-notes/differential-review.md` §3 (MEDIUM M1).

#### F-12 — Metrics/profile evidence split + selection-blind metrics verdict undocumented; same capture can disagree (Medium, confirmed)

Metrics serializes `Evidence` directly (4 `#[serde(skip)]` v3 fields absent)
with `verdict_with_selection(false)`; profile uses `versioned_evidence`. A
selection gap forcing profile PARTIAL is invisible to metrics; v3 doc claims
both "have a closed exact key set" without stating they differ.

- Sources: `audit-notes/spec-compliance.md` §F4;
  `audit-notes/sharp-edges.md` §SE-20.

#### F-13 — Sixth skip reason emitted by code, rejected by doc + validator (Medium, confirmed)

`"physical identity is ambiguous; …"` (render.rs:670-671, reachable via
identity.rs:785-803) is outside the doc's 5-item list and the validator's
sets → honest output the release oracle calls invalid (false gate failure or
pressure to hand-edit evidence). Code behavior correct; fix in doc+validator.

- Sources: `audit-notes/spec-compliance.md` §F2.

#### F-14 — Future-minor tables silently invisible to the memory scan (Medium, confirmed behavior, future-conditional impact)

`spans_for` refuses 2.x minor>40 / 3.x minor>2 before `tables_for`
(scan.rs:887-894): no table, no skip, no counter — while helper walks a known
prefix and live-export counts PARTIAL loss. No such provider ships (OASIS
latest 3.2); doc-vs-doc tension (Slice-1 vs v0.1 matrix) compounds it.

- Sources: `audit-notes/spec-compliance.md` §F1 (A-REQ-8).

#### F-15 — `run` hands back a live child, exits 0, never names the orphan PID (Medium, confirmed)

Duration expiry without `--kill-on-timeout` stages a hand-off (`None → exit 0`,
PID dropped by binary, no terminal message). Related: `--pid` cannot read a
non-child exit status (death attribution is a stderr warning, not proof).

- Sources: `audit-notes/sharp-edges.md` §SE-02;
  `audit-notes/stride-threat-model.md` §3.3 R4, §3.5 D6 (unverified remainder).

#### F-16 — Silent history/attribution loss at capacity + untracked fallback (Medium, confirmed)

History admission refuses silently (`(None, [])` at capacity / stale / closed,
history.rs:84-86) with no evidence; `Tracker::identify` Untracked mode assumes
alive with synthetic generations; fd pressure forces the weakest rung.

- Sources: `audit-notes/stride-threat-model.md` §3.5 D3, §3.1 S4.

#### F-17 — Trace's hidden 10M default cap; TRUNCATED blames a flag never passed (Medium, confirmed)

`capture_trace` always arms `remaining=Some(10M)`; message cites
`--max-events` the operator never gave; no-duration notice promises streaming
"until interrupted" with no mention of the cap.

- Sources: `audit-notes/sharp-edges.md` §SE-01.

#### F-18 — `capture()`/`run_owned()` install process-global signal handlers (Medium, confirmed)

`install_stop_flag()` with no opt-out, no double-registration guard, no
restoration. Embedding apps get Ctrl-C/SIGTERM disposition replaced; calling
twice stacks handlers.

- Sources: `audit-notes/sharp-edges.md` §SE-12.

#### F-19 — `CaptureArgs`/`RunArgs` unvalidated pub-field structs; refused CLI combos silently degrade via library (Medium, confirmed)

`(Trace, metrics)` silently drops metrics; `(Profile, max_events)` silently
ignored; `max_scan_pids=Some(0)` silently becomes 256. ~20-field flat
god-struct; 17-of-20 modules `pub` with no documented supported surface.

- Sources: `audit-notes/sharp-edges.md` §SE-13;
  `.full-review/01-quality-architecture.md` §A-L1, §A-M3.

#### F-20 — `inspect --json` failure path prints non-JSON to stdout (Medium, confirmed)

`println!` + exit 1 on the diagnose-failure path breaks `| jq` machine
contracts exactly when it matters.

- Sources: `audit-notes/sharp-edges.md` §SE-14.

#### F-21 — `params: null` + empty `templates.operations` read as negative evidence (Medium, confirmed)

Default-allowlisted shape for "policy forbade decoding" is identical to "no
parameters observed"; machine consumers test `params is None`, not the `note`
field. "It's documented" does not fix the pit of success.

- Sources: `audit-notes/sharp-edges.md` §SE-21.

#### F-22 — `*.path` fields are target-mount-namespace labels typed as plain strings (Medium, confirmed)

Automation that `open()`s the label reads the wrong file or fails; true
identity `{dev,ino,sha256}` sits beside it inviting the weaker use.

- Sources: `audit-notes/sharp-edges.md` §SE-22.

#### F-23 — Semantic evidence collapses at scale exactly when most needed (Medium, confirmed by design)

At 1M calls/s the ring loses 99%+ of per-call events; aggregates stay exact
but mechanisms/sessions/logins/cgroups/trace degrade. Fixed ceilings (512
slots shared across modules — p11-kit proxy dropped whole; 512 tables; 256
members/pass; terminal drain bound) are cliff edges with honest labels. Product
story ("observe every container") does not lead with this.

- Sources: `audit-notes/stride-threat-model.md` §3.5 D2;
  `audit-notes/adversarial-review.md` §Perspective 1 + Concerns 6, 8.
- TRIAGE: downgraded from STRIDE-High(6): loss is disclosed by construction
  (RING_LOSS evidence, PARTIAL); residual risk is consumer misread → see F-02.

#### F-24 — Mid-scan remap can corrupt discovery→attach; residual race window (Medium, mitigated + suspected residual)

maps-A/maps-B bracket + budget caps + truncation check mitigate; residual is
pid-reuse + maps-colliding content in the pin→open window.

- Sources: `audit-notes/stride-threat-model.md` §3.2 T1, §3.1 S1.
- TRIAGE: downgraded from STRIDE-High(6): bracket verified in code; remaining
  window is narrow and unquantified → Medium mitigated/suspected.

#### F-25 — `--pause auto` wedge holds child stopped; SIGTERM ignored, SIGKILL required (Medium, confirmed occurrence)

Observed over an NSS cascade (usage.md:333-338); workaround documented, fix
unscheduled. No pause watchdog (bounded STOP window + forced CONT + evidence).

- Sources: `audit-notes/architecture-review.md` §AR-9;
  `audit-notes/adversarial-review.md` §Synthesis Risk 1(b);
  `audit-notes/stride-threat-model.md` §3.5 D5.

#### F-26 — Hidden `P11SCOPE_BROAD_ADMIT` changes discovery admission; `P11SCOPE_*` vars operator-invisible (Medium, confirmed)

Env-gated experiment (up to 64 heuristic tables/module, lifted caps) in no
help text, no usage.md, not in capture evidence; SMALL_RING/SMALL_STATE_MAPS/
PREPARED_BPF_* similarly invisible. Default (absent→false, narrower) is
verified fail-secure — this is an observability finding, not a bypass.

- Sources: `audit-notes/differential-review.md` §3 (L3);
  `.full-review/02-security-performance.md` §S-M1;
  `.full-review/03-testing-documentation.md` §D-M2.
- TRIAGE: differential rates Low, full-review Medium: Medium adopted
  (operator-invisible behavior change in a security observer; CWE-489).

#### F-27 — No dependency-vulnerability scanning; pins age silently (Medium, confirmed absence)

No `cargo audit`/`deny` gate, no deny.toml; pinned git rev + vendored patches
+ third-party `object` 0.39.1 (largest external parser risk) unbumped without
review. Integrity (SHA pins) is strong; CVE knowledge is zero.

- Sources: `.full-review/02-security-performance.md` §S-M2;
  `.full-review/04-best-practices.md` §B-L3;
  `audit-notes/fuzzing.md` §F3.

#### F-28 — Shipped artifacts never built/validated in CI (Medium, confirmed)

No musl build, docker build/lint, kubeconform, SBOM, signing, release
workflow; `build-release.sh` unreferenced from docs. Exact shippable bytes
assembled only by hand.

- Sources: `.full-review/04-best-practices.md` §C-M1.

#### F-29 — Contract-suite feedback time + load-sensitive flakes (Medium, confirmed)

128 hosted cases in 703-783s; ~1 failure per full run (7 documented flakes,
200s+ single tests). No-weakening rule is correct; merge throughput is the
binding constraint.

- Sources: `audit-notes/architecture-review.md` §AR-11;
  `.full-review/03-testing-documentation.md` §T-M2.

#### F-30 — Operator docs + help text trail the CLI; excerpt duplication untested (Medium, confirmed)

usage.md missing `--attach-backend`/`--version`; CHANGELOG 145 commits stale;
per-subcommand `*_HELP` excerpts must stay "verbatim from USAGE" but are
tested for scoping only, not excerpt-equality; hand-rolled parser help
copy-pasted across five topics.

- Sources: `.full-review/03-testing-documentation.md` §D-M1;
  `audit-notes/architecture-review.md` §AR-8;
  `audit-notes/adversarial-review.md` §Observations (CLI drift).

#### F-31 — Completeness predicate in four artifacts; two conjuncts unpinned (Medium, confirmed)

~55-condition verdict replicated across render.rs, v3 schema doc, Python
oracle, usage.md prose. Mutation sample: `initial_set_timing` conjunct and
`known_pre_relocation` summand survive (masked in production today — co-gap
and empty D3 catalog — but unpinned against future accounting changes);
no verdict-monotonicity property asserted.

- Sources: `audit-notes/architecture-review.md` §AR-5;
  `audit-notes/mutation-testing.md` §M-1, §M-2;
  `audit-notes/property-based-testing.md` §1 (verdict row).

#### F-32 — Dual attach backends need a standing equivalence gate (Medium, confirmed absence)

Multi-vs-singles proven equivalent once (Task 2.3 lane); without a recurring
gate later attach changes can diverge backends while each stays self-consistent.

- Sources: `audit-notes/architecture-review.md` §AR-7.

#### F-33 — Discover helper executes provider code with uid-drop only; no seccomp/net/mount sandbox (Medium, confirmed architecture)

Containment is drop-to-nobody + no_new_privs + closed fds + sanitized env +
nondumpable (verified sound); a malicious provider can still exfiltrate as
that uid or crash/hang the helper. Trust boundary sits in prose, not a sandbox.

- Sources: `audit-notes/stride-threat-model.md` §3.4 I5, §3.6 E1;
  `audit-notes/adversarial-review.md` §Perspective 2 (discover).

#### F-34 — BPF scope/auth trust root + attach binding unaudited in this round (Medium, suspected — bodies unopened)

`scope_auth` (single trust root on every probe), `store_start`, identity
natives, `multi_link_pid` vs in-BPF filter agreement, `attach_path_for`
fd-binding, `publish_descriptors` correctness (freeze proves stability, not
correctness), unsafe decoder depth (`walk_template`, `p11_decode_params`).
Highest-leverage unresolved evidence.

- Sources: `audit-notes/stride-threat-model.md` §3.6 E7, E6; §3.2 T2, T3;
  §3.4 I6; §6 Unresolved evidence.

#### F-35 — Spoofing residuals: loader context, task cookie, manifest binding (Medium, suspected)

Unbound loader contexts authenticate record-supplied pairs only (S2);
`task_cookie` uniqueness asserted nowhere (S3); manifest digest re-check at
pin time unverified (S5). (Pid-reuse S1 folded into F-24; Untracked-mode S4
into F-16.)

- Sources: `audit-notes/stride-threat-model.md` §3.1 S2, S3, S5.

#### F-36 — Stringly-typed errors across 10 modules (Medium, confirmed)

`Result<_, String>` erases kinds (permission-denied vs not-found), no source
chains, unmatchable for recovery; `map_err` sites already mark conversion points.

- Sources: `.full-review/04-best-practices.md` §B-M1.

#### F-37 — Whole-history clones per discovery transaction (Medium, confirmed)

`begin_stage` + `merge_current` clone full/visible history; discovery-time
cost multiplied by system scope; 168 `.clone()` in engine.rs. Needs
measurement on system scope before refactor.

- Sources: `.full-review/02-security-performance.md` §P-M1.

#### F-38 — Linear `function_id` string lookups on every-call correlation paths (Medium, confirmed)

~15 linear `.position()` lookups per correlated call sequence + descriptor
lookups; small absolute cost, paid on every call. Hoist to const/LazyLock.

- Sources: `.full-review/01-quality-architecture.md` §Q-M4;
  `.full-review/02-security-performance.md` §P-M2.

#### F-39 — `#[cfg(test)]` hooks threaded through production modules (Medium, confirmed)

Test-only fields/ctors/impl blocks in prod mean the tested binary differs
structurally from the shipped binary; fixtures auditable only via prod files.

- Sources: `.full-review/01-quality-architecture.md` §Q-M1.

#### F-40 — No coverage measurement for 1,604 tests (Medium, confirmed absence)

Volume ≠ coverage: production-unreachable `Tracker::identify` has passing
tests while zero shipped lines execute it — line coverage would flag this class.

- Sources: `.full-review/03-testing-documentation.md` §T-M1.

#### F-41 — Decoder/budget/state-machine property gaps; scan glue unreachable from harnesses (Medium, confirmed absence)

No exhaustive `spans_for`-vs-`select()` 2¹⁶ oracle (a one-line gate edit keeps
pinned examples green), no decoder agreement/subset/error-path invariants, no
ordering/stability, budget-identity, coverage-machine, or bounded-reader
accounting properties; key glue is `pub(crate)` (needs `#[cfg(fuzzing)]`
exposure or a public-module move).

- Sources: `audit-notes/property-based-testing.md` §3 findings 1-7 + §4 P1-P7;
  `audit-notes/fuzzing.md` §F2.

#### F-42 — Loss disclosure depends on dual-authority discipline in every future consumer (Medium, confirmed design risk)

STATS-authority vs EVENTS-detail split is correct and tested, but each new
consumer must re-learn which fields survive loss; one wrong join silently
overclaims. Mitigation for pkcs11-lab lives outside this repo.

- Sources: `audit-notes/architecture-review.md` §AR-4.

#### F-43 — Forked-dependency maintenance with no upstream-exit plan (Medium, confirmed)

Patched aya/aya-obj reconstructions (hash-verified) + pinned
nightly/clang/bpf-linker; upstream merged multi-uprobe 2026-07 so the local
backport is already tech debt; every upstream release widens the rebase.

- Sources: `audit-notes/architecture-review.md` §AR-6;
  `audit-notes/adversarial-review.md` §Observations (carried-patch debt).

#### F-44 — Unreachable + speculative dead code in privileged paths (Medium, confirmed)

`Tracker::identify` + pidfd machinery called only from tests (~130 lines of
security-sensitive logic rotting); speculative `Task 8` allows, `history.rs`
allows, unread `TaskMembership` adapter.

- Sources: `.full-review/01-quality-architecture.md` §Q-M5, §Q-M2.

### LOW (25)

| ID | Finding | Status | Sources |
|----|---------|--------|---------|
| F-45 | Rebuild re-round duplicates failure entries for return-refused members (bounded; idempotent downstream — diagnostic rows only) | confirmed | `audit-notes/differential-review.md` §L1 |
| F-46 | UAPI layout assertions `debug_assert`-only in `bpf-multi` (release loads BPF; use `const` asserts per in-repo pattern) | confirmed | `audit-notes/differential-review.md` §L2 |
| F-47 | CLI parser edge gaps: `--duration 0` accepted; `--pid 0` late exit-1 not usage-2; empty-string values; silent last-wins repeats; `-o -` creates `./-`; profile-without-duration silent; bare `--hook-symbol` defaults functionlist ABI; trace `-o` truncates pre-existing output before discovery (profile is atomic) | confirmed | `audit-notes/sharp-edges.md` §SE-04..SE-11 |
| F-48 | `AtomicFile` lacks `#[must_use]` (silent discard); Drop check-then-unlink by name (mitigated by trusted-parent + O_EXCL); final-name stat policy unverified (suspected facet) | confirmed (+1 suspected facet) | `audit-notes/sharp-edges.md` §SE-16; `.full-review/02-security-performance.md` §S-L4; `audit-notes/stride-threat-model.md` §T4 |
| F-49 | Trace line format breaks naive parsers (space suffix, six prefixes); ~8 strings/line (fine for humans, not machine pipelines) | confirmed | `audit-notes/sharp-edges.md` §SE-17; `.full-review/02-security-performance.md` §P-L1 |
| F-50 | Schema-doc precision debt: 4 emitted+gated+validated evidence fields missing from v2/v3 docs (third-party consumers reject real output); F5 7-item bundle (entries count, modules_skipped shape, providers bound, rv==0 case, capture fields, terminal keys, role-counts literal); stringly enums + no machine-readable JSON schema | confirmed | `audit-notes/spec-compliance.md` §F3, §F5; `audit-notes/sharp-edges.md` §SE-24 |
| F-51 | Undocumented `unsafe` family (10 sites: provider FFI, helper hardening, output publisher, scope opener, post-fork fns, seccomp arming, Pod impls, eBPF blocks, setrlimit, dup) + `unsafe fn` items lack `# Safety` docs (~97 notes / ~370 occurrences) — all sampled bodies audited sound; maintenance risk only | confirmed | `.rust-review-results/20260920T185730Z/REPORT.md` §SAFETYDOC-001..010 + `REPORT.sarif` (10× safety-doc/note); `.full-review/02-security-performance.md` §S-L5 |
| F-52 | No shared lint config: no `[lints]`/clippy.toml/rustfmt.toml, no `missing_docs` lint on 17-module pub surface — enables F-51 to recur silently | confirmed absence | `.rust-review-results/…/REPORT.md` §CARGOLINT-001 + `REPORT.sarif` (cargo-lint-config/note); `.full-review/04-best-practices.md` §B-L1; `.full-review/03-testing-documentation.md` §D-L1 |
| F-53 | Concurrent truncation of mapped provider file SIGBUS-aborts observer (`read_export_facts`) — needs write access + microsecond race; code's own SAFETY comment names it as plan-accepted | confirmed, accepted | `.rust-review-results/…/REPORT.md` §SHMRACE-001 + `REPORT.sarif` (shared-memory-race/note); `audit-notes/fuzzing.md` §Verified-safe (plan-accepted) |
| F-54 | `expect()`-as-invariant (~40 sites) aborts whole captures; cross-crate `expect` couples scan glue to pkcs11 catalog (safe today via 104-field invariant spanning two repos — one dependency skew from a capture-thread panic on target bytes) | confirmed pattern, no live crash | `.full-review/01-quality-architecture.md` §Q-L1; `.full-review/02-security-performance.md` §S-L2; `audit-notes/fuzzing.md` §F1; `audit-notes/adversarial-review.md` §Perspective 3 (expects) |
| F-55 | `attach_failures[]` keeps raw target-controlled path bytes in JSON (terminal escaped, stored raw); trace function/mechanism path unescaped (bounded alphabet — residual) | confirmed | `audit-notes/sharp-edges.md` §SE-23; `audit-notes/stride-threat-model.md` §I4 |
| F-56 | `p11scope-discover -o` uses plain `fs::write` (symlink-following, non-atomic, umask modes); `--help` to stderr — weaker hygiene than observer sinks for a trusted input artifact | confirmed | `audit-notes/sharp-edges.md` §SE-18; `audit-notes/stride-threat-model.md` §T5 |
| F-57 | SUDO_UID/GID is a selector, not authentication; trusted whenever euid==0 (env can redirect root's output dirs / child uid); supplementary-group clearing excludes HSM-group workloads from `run` | confirmed, bounded | `audit-notes/architecture-review.md` §AR-10; `.full-review/02-security-performance.md` §S-L1 |
| F-58 | STRIDE residual lows: u64 counter wraps in release (T7 — saturating rule inconsistent); malformed-EVENTS counter-only forensics (R2); saturating loader context_failures (R3); all-stdout-through-sink is convention only (R5); stream chmod-after-truncate window (I3, confirmed); EMFILE ends whole run instead of degrading (D7); doctor full-session detach-on-drop unverified (D8, suspected); manifest/object openers follow symlinks while scope/output refuse (E4 — policy matrix unstated) | mixed confirmed/suspected | `audit-notes/stride-threat-model.md` §3.2 T7; §3.3 R2,R3,R5; §3.4 I3; §3.5 D7,D8; §3.6 E4 |
| F-59 | Doctor `render()` writes check details verbatim; newline-bearing detail splits rows / displaces trailing verdict line (cosmetic, terminal-only; real details single-line today) | confirmed | `audit-notes/property-based-testing.md` §3 finding 8 |
| F-60 | Notes sprawl (60+ files, no decision index) + no operator runbook mapping failure modes to actions | confirmed | `audit-notes/architecture-review.md` §AR-13; `.full-review/04-best-practices.md` §C-L2 |
| F-61 | Silently discarded errors (`raise_nofile`, doctor `write!`, `fetch_update`); duplicated expect strings / `is_some`+`unwrap`; BPF diagnostic CAS drops increments on contention; BPF O(64)/O(512) bounded scans (correct, noted); non-saturating cgroup counters (unreachable, convention) | confirmed | `.full-review/01-quality-architecture.md` §Q-L2, §Q-L3; `.full-review/02-security-performance.md` §S-L3, §P-L2, §P-L3 |
| F-62 | Python suite has no single entry point; 4 `#[ignore]`d tests on no schedule (fold into privileged job) | confirmed | `.full-review/03-testing-documentation.md` §T-L1, §T-L2 |
| F-63 | 130 shell/python scripts with zero static analysis in CI (shellcheck/ruff absent; authors annotate manually) | confirmed absence | `.full-review/04-best-practices.md` §C-M2 |
| F-64 | Diagnostics have no levels/timestamps/quiet flag (31 direct stderr writes; adequate for one-shot CLI, gap only under automation) | confirmed | `.full-review/04-best-practices.md` §C-L1 |
| F-65 | Edition 2024/2021 split unexplained (likely BPF conservatism); discovery re-exports CLI's `PausePolicy` (layering nit) | confirmed | `.full-review/04-best-practices.md` §B-L2; `.full-review/01-quality-architecture.md` §A-M2 |
| F-66 | Hand-rolled 1,466-line CLI parser (no clap): every flag re-risks parse/help drift; no completion/man pages | confirmed (downgraded, TRIAGE below) | `.full-review/01-quality-architecture.md` §Q-M3 |
| F-67 | Overlay/inode-sharing headline bet carries explicit uncertainty (byte-identical collapse heuristic forces PARTIAL — differentiator and uncertainty are the same mechanism) | confirmed, disclosed | `audit-notes/adversarial-review.md` §Synthesis Concern 10 |
| F-68 | `--system`/cgroup collection breadth is operator-gated only; reports carry per-mechanism detail (no breadth warning like the trace-duration notice) | accepted (documented behavior) | `audit-notes/stride-threat-model.md` §I1 |
| F-69 | Structural EoP notes: BPF object is build-produced (toolchain compromise bypasses runtime checks — sign/attest at build); main CLI has no privilege separation (whole-lifetime CAP set; split loader/reducer or drop caps after attach) | accepted (structural, pre-release) | `audit-notes/stride-threat-model.md` §E2, §E3 |

TRIAGE notes on Low adjustments: F-66 downgraded Medium→Low — no parsing
defect demonstrated (sharp-edges parser matrix shows a strict parser: zero-
rejecting bounds, order-independent mode refusal, removed-flag hints);
framework adoption is a maintenance preference pending binary-size
measurement (Brocard 6: rewrite churn vs unproven benefit). F-57 kept Low
(Brocard 2: process already root — no privilege gained; residual is
operator-confusion/output-redirection). F-68 kept as accepted/info (Brocard 5:
documented intended behavior of an explicit operator flag; only mitigation is
a warning). F-53 kept Low+accepted (fp-check: mechanism TRUE POSITIVE,
exploitability requires local write + microsecond race; in-code SAFETY
documents acceptance).

## Refuted / mitigated / accepted / undecidable records (not active)

### R-01 — Insecure-defaults: 14 candidates investigated, all refuted (refuted)

Source: `audit-notes/insecure-defaults.md` §Refuted candidates (0 findings
confirmed). fp-check verdicts concur — each fails a brocard or the code
evidence:

| # | Location | Claim | Verdict / reason |
|---|----------|-------|------------------|
| 1 | cli.rs:620-634 scope | fail-open default scope | FALSE POSITIVE — no default scope; missing flag is a usage error (fail-secure) |
| 2 | attach.rs:689-702 `from_cli` | fail-open unsafe policy | FALSE POSITIVE — double-gated (CLI flag AND cargo feature); default Allowlisted |
| 3 | uretprobe_hazard.rs:107-111 | fail-open hazard | FALSE POSITIVE as stated — known-hazard branches refuse by default; residual corner is F-01 (different arm: Unknown/None) |
| 4 | engine.rs:3886-3887 BROAD_ADMIT | fail-open env | FALSE POSITIVE as fail-open — absent→false (narrower); residual is observability F-26 |
| 5 | run.rs:454-474 SUDO_UID/GID | fail-open root | FALSE POSITIVE as privesc (Brocard 2: already root); residual is F-57 |
| 6 | discover/main.rs:64-80 `unwrap_or(65534)` | fail-open drop | FALSE POSITIVE — fallback drops *to* least privilege (verified non-root/zero-caps/nnp/nondumpable) |
| 7 | run.rs:390 PATH default | fail-open exec | FALSE POSITIVE — empty PATH → NotFound refusal (fail-secure) |
| 8 | output.rs:427-441 `sudo_uid()` | fail-open trust | FALSE POSITIVE — digits-only, non-root, existing-account, euid==0 only; else None |
| 9 | k8s-profile-entry.sh:29 | fail-open default image | FALSE POSITIVE — fixed-path default, no privilege boundary crossed; inputs validated, TLS+SA CA |
| 10 | output.rs file creation | permissive modes | FALSE POSITIVE — 0600 + O_EXCL/O_NOFOLLOW/O_CLOEXEC + trusted ancestors + mode enforcement |
| 11 | root_fence_runtime.rs:591-611 socket | permissive socket | OUT OF SCOPE — `#[test] #[ignore]` only, and still 0700/0600 + chown |
| 12 | knative-server.py `0.0.0.0` | permissive bind | OUT OF SCOPE — test-matrix fixture only |
| 13 | trace.rs SHA1/MGF labels | weak crypto | FALSE POSITIVE — display labels for *observed* params; identity pinning is SHA-256; no `rand` in prod |
| 14 | main.rs errors / `debug_assert!` | debug leakage | FALSE POSITIVE — one stderr line to invoker, no backtrace dump, no lower-privileged exposure |

Secrets-handling gate: no secret values ever captured/decoded/emitted
(PIN pointers never decoded, template types-only, param ids/lengths only,
session pseudonyms) — `secrets-management` correctly skipped.

### R-02 — STRIDE mitigated threats → regression guards (mitigated)

Source: `audit-notes/stride-threat-model.md` (all cited bodies opened):

| ID | Threat | Control in place |
|----|--------|------------------|
| T6 | Ring-record transplant across rebuild | Domain-ID match refuses (`events.rs` Drain + `history.rs:69` exact-domain gate) |
| I2 | Raw session handles on EVENTS ring | Pseudonymized pre/post-observe; rejected path never shows pseudonyms |
| D4 | Huge-fleet discovery blowup | `max_scan_pids` cap + two-phase sweep + published cap-skip + maps caps |
| E5 | SUDO_UID helper drop-target confusion | 0/MAX filtered, set-id refused |

### R-03 — Differential-review cleared items (verified, no finding)

Source: `audit-notes/differential-review.md` §6: zero security regressions —
every removed check traced to a moved/strengthened equivalent (bracketed
reader extraction, singles-branch gate move, aya API migration, oracle
migrations, mislabel-guard tightening, bounded terminal drain); trust-boundary
deltas cleared (multi pid=0 + in-BPF PID_FILTER identical event sets;
tail-call 48/0 load split correct; fallback sentinel survives error mapping;
non-empty-group construction; poll clamps; sink flush discipline). F8
oracle widening is oracle-only with negative fixtures; no proxy bypass exists.

### R-04 — Mutation killed mutants + declined observation (verified, no finding)

Source: `audit-notes/mutation-testing.md` §Killed Mutants: M3 (surface
quantifier via empty-surfaces edge), M4 (`scan_unavailable`), M5 (count-only
authority), M6 (`slots==0` boundary) all killed — neighboring conjuncts
pinned. M3 mixed-surface hardening idea explicitly declined as a finding
(mutant killed; pure hardening).

### R-05 — Verified-safe non-findings (accepted, no action)

- SE-15: library direct construction of `UnsafeUnvalidatedMetadata` bypasses
  the double gate but attach re-checks and bails loudly — confusing error,
  not silent unsafe decoding (`audit-notes/sharp-edges.md` §SE-15).
- Fuzzing §Verified-safe: `resolved_for` expect (private-field guard),
  scan.rs:960 expect (one-word slice by construction), parse_maps pre-caps +
  budget charges, `read_name`/`read_mountinfo_with`/`read_mapping` bounds,
  MapIndex half-open probes, SIGBUS window plan-accepted.
- Sharp-edges §Validated non-findings: unsafe double-gate + metrics refusal +
  loud safe-build error; measured uretprobe self-probe (Unknown never Clean
  for confined targets); output-sink symlink/mode/ownership refusals;
  attach_gap/sha256/child_still_running pit-of-success shapes; doctor
  NotApplicable lanes.
- PBT: 36/36 scratch checks pass; shared-`target/` interference is a process
  note (use isolated `CARGO_TARGET_DIR`), not a code finding.
- Differential L3 note: broad-admit tables validated through the shared
  bracketed reader with version pin + budget charge; 1.3 mislabel guard
  untouched.

### R-06 — Undecidable: OASIS PKCS#11 v3.2 grounding (undecidable)

Source: `audit-notes/spec-compliance.md` §A-REQ-7: the OASIS standard is cited
by URL only; no spec text/PDF/headers in repo (globs empty). The 110-prose /
104-slot / six-function-gap claim cannot be checked here; code-vs-in-repo-doc
is consistent (104 unique ordered names, no `C_DigestXof*`, boundary names
match). Needs external spec procurement, not a code fix.

## Coverage gaps (explicit non-coverage)

1. **Rust supply chain unassessed.** Collector supports npm/PyPI/Go only; no
   supported manifest exists. Cargo advisory/maintainer/staleness/license
   state unknown: 668-line `Cargo.lock`, `[patch.crates-io]` vendored aya
   trees, two git-rev `pkcs11-components` deps, `object` 0.39.1. Remedy:
   `cargo audit` / `cargo deny` against locked offline build + pin
   verification (see F-27). Source: `audit-notes/supply-chain-review.md`
   (0 findings = 0 coverage, not 0 risk).
2. **Trailmark absent.** Call-graph gate unavailable (`trailmark` exit 127);
   differential blast-radius claims rest on targeted grep/read, not graph
   evidence. Source: `audit-notes/differential-review.md` §8.
3. **cargo-fuzz blocked offline.** `cargo-fuzz`, `libfuzzer-sys`, `arbitrary`
   absent from registry cache; no coverage-guided campaign, no sanitizer run.
   Substitute (17.5M RNG iterations, 0 panics) cannot catch silent
   memory-unsafety in `unsafe` dependency code. Networked
   `cargo +nightly fuzz run` + ASan remains open. Source:
   `audit-notes/fuzzing.md` §cargo-fuzz run.
4. **Full-suite timing flake under load.** ~1 failure per full run; load-
   sensitive wall-clock assertions (`stall_ms`, lifecycle tests) green in
   isolation, red under parallel load; audit runs shared one `target/`
   (a deterministic verdict test flipped COMPLETE/PARTIAL across runs).
   Source: `.full-review/03-testing-documentation.md` §T-M2;
   `audit-notes/architecture-review.md` §AR-11;
   `audit-notes/property-based-testing.md` §3 finding 9.
5. **proptest unavailable offline** (not in Cargo.toml/lock/cache) — P1–P7
   in-crate suites unlanded; maintainer decision pending.
   Source: `audit-notes/property-based-testing.md` §3 finding 10.
6. **No `cargo build`/`cargo test` in differential pass** (a suite was already
   running); `render.rs` +290 reviewed at hunk-outline level only;
   kernel-runtime claims taken from in-code notes, not re-measured.
   Source: `audit-notes/differential-review.md` §8.
7. **STRIDE unopened bodies** (`scope_auth`, `store_start`, identity natives,
   `walk_template`, unsafe decoders, `run_loop`, `publish_descriptors`,
   `attach_path_for`, Session drop, `attach_targets_multi` pid choice, pause
   remainder, `pin_manifest_*`, output openers) — see F-34/F-35/F-58(D8).
   Source: `audit-notes/stride-threat-model.md` §6.
8. **Single-reviewer inline execution everywhere** (no subagent fan-out, no
   independent refutation pass per task rules) — verdicts carry that caveat;
   spec-compliance and full-review note it explicitly.
9. **OASIS spec text absent** — see R-06.

## Per-report finding counts

| Report | Raw findings | Active after dedup | Refuted/mitigated/accepted |
|--------|-------------|--------------------|-----------------------------|
| `audit-notes/architecture-review.md` (AR-1..13) | 13 (3H/4Sig/3M/3L) | 13 in F-06,F-07,F-08,F-25,F-30,F-31,F-32,F-42,F-43,F-57,F-29,F-10,F-60 | 0 |
| `audit-context/DOSSIER.md` | 0 (context only) | — | — |
| `.rust-review-results/…/REPORT.md` + `REPORT.sarif` (12 results, all `note`) | 12 Low | 12 in F-51,F-52,F-53 | 0 |
| `.full-review/05-final-report.md` (+01–04 detail; 6H/20M/20L) | 46 | 46 across F-03,F-04,F-06,F-07,F-08,F-26..F-30,F-32,F-36..F-40,F-44,F-47..F-52,F-54,F-57,F-58,F-60..F-66 | 0 (Q-M3 downgraded M→L: F-66) |
| `audit-notes/differential-review.md` (1M/3L) | 4 | 4 in F-11,F-45,F-46,F-26 | §6 cleared → R-03 |
| `audit-notes/supply-chain-review.md` | 0 (no coverage) | 0 (→ coverage gap 1, F-27) | 0 |
| `audit-notes/spec-compliance.md` (2M/3L) | 5 | 5 in F-12,F-13,F-14,F-50 | A-REQ-7 → R-06 |
| `audit-notes/sharp-edges.md` (1H/9M/14L) | 24 | 23 in F-01,F-02,F-12,F-15,F-17..F-22,F-47..F-50,F-55,F-56 (+F-10/F-57 evidence) | SE-15 → R-05 |
| `audit-notes/insecure-defaults.md` | 0 confirmed | 0 | 14 refuted → R-01 |
| `audit-notes/property-based-testing.md` | 7 gaps + 1 Low + 2 info | 8 in F-31,F-41,F-59 (+gap 9 process note below) | 1 process note → R-05; proptest offer → gap 5 |
| `audit-notes/mutation-testing.md` | 2 Medium (+4 killed) | 2 in F-31 | 4 killed + 1 declined → R-04 |
| `audit-notes/fuzzing.md` (1M/2L, 0 crashes) | 3 | 3 in F-05,F-41,F-27/F-54 | 0-dynamic-failures recorded; §Verified-safe → R-05 |
| `audit-notes/stride-threat-model.md` (38 threats: 3 high/15 med/20 low scores) | 38 | 34 in F-01,F-08,F-15,F-16,F-23..F-25,F-33..F-35,F-48,F-53,F-55,F-56,F-58,F-68,F-69 | 4 mitigated → R-02 |
| `audit-notes/adversarial-review.md` (3 risks + 7 concerns + obs) | 10 + obs | 10 in F-01,F-02,F-05,F-06,F-09,F-10,F-23,F-25,F-30,F-43,F-54,F-67 | finance/operator observations → accepted context (no action) |
| **Total** | **~167 raw** | **69 active (8H/36M/25L)** | **14 refuted, 4+ mitigated, ~15 accepted/verified-safe, 1 undecidable** |

## Dedup map (source ID → final ID)

- AR-1→F-06, AR-2→F-07, AR-3→F-08, AR-4→F-42, AR-5→F-31, AR-6→F-43,
  AR-7→F-32, AR-8→F-30, AR-9→F-25, AR-10→F-57, AR-11→F-29, AR-12→F-10,
  AR-13→F-60
- SAFETYDOC-001..010→F-51, CARGOLINT-001→F-52, SHMRACE-001→F-53
- Q-H1→F-06, Q-H2→F-07, Q-M1→F-39, Q-M2→F-44, Q-M3→F-66, Q-M4→F-38,
  Q-M5→F-44, Q-L1→F-54, Q-L2→F-61, Q-L3→F-61, A-H1→F-07, A-H2→F-06,
  A-M1→F-08, A-M2→F-65, A-M3→F-19, A-L1→F-19, S-H1→F-03, S-M1→F-26,
  S-M2→F-27, S-L1→F-57, S-L2→F-54, S-L3→F-61, S-L4→F-48, S-L5→F-51,
  P-M1→F-37, P-M2→F-38, P-L1→F-49, P-L2→F-61, P-L3→F-61, T-H1→F-04,
  T-M1→F-40, T-M2→F-29, T-M3→F-05, T-L1→F-62, T-L2→F-62, D-M1→F-30,
  D-M2→F-26, D-L1→F-52, B-M1→F-36, B-L1→F-52, B-L2→F-65, B-L3→F-27,
  C-M1→F-28, C-M2→F-63, C-L1→F-64, C-L2→F-60
- Diff M1→F-11, L1→F-45, L2→F-46, L3→F-26
- Spec F1→F-14, F2→F-13, F3→F-50, F4→F-12, F5→F-50
- SE-01→F-17, SE-02→F-15, SE-03→F-01, SE-04..11→F-47, SE-12→F-18,
  SE-13→F-19, SE-14→F-20, SE-15→R-05, SE-16→F-48, SE-17→F-49,
  SE-18→F-56, SE-19→F-02, SE-20→F-12, SE-21→F-21, SE-22→F-22,
  SE-23→F-55, SE-24→F-50
- PBT gaps 1-7→F-41 (+verdict row→F-31), PBT-8→F-59, PBT-9→R-05, PBT-10→gap 5
- Mut M-1,M-2→F-31; M3-M6→R-04
- Fuzz F1→F-54, F2→F-05/F-41, F3→F-27
- STRIDE: S1→F-24, S2/S3/S5→F-35, S4→F-16, T1→F-24, T2/T3→F-34,
  T4→F-48, T5→F-56, T6→R-02, T7→F-58, R1→F-08, R2/R3/R5→F-58, R4→F-15,
  I1→F-68, I2→R-02, I3→F-58, I4→F-55, I5→F-33, I6→F-34, D1→F-01,
  D2→F-23, D3→F-16, D4→R-02, D5→F-25, D6→F-15, D7/D8→F-58, E1→F-33,
  E2/E3→F-69, E4→F-58, E5→R-02, E6/E7→F-34
- Adv Risk1a→F-01, Risk1b→F-25, Risk2→F-05, Risk3→F-10, Concern4→F-09,
  Concern5→F-02, Concern6→F-23, Concern7→F-04/F-28, Concern8→F-23,
  Concern9→F-06, Concern10→F-67

## Top-5 recommended next actions (synthesizer's cut)

1. F-01: fail closed on uretprobe hazard for wide scopes (`(Unknown,None)` →
   warn-or-refuse); add preflight to the `run` lane; record overrides in evidence.
2. F-03+F-04+F-28: fix the CI integrity triangle — repoint aya tests to `-p2`,
   add release-preview (musl/docker/kubeconform/SBOM), schedule one privileged E2E.
3. F-09: fix the `doctor` row-name/classifier mismatch + regression test (one-line
   class, unblocks all tier-gated work).
4. F-02: split the verdict signal — keep honest PARTIAL but add a
   machine-readable "clean run, drain unproven" state distinct from concrete gaps.
5. F-13+F-12+F-50: close the producer/validator/doc triangle — admit the sixth
   skip reason, document the metrics/profile split, document the 4 missing
   evidence fields (all doc/validator-side, no prodcode risk).
