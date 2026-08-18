# Slice 1b-2 corrective live-discovery design

**Date:** 2026-08-18

**Status:** Owner-approved for written-design review; no implementation or
production authorization

**Exact source base:** `37c5b41112b137ecd7b2c703fa0e9ebcee765c16`

## 1. Scope and authority

This design corrects and supersedes only the Slice 1b-2 loader, pause, and
dependent spike premises in
`2026-08-15-productization-slice1-discovery-and-trust-design.md`, principally
§4.3, §4.4, §6.1–§6.3, the related §8 acceptance statements, §10.2, and
§10.5. Where those sections conflict with this document, this document
governs Slice 1b-2.

It does not:

- change or close Slice 1b-1; the ROADMAP status remains **OPEN**;
- claim that loader/export hooks, pause, or `run` exist in production;
- modify the current schema, privacy allowlist, ROADMAP, source, BPF object,
  fixture, gate, or retained evidence;
- authorize Task 5, a production implementation plan, or release work;
- change the Rust 1.88, Edition 2024, Linux x86-64-first, upstream-5.15
  baseline;
- change the current final-document rule that every written profile is
  `PARTIAL` because terminal BPF drain is unproved.

The next action after this commit is independent review of this written spec.
No implementation plan is written until that review returns **PASS**. Even
then, the ROADMAP still requires Slice 1b-1 to land before the Slice 1b-2
production plan is written.

## 2. Binding evidence and status

The four corrective inputs are immutable evidence inputs to this design:

| Artifact | SHA-256 | Status carried into this design |
| --- | --- | --- |
| `/tmp/slice1b2-gatea-corrective-analysis.md` | `a8578527c2e63aaffe73f0233823570e4bde491286a7f95d4f2a4e929dfa79a8` | Static/artifact-reproduced root cause and a proposed structural correction. Gate A remains NON-PASS; the correction is unimplemented and unrun. |
| `/tmp/slice1b2-gateb-variance-analysis.md` | `2abc938c0516f4403a655da0bcee15cc0ec49afcb3d1a131982910759efee3c8` | Static/artifact-reproduced variance analysis. Task 3 Jammy remains canonical FAIL and Task 4 Jammy remains canonical PASS; pause is unpromoted. |
| `/tmp/slice1b2-loader-corrective-analysis.md` | `89ed5bf3d52912e596be49b13396216e1cf40a4e31120358cf7820d567e74374` | Direct runtime loader evidence plus a corrective design. The exact glibc timing premise failed; the musl result is a narrow direct control, not product proof. |
| `/tmp/slice1b2-corrective-design-cross-review.md` | `31ca2a2ffc8de95fc4c3439dd650ae69dc5a7759fbe4b59ab464d56991b55557` | **NEEDS FIXES** input review. This design resolves its four Important findings and one Minor finding; that resolution itself still needs independent review. |

The resulting gate status is exact: Gate A is **NON-PASS**; revised Gate B is
**UNRUN**; corrective Gate C is **UNRUN**; and the final multi-artifact
campaign is **UNRUN**. The Task 3/Task 4 Gate B observations remain retained
historical evidence and do not make revised Gate B PASS.

Decisive retained binary evidence includes:

- Gate A diagnostic BPF object
  `9818d79d08772c0cea34f6b76c9757b6393ada2e59907bcaab596d904269b27f`;
- final six-program spike BPF object
  `d405edee75d762fdc63b2c663a9ebaa25f9a0ef07c3a80376fbb1d250f374831`;
- Gate B source manifest
  `609d876d69e62c599fd7ff981317e40f7c44def86bb4e46a825005db87e64e55`,
  runner `2c69fce68ee6292c8cf65e8233fa6d44bccefdf8aa8349cf4b55a728db5641dd`,
  and fixture
  `1570f73ec282aa152867696e758a8648b7541f29ca35f771d5cfba494939506b`;
- canonical loader transcripts: musl
  `05a84f37d469fa8582274e78d53b8313042a116853b454689348458cf7d746af`,
  glibc 2.35
  `32dc68bce74c3ee7ad27488b47922b1bee02bc3e8689c55052ea36f077a0d31a`,
  and glibc 2.39
  `0ca41c4a4d7c45af480912281f261188d2e3ba083f7647f5c05f925a74906a02`.

Status labels are exact:

- **PASS** means every predeclared semantic predicate passed under the frozen
  campaign identity;
- **NON-PASS** is a summary state meaning no qualifying PASS exists; it never
  replaces the underlying FAIL, TIMEOUT/INCOMPLETE, or UNRUN records;
- **FAIL** means a completed finite verifier, runtime, oracle, validation,
  privacy, provenance, or lifecycle predicate failed;
- **TIMEOUT/INCOMPLETE** means the bounded attempt did not produce a complete
  canonical outcome;
- **UNRUN** means no authorized attempt exists;
- **PARTIAL** is product evidence completeness, never a synonym for a gate
  PASS or a forgiven lifecycle failure.

Every FAIL, TIMEOUT/INCOMPLETE, and negative control remains retained. A later
PASS is additional evidence, not a replacement.

## 3. Corrective decisions and artifact graph

The corrective evidence uses a frozen multi-artifact campaign manifest. There
is no object that is simultaneously the isolated four-map spike and the future
production observer. Every manifest entry records its role, exact Git
commit/tree, source archive and file manifest SHA-256, toolchain, BPF/host/
fixture/validator SHA-256, userland and kernel identity, complete map/program
inventory, common ABI, caps, deadlines, oracle version, and parent campaign ID.
An unlisted or mismatched artifact has no authority.

The manifest has exactly these roles:

1. **A/B spike:** one isolated six-program object with exactly `EVENTS`,
   `DISCOVERY`, `START`, and `COUNTERS`, plus its frozen runner and fixtures.
   Gate A retains its exact four-map/five-case oracle; revised Gate B retains
   its own 120-child oracle on those same final A/B bytes.
2. **C qualification:** one product-shaped observer/fixture/harness bundle for
   each exact loader/userland control. Each bundle has its own declared
   BPF/map/program and userland inventory and authorizes only the timing or
   fallback predicate that it actually proves.
3. **Production candidate:** only after Slice 1b-1 lands and the owner approves
   a production plan, one exact production source/object/runner/schema/privacy
   bundle with its own complete production map/program/verifier/runtime oracle.
   It never runs the spike's exact-four-map assertion.

The correction and order are:

```text
independent PASS on this written design + owner execution authorization
  -> A structural GREEN and unchanged isolated Gate A on 5.15/6.8
  -> revised B repeatability on the final A/B spike bytes
  -> C exact-build qualification bundles on 5.15/6.8
  -> retain the reviewed corrective evidence while Slice 1b-1 remains OPEN
  -> Slice 1b-1 lands + owner approves a separate production plan
  -> implement and freeze the production candidate
  -> final multi-artifact A/B/C/production re-gate + independent review
```

Corrective A/B/C implementation and evidence may therefore be separately
authorized before Slice 1b-1 lands; production planning, implementation, and
the final re-gate may not. This document itself authorizes none of them.

Invalidation follows the manifest edges, not an impossible one-object rule:

- an A/B spike BPF, common record, runner, fixture, cap, validator, or oracle
  change reruns structural A, both-kernel A, and the full revised B matrix;
- a C source/control BPF, context encoding, fixture, loader/libc, validator, or
  predicate change reruns every affected C control on both kernels;
- a production emitter that reserves the 896-byte record must independently
  pass the semantic initializer guard in §4.4, while any production map,
  program, ABI, schema, cap, validator, privacy, or oracle change reruns the
  corresponding production gate;
- a shared source or ABI change invalidates every manifest node that names its
  digest; schema/render-only changes do not invalidate unrelated BPF evidence;
- a catalog entry is derived only from unchanged reviewed C evidence and final
  production integration review. Qualification bytes never authorize different
  BPF bytes or a broader capability.

## 4. Gate A — discovery-record initialization

### 4.1 Frozen implementation shape

The only authorized Gate A source experiment is replacing the current 896-byte
zero-initialization loop with exactly 112 flat calls semantically equivalent to:

```rust
core::ptr::write_volatile(words.add(K), 0u64);
```

for the complete integer set `K = {0, 1, ..., 111}`, each exactly once. The
calls stay inside the existing documented discovery raw-write `unsafe` block.
No runtime loop, iterator, slice fill, `write_bytes`, recursive helper, chunk,
plain nonvolatile store, new dependency, or linker-unrolling assumption is
accepted.

The Gate A initializer correction itself leaves these invariants unchanged:

- `DiscoveryRecord`: size 896, alignment 8, fixed field offsets, 104 pointer
  words and existing tail fields;
- all common host/eBPF ABI record sizes, alignments, and field offsets;
- the four maps `EVENTS`, `DISCOVERY`, `START`, and `COUNTERS` in the spike;
- the final six-program/four-map inventory and every Gate A mode meaning;
- literal behavioral bounds `pointer_index < 104` and
  `interface_index < 16`;
- `START.insert(..., BPF_NOEXIST)`, fail-closed `usable_n = 0`, the single raw
  write block, and submit-after-initialization ordering;
- Aya `VERBOSE | STATS`, program load order, timeout, log/export caps, record
  cardinalities, privacy checks, and the Gate A runtime oracle.

The later §5 Gate B mode extends only existing `START`/status value namespaces;
it does not change this inventory or record layout. Because that changes the
final A/B bytes and non-Gate-A behavior, §3 requires the exact Gate A oracle to
run again on those bytes; the extension is not attributed to the initializer
fix or used to weaken Gate A.

### 4.2 Semantic source and disassembly guard

The source guard proves the exact finite index set with no duplicate or missing
index and proves that no record field is read or submitted before all 112 stores.

The frozen-object guard consumes the exact BPF ELF and scoped
`llvm-objdump -dr` output. It proves, on every reservation-to-use path for the
896-byte discovery record:

1. exactly 112 aligned 64-bit zero stores cover byte offsets
   `{0, 8, ..., 888}` and therefore bytes `0..895`;
2. every store precedes any record read, field use, or submit;
3. the initializer has no call relocation to `memset`, no byte-store zero
   loop, and no backward branch;
4. the ABI, map inventory, program inventory, 104/16 behavioral loops,
   fail-closed rules, and submit ordering above are unchanged.

The guard is semantic. It must not require a particular base register,
instruction order among independent stores, compiler text spelling, or the
absence of unrelated `memset` elsewhere in the ELF.

### 4.3 RED, GREEN, and kernel gate

Before the source change, the structural test must fail on the exact current
object because the discovery initializer calls `memset`, reaches an 896-step
byte-store loop, contains a backward branch, and lacks the full direct-store
set.

After the source change, the candidate may enter a kernel only when the exact
locked build passes the semantic source and object guard. A remaining
initializer call, byte store, back edge, ABI/map/program drift, or missing
offset is structural FAIL; no VM run is used to negotiate around it.

The unchanged Gate A then runs once from a fresh overlay on Jammy 5.15 and once
on Noble 6.8 with identical BPF, runner, and fixture bytes. Both kernels run
regardless of the first oracle result. PASS still requires exactly four
accepted verifier records, all five exact cases, four maps, exact
records/counters, empty final `START`, canonical validation, and complete
privacy-bounded export. The inner 120-second limit, finite outer limit, 8 MiB
verifier-log cap, 16 MiB total cap, six-file inventory, and existing validator
remain unchanged.

A new verifier failure or TIMEOUT/INCOMPLETE is retained as the result. The
store correction is a causal hypothesis, not permission to tune the verifier,
change caps, or weaken the oracle.

### 4.4 Production-candidate initializer gate

The future production object has a different program/map inventory. Every
production program path that reserves this 896-byte `DiscoveryRecord` must pass
the same source-index and semantic disassembly guard in §4.2. The production
validator separately freezes and checks every production program, map, helper,
record ABI, cap, verifier result, and runtime oracle; it does not assert four
maps or reuse the spike's five cases. A shared initializer/source digest binds
the two guards, but a PASS for one object proves nothing about the other's
inventory or verifier acceptance.

## 5. Pause product contract

### 5.1 CLI policy

`run` has exactly these pause choices:

| User input | Meaning |
| --- | --- |
| omitted | Exactly `never`. No pause authorization is published and no stop is requested. |
| `--pause never` | Same as omission. Attach normally and report the measured gap. |
| `--pause auto` | Explicit best effort. A failed or unconfirmed non-lifecycle attempt falls back to attach/resume with `pause: partial`; early calls may have been missed. |
| `--pause always` | Explicit required pause. If safe arming, request acceptance, confirmation, required attachment, or protected resume cannot be completed, clean up through the original pidfd and return a named nonzero refusal/failure. It never falls back as a successful unpaused run. |

Pause remains limited to the observer's owned, unreaped `run` child. External
`--pid` and `--cgroup` targets are never paused. A pause request outside `run`
is refused. `auto` is not silently selected by omission and is not promoted
until revised Gate B passes.

An exact-negative or unproven loader does not by itself make `always`
unarmable: an exact safe hook may still request and confirm a stop. Such a run
remains `PARTIAL` for loader timing. Conversely, a positive loader capability
does not forgive an unconfirmed pause.

### 5.2 One outstanding owner

There is at most one outstanding pause owner per child generation. The owner
holds:

- the original pidfd opened for that child;
- the pinned child generation and pre-request expected task set;
- the earliest causal hook timestamp;
- the coalesced modules and exact attach keys required to protect that window;
- request, confirmation, marker, attach, resume, and cleanup state.

Only an idle coordinator may begin an attempt. The planned production
`PAUSE_PIDS` value has exactly `ARMED = 1` and `REQUESTED = 2`; absence means no
pause authorization. Userspace inserts `ARMED` only after preflight. A scoped
hook atomically compares and exchanges `ARMED -> REQUESTED`; only the winner may
call `bpf_send_signal(SIGSTOP)`. Hooks observed while the owner exists emit and
coalesce their attach keys but cannot create another signal, owner, deadline,
or resume.

The isolated A/B spike adds no fifth map. In Gate B mode it uses the existing
`START` map only at the disjoint group key
`StateKey { pid_tgid: tgid << 32, attach_cookie: u64::MAX }`: a real thread key
always has a nonzero low TID. `StartState.arg0` carries `ARMED|REQUESTED` and
`arg1` stays zero. Normal entry/return keys and `BPF_NOEXIST` behavior are
unchanged. The Gate B validator proves namespace separation and empty final
`START`; the exact Gate A oracle is rerun on the same final four-map bytes.

Userspace removes `REQUESTED` after the accepted stop's safe resume, or after
failure cleanup proves no stop was accepted, and then closes the owner. A fresh
`ARMED` value is inserted only for a later attempt. A hit in the unarmed
transition window remains observable but cannot claim pause protection and is
folded as a partial attempt for explicit `auto`, or a required failure for
explicit `always`. No second owner map or public state is added.

### 5.3 Hook timestamp and confirmation

The BPF hook performs, in this order:

1. scope, process generation, and exact attach-key checks;
2. reserve the exact `DISCOVERY`/private `SignalRecord`; on failure increment
   `discovery_ring_loss`/`RING_LOSS`, return without changing `ARMED`, and send
   no signal;
3. initialize every helper-independent record byte;
4. atomically compare/exchange `ARMED -> REQUESTED`;
5. for the winner, take `hook_ts_ns = bpf_ktime_get_ns()` immediately before
   the single `bpf_send_signal(SIGSTOP)` and store its real signed return; for a
   nonwinner, store its causal timestamp and the exact coalesced/no-helper
   status;
6. finish initialization and submit the record.

Reservation therefore precedes authorization consumption and signalling. In
the private spike, `SignalRecord.send_signal_rc == i64::MIN` means exactly
`coalesced_no_helper`; it is outside the helper's finite zero/negative-errno
return range. Zero means an accepted helper request and every other value is
the actual helper return. In the product `DiscoveryRecord`, reserved
`status_flags` bit `0x02` means exactly `coalesced_no_helper`; bit `0x01` keeps
its existing read-failure meaning. No record size, offset, public field, or raw
status output changes. Source/layout tests freeze these values and prove that a
coalesced record never calls the signal helper.

`bpf_ktime_get_ns` and `bpf_send_signal` remain outside the record raw-write
`unsafe` block. That block contains only the writes needed to initialize the
record; submit remains after complete initialization.

Userspace uses the same monotonic clock domain. The absolute confirmation
deadline is exactly `hook_ts_ns + 100_000_000 ns`; ring delivery and scheduling
consume this budget. Overflow, a clock-domain inconsistency, or an impossible
future timestamp is a finite timing/lifecycle error, never a wrapped or reset
deadline.

No SIGSTOP is resent. Userspace samples no more frequently than once per
millisecond. Two exact-set/all-`T` samples prove that the previously executing
hooks have returned to a stopped user boundary. Userspace then drains and
validates all already-submitted exact-child discovery records until the ring is
empty and only then freezes the owner's coalesced required attach set. With all
tasks stopped there is no exact-child producer left to race that empty read.

`pause: sigstop` eligibility requires:

1. one accepted request for the exact child generation;
2. two consecutive snapshots equal to the frozen expected task set, with every
   task in state `T`;
3. at least `1_000_000 ns` between those two snapshots;
4. both snapshots no later than the absolute 100 ms deadline;
5. a complete drain-to-empty containing the winner and every coalesced record,
   with no relevant ring loss, malformed record, stale generation, unknown
   status, duplicate winner, or unaccounted queued record;
6. no protected marker before attachment;
7. every attach key required by the frozen owned attempt attached while
   the group remains stopped;
8. a third exact-set/all-`T` snapshot, absent marker, and still-empty
   exact-child queue immediately before
   resume;
9. one successful resume attempt through the original pidfd, followed by the
   expected post-resume marker/lifecycle result.

A changed task set, non-`T` task at the deadline, `/proc` read error, marker,
rejected helper request, relevant ring loss, malformed coalesced record,
failed drain closure, failed required attach, failed post-attach sample, or
deadline miss cannot become `sigstop`. After safe resume, explicit `auto`
records a non-lifecycle failure as `partial`; explicit `always` returns a
required-lane failure. Pidfd, resume, detach, cancellation, kill/reap, or
provenance failure is a lifecycle error in either mode and is never converted
to partial success.

### 5.4 Resume and cancellation

Each accepted owned stop has exactly one resume attempt through the original
pidfd on success, error, timeout, Ctrl-C, SIGTERM, or guard drop. There is no
fresh-pidfd recovery and no numeric-PID `SIGCONT` fallback. A failed original-
pidfd resume stops the campaign or command for lifecycle review; cleanup may
kill/reap only through the already-owned child lifecycle.

An observer SIGKILL during the stop window can still leave the child stopped;
that accepted residual risk remains documented. Ordinary errors are covered by
the owner guard. Third-party stop interaction remains standard signal behavior
and cannot be distinguished or claimed away.

### 5.5 Attach-gap definition

For each live-discovered module, the causal start is the earliest accepted
loader/export event that first made any attach key in the module's eventual
required set discoverable. Repeated hits and coalesced pause attempts never
move this timestamp later.

The causal end is the monotonic timestamp immediately after the last required
entry/return probe for that module attaches successfully. Therefore:

```text
per_module_attach_gap_ms =
    (last_required_attach_ts_ns - earliest_causal_event_ts_ns) / 1_000_000
```

Subtraction is checked. Clock reversal/overflow is a finite timing error. If no
required attach succeeds, or one remains failed, the module gap is `null` and
the existing `attach_failures` counter records the exact finite attachment
loss; zero is never invented. If discovery loss or a malformed relevant record
makes the earliest causal timestamp unknowable, the capture-level gap is
`null`, the corresponding loss counter forces `PARTIAL`, and a later surviving
event is never substituted as the causal start. The
top-level `attach_gap_ms` is the maximum of defined per-module values and is
`null` when none is defined. Initial/periodic scans retain `scan_ms` and
`attached_at_ms`; they do not manufacture a hook gap.

Pause confirmation does not zero or replace this measured gap. A later event
or successful attach cannot erase the earlier causal window.

### 5.6 Capture-level pause lattice

The pause coordinator exclusively owns three aggregate counters:

- `pause_attempts`: pause-protection attempts begun, including an owned attempt,
  an explicit `auto` attempt that cannot be armed, or an exact-child record
  loss that prevents ownership;
- `pause_confirmed`: attempts that satisfy every predicate in §5.3 and resume
  successfully;
- `pause_partial`: nonfatal `auto` attempts that fail to protect their attach
  window but complete safe resume/cleanup.

Each relevant reservation loss or malformed exact-child record under explicit
pause authorization is accounted exactly once. If the bounded observation and
current owner state assign it to that owner, the owner becomes partial;
otherwise it creates one standalone
`pause_attempts += 1, pause_partial += 1` protection
attempt without claiming a stop. Thus `auto` renders `pause: partial` even when
reservation failed before authorization was consumed. Under `always`, the same
condition is a required failure after any accepted stop is safely resumed.

For every normally rendered capture,
`pause_confirmed + pause_partial == pause_attempts`. The public `pause` value is
the exact lattice:

```text
none     iff pause_attempts == 0
sigstop  iff pause_attempts > 0
            and pause_confirmed == pause_attempts
            and pause_partial == 0
partial  iff pause_attempts > 0 and pause_partial > 0
```

`partial` is sticky: a later confirmed attempt cannot mask an earlier partial
attempt. A lifecycle error prevents a normal successful result rather than
creating a fourth pause value.

### 5.7 Live-window completeness

Any module whose first required attach key is learned from a live loader or
export event forces capture `PARTIAL` unless that exact causal window belongs
to a confirmed pause owner and every required key is attached before its one
resume. This is independent of the numeric attach gap and loader timing.

`pause: none` is not itself a gap when no live attach window occurred, such as
an initial scan whose full plan was attached before observation began. Once a
live window is unprotected, `pause: partial` or the corresponding unprotected
live-source completeness loss is sticky; a later scan, pause, attach, or
positive loader capability cannot erase it. Positive pre-constructor timing
identifies an early event only—it never supplies attach protection.

## 6. Revised Gate B

### 6.1 Private bounded evidence

The spike extends only its existing private `signal-timing.jsonl`. No stop
timeline is added to profile, metrics, trace, ordinary logs, or doctor output.
Each child retains at most 101 samples at the one-millisecond cadence, each
containing only:

```text
elapsed_us
task_count
exact_expected_task_set
state_counts { R, S, D, T, t, Z, X, I, other }
```

It also retains the two finite fixture case IDs and record-observed times, the
two accepted confirmation sample indexes/times or `null`, first
marker-observed time or `null`, `winner_records`, `coalesced_records`,
`signal_helper_calls`, `required_attach_keys`, `resume_attempts`,
`drain_empty`, and the constant `stop_wait_ceiling_us = 100000`. Raw PID, TID,
task sets, signal records, runtime addresses, and private guest paths are never
serialized.

The independent validator recomputes monotonicity, bounds, exact-set/all-`T`,
minimum separation, record/status closure, marker ordering, attachment, gap,
resume, detach, exit, reap, and result. It ignores any serialized `pass` or
summary field.

### 6.2 Repeatability campaign

Before execution, freeze one reviewed binding, source archive, source manifest,
BPF ELF, Jammy-built runner, fixture, validator, timeout, cap set, and campaign
manifest. Use byte-identical BPF, runner, fixture, and validator on both
kernels.

Predeclare exactly six serialized lanes:

- three fresh cold boots/runtime overlays on Jammy 5.15;
- three fresh cold boots/runtime overlays on Noble 6.8;
- exactly 20 fresh children per boot, for 60 children per kernel and 120 total.

Every child uses the same two-thread fixture barrier to reach two distinct hook
offsets/attach keys concurrently. Its exact additional oracle is one real
signal-helper call and accepted winner, one `i64::MIN` coalesced/no-helper
record, both finite case IDs in the drained frozen attach set, both required
keys attached while stopped, an empty record queue before resume, and exactly
one original-pidfd resume. The existing timing, marker, late-hit, exit, reap,
detach, counter, privacy, and provenance predicates all remain required. A
single-hook focused test remains as a producer/decoder check but cannot replace
any concurrent campaign child.

All safe predeclared kernel lanes run regardless of an earlier oracle FAIL.
There are no replacement lanes. A host-safety, quiescence, provenance,
resume, detach, or reap failure stops the campaign after safe cleanup. A child
FAIL makes its lane and campaign fail even if later predeclared lanes pass.

Campaign promotion requires 120/120 semantic PASS, no verifier, runtime,
oracle, timeout, privacy, validation, cleanup, provenance, or environment
failure, and independent recomputation from every attempt. One green lane,
aggregate pass rate, or “N passes since failure” is insufficient.

Task 3 Jammy run 19 remains canonical historical FAIL/oracle. Task 4 Jammy
20/20 remains canonical historical PASS. Neither counts toward the revised
matrix because neither recorded the revised timeline or used the actual-wait
implementation. Both remain in the chronological ledger. If a new attempt
records the old early non-`T` signature and later confirms within 100 ms, the
report may additionally mark that race class reproduced; absence of that
signature leaves the precise historical cause unresolved and does not weaken
the 120/120 criterion.

Any code, schema, ceiling, BPF object, runner, fixture, validator, or oracle
change creates a new campaign identity and a fresh six-lane matrix.
The 100 ms ceiling is not adaptive. A larger ceiling requires a separately
approved calibration design and an entirely new validation campaign.

## 7. Loader product contract

### 7.1 One every-hit runtime

`_dl_debug_state` is an event source, not a portable relocation-ready
contract. Every scoped debug-state hit is submitted and handled. Neither
`RT_CONSISTENT`, an unreadable state, a libc family, a version string, nor a
package name suppresses a hit.

For every accepted hit, userspace revalidates the process generation and exact
loader context, refreshes mappings, pins new candidate objects, attaches exact
standard export symbols available from the pinned ELF, and runs the bounded
memory scan when `/proc/<pid>/mem` is available. An empty scan is evidence, not
relocation proof. When memory scan is unavailable, live export hooks remain the
table-read path; the loader event alone is not called a table scan.

Duplicate exact `{pinned object identity, offset}` targets remain deduplicated.
Scope filtering occurs before every target-memory read. A stale generation,
unbound mapping, identity mismatch, or unknown address cannot authorize an
attachment.

### 7.2 Candidate capability key

A timing capability candidate is keyed only by the exact tuple:

```text
architecture + loader SHA-256 + companion-libc SHA-256
```

For musl, loader and libc may be the same exact file and digest. GNU build IDs,
symbol offsets, source commit, fixture, compiler/configuration, kernel lanes,
and proof artifact are retained private provenance. Version, distro, package
name, changelog text, or “newer than” reasoning never selects a capability.

The one timing vocabulary, used by qualification and eventual product
aggregation, is:

- `qualified_pre_constructor` — product-shaped C evidence passed for this
  exact tuple and load kind; before final multi-artifact review this is only a
  candidate classification and product selection must ignore it;
- `known_pre_relocation` — reviewed product-shaped negative evidence proves
  the qualified event is too early for relocated-table claims;
- `unproven` — no reviewed exact product qualification exists;
- `none` — the strategy supplies no debug-state timing claim.

Timing is recorded separately for `dlopen` and `initial_set`. A positive value
for one load kind grants nothing to the other.

All currently named tuples are qualification controls/candidates, not product
catalog entries:

| Control | Exact tuple | Current control expectation |
| --- | --- | --- |
| Alpine 3.24.1 musl 1.2.6 | x86-64; loader/libc SHA-256 `38d022ce7425ff105ccfb53598f606e6e5f5f0a34bfbc793d65e6f34c9d72806`, build ID `2b26dfbb1a8172e32ed88052349fd6c997e6aa79` | Direct `dlopen` witness was pre-constructor/equal; initial set unproved. Candidate positive control only. |
| Ubuntu glibc 2.35 | x86-64; loader SHA-256 `8d06f393f4a93bcf9b81145a259524d66a95522a646bf8d7e05b6ffdf2e63dcc`; libc SHA-256 `e01b1ce7be2987f3b8560e26d0df2623f9dd5cec17be923ae28a785bc0d32d50` | Direct `dlopen` first post-ADD consistent witness was zero. Exact negative control only. |
| Ubuntu glibc 2.39 | x86-64; loader SHA-256 `cd4df4f3c7b83673d61189bf2eaebd33ca4f2853ab9772b8a25e025ef99b1e81`; libc SHA-256 `8db37cf3f2169f59a0f07ef1fea308c35656668c64c8ff294e1860f4121eb161` | Same direct `dlopen` zero-at-consistent result. Exact negative control only. |
| Fixed-glibc candidate | Reproducible exact tuple built from source containing upstream commit `43db5e2c0672cae7edea7c9685b22317eae25471` | Source evidence predicts corrected `dlopen` order; no runtime product qualification exists. |

The current direct `/proc/<pid>/mem` evidence may select expectations for the
qualification controls. It cannot populate a product catalog.

### 7.3 Exact ptrace-free loader context

The initial implementation is x86-64 and uses one finite pre-exec method. While
the owned direct-ELF `run` child is still behind its barrier, userspace pins and
hashes the intended executable, parses its exact `PT_INTERP`, pins and hashes
that loader through the child's root, and derives from the pinned ELF:

- `_dl_debug_state` virtual address and exact file offset;
- optional `_r_debug` virtual address and the frozen x86-64
  `R_STATE_OFFSET = 24` layout;
- checked signed `delta = _r_debug_vaddr - hook_vaddr`.

It attaches the loader uprobe by pinned file offset and one-process scope before
releasing the barrier. It does not resolve libc, walk dependencies, read
`/proc/<pid>/mem`, or predict the future loader base.

One session-local userspace registry has capacity exactly 256, matching the
existing `MAX_SCAN_PIDS` scope bound. Context IDs are monotonically allocated
from 1 through 256 and never reused. Each immutable descriptor contains the
process generation, pinned loader identity/digest, hook virtual/file offsets,
optional state metadata/delta, link identity, and live/tombstoned lifecycle.
Insertion precedes link attachment. A failed attachment tombstones the entry;
a live entry is tombstoned only after its link detaches. Descriptors remain
until all loader links are detached and the discovery ring is drained at
session end, then the registry is removed.

The loader attach cookie is one exact `u64` encoding:

```text
bits 0..7   = context_id - 1
bit 8       = state_present
bits 9..63  = signed 55-bit two's-complement delta
```

The encoder rejects a delta outside `[-2^54, 2^54 - 1]`; BPF decodes it with
`(cookie as i64) >> 9`. `state_present = 0` requires the encoded delta to be
zero; any other combination is malformed. A loader record copies bits 0..7
into its existing `case_id`; userspace adds one and validates the immutable
descriptor and exact generation. There is no loader-context BPF map and no
public context ID.

At the hook, after scope and reservation, BPF obtains
`hook_runtime_ip = bpf_get_func_ip(ctx)`, rejects zero, applies the signed delta
with checked add/subtract to obtain `_r_debug`, then checked-adds exactly 24 and,
only when `state_present`, reads `r_state` with bounded
`bpf_probe_read_user` as one 4-byte value. Gate C must prove on both kernels that
`hook_runtime_ip == load_bias + hook_vaddr`, the derived debug address equals
`load_bias + _r_debug_vaddr`, and the read uses that exact field offset before
any state-dependent classification. Overflow, helper failure, or a formula
mismatch never drops the every-hit record.

The existing BPF `state_read_failures` counter owns state-address/helper
failures. Registry exhaustion, an unknown/out-of-range context, generation or
loader mismatch, or an undecodable record contributes exactly once to the
existing userspace `discovery_truncated` accumulator, makes
`initial_set_capture = none`, and forces `PARTIAL`; unsafe identity refuses the
attachment. A state-absent loader can still emit every hit, but cannot satisfy a
state-dependent catalog predicate. No ID is recycled to reinterpret a queued
record.

The corrective C spike uses this same cookie/IP/state path. Its fixture-only
relocation witness is read with bounded `bpf_probe_read_user` and serialized
only as `zero|equal|unequal|unreadable`. Raw addresses, cookies, deltas, and
context IDs are never evidence output; the witness and constructor marker do
not become production ABI. GDB or `/proc/<pid>/mem` evidence is not a
substitute.

### 7.4 Event-time tuple binding and initial-set predicate

Pre-exec eligibility requires the exact loader identity and attached hook, not
a guessed companion libc. At each candidate qualifying event, userspace first
matches the record's context/generation, refreshes target mappings, revalidates
the mapped loader against its pinned descriptor, then pins and hashes the actual
mapped companion libc. Only that event-time
`{architecture, loader SHA-256, companion-libc SHA-256}` tuple may select a
catalog candidate. Failure or absence leaves timing `unproven` and
`initial_set_capture = none`; there is no pre-exec libc resolution or generic
loader resolver.

A tuple's `initial_set = qualified_pre_constructor` remains capability only. A
particular capture is initial-set eligible only when all of these are true:

1. the target is the observer's owned, unreaped `run` child;
2. its pinned PT_INTERP loader/context and exact hook were armed before the
   parent released the pre-exec barrier;
3. the event-time context, process generation, loader mapping, and actual
   companion-libc tuple all revalidate;
4. the cookie/IP formula and every state/witness predicate required by the
   tuple passed;
5. the tuple has reviewed `initial_set = qualified_pre_constructor` product
   capability;
6. no relevant loader event, state/context read, identity transition, or
   discovery record was lost;
7. any resulting live attach window satisfies §5.7 independently.

The existing after-`sched_process_exec` attachment model does not satisfy this
predicate. An executable whose direct PT_INTERP cannot be pinned and armed, a
shebang/exec chain that cannot be bound, registry exhaustion, external
`--pid`/`--cgroup`, and any late attachment have
`initial_set_capture = none` and force `PARTIAL`. Pause success after exec does
not retroactively make pre-exec arming eligible.

### 7.5 Fallbacks and refusal

An exact-negative or unlisted tuple with usable `_dl_debug_state` continues on
the every-hit path. It may expose mappings early enough to attach standard
export hooks, but it forces `PARTIAL` for constructor timing. A later successful
export hand-out proves observation only from that hand-out forward.

Use an exact pinned libc `dlopen` return uretprobe only when the debug-state hook
is absent, unresolved, or unsafe to attach. Its timing is always `none`; it is
constructor-blind and initial-DT_NEEDED-blind, and forces `PARTIAL`. Pausing at
return repairs neither blind spot.

If neither safe hook exists, retain initial scan, manifest, or already-armed
export coverage where available and report loader strategy `unavailable`.
Unsafe identity or guessed symbol offsets are refused. Zero discovered modules
still produces the existing honest `PARTIAL` report; it never becomes a
no-findings claim.

## 8. Corrective Gate C

### 8.1 Fixture and lanes

Use one reviewed fixture source with:

- a direct `puts` relocation witness;
- a constructor-entry marker;
- a minimal standard function table and `C_GetFunctionList`;
- a constructor path that obtains the table through that export and immediately
  calls fixture `C_Initialize`;
- a distinct protected post-return path in the `dlopen` harness that calls the
  export and fixture `C_Initialize` only after `dlopen` has returned;
- a DT_NEEDED harness and a `dlopen` harness using the same DSO bytes within
  each exact userland lane.

Each exact loader/userland control gets one provenance-bound frozen bundle,
identical across its kernel runs. Run serialized product-shaped controls on
upstream 5.15 and 6.8 for:

1. the fixed-glibc candidate;
2. exact glibc 2.35 negative control;
3. exact glibc 2.39 negative control;
4. exact Alpine/musl control.

Run exactly 20 fresh DT_NEEDED primary attempts and 20 fresh `dlopen` primary
attempts for each control/kernel pair. Also run 20 fresh `dlopen_return`
fallback attempts per pair with the debug-state path deliberately unavailable;
those attempts test only the explicit post-return call. Preserve every
attempt. A lane stops promotion on its first finite failure but retains it; the
remaining predeclared safe diagnostic lanes continue unless lifecycle or host
safety fails.

### 8.2 Attempt validity and finite classifications

Evidence validity is separate from capability classification. Every attempt
must have exact source/bundle/loader/libc/fixture/interpreter/hook provenance;
the §7.3 cookie/IP formula; verifier-accepted product-shaped programs; complete
records; and zero unexpected helper, ring, stale-context, identity, privacy,
timeout, cleanup, or lifecycle errors. Explicit pause attempts also satisfy the
revised pause oracle. Any violation is operational/oracle **FAIL**, not an
`unproven` capability result. It makes Gate C fail and contributes no catalog
candidate for the affected row.

A valid primary attempt yields exactly one timing classification for its load
kind:

- `qualified_pre_constructor`: equal nonzero witness before constructor and
  every row-specific ordering predicate passed;
- `known_pre_relocation`: the predeclared qualified event was observed with a
  zero/unequal witness before constructor;
- `unproven`: the complete lane produced no conclusive qualified event;
- `none`: reserved for the `dlopen_return`/unavailable strategies, not a
  debug-state primary result.

The independent validator also classifies debug-state mapping/export protection
as `protected` only when the exact mapping was pinned, its export attached
while the causal owner was confirmed stopped, and the constructor's first
fixture `C_Initialize` was observed. A clean absence of that window is
`unproven`; an attach, marker, record, or lifecycle error is FAIL. This
classification never upgrades timing.

A stable `protected` result is a candidate for exact debug-state-triggered
mapping/export protection after final review. Stable `unproven` is a valid
conservative classification, creates no protection entry, and leaves that
best-effort product path sticky `PARTIAL`. Either result must be consistent;
operational error is never reclassified as `unproven`. This is private
qualification/catalog metadata and adds no public evidence key.

### 8.3 Predeclared control matrix and effects

The expected outcome/effect table is frozen before execution. “Classification”
means the same finite result on every attempt on both kernels; mixed attempts
or kernels are inconsistent and **FAIL**.

| Control | Load kind | Required timing result | Mapping/export result | Gate C and catalog effect |
| --- | --- | --- | --- | --- |
| Fixed-glibc candidate | `dlopen` | Mandatory `qualified_pre_constructor`: `RT_ADD`, first following `RT_CONSISTENT`, then equal witness before constructor. | Classify `protected|unproven`. | A negative/unproven timing result fails C and creates no entry. A valid positive is a candidate; mapping result is retained separately. |
| glibc 2.35 | `dlopen` | Mandatory `known_pre_relocation`: first post-`RT_ADD` `RT_CONSISTENT` witness remains zero. | Classify `protected|unproven`. | Expected negative is a valid C result with no positive entry. Any positive is negative-control FAIL and creates no entry. |
| glibc 2.39 | `dlopen` | Mandatory `known_pre_relocation`: first post-`RT_ADD` `RT_CONSISTENT` witness remains zero. | Classify `protected|unproven`. | Expected negative is a valid C result with no positive entry. Any positive is negative-control FAIL and creates no entry. |
| Alpine/musl control | `dlopen` | Mandatory `qualified_pre_constructor`: at least one post-load hit has equal witness before constructor; earlier empty hits are permitted. | Classify `protected|unproven`. | A negative/unproven result fails C and creates no entry. A valid positive is a candidate. |
| Fixed-glibc candidate | `initial_set` | Classification lane: stable `qualified_pre_constructor|known_pre_relocation|unproven`; positive also requires §7.4. | Classify `protected|unproven`. | Positive creates a candidate; stable negative/unproven is valid C with no entry; inconsistency fails C. |
| glibc 2.35 | `initial_set` | Classification lane: stable `qualified_pre_constructor|known_pre_relocation|unproven`; positive requires §7.4; no zero-at-consistent expectation. | Classify `protected|unproven`. | Positive creates a candidate; stable negative/unproven is valid C with no entry; the `dlopen` negative grants nothing; inconsistency fails C. |
| glibc 2.39 | `initial_set` | Classification lane: stable `qualified_pre_constructor|known_pre_relocation|unproven`; positive requires §7.4; no zero-at-consistent expectation. | Classify `protected|unproven`. | Positive creates a candidate; stable negative/unproven is valid C with no entry; the `dlopen` negative grants nothing; inconsistency fails C. |
| Alpine/musl control | `initial_set` | Classification lane: stable `qualified_pre_constructor|known_pre_relocation|unproven`; positive requires a pre-constructor equal hit and §7.4. | Classify `protected|unproven`. | Positive creates a candidate; stable negative/unproven is valid C with no entry; inconsistency fails C. |
| Fixed-glibc candidate | `dlopen` return fallback | Timing `none`; constructor and DT_NEEDED blind. | Observe the explicit post-return call only. | Required fallback oracle; PASS authorizes only exact post-return best effort, failure fails C, no timing entry. |
| glibc 2.35 | `dlopen` return fallback | Timing `none`; constructor and DT_NEEDED blind. | Observe the explicit post-return call only. | Required fallback oracle; PASS authorizes only exact post-return best effort, failure fails C, no timing entry. |
| glibc 2.39 | `dlopen` return fallback | Timing `none`; constructor and DT_NEEDED blind. | Observe the explicit post-return call only. | Required fallback oracle; PASS authorizes only exact post-return best effort, failure fails C, no timing entry. |
| Alpine/musl control | `dlopen` return fallback | Timing `none`; constructor and DT_NEEDED blind. | Observe the explicit post-return call only. | Required fallback oracle; PASS authorizes only exact post-return best effort, failure fails C, no timing entry. |

The zero-at-consistent negative is therefore scoped only to glibc 2.35/2.39
`dlopen`. Fixed-glibc and musl `dlopen` are the two mandatory positive controls;
failure of either makes Gate C FAIL even when the failure is a clean negative.

### 8.4 `dlopen_return` fallback oracle

The debug-state mapping/export classification above is not the
`dlopen_return` fallback. For each exact control, the forced-fallback lane must
show no constructor or DT_NEEDED coverage, then attach after the exact pinned
`dlopen` return and observe the harness's explicit post-return
`C_GetFunctionList`/fixture `C_Initialize` call. All 20 attempts on both kernels
must pass that ordering and the normal evidence/lifecycle oracle.

A passing fallback lane authorizes only exact post-return observation with
timing `none`; it creates no constructor/initial-set timing entry and always
forces product `PARTIAL`. Missing the explicit post-return call, observing an
impossible ordering, inconsistency, or any operational failure makes the
fallback lane and Gate C FAIL and leaves that exact fallback unauthorized.

Passing C produces reviewed qualification candidates and conservative fallback
results, not product entries. Only the final multi-artifact campaign and
independent production integration review may derive immutable catalog bytes.

## 9. Exact public evidence vocabulary

### 9.1 Existing deferred fields

Slice 1b-2 adds these exact fields to both profile and metrics `evidence` and
to the final trace `EVIDENCE` object. Because v2 is unpublished, no schema fork
is required, but the schema and allowlist must be updated explicitly in the
future reviewed implementation range.

| Field | Type and meaning | Canonical owner |
| --- | --- | --- |
| `attach_gap_ms` | Nonnegative number or `null`; maximum of defined per-module earliest-causal-event-to-last-required-attach gaps (§5.5). | Discovery engine, from monotonic event/attach timestamps. |
| `pause` | Exactly `none`, `sigstop`, or `partial`, derived only by §5.6. | Pause coordinator. |
| `pause_attempts` | Unsigned 64-bit count. | Pause coordinator. |
| `pause_confirmed` | Unsigned 64-bit count. | Pause coordinator. |
| `pause_partial` | Unsigned 64-bit count. | Pause coordinator. |
| `child_still_running` | Boolean, present only for `run`; true only when duration ended while the child remained alive. | Owned-child lifecycle. |
| `discovery_ring_loss` | All failed `DISCOVERY` reservations across loader, exec, and export records; forces `PARTIAL`. | BPF `COUNTERS`; renderer never derives it from received records. |
| `discovery_state_failures` | Export entry-state no-overwrite/cleanup failures; forces `PARTIAL`. | BPF `COUNTERS`. |
| `discovery_read_failures` | Export table/interface bounded user-read failures only; forces `PARTIAL`. It excludes loader-state reads. | BPF `COUNTERS`. |
| `discovery_truncated` | Source-declared truncations in successfully received records plus userspace discovery-record decode failures, including loader-registry capacity refusal or an unknown/out-of-range/stale context; forces `PARTIAL`. | One discovery-engine accumulator; each record flag, decoder result, or refused context feeds it once. |

Call-event `event_loss`, `malformed_records`, and semantic counters retain their
existing owners. Existing `attached_probes` and `attach_failures` remain owned
only by the session attachment-result accounting. No live-discovery loss is
folded into them.

### 9.2 Loader aggregate

`evidence.loader_discovery` is always present in a Slice 1b-2 profile/metrics
document. It contains no identity or correlation key:

```json
{
  "strategies": {
    "debug_state_every_hit": 0,
    "dlopen_return": 0,
    "unavailable": 0
  },
  "dlopen_timing": {
    "qualified_pre_constructor": 0,
    "known_pre_relocation": 0,
    "unproven": 0,
    "none": 0
  },
  "initial_set_timing": {
    "qualified_pre_constructor": 0,
    "known_pre_relocation": 0,
    "unproven": 0,
    "none": 0
  },
  "initial_set_capture": {
    "eligible": 0,
    "none": 0
  },
  "hits": 0,
  "state_read_failures": 0
}
```

Every value is an unsigned 64-bit count and every key is always present.
Strategy/timing/capture counts count unique internal
`{process generation, optional exact build tuple}` contexts. The tuple is
`{architecture, loader digest, libc digest}` when binding succeeds and absent
when strategy is `unavailable`; all identity is discarded before rendering.
Each context contributes exactly once to each of the three classification
groups. `hits` is the scoped BPF debug-state hit counter incremented before
ring reservation.
`state_read_failures` is the separate BPF counter for `_r_debug.r_state` reads.

The canonical owners are:

- BPF `COUNTERS`: `hits` and `state_read_failures`;
- discovery engine's deduplicated bound-context set: `strategies`,
  `dlopen_timing`, and `initial_set_timing`;
- owned-child/pre-exec coordinator: `initial_set_capture`.

There is no second public `loader_state_read_failures`, `proof_id`, loader list,
or event count derived from received records. Nonzero
`state_read_failures`, any `dlopen_return`/`unavailable` strategy, any
`known_pre_relocation`/`unproven`/`none` timing relevant to a discovered
module, or `initial_set_capture.none` forces `PARTIAL`.
`qualified_pre_constructor` and `eligible` merely remove those specific gaps;
they do not override any other completeness gate. In particular,
`pause: none` with no live window is neutral, while any unprotected live source
identified by §5.7 forces sticky `PARTIAL` without adding a public field.

### 9.3 Privacy boundary

The public vocabulary above is aggregate and finite. Profile, metrics, trace
evidence, ordinary logs, and doctor must not publish:

- raw PID/TID/task identities or task sets;
- loader/libc paths, device/inode identities, SHA-256, build IDs, symbol
  offsets, catalog proof IDs, or source commit IDs;
- `_r_debug`, table, function, interface-name, marker, or runtime addresses;
- raw pointer words, raw interface-name bytes, signal records, or per-event
  loader/stop timelines;
- object-handle correlation or symbolic `CKA_CLASS`, `CKA_KEY_TYPE`, or any new
  CKA value.

Provider module identity remains allowed only at its existing named fields.
Loader/libc qualification identity and proof metadata remain private campaign
provenance; they are not added to the allowlist. `inspect` keeps its existing
separate discovery-name behavior. Default profile/trace remains `allowlisted`;
metrics remains `aggregate-only`; unsafe metadata remains feature-plus-flag
only.

Before release, `docs/privacy/allowlist-v1.md` and
`docs/schema/observed-profile-v2.md` must be amended in the same reviewed
implementation range to list exactly the aggregate fields above and no more.
This is explicit documentation of bounded operational evidence, not implicit
capture broadening.

### 9.4 Canary obligations

The release canary gate must retain all existing sentinels and add protected
sentinels for:

- loader/libc/runtime addresses and exact raw address byte sequences;
- `_r_debug`, table, and function-pointer values;
- raw loader/interface name bytes;
- private proof/source IDs and raw task identifiers;
- packed loader attach cookies, context IDs, signed deltas, and
  process-generation values wherever they can enter an internal record; plus
  pause/loader context values in every observer-owned live map.

It scans profile JSON, metrics JSON, trace output, observer/workload logs,
private temporary output, and every map owned by the exact live observer map
IDs. The scanner proves its positive control first. Public output must contain
only the finite aggregates. The positive-control fixture injects distinctive
valid cookie/context/delta sentinels and proves they are found when deliberately
placed in a scanned output/log/map surface, then absent from the release
artifacts. Private spike bundles are separately permissioned and are not
release output. Any new public render field, discovery record,
pause map value, loader context, or catalog representation requires allowlist
review and canary update before release.

## 10. Doctor, errors, privileges, and lifecycle

### 10.1 Doctor

`doctor` retains separate scan and live lanes and adds only finite public
loader/pause classifications:

- target loader build identity: `bound|unbound`;
- debug-state hook: `available|unavailable`;
- loader timing per load kind:
  `qualified_pre_constructor|known_pre_relocation|unproven|none`;
- loader-state live read: `available|unavailable`;
- live export reads: `available|unavailable`;
- memory scan: current available or `unavailable: ptrace` result;
- run initial-set capture: `eligible|none`;
- pause: `never default`, plus whether explicit `auto`/`always` can arm.

The ordinary output does not print loader/libc identities or proof IDs. A
degraded timing value is a warning and makes complete timing unavailable; it
does not make every capture lane fatal. A requested scan or required pause lane
that is unavailable is nonzero. No BPF program remains loaded after doctor.

### 10.2 Privileges

No new privilege is authorized:

- BPF/uprobe: `CAP_BPF` + `CAP_PERFMON`, or `CAP_SYS_ADMIN` where the measured
  host requires it;
- `/proc/<pid>/maps`, executable/root path resolution, and exact object pinning:
  existing `PTRACE_MODE_READ` rules;
- `/proc/<pid>/mem` memory scan: existing `PTRACE_MODE_ATTACH`/Yama rules;
- live loader-state and export reads: bounded `bpf_probe_read_user` in the
  current task, with no `/proc/<pid>/mem` dependency;
- pause/resume: owned `run` child only, using existing same-credential signal
  authority and the original pidfd; no `CAP_KILL` grant;
- `CAP_LEASE`, root-owned staging, sysctl changes, external-target pause,
  `CAP_CHECKPOINT_RESTORE`, and `map_files` remain unnecessary or optional as
  already documented.

### 10.3 Error categories

Verifier, helper, ring loss, table/state read, context capacity/staleness,
truncation, identity, attachment, pause observation, timing arithmetic, resume,
detach, cancellation, kill/reap, provenance, validator, timeout, and
environment errors remain distinct finite diagnostic categories. They are not
collapsed into `PARTIAL` or into one generic runtime failure; only their
explicit aggregate ownership in §7.3/§9 is shared.

Discovery negatives normally produce evidence and continue safely. Unsafe
identity transitions and explicit `always` requirements that cannot be honored
refuse. A zero-module result remains `PARTIAL`. Resume/detach/reap/provenance or
host-safety failure stops the command/campaign after safe cleanup. Every
created link is detached, every owned child is resumed at most once through its
original pidfd and reaped, every private overlay/listener/NBD is quiesced, and
each material cleanup outcome is retained.

## 11. Final multi-artifact campaign and promotion

Corrective A/B/C results may be collected under §3 while Slice 1b-1 is OPEN,
but no production candidate or final campaign exists until Slice 1b-1 lands and
the owner approves and completes a separate production plan. At that later
boundary, freeze the complete multi-artifact manifest and its dependency graph.

The final campaign performs exactly the applicable gate for each artifact:

1. verify the isolated A/B spike provenance and rerun structural/two-kernel A
   plus the six-lane revised B matrix when any A/B dependency changed;
2. verify every C control bundle and rerun each affected control/load-kind/
   fallback lane on both kernels when any C dependency changed;
3. apply the §4.2 semantic initializer guard to every relevant emitter in the
   production object, then run its separately frozen complete production
   map/program/verifier/runtime oracle on 5.15 and 6.8—never the spike's
   four-map assertion;
4. validate that production tuple selection, context/cookie handling, pause
   closure, fallback behavior, catalog bytes, schema, privacy, canaries,
   provenance, caps, lifecycle, locked build, and unprivileged Rust gates match
   the exact manifest and reviewed C classifications.

Promotion requires every required node PASS, every predeclared attempt present,
all identities/digests and dependency edges matching, all historical and new
negative evidence linked, and an independent final code/evidence review PASS.
The expected glibc `dlopen` negatives are valid only under §8.3; an unexpected
positive, a lost negative, a mandatory-positive miss, a fallback-oracle miss,
or an inconsistent classification is campaign FAIL.

Only this final review may derive immutable product catalog entries from
unchanged C candidates. A post-campaign program, shared source/ABI, map, schema,
cap, timeout, validator, fixture, oracle, catalog, or privacy change invalidates
the manifest nodes that name it and requires their gates plus production
integration to rerun. No qualification artifact authorizes another artifact.

No Task 5, production plan, implementation, or final re-gate begins on this
design commit.

## 12. Acceptance criteria

This corrective design is accepted for planning only when an independent
review confirms all of the following:

- it changes only Slice 1b-2 premises and preserves Slice 1b-1 OPEN status;
- the multi-artifact manifest keeps the isolated A/B spike's exact four-map
  oracle, gives each C bundle its own inventory, and gives the future
  production object its own complete oracle plus every-emitter semantic guard;
- Gate A has the exact flat 112-store and semantic disassembly contract without
  spike ABI/map/104/16/oracle drift;
- pause omission is `never`, `auto` is explicit best effort, `always` is
  required/refusal, and only an owned `run` child can be stopped;
- reservation precedes `ARMED -> REQUESTED`/signal, the finite coalesced status
  preserves record layout, and ring loss consumes no authorization;
- one outstanding owner, the 100 ms hook-timestamp deadline, at least 1 ms
  confirmation separation, drain-to-empty/frozen attach-set closure, exact
  task-set/all-`T` oracle, original-pidfd-only resume, aggregate lattice, and
  concurrent two-hook oracle are unambiguous;
- attach gap uses the earliest causal event and last required successful attach;
- any first live-required key forces `PARTIAL` unless its exact confirmed owner
  attaches the full required set before resume; timing never substitutes;
- every debug-state hit is handled and capability selection uses only exact
  architecture/loader/libc digests;
- the exact 256-entry monotonic registry, cookie layout, IP-relative state read,
  lifecycle/counters, and event-time companion-libc binding are frozen without
  a context map, resolver, pre-exec libc lookup, or `/proc/<pid>/mem` read;
- current loader tuples are controls, not product entries, and initial-set
  eligibility requires the exact pre-exec loader hook plus event-time tuple for
  the capture;
- public evidence has one finite vocabulary, one owner per counter, no public
  timeline or loader/proof identity, and all privacy/canary obligations are
  explicit;
- Gate B is exactly three cold boots × 20 children per kernel, and Gate C has
  fixed-glibc, exact-negative glibc, and musl controls on 5.15/6.8;
- Gate C separates attempt validity from the exact control/load-kind timing,
  mapping/export, and `dlopen_return` fallback effects in §8.3–§8.4;
- gate order, dependency invalidation, exact negative retention, final
  multi-artifact re-gate, and the no-production/no-Task-5 boundary are explicit;
- no unresolved design value, adaptive threshold, rerun-until-green rule, or
  implicit privilege/privacy expansion remains.

## 13. Non-goals and rejected alternatives

The following are rejected by this corrective design:

- chunked discovery records or reassembly;
- tail calls, `PROG_ARRAY`, per-interface programs, or a fifth Gate A map;
- smaller records, changed 104-pointer/16-interface ceilings, or common ABI
  redesign;
- verifier/log cap, timeout, oracle, marker, or validator weakening;
- adaptive pause deadlines, calibration selected mid-campaign, repeated
  SIGSTOP, fresh-pidfd recovery, numeric-PID resume, external-target pause,
  cgroup freezer, or bounded busy-wait;
- separate old/fixed/musl runtime state machines;
- version, distro, package, build-ID-only, or changelog inference for loader
  capability;
- a generic ELF relocation engine, static file-relocation scan, or
  compiler-specific instruction decoding;
- a user-editable loader policy or public loader/proof catalog;
- a loader-context BPF map, pre-exec companion-libc resolver, or dependency
  graph reconstruction;
- public per-event loader, task-state, stop, or signal timelines;
- provider execution by the observer;
- object-handle correlation, symbolic `CKA_CLASS`/`CKA_KEY_TYPE`, new CKA
  values, arbitrary parameter bytes, or any other privacy expansion;
- AArch64, 32-bit, `uprobe_multi`, DaemonSet/operator, or Slice 2/3 work.

These exclusions are deliberate. The smallest acceptable path is the flat
initializer, one bounded pause coordinator, one every-hit loader runtime, one
private exact-build qualification catalog, and one final multi-artifact
re-gate.
