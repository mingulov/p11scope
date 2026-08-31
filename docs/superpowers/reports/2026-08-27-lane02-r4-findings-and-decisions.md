# Lane 02 r4 findings and decisions

Date: 2026-08-27

Evidence root:
`/home/user/.local/state/p11scope/lane02-20260827-uSLuN4/evidence`

Tree under test: commit `0627c6ad8e791d340963b05e2bf61430b8a6d067`.

## Result

The fresh six-row lane is `NON-PASS`.

| Row | Result | First failed predicate |
| --- | --- | --- |
| initial-set / never | PASS | none |
| initial-set / auto | FAIL | loader strategy count 3, expected 2; independently pause `partial 1/0/1` |
| initial-set / always | FAIL | loader strategy count 3, expected 2 |
| dlopen / never | PASS | none |
| dlopen / auto | FAIL | pause `partial 1/0/1`, expected confirmed `sigstop` |
| dlopen / always | FAIL | missing bootstrap `C_GetFunctionList=1` |

All rows ended without child residue. Every row reached 68 slots and 136/136
probes in its final document. The checker and the frozen Lane 02 oracle remain
unchanged.

## Decision 1: loader aggregate identity

`LoaderContextId` is an allocation/cookie lifecycle identity and must not be
used as the stable public-classification identity. Replacement attachments for
the same opened loader tuple caused the strategy count of 3.

The private historical aggregate key is:

- `Unbound` when no loader context attached;
- `Bound(PinnedTimingKey)` when stable replacement deduplication is proven;
- `BoundUnkeyed(LoaderContextId)` when attachment is real but stable deduplication
  is not provable.

`BoundUnkeyed` remains a truthful debug-state attachment, is conservatively
unique, and records one bounded privacy-safe PARTIAL loss. No internal key is
rendered. Initial-set and ordinary load kinds remain separate. Sol, Terra, and
Luna agreed on this behavior after reviewing both production call paths.

Rejected:

- widening the Lane 02 strategy oracle from 2 to 3;
- collapsing an attached unkeyed context into the unbound bucket;
- making the missing aggregate key fatal before the pause coordinator exists.

## Decision 2: protected bootstrap attachment

Row 06 proves that confirmed stop/resume cycles alone do not guarantee the
first `C_GetFunctionList` call was observable. Discovery entry/return uprobes do
not update the normal function metrics.

During the confirmed owned loader pause, before pidfd resume, the existing
exact pinned export resolution must seed a normal count-only plan slot for the
exact executable `C_GetFunctionList` offset and attach its normal metrics return
then entry pair. Later function-table discovery must merge the same
`{object, offset, canonical name}` into that slot without a duplicate link,
aggregate cell, or false table-authority claim.

The seed stays inside the existing candidate/preflight/attachment transaction,
single ring owner, frozen policy maps, retained process generation, and normal
static-link retirement. Seed failure makes required work incomplete: `auto`
becomes sticky partial; `always` cleans up and refuses.

Rejected:

- removing the bootstrap count from the checker;
- waiting for the bootstrap return to attach the first metrics probes;
- treating discovery uprobes as metrics probes;
- resolving from the CLI module path rather than the exact mapped pinned object;
- adding another ring, reader, public identity, or runtime option.

## Marker and evidence boundary

`marker_never_seen()` is fixed false and cannot prove a protected application
marker did not race attachment. It must not support a strong first-call claim.
For Lane 02, the honest claim is limited to exact attachment completion before
the retained pidfd resume, proven by private fixture ordering and positive exact
counts. A generic arbitrary-marker guarantee requires a real private marker
probe later.

Row 05's exact auto-failure branch is absent from retained evidence because its
internal message is discarded. A diagnostic experiment may retain only a
finite category such as authorization, task-state, queue, attach, marker,
resume, or lifecycle. It must not add PID/TID, path, digest, cookie, address,
timestamp, marker identity, or any new capture JSON field.

## Required gates before another full Lane 02 run

1. TDD and independent review for the stable aggregate key.
2. TDD for a pre-resume count-only bootstrap slot, return-before-entry rollback,
   exact later-table merge, generation separation, and auto/always failure policy.
3. A/B fixture evidence: immediate bootstrap call versus a privately gated late
   call; current code must distinguish the gap and seeded code must count both.
4. Privacy-canary scan of every experiment artifact and map projection.
5. Canonical format, check, all-target tests, and clippy.
6. One fresh six-row privileged run in a new evidence root. No frozen r4 row may
   be amended or reused as a pass.

Lane 02, r3 freeze, and 9.2d remain locked until these gates pass.

## Pause-epoch diagnostic campaign

The reviewed production diagnostic is commit
`d30fa4451505157bb99283429d4ad02f70c452d2` with the unchanged 100 ms epoch.
The diagnostic-only descendant is commit
`8bf158385643345b2c087ed6dcb2608298b11e42` with exactly one changed line:
`CYCLE_NS` is 500 ms. The descendant
must not be merged or used as a product-policy change.

The predeclared counterbalanced order is fixed before execution:

| Pair | First | Second |
| --- | --- | --- |
| 1 | `pair1-a100` | `pair1-b500` |
| 2 | `pair2-b500` | `pair2-a100` |
| 3 | `pair3-a100` | `pair3-b500` |
| 4 | `pair4-b500` | `pair4-a100` |

Every name is rooted below
`/home/user/.local/state/p11scope/lane02-pause-ab-20260827/`. Each root must be
absent before its campaign, and the unedited Lane 02 driver owns the build,
fixture, hashes, six-row execution, cleanup, and evidence finalization.

The 500 ms source variant compiles. Its focused pause suite has 114 passes and
four expected failures because those fixtures intentionally contain absolute
100 ms timestamps. The fixtures are not changed: keeping the A/B source diff
to exactly one constant is the stronger control.

### Completed result

All eight roots finalized six invocations. A live check after the campaign
found no matching `p11scope`, `harness`, or `harness-initial` process, but the
roots do not retain a per-run terminal process-list receipt. The module,
driver, checker, and both harness hashes are identical across all roots. The
per-root configuration hash differs because the private token directory
contains the absolute evidence-root path; replacing only the run-name segment
in every configuration produces the same normalized SHA-256
`ced248787c565377250523c84ee2db041597a86729847d7552b3eb5ff9248f56`.

| Pair | 100 ms result | 100 ms diagnostic | 500 ms result |
| --- | --- | --- | --- |
| 1 | rows 05 and 06 FAIL | both `deadline_during_engine_apply` | all six PASS |
| 2 | rows 05 and 06 FAIL | row 05 `deadline_during_engine_apply`; row 06 `nested_collector_deadline` | all six PASS |
| 3 | all six PASS | none | all six PASS |
| 4 | rows 03 and 06 FAIL | both `deadline_during_engine_apply` | all six PASS |

The four 100 ms roots use binary SHA-256
`1d6d54dba26f430efaa71d1c7b471d8c05cd3b57cac42cf1a5851f2a2ca351c0`.
The four 500 ms roots use binary SHA-256
`f2048d03024ddf0494ec0bd7c188941527cb1be90695127f949b69292445f87c`.

Every 500 ms direct Auto row has 68 slots, 136 attached probes, an exact
`C_GetFunctionList` count of one, `pause_confirmed == pause_attempts`, and
`pause_partial == 0`. The failed 100 ms direct Auto rows still reach 68 slots
and 136 probes but publish `pause=partial`, `1/0/1`, and the bounded apply
deadline diagnostic. Initial-set rows remain empty-catalog controls.

This is a mixed-variance result under the predeclared decision rule: 500 ms was
stable in four of four campaigns, but 100 ms was not consistently failing and
its per-row/category pattern varied. The sole source change and repeated B
passes strongly support an epoch-associated effect and do not support an
invariant fixture failure under these campaign conditions. They do not isolate
one reproducible latency source or rule out every non-timeout confounder.

Independent Sol, Terra, and Luna review therefore rejected timeout promotion,
deadline-anchor changes, Engine checkpoint work, and gate amendment from this
evidence. The diagnostic B worktree and branch were removed after review; its
unmerged commit remains recoverable by the recorded hash only.

The subsequent diagnostic reused the existing private
`before_ns`, `after_ns`, and deadline observations to classify two finite
facts separately: budget remaining at Engine entry and Engine elapsed-time
band. It changed no deadline, Engine API, cleanup, attachment behavior, public
JSON, checker, or privacy contract. The predeclared matched 100 ms campaigns
then tested whether the classifier distinguished pre-Engine budget consumption
from long synchronous Engine work; the closure below records their result.

## Pause-phase campaign closure

The diagnostic above was implemented at unmerged commit
`9c40c5065bd5405eaea0dc6ef32c6ea395426e66`, tree
`aba30fb1d38113ffee0b15d7c42a985c2b332de6`. Its commit changes exactly the
Lane 02 driver, pause classifier, and artifact contracts. Its parent contained
an independently required Lane 13 work-parent repair; that repair alone landed
on the product branch as `da5005e`.

The four finalized roots are `rep1-d100` through `rep4-d100` below
`/home/user/.local/state/p11scope/lane02-pause-phase-20260827/`.

| Root | Terminal | Target `05-dlopen-auto` | Retained target diagnostic |
| --- | --- | --- | --- |
| rep1 | non-pass | PASS | none |
| rep2 | PASS | PASS | none |
| rep3 | non-pass | FAIL | `later_pause_boundary` |
| rep4 | non-pass | PASS | none |

### Confirmed

- Every root is fresh, caller-owned mode 0700, and contains six invocation
  receipts in the frozen order.
- All 24 row cleanup pairs record zero exact evidence processes and complete
  cleanup; every root also has a final zero exact-process receipt.
- Commit/tree, module, observer binary, driver, checker, both harnesses, oracle,
  interpreter, libc, and build-tool identities match across all roots.
- Raw configuration hashes differ because their absolute roots differ. The
  byte-normalized semantic hash is identical:
  `32f08cfe20f627e54117fdc1b6eb927ea637e3bef6119d983ff4fe0e5f0b5e48`.

### Contradicted

The frozen rule is contradicted by three target PASS results, one target FAIL,
and the FAIL's non-selecting fallback token. No four-of-four phase category
exists. Configuration divergence, missing cleanup receipts, and process
residue are confirmed non-causes.

### Missing

No retained receipt hashes the exact diagnostic diff. The cumulative ancestry
from `d30fa44` also includes this report and the separate Lane 13 script repair,
so it does not satisfy the planned cumulative changed-path set even though the
exact diagnostic commit itself is the reviewed three-file change. Roots are
mutable and unsealed, as predeclared. Raw timing is intentionally absent.

### Decision

The campaign is **mixed/unresolved**. It selects no timeout, deadline-anchor,
Engine, collector, or other product change, and it authorizes no replacement
or repeat run. The earlier proposed phase diagnostic is now closed rather than
an approved next action. Any further investigation requires a new reviewed
plan and fresh roots. Sol, Terra, and Luna independently agreed on this
conservative decision.
