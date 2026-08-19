# Slice 1b-2 D3 scope amendment

**Status:** Accepted conservative implementation of the recorded owner decision
D3=`no`; independently reviewed and owner-approved for source implementation.

## 1. Scope and authority

The binding corrective design remains
`2026-08-18-slice1b2-corrective-live-discovery-design.md`, with the pause state
machine superseded by
`2026-08-19-slice1b2-no-busy-wait-pause-amendment.md`.

The approved research-plan decision D3=`no` leaves the 12-row/480-attempt
relocation-witness catalog campaign dormant and off the Slice 1b-2 product
critical path. This amendment therefore supersedes only the corrective
design's requirements to run that campaign and promote its results into a
compiled-in timing catalog. It does not supersede §9.2 completeness rules or
weaken loader/context validation, exact identity, pause closure, privacy, or
the production kernel gates.

## 2. Product strategy

Slice 1b-2 uses loader and export events as bounded attachment opportunities,
not as portable relocation-readiness claims:

1. for an owned `run` child, attach the exact pinned PT_INTERP loader's
   `_dl_debug_state` hook before releasing the pre-exec barrier when safe;
2. handle every scoped hit without gating on `r_state`;
3. refresh mappings and pin exact objects at the hit;
4. attach exact standard export hooks by pinned ELF offset;
5. when an export returns a table, resolve its bounded entries through current
   mappings and attach exact targets;
6. when the corrected pause protocol is available, close each observed
   loader/export window before its protected marker and one original-pidfd
   resume.

The compiled-in timing catalog is exactly empty. There is no package/version
inference, runtime catalog file, generic relocation engine, or guessed
companion libc. Future catalog work requires a new owner decision, design
amendment, qualification campaign, and product re-gate.

## 3. Completeness boundary

With an empty catalog, every debug-state context has timing `unproven` and
`initial_set_capture = none`. The existing §9.2 rule therefore makes the final
capture `PARTIAL`. Attach-first protection can prevent calls from escaping an
observed live window, but it cannot prove that the observed event was the first
relevant loader event or that no earlier constructor/application call occurred.

Consequently:

- no context contributes `qualified_pre_constructor`,
  `known_pre_relocation`, or `initial_set_capture.eligible`;
- successful attach-first closure removes only the corresponding observed live
  attachment gap; it never upgrades initial-set completeness;
- a later protected window cannot repair an earlier lost, ambiguous, or
  unobserved window;
- `dlopen_return` and `unavailable` remain timing `none`, constructor and
  DT_NEEDED blind, `initial_set_capture = none`, and `PARTIAL`;
- external PID/cgroup targets remain unpaused and `PARTIAL` whenever a live
  source cannot be proved protected.

This is intentionally useful but conservative: late providers can be found and
attached without a manifest, while the output states exactly what was not
proved.

## 4. Mandatory replacement gates

The dormant relocation-witness campaign is replaced by product behavior gates,
not by a new timing-eligibility oracle.

### 4.1 Corrected pause prerequisite

The independently reviewed corrected Gate A/B bundle must pass Gate A on both
Jammy 5.15 and Noble 6.8 and all six Gate B lanes. A Gate B non-PASS stops
`auto|always` and every pause-dependent product campaign as `UNRUN`. The
`pause=never` discovery path may continue as useful partial progress, but it is
not Slice 1b-2 completion and no dormant pause implementation is added.

### 4.2 Loader/context preflight

- the product-shaped every-hit loader program is verifier-accepted on both
  kernels;
- all 256 monotonic context IDs round-trip for absent-state sentinel, present
  zero delta, and signed-delta bounds;
- cookie zero and Aya no-cookie produce one `loader_context_invalid`, no
  lookup/IP/state operation, one `discovery_truncated`, and clean teardown;
- exact `bpf_get_func_ip`/x86-64 fallback, hook-vaddr/load-bias, optional
  `r_state +24` read, event-time loader/companion-libc identity, registry
  lifecycle, and privacy predicates pass;
- registry exhaustion, stale/tombstoned context, generation mismatch, identity
  mismatch, and state-read failure retain distinct finite outcomes.

### 4.3 Frozen attach-first behavior campaign

Before the first attempt, freeze and hash one source tree, product BPF object,
runner, validator, execution manifest, cold-boot topology, caps, deadlines, and
two reviewed fixture providers. Each provider is built as an initial
`DT_NEEDED` dependency and loaded later as the same bytes through `dlopen`.
Every attempt deterministically exercises all supported standard return
surfaces—`C_GetFunctionList`, `C_GetInterfaceList`, and `C_GetInterface`—with
separate predeclared constructor/application markers and an exact target set
per surface. One fixture
exports its tables; the other exposes hidden returned tables.

For each kernel, run 20 fresh owned children for every
load-kind/provider/public-pause-mode combination:

| Mode | Exported provider | Hidden-table provider |
| --- | --- | --- |
| `never` | No owner/signal; eventual exact attachment may pass, but protected-window and final completeness remain `PARTIAL`. | No owner/signal; returned tables may attach later, but protected-window and final completeness remain `PARTIAL`. |
| `auto` | Each observed loader/export window closes before its marker. A failed window must clean up safely, disable rearming, and stay sticky `PARTIAL`, but that primary campaign row is non-PASS. | Each observed loader/export window, including each returned hidden table, closes through the amended successor-owner protocol before its marker; the same safe-failure behavior is valid runtime handling but campaign non-PASS. |
| `always` | The same exact closure is required; any protection failure safely cleans up and fails the command. | The same exact successor closure is required; any protection failure safely cleans up and fails the command. |

Run the table separately for `initial_set` and `dlopen`: 240 children per
kernel, 480 primary attempts total. The public runner has no private pause-count
or timing-proof switch. Preserve every attempt; no replacement rows or
rerun-until-green. A missing ABI surface, marker, target, record, owner,
lifecycle fact, privacy fact, or classification is campaign non-PASS. Even a
fully passing campaign leaves timing `unproven`, initial-set capture `none`, and
the final profile `PARTIAL`.

### 4.4 Compatibility and fallback controls

- every-hit discovery and exact export attachment run against the retained
  glibc 2.35, glibc 2.39, glibc 2.41+, and Alpine/musl fixtures without
  package/version selection;
- historical relocation classifications may be recomputed as diagnostics but
  create no product catalog entry or completeness claim;
- forced exact pinned-libc `dlopen_return` fallback runs 20 fresh attempts on
  each kernel and proves only its explicit post-return call, timing `none`,
  initial-set capture `none`, and `PARTIAL`;
- unsafe or missing hook identity refuses that hook and retains other exact
  scan/manifest/live coverage where available.

### 4.5 Existing gates retained

- corrected isolated Gate A/B on both kernels;
- production 896-byte initializer and no-busy-wait guards;
- complete production map/program/verifier/runtime oracle on both kernels;
- provider/container/privacy/lifecycle and ordinary Rust gates;
- final multi-artifact dependency manifest, CI evidence, and independent
  review.

## 5. Evidence and privacy

The public `loader_discovery` key set remains unchanged. With an empty catalog:

- `debug_state_every_hit` contributes timing `unproven`;
- `qualified_pre_constructor`, `known_pre_relocation`, and
  `initial_set_capture.eligible` remain zero;
- observed attach-first results affect only the existing live-gap, pause, loss,
  and completeness aggregates;
- no public field reveals loader/libc identity, version, package, digest, build
  ID, address, cookie, context, delta, marker, raw signal record, or per-event
  timeline;
- no new loader/pause PID or TID disclosure is added; the existing separately
  allowlisted trace PID/TID contract is unchanged;
- every existing completeness loss retains its force.

Schema, allowlist, checker, and canaries must reject any attempt to infer
eligibility or complete status from attach-first success or a timing category.

## 6. Invalidation and future work

Any product loader/pause BPF, common ABI, runner, fixture, validator, deadline,
cap, oracle, schema, privacy, or attach-first predicate change reruns the
affected product controls. Any isolated A/B dependency change reruns its own
Gate A/B node.

The dormant catalog campaign is not deleted. If reactivated, it remains a
separate artifact with a separate map/program/record/cap/validator identity and
cannot retrospectively upgrade a prior capture.

## 7. Acceptance criteria

This amendment is accepted when independent review confirms:

- it implements D3=`no` without inventing a replacement timing proof;
- the catalog is exactly empty and no version/package heuristic exists;
- every-hit discovery and exact attach-first behavior remain mandatory;
- unproven timing and initial-set capture `none` keep final evidence `PARTIAL`;
- corrected Gate B is a hard prerequisite for pause implementation and its
  product campaign;
- the frozen 480-primary-plus-40-fallback campaign covers both load kinds, both
  provider shapes, all three supported return ABIs, all public pause modes, and
  both kernels without replacement rows;
- public vocabulary/privacy stay bounded; and
- CI plus final multi-artifact/provider/kernel reviews remain mandatory before
  Slice 1b-2 completion.
