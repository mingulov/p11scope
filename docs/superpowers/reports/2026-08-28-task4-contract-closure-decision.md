# Task 4 Contract Closure Decision

**Status:** accepted after independent Sol, Terra, and Luna review; this amends
commit `5fdc7cb` planning authority without claiming executable contracts.

## Problem

The committed plan requires six executable contracts before their fixed
artifacts and replay/privacy checker interfaces exist. Current lane drivers use
inline live-only predicates, first-match capture selection, and fleeting Lane
14 surfaces. A complete JSON file today would invent authority.

Contract closure has three distinct gates:

1. **inventory-complete:** reviewed fixed inputs, resources, checker roles,
   privacy surfaces, paths, bounds, and cardinalities;
2. **interface-complete:** every referenced checker/scanner CLI exists and its
   mutation self-tests pass;
3. **executable:** every referenced byte exists at a committed identity and the
   envelope validates and replays it.

Only inventory completion can precede checker implementation.

## Decision

Store blueprints only beneath `docs/superpowers/contracts/task4/` with schema
`p11scope-task4-contract-blueprint-v1`. The helper rejects that schema
unconditionally with exit 77 before root creation. A blueprint has the exact
runtime-contract keys plus `unresolved_interfaces`; `schema` is the blueprint
literal and `requested_mode` is already present. Every other field uses the
runtime type, bound, uniqueness, reference, and canonical-order rules.

`unresolved_interfaces` contains 0..3 records per blueprint, sorted by `label`,
with exactly
these fields:

```text
bindings, executable, kind, label, locator, self_test
```

`kind` is `lane-checker|privacy-scanner|envelope-helper`; `label` names exactly
one declared tracked input of kind `checker|helper` as applicable; `locator`
exactly equals that input's repository-relative locator; and `executable` names
the interpreter/direct input for the exact rootless `self_test` argv.
`self_test` contains 1..512 canonical `literal|input` `ArgToken` objects. It
uses the interface in exactly one form: `executable==label` with no matching
input token, or a different executable with exactly one matching input token.

`bindings` has 1..4096 records for checker/scanner kinds and is empty for the
helper. Each binding has exactly `argv,checker,executable,role`, is sorted by
`checker`, and byte-for-byte repeats one `CheckerDecl` label, executable, argv,
and `domain|privacy` role. Every checker reference to this interface must be
exactly one of: executable equals the interface label with zero matching input
tokens, or executable differs and argv contains exactly one matching input
token. Mixed executable+argv use and repeated tokens are schema errors. The
binding set is exactly every checker declaration with either form. Bindings are
unique within one interface record; one CheckerDecl may appear once in each of
multiple interface records when its argv legitimately names each interface
exactly once. This permits one retained scanner/interpreter to serve all explicit
`json|trace|map-json|bytes|workload-log|checker-log` invocations without a
wrapper, and lets the Lane 14 domain checker explicitly consume both its own
script and the scanner. No interface label or locator may appear in two
interface records. The union is the only forward-reference allowlist.

Discharge resolves the tracked locator at the candidate promotion commit,
verifies its declared input metadata and exact bytes, expands every binding and
self-test argv under the normal token rules, and requires `self_test` to exit zero without a
privileged/container/network/Cargo/lane-body command. An existing pathname
does not discharge a missing CLI or failing self-test. Promotion is a separate
reviewed commit that removes `unresolved_interfaces`, changes only `schema` to
`p11scope-task4-contract-v1`, and otherwise preserves every canonical value
byte-for-byte. The envelope helper has no checker binding and must discharge
before any runtime manifest promotes.

Do not add a generic replay adapter. Preserve the accepted narrow adapter
exception if an independently reviewed lane later proves it necessary, but the
selected design uses explicit-path lane-owned checkers:

- `scripts/check-task4-lane07.py` owns the extracted G1/G2, live-map advance,
  and freeze-composition predicates and invokes existing capture/map checkers;
- `scripts/check-task4-lane09.py` owns shared-overlay and three-capture
  composition and invokes the existing shared-layer metrics mode;
- `scripts/check-task4-lane10.py` owns fork/capability composition;
- `scripts/check-task4-lane11.py` owns report/capture/subset composition;
- `scripts/check-task4-lane14.py` owns the exact release/distribution/canary/
  attach/discover composition predicate inventory: exact four-binary
  distribution names and hashes, static `p11scope`, byte-identical glibc helper
  names, dynamic musl-helper policy, unsafe-flag rejection, canary G1–G5/freeze,
  attach scan/dynamic rows, discover manifests/images, smoke results, and exact
  raw-to-derived surface equality. It also consumes the retained positive-
  control artifact and shared scanner input, invokes `map-json`, requires exact
  return code 1 with bounded diagnostics, and only then returns its ordinary
  domain-checker zero;
- `scripts/check-task4-lane16.py` owns the fixed structural mode predicate;
- `scripts/check-privacy-surfaces.py` is the only shared privacy scanner;
- existing `check-capture-evidence.py`, `check-bpf-map-defs.py`, and
  `scripts/fixtures/discover-manifest.jq` retain their current semantic scope.

Every lane checker supports `--self-test` and explicit retained paths only.
Before an inline predicate is removed, mutation-equivalence tests name the old
symbol and its sole new lane-checker owner.

The privacy scanner CLI is exact:

```text
check-privacy-surfaces.py --self-test
check-privacy-surfaces.py json PATH...
check-privacy-surfaces.py trace --exclude trace-pid-tid-positions PATH...
check-privacy-surfaces.py map-json PATH...
check-privacy-surfaces.py bytes PATH...
check-privacy-surfaces.py workload-log PATH...
check-privacy-surfaces.py checker-log PATH
```

Paths are explicit positional files; no directory or glob is accepted. Normal
modes exit 0 clean, 1 only when a well-formed input contains a forbidden value,
2 on usage, and 3 on malformed input, I/O failure, or bound violation; stdout
is empty and bounded diagnostics use stderr. `checker-log` accepts exactly one
path and is silent. Every invocation runs its mode-specific planted positive control.
`map-json` accepts only the frozen dump schema, reconstructs encoded bytes, and
scans both source bytes and reconstructed bytes; unknown encodings fail. The
frozen schema is duplicate-free JSON of depth at most 6 with either (a) a
top-level array whose every entry has exactly `{key,value}` or `{key,values}` or
(b) the exact positive-control object `{"value":[BYTE...]}`. `key` and scalar
`value` are nonempty byte arrays containing only exact lowercase
`0x[0-9a-f]{2}` tokens. `values` is a nonempty list of objects with exactly
`cpu,value`; CPU is a unique, strictly increasing integer in 0..1048575 and its
`value` is a nonempty byte array. Unknown/missing entry members and all other
shapes fail; an empty top-level array remains valid for an empty map. Decoded
arrays are concatenated in document order for scanning. Duplicate JSON keys,
floats, invalid source UTF-8, depth/bound overflow fail; reconstructed bytes are
arbitrary bytes and receive no UTF-8 constraint. The retained positive control invokes
ordinary `map-json` and must return leak code 1 before clean claims are accepted;
it is not a privacy surface and introduces no scanner mode.

The helper remains custody-only: `scripts/task4-receipt.py` interprets none of
these lane predicates.

## Contract count

Use seven executable manifests for six lanes:

```text
scripts/task4-contracts/lane07.json
scripts/task4-contracts/lane09.json
scripts/task4-contracts/lane10.json
scripts/task4-contracts/lane11.json
scripts/task4-contracts/lane14.json
scripts/task4-contracts/lane16-never.json
scripts/task4-contracts/lane16-auto.json
```

Both Lane 16 files retain `"lane":"16"` and have the required top-level field
`"requested_mode":"never"|"auto"`; other lanes require the field with JSON
null. `receipt.json` has the same required top-level field. For Lane 16 the
driver's sole mode token and the lane checker's sole mode literal must equal the
contract and receipt value; other lanes have no mode token. The helper rejects
any contract, receipt, driver argv, checker argv, or mode mismatch. This is a
narrow gate-only schema amendment, not filename authority.

## Fixed retained-path families

- Lane 07: `artifacts/freeze/` plus `artifacts/g1/` through `g5/`, each with
  literal observed JSON/log, inventories, and one path per retained map dump.
- Lane 09: `artifacts/broad/`, `a-only/`, and `b-only/`, each with literal
  observed JSON/log, plus Docker/provider identity records.
- Lane 10: `artifacts/fork/`, `artifacts/capabilities/rows.json`, and four
  literal document/log pairs; zero-byte documents remain declared artifacts.
- Lane 11: `artifacts/oracle/` report/results/subset, observed capture, sibling
  ledgers, and state/policy/cache snapshots.
- Lane 14: use the separately reviewed literal canary/privacy subset crosswalk
  [`2026-08-28-lane14-canary-surface-crosswalk.md`](2026-08-28-lane14-canary-surface-crosswalk.md).
  Its 194 rows do not replace the separately literal distribution, attach,
  protocol, release, or smoke blueprint rows. Every crosswalk row binds label,
  full `artifacts/...` path, producer,
  resource identity, scanner mode, exclusion, and allowlist obligation. Its
  exact lowercase-and-slash-to-dot normalization binds each planning token to a
  legal runtime resource label; live maps including `START` bind the resulting
  exact BPF-map identities. Row 194 has privacy `none`, names the Lane 14 domain
  checker in `checker_roles`, and is passed with the scanner input to that
  checker. The domain checker accepts only scanner code 1; code 0 (sentinel
  absent), 2, 3, signal, timeout, or any other result is non-pass. It is never a
  direct privacy-checker invocation. Currently
  deleted smoke/map files become produced runtime artifacts, never tracked-file
  forward references. A count alone cannot authorize the set.
- Lane 16: one literal `artifacts/observed.json` per root plus fixed
  observer/workload records. The checker log remains the common envelope log.

No contract uses a glob, basename, path-order selection, stdout substitution,
or a derived summary in place of raw evidence.

## Blueprint completeness

Each blueprint contains complete closed arrays for inputs, environment,
resources, artifacts, checker roles, privacy surfaces, and exact bounds; only
the declared interface records may be unresolved. No placeholder string, schema
maximum used as an unevidenced artifact bound, or inferred resource count is
accepted.

Resource arrays name every owner-visible generation: observer/workload/helper
processes and process groups, units/cgroups, token stores, BPF links and every
owned map, plus Lane 09 images/containers, Lane 10 FIFO/capability targets, Lane
11 private state/policy/cache objects, and Lane 14 images/containers/build and
smoke processes. Each label fixes class and identity scheme. Lane 14 crosswalk
map rows reference the corresponding exact BPF-map label.

Input closure names every consumed tracked byte and resolved external tool,
interpreter, configuration, provider, dynamic dependency, Docker image digest,
`jq` program, LLVM/file utility, and magic database as applicable. Replay tools
are retained inputs; collection-only external inputs remain descriptor-pinned.
Promotion review proves the exact transitive set rather than trusting `PATH` or
a version string.

## Revised gate order

1. Amend and independently review the governing plan.
2. Write and review seven inventory-complete, non-executable blueprint-schema
   files plus the Lane 14 crosswalk. Only their exact interface records may be
   unresolved.
3. The sole `tests/artifact_contracts.rs` writer adds rootless RED rows and
   blueprint-schema rejection tests. Focused command:
   `cargo +1.88 test --locked --test artifact_contracts task4_contract_ -- --nocapture`.
4. Sequential stopped writers implement privacy, then lane 07, 09, 10, 11, 14,
   and 16 checkers. Each owns only its named file and embedded `--self-test`;
   run the exact script self-test and corresponding Rust row from
   `task4_contract_privacy`, `task4_contract_lane07`,
   `task4_contract_lane09`, `task4_contract_lane10`,
   `task4_contract_lane11`, `task4_contract_lane14`, and
   `task4_contract_lane16`, then Sol/Terra/Luna review.
5. The sole `tests/artifact_contracts.rs` owner adds the envelope core RED,
   stops, and receives review; then the sole `scripts/task4-receipt.py` owner
   implements the helper, runs focused GREEN including blueprint exit 77,
   stops, and receives review.
6. Re-review blueprints against exact checker and helper bytes, require zero
   unresolved records, and promote the seven runtime manifests with no other
   value change.
7. Migrate drivers serially under separate sole ownership: Lane 07, 09, 10,
   11, all Lane 14 scripts as one group, and Lane 16 (`never` then `auto`). Each
   cycle is lane RED, minimal implementation, focused GREEN, writer stop, and
   independent review. Ownership returns to the primary before any stopped
   writer's file is touched again.
8. Preserve frozen Lane 02 compatibility, untouched Lane 13 history, and the
   downstream fresh-r3, 9.2d, 9.3, 9.4, exact-tip CI, and Task 10 order.

The initial RED is the focused Cargo command failing only on the seven absent
checker/scanner interfaces; static blueprint key/reference checks are already
GREEN. Each writer runs its exact named script with `--self-test`, then the
fixed Cargo prefix `cargo +1.88 test --locked --test artifact_contracts`
followed by its one full test name listed above and `-- --nocapture`.
Only one Cargo-heavy command runs at a time. The full `task4_contract_` filter is
GREEN only after the Lane 16 checker stops and passes review.

## Decisive tests

- Blueprint schema always exits 77 in helper/runtime validation. Interface
  discharge requires exact locator bytes, complete checker bindings, and named
  self-test success; promotion requires zero unresolved records, including the
  helper record.
- Contract A+B with a zero checker consuming only A is non-pass.
- Each new capture-checker mode rejects a mutation of every extracted inline
  predicate.
- Each privacy mode catches a planted leak; trace rejects any exclusion beyond
  the exact two PID/TID positions.
- Lane 14 control translation rejects a sentinel-free well-formed control
  (scanner 0), malformed control (scanner 3), usage 2, signal/timeout, or any
  result other than exactly 1; missing scanner/control consumption is rejected
  by checker-role and interface-binding equality.
- Lane 14 exact-set review rejects missing, duplicate, relabelled, deleted, or
  wrong-scanner surfaces; a count alone is never proof.
- Lane 16 mode/contract mismatch is non-pass.
- Every real driver row remains RED until it registers its exact fixed artifact
  and resource sets.

## Boundaries

This changes gate sequencing, manifest count, the gate-only `requested_mode`
schema, and only the named gate-checker/helper interfaces. It changes no product
Rust/BPF, public schema, privacy allowlist, lane oracle meaning, Lane 02/13
disposition, runtime authorization, or downstream order. Contracts are never
called valid or executable while a forward reference remains.
