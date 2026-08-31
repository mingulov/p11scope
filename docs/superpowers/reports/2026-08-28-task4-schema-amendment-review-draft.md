# Task 4 Facts and Retained-Artifact Amendment Review Draft

**Status:** rejected review draft; retained as a decision record. Do not
implement shell receipts from this document. Independent Sol, Terra, and Luna
reviews agreed that it removes required provenance, lacks exact resource
witness tables and compound grammars, and retains too little raw Lane 14
evidence to replay the privacy oracle. The fixed-path/immutable-identity/no-glob
principles remain candidates for the replacement amendment.

## Decision being reviewed

The receipt plan fixes lifecycle order and facts keys but does not fix most
compound value grammars or retained artifact paths. Current scripts also use a
first-matching `*observed*.json` selection in several lanes. That cannot prove
the approved multi-capture lane cardinalities. The acceptance oracle therefore
must not infer authority from current output names.

Adopt one explicit retained-artifact table. Keep raw oracle input once, keep
build/runtime work disposable, and record input/tool/resource identities in
bounded lane facts. Do not broaden `docs/privacy/allowlist-v1.md`.

## Common artifact grammar

`facts.log`, `stdout.log`, `stderr.log`, and `status` are common receipt files
and are outside `artifact.count`. Every indexed artifact is a caller-owned
regular file below `artifacts/`, mode 0600, `nlink=1`. No extra entry, symlink,
device, socket, glob selection, directory-order selection, or captured-stdout
substitution is valid.

Artifact indices enumerate the lane table in order. Both values use:

```text
path=REL;type=regular;mode=0600;uid=U;gid=G;dev=D;ino=I;nlink=1;size=S;sha256=H
```

`artifact.NNN.creation` is recorded after the producer closes and synchronizes
the object but before a checker consumes it. `artifact.NNN.final` is recorded
by the finalizer. They must be byte-equal. `REL` is the table literal;
`U,G,D,I,S` are canonical unsigned decimals and `H` is 64 lowercase hex.
Compound atoms permit `[A-Za-z0-9._/@:+-]`; other bytes, including `%`, `;`,
`=`, comma, tab, and newline, use uppercase `%HH`. Lane fields reference an
artifact only as `artifact=NNN` or a documented fixed-order `+` list.

## Exact retained artifact table

| Lane | Indices | Paths in index order | `artifact.count` |
|---|---:|---|---:|
| 07 | 000-023 | For `freeze,g1,g2,g3,g4,g5`: `CASE.capture.json`, `CASE.manifest.json`, `CASE.checker.log`, `CASE.exit` | 40 |
| 07 | 024-039 | For `config,pid-filter,cgroup-filter,descriptors,async-functions,mech-shape,attr-bool-bits,template-tail`: `map-NAME.before.json`, `map-NAME.after.json` | 40 |
| 09 | 000-005 | For `broad,a-only,b-only`: `CASE.capture.json`, `CASE.checker.log` | 6 |
| 10 | 000 | `fork.capture.json` | 13 |
| 10 | 001-012 | For `bpf-perfmon,sysadmin,sysadmin-scan,sysadmin-ptrace`: `cap-NAME.row.json`, `cap-NAME.log`, `cap-NAME.document.json` | 13 |
| 11 | 000-005 | `report.jsonl`, `results.json`, `capture.json`, `subset.json`, `sibling.start.tsv`, `sibling.end.tsv` | 6 |
| 14 | 000-003 | `dist/p11scope`, `dist/p11scope-discover`, `dist/p11scope-discover-glibc`, `dist/p11scope-discover-musl` | 21 |
| 14 | 004 | `discover.facts` | 21 |
| 14 | 005-014 | `canary-default-safe-profile.json`, `canary-default-safe-trace.json`, `canary-feature-safe-profile.json`, `canary-feature-safe-trace.json`, `canary-feature-unsafe-profile.json`, `canary-feature-unsafe-trace.json`, `canary-aggregate-only-metrics.json`, `canary-default-safe-start.json`, `canary-feature-safe-start.json`, `canary-feature-unsafe-fault.json` | 21 |
| 14 | 015-020 | `smoke-glibc-container.json`, `smoke-musl-container.json`, `smoke-host-glibc.json`, `smoke-packaged-helper.json`, `smoke-attach-e2e.json`, `smoke-static-attach.json` | 21 |
| 16 | 000-003 | `observed.json`, `checker.log`, `source.start.tsv`, `source.end.tsv` | 4 |

Lane 14 distribution copies remain mode 0600 and are never executed from the
receipt. All executable build IDs and linkage results remain bounded facts.

## Fixed counts and resource authority

| Lane | `source.exception_count` | `resource.count` | `artifact.count` |
|---|---:|---:|---:|
| 07 | 0 | 6 | 40 |
| 09 | 0 | 3 | 6 |
| 10 | 0 | 6 | 13 |
| 11 | 0 | 5 | 6 |
| 14 | 0 | 8 | 21 |
| 16 | 0 | 2 | 4 |

The unrelated untracked OpenSSL report remains visible in the equal start/end
untracked source ledger but is not consumed and is not an exception.

Remove generic `tool.count`, `input.count`, and `build_env.count` plus their
indexed families. They duplicate the already mandatory clean source/tree,
receipt clean-environment proof, and exact lane fields for consumed provider,
toolchain, configuration, checker, executable, and external inputs. Reviewers
must reject this simplification if any consumed identity would become
unrepresented.

Main owners append and synchronize `resource.NNN.requested` before creation,
`resolved` before activation, `cleanup` before an absence query, and
`absence=true` only after an identity-bound absence proof. Lanes 07, 09, 10,
11, and 16 use main facts. Lane 14 main facts own three images, three
containers, the nested-child generation, and facts-creator generation. Its
existing bounded write-ahead journal is imported into `discover.facts` for
nested resources. Post-hoc checker output is never cleanup authority.

If a canary, attach, or static helper owns an independently cleaned resource,
its retained evidence must contain the same bounded write-ahead lifecycle
before activation; otherwise Lane 14 is non-pass.

## Lane value rules

- Lane 07 case order is `freeze,g1,g2,g3,g4,g5`; its capture, manifest,
  checker, exit, map-before, and map-after values reference the matching
  artifact indices. Freeze uses the eight map names above. Oracle values retain
  the approved G1 `160/93/186`, G2 `68/2/4`, G3 `68/68/136`, and G4/G5
  `988/104/208` predicates and their existing exact counters.
- Lane 09 order is `broad,a-only,b-only`. Capture/checker values reference the
  paired artifacts. Oracle is `workloads=2;uncertainty=1` for broad and
  `workloads=1;uncertainty=0` for both leaves.
- Lane 10 capability order is
  `bpf-perfmon,sysadmin,sysadmin-scan,sysadmin-ptrace`. Each row references its
  row/log/document artifacts and records literal capability argv, canonical
  exit, and the approved scan relationship.
- Lane 11 report order is `report.jsonl,results.json`; private order is
  `state,policy,derived-cache`; sibling start/end values reference artifacts
  004/005. All three private objects and both sibling defaults are absent at
  finalization.
- Lane 14 distribution, canary, and smoke orders are exactly the artifact
  table. `artifacts`, `input`, and `output` values are fixed artifact
  references, not path lists.
- Lane 16 references artifacts 000-003 and records the complete predicate in
  the existing plan: 68/68/136, one sanitized discovery-unavailable timing,
  zero loss/ambiguity/in-flight, child false, exact cleanup/absence, and the
  mode-specific pause tuple. Timing and function-call totals remain
  non-authoritative.

Booleans are `true|false`; lists use fixed-order `artifact=NNN+NNN...`.
Every remaining compound value has documented `name=value` order before the
schema can be accepted; this draft does not authorize an unspecified order.

## Facts order and terminal delta

Facts order is: schema; receipt/time/host/source/root/directory/lock fields;
common counts; common indexed groups; lane counts; lane groups; `body.result`;
`signal.result`; and `terminal_status_intent` last.

From `publisher-isolated` to reap, the only tree changes are one exact append:

```text
facts-v1<TAB>N<TAB>terminal_status_intent<TAB>CODE<LF>
```

and the planned status operation: N97 retains no status; I97 retains its exact
invalid inode/content; R97 writes `97\n`; INT/HUP/TERM write `130\n`, `129\n`,
`143\n`; S0 writes `0\n`. All other bytes, identities, types, modes, owners,
links, sizes, and paths remain unchanged; `work/status.pending` is absent.

The accepted amendment must replace the schema marker contents and recompute
SHA-256 over the exact bytes between marker lines. Rust and drivers must derive
that digest from the clean, input-bound plan rather than maintain a second
manually copied constant.

## Required review decisions

1. Does removing generic tool/input/build-environment families preserve every
   consumed identity, or must exact per-lane tables be retained instead?
2. Are resource counts and compound lifecycle rows independently sufficient,
   especially for Lane 14 nested helpers?
3. Is each retained artifact the minimum raw set needed to replay the lane
   oracle, with no privacy expansion or missing raw input?
4. Which remaining compound lane values still need literal field-order tables?
