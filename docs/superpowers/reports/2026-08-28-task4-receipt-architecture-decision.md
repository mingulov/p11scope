# Task 4 Receipt Architecture Decision

**Status:** unanimously accepted by independent Sol, Terra, and Luna review on
2026-08-28. This decision governs the Task 4 closure-plan and ROADMAP
amendments; implementation remains prohibited until those amendments are
independently reviewed.

## Decision

Replace the monolithic live Rust receipt observer and global `facts-v1` domain
schema with one gate-only sealed receipt envelope. Existing lane checkers remain
the domain oracles. A source-controlled, independently reviewed lane contract
manifest—not checker output—defines each lane's required inputs, resources,
checker roles, privacy surfaces, and cardinalities.

Product Rust/BPF, public v2 schemas, the privacy allowlist, and runtime gate
order do not change. The receipt protects ordinary reproducibility and detects
unreconciled same-UID mutation; malicious same-UID rewriting of both evidence
and an unsigned seal is outside its threat model.

## Scope and authority

- The envelope validates custody, provenance, lifecycle, privacy scanning,
  replay isolation, sealing, and terminal publication. It never interprets
  lane semantics.
- Each remaining lane has a committed manifest whose digest is bound into the
  receipt before execution. Runtime producers and checkers may attest what they
  consumed but cannot define or reduce the required inventory.
- Lane 14's manifest independently enumerates every required profile, log, map,
  live `START`, attach, discover, distribution, protocol, and canary surface
  required by `allowlist-v1.md`. Exact set equality is mandatory.
- Lane 16's reviewed gate-only validator is the sole exception where no prior
  standalone checker exists.
- Frozen Lane 02 evidence is compatibility-checked, not rerun. Lane 13 history
  is not amended or rerun in Task 4; it remains the single frozen-candidate
  9.2d negative control.

## Remove and salvage

Remove from the proposed commit `Task4ObservedSession`, its FD-5 protocol,
process-group observer, custom SHA-256, custom per-lane facts interpreter, and
duplicated lane semantics. Keep its adversarial cases as behavioral tests:
unsafe roots, preflight refusal, provenance mutation, registration-boundary
signals, identity-bound cleanup and absence, descriptor inheritance, seal and
status faults, and exact terminal delta.

The Rust artifact contract becomes a small table that invokes the real driver,
checker, manifest, and envelope self-tests. It does not parse lane facts.

## Canonical envelope

```text
ROOT/
  contract.json
  receipt.json
  resources.jsonl
  artifacts.jsonl
  inputs/...
  artifacts/...
  checker.log
  stdout.log
  stderr.log
  verdict
  seal.sha256
  status
```

Canonical JSON uses UTF-8, sorted keys, no insignificant whitespace, and one
final LF. JSONL uses the same object encoding, one record per LF-terminated
line, monotonically increasing sequence numbers, and bounded record sizes.
Duplicate logical labels, undeclared paths, links, special files, and alternate
spellings are rejected.

`receipt.json` binds the envelope version, lane-manifest path and digest, exact
argv/cwd/uid/gid, HEAD and tracked-tree digest, start/end ledgers for every
consumed source/input/checker/interpreter/dependency/tool/configuration, checker
invocation, and timestamps. Recording an untracked repository build input or
executable never authorizes it. Mutable external inputs are descriptor-pinned
or copied into the envelope before consumption.

The tracked index and worktree are clean at start and end. Every consumed
tracked source byte must equal the recorded HEAD tree. Repository-untracked
Cargo or container build inputs are rejected. The manifest is descriptor-pinned
as a consumed input, retained canonically as `contract.json`, included in both
start/end ledgers, and sealed so replay needs no original repository path.

`artifacts.jsonl` maps manifest labels to explicit relative retained paths,
producer, checker role, acquisition identity (owner/mode/dev/inode/size), and
portable replay identity (size/SHA-256). The required manifest set and recorded
set must be exactly equal. No glob, `find | head`, basename, stdout-as-capture,
or path-order authority is permitted.

All access is root-descriptor-relative with `O_NOFOLLOW` and `fstat` identity
checks. The caller supplies a canonical mode-0700 parent it owns, with no
symlink path component; the publisher claims an absent root race-free before
any mutation and installs its cleanup/finalization authority before creating
receipt files. Public body re-entry environment seams are rejected in normal
mode.

## Resource journal

`resources.jsonl` is parent-owned, serialized, append-only, and fsynced at every
transition:

```text
requested(nonce, class, intended locator)
resolved(nonce, immutable identity)
cleanup(nonce, result)
absent(nonce, identity query)
```

`requested` is durable before creation; `resolved` is durable before activation
or handoff. Nested helpers inherit only a pre-opened journal FD. The parent
retains cleanup authority. A crash after creation but before `resolved` may be
reconciled only when the request nonce identifies exactly one owned candidate;
otherwise the run is non-pass and cleanup is non-destructive. Mutable names
alone never authorize deletion. Cleanup and absence failure are non-pass.
The plan amendment must define the bounded canonical JSON object fields and
allowed transition graph. Crash recovery remains lane-owned and may use only
the journaled nonce plus immutable identity; the generic envelope validates the
record and never infers resource-specific deletion.

## Replay and privacy

After resources are absent, the pinned checker is rerun in the original private
root in a clean bounded environment over only manifest-registered root-relative
inputs. Those inputs are made read-only for replay and checker output goes to a
separate bounded destination. Original absolute paths, network, privilege,
Cargo, Docker, systemd, collection commands, globs, and mutable imports are
tripwired.
Checker/interpreter bytes and transitive dependencies are retained or bound to
an exact reproducible content/toolchain identity.

Every manifest-declared privacy surface is scanned. Failed privacy evidence is
private/quarantined and cannot be promoted. A checker that mixes collection and
validation may receive only the smallest pinned replay-only adapter needed to
consume retained inputs; the governing plan's checker-freeze rule is amended
solely for that adapter, and it is not rewritten in Rust.

## Seal, verdict, and terminal publication

The sealed inventory is canonical and complete: every regular envelope file
and declared artifact is listed in stable bytewise path order, except
`seal.sha256` and `status`; undeclared entries are rejected. `verdict` contains
the validator-derived decimal terminal intent and one final LF. It is included
in the seal.

`contract.json`, `receipt.json`, both JSONL journals, all retained replay inputs,
all manifest artifacts,
`checker.log`, `stdout.log`, `stderr.log`, and `verdict` are mandatory common
sealed entries. Logs and verdict are not additional manifest-labelled domain
artifacts, and no other retained file is allowed.

Terminal order is:

1. reap owned descendants;
2. perform identity-bound cleanup and durable absence queries;
3. revalidate provenance, manifests, resources, and artifacts;
4. replay checker and privacy validation from read-only retained inputs in the
   original private root;
5. write/fsync `verdict`, the canonical seal, and the root directory;
6. create `ROOT/status.pending` descriptor-safely in the retained root
   directory, write exactly the sealed verdict code, fsync it and its containing
   directory;
7. make `status` visible with `renameat2(RENAME_NOREPLACE)` as the sole final
   namespace mutation, fsync the root directory, then exit without mutation.

An existing `status`, pending collision, fsync failure, unavailable no-replace
rename, mismatch with sealed verdict, missing status, later mutation, or seal
failure is non-pass. Every consumer revalidates the seal and exact terminal
delta before accepting `status=0`.

## Acceptance before lane migration

The generic real-process RED/GREEN harness must prove at least:

- a committed manifest requires artifacts A+B while a zero-exit checker uses
  only A: reject and publish no zero status;
- child death after create-before-resolve: uniquely reconcile and clean, or
  retain uncertainty without destructive guessing and publish non-pass;
- live-state replay succeeds in the original private root after original
  absolute inputs and services are unavailable; after completion, a copied
  sealed envelope independently revalidates and replays from a new path;
- changed/omitted/alternate source, input, checker, dependency, tool, artifact,
  manifest, resource, privacy surface, verdict, or seal is rejected;
- symlink/replacement/hard-link/root-mode faults, signal boundaries, inherited
  descriptors, cleanup/absence failure, early/duplicate/replaced status,
  pending/rename collision, and post-publication mutation are rejected;
- no body/runtime command occurs after preflight refusal.

A fake lane proves the common protocol, but is insufficient alone. Every real
remaining driver must execute its finalizer through the common envelope and
prove exact manifest registration and replay before runtime acceptance.

## Migration gate

1. Obtain independent Sol, Terra, and Luna acceptance of this revision.
2. Amend the Task 4 closure plan and ROADMAP; permit one private stdlib-Python
   helper and remove the lane-local/no-shared-helper rule.
3. Replace—not extend—the current Rust observer RED with the generic behavioral
   RED, including the three decisive cases above.
4. Implement and independently review the envelope without product changes.
5. Migrate Lane 07 first, then the other remaining lanes serially. Replace each
   local receipt wrapper; do not layer the envelope on top of it.
6. Run canonical checks, independent lifecycle/provenance/oracle review, then
   the unchanged serial runtime board and downstream gates.
