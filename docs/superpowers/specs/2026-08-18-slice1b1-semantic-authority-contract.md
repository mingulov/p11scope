# Slice 1b-1 Semantic Authority Contract

**Status:** owner-approved on 2026-08-18; implementation and evidence remain OPEN.

## Decision

Every scan-only exact target/name is heuristic and semantically unverified. It uses
`SlotSemantics::COUNT_ONLY`, retains aggregate calls/errors/RVs/latency, creates no
mechanism/session/login/template/async interpretation, forces live and terminal
`PARTIAL`, and is excluded from semantic joins.

Supplying an explicit `--manifest` is operator attestation of only each accepted
manifest claim's exact pinned object, file offset, and canonical function name. Scan
agreement, hash pinning, raw `{dev,ino}`, path identity, stale fallback, and claim
proximity never transfer that attestation. A conflict remains `PARTIAL` and is wholly
ineligible for P11Lab semantic joining. Slice 1b-2 may later authorize exact
live-acquired claims.

## What the two authorities mean

- `evidence.authority: "hash-pinned"` proves which opened object bytes and file offset
  receive the probe. It never proves function-table semantics.
- Manifest attestation means the operator accepts the manifest's validated standard
  function name at that exact pinned offset. It does not prove that the selected
  application acquired that table or that the provider implements PKCS #11 correctly.
- Future `live-acquired` authority may prove that the selected process received one
  exact table address through a successful acquisition path. It still will not validate
  provider behavior; `pkcs11-check` remains the active capability validator.

## Compatibility and limitations

| Situation | Aggregate calls/RVs/latency | Semantic interpretation | Completeness consequence |
| --- | --- | --- | --- |
| Current, valid explicit manifest | Yes | Yes, for exact accepted manifest claims | Other evidence gaps still apply |
| Manifest-free Slice 1b-1 scan | Yes | No; count-only | `PARTIAL` |
| Scan plus exact accepted manifest agreement | Yes | Yes only for exact object + offset + name matches | Agreement is not live acquisition |
| Scan/manifest conflict | Yes, for the union | Manifest claims only internally; scan-only claims stay count-only | `PARTIAL`; whole module is not P11Lab-joinable in v2 |
| Stale or identity-mismatched manifest object with scanned fallback | Yes when the exact fallback remains attachable | No inherited attestation | `PARTIAL` |
| Future exact Slice 1b-2 acquisition | Yes | Yes for the exact live-acquired claim | Acquisition alone does not erase unrelated gaps |

The known glibc loader-timing problem is separate from this contract. It can prevent a
future loader hook from proving that some dynamically loaded tables were ready at the
observed hook. It does not prevent manifest-attested semantic capture, hash-pinned
attachment, or scan-only aggregate counting. On an unqualified loader/build without a
manifest, the safe fallback remains count-only and `PARTIAL`; it never silently regains
semantic authority.

An explicit manifest is therefore the dependable current path for full semantic
profiling when automatic live acquisition is unavailable. Its practical limits are:

1. the manifest must be structurally valid, current, and comparable to the pinned files;
2. the operator, not p11scope, attests its function-position semantics;
3. stale fallback loses attestation rather than borrowing it;
4. provider behavioral correctness is not established; and
5. current v2 output rejects an entire conflict module for semantic joining because it
   has no per-function source field.

## Exact enforcement boundary

Semantic authorization merges only at the existing planner identity
`(PinnedObjectId, file_offset)` and only for the same canonical name. A manifest claim
cannot authorize a different name, another pinned object sharing raw `{dev,ino}`, or an
adjacent target. `src/main.rs` corroboration reporting remains evidence-only and cannot
promote authority.

An unverified slot publishes the existing `SlotSemantics::COUNT_ONLY`. No new eBPF map,
program, common ABI field, dependency, pointer read, or privacy-allowlist field is
authorized by this decision.

## Consumer rule

P11Lab may join a positive normalized semantic key only when all of these hold:

1. the document exact-dispatches as profile schema v2, not metrics;
2. `functions[].module` maps by exact `{dev,ino,sha256}` to one discovery module;
3. the function is neither aliased nor module-ambiguous;
4. the module is manifest-only, or it is scan+manifest with `agreed` and without
   `conflict`, `identity_mismatch`, or `object_fallback`; and
5. ordinary completeness/evidence rules permit the conclusion being made.

Scan-only rows render as `OBSERVED-ADDRESS / SEMANTICS-UNVERIFIED`. A conflict module is
conservatively unjoinable. `pkcs11-check` results never retroactively promote a scan
claim.

## Later improvements

This decision is intentionally upgradeable without changing the current eBPF ABI:

- Slice 1b-2 can add exact `live-acquired` authority after its corrected Gates B/C pass.
- A qualified fixed-glibc capability tuple can enable loader-specific acquisition only
  for the exact witnessed loader/build and load kind.
- A per-function public authority field is justified only if P11Lab must join the
  manifest-owned subset of a conflict union; current v2 safely rejects the whole module.
- A separate attested-manifest flag is justified only if one invocation must mix
  trusted and discovery-only manifest files. Existing `--manifest` has one policy now.

None of these future options weaken the scan-only count-only baseline.
