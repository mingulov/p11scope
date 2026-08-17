# `observed-profile.json` schema v2

Current schema identifiers:

- profile: `pkcs11-scope/observed-profile/v2`
- metrics: `pkcs11-scope/observed-profile/v2-metrics`

The safe-policy implementation landed before publication, so `v1.3` and
`v1-metrics` were internal corrective-tree waypoints that no consumer ever
received. The published migrations are therefore **v1.2 → v1.4 → v2** and
**v0-metrics → v1.1-metrics → v2-metrics**; nothing observes a v1.3 document.
Schema identifiers are opaque exact dispatch keys — the apparent major/minor
spelling grants no compatibility, and a consumer must dispatch on the exact
string.

Both documents carry `capture.privacy_mode`, naming the policy that produced
them: `allowlisted` (the profile/trace default), `aggregate-only` (the only
metrics policy, which reads no call arguments at all), or
`unsafe-unvalidated-metadata`. The policy is fixed in the eBPF object before
attachment and its maps are frozen, so the label describes kernel behavior
rather than a userspace intention.

A capture no longer needs a manifest at all: it discovers providers by reading
the target's own mapped memory. `p11scope-manifest/4` remains a separate,
**optional** discovery *input* schema produced by the offline helper
`p11scope-discover`, for a provider whose table the scan cannot read. It keeps a
GNU build-ID when present and the whole-file SHA-256 that the observer matches
against the pinned object at attach; the schema still carries the
`provenance_objects` closure recorded by earlier versions, which the observer
reads only for the `{device, inode}` an object had when it was recorded, never
for authorization (Productization Slice 1a).

## Data authority

- `functions` comes from aggregate BPF maps (`STATS` and `RV_COUNTS`). These
  maps are the call-count authority and are not subject to ring-buffer loss.
- `mechanisms`, `sessions`, `logins`, `templates`, and `cgroups` come from the
  event stream and semantic state machine. Any event/state loss is reported in
  `evidence` and makes the affected profile `PARTIAL`.
- The mechanism registry selects only the small parameter-shape allowlist. It
  never adds, removes, or renames an observed mechanism id.

Do not derive function totals by summing mechanism totals: one initialized
operation can cover several later function calls, and a capture can start in
the middle of an operation.

## Top-level objects

Profile mode always emits:

```json
{
  "schema": "pkcs11-scope/observed-profile/v2",
  "capture": {},
  "evidence": {},
  "functions": [],
  "mechanisms": [],
  "sessions": {},
  "logins": {},
  "templates": { "note": "...", "operations": [] },
  "cgroups": []
}
```

Metrics mode emits only `schema`, `capture`, `evidence`, and `functions`.

## `capture`

| Field | Type | Meaning |
| --- | --- | --- |
| `start`, `end` | RFC3339 UTC string | Capture window. |
| `mode` | string | `profile` or `metrics`. |
| `kernel` | string | Kernel release used for the capture. |
| `modules[]` | array | One entry per discovered module. A capture can observe more than one provider in one process. |
| `modules[].path` | string | The pathname the source that found it saw. **Not an identity, and not necessarily openable by the observer**: for a module the memory scan found, this is a path in the *target's* mount namespace, which may name a different file — or none — on the host. |
| `modules[].dev` | `[major, minor]` | Device of the object, as `/proc/<pid>/maps` renders it. |
| `modules[].ino` | integer | Inode of the object. |
| `modules[].sha256` | string | Whole-file digest, taken once at pin time. |
| `modules[].build_id` | string or `null` | GNU build-id when the object carries one. |

`capture.modules[]` is a projection of `evidence.discovery[]` in the same order,
and is the identity `functions[].module` refers to. Both current schemas use the
same `capture.modules` shape.

## `evidence`

Discovery and attachment:

| Field | Meaning |
| --- | --- |
| `table_entries` | Function records discovery decoded across every walked surface. |
| `slots` | Unique `{object, file_offset}` targets. |
| `attached_probes` | Successful probe attachments; two per fully attached slot. |
| `attach_failures` | Per-slot attachment errors. |
| `aliased` | Name groups that share one address and therefore one count. |
| `skipped` | Everything discovery could not use, and why. Entries: a NULL table slot, an entry whose object could not be pinned, an unresolvable manifest record. Whole objects: a mapping with no usable pathname (a memfd, or a file deleted under a running process), exports that could not be read, an object over the byte caps, a snapshot that ended early on a read error. An object-level skip is the only record of a provider that was never decoded at all — its module contributes no table, so nothing else in the document would show it. Deduplicated: one loss is one entry however many processes of a `--cgroup` hit it. |
| `surfaces` | Source, acquisition status, walk outcome, and function count for every surface. |
| `vendor_interfaces` | Present but undecoded interfaces. |
| `interface_list` | `C_GetInterfaceList` acquisition outcome. |
| `in_flight_at_end` | Entries with no matching return at shutdown. |
| `provider_changed` | A pinned provider object changed (ino, size or ctime) after attach; forces `PARTIAL`. |
| `authority` | How every probed object was authorized. `"hash-pinned"` is the only value this version emits: pinned by fd, hashed once with SHA-256, and re-checked by `fstat` `(ino, size, ctime)` during the capture. |
| `discovery[]` | One entry per discovered module — see below. |
| `discovery_conflicts` | Manifests whose recorded targets differ from the ones the scan decoded in the same object; the union is attached (spec §4.12). Forces `PARTIAL`. |
| `discovery_uncorroborated` | Modules whose offsets nothing corroborated: not mapped in scope, no scan, or a scan that decoded no table there — plus every `--manifest` ignored as stale (§4.12 case 4), which has no module of its own in `discovery[]` and would otherwise raise no counter at all. Forces `PARTIAL`. |
| `module_ambiguous` | Attach slots two modules both publish: counted, never attributed. Forces `PARTIAL`. |
| `modules_skipped[]` | Modules refused whole at the `MAX_SLOTS` attach ceiling, `{name, reason}` — a module is never attached in part. Forces `PARTIAL`; fatal only when the refusal leaves nothing to attach at all. |
| `scan_unavailable` | `null`, or why the memory scan could not run (e.g. `"ptrace"`). Objects are still identified from `maps` + `.dynsym`, but no table is decoded, so any `--manifest` offsets stand alone. Forces `PARTIAL` in its own right: under `--cgroup` one unreadable process among readable ones still plans slots, so nothing else would notice. |
| `scan_ms` | Wall time the memory scan took, summed over the scanned processes. |

`table_entries` counts every record discovery decoded, including the ones no
probe can reach: a NULL table slot, and an entry whose object could not be
pinned. Both are counted here *and* listed in `skipped`, so `slots` against
`table_entries` reads as attached against seen. A `--manifest` overlapping a
scanned module contributes its own records too, so an entry both sources
describe is seen twice and attached once; `discovery[].tables[]` shows the split
per source.

### `evidence.discovery[]`

| Field | Meaning |
| --- | --- |
| `dev`, `ino`, `sha256`, `path`, `build_id` | Identity of the module — same fields, and the same path caveat, as `capture.modules[]`. `sha256` is `null` when nothing pinned the object, never `""`: no digest was taken. |
| `objects[]` | Every object this module's **planned slots** attach into; a table entry may resolve into a dependency rather than into the module that published it, and an entry that never became a slot is in `skipped` instead. Each carries the same identity fields plus `identity_source` (`"mountinfo"` when the whole `{dev, ino}` was comparable against the mapping, `"stat"` when only the inode was, `"unpinned"` when this capture pinned nothing and compared nothing) and `note`, the reason for a downgrade. |
| `sources[]` | `["scan"]`, `["manifest"]`, or both. |
| `corroborated` | Whether a second source described the same targets. |
| `corroboration[]` | Which §4.12 outcome each source pairing produced — one entry per `--manifest` that named this object, since `--manifest` is repeatable and one outcome must not hide another. Values: `single_source` (no manifest named it), `agreed`, `conflict` (both decoded targets and they differ), `scan_empty` (the scan pinned this object but decoded no table in it — the documented use of `--manifest`, counted as uncorroborated rather than as a disagreement), `uncorroborated` (not mapped in scope, or no scan), `identity_mismatch` (a `--manifest` naming this object was ignored: the mapped bytes are not the ones it records). |
| `tables[]` | `{version: [major, minor], entries, source}` per function table published, one entry per source that saw it. |
| `interfaces` | How many interfaces were seen — **the most any one source saw, never the sum across sources**: the scan and a manifest describing one provider each count its interfaces, and each sees a subset (the scan records only an interface whose table it decoded), so this is a lower bound. **Never their names**: those are bytes read out of a provider's memory, and `p11scope inspect` is where they are shown. |
| `skipped[]` | This module's own unattachable records, `{name, reason}` — the same records as the top-level `skipped`, attributed to the module that published them. |

`identity_mismatch` is decided per *manifest*, not per object: the observer
compares the SHA-256 of the object at `module_path` and, on a mismatch, ignores
that whole manifest rather than that one object. A manifest whose *dependency*
diverged is therefore not detected by this check. The divergent dependency is
still pinned and hashed independently and its digest appears in `objects[]`, but
nothing compares it against the manifest's record of it.

Kernel/event loss:

| Field | Meaning |
| --- | --- |
| `event_loss` | Ring-buffer reservations that failed. |
| `start_insert_failures` | Calls whose no-overwrite `START` insertion failed. |
| `unmatched_returns` | Returns with no removable `START` entry. |
| `rv_update_failures` | Failed `RV_COUNTS` updates. |
| `cgroup_scope_failures` | Native cgroup-membership helper failures. |
| `semantic_capture_failures` | Descriptor-selected argument or bounded user-memory reads that failed. |
| `template_tail_failures` | Internal second-template handoff failed; the first template may remain available, but the key-pair request is incomplete. |
| `malformed_records` | Event records rejected for ABI size mismatch. |

Process and semantic uncertainty:

| Field | Meaning |
| --- | --- |
| `process_tracking_fallbacks` | pidfds demoted or unavailable but safely replaced by `/proc/<pid>/stat` start-time tracking. Informational. |
| `process_tracking_failures` | Neither pidfd nor start-time identity could be established. |
| `process_tracking_evictions` | Process identity records evicted at the bounded capacity. |
| `state_reconciliations` | Local state contradicted by a conclusive provider return and was corrected. |
| `session_cancel_ambiguities` | Multi-operation cancellation results could not be attributed exactly. |
| `session_cancel_unknown_flags` | `C_SessionCancel` contained unknown flag bits. |
| `operation_state_imports` | Successful `C_SetOperationState`; imported hidden state cannot be reconstructed. |
| `auth_state_ambiguities` | Login/logout/PIN-lock transitions invalidated uncertain local operation state. |
| `async_target_failures` | Async target name/value could not be safely correlated. |
| `async_orphans` | Complete/get-id/join observed without its pending record. |
| `async_duplicates` | A pending/detached async key was reused. |
| `async_evictions` | Async state evicted at its bounded capacity. |
| `fork_state_ambiguities` | A child used state that was not proven fork-safe. |
| `semantic_state_drops` | New semantic keys refused after the bounded per-capture state budget was exhausted. Aggregate kernel counts remain authoritative. |
| `pending_at_end` | Pending or detached async records remaining at shutdown. |
| `orphan_ops` | Operational calls without a captured active init. Informational because attach may start mid-operation. |
| `unmatched_closes` | Successful close with no captured open. Informational for the same reason. |
| `shape_decode_failures` | Calls for known allowlisted shapes that did not decode. Informational when other calls for the id decoded. |
| `shape_decode_total_failures` | Mechanism ids whose allowlisted shape never decoded in this capture. |
| `templates_truncated` | At least one template exceeded `MAX_ATTRS` or became unreadable mid-walk. |
| `completeness` | `COMPLETE` or `PARTIAL`. |

`COMPLETE` requires all discovery surfaces to be acquired and fully walked,
no undecoded vendor interface or failed interface-list acquisition, every
planned probe attached, and zero ambiguity/loss fields. It additionally requires
that discovery found something and planned something: **an empty `discovery[]`,
or `slots: 0`, is always `PARTIAL`**. A capture that observed nothing has no
attach failure and no skip to report, so gap counters alone would call it
complete — the most misleading verdict this tool could publish. `slots: 0` is
not a rare case: a scan refused `/proc/<pid>/mem` still names every mapped
object, with no tables, so any ptrace-refused capture lands there. The only nonzero
fields permitted in a complete document are the explicitly informational
`process_tracking_fallbacks`, `orphan_ops`, `unmatched_closes`, and
`shape_decode_failures`. An alternate or null interface name can be walked as
a structurally corroborated known prefix, but that surface deliberately keeps
the verdict `PARTIAL`.

**A written profile is always `PARTIAL`.** Detaching a perf link stops new
probe invocations but does not wait for BPF callbacks already executing on
another CPU, so no terminal snapshot can prove it drained everything. The
in-capture verdict above still governs live rendering, and the final document
is downgraded once on the way out. Read a clean run as `PARTIAL` with every
concrete gap counter zero — that combination, not the `COMPLETE` string, is
what the release lanes assert
(`scripts/check-capture-evidence.py: terminal_capture_is_clean`).

`trace` ends with `EVIDENCE {json}`. The JSON object is this same evidence
contract, including its final `completeness` verdict; `LOST n events` remains
an immediate human-readable notification when ring loss grows.

## `functions[]`

One item per attach slot:

| Field | Meaning |
| --- | --- |
| `names` | Every standard function name resolving to the target. |
| `aliased` | Whether more than one name shares the target. |
| `module` | `{dev, ino, sha256}` of the module these counts belong to, matching one `capture.modules[]` entry; `null` when two modules publish this target. |
| `module_ambiguous` | True exactly when `module` is `null` because two modules claim the slot. The counts are real; the owner is not knowable and is never guessed. |
| `calls` | Returns observed by the aggregate map. |
| `errors` | Nonzero returns excluding `CKR_PENDING`. |
| `pending_returns` | Returns equal to `CKR_PENDING`; also present in `rv_counts`. |
| `in_flight` | Entries minus returns at read time. |
| `latency_ns` | `approximate`, bucket-lower-bound `p50`/`p95`/`p99`, and exact `total`/`max`. |
| `rv_counts` | Full-width `CK_RV` formatted as a 16-digit hex key to count. |

Aliased slots are never split into guessed per-name counts.

## `mechanisms[]`

| Field | Meaning |
| --- | --- |
| `mechanism`, `mechanism_hex` | Verbatim 64-bit standard or vendor id. |
| `ops` | Operation categories observed for this id. |
| `calls`, `errors` | Event-derived semantic calls and non-success final results. |
| `latency_ns` | Same shape as function latency; async semantic latency spans pending entry to completion. |
| `params` | `null` or distinct allowlisted parameter combinations with counts. |
| `note` | Whether decoding was unavailable, failed totally, or succeeded. |

Allowed parameter objects are:

```json
{"shape":"rsa_pkcs_pss","hash_alg":592,"hash_alg_hex":"0x250","mgf":2,"salt_len":32,"count":1}
{"shape":"gcm","layout":"v2.20","iv_len":12,"aad_len":8,"tag_bits":128,"count":1}
{"shape":"gcm","layout":"v2.40","iv_len":12,"aad_len":8,"tag_bits":128,"count":1}
```

No arbitrary parameter bytes are serialized.

## `sessions`

| Field | Meaning |
| --- | --- |
| `opened` | Explicit successful opens observed. |
| `inherited` | Fork-safe sessions copied into a child process. |
| `closed` | Tracked sessions retired for any conclusive reason: successful close/close-all/finalize, whole-process exit, or PID-generation replacement. |
| `async_opened` | Successful opens requested with `CKF_ASYNC_SESSION`. |
| `peak_concurrent` | Maximum tracked sessions across process identities. |
| `balance` | Saturating `opened + inherited - closed`. |

`sessions.closed` is a lifecycle-retirement count, not a count of
`C_CloseSession` calls. Use `functions[]` for API call counts.

## `logins`

Object from numeric `CK_USER_TYPE` strings to successful-login counts. No PIN,
username, or raw session handle is present.

## `templates`

`templates.operations[]` contains `names`, `aliased`, an optional template
`role` (`public`/`private` where applicable), `requested: true`, numeric
`attr_types`, tri-state allowlisted `policy_booleans`, and `truncated`.
These are application requests, never assertions about effective object
policy. Attribute values other than the 11 one-byte policy booleans are not
captured.

## `cgroups[]`

Each item has numeric `cgroup_id`, best-effort `label`, calls, errors, and a
per-mechanism breakdown. A missing label is `null`; the resolver never guesses.

## v1.4 → v2 migration

Breaking:

- `capture.module` (one object) → `capture.modules[]` (one entry per discovered
  module, each `{path, dev, ino, sha256, build_id}`). A capture can now
  legitimately observe more than one provider in one process (a p11-kit proxy
  and its backend), so a single field could not stay honest.
- `functions[]` items gain `module: {dev, ino, sha256}`; a slot claimed by two
  modules renders `module: null, module_ambiguous: true` and is counted, never
  attributed. The flag is spelled `module_ambiguous` rather than `ambiguous`:
  the item already carries `aliased` for *name* ambiguity, and this spelling
  matches the `evidence.module_ambiguous` counter that totals these slots.
- `evidence.surfaces[].source` no longer contains an interface's recorded name.
  An interface surface is labelled `interface[<index>] <classification>`
  (`exact_standard` or `corroborated_standard_prefix`). The name is
  provider-supplied bytes and belongs to `p11scope inspect`, not to a capture
  document (spec §4.3, [`docs/privacy/allowlist-v1.md`](../privacy/allowlist-v1.md)).
- Both identifiers change, including the metrics one, whose evidence object
  carries all of the above: `v1.1-metrics` → `v2-metrics`.

Added:

- `evidence.authority` — `"hash-pinned"`: the provider was pinned by fd, hashed
  once with SHA-256, and re-checked by `fstat` `(ino, size, ctime)` during the
  capture.
- `evidence.discovery[]` — per module: identity, the objects its entries live
  in, whether it came from the memory `scan` or a `--manifest`, whether a
  manifest was corroborated by the scan and how, its tables and interface count,
  and anything skipped.
- `evidence.discovery_conflicts`, `evidence.discovery_uncorroborated`,
  `evidence.module_ambiguous`, `evidence.modules_skipped[]`,
  `evidence.scan_unavailable`, `evidence.scan_ms`.
- Each of those, and an empty `discovery[]` or `slots: 0`, forces `PARTIAL`.
- `evidence.skipped` additionally carries object-level losses (a provider
  discovery could not read at all), which v1.4 only printed to stderr.

Deferred to Slice 1b-2 (same v2, nothing is published yet): `attach_gap_ms`,
`pause`, `child_still_running` and the live-discovery loss counters
(`discovery_ring_loss`, `discovery_state_failures`, `discovery_truncated`,
`discovery_read_failures`). They are **absent rather than null**: this slice has
no live discovery to report on, and an always-null field is a claim that
something was measured.

## v0-metrics → v1.1-metrics migration

`pkcs11-scope/observed-profile/v1.1-metrics` replaces the experimental
`v0-metrics`. This is intentionally a major schema change: `capture.module`
is now `{path, build_id}`, function return codes are full-width, and the
expanded evidence object carries independent loss classes. It additionally
carries `capture.privacy_mode`, always `aggregate-only`: metrics mode reads no
call arguments in the kernel at all, so it cannot contain argument-derived
metadata regardless of build features.

## v1.2 → v1.4 migration

Everything in the v1.2 → v1.3 section below applies, plus the safe-policy
revision:

- `capture.privacy_mode` names the kernel capture policy that produced the
  document (`allowlisted` by default, `unsafe-unvalidated-metadata` only in a
  build that opted into the feature *and* passed the flag).
- Under `allowlisted`, pointer-derived metadata appears only when it matched
  the finite published mechanism registry or the 104-name function catalog
  exactly. A caller that aliases a metadata pointer elsewhere yields no
  decoded value rather than an arbitrary read.
- Mechanism parameter and template decoding beyond that finite equality is
  absent from the default eBPF object, so `params: null` is now the normal
  result for shapes the safe policy does not cover.

### v1.2 → v1.3 (folded into the above; v1.3 was never published)

This is a semantic, not merely additive, revision:

- `capture.module` is the shared `{path, build_id}` object.
- `functions[].pending_returns` distinguishes `CKR_PENDING`, and pending is
  excluded from `functions[].errors`.
- process, START/RV/cgroup, state-reconciliation, fork, cancellation, and PKCS
  #11 3.2 async evidence fields were added.
- `sessions` gained `inherited` and `async_opened`.
- `sessions.closed` now counts every conclusively retired tracked session,
  including close-all, finalize, process exit, and PID reuse. In v1.2 it meant
  only a successful `C_CloseSession` matched to a captured open. Consumers that
  estimate explicit-close rates must use `functions[]` instead.
- `sessions.balance` is now `opened + inherited - closed`.

Earlier v1/v1.1/v1.2/v1.4 documents remain distinguishable by their schema
strings; consumers must not reinterpret them as v2. The historical sections
above describe those documents as they were published — `capture.module` in them
means the singular object v2 replaced.

## Privacy boundary

No PIN, key material, raw session handle, arbitrary buffer, label/id value,
signature, plaintext/ciphertext, IV/AAD bytes, or unrestricted mechanism/
attribute parameter bytes appear in either schema. See
[`docs/privacy/allowlist-v1.md`](../privacy/allowlist-v1.md).
