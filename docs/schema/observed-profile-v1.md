# `observed-profile.json` schema v1.3

Current schema identifiers:

- profile: `pkcs11-scope/observed-profile/v1.3`
- metrics: `pkcs11-scope/observed-profile/v1-metrics`

These are interim schemas for the unreleased corrective tree, not the final
safe-policy contract. Implementing the approved privacy design advances them
to profile v1.4 and metrics v1.1-metrics; consumers must not reinterpret old
documents under the new semantics.

`p11scope-manifest/3` is a separate discovery input schema. Version 3 keeps a
GNU build-ID when present and adds a mandatory whole-file SHA-256 used for
fresh attach authorization. Authorization also requires fresh table
provenance and candidate-object read leases, but the current first pass has
open `$ORIGIN`, dependency-closure, and teardown-order findings. Manifest v4
adds the exact-inode provenance closure required by the corrected design. A
profile consumer must dispatch on the exact observed-profile schema string.

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
  "schema": "pkcs11-scope/observed-profile/v1.3",
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
| `module.path` | string | Absolute provider path recorded by the manifest. |
| `module.build_id` | string or `null` | GNU build-id or fallback file identity from the primary manifest object. |

Both current schemas use the same `capture.module` object shape.

## `evidence`

Discovery and attachment:

| Field | Meaning |
| --- | --- |
| `table_entries` | Function records seen across manifest surfaces. |
| `slots` | Unique `{object, file_offset}` targets. |
| `attached_probes` | Successful probe attachments; two per fully attached slot. |
| `attach_failures` | Per-slot attachment errors. |
| `aliased` | Name groups that share one address and therefore one count. |
| `skipped` | Unattachable manifest entries and reasons. |
| `surfaces` | Source, acquisition status, walk outcome, and function count for every surface. |
| `vendor_interfaces` | Present but undecoded interfaces. |
| `interface_list` | `C_GetInterfaceList` acquisition outcome. |
| `in_flight_at_end` | Entries with no matching return at shutdown. |

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
planned probe attached, and zero ambiguity/loss fields. The only nonzero
fields permitted in a complete document are the explicitly informational
`process_tracking_fallbacks`, `orphan_ops`, `unmatched_closes`, and
`shape_decode_failures`. An alternate or null interface name can be walked as
a structurally corroborated known prefix, but that surface deliberately keeps
the verdict `PARTIAL`.

`trace` ends with `EVIDENCE {json}`. The JSON object is this same evidence
contract, including its final `completeness` verdict; `LOST n events` remains
an immediate human-readable notification when ring loss grows.

## `functions[]`

One item per attach slot:

| Field | Meaning |
| --- | --- |
| `names` | Every standard function name resolving to the target. |
| `aliased` | Whether more than one name shares the target. |
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

## Metrics v1 migration

`pkcs11-scope/observed-profile/v1-metrics` replaces the experimental
`v0-metrics`. This is intentionally a major schema change: `capture.module`
is now `{path, build_id}`, function return codes are full-width, and the
expanded evidence object carries independent loss classes.

## v1.2 → v1.3 migration

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

Earlier v1/v1.1/v1.2 documents remain distinguishable by their schema strings;
consumers must not reinterpret them as v1.3.

## Privacy boundary

No PIN, key material, raw session handle, arbitrary buffer, label/id value,
signature, plaintext/ciphertext, IV/AAD bytes, or unrestricted mechanism/
attribute parameter bytes appear in either schema. See
[`docs/privacy/allowlist-v1.md`](../privacy/allowlist-v1.md).
