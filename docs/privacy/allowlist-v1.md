# Privacy allowlist v1 — decoder inventory

This inventories the bounded metadata decoders. There is no arbitrary-buffer
dump switch.

Rows below are marked by the capture policy that contains them. The default
policy for `profile` and `trace` is `allowlisted`; `metrics` is always
`aggregate-only` and reads no call arguments at all. The unvalidated
fixed-offset decoders are present only in a build compiled with the
off-by-default `unsafe-unvalidated-metadata` Cargo feature *and* run with
`--unsafe-unvalidated-metadata`; the flag cannot reach code that is absent
from the object. The design is
`docs/superpowers/specs/2026-08-13-safe-and-unvalidated-metadata-design.md`.

The boundary assumes ABI-valid PKCS #11 structures for *scalar* fields: a
deliberately malicious caller can place arbitrary numbers in an allowlisted
scalar, and the kernel cannot distinguish that from a legitimate value.

Under `allowlisted`, that is the whole exposure — pointer-derived bytes become
output only by exact membership in a finite published set (the mechanism
registry, or the 104 published function names), so aliasing a metadata pointer
into unrelated readable memory yields no decoded value rather than an
arbitrary read. Under `unsafe-unvalidated-metadata` the older behavior returns
in full: an allowed fixed-offset read can be redirected to unrelated readable
bytes. `bpf_probe_read_user` prevents a target fault; it does not validate C
type or provenance in either policy.

It also assumes the explicitly selected native provider truthfully exposes
PKCS #11 ABI functions in its own tables. A malicious provider is already
arbitrary native code in the observed application and is outside that semantic
guarantee. A manifest is trusted operator input, structurally validated and
hash-matched against the pinned object; the observer executes no provider
code.

The controlling policy is `kinds::descriptor`. Each of the 104 published
PKCS #11 3.2 function-table slots has an explicit `SlotSemantics` descriptor;
older 2.x and 3.x tables are prefixes of that inventory. Unknown or
semantically ambiguous aliases are count-only. `attach::entry_program` selects
one entry program per slot, and only template-bearing calls use
`p11_entry_template`.

## Allowed capture

| Value | Kernel source and guard | Output |
| --- | --- | --- |
| Function identity | Attach cookie indexes a slot authenticated by fresh provider-table discovery. No function-name pointer is needed for ordinary calls. | Standard name or an explicit alias group. |
| PID/TID | `bpf_get_current_pid_tgid`; no user-memory read. | Raw PID/TID in bounded `trace` output; process identity is internal in profile/metrics output. |
| Cgroup id | `bpf_get_current_cgroup_id`; no user-memory read. | Numeric id and best-effort host cgroup label. |
| Session handle | One allowlisted argument word read by `arg_u64`. | Internal state key only; `trace` emits a capture-local `sess#N`, never the handle. |
| Slot id and session flags | One allowlisted argument word each. | Aggregate lifecycle/async-session evidence only. |
| Login user type | One allowlisted argument word. | Successful-login counts by numeric `CK_USER_TYPE`. |
| Mechanism type | After the descriptor identifies `pMechanism`, one bounded read of `CK_MECHANISM.mechanism`. | Verbatim 64-bit id, including vendor ids. |
| Transient mechanism pointer | In `allowlisted` mode, the entry probe copies the raw `pMechanism` argument register into `START` without dereferencing it. Only the matching return probe may use it, and only after `CKR_OK`/`CKR_PENDING`, for the finite mechanism-registry equality check. Every terminal path removes it. | Privileged internal map state only; never copied to `Event`, profile, trace, logs, or errors. The live canary scans this run's exact map id and proves address bytes are not mistaken for pointee data. |
| RSA-PSS parameters | Exact `ulParameterLen == 24`, then only `hashAlg`, `mgf`, and `sLen`. | Shape-tagged scalar combination. |
| GCM parameters | Exact known layout length (`40` legacy v2.20 or `48` v2.40+), then only IV length, AAD length, and tag bits. | Shape-tagged scalar combination including layout. |
| Output-pointer nullness | `capture_scalar` reads only the pointer-sized argument word with `ctx.arg::<u64>(n)` (or the single x86-64 stack word for argument 6). It never dereferences ordinary output buffers. | Null/non-null/unreadable capture state used for operation termination. The pointer value is not emitted. |
| Template attribute types | `walk_template` reads at most `MAX_ATTRS` `CK_ATTRIBUTE.type` values. | Requested numeric types; truncation/read failure is evidence and forces `PARTIAL`. |
| Policy booleans | Only after type lookup in `ATTR_BOOL_BITS`, `walk_template` reads `{pValue, ulValueLen}`; only `ulValueLen == 1` permits one byte at `pValue`. | Requested true/false for `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_SENSITIVE`, `CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_SIGN`, `CKA_VERIFY`, `CKA_DERIVE`, and `CKA_EXTRACTABLE`. |
| Return code and latency | Return register plus kernel monotonic timestamps. | Full-width `CK_RV`, counts, and latency aggregates/trace duration. |
| PKCS #11 3.2 async function name | The current `capture_async_target` snapshots at most 29 bytes and authorizes by FNV-1a-64 plus length. This rejects ordinary unknown names but is not byte-exact against an attacker-chosen collision; replacing it with a fixed-size byte-exact key is a release requirement. | Numeric target id only; raw bytes/pointer do not enter a map or output. |
| Async id | Descriptor-selected scalar for `C_AsyncJoin`, or one bounded output-scalar read after successful `C_AsyncGetID`. `C_AsyncComplete` uses its function return register as the completed `CK_RV`; it never dereferences `pResult`/`CK_ASYNC_DATA`. | Internal correlation key only; never rendered. |

The only output-pointer dereferences are protocol necessities with narrow
guards:

- successful or pending `C_OpenSession`: read the returned scalar session
  handle so lifecycle/async completion can be correlated;
- successful `C_AsyncGetID`: read the returned scalar async id described
  above. `C_AsyncComplete` performs no output-pointer dereference.

Those scalars remain internal and are never serialized.

## No direct decoder

No descriptor intentionally selects or emits:

- PINs, PIN lengths, usernames, labels, or `CKA_ID` values;
- `CKA_VALUE`, key material, plaintext, ciphertext, digest/signature input,
  signatures, wrapped blobs, random output, or operation-state blobs;
- ordinary input/output buffers or their contents;
- GCM IV/AAD pointers or bytes;
- arbitrary mechanism parameter bytes;
- arbitrary attribute values (anything outside the 11 one-byte booleans);
- raw provider-supplied async name bytes;
- raw session handles, raw output pointers, or async ids in any output.

Input lengths are also refused unless they are one of the explicitly listed
structural lengths used to validate an allowlisted decode. In particular,
message/data/PIN/signature lengths are not captured.

These are decoder-inventory statements. Until the safe policy is implemented,
they do not prevent a hostile caller from placing one of these values behind a
pointer and offset that an existing scalar decoder is allowed to follow.

## Structural enforcement

- Manifests are trusted operator input: structurally validated
  (`manifest_input::validate_structure`), every object opened once and
  identity-matched (GNU build-id / whole-file SHA-256) against the opened
  file, then pinned by descriptor; attach goes through `/proc/self/fd/N`,
  never the manifest path.
- The pinned objects' `(ino, size, ctime)` are re-checked before and after
  attach (refuse to attach on change) and during capture; a change during
  capture sets `evidence.provider_changed` and forces `PARTIAL`. The observer
  executes no provider code; discovery is the separate offline helper
  `p11scope-discover` (executes the provider, opt-in, never launched by the
  observer).
- `arg_u64` has explicit constant cases `0..=6`; descriptors requesting any
  higher argument are rejected before BPF publication.
- `p11_entry` excludes template walking; `p11_entry_template` is attached only
  to a descriptor that names a template. No descriptor combines template and
  async-name capture.
- `decode_params` accepts exact known structure lengths and reads fixed scalar
  offsets only. A failed/unknown layout emits no partial decode.
- `walk_template` checks the type allowlist before reading `pValue` or
  `ulValueLen`, and checks `ulValueLen == 1` before dereferencing `pValue`.
- `capture_async_target` keeps its bounded snapshot on the BPF stack. The safe
  amendment replaces current hash-only authorization with byte-exact catalog
  membership.
- `CallStart` may temporarily hold protocol pointers required at return; the
  emitted `Event` and public render types have no raw-pointer output field.
- Every kernel read/update failure has evidence that forces `PARTIAL` where it
  can affect attribution.

## Release canaries

`scripts/verify-canaries.sh` is an existing gate, but is not sufficient for the
amended release boundary until its malicious-alias and dual-policy lanes are
implemented. It plants distinct sentinels
in PIN, username, key/value, label, id, plaintext, IV, AAD, signature, async,
output-buffer, overlong-boolean, and arguments 7–9 positions. It then scans:

- profile JSON and observer/workload logs;
- every map owned by the exact live observer process, resolved by map id;
- a live `START` map containing simultaneous PKCS #11 2.40, 3.0, and 3.2
  calls, including stack argument 6.

The scanner first proves itself with a nonempty positive control. Any sentinel
in any artifact fails the gate. The same run verifies both known GCM layouts,
malformed-length refusal, and RSA-PSS scalar decoding. These ordinary-placement
checks do not prove safety against an attacker deliberately aliasing a decoded
pointer.

Changes to `SlotSemantics`, `CallStart`, `Event`, `arg_u64`, `decode_params`,
`walk_template`, `capture_async_target`, or public render fields require an
allowlist review and a canary update before release.
