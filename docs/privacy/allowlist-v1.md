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

| Value | Policy | Kernel source and guard | Output |
| --- | --- | --- | --- |
| Provider module identity | All modes | Module `path`, `dev`, `ino`, whole-file `sha256`, and GNU `build_id` come from operator input, filesystem mapping names/metadata, and the pinned provider file. They are not PKCS#11 call arguments and require no provider-memory pointer dereference. | `capture.modules[]` and `evidence.discovery[]`; filesystem/operator facts only. |
| Function identity | All modes | Attach cookie indexes a slot from a current memory scan or a trusted operator manifest. Hash pinning binds the selected offsets to the opened bytes; a manifest that the scan cannot corroborate forces `PARTIAL`. No function-name pointer is needed for ordinary calls. | Standard name or an explicit alias group. |
| PID/TID | All modes | `bpf_get_current_pid_tgid`; no user-memory read. | Privileged internal correlation state in every mode; only bounded `trace` output serializes raw PID/TID. Profile and metrics do not publish it. |
| Cgroup id | All modes | `bpf_get_current_cgroup_id`; no user-memory read. | Numeric id and best-effort host cgroup label. |
| Discovery skip record | All modes | Scan, pinning, process, and scope losses share one untyped internal record after aggregation. Exact standard function names survive; every other name becomes `discovery subject`. Reasons come only from the five finite categories documented by the v2 schema; unknown/internal reasons become `discovery unavailable`. | `evidence.skipped[]`; never an arbitrary mapped path, numeric PID label, `/proc/<pid>` path, cgroup path, unknown name, or raw error chain. The categorical reason, number of distinct losses, and resulting `PARTIAL` verdict remain intact. |
| Session handle | `allowlisted` and unsafe diagnostic | One descriptor-selected argument word read by `arg_u64`. | Internal state key only; `trace` emits a capture-local `sess#N`, never the handle. |
| Slot id and session flags | `allowlisted` and unsafe diagnostic | One descriptor-selected argument word each. | Aggregate lifecycle/async-session evidence only. |
| Login user type | `allowlisted` and unsafe diagnostic | One descriptor-selected argument word. | Successful-login counts by numeric `CK_USER_TYPE`. |
| Mechanism type | `allowlisted` and unsafe diagnostic | After the descriptor identifies `pMechanism`, one bounded read of `CK_MECHANISM.mechanism`. | Verbatim 64-bit id, including vendor ids. |
| Transient mechanism pointer | `allowlisted` | The entry probe copies the raw `pMechanism` argument register into `START` without dereferencing it. Only the matching return probe may use it, and only after `CKR_OK`/`CKR_PENDING`, for the finite mechanism-registry equality check. Every terminal path removes it. | Privileged internal map state only; never copied to `Event`, profile, trace, logs, or errors. The live canary scans this run's exact map id and proves address bytes are not mistaken for pointee data. |
| RSA-PSS parameters | Unsafe diagnostic only | Exact `ulParameterLen == 24`, then fixed-offset reads of `hashAlg`, `mgf`, and `sLen`. This decoder is absent from the default release BPF object. | Shape-tagged scalar combination. |
| GCM parameters | Unsafe diagnostic only | Exact known layout length (`40` legacy v2.20 or `48` v2.40+), then fixed-offset reads of IV length, AAD length, and tag bits. This decoder is absent from the default release BPF object. | Shape-tagged scalar combination including layout. |
| Output-pointer nullness | `allowlisted` and unsafe diagnostic | `capture_scalar` reads only the pointer-sized argument word with `ctx.arg::<u64>(n)` (or the single x86-64 stack word for argument 6). It never dereferences ordinary output buffers. | Null/non-null/unreadable capture state used for operation termination. The pointer value is not emitted. |
| Template attribute types | Unsafe diagnostic only | `walk_template` reads at most `MAX_ATTRS` `CK_ATTRIBUTE.type` values. This decoder is absent from the default release BPF object. | Requested numeric types; truncation/read failure is evidence and forces `PARTIAL`. |
| Policy booleans | Unsafe diagnostic only | Only after type lookup in `ATTR_BOOL_BITS`, `walk_template` reads `{pValue, ulValueLen}`; only `ulValueLen == 1` permits one byte at `pValue`. This decoder is absent from the default release BPF object. | Requested true/false for `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_SENSITIVE`, `CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_SIGN`, `CKA_VERIFY`, `CKA_DERIVE`, and `CKA_EXTRACTABLE`. |
| Return code and latency | All modes | Return register plus kernel monotonic timestamps. | Full-width `CK_RV`, counts, and latency aggregates/trace duration. |
| PKCS #11 3.2 async function name | `allowlisted` and unsafe diagnostic | `capture_async_target` snapshots one bounded C string and looks up its length plus exact bytes in the frozen 104-name standard catalog. Unknown names fail capture. | Numeric target id only; raw bytes/pointer do not enter a map or output. |
| Async id | `allowlisted` and unsafe diagnostic | Descriptor-selected scalar for `C_AsyncJoin`, or one bounded output-scalar read after successful `C_AsyncGetID`. `C_AsyncComplete` uses its function return register as the completed `CK_RV`; it never dereferences `pResult`/`CK_ASYNC_DATA`. | Internal correlation key only; never rendered. |

The only output-pointer dereferences are protocol necessities with narrow
guards:

- successful or pending `C_OpenSession`: read the returned scalar session
  handle so lifecycle/async completion can be correlated;
- successful `C_AsyncGetID`: read the returned scalar async id described
  above. `C_AsyncComplete` performs no output-pointer dereference.

Those scalars remain internal and are never serialized.

Interface name bytes are discovery data, not capture output. `inspect` and an
optional offline manifest may show the names they discovered; profile, metrics,
and trace evidence publish only interface counts/classification consequences,
never the bytes or their pointer. Slice 1b-1 added no pointer-derived capture
field.

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

These are decoder-inventory statements. The default `allowlisted` policy's
finite equality checks remain the boundary when a hostile caller aliases a
metadata pointer into unrelated readable memory.

## Structural enforcement

- Manifests are trusted operator input: structurally validated
  (`manifest_input::validate_structure`), every object opened once and
  identity-matched (GNU build-id / whole-file SHA-256) against the opened
  file, then pinned by descriptor; attach goes through `/proc/self/fd/N`,
  never the manifest path.
- The pinned objects' `(ino, size, ctime)` are re-checked before and after
  attach (refuse to attach on change) and during capture; a change during
  capture sets `evidence.provider_changed` and forces `PARTIAL`. The observer
  executes no provider code. The default discovery source is the target memory
  scan; `p11scope-discover` is an optional offline helper that executes the
  provider in its own process and is never launched by the observer.
- `arg_u64` has explicit constant cases `0..=6`; descriptors requesting any
  higher argument are rejected before BPF publication.
- `p11_entry` excludes template walking; `p11_entry_template` is attached only
  to a descriptor that names a template. No descriptor combines template and
  async-name capture.
- `decode_params` accepts exact known structure lengths and reads fixed scalar
  offsets only. A failed/unknown layout emits no partial decode.
- `walk_template` checks the type allowlist before reading `pValue` or
  `ulValueLen`, and checks `ulValueLen == 1` before dereferencing `pValue`.
- `capture_async_target` keeps its bounded snapshot on the BPF stack and uses
  byte-exact catalog membership; no hash-only authorization path remains.
- `CallStart` may temporarily hold protocol pointers required at return; the
  emitted `Event` and public render types have no raw-pointer output field.
- Every kernel read/update failure has evidence that forces `PARTIAL` where it
  can affect attribution.

## Release canaries

`scripts/verify-canaries.sh` covers the default, feature-safe,
unsafe-unvalidated, aggregate-only, malicious-alias, and policy-map freeze
lanes. It plants distinct sentinels
in PIN, username, key/value, label, id, plaintext, IV, AAD, signature, async,
output-buffer, overlong-boolean, and arguments 7–9 positions. It then scans:

- profile JSON and observer/workload logs;
- every map owned by the exact live observer process, resolved by map id;
- a live `START` map containing simultaneous PKCS #11 2.40, 3.0, and 3.2
  calls, including stack argument 6.

The scanner first proves itself with a nonempty positive control. Any sentinel
in any artifact fails the gate. The same run verifies both known GCM layouts,
malformed-length refusal, and RSA-PSS scalar decoding. The hostile-alias lanes
deliberately place sentinels behind decoded pointers; the ordinary lanes
independently cover the supported ABI shapes.

Changes to `SlotSemantics`, `CallStart`, `Event`, `arg_u64`, `decode_params`,
`walk_template`, `capture_async_target`, or public render fields require an
allowlist review and a canary update before release.
