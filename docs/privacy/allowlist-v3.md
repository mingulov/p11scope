<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Privacy allowlist v3 — PROPOSED object and attribute extension

**Status: PROPOSED; pending independent privacy and implementation review,
except [Inventory caller identity](#inventory-caller-identity-owner-ruling-fb-priv),
which is IMPLEMENTED in v0.2.0 by owner ruling FB-PRIV (2026-10-03), and
[offline inventory diff re-projection](#offline-inventory-diff-re-projection),
which describes the implemented offline report and grants no capture authority,
and [inline inventory identity](#inline-inventory-identity-p5u-2026-10-09),
which implements the reviewed compact re-projection with no new capture,
and [inspect presentation identity](#inspect-presentation-identity-p5u-2026-10-09),
a reviewed scan-local presentation contract whose PID/system implementation
and installed qualification are tracked separately,
and [trace executable labels](#trace-executable-labels-p5u-2026-10-09),
which permits the reviewed bounded trace publication below while its installed
and cgroup P4 qualification gates remain open,
and [cgroup trace sampling](#p4-cgroup-trace-sample-attempt-authority),
which describes its reviewed development implementation with installed gates
still open,
and [inventory diagnostics](#inventory-diagnostics-v04), which defines the
optional userspace decision export without additional target reads,
and [DR04 caller metadata](#dr04-caller-metadata-2026-10-18), whose opt-in source contract is described below and whose installed qualification remains open,
and [object producer activation](#object-producer-activation-h7-slice-d-2026-10-14),
which implements the reviewed finite producer below with no public
object projection,
and [H7-E4 attribute capture](#h7-e4-attribute-capture-2026-10-20):
the H7-E4 read set, the six attribute rows, the finite vocabulary,
the GetAttributeValue result rules, the output/retention table and
the [H9 publication section](#object-observations-publication-h9) are
APPROVED (owner decision OD11, 2026-10-24),
and [extensive-mode executable dependency hints](#extensive-mode-executable-dependency-hints-614-option-b-d-transitive),
which implements the ratified D-transitive hint contract below.**
Apart from those sections, this document does not enable capture, describe
implemented fields, or qualify a release. The implemented contracts remain
[v1](allowlist-v1.md) and [v2](allowlist-v2.md), whose bytes and existing
exclusions are unchanged.
Implementation, schema changes, decoder review and the evidence below must
precede activation. This proposal extends the default `allowlisted` policy;
it never enables `unsafe-unvalidated-metadata`. Metrics remains aggregate-only
and performs none of the new argument or pointer reads.

The purpose is capture-local object activity and limited metadata observed
from application calls. The observer must not load, initialize or query a
provider to fill gaps. An observed attribute result is a provider-reported
value from an application buffer, not independent proof of a physical key's
properties. An object pseudonym identifies an observation incarnation, not a
globally unique key, token inventory, or age before observation.

## Authority and ABI rules

Every new call-derived field requires all of: an explicitly operator-attested
function/offset claim, its retained and unchanged physical provider pin, one
unambiguous named descriptor, an accepted LP64 or ia32 specialization, exact
process-image identity, and the matching owned entry/return lifetime. A
provider export, readable pointer, equal path/hash, scan result, or successful
return alone is insufficient. Scan-only and ambiguous slots remain count-only.
Public inventory must retain modules and callers when semantics are withheld.

Arguments below are **zero-based**. Linux x86-64 LP64 uses eight-byte pointers,
handles and `CK_ULONG`; Linux ia32 uses four-byte words, zero-extended after a
successful four-byte read. `CK_BBOOL` is exactly one byte. A `CK_ATTRIBUTE`
has `{type, pValue, ulValueLen}` at offsets `{0, W, 2W}`, stride `3W`, where
`W` is the target word width. Host width must never substitute for target width.

For every read, checked multiplication and addition must validate the entire
span, including the last byte. ia32 spans cannot exceed `0xffff_ffff` and
LP64 arithmetic cannot wrap; null, failed, short, incompatible or overflowing
reads yield no value. Preserve the existing ABI-refusal evidence. Read failure
is distinct from a zero value; zero is not a valid object handle.

Compare selectors, mechanism IDs, scalar values and lengths at their full
target width before narrowing to any enum, u16, u32 or byte count. Successful
ia32 reads are zero-extended, not truncated again at classification. An
accepted constant ORed with `1 << 16` or `1 << 32` is not that constant and
must be rejected; the latter is also an out-of-range ia32 classifier input.

Argument index **7** is additionally authorized only as `C_GenerateKeyPair`
private-key result pointer or `C_UnwrapKey` result pointer. Its LP64 stack
word is at entry SP+16; its ia32 stack word is at entry SP+32. The complete
word must fit. No other descriptor may request 7, and indices 8 or higher
remain forbidden. A generic argument-reader implementation accepting 7 is
not authority: userspace publication and the kernel descriptor must both
enforce the named-function restriction.

## Exact object descriptor combinations

Unlisted combinations add no capture permission. Session argument 0 is the
existing v1 field. `in` means a scalar argument, never a pointer dereference;
`out` means one target-width handle read at the matched **CKR_OK** return,
subject to the result-protocol guard below for `C_DeriveKey`.
Input handles establish at most an attempted access until the result permits
the stated observation. Failed creation produces no object or creation time.

| Function | New input handles | New result pointers and reads | Safe requested template pointer/count |
| --- | --- | --- | --- |
| `C_CreateObject` | None | out 3 | 1 / 2 |
| `C_CopyObject` | source 1 | out 4; a distinct incarnation, never identity with source | 2 / 3 |
| `C_GenerateKey` | None | out 4 | 2 / 3 |
| `C_GenerateKeyPair` | None | public out 6, private out 7; distinct results | public 2 / 3, private 4 / 5 |
| `C_DeriveKey` | base key 2 | out 5 only for a supported scalar-result mechanism below; no identity with base | 3 / 4 only after the same entry-time mechanism guard |
| `C_UnwrapKey` | unwrapping key 2 | out 7 | 5 / 6 |
| `C_DestroyObject`, `C_GetObjectSize`, `C_GetAttributeValue`, `C_SetAttributeValue` | object 1 | None | None; `C_GetAttributeValue` uses the separate result protocol below |
| `C_EncryptInit`, `C_DecryptInit`, `C_SignInit`, `C_SignRecoverInit`, `C_VerifyInit`, `C_VerifyRecoverInit` | key 2 | None | None |
| `C_MessageEncryptInit`, `C_MessageDecryptInit`, `C_MessageSignInit`, `C_MessageVerifyInit`, `C_VerifySignatureInit` | key 2 | None | None |
| `C_DigestKey` | key 1 | None | None |
| `C_WrapKey` | wrapping key 2, wrapped key 3 | None | None |
| `C_SetOperationState` | encryption key 3, authentication key 4, only when nonzero | None; operation import remains uncertain | None |
| `C_FindObjects` | None | array pointer 1, entry capacity 2, returned count pointer 3 | None |

For an Init descriptor with `NULL_MECHANISM_CANCEL`, a null mechanism and
`CKR_OK` mean cancellation. Apply the existing cancellation transition before
object processing: an unrelated nonzero key argument must create no object
identity, accessing-session association or key-use count. Ordinary API-call
and cancellation accounting remain. This rule preserves the descriptor's
existing flag distinction; it does not classify every null mechanism as a
successful cancellation.

### DeriveKey result protocol

Function identity and `CKR_OK` alone do not authorize `C_DeriveKey.phKey`.
The initial scalar-result set is exactly:

| Mechanism | Full-width value | Result protocol |
| --- | --- | --- |
| `CKM_DH_PKCS_DERIVE` | 0x00000021 | One handle through arg 5 |
| `CKM_SHA256_KEY_DERIVATION` | 0x00000393 | One handle through arg 5 |
| `CKM_ECDH1_DERIVE` | 0x00001050 | One handle through arg 5 |
| `CKM_ECDH1_COFACTOR_DERIVE` | 0x00001051 | One handle through arg 5 |

These scalar-result mechanisms are specified in PKCS #11 Current Mechanisms
3.0 sections 2.4.10, 2.22.5, 2.3.17 and 2.3.18. In contrast, its sections
2.39.6, 2.40.6–2.40.7 and 2.41.6–2.41.8 describe SSL3/TLS12/WTLS
key-material or PRF results outside `phKey`; that cell can be ignored.
[Primary mechanism specification](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html).
Numeric IDs are pinned by the
[pkcs11-types mechanism catalog](https://github.com/mingulov/pkcs11-components/blob/d0a47c71d34294466bc41100ae6b5a5a329029d2/crates/types/src/mechanism_official.rs).

Before reading/retaining arg 5 or reading the requested template, classify
one target-width `CK_MECHANISM.mechanism` word at arg 1's pointer by exact
equality to this four-member set. This is an explicitly proposed entry-time
read, separate from v1's return-time mechanism read. Retain only the finite
accepted mechanism enum. At the matching CKR_OK return, reuse the existing
guarded return-time captured mechanism scalar: it must have
`MECHANISM_VALUE` status and match the entry enum exactly before dereferencing
arg 5. This guard authorizes no additional return-time mechanism read.

Missing, null, unreadable or unlisted entry mechanisms authorize neither
arg 5 capture/retention/dereference nor requested-template reads. Missing or
changed return evidence discards the pending result/request association
without reading `phKey`. Even a readable nonzero untouched `phKey` cell cannot
establish a derived object. Report the result protocol unavailable; retain
only otherwise-authorized call/mechanism/base-key observations. No nested
mechanism parameters, nested output handles, PRF bytes or fallback probing
are allowed. Other scalar-result mechanisms remain outside this initial set
until explicitly reviewed.

`C_FindObjectsInit` search filters are not object attributes and gain no reads.
`C_GetObjectSize` gains no size-result read. `C_SetAttributeValue` gains no
template read: a successful mutation invalidates established metadata for
that handle view until a new allowed result is observed. Wrapped data,
mechanism parameters, ordinary buffers and operation-state bytes remain
excluded even on the named calls. `C_EncapsulateKey`, `C_DecapsulateKey`,
`C_WrapKeyAuthenticated` and `C_UnwrapKeyAuthenticated` gain no object decoder
from this proposal; existing observations remain, with unavailable object
detail explicit. They cannot use the new index-7 exception.

No result pointer is read on `CKR_PENDING`. S1's existing async mechanism
correlation remains separate. `C_AsyncComplete.pResult`/`CK_ASYNC_DATA` stay
unread; asynchronous object results remain unavailable, even after completion.
Retaining a result pointer beyond its matching call is prohibited.

## Field inventory and retention

The bounds and evidence identifiers in later sections are part of every row.
Private fields must use non-serializable types without raw-value `Debug`,
logging, error formatting or map-dump output paths. Addresses and handles are
explicit, narrow internal exceptions, not finite attribute values.

| New field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Entry instruction pointer | Probe context of an authorized named call; normalize for the qualified ABI and require the exact attached file offset in one executable mapping of the retained image. No user-memory read. | Private `CallStart`, completed-call transport and join queue only; discard after routing. No serialized address, address-derived hash, or persistent ID. | No unique current mapping: unattributable-instance gap, no semantic join. C1/C2. |
| Mapping continuity epoch and state | Kernel/observer-owned per-image monotonic epoch, mutation-in-progress/uncertain flags, and bounded continuity checks; never inferred from equal maps alone. No syscall pointer, length or path is read for this witness. | Private entry/return and join state; public capture-local instance ID and finite continuity/loss status only. | Missing tracking, overflow, missed event or incomplete scan invalidates the affected associations. C2/C7. |
| Input object/key handle | Only the scalar positions in the descriptor table; reject zero except optional absent `C_SetOperationState` keys. Successful use may establish first-observed accessibility, not creation. | Private call and session-binding state; public `object#N` plus finite role and provenance. | Unreadable or authority failure cannot join; invalid-handle return ends accessibility, not presumed destruction. C1/C3. |
| DeriveKey result-protocol discriminator | Only `C_DeriveKey`, arg 1: one bounded target-word entry read of `CK_MECHANISM.mechanism`; exact full-width membership in the four scalar-result mechanisms above before arg 5/template access. At matched CKR_OK return, compare the existing guarded captured mechanism scalar/status with that entry enum; no extra return-time read. Never read `pParameter` or `ulParameterLen`. | Four-member accepted mechanism enum or unavailable state in private in-flight state; clear on every terminal/loss path. Public result-unavailable reason only; existing mechanism output retains its existing guards. | Missing/changed/unlisted evidence prevents a result read/identity; an ignored nonzero `phKey` sentinel gets no exception. C1/C3/C6. |
| Result-handle pointer | Only the named out positions, captured at entry; `C_DeriveKey` additionally requires its finite entry protocol guard before retention. Equal image/owner/descriptor at CKR_OK return, the matched derive mechanism where applicable, and full-span validation precede one result read. | Private in-flight state only; clear on every terminal, loss, cancellation, exec or teardown path. Never copied into the public projection. | Null/read failure or unavailable result protocol: result unavailable; no retry after return. C1/C3. |
| Returned object/key handle | One target word from the preceding pointer; nonzero opaque handle. No finite whitelist is possible for valid handles; this is an explicit internal scalar exception analogous to v1 session handles. | Private call transport and generation-scoped registry only; fresh capture-local pseudonym on accepted creation. | Failed/ambiguous reads create no association. Duplicate pair handles or overlapping pair-result spans invalidate the pair; one unreadable independent result does not invent its sibling. C1/C3. |
| Find array pointer | `C_FindObjects` arg 1 only, retained at entry; used only at matched CKR_OK return with valid entry capacity and returned count. | Private in-flight state only. | Null with nonzero count, overlap with count word, invalid span or read failure gives unavailable results. C1/C4. |
| Find entry capacity | Arg 2, target-width scalar; retain only validation/cap state. | Private in-flight state; publish bounded decoded count and truncation status, not arbitrary caller capacity. | Count/capacity violation permits no array read. C4. |
| Find returned-count pointer | Arg 3; full target-word span; matched CKR_OK only. | Private in-flight state only. | Null/unreadable count permits no array read. C1/C4. |
| Find returned count and handles | Read count once; require `count <= entry_capacity`; validate the complete claimed array span before reading at most eight handles. Recheck count after the bounded read. | At most eight private handle words; publish first-observed pseudonyms, decoded count 0..8 and a truncation flag. No raw count/array. | Changed count discards the batch; failed element is unknown, never a zero handle. Count >8 records bounded omission and invalidates any assumption of an exhaustive search. C4. |
| Template pointer and count | Only the six creation families above, or `C_GetAttributeValue` args 2/3; checked `count * 3W` span. Inspect first eight slots of each allowed template. | Request templates read at entry and discarded; GetAttribute headers retained only until matching return. Publish finite omission/read status, not raw count/pointer. | Overflow refuses decode; >8 records truncation; a failed header is unknown. Never recurse into array attributes. C1/C5/C6. |
| Attribute selector | Read just `CK_ATTRIBUTE.type` to test equality against the six identifiers below before reading its pointer/length. | Retain a six-value selector enum only; unknown selectors are discarded without retaining their raw number or reading their pointer/length. | No new `CKA_ID` collection or pre-collection, including its value, length or pointer. C5/C6. |
| Attribute value pointer | Only after selector equality; GetAttribute retains entry pointer and compares returned header pointer before decode. | Private in-flight GetAttribute slots only; request pointer is transient probe scratch. No pointer in result transport. | Null is size-only for GetAttribute, unavailable for requests; pointer/header changes or detectable overlap refuse the affected values. C1/C5/C6. |
| Attribute entry capacity / returned length | Read the named selector's `ulValueLen`; target word, exact accepted value size and full-span checks. GetAttribute retains capacity and reads returned length. | Private in-flight validation; only finite state such as `size_only`, `unavailable`, `invalid_length`, `changed`, `unreadable` is public. | Width-correct unavailable sentinel, growing length, zero/wrong length, insufficient entry capacity, read failure: no value read. C5/C6. |
| `CKA_CLASS` | Exact selector 0x0000; one target word, exact width, finite set below. | Six-field request/result snapshot; public finite class plus source/state. Raw unmatched word discarded in probe scratch. | Unsupported/conflicting value stays unknown. C5/C6. |
| `CKA_KEY_TYPE` | Exact selector 0x0100; one target word, exact width, finite set below. | As class, with finite key-type label. No vendor numeric fallback. | Unsupported/conflicting value stays unknown. C5/C6. |
| `CKA_TOKEN` | Exact selector 0x0001; exactly one byte and exact equality to 0 or 1. | Requested or established `session`/`token`, with provenance; only established result may drive object lifetime. | Other byte/length is unknown; a request is never promoted by CKR_OK creation alone. C3/C5/C6. |
| `CKA_VALUE_LEN` | Exact selector 0x0161; one target word equal to 16, 24 or 32 only. | Finite byte-size code; label as AES 128/192/256 bits only with independently established AES type for established metadata. | Other values unknown; no `CKA_VALUE` read and no inference from mechanism alone. C5/C6. |
| `CKA_MODULUS_BITS` | Exact selector 0x0121; one target word equal to a selected RSA size below. | Finite size code; RSA label requires matching RSA type/provenance. | Other values unknown; no modulus or exponent buffer read. C5/C6. |
| `CKA_EC_PARAMS` | Exact selector 0x0180; exact length 7 or 10 and byte-for-byte equality to one complete encoding below. At most ten bytes in probe scratch. | Only curve enum; scratch bytes never leave the probe's stack frame and are not copied to any map, record or output, including recognized encodings. The buffer is not explicitly zeroed. Curve label requires matching EC type/provenance. | No hash-only, prefix, permissive DER, explicit-parameter or arbitrary-string fallback. C5/C6. |
| Public identities and derived facts | Monotonic capture-local allocation plus accepted reducer transitions; never raw handle, IP or digest of either. | `instance#N`, `sess#N`, `object#N`; finite origin/lifecycle/metadata states, times within observation, and saturating counts. JSON, JSONL and dashboard use the same immutable projection. | Allocation exhaustion refuses new association, records loss, and never reuses an ID. C3/C7/C8. |

## Finite attribute vocabulary

Class and key-type numbers follow the OASIS PKCS #11 3.0 `pkcs11t.h`;
the pinned pkcs11-types `CkKeyType` table misnumbers values from 0x27
upward and is not a source for this vocabulary. The selected attribute
selectors are a deliberately small subset of the pinned [pkcs11-types
attribute definitions](https://github.com/mingulov/pkcs11-components/blob/d0a47c71d34294466bc41100ae6b5a5a329029d2/crates/types/src/attribute.rs).
These sets are closed; support for another standard or vendor value requires
a reviewed policy change, not numeric passthrough.

| Field | Exact accepted values and labels |
| --- | --- |
| Class | 0 `data`, 1 `certificate`, 2 `public_key`, 3 `private_key`, 4 `secret_key` |
| Key type | 0x00 `rsa`, 0x01 `dsa`, 0x02 `dh`, 0x03 `ec`, 0x04 `x9_42_dh`, 0x10 `generic_secret`, 0x1f `aes`, 0x40 `ec_edwards`, 0x41 `ec_montgomery` |
| Token flag | 0 `session`, 1 `token` |
| AES byte sizes | 16, 24, 32, presented as 128, 192, 256 bits with the type guard |
| RSA bit sizes | 1024, 2048, 3072, 4096, 8192; an observer support set, not a cryptographic-strength recommendation |
| EC curve | `secp256r1`: `06 08 2a 86 48 ce 3d 03 01 07`; `secp384r1`: `06 05 2b 81 04 00 22`; `secp521r1`: `06 05 2b 81 04 00 23` |

The curve identifiers follow [RFC 5480 section 2.1.1.1](https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1.1.1);
the complete DER octets above are the observer's exact equality set. Edwards
and Montgomery key-type labels do not authorize curve decoding for those
types. Unsupported sizes/curves stay unknown rather than weakening the
finite set. The AES byte-size policy follows the 128/192/256-bit key sizes in
[FIPS 197](https://doi.org/10.6028/NIST.FIPS.197-upd1). Public JSON carries
the accepted numeric code; labels are presentation names. The projection's
`rsa_other` fallback label can only mean 8192 (every other accepted RSA size
has its own label), and `aes_other` can never occur (every accepted AES size
has its own label).

Pointer aliasing can still place an exact permitted constant at a readable
address. Finite equality limits the value disclosed; it does not prove C type
or buffer ownership. Unmatched bytes never leave probe scratch. The opaque
handle exceptions above must not be reused to transport attribute bytes.

## Requested values and GetAttributeValue results

Entry-time values from creation templates are **requested** metadata, kept
separately for each resulting object and separately for each key-pair member.
Missing or duplicate-conflicting requests stay unknown. Successful creation,
mechanism choice, key-pair membership, copy/derive ancestry and requested
`CKA_TOKEN` do not establish resulting attributes. Failed creation must not
attach its requested facts to an existing handle incarnation.

For `C_GetAttributeValue`, accept per-attribute result processing only on
`CKR_OK`, `CKR_ATTRIBUTE_SENSITIVE`, `CKR_ATTRIBUTE_TYPE_INVALID`, or
`CKR_BUFFER_TOO_SMALL`; the latter three can coexist with usable results for
other attributes. The entry capacity, selector and pointer govern each
returned read. Size-only requests produce no attribute value; a later retry
is a new call and cannot borrow the earlier call's capacity or pointer.
These partial-result and session-handle rules follow the
[PKCS #11 base specification, sections 3.4, 5.6 and 5.7](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html).

For each selected slot, in order:

1. Preserve its entry selector, slot index, value pointer and capacity. A
   null entry pointer is size-only even if the returned pointer changes.
2. At return, read that same header and require unchanged type and pointer.
   `CK_UNAVAILABLE_INFORMATION` is all ones at the target width. Unavailable,
   null, insufficient capacity or non-exact accepted length means no value
   read. A capacity larger than the exact size is allowed; returned length
   must fit capacity and exactly match the allowed shape.
3. Reject readable-span arithmetic overflow, a selected value overlapping
   the inspected template headers, or overlapping selected value spans.
   Unknown attribute pointers must not be read to search for aliases.
4. Read only the allowed scalar or exact bounded curve encoding; classify
   immediately, then recheck the header. Any changed header discards that
   attribute. This detects observable races, not an atomic snapshot of
   arbitrary caller-writable memory.
5. Equal duplicate results may coalesce. Conflicting duplicate or previously
   established values produce a conflict state, never last-writer-wins.
   An unsuccessful/unavailable observation cannot erase an older established
   fact by itself; it records that the latest query did not establish one.
   A lifecycle uncertainty or successful `C_SetAttributeValue` does invalidate
   current facts. Keep historical provenance separate from current validity.

Only the observed result may establish the six fields. Incomplete, unsupported
or unreadable values never acquire a label from another attribute, another
object, requested metadata or a recognized mechanism. For a known size without
a known matching key type, retain the finite field fact but show type/size
association as unknown. A combined label requires an established,
non-conflicting key type and is withheld when class conflicts or an
established class is incompatible (AES and generic_secret need
`secret_key`; RSA and EC need `public_key` or `private_key`). No default
token/session classification is assumed.

## Instance, session and object lifetime

`ModuleKey` remains physical file identity. A semantic domain additionally
requires capture identity, exact process image, a **proven load instance**,
initialization epoch and applicable observed slot/token epoch. File identity
alone never supplies the load instance. Runtime mapping ranges are private,
generation-local join inputs, not persistent identity.

A complete accepted maps snapshot may partition executable segments into
instances only where the pinned ELF segment layout and exact file offsets
admit one partition. Calls join by their entry IP and attached target offset,
within the same image and continuity epoch, to exactly one such partition.
Ambiguous partitions, uncorroborated aliases, data-only duplicate evidence,
missing ranges and unknown epochs provide no instance authority.

Continuity requires a qualified mutation witness active before the maps
snapshot and throughout the call. Mapping-changing activity must dirty the
image **before** the change can affect an entry probe; a scan is accepted only
when bracketed by the same clean epoch and no mutation in progress. Missing
hooks, uncertain image identity, counter overflow, event loss, a scan gap or
an incomplete snapshot end continuity. A later scan mints new incarnation
IDs. An unload/reload at the same address never revives the old IDs. Repeated
`dlopen` of the same live loader object can keep one instance only with this
continuity proof. A loader notification or two equal snapshots alone is not
that proof. Unqualified mapping mechanisms leave semantics withheld.

Maintain separate session and object registries. Bind a raw handle to an
incarnation under its authoritative domain and accessibility session. A
create/copy/generate/pair/derive/unwrap result can establish observed creation;
find or successful use establishes **first observed**, with creation time
unknown. Different callers, load instances, token slots, sessions without
shared-identity proof, and successive lifetimes must not join merely because
their numeric handles match. Different handles must not be merged by equal
safe metadata. Do not claim distinct physical-key cardinality from these
observation IDs.

Record a known creator session separately from accessing-session bindings.
Do not assume a session's view owns an object. Where the allowed evidence
cannot prove cross-session identity, retain separate views with shared
identity unknown; a fixture oracle's knowledge is not observer authority.
Closing an accessing session ends that access. Closing a known creator
session establishes destruction only for objects independently established
as session objects; it never establishes destruction of token objects.
Unknown persistence produces `observation_ended`, not `destroyed`.

Successful destruction ends the affected proven incarnation. Failed
destruction does not. An invalid-handle response ends that accessibility
binding, not a claimed physical-object lifetime. Logout invalidates affected
accessibility because private/public classification is unavailable here;
do not falsely declare token destruction. Finalize, successful token
initialization, exec, unload, provider mutation, unknown token continuity,
loss, and eviction invalidate affected associations and metadata. With an
unknown scope, invalidate the entire semantic domain/capture conservatively.
Fork does not copy trusted sessions or object IDs into the child's image.
Initialization/token epochs are local observed epochs, never token serials.

Late calls, async completions or attribute results cannot reattach to a new
incarnation after invalidation. Creation overlapping unresolved use/destruction
is uncertain unless an ordered lifetime can be proven; completion timestamp
sorting alone must not settle concurrent handle reuse. Terminal shutdown
drains known producers before publishing observation-ended status, and marks
an incomplete drain as loss.

## Stage A continuity witness (Task 3; PROPOSED addendum)

This addendum is additive and PROPOSED like the rest of this document. It
names the only new state the Task 3 Stage A continuity mechanism keeps. It
does not enable any semantic field above; it only supplies the private
load-instance authority that "Instance, session and object lifetime"
requires. v1 and v2 are unchanged.

Kernel-side state, owned by the exact observer:

- `WATCHED_FILES` (`{s_dev, i_ino}` to a file slot) and `SLOT_FILE`,
  written by userspace only from the calibrated watched provider files.
- A per-process task-storage record of at most eight `(file slot, mutation
  counter)` pairs plus finite flags, a per-file global counter, a fault
  generation and an attach generation, and finite hook counters. These are
  counts of file-VMA map/unmap/move events for watched provider files. No
  address, length, protection, path or content of any VMA is stored.
- `INSTANCE_CALIB`: one transient cell holding the observer's own
  calibration mapping (`vm_start`, `s_dev`, `i_ino`), cleared after use.
- `INSTANCE_START` (LRU, bounded): per in-flight call, keyed by the existing
  START key, the private **entry IP** (the probed address) and a 16-byte
  stamp `{epoch, global, fault, file slot, flags}`. Consumed and deleted on
  return; eviction is a counted unknown, never a join.

Detailed image continuity keeps, per existing task cookie, only its existing
exec ID, a nonwrapping serialization sequence and finite Ready/Poisoned
state. Authentic admitted non-aggregate entries alone establish/renew Ready.
Before any joinable stamp, that entry publishes a bounded private index
from its existing initial-kernel TGID to its existing cookie. The pre-mm
`exec_mm_release` hook reads current TGID through the existing PID helper,
looks up this index and poisons the indexed record before replacement.
This index supplies negative invalidation only: selected-task queries
freshly obtain TASK_COOKIE/self_exec_id and never consult it or repair
state. The hook reads no task-storage value, arguments or mm pointer.
State, index, query buffers and finite health remain private and bounded
to the owning Session; no new public identity, target memory, syscall
range, path or pointer retention is introduced. Metrics and both Inventory
producers perform none of these new reads/writes. This narrow clarification
was accepted for Task 1 implementation on 2026-10-09; the proposed object
and attribute reads above retain their separate approval gates.

Both continuity hashes cap at 16,384 retained nodes and are frozen against
userspace writes before producers attach. Their combined raw key/value
payload is 768 KiB, plus hash bucket/allocator overhead and one 8-byte
coverage cell. No node is deleted, evicted or replaced. The index changes
only through ordered 64-bit CAS at an authentic entry. Before mutating a
missing or foreign index, an existing continuity record causes permanent
coverage failure; it cannot be repaired. The selected-task query uses at
most 1,024 private request slots and a 65,536-callback visit cap under the
original scan deadline. All state dies with the owning Session.

Kernel metadata read transiently by the hooks and never stored except as
the counters above: `vm_file`, `f_inode`, `i_ino`, `i_sb->s_dev`, `vm_mm`,
`mm_users`, `current->mm`, `current->flags` (the `PF_KTHREAD` bit only, to
exclude mm borrowers from localization), `group_leader`, `clone_flags`. No
syscall argument, user address or length, target memory, or kernel pointer
is captured or emitted.

The image query additionally reads the candidate task's flags word for the
kernel-thread bit; fork and exec maintain only the row's shared-memory mark
and attach generation; the calibration cell also carries the observer's own
calibration thread id and hit count. The flags word is checked and
discarded; none of these values is emitted.

The post-attach birth marker is deferred to 0.6.0 and is excluded from the
v0.5.0 build. Its planned Detailed-only amendment is as follows:
an in-scope exec
after closure reads the leader's exec generation onto its continuity row;
any out-of-scope or refused call dirties the row instead, with no
exec-generation read on that path. The marker word and the admission
spent/failed counts stay private to the birth observation, read back
through the held pidfd, and are never published.

Wire: each EVENTS record carries a private 40-byte tail `{entry_ip,
entry_stamp, return_stamp}` after the unchanged 328-byte `Event`.
Userspace keeps the entry IP inside the instance router (`EntryIp`: no
`Debug`, `Display` or `Serialize`) and drops the tail before any decoder
used by renderers. The entry IP, stamps, maps ranges and map_files
identities never reach JSON, JSONL, trace, profile, dashboard, logs or
errors; public output may carry only finite continuity, coverage and
refusal facts and capture-local instance IDs.

Userspace join input: `/proc/PID/maps` ranges of the watched file, each
confirmed by `stat()` of `/proc/PID/map_files/<range>` against the identity
recorded at calibration (device and inode numbers of a provider file, used
for equality only, never emitted). The `(s_dev, i_ino)` maps key alone is
not unique (btrfs subvolumes, overlay without xino) and is never a join
authority.

Required evidence before activation adds: an exact-offset canary scanner for
the entry IP and stamps in the EVENTS tail and `INSTANCE_START`, with
must-detect positive controls in public outputs; and a sentinel regression
proving renderers never receive the tail.

## Bounds, loss and output

Proposed ceilings are eight inspected attributes per template, at most two
templates per call, six classified fields per metadata snapshot, ten curve
bytes of transient scratch, two scalar input handles, two scalar result
handles, and eight find handles per call. The existing in-flight owner ceiling
of 16,448 still bounds private call state; an added side map cannot multiply
that allowance or outlive its owner. Its byte cost must be measured before
activation.

Userspace semantic state is additionally bounded: 1,024 live sessions and
4,096 retained object views per instance, 16,384 session records and 65,536
object records capture-wide, and at most 32 accessing-session relations per
object. At most 4,096 instance records and 16,384 executable ranges are retained
capture-wide; existing tighter caller/module/edge admission limits still
apply. Six requested and six established attribute facts per object are
fixed slots, not unbounded histories. Pending joins are capped at 1,024 calls;
reject or invalidate on overflow, never wait unboundedly for a scan.

Refusals do not erase broad module/caller inventory or historical positive
observations. Saturating counters and finite reasons distinguish read failure,
malformed result, unsupported value, attribute truncation, find truncation,
unattributable instance, continuity loss, state refusal, stale result,
conflict, result-protocol-unavailable, pending-result-unavailable and drain
loss. Omission that affects semantic coverage forces semantic `PARTIAL` and
the overall documented
coverage verdict; an unsupported attribute is an explicit unknown, never a
value. Attribution-relevant loss invalidates joins before subsequent use.
Unlocalizable loss invalidates all live semantic associations. Saturation is
visible and never wraps into a clean verdict.

One immutable sanitized projection supplies versioned inventory JSON, JSONL
and the dashboard. Public data may contain capture-local IDs, finite labels,
known/unknown/conflict and lifetime states, observation timestamps, roles,
existing function/return/mechanism provenance, and bounded counters. It must
not contain IPs, raw handles, result pointers, attribute pointers, private
epoch keys or address-derived hashes. Apart from the inventory caller
identity row below, this extension adds no raw PID/TID, path, caller-name or
command-line serialization authority to any surface.
Existing output-specific rules still govern existing fields. In particular,
this proposal does not extend v1's trace PID/TID exception.

The profile-v3 and trace schemas gain no object fields by this proposal alone.
Any future projection there requires its own coordinated schema review. An
inventory implementation must document its additive instance/object fields
in [inventory v1](../schema/inventory-v1.md) and
[inventory events v1](../schema/inventory-events-v1.md), including unknown
states, references, budgets and stream-loss behavior, before enabling them.
The `evidence.object_capture` build-availability field (`available`, with a
finite `reason`) is the only object-related addition outside inventory: a
build fact, not an observed attribute. The owner decided (2026-10-24,
decision I1) that these reads stay enabled in FULL builds in `profile`,
`trace` and `run` captures with `--manifest`. Those commands publish no
object facts; the validated tail is discarded after record validation.

Observed attribute values live only on these surfaces, with these lifetimes:

| Surface | What is retained | Lifetime |
| --- | --- | --- |
| Kernel `OBJECT_START` rows | At most 16,384 rows of 432 B: finite codes plus the Get template base, header-end and value pointers and capacity | Zeroed and deleted on every terminal path |
| Kernel EVENTS ring | Tail records (616 B with header) | Stay in the 4 MiB ring until overwritten |
| Observer memory | The validated tail (no Debug/Serialize) until ordinary decode or registry apply; the model holds at most 65,536 objects with six requested and six established fixed slots each | The capture's lifetime |
| Public inventory | Only `p11scope/inventory/v1` `object_observations` (objects requested, established, queries and label; key operations metadata at use) and inventory event kinds `object_observed`, `key_operations_observed` and `snapshot.object_observations` | The existing report-file and bounded event-file rotation lifetimes |
| Dashboard | Aggregate counts only | The rendered view |
| Never | Profile, trace, metrics, inspect, diagnostics, diff, logs or errors carry no object facts. Doctor and `evidence.object_capture` carry only the build fact | — |

## Inventory caller identity (owner ruling FB-PRIV)

**Status: PROPOSED row; records the owner ruling of 2026-10-03.** It adds no
capture: every field comes from `/proc` reads the inventory scan lane
already makes, and it changes no v1/v2 exclusion (trace, profile and
inspect outputs are untouched).

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Inventory caller `pid`, `start_time`, `image.exe` (`dev`, `ino`, `mtime_secs`, `mtime_nanos`, `path`) | `/proc/<pid>/stat` starttime and the `/proc/<pid>/exe` link (readlink plus stat) of a process whose maps hold an admitted provider object, read by the scan lane at admission and revalidation. No `cmdline`, `environ`, argument or memory read, and no retained or published `comm` (start-time sampling reads the whole stat line and parses around the comm field, discarding it). The native lane adds none: CALLER_USE rows bind through a pidfd TASK_COOKIE query, and their kernel tgid is never published. | Public per caller incarnation in `p11scope/inventory/v1` (`callers[]`), the inventory event stream's caller records, and the inventory dashboard/pager. PIDs are in the observer's `/proc` numbering (`pid_namespace`). `gaps[].pid` repeats the `/proc` pid of the caller or admission subject a gap names; no native witness gap carries a row's kernel tgid. | An unreadable value is `null`, never guessed. The path is the exe link observed at admission, not identity: incarnation identity is the pidfd/start-time pin plus `dev`/`ino`/`mtime`. Documented in [inventory v1](../schema/inventory-v1.md#privacy). |

**Status of the row below: IMPLEMENTED on this branch per owner ruling
D-C7-1 (2026-10-05); the controller shows this final text to the owner
before merge.** It adds no target-memory or argument capture: the only
new kernel-side state is the per-pair entry counter BPF already keeps.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Per-edge entry count and last activity (C7 C4) | The uprobe firing on an admitted endpoint, counted in BPF against the existing CALLER_USE key for the (caller image, provider object) pair. No target-memory read and no argument read. Each row carries the BPF entry timestamp of its first record (`recorded_at_ns`, kernel monotonic clock), published as `first_ns`; `last_seen_ns` remains derived in userspace from the read instant. | Public per (caller incarnation × module) edge in `p11scope/inventory/v1` (`edges[].entries`: saturating lower-bound `count` of entries on attached endpoints since the pair's first record, including calls that returned errors, with `last_seen_ns` at pass resolution), the inventory event stream's `edge_observed` records, and the inventory dashboard/pager. Never per function, per thread, or per call time. A pair with no row reads `unknown (uncounted)` and names the `PairInsertFailure` evidence, never 0. | A count read mid-capture is a lower bound; only the post-stop read is final, and settlement stays `unsettled`. An unreadable health cell withholds watches without inventing counts. Documented in [inventory v1](../schema/inventory-v1.md) (`edges[].entries.coverage`) and [inventory events v1](../schema/inventory-events-v1.md) (`edge_observed`). |

## Inline inventory identity (P5U, 2026-10-09)

**Status: IMPLEMENTED inline re-projection; root reviewed the concrete
amendment on 2026-10-09 before publication activation. Installed-file and
privacy qualification remain separate gates.**
This placement and retention amendment reprojects only inventory caller and
module identity already retained in one immutable `Presentation` revision.
It authorizes no additional collection, `/proc` lookup, target-memory or
argument read. The caller authority and observer `/proc` PID numbering remain
those of the inventory caller row above; `scan_pinned` never becomes
`native_exact`. Capture-local IDs remain the join keys, never names or paths.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| `edge_observed.identity_context` | Only the same immutable publication revision's referenced caller/module records; no late PID lookup. `version: 1`; `caller` contains exactly `id`, `pid`, `incarnation`, `start_time`, `authority`, `lifecycle`, `executable`, `status`. A non-null `executable` contains exactly `dev`, `ino`, `mtime_secs`, `mtime_nanos`, `path`. `module` contains exactly `id`, `device_major`, `device_minor`, `inode`, `path`, `status`. | One compact context in the edge's own JSONL record, for the existing bounded event-file rotation/retention lifetime only. One observed UTF-8 path per subject, at most 4096 bytes before escaping; module path is the lexicographically first retained path. No path array or duplicated full caller/module record. Total encoded context is at most 65536 bytes. | Subject `status` is exactly `observed`, `unavailable`, `path_budget`, or `context_budget`. Missing referenced records retain their capture-local ID with every other subject field null and status `unavailable`. An absent executable/path is null and unavailable. An overlong path becomes null with `path_budget`; physical metadata remains. Encoded overflow retains IDs only, nulls all other fields and sets both statuses to `context_budget`. Exact key-set and forbidden-neighbor controls run through real commit, stop and sweep; actual rotation/ended accounting includes context bytes. |
| `caller_event.identity_context` | Same revision and caller projection as above. `version: 1`; admitted/exited records contain `caller`; exec-retired/reused records contain `old` and `new`, matching their existing capture-local references. | The context accompanies the turnover record, including retirement; lifecycle describes that revision only. `admit_failed` retains its existing PID/reason/budget shape with no identity context or invented incarnation. The same path/context bounds and bounded file lifetime apply. | Missing old/new/caller records stay explicitly unavailable. Tests require nonempty expected executable positives, old/new preservation, metadata-only changes and queued reversion under the existing per-pass cap. |

Earlier records are observations of their own revision; a retained suffix does
not establish complete capture history or a later final state. Missing
`started`/`ended`, eviction, a partial last line, or nonzero `edges_unretained`
retain their existing incomplete-history meaning. Contextless older records
require their matching snapshot for names; consumers must not guess. Counts
remain cumulative lower bounds and successive records must never be summed.

This amendment publishes no command line, arguments, environment, `comm`, raw
native tgid, task cookie or exec ID, hash/build ID, module admission reasons or
history, semantic subtree, or object graph. It adds no other mode or unbounded
history retention. V1/v2 bytes and exclusions and the offline comparison
amendment below remain unchanged. Installed/privacy qualification remains a
separate gate; a source-level producer test is not an installed-file receipt.

## Offline inventory diff re-projection

`p11scope inventory diff` reads two explicitly supplied saved
`p11scope/inventory/v1` files as an ordinary user. Its
[inventory-diff v1 report](../schema/inventory-diff-v1.md) reprojects only
already-published inventory fields. It performs no target-memory or argument
read, live process lookup, provider loading, or new capture. This section
adds no permission to any live observer, decoder, profile, metrics, trace,
inventory producer or kernel map. V1/v2 exclusions remain unchanged.

| Field | Source, authority and validation | Retention and public output | Failure and evidence boundary |
| --- | --- | --- | --- |
| Offline inventory comparison | Exact saved inventory v1 schema, bounded JSON and resolved same-input caller/module references; no additional authority inferred from file contents. | Per-side scope/clock/window, PID-namespace labels, budgets/refusals, loss/gap evidence; pooled caller PID/start/executable path and file metadata/lifecycle; pooled module recorded paths/device/inode/digest/build ID/admission/lifecycle/unbound-use; pooled physical-edge mapping/entry count/coverage and semantic-availability label. Report-local numeric references, occurrence/population lists, shared executable-path dictionary, content/path/application presence and change codes, summary counts and limitations are derived from those fields only. | Malformed shapes/references and exceeded limits fail. Unknown additive data is bounded and ignored, never copied to output. Unknown labels/units remain unknown. Validate staged installed offline behavior separately from input capture provenance and live capture qualification. |

The [schema's field inventory](../schema/inventory-diff-v1.md#evidence-pools-and-references)
defines the precise output projection. Input caller/module IDs, incarnation,
task cookies and exec IDs are not output identities. Detailed mechanism and
operation values, additive load-instance and semantic-edge data,
`object_observations` rows, and arbitrary
unknown subtrees are not copied into the report. Recorded paths and allowed
free-text evidence remain input facts; a saved file does not authorize new
reads or establish that the application called a provider. Text/diagnostics
escape controls; JSON preserves decoded input strings through JSON escaping.

Every count and clock belongs to its own observation window; no counter delta
or host/boot/process/physical continuity is inferred. Missing observations do
not prove removal or inactivity, and unknown scope completeness remains
explicit. This re-projection introduces no host ID, boot ID, machine ID,
executable hash, command line, argument, buffer, handle, or raw address capture.
Its output remains subject to the input publication's privacy contract; it is
not a secret scrubber for fabricated or otherwise untrusted saved input.

## Trace executable labels (P5U, 2026-10-09)

**Status: IMPLEMENTED in accepted v0.4 development source by reviewed U2b
producer/consumer, renderer and parser integration (2026-10-09). This status
permits only the bounded trace publication below. Installed named-trace scope
qualification remains open, including the cgroup P4 installed checks;
source acceptance does not qualify a release or installed scope coverage.**

This section permits only bounded executable labels in trace text, including
`p11scope trace`, `run --trace`, stdout and their existing file copies. It does
not authorize names or raw PIDs in profile/metrics, and grants no inspect or
inventory authority. An executable basename is a label of an observed path,
not a desktop application, script name, package, service or trust identity.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Trace executable observed path and derived basename | The private same-Session `VerifiedTraceSeed`, minted by the Detailed producer from an already admitted original ProcessView and retained pidfd. For PID/system, a bounded before/after executable/start-time/pin sample precedes the eligible authentic CALL. Exact original-pidfd TASK_COOKIE confirmation, authenticated same-object EVENTS/DISCOVERY domains and strictly later complete lifecycle drain and healthy counter-read starts settle that exact `(domain, task cookie, exec_id)`. A cookie read alone, ProcessKey alone, launch path, inventory row, renderer assertion or late PID lookup supplies no authority. | Only already history-admitted completed call rows in existing bounded trace text/stdout/file output. Lookup requires event completion CLOCK_MONOTONIC `ts_ns` strictly greater than immutable `eligible_after_ns = max(sample completion, validated exec coverage start)`. The path is at most 4096 UTF-8 bytes before escaping; basename derives from that path, preserving an observed deleted marker. Quote and escape both; no terminal controls. Internal `dev`, `ino`, `mtime_secs`, `mtime_nanos`, start-time validation, cookie, domain and exec ID are never added to output. | Missing proof renders the exact Unknown executable form with existing diagnostic PID/TID. Finite private lookup reasons are NotSeeded, AfterEvent, ExecChanged, LifecycleLoss, DomainMismatch, NamespaceMismatch, TargetGone, Unreadable, ProofPending and Budget. These reasons add no trace evidence field. Wrong Session/domain, invalid clock, namespace disagreement, lifecycle loss, conflicting image, invalid history or insufficient budget cannot publish a name. Meaningful production-store/reducer tests and installed nonempty named positives plus zero-false-name controls are mandatory. |

Producer sample attempts may read only the original admitted task's exe link
and existing filesystem identity, start time and retained-pin/namespace/cookie
validation facts. Failed or deferred partial samples are discarded within the
same shared accounting. No command line, argument, environment, secret,
provider-memory or new kernel capture/query is introduced, and no `comm` is
retained or published (start-time sampling reads the whole stat line and
parses around the comm field, discarding it). Rendering performs
no I/O and holds only an already decided borrowed view.

The whole bridge shares one Session-owned ceiling of 16384 charged entries
across pending candidates, accepted labels and retained reason/interest state,
and 8 MiB of owned path capacity including temporary sample work. It permits
one owned path per accepted image, no uncharged candidate/reason cache and no
copied pidfd. Sampling uses existing original view/FD reservations. Rejection
or capacity pressure cannot change event/count admission. Refused proof remains
unknown; no event is buffered, reordered, or later rewritten for naming.

Accepted labels remain immutable capture-local historical facts while their
charged receipt remains retained. They may name delayed events only if the
existing historical reducer still accepts the exact image and its event time
passes the boundary. Exit/liveness loss does not move the name to a successor;
closed/older history remains rejected. Equal basenames/paths never merge keys
or counts. An accepted-key duplicate cannot move eligibility backward. Receipt
teardown releases its one reservation and any bounded nonowning aliases outside
ledger locks; retained files obey the existing output lifetime and permissions.

The reviewed cgroup producer uses the separate
[sample-attempt authority below](#p4-cgroup-trace-sample-attempt-authority).
It samples an already admitted original task after one authentic CALL and proves
its historical image with a second same-key post-sample CALL. Pending or refused
proof remains unknown; this method does not infer continuous cgroup membership.
Installed named coverage remains an open required release obligation.

In selected sessions only, the kernel gate additionally compares the calling
task's leader process id, exec id and task cookie against the published
target; a cgroup-migrate hook reads only the migrating task's process id to
invalidate a stale target; and a bounded task iterator publishes one
bootstrap row per selected target to the selecting session. The gate and
migrate values are checked and discarded; the bootstrap row is kept for
the selecting session only. None reaches public output.

V1/v2 bytes/exclusions, U5 inline inventory identity and offline inventory diff
remain unchanged. Source acceptance and permission to publish these fields do
not establish installed scope coverage or complete named-trace qualification.

## P4 cgroup trace sample-attempt authority

**Status: IMPLEMENTED in reviewed v0.4 development source. Installed positive,
negative, privacy, resource and stop checks remain open.** This addition
reconciles the reviewed U2b/P4 two-CALL method with the trace section above.
It preserves that section's
PID/system method, private finite reasons and exact Unknown executable output;
it adds no reason field.

The accepted trace section remains the publication contract. This cgroup
supplement describes the accepted producer and attempt authority. Required
installed checks remain separate; source acceptance does not close P4/U2b
qualification. All current U4/U5, trace and other
v3 sections and all v1/v2 exclusions remain unchanged. This is bounded Detailed
metadata sampling, including attempts that later fail proof, rather than only
saved-output re-projection.

| Field | Source, authority and validation | Retention and public output | Failure and evidence boundary |
| --- | --- | --- | --- |
| Cgroup trace observed executable path/basename; finite private unknown reason | Existing scoped discovery admission supplies an original still-admitted ProcessView and live pidfd. The Detailed producer may attempt bounded `/proc/<pid>/exe` stat/readlink for only `path`, `dev`, `ino`, `mtime_secs`, `mtime_nanos`, with existing original-generation/start-time/namespace checks. PID/system preserves the accepted A sequence: sample under the original admitted view before an eligible authentic CALL witness, then confirm the witness task cookie through the original live pidfd and require the later complete lifecycle/health horizons. This row adds no pre-sample TASK_COOKIE check to PID/system. For cgroup only, the first authentic scoped CALL precedes the sample, same-Session TASK_COOKIE validation through the original live pidfd occurs before and after the executable reads, and a second authentic same-Session exact-key CALL follows the complete validated sample under the documented conditional no-overflow/reset image model. The cgroup retained-task sample-attempt authority explicitly includes temporary movement outside the selected cgroup before ordinary view retirement and samples later discarded when proof fails. It selects no new process and adds no out-of-scope CALL/lifecycle capture or kernel query. No argv, cmdline, environ, argument, payload or new provider-memory read, and no retained or published `comm` (start-time sampling reads the whole stat line and parses around the comm field, discarding it). | Only bounded trace and `run --trace` text, including their stdout/file copies, after exact historical admission, verified receipt and strict event-time eligibility. Path/basename is an observed historical executable label, not current membership/executable or script/package/service identity. Dev/ino/mtime, start-time validation, opaque admission, domain/cookie/exec IDs and witness/sample timing remain private. No new profile/metrics or terminal trace-evidence field. One shared 16384-entry/8-MiB path/work pool includes pending registrations, failed/accepted metadata and all temporary path copies; 16384 work bytes are charged before a sample and shrink to the one retained <=4096 UTF-8-byte path before escaping. No extra FD or event queue. For cgroup only, await-first registration has a fixed 60-second lease; its candidate deadline is separately fixed 60 seconds from first sample-start, with checked arithmetic and earlier view/capture/stop bounds. Cgroup permits at most two transaction starts: one initial attempt and one restart solely for a budget-deferred incomplete sample, never for an actual validation failure. Cgroup failed sample bytes are discarded; its finite parked failure metadata uses the same charge until expiry or earlier cancellation. PID/system retains accepted A pending-sample and retry rules. Accepted historical labels retain the ordinary bounded capture/store lifetime. | Failure or missing proof is finite unknown; no label can be guessed, backdated, reassigned to a successor, published before proof or applied to an already emitted line. Original admission cancellation, historical rejection, later complete-cursor/health checks and saturation/refusal rules remain binding. For cgroup, only the exact-image bracket is claimed, never continuous residency. Required installed controls include positive named calls; same-path/different-path/nonleader exec, PID reuse, leave/exec/re-enter, allowed sample during temporary nonresidency, delayed/old/equal-time witnesses, later exec after the bracket, lost/busy/malformed/unreadable/exhausted health, fixed expiry/retry/fairness, shared capacity, output parity and bounded stop. Unknown-only output cannot close P4/U2b. |

The cross-command output specification defines the precise producer protocol.
For the cgroup method, an equivalent scan, an old/replayed CALL or a saved
executable path grants no new sample authority. A cgroup sample after expiry
requires a fresh charged registration under the still-admitted original view
and a newly produced CALL strictly after that registration. Actual authoritative view retirement ends
live sampling. Accepted old-image facts can remain only for events still
accepted by existing historical reduction. No inventory or offline-diff row is
reused as permission for this trace sampling/publication.

The retained EVENTS domain and task cookie must be nonzero; exec ID zero is
valid. Candidate registration completes at G before a first CALL produced at
T0 > G. Its copy R0 is valid and no earlier than T0; the first external sample
read starts at S0 > R0, and the second same-key CALL is produced at T1 > S1,
where S1 ends the complete sample, including both cookie/pin checks. Delayed
copies of pre-sample calls cannot provide the upper endpoint. Both later
complete-DISCOVERY and health-read starts must be strictly after the immutable
arm boundary max(R1, C1), where R1 is the upper CALL copy and C1 is the original
pidfd/cookie confirmation completion. All health/clock/custody checks remain.

An exec or competing image inside or at either bracket endpoint rejects pending
proof regardless of arrival order; ordinary later exec strictly after T1 may
coexist with the historical fact while the same original admission still holds.
Exit, task-cookie turnover or authoritative view removal cancels pending proof.
Accepted labels do not receive a 60-second TTL. One nonowning admission-interest
alias/request bit is charged to the accepted receipt; repetitions of its key
cause no new sample. A differing newer CALL can request fair re-registration,
but its own copy precedes the new G and cannot arm that new candidate. Alias
teardown follows the original reservation/drop discipline, with no second pool.

All cgroup phases share the existing 5-ms/32-visit/32-external-read frame ticket;
saved traversals yield after at most eight visited slots per phase. No terminal
service registers, samples or restarts a candidate, waits for another CALL, or
renews the single remaining stop ticket. Deadline equality expires a candidate;
an overlong syscall supplies no permission for another read or late promotion.

## Inventory diagnostics (v0.4)

**Status: Implemented in v0.4 development source.** This section permits only the
separate opt-in `inventory --diagnostics` JSONL file. It does not change native
attribution, capture scope, public inventory coverage or the event-log schema.

- Export actual native count observations, ownership transitions, staging and
  publication decisions, withholding/refusal reasons and capture health. Copy
  existing count/base/range values, read PRE/POST intervals, fences and retained
  decision context at their production source; unavailable context stays unknown.
  Do not reconstruct an earlier observation from a later maximum or claim that
  a staged count was published.
- Reuse retained inventory caller/module IDs, PID/incarnation, executable and
  module paths. Labels are escaped and limited to 96 input bytes each. Export
  never reads `/proc`, loads a provider or reads target memory. No command line,
  arguments, environment, PIN, payload, key material or new BPF data is added.
- Raw native domain, cookie, exec and object keys remain private in memory.
  Pair/read/epoch/pending references use capture-local surrogates scoped to their
  actual source. Equal raw integers do not join unrelated sources. Missing
  predecessors remain `not_retained`/unknown, with incomplete history disclosed.
- Two bounded rings retain recent observations: at most 24,576 ordinary and
  8,192 exceptional records. Requested recorder storage, export indexes and
  scratch are bounded by 16 MiB; this is not a total-process RSS limit. Fixed
  coordinator bookkeeping is accounted separately. Export is at most 64 MiB,
  with data lines at most 1,800 bytes. Filtering, eviction and diagnostic loss
  are separate from capture loss and do not change coverage or count decisions.
- Export after capture stops, using the existing private 0600 atomic-file
  output contract. Reject stdout, pipes, devices, symlinks and report/event-log
  aliases; preserve an existing destination if delivery fails. Files are
  optional debugging output and have no mandatory archival or retention rule.

The [diagnostics schema](../schema/inventory-diagnostics-v1.md) describes the
projection and footer. A complete file can contain incomplete history; neither
the file nor its diagnostic arithmetic proves exact whole-workload counts.
The existing v1/v2 exclusions and other v3 sections remain unchanged.

## Required evidence before activation

Every lane binds the exact source, BPF object, observer binary, target ABI,
kernel, owned workload and independent completion ledger. Existing v1/v2
canaries remain mandatory. Extend [the canary driver](../../scripts/verify-canaries.sh)
and its scanner rather than weakening previous checks. Test LP64 and ia32;
scan JSON, JSONL including rotations, dashboard/trace/profile artifacts where
produced, stdout/stderr/debug/error paths, and every map owned by the exact
observer. No unrelated process or map is a substitute.

| Evidence | Required positive and negative controls |
| --- | --- |
| C1 — field custody | Place unique addresses/handles in every authorized position and forbidden neighbor. Prove addresses exist only in their exact private in-flight/join cells and handles only in designated call/binding cells; prove cleanup after return, failure, loss and teardown. Descriptor-specific index 7 positive controls plus every other function's 7 and all 8/9 negatives. Failed/overflowing and page-straddling LP64/ia32 reads. |
| C2 — instance authority | Same-file `dlmopen` siblings with overlapping handles separate; same-object repeated `dlopen` remains one while proven continuous. Same-address unload/reload, missing loader notification, direct remap, wrong image, stale scan, range ambiguity and in-progress mutation never join old state. |
| C3 — object lifetime | Every named create family, including the four permitted scalar-result derive mechanisms; ignored `phKey` cells containing nonzero sentinels on successful SSL3/TLS12/WTLS key-material/PRF and unknown mechanisms must not be retained/read or create result identities. Changed/missing return mechanism likewise refuses the result. Distinct pair members and partial pair-read failure; caller/session/token/instance/lifetime collisions, failed destroy, mid-lifetime attach, shared access, creator/accessing close, logout, finalize, token epoch, exec/fork/unload and stale completion. Successful null-mechanism Init cancellation with an unrelated key makes no object/access/key-use claim. Compare an independent workload ledger; object age is never invented. |
| C4 — find bounds | Zero through eight, nine and huge count/capacity; returned count exceeding entry capacity, changed count, null/aliasing pointers, unreadable element and full-span overflow. No arbitrary array retention and no exhaustive-result claim after truncation. |
| C5 — safe values | Positive exact classes/types, AES-128/256, selected RSA size and every listed curve. Check request/result separation, key-pair template separation, no labels from mechanism alone, unknown type/size and finite-value conflicts. |
| C6 — hostile attributes | Secret sentinels behind excluded selectors, `CKA_ID`, labels, values, modulus buffers and arbitrary DER; malformed lengths, unsupported words, null/size-only, unavailable, partial error, retries, changed headers, capacity growth, duplicate conflicts and overlapping buffers. For every accepted selector, scalar value, exact length and derive mechanism ID, reject the value ORed with `1 << 16` and `1 << 32` before any narrowing; cover representable LP64/ia32 inputs and out-of-range classifier inputs. Recognized-value aliases may disclose only the finite permitted classification with honest provenance. |
| C7 — bounds and loss | In-flight and userspace caps, ring/state/update failures, dropped lifecycle, out-of-order/concurrent operations, unknown loss scope, eviction, saturated epochs/counters, slow output and incomplete shutdown. Measure allocated/occupied bytes and ensure invalidation precedes reuse. |
| C8 — public delivery | The installed `p11scope inventory` command with explicit operator semantics, real owned provider calls and independently recorded operations populates the same facts in JSON and JSONL; the dashboard shows aggregate counts derived from the same revision. Withheld semantics preserves count-only inventory; mixed authorized/refused providers stay visible. Harness-only results do not close this gate. |

An internal exception is **field-specific**: canary scanners must validate the
exact map type, field offset, current owner and authorized protocol value.
They must not suppress a sentinel globally because it also occurs in an
allowed handle field. An alias to arbitrary readable memory can place one
opaque returned word in that permitted private handle cell; this proposal
expressly accepts that narrow internal exposure and forbids its propagation
elsewhere. Unauthorized selectors, attribute payload bytes and buffers have
no such exception. Every scanner needs a nonempty must-detect positive
control, including a leak in a neighboring or public field.

PINs, usernames, labels, `CKA_ID`/`CKA_UNIQUE_ID`, key values, public modulus
buffers, EC points, arbitrary DER, application payloads, signatures, wrapped
blobs, random output and operation-state contents remain prohibited. There
is no pre-collection for a later `CKA_ID` feature and no unsafe decoder
activation. A new field, read site, broader set, longer retention or wider
output needs a new explicit review.

## Inspect presentation identity (P5U, 2026-10-09)

This amendment authorizes only scan-local executable presentation in
`p11scope/inspect/v1`, `p11scope/inspect-system/v1` and their text detail.
It adds no call-derived identity, provider-memory capture or output authority
for profile, metrics or trace. V1 and v2 remain byte-for-byte unchanged.

| Field | Source and validation | Output/retention | Failure |
| --- | --- | --- | --- |
| Inspect `application`: observed executable `path`, `dev`, `ino`, `mtime_secs`, `mtime_nanos`, retained `start_time`, finite identity `status` | New private validated application receipt from BOTH PID and system deep-scan producers: executable and fresh start-time samples before scan and after scan/provider pinning agree while the SAME original ProcessView pin holds. Retained pin start-time is also checked. MapsMatched instead consumes the separately confirmed SweptMember through its dedicated producer adapter. Raw ProcessRecord.generation.exe and pidfd liveness alone grant no publication. No cmdline, environ, argument or extra memory read, and no retained or published comm (start-time sampling reads the whole stat line and parses around the comm field, discarding it). | Additive root application/application_status in inspect v1 and per-process application/application_status in inspect-system v1, plus their text detail. Existing PID numbering/references persist. Application contains exactly path/dev/ino/mtime_secs/mtime_nanos/start_time/status; successful status is observed. Retain only this completed scan's fact; render without live lookup or late repair. | Null application and finite application_status: unavailable, changed, lost or not_examined. Scanned/MemoryUnavailable may name only after successful receipt and completed mapping scan; Unreadable/Exited/NotSelected stay unknown. MapsMatched uses confirmed attribution only. A receipt rejection withholds names without reclassifying provider mappings. |

The path is an observed executable-link label, including a retained deleted
marker, not a service/package/script or trust identity. Text escapes controls,
shows basename before PID and full path/physical details; equal display labels
never merge records. Mapped-only means no activity was captured by inspect.
Unchanged-image re-exec, including A-to-B-to-A between samples, is a documented
scan limitation. These receipts provide no trace-event naming authority.

## Object producer activation (H7 slice D, 2026-10-14)

**Status: IMPLEMENTED the reviewed finite producer; H8 journal/bootstrap
and H9 model delivery remain open, and no public object field carries
observed data** (`object_observations` is emitted only as an explicit
unavailable marker while H9 is open). This amendment records the reviewed read sites, retention
and honesty rules for the activated lane only. Every other section
keeps its own status; v1/v2 bytes are unchanged.

The lane is the operator-attested allowlisted Detailed lane: BPF sets
the required-object marker only under the allowlisted policy flag with
an exact frozen descriptor row and attachment admission, and userspace
decodes 608-byte records only against the receipt-bound frozen table
(`Session::start_attested` refuses the session unless the live
`OBJECT_DESCRIPTORS` readback is exactly canonical). All other lanes
stay 368-byte-only. The 16/32/36/240/432/608 B layouts are unchanged.

Reviewed read sites (each under the marker, the frozen row, the
accepted LP64/ia32 ABI, the live START owner and, for return reads,
the joined entry/return continuity):

- Entry input scalars and null-cancel (BPF `object_fill_entry`).
- Derive entry mechanism word plus arg 5 retention after exact
  four-member membership (BPF `object_entry_derive`).
- Result-pointer retention, with the named arg-7 stack word for
  pair-private/unwrap only (BPF `object_entry_results`).
- Find capacity scalar and count-pointer retention (BPF
  `object_entry_find`).
- Return result words at retained pointers with pair
  alias/duplicate/partial recomputed from retained pointers, and the
  Derive result gated on the full S1 return match
  (`MECHANISM_VALUE` exactly equal to the entry code) before any
  `phKey` read (BPF `object_fill_return`).
- Find count, at most eight elements and count reread, streamed into
  the reserved tail (BPF `object_emit_find`); the single-handle result
  cell carries the constant unavailable status, never the array base.

BPF performs no entry template inspection and no GetAttributeValue
protocol: those need 72–200 B helper frames the measured <=512 B
return chain cannot spare. Slice D therefore marks never-inspected lists honestly
instead of emitting fake inspected-empty lists: present request pairs
and the Get result list carry attribute-list flags bit 4
(`0x10`, uninspected), accepted by the validator only with zero cells,
zero inspected count and no inspected bits. Absent pairs stay
all-zero. The host protocol core keeps proving the full
template/Get/Find/pair protocols for a future budgeted increment; the
small BPF mirrors are reviewed against it.

Retention: one 432 B side row per in-flight required call (bounded by
`START_ENTRIES`, scrubbed and deleted on every terminal path); the
240 B tail rides the completed 608 B CALL record through the single
H3 cursor, collection, pending queue, owned routed call, move-only
evidence and the descriptor-bound admission result, and is dropped
unread at registry apply. No production disk, log, error, map-dump
or public output carries raw words; `ValidatedObjectCall`, the envelope, the
evidence and the admission result have no raw-value Debug/Serialize.
Ring records grow to 616 B with header for object CALLs only; the
4 MiB ring and all caps are unchanged. Measured 2026-10-15
(H7-E1–E3; default, small-state and wide-2112 objects): entry and
return chains stay <=512 B (roots 440/440 B;
`object_fill_return` 64 B and `object_emit_find` 56 B as leaves,
`object_tail_fill` 4 B over the single memset edge). Entry attribute
inspection stays out of budget on the attempted constructions
(measured stop, H7-E4): a one-slot retain probe fits (8 B), but the
alias-checked eight-slot protocol needs ~104 B live against the 32 B
left under the mandatory ia32 nesting, and object-phase scalar diet
frees nothing (the S1 phase owns the 440 B root). That figure is
estimated live state for the attempted single-program shape, not a
compiled full-protocol frame: it omits register allocation, value
lifetimes and staging, and it excludes neither an args-first
construction with a separate scanner sharing no nested chain with the
ia32 reader nor spill-reuse of scratch below the measured max frame.
The UNINSPECTED marking above therefore stands pending a budgeted E4,
and budgeted six-attribute capture remains an open requirement, not a
weakened one.

Required live qualification before release use: owned LP64/ia32
producer positives with independently expected nonempty facts,
selected 5.15 verifier/live ABI control, existing v1/v2 privacy
regressions, count-only/aggregate no-read twins, partial failures,
ring/map pressure and stop cleanup, through the `object-lp64` /
`object-ia32` canary cells. Any new read site, broader set, longer
retention or public projection needs a new explicit review.

## H7-E4 attribute capture (2026-10-20)

**Status: IMPLEMENTED in reviewed v0.4 development source (`3cd49af4`
on `feat/v040-h7e4-attributes`); APPROVED (owner decision OD11,
2026-10-24). The finite key-type numbers were corrected to the OASIS
values in `8d8c7422`. FULL builds perform the reads below; P0 builds
(`--no-default-features --features stub-object-attributes`) perform
none of them. The owner decision is not installed qualification: the
E5 cells below must pass on the matching candidate before release
notes claim FULL coverage. Public projection is governed by
[Object observations publication](#object-observations-publication-h9).**

The six-field reads require the `allowlisted` policy, an armed object
marker (a valid frozen `OBJECT_DESCRIPTORS` row) and a FULL build. The
marker is never armed under `aggregate-only`, under
`unsafe-unvalidated-metadata` or in the inventory count-only object. P0
arms it for the slice-D handle, Find and Derive-mechanism reads, but
performs no attribute read. P0 marks present lists `UNINSPECTED`, and
reports `evidence.object_capture = {available: false, reason: "not_enabled"}`.
FULL reports `available: true`, which is a build fact, not evidence that any
attribute was observed.

In FULL builds, for object-marked calls under `allowlisted`, `p11_entry`
performs the inspection described here for both LP64 and ia32 callers
(mixed-ABI root). (`p11_entry_ia32` exists only in
`unsafe-unvalidated-metadata` builds, where the entry roots split by ABI.)
This narrows v1's
structural statement at its "Structural enforcement" section; v1's
`walk_template` and its numeric template-type output remain
unsafe-diagnostic only, and v3 publishes no raw attribute type.

This amendment records the reviewed
attribute read sites, retention and honesty rules for the qualified
lane only, and supersedes slice D's no-inspection paragraph and
measured-stop paragraph for that lane. Every other section keeps its
own status; v1/v2 bytes are unchanged. Lane, admission and layouts are
unchanged: the operator-attested allowlisted Detailed lane, 608-byte
records only against the receipt-bound frozen table, and the
16/32/36/240/432/608 B layouts.

Reviewed read sites (each under the required-object marker, the exact
frozen descriptor row, the accepted LP64/ia32 ABI, the live START owner
and, for return reads, the joined entry/return continuity):

- Entry creation-template inspection (BPF `object_entry_attributes`,
  shared `inspect_request_template_into`): selector-first reads of at
  most eight slots per authorized pair (two pairs per call), bounded
  header-rescan alias checks against own and peer spans, one value read
  per eligible selected slot and a stable header recheck before
  publishing. Inspected lists land in the side row's request lists;
  refused or acquisition-failed pairs keep the honest UNINSPECTED
  marking. Unknown and excluded selectors authorize no pointer/length
  reads. C6 full-width/high-bit vectors refuse before narrowing.
- Get entry header retention (same level, shared
  `capture_get_entry_into`): at most eight selected headers retained
  into the side row's Get fields (base, header end, slots, inspected
  count); entry-list flags use private side bits 8-11, masked out of
  every public tail copy.
- Get return establishment (BPF `object_emit_get_attributes`, shared
  `capture_get_return_into`): accepted return values only
  (`CKR_OK`/`CKR_ATTRIBUTE_SENSITIVE`/`CKR_ATTRIBUTE_TYPE_INVALID`/
  `CKR_BUFFER_TOO_SMALL`), unchanged full-width selector/pointer,
  width-correct unavailable sentinel, returned length within retained
  entry capacity, span validation, retained-capacity alias checks, one
  value read and a header recheck per slot. Results stream into the
  reserved tail's result list; conflicting duplicates stay separate
  cells. Failed acquisition keeps the UNINSPECTED marking with zero
  reads.
- Refused Derive authorizes no template access: present pairs carry
  the UNINSPECTED marking (no fetch, no read, no result association),
  matching the oracle's `[None, None]` authorization. Accepted Derive
  inspects through the same creation protocol after the exact
  four-member mechanism membership and arg-5 retention.

No new read authority is introduced: every value read above was already
an approved v3 row (template pointer/count, selector, value pointer,
entry capacity/returned length, the six finite values); E4 activates
the BPF execution of those rows through the qualified shared protocol.
Retention is unchanged (one 432 B side row per in-flight required
call, scrubbed and deleted on every terminal path; the 240 B tail
rides the completed 608 B CALL record and is dropped unread at
registry apply). The closed six-field vocabulary, requested/result
separation and no-promotion rules are unchanged.

Honesty rules: an inspected list carries PRESENT plus its inspected
count and finite cells; a never-inspected authorized list carries the
UNINSPECTED marker only; descriptor-absent pairs and non-Get result
lists stay all-zero. An inspected count-0 template is a valid
inspected-empty list (inspection ran; zero slots is the true fact),
which the current Python canary oracle's template-family non-zero
rule does not yet distinguish from a never-inspected list; the
canary workload uses six-slot templates, and E5's ledger-aware
oracle refinement owns that distinction.

Historical engineering record, not a contract term — measured budgets
(default object at `3cd49af4`, rustc 1.98.1; frames gate
`object_producer_compiled_frames_are_bounded` green):

- Entry object path: 512 B exactly (root 192 + attributes level 264
  rounded to 288 + ia32 reader 32). Zero headroom: any entry-path
  growth breaks the gate. The attributes level holds 4,652 static
  instructions (inlined bounded scan; no nested BPF call besides the
  arg reader and map-row memsets).
- Return object path via Get emission: 448 B (root 32 + branch 160 +
  emission level 208 rounded to 224 + the emitted
  `object_emit_get_attributes` -> `memset` edge, 32 minimum;
  1,467 static instructions in the emission level). Still within
  the 512 B budget. Fill/tail/Find levels unchanged (64/32/64
  rounded).
- Exec/exit roots unchanged (128 B chains). Maps unchanged
  (`OBJECT_START` 16/432/16,384; `OBJECT_DESCRIPTORS` 4/16/105
  frozen; `OBJECT_ZERO` 4/432/1). Ring records stay 616 B with
  header for object CALLs; the 4 MiB ring and all caps unchanged.
- Small-state, small-ring and wide flavors change capacity consts
  only (identical entry/return code, same frames). Diagnostic
  (`unsafe-unvalidated-metadata`) template roots project to 512 B
  exactly (root 192 + the same 288 level + 32); the release matrix
  remeasures on its own build.
- Read cost per established attribute (single slot, identical
  LP64/ia32): scalar kinds 7 word-reads on request, 10 on Get;
  token/EC 6/9 word-reads plus one 1/7/10-byte read. Full
  eight-slot six-field call: 220 word + 4 byte-reads (request),
  76 word + 4 byte-reads (Get entry+return). These are
  single-template protocol costs: they exclude argument
  acquisition (two fetches per present pair, template pointer +
  count; on ia32 each fetch additionally reads an argument word)
  and, on request paths, the second template's peer rescans. A
  full two-template capture of eight-slot six-field templates
  costs 872 word-reads + 8 byte-reads; two all-scalar templates
  reach 880 word-reads.

Historical engineering record, not a contract term — host
qualification at `3cd49af4`: G05
`object_attributes_real_adapter_six_fields` and
`object_attributes_refuse_before_unsafe_read` green on LP64/ia32
(all six fields VALUE through the production adapters, pair
separation, no promotion, selector-first silence, finite
rejections, Set no-read); wired-marking/entry twins green
(acquisition-failure, refused/accepted Derive, truncation
privacy); owner-store, adapters, activation,
`p11scope-ebpf-common` and named frame/budget contracts green;
fmt and clippy-touched clean; kernel 7.0.0-38 verifier smoke
ACCEPTS the object load-only (no attach; not the 5.15
headroom cell). Live qualification remains E5's: owned LP64/ia32
producer positives with nonempty six-attribute facts, the selected
5.15 verifier/live ABI cell with >=5% processed-instruction
headroom, v1/v2 privacy regressions, count-only/aggregate no-read
twins, partial failures, ring/map pressure and stop cleanup
through the `object-lp64` / `object-ia32` canary cells.

## Object observations publication (H9)

**Status: APPROVED (owner decision OD11, 2026-10-24).** This section
scopes the public projection of the attribute values read under H7-E4;
it grants no read beyond that section.
The projection is exactly section version 1 of
[docs/schema/inventory-v1-object-observations.schema.json](../schema/inventory-v1-object-observations.schema.json):
`objects[].requested|established|queries|label` and
`key_operations[].metadata_at_use` in `p11scope/inventory/v1`
`object_observations`, the inventory event kinds `object_observed` and
`key_operations_observed` (plus `snapshot.object_observations` in
test/sync emission), and aggregate counts derived from the same revision
on the dashboard. Unknown, conflicting and invalidated states stay
explicit; profile, trace and metrics never carry object facts. The
unknown-bucket summaries never fabricate starts, and role rows cannot be
summed into a global operation denominator. Approval does not enable
delivery. While H9 delivery is gated, production captures carry
`object_observations` only as an explicit `unavailable` marker.

## DR04 caller metadata (2026-10-18)

**Status: opt-in implementation contract; installed qualification remains
open.** This subsection permits only the finite Inventory context below.
Every other section keeps its own status; v1/v2 bytes and exclusions are
unchanged, and there is no global v3 activation. Required real two-container,
two-pod, unavailable and migration acceptance is tracked separately.

When the operator explicitly opts in
(`inventory --caller-metadata=cgroup`, default `none`), the allowlisted
display context from retained `/proc`/cgroup filesystem observations is
exactly: finite cgroup2 directory inode plus capture-local
mount-context identifier, canonical 64-hex container ID, canonical
36-character pod UID, fixed parser/runtime/source/status enums,
observation times/revision and refresh/loss counters. New u64
identifiers, times and revisions travel as exact decimal strings so
values above 2^53 round-trip. Full cgroup paths, member names, labels,
service names, command line, environment, credentials and key material
stay private; no engine/CRI/Kubernetes API, network access, namespace
entry or new BPF target read is authorized. Metrics, profile and trace
gain nothing through this Inventory option, and the default capture
gains no new target-memory read.

Lexical container/pod hints carry provenance `cgroup_path_pattern` and
are display hints only: they never prove orchestrator ownership, never
authorize admission, scope, provider identity or counts, and never join
callers across captures. Numeric provenance stays withheld as
`namespace_unresolved` until a mount-proofed resolver proves the held
cgroup2 root and namespace-coordinate agreement. Missing, refused or
stale observations remain explicitly unknown/stale/historical, never
silent.

The systemd pod grammar accepts the exact `kubepods.slice` stem or the
exact `kubelet.slice/kubelet-kubepods.slice` stem. An optional burstable or
besteffort slice and the pod slice must use that same complete stem and
matching QoS. The pod UID uses the fixed underscore-separated UUID form;
the next component must be an exact recognized runtime container unit.
No generic prefix stripping or substring recognition is allowed. This adds
no public value beyond the canonical container ID and pod UID above.

The full64 native task/image checks bracket the two retained-original proc
reads. They reuse the Inventory identity-only query and add no application
argument/pointer reads. The expected image comes from a genuine native caller-use binding whose
admission follows the capture's coverage start; pre-coverage, unbound, changed
or unprovable callers remain unknown. A scan-based CallerRecord is never
upgraded to native admission authority by this display proof or a later query. Equal membership endpoints remain `endpoint_sample_only`;
A-to-B-to-A excursions are not excluded. Raw membership is temporary private
scratch, zeroed/discarded on job completion. One cancellable worker,4096 retained
caller slots,64 starts/100ms,25ms cooperative job budget,1s target refresh and
10s staleness bound apply. The independent8MiB allocation ceiling includes
actual old/new immutable frame overlap and retained job/completion ownership.
Cancellation cannot preempt a blocked kernel operation; its owned job retains
original custody and reservations until it actually returns and joins.

## Extensive-mode executable dependency hints (6.14 Option B, D-transitive)

**Status: APPROVED (owner ratification 2026-10-29, batch item 5,
merged P5 text, branch D-transitive; the D-direct branch was
considered and not ratified).** The rows below are additive in v3
and precede any B1 capture code. Default capture is OFF
(`--track-short-lived`, extensive mode); allowlist-v1 is unchanged.
Option A (kernel exit summaries) needs no decision here and is
unaffected. All numbers are the ratified initial bounds, stated in
these rows themselves.

**Row A — Executable identity (extensive mode only).** At
`sched_process_exec` the kernel reads `current->mm->exe_file`'s
`(dev, ino)` (kernel file metadata only; no path, argv,
environment, or user-memory read) into the exec record, only in
builds/captures with extensive mode armed. With the flag off, no
exe `(dev, ino)` is recorded anywhere, including counters and
aggregates — not "captured but unclassified." Any exit↔exec join
reuses the existing (domain, ticket) discipline, never bare PID.
Userspace resolves `(dev, ino)` to a path only from paths already
learned by live scans of observed processes (never a `/proc` walk
of dead PIDs, never a filesystem search), re-opens that path, and
requires `fstat` `(dev, ino)` equality with the recorded pair,
else `unknown`. The opened FD's `(dev, ino, size, mtime(sec,nsec),
ctime(sec,nsec))` are rechecked for stability around parsing,
within one identity domain (domains never interchanged,
`identity.rs` map-files/pinned/probe rules); any change →
`unknown`. Retention: private capture-local identity/cache tuples
only; analysis FDs closed on completion/refusal. No executable
path, inode, digest, cookie, or exec sequence is ever published.

**Row B — Static metadata (span-bounded reader only).** Only ELF
identification/header, program headers, `PT_DYNAMIC`,
`DT_NEEDED`, and the bounded dynamic string-table spans needed to
read them. The whole-file path is forbidden for never-admitted
executables: no whole-file retention or snapshot reuse. Raw
names/bytes are transient probe/userspace scratch, discarded
after classification; only finite verdicts (Row C) are retained.
No provider execution, no arbitrary section inspection, no
symbol-table classification of unpinned files. The provider test
is exact string equality of a `DT_NEEDED` name to the SONAME (or
basename if no SONAME) of this capture's *pinned watched-provider*
objects — pinned objects already carry held-file evidence, so
SONAME equality to them is the complete test; equality to anything
else, including provider-looking unpinned files, proves nothing
here.

**Row C — Hint result (finite, scoped, never a verdict).** The
only published values are per-gap classification counts in
{`links_provider`, `links_pkcs11_loader`,
`no_static_link_within_scope`, `unknown`}, where the loader
vocabulary is exactly one SONAME, `libp11-kit.so.0` (no extensible
loader list). Every publication is labelled **STATIC HINT**
including its depth/budget scope (Row D branch). A positive is
complete when its witnessing needed-entry (D-transitive:
witnessing chain) was fully read within budget; a negative is
complete only when the entire in-scope needed set was examined;
anything else — over-budget, unresolved, malformed, changed,
unreadable, kernel-thread/zombie shape — is `unknown`, never a
partial hint presented as complete and never truncation to a
verdict. A hint is never a call, never a conformance or
provider-free verdict, and is never merged into observed-call or
caller-attribution shares (shares-unchanged twin required).
Absence of a hint excludes nothing: `dlopen`-only, private, and
sparse provider use are invisible by design and stay honestly
`no_static_link_within_scope`/`unknown`. Cache hits require
current same-file proof (Row A recheck) and supply no birth,
admission, or absence authority. New wire fields/validators
require coordinated producer/consumer/schema review.

**Row D — Bounds (agreed core).** At most **1 MiB examined per
executable analysis** and **64 MiB examined per capture**,
charging every ELF/program/dynamic/string span read including
duplicates and failed parses, within existing capture
work/deadline limits (no limit waived for hints). Name strings
longer than 255 bytes → `unknown`. Retention beyond Row C counts:
none — `(dev, ino)`→path cache and all ELF bytes are
capture-end-discarded scratch.

**Row D — Depth + counts (ratified branch D-transitive).**
Executable at depth 0, `DT_NEEDED` followed through depth 2; at
most 32 ELF objects and 128 dependency edges per analysis; at
most 1,024 retained verdict-cache entries per capture; needed
names resolve *only* against pinned watched-object paths and the
scan-learned path cache inside retained custody — no
RUNPATH/LD search, no filesystem walks (an unresolved branch voids
only the negative, per Row C).

**Implementation notes (narrowing, not broadening).** The kernel
word is the raw `s_dev` (`dev_t`), never a userspace `st_dev`:
userspace decodes the kernel kdev_t `(major, minor)` pair and
compares it against `makedev`-reconstructed `fstat` identity, the
same decode the watched-file calibration uses. A zero ticket
never seeds the exe-identity stash, and a stash entry is consumed
at most once, in timestamp order; the live-comparison half of the
ticket discipline is inapplicable to dead processes, so PID reuse
under ring loss remains a documented residual — one reason the
output is a hint, never evidence. Likewise a file replaced or
modified between exec and analysis keeps its `(dev, ino)` while
changing content; the stability recheck defeats racing
modification, not earlier replacement. The scan-learned path
cache keeps at most 4,096 entries (no-retain-when-full); the
verdict cache stores size/mtime/ctime beside each verdict and a
hit requires all-fields equality. This packet arms Detailed
captures only (profile/trace/run); inventory arming is a
follow-up, and inventory captures keep no exe identity.
