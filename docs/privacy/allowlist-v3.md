<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Privacy allowlist v3 — PROPOSED object and attribute extension

**Status: PROPOSED; pending independent privacy and implementation review,
except [Inventory caller identity](#inventory-caller-identity-owner-ruling-fb-priv),
which is IMPLEMENTED in v0.2.0 by owner ruling FB-PRIV (2026-10-03).**
Apart from that one section, this document does not enable capture, describe
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
| `CKA_VALUE_LEN` | Exact selector 0x0161; one target word equal to 16, 24 or 32 only. | Finite byte-size code; label as AES 128/192/256 bits only with independently established AES type for established metadata, or requested AES type for requested metadata. | Other values unknown; no `CKA_VALUE` read and no inference from mechanism alone. C5/C6. |
| `CKA_MODULUS_BITS` | Exact selector 0x0121; one target word equal to a selected RSA size below. | Finite size code; RSA label requires matching RSA type/provenance. | Other values unknown; no modulus or exponent buffer read. C5/C6. |
| `CKA_EC_PARAMS` | Exact selector 0x0180; exact length 7 or 10 and byte-for-byte equality to one complete encoding below. At most ten bytes in probe scratch. | Only curve enum; discard scratch bytes immediately, including recognized encoding. Curve label requires matching EC type/provenance. | No hash-only, prefix, permissive DER, explicit-parameter or arbitrary-string fallback. C5/C6. |
| Public identities and derived facts | Monotonic capture-local allocation plus accepted reducer transitions; never raw handle, IP or digest of either. | `instance#N`, `sess#N`, `object#N`; finite origin/lifecycle/metadata states, times within observation, and saturating counts. JSON, JSONL and dashboard use the same immutable projection. | Allocation exhaustion refuses new association, records loss, and never reuses an ID. C3/C7/C8. |

## Finite attribute vocabulary

The selected constants are a deliberately small subset of the pinned
[pkcs11-types object definitions](https://github.com/mingulov/pkcs11-components/blob/d0a47c71d34294466bc41100ae6b5a5a329029d2/crates/types/src/object.rs)
and [attribute definitions](https://github.com/mingulov/pkcs11-components/blob/d0a47c71d34294466bc41100ae6b5a5a329029d2/crates/types/src/attribute.rs).
These sets are closed; support for another standard or vendor value requires
a reviewed policy change, not numeric passthrough.

| Field | Exact accepted values and labels |
| --- | --- |
| Class | 0 `data`, 1 `certificate`, 2 `public_key`, 3 `private_key`, 4 `secret_key` |
| Key type | 0x00 `rsa`, 0x01 `dsa`, 0x02 `dh`, 0x03 `ec`, 0x04 `x9_42_dh`, 0x10 `generic_secret`, 0x1f `aes`, 0x3a `ec_edwards`, 0x3b `ec_montgomery` |
| Token flag | 0 `session`, 1 `token` |
| AES byte sizes | 16, 24, 32, presented as 128, 192, 256 bits with the type guard |
| RSA bit sizes | 1024, 2048, 3072, 4096, 8192; an observer support set, not a cryptographic-strength recommendation |
| EC curve | `secp256r1`: `06 08 2a 86 48 ce 3d 03 01 07`; `secp384r1`: `06 05 2b 81 04 00 22`; `secp521r1`: `06 05 2b 81 04 00 23` |

The curve identifiers follow [RFC 5480 section 2.1.1.1](https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1.1.1);
the complete DER octets above are the observer's exact equality set. Edwards
and Montgomery key-type labels do not authorize curve decoding for those
types. Unsupported sizes/curves stay unknown rather than weakening the
finite set. The AES byte-size policy follows the 128/192/256-bit key sizes in
[FIPS 197](https://doi.org/10.6028/NIST.FIPS.197-upd1).

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
   null entry pointer is size-only even if the return header changes it.
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
association as unknown. Class/type contradictions invalidate the combined
key label. No default token/session classification is assumed.

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

Kernel metadata read transiently by the hooks and never stored except as
the counters above: `vm_file`, `f_inode`, `i_ino`, `i_sb->s_dev`, `vm_mm`,
`mm_users`, `current->mm`, `group_leader`, `clone_flags`. No syscall
argument, user address or length, target memory, or kernel pointer is
captured or emitted.

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

## Inventory caller identity (owner ruling FB-PRIV)

**Status: PROPOSED row; records the owner ruling of 2026-10-03.** It adds no
capture: every field comes from `/proc` reads the inventory scan lane
already makes, and it changes no v1/v2 exclusion (trace, profile and
inspect outputs are untouched).

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Inventory caller `pid`, `start_time`, `image.exe` (`dev`, `ino`, `mtime_secs`, `mtime_nanos`, `path`) | `/proc/<pid>/stat` starttime and the `/proc/<pid>/exe` link (readlink plus stat) of a process whose maps hold an admitted provider object, read by the scan lane at admission and revalidation. No `cmdline`, `environ`, `comm`, argument or memory read. The native lane adds none: CALLER_USE rows bind through a pidfd TASK_COOKIE query, and their kernel tgid is never published. | Public per caller incarnation in `p11scope/inventory/v1` (`callers[]`), the inventory event stream's caller records, and the inventory dashboard/pager. PIDs are in the observer's `/proc` numbering (`pid_namespace`). `gaps[].pid` repeats the `/proc` pid of the caller or admission subject a gap names; no native witness gap carries a row's kernel tgid. | An unreadable value is `null`, never guessed. The path is the exe link observed at admission, not identity: incarnation identity is the pidfd/start-time pin plus `dev`/`ino`/`mtime`. Documented in [inventory v1](../schema/inventory-v1.md#privacy). |

**Status of the row below: IMPLEMENTED on this branch per owner ruling
D-C7-1 (2026-10-05); the controller shows this final text to the owner
before merge.** It adds no target-memory or argument capture: the only
new kernel-side state is the per-pair entry counter BPF already keeps.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Per-edge entry count and last activity (C7 C4) | The uprobe firing on an admitted endpoint, counted in BPF against the existing CALLER_USE key for the (caller image, provider object) pair. No target-memory read, no argument read, no BPF timestamp: recency is derived in userspace from the read instant. | Public per (caller incarnation × module) edge in `p11scope/inventory/v1` (`edges[].entries`: saturating lower-bound `count` of entries on attached endpoints since the pair's first record, including calls that returned errors, with `last_seen_ns` at pass resolution), the inventory event stream's `edge_observed` records, and the inventory dashboard/pager. Never per function, per thread, or per call time. A pair with no row reads `unknown (uncounted)` and names the `PairInsertFailure` evidence, never 0. | A count read mid-capture is a lower bound; only the post-stop read is final, and settlement stays `unsettled`. An unreadable health cell withholds watches without inventing counts. Documented in [inventory v1](../schema/inventory-v1.md) (`edges[].entries.coverage`) and [inventory events v1](../schema/inventory-events-v1.md) (`edge_observed`). |

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
| C8 — public delivery | The installed `p11scope inventory` command with explicit operator semantics, real owned provider calls and independently recorded operations populates the same facts in JSON, JSONL and PTY dashboard. Withheld semantics preserves count-only inventory; mixed authorized/refused providers stay visible. Harness-only results do not close this gate. |

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
