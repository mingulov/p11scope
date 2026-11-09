<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
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
and [DR04 caller metadata](#dr04-caller-metadata-2026-10-18), whose opt-in source contract is described below and whose installed qualification passed on Fedora 7.2 with Docker, synthetic pod cgroups and real kind pods watched from the host in v0.7.0 (in-node kind cells blocked: nested-observer cgroup refusal and unbound system passes; migration acceptance remains open; tracked separately),
and [object producer activation](#object-producer-activation-h7-slice-d-2026-10-14),
which implements the reviewed finite producer below with no public
object projection,
and [H7-E4 attribute capture](#h7-e4-attribute-capture-2026-10-20):
the H7-E4 read set, the six attribute rows (seven with F16), the finite vocabulary,
the GetAttributeValue result rules, the output/retention table and
the [H9 publication section](#object-observations-publication-h9) are
APPROVED (owner decision OD11, 2026-10-24),
and [extensive-mode executable dependency hints](#extensive-mode-executable-dependency-hints-614-option-b-d-transitive),
which implements the ratified D-transitive hint contract below, as
widened by 7.10b,
and [unregistered mechanism id publication](#unregistered-mechanism-id-publication-owner-2026-11-03),
which publishes unregistered mechanism ids with counts only,
and [pre-arm mapping-instant witness](#pre-arm-mapping-instant-witness-v060),
which loads the short-lived kernel witness behind `--prearm-module` and
publishes no new field,
and [reload-disclosure linkage publication](#reload-disclosure-linkage-publication-b17-leg-2-2026-11-04),
which names the `instance_reload_not_excluded` labels-and-counts projection,
and [gap-admission prefix publication](#gap-admission-prefix-publication-jk-22a),
which names the admitted-prefix counts in module gaps,
and [detach-quarantine refusal publication](#detach-quarantine-refusal-publication-ruling-jk-22a-2026-11-05),
which names refused slots with their recorded detach reason and no new capture,
and [unpublished mechanism approval count](#unpublished-mechanism-approval-count-ruling-jk-22a-2026-11-05),
which gaps shed approval ids by count only,
and [legacy collection gaps](#legacy-collection-gaps-v060),
which names the `legacy_collection` counts-and-reasons projection,
and [counter bank gaps](#counter-bank-gaps-v060),
which names the `bank_gaps` counts-and-flags projection,
and [derived count projections](#derived-count-projections-v060),
which are derived counts with no new capture,
and [PQC parameter-set metadata](#pqc-parameter-set-metadata-f16-2026-11-06),
which reads `CKA_PARAMETER_SET` with its PQC key-type qualifier and publishes
the finite eighteen-label vocabulary below,
and [per-provider mechanism counts](#per-provider-mechanism-counts-owner-ruling-kg-1kg-2-2026-11-03),
which partitions each mechanism row's calls/errors by provider module,
and [short-lived tracking widened to trace, metrics, `--pid` and owned run (7.10b)](#short-lived-tracking-widened-to-trace-metrics---pid-and-owned-run-710b),
which approves the widened read/retention contract below,
and [offline CBOM export re-projection](#offline-cbom-export-re-projection-v070),
which describes the implemented offline report and grants no capture authority,
and [app identity hints](#app-identity-hints-owner-ruling-2026-11-08),
whose status is privacy review accepted 2026-11-08; owner
approval/installed qualification pending,
and [copy-up layer publication](#copy-up-layer-publication-f11-2026-11-07),
which attributes a witness-proven pre-copy-up lower file as its own
module row with the finite `pre_copy_up` marker,
and [caller launcher chain](#caller-launcher-chain-v070),
which publishes the implemented per-caller parentage below,
and [pid-scope caller executable](#pid-scope-caller-executable-v070),
which names the pid-scope target exe in profile/metrics below,
and [foreign target root path in gap reasons](#foreign-target-root-path-in-gap-reasons-v070),
which documents the implemented chroot/container gap publication below; owner approval pending.**
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

Every new call-derived field requires all of: a function/offset claim with
semantic authority (below), its retained and unchanged physical provider pin,
one unambiguous named descriptor, an accepted LP64 or ia32 specialization,
exact process-image identity, and the matching owned entry/return lifetime. A
provider export, readable pointer, equal path/hash, scan result, or successful
return alone is insufficient. Ambiguous slots remain count-only.
Public inventory must retain modules and callers when semantics are withheld.

Semantic authority comes from exactly one of three sources:

- an operator-attested claim (`--manifest`), as before; or
- a scan-derived publication-proved claim, only in `inventory --key-operations`
  runs started without a manifest (the explicit key-operations opt-in), and
  only for a scanned function table that meets every condition: its
  publication is proved by standard interface linkage (`C_GetInterfaceList` /
  `C_GetInterface` naming the table) or by a live function-list return —
  export-name agreement alone never grants it; and
  every required key lives in the provider's own object (a provider whose
  table entries point into another object, such as the p11-kit trust shim,
  is refused). A non-full walk or an unpinned affecting entry refuses the
  provider whole; a rival, aliased or degraded entry, including one reached
  only through an exports-only table, stays count-only at that entry, with
  no argument reads there; or
- a scan-derived sole-complete-table claim, only in the same no-manifest
  `inventory --key-operations` opt-in, and only when every condition holds
  together: (a) at least one view's tables scan finished with no
  truncating skip, I/O ceiling, budget or table-cap stop on that module,
  proving the provider object holds exactly one function-table candidate
  — no rival, aliased or degraded second candidate (including no
  exports-only second table), every other view of the object agreeing,
  and no vendor or opaque interface claiming this table's layout; (b)
  that table's published walk is full with a
  version-consistent 2.x 68-slot layout (a 3.x label with a proven complete
  68-slot legacy prefix counts as full; any other walk, version or slot
  count refuses), with a complete export witness and no 3.x interface
  getter, and the table is file-backed with every retained entry agreeing
  with the object's exports; (c) every slot is either NULL (an
  unimplemented function, which gets no probe and no argument reads) or
  resolves to code inside the provider's own executable mapping, with
  every 2.x function with an object-capture descriptor (the 20 the decoder
  reads: `C_CreateObject`, `C_CopyObject`, `C_DestroyObject`,
  `C_GetObjectSize`, `C_GetAttributeValue`, `C_SetAttributeValue`,
  `C_FindObjects`, `C_EncryptInit`, `C_DecryptInit`, `C_DigestKey`,
  `C_SignInit`, `C_SignRecoverInit`, `C_VerifyInit`, `C_VerifyRecoverInit`,
  `C_GenerateKey`, `C_GenerateKeyPair`, `C_WrapKey`, `C_UnwrapKey`,
  `C_DeriveKey`, `C_SetOperationState`) non-NULL and in own code; (d) the
  object exports `C_GetFunctionList`; (e) the provider file has a single
  load in the process, not a proxy's multi-table closure array. A rival,
  aliased or degraded entry stays count-only at that entry, as above.
  Anything else stays refused as today.

Every other scan result, including every ordinary (non-`--key-operations`)
capture, stays count-only. The read set is the same in all sources: a
scan-derived claim never adds a field, an argument or a read beyond the rows
below; it only replaces the operator attestation as the source of the
function/offset claim, and the run discloses it as the
`semantic subset scan-derived` scope gap.

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

Amendment (packet 6.07c, owner P1 clause 2): extend the named
argument-7 exception to these two functions only — `C_EncapsulateKey`
and `C_DecapsulateKey` result pointers: LP64 entry-SP+16 or ia32
entry-SP+32, with complete-word bounds checks. The KEM rows below
carry no template authorization: template pointer/count scalars may
bound span guards, but no template header or value is read. No other
descriptor may request 7; indices 8 or higher remain forbidden.

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
| `C_EncapsulateKey` | encapsulation key 2 | out 7; only with a positively non-null entry ciphertext pointer | None (T0: no template read) |
| `C_DecapsulateKey` | decapsulation key 2 | out 7 | None (T0: no template read) |
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
[pkcs11-types mechanism catalog](https://github.com/mingulov/pkcs11-components/blob/v0.2.3/crates/types/src/mechanism_official.rs).

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
| Template pointer and count | Only the six template-authorized creation families above (KEM excluded under T0), or `C_GetAttributeValue` args 2/3; checked `count * 3W` span. Inspect first eight slots of each allowed template. | Request templates read at entry and discarded; GetAttribute headers retained only until matching return. Publish finite omission/read status, not raw count/pointer. | Overflow refuses decode; >8 records truncation; a failed header is unknown. Never recurse into array attributes. C1/C5/C6. |
| KEM template-header span scalars | `C_EncapsulateKey`/`C_DecapsulateKey` args 3/4 register words only: checked `count * 3W` span arithmetic to test disjointness from the result cell. No template header or value is read under T0. | Probe scratch during entry only; no retention, no publication. | Unreadable words, overflowing count, or an invalid/overlapping span withholds the result pointer (unavailable); over-cap counts guard by arithmetic alone. C1/C3. |
| KEM length-cell address | `C_EncapsulateKey` arg 6 register word only: one-word span guard against the result cell; the length value is never read. Decapsulation arg 6 is a scalar length value and is never consulted. | Probe scratch during entry only; no retention, no publication. | Unreadable address or an invalid/overlapping span withholds the result pointer; null has no span. C1/C3. |
| KEM ciphertext/result-span guard | `C_EncapsulateKey`/`C_DecapsulateKey` arg 5 register word only: the ciphertext base bounds a wholly-below ordering check against the result cell. No ciphertext byte, no length value, and no decapsulation scalar length is read or used as a bound. | Probe scratch during entry only; no retention, no publication. | Unreadable arg 5, equality/interior/at-or-above-base geometry, or a null contradicting the non-null S1 decision withholds the result pointer; a null decapsulation input has no span. C1/C3. |
| KEM entry ciphertext-pointer decision | The owned call's validated S1 entry output-pointer state (finite null/non-null/unreadable class, never an address) for `C_EncapsulateKey`: only a positively non-null decision authorizes result-pointer retention. | Decided at entry; retained as retained-vs-zero result pointer only, in the existing fixed side-row fields (no new retained KEM field). Public result-unavailable reason only. | Null or unavailable decision retains no pointer: zero result-cell reads, no output authority, no key-use count. S1 call accounting unchanged. C1/C3. |
| KEM capture flavor gate | FULL builds only (`KEM_CAPTURE_WIRED`); P0 refuses KEM input and result-pointer acquisition before any fetch. Clearing follows the existing result-pointer row: private in-flight state only, cleared on every terminal, loss, cancellation, exec or teardown path. | No KEM state exists in P0; FULL retains only the existing fixed side-row fields above. | P0 KEM calls stay S1-only with explicit unavailability. C1. |
| Attribute selector | Read just `CK_ATTRIBUTE.type` to test equality against the six identifiers below (seven with F16: plus `CKA_PARAMETER_SET`) before reading its pointer/length. | Retain a six-value selector enum only (seven with F16); unknown selectors are discarded without retaining their raw number or reading their pointer/length. | No new `CKA_ID` collection or pre-collection, including its value, length or pointer. C5/C6. |
| Attribute value pointer | Only after selector equality; GetAttribute retains entry pointer and compares returned header pointer before decode. | Private in-flight GetAttribute slots only; request pointer is transient probe scratch. No pointer in result transport. | Null is size-only for GetAttribute, unavailable for requests; pointer/header changes or detectable overlap refuse the affected values. C1/C5/C6. |
| Attribute entry capacity / returned length | Read the named selector's `ulValueLen`; target word, exact accepted value size and full-span checks. GetAttribute retains capacity and reads returned length. | Private in-flight validation; only finite state such as `size_only`, `unavailable`, `invalid_length`, `changed`, `unreadable` is public. | Width-correct unavailable sentinel, growing length, zero/wrong length, insufficient entry capacity, read failure: no value read. C5/C6. |
| `CKA_CLASS` | Exact selector 0x0000; one target word, exact width, finite set below. | Six-field request/result snapshot (seven with F16); public finite class plus source/state. Raw unmatched word discarded in probe scratch. | Unsupported/conflicting value stays unknown. C5/C6. |
| `CKA_KEY_TYPE` | Exact selector 0x0100; one target word, exact width, finite set below. | As class, with finite key-type label. No vendor numeric fallback. | Unsupported/conflicting value stays unknown. C5/C6. |
| `CKA_TOKEN` | Exact selector 0x0001; exactly one byte and exact equality to 0 or 1. | Requested or established `session`/`token`, with provenance; only established result may drive object lifetime. | Other byte/length is unknown; a request is never promoted by CKR_OK creation alone. C3/C5/C6. |
| `CKA_VALUE_LEN` | Exact selector 0x0161; one target word equal to 16, 24 or 32 only. | Finite byte-size code; label as AES 128/192/256 bits only with independently established AES type for established metadata. | Other values unknown; no `CKA_VALUE` read and no inference from mechanism alone. C5/C6. |
| `CKA_MODULUS_BITS` | Exact selector 0x0121; one target word equal to a selected RSA size below. | Finite size code; RSA label requires matching RSA type/provenance. | Other values unknown; no modulus or exponent buffer read. C5/C6. |
| `CKA_EC_PARAMS` | Exact selector 0x0180; exact length 7 or 10 and byte-for-byte equality to one complete encoding below. At most ten bytes in probe scratch. | Only curve enum; scratch bytes never leave the probe's stack frame and are not copied to any map, record or output, including recognized encodings. The buffer is not explicitly zeroed. Curve label requires matching EC type/provenance. | No hash-only, prefix, permissive DER, explicit-parameter or arbitrary-string fallback. C5/C6. |
| Public identities and derived facts | Monotonic capture-local allocation plus accepted reducer transitions; never raw handle, IP or digest of either. | `instance#N`, `sess#N`, `object#N`; finite origin/lifecycle/metadata states, times within observation, and saturating counts. JSON, JSONL and dashboard use the same immutable projection. | Allocation exhaustion refuses new association, records loss, and never reuses an ID. C3/C7/C8. |
| Per-module `C_Initialize` roll-up | New aggregation over already-captured fields only: the attested slot name (`C_Initialize`, single-named, authorized, unambiguous probe) plus the verbatim return code, from joined and shed semantic Events since the lane sealed. No new capture: no argv, env, keys, PINs, payloads, handles or addresses are read or retained for this roll-up. | Saturating per-module counts (`calls`, `ok`, `already_initialized`), the last non-OK/non-already return as a `returns`-shaped row, and a finite status (`initialised`, `failed`, `unseen`, `unknown`) with its detail line, in JSON and verbose text. | The verdict fails closed: `unknown` when the lane never sealed or EVENTS loss (or an unreadable loss counter) may have hidden evidence; zero observed calls word the absence, never "never initialised". |

## Finite attribute vocabulary

Class and key-type numbers follow the OASIS PKCS #11 3.0 `pkcs11t.h`;
the three PQC key-type codes and the parameter-set selector and code
range follow PKCS #11 3.2.
pkcs11-types is not a source for this vocabulary (its `CkKeyType` table
misnumbered values from 0x27 upward before v0.2.3; the closed sets below
stay the authority). The selected attribute
selectors are a deliberately small subset of the pinned [pkcs11-types
attribute definitions](https://github.com/mingulov/pkcs11-components/blob/v0.2.3/crates/types/src/attribute.rs).
These sets are closed; support for another standard or vendor value requires
a reviewed policy change, not numeric passthrough.

| Field | Exact accepted values and labels |
| --- | --- |
| Class | 0 `data`, 1 `certificate`, 2 `public_key`, 3 `private_key`, 4 `secret_key` |
| Key type | 0x00 `rsa`, 0x01 `dsa`, 0x02 `dh`, 0x03 `ec`, 0x04 `x9_42_dh`, 0x10 `generic_secret`, 0x1f `aes`, 0x40 `ec_edwards`, 0x41 `ec_montgomery`; 0x49/0x4a/0x4b PQC qualifier (PKCS #11 3.2, no standalone label) |
| Parameter set | 1..=12, the `CKP_*` union across ML-DSA, ML-KEM and SLH-DSA (PKCS #11 3.2); uninterpretable without the same-view key type |
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

Only the observed result may establish the six fields (seven with F16). Incomplete, unsupported
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
from its existing initial-kernel TGID to its existing cookie. At the exec
mm switch, the `exec_mm_release` hook reads current TGID through the
existing PID helper, looks up this index and poisons the indexed record
before replacement. On 7.3+ the same invalidation runs at the `exec_mmap`
exit and reads only its int return, acting on 0.
This index supplies negative invalidation only: selected-task queries
freshly obtain TASK_COOKIE/self_exec_id and never consult it or repair
state. The hook reads no task-storage value, arguments or mm pointer.
The `copy_vma` exit reads only the returned new VMA pointer: the fixed
return slot on the 5-argument prototype, `bpf_get_func_ret` on 6/7-argument
prototypes. It reads the transient fields listed below and stores nothing
new.
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
is captured or emitted. The birth marker's exec-hook read of the group
leader's `self_exec_id` is covered separately in
[Post-attach birth marker](#post-attach-birth-marker-object-journal-slice-d).

The image query additionally reads the candidate task's flags word for the
kernel-thread bit; fork and exec maintain only the row's shared-memory mark
and attach generation; the calibration cell also carries the observer's own
calibration thread id and hit count. The flags word is checked and
discarded; none of these values is emitted.

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

## Post-attach birth marker (object journal slice D)

**Status: IMPLEMENTED in development for v0.6.0. FULL and P0 builds contain the
marker in their Detailed objects and the journal object by default. `P11SCOPE_BIRTH_MARKER=0` omits it
from the Detailed object only: the journal object always carries both marker writers and the
`self_exec_id` read, so only `P11SCOPE_JOURNAL=0` removes them there (it also omits the Detailed marker
unless `P11SCOPE_BIRTH_MARKER=1`). SMALL, WIDE and unsafe builds omit both by default.
`P11SCOPE_BIRTH_MARKER=1` compiles the marker into the Detailed object
of any build, SMALL, WIDE and unsafe builds included. The owner approved FULL/P0 inclusion (owner B2, 2026-11-01;
final yes/no at freeze). Shipping is gated on the live cells and the freeze decision.
The linked birth seals activate only when the user opts in to per-key tracking
(owner B1, 2026-11-01), with no new read.
No formal privacy sign-off before about v0.9 (OD25).** The opt-in is
`p11scope inventory --key-operations` (default off; selection ruling 2026-11-01).
What runs at this revision: only the journal object publishes an attach generation, and only under
`--key-operations`. The journal object carries both the READY exec writer and the DIRTY gap writer
(controller ruling WB-3), so post-closure execs in opted-in sessions publish READY and exec-marker
births can be minted. Under the opt-in, both exec-marker births and absence-then-appearance births
(the provider appears in the process after closure, with a committed negative witness) can be minted;
whether they mint at runtime is not yet measured live. Ordinary
sessions never get a generation, so the Detailed object's marker stays inactive: its hooks do one gated
read and return.
In a marker build, this adds state only in a lane Session that has published an attach generation
(closure): only an `inventory --key-operations` capture whose semantic lane seals over the loaded
journal pair publishes the attach generation — with `--manifest` over the attested subset, or without
one over the scan-derived subset under the conditions in "Authority and ABI rules". That Session runs the journal object, which carries
both the READY exec writer and the DIRTY gap writer, so the generation arms gap marking and exec-time
READY records. Ordinary captures seal with generation 0 and never touch the attach cell; their marker
hooks stop at the gated read. Under `--system` with the flag, records come from both writers: DIRTY
from the gap writer and READY from post-closure execs.
In a marker build, non-counter metrics, profile and trace Sessions load the same Detailed object
(counter-mode Sessions load counter objects), so the control map exists there,
zeroed and frozen, and the hooks do one gated read. The marker adds no state to them. Inventory and counter
objects do not contain the map. The journal object instead carries the control map with both the READY
publish body and the DIRTY gap writer (and its transient `self_exec_id` read at exec only), and its
control row is read back as zero and frozen before any link.
The journal object is reachable only through `inventory --key-operations`. v1 is unchanged; the v2 table
carries one row for this read beside the Exec task ticket row.

Kernel-side state, owned by the exact observer Session:
- The existing 8-byte `journal_bootstrap` word of the per-process `PROC_EPOCH` record (the record stays
  152 B). Its values: 0 (unmarked); 1 (DIRTY: the process ran a
  watched function while outside the selected scope, or a watched call of the process was not fully
  captured for any reason: refused scope or ABI, a lost identity, start record or ring slot, or a call
  abandoned at thread exit); or `(exec ID << 2) | 2` (READY: this image exec'd inside the selected scope
  after closure, and every watched call since was fully captured). The exec ID is the kernel's per-process
  `self_exec_id` counter, the same value the approved image identity already reads. It is not a PID, path or
  name.
- `JOURNAL_MARKER_CTL`: one 16-byte cell `{spent, failed}`, the marker admissions spent in this Session and
  a sticky failure latch. In a Detailed marker Session, userspace reads it back as zero and freezes it
  before any probe attaches, and never writes it. (The journal object's control row is likewise read back
  as zero and frozen before any link; see Status above.)

Writers, at exec, fork, first watched call or thread exit (before closure the exec and gap hooks each do
one array read and return; fork only zeroes the marker in fresh task storage):
- at `sched_process_exec` of an in-scope process: create the group leader's `PROC_EPOCH` record if it
  is absent, store the attach generation, and publish READY with the leader's `self_exec_id`; a DIRTY
  word stays DIRTY and spends no further admission (if the record had to be created first, that creation
  already spent one). This writer exists in both the Detailed marker object (which never runs with a
  published generation, so it stops at the gated read) and the journal object (which publishes READY
  after closure in opted-in sessions);
- at fork: nothing is inherited or published; the child starts unmarked in fresh task storage;
- when a watched call is not fully captured (entry or return refused for scope or ABI, an in-scope
  capture failure such as a lost identity, start record or ring slot, or a call abandoned at thread
  exit): create the group leader's record if it is absent, and store DIRTY. This reads no argument,
  user memory, exec ID, path or name of that process.

Under `--system` every process is in scope, so once a Session carries both a published generation and the
exec writer, every process that execs after closure gets a record holding its exec ID and the attach
generation. Only an opted-in journal Session (`inventory --key-operations`) publishes a generation, so
only such a Session writes these records. Ordinary Sessions never publish one: in a marker build their
Detailed object contains the exec writer, but it stops at the gated read and writes nothing.

New transient kernel read: the current group leader's `self_exec_id`, at exec only. It adds to the Stage A
list (`group_leader`, `flags`, `mm`).
Under `--pid` the same exec writer also reads the group leader's `start_boottime` (its thread-group
start time), after the generation and control gates and before any write, and compares it in kernel,
in USER_HZ ticks, with the target's start tick. Userspace reads that tick from the target's
`/proc/PID/stat` field 22 at scope publication (it must match the retained process pin when the
Session holds one) and publishes it into `PID_START_TICK`,
a read-only map of the PID-scope tgid and the tick (at most 1,024 entries, frozen before any link) beside
`PID_FILTER`, in both the Detailed marker object and the journal object. A missing entry, an
unreadable task or a different tick refuses the write: no record, no admission, no latch and no
`self_exec_id` read. Cgroup and system scopes skip the comparison. The start time is never stored in
the record, emitted or published; a reader whose time namespace offsets boottime refuses the PID-scope
session instead of publishing a tick the kernel cannot match.

Scope note: under `--cgroup`, a process outside the selected scope that calls a watched function gets a
record holding DIRTY (a record the gap creates holds only DIRTY and zero fields; a record Stage A created
first keeps its Stage A fields and gains DIRTY). Under `--pid` an outside process never reaches BPF, so it
gets no record from the marker, except a CLONE_VM sharer of the target (a vfork or posix_spawn child before it
execs) that calls a watched function: it is left not covered. Under the single-link backend the call
reaches BPF (the kernel filter compares only the mm), so the scope check refuses it and the gap marks the
row DIRTY, spending one admission; under the multi backend the kernel skips the call before BPF runs, so
the row stays unmarked. Neither path is yet verified live. (The CLONE_VM fork hook
already creates a shared-mm `PROC_EPOCH` row for such a child regardless of scope.)
`--pid` admits the exec hook by PID number, but the start-time comparison above means a different
process that later gets the same PID number and execs after closure gets no record and spends no
admission, under `--key-operations` too.
Stage A already keeps unscoped `PROC_EPOCH` records for processes that map a watched
provider file (see above), so this is not new in kind. It is never emitted, and it dies with the task.

Bounds: each record creation, or first marker write, spends one admission from a fixed per-Session budget
of 16,777,216, charged before allocation and never refunded. Exhaustion or a marker failure sets the latch,
except a task-storage NULL at exec, which only leaves that process unborn. After that, no process in the Session is reported as born, and API and S1 counts continue with a
named loss. Live memory is bounded by live tasks: records are task storage and die with the task or the Session.
TBD: the per-record kernel memory cost above the 152 B payload (estimated at about 0.4-0.5 KB per record);
decided by measured task-storage accounting on a target kernel.

Linked birth seals (owner B1): key-operation rows are born only when the user opts in to per-key tracking;
otherwise the seals stay off and marker state alone mints no birth. Each seal re-checks fresh evidence —
the image pair, the read-back marker word, the admission latch, pidfd custody and the attach generation —
against the attested grant, and adds no read beyond the ratified set above. The seal path keeps two bounded
private capture-lifetime userspace copies (`src/semantics_objects/journal.rs`), released at capture teardown
and never published: `SessionBirthEvidence` (the image cookie/exec pair, the marker word, the admission
failure state, the attach generation and custody) and `SessionBirthGrant` (the domain proof, the birth kind,
the birth cut, the closure generation, the bundled evidence and the optional stream binding). Their raw-value
`Debug` output must be redacted before activation. Both exec-marker births and absence-then-appearance
births can be minted under the opt-in (see Status above); whether they mint at runtime is not yet
measured live.

Output: nothing new is emitted. The marker only decides whether a process's key operations are reported as
complete or withheld with a finite `joint_birth_native_<reason>`. No argv, environment, PIN, key, payload or
raw buffer is read or kept, and no pointer is retained or emitted.

## Bounds, loss and output

Proposed ceilings are eight inspected attributes per template, at most two
templates per call, six classified fields per metadata snapshot (seven with F16), ten curve
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
apply. Six requested and six established attribute facts per object
(seven with F16) are fixed slots, not unbounded histories. Pending
joins are capped at 1,024 calls;
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
| Observer memory | The validated tail (no Debug/Serialize) until ordinary decode or registry apply; the model holds at most 65,536 objects with six requested and six established fixed slots each (seven with F16) | The capture's lifetime |
| Public inventory | Only `p11scope/inventory/v1` `object_observations` (objects requested, established, queries and label; key operations metadata at use) and inventory event kinds `object_observed`, `key_operations_observed` and `snapshot.object_observations` | The existing report-file and bounded event-file rotation lifetimes; the `--event-log -` stdout transport carries the same records under the same limits, never rotated, with retention set by the receiving pipeline and no p11scope lifetime bound |
| Dashboard | Aggregate counts only | The rendered view |
| Never | Profile, trace, metrics, inspect, diagnostics, diff, logs or errors carry no object facts. Doctor and `evidence.object_capture` carry only the build fact | — |

## Inventory caller identity (owner ruling FB-PRIV)

**Status: PROPOSED row; records the owner ruling of 2026-10-03.** It adds no
capture: every field comes from `/proc` reads the inventory scan lane
already makes, and it changes no v1/v2 exclusion (trace, profile and
inspect outputs are untouched).

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Inventory caller `pid`, `start_time`, `image.exe` (`dev`, `ino`, `mtime_secs`, `mtime_nanos`, `path`) | `/proc/<pid>/stat` starttime and the `/proc/<pid>/exe` link (readlink plus stat) of a process whose maps hold an admitted provider object, read by the scan lane at admission and revalidation. No `cmdline`, `environ`, argument or memory read, and no retained or published `comm` (start-time sampling reads the whole stat line and parses around the comm field, discarding it). The native lane publishes a kernel tgid only for unidentified caller images (row below): CALLER_USE rows bind through a pidfd TASK_COOKIE query, and a bound row's kernel tgid is never published. | Public per caller incarnation in `p11scope/inventory/v1` (`callers[]`), the inventory event stream's caller records, and the inventory dashboard/pager. PIDs are in the observer's `/proc` numbering (`pid_namespace`). `gaps[].pid` repeats the `/proc` pid of the caller or admission subject a gap names; no native witness gap carries a row's kernel tgid. | An unreadable value is `null`, never guessed. The path is the exe link observed at admission, not identity: incarnation identity is the pidfd/start-time pin plus `dev`/`ino`/`mtime`. Documented in [inventory v1](../schema/inventory-v1.md#privacy). |

## Unidentified caller host pids (owner ruling 2026-11-07)

**Status: IMPLEMENTED on this branch per the owner ruling of
2026-11-07 ("if there is no more info than pid - then why not to
show it").** It adds no `/proc` read and no name/argv/env capture:
the only new state is the per-image (tgid, first-call) retention
beside the slice-1 image sets, in the same bounds.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Unidentified caller image host `pid_host` and `first_call_ns` | The kernel tgid in host (init-namespace) numbering, with the row's first-association instant, of a CALLER_USE row the binder could not bind to any caller incarnation — read from the row already in hand. No `/proc` read for these numbers themselves: no name, no cmdline/environ, no argument or memory read. (Executable naming under the next row reads `/proc` for its own sources; the numbers stay unread.) Equal numbers across images are pid reuse, not identity. | Public per module in `p11scope/inventory/v1` (`modules[].unbound_use.pids`, complete while `pids_dropped` is zero), up to five on the concise `unidentified callers` line, all collected on the verbose `host pids` line. Bounded (4096 per module, 16384 run-wide; LIM-1, never lowered); saturation counts, never refuses. | Historical only, always qualified (`not running now or never scanned`): a listed pid is never the process now holding that number, and a live different process at that pid is not described. Documented in [inventory v1](../schema/inventory-v1.md#privacy). |

## Unidentified caller executables (owner ruling 2026-11-07)

**Status: IMPLEMENTED on this branch per the owner ruling of
2026-11-07 ("really no way to get executable which did the
call?").** It adds a kernel exe-identity read at exec plus three
narrowly scoped userspace resolution sources, each confirmed by
matching `(dev, ino)` in the mapped-device domain (a private
one-page mapping read back from the observer's own maps) — never by
stat alone. No argv, environ, key, PIN, payload, `comm`, cwd, or
cmdline is read or published; allowlist v1 is byte-identical.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Unidentified caller image executable (`exe`, `dev: {major, minor}`, `ino`, `resolution`, `identity_ambiguous`, `identity_candidates`) | The kernel `(s_dev, i_ino)` of `current->mm->exe_file`, read at exec into the EXEC record's pointer word when a Callers-flavor inventory capture outside PID scope arms the exe-identity bit (the Detailed extensive bit, accepted beside one inventory scope; no new BPF state, and no arming where the EXEC carries no joinable ticket). Userspace joins the exact (domain, ticket) pair against the row's (domain, cookie) — never a bare PID — and resolves the pair to a path, in order: (a) a live `/proc/<pid>/exe` whose start time predates the EXEC — the starttime from `/proc/<pid>/stat` (the whole line is read; the start field is parsed around the comm field, which is discarded, never retained or published), the exe link text, the exe mtime, and the mapped `(dev, ino)` from opening `/proc/<pid>/exe` itself (never the readlink target) — refused under pidns mismatch, incomparable clocks, or boottime skew, and no other reads (no cwd, cmdline, environ, content, or `comm`); (b) an exe identity the scan already learned from an admitted caller (the learned path re-probed through the sticky per-path cache: once per distinct path per capture); (c) a lazy, bounded, cached index of the fixed system binary dirs (`/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/bin`, `/sbin`, `/usr/libexec` plus one level below it — never the user's PATH or environment), same-ino candidates confirmed one by one at lookup; else (d) unknown with its reason. Every candidate is confirmed by mapping it privately and reading the mapping's `(dev, ino)` back from the observer's own maps — the mapped-device domain the kernel pair lives in — never by stat alone (btrfs subvolumes report stat devices that differ from mapped devices). The mapped page is never touched: no file content, argument, or environment is read. Publication decodes the kernel word to `{major, minor}` through the shared kdev decode, like `modules[].identity.device` — never the raw word and never the stat-domain `callers[].image.exe.dev`. | Public per module in `p11scope/inventory/v1` (`modules[].unbound_use.executables`, one complete record per collected image in pid order while `pids_dropped` is zero), grouped with call counts on the concise `unidentified executables` line (five groups, five host pids each, the rest counted; an ambiguous group keeps the executable name first with the candidates' full paths beside it, `name (ambiguous: /path/a, /path/b)`), and with `dev major:minor`/`ino`/source/first-call on the verbose per-module line (plus every other verified spelling when ambiguous). When two or more distinct canonical paths verify to one pair the record keeps its path with `identity_ambiguous: true` and the sorted `identity_candidates` list; no new read — the same (b)/(c) candidates, all verified. Bounded (EXEC stash 16384, exe-probe cache 4096, system index 65536; LIM-1, never lowered); shed EXEC records latch domain loss and saturation counts, never refuse. | Each image reads its resolution or its reason: `exec_record_lost` (counted) when lifecycle evidence was lost in its domain, `no_exec_record` when the exec predates the capture, the image is a fork child that never exec'd, or the ticket was unavailable, `exe_unavailable` when the kernel read failed, `path_unknown` when no source names the pair (deleted file, container overlay, or a binary outside the system index). A listed pid never names the live process now holding that number: the generation check refuses PID reuse, and a re-exec keeps its ticket with the latest EXEC winning the pair. Documented in [inventory v1](../schema/inventory-v1.md#privacy). |

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
| `edge_observed.identity_context` | Only the same immutable publication revision's referenced caller/module records; no late PID lookup. `version: 1`; `caller` contains exactly `id`, `pid`, `incarnation`, `start_time`, `authority`, `lifecycle`, `executable`, `status`. A non-null `executable` contains exactly `dev`, `ino`, `mtime_secs`, `mtime_nanos`, `path`. `module` contains exactly `id`, `device_major`, `device_minor`, `inode`, `path`, `status`. | One compact context in the edge's own JSONL record, for the existing bounded event-file rotation/retention lifetime, or for the `--event-log -` stdout transport (same records and limits, never rotated, retention set by the receiving pipeline with no p11scope lifetime bound). One observed UTF-8 path per subject, at most 4096 bytes before escaping; module path is the lexicographically first retained path. No path array or duplicated full caller/module record. Total encoded context is at most 65536 bytes. | Subject `status` is exactly `observed`, `unavailable`, `path_budget`, or `context_budget`. Missing referenced records retain their capture-local ID with every other subject field null and status `unavailable`. An absent executable/path is null and unavailable. An overlong path becomes null with `path_budget`; physical metadata remains. Encoded overflow retains IDs only, nulls all other fields and sets both statuses to `context_budget`. Exact key-set and forbidden-neighbor controls run through real commit, stop and sweep; actual rotation/ended accounting includes context bytes. |
| `caller_event.identity_context` | Same revision and caller projection as above. `version: 1`; admitted/exited records contain `caller`; exec-retired/reused records contain `old` and `new`, matching their existing capture-local references. | The context accompanies the turnover record, including retirement; lifecycle describes that revision only. `admit_failed` retains its existing PID/reason/budget shape with no identity context or invented incarnation. The same path/context bounds apply, with the bounded file lifetime for event files and, for the `--event-log -` stdout transport, the same records and limits, never rotated, with retention set by the receiving pipeline and no p11scope lifetime bound. | Missing old/new/caller records stay explicitly unavailable. Tests require nonempty expected executable positives, old/new preservation, metadata-only changes and queued reversion under the existing per-pass cap. |

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
| C2 — instance authority | Same-file `dlmopen` siblings with overlapping handles separate; same-object repeated `dlopen` remains one while proven continuous. Same-address unload/reload, missing loader notification, direct remap, wrong image, stale scan, range ambiguity and in-progress mutation never join old state. One named exception (JK-16): after a fault era raised for skipped mapping hooks, a load whose ranges and local epoch match its previous observation (with no proven absence and no unrecorded hook event since) reuses its instance row, marked uncertain; a same-address reload hidden by the skip itself merges into that row. |
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

**Status: IMPLEMENTED the reviewed finite producer. H8 journal transactions and linked birth seals are
contained in v0.6.0 FULL/P0 builds (owner B2 approved inclusion, final at freeze; shipping is gated on
the live cells and the freeze decision) and activate only under the per-key-tracking opt-in
`inventory --key-operations` (the
post-attach birth marker read and retention is described in
[Post-attach birth marker](#post-attach-birth-marker-object-journal-slice-d)).
H9 model delivery remains open. No public object field carries observed data**
(`object_observations` is emitted only as an explicit unavailable marker while H9 is open). This amendment
records the reviewed read sites, retention
and honesty rules for the activated lane only. Every other section
keeps its own status; v1 bytes are unchanged (v2 carries the one marker row beside the Exec task ticket row).

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

Packet 6.07c KEM reads are FULL-only: P0 acquires nothing for KEM —
the KEM adapter refuses input and result-pointer acquisition before
any fetch (the attribute stub alone does not cover them, so the KEM
adapter carries its own `KEM_CAPTURE_WIRED` gate). P0 KEM calls stay
S1-only with explicit unavailability; FULL KEM capture follows the D1
rows above.

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

## Not-attributed key-operation counters (owner ruling JK-22, 2026-11-05)

**Status: APPROVED by owner ruling JK-22 (2026-11-05).** This section
scopes section version 3 of
[docs/schema/inventory-v1-object-observations-v3.schema.json](../schema/inventory-v1-object-observations-v3.schema.json):
the `object_observations.unattributed` counters and their aggregate
rendering on the text `key operations:` line. It grants no read: every
count derives from counters the observer already retains for its own
accounting (staged-call disposal, fallback replay, unsealable-shape
refusal, direct reduction without a witnessed birth, and pre-application
caller refusal). No target memory, argument, template, handle, label,
PIN or payload is read or published for these rows; `CKA_ID`, object
handles and labels remain excluded exactly as above.

Each row is exactly one finite reason name and one saturating count of
calls that carry no per-key row because no key could be proved:

| Reason | What the count means |
| --- | --- |
| `started_before_attach` | Direct reductions on a feed registered without a witnessed birth (attach after start, or the birth race). Proved-irrelevant info calls are not key operations and never count. |
| `record_lost` | Staged calls disposed once as history after bounded loss, plus direct reductions in the degraded window after such a loss ended a segment, before its next clean point. |
| `foreign_or_unproven_caller` | Calls refused before application for an unproven or unbound caller. |
| `session_state_lost` | Reserved: calls whose session state was lost before a clean point. |
| `watchdog_no_progress` | Staged calls left unsealed when the named no-progress watchdog trip ended the lane (finish or running audit), snapshotted once at the trip. |
| `unmodelled_call_shape` | Affecting calls the frozen endpoint table cannot seal, reduced S1-direct. Proved-irrelevant info calls are not key operations and never count. |
| `proof_refused_fallback` | Staged calls a proof-only or ordered fallback replayed S1-direct without object proof, plus direct reductions in the degraded window after such a fallback ended a segment, before its next clean point. |

Attributed rows beside these counters stay exact: the certainty bar for
attributing an operation to a key is unchanged, and no counter is ever
converted into a guessed key row. The key is present exactly when the
section version is 3, which is exactly when at least one count is
nonzero; fully attributed publications stay byte-stable at versions 1
and 2. Profile, trace and metrics never carry these counters.

## Unknown-metadata key rows (owner ruling DEMO-4, 2026-11-05)

**Status: APPROVED by owner ruling DEMO-4 (2026-11-05).** This section
scopes section version 4 of
[docs/schema/inventory-v1-object-observations-v4.schema.json](../schema/inventory-v1-object-observations-v4.schema.json):
one additional finite `metadata_at_use` label, `unknown`, on a per-key
row whose object the model first observed in the observed window
(the key's creation or lookup predates attach) and whose type/size
were never established by an already-observed attribute call. The
label states an absence of already-held facts only: it grants no
read, derives from the object's existing first-observed origin and
its empty established metadata, and never guesses a type or size.
If a later already-observed `C_GetAttributeValue` establishes the
type, later uses row under their exact label; earlier uses are never
backfilled. No `CKA_ID`, object handle, label, PIN or payload is read
or published for these rows. Version 4 is present exactly when such
a row exists; versions 1, 2 and 3 stay frozen and byte-stable.

## PQC parameter-set metadata (F16, 2026-11-06)

**Status: IMPLEMENTED in v0.7.0 by owner decision 2026-11-06 evening
(release lane F16), overriding the v0.7.0 "no new captured field"
non-goal for this one field only; Opus privacy second-tier review
follows. The approving capture contract is the owner-approved
v0.7.0 PQC capture contract (plan item 7.05a).** This section scopes
section version 5 of
[docs/schema/inventory-v1-object-observations-v5.schema.json](../schema/inventory-v1-object-observations-v5.schema.json):
the two read rows below plus the finite eighteen-label publication.
It supersedes the M2 "no ML-KEM/PQC labels, vocabulary unchanged"
clause for parameter-set labels only; KEM T0 (no template read on
encapsulate/decapsulate), the terminal states and every other M2
behavior stay in force. Allowlist-v1 bytes are unchanged.

The observed value is a provider-reported attribute word from an
application buffer, not independent proof of a physical key's
properties. The `CKP_*` numbers overlap across families, so a label
always joins an established parameter-set code with the established
key type from the same object view; a code alone, a type alone, or a
recognized mechanism never labels.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| `CKA_PARAMETER_SET` (P1) | Exact selector 0x061d at full target width before any pointer/length read, on the already template-authorized creation calls (requested) and `C_GetAttributeValue` (established) only; KEM calls gain no read. The read is selector-`0x061d`-driven: any authorised slot carrying that selector classifies, not only slots beside PQC key types. One target word (`W` bytes LP64/ia32, `ulValueLen` exact, ia32 zero-extended with high-bit refusal); the word must be `1..=12`. The H7-E4 request/Get protocols (selector-first, capacity, alias/overlap, header recheck, accepted partial RVs, duplicate/conflict rules, Set invalidation, pair separation) apply unchanged; no new read site or descriptor exists. | Raw code `1..=12` in the existing side-row cell and per-view seventh metadata field; scrubbed/deleted on every terminal path like the six existing kinds. Public: the `parameter_set` key (`{status, value}`) in the v5 requested/established/query blocks, and the eighteen `metadata_at_use`/object labels enumerated in `$defs/metadata_label` of [the v5 schema](../schema/inventory-v1-object-observations-v5.schema.json). Concise text spotlights PQC uses (`ML-DSA-65 sign: 12`); `-v` adds failed/active; JSON/JSONL carry every row; dashboard, profile, trace and metrics gain nothing. | Missing key type, valid-code/wrong-family pair (including XMSS/XMSS-MT and vendor objects, whose codes name other parameter sets), incompatible class or conflict: no label (`metadata_unknown`/`metadata_conflicting` as today). The field publishes the classified code `1..=12` whenever the word is in range, whatever the key type; only the combined label needs the same-view PQC key type, a family-valid code and a compatible class. Out-of-range words publish no value (`unsupported`); conflicts publish `conflict`. P0 builds read nothing (`UNINSPECTED`, `not_enabled`). Required evidence: partial-error neighbor preservation, hostile-width (ia32 high-bit, `1<<16`, `1<<32` OR-alias) and secret-alias (`CKA_SEED`/`CKA_VALUE` silence, secret bytes behind the value pointer classify to nothing) twins; `object_producer_compiled_frames_are_bounded` unmodified; a live PQC-provider capture showing one PQC segment with matching v5 JSON. |
| PQC `CKA_KEY_TYPE` qualifier (P2) | Exact selector 0x0100 (already approved); additionally accepted values `0x49` (`CKK_ML_KEM`), `0x4a` (`CKK_ML_DSA`), `0x4b` (`CKK_SLH_DSA`) from PKCS #11 3.2 sections 6.67.1/6.68.1/6.69.1. Same source/ABI/span rules as every key-type value; establishes the key-type field exactly like the nine existing types. | Same retention as the key-type field; public only as the numeric scalar beside `parameter_set` and inside the eighteen combined labels. Never a standalone PQC key-type label, never taken from a mechanism. | Any other key-type value (including XMSS and vendor types) stays refused with no numeric fallback; a PQC type without a valid same-view parameter set labels nothing. The M2 `!is_established(1)` pin for key type 73 is the one superseded assertion (the superseding assertion lives in `key_operation_kem_encapsulate_binds_input_role`). |

`CKA_SEED` (0x637) and `CKA_VALUE` (0x11) — the FIPS 203/204/205 seed
and private values, Table 13 footnote 7 — stay excluded: no selector
match, no pointer/length read, no value retained. The parameter set
itself carries no footnote 7, matching the specification's
revealable-metadata treatment. Version 5 is emitted exactly when PQC
content is present; versions 1–4 stay frozen and byte-stable.

## DR04 caller metadata (2026-10-18)

**Status: opt-in implementation contract; qualified on Fedora 7.2 with
Docker (two-container labels), synthetic pod cgroups (systemd and cgroupfs
stems) and real kind pods watched from the host (two-pod labels with
kubectl-matched IDs and counted calls) in v0.7.0. In-node kind
qualification (observer inside the node, nested PID namespace) remains
blocked (nested observer: `--cgroup` refuses pid-namespace-mismatch
and `--system` binds no callers, leaving witness rows unbound with
pid_namespace gaps).** This
subsection permits only the finite Inventory context below.
Every other section keeps its own status; v1/v2 bytes and exclusions are
unchanged, and there is no global v3 activation. Real two-container,
host-view two-pod and mid-capture-exit acceptance passed in v0.7.0;
in-node two-pod and migration acceptance remain tracked separately.

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

Concise inventory text (never `--quiet`) shows one scope line per labeled caller with edges, naming the executable basename and PID (both new to concise text), the caller's logical entry total with forwarding-layer observations excluded, and the scope label: `container <12-hex> (<runtime>, cgroup hint)` for a lone container — `<runtime>` is the canonical `docker`/`containerd`/`cri_o`/`unknown` label, omitted when the parser claims no runtime — or `pod <8-hex> / container <12-hex> (cgroup hint)` for a pod pair, or `pod <8-hex> (cgroup hint)` for a lone pod. Stale rows append `, stale` and retired rows `, exited` (the concise display word for JSON `historical`) inside the parentheses; verbose caller lines carry the same markers. At most eight scope lines print, then `and M more labeled callers (-v or --json)` (`and 1 more labeled caller` when singular); a `caller context:` line counts labeled, unknown and pending callers with edges (nonzero parts only) with a `(-v for details)` suffix. Sampled rows that matched no container pattern — including Podman/libpod paths, which the parser leaves unrecognized like host cgroups — stay silent in that count even when stale or historical, as long as they carry a sample; only never-sampled or refused rows count as unknown. Verbose text and JSON carry the full canonical IDs. The prefixes and status words are a display projection of the allowlisted IDs and statuses above, not new captured fields; no separate derived row is needed.

## Extensive-mode executable dependency hints (6.14 Option B, D-transitive)

**Status: APPROVED (owner ratification 2026-10-29, batch item 5,
merged P5 text, branch D-transitive; the D-direct branch was
considered and not ratified). The kernel exe-identity read in
Row A is granted by the 614b P1 narrow authorization recorded in
the standing v0.6.0 requirements; merged P5 alone covered the
cache-only D-transitive analysis, not the new capture.** The rows below are additive in v3
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
is PID-keyed with timestamp-ordered consume-once; Detailed seeding
requires the ticket, aggregate seeding (7.10b) does not.
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
never seeds the exe-identity stash under Detailed policy —
aggregate seeding (7.10b) does not require the ticket — and a
stash entry is consumed at most once, in timestamp order; the
live-comparison half of the ticket discipline is inapplicable to
dead processes, so PID reuse after a lost exit record remains a
documented residual — one reason the output is a hint, never
evidence. Likewise a file replaced or
modified between exec and analysis keeps its `(dev, ino)` while
changing content; the stability recheck defeats racing
modification, not earlier replacement. The scan-learned path
cache keeps at most 4,096 entries (no-retain-when-full); the
verdict cache stores size/mtime/ctime beside each verdict and a
hit requires all-fields equality. This packet arms only where
hints publish: Detailed profile (non-metrics) captures over
cgroup/system scope (614b P1 narrow authorization). Beside
trace, metrics, exact-PID scope or an owned `run` the flag is
accepted but arms nothing and records no exe identity; beside
counter modes it is refused. Inventory captures never arm and
keep no exe identity. (Superseded for v0.7.0+ by [Short-lived
tracking widened to trace, metrics, `--pid` and owned run
(7.10b)](#short-lived-tracking-widened-to-trace-metrics---pid-and-owned-run-710b),
which widens this arming rule; the narrow rule stays the v0.6.0
scope.)

## Pre-arm module watch intervals (6.13 Detailed and inventory `prearm[]`)

**Status: IMPLEMENTED for v0.6.0 behind the operator opt-in `--prearm-module`
(default off).** Additive in v3; v1 and v2 are unchanged. These rows add no
BPF program, map, hook or kernel read: pre-armed endpoints attach through the
existing Detailed slot and inventory count-only entry paths (see the C7 C4 row
under [Inventory caller identity](#inventory-caller-identity-owner-ruling-fb-priv)),
and every published value is operator input, filesystem metadata of the
operator-named file, or an observer `CLOCK_MONOTONIC` instant. No PKCS#11
argument, target memory, provider execution, command line, environment, PIN,
key material or payload is read or published.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Pre-arm object identity: inventory `prearm[].path` and `prearm[].identity.{device{major, minor}, inode, sha256}`; Detailed `evidence.discovery[]` records of pre-armed modules (existing identity fields; `sources` gains `"prearm"`) | The operator's absolute `--prearm-module` path, lexically normalized. The file is opened once, in the observer's view or through `/proc/<pid>/root` of an exactly retained process view, and the descriptor is held for the run; it is never reopened by pathname. The device is the mapped-device pair from that view's mount table (`/proc/self/mountinfo` or the retained view's), never `fstat` `st_dev`. Inode and the whole-file SHA-256 come from the held descriptor, bracketed by `fstat` `(ino, size, ctime)` before and after hashing. The ELF header and dynamic export table of the held bytes are read only to prove standard-name entry offsets, which stay internal. The kernel self-mapping probe maps the held descriptor privately in the observer and reads `/proc/self/maps`. | Inventory: public per input, in flag order, in the `p11scope/inventory/v1` JSON report only (not the event stream, dashboard/pager or diagnostics export; `inventory diff` ignores it). Detailed: the profile, metrics and trace `evidence.discovery[]` records already covered by v1 "Provider module identity". Filesystem and operator facts only; the held descriptor and proved offsets die with the capture. | `sha256` is null when unproven. A relative, unresolvable, changed-while-hashed or over-budget input refuses the run before capture with a named error. Exact key-set twin for the inventory row and its `identity`/`device` objects. |
| Inventory `prearm[].mapped` | A join, with no new read, of the run's published registry module records against the pin: same mapped device and inode, and an equal SHA-256 whenever the record carries one. Records are never removed. | Public boolean per row meaning "observed mapped by a scope member during the capture"; it stays true after an unload and never means "maps it now". | False when no scope member was observed mapping it. Negative control: the same key with a different digest reads false. |
| Watch interval: inventory `prearm[].watch`; Detailed `evidence.discovery[].watch` (pre-armed modules only) | Arm instant: the maximum of the declared set's real attach-complete stamps (inventory lane extend receipts; Detailed session slot stamps), only when every member is stamped. End: the frozen first-stop instant, a lost declared link (at the last verified instant), health or scope truncation at the last proven-clean read, or a pinned-object change. Object change: held-descriptor `fstat` `(ino, size, ctime)` rechecks; `changed` brackets the last unchanged check and the detecting check, and `previous_ino` is the held descriptor's `st_ino`. All instants use the observer's `CLOCK_MONOTONIC`. | Public `{since_ns, state, until_ns?, ended_by?, changed?{last_ok_ns, detected_ns, previous_ino}}`. `state` is one of `pinned_unarmed`, `armed`, `armed_idle`, `unavailable`, `ended`; inventory never emits `armed_idle`. `ended_by` is one of `attached`, `scope_end`, `stop`, `object_changed`, `health_loss`, `scope_uncertain`. | `since_ns` is null until armed. `until_ns` and `ended_by` are absent until the end happens; `until_ns` is absent when the stop instant is unknown. Inventory `watch` is null only for an input that resolved to no retained object. Twins: frozen-stop clamp, health truncation, stop/scope-end cause, privileged armed cell. |
| Attach instant and unobserved windows: inventory `prearm[].attached_at_ns` and `prearm[].unobserved_windows`; Detailed `evidence.discovery[].attached_at_ns` and `.unobserved_windows` | The same attach stamps and observer clock as the watch row. Window bounds are the capture's scope-start instant and those stamps: `[scope_start_ns, attached_at_ns]` for `pre_attach` and `late_discovery`; up to the latest same-object attach outside the declared set for `mapped_unattached`. No missed-call estimate. | Public nullable `CLOCK_MONOTONIC` nanoseconds, and a list of `{start_ns, end_ns, reason}`. Inventory emits windows only for a pre-armed object observed mapped, with reasons `pre_attach` and `mapped_unattached` only. Detailed assembles both keys onto every module with attach stamps, pre-armed or not, and may also emit `late_discovery`. | `attached_at_ns` is null unless every declared member carries a stamp. Absent windows mean undisclosed, never exact. An explicitly empty list would claim exactness and requires an R2-D1-6 proof, which no producer ships. |

## Exit-time watched-provider mapping summaries (6.14 Option A)

**Status: IMPLEMENTED for v0.6.0 behind `--track-short-lived` (owner OD15/B4),
default off.** Additive in v3; v1 and v2 are unchanged. It adds no hook, map,
task-storage row, VMA field or user-memory read beyond the
[Stage A continuity witness](#stage-a-continuity-witness-task-3-proposed-addendum).

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Kind-7 leader-exit record (`DISCOVERY_KIND_LEADER_EXIT_MAPPINGS`) | At `sched_process_exit` of a thread-group leader, only in Detailed objects whose scope configuration carries the extensive bit (profile, `--cgroup` or `--system`, not metrics): a no-create task-storage lookup of the leader's existing `PROC_EPOCH` record through `current->group_leader`. It copies the record's eight watched-file `slot+1` cells (0, or 1 to 1024) and projects the shared-mm, overflow and local-fault record bits into `status_flags`. Mutation counters, epochs, attach generation and the birth-marker word are not copied. No path, address, argument or target memory is read. | A private DISCOVERY-ring record that replaces kind 6 (never sent beside it); consumed by the engine and never serialized. Every other capture (default, counter, inventory, trace, metrics, PID scope) emits the byte-identical kind-6 record. | The validator rejects cells above 1024, any nonzero word after the eight cells, and unknown status bits. A missing record yields zero cells and reads `unknown`. Evidence: Detailed `sched_process_exit` verifier counts under their pins on 6.6, 6.12 and 6.18; the live default-twin cell shows kind 6 unchanged. |
| `evidence.gap_exit_mappings` `{mapped, unknown}` | Engine classification of each novel unmatched leader exit (the `pid_descendant_gaps` subpopulation). `mapped` requires live instance hooks, neither the shared-mm nor the local-fault bit (overflow does not disqualify), an EXEC of that PID observed earlier in the capture, and a cell naming a watched slot. Every other shape reads `unknown`. A capture-local table maps PID to EXEC hook timestamp: at most 256 entries, smallest PID evicted first, entry dropped when an admitted PID exits. | Two saturating u64 counts in the profile document's `evidence` only, present exactly when extensive mode is armed (absent, never null, otherwise; metrics, trace, inventory and PID-scope captures never arm). No per-process, per-slot, per-provider or timing value is published; the table and counters die with the capture. `mapped` means the kernel recorded a localized mapping of a watched provider file by that process while watched (cells persist across unmap and exec), not that the file was mapped at exit. | There is no negative claim: multi-threaded, shared-mm, late-watch, refused-hook, faulted and empty exits all read `unknown`. The counts never feed calls, callers, shares, verdicts, births, admissions or completeness (R57; render twin). |

## Pause thread-birth dating (v0.6.0)

**Status: IMPLEMENTED in v0.6.0 by owner decision 2026-11-02
(rulings PT-1, PT-2, PT-3): `run --pause` dates threads that appear
after preflight by kernel start time against the last completed
provider hook attach instead of reporting a blanket partial.** It
adds no publication: the only new userspace read is one more field
of the `/proc` task `stat` file the pause stop check already reads,
plus the observer's own boot-clock stamp when each of its provider
hook attaches completes. Output still carries only the
v1 pause aggregate (`none`/`sigstop`/`partial` and the three
counters); allowlist-v1 bytes are unchanged.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Owned-child thread start time (`starttime`) | `/proc/<pid>/task/<tid>/stat` field 22 (boot-relative clock ticks) of the observer's own owned child only, read beside the existing state-letter sample at pause preflight and at each stopped sample; the whole stat line is parsed around the `comm` field, which is discarded. The observer stamps each of its own provider hook attach completions (static targets, dynamic exports, multi-group rebuilds) in the same boot domain (`CLOCK_BOOTTIME`) and keeps one process-wide latest stamp plus an in-flight count; the pause arm is not stamped. No `cmdline`, `environ`, argument, payload or memory read. | Private to the capture: a new thread counts as covered only when its earliest possible birth (tick floor) is strictly after the last completed attach (ruling PT-3: the kernel's floored tick is a lower bound on the birth in the reader's time namespace), and a reused tid (same tid, different start time) never counts as the preflight thread. Start times and attach stamps never enter output, logs or errors. | An unreadable or missing start time, a floored birth at or before the attach, a reused tid, no recorded attach or an attach in flight keeps the existing `task set changed` partial with its existing diagnostic; nothing is guessed. Required evidence: covered/before-boundary/unreadable/reuse twins at the pause seam plus the OpenSC live cell before/after counts. |

## Unregistered mechanism id publication (owner, 2026-11-03)

**Status: IMPLEMENTED in v0.6.0 by owner decision 2026-11-03 (rulings
KG-1/KG-2): mechanism ids are public constants, so the observer publishes
the numeric id (hex) of every 32-bit mechanism id it counts as
unregistered, with its call/error counts, instead of only a total.** For
the mechanism word in the Detailed object this replaces v1's membership
rule with provider acceptance (CKR_OK/CKR_PENDING) plus a ≤0xFFFFFFFF
bound. A readable, provider-accepted value outside `MECH_SHAPE` and at
most `0xFFFFFFFF` is published as a bare number with counts, never
decoded, never named. Allowlist-v1 bytes are unchanged.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Unregistered mechanism id (`registered: false`) | The existing guarded return-time `CK_MECHANISM.mechanism` word, read under `allowlisted` with the same descriptor, span and `return_allows_mechanism` gates as a registered publication; only the membership outcome differs, so no new read exists. Published only when the value is at most `0xFFFFFFFF` (every standard and portable vendor id; `CK_ULONG` is 32-bit on ILP32 and Windows); a wider word stays unpublished. `pParameter` and `ulParameterLen` are never touched for these ids. Detailed object only; the journal object keeps withholding (its validator pins the capture transition set). Unsafe diagnostic builds, whose allowlisted return gate is off, flag membership misses at entry; they never carry the journal object. | The id beside `MECHANISM_VALUE` with the `MECHANISM_UNREGISTERED` capture bit, aggregated per id through the existing bounded semantic path (16,384-key capture budget, event ring), private until publication. Public: `mechanisms[]` rows with `registered: false`, hex id, calls, errors and null params; `cgroups[].mechanisms[]` rows with `registered: false`, hex id, calls and errors (no `params` key); inventory `edges[].mechanisms[]` with `name: null` and no `registered` key; inventory snapshot/dashboard text shows the bare hex id with counts; trace text shows the bare hex id. Key-operation rows never carry an unregistered id. No name is assigned or guessed from any header. | An unreadable id stays `MECHANISM_UNREADABLE` with `ARG_READ_FAILURE`. Every occurrence, including wider-than-32-bit values and journal-lane occurrences, counts in `evidence.unregistered_mechanisms` under `allowlisted` (unsafe documents mark rows, total stays 0); ring loss and state-budget refusals disclose through their existing `PARTIAL`-forcing evidence, never silently. Required evidence: unregistered/registered/sticky/overflow twins and a wider-than-32-bit twin (counted, unpublished) at the semantic seam; journal withholding pins; the bits-aware live canary on 32- and 64-bit targets; a live before/after capture listing every remaining unregistered id. |

For a conforming provider the value is one of its mechanism ids.
Residual risk: a provider that accepts any value, together with a caller
that aliases `pMechanism`, publishes that memory's first `CK_ULONG` (one
per call, within the key budget). The bound filters nothing on 32-bit
processes. On 64-bit processes it withholds pointers and any word with a
nonzero upper half, but not short zero-padded values. The v1
function-name rule is untouched: function words still reach output only
by exact membership in the 104 published names.

## Pre-arm mapping-instant witness (v0.6.0)

**Status: IMPLEMENTED in v0.6.0 by owner decision 2026-11-01 (WU-13 in full).**
With `--prearm-module`, `profile` and `trace` captures under `--pid`,
`--cgroup` or `--system` load a short-lived kernel witness at startup and
drop it before the capture reports ready. Its only purpose is to let the
pre-armed module's existing `unobserved_windows` value be an explicitly empty
list when the kernel shows that no scope member had the pinned provider file
mapped between the capture's scope start and the module's attach-complete
instant. `run` loads it during discovery but drops it without a verdict (the
pause hold is its proof); inventory does not load it. It adds no
output field.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Witness file key and observer exclusion | The observer opens each `--prearm-module` path (regular files only), maps one read-only page of it once and unmaps it; the unmap hook records that file's kernel `(s_dev, i_ino)` and the observer's own address-space pointer. The key is then compared with the trusted pin of the same path. | Key and pointer stay in capture-private BPF maps; the pointer is never read by userspace; nothing is retained after the witness is dropped (before readiness). | Calibration miss, inode 0, identity mismatch with the pin, or more than 64 files: no witness, today's window. Evidence: calibration twins, identity-mismatch twin. |
| Mapping-removal latch | `fentry/uprobe_munmap`, from just before the scope-start stamp until close: for every file VMA removal host-wide it reads `vm_file`, `f_inode`, `i_ino`, `i_sb->s_dev`, `vm_mm`, `mm_users`, and for the current task its flags, `mm` and scope membership (TGID for `--pid`; default-hierarchy cgroup ids up the parent chain for `--cgroup`). A watched file's removal sets one per-file bit unless it is the observer's address space or a single-threaded non-member removing from its own never-member-departed address space. | One bit per pre-armed file; no address, length, protection, path, PID or time is stored or published. | Read failure before the key lookup, unreadable membership or cgroup depth over 64 counts as a fault: today's window. Evidence: native harness for every return path; map-unmap and teardown privileged cells. |
| Address-space departure accounting | `exit_mm_release`/`exec_mm_release` (Linux 6.6-7.2) or `mm_exit_exec_release` (7.3+) record, for scope members only, the address-space pointer a task leaves; `fexit/exit_mmap` resolves the entry at teardown and sets the per-file teardown bit if a watched file was torn down. The presence walk clears an entry only after a complete member visit that started after the last departure. | Pointers and sequence numbers stay kernel-only in bounded hash maps (16,384 departed, 65,536 visited); userspace reads only two counters (entries opened, entries resolved) and per-file bits. | A pending entry at close, a failed insert or an exhausted update: today's window. Evidence: held-address-space teardown cell (a holder keeps the exited member's address space past close), exec-departure cell, harness CAS and insert-failure twins. |
| Cgroup out-migration latch (`--cgroup` only) | `fentry/cgroup_migrate`: whether the moved task was in the scope cgroup subtree before the move. | One counter. | Any member migration while the witness is active: today's window. Evidence: migration-out privileged cell. |
| Presence walk | One `iter/task_vma` pass after attach-complete: `--pid` over the target process (pidfd), otherwise over every task in the initial PID namespace; per VMA it reads `vm_mm`, `mm->map_count`, `vm_file`, `f_inode`, `i_ino`, `i_sb->s_dev` (any protection), and membership as above; no leader gate. It sets one bit per watched file found in a member address space, and resolves departure entries. | Per-file found bits, an END count and fault counters; no range, address, PID or inode is emitted (the iterator writes no bytes). | No END, read error, deadline, observer outside the initial PID namespace, or found bit: today's window. Evidence: zombie-leader, read-only-mapping, non-member, observer and 1M-VMA cells. |
| Published result | Userspace combines the bits and counters above with the existing attach-complete stamps and scope-start stamp, plus hook health (`recursion_misses`, `ftrace_enabled`). | Only the existing `unobserved_windows` value of the pre-armed module's discovery record: an explicitly empty list only when every witness fact is clean and the R2-D1-6 interval matches exactly; otherwise unchanged. The `--system` result is exact for all tasks; `--pid`/`--cgroup` results can show a window caused by removals outside the scope (multi-threaded or remote unmaps), never an empty list caused by them. | Any missing, failed or dirty fact keeps today's window (or today's absent key for a never-mapped module). Evidence: engine twins for every fact; sentinel test that no witness bit, counter, key or pointer reaches JSON, JSONL, trace output, stderr diagnostics or logs. |

## Reload-disclosure linkage publication (B17 leg 2, 2026-11-04)

**Status: REVIEWED in the batch-11a integration review (2026-11-04):
the inventory `instance_reload_not_excluded` object publishes only
capture-local module/instance labels with two saturating router counts,
projected from the already-retained reload ledger. No new capture exists;
allowlist-v1 bytes are unchanged.** The linkage fact — *these instances
were not excluded across a reload* — rests on the "Public identities and
derived facts" and "Mapping continuity epoch and state" rows above; this
section names the exact field so a future reader does not reconstruct
authority from the generic rows.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Reload-disclosure linkage (`instance_reload_not_excluded`) | A pure projection of the staged reload-disclosure ledger in the semantic finalizer (the `reload_not_excluded` map plus the `continued_across_global`/`joined_across_global` counters). No target-memory, argument, pointer, map or file read happens for this field: each ledger identity's router IDs resolve through their registered instances and group by the one module conversion the ledger recorded — never a second lookup — so the named module is always the recorded one. Router IDs that never registered are omitted; identities with nothing nameable are dropped. The key stays absent (never null) when the capture produced no disclosure. | Public inventory JSON only: the two capture-monotonic saturating u64 router totals plus `identities`, one entry per affected registry module in numeric module order with its disclosed instance references in numeric instance order (`{"module": "mN", "instances": ["iN", ...]}`), same-module entries merged into one sorted union. Labels are the monotonic capture-local `mN`/`iN` allocation, never a raw handle, address or digest. An empty `identities` list with nonzero counts means continuations projected to no nameable identity (mint exhaustion, an all-unregistered identity, or ledger-cap shed); the counts stay exact in each case. | No router ID, file slot, native domain, task cookie, exec ID, address, session, slot, async handle, argv, environ, PIN, key or payload value reaches output. Registration refusals disclose under the existing `instance semantics refused` gap, conversion refusals under `semantic input refused`, and ledger-cap shed under `reload disclosure identities shed`. Required evidence: the 12-instance reverse-order merge/sort twins with the `m10`/`m11` lexicographic-separation guard, the mint-exhaustion empty-with-counts twin, the unregistered-omission and no-private-identity pins at the reload-disclosure seam, and the matching shape in `docs/schema/inventory-v1.md`. |

## Gap-admission prefix publication (JK-22a)

**Status: IMPLEMENTED in v0.6.0 by ruling JK-22a (owner rule 2026-11-05):
when a module does not fit whole, admission attaches the leading prefix
that fits and reports the remainder as a named partial gap instead of
refusing the module whole. Counts and reason names only; no new capture,
no new read, no new retained field.** The counts are admission
accounting over already-decoded tables and endpoints (how many tables
or endpoints the module needed, how many attached). The module path in
the gap record is the same verbatim discovery label the whole-refusal
record already carries. Allowlist-v1 bytes are unchanged apart from
the gap-reason text itself.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Closure prefix gap (`closure_prefix`) | A pure projection of the planner's prefix decision: the count of leading template tables attached and the count of distinct tables decoded for that closure-array object. No target-memory, argument, pointer or file read happens for this field; the tables were decoded by the existing scan. The record exists only when at least one table attached and at least one did not. | The existing `evidence.modules_skipped[]` entry for the module, whose `reason` ends with the `(closure_prefix)` name beside the `N of M template tables attached` counts, in every scope. Terminal text carries the same reason through the `Module gaps` section. A zero-table outcome stays a whole refusal, never a `0 of M` partial. | No address, offset, entry name, table content, key or payload value reaches output. A refused whole closure keeps its existing refusal text. Required evidence: the shared-scope prefix test with its `(closure_prefix)` pin, the named-scope prefix tests, the whole-admission healthy twin, and the start-anchored `N of M` reader pins in `scripts/check-capture-evidence.py` and `scripts/verify-p11kit-remote.sh`. |
| Closure published-only spill gap (`closure_published_only`) | A pure projection of the planner's published-only decision: the count of attached (published) template tables and the count of distinct tables decoded for that closure-array object. No target-memory, argument, pointer or file read happens for this field; the tables were decoded by the existing scan. The record exists only for an already-loaded unnamed layer that attached at least one table and spilled at least one unpublished template. | The existing `evidence.modules_skipped[]` entry for the module, whose `reason` ends with the `(closure_published_only)` name beside the `K of M template tables attached` counts, in every scope. Terminal text carries the same reason through the `Module gaps` section with `partially covered` status. A zero-table outcome stays a whole refusal, never a `0 of M` partial. | No address, offset, entry name, table content, key or payload value reaches output. A named layer that falls through to published-only stays silent, as does a mid-capture spill and a spill-free re-admission. Required evidence: the already-loaded spill twin with its `(closure_published_only)` pin, the mid-capture guard, the named fall-through silence twin, the full-re-admission no-spill twin, and the zero-published whole-refusal pins. |
| Provider prefix gap (`provider_prefix`) | A pure projection of the planner's prefix decision: the count of leading endpoints attached and the count of fresh endpoints the shared-scope Detailed provider needed. No target-memory, argument, pointer or file read happens for this field; the endpoints were decoded by the existing scan. The record exists only when at least one endpoint attached and at least one did not; a provider whose strongest table does not fit within its reserve-aware budget, or whose corroborated (published) tables together do not fit, stays a whole refusal — published tables stay atomic and never prefix. | The existing `evidence.modules_skipped[]` entry for the module, whose `reason` carries the `A of N endpoints attached` counts with the `(provider_prefix)` name, plus the reserve clause when the module was held out of the shared-scope reserve. Terminal text carries the same reason through the `Module gaps` section with `partially covered` status. | No address, offset, entry name, table content, key or payload value reaches output. Operator (manifest), Inventory, counter and broad modules keep their whole-only rule and existing refusal text. Required evidence: the shared-scope provider-prefix test with its `(provider_prefix)` pin, the exact-fit healthy twin, the strongest-table whole-refusal pins, the published-union whole-refusal pin, and the catalog prefix-gap test. |

## Detach-quarantine refusal publication (ruling JK-22a, 2026-11-05)

**Status: IMPLEMENTED in v0.6.0 under ruling JK-22a (never-stop partial
coverage, owner rule 2026-11-05): a refused slot names its quarantine and
the recorded detach reason. No new capture exists; allowlist-v1 bytes are
unchanged.** A static slot whose detach failed refuses re-attachment while
unrelated slots keep admitting. The refusal carries only the capture-local
slot index, the fixed `quarantined after detach failure` name, and the
recorded detach reason (a static BPF program name plus a kernel/libbpf
error string). Dynamic-hook and diagnostic refusals return the same
vocabulary to the caller; their JSON mark stays the existing generic
partial record.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Slot quarantine refusal (`evidence.attach_failures[]`) | The Session's existing per-slot attach-failure record, written only when `attachment_admission_for` refuses a proposed slot index already in the detach quarantine. The slot index is the existing capture-local plan allocation; the reason is the first recorded detach message for that unit (static program names such as `p11_return` plus aya/libbpf error text — no path, PID, address, handle, payload or key material). Control bytes are escaped at the existing attach-failures publication boundary. No target-memory, argument, pointer, map or file read happens for this record. | The existing `evidence.attach_failures` array (profile/metrics/trace lanes) and the matching terminal `attach failed (slot N)` diagnostic; the existing `attach_failures` gap cause forces `PARTIAL`. | A global (unattributed) quarantine refuses without per-slot records; the terminal detach story stays in the existing detach-failure evidence. Required evidence: slot/dynamic/global/empty quarantine twins at the admission seam. |

## Unpublished mechanism approval count (ruling JK-22a, 2026-11-05)

**Status: IMPLEMENTED in v0.6.0 under ruling JK-22a (never-stop partial
coverage, owner rule 2026-11-05): an oversized approval union publishes
its official-first subset and gaps the rest by count. No new capture
exists; allowlist-v1 bytes are unchanged.** The count is a pure function
of the compiled-in mechanism registry (official catalog size plus
configured vendor overlay minus map capacity): it names no observed call,
mechanism id, process, path or handle. No unpublished id is published
anywhere; the tail is visible only as this count plus the existing
unregistered counting for ids that are actually observed.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Approval shed count (`evidence.unpublished_mechanisms`) | The Session's retained `MECH_SHAPE` publication count: approved-union size minus published-subset size, computed once at session preparation from the same registry the publication used (never recomputed at render). A u64, 0 unless the union exceeded 1,024 entries. No target-memory, argument, pointer, map or file read happens for this record. | `evidence.unpublished_mechanisms` (profile/metrics/trace lanes) with the `unpublished mechanisms` gap line; the `unpublished_mechanisms` attribution cause forces `PARTIAL` when nonzero. | Render-side shape notes are computed over the published subset only, so an unpublished id reads "no diagnostic shape", never "decode failed". Required evidence: the official-first overflow twin, the exact-partition twin, and the within-capacity whole-union twin at the selection seam. |

## Never-stop discovery gaps (2026-11-05)

**Status: IMPLEMENTED by owner ruling 2026-11-05 (never-stop): one bad
`--manifest` object, `--prearm-module` path, or live discovery-ring dequeue
must not abort siblings. Each becomes one finite `evidence.skipped[]` record;
the capture continues and reads `PARTIAL`.** Counts and reason names only; no
new capture, no path/PID/error publication. Allowlist-v1 bytes are unchanged.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Manifest object gap (`manifest object unavailable`) | A `--manifest` object the observer could not pin: unreadable locator, changed during hash, out-of-segment offset, over the shared byte budget, or stale with no scanned replacement. The decision uses only the observer's own open/hash/identity comparison against the operator-attested manifest; no provider code runs and no target memory is read for the gap itself. One internal record per bad object, deduplicated by exact path. | Public `evidence.skipped[]` records with `name: "discovery subject"`, `reason: "manifest object unavailable"`, one per bad object (array length is the count). Detailed paths and error chains stay in stderr diagnostics only. Forces `PARTIAL` via the existing `skipped` cause. | A structurally invalid manifest stays a whole-input refusal (operator syntax error, no capture). Object-count overrun stays a whole-input refusal; the shared byte cap gaps the object that would cross it (limit unchanged). Required evidence: one-bad-keeps-good and healthy-twin at the pinning seam; stale-without-replacement and mixed-manifest rebuild twins. |
| Pre-arm object gap (`prearm object unavailable`) | A `--prearm-module` path the observer could not pin, decided by the same open/hash discipline as manifests. One internal record per bad path. | Public `evidence.skipped[]` records with `name: "discovery subject"`, `reason: "prearm object unavailable"`, one per bad path. Detailed paths stay in stderr only. Forces `PARTIAL` via `skipped`. | Object-count overrun stays a whole-input refusal; the shared byte cap gaps the object that would cross it (limit unchanged). Required evidence: one-bad-keeps-good and healthy-twin at the pre-arm seam. |
| Discovery transport gap (`discovery transport unavailable`) | A live `discovery_dequeue` failure after a prefix was already pulled off the ring. The exact prefix is applied before the gap is recorded; the failure itself is a transport error, never a record. One internal record per failing tick (deduplicated). | Public `evidence.skipped[]` records with `name: "discovery subject"`, `reason: "discovery transport unavailable"`. No record content, address, or error chain is published. Forces `PARTIAL` via `skipped`. | Ring destruction (producers detached) ends the capture through the existing terminal path, which still publishes the retained prefix before detach. Required evidence: prefix-retained and healthy-twin at the live-drain seam. |

| Pause unavailable gap (`pause_unavailable`) | A `--pause always` arm or service failure that is not lifecycle (child alive, ring present): the observer could not pause, so it collected unpaused. Decided by the pause coordinator's own arm/service result against the owned child; no target memory or key material is read for the gap itself. One count per degraded attempt. | Public `evidence.pause_unavailable` count (integer, 0 when never degraded) plus `evidence.pause: "partial"`. No PID, timing, or error chain is published. Forces `PARTIAL` via the new `pause_unavailable` cause. | Lifecycle failures (child gone, ring destroyed) still abort with cleanup, never a silent unpaused run. `--pause auto` behavior is unchanged (`pause_partial`, no `pause_unavailable`). Required evidence: always-degrade and healthy-twin at the pause seam. |

## Legacy collection gaps (v0.6.0)

**Status: IMPLEMENTED in v0.6.0 under the owner never-stop rule
(2026-11-05): a legacy aggregate read that cannot read one slot's counters
or one kernel-evidence cell reports zeros as unknown with named gaps instead
of blanking the capture. No new capture exists; the gaps project read-failure
facts the observer already holds. Allowlist-v1 bytes are unchanged.**

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Legacy gap object (`evidence.legacy_collection`) | A pure projection of the legacy read's per-slot and per-cell failure flags: the STATS slots whose map read failed, whether any RV-table entry read failed, and the EVIDENCE/control cells whose map read failed. No target-memory, argument, pointer, map-content or file read happens for this field beyond the already-attempted aggregate reads; a missing STATS/RV/EVIDENCE map remains fatal (the data source itself is gone), and missing control maps (Inventory flavors) contribute nothing without a gap bit. The key stays absent (never null) when the legacy read was exact. | Public profile/metrics JSON only: `unread_stats` (saturating u64 count of slots that read zero as unknown), `rv_failed` (whether the RV table read failed), and `unknown_evidence` (finite names of the unread cells, in bit order: the nine EVIDENCE names plus `owner`, `cookie`, `root`). Counts and reason names only; no per-slot index, offset, timing, RV value or control word reaches output. Zeros in the rows are unknown, not exact, whenever this object is present, and the report reads PARTIAL with cause `legacy_collection`. | No slot index, file offset, ordinal, name, RV value, timing, bucket, control word, address, session, PID, argv, environ, PIN, key or payload value reaches output. A gap object with zero counts and an empty name list is never emitted. Required evidence: per-slot zero-with-gap and per-cell unknown twins at the legacy collection seam, an exact-read omission twin, and the matching shape in `docs/schema/observed-profile-v3.md`. |

## Counter bank gaps (v0.6.0)

**Status: IMPLEMENTED in v0.6.0 under the owner never-stop rule
(2026-11-05): one bank's unreadable cell gaps only its slots with a named
count, and a health or kernel read failure degrades the evidence without
voiding the folded rows. No new capture exists; the gaps project
read-failure facts the observer already holds. Allowlist-v1 bytes are
unchanged.**

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Bank gap object (`evidence.counter_collection.bank_gaps`) | A pure projection of the counter acquisition's per-bank failure flags: how many slots failed to fold, and whether the health or kernel evidence read failed. No target-memory, argument, pointer, map-content or file read happens for this field beyond the already-attempted bank reads; a missing bank map or a global quarantine/routing refusal still voids via the existing failure cause. The key stays absent (never null) when the acquisition was exact. | Public profile/metrics JSON only, inside `counter_collection`: `failed_slots` (saturating u64 count of slots that failed to fold), `health_failed` (whether the health read failed), and `kernel_failed` (whether the kernel evidence read failed). Counts and finite flags only; no per-slot index, offset, timing, RV value, health word or control word reaches output. A gap read publishes the last good values (stale) until the next exact read telescopes, except the first read of a generation, which publishes its current rows with zeros as unknown for the failed slots; either way the report reads PARTIAL with cause `counter_collection`. | No slot index, file offset, ordinal, name, RV value, timing, bucket, health word, control word, address, session, PID, argv, environ, PIN, key or payload value reaches output. A gap object with zero counts and false flags is never emitted. Required evidence: per-bank partition and evidence-degradation twins at the counter acquisition seam, an exact-read omission twin, and the matching shape in `docs/schema/observed-profile-v3.md`. |

## Derived count projections (v0.6.0)

**Status: IMPLEMENTED in v0.6.0: `forwarding_layer`, `layer_totals`,
`observation.semantic_capture.events_lost` and `selected_detail` are
derived counts over already-observed calls, admission decisions and
loss counters — no new capture, no new read, no new retained field.
Allowlist-v1 bytes are unchanged.**

## Per-provider mechanism counts (owner ruling KG-1/KG-2, 2026-11-03)

**Status: IMPLEMENTED on this branch per owner ruling KG-1/KG-2
(2026-11-03): mechanism ids are public constants, so each
`mechanisms[]` row additionally partitions its calls/errors by
provider module. Publication change only; no new read exists. The
controller shows this final text to the owner before merge.
Allowlist-v1 bytes are unchanged.**

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Per-provider mechanism counts (`mechanisms[].by_module`) | The existing guarded return-time `CK_MECHANISM.mechanism` word (the same v1 capture the row aggregates) joined in userspace with the capture-lifetime sole-owner module of the observing slot (`module_of_slot`); no new kernel read, no new map and no new retention site exists — each cell lives inside its existing semantic row under the existing 16,384-key capture budget. Only sole-owner observations partition; unknown-owner observations count in the row alone, and doubly claimed slots are count-only and record nothing. | Public profile JSON only (`p11scope/observed-profile/v3`): each `mechanisms[]` row carries `by_module`, one `{module: {dev, ino, sha256}, calls, errors}` entry per sole-owner module in module-id order, the module reference resolved through the document's discovery list. Metrics, trace lines, inventory documents and text frames gain nothing (inventory `edges[].mechanisms[]` already carries per-edge counts). Never per thread, per call time, per session, or per key. | An entry whose module the discovery list does not name is skipped, never fabricated; entry sums never exceed the row. A budget-refused entry records nothing and counts the existing `semantic_state_drops` gap (`PARTIAL`). Required evidence: two-provider split/partition twins, unowned/ambiguous exclusion twins, budget-refusal and purge twins at the semantic seam, and the matching shape in `docs/schema/observed-profile-v3.md`. |

Owner ruling KG-1/KG-2 also covers key creation/derivation counts as
not secret; this section implements the mechanism-count half only.
Creation/derivation counts remain future work and gain no row here.

## Short-lived tracking widened to trace, metrics, `--pid` and owned run (7.10b)

**Status: APPROVED 2026-11-07 (controller second-tier privacy
review; owner rule: privacy wording is ours). This section is the
widened read/retention contract; it supersedes the 614b P1 narrow
arming rule above, which stays quoted as the v0.6.0 scope. The
implementation on `task/v070-shortlived-wide` follows this contract.
No new kernel read, no new retained field, no argv, environment,
payload, PIN or key-material read or publication: the single
captured field stays the Row A exe identity (`(dev, ino)` file
metadata only), behind the same opt-in `--track-short-lived`
(default off). The one new userspace read is the exec-time
`readlink` of the already-scanned target exe (validated-target-exec
row below), whose path stays private and unpublished. Allowlist-v1
bytes are unchanged. Counter modes still refuse the flag by name;
inventory still never arms.**

What widens, per mode and scope (Detailed policies only, flag armed;
disarmed captures record nothing, as today):

| Capture | New consumer | New publication |
| --- | --- | --- |
| trace `--cgroup`/`--system` | Novel unmatched exits, as profile today | `gap_exe_hints` + `gap_exit_mappings` in the terminal `EVIDENCE` object (the trace lane already renders through `versioned_evidence`) |
| `--mode metrics` `--cgroup`/`--system` (non-counter) | Novel unmatched exits, as profile today | `gap_exe_hints` in the metrics evidence object (same closed shape as profile); `gap_exit_mappings` stays absent there because instance hooks never attach — use profile/trace for `mapped` |
| profile/trace/metrics `--pid`, owned `run` (any lane) | Validated target execs (below) | `target_exec_hints` in that lane's evidence; the gap keys stay absent (no descendant-gap subpopulation exists under PID scope; after F8 lands the run-tree cgroup scope, an owned run still classifies only its direct child there — descendant gaps are counted without hints) |
| profile/trace/metrics `--cgroup`/`--system` | — | `target_exec_hints` stays absent (no single target; per-member exec classification is out of scope) |

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Exe identity read (Row A, unchanged) | At `sched_process_exec` the kernel reads `current->mm->exe_file`'s `(dev, ino)` into the EXEC record whenever `FLAG_TRACK_SHORT_LIVED` is set. No new read: the stanza already stamps the pair in every flavor and scope once the bit is set; only userspace arming widens. Under PID scope the pair rides the named target's EXEC records; the EXEC ticket stays unavailable there by design (number-only admission cannot bind it), exactly as the v2 ticket row requires. | Unchanged: private capture-local identity/cache tuples only; never published. | Unchanged: absent pair reads `unknown`. |
| Aggregate-policy stash seeding (seeding-rule amendment, userspace only) | Under `--mode metrics` (aggregate policy) over `--cgroup`/`--system`, EXEC records seed the exe-identity stash without a kernel ticket; the scope binding is the same exit-side admission, timestamp-ordering and consume-once discipline as the ticketed path. Justification: the exe pair is read directly from the exec'ing task and does not depend on ticket allocation; cgroup admission is membership-based and system scope covers the whole machine, so admission plus the unchanged timestamp-ordering and consume-once discipline binds as strongly as the ticketed Detailed path. The v2 ticket row stands unamended — the kernel still stamps no ticket under aggregate policy (and none under PID scope, where the gap stash still never seeds: number-only admission cannot bind). Detailed (non-aggregate) seeding still requires the ticket, so the qualified profile path is byte-identical. No BPF change exists in 7.10b. | Unchanged stash bounds (256 entries, smallest PID evicted first, consumed at most once, in timestamp order). | Unchanged: missing/reordered/absent entries classify `unknown` without analysis. Required evidence: ticketless-seed and ticketed-refusal twins at the stash seam. |
| Validated target exec (PID scope, new consumer) | Under exact-`--pid` scope (trace/profile/metrics `--pid`, owned `run`) each EXEC record that matches the retained target view through the existing lifecycle matcher, while that view is still the same generation (`still_the_same`, pidfd-backed), validates as one target exec. Unmatched EXECs and EXECs against a dead/retired view validate nothing and carry no hint. At validation the observer learns the target's exe path with the same `readlink /proc/<pid>/exe` + `stat(path)` read inside the same `run_while_same` bracket that scan learning uses — the same file the observer already reads on every scan of the named target, timed at exec instead of at scan — then runs the unchanged Row B/D analysis on the recorded pair. | No per-exec retention: the learn feeds the shared capture-local path cache (4,096 entries, no-retain-when-full) and the analysis feeds the shared verdict cache (1,024 entries) under the shared Row D capture budget (64 MiB; per-analysis 1 MiB, 32 objects, 128 edges, 255-byte names). Only the four saturating `target_exec_hints` counts publish, with the `STATIC HINT` label and the D-transitive scope string. A target exec is never a call, verdict, share, birth, admission or completeness input (Row C, R57). | A re-exec between the record and the learn fails the reopen `fstat` equality and reads `unknown`; a dead target fails the bracket and adds no count (unvalidated execs are outside the subpopulation, not even `unknown`); an absent pair reads `unknown` without analysis. A fast exec chain degrades superseded images to `unknown`, never to a wrong image's hint. Required evidence: validated-exec, stale-view, absent-pair and re-exec-race twins at the dispatch seam. |
| `target_exec_hints` publication (new key) | The validated-target-exec subpopulation above: exactly one hint per validated target exec. | Present if and only if the capture armed extensive mode under PID scope (trace/profile/metrics `--pid` or owned `run`); absent, never null, otherwise. Closed shape identical to `gap_exe_hints`: `label`, `scope`, `links_provider`, `links_pkcs11_loader`, `no_static_link_within_scope`, `unknown`. Zeros mean no validated target exec was observed, never "no provider use". | Unvalidated execs are outside the subpopulation (like admissions/overflow for gaps): they add no count, not even `unknown`. Required evidence: exact-shape, absent-when-disarmed, gap-keys-absent-under-PID and target-key-absent-under-cgroup/system twins per lane. |

Kernel-bit forwarding is unchanged: the bit publishes if and only if
the engine armed extensive mode (either consumer) under a Detailed
policy; a counter policy still refuses the flag by name before any
map write. The kind-7 exit record already flows under the armed bit
in every Detailed lane and scope; under PID scope it retires the
target view exactly like kind 6 and is never classified (no gap
subpopulation; target mappings stay directly observed through scans),
so it adds no retention and no publication there. Human text lines
are unchanged: concise stays concise and `-v` adds no hint lines.
The machine-readable trace `EVIDENCE` record carries the new keys
like the JSON lanes, which carry the complete new keys.

Residuals (same class as the Row A note): every processed leader
exit drops its PID's stash entry and exec timing — a matched exit at
retirement, an admission-covered unmatched exit (its view retired
before the ring record arrived) at the covers check, a novel exit by
consuming it, a redelivered exit like its first delivery, an
overflow-shedded exit at the sentinel — and a removed admitted view
drops both at admission close, so, apart from the migration case
below, only a *lost* exit record can still leave a stale entry
(PARTIAL via `discovery_ring_loss`),
attributing one image-correct hint to the wrong generation's count;
the `still_the_same` gate plus the reopen re-verify bound the
misattribution to that lost-exit case. Under `--cgroup`, a member
that execs, migrates out and exits produces no exit record; a
fork-only reused PID can then consume its entry without PARTIAL —
but only for members with no open admission when they exec (never
admitted, or already evicted). Target execs before attach
are invisible; metrics ticketless seeding trusts membership admission
(the same admission that authorizes every other metrics lifecycle
record). An owned `run` whose child never execs (spawn failure aside,
the child always execs its command once) publishes a zero split.

The CLI-text finding 32 contradiction is removed with this widening:
`run` accepts `--track-short-lived` and arms the PID consumer for its
child, so the "records nothing beside run" refusal is gone; the
profile, trace and run help texts each describe what the flag arms on
their own surface (gap splits on `--cgroup`/`--system`, target-exec
hints on `--pid`/owned run); profile and run keep the `--counter-mode`
refusal line (trace has no counter mode). `docs/usage.md`, `README.md`,
`docs/known-limitations.md` and `docs/schema/observed-profile-v3.md`
carry the same widened rule; the lifecycle-cli oracle's `--pid` cell
keeps asserting the gap keys absent and now accepts the target key.

Required evidence beyond this lane's V1 twins: per-mode live cells
(trace-armed `EVIDENCE`, metrics-armed evidence, a `--pid`/run cell
whose target execs mid-capture) through the privileged lanes, and
equal-coverage cost cells (armed versus disarmed over the identical
workload: identical call/attribution surfaces plus the measured
arm/disarm cost delta) before release claims.

## Offline CBOM export re-projection (v0.7.0)

**Status: IMPLEMENTED in v0.7.0 by owner scope-freeze exception
(2026-11-07): `p11scope inventory cbom` converts one explicitly
supplied saved `p11scope/inventory/v1` or observed-profile file into
a CycloneDX 1.6 document. Derived output only: no new capture, no
new read, no new retained field. Allowlist-v1 bytes are unchanged.**

`p11scope inventory cbom` reads one explicitly supplied saved
`p11scope/inventory/v1`, `p11scope/observed-profile/v3` or
`p11scope/observed-profile/v2` file as an ordinary user. Its
CycloneDX 1.6 document reprojects only already-published inventory or
profile fields. It performs no target-memory or argument read, live
process lookup, provider loading, or new capture. This section adds
no permission to any live observer, decoder, profile, metrics,
trace, inventory producer or kernel map. V1/v2 exclusions remain
unchanged.

| Field | Source, authority and validation | Retention and public output | Failure and evidence boundary |
| --- | --- | --- | --- |
| Offline CBOM conversion | Exact saved inventory v1 or observed-profile v3/v2 schema, bounded JSON under the shared offline-reader bounds, and resolved same-input caller/module/edge/instance references; mechanism names and operation categories verbatim from the input (never re-resolved); key metadata from established slots only — requested, conflicting and invalidated slots never qualify. No additional authority inferred from file contents. | CycloneDX 1.6 components minted per distinct caller path (`application`), per module record (`library`, with the SHA-256 hash only when the input carries a valid digest), per mechanism id (`cryptographic-asset` algorithm with name-determined primitive/mode/padding and observed operation categories as `cryptoFunctions`), and per key-class, labelled or key-operation-used object (`related-crypto-material` with established class, size and curve only). Report-local `bom-ref` values; `dependencies[]` only for joins the input proves (application to module, application/module to mechanism, key to module/caller through key-operation to instance). Provenance, counts and unknown tallies in `metadata.properties`; concise and verbose text views carry the same facts. | Malformed shapes/references, unsupported schemas and exceeded limits fail. Unknown additive data is bounded and ignored, never copied to output. A malformed crypto detail degrades its component to unknown with a named note and never stops the view. Unknown labels/units remain unknown. Validate staged installed offline behavior separately from input capture provenance and live capture qualification. |

The [CBOM design note](../cbom-export.md) defines the precise output
projection. Input caller/module IDs are not output identities:
`bom-ref` values are minted by the report, and the capture-local
object id rides a `p11scope:object` traceability property, never the
material `id`. Detailed operation aggregates, API-return histories
beyond their names, per-edge usage counts, session rows and arbitrary
unknown subtrees are not copied into the report. Key values, CKA
labels and IDs, PINs, key states and key dates are never in the
input and are never emitted: the material `value`, `id`, `state`
and date keys stay absent. Recorded paths and allowed free-text
evidence remain input facts; a saved file does not authorize new
reads or establish that the application called a provider. Text
escapes controls; JSON preserves decoded input strings through JSON
escaping.

Every count belongs to its own observation window; no host/boot,
process or physical continuity is inferred. Missing observations do
not prove inactivity, and unknown scope completeness remains
explicit. This re-projection introduces no host ID, boot ID, machine
ID, executable hash, command line, argument, buffer, handle, or raw
address capture. Its output remains subject to the input
publication's privacy contract; it is not a secret scrubber for
fabricated or otherwise untrusted saved input.

## App identity hints (owner ruling 2026-11-08)

**Status: privacy review accepted 2026-11-08; owner approval/installed
qualification pending (v0.7.0 if approved by 2026-11-09 03:00, else
v0.7.1).** Owner ruling recorded in
`docs/superpowers/decisions/2026-11-06-schedule-dl10.md`, as corrected the
same day: runtime basenames (`python3`, `java`, `node`, `perl`, `ruby`) do
not tell the operator who called; a narrow app-identity extension is
authorized for those runtimes only. Shells (`sh`/`bash`/`dash`) get no
labels — a shell cannot load a provider — and native executables keep the
plain name with no packaging hints. It supersedes the FB-PRIV 2026-10-03
no-comm/no-argv rule in part, for the three rows below only. v1 and v2
bytes and exclusions are unchanged: metrics and profile gain nothing, and
no BPF, provider-memory, or target-memory read is added.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Caller app hint from comm | `/proc/<pid>/comm` (16 bytes, trailing newline trimmed) of an admitted caller whose exe basename is a tabled python/perl/ruby runtime (`python`, `python3`, `python3.<N>` digits-only, `perl`, `ruby`); comm is read only for those three — node and java get no comm read, and shells and non-interpreter exes get no read. comm is writable by the process (`$0`, prctl), so it is accepted only when it equals the first 15 bytes of the basename of the script-position token (`argv[1]`, or `argv[2]` when `argv[1]` is a single dash-led shebang argument) from the same cmdline sample: a rewritten title has no script-position token whose basename matches, so it never matches. The accepted comm is nonempty, at most 255 bytes, and differs from the exe basename. Sampled once beside the admission exe read; the exe identity and the process start time are re-read after sampling and must match. A mismatch — pid reuse or exec under the reads — drops the hint; a same-binary re-exec inside the sample window keeps a stale label (disclosed here: the label is a point sample, never proof of identity). | `app_hint: {"value", "source": "comm"}` in `p11scope/inventory/v1` (`callers[]`, absent when unknown); concise `[value]` label beside the interpreter basename; `-v` names the source. Label only: never identity, admission, or a join key. | Unreadable, empty, equal-to-basename, unmatched, overlong, or identity/start-time-mismatched: no hint, bare basename. |
| Caller app hint from argv | Bounded 4096-byte prefix of `/proc/<pid>/cmdline` of an admitted caller whose exe basename is a tabled runtime (python, `java`, `node`/`nodejs`, `perl`, `ruby`), parsed by that runtime's recognize-or-bail grammar: only the grammar-proven script/module/jar/class token is ever captured — python script/`-m` module (dotted ident, `-W`/`-X` values skipped, `--` honored), java `-jar` jar (`.jar` suffix) or dotted main class (classpath-style values skipped; self-contained `--name=value` only from the tabled JDK list — `--module=` and any unlisted `=` form bail, since later tokens then belong to the application), node script (script suffix or `/`; `--eval=`/`--print=` bail like `-e`; `--run=` and any unlisted `--*=*` bail — only tabled documented `=` forms skip), direct `perl`/`ruby` script only (any flag bails; flagged grammars are a deferred later step, not a guess). No environ read; no `-c`/`-e` text; no flag value; a token cut by the prefix cap is unusable; non-interpreter exes get no read. Basename or validated identifier only, at most 255 bytes, controls escaped. Same admission sampling, exe and start-time revalidation as comm. | `app_hint: {"value", "source": "argv"}`; concise `[value]` label; `-v`/JSON name the source. | Any unrecognized shape, truncation, or validation failure: no hint. Required evidence: `--pin`-value negative controls at the parser seam (incl. `--module=`/module-entry shapes), unknown-`=` refusals (`--affinity=`, `--future=`), plus live CLI cells with a real console script and a rewritten perl title, each with a `--pin`-style argument proving the value is nowhere in the outputs. |
| Caller app hint from cgroup leaf | Leaf component of a new bounded `/proc/<pid>/cgroup` read at admission (DR04 reads only under its opt-in) of an admitted caller whose exe basename is a tabled runtime: exact `snap.<snap>.<app>-<id>.scope` with `[a-z0-9-]` words yields `snap <snap>`; `*.service` yields the unit name (`user@*` excluded; template instances publish the template only: `job@tenant.service` yields `job@`); `app-*.scope` yields the opaque scope name. Shells and native executables get no read and no label. Generic `session-*.scope`, slices, and `init.scope` yield nothing. The leaf is accepted only when every ancestor component ends in `.slice`, except at most one `user@<digits>.service`; every component of the `0::` path is additionally screened for container/pod shapes (`docker-*`, `crio-*`, `cri-*`, `containerd-*`, `*kubepods*`, `*libpod*`, `*podman*`, `*lxc.payload.*`, `*systemd-nspawn@*`): any match yields nothing — a service inside a container is never a default-on hint. DR04 owns that display under its opt-in. Same admission sampling, exe and start-time revalidation; a value equal to the exe basename is dropped; the composed value is bounded to 255 bytes. | `app_hint: {"value", "source": "unit"` or `"snap"}`; concise `[value]` label; `-v`/JSON name the source. | Unparseable, excluded, overlong, or identity/start-time-mismatched: no hint. |

Precedence is argv, then comm, then the cgroup leaf; the first proven
source wins. Counts, caller IDs, incarnation identity, joins, and
admissions never change. A hint equal to the exe basename is dropped
everywhere. Trace, inspect, metrics, and profile outputs are untouched
by this section.

## Copy-up layer publication (F11, 2026-11-07)

**Status: IMPLEMENTED in v0.7.0 by controller ruling F11 copy-up
(2026-11-07): when the kernel VMA witness proves a mapped range runs
the pre-copy-up lower file rather than the merged path's current file,
the lower file is attributed as its own module row instead of missed.
Allowlist-v1 bytes are unchanged; the lower file's identity publishes
under the existing v1 module-identity fields, plus one finite marker.
No new kernel read exists: the proof reuses the ratified v2 "Kernel VMA
identity proof" reads.** Userspace additionally parses the `lowerdir`
option of the already-read mount table, opens the proven lower file,
and ELF-inspects and hashes it exactly like any pinned provider file;
each lower query spends from the existing 8/scan witness budget, and
exhaustion keeps the named `original_file_unproven` gap. Only the
merge path is published, never lowerdir host paths.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Lower module row (merge path plus lower identity) | The lower file the kernel VMA witness proved for the stale range: opened by descriptor, whole-file SHA-256 at pin time, `(ino, size, ctime)` re-checks, and ELF re-inspection from the lower fd — the same custody as any provider file. Upper offsets are never reused for it. The row exists only on a kernel `same_file` proof for a lower candidate; an unproven, unopenable, escaped, or budget-exhausted candidate keeps the named gap, never a join. | A second module row beside the upper file's, in `evidence.discovery[]` (profile/metrics), `inspect --pid` modules, and the `inspect --system` catalog. Both rows publish the merge path and the shared merge-view key `{dev, ino}` under the existing module-identity fields; `sha256` and `build_id` are read from each row's own file, and only the lower row carries `layer` — digest and layer tell the two rows apart whenever the copy-up changed a byte (a byte-identical copy-up still admits the pair, differing only by `layer`). `functions[].module` joins either row by identity, so stale-mapping calls count on the lower edge and fresh calls on the upper edge. `capture.modules[]` stays the identity-only projection. A fallback search that proves no lower file publishes only the refused count and the finite stage words in the gap reason (`; lower candidates refused: N (stage; ...)` — the first eight stages in search order, any rest counted). The words print in the order candidates were tried, so a word's position reflects the search order, and they name the witness's other-file outcome where it occurred; no candidate path or numeric index is published. | No lowerdir host path, candidate list, candidate path, numeric candidate index, range, address, PID, argv, environ, PIN, key or payload value reaches output. A genuine in-place change (no witness proof) still blocks with the existing changed-identity refusal. Required evidence: the stale-mapper acceptance with 2 witness queries, the lower/upper routing twins, the in-place-change refusal twin, the budget-exhaustion gap twin, the unopenable/escaped-candidate refusal twins, and the matching shapes in `docs/schema/observed-profile-v3.md` and `docs/schema/inspect-v1.md`. |
| Finite layer marker (`layer: "pre_copy_up"`) | A pure projection of the pin's proven side: present exactly on rows whose pinned object is the witness-proven pre-copy-up file. One finite value; no target read happens for this key. | JSON `"layer": "pre_copy_up"` on the lower file's module row only (absent — never null — on every ordinary row); verbose text marks the row `(file before copy-up)`; concise text shows the same counts unmarked. | No second value exists; an unproven side never carries the marker. Required evidence: the marker serialization twins (profile, inspect JSON, catalog), the verbose-marker twins, and the concise-silence twins. |

## Caller launcher chain (v0.7.0)

**Status: IMPLEMENTED on this branch; the v0.7.0 parent-chain lane
captures the rows below, pending independent review and merge.**
It adds no target-memory, argument, command-line or environment
capture: every field comes from `/proc` stat/exe reads of the same
kind the inventory scan lane already makes for callers, plus the
ancestor and caller cgroup/status reads the row below names, and
it changes
no v1/v2 exclusion (trace, profile, metrics and inspect outputs are
untouched).

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Caller launcher chain (`launched_by`, `launched_by_gap`, `launched_by_origin`, `launched_by_unit`) | The caller's ppid (stat field 4) from the SAME `/proc/<pid>/stat` line already read for its start_time, parsed once for both fields, so pid reuse between two reads cannot mix generations; then up to four ancestors, nearest first, each as a (pid, start_time) generation with its exe basename from `/proc/<ppid>/stat` (starttime plus ppid) and the `/proc/<ppid>/exe` link (readlink, the same read kind as caller exe identity), pinned by a start_time re-read so a recycle between the stat and the readlink drops the exe instead of misattaching it. Every ancestor's `/proc/<ppid>/cgroup` and `/proc/<ppid>/status` are read in full for classification (the caller's own status too, for the container-init caller rule); only the unit name and the boundary classifications below are kept. Init (pid 1 of the scope's pid namespace), the systemd user manager (its cgroup `user@<uid>.service/init.scope`), container inits (status `NSpid` innermost 1), a parent with fewer `NSpid` levels than its child (outside the child's pid namespace) and kernel threads (`PF_KTHREAD`, which have no exe link) are NEVER recorded, and neither is the observer-visible parent of a caller that is itself a container init; a parent younger than its child proves pid reuse and stops the walk. No parent in this pid namespace (ppid 0) is an init-type boundary too. Same-namespace child subreapers (`tini -s`, s6/runit, `--pid=host` runtimes) expose no `/proc` flag and stay visible links: a known limit, never a silent rename. Only when the immediate parent is init-type, the caller's systemd unit/scope is parsed from `/proc/<pid>/cgroup` the way `sd_pid_get_unit` does (the cgroup-v2 `0:` line only — a v1-only file has no unit — leading slices skipped, first valid unit taken (systemd unit-name charset, 256-byte length and `@` rules), one `_` escape prefix stripped, ` (deleted)` truncated, `/../` refused; no libsystemd link); inside a `user@<uid>.service` subtree the `sd_pid_get_user_unit` rule applies instead (the first unit after the user manager, or nothing), but only when that service is the first non-slice component — a mid-path occurrence sits in a delegated subtree and leaves the system first-unit rule in place. An unreadable entry is proven exited only by `kill(pid, 0)` answering `ESRCH`, a channel `/proc` `hidepid` cannot affect; no mount table is read. No `cmdline`, `environ`, argument or memory read, and no retained or published `comm` (each stat line is parsed around the comm field, discarding it). Cgroup and status reads keep only the unit name and the boundary classifications; full cgroup paths and status bodies are never retained or published. The native lane adds none: no BPF parent record exists, and short-lived parents that exit before the scan read are reported, not reconstructed. | Public per caller incarnation in `p11scope/inventory/v1` (`callers[].launched_by`: `pid`, `start_time` in `clock_ticks_since_boot`, exe basename `exe`, optional `label` hook unset in v0.7.0, per-ancestor `exe_gap` only when the exe link could not be pinned to the statted generation (naming the exit or the unreadable link), `folded` only when identical adjacent wrappers collapsed; `callers[].launched_by_gap` with `subject` `caller parent chain` and a named `reason`; `callers[].launched_by_origin` `chain`/`init_parent`/`gap`; `callers[].launched_by_unit` with the systemd unit/scope or null), the inventory event stream's caller records (same producer), the `-v` chain detail line (repeated identical wrappers collapsed as `sh (×2)`; an init-only parent with a unit renders `app (from unit)`), and the concise one-hop suffix (`app (from parent)` for a named parent, or `app (from unit)` for an init-only parent with a `.service` unit; nameless links and scopes/transient units print no suffix and stay in `-v`/JSON). PIDs are in the observer's `/proc` numbering (`pid_namespace`). Chains are frozen at admission like exe identity. | An unreadable ancestor is a named gap with the ancestors read so far, never a guess: `launcher exited before read` when the exit is proven (`ESRCH` on a signal-0 check, or a proved reuse), else `launcher hidden by /proc hidepid` (an unreadable entry whose pid still answers is hidden-alive, never presumed exited); a proved recycle or a dead generation carries `exe: null` with the per-ancestor gap `launcher exited before read`, while a stat-readable live ancestor whose exe link could not be read carries `launcher exe unreadable`, never a guessed name; a fifth ancestor above the fourth is `parent chain truncated after 4 ancestors`; cgroup-transaction commits sample no parentage (`parent chain not sampled in cgroup transaction`); an init-only parent emits no gap (it is not a read failure). Documented in [inventory v1](../schema/inventory-v1.md#model). |

Command lines, environments, arguments, `comm` values, session IDs and
full ancestor paths are never read or published in this lane: the
basename is the whole exe fact. A recorded parent proves process
parentage at admission, not operator attestation and not that the
parent invoked PKCS#11. An `init_parent` unit names the caller's
systemd scope, never a launcher process. Counts and caller identity
never change.

## Pid-scope caller executable (v0.7.0)

**Status: IMPLEMENTED in v0.7.0: a pid-scope profile/metrics capture
names its target's executable in `capture.caller` and on the stderr
target line, so the report never shows a pid-scope capture without its
caller. Allowlist-v1 bytes are unchanged; this section authorizes the
one new profile/metrics disclosure below, and no other surface gains a
name or path.** It adds no target-memory, argument, command-line,
environment, payload, key, or PIN capture: the reads are the
`/proc/<pid>/exe` link (the same read kind as caller exe identity),
plus the existing exit and pin checks (`kill(pid, 0)`, the pidfd, and
the `/proc/<pid>/stat` state and start time); the stat line is parsed
around the comm field and comm is discarded, never kept or published.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Pid-scope caller executable (`capture.caller`, stderr target line) | The `/proc/<pid>/exe` link text (readlink, lossy UTF-8) of the pid-scope target, read once probes are attached and bound to the target's retained pin: the owned child's pin on the degraded run path, else the named view's. The pin's `still_the_same` must hold before and after the readlink, else even a readable path is discarded and the exit named, so a recycled pid never misattaches an unrelated program's exe. No cwd, cmdline, environ, argument, payload, key, or PIN read; the exit proof reuses the existing `kill(pid, 0)` check and the `/proc/<pid>/stat` state and start time, and no retained or published `comm` (the stat line is parsed around the comm field, discarding it). | Public in profile/metrics JSON `capture.caller` (`{exe, exe_unknown_reason}` with exactly one non-null) for pid scope only; cgroup and system scopes emit no key (absent, never null), since their counts are aggregate. The stderr `p11scope: target: pid <N> exe <path>` line names the operator's own target pid beside the exe; the JSON report carries no PID number. A container target's path is as its mount namespace names it; a deleted binary reads `<path> (deleted)`. | An unreadable link on a live pin reads `target exe link unreadable`; a proven exit (`kill(pid, 0)` `ESRCH`, or a zombie/dead stat) or a changed generation reads `target exited before its exe link was read`. Known limitation: a mid-capture exec keeps the attach-time name. Required evidence: pin-change discard, zombie-exit, and aggregate-omission twins at the resolver seam. |

The exe names the observed image, not a desktop application, script,
package, service, or trust identity, and proves no operator
attestation. Counts, joins, admissions, and completeness never change.

## Foreign target root path in gap reasons (v0.7.0)

When a process runs under a different filesystem root than the observer
(a chroot or a container), its mapped objects can fail to open under
that root on every pass. Each such failure keeps its own per-object gap
record naming the foreign root, so the operator sees which root missed;
concise text folds identical reasons into one counted line per distinct
reason, while JSON and verbose text list every object. This section
documents that one new gap-reason suffix in plain words; it is not
owner sign-off. Allowlist-v1 bytes are unchanged.

| Field | Source, authority and validation | Retention and public output | Failure and required evidence |
| --- | --- | --- | --- |
| Target root path in foreign-root gap reasons (`(target root … differs from the observer root)` suffix) | The `/proc/<pid>/root` link text (readlink) of a process view whose root differs from the observer's, read at most once per failed mapping open and only when the root is already known foreign. The link is display-only: no file is opened through it, and the open's identity guards (mount-table resolution, the self-mapping probe, `mapped_file_guard`) still verify the held descriptor against the maps key. A container target's root renders as `/`; a chroot's as its chroot path. | Public in per-object gap reasons (JSON reports and `-v` text list every object with its suffix) and in concise folded lines (one counted line per distinct reason naming the root, with a `--json lists each` pointer). The suffix appears only on retained-root open failures; size-cap and precondition refusals carry no root and keep their own records. No retention beyond the gap record itself. | An unreadable link publishes `(target root unreadable: …)` and never blocks the scan. No PID, argv, environ, PIN, key or payload value reaches output. Required evidence: per-object JSON/`-v` completeness twins, concise-fold twins, and size-cap/precondition separation twins at the scan and rendering seams. |
