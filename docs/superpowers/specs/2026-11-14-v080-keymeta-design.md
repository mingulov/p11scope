<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# v0.8.0 Key Metadata: Inferred Family, Size Class, Creation Sources

Status: design (spark lane, round 6). Base: task/v080-design-keymeta 763b29998.
Branch: task/v080-design-keymeta. Plan: `docs/superpowers/plans/2026-11-14-v080-keymeta.md`.

Owner direction (2026-11-14 07:05): v0.8.0 carries much more key
information — family inferred from the successful operation's
mechanism, size class from output/input lengths, creation-template
curves and parameter sets. Owner privacy stance (binding): the host
owner runs p11scope, so more observability is fine; the hard line is
PINs, key material, payloads and environment. Lengths, mechanism ids,
curve OIDs and parameter-set ids are NOT secrets. The allowlist-v3
amendment texts below (§11, §17.3) are written by this design
(no owner wording round-trip); `docs/privacy/allowlist-v1.md` stays
byte-identical.

Owner decisions (2026-11-14 07:35, binding): Task 7 (provider,
token and mechanism info, §17) is REQUIRED for v0.8.0, no longer
optional; findings/enforcement (8.05) and correlation (8.06) are
out of scope for v0.8.0 (later). (The 07:35 Task 8 line is
superseded: see below.)

Owner decisions (2026-11-14 07:40 and 07:52, binding, supersede
the 07:35 Task 8 line and §15 K3): Task 8 (small fixed-size
mechanism parameters) is postponed to a later version — §18 is
now a short Later pointer with no v0.8.0 BPF/schema/privacy rows,
and Task 7 stays required; size display names the standard size
with its source and renders no bit range anywhere (§5.2, §10.2,
§10.3, §15 K3).

## 1. Goal, non-goals, constraints

Goal: per-key rows carry, beside established token-reported facts,
three new fact classes with explicit provenance — inferred family
("probably RSA (from mechanism)"), size class from operation lengths
("RSA 2048 (from signature length)"), and
creation-template facts with requested-with-success provenance —
without ever silently promoting a request or an inference into an
established fact.

Non-goals: exact RSA modulus bits for non-standard octet lengths
(masked class + byte count only, §5.2); `CKA_ID`-joined twin
attribution (O3, deferred); cross-session key joining (D5, separate
task, opt-in with per-provider proof); `C_GetObjectSize` result reads;
`C_FindObjectsInit` template reads; new attribute selectors; Message*
(v3.0 Begin/Next/Final) param-block lengths; any payload, key-material,
PIN or environment read; findings/enforcement (8.05) and correlation
(8.06) — owner 07:35: later, not v0.8.0; small fixed-size mechanism
parameters (Task 8) — owner 07:40: later, not v0.8.0 (§18).

Constraints: never capture PINs/keys/payloads/env;
`docs/privacy/allowlist-v1.md` byte-identical; missing observations
stay unknown with named reasons; concise CLI default; profile, trace
and metrics never carry object facts; observed-profile v2/v3 schemas
untouched; bounded steps for I/O/close/join/scan; Linux x86-64 LP64
first, ia32 claims require actual ABI cells.

## 2. Prior work and dispositions

- `tmp/muse-jobs/design-v070-keysize-browser.md` (R2): the measured
  browser gap (used keys never attribute-queried), the O2 RSA
  signature-length sketch, and the R2 new-site creation-template path
  (§7). This design implements O2 generalized (all size-determining
  lengths, §5) and lands R2 with source-carrying provenance (D4, §6).
- `tmp/muse-jobs/rv2-v070-keysize-browser-design.review.md` F1–F4/N5/N6:
  F1 (per-family new-site path incl. X25519/X448/Ed25519/Ed448/PQC)
  is carried by the R2 land (§6), except ChaCha20/Poly1305 creation:
  R2's KeyType set has no `0x33`/`0x34` (`CKK_CHACHA20`/
  `CKK_POLY1305`, `pkcs11.h:506-507`), so that corner is closed by
  the §6 generic unlisted-type creation row (fact-only promotion, no
  label), not by R2's type set; F2 (separate Sign pointer vs Verify
  scalar protocols, SignFinal/VerifyFinal, LP64/ia32 widths,
  retention/failure/PENDING/length-query rules) is specified in §5.1;
  F3 (as overridden by owner 07:52: standard octet lengths name the
  standard size with source; only non-standard lengths show a masked
  class + byte count; the 2041-bit control pins no `metadata_at_use`
  leak) is specified in §5.2; F4 (honest demo
  wording) constrains §10 text; N5 (operation-scoped join, mechanism
  as aggregate dimension, no metadata backfill) is decided in §9
  (no new dimension; result-derived evidence gets its own row fields,
  `metadata_at_use` stays frozen); N6 (PKCS#11 raw r||s vs TLS DER
  encoding) is specified in §5.2 (raw 2×field maps; DER/other stays
  unknown with reason).
- Branch `task/v070-keysize-browser` at 2d37b0e28 (RED 6839e226d,
  GREEN eba746421, script 2d37b0e28): creation-template new-site keys
  behind the PROPOSED v3 R2 amendment + section version 6. §6 ports
  it onto the v0.8.0 base with the §3 source labels.
- `tmp/controller/later-batch.md` "v0.8.0 key metadata" and
  `tmp/controller/v080-tasks.md` D2–D6: D2 (family), D3 (size class),
  D4 (creation-template) are this design; D5 stays PLAN (not here);
  D6 (rows without a manifest) is an interface dependency, §7.4.
- Keyrows design FINAL 4cca0dd88 (`task/v080-design-keyrows`): rows
  must exist before they carry the new facts. §13 names the consumed
  interface and the order. Keyrows owns row existence, voids, fences,
  births and seals; keymeta adds evidence columns only and touches no
  void/fence/birth/seal path.

## 3. Provenance vocabulary: every fact carries its source

Five sources, exact strings, closed enums in schema v7 (§10). No fact
may change source silently; conflicts keep both sides visible.

| Source | Meaning | Established by |
| --- | --- | --- |
| `query` (token-reported) | Provider attribute-result read on the object | `C_GetAttributeValue` result rules (H7-E4, unchanged) |
| `creation_success` (requested-with-success) | The call's own finite creation template, honored | CKR_OK + retained result handle on a template-authorized creation (R2 promotion, §6); never another object's template, never mechanism-derived |
| `mechanism` (inferred-from-mechanism) | Family implied by a successful operation's mechanism | Operation completion under a listed mechanism id (§4); display "probably \<family\> (from mechanism)" |
| `length` (inferred-from-length) | Size class implied by an operation length | Length evidence + family (§5); display per §10.3 ("\<size\> (from \<evidence\> length)"; non-standard RSA shows a masked class + byte count, never a range) |
| `requested` | Template value without success | Unchanged: never labels, never promotes |

Rules. Token-reported wins: an inferred family/size contradicting a
token-reported (or creation-success) fact is shown as `conflicting`
beside it, never merged, never overwriting. `metadata_at_use` stays
established-only (`query` + `creation_success` labels; `unknown`
otherwise): inferred facts ride the new §10 row keys and never rewrite
it, preserving the no-backfill pins
(`key_operation_delayed_receipt_does_not_backfill_metadata`,
`key_operation_later_metadata_never_rewrites_rows`). A lone size
without family, a lone family without size, or a recognized mechanism
alone never joins into a combined exact label.

## 4. D2: inferred family from the mechanism

### 4.1 Source and cost

The operation's mechanism id is already captured (v1 return-time
mechanism read; KG-1/KG-2 approve mechanism-id publication). Family
inference is pure userspace: no new BPF read, no new retained field,
no wire change. Input: `OpMachine.mechanism: Option<u64>` (bound at
the Init) for Init-based operations, and the already-captured call
mechanism for single-call operations (`C_WrapKey`, `C_UnwrapKey`,
`C_EncapsulateKey`, `C_DecapsulateKey`, `C_DeriveKey` base-key use).

### 4.2 Finite family sets (full-width equality, explicit members)

Unlisted ids (including every vendor id `>= 0x8000_0000` and every
NSS `CKM_NSS_*`) infer nothing. `_KEY_PAIR_GEN`/`_KEY_GEN`/
`_PARAMETER_GEN` ids infer nothing (creation families are covered by
§6 templates, not by mechanism). The implementation lane expands
these name lists to exhaustive `u64` const tables with a coverage
test against `src/mechanism_names.rs` (every listed id resolves to
the expected name; every function-adjacent id is either listed or
pinned `unknown`).

- `rsa`: CKM_RSA_PKCS, RSA_9796, RSA_X_509, MD2/MD5/SHA1/RIPEMD128/
  RIPEMD160/SHA224/SHA256/SHA384/SHA512/SHA3_224/SHA3_256/SHA3_384/
  SHA3_512_RSA_PKCS, RSA_PKCS_OAEP, RSA_X9_31, SHA1_RSA_X9_31,
  RSA_PKCS_PSS, SHA1/SHA224/SHA256/SHA384/SHA512/SHA3_224/SHA3_256/
  SHA3_384/SHA3_512_RSA_PKCS_PSS, RSA_PKCS_TPM_1_1,
  RSA_PKCS_OAEP_TPM_1_1, RSA_AES_KEY_WRAP.
- `ec`: CKM_ECDSA, ECDSA_SHA1/SHA224/SHA256/SHA384/SHA512/
  SHA3_224/SHA3_256/SHA3_384/SHA3_512, ECDH1_DERIVE,
  ECDH1_COFACTOR_DERIVE, ECMQV_DERIVE, ECDH_AES_KEY_WRAP,
  ECDH_X_AES_KEY_WRAP, ECDH_COF_AES_KEY_WRAP. (ECDH1-family
  mechanisms accept Montgomery keys too: the §4.5 compat table,
  not the family name, keeps X25519/X448 uses conflict-free.)
- `eddsa`: CKM_EDDSA only.
- `xeddsa`: CKM_XEDDSA only (`0x4029`, `pkcs11.h:980`;
  X25519-based, uses Montgomery keys — never `eddsa`).
- `dsa`: CKM_DSA, DSA_SHA1/SHA224/SHA256/SHA384/SHA512/
  SHA3_224/SHA3_256/SHA3_384/SHA3_512.
- `dh`: CKM_DH_PKCS_DERIVE, X9_42_DH_DERIVE,
  X9_42_DH_HYBRID_DERIVE, X9_42_MQV_DERIVE, KEA_KEY_DERIVE,
  KEA_DERIVE.
- `aes`: CKM_AES_ECB/CBC/CBC_PAD/CTR/GCM/CCM/CTS/CMAC/CMAC_GENERAL/
  XCBC_MAC/XCBC_MAC_96/GMAC/XTS/OFB/CFB64/CFB8/CFB128/CFB1/MAC/
  MAC_GENERAL, ECB/CBC_ENCRYPT_DATA, KEY_WRAP/KEY_WRAP_PAD/
  KEY_WRAP_KWP/KEY_WRAP_PKCS7.
- `generic_secret`: every `*_HMAC` and `*_HMAC_GENERAL` (MD2, MD5,
  SHA_1, SHA224/256/384/512, SHA512_224/256/T, SHA3_224/256/384/512,
  BLAKE2B_160/256/384/512, GOSTR3411, RIPEMD128/160) and HOTP
  only. GENERIC_SECRET_KEY_GEN excluded (creation).
- `secret` (superclass, never conflicts — §4.4): mechanisms that
  accept any secret-key type — the `*_KEY_DERIVATION` ids,
  CONCATENATE_BASE_AND_KEY/BASE_AND_DATA/DATA_AND_BASE,
  XOR_BASE_AND_DATA, EXTRACT_KEY_FROM_KEY, the
  TLS/WTLS/SSL3/IKE/SP800_108 KDF ids, and KIP_DERIVE/WRAP/MAC.
  An AES key passing through one of them keeps its AES family
  with no conflict.
- Infer nothing (explicit, each pinned by a twin): `CKM_CMS_SIG`
  (`0x500`, `pkcs11.h:809`) — a signature mechanism usable with
  RSA, EC and DSA keys, so it names no single family;
  `CKM_PKCS5_PBKD2` (`pkcs11.h:789`) and the `CKM_PBA_*` ids
  (`pkcs11.h:790`) — `C_GenerateKey` mechanisms with no input
  key, already infer-nothing under the generation rule above.
- `hkdf`: CKM_HKDF_DERIVE, HKDF_DATA, HKDF_KEY_GEN excluded (creation).
- `ml_kem`: CKM_ML_KEM. `ml_dsa`: CKM_ML_DSA, HASH_ML_DSA and the
  ten HASH_ML_DSA_* hash variants. `slh_dsa`: CKM_SLH_DSA,
  HASH_SLH_DSA and the ten HASH_SLH_DSA_* variants.
- `chacha20`: CKM_CHACHA20, CHACHA20_POLY1305. (The SALSA20
  family stays unknown: no observed key type.)
- `poly1305`: CKM_POLY1305.
- Legacy block ciphers (RC2/RC4/RC5/DES/DES2/DES3/CAST/CAST3/CAST128/
  IDEA/CDMF/SKIPJACK/BATON/JUNIPER/CAMELLIA/ARIA/SEED/BLOWFISH/TWOFISH/
  GOST28147, KEA_KEY_PAIR_GEN excluded): infer display families
  `des`, `des3`, `camellia`, `aria`, `seed`, `gost` only — sign/encrypt
  use implies the family, but no size class (no length map, §5.3).
  RC4/RC5/CAST/IDEA/CDMF/SKIPJACK/BATON/JUNIPER/BLOWFISH/TWOFISH stay
  `unknown` (unobserved; adding them later is a table row, not a
  design change).

### 4.3 Attribution roles

The mechanism names the algorithm of the operation key only:

| Call | Family attaches to |
| --- | --- |
| `*Init` + operation calls | The Init key (`KeyRole::OperationKey`) |
| `C_WrapKey` | Wrapping key (input 0) only; wrapped key (input 1) gains nothing from this mechanism |
| `C_UnwrapKey` | Unwrapping key (input 0); the fresh view gains nothing from this mechanism (template + §5 U1 length only) |
| `C_EncapsulateKey` / `C_DecapsulateKey` | En/decapsulation key (input 0) |
| `C_DeriveKey` | Base key (input 0); ECDH-family on the base does not type the derived key |
| `C_SetOperationState` | Neither key (import stays uncertain) |
| NULL-mechanism cancel Init | Nothing (cancellation, not an operation) |

### 4.4 Multi-mechanism rows and conflicts

Rows aggregate across mechanisms (`AggKey` unchanged, §9). The row's
`inferred_family` accumulates: one family + supporting-completion
count; a second distinct *specific* family flips status to
`conflicting` and both families stay listed with counts (two
distinct specific families on one object names provider
non-compliance or hostile aliasing — visible, never resolved by
first-wins). The `secret` superclass never flips: it accumulates
its own completion count beside (or instead of) a specific family
and never raises `conflicting`, in either direction, against an
inferred family or an established key type — it is the weakest
claim the lane makes. A third and further distinct values are
counted, never listed: the first two values stay pinned in
`detail`/`conflict_detail` (families: `value`/`conflict_value`) and
`further_conflicts: u64` counts the extra distinct values (omitted
when 0, §10.2). The same keep-first-two-count-extras rule applies
to `inferred_size`. Against token-reported/creation-success
facts, an *incompatible* pair (§4.5) shows `conflicting` on the
inferred side while the established label stands (§3); a
compatible pair shows both sides with no conflict.

### 4.5 Inferred-family × established-key-type compatibility

The comparison left side is the receipt's frozen established key
type: the `query`/`creation_success` key-type fact snapshotted into
`metadata_at_use` at Init (frozen — a later query never re-opens
the comparison). The right side is the completion's inferred
family plus, where the row says so, the completion's mechanism.
A receipt with no established key type (the normal browser shape)
skips the comparison: the inference stands alone, never conflicting.

Compatible pairs (everything else cross-name is `conflicting`):

| Inferred family | Established key types | Mechanism qualifier |
| --- | --- | --- |
| `rsa` | `rsa` (`0x00`) | — |
| `ec` | `ec` (`0x03`) | — |
| `ec` | `ec_montgomery` (`0x41`) | ECDH1-family only (`CKM_ECDH1_DERIVE`, `CKM_ECDH1_COFACTOR_DERIVE`, the three `ECDH_*_AES_KEY_WRAP` ids) — the Firefox X25519/X448 derive case |
| `eddsa` | `ec_edwards` (`0x40`) | — |
| `xeddsa` | `ec_montgomery` (`0x41`) | — |
| `dsa` | `dsa` (`0x01`) | — |
| `dh` | `dh` (`0x02`), `x9_42_dh` (`0x04`) | — |
| `aes` | `aes` (`0x1f`) | — |
| `aes` | `aes_xts` (`0x35`) | XTS only (`CKM_AES_XTS`) |
| `generic_secret` | `generic_secret` (`0x10`), `hkdf` (`0x42`) | — |
| `hkdf` | `hkdf` (`0x42`), `generic_secret` (`0x10`) | — the Firefox TLS 1.3 case (ECDH result established as generic secret, then HKDF) |
| `des3` | `des3` (`0x15`), `des2` (`0x14`) | — (inert while both stay unlisted in the KeyType set) |
| `secret` | every established type | never flips (§4.4) |
| `ml_kem` / `ml_dsa` / `slh_dsa` / `chacha20` / `poly1305` / `des` / `camellia` / `aria` / `seed` / `gost` | same name only | — |

Key-type codes are `pkcs11.h:467-469` (`dh`/`ec`/`x9_42_dh`),
`:471` (generic secret), `:475-476` (des2/des3), `:486` (aes),
`:506-507` (chacha20/poly1305), `:508` (aes_xts), `:519-521`
(ec_edwards/ec_montgomery/hkdf). Twins (§12.1) pin every row:
X25519 + ECDH1 compatible, generic-secret + HKDF compatible,
AES + CONCATENATE (`secret`, no conflict), XEDDSA + Montgomery
compatible, XEDDSA + Edwards conflicting, RSA-established +
ECDSA-inferred conflicting, des2/des3 inert, CMS_SIG/PBA/PBKD2
infer nothing.

## 5. D3: size class from operation lengths

### 5.1 Capture protocols (F2, exact)

Arguments are zero-based. LP64: 8-byte words, args 0–5 in registers,
arg 6 at entry SP+8 (existing `target_stack_arg_address` helper).
ia32: 4-byte words on the stack, zero-extended after a successful
four-byte read, high-bit refusal. All indices are ≤ 6: no new
argument-7 exception is needed. FULL builds only (`KEM_CAPTURE_WIRED`
gate reused for the length adapters); P0 acquires nothing and reports
explicit unavailability. No length-cell pointer is retained beyond
its matching call; every terminal/loss/cancellation/exec/teardown
path clears it, exactly like the result-handle pointer row.

Two protocols (F2: never one shared read):

**S-protocol (output length cell, `CK_ULONG_PTR` out):** entry
retains the cell pointer; return reads one target word.

| Call | Cell arg | Notes |
| --- | --- | --- |
| `C_Sign` | 4 | `pulSignatureLen`; query (NULL `pSignature` arg 3) still reads at BPF: CKR_OK writes the required length, and userspace drops the query value (never classifies, §5.4) |
| `C_SignRecover` | 4 | RSA single-block output = modulus octets |
| `C_SignFinal` | 2 | Multipart terminal (fixture `rsa-ledger.c` multipart arm) |
| `C_Encrypt` | 4 | RSA output = modulus octets; other families classify to nothing (§5.3) |
| `C_WrapKey` | 5 | RSA wrap = wrapping-key modulus octets; AES-KW = wrapped material + 8 (§5.2) |
| `C_EncapsulateKey` | 6 | Ciphertext length; extends the existing KEM descriptor (T0 length lift, §11) |

Per-function output-buffer bases for the disjointness guard (the
call's own output-buffer pointer arg; the evidence table carries
the cell/scalar position, this table carries the base):

| Call | Base arg | Notes |
| --- | --- | --- |
| `C_Sign` | 3 (`pSignature`) | NULL in query shapes |
| `C_SignRecover` | 3 (`pSignature`) | NULL in query shapes |
| `C_SignFinal` | 1 (`pSignature`) | NULL in query shapes |
| `C_Encrypt` | 3 (`pEncryptedData`) | NULL in query shapes |
| `C_WrapKey` | 4 (`pWrappedKey`) | NULL in query shapes |
| `C_EncapsulateKey` | 5 (`pCiphertext`) | NULL in query shapes |

Explicit null-base rule: a NULL base skips the below-check and the
cell still reads (query shapes read). This diverges deliberately
from the KEM T0 path, which withholds on null ciphertext
(`object_flow.rs` KEM guard): T0 needs the ciphertext extent as a
bound, while the length cell needs only disjointness from a base
that a query shape does not pass. Copying the T0 withhold here
would fail the §12.1 length-query positives.

Entry guards: null cell → no retention (`length_query_no_cell`
unavailable); read the capacity C from the cell at entry (one
target word, full width — the cell is already allowlisted); C >
`1<<20` → unavailable (absurd capacity: the largest classifiable
evidence is the 49856-octet SLH-DSA-256f signature, so 1 MiB
admits every classifiable shape with headroom, and larger cells
are bulk-encrypt outputs that classify to nothing under §5.3);
cell full-span validation of `[cell, cell+W)`; non-NULL base →
checked `base+C` (overflow → unavailable) and disjointness
`[cell, cell+W)` ∩ `[base, base+C)` = ∅ on either side (the
provider writes at most C bytes by contract, so a disjoint cell
is sound under the existing hostile-caller rule; this admits the
common real layout — NSS `PK11_Sign` and pkcs11-provider pass a
heap buffer with the length word above it on the stack); overlap
→ unavailable, never a guessed bound; NULL base → skip the
check (the null-base rule above: query shapes read). Return
guards: owned entry/return lifetime match (image/owner/descriptor,
unchanged); `CKR_OK` with a non-NULL buffer → read (terminal);
`CKR_OK` with a NULL buffer → read (the query value; BPF cannot
tell it is a query without decoding the base, so it reads and
userspace drops it — never classified, never counted, §5.4);
`CKR_BUFFER_TOO_SMALL` → read (the provider wrote the exact
required length — PKCS#11 v2.40 §5.2: only BUFFER_TOO_SMALL is
exact, a NULL-buffer query "may somewhat exceed the precise
number"; userspace keeps it as corroboration, never as a
completion, §5.4; the `rsa-ledger.c` `too_small` arm pins the
read); `CKR_PENDING` → never (async results stay unavailable, as
v3:281-283); every other return → never. No retry after return.

**V-protocol (input length scalar, `CK_ULONG` in):** entry snapshots
the register/stack word; no dereference, no pointer retention. The
scalar snapshot is held in the side row until the matching return
and cleared on every terminal path (the same retention the
S-protocol cell gets: private in-flight + completed-call
transport, §8.3).

| Call | Scalar arg | Notes |
| --- | --- | --- |
| `C_Verify` | 4 | `ulSignatureLen` input (F2: NOT a pointer) |
| `C_VerifyFinal` | 2 | Multipart terminal scalar |
| `C_Decrypt` | 2 | `ulEncryptedDataLen`: RSA input = modulus octets (output length says nothing) |
| `C_UnwrapKey` | 4 | `ulWrappedKeyLen`: RSA input = unwrapping-key modulus octets; AES-KW = material + 8 |
| `C_DecapsulateKey` | 6 | Ciphertext input length (existing KEM descriptor: arg 6 stays "never consulted" as a *bound*; the V-protocol snapshots it as *evidence* — §11 amendment text is explicit) |

Userspace admits a snapshot only on `CKR_OK`. `CKR_SIGNATURE_INVALID`
is explicitly excluded: a provider may fail fast on a length
mismatch, so a rejected input length is ambiguous evidence. Same
exclusion for decrypt/unwrap failures: only successful consumption
proves the key's expected length.

Hostile-caller boundary (shared with v1:16-18): a malicious caller
can place any number in an allowlisted scalar word. Length words are
bounded (full-span validation, finite classification §5.2,
full-width equality with `1<<16`/`1<<32` OR-alias refusal) and only
their numeric value publishes — payload bytes are never read, so the
no-payload property holds absolutely; the soundness property (the
word is the true operation length) holds for non-hostile callers
plus guards. Overlap/alias twins (§12) pin the guards, not the
caller.

### 5.2 Length-to-size maps (keyed by mechanism subset, evidence kind, length)

A length alone never maps, and a family alone neither: every map
entry is keyed by the triple (mechanism subset, evidence kind,
length) from the same operation. Family-only subsets (hybrid or
ambiguous formats) infer the §4 family and classify every length
to `unknown` with a named reason. Lengths arrive as full-width
words; classification is full-width equality against finite sets.
RSA additionally admits non-standard octets inside 64..=2048 as a
masked class (an anti-alias admission bound, never rendered as a
range). No map entry renders a bit range anywhere (owner 07:52,
§15 K3).

- RSA sign/verify/cipher subset (every §4.2 `rsa` id EXCEPT
  `CKM_RSA_AES_KEY_WRAP`) × `sign_output` / `verify_input` /
  `encrypt_output` / `decrypt_input` / `wrap_output` /
  `unwrap_input`, octets L in 64..=2048: standard sizes name the
  size — 128 → "RSA 1024", 256 → "RSA 2048", 384 → "RSA 3072",
  512 → "RSA 4096" — each with "(from \<evidence\> length)" and
  JSON `size_class` + `modulus_bytes: L` (§10.2). A 2041-bit key's
  256-byte signature therefore shows "RSA 2048 (from signature
  length)": the source label keeps it honest, and `metadata_at_use`
  still never takes `rsa_2048` (the 2041 control pins that leak
  shut). Any other L in range → "RSA, \<masked\>-bit class (from
  \<evidence\> length)" where \<masked\> is 8L with the last two
  digits masked (2056 → "2,0xx", 1536 → "1,5xx"), JSON carries
  `modulus_bytes: L` only (no `size_class`). Outside 64..=2048 →
  `unsupported` (anti-alias bound: below 512-bit and above
  16384-bit RSA are not observed; widening the bound later is an
  amendment row, not new capture).
- `CKM_RSA_AES_KEY_WRAP` subset × `wrap_output` / `unwrap_input`:
  family-only (family `rsa`, no size). The hybrid format —
  RSA-OAEP block plus AES-KWP block, e.g. 256 + 40 = 296 — sizes
  neither key, so every length classifies `unknown` with reason
  `hybrid_wrap_format`.
- ECDSA subset (the `CKM_ECDSA*` sign/verify ids) × `sign_output` /
  `verify_input`, raw r||s: 64 → "EC P-256", 96 → "EC P-384",
  132 → "EC P-521" (2× field size), each with "(from \<evidence\>
  length)" and JSON `curve` + `octets` (§10.2). Curves sharing a
  field size (secp256k1/brainpoolP256r1 with P-256) alias to the
  same display; the `length` source marks it inferred, never
  established. Any other length → `unknown` with reason
  `variable_length_encoding` (DER and other curves; N6: the PKCS#11
  result representation is what was measured, not the TLS wire
  encoding — SoftHSM/pkcs11-tool produce raw 64-byte results,
  rv2 §6; NSS/browser format is measured in Task 5, never assumed).
- ECDH1-family subset (`CKM_ECDH1_DERIVE`,
  `CKM_ECDH1_COFACTOR_DERIVE`, `CKM_ECMQV_DERIVE`, the three
  `ECDH_*_AES_KEY_WRAP` ids): family-only (family `ec`, no size;
  derive mechanisms carry no S/V evidence position, and derived
  sizes come from templates).
- EdDSA subset (`CKM_EDDSA`) × `sign_output` / `verify_input`:
  64 → Ed25519, 114 → Ed448 (curve-unique fixed lengths, RFC 8032;
  the mechanism carries no curve parameter, so length determines
  it). Other → `unknown`.
- XEdDSA subset (`CKM_XEDDSA`): family-only (family `xeddsa`, no
  size — a 64-octet XEdDSA signature would alias Ed25519).
- ML-KEM subset (`CKM_ML_KEM`) × `encapsulate_output` /
  `decapsulate_input`, ciphertext octets: 768 → ML-KEM-512, 1088 →
  ML-KEM-768, 1568 → ML-KEM-1024 (FIPS 203 Table 2).
  Other → `unknown`.
- ML-DSA subset (`CKM_ML_DSA`, `HASH_ML_DSA`, the ten hash
  variants) × `sign_output` / `verify_input`: 2420 → ML-DSA-44,
  3309 → ML-DSA-65, 4627 → ML-DSA-87 (FIPS 204 Table 2).
  Other → `unknown`.
- SLH-DSA subset × `sign_output` / `verify_input`: 7856 →
  SLH-DSA-128s class, 17088 → 128f, 16224 → 192s, 35664 → 192f,
  29792 → 256s, 49856 → 256f (FIPS 205 Table 2). SHA2-vs-SHAKE
  stays ambiguous (shared sizes) and is said so.
- DSA subset × `sign_output` / `verify_input`: 40 → DSA 1024-bit
  class, 56 → DSA 2048/224 class, 64 → DSA 2048/256-or-3072 class
  (ambiguous, said so). Legacy; same adapter, table rows only.
- AES-KW subset (`CKM_AES_KEY_WRAP` only) × `wrap_output`:
  output L → wrapped-key material L−8 octets, attributed to the
  WRAPPED key (input 1) as `wrapped_material` evidence — it sizes
  the wrapped key, never the wrapping key. `KEY_WRAP_PAD`/KWP/
  PKCS7 (padded) → `unknown` with reason `padding_ambiguity`
  (L−8 is an upper bound, not a size).
- AES-KW subset (`CKM_AES_KEY_WRAP` only) × `unwrap_input` (U1):
  input L → unwrapped-key material L−8 octets about the fresh
  view. The fresh view has no row at unwrap time, so U1 parks on
  the view and the view's first sealed row carries it (§5.4, §9);
  padded variants → `padding_ambiguity` as above. (RSA-subset
  × `unwrap_input` needs no parking: it sizes the unwrapping key,
  the operation key whose row exists.)

### 5.3 What lengths do NOT determine (closed list)

HMAC tags and `*_HMAC_GENERAL` truncation (caller-chosen); AES
GCM/CCM/CBC/CTR/XTS and legacy-cipher encrypt/decrypt outputs
(plaintext-derived — for these mechanisms the captured output
length IS the message length plus tag or padding, read as a
scalar word; it classifies to nothing and is dropped in
userspace, §11); digests and `C_DigestKey` (no key info);
ECDH/DH outputs (derived-key size comes from the template
`CKA_VALUE_LEN`, not an operation length); HKDF/KDF outputs
(template-driven); `C_VerifyRecover` output (recovered plaintext
length); `*Update` chunk lengths (partial by construction);
`C_Message*` param-block lengths (no decoder, non-goal);
`secret`-family operations (no S/V evidence position, §4.2);
message/data/PIN lengths as payloads (never read — but output
lengths of stream-like ciphers equal message length plus
tag/padding and ARE read as words; only classified shapes
publish, §11); `CKA_VALUE` lengths (no read, unchanged). Each
(mechanism subset, evidence kind, length) triple outside §5.2
classifies to `unknown`/`unsupported` with the named reason —
never to a neighboring class.

### 5.4 Operation/session incarnation and late-result provenance (N5)

Completion length binds to the existing operation identity, never to
a re-looked-up key: every completed-call record at an evidence
endpoint carries (operation generation from `OpMachine`, fixed
`KeyReceipt`, mechanism, length evidence). Only a terminal
`CKR_OK` length with a non-NULL buffer counts as a completion and
classifies. Retained (non-End) completions — `CKR_BUFFER_TOO_SMALL`
and NULL-buffer query OK, which keep the machine alive under
`semantics_edge.rs:1690-1703` — feed a per-operation
corroboration slot instead of the join: `BUFFER_TOO_SMALL` values
are kept as corroboration (exact per PKCS#11 v2.40 §5.2) without
counting as completions; query values are dropped on arrival
(they may exceed the true length) and never stored, classified or
counted. On `Ended` the reducer compares: terminal length ≠
corroboration records the named residual `corroboration_mismatch`
(counted, never a conflict); equality (or no corroboration) is
silent. Operation 1 of `rsa-ledger.c:270-287` therefore yields
exactly one completion (query dropped, too_small corroborates,
terminal classifies) — never a triple count.

The reducer attributes the terminal length to the receipt's key
aggregate row as `inferred_size` (new row keys, §10); the frozen
`metadata_at_use` is untouched. Evidence about a key with no
sealed row yet (U1 about the fresh unwrap view; `wrapped_material`
about a wrapped key with no rows) parks on the key's view; the
key's first sealed row carries it as its initial `inferred_size`
(forward-fill onto a new row — never a `metadata_at_use` rewrite,
so the no-backfill pins stand). Parked evidence expires with the
view: it never migrates across sessions, handles or incarnations.
Session incarnation: lengths join only within the same owned
entry/return lifetime; cross-session handle reuse never joins
(existing rule, unchanged). Failures, cancellation and loss clear
retained cells and parked evidence with nothing recorded; a late
result after the row sealed lands on the row's inferred keys with
its own completion ordinal (rows are cumulative; inferred keys are
monotone: unknown → valued → conflicting, never valued → unknown;
`unsupported` is not a value — it never overwrites `inferred` and
never flips to `conflicting`; a row with only `unsupported`
evidence shows `unsupported`).

## 6. D4: creation-template curves and parameter sets (R2 land)

Port `task/v070-keysize-browser` 6839e226d (RED) + eba746421 (GREEN)
+ 2d37b0e28 (script) onto the v0.8.0 base (port, not blind
+cherry-pick: the branch predates keyrows Task 0/1 and the attach
+changes; re-check every seam). What lands unchanged: the finite
+read set (11/5-byte `CKA_EC_PARAMS` incl. the measured 11-byte
+draft-josefsson X25519 OID + four RFC 8410 OIDs; `CKK_HKDF`;
+value lengths 12/48; HKDF/concat derive-result protocols),
+the R2 promotion rule (successful creation promotes the fresh
+view's finite requested facts except `CKA_TOKEN`), the negative
+cases (typeless keypair, class-incompatible PQC triple, TOKEN never
+promotes, failed creation attaches nothing, class-0 data-object
+lens never label), and section version 6 scoping.

One refinement (owner/Opus note "facts carry their source", brief
"requested-with-success provenance"): promoted facts record source
`creation_success` per field (§3), distinct from `query`. R2's v6
schema file (PROPOSED, unshipped — no freeze violation) gains the
per-field `source` key before approval; v6 stays the R2 version.
Labels derived from promoted facts render identically to
query-established labels, but the objects[] view shows the source,
and CBOM qualifies them as established (§10.4 decision K4).

Generic unlisted-type creation row (beyond R2's KeyType set):
R2's finite KeyType set
(`0x00..=0x04 | 0x10 | 0x1f | 0x40 | 0x41 | 0x42 | 0x49..=0x4b`
after the R2 land — `object_policy.rs:76` plus R2's `0x42`) has no
`0x33`/`0x34` (`CKK_CHACHA20`/`CKK_POLY1305`,
`pkcs11.h:506-507`; the earlier draft's `0x55`/`0x57` were wrong —
`0x57` is the mechanism `CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH`,
`pkcs11.h:620`), so a creation template carrying an unlisted key
type — ChaCha20/Poly1305 are the observed instances — promotes
only the value-length fact (source `creation_success`, e.g. the
32-octet ChaCha20 key length) and never a label. The use-side
family for such keys still comes from the §4.2
`chacha20`/`poly1305` mechanism sets on successful operations.
Twins (§12.1, Task 1): a `0x33` creation promotes the value-length
fact with no label; a `0x34` creation likewise; a `0x33`-created
key used under `CKM_CHACHA20` infers family `chacha20` while its
established block stays label-free.

R2's measured non-yield (R2-doc §7.3: derive results never retained,
session pooling vs (session,handle) bindings) is re-proven on the
new base in Task 1: the entry-evidence gap belongs to keyrows/void
work if it persists, not to keymeta. Task 1 acceptance is the
RED→GREEN twins plus the R2 finite-set twins on the v0.8.0 base,
not browser yield (yield is Task 5, after keyrows Task 3).

## 7. Other cheap facts, ranked by value/cost

1. Attribute results apps already query — zero cost, already
   captured (H7-E4), already projected. Value: high wherever apps
   query (pkcs11-tool, OpenSSL provider); zero for browsers (measured
   R2 §1). No work; Task 5 measures the yield per app.
2. §4 family inference — userspace only, no BPF. High value
   everywhere (every successful operation carries a mechanism).
3. §5 wrap/unwrap lengths — same S/V adapters, two more functions.
   Medium value (wrapping-key class; wrapped-material length).
4. §6 R2 creation-template facts — port + review. High value for
   Firefox new-site keys; zero for Chromium (no creation calls).
5. O1 EC pair-mate inheritance (optional, Task 6): extend
   `resolved_label` to EC private mates of established `ec_p*`
   publics. Userspace + schema-label only, no new read. ~0 browser
   yield (needs the private's own class/type reads); worth it only
   beside queried-pair workloads. Optional lane, own twins.
6. CKA_ID-joined twin attribution (O3) — deferred past v0.8.0:
   needs BPF + policy for `CKA_ID` (v1 canaries plant id sentinels
   today), and the measured Chromium twin was type-only anyway.
7. `C_GetObjectSize` result — recommended NO: storage size is not
   key size (overhead included), value low, needs its own amendment.
8. `C_FindObjectsInit` templates — NO: prohibited, and still needs
   `CKA_ID` to join twins.
9. New attribute selectors — NO in v0.8.0: each is a full
   BPF+policy+canary cycle for low value.
10. `C_Message*` param-block lengths — NO: new decoder, no browser
    yield.

### 7.4 D6: per-key rows for --system without a manifest

No new authority is needed: the scan-derived publication-proved and
sole-complete-table claims (v3:106-161) already grant key-operations
runs without a manifest the SAME read set — a scan-derived claim
"never adds a field, an argument or a read beyond the rows below".
Every §4/§5/§6 fact therefore rides wherever rows exist, manifest
or not. The D6 row gap (rows not produced without a manifest) is a
row-existence question owned by keyrows follow-up, not keymeta:
keymeta consumes the §13 row interface and inherits D6's outcome.
Task 6 verifies the inheritance on one no-manifest `--system` run
(rows present ⇒ inferred keys present with identical rules) and
reports the row gap, if any, back to keyrows instead of working
around it here.

## 8. BPF design: evidence-only trailers (no object-lane contact)

### 8.1 Evidence positions (separate table — zero descriptor churn)

`object_descriptor()` (`object_policy.rs:163`) is UNTOUCHED: no new
`ObjectAction`, no new descriptors, no descriptor-field changes.
`OBJECT_ACTION_MAX` stays 14, `ObjectDescriptorWire` stays frozen
at 16 bytes, and the tail-contract comment ("no raw length",
`object_wire.rs:160-162`) stays true — evidence trailers ride
OUTSIDE the tail. The KEM exact-row check
(`object_flow.rs:590-597`) is untouched: descriptor rows do not
change shape.

Evidence positions live in a SEPARATE frozen table,
`EVIDENCE_POSITIONS` (new module
`crates/ebpf-common/src/evidence_table.rs`, keyed by function
ordinal, exact-count test pins 14 rows): each row names
`length_cell_arg` / `length_scalar_arg` (`ARG_NONE` when unused)
and, for Task 7, the info kind + read ranges (§17.1). The 14 rows:

| Function | Existing record (unchanged base) | Evidence trailer |
| --- | --- | --- |
| `C_Sign` | ordinary 368 (key comes from the Init receipt, §9) | length, S-cell arg 4 |
| `C_SignRecover` | ordinary 368 | length, S-cell arg 4 |
| `C_SignFinal` | ordinary 368 | length, S-cell arg 2 |
| `C_Verify` | ordinary 368 | length, V-scalar arg 4 |
| `C_VerifyFinal` | ordinary 368 | length, V-scalar arg 2 |
| `C_Encrypt` | ordinary 368 | length, S-cell arg 4 |
| `C_Decrypt` | ordinary 368 | length, V-scalar arg 2 |
| `C_WrapKey` | object 608 (inputs 2, 3; Access kept) | length, S-cell arg 5 |
| `C_UnwrapKey` | object 608 (input 2, result 7, template (5, 6); Unwrap kept) | length, V-scalar arg 4 |
| `C_EncapsulateKey` | object 608 (input 2, result 7; Encapsulate kept) | length, S-cell arg 6 |
| `C_DecapsulateKey` | object 608 (input 2, result 7; Decapsulate kept) | length, V-scalar arg 6 |
| `C_GetInfo` | ordinary 368 | info, pointer arg 0 (§17) |
| `C_GetTokenInfo` | ordinary 368 | info, slot scalar 0 + pointer arg 1 (§17) |
| `C_GetMechanismInfo` | ordinary 368 | info, slot scalar 0 + mechanism scalar 1 + pointer arg 2 (§17) |

The `C_UnwrapKey` creation template (5, 6) stays acquired by the
existing Unwrap adapter and stays authorized exactly as today
(allowlist-v3 unwrap row): it is an R2 promotion source (Task 1),
and nothing in this design removes or re-gates it. Evidence rows
carry no template pairs (T0-style: never authorized).

Non-interference (why the four B7 pins stand — Task 2 re-runs
each as a twin, §12.1):

- Journal classification: `endpoint_class` consults
  `is_modeled_function` ← `call_kind` ← `object_descriptor()`
  (`state.rs:211-213`), then the neutral list
  (`journal.rs:49-58`) and the proved-irrelevant list
  (`journal.rs:154-174`), all via `journal.rs:186-189`. None
  changes: the 3 info calls stay ProvedIrrelevant, the 7 length
  calls stay Neutral, Wrap/Unwrap/KEM stay modeled exactly as
  today. The no-tail path (`journal.rs:3127-3138`) is unchanged:
  evidence endpoints still produce no object row
  (`tail_absent`, `object_journal.rs:361`), and trailers are
  outside the journal payload.
- Journal census: `journal_class_for_descriptor` consults
  `endpoint_class` only (`attach/journal.rs:275-285`), so the
  pinned `[0,19,79,6]` (`attach/journal.rs:316-333` test) is
  byte-identical.
- Sole-complete set: the `plan.rs:11181-11193` test computes the
  required set from `kinds::object_descriptor`, a pure wrapper
  over `object_policy::object_descriptor` (`kinds.rs:25-30`) —
  unchanged, so the 20 names (`plan.rs:5793-5814`) stand with no
  condition-(c) amendment (§8.4).
- Alias agreement (`kinds.rs:90-123`): consults S1 shapes plus
  `object_descriptor` — unchanged. `C_Verify`/`C_VerifyFinal`
  share one S1 shape (`kinds.rs:308`) and both keep no object
  protocol, so they still agree (no new count-only downgrade).

### 8.2 Adapters

`adapter_length_entry` (shared, host-tested with injected readers,
BPF bindings only in `crates/ebpf/src/main.rs` beside
`object_entry_kem`): FULL-gate first (P0: mark unavailable, fetch
nothing); V-scalars snapshot via `arg_u64` (LP64 regs / ia32 stack /
LP64 arg 6 via the existing SP+8 helper); S-cells retained with the
§5.1 entry guards (null → no retention; entry capacity read with
the `1<<20` cap; full-span; disjointness vs the §5.1 per-function
buffer base on either side, with the explicit null-base rule: a
NULL base skips the check and the cell still reads — query shapes
read; overlap → unavailable).
`adapter_length_return`: owned-lifetime match, then the §5.1 return
rules (terminal OK / BUFFER_TOO_SMALL-on-cells / query-shape → one
word; PENDING and all else → no read, no retry). Both adapters live
in `crates/ebpf-common/src/object_flow.rs`. No existing adapter is
forked: the Wrap (Access), Unwrap, Encapsulate and Decapsulate
entry adapters still acquire their §8.1 existing positions
(inputs, result pointers, the unwrap template), and the length
adapters compose onto the same calls for the length positions only
(the KEM entry adapter is NOT forked either).

Retention reuses the two existing in-flight maps (no new map):
neutral endpoints stash in the S1 `START` map (`CallStart` gains
`ev_cell: u64` — retained S-cell pointer, V-scalar snapshot or
info pointer — plus `ev_kind: u8` and 7 pad bytes: +16 B/row ×
16384 entries = +256 KiB worst case); the 4 object endpoints stash
in `OBJECT_START` (`ObjectStart` gains `length_cell: u64`,
`length_scalar: u64`, `length_status: u8`, 7 pad bytes: +24 B/row
× 16384 = +384 KiB worst case). Every terminal/loss/cancellation/
exec/teardown path clears the stash, exactly like the result-handle
pointer row. Emission is reserve-and-fill (never stack-built), one
record per completed call: base + trailer (§8.3).

### 8.3 Wire: trailer forms and sizes

Five exact record forms; dispatch is by exact length only:

| Form | Bytes | Layout |
| --- | --- | --- |
| ordinary | 368 | `EventRecord` (unchanged; `lib.rs:2507` assert) |
| ordinary+length | 384 | 368 + 16-byte length trailer (`version: u16`, `kind: u8`, `status: u8`, `value: u64`, 4 reserved bytes) |
| ordinary+info | 496 | 368 + 128-byte info trailer (§17.4) |
| object | 608 | `EventRecord` + 240-byte v1 tail (UNCHANGED — `OBJECT_CALL_VERSION` stays 1, the `object_wire.rs:363` check and the v1 validator are byte-identical) |
| object+length | 624 | 608 + the same 16-byte length trailer |

FULL builds emit the trailer form at evidence endpoints on every
completed call (the status field marks unavailable shapes);
P0 builds emit the base form (nothing acquired, explicit
unavailability). Length-based dispatch (`object_record_form`,
`object_wire.rs:614-633`, plus its userspace mirror
`decode_object_record`, `src/events.rs:294-313`) gains the exact
lengths 384/496/624; every other length stays malformed. The
trailer validates against `EVIDENCE_POSITIONS` (exact version +
kind, function-matched row, zero reserved); the object-tail slice
`bytes[368..608]` still validates under the unchanged v1
validator. Old readers refuse the new lengths loudly (no silent
misparse). The `object_producer_compiled_frames_are_bounded`
512-byte frame test must pass unmodified in limit (frames are
adapter code, and records are reserve-filled, never stack-built;
if frames do not fit, the lane stops and reports — no silent
bound raise).

No new maps. No new arg-7 exception (all indices ≤ 6, §5.1).
Attach/plan: +0 newly probed functions and +0 endpoints — all 14
evidence endpoints already carry S1 probes (info:
`kinds.rs:184-191`; length: `kinds.rs:274-308`). The real cost is
per-call bytes on already-hot endpoints (368→384 on `C_Sign`/
`C_Encrypt`/`C_Decrypt` et al; 608→624 on Wrap/Unwrap/KEM;
368→496 on the rare info calls) plus the in-flight-row growth
above — sized by the ring-loss gate (§12.3), not by endpoint
count. The 8192 slot budget is unchanged.

### 8.4 Authority: no decoder-read-set change (no condition-(c) edit)

The decoder-read set is unchanged (no new descriptors, §8.1), so
the sole-complete-table condition (c) ("the 20 the decoder reads",
`plan.rs:5793-5814`) is UNCHANGED — the §11 amendment carries no
condition-(c) sentence. Evidence reads happen only at entries the
existing rules already admit for that endpoint in that mode; an
unreadable, foreign or degraded entry yields unavailable evidence
with a named reason at that entry and never refuses the provider
(the existing per-entry behavior, not a new rule). The earlier
"per-entry-optional length descriptors" split is deleted: there is
nothing to gate, because no entry is added. A provider with NULL
`C_SignRecover` keeps working exactly as today (no evidence at a
NULL entry — the entry does not exist).

### 8.5 Verifier and size budget

Per changed program: ≥5% verifier headroom on the 6.6 floor (R-52
precedent), `object_producer_compiled_frames_are_bounded` green,
`bpf-noninterference` baseline unchanged (no new maps, no new hook
sites, no new endpoints — all 14 evidence endpoints ride their
existing probes), `bpf loads` on vng 6.6/6.12 + host 7.x, LP64 +
ia32 load cells. The 6.1 E2BIG-style refusal precedent applies: if
a floor kernel refuses, the lane reports the named refusal instead
of simplifying the program.

## 9. Userspace join (N5 decided)

No mechanism dimension on `AggKey`: rows stay (instance, object,
category, role, metadata_at_use). Result-derived evidence gets its
own row keys (`inferred_family`, `inferred_size`, §10) and never
rewrites `metadata_at_use` — the frozen-at-Init contract and its
pins stand. The binding path, end to end:

1. The completed-call record (base + length trailer, one record —
   no pairing) decodes in `src/events.rs` (`decode_object_record`
   extended with 384/624); the trailer's evidence rides the
   record into `OpMachine` with (generation, fixed `KeyReceipt`,
   `mechanism: Option<u64>`).
2. Init-based operations (Sign/Verify/Encrypt/Decrypt + Finals):
   `OperationEffect::Ended` (today: id, category, outcome, origin
   — `semantics_edge.rs:347-352`) gains (generation, receipt,
   mechanism, terminal length evidence). Retained completions
   (BUFFER_TOO_SMALL / query-OK — `semantics_edge.rs:1690-1703`)
   never emit `Ended`; they feed the per-operation corroboration
   slot (§5.4), which `Ended` also carries for the
   `corroboration_mismatch` check.
3. Direct calls (`C_WrapKey`, `C_UnwrapKey`, `C_EncapsulateKey`,
   `C_DecapsulateKey` — `C_Sign`/`C_Encrypt` carry no inputs and
   join through the Init receipt instead): `DirectCompleted`
   gains the length evidence alongside its mechanism +
   key_receipts.
4. The key-use reducer attributes family (§4.3 roles, §4.5 compat)
   and size (§5.2 triples) to the receipt's aggregate row;
   U1/`wrapped_material` about a rowless key parks on the view
   (§5.4); unattributed completions (no receipt) carry nothing —
   no guessed rows.
5. Conflicts: second distinct specific family / size on a row →
   `conflicting` with both values + counts (§4.4); incompatible
   established pair (§4.5) → inferred side `conflicting`,
   established label stands (§3); `secret` and `unsupported`
   never flip.
6. Same-key/two-mechanism, session/handle reuse, failed-Init,
   PENDING, corroboration-mismatch and over-estimate-query
   controls are §12 twins.

Files: `src/events.rs` (trailer decode), `src/semantics_edge.rs`
(machine corroboration slot + both effects carry evidence),
`src/semantics_key_use.rs` (row accumulation, parking, compat),
`src/key_operation_projection.rs` (row keys + render),
`src/mechanism_names.rs` adjacent `family_table` (new module or
section; exhaustive §4.2 const tables + §4.5 compat table +
catalog coverage test).

## 10. Schema and output

### 10.1 Section versions (coordination)

- v6 = R2 new-site + per-field `source` (§6; R2's PROPOSED file is
  amended pre-approval). Emitted exactly when v6 content is present;
  v1–v5 stay frozen and byte-stable.
- v7 = keymeta inferred keys (this design). Emitted exactly when a
  row carries a non-blank `inferred_family`/`inferred_size`;
  v1–v6 stay frozen and byte-stable. (Per-field `source` lives in
  v6 — a view carrying a non-`query` source emits v6, never v7.)
- Version allocation is the integrator's: if keyrows claims a section
  version first for gap subjects, keymeta takes the next free number
  and this §10 is re-pointed (numbers only, shapes unchanged). The
  plan's Task 3 checks the allocation before writing schemas.
- Task 7 takes the next free number after v7 (suggest v8, §17.5).

### 10.2 v7 row keys (exact, closed)

On every `key_operations[]` row (absent below v7):

```json
"inferred_family": {
  "status": "inferred | unknown | conflicting | unsupported",
  "value": "rsa | ec | eddsa | xeddsa | secret | dsa | dh | aes | generic_secret | hkdf | ml_kem | ml_dsa | slh_dsa | chacha20 | poly1305 | des | des3 | camellia | aria | seed | gost | null",
  "completions": 10,
  "conflict_value": "same enum | omitted",
  "conflict_completions": "u64 | omitted",
  "further_conflicts": "u64 | omitted"
},
"inferred_size": {
  "status": "inferred | unknown | conflicting | unsupported",
  "detail": null | { "kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output | verify_input | encrypt_output | decrypt_input | wrap_output | unwrap_input" }
                  | { "kind": "rsa_nonstandard", "modulus_bytes": 257, "evidence": "sign_output | verify_input | encrypt_output | decrypt_input | wrap_output | unwrap_input" }
                  | { "kind": "ec", "curve": "p256 | p384 | p521", "octets": 64, "evidence": "sign_output | verify_input" }
                  | { "kind": "eddsa", "curve": "ed25519 | ed448", "octets": 64, "evidence": "sign_output | verify_input" }
                  | { "kind": "dsa_class", "label": "dsa_1024 | dsa_2048_224 | dsa_2048_256_or_3072", "octets": 40, "evidence": "sign_output | verify_input" }
                  | { "kind": "pqc_set", "parameter_set": "ml_kem_512 | ml_kem_768 | ml_kem_1024 | ml_dsa_44 | ml_dsa_65 | ml_dsa_87 | slh_dsa_128s | slh_dsa_128f | slh_dsa_192s | slh_dsa_192f | slh_dsa_256s | slh_dsa_256f", "octets": 1088, "evidence": "encapsulate_output | decapsulate_input | sign_output | verify_input" }
                  | { "kind": "wrapped_material", "material_octets": 24, "octets": 32, "evidence": "wrap_output | unwrap_input", "about": "wrapped" },
  "completions": 10,
  "conflict_detail": "same shape | omitted",
  "further_conflicts": "u64 | omitted"
}
```

`unknown`: no evidence or evidence outside every map (§5.3, with the
named reason in `-v`/JSONL detail, not in this closed shape).
`conflicting`: two distinct values observed — `detail` holds the
first, the second rides `conflict_detail` (same shape; omitted when
absent); for families the second rides `conflict_value` +
`conflict_completions` (§4.4: both sides stay listed with counts).
(`inferred_size` has no `conflict_completions` key by design:
`conflict_detail` is its second-value carrier, and the row-level
`completions` counts all completions behind both values.) A third
and further distinct values are counted in `further_conflicts`
(omitted when 0); the first two stay pinned and no third value is
ever listed. "Same size" means same `detail` kind + size params —
the evidence tag does NOT count (a 256-octet `sign_output` and a
256-octet `verify_input` are the same size; `detail` keeps the
first tag). "First" is first-seen in ingestion order (deterministic
per capture replay; multi-CPU interleaves order by ring timestamp).
`unsupported`: evidence exists but the (mechanism subset, evidence
kind) has no map (legacy ciphers, padded wraps, family-only
subsets); it never overwrites `inferred` and never flips to
`conflicting` (§5.4). Every transition of either inferred key bumps
the JSONL row revision. `metadata_at_use` semantics are unchanged;
`unknown` there beside valued inferred keys is the normal browser
shape, not a contradiction.

Views (`objects[]` established/requested blocks, v6): each
`metadata_field_*` gains `"source": "query | creation_success | null`
(`null` unless status is `value`; `requested` blocks: `creation_success`
is impossible, `null` or absent — the lane pins the exact spelling).

JSONL `key_operations_observed` / `object_observed` carry the same
keys under the same section version. `docs/schema/inventory-v1.md`
documents the row contract delta; `scripts/qualify-key-operations.py`
gains v6+v7 acceptance (extends 2d37b0e28's v6 acceptance).

### 10.3 Text: concise default, -v detail

Concise default keeps existing tallies; inferred facts appear only
as a parenthetical where they add information (rows whose
`metadata_at_use` is `unknown`):

- `sign: 12 operations (probably RSA 2048: 10; unknown: 2)`
- `verify: 10 operations (probably EC P-256: 10)`
- Non-standard RSA tallies as `probably RSA (non-standard length)`;
  `-v`/JSON carry the masked class + byte count.
- No inferred content anywhere → line renders exactly as today
  (byte-stable when v7 is absent).

`-v` per-row detail (exact wording pinned by twins):

- `probably RSA (from mechanism)` / `probably EC (from mechanism)`
  / `probably XEdDSA (from mechanism)` / `probably secret-key
  (from mechanism)` (the `secret` superclass)
- `RSA 2048 (from signature length)` /
  `EC P-256 (from signature length)` /
  `ML-KEM-768 (from ciphertext length)` /
  `wrapped material 24 bytes (from 32-byte wrap output, about wrapped key)`
- Non-standard RSA: `RSA, 2,0xx-bit class (from signature length)`
  (§5.2 masking rule; the byte count rides JSON `modulus_bytes`).
- The `\<evidence\>` noun follows the evidence tag: sign/verify →
  "signature", encrypt/decrypt/encapsulate/decapsulate →
  "ciphertext", wrap output → "wrap output", unwrap input →
  "unwrap input" (RSA subset, about the unwrapping key) or
  "wrapped key" (U1, about the fresh view) (twins pin each
  spelling).
- Conflicts: `family conflicting (RSA: 9, EC: 1)`; unknown reasons:
  `size unknown (variable-length encoding)`, `size unknown (padding ambiguity)`.
  Further distinct values append `, +N more` (`family conflicting
  (RSA: 9, EC: 1, +2 more)`); sizes likewise (`RSA 2048
  (from signature length), +1 more conflicting size`).

### 10.4 CBOM and profile

- Observed-profile v2/v3: untouched (never carry object facts).
- CBOM (`p11scope inventory cbom`, re-projection only, no new read):
  inferred (`mechanism`/`length` source) facts NEVER qualify for
  `related-crypto-material` established fields — a CBOM consumer
  must not mistake inference for attested metadata. R2-promoted
  (`creation_success`) facts DO qualify as established (K4,
  recommended): promotion soundness rests on provider compliance,
  the same trust the observer already places in query results (R2
  text). The CBOM exporter records the source in
  `metadata.properties` provenance tallies. If K4 review disagrees,
  the fallback is query-only qualification (one predicate, no
  schema change).

## 11. Allowlist-v3 amendment text (PROPOSED, written by this design)

Status when merged: PROPOSED for owner/Opus privacy review + Codex
re-review; not active until reviewed. Placement: the R2 block (§6,
the `eba746421` allowlist hunk) plus a new `## Key metadata:
inferred family and size class (v0.8.0 keymeta)` section, appended
after the last section, plus the field-inventory edit below. Header
status line gains both sections (PROPOSED). v1/v2 bytes unchanged.
There is no descriptor-table edit and no authority-condition edit:
evidence reads add no descriptors and change no entry gating
(§8.1, §8.4) — the amendment adds fields, not entries.

Edit 1 — field inventory (§Field inventory and retention): append
rows: `Operation length cell (S-protocol)` (named out positions,
entry retention with entry capacity read + `1<<20` cap, full-span +
disjointness guards, terminal-OK / BUFFER_TOO_SMALL / query-shape
return read, PENDING never, clear on every terminal path; private
in-flight + completed-call transport; public numeric value only
from CLASSIFIED shapes per §5.2 — query values never classify,
BUFFER_TOO_SMALL corroborates only, §5.4); `Operation length
scalar (V-protocol)` (named in positions, entry snapshot, no
dereference; admitted userspace-side on CKR_OK only; same
retention/publication); `KEM length lift` (encapsulate arg 6 cell /
decapsulate arg 6 scalar snapshot; T0 stays for template headers,
values, ciphertext bytes and bounds — arg 6 as a *bound* stays
forbidden, as *evidence* it is snapshotted).

R2 block (merged by the same Task 0, reviewed together): the
`eba746421` allowlist-v3 hunk (finite creation-template read set,
R2 promotion rule, v6 scope — 115 changed lines) with the
per-field `source` refinement (`creation_success` on promoted
fields, `query` on queried fields, §6/K5) instead of R2's
sourceless promotion. Task 1 consumes this approved block; there
is no other R2-amendment owner.

New section body (normative):

> **Status: PROPOSED (v0.8.0 keymeta design 2026-11-14); owner/Opus
> privacy review and Codex re-review required before activation.**
> This section scopes section version 7 of
> `inventory-v1-object-observations-v7.schema.json`: the
> `inferred_family`/`inferred_size` row keys and the finite
> family/length vocabulary below (per-field `source` on
> established/requested blocks is v6, via the R2 block above). It
> partially supersedes "requested metadata never labels" only via
> the R2 promotion (§6, v6); it partially supersedes the F16 rule
> "a code alone, a type alone, or a recognized mechanism never
> labels" for inferred facts only: a recognized mechanism infers a
> family (§4.2, display "probably …"), never an established label.
> Inferred facts never label `metadata_at_use` and never overwrite
> established facts. KEM T0 stays except the length lift above;
> terminal states, `CKA_ID`/payload/PIN prohibitions and every
> other exclusion stay in force. Allowlist-v1 bytes are unchanged.
>
> What is captured: one output-length WORD per completed call at
> the §8.1 evidence endpoints (signature, ciphertext and wrap
> lengths), plus the already-captured mechanism id the family
> inference reuses (no new read). BPF cannot see the mechanism
> family at `C_Encrypt`/`C_Decrypt`, so those words are read for
> every mechanism — for AES-GCM/CBC the word IS the message length
> plus tag or padding. This lane therefore partially supersedes
> `allowlist-v1.md:99-101` ("message/data/PIN/signature lengths
> are not captured") for its own words only: length words are
> within the owner privacy line (lengths, mechanism ids, curve
> OIDs and parameter-set ids are not secrets — owner stance
> 2026-11-14), v1 bytes are unchanged, and every other v1
> statement stands. Unclassified length values are dropped in
> userspace: never published, never logged, never written to
> JSONL — only the §5.2 classified shapes publish, with the
> `length` source and the named evidence tag.
>
> Length words are scalars under the v1 hostile-caller boundary: a
> malicious caller can place any number in one, so classification is
> full-width (§5.2 finite triples) and only the numeric value publishes.
> Payload, key-material, PIN and environment bytes are never read;
> the length value is the only new word. Standard RSA octet lengths
> (128/256/384/512) name the standard size with the `length` source;
> other admitted octets show a masked class with the byte count;
> ECDSA raw lengths name P-256/P-384/P-521 with the `length` source;
> PQC lengths name the parameter set; no bit range is rendered
> anywhere (owner 07:52). Wrapped-material lengths size the wrapped
> key, never the wrapping key. Family inference uses
> already-captured mechanism ids and the §4.2 explicit sets;
> unlisted and vendor ids infer nothing.
>
> Required evidence before activation: the §12 twin tables (host
> RED/GREEN at the journal seam, hostile-width, overlap/alias,
> 2041-bit and DER/padding negative controls), canary lanes with
> length-cell sentinel positions on every §5.1 shape (LP64+ia32)
> proving no payload byte reaches output/maps/logs, verifier
> headroom + `bpf loads` (§8.5), full `artifact_contracts`, and the
> Task 5 live matrix (Firefox/Chromium/pkcs11-tool/OpenSSL
> provider, ≥5 runs each, 6.6+).

## 12. Tests and live proof

### 12.1 Host twins (RED-first, journal seam, `newsite_*` style)

Per §5.1 shape (S-cell and V-scalar, LP64 + ia32 widths): positive
(CKR_OK reads), length-query positive (NULL buffer + OK reads at
BPF — userspace drops the value, §5.4),
BUFFER_TOO_SMALL positive on cells (read; kept as corroboration
only, §5.4), PENDING negative, NULL-cell negative, failure-RV
negative, SIGNATURE_INVALID negative for verify scalars,
owner-mismatch negative, null-base positive per S-shape (NULL base
+ CKR_OK reads — the §5.1 null-base rule, one twin per each of the
6 S-shapes, including encapsulate where it diverges from the T0
null-ciphertext withhold), disjointness twins (cell above the
buffer accepted — the NSS/pkcs11-provider layout; cell
on/inside `[base, base+C)` refused; `base+C` overflow refused;
C > `1<<20` refused with a named reason; sentinel payload word
behind the cell classifies to nothing outside its map).
Per §5.2 triple: RSA-subset 256→`size_class` 2048 +
`modulus_bytes` 256 (and `metadata_at_use` NOT `rsa_2048`: the
2041-bit control), RSA 257→masked `2,0xx-bit class` +
`modulus_bytes` only (no `size_class`), RSA 192→`1,5xx-bit
class`, RSA_AES_KEY_WRAP 296→family `rsa`, size unknown
`hybrid_wrap_format`; ECDSA 64/96/132 → P-256/P-384/P-521,
70-byte ECDSA → unknown `variable_length_encoding`, ECDH1-family
mechanisms → family-only; EdDSA 64/114; XEDDSA 64 → family
`xeddsa`, size unknown (no Ed25519 alias); KEM 768/1088/1568,
ML-DSA 2420/3309/4627, SLH-DSA six classes + hash-ambiguity note,
DSA 40/56/64, AES-KW × `wrap_output` L→L−8 about-wrapped, U1
× `unwrap_input` L→L−8 parked-then-forward-filled (§5.4), KWP →
`padding_ambiguity`, HMAC/GCM/digest/ECDH-output lengths →
unknown (each pinned: the length is captured, the class is
refused; the GCM value never publishes — §12.2 canary).
Family (§4.2 + §4.5): every listed id infers;
vendor/unlisted/keygen ids infer nothing; CMS_SIG/PBA/PBKD2 infer
nothing; two-specific-family conflict; `secret` beside any family
never conflicts (AES + CONCATENATE twin); three-family
`further_conflicts` count (first two pinned, third counted, never
listed); same keep-first-two-count-extras twin for sizes;
compat-twin per §4.5 row (X25519 + ECDH1, generic-secret + HKDF,
XEDDSA + Montgomery compatible, XEDDSA + Edwards conflicting,
RSA-established + ECDSA-inferred conflicting, des2/des3 inert);
incompatible established pair → inferred side conflicting, label
stands; receipt without an established type → inference stands
alone. Same-size twin (sign 256 + verify 256 = one size, first
tag kept); interleave twin (first-seen in ingestion order);
`unsupported`-never-flips twin; revision-bump twin. Join (§9):
same-key/two-mechanism, session/handle reuse, failed-Init,
corroboration-mismatch residual, over-estimate-query twin (query
72, too_small 64, terminal 64 → one completion, no conflict),
U1 forward-fill twin (fresh view → first row; no-backfill pins
re-run green).
Non-interference twins (B7): journal census `[0,19,79,6]`
re-run green, sole-complete test re-run green, alias-agreement
twin (`C_Verify`/`C_VerifyFinal` still agree), journal-class
snapshot (info still irrelevant, length still neutral),
dispatch twins (384/496/624 accept, neighbors malformed, old
lengths unchanged).
R2 port (§6): RED→GREEN twins + finite-set twins on the new base;
generic unlisted-type twins (`0x33`/`0x34` promote the
value-length fact with no label; use-side family still infers).

### 12.2 Canaries (proving no payload/key bytes captured)

Extend `scripts/fixtures/canary_workload.c` with length-cell
positions on every §5.1 shape: sentinel payload buffers adjacent
to the cells (sentinel bytes chosen to collide with accepted
lengths, e.g. a 256-valued payload word), NULL/query shapes,
absurd-capacity cells, and ia32 twins; plus the Task 7 sentinel
positions (§17.6: sentinel serial/label/session/memory/utcTime
and sentinel `CK_INFO` pads). `scripts/verify-canaries.sh` +
`check-canary-evidence.py` assert: the length VALUE publishes
exactly on CLASSIFIED shapes only (§5.2); no sentinel payload
byte appears in JSON/logs/maps; hostile-width cells (ia32
high-bit, `1<<16`/`1<<32` OR-alias) classify to nothing. The
AES-GCM canary: a GCM encrypt of sentinel plaintext publishes no
length anywhere (the captured word is dropped unclassified, §5.3).
The positive control proves the scanner sees planted length values.

### 12.3 Gates and live proof (Task 5)

Canonical gates on the candidate (fmt/check/test/clippy, release
toolchain), full `artifact_contracts` (no blanket excludes, no
zero-match selectors), privileged lib cells, `bpf-kernels.yml`
loads, public-CLI cells. Per-call overhead + ring-loss gate
(Task 2 measures, Task 5 re-runs on the candidate): scripted
`C_Encrypt` AES-GCM and `C_Sign` at 5k and 10k calls/s each, with
and without the lane — record per-call ns delta, ring bytes/s
(384/624-byte forms), and ring-loss counts; the lane passes if
loss at 5k calls/s stays zero and loss at 10k calls/s does not
regress vs the no-lane baseline (numbers recorded, not
threshold-gamed — a regression stops the lane for a design
revisit). Live matrix on 6.6+ (vng 6.6/6.12 + host
7.x split): Firefox (Playwright, strict), Chromium (Playwright,
strict), pkcs11-tool (scripted RSA/ECDSA sign+verify, keygen),
OpenSSL provider (pkcs11-provider + SoftHSM signs) — ≥5 runs EACH
(20 runs; per-app proof is required because yields differ by
mechanism: Chromium RSA signs vs Firefox ECDH/HKDF/AES/KEM).
Per-run denominator: eligible rows (successful attributed
completions under listed mechanisms) → inferred fraction, with
named reasons for every residual unknown. Chromium client-cert
expectation: RSA rows → RSA 2048; Firefox new-site:
R2 curves + inferred families on created keys, ECDH/HKDF rows
family-only where no length map exists.

## 13. Composition with keyrows: interface, DAG and file ownership

Consumed interface (keyrows produces, keymeta reads, never writes):
sealed per-key aggregate rows (`AggKey` buckets + counters),
`KeyReceipt` operation identity (generation, fixed receipt,
mechanism), unknown-key rows and unattributed counters, per-key
gap subjects. Keymeta adds `inferred_family`/`inferred_size` keys
to rows that exist; a row that never seals carries nothing (no
guessed rows, no void/fence/birth/seal contact).

One DAG (keyrows plan `4cca0dd88`; keymeta tasks are this plan):

```
keyrows T0 ──► keyrows T1 ──► keymeta T1 ──► keyrows T3 ──► keyrows T4 ──► keymeta T3 ──► keymeta T7 ──► keymeta T6
                  │                │                                                     ▲
                  │                └────► keymeta T2 ────────────────────────────────────┘
                  │                              (wire base for T3/T7)
                  ▼
             keymeta T0 ──► Task 7 Step 0 (§17.3 allowlist block)
             (docs; independent of code order)

keymeta T4 (canaries) after keymeta T3 + keymeta T7 merges (owns canary files;
  Task 7 positions arrive as specified input, §17.6) — parallel-safe with keyrows.
keymeta T5 (live proof) after keymeta T4 + keymeta T7 + keyrows T4 (yield needs
  rows AND facts; carries the Task 7 info positives, §17.6).
```

Why this order: keymeta Task 1 edits `state.rs`,
`semantics_key_use.rs` and `semantics_objects/journal.rs` — the
same files keyrows Tasks 0, 1, 3 and 4 edit (keyrows plan
`4cca0dd88`: T0 `:85-88`, T1 `:134-136`, T3 `:261-264`, T4 `:290`),
so the old "disjoint files" claim is dropped and the merge
serializes. Keymeta T1 lands between keyrows T1 and T3 (its R2
hunks are small and region-disjoint; keyrows T3 rebases over them
and re-runs). Keymeta T2 (ebpf-common evidence table/trailers,
`main.rs`, `CallStart`, `src/events.rs` dispatch) is file-disjoint
from keyrows but consumes the T1 base (shared
`object_policy.rs`/`object_flow.rs`/`object_wire.rs` — one writer
at a time, never parallel with T1). Keymeta T3 (join + v7 +
projection) consumes sealed rows, so it merges after keyrows T4,
developing against recorded fixtures until then. Keymeta T7
consumes the T2 wire base through the T3 chain and shares
projection/schema/test files with T3 — merges after T3. Task 4
owns the canary files alone (Task 7 never writes them). Task 5
runs after Tasks 1–4 AND Task 7 (it checks Task 7 results).

File ownership (ordered writers; each merge re-runs the affected
twins on the merged SHA):

| File | Ordered writers |
| --- | --- |
| `src/semantics_objects/journal.rs` | keyrows T0 → T1 → keymeta T1 → keyrows T3 |
| `src/semantics_key_use.rs` | keyrows T0 → T1 → keymeta T1 → keyrows T3 → keymeta T3 |
| `src/semantics_objects/state.rs` | keymeta T1 → keymeta T6 (EC arm, optional) |
| `src/key_operation_projection.rs` | keymeta T1 → keyrows T4 → keymeta T3 |
| `src/inventory/present.rs` | keyrows T0 → T1 → T3 → T4 → keymeta T3 → keymeta T7 |
| `src/inventory/present_key_ops_tests.rs` | keyrows T0 → T3 → T4 → keymeta T3 → keymeta T7 |
| `src/semantics_edge.rs`, `src/events.rs` | keymeta T2 (dispatch) → keymeta T3 (effects/compat) → keymeta T7 (info decode) |
| `crates/ebpf-common/src/object_{policy,flow,wire}.rs` | keymeta T1 (R2 finite sets) → T2 (length) → T7 (info) |
| `crates/ebpf-common/src/evidence_table.rs` (new) | keymeta T2 → keymeta T7 |
| `crates/ebpf/src/main.rs`, `ebpf-common/src/lib.rs` (`CallStart`) | keymeta T2 → keymeta T7 |
| `docs/privacy/allowlist-v3.md` | keymeta T0 (§11 + R2 block) → Task 7 Step 0 (§17.3) |
| `docs/schema/inventory-v1.md`, `scripts/qualify-key-operations.py` | keymeta T1 (v6) → T3 (v7) → T7 (v8) → T6 |
| `src/inventory/cbom/render.rs`, `docs/cbom-export.md` | keymeta T3 → keymeta T7 |
| canary files (`canary_workload.c`, `verify-canaries.sh`, `check-canary-evidence.py`, `test_canary_object.py`) | keymeta T4 alone |

Schema version allocation is the integrator's (§10.1). No v0.8.0
task depends on the postponed Task 8 (§18).

## 14. Risks

- Short post-void windows seal no rows even after keyrows Task 3
  (§11 keyrows decision, C4-conditional): keymeta facts have no
  rows to ride. Mitigation: Task 3 fixtures first; Task 5 gated on
  keyrows C4 showing rows in re-selected segments.
- Disjointness cell guards over-refuse legitimate layouts (the old
  wholly-below guard refused the common heap-buffer/stack-word
  layout outright — fixed by design in §5.1 before the Task 0
  merge). Residual: absurd-capacity or overlapping cells on real
  apps. Mitigation: Task 2 measures the refusal rate per shape on
  real apps; if a shape sterilizes, narrowing needs reviewer
  approval (amendment row, not silent).
- NSS/browser ECDSA format differs from SoftHSM raw (DER?) —
  measured in Task 5, never assumed; DER classifies unknown with
  reason (no yield loss vs today, which is 0 typed).
- Section-version collision with keyrows gap subjects: mitigated by
  integrator allocation (§10.1).
- Ring pressure from longer records (368→384, 608→624 on hot
  endpoints): +0 endpoints, so slot budgets are untouched — the
  cost is bytes/s. Sized by the §12.3 ring-loss gate; a regression
  stops the lane for a design revisit, never a silent budget or
  threshold change.

## 15. Open decisions (DECIDED by controller rulings)

- K1: BUFFER_TOO_SMALL lengths corroborate; query values never
  classify. REFINED (round 6, was: accepted as completions): only
  BUFFER_TOO_SMALL returns the exact number (PKCS#11 v2.40 §5.2 —
  a NULL-buffer query "may somewhat exceed the precise number"),
  so BUFFER_TOO_SMALL values corroborate without counting as
  completions, and query values are dropped on arrival (§5.4; pins
  the `too_small` arm without the triple count).
- K2: SIGNATURE_INVALID verify lengths excluded. DECIDED YES
  (ambiguous evidence; revisit only with per-provider proof that a
  provider length-checks before crypto-failing).
- K3: RSA size display. OVERRIDDEN by owner 2026-11-14 07:52
  (was: RANGE with arithmetic class): a standard octet length
  (128/256/384/512) shows the standard size — text "RSA 2048 (from
  signature length)", JSON `size_class: 2048` + `modulus_bytes: 256`
  under the length-evidenced `inferred_size` key. Only a non-standard
  admitted octet
  length shows a masked class ("RSA, 2,0xx-bit class (from signature
  length)") with the byte count. Same rule for the other families:
  ECDSA raw lengths → P-256/P-384/P-521, ML-KEM/ML-DSA lengths →
  parameter sets. The evidence tag keeps it honest; no range text
  is rendered anywhere. The 64..=2048 admission bound stays as
  anti-aliasing (real odd sizes like 192-byte/1536-bit stay
  classed); widening it later is an amendment row.
- K4: CBOM qualifies `creation_success` facts as established.
  DECIDED YES (§10.4); fallback query-only is one predicate.
- K5: v6 amended pre-approval with per-field `source` (vs v6 as R2
  wrote it + source only in v7). DECIDED AMEND (v6 unshipped;
  one coherent version; R2 re-review covers it).
- K6: Live matrix 5 runs/app (20) vs 5 total. DECIDED 5/APP
  (per-app mechanism yields differ; a 5-total matrix cannot prove
  both Chromium-RSA and Firefox-new-site).

## 16. Review provenance

Round 1 (this document): dispositions of rv2 F1–F4/N5/N6 in §2;
Codex re-review + Opus privacy review required on the §11 text
before any BPF change (F2 fix line). No implementation, no capture
change, no assertion change in this lane.
Round 2: spark-review findings 1–9 fixed in place (§8.1 action
table + counts, Task 1→2 order, §5.1 base table + null-base rule,
§6 ChaCha20/Poly1305 row, §11 F16 rule naming, V-protocol
retention wording, keep-first-two-count-extras conflicts, Task 5
executable PQC pointer); K1–K6 recorded as decided (§15); §17
added (optional provider/token/mechanism info, owner question
pending, droppable).
Round 3 (owner decisions 2026-11-14 07:35): §17 Task 7 REQUIRED
(exact §17.3 amendment block written, string-trimming rule,
library/token/device CBOM components + algorithm limits, pinned
concise wording, unconditional canary/live); new §18 Task 8
mechanism parameters (exact per-mechanism field lists against
cryptoki-sys 0.5 bindings, exact-length pointer-safety rule, new
shape codes, honored-only publication, §18.5 amendment block,
§18.8 exclusions); 8.05/8.06 noted out of scope (§1); order and
risks extended (§13, §14).
Round 4 (owner decisions 2026-11-14 07:40 + 07:52): Task 8
postponed to Later (§18 shortened to a pointer, full round-3 text
in history; no v0.8.0 BPF/schema/privacy rows; nothing depends on
it); K3 overridden to standard-size display with no range text
(§5.2, §10.2, §10.3, §15); Task 7 stays required.
Round 5 (fix4 review findings 1–6): §17.1 rebuilt on per-ABI
cryptoki-sys 0.5.0 layouts (packing evidence, exact LP64/ia32
offsets, per-ABI read lists, 4-layer BPF validation); Task 7
merge order made explicit (after Task 3, Step 0 after Task 0,
Task 6 after Task 7 — §13 + plan Tasks 0/3/6/7); §8.5 count
fixed to 7; K3 reworded onto the closed §10.2 shape (§15);
§17.3 gains the condition-(c) Edit 3 and §17.4 names wire
value 16; plan Tasks 2/7 Step 1 gain the dropped negatives.
Round 6 (Opus review B1–B9 + Important 1–11 + minors, all fixed
pre-Task-0): §4.2 `secret` superclass + `xeddsa` family +
CMS_SIG/PBA/PBKD2 infer-nothing, new §4.5 compat table; §5.2
keyed by (mechanism subset, evidence kind, length) with
family-only subsets + U1; §5.1 disjointness guard (+1 MiB
capacity cap) and §5.4 corroboration slot (K1 refined);
evidence-only trailers replace all descriptor churn (§8.1/§8.3/
§8.4, no condition-(c) edit, +0 endpoints, 384/496/624 forms);
§11 states the capture + v1:99-101 lane supersession and merges
the R2 block; §10.2 gains `secret`/`xeddsa` + size-identity
rules, per-field `source` stays v6; §12 twins/canaries/gates
cover every case incl. the ring-loss gate; §13 is one DAG with
file ownership against keyrows `4cca0dd88`; §17 reads
`CK_INFO` field ranges, publishes PIN policy (not serials),
rules repeats, lands in default inventory/CBOM (§17.7), takes
the third 496-byte form (§17.4), and pins supplier/slot-mapping
rules; ChaCha20/Poly1305 corrected to `0x33`/`0x34` (generic
unlisted-type row).

## 17. Required: provider, token and mechanism info (Task 7)

Owner decision 2026-11-14 07:35: v0.8.0 captures `C_GetInfo`,
`C_GetTokenInfo` and `C_GetMechanismInfo` results for the inventory
(JSON + concise/`-v` text) and CBOM. This section designs that
capture as required plan Task 7; it shares no wire version and no
schema section with Tasks 0–6 (separate amendment rows, §17.3), so
its review lane stays independent even though it now ships with
them.

### 17.1 Read set (fixed-size struct reads at return)

Arguments are zero-based; all indices ≤ 2 (no arg-7 exception).
Layouts below are transcribed from the product's ABI pin,
cryptoki-sys 0.5.0 (`Cargo.toml:38`, `Cargo.lock:178-181`), whose
per-target bindgen files carry compile-time size/offset asserts:
`src/bindings/x86_64-unknown-linux-gnu.rs` (LP64) and
`src/bindings/i686-unknown-linux-gnu.rs` (ia32). Both files
number identically: `CK_VERSION` :1308, `CK_INFO` :1321 with
asserts :1330-1340, `CK_MECHANISM_INFO` :1397 with asserts
:1404-1410, `CK_TOKEN_INFO` :1468 with asserts :1490-1526.

Linux packing is natural C alignment (`#[repr(C)]`, e.g. LP64
:1319): the header's 1-byte pack is Windows-only —
`vendor/pkcs11.h:10-12` guards `#pragma pack(push, cryptoki, 1)`
with `#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)`
(pop at :2774-2775), and `build.rs:120-122` rewrites bindgen's
`#[repr(C, packed)]` to `#[repr(C)]` plus a windows-only packed
attribute. `CK_ULONG`/`CK_FLAGS` are `c_ulong` (:1056/:1074):
8 bytes on LP64, 4 on ia32 — so ia32 differs from LP64 in
offsets, sizes AND padding, never "only in width".

Per-ABI field offsets (`@off[width]`; `R` = read, `–` = never
fetched (§17.2), `P` = padding, never fetched — every pad byte
sits outside the read ranges, so uninitialized caller bytes never
reach the ring or userspace, per §17.2's own "never fetched, not
read-and-scrubbed" rule).

`CK_INFO` — LP64 88 B (align 8), ia32 76 B (align 4):

| Field | LP64 | ia32 | Use |
| --- | --- | --- | --- |
| cryptokiVersion | @0[2] | @0[2] | R |
| manufacturerID | @2[32] | @2[32] | R |
| (pad) | [34..40) | [34..36) | P |
| flags | @40[8] | @36[4] | R |
| libraryDescription | @48[32] | @40[32] | R |
| libraryVersion | @80[2] | @72[2] | R |
| (tail pad) | [82..88) | [74..76) | P |

`CK_TOKEN_INFO` — LP64 208 B (align 8), ia32 160 B (align 4),
LP64 only has a 4-byte tail pad (last field ends at 204):

| Field | LP64 | ia32 | Use |
| --- | --- | --- | --- |
| label | @0[32] | @0[32] | – |
| manufacturerID | @32[32] | @32[32] | R |
| model | @64[16] | @64[16] | R |
| serialNumber | @80[16] | @80[16] | – |
| flags | @96[8] | @96[4] | R |
| ulMaxSessionCount | @104[8] | @100[4] | – |
| ulSessionCount | @112[8] | @104[4] | – |
| ulMaxRwSessionCount | @120[8] | @108[4] | – |
| ulRwSessionCount | @128[8] | @112[4] | – |
| ulMaxPinLen | @136[8] | @116[4] | R |
| ulMinPinLen | @144[8] | @120[4] | R |
| ulTotalPublicMemory | @152[8] | @124[4] | – |
| ulFreePublicMemory | @160[8] | @128[4] | – |
| ulTotalPrivateMemory | @168[8] | @132[4] | – |
| ulFreePrivateMemory | @176[8] | @136[4] | – |
| hardwareVersion | @184[2] | @140[2] | R |
| firmwareVersion | @186[2] | @142[2] | R |
| utcTime | @188[16] | @144[16] | – |
| (tail pad) | [204..208) | none | P |

`CK_MECHANISM_INFO` — LP64 24 B (align 8), ia32 12 B (align 4):

| Field | LP64 | ia32 | Use |
| --- | --- | --- | --- |
| ulMinKeySize | @0[8] | @0[4] | R |
| ulMaxKeySize | @8[8] | @4[4] | R |
| flags | @16[8] | @8[4] | R |

Fixed read lists per call and ABI (full-span sizes differ — the
entry guard and the return reader both take the target's ABI):

| Call | Args | LP64 bytes read | ia32 bytes read |
| --- | --- | --- | --- |
| `C_GetInfo` | 0: `pInfo` | 76 B: [0..34) + [40..82) (pads [34..40) + [82..88) never fetched) | 72 B: [0..34) + [36..74) (pads [34..36) + [74..76) never fetched) |
| `C_GetTokenInfo` | 0: slotID (scalar), 1: `pTokenInfo` | 76 B: [32..80) + flags [96..104) + PIN lens [136..152) + versions [184..188) | 64 B: [32..80) + flags [96..100) + PIN lens [116..124) + versions [140..144) |
| `C_GetMechanismInfo` | 0: slotID (scalar), 1: mechanism type (scalar), 2: `pInfo` | whole struct, 24 B | whole struct, 12 B |

BPF-side validation (Task 7 implements all four layers): (1)
per-`LinuxLayout` const read-list tables (offsets, widths, span
sizes) in `crates/ebpf-common`, following the pkcs11-abi
`InterfaceLayout` pattern (`LinuxLayout::word_bytes`, per-layout
const fn) — ebpf-common is no_std on the kernel side and cannot
depend on cryptoki-sys (std + libloading), so the tables are
checked-in consts, not the bindgen types; (2) `const _: () =
assert!` / `const _: [(); N]` static asserts on the tables
(precedent: `crates/ebpf-common/src/lib.rs:1941-1945`) — every
range end ≤ its per-ABI span, every width = the ABI word; (3)
host tests in the ROOT crate cross-checking the LP64 consts
field-by-field against `size_of`/`offset_of` of the cryptoki-sys
types (`inventory_callers.rs:197-221` is precedent only for the
assert style — it checks the crate's own types, because
`crates/ebpf-common` has no cryptoki-sys dependency; the root
crate has it, `Cargo.toml:38`), so a pin bump that moves any
field fails the build; the ia32 consts are checked-in literals
cited to the i686 assert lines above, and the §17.6 ia32 host
twins (byte-exact buffers built at ia32 offsets) fail on any
wrong offset; an `artifact_contracts` case pins both read lists;
(4) at runtime the probe selects the
layout from the target CS register (`target_layout_from_cs`,
`crates/ebpf-common/src/lib.rs:65-68`) exactly like `arg_u64`
(`crates/ebpf/src/main.rs:2821`), and the full-span guard uses
that ABI's span size.

Protocol: entry retains the `pInfo` pointer with full-span
validation of the per-ABI fixed struct size (LP64/ia32: 88/76,
208/160, 24/12) and snapshots the slot/mechanism
scalars; return reads the fixed bytes on `CKR_OK` only. NULL
pointer → unavailable; any other return → never (no
BUFFER_TOO_SMALL/query-shape rule: these are not length cells).
Every terminal/loss path clears the retained pointer, exactly like
the S-protocol cell. FULL builds only; P0 reports explicit
unavailability.

Padded fixed-width strings (`CK_INFO.manufacturerID`,
`CK_INFO.libraryDescription`, `CK_TOKEN_INFO.manufacturerID`,
`CK_TOKEN_INFO.model`) are space-padded per the PKCS#11 spec:
userspace trims trailing spaces and NULs, truncates at the first
embedded NUL, and publishes the trimmed text; an all-spaces field
publishes as the empty string, never as spaces. Non-UTF8 bytes
refuse the field with a named reason (the row still publishes its
numeric fields).

### 17.2 Excluded fields (never read, not read-and-scrubbed)

`CK_TOKEN_INFO` excluded ranges are never fetched from the target
(the BPF read list is the four §17.1 ranges only):

- `serialNumber`@80[16] (same offset on both ABIs): an
  identifier — EXCLUDED by default, and
  this design provides no opt-in flag to capture it in v0.8.0.
  Reintroducing it needs its own amendment + owner/Opus review.
- `label`@0[32] (same offset on both ABIs): operator-set,
  identifier-ish — excluded (not
  requested, same treatment as the serial).
- Session counts, memory sizes: not requested — excluded.
- `utcTime`: a clock reading (environment) — excluded.

READ (policy state, not secrets — owner privacy line): the flags
word is published whole, INCLUDING the PIN-state bits
(`CKF_USER_PIN_COUNT_LOW`, `FINAL_TRY`, `LOCKED`, `TO_BE_CHANGED`
and the `SO_*` equivalents, `pkcs11.h:423-430`) — locked/final
try/count low/to be changed are useful operational facts, and the
owner line covers PINs/key material/payloads/env, not policy
state. `ulMinPinLen`/`ulMaxPinLen` are published for the same
reason (policy limits, not secrets). The schema (§17.5) has no
serial/label/session/memory/clock keys, so that exclusion is
structural: there is nowhere to publish them even by accident.

### 17.3 Allowlist-v3 amendment block (PROPOSED, written by this design)

Status when merged: PROPOSED for owner/Opus privacy review + Codex
re-review (the Task 0 gate applies to this block too); not active
until reviewed. Placement: a new `## Provider, token and mechanism
info (v0.8.0 keymeta Task 7)` section appended after the §11 keymeta
section, plus the field-inventory edit below (Task 7 Step 0
serializes after the Task 0 merge, §13 — shared file, one writer
at a time). Header status line gains the section (PROPOSED). v1/v2
bytes unchanged. No descriptor-table edit, no authority-condition
edit: §8.4 covers Task 7 too (fields, not entries).

Edit 1 — field inventory (§Field inventory and retention): append
rows: `Provider info struct (C_GetInfo)` (the two §17.1 field
ranges — the struct pads are never fetched, not read-and-scrubbed;
entry retention, full-span guard, CKR_OK return read only, clear on
every terminal path; private in-flight + completed-call transport;
public parsed fields only: cryptoki/library versions, manufacturer,
description, flags); `Token info ranges (C_GetTokenInfo)` (the
four §17.1 ranges — manufacturer, model, flags incl. the PIN-state
bits, PIN min/max lens, hardware/firmware versions — plus the slot
scalar from the base record; §17.2 bytes never fetched, not
read-and-scrubbed); `Mechanism info struct (C_GetMechanismInfo)`
(whole `CK_MECHANISM_INFO` + slot/mechanism scalars from the base
record; min/max key size as raw mechanism-dependent numbers,
flags incl. `CKF_HW`). Evidence reads ride already-admitted
entries only (the §8.4 rule, never provider-gating).

New section body (normative):

> **Status: PROPOSED (v0.8.0 keymeta Task 7 2026-11-14);
> owner/Opus privacy review and Codex re-review required before
> activation.** This section scopes the Task 7 schema section
> (§17.5): the per-instance `provider_info`, per-slot `tokens[]`
> and per-mechanism `mechanisms[]` keys. Reads are fixed-size
> struct/range reads at return on `CKR_OK` only (§17.1); entry
> retains the info pointer with a full-span guard.
> `CK_TOKEN_INFO.serialNumber`, `label`, session counts, memory
> sizes and `utcTime` are never fetched (§17.2); there is no
> opt-in flag for the serial in v0.8.0, and the schema has no keys
> for any excluded byte. Padded fixed-width strings publish
> trimmed (§17.1). Provider build metadata, token
> manufacturer/model/versions/flags (incl. PIN-state bits),
> PIN min/max lengths, and mechanism limits/flags are not secrets
> (owner stance 2026-11-14 — policy state, not PINs). Terminal
> states, `CKA_ID`/payload/PIN prohibitions and every other
> exclusion stay in force. Allowlist-v1 bytes are unchanged.
> Task 7 ships in default inventory and CBOM, not only under
> `--key-operations` (§17.7).
>
> Required evidence before activation: the §17.6 host twins
> (LP64+ia32 layouts, sentinel non-publication, 129th-mechanism
> cap, CBOM serial-absence), canary lanes with Task 7 sentinel
> positions proving no excluded byte reaches output/maps/logs,
> verifier headroom + `bpf loads` (§17.4), full
> `artifact_contracts`, and the Task 5 live positives (SoftHSM
> info calls with parsed fields matching the provider's own
> reports).

### 17.4 BPF design and budget

No new `ObjectAction` (`OBJECT_ACTION_MAX` stays 14): the 3 info
functions are rows 12–14 of `EVIDENCE_POSITIONS` (§8.1) with the
§17.1 info kind + read ranges; no inputs, no templates (never
authorized). Retention is the info pointer only
(`CallStart.ev_cell`, §8.2) — slot and mechanism scalars ride the
base S1 record, never the stash. +0 endpoints (all three already
carry S1 probes, `kinds.rs:184-191`); no new maps. Entry-guard
spans are the full struct sizes (88/76, 208/160, 24/12 LP64/ia32);
bytes read are the field ranges only (76/72, 76/64, 24/12 —
§17.1). The 512-byte frame test must pass unmodified in limit.
Verifier: same §8.5 gates (≥5% headroom on the 6.6 floor, `bpf
loads` on vng 6.6/6.12 + host 7.x, LP64 + ia32).

Wire: the third 496-byte form (368-byte base + fixed 128-byte info
trailer: `version: u16`, `kind: u8`, `status: u8`, `layout: u8`,
`payload_len: u8`, 3 reserved bytes, `payload: [u8; 120]` —
payload_len is exact per (kind, layout): 76/72 for `CK_INFO`,
76/64 for token ranges, 24/12 for mechanism info). The trailer
validator is exact length + version + kind + layout +
payload_len + zero reserved. This beats the v2-tail-union
alternative on validator surface: the union would put info
endpoints in the object lane (journal/authority/sole-complete
contact) and fork `validate_object_tail` with a union tag plus
per-action offsets, while the third form adds one standalone
exact-length check and leaves every existing validator,
classification and pin byte-identical. Old readers refuse 496
loudly. Task 7 merges after Task 3's merge commit and consumes
the Task 2 wire base through that chain (shared files, one writer
at a time — the §13 rule).

### 17.5 Schema, output and CBOM

New schema section, next free number after v7 (suggest v8;
integrator allocates per §10.1), emitted exactly when Task 7
content is present; v1–v7 stay frozen and byte-stable:

- per instance `provider_info`: cryptoki/library major+minor,
  manufacturer, library description, flags;
- per (instance, slot) `tokens[]`: manufacturer, model,
  hardware/firmware version, flags (whole word, incl. PIN-state
  bits), `pin_min_len`, `pin_max_len`, `completions`, `changes`;
- per (instance, slot, mechanism) `mechanisms[]`: type, min/max
  key size as RAW numbers (no unit claim — PKCS#11 v2.40 §3.5:
  "bits or bytes, mechanism-dependent"), flags, `completions`,
  `changes` — capped at 128 mechanisms per (instance, slot);
  extras refuse with a named `mechanism_info_refused: too_many`
  counter, never silently.

Repeat rule (apps poll; flags change; tokens swap): last-wins per
(instance, slot) and per (instance, slot, mechanism).
`completions` counts polls; `changes` counts value transitions
(first observation sets the value with `changes: 0`). A different
token inserted into the same slot is last-wins plus one `changes`
bump — never a second entry, never a merge. Per-slot caps: tokens
are 1 per slot by construction; mechanisms 128 per slot (above).

Join: completed-call record → owning instance (slot/mechanism
from the base S1 record, payload from the trailer); no `AggKey`
contact (these are not key rows) and no `metadata_at_use` contact.
A provider with no completed Task 7 calls has no `provider_info`
block: "provider never watched" is derivable from the JSON
already (no rows for its instance beside coverage notes), so no
new field marks it.

Text: concise gains one provider line only where Task 7 content
exists (byte-stable otherwise), pinned wording:
`provider: <libraryDescription> <libraryVersion> (cryptoki
<cryptokiVersion>, <manufacturerID>)`. `-v` adds per-slot token
lines (`token slot <N>: <manufacturerID> <model> fw
<firmwareVersion> hw <hardwareVersion> pin <min>-<max>`) and
per-mechanism limit lines (raw `min-max` numbers, never "bits").
Every provider-controlled string (manufacturer, description,
model) passes through `render::escape_controls` (`src/render.rs:26`)
in text output — valid UTF-8 can still carry ESC or C1 controls;
JSON is unaffected. JSON carries the full keys.

CBOM (re-projection only, `docs/cbom-export.md` gains a provider
section, CycloneDX 1.6 per `src/inventory/cbom/render.rs:22`): the existing
`type: library` provider component keeps its `name`
(`src/inventory/cbom/render.rs:169-170`, still `provider.name`)
and gains `supplier` as an OBJECT (`{"name": <manufacturerID>}`
— CycloneDX 1.6 `supplier` is an OrganizationalEntity, never a
string) plus `version` (`<libraryVersion>`); each token projects
to a `type: device` component named `<manufacturerID> <model>`
with hardware/firmware versions, flags and PIN lens in
`properties[]`, linked to its library via `dependencies[]`.
Per-slot mechanism limits map onto the global-per-id
`type: cryptographic-asset` algorithm components
(`src/inventory/cbom/input.rs:94-104`, no slot key) by reporter
count: exactly one (instance, slot) reporter → plain properties
(`p11scope:min-key-size`, `p11scope:max-key-size`,
`p11scope:mechanism-flags`, `p11scope:mechanism-hw`); more than
one → per-reporter properties suffixed
`p11scope:slot-<slot>:<base>` (slot ids are provider-small;
different instances sharing a slot id each report — suffix
collisions append `p11scope:slot-limits-truncated: true` instead
of merging), capped at 16 reporters per mechanism with the same
truncation flag. When limit properties are present the algorithm
`description` (today: "carries no key size, curve or parameters")
gains "; provider key-size limits in properties" — the old
sentence alone would be false. The lane pins the exact property
names against CycloneDX 1.6 and never invents enum spellings.
Serials never appear (no such key exists anywhere).

### 17.6 Tests

Host twins per call (LP64 + ia32 layouts): CKR_OK positive
(exact parsed fields), NULL-pointer negative, failure-RV
negative, owner-mismatch negative; sentinel twin: a provider
returning sentinel serial/label/session/memory/utcTime bytes and
sentinel `CK_INFO` pad bytes publishes none of those bytes
anywhere (JSON/logs/maps scanned — the B6 padding-sentinel twin);
PIN-policy positive twin: PIN-state flag bits and
min/max PIN lens publish with exact values; repeat twin:
re-polled token (same value → `completions` bump only; changed
flags → `changes` bump; swapped token → last-wins + `changes`
bump, single entry); cap twin: the 129th mechanism on a slot
refuses with the named reason while the first 128 stand; units
twin: mechanism limits render as raw numbers with no "bits"
wording anywhere; escape twin: ESC/C1 bytes in provider strings
are escaped in text, raw in JSON; CBOM twins: no serial key in
any CBOM output, `supplier` is an object, library `name`
unchanged, single/multi-reporter limit mapping incl. the
truncation flag. Canary lane: Task 7 SPECIFIES its sentinel
positions (§12.2) and Task 4 OWNS the canary files and implements
them (single writer, §13). Live (inside the Task 5 matrix,
required): SoftHSM `C_GetInfo`/`C_GetTokenInfo`/
`C_GetMechanismInfo` positives with parsed fields matching the
provider's own reports.

### 17.7 Mode scope: default inventory and CBOM (no object lane)

Task 7 rides the S1 lane, not the object lane: retention is one
`CallStart` pointer (§8.2, §17.4), the record is the 368-byte base
plus trailer (§8.3), and the join keys off the base S1 record's
slot/mechanism. The object lane's `--key-operations` gate
(`src/cli.rs:828`, `allowlist-v3.md:108-125`) therefore does not
apply: provider/token/mechanism info appears in DEFAULT inventory
(JSON + concise/`-v` text) and in CBOM whenever the Task 7
amendment rows (§17.3) are approved and the calls are observed.
Cost in default runs: +0 endpoints (all three already probed),
+128 bytes per info call (rare — apps poll tokens, not hot paths),
+16 bytes per in-flight S1 row (§8.2). No `--key-operations`
+requirement, no object-lane dependency. (Keymeta Tasks 1–3 DO
need `--key-operations`: inferred facts ride per-key rows, which
exist only there.)

## 18. Later (not v0.8.0): small fixed-size mechanism parameters

Owner decision 2026-11-14 07:40 (binding): Task 8 is postponed to
a later version. It is NOT in v0.8.0 scope: no BPF decode arms, no
schema keys, no allowlist amendment rows, and no other v0.8.0 task
depends on it (Tasks 0–7 are self-contained without it).

What Task 8 was (one paragraph, for the later revival): allowlisted
entry-time decodes of the non-secret scalar fields of small
fixed-size mechanism parameter structs (PSS/OAEP/GCM lengths, KDF
ids, CTR/ECDH/HKDF/SP800-108/DH/DSA param-gen fields) on the 11
Init/Wrap/Unwrap/Derive/Encapsulate/Generate calls, with honored-only
(CKR_OK) publication on operation-level `mechanisms[].params[]`
combos under new shape codes, exact-length pointer-safety guards,
and canary proof that no payload-adjacent byte publishes.

The full round-3 design text (per-mechanism field table, §18.3
pointer-safety rule, §18.5 amendment block, tests/canaries,
exclusions) is preserved in git history at commit 8a2556d4b
(`docs: require keymeta Task 7 and design Task 8 mechanism params`),
§18. A revival starts from that text with a fresh privacy review;
it must not reactivate without one.
