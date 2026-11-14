<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# v0.8.0 Key Metadata: Inferred Family, Size Class, Creation Sources

Status: design (spark lane, round 11). Base: task/v080-design-keymeta c54492cdf.
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

Owner ruling (2026-11-14 08:50, binding, §15 K7): the
length-based size inference that needs new reads on hot per-call
paths (Opus B7 put hot `C_Encrypt`/`C_Decrypt`/`C_Sign` record
growth at ~70% with a classification change) is OPTIONAL and OFF
by default behind one flag, `--key-sizes` (valid only with
`--key-operations`, §10.5). Without the flag the user still gets
family-from-mechanism (§4, no new reads), creation-template facts
(§6) and token-reported sizes — plus a one-line `-v` hint that
size-from-length needs the flag. With the flag off, hot-path
records, ring/journal load, the linked program set at hot
endpoints, standard verifier counts and classification are
exactly today's (§8.6, §12.1 identity contract). Task 7 stays ON
by default (cold calls, §17.4/§17.7).

Controller rulings (fix7, binding, dispose the Opus re-review R1
and R2): R1 takes option 1 — the length capture lives in extra
programs `p11_entry_journal_length`/`p11_return_journal_length`
in the SAME journal object (mixed-ABI like the base journal
pair, so no separate ia32 program there), sharing every map, the
ring and the journal state; userspace loads/links them only with
`--key-sizes` (aya verifies only loaded programs). Length
trailers are specified on the journal END forms (632/472 B
today); keyrows co-owns `object_journal.rs` and
`journal_roots.rs` (serialized, §13); the new programs get
budget cells and the flag-off identity pins against the journal
programs' existing cells. The separate-object design is removed.
R2 takes option (b) — a small info entry+return pair at the 3
cold endpoints in the inventory object (stash map, small ring,
drain in the inventory session, `inventory/*` budget cells,
identity pin for `p11_usage_entry_*` unchanged), with the
endpoint/link cost corrected (+3 return links per provider);
under `--key-operations` the 3 endpoints use journal-program
info variants keeping the journal entry's info-call handling
(the `begin_decision` Call arm for proved-irrelevant calls)
[that sentence is superseded by fix8 C3 — there is no journal
info carrier; the inventory info pair serves every native
inventory mode including under `--key-operations`].

Controller rulings (fix8, binding, dispose the Opus r3 review
C1–C3, I1–I3 and minors; C2/I3/minors figures superseded by
fix9 — see the fix9 rulings below): C3 takes the recommended
fix — the journal info programs, the 760/600 END+info forms,
the `EVIDENCE_START` info use and Task 7's co-ownership of the
two journal files are dropped; the inventory info pair links in
every native inventory mode including under `--key-operations`,
and a refused journal start leaves Task 7 running on the
ordinary retry's broad inventory (§17.4, §17.7). C1 — the info
entries run the unchanged `usage_entry` body in both flavors,
then stash, with a Callers-flavor twin pinning `CALLER_USE`
rows and counts at the 3 endpoints equal to baseline. C2 —
`INFO_START` rows carry {info pointer, slot, mechanism,
function kind, layout, generation [superseded by fix9 R8 —
`generation` dropped]}, the 160-B record header [superseded by
fix9 R2 — 48-B header, 176-B record with `ImageIdentity`]
carries {endpoint id, host tgid + caller incarnation cookie,
slot, mechanism, kind}, and the default-mode join keys by
(module via endpoint, caller incarnation, slot[, mechanism])
onto `modules[]`/`edges[]`, using instances only where the
semantic lane proves one. I1 — per-backend link deltas (Multi
and Singles), a per-group return program, and
`entry_link_bound`/`fd_preflight` extended with the info return
links and the `INFO` ring, pinned in the routing twins. I2 —
full stash-map lifecycles (§8.2, §17.4). I3 — function kind via
a frozen endpoint→kind map [superseded by fix9 R1 —
admission-published, never frozen] (cookie tag rejected,
§17.4), function identity plumbed through `InventoryEndpoint`/
`AttachEndpoint` routing, the info pair linked only where the
endpoint's slot set is exactly one info function (named gap
otherwise), with the map validators, the freeze sequence and
Multi load mode covered. Minors — `JOURNAL_MAPS`/program
inventory growth, a `check-bpf-load-journal.sh --key-sizes`
run, the compact 488 form dropped (no producer), byte-for-byte
ELF section identity for the base programs [superseded by fix9
R6 — linked-instruction-stream hashes], and the P0 inventory
flavor list stated.

Controller rulings (fix9, binding, dispose the Opus r4 review
R1–R8): R1 — `INFO_KIND` follows `ENDPOINT_OBJECT` exactly
(written per endpoint at admission with read-back, re-publication
refused, never frozen; `Freeze("INFO_KIND")` dropped). R2 — the
info header carries the full 16-B `ImageIdentity` (48-B header,
176-B record, every figure updated; the Global flavour emits a
zero identity). R3 — the info stash is scope-gated
(`scope_auth()` `Some`, layout == declared ABI, valid
config/cookie endpoint, `INFO_KIND` != 0) through re-evaluation
or a shared admit helper, with the usage-entry bytes still pinned,
plus an out-of-scope negative twin. R4 — `EVIDENCE_START` binds
on the START row `ts_ns` (no native accessor). R5 — the info
return always deletes `INFO_START` and reads only on `CKR_OK`.
R6 — identity hashes each base program's fully linked instruction
stream incl. subprograms (`aya_obj` precedent), with the verifier
cells as backstop. R7 — a static fd-preflight bound for info
returns; the 4096-endpoint Singles cell stays passing. R8 —
`generation` dropped (unnamed source); the fix7 R2 sentence marked
superseded; plan Task 7 Step 4 lists inventory cells only.

## 1. Goal, non-goals, constraints

Goal: per-key rows carry, beside established token-reported facts,
three new fact classes with explicit provenance — inferred family
("probably RSA (from mechanism)", on by default), size class from
operation lengths ("RSA 2048 (from signature length)", opt-in
behind `--key-sizes`, off by default per the 08:50 ruling), and
creation-template facts with requested-with-success provenance (on
by default) — without ever silently promoting a request or an
inference into an established fact.

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
first, ia32 claims require actual ABI cells; with `--key-sizes`
off, hot-path records, ring/journal load, the linked program set
at hot endpoints, base-program bytes and classification are
exactly today's (§8.6 — extra programs in the same journal
object, loaded and linked only with the flag, never a runtime
branch inside the hot programs; the only linked-set additions
are the cold-only Task 7 inventory info programs, which link in
every native inventory mode including under `--key-operations`,
§17.4).

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
- Opus review B7 (hot-call cost: hot `C_Encrypt`/`C_Decrypt`/`C_Sign`
  records growing ~70% with a classification change) is disposed by
  the owner 08:50 ruling (§15 K7), not by narrowing the capture:
  length capture on hot paths moves behind `--key-sizes` (off by
  default, §10.5) in extra journal-object programs loaded and
  linked only with the flag (§8.6), the §12.3 gate becomes the
  opt-in's acceptance, and family (§4),
  creation (§6) and Task 7 info (§17) stay on by default.

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
Family inference stays ON by default: it needs no `--key-sizes`
(§10.5, §15 K7) and its cost is a userspace table lookup per
attributed completion.

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

This whole section is the `--key-sizes` opt-in (owner 08:50,
§15 K7, flag §10.5): every capture protocol below (§5.1) runs
only when the flag is on, in the journal length programs (§8.6).
With the flag off no length word is acquired on
any path, and `inferred_size` from lengths is absent (§9, §10.2).
The maps (§5.2), the closed non-map list (§5.3) and the join
rules (§5.4) are unchanged — they just never see evidence when
the flag is off.

### 5.1 Capture protocols (F2, exact)

Arguments are zero-based. LP64: 8-byte words, args 0–5 in registers,
arg 6 at entry SP+8 (existing `target_stack_arg_address` helper).
ia32: 4-byte words on the stack, zero-extended after a successful
four-byte read, high-bit refusal. All indices are ≤ 6: no new
argument-7 exception is needed. FULL journal builds with
`--key-sizes` only: the length adapters compile into the journal
length programs only (§8.6), so without the flag there is no
length code on any loaded path at all — and aya verifies only
loaded programs, so the length code is never even verified
without the flag (stronger than the `KEM_CAPTURE_WIRED`
FULL/P0 split — the P0 journal flavor omits the length programs
and P0 refuses the flag, §10.5). No length-cell
pointer is retained beyond its matching call; every
terminal/loss/cancellation/exec/teardown path clears it, exactly
like the result-handle pointer row.

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

Length evidence is admitted to the join only when `--key-sizes`
is on (§9): with the flag off the reducer drops any length
trailer unclassified with the named reason `size_inference_off`
(never stored, classified, counted or published — the same
drop rule as query values, §10.2). The family path (§4) is
unaffected by the flag.

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

Creation-template facts stay ON by default (owner 08:50, §15 K7):
creation calls are cold (not hot per-call paths), the R2 reads
ride the existing creation adapters, and no `--key-sizes` is
needed to see them. The R2 BPF delta is finite-set const data on
those cold paths; the §12.1 off-mode identity twin pins the
journal programs' linked instruction streams byte-identical to
the baseline for the lane's rebased base (§8.5 — keymeta lanes
never re-hash; the integrator re-records on non-keymeta base
changes), and if the Task 1 lane cannot hold that pin it
restructures its delta (dedicated tables, no shared-helper
growth — §8.6 rule) instead of moving the hashes.

## 7. Other cheap facts, ranked by value/cost

1. Attribute results apps already query — zero cost, already
   captured (H7-E4), already projected. Value: high wherever apps
   query (pkcs11-tool, OpenSSL provider); zero for browsers (measured
   R2 §1). No work; Task 5 measures the yield per app.
2. §4 family inference — userspace only, no BPF, on by default.
   High value everywhere (every successful operation carries a
   mechanism).
3. §5 wrap/unwrap lengths — same S/V adapters, two more functions,
   behind `--key-sizes` like all §5 lengths. Medium value
   (wrapping-key class; wrapped-material length).
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
or not (§5 lengths additionally need `--key-sizes`, like everywhere
else). The D6 row gap (rows not produced without a manifest) is a
row-existence question owned by keyrows follow-up, not keymeta:
keymeta consumes the §13 row interface and inherits D6's outcome.
Task 6 verifies the inheritance on one no-manifest `--system` run
(rows present ⇒ inferred keys present with identical rules) and
reports the row gap, if any, back to keyrows instead of working
around it here.

## 8. BPF design: evidence-only trailers (no descriptor contact)

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
and, for Task 7, the info kind + read ranges (§17.1). The table
names positions only; record forms live in §8.3 (length) and
§17.4 (info). The 14 rows:

| Function | Evidence position | Record carrying the trailer |
| --- | --- | --- |
| `C_Sign` | length, S-cell arg 4 (key comes from the Init receipt, §9) | journal END + 16-B length trailer (§8.3) |
| `C_SignRecover` | length, S-cell arg 4 | journal END + 16-B length trailer (§8.3) |
| `C_SignFinal` | length, S-cell arg 2 | journal END + 16-B length trailer (§8.3) |
| `C_Verify` | length, V-scalar arg 4 | journal END + 16-B length trailer (§8.3) |
| `C_VerifyFinal` | length, V-scalar arg 2 | journal END + 16-B length trailer (§8.3) |
| `C_Encrypt` | length, S-cell arg 4 | journal END + 16-B length trailer (§8.3) |
| `C_Decrypt` | length, V-scalar arg 2 | journal END + 16-B length trailer (§8.3) |
| `C_WrapKey` | length, S-cell arg 5 (Access inputs 2, 3 kept) | journal END + 16-B length trailer (§8.3) |
| `C_UnwrapKey` | length, V-scalar arg 4 (input 2, result 7, template (5, 6); Unwrap kept) | journal END + 16-B length trailer (§8.3) |
| `C_EncapsulateKey` | length, S-cell arg 6 (input 2, result 7; Encapsulate kept) | journal END + 16-B length trailer (§8.3) |
| `C_DecapsulateKey` | length, V-scalar arg 6 (input 2, result 7; Decapsulate kept) | journal END + 16-B length trailer (§8.3) |
| `C_GetInfo` | info, pointer arg 0 (§17) | 176-B inventory info record in every native inventory mode (§17.4) |
| `C_GetTokenInfo` | info, slot scalar 0 + pointer arg 1 (§17) | 176-B inventory info record in every native inventory mode (§17.4) |
| `C_GetMechanismInfo` | info, slot scalar 0 + mechanism scalar 1 + pointer arg 2 (§17) | 176-B inventory info record in every native inventory mode (§17.4) |

The `C_UnwrapKey` creation template (5, 6) stays acquired by the
existing Unwrap adapter and stays authorized exactly as today
(allowlist-v3 unwrap row): it is an R2 promotion source (Task 1),
and nothing in this design removes or re-gates it. Evidence rows
carry no template pairs (T0-style: never authorized).

Variant mapping (mechanism in §8.6, §17.4): the 11 length
rows link the journal length programs iff `--key-sizes` is on,
else the base journal pair exactly as today; the 3 info rows
link the inventory info pair in every native inventory mode,
including under `--key-operations` (default-on, §17.4 — fix8
C3: there is no journal info carrier, so there is nothing to
deduplicate and no `--key-operations`-only info path). The
table above names positions, never programs: which program runs
at a position is an attach-time routing decision.

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
  (`tail_absent`, `object_journal.rs:361`), and trailers ride
  outside the 608-byte payload (appended to the END record,
  §8.3).
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

`adapter_length_entry` (shared source, host-tested with injected
readers; BPF bindings compile into the journal length programs
only, §8.6 — never into the base journal pair):
V-scalars snapshot via `arg_u64` (LP64 regs / ia32 stack /
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
(the KEM entry adapter is NOT forked either). (There is no
FULL/P0 runtime gate inside the adapters: the whole length path
is absent unless the length programs load, §8.6.)

Retention (no shared row grows — still no new map KIND): the
journal object gains one dedicated stash map, `EVIDENCE_START`
(`HashMap<StartKey, EvidenceStart>`, existing kinds only), used
solely by the length programs (Task 2; fix8 C3 drops the info
use, so the `ev_kind` tag is gone — length rows only). Key is
the call's `StartKey` (`lib.rs:1206-1212`: `pid_tgid` + slot).
Row (32 B): `ev_cell: u64` (retained S-cell pointer or V-scalar
snapshot), `ev_ts_ns: u64` (the START row's entry timestamp,
snapshotted at entry), `ev_kind: u8` (S-cell vs V-scalar) +
layout/flags bytes and reserved zero. The binding is the START
row's `ts_ns` (fix9 R4 — the old (thread, sequence) binding is
dropped: thread and sequence live in `JOURNAL_START`, a native C
map (`object_journal.c:8-13`), and `p11_journal_begin` always
returns 0 (`:904-975`), so Rust at a length entry cannot read
either; `ts_ns` is stamped at entry (`main.rs:4008`) and read at
return (`journal_roots.rs:320`), both sides Rust-readable, with
no native accessor added). Lifecycle (fix8 I2): the
entry always overwrites its key on retention and always deletes
it on the unavailable path (a stale row is never trusted); the
length return deletes its `EVIDENCE_START` row on every return
path — match, mismatch, unavailable shape, failure RV —
mirroring fix9 R5 for `INFO_START`: it matches the row's `ts_ns`
against the START row's `ts_ns` and on mismatch deletes the row
and emits the base END with the trailer status unavailable
(counted, never a guessed length), and on match deletes the row
after emitting the trailered END; every terminal/loss/
cancellation/exec path clears the stash, exactly like the
result-handle pointer row;
the stop scrub (`src/attach/object_stop.rs`, today
OBJECT_START-only) is extended to zero-verify-remove
`EVIDENCE_START` after quiescence; full-map insert failures and
mismatch deletes each land in their own evidence counter (new
cells beside `EVIDENCE_START_INSERT_FAILURES`-style accounting,
never silent). The map is cfg-gated to the journal build
(`p11scope_journal_roots`, following the `main.rs:50` journal
gate): it exists only where the length programs can load.
With the flag on, `max_entries` is 16384 (the `START_ENTRIES`
precedent, `lib.rs`: small-state-maps shrinks to 1); with the
flag off the loader overrides it to 1, so the off-state
reservation is exactly one row. Memory (corrected — the old
"+256 KiB" counted payload only): the on-state preallocated
reservation is key + value + per-element hash overhead over
16384 entries, order of 1 MiB, measured at load and recorded by
the Task 2 lane; the off-state reservation is one row. No
shared `START`/`OBJECT_START` row changes shape, so the base
journal programs' bytes are untouched by construction (§8.5
linked-instruction identity). Emission is reserve-and-fill (never
stack-built): one END per completed call, base END + trailer
(§8.3). The inventory info pair keeps its own stash map and ring
(§17.4), never this one.

### 8.3 Wire: trailer forms on the journal END records

`--key-sizes` only works with `--key-operations`, and that mode
loads the journal object (`src/attach.rs` journal selection,
`src/attach/journal.rs:9-19`), where each call produces journal
BEGIN (224 B) and END records (`object_journal.rs:33-38`) —
never 368/608 CALL records. Length trailers therefore ride the
journal END form. Three exact END lengths; dispatch is by exact
length only (BEGIN 224 B is never trailered):

| Form | Bytes | Layout |
| --- | --- | --- |
| END full | 632 | `JournalEndFull`: 24-B header + 608-B payload (UNCHANGED — `JOURNAL_VERSION` stays 1, `validate_end` accepts it exactly as today) |
| END compact | 472 | 24-B header + 448-B compact payload (UNCHANGED decoder form; no BPF root emits it — the roots reserve only `JournalEndFull` (`journal_roots.rs:342`, `main.rs:5028`) and the compact packer "does not activate compact production emission" (`object_journal.rs:659)) |
| END+length full | 648 | 632 + 16-byte length trailer (`version: u16`, `kind: u8`, `status: u8`, `value: u64`, 4 reserved bytes) |

Fix8 drops two carriers: the 760/600 END+info forms are gone
with the journal info programs (C3 — the inventory pair is the
only info carrier, §17.4), and the compact 488 form is dropped
because no producer is named (minor — the compact base itself
has no producer, so a compact trailer would be dead wire).
Every length END carries exactly one trailer. The 608-B payload
slice of a trailered END validates under the unchanged v1
validator; the header `length` field carries the total record
bytes (the existing pattern: 632/472 today, plus 648 with the
flag). The 368/608 ordinary/object CALL forms are untouched —
keymeta adds no trailer to any non-journal record.

The journal length programs emit the 648 form at their endpoints
on every completed call (the status field marks unavailable
shapes); the base journal pair always emits the base END there,
so with the flag off every length endpoint yields only base
ENDs exactly as today (§8.6 identity contract). The P0 journal
flavor omits the length programs and P0 refuses the flag
(§10.5). Length-based dispatch (`decode_journal_record` /
`validate_end`, `object_journal.rs`, plus its userspace mirror
in the `src/events.rs` poll dispatch) gains the exact length
648; 488/760/600 and every other length stay malformed (the
§12.1 dispatch twin pins 648 accept + 488/760/600 malformed +
224/632/472/368/608 unchanged). The trailer validates against
`EVIDENCE_POSITIONS` (exact version + kind, function-matched
row, zero reserved). Old readers refuse the new length loudly
(no silent misparse). The
`object_producer_compiled_frames_are_bounded` 512-byte frame test
must pass unmodified in limit (frames are adapter code, and
records are reserve-filled, never stack-built; if frames do not
fit, the lane stops and reports — no silent bound raise).

No new map kinds (`EVIDENCE_START` is a `HashMap`), no new arg-7
exception (all indices ≤ 6, §5.1). Attach/plan: +0 newly
probed functions, +0 endpoints. Links (fix8 I1 — the old "+0
links" line was false on Multi): groups key per (attach path,
entry program) with one return link plus one entry link per
group (`attach.rs:3119-3129, 4289-4326`), so on Multi the
length endpoints split out of their base groups into new
groups: +G entry links and +G return links with the flag on,
where G is the number of distinct attach paths among the 11
length endpoints (one provider path in the fixture, pinned by
the routing twin). On Singles the length pair substitutes the
base pair at already-linked sites: +0 entry, +0 return. The
return program becomes per-group (§8.6): length groups link
`p11_return_journal_length`, every other group the base return.
The length cost is per-call bytes on already-hot endpoints
(END 632→648, BEGIN unchanged at 224 — +16 B, +2.5%, ≈ +160
kB/s ring per hot endpoint at 10k calls/s) plus the
`EVIDENCE_START` reservation (§8.2) — paid ONLY with
`--key-sizes`, and sized by the ring-loss gate (§12.3, now the
opt-in's acceptance), not by endpoint count. The 8192
slot budget is unchanged. Info cost (default-on) is sized in
§17.4 and never touches a hot program (§8.6).

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
NULL entry — the entry does not exist). Variant selection (§8.6,
§17.4) changes no entry gating either: the same admitted
endpoints link a different program (length: journal-side
substitution per group; info: inventory-side entry substitution
plus the §17.4 return links at already-admitted endpoints),
under the same admission rules.

### 8.5 Verifier and size budget

Per changed program: ≥5% verifier headroom on the 6.6 floor (R-52
precedent), `object_producer_compiled_frames_are_bounded` green,
`bpf loads` on vng 6.6/6.12 + host 7.x, LP64 + ia32 load cells.
The 6.1 E2BIG-style refusal precedent applies: if a floor kernel
refuses, the lane reports the named refusal instead of
simplifying the program. The dedicated maps (`EVIDENCE_START`,
the §17.4 `INFO_START` + `INFO` ring + `INFO_KIND` +
`INFO_EVIDENCE`) and the cold info return hook sites (§17.4) go
through the `bpf-noninterference` allowed-change record
(`scripts/bpf-noninterference-allowed.json`, reviewed) — never a
silent baseline move, and no hot-path contact.

Base programs (flag off): their compiled bytes are pinned by
hashing each base program's fully linked instruction stream,
subprograms included — not by "counts equal" (fix8 minor — the
gates check count ≤ budget, so equal counts never proved the
base programs unchanged) and not by a per-section hash (fix9 R6
— the base programs call out-of-line `#[inline(never)]`
subprograms that a section hash would not see, e.g.
`capture_entry` / `begin` / `ordinary_return`
(`journal_roots.rs:235, 256, 311`), plus the native noinline
functions). The integrator records the baseline hashes of each
base program's fully linked instruction stream (parsed with
`aya_obj`, the `tests/inventory_caller_bpf_contracts.rs:45`
precedent) at the integration base; each keymeta lane builds its
own rebased base commit and the §12.1 identity contract compares
the candidate's linked streams byte for byte against that
build's hashes: `p11_entry_journal` / `p11_return_journal` in
the journal object, `p11_usage_entry_lp64` /
`p11_usage_entry_ia32` in the inventory object. Keymeta lanes
never re-hash — any drift fails the contract and the lane
restructures its delta (dedicated tables/maps, no shared-helper
or shared-row growth — the §8.6 rule); only the integrator
re-records the baseline, when a non-keymeta lane (keyrows T1/T3
on the co-owned journal files, §13) legitimately changes the
base programs. Today's journal cells stay as
reference numbers and a backstop (processed insns,
115%-margined; limit
1,000,000): `journal-gate1/p11_entry_journal` max 390,605
(39.1%; 6.6 floor 145,313), `journal-gate1/p11_return_journal`
max 186,862 (18.7%; 6.6 floor 95,914); inventory
`p11_usage_entry_*`, max 1,025 each — still checked, never
re-pinned by a keymeta lane, but the proof is the bytes.
Keymeta adds no program to the Detailed object, so the
`detailed/*` cells are out of scope (untouched, never re-pinned
by a keymeta lane).

New programs (flag on / info): each linked new program gets its
own budget cell per measured kernel in
`tests/bpf-verifier-budgets.json`, recorded via
`scripts/record-verifier-budgets.py` (same 115% margin rule):
`journal-gate1/p11_entry_journal_length`,
`journal-gate1/p11_return_journal_length` (mixed-ABI like the base
journal pair — no separate ia32 program, following the
journal-roots precedent), plus `inventory/p11_info_entry_lp64`,
`inventory/p11_info_entry_ia32`, `inventory/p11_info_return`
(§17.4, per-ABI entries following the usage-entry precedent;
the journal info pair is gone with C3). Every linked new program
on every measured kernel gets a cell. Exact-inventory growth
(fix8 minor): `JOURNAL_MAPS` (`src/attach/journal.rs:36-56`)
gains the `EVIDENCE_START` row (flag-dependent `max_entries`
16384/1, §8.2) and `journal_expected_programs`/
`validate_journal_inventory` (`:190-215`) gain the length pair
(flag-dependent — the flag-off object must validate without
them); `INVENTORY_PROGRAMS`
(`src/attach/inventory.rs:602-617`) grows from 12 to 15 entries
with review in the FULL inventory flavors, while the P0
inventory flavor keeps the exact 12-program list (info omitted,
explicit unavailability — the per-flavor lists are stated, not
assumed). BUD-1 applies to every new cell: any pin past 750,000
(75% of the 1M limit) is refused — growth past 75% needs
restructuring, never a mechanical pin — and the 95%
budgets-cap contract still enforces the file. The new programs
share helpers with the base programs plus the §8.2 adapters, so
their pins will sit above today's pins; the acceptance is
recorded cells, every cell under 750,000, and ≥5% headroom on
the 6.6 floor. The `frames_are_bounded` 512-byte frame check
must pass with the limit unmodified. `check-bpf-load-journal.sh`
(which today runs only the `--key-operations` load, header
lines 32-36) gains a `--key-sizes` run scoring the
`journal-gate1/*_length` cells — without that probe row the new
cells would fail the check.

### 8.6 Opt-in: extra programs in the same journal object

Rule (owner 08:50): no keymeta length instruction executes in a
base program, and no runtime branch inside a hot program selects
length behavior. Length capture lives in EXTRA programs in the
SAME journal object, sharing every map, the ring and the journal
state; attach-time routing decides which program links at each
endpoint, and userspace loads and links the length programs only
when `--key-sizes` is on (aya verifies only loaded programs, so
with the flag off the length code is never even verified).

Programs (names are this design's; the lane keeps them unless
the integrator renames), all in the one journal object:

- Base pair (as today): `p11_entry_journal` /
  `p11_return_journal` with today's code, untouched. The base
  programs never reference the length adapters or the
  `EVIDENCE_START` stash (§8.2).
- Length pair (FULL journal flavor only):
  `p11_entry_journal_length` / `p11_return_journal_length`,
  mixed-ABI like the base pair. They run the same journal
  BEGIN/END protocol as the base pair (same sequence, same
  BEGIN/END pairing, same per-session call order, same `STATS`,
  `RV_COUNTS`, `CONFIG`, filters, gates and loss counters —
  nothing is split) and additionally run the §8.2 length
  adapters, stashing into `EVIDENCE_START` and emitting the
  648 END+length form (§8.3). (Fix8 C3: no info pair lives in
  this object — Task 7 is inventory-side only, §17.4.)

The P0 journal flavor omits the length programs (the SMALL
flavor omits the whole journal object — the same flavor
precedent in `build.rs`); P0 refuses `--key-sizes` with the
named FULL-only reason (§10.5).

Attach-time routing (Task 2, `src/attach.rs` group routing +
`src/attach/journal.rs` program selection + planner mode input;
classification stays untouched): a multi-attach unit already
pairs "one return link plus one entry link" per (attach path,
entry program) (`attach.rs` static-group rule), so routing is
per group, in both backends (multi and singles). The
`return_program` single constant per mode
(`attach.rs:4282-4288`) becomes per-group: each group names its
own return program alongside its entry program.

- Flag on (FULL): the 11 length-endpoint groups link the
  length pair (entry and return always as a pair — a mixed pair
  would strand the stash and is a planner bug, pinned by the
  routing twin); every other group links the base pair as
  today.
- Flag off: every group links the base pair — the linked set
  at every endpoint is exactly today's, the length programs
  never load (no verification, no floor-kernel refusal risk
  from length code), and every length endpoint yields only base
  ENDs. With the flag off no endpoint links a length program,
  and with the flag on no non-length endpoint does (pinned by
  the routing twin, §12.1).

Length evidence rides the END record of the call it measures,
so the evidence itself needs no cross-record pairing — but
session order still comes from the shared journal sequence
(the operation machine's cross-call order within a session is
unchanged, because the length programs share the journal state
rather than splitting it).

Off-mode identity (the §12.1 contract proves each, none is
assumed): per-endpoint record bytes identical to the no-length
baseline (base forms only, byte-identical BEGIN/ENDs, never
648); linked program set at every endpoint exactly today's;
base-program linked instruction streams byte-for-byte identical
to the baseline for the lane's rebased base (§8.5 — keymeta
lanes never re-hash); journal classification, census,
sole-complete set and alias agreement byte-identical (the four
existing pins); ring bytes/s at the gate workload equal to the
baseline. If a lane cannot hold the byte identity it
restructures its delta (dedicated tables/maps, no shared-helper
or shared-row growth) instead of re-hashing — only the
integrator re-records the baseline, on non-keymeta base changes.

## 9. Userspace join (N5 decided)

No mechanism dimension on `AggKey`: rows stay (instance, object,
category, role, metadata_at_use). Result-derived evidence gets its
own row keys (`inferred_family`, `inferred_size`, §10) and never
rewrites `metadata_at_use` — the frozen-at-Init contract and its
pins stand. Length evidence enters the join only when
`--key-sizes` is on: with the flag off the reducer drops any
length trailer unclassified (`size_inference_off`, §5.4 — a
stale or replayed trailer can never classify), while family
evidence joins in both modes. The binding path, end to end:

1. The journal END (base + length trailer, one record)
   dispatches in `src/events.rs` (gains 648) and validates in
   `decode_journal_record` / `validate_end`
   (`object_journal.rs`, co-owned with keyrows, §13); the
   BEGIN/END pairing (`ingest_end`, keyed by (thread,
   sequence)) is unchanged, and the trailer's evidence rides
   the validated END into `OpMachine` with (generation, fixed
   `KeyReceipt`, `mechanism: Option<u64>`).
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

Files: `src/events.rs` (journal dispatch), `object_journal.rs`
(trailer validation + accessor, co-owned with keyrows, §13),
`src/semantics_objects/journal.rs` (trailer carry through
`ingest_end`/`completed_of`), `src/semantics_edge.rs`
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
  With `--key-sizes` off, family alone emits v7
  (`inferred_family` valued, `inferred_size` unknown) — v7 is not
  gated on the flag, only its size half is.
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
With `--key-sizes` off, `inferred_size` is always `unknown` with
the `-v`/JSONL reason `size_inference_off` ("needs --key-sizes");
`inferred_family` is unaffected and infers in both modes.
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
`metadata_at_use` is `unknown`). With `--key-sizes` on:

- `sign: 12 operations (probably RSA 2048: 10; unknown: 2)`
- `verify: 10 operations (probably EC P-256: 10)`
- Non-standard RSA tallies as `probably RSA (non-standard length)`;
  `-v`/JSON carry the masked class + byte count.

With the flag off, tallies are family-only (sizes need the flag):

- `sign: 12 operations (probably RSA: 10; unknown: 2)`
- `verify: 10 operations (probably EC: 10)`

In both modes: no inferred content anywhere → the line renders
exactly as today (byte-stable when v7 is absent).

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
- With the flag off, per-row size detail reads `size unknown (needs
  --key-sizes)`; family detail is unchanged in both modes.

With the flag off, `-v` prints this one line once per run (in the
key-operations section, exact wording pinned by a twin):

`sizes from operation lengths need --key-sizes (families, creation and token-reported sizes still shown)`

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

### 10.5 The `--key-sizes` opt-in flag

One flag (owner 08:50, §15 K7), on `p11scope inventory` beside
`--key-operations`:

- Name: `--key-sizes`. Valid only with `--key-operations`:
  without it the CLI refuses with `--key-sizes requires
  --key-operations` (the same refusal shape as `--key-operations
  requires --capture auto or native`, `cli.rs:2179-2183`).
  Under P0 builds (the P0 journal flavor omits the length
  programs, §8.6) it refuses with a named FULL-only reason.
  Default off.
- Help/usage text (added beside the `--key-operations` line,
  `cli.rs:828` style; exact wording pinned by a twin):
  `--key-sizes also infers key sizes from operation lengths
  (needs --key-operations; off by default — token-reported and
  creation-template sizes and inferred families are still shown
  without it).`
- What the user sees WITHOUT the flag: token-reported sizes
  (H7-E4, unchanged), creation-template curves/parameter sets
  and value lengths (§6), inferred families with the
  `mechanism` source (§4 — `probably RSA (from mechanism)` in
  `-v`, family-only concise tallies, §10.3); `inferred_size`
  from lengths is absent (`unknown` /
  `size_inference_off`, §10.2); `-v` prints the one-line hint
  (§10.3). Task 7 provider/token/mechanism info is unaffected
  by the flag (§17.7).
- What the flag adds: the journal length programs load and link
  (§8.6), length trailers flow, and `inferred_size` classifies
  per §5.2
  (concise `probably RSA 2048` tallies, §10.3). Family,
  creation and token-reported output are identical in both
  modes (pinned by the §12.1 mode twins).

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
forbidden, as *evidence* it is snapshotted). All three rows are
gated by `--key-sizes` (off by default, §10.5): without the flag
no length word is acquired on any path.

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
> Length capture is opt-in (owner 08:50, §15 K7): the length words
> above are acquired only under `--key-sizes` (valid only with
> `--key-operations`, off by default), in extra journal-object
> programs loaded and linked only with the flag (§8.6) — never
> in the base journal pair. Without the flag no length word is
> acquired on any path, and family, creation-template and
> token-reported facts are still published as above.
>
> Required evidence before activation: the §12 twin tables (host
> RED/GREEN at the journal seam, hostile-width, overlap/alias,
> 2041-bit and DER/padding negative controls), the §12.1 off-mode
> identity contract (byte-identical records, same linked set,
> base-program linked-instruction identity), canary lanes with length-cell sentinel
> positions on every §5.1 shape (LP64+ia32) proving no payload byte
> reaches output/maps/logs, verifier headroom + `bpf loads` for
> base journal AND length programs (§8.5), full `artifact_contracts`,
> and the Task 5 live matrix (Firefox/Chromium/pkcs11-tool/OpenSSL
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
dispatch twins (648 accepts; 488/760/600 and neighbors
malformed; old lengths — 224/632/472/368/608 — unchanged;
176-B info records dispatch on the INFO drain, §17.6).
Off-mode identity contract (§8.6, one `artifact_contracts` case
plus host twins): with `--key-sizes` off on the scripted gate
workload — every length-endpoint record is the base form
(632-byte ENDs, never 648) with byte-identical BEGIN/ENDs vs
the no-length baseline; the attach plan links the base journal
pair at every group (pinned name list = today's set; the length
programs never load — asserted, not assumed); base-program
linked instruction streams byte-for-byte identical to the
baseline for the lane's rebased base (§8.5 — keymeta lanes
never re-hash; the integrator re-records on non-keymeta base
changes) with the `journal-gate1/*` cells still checked as a
backstop;
ring bytes/s equal the baseline. Routing twins: flag on → the
11 length-endpoint groups link the length pair (entry+return
always paired — a mixed-pair plan is refused), all other
groups link the base pair; with the flag off no endpoint links
a length program (both backends); per-backend link deltas
pinned (Singles +0/+0 substitution; Multi +G/+G with G = the
distinct length-endpoint paths, one in the fixture).
Mode twins (Task 3): flag off → `inferred_size` always
`unknown`/`size_inference_off`, family/creation/token-reported
output identical to flag-on output minus sizes, `-v` hint line
exact (§10.3), `--key-sizes` without `--key-operations`
refused, P0 refuses the flag; a replayed length trailer with
the flag off drops unclassified (§9).
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
The lane runs both modes: flag on (positions active, above) and
flag off (no 648 record emitted, no length value published
anywhere — the off-mode canary is a negative control).

### 12.3 Gates and live proof (Task 5)

Canonical gates on the candidate (fmt/check/test/clippy, release
toolchain), full `artifact_contracts` (no blanket excludes, no
zero-match selectors), privileged lib cells, `bpf-kernels.yml`
loads, public-CLI cells. Per-call overhead + ring-loss gate — now the OPT-IN's acceptance
(Task 2 measures, Task 5 re-runs on the candidate): scripted
`C_Encrypt` AES-GCM and `C_Sign` at 5k and 10k calls/s each, in
three configurations: no-lane baseline, flag off, flag on.
Record per-call ns delta, ring bytes/s (224/632-byte journal
forms vs the 648-byte trailer form), and ring-loss counts. Flag
off must EQUAL the baseline
on all three (the identity contract, §12.1 — any delta stops the
lane). Flag on passes if loss at 5k calls/s stays zero and loss
at 10k calls/s does not regress vs the baseline (numbers
recorded, not threshold-gamed — a regression stops the lane for
a design revisit). This default-vs-opt-in measurement follows
the R-28/29 extensive-mode precedent (overhead measured default
vs extensive and disclosed). Live matrix on 6.6+ (vng 6.6/6.12 +
host 7.x split): Firefox (Playwright, strict), Chromium
(Playwright, strict), pkcs11-tool (scripted RSA/ECDSA
sign+verify, keygen), OpenSSL provider (pkcs11-provider + SoftHSM
signs) — ≥5 runs EACH (20 runs; per-app proof is required because
yields differ by mechanism: Chromium RSA signs vs Firefox
ECDH/HKDF/AES/KEM), each app both with the flag on (size yield)
and off (family-only baseline + hint check). Per-run
denominator: eligible rows (successful attributed completions
under listed mechanisms) → inferred fraction, with named reasons
for every residual unknown. Chromium client-cert expectation
(flag on): RSA rows → RSA 2048; Firefox new-site: R2 curves +
inferred families on created keys, ECDH/HKDF rows family-only
where no length map exists.

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
                  │                   (journal length programs + flag + routing; evidence-table base for T3/T7)
                  ▼
             keymeta T0 ──► Task 7 Step 0 (§17.3 allowlist block)
             (docs; independent of code order)

keymeta T4 (canaries) after keymeta T3 + keymeta T7 merges (owns canary files;
  Task 7 positions arrive as specified input, §17.6; runs both flag modes,
  §12.2) — parallel-safe with keyrows.
keymeta T5 (live proof) after keymeta T4 + keymeta T7 + keyrows T4 (yield needs
  rows AND facts; on+off matrix per app + Task 7 info positives, §17.6).
```

Keyrows co-owns the two journal files keymeta T2 touches
(`object_journal.rs`, `journal_roots.rs` — keyrows' void/fence/
birth/seal ride BEGIN/END): keymeta T2 rebases onto the keyrows
T1 merge for those files and re-runs the keyrows journal twins
on its merge (serialized, never parallel with keyrows journal
work). Fix8 C3 removes Task 7 from both files: Task 7 touches
no journal wire, program or map, so the T2→T7 serialization on
them is gone — T7 consumes only the T2 evidence-table base
through the T3 chain.

The order is unchanged by the 08:50 opt-in (round 7): Task 2
produces the length programs, the flag and the attach-time
routing before Task 3 consumes the flag for join gating and
rendering, which is already the T2→T3 direction above. No new
edge, no new task — only wider node contents (plan Tasks
2/3/4/5/7). Round 8 keeps the same edges: R1/R2 change node
contents (same-object programs, END trailers, inventory info
pair) and the file table below, not the order. Round 9 (fix8)
likewise: C3/I1/I2/I3 change node contents (no journal info
carrier, per-group returns, stash lifecycles, endpoint→kind
map) and the file table below, not the order. Round 10 (fix9)
likewise: R1–R8 change node contents (admission-published kind
map, 16-B identity headers, scope-gated stash, `ts_ns` binding,
always-delete returns, linked-stream hashes, static fd bound,
`generation` dropped) and the twin lists below, not the order.

Why this order: keymeta Task 1 edits `state.rs`,
`semantics_key_use.rs` and `semantics_objects/journal.rs` — the
same files keyrows Tasks 0, 1, 3 and 4 edit (keyrows plan
`4cca0dd88`: T0 `:85-88`, T1 `:134-136`, T3 `:261-264`, T4 `:290`),
so the old "disjoint files" claim is dropped and the merge
serializes. Keymeta T1 lands between keyrows T1 and T3 (its R2
hunks are small and region-disjoint; keyrows T3 rebases over them
and re-runs). Keymeta T2 (ebpf-common evidence table, journal END
trailers in `object_journal.rs`, journal length programs in
`journal_roots.rs` — both co-owned with keyrows, serialized per
the note above — `EVIDENCE_START` stash map, `src/events.rs`
journal dispatch, `--key-sizes` flag parse/refusal/help in
`src/cli.rs`, attach-time routing in `src/attach.rs` +
`src/attach/journal.rs` + planner mode input) is file-disjoint
from keyrows except the CLI/planner inputs and the two co-owned
journal files (integrator checks keyrows writers there at merge)
but consumes the T1 base (shared
`object_policy.rs`/`object_flow.rs`/`object_wire.rs` — one writer
at a time, never parallel with T1). Keymeta T3 (join + v7 +
projection + flag consumption: join gating, family-only default,
`-v` hint) consumes sealed rows, so it merges after keyrows T4,
developing against recorded fixtures until then. Keymeta T7
consumes the T2 evidence-table base through the T3 chain and
shares projection/schema/test files with T3 — merges after T3;
its BPF half (inventory object, attach routing, INFO drain) is
journal-free. Task 4
owns the canary files alone (Task 7 never writes them). Task 5
runs after Tasks 1–4 AND Task 7 (it checks Task 7 results).

File ownership (ordered writers; each merge re-runs the affected
twins on the merged SHA):

| File | Ordered writers |
| --- | --- |
| `src/semantics_objects/journal.rs` | keyrows T0 → T1 → keymeta T1 → keyrows T3 → keymeta T3 (length carry) |
| `src/semantics_key_use.rs` | keyrows T0 → T1 → keymeta T1 → keyrows T3 → keymeta T3 |
| `src/semantics_objects/state.rs` | keymeta T1 → keymeta T6 (EC arm, optional) |
| `src/key_operation_projection.rs` | keymeta T1 → keyrows T4 → keymeta T3 |
| `src/inventory/present.rs` | keyrows T0 → T1 → T3 → T4 → keymeta T3 → keymeta T7 |
| `src/inventory/present_key_ops_tests.rs` | keyrows T0 → T3 → T4 → keymeta T3 → keymeta T7 |
| `src/semantics_edge.rs`, `src/events.rs` | keymeta T2 (journal dispatch) → keymeta T3 (effects/compat); keymeta T7 touches neither (INFO drain lives in the inventory session, §17.4) |
| `crates/ebpf-common/src/object_{policy,flow,wire}.rs` | keymeta T1 (R2 finite sets) → T2 (length adapters) → T7 (info adapters) |
| `crates/ebpf-common/src/evidence_table.rs` (new) | keymeta T2 → keymeta T7 |
| `crates/ebpf-common/src/object_journal.rs` | keymeta T2 (length END trailers); keyrows co-owner (journal-wire consumer — twins re-run, serialized) |
| `crates/ebpf/src/journal_roots.rs` | keymeta T2 (length programs); keyrows co-owner (same) |
| `crates/ebpf/src/main.rs` (`EVIDENCE_START`, journal-gated; `INFO_START` + `INFO` ring + `INFO_KIND` + `INFO_EVIDENCE`, inventory-gated) | keymeta T2 (length stash) → keymeta T7 (info stash + ring + kind + evidence) |
| `crates/ebpf/src/inventory_info.rs` (new, info pair) | keymeta T7 alone |
| `src/attach/inventory.rs`, `src/attach/inventory/capture.rs` (program list 12→15 FULL / 12 P0, per-group info returns, link-bound/fd-preflight growth, INFO drain, PRODUCED cross-check) | keymeta T7 alone |
| `src/attach/inventory/activation.rs`, `src/discovery/inventory_attach_set.rs` (function identity plumbing, single-info-function rule, INFO_KIND publication) | keymeta T7 alone |
| `build.rs` (journal/inventory flavor program sets) | keymeta T2 (P0 journal omits length) → keymeta T7 (info programs in FULL inventory flavors; P0 list stated) |
| `src/cli.rs` (`--key-sizes`) | keymeta T2 (flag) — integrator checks keyrows writers at merge |
| `src/attach.rs` (group routing), `src/attach/journal.rs` (program selection), planner mode input | keymeta T2 (routing) — integrator checks keyrows writers at merge |
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
- Ring pressure from longer records (END 632→648 on hot
  endpoints): +0 endpoints, and links only per §8.3 (+0/+0 on
  Singles, +G/+G on Multi), so slot budgets are
  untouched — the cost is bytes/s, and only with `--key-sizes`
  (default runs are unaffected by construction, §8.6). Sized by
  the §12.3 ring-loss gate as the opt-in's acceptance; a
  regression stops the lane for a design revisit, never a silent
  budget or threshold change.
- Length/base-program skew: shared helpers evolve and the length
  pair drifts from the base pair (a helper change alters length
  behavior but not base, or vice versa). Mitigation: one shared
  source for adapters/helpers (no forks, §8.2), the off-mode
  identity contract re-run on every candidate (§12.1), and the
  routing twin proving which program serves each group.

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
- K7: Length capture on hot paths opt-in vs default-on. DECIDED
  OPT-IN by owner 2026-11-14 08:50 (after Opus B7): one flag,
  `--key-sizes`, valid only with `--key-operations`, off by
  default (§10.5); extra journal-object programs loaded and
  linked only with the flag, never a runtime branch in the hot
  programs (§8.6).
  Family-from-mechanism, creation-template facts and
  token-reported sizes stay on by default; Task 7 stays on by
  default (cold calls, §17.4/§17.7). The §12.3 gate is the
  opt-in's acceptance.

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
Round 7 (owner ruling 2026-11-14 08:50 after Opus B7, §15 K7):
length capture on hot paths is opt-in behind `--key-sizes` (off
by default, §10.5: help text, refusal, per-mode output, `-v`
hint); separate length-variant object + attach-time routing with
an off-mode identity contract (§8.6, §12.1); variant budget
cells under BUD-1 750,000 with standard pins frozen (§8.5);
§12.3 gate becomes the opt-in's acceptance (baseline/flag-off/
flag-on); Task 7 stays default-on via cold-only info variants
(§17.4, §17.7); family (§4.1) and creation (§6) stay default-on;
DAG order unchanged, node contents widened (§13).
Round 8 (fix7: Opus re-review R1/R2, controller options 1/(b)):
R1 — the separate-object design is removed; length capture moves
into `p11_entry_journal_length`/`p11_return_journal_length` in
the same journal object (shared maps/ring/journal state,
load/link only with the flag), trailers specified on the journal
END forms (648/488), keyrows co-owns `object_journal.rs` and
`journal_roots.rs` (serialized, §13 + plan file lists), new
`journal-gate1/*` budget cells, flag-off identity pinned against
the journal programs' cells (§8.2/§8.3/§8.5/§8.6, §9, §12);
R2 — Task 7 moves to the inventory-object info pair (stash map,
152-B records on a small ring, drain in the inventory session,
`inventory/*` cells, usage-entry pins unchanged, +3 return links
per provider) with journal info programs under
`--key-operations` keeping the `begin_decision` Call arm
(§17.4/§17.6/§17.7); DAG edges unchanged (§13).
Round 9 (fix8: Opus r3 C1–C3/I1–I3/minors, controller rulings;
C2/I3/minors figures superseded by fix9 — see Round 10):
C3 — the journal info programs, the 760/600 forms, the
`EVIDENCE_START` info use and Task 7's journal co-ownership are
dropped; the inventory info pair links in every native inventory
mode including under `--key-operations`, with the refused-start
fallback stated (§17.4/§17.7); C1 — info entries run the
unchanged `usage_entry` body in both flavors, then stash, plus a
Callers twin (§17.4/§17.6); C2 — `INFO_START` rows and the 160-B
record header [superseded by fix9 R2/R8 — 48-B header, 176-B
record, no `generation`] carry joinable identity, the default
join keys onto `modules[]`/`edges[]` (§17.4/§17.5); I1 —
per-backend link deltas, per-group returns, extended
link-bound/fd-preflight (§8.3/§8.6/§17.4, routing twins); I2 —
stash-map lifecycles (§8.2/§17.4); I3 — frozen endpoint→kind
map [superseded by fix9 R1 — admission-published, never frozen],
function-identity plumbing, single-info-function rule (§17.4,
§13 + activation/attach-set files); minors —
`JOURNAL_MAPS`/program inventory growth, a `--key-sizes`
load-check run, 488 dropped, ELF section identity [superseded
by fix9 R6 — linked-instruction-stream hashes], P0 flavor lists
(§8.5/§12); DAG edges unchanged (§13).
Round 10 (fix9: Opus r4 R1–R8, controller rulings): R1 —
`INFO_KIND` follows the `ENDPOINT_OBJECT` precedent (per-endpoint
admission publication with read-back, re-publication refused,
never frozen); R2 — the header carries the full 16-B
`ImageIdentity` (48-B header, 176-B record); R3 — the info stash
is scope-gated with an out-of-scope negative twin; R4 —
`EVIDENCE_START` binds on the START row `ts_ns`; R5 — the info
return always deletes `INFO_START`; R6 — linked-instruction-stream
hashes with the verifier cells as backstop; R7 — a static
fd-preflight bound for info returns; R8 — `generation` dropped
(§8.2/§8.5/§8.6/§11/§12.1/§17.1/§17.4/§17.5/§17.6/§17.7); DAG
edges unchanged (§13).
Round 11 (Opus r5 nits N1–N5, controller direction): N1 — the
info return obtains the caller identity via
`p11_link_current_identity` (same task; 32-B row kept; Global
emits zero without the helper); N2 — the integrator re-records
the hash baseline, keymeta lanes compare against a build of
their own rebased base and never re-hash; N3 — the fix8 rulings
and Round 9 history marked superseded by fix9; N4 — info return
links on EMFILE defer with the named counted
`info_return_deferred` gap (partial, never stop), excluded from
the hard preflight (Singles N + 68; Multi +G/+G kept); N5 — the
length return deletes `EVIDENCE_START` on every return path
(§6/§8.2/§8.5/§8.6/§12.1/§17.4/§17.6/§17.7); DAG edges unchanged
(§13).

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
208/160, 24/12) and snapshots the slot/mechanism scalars into
the `INFO_START` row (§17.4); the return — a uretprobe, which
cannot read entry arguments — emits the record header's
slot/mechanism words FROM that stash row (fix8 C2: the old
"ride the header, never the stash" line contradicted this
paragraph and was wrong — without the stash the return has no
scalars). The return always deletes the stash row and reads
the fixed bytes on `CKR_OK` only (fix9 R5 — a failed return such
as `CKR_TOKEN_NOT_PRESENT` on a polled empty slot must not leave
its row behind to fill the map). NULL
pointer → unavailable; any other return → never (no
BUFFER_TOO_SMALL/query-shape rule: these are not length cells).
Every terminal/loss path clears the retained row, exactly like
the S-protocol cell. FULL builds only: the P0 flavors omit the
info programs (explicit unavailability, §17.4), so P0 acquires no
info bytes.

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
every terminal path; private in-flight + info-record transport;
public parsed fields only: cryptoki/library versions, manufacturer,
description, flags); `Token info ranges (C_GetTokenInfo)` (the
four §17.1 ranges — manufacturer, model, flags incl. the PIN-state
bits, PIN min/max lens, hardware/firmware versions — plus the slot
scalar from the INFO record header, snapshotted at entry;
§17.2 bytes never fetched, not read-and-scrubbed); `Mechanism
info struct (C_GetMechanismInfo)` (whole `CK_MECHANISM_INFO` +
slot/mechanism scalars from the INFO record header, snapshotted
at entry; min/max key size as raw mechanism-dependent numbers,
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
> `--key-operations`, and independent of `--key-sizes` (§17.7).
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
authorized). Every native inventory mode loads the inventory
object, which carries only the usage entry probes and compiles
out `START`/`CallStart`, `EVENTS`, `STATS` and `DESCRIPTORS`
(`main.rs` `cfg(not(feature = "inventory-only"))`) — so Task 7
brings its own entry+return pair, stash map, kind map and ring
there. Fix8 C3: there is no journal info carrier — no journal
info programs, no 760/600 forms, no `EVIDENCE_START` info use —
so the inventory pair is the only carrier and no dedup rule is
needed (the old design's mechanism loss — `C_GetMechanismInfo`
records only `slot_arg 0` with no `mechanism_arg`,
`src/kinds.rs:188-191` — and its double-carrier duplication are
both gone with the journal carrier).

Programs, in every native inventory mode including under
`--key-operations`: `p11_info_entry_lp64` /
`p11_info_entry_ia32` / `p11_info_return` (new programs in the
inventory object; per-ABI entries follow the usage-entry
precedent). The entry programs run the UNCHANGED `usage_entry`
body first — in the Global flavor `mark_usage`, in the Callers
flavor `inventory_callers::record` (fix8 C1: live inventory
always loads the Callers flavor — `FacadeLane::prepare` →
`default_caller_budget`, `src/inventory/capture.rs:4386-4400` →
`prepare_callers_pinned`,
`src/attach/inventory/capture.rs:2108-2181` — and in that
flavor the usage entry records the `CALLER_USE` witness plus
entry count, `crates/ebpf/src/inventory.rs:66-79`; a
mark-usage-only info entry would drop the caller's "which
program called my token?" rows by default) — and then stash,
but only when the admit gates pass (fix9 R3: `usage_entry`
returns 0 on every path, `inventory.rs:39-81`, so its return
value cannot gate the stash — without re-evaluation, processes
outside the operator's PID or cgroup scope would have their
info captured). The info entry re-evaluates the gates after the
usage body — or through an admit helper shared by the two info
entries only, never by refactoring `usage_entry` — and stashes
only when `scope_auth()` is `Some`, the probed layout equals
the declared ABI, the config and cookie endpoint are valid, and
`INFO_KIND[endpoint]` is nonzero; otherwise it stashes nothing
(while the usage witness above still records).
`p11_usage_entry_*` code is untouched and its bytes stay pinned
(§8.5 linked-instruction identity). The return program always
deletes the stash row, obtains the caller identity via
`p11_link_current_identity` (Callers flavor; Global emits zero),
reads the §17.1 ranges on `CKR_OK` only (R5), and emits the
176-B info record on the dedicated `INFO` ring. +0 newly probed
functions (all three already carry usage probes).

`INFO_START` stash map (fix8 C2/I2): `HashMap`, key 16 B
(`pid_tgid: u64`, `endpoint: u32`, pad — the endpoint leg is
required because the p11-kit proxy nests info calls on the same
thread across endpoints, so `pid_tgid` alone aliases), value
32 B (`info_ptr: u64`, `slot: u64`, `mechanism: u64`, `kind:
u8`, `layout: u8`, reserved 6 B — fix9 R8 drops the `generation`
stamp, whose "control cell" named no map; the row carries no
caller-identity field — the return obtains it via
`p11_link_current_identity`, below), capacity 1024 (cold
in-flight calls only; order of 64 KiB reservation with hash
overhead, measured at load). Lifecycle: the entry
always overwrites its key on retention and always deletes it on
the unavailable path (a stale row is never trusted — NULL-cell
and refused-guard shapes delete, never leave); the return
always deletes the row and reads the §17.1 ranges only on
`CKR_OK` (fix9 R5 — failed calls such as
`CKR_TOKEN_NOT_PRESENT` on polled empty slots must not leave
rows behind to fill the 1024-entry map), and on a missing row
emits nothing with the named `info_unmatched_return` count
(the same-thread same-endpoint nesting case: the inner entry
overwrites, the inner return consumes the inner row, the outer
return finds no row and yields unavailable — exactly one good
record plus one named unavailable, never a crossed pointer).
Stop
scrub: after callback quiescence the inventory teardown
zero-verify-removes every `INFO_START` row (the
`object_stop.rs` pattern) and asserts the map empty — plus
fresh maps per preparation, so no row survives the session.
Full-map insert failures, unmatched returns and nested
overwrites each land in their own `INFO_EVIDENCE` PerCpuArray
cell (new map, 4 cells: insert failures, unmatched returns,
nested overwrites, stash mismatches — never silent, never
folded into `EVIDENCE`).

Function kind (fix8 I3, publication fixed by fix9 R1): the BPF
side learns the function from an endpoint→kind map, `INFO_KIND`
(`Array`, key 4 B, value 8 B with the kind in the low byte,
capacity N, `BPF_F_RDONLY_PROG` so the BPF side stays
read-only). Publication follows the `ENDPOINT_OBJECT` precedent
exactly (`publish_caller_endpoint_with`,
`src/attach/inventory/callers.rs:163-181`; invariant (a),
`capture.rs:11-19`): each endpoint's kind is written once at
admission in `admit_entry`/extend and read back, re-publication
is refused, and the map is never frozen — `ENDPOINT_OBJECT`
appears in no freeze list
(`src/attach/inventory.rs:726-769`) because endpoints are
admitted during capture extends, after preparation has already
loaded the programs; freezing `INFO_KIND` in the prepare
sequence would freeze it empty and no info would ever be
captured. The entry reads
`INFO_KIND[endpoint]` to select argument positions and read
ranges; kind zero (usage-only endpoint) takes the usage body
with no stash. The cookie-tag alternative is REJECTED: the
cookie's high word is fully consumed by `INVENTORY_COOKIE_TAG`
and the low word by the endpoint id
(`crates/ebpf-common/src/lib.rs:443-450`), so stealing kind bits
would fork `inventory_cookie_endpoint` and every cookie site
(activation, capture, tests) and weaken the exact-tag refusal —
the map follows the `ENDPOINT_OBJECT` precedent, keeps the
cookie ABI byte-identical, and costs one array lookup.
Plumbing: `AttachEndpoint`
(`src/discovery/inventory_attach_set.rs:152-157`) and
`InventoryEndpoint` (`src/attach/inventory/activation.rs:43-48`)
each gain the endpoint's info kind (`None` = usage-only). The
attach set computes it from the plan slots' names at that
physical (object, offset) (`Slot.names`/`aliased`,
`src/plan.rs:182-210`): the set is exactly one of the 3 info
functions → that kind; anything else (alias of two info
functions, info aliased with a non-info function, no info
function) → `None`. Link rule: the info pair links ONLY where
the kind is `Some`; otherwise the usage entry stays and the
endpoint reports the named gap `info_aliased_endpoint`
(counted per endpoint, surfaced in the Task 7 section — never
a silent skip, never a guessed kind). Validators, freeze and
load mode: `validate_inventory_maps` and
`validate_caller_maps` (`src/attach/inventory.rs:437-560`,
`src/attach/inventory/callers.rs:38-90`) gain the exact
`INFO_START`/`INFO`/`INFO_KIND`/`INFO_EVIDENCE` rows and the
`PRODUCED` size 3; the freeze sequence
(`prepare_inventory_with_kind`, `src/attach/inventory.rs:726-771`)
gains nothing — there is no `Freeze("INFO_KIND")` (fix9 R1:
admission-published maps are never frozen); Multi load mode
(`inventory_program_load`,
`:662-678` — today `UProbeMulti` for the usage entries only)
extends to the info entries, and info returns attach per group
(a new return-group attach mirroring `attach_entry_group`,
`activation.rs:291-301`).

Links (fix8 I1 — the old "+3 return links per provider" line
assumed Singles): on Singles the info entries substitute usage
entries (+0 entry links) and each info endpoint attempts one
return link (+1 per info endpoint, attempted). On Multi the info
endpoints split out of their usage groups into their own groups
per (object, info entry program)
(`capture.rs:1822-1890` grouping): +G entry-group links and +G
return-group links, where G is the number of distinct (object,
ABI) pairs among the info endpoints (one provider object × one
ABI in the fixture, pinned by the routing twin — the Multi
figure is kept). Info return links are NOT counted in the hard
preflight (N4 deferral, superseding the fix9 R7 static
info-return bound for preflight counting): `entry_link_bound`
(`src/attach/inventory/capture.rs:225-229`) stays entry links
only, and `fd_preflight` (`:235-261`) grows from links + 3 + 64
to entry links + 4 (2 roots + `DISCOVERY` + `INFO`) + 64 —
the §17.6 routing twins pin the exact link plan and the fd
formula per backend, and the 4096-endpoint Singles cell stays
passing: the guest load cell (`check-bpf-load-kernels.sh:50-51`,
4163 fds today) and the host exact-arithmetic cell
(`capture/tests.rs:2996-3024`) are updated to the new formula
with review (Singles 4096 needs N + 68 = 4164, still far below
the guest's raised 65536), never deleted or left red. Info
return links attach opportunistically after the entries; on
EMFILE the endpoint's (Singles) or group's (Multi) info return
is left unlinked and reports the named counted gap
`info_return_deferred` (per endpoint/group, surfaced in the Task
7 section — the usage entry still records, the capture never
stops: owner partial-never-stop, following the entry-deferral
precedent `fd_exhausted` + `deferred`,
`capture.rs:722-724/2299-2301`). A later extend with free fds
retries the return attach; until then that endpoint's info is
unavailable with the named gap, never silent. The
`INFO` ring (64 KiB `RingBuf`, cold traffic)
drains in the inventory session alongside `DISCOVERY`; loss
accounting rides a new `PRODUCED_INFO = 2` cell with
`PRODUCED_CELLS` 2→3 (`lib.rs:609-611`) — the drain
cross-checks produced vs consumed per quantum and counts the
difference, never a silent drop.

Feasibility inside the inventory-only build: the info pair needs
none of the compiled-out items. It brings its own stash/kind
maps, evidence cells and ring (existing `HashMap`/`Array`/
`PerCpuArray`/`RingBuf` kinds, without the
`cfg(not(feature = "inventory-only"))` gate); entry/return probe
support already exists in the inventory object (the
`INVENTORY_PROGRAMS` table carries both `Entry` and `Return`
kinds, `src/attach/inventory.rs:602-617`); `scope_auth`
(`main.rs:630`), `probe_layout`/`ret_probe_layout`
(`:540-548`), `read_word`/`BpfReader` (`:550-575`),
`cookie_of` (`:2378`), `arg_u64` (`:2821`),
`p11_read_ia32_arg` (`:2848`) and the no-op inventory stop gate
(`:443-454`) plus `validate_target_span` (ebpf-common
`object_capture.rs:340`) are all available outside the gate;
the byte-range reader is a 2-line body the lane adds for the
inventory flavor (the existing `read_bytes_user` is gated,
`:576-581`, its body is not special). `INVENTORY_PROGRAMS`
grows from 12 to 15 entries with review in the FULL inventory
flavors (Global and Callers); the P0 inventory flavor keeps the
exact 12-program list (info omitted, explicit unavailability).
No fallback to key-operations-only is needed; Task 7 ships in
default inventory and CBOM as §17.7 requires.

Refused journal start (fix8 C3 fallback): a refused journal
start retries the ordinary lane and keeps broad inventory
running with an honest "key operations unavailable" gap
(`src/inventory/mod.rs:5910-5928`). The inventory info pair
rides that broad lane — it never rode the journal — so Task 7
output continues unchanged across the refusal; that
independence IS the fallback, pinned by a §17.6 twin asserting
info positives on a journal-refused run.

Entry-guard spans are the full struct sizes (88/76, 208/160,
24/12 LP64/ia32); bytes read are the field ranges only (76/72,
76/64, 24/12 — §17.1). The 512-byte frame test must pass
unmodified in limit. Verifier: the info programs get their own
budget cells (§8.5: recorded, <750,000, ≥5% headroom on the 6.6
floor), `bpf loads` on vng 6.6/6.12 + host 7.x, LP64 + ia32.
The P0 inventory flavor omits the info programs (exact
12-program list above); Task 7 in P0 reports explicit
unavailability (no info bytes acquired).

Cold cost (default-on, negligible by construction): one 176-B
record per info call in every mode at application poll rates
(Hz, not the kHz of hot paths — the Task 7 lane records the
observed info-call rates on the Task 5 matrix apps as coldness
evidence); one stashed row per in-flight info call (bounded by
the 1024-entry map); zero per-call record, ring or count delta
at any non-info endpoint (covered by the §12.1 identity
contract). No shared row grows, so the Task 7 delta never moves
the base-program hashes (§8.5 — keymeta lanes never re-hash;
the integrator re-records on non-keymeta base changes).

Wire: the 128-byte info trailer (`version: u16`, `kind: u8`,
`status: u8`, `layout: u8`, `payload_len: u8`, 3 reserved bytes,
`payload: [u8; 120]` — payload_len is exact per (kind, layout):
76/72 for `CK_INFO`, 76/64 for token ranges, 24/12 for mechanism
info) rides one carrier: the 176-B inventory info record (48-B
header + trailer) on the `INFO` ring. Header (fix8 C2, identity
fixed by fix9 R2, `generation` dropped by fix9 R8):
`endpoint_id: u32`, `kind: u8`, `layout: u8`, reserved `u16`
(8 B); `host_tgid: u32`, reserved `u32` (8 B, the witness's host
thread group, mirroring `CallerObjectUse.host_tgid`);
`caller: ImageIdentity` (`task_cookie: u64`, `exec_id: u64`,
16 B — the full caller identity `CALLER_USE` is keyed by,
`inventory_callers.rs:35-39`, so the header joins exactly the
way `CALLER_USE` rows resolve, `callers.rs:473-480`; the old
truncated 32-bit cookie with no exec id could not survive an
exec); `slot: u64`, `mechanism: u64` (16 B, snapshotted at entry
into `INFO_START` — §17.1 — because a uretprobe cannot read
entry arguments). In the Callers flavor the return obtains the
calling image's identity via `p11_link_current_identity` (same
task as the entry, so the same image; the helper already runs in
return context — `ordinary_return`, `main.rs:4695-4696` — and is
linked into the Callers inventory build,
`main.rs:3247-3248`), so the 32-B `INFO_START` row carries no
identity field; in the Global flavor (proof only, no caller
witnesses) the return emits a zero identity without calling the
helper (cookie 0 = unavailable, `lib.rs:1594`; the helper is not
linked into the Global inventory-only build). `mechanism` is 0 for
`C_GetInfo`/`C_GetTokenInfo` and `slot` is 0 for `C_GetInfo`.
The join reads header words
per the kind (the provider kind ignores slot) and keys by
(module via endpoint, caller incarnation, slot[, mechanism])
(§17.5). The record validator is exact length + header (known
endpoint, known kind, layout, zero reserved) + trailer
(version + kind + layout + payload_len + zero reserved). This
keeps the v2-tail-union alternative beaten on validator surface:
the union would fork `validate_object_tail` with a union tag
plus per-action offsets, while the record adds standalone
exact-length checks and leaves every existing validator,
classification and pin byte-identical. Old readers refuse 176
loudly. Task 7 merges after Task 3's merge commit and consumes
the Task 2 evidence-table base through that chain (shared
files, one writer at a time — the §13 rule).

### 17.5 Schema, output and CBOM

New schema section, next free number after v7 (suggest v8;
integrator allocates per §10.1), emitted exactly when Task 7
content is present; v1–v7 stay frozen and byte-stable (fix8 C2:
keys hang off `modules[]`/`edges[]`, never bare instances):

- per module `provider_info`: cryptoki/library major+minor,
  manufacturer, library description, flags (references the
  `modules[]` record — library facts do not vary by caller);
- per (module, caller incarnation, slot) `tokens[]`:
  manufacturer, model, hardware/firmware version, flags (whole
  word, incl. PIN-state bits), `pin_min_len`, `pin_max_len`,
  `completions`, `changes`;
- per (module, caller incarnation, slot, mechanism)
  `mechanisms[]`: type, min/max key size as RAW numbers (no unit
  claim — PKCS#11 v2.40 §3.5: "bits or bytes,
  mechanism-dependent"), flags, `completions`, `changes` —
  capped at 128 mechanisms per (module, caller, slot); extras
  refuse with a named `mechanism_info_refused: too_many`
  counter, never silently.

Repeat rule (apps poll; flags change; tokens swap): last-wins per
(module, caller, slot) and per (module, caller, slot, mechanism).
`completions` counts polls; `changes` counts value transitions
(first observation sets the value with `changes: 0`). A different
token inserted into the same slot is last-wins plus one `changes`
bump — never a second entry, never a merge. Per-slot caps: tokens
are 1 per (module, caller, slot) by construction; mechanisms 128
per (module, caller, slot) (above).

Join (fix8 C2, identity fixed by fix9 R2): info record →
(module via endpoint id, caller incarnation via the header's
`ImageIdentity`, slot[,
mechanism]) onto `modules[]`/`edges[]` (the header carries all
four — §17.4 — because slot ids are per-process and joining by
(provider, slot) across processes on a busy `--system` host
would mix different processes' tokens under last-wins). The
default no-manifest run has no semantic lane at all
(`src/inventory/mod.rs:1696-1712`: "No manifests means no
Session") and instances exist only there
(`docs/schema/inventory-v1.md:1001-1013`), so the default join
never mentions instances: rows carry module + caller references
resolving in `modules[]`/`edges[]`. Where the semantic lane
proves an instance (manifest runs), the same rows additionally
carry the instance id — attached, never synthesized, and never
required. No `AggKey` contact (these are not key rows) and no
`metadata_at_use` contact.
A provider with no completed Task 7 calls has no `provider_info`
block: "provider never watched" is derivable from the JSON
already (no rows for its module beside coverage notes), so no
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
count: exactly one (module, caller, slot) reporter → plain properties
(`p11scope:min-key-size`, `p11scope:max-key-size`,
`p11scope:mechanism-flags`, `p11scope:mechanism-hw`); more than
one → per-reporter properties suffixed
`p11scope:slot-<slot>:<base>` (slot ids are provider-small;
different reporters sharing a slot id each report — suffix
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
negative, owner-mismatch negative; usage-preservation twins
(fix8 C1): in the Global flavor the USAGE bitmap still marks
the 3 endpoints used, and in the Callers flavor the
`CALLER_USE` rows and entry counts at the 3 endpoints equal the
usage-entry baseline exactly (same rows, same counts — the info
entries run the unchanged `usage_entry` body first); scope twin
(fix9 R3): an info call from a process outside the PID/cgroup
scope — and an info call at a usage-only endpoint with kind
zero — stashes nothing and emits no record, while the usage
witness still records; selection
twins: in every native inventory mode including under
`--key-operations` the info endpoints link the inventory info
pair while every other endpoint links usage entries
(cold-only proof — no journal program links at an info
endpoint in any mode); routing twins per backend (fix8 I1,
N4 deferral): Singles pins +0 entry links and +1 attempted
return link per info endpoint, Multi pins +G/+G with G = the
distinct (object, ABI) info pairs, and both pin the extended fd
formula (entry links + 4 + 64 — info returns excluded from the
hard preflight); a deferral twin pins EMFILE leaving the info
return unlinked with the named counted `info_return_deferred`
gap while the usage entry still records and the capture
continues; single-info-function twins
(fix8 I3): an endpoint whose slot set is exactly one info
function links the info pair with the right kind in
`INFO_KIND`, while an info/non-info alias and an info/info
alias keep the usage entry and report the named
`info_aliased_endpoint` gap; lifecycle twins (fix8 I2):
same-thread cross-endpoint nesting yields two good records
(p11-kit case), same-thread same-endpoint nesting yields one
good record plus one named unavailable, a full `INFO_START`
lands in its evidence cell, the teardown scrub leaves the map
empty, a failed-RV return deletes its row with no record (fix9
R5), and the drain's `PRODUCED_INFO` cross-check counts a
forced loss; fallback twin (fix8 C3): info positives on a
journal-refused run equal the unrefused run's; join twins
(fix8 C2): two processes' same-slot tokens stay separate rows
under one (module, caller) each, and a manifest run attaches
the proved instance id while a no-manifest run carries none;
sentinel twin: a provider
returning sentinel serial/label/session/memory/utcTime bytes and
sentinel `CK_INFO` pad bytes publishes none of those bytes
anywhere (JSON/logs/maps scanned — the B6 padding-sentinel twin);
PIN-policy positive twin: PIN-state flag bits and
min/max PIN lens publish with exact values; repeat twin:
re-polled token (same value → `completions` bump only; changed
flags → `changes` bump; swapped token → last-wins + `changes`
bump, single entry); cap twin: the 129th mechanism on a
(module, caller, slot) refuses with the named reason while the
first 128 stand; units
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

### 17.7 Mode scope: default inventory and CBOM

Task 7 rides one info lane in every native inventory mode: the
inventory info pair stashes one row per in-flight info call
(`INFO_START`: pointer + slot/mechanism/kind/layout)
and emits the 176-B record on the `INFO` ring (§17.4), drained
in the inventory session — under `--key-operations` too, where
the broad inventory lane runs beside the journal lane. The join
keys off the record header's (module via endpoint, caller
incarnation, slot[, mechanism]) (§17.5). The object lane's
`--key-operations` gate (`src/cli.rs:828`,
`allowlist-v3.md:108-125`) therefore does not apply:
provider/token/mechanism info appears in DEFAULT inventory
(JSON + concise/`-v` text) and in CBOM whenever the Task 7
amendment rows (§17.3) are approved and the calls are observed.
A refused journal start changes nothing for Task 7: the
ordinary retry keeps the broad lane (and the info pair on it)
running with an honest gap (§17.4 fallback). Cost per run: +0
newly probed functions (all three already carry usage probes);
links per backend (§17.4: Singles +1 attempted return per info
endpoint, Multi +G/+G; EMFILE defers with the named counted
`info_return_deferred` gap, never a stop); one 176-B record per
info call (rare — apps poll tokens, not hot paths); one stashed
row per in-flight info call. No `--key-operations` requirement, no object-lane
dependency, no `--key-sizes` interaction: Task 7 output is
identical with the flag on or off (§10.5; pinned by a
both-modes twin in Task 7).
(Keymeta Tasks 1–3 DO need `--key-operations`: inferred facts
ride per-key rows, which exist only there; §5 sizes additionally
need `--key-sizes`.)

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
