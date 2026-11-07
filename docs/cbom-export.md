<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# CBOM export design note (v0.7.0, V1)

`p11scope inventory cbom INPUT.json [-o out.cdx.json] [--json] [-v] [--quiet]`
converts one saved report into a [CycloneDX](https://cyclonedx.org/) 1.6
Cryptographic Bill of Materials. It is an OFFLINE re-projection, like
`inventory diff`: it reads one explicitly supplied regular file as an
ordinary user, performs no live lookup, loads no provider, captures
nothing new, and needs no privileges. Input is `p11scope/inventory/v1`
(full graph) or `p11scope/observed-profile/v3` / `v2` (mechanisms and
discovery-listed providers only). Anything else is refused with exit 1.

## Mapping (CycloneDX 1.6 cryptographic-asset model)

| p11scope fact (already published) | CBOM component |
| --- | --- |
| Caller executable path (`callers[].image.exe.path`), one component per distinct path | `type: application`, `name` = verbatim path |
| Provider module (`modules[]`: paths, device/inode, SHA-256, admission, lifecycle) | `type: library`, `name` = first recorded path; SHA-256 becomes a `hashes[]` entry when it is 64 hex digits |
| Mechanism id (`edges[].mechanisms[]`, profile `mechanisms[]`), unioned by id | `type: cryptographic-asset`, `cryptoProperties.assetType: algorithm` |
| Key object (`object_observations.objects[]` with established metadata or a label) | `type: cryptographic-asset`, `cryptoProperties.assetType: related-crypto-material` |

`bom-ref` values (`p11scope:caller:N`, `p11scope:module:N`,
`p11scope:mechanism:<hex>`, `p11scope:key:<object>`) are minted by this
report only, like the diff report's local references. `dependencies[]`
carries only joins the input proves: application → its modules,
application/module → mechanisms observed on their edges, key object →
its provider module via the key-operation → instance → module join
(when joinable, otherwise no edge and a named note).

## Algorithm properties (name-determined only)

`algorithmProperties` is filled only where the mechanism's own
registered `CKM_*` name determines it: family → `primitive`
(AES/DES/3DES/Camellia/ARIA/CAST/IDEA/SEED/SM4 block ciphers,
ChaCha20/RC4/Salsa20 stream ciphers, `_GCM`/`_CCM` authenticated
encryption, RSA asymmetric encryption except signature spellings, DSA /
ECDSA / EdDSA / ML-DSA / SLH-DSA signatures, DH/ECDH key agreement,
HKDF/PBKDF/TLS-PRF key derivation, ML-KEM key encapsulation,
SHA-2/SHA-3/MD2/MD5/RIPEMD/BLAKE2 hash, HMAC message authentication,
SHAKE extendable output); mode/padding suffixes (`_CBC`, `_ECB`,
`_GCM`, `_CCM`, `_CTR`, `_CFB`, `_OFB`, `_OAEP`, `_PKCS`, `_PAD`) →
`mode`/`padding`. `cryptoFunctions` comes from the input's observed
operation categories (`sign`, `encrypt`, …), never from the name.
Anything else — unregistered ids (no name), profile rows (names are
not in the published JSON and are never re-resolved here), key-pair
generation spellings, unknown categories — reads `primitive:
unknown` (or omits the key) with the raw input kept in `properties`.
S1 output carries no sizes, curves or parameters, so those keys are
always absent on algorithm components; the omission is stated, not
defaulted.

## Key material (no values, ever)

`relatedCryptoMaterialProperties.type` comes from the established
object class (public/private/secret key, else `unknown`); `size` in
bits from established `modulus_bits` or `value_len × 8` only; `curve`
from an established EC curve name only. The `value`, `id`, `state`
and date keys are never emitted: key bytes, CKA labels/IDs and PINs
are not in the input (see the object-observations privacy rule) and
this projection invents no identifier for them. The capture-local
object id rides a `p11scope:object` property for traceability, with
the label, key-type code, creation family and reference counts beside
it.

## Provenance and unknowns

The BOM carries no `serialNumber` (no stable identity to mint from)
and no `metadata.timestamp` (inputs carry capture windows, not wall
clock: RFC3339 for profile, monotonic nanoseconds for inventory, both
quoted verbatim in `metadata.properties` beside the source schema,
scope, passes, gap count and coverage notes). Every unknown the input
states stays an explicit unknown: unregistered mechanism ids, unnamed
primitives, keys without established size, callers without an
executable path, unavailable object observations, and profile inputs'
missing caller/key/provenance linkage are counted in properties and
named in text. Text output follows the usual contract (concise
default, `-v` detail, `--quiet` head only, `--json`/`-o` complete);
a malformed crypto detail degrades its component to unknown with a
named note and never stops the view. Input, schema or output failures
exit 1; usage errors exit 2; a broken stdout pipe exits 0.

Reader bounds are exactly the `inventory diff` per-input bounds (same
constants, same help line); unknown additive input is bounded and
ignored, never copied through. Output is validated against the
vendored official `bom-1.6.schema.json` (see
`tests/fixtures/cbom/README.md`) in the command tests.
