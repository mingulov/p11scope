<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
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
| Folded departed caller (`modules[].departed_use.identities[].exe.path`), merged into the same per-path component | `type: application` (same component; `p11scope:departed_incarnations` counts the folded incarnations) |
| Provider module (`modules[]`: paths, device/inode, SHA-256, admission, lifecycle) | `type: library`, `name` = first recorded path; SHA-256 becomes a `hashes[]` entry when it is 64 hex digits |
| Mechanism id (`edges[].mechanisms[]`, `modules[].departed_use.mechanisms[]`, profile `mechanisms[]`), unioned by id | `type: cryptographic-asset`, `cryptoProperties.assetType: algorithm` |
| Key object (`object_observations.objects[]` with established metadata or a label) | `type: cryptographic-asset`, `cryptoProperties.assetType: related-crypto-material` |
| Provider facts (`modules[].provider_info`) | `supplier` object + `version` on the provider's `type: library` component |
| Token row (`provider_observations.tokens[]`) | `type: device`, linked to its library via `dependencies[]` |
| Mechanism limit rows (`provider_observations.mechanisms[]`) | limit properties on the mechanism id's `algorithm` component |

`bom-ref` values (`p11scope:caller:N`, `p11scope:module:N`,
`p11scope:mechanism:<hex>`, `p11scope:key:<object>`,
`p11scope:token:N`) are minted by this
report only, like the diff report's local references. `dependencies[]`
carries only joins the input proves: application → its modules,
application/module → mechanisms observed on their edges, key object →
its provider module and caller application via the key-operation →
instance → module/caller join (when joinable, otherwise no edge and
a named note). Folded instances keep the same joins through
`modules[].departed_use.folded_instances[]` (instance → caller) plus
the identities (caller → executable path). One caller folded at
several providers counts one
incarnation under its path: the per-module identity copies
deduplicate by caller. Folded joins follow the same rule: each
departed application joins the provider it folded at, and folded
mechanisms join that provider, but per-application mechanism pairs
survive the fold only when every folded caller at the module is named
and all share one executable path — otherwise the pairs are withheld
and the module counts into `p11scope:departed_links_withheld`, never
guessed.

## Provider, token and mechanism info (Task 7, v1 only)

When the input carries Task 7 content (`modules[].provider_info`
and/or the top-level `provider_observations` section, section
version 8 — any other section version refuses the conversion), the
projection re-projects it; profile inputs never carry it.

- The `type: library` provider component keeps its `name` (first
  recorded path) and gains `supplier` as an object
  (`{"name": <manufacturerID>}` — never a string) plus `version`
  (`<library major>.<library minor>`). A refused (non-UTF8)
  manufacturer omits the supplier; malformed provider detail
  degrades to no supplier/version while the component renders.
- Tokens dedup to one `type: device` component per (module,
  slot, token identity) named `<manufacturerID> <model>`
  (available parts only; `token slot <N>` when both strings were
  refused) with hardware/firmware versions, flags and PIN lengths
  in `properties[]`, linked to its library via `dependencies[]`.
  Callers reporting the same token share the device; a
  conflicting identity on the same slot keeps its own device.
  Serial numbers, labels, session counts, memory sizes and clock
  readings have no key anywhere in this output.
- Per-slot mechanism limits map onto the global-per-id `algorithm`
  components by reporter count: exactly one (module, caller, slot)
  reporter reads plain properties (`p11scope:min-key-size`,
  `p11scope:max-key-size`, `p11scope:mechanism-flags`,
  `p11scope:mechanism-hw` from the `CKF_HW` bit); more than one
  reads per-reporter properties suffixed
  `p11scope:slot-<slot>:<base>`, capped at 16 reporters per
  mechanism id, with `p11scope:slot-limits-truncated: true` instead
  of merging when reporters share a slot suffix or exceed the cap.
  Limit numbers are the raw provider words, never a unit claim.
  When limit properties are present the algorithm `description`
  gains `; provider key-size limits in properties`. A mechanism id
  with limits but no observed operation row mints an algorithm
  component from the limits alone (zero calls, no observed
  operations); it stays out of the unknown-primitive count.
- Text: the head counts tokens only when devices exist; `-v` adds a
  tokens block. Section gaps (`info_*`, `mechanism_info_refused`)
  have no CBOM mapping and are not projected.

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
Key-generation spellings carry their family's primitive with
`cryptoFunctions: keygen` (the family is name-determined; only
family-less spellings like `CKM_GENERIC_SECRET_KEY_GEN` read
unknown). Anything else — unregistered ids (no name), profile rows
(names are not in the published JSON and are never re-resolved
here), unknown categories — reads `primitive: unknown` with the raw
input kept in `properties`.
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
it. The key-type code 66 renders `key_type_name: hkdf`; other
codes keep their established names. K4 qualification: a slot whose
`status` is `value` qualifies however it was established — a query
answer and a creation-success promotion read identically; the
recorded `source` only feeds the
`p11scope:established_source_{query,creation_success,unrecorded}`
provenance tallies in `metadata.properties` (unrecorded covers
pre-v6 inputs, which carry no source). Inferred facts never reach
these established fields: a v7
`inferred_family`/`inferred_size` is not `type`, `size` or `curve`
here, and no property echoes it.

## Provenance and unknowns

The BOM carries no `serialNumber` (no stable identity to mint from)
and no `metadata.timestamp` (inputs carry capture windows, not wall
clock: RFC3339 for profile, monotonic nanoseconds for inventory, both
quoted verbatim in `metadata.properties` beside the source schema,
scope, passes, gap count and coverage notes). Every unknown the input
states stays an explicit unknown: unregistered mechanism ids, unnamed
primitives, keys without established size, callers without an
executable path, unavailable object observations, profile inputs'
missing caller/key/provenance linkage, and the departed-fold bounds
(`departed_identities_dropped`, `departed_identities_saturated`,
`departed_folded_instances_dropped`,
`departed_folded_instances_saturated`, `departed_mech_overflow` with
its calls/errors, and `departed_links_withheld`) are counted in
properties and
named in text. The departed properties ride only when nonzero, so
inputs without a fold render exactly as before. Text output follows
the usual contract (concise
default, `-v` detail, `--quiet` head only, `--json`/`-o` complete);
a malformed crypto detail degrades its component to unknown with a
named note and never stops the view. Input, schema or output failures
exit 1; usage errors exit 2; a broken stdout pipe exits 0.

Reader bounds are exactly the `inventory diff` per-input bounds (same
constants, same help line); unknown additive input is bounded and
ignored, never copied through. Output is validated against the
vendored official `bom-1.6.schema.json` (see
`tests/fixtures/cbom/README.md`) in the command tests.
