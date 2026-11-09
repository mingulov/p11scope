<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# CBOM fixtures

`bom-1.6.schema.json` is the official CycloneDX 1.6 JSON schema,
vendored byte-identical from
`https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json`
(fetched 2026-11-07, SHA-256
`3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93`).
It is used only by the `inventory cbom` command tests to validate the
produced BOM. Upstream license: Apache-2.0, see
`LICENSE.CycloneDX-specification` (the upstream LICENSE file,
vendored byte-identical).

`jsf-0.82.schema.json` (SHA-256
`8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae`)
and `spdx.schema.json` (SHA-256
`baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e`)
are the schema's two sibling documents from the same upstream
directory, vendored byte-identical: the main schema references them
(`jsf-0.82.schema.json#/definitions/signature`, `spdx.schema.json`),
so the validator registry preloads them under their canonical
`http://cyclonedx.org/schema/…` URIs to stay fully offline. This
directory's other files are p11scope's own test inputs under the
repository license.

`inventory-with-crypto.json` is a synthetic `p11scope/inventory/v1`
document shaped after `../inventory-diff/scan-current.json` with a
second caller, a second provider, S1 mechanism rows (AES-GCM, RSA
PKCS#1 v1.5, SHA-256, ML-KEM-768 and one unnamed vendor id), and a
populated `object_observations` section (an RSA-2048 private key, an
AES-128 secret key, one key without established size). Digests are
SHA-256 of fixed literal labels, never real provider bytes. No real
caller or provider metadata is included.
