<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Inventory reader inputs

`scan-current.json` derives its complete shape from `caller_json`,
`module_json`, `edge_json`, `budgets_json` and
`render_json_from_presentation` in `src/inventory.rs`, and its synthetic
identities from the existing `inventory_workload::Harness` tests. The digest
is SHA-256 of the literal bytes `inventory reader fixture`, replacing the
harness's intentionally non-digest `sha000000` placeholder. Times and the
one reference-bearing gap are fixed synthetic evidence. No real caller or
provider metadata is included. The reader tests also exercise a newly rendered
Harness document through the production serializer, with the same explicit
digest normalization; they do not use the abridged schema example.
