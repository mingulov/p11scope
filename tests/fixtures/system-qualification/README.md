<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System qualification policy fixtures

These files define the acceptance inputs used by
`scripts/verify-system-test-manifest.py` and its mutation tests:

- `closure-ledger.json`: 147 finding policies, with stable identifiers,
  dispositions, task owners and required checks.
- `system-deferred-gates.json`: 43 additional gate groups, including the two
  explicitly optional groups.
- `system-test-manifest.json`: a complete 214-cell register with every cell
  marked `NOT_RUN`. Seven cells retain their registered test selectors.

The register is a test input, not a successful qualification receipt. Its
`ledger_sha256` binds the JSON policy file; `deferred_sha256` binds the gate
catalog. Historical identifiers and task labels are retained so moving
internal campaign reports out of the public repository does not weaken or
rename the acceptance requirements.

See the [manifest guide](../../../docs/qualification/system-test-manifest.md)
for structure checks, execution receipts and the distinction between
`STRUCTURE_VALID` and a qualified claim.
