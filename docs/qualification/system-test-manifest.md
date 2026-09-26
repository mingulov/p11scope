<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System acceptance manifest v1

`system-test-manifest.json` is the checked-in register, not a claim that its
tests have run. Initially all 214 cells are `NOT_RUN`: 147 closure findings,
43 deferred-work groups,
10 client requirements through public commands, seven private T7 cells,
four installed kernel/profile combinations and three actual-duration soaks.
The ten optional ledger findings, parked feature registry U-23 and cleanup
group G-09 do not gate the product claim. Source-fixed
or refuted findings retain their disposition in the limitation field; the
final audit still needs a named check and an execution receipt at its pin.

The authority is the closure ledger, `system-deferred-gates.json` and `catalog()` in
`scripts/verify-system-test-manifest.py`. Changes to required cells, levels,
profiles or claims must be reviewed there; a submitted manifest cannot
drop a row, remove its claim membership, or relabel its evidence level.
Unknown cells are refused so newly required lanes cannot be silently ignored.
The fixed 147-row assertion makes changes to the ledger inventory explicit.

```sh
python3 -I tests/python/test_system_test_manifest.py -v
python3 -I scripts/verify-system-test-manifest.py \
  --manifest docs/qualification/system-test-manifest.json \
  --evidence-root . --check-structure
```

Structure validation permits open work and returns `qualification: false`.
The normal invocation requires every selected claim's required cell to be
`PASS`. `FAIL`, `INVALID`, `NOT_RUN`, `UNSUPPORTED` and `BLOCKED` never pass
that gate. An expected negative has `PASS` plus an explicit matching
`expected_behavior`; the 8192-endpoint FD refusal therefore proves refusal,
not capture. Use `--claim t7-static` for only the seven static cells;
the default `--claim system-product` includes all 202 nonoptional cells.

## Execution copies and receipts

Create an execution copy outside the tracked source tree. Set `subject` to
the final source revision and tree (40-character Git IDs), and fill each
executed row's exact `test_ids`, argv `command`, `artifact_hashes`,
`evidence_paths`, outcome, receipt path and SHA256. Evidence paths are
relative to a durable evidence root; escaping paths and symlinks are refused.
Every evidence file must also appear in `artifact_hashes`, whose entries
have `path` and `sha256`. The verifier reads files and never executes argv.

Receipt schema `p11scope/test-execution/v1` carries `cell_id`, `subject`,
`evidence_level`, `entrypoint`, `kernel_profile`, `test_ids`,
`executed_test_ids`, `command`, `exit_code`, `outcome`, `artifact_hashes`,
`evidence_paths` and `observed_behavior`. These must agree with the row.
Execution IDs must exactly equal the nonempty, duplicate-free declared IDs.
Entrypoints are `unit-test`, `artifact-check`, `private-live-test`,
`public-cli` and `installed-cli` for their corresponding levels; a soak
also requires the installed command. Installed/soak receipts identify the
`installed` artifact's digest. Soaks require actual monotonic start/end
timestamps covering 1800, 14400 or 86400 seconds respectively.

`final-supported-matrix` is deliberately an unqualifiable placeholder.
T11/T12 must expand those entries into concrete kernel/profile cells and
register exact test bodies before closing them. An aggregate label cannot
substitute for missing kernel tests. Existing named T7 selectors are filled
in the initial register; other owners fill their real test inventory as
their tasks are implemented.

This checks receipt consistency and artifact custody. It does not make an
invented receipt true, validate every product oracle, or replace review of
the owned runner and its logs. Exact workload denominators, physical joins,
scope, loss, terminal output and cleanup belong to each registered test.
Failure logs remain preserved when a successor run is made.

## Owned T7 runner

`scripts/run-t7-static-campaign.py --pins PIN_JSON --output NEW_DIRECTORY`
runs the fixed seven selectors once, serially, from prebuilt pins. It holds
all five current shared live leases and the Cargo-heavy lease, checks exact
one-body listings, validates source/binary/embedded-object/oracle/driver
pins and kernel/BTF, and records typed `(map|prog|link, id)` censuses before
and after each cell. Enumeration failure aborts with evidence preserved.
No host BPF object is deleted. A changed census prevents further cells.
The 1800-second test deadline has ten seconds of termination grace; a timeout
never passes. Failed completed tests retain their evidence and later safe
cells still run. Each cell and the campaign have durable JSON records.

The controller prepares schema `p11scope/t7-static-pins/v1` with exact
`source_revision`, `source_tree`, `kernel_release`, `kernel_btf_sha256` and
an `artifacts` mapping (relative `path` and SHA256). Required roles are
`driver`, `oracle`, `cargo_lock`, and `default`/`wide` `.binary`, `.inventory`
and `.detailed`. The binary must actually contain the pinned object bytes.
Pin the driver itself and use a new output directory. Generated fixture
ELFs and offset receipts are copied and hashed by the owned Rust tests.
This host runner uses Python 3.11+ and existing passwordless sudo authority;
it does not establish that authority or acquire permission on the user's behalf.

Before execution the controller also checks actual host jobs and custody:
cooperative lock acquisition cannot detect an unrelated process that ignores
the lease protocol. Do not overlap heavy builds/VM setup or other BPF work.
This campaign remains private static-mechanism evidence. Public discovery,
live growth, counts, performance and the installed workflow have other gates.
