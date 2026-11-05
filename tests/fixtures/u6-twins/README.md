<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# U6 installed journey cells (G22)

Driver: `tests/fixtures/u6-installed-drive.py`, selected by
`installed_all_modes_match_owned_ledger` (ledger journey) and
`installed_named_trace_positive_and_false_name_controls` (named-trace
journey) in `tests/cross_command_journeys.rs`.

Twins are generated in this task's scratch from the real oracles'
vocabulary (`scripts/inventory-native-oracle.py` `Synth`,
`scripts/cgroup-trace-oracle.py` triples, the reviewed
`inventory-diff/scan-current.json` pair); nothing static can rot against
oracle evolution. Every twin runs through the real check path: green
twins must pass, red twins must exit nonzero, and any inversion fails
the selector.

## Ledger journey: all modes vs the owned ledger

| Twin | Oracle | Red is caught by |
| --- | --- | --- |
| `ledger-green-native-pass` | C8 `Synth("native")` + `oracle()` | — (338 passing assertions) |
| `ledger-red-drop-use` | same | `USED-POSITIVE`, exit 1 |
| `ledger-red-phantom-edge` | same | `NO-CROSS-ATTRIBUTION`, exit 1 |
| `ledger-red-exec-merged` | same | `EXEC-SPLIT`, exit 1 |
| `ledger-red-pty-disagree` | same | `DASH-TOTALS`, exit 1 |
| `ledger-red-pipe-disagree` | same | `AGREE-EDGE-EVENTS`, exit 1 |
| `rotation-green-conserved` | `rotation_verdict` (retained + accounted == emitted, exact ledger match) | — |
| `rotation-green-window-excludes-idle` | same with capture window | out-of-window uses excluded |
| `rotation-red-gap` / `-duplicate` | same | conservation |
| `rotation-red-phantom` / `-missing-use` | same | ledger match |
| `rotation-red-no-rotation` | same | rotation-not-exercised |

Live: `qualify-inventory-native.sh --lane native` (system/pipe-JSON,
dashboard-PTY, exec chain, stop) plus a rotation cell (`--event-rotate-bytes
1K --event-max-files 3`, conservation plus exact retained-ledger match with
`edges_unretained == 0`) and a U6 compact 48x12 PTY cell
(`record-pty … 12 48 …`, frame totals and framed PIDs vs document and
ledger). Inputs: `--binary`, `--source-revision`,
`--c8-base`, `--workload-coordinator` (`{pid, modules, ledger, gate?}`).

## Named-trace journey: positives plus false-name twins

| Twin | Oracle | Red is caught by |
| --- | --- | --- |
| `trace-green-named-positive` | `cgroup-trace-oracle.evaluate` (2 named / 1 unknown / 0 false) | — |
| `trace-red-false-name` | same | `false_names == 1` |
| `trace-green/red-duplicate-basename` | same | wrong-path row with right basename |
| `trace-green/red-exec-generations` | same | generation mixup |
| `trace-green/red-unreadable` | same | invented label for Unknown |
| `trace-green-unknown-honest` | same | — (Unknown is honest) |
| `trace-red-mapped-only-phantom` | same | population disagreement |
| `trace-red-slow-reader-drop` | same | terminal-count disagreement |
| `diff-green-known-change` | `cross-command-drive.Journey.saved` (offline diff) | — |
| `diff-red-empty-population` / `-wrong-schema` | same | input rejection |

Live runs `qualify-cgroup-trace.py` with explicit trusted manifests only
(default discovery is refused: `--manifest` + `--manifest-helper` +
`--helper-source-revision` are mandatory, and each manifest must bind the
held provider's path and SHA-256). Twin verdicts reuse the qualify oracle
results with an explicit `false_names == 0` gate: `stable` → named
positive, `onecall` → unknown-honest, `exec` → both generations named,
`run` → public-route parity. The default `--cells` is the full U6 twin
matrix; the extended twins (`mapped-only`, `unreadable`,
`duplicate-basename`, `slow-reader`) run when the qualify matrix supports
them, and until then the live path fails closed naming the missing
support. The diff path captures two real saved inventories with
the installed binary (`capture_inventory_pair.py`) or accepts an
explicit `--before/--after` pair, then runs the offline diff journey.

## Seams

- `P11SCOPE_U6_INSTALLED_BINARY`: absolute installed candidate (live).
- `P11SCOPE_U6_SOURCE_REVISION`: exact 40-hex source commit (live).
- `P11SCOPE_U6_DRY_RUN=1`: selector proves wiring without capturing.
- `P11SCOPE_U6_RED_PROOF=<red-twin>`: proof-only; runs one red twin
  through the pass assertion so the check must exit nonzero. Self-test
  and dry-run only; live refuses it; the installed gate never sets it.
- Live inputs (`P11SCOPE_U6_OUT`, `P11SCOPE_U6_C8_BASE`,
  `P11SCOPE_U6_COORDINATOR`, `P11SCOPE_U6_PROVIDER/CALLER/MANIFESTS/
  MANIFEST_HELPER/HELPER_REVISION/UID/GID/CELLS/BEFORE/AFTER/
  PAIR_PREBUILT`) map 1:1 to driver flags; a partial seam fails closed.
