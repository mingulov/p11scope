<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Provider matrix

One cell per real PKCS#11 provider: the pinned pkcs11-check suite (or a
pkcs11-tool probe for reader-less providers) alone and under
`p11scope run`, plus a `p11scope-discover` manifest assertion and a paced
workload under `p11scope inventory --pid`. The same cell
(`scripts/ci/provider-matrix-cell.sh`, judged by
`scripts/ci/provider_matrix_cell_compare.py`) runs in CI and on test
hosts; CI runs it as root with a setpriv suite user, test hosts as the
user with `sudo -n` for the observer only.

## Providers

| env file | provider | module source |
|---|---|---|
| `softhsm2-2.7.env` | SoftHSM2 2.7, system library | probed system paths |
| `softhsm2-2.6.env` | SoftHSM2 2.6.1, pinned rpm | `fetch-provider.sh softhsm26` |
| `kryoptic.env` | Kryoptic 1.5.2, pinned rpm | `fetch-provider.sh kryoptic` |
| `haskoki.env` | Haskoki 0.5.0.0, pinned tarball | `fetch-provider.sh haskoki` |
| `bouncyhsm.env` | BouncyHsm 2.3.2 client + .NET server | `--extra-deliver bouncyhsm/` |
| `freehsm.env` | FreeHSM `libfreehsm.so` | `--extra-deliver freehsm/` |
| `opensc.env` | OpenSC, reader-less (no suite legs) | probed system paths |
| `p11kit-proxy.env` | p11-kit client + per-cell server over SoftHSM | probed system paths |

Module paths are probed from each env file's `PROVIDER_CANDIDATES`, never
assumed; a pinned task-dir copy wins over system paths, and the winner
plus its sha256 lands in the cell's `cell.env`. Fresh token per cell.

## Entry command

```sh
scripts/provider-matrix/run-matrix.sh --host fedora-sm1 --task v080-matrix \
  --p11scope target/release/p11scope --discover target/release/p11scope-discover
```

Delivers the binaries, cell scripts and extras to
`~/p11scope-live/<task>/`, runs one cell per provider through
`lane-run.sh shared bpf`, collects `out/` to `--collect`
(`./provider-matrix-out`), prints the per-provider table, and deletes
the task folder unless `--keep`. `--providers` selects a subset;
`--mode full` runs the whole pkcs11-check suite per provider (nightly
scale, not per push); `--print-plan` shows the provider list without
touching the host. Exit 0 means no cell failed (UNRUN providers stay
listed in the table), 1 a cell failed, 2 a harness/collect error.

## BouncyHsm / FreeHSM acquisition

- BouncyHsm: the v2.3.2 client library, published server and a .NET
  runtime, laid out as `$TASK_DIR/bouncyhsm/` (see `bouncyhsm.env`).
  Deliver the dir with `--extra-deliver /path/to/bouncyhsm`.
- FreeHSM: `libfreehsm.so` built from upstream main
  (`https://github.com/afchine1337/freehsm.git`):
  `make generate PROFILE=interop`, then
  `make OPENSSL_PREFIX=/usr PROFILE=interop libfreehsm.so`;
  deliver as `--extra-deliver /path/to/freehsm` holding
  `libfreehsm.so`. Record the built commit in the run report.

## Rows per cell

`<provider>-identical-results`, `<provider>-observer-clean`,
`<provider>-run-observed` (FAIL when the provider is not observed),
`<provider>-inventory-pid` (FAIL when the provider is not observed),
and the discover row (`<provider>-discover`, or `kryoptic-multi-table`
for kryoptic, which pins the exact 4-surface shape; an ambiguity
refusal there becomes an expected-failure pointing at the static-progs
I2 fix). Reader-less providers mark identical-results nonqualifying.
Run coverage (`call_recall` over the rv-trace oracle) is printed in
each cell's `summary.txt`.
