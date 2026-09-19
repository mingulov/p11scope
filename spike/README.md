<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# spike/

Throwaway-feasibility experiments live here — but two files graduated to
load-bearing e2e fixtures, so this directory cannot simply be deleted.

## Live (do not move)

- `harness.c` + `expected.txt` — deterministic SoftHSM workload and its
  ground-truth oracle, compiled and asserted by
  `scripts/verify-attach-e2e.sh` (Gate G1).
- `discover.c` — v2.40 `CK_FUNCTION_LIST` index reference cited by
  `scripts/fixtures/*` and `scripts/matrix/fork-harness.c` comments.
- `Dockerfile` — original SoftHSM holder shape; the committed K8s holder
  (`deploy/Dockerfile.holder`) is modeled on it.

## Historical (kept for provenance, executed by nothing)

- `aya-offset-pin/` — evidence for `docs/notes/aya-offset-semantics.md`.
- `check.sh`, `gen-bt.sh` — phase-0 feasibility helpers (Aug 2026).
- `work/` — gitignored scratch (binaries, tokens, manifests, outputs).

## Relocated 2026-09-15

The Slice 1b-2 experiment bundle (`slice1b2-kernel`, `slice1b2-loader`,
`slice1b2-loader-bpf`, `slice1b2-loader-host`: TCG verifier-gate runner,
loader witness harnesses, BPF/host fixtures) moved to
`preserved/2026-09-15-spike-slice1b2/`. Nothing executes these — no
script, test, or workspace member references them; the productized
discovery engine (`src/discovery/`) superseded them. They are kept
because the slice-1b-2 plans and `docs/notes/slice1b2*` pin analyses by
SHA-256 against these sources. Historical plan prose still says
`spike/slice1b2-…`; read it as the preserved path above.
