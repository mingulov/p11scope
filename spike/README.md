<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Experimental sources and retained fixtures

This directory contains early feasibility experiments and source inputs
that remain part of reproducible product checks.

## Live fixtures

- `harness.c` and `expected.txt` supply the deterministic SoftHSM workload
  and its ground-truth oracle for `scripts/verify-attach-e2e.sh`.
- `discover.c` supplies the v2.40 `CK_FUNCTION_LIST` index reference cited
  by fixture source comments under `scripts/fixtures/` and `scripts/matrix/`.
- `Dockerfile` records the SoftHSM holder shape used by
  `deploy/Dockerfile.holder`.

## Historical experiments

- `aya-offset-pin/` records the distinction between an ELF virtual address
  and the object-file byte offset used for uprobes; see
  [the offset contract](../docs/notes/aya-offset-semantics.md).
- `check.sh` and `gen-bt.sh` are the original feasibility helpers.
- `slice1b2-kernel/` and `slice1b2-loader-host/` retain the kernel and
  loader experiment sources and their runners.
- `work/` is ignored scratch output, not a source or qualification input.

The production discovery engine lives under `src/discovery/`. Historical
campaign reports live in the development workspace; retained experiment
sources remain here alongside the fixtures.
