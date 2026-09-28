<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Unavailable maps snapshots

Initial candidate selection and periodic reconciliation read process maps
before choosing a deep scan. These reads provide prioritization hints;
they do not establish a retained process generation, provider absence or
complete discovery.

Previously, both paths replaced read errors with an empty list. A later
deep scan could disclose the failure only if that process was selected.
Reconciliation also counted failed reads as covered processes, including
when no deep-scan slot was available.

## Required behavior

- Preserve successful reads, including successful EOF, separately from
  unavailable snapshots. Open failures, I/O failures and budget refusals
  remain unavailable.
- Publish unavailable evidence independently of deep-scan selection.
  Internal diagnostics count unavailable snapshots and attempted reads;
  the public report uses its existing finite `discovery unavailable` reason.
- Keep unknown processes eligible for later deep scans. The advisory
  rarity ordering may group them with candidates having no provider hint;
  that grouping is never evidence of absent mappings or providers.
- Count only successful reads as covered. Deferred processes are those
  not attempted in this slice; failed attempts are accounted separately.
- Advance the cursor after failed attempts so other processes can progress.
  A failed maps read cannot retire an already retained generation.

## Regression checks

The `discovery::engine::tests::maps_sweep_` tests exercise the actual initial
and reconciliation paths, with a real failed `/proc` open, an expired read
deadline, a successful self snapshot, a failing reader and successful EOF.
They also check zero deep-scan capacity, the public reason, next-slice
progress and retained-generation protection.

Two behavioral regressions failed on the previous implementation: failed
open and expired-budget reconciliation emitted no unavailable evidence.
The successful-read control passed on that same implementation.

This behavior does not establish resumable scanning, fair progress across
all discovery owners, bounded service latency, first-use coverage or live
system-scale qualification. See the [first-use contract](first-use-contract.md)
and the [release qualification record](../../CHANGELOG.md#qualification-of-this-release)
for those distinct evidence requirements.
