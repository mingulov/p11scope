<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T7-r2f static campaign: complete at f265b9e

The seven owned host cells pass at source
`f265b9e938e64bda5c58368fe56b6e45a8109de9`, tree
`fb1100db9a32462bbe2530bd64fabbb9cddd4bcb`, kernel `7.0.0-31-generic`.
The private static entry-only path observed all 6530 physical endpoints,
retained the repeated-call and terminal evidence, and released its owned
kernel objects. This closes Gate 2 of the 2026-09-26 product finish plan.

## Results

| Profile / cell | Result | Test command wall time |
| --- | --- | ---: |
| Default Inventory, 576 endpoints | PASS: complete capture and cleanup | 47.04s |
| Default Inventory, 1024 endpoints | PASS: complete capture and cleanup | 83.46s |
| Default Inventory, 4097 endpoints | PASS: complete capture and cleanup | 335.53s |
| Default Inventory, 6530 endpoints | PASS: complete capture and cleanup | 539.15s |
| Default Inventory, 8192 boundary | PASS: expected preflight FD refusal | 0.17s |
| Default Detailed, hot slot / third return value | PASS | 3.28s |
| Wide Detailed, hot slot / third return value | PASS | 3.58s |

The large raw files contain exactly 20490 and 32655 rows (`5N + 5`).
All four snapshots and the unique terminal record are present. The 6530
raw file is 2143581 bytes; its link evidence is 3622428 bytes. Both remain
within the unchanged 16 MiB file limit. The 8192 case proves the specified
refusal under soft FD limit 8192; it supplies no 8192-endpoint capture result.

The run uses single-probe links and the private owned fixture. Much of its
wall time is retirement of those links. These totals are not throughput,
application overhead or public stop-latency measurements. Those require
the [resource pilot](system-resource-pilot.md) and final support matrix.

## Changes and failure history

- `30c3549` derives bounded evidence rows from endpoint count and retains
  the byte guard. The three large writer regressions failed on the old
  20000-row cap; all five writer/guard controls then passed. Retirement
  allowance now reflects measured per-link time, with an outer deadline.
- `6e4e268` adds the acceptance register and pinned seven-cell driver.
  The first live attempt passed its 576 body, then stopped as INVALID
  because two ambient cgroup-device programs changed the host census.
  The remaining six cells were not run in that attempt.
- `f265b9e` checks exact owned IDs independently and records only
  kernel-typed cgroup-device changes separately. Names cannot authorize
  that exception. Every map/link change, other unexplained program
  change, missing census or retained owned ID still stops the campaign.
  All 12 runner controls pass. The successful 4097 cell retained four
  ambient device-policy changes; no owned ID remained after any cell.

The original r2 exit-101 results, the invalid first r2f attempt and all raw
outputs are preserved. No workload was reduced, failed attempt overwritten,
host BPF object removed or unrelated VM stopped.

## Verification and custody

Ordinary default workspace tests passed, including 1608 library tests
(45 privileged ignored), 139 artifact tests and 29 T7 capacity tests. Wide
affected suites passed: 1609 library tests (41 privileged ignored), 139
artifact tests and 29 T7 tests. Formatting and strict Clippy passed for both
profiles. The later census repair changed Python and documentation only;
both binaries and all six embedded BPF objects remained byte-identical.

Test binary SHA256:

- Default: `0b4bd31e1166983d7995838e28c4cb48026be04d667079ffb6ebcfd61a29fee6`
- Wide: `05e13b30a8137ca96f83ce7bb3d33426c7d0036db7f6654c13f1a796545fbad5`

Workspace evidence root:
`/home/user/src/m/p11scope-ws/preserved/evidence-roots/product-finish-20260926/`.
`t7-r2f-census2/` contains pins, tracked-source archive, all fixtures,
physical offsets, raw evidence, censuses, commands and execution receipts.
`bundle-files.json` seals its files. `t7-r2f/` preserves the failed attempt,
ordinary gates and the original r2 campaign/binaries.

The acceptance verifier passed all seven required `t7-static` rows. Its
`system-product` check correctly failed on an unrun required product row.
The checked-in register remains a template; the execution copy is
`t7-r2f-census2/acceptance/system-test-manifest.json` under that evidence root.

## Product boundary

Public `--mode metrics` already avoids event-stream decoding, but retains
the existing planner's finite physical-target slots: 512 by default or
2112 in the explicit wide build. The compact Inventory path tested here
still needs public command/coordinator integration. Its evidence means an
entry was observed; it does not establish exact call counts or returns.

Continuous discovery, first-use guarantees, caller/lifetime attribution,
runtime growth, output pressure and the final installed/performance matrix
remain open. Detailed reporting is only one part of that work. This report
does not promote private static capture into broad system-wide qualification.
