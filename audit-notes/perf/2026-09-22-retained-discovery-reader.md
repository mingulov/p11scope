<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Retained DISCOVERY reader: functional and syscall check

Source baseline: 7dee8b32ff811b3ab30ee46ac4719b73ca7e4e49.
Baseline observer SHA256: 66d1818e687feac609004febab1bc39611b29aff76ebd49a30e8d2d829957c8f.
Candidate observer SHA256: 36619886c863834a5cd7ba1b0e70610efc79d0d435ac459b774841a834fdda2b.
The candidate differs in Session ownership and the DISCOVERY reader only.
Its binary/source-patch receipt is `retained-reader-manifest.json` under
`/var/tmp/p11scope-ws-tmp/full-system-20260922.FbcpaT`.

One Session now retains its DISCOVERY map domain and lazily constructs one
owned reader. This replaces construction and destruction at every dequeue,
including empty polls. It retains two additional descriptors and two mappings
until Session destruction; decoding and capture/admission behavior are unchanged.

The privileged real-map ownership test passed: one test, zero ignored. It
checks exact-map rejection and retained descriptor ownership. The unprivileged
events slice separately passed 23 tests, with three privileged tests ignored
in that command. Independent source review found no blocking defect, conditional
on the actual Session checks below. Workspace gates are recorded separately.

The owned workload maps one provider before attachment, issues 64 publication
calls and 100 table endpoint calls, leaves an idle interval, loads a second
physical copy, waits for its attachment, then repeats the burst. The copies
have equal bytes and distinct inodes. The target remains alive until capture
finishes. Reports and the target's maps distinguish both physical objects.

| Observed fact | Baseline normal | Candidate normal | Candidate SIGINT |
|---|---:|---:|---:|
| Controlled table endpoint entries, first / late object | 100 / 100 | 100 / 100 | 100 / 100 |
| Successful returns for those entries | 100 / 100 | 100 / 100 | 100 / 100 |
| DISCOVERY reader constructions | 135 | 1 | 1 |
| DISCOVERY mmap / munmap calls | 270 / 270 | 2 / 2 | 2 / 2 |
| Remaining reader descriptors / mappings after destruction | 0 / 0 | 0 / 0 | 0 / 0 |
| CALL-ring / DISCOVERY-ring loss | 0 / 0 | 0 / 0 | 0 / 0 |
| Observer / workload exit status | 0 / 0 | 0 / 0 | 0 / 0 |

The syscall analysis follows the descriptor returned by the named DISCOVERY
map creation through each duplication and close. It pairs mappings with their
successful unmaps. The candidate's two maps are 4096 and 135168 bytes, reflecting
the ring's consumer and double-mapped producer areas. Metrics does not map EVENTS
in these cells. Cancellation targets the birth-checked observer through a pidfd.

Raw source, fixture identities, commands, phase markers, maps, reports and
syscalls are under `discovery-retention-experiment/`; `comparison.json` records
the assertions. The first harness attempt used an overly exact probe-count
gate; the next completed capture required a privileged read of its root-owned
0600 report during postprocessing. Both artifacts remain preserved. The final
candidate runs completed the corrected harness normally.

This is a small functional and syscall-count experiment, not a timing benchmark.
The baseline ran during compilation; neither wall time nor measured latency is
used to claim a speedup. The 200 table calls do not cover every publication call,
prove broad system coverage, or establish terminal producer quiescence. The
512-endpoint admission failure and discovery scheduling barriers remain separate.

## Final source and gate status

Implementation commit: `6bd4d3b` (`perf: retain the discovery reader for each
session`). The final independent review verified that the reader's three-file
patch is identical to the recorded live candidate patch. Additional test
synchronization changes preserve assertions and introduce a production no-op
hook; the settlement implementation otherwise remains identical to baseline.

The first full gate exposed two lifecycle test synchronization failures. After
their repair, the library gate passed 1306 tests with zero failures and five
ignored. The following artifact gate passed 128 tests and failed one obsolete
source declaration matcher. Updating that matcher and rerunning its exact test
passed one test with zero failures. Final formatting, workspace all-target
checking, clippy with warnings denied, and diff checks passed.

The final source review approved the patch with one nonblocking test-coverage
nit: a source marker alone does not prove the exact-map comparison. The real
map-mismatch test remains the behavioral evidence for that property. The
remaining workspace targets and the full integrated feature gate are still
required; the interrupted full-suite command is not represented as green.
