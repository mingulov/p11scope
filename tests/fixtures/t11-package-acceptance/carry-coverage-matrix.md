<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T11 carry-coverage matrix

Each row: one carry family the live campaign must disposition. Status
words: DONE (evidence at base), OPEN (live cell still to run), GAP
(harness/selector/decision missing), DECISION (owner ruling required).
Base `fabbb0a4`.

| # | Carry family | Gate | Producer / artifact | Status | Live need |
| --- | --- | --- | --- | --- | --- |
| C1 | Canary hostile-alias matrix completion | G23 | `verify-canaries.sh`, canary suites | OPEN | Affected live canary paths on final objects |
| C2 | 5.15 identity denial/fallback proof | G23 | MISSING `privileged_identity_515_denial_is_disclosed` | GAP | New native selector + guest cell |
| C3 | Nonempty ia32 ops/attrs + refusals | G23 | `verify-ia32-compat.sh`, ia32 suites | OPEN | Live ia32 workload cells |
| C4 | Seccomp/namespace/overlay live checks | G23 | `verify-uretprobe-seccomp.sh`, matrix scripts | OPEN | Re-select after T2/T5/T6 |
| C5 | Exact-SHA green CI + BPF baseline | G25 | `ci.yml`, `check-bpf-noninterference.py` | OPEN | Candidate CI run; e2961e08 vs ca3a181 review |
| C6 | Official build + package + notices | G25 | `build-release.sh`, `package-release.py`, `release-notices.py`, `release-artifacts.py` | OPEN | Receipt + 3 tarballs + RELEASE.json + SHA256SUMS |
| C7 | Source export + offline recipient | G25 | `export-source.py`, `build-offline.py`, `docs/build-offline.md` | OPEN | Recipient builds per checklist |
| C8 | Recipient uses selected binary | G25 | MISSING `test_release_recipient_uses_selected_binary` | GAP | New journey-harness control |
| C9 | Doc/version freshness | G25 | RELEASING.md, CHANGELOG.md, usage/limits/schema docs | GAP | v0.4 version pass (RELEASING still v0.2.0; no Unreleased section) |
| C10 | H0/H1/H2 regression preservation | G26 | lib suites (`engine_tests`, `instances_tests`, `s1_tests`, diff tests) | OPEN | Enumerate + rerun at boundaries (`scheduler.rs` path stale) |
| C11 | Safe/unsafe/aggregate policy matrix | G32 | policy tests, `attach.rs` freeze | OPEN | Exact matrix cells + freeze EPERM pairs |
| C12 | E17 ring x sink x stage stop matrix | G32 | journey/sink suites | OPEN | Cell-by-cell live enumeration |
| C13 | Privmin/sandbox/license/parked-platform | G32 | prior decisions + G21 operator lane | DECISION | Explicit reconciliation, no inferred mandate |
| C14 | Real providers + p11-kit/namespaces | G33 | provider/matrix scripts, SoftHSM fixtures | OPEN | Installed scoped cells on final bytes |
| C15 | Firefox/NSS + Chrome application checks | G33 | MISSING (no harness in checkout) | GAP | New D-lane harness or scope decision |
| C16 | Docker/kind/Knative deployment cells | G33 | `deploy/k8s`, matrix `verify-*.sh`, `kind-e2e.sh` | OPEN | Scoped acceptance; Knative boundary stays negative |
| C17 | Packaged 7.0 guest 12-cell gate | G33 | MT12 host-side coverage only | OPEN | Packaged-guest cell separate from H7 T1 |
| C18 | Kernel/backport/SELinux claim matrix | G33 | release-matrix lanes | DECISION | Claim membership + scope ruling |
| C19 | 147-row closure ledger disposition | G34 | `closure-ledger.json` + manifest | OPEN | Per-row source-fixed/dup/boundary/repair close |
| C20 | 43-group deferred-gate routing | G34 | `system-deferred-gates.json` | OPEN | Qualify each required gate at final pin |
| C21 | Bounded-release claim membership | G34 | `system-bounded-scope.json` (proposed) | DECISION | Owner approval; IN/OUT with move-IN conditions |
| C22 | Skipped-selector rejection proof | G34 | MISSING `required_positive_rejects_skipped_selector` | GAP | New oracle control (D lane) |
| C23 | M2/A:DR-T3A-9/10/13/14 validity spine | G34 | `test_bench_count_overhead.py`, bench analyzer | DONE at base for oracle legs | Re-run; T10 needs G34-green first |
| C24 | Ignored bodies + Lane13 BPF assertions | G34 | lib `--list --ignored`, lane13 inputs | OPEN | Full inventory on the candidate |

Rules: no generic "later" closure; duplicates close by source key;
accepted boundaries close by actual owner ruling; repairs close in their
owning task; a skipped/UNRUN/unsupported cell never passes a
positive-required row.
