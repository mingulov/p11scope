<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# G32 runbook — policy, safety, privileges, live stop/sink boundaries

No new capture policy, no universal hard deadline. Base `fabbb0a4`;
enumerate exact cells on the converged candidate.

## Policy matrix (enumerate, then run exact selectors)

Safe default; feature-enabled unsafe without opt-in; unsafe with explicit
opt-in; default-build unsafe refusal; metrics+unsafe refusal. Seams:
`src/attach.rs` policy/map freeze, `src/cli.rs`, semantics policy tests,
`scripts/check-bpf-noninterference.py` for intentional deltas.

- Aggregate metrics makes zero semantic reads/events; release artifacts
  omit unsafe decoders.
- Shared ABI builds for default/unsafe/small-ring/unsafe+small-ring.
- Unsafe fixed-offset-overflow zero-derived-read / final-entry-PARTIAL
  controls; safe approved success/PENDING; refused Init / unregistered /
  null mechanisms; policy-disabled vs decode-failed fields; permitted
  unsafe vendor u64::MAX; exact byte-name async matching.
- Failure twin: invalid FD as fake freeze proof; unattached-only seccomp;
  semantic reads smuggled into metrics; suppressed sink failure; canceled
  display mistaken for lost primary data.

## Frozen maps, seccomp, privileges

- Valid mutation of every applicable frozen policy map returns EPERM while
  a matching unfrozen map permits it (document fd-array exceptions).
  Enumerate the valid freeze pairs; do not relabel old pairs without
  re-running them.
- `scripts/matrix/verify-uretprobe-seccomp.sh`: affected set is NOT a
  version range (measured: Ubuntu 6.11.0-17 affected, 6.11.0-29 clean).
  Only probing answers; never `uname`. Exit 0 = trustworthy verdict
  (`RESULT:`), exit 1 = unknown.
- Preserve affected-kernel uretprobe/seccomp, child post-attach
  confinement, hidepid/PID-namespace/device-group/credential changes,
  helper isolation, two concurrent observers. Related harnesses:
  `scripts/matrix/verify-pidns.sh`, `verify-proxy-stack.sh`,
  `verify-fork-scope.sh`, `verify-oracle.sh` (confirm each CLI first).

## E17 stop/sink matrix (live, authorized lane)

Real 4KiB/4MiB/16MiB rings x file/discard/slow-pipe sinks x cancellation
stages, exact loss/drop units, repeated signals. Existing journey/sink
coverage lives in `tests/cross_command_journeys.rs`,
`tests/inventory_command.rs`, `tests/output_preflight.rs` and neighbors —
enumerate the exact E17-named selectors on the candidate; the catalogue's
full ring x sink x stage matrix must be shown cell by cell, not assumed
from neighboring sink tests.

- Inherited <100ms cancellation-response target: measure with a stated
  scope/ruling; it is distinct from normal-stop 30s/60s and is NOT a hard
  guarantee for uninterruptible file I/O.
- Blocked stderr, child-held stdout, regular-file limits and allocation /
  write / rename / fsync failure + cancellation controls preserve the
  existing destination and primary report.

## Reconciliation items (explicit, live)

- Reconcile the existing privmin decision and support claims without
  automatically changing grants or sandbox architecture.
- Reconcile privmin/helper-sandbox/license and parked-platform owner
  decisions explicitly; infer no new mandate.
- Known adjacent failure: G21 root-owned FAIL persists on the operator
  lane (separate lane; do not conflate with G32 verdicts).
