<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System first use: cold-start boundary and gap enumeration (T2)

Finish-plan Task 2 box 1. Scope: ordinary evidence only — everything here
was produced unprivileged on the dev host (`7.0.0-31-generic`) at T2 BASE
plus the T2 stack. Live first-use proofs are controller-owned; the exact
cells sit at the end.

## Supported first-use boundary (2026-09-26)

A first boot with **no ambient credentials** is supported for
qualification and honest refusal:

- `env -i p11scope doctor` completes and prints an honest tier + verdict
  (T0 offline, exit 1 unprivileged) — no `PATH`, `HOME`, `TMPDIR`,
  `SUDO_*`, or `P11SCOPE_*` required.
- `env -i p11scope doctor --help`, `--version`, `profile --help`,
  `run --help` all exit 0. Bogus `TMPDIR` and `cwd=/` change nothing.
- `env -i p11scope profile --pid 1` and `run -- /bin/true` refuse with a
  named cause (exit 1), never a panic or traceback.
- File audit (`strace -f -e trace=%file`): the cold doctor touches only
  loader paths, `/proc/self/*`, `/proc/sys/kernel/*`, and
  `/sys/kernel/{btf/vmlinux,security/lockdown}`. No HOME, no credentials,
  no state directories. Sole `ENOENT`: `/etc/ld.so.preload`.
- Network audit (`strace -f -e trace=%network`): zero
  `connect`/`bind`/`sendto`/`recvfrom`.

Committed proof: `tests/t2_cold_start.rs` (6 tests, both profiles). The
`--extra-strict` qualification gate (`src/doctor.rs`, T2 box 2) is the
machine-readable form of this boundary: exit 1 plus an
`extra-strict refusal:` line naming every violating row.

## Gap enumeration (dated findings)

| ID | Date | Gap | Disposition / owner |
|---|---|---|---|
| T2-C1 | 2026-09-26 | Cold start with zero ambient state | FEASIBLE, proven by `t2_cold_start` 6/6. Owner: T2 (done). |
| T2-C2 | 2026-09-26 | First-failing BPF map name varies run to run (`COUNTERS` / `TASK_COOKIE` / `MECH_SHAPE` / `PAUSE_PIDS` / … across identical cold runs); verdict/tier lines are stable. Diagnostics-only nondeterminism inside the loader error path (`attach.rs` load site). | Routed: T13 diagnostics polish (T5 alternate). Not fixed in T2: verdicts unaffected. |
| T2-C3 | 2026-09-26 | Same-uid non-descendant `doctor --pid`: `/proc/<pid>/mem` is `EACCES` (yama scope 1); doctor reports honest `FAIL mem unavailable`. | Accepted boundary, already surfaced (yama row + FAIL). No owner needed. |
| T2-C4 | 2026-09-26 | First-use end-to-end (simplest PID SoftHSM profile) needs a provider fixture plus privilege; fixture present on the dev host (`libsofthsm2.so`), live run not attempted by T2. | Controller-owned live cell L-T2-1 below. |
| T2-C5 | 2026-09-26 | E13 never-seen transient: an ungated `load -> one call -> unload` that finishes before observer attachment is missed by construction. Ordinary boundary characterized (`f_e13_first_call_gap_and_precapture_boundary`: pre-ready calls uncovered, post-ready covered, trigger-to-ready latency reported, never zero-promised). No safe generic pre-execution hook is proven; ptrace stops / provider interposition / active provider calls are explicitly NOT added silently. | Live counterexample + scope/architecture decision owed. Proposed: `accepted-boundary` for the ungated transient miss once L-T2-2 confirms the ordinary boundary live. Decision owner: controller (finish review). |
| T2-C6 | 2026-09-26 | No ambient file or network dependency in the cold path (strace audits above). | FEASIBLE. Owner: T2 (done). |

## Controller-owned live cells (T2 handoff)

| Cell | Procedure | Expected verdict |
|---|---|---|
| L-T2-1 | Privileged: simplest PID SoftHSM profile per G-14 (owned supervisor, default ring). | Ends `PARTIAL`/`concrete_gap` until T5/T6 close the underlying gaps — the verdict must name the gap, never pass silently. |
| L-T2-2 | Privileged: ungated never-seen transient (`load -> verify table -> one ordinary API call -> unload/exit`, no GO gate; new inode with equal bytes + short-lived namespace variants). | Miss confirmed as an explicit coverage boundary with a minimal repeatable counterexample; post-ready calls covered. Confirms or refutes the T2-C5 proposed disposition. |
| L-T2-3 | Privileged: `doctor --extra-strict` on a fully capable host. | Exit 0 with `extra-strict: no qualification violations`. Any refusal names a real lane to fix or a boundary to accept. |

## Open uncertainties

1. Whether any safe pre-attachment discovery covers the new-object case at
   acceptable target-interference cost is unmeasured (plan Task 2 box 3);
   T2 proves the boundary, not the mechanism.
2. T2-C2's loader-error ordering is unrooted (inside Aya's load path);
   whoever polishes it should pin the first-failure order with a test.
