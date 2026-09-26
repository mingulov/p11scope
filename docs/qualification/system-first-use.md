<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System first use: evidence and open feasibility work (T2)

The active requirements are the [six original T2 boxes](t2-first-use-requirements.md).
The [resource and latency pilot](system-resource-pilot.md) defines the
preliminary measurement protocol for T7/T12; its axes are not executed results.
Cold CLI startup is supporting evidence; it does not complete the gated /
ungated provider-first-use matrix. The earlier ordinary evidence below
was produced unprivileged on the dev host (`7.0.0-31-generic`) at T2 BASE
plus the T2 stack. Earlier live procedures are retained below; the full
required first-use inventory remains open.

## Demonstrated cold-start behavior (2026-09-26)

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
`--extra-strict` diagnostic gate (`src/doctor.rs`) is the
machine-readable form of this boundary: exit 1 plus an
`extra-strict refusal:` line naming every violating row.

## Gap enumeration (dated findings)

| ID | Date | Gap | Disposition / owner |
|---|---|---|---|
| T2-C1 | 2026-09-26 | Cold start with zero ambient state | FEASIBLE, proven by `t2_cold_start` 6/6. Owner: T2 (done). |
| T2-C2 | 2026-09-26 | First-failing BPF map name varies run to run (`COUNTERS` / `TASK_COOKIE` / `MECH_SHAPE` / `PAUSE_PIDS` / … across identical cold runs); verdict/tier lines are stable. Diagnostics-only nondeterminism inside the loader error path (`attach.rs` load site). | Routed: T13 diagnostics polish (T5 alternate). Not fixed in T2: verdicts unaffected. |
| T2-C3 | 2026-09-26 | Same-uid non-descendant `doctor --pid`: `/proc/<pid>/mem` is `EACCES` (yama scope 1); doctor reports honest `FAIL mem unavailable`. | Accepted boundary, already surfaced (yama row + FAIL). No owner needed. |
| T2-C4 | 2026-09-26 | First-use end-to-end (simplest PID SoftHSM profile) needs a provider fixture plus privilege; fixture present on the dev host (`libsofthsm2.so`), live run not attempted by T2. | Controller-owned live cell L-T2-1 below. |
| T2-C5 | 2026-09-26 | E13 never-seen transient: an ungated `load -> one call -> unload` that finishes before observer attachment is missed by construction. Ordinary boundary characterized (`f_e13_first_call_gap_and_precapture_boundary`: pre-ready calls uncovered, post-ready covered, trigger-to-ready latency reported, never zero-promised). No safe generic pre-execution hook is proven; ptrace stops / provider interposition / active provider calls are explicitly NOT added silently. | Live counterexample + scope/architecture decision owed. Proposed: `accepted-boundary` for the ungated transient miss once L-T2-2 confirms the ordinary boundary live. Decision owner: product owner; a confirmed miss does not approve the scope change. |
| T2-C6 | 2026-09-26 | No ambient file or network dependency in the cold path (strace audits above). | FEASIBLE. Owner: T2 (done). |

## Earlier controller-owned live procedures (incomplete T2 inventory)

These remain useful procedures. The original requirements additionally
need five physical/lifetime classes in both gated and ungated forms, seven
independent transition facts, a retained-probe/pre-execution comparison,
resource/latency protocol and completed G-14 diagnosis. A missing first
call requires a demonstrated counterexample and the product owner's scope
decision; confirming a miss does not itself approve a new boundary.

| Cell | Procedure | Expected verdict |
|---|---|---|
| L-T2-1 | Privileged: simplest PID SoftHSM profile per G-14 (owned supervisor, default ring). | Preserve the initial `PARTIAL`/`concrete_gap` reproduction, diagnose its cause, fix it in the owning task, then obtain the required supported-boundary green result. Do not force a COMPLETE label without its evidence. |
| L-T2-2 | Privileged: ungated never-seen transient (`load -> verify table -> one ordinary API call -> unload/exit`, no GO gate; new inode with equal bytes + short-lived namespace variants). | Miss confirmed as an explicit coverage boundary with a minimal repeatable counterexample; post-ready calls covered. Confirms or refutes the T2-C5 proposed disposition. |
| L-T2-3 | Privileged: `doctor --extra-strict` on a fully capable host. | Exit 0 with `extra-strict: no qualification violations`. Any refusal names a real lane to fix or a boundary to accept. |

## Open uncertainties

1. Whether any safe pre-attachment discovery covers the new-object case at
   acceptable target-interference cost is unmeasured (plan Task 2 box 3);
   T2 proves the boundary, not the mechanism.
2. T2-C2's loader-error ordering is unrooted (inside Aya's load path);
   whoever polishes it should pin the first-failure order with a test.

## Measurement-window acceptance repair (ordinary, 2026-09-26)

The real measurement entry point could previously mark a weak-gated
window valid from FD estimates and matching counts without observer-owned
timestamps. It also used attach time where actual loop-start time was
required. The regression tests reproduce those failures through `main()`.

Window acceptance now requires complete, ordered observer attach/start/end
stamps within the observer process lifetime, a recognized successful end
reason, and containment of the independent workload burst within the actual
loop interval. Frame-gated runs also validate the frame release timestamp.
The record retains diagnostic estimates; accepted capture duration is
`loop_end - loop_start`, not a reconstructed interval. The observer's
completeness verdict, loss counters and physical matching are preserved as
separate facts. Valid timing alone never establishes complete capture.

`window.observer_phase_authority` records this check. Missing, partial,
malformed, contradictory, pre-loop and post-loop cases fail window validity;
complete frame and marker controls pass. `tests/python/test_measure_e03.py`
is now invoked by hosted CI and the local gate entry point. This ordinary
repair supplies no new live first-use, performance or caller-identity result.

### Owned-workload authority

`window.owned_workload_authority` separately requires positive workload
truth and receipt-attributed activity. PID windows must bind the selected
PID to the complete mapping receipt and the workload's recorded generation;
their physical module rows must exactly match the workload counts. This
uses existing fixture custody receipts and does not add a runtime image
identity key. Matching aggregate `counts_match` remains a diagnostic fact.

Valid-clock controls reproduced 19 false-positive subcases: wrong selected
PID/generation/endpoint, changed mapping receipts, foreign or missing module
identity, admission without owned calls, empty workload truth, and an
unattributed PID trace total. All now reject window qualification. Positive
PID and system profile controls still pass. Trace currently has no physical
module rows, so its aggregate equality cannot qualify an owned window;
adding attributable trace evidence remains open. These acceptance changes
do not modify the captured data or promote an old run to live qualification.
