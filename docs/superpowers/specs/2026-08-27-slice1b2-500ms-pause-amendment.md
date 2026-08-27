# Slice 1b-2 fixed 500 ms owned-pause amendment

**Date:** 2026-08-27

**Status:** Proposed; no source or runtime authority until independent Sol,
Terra, and Luna review agrees and this amendment is committed.

**Exact base:** `17c538ff6a73bf2aecd3ee539bee54732a964229`

## Scope and authority

This document amends only the fixed causal-closure ceiling in:

- `2026-08-18-slice1b2-corrective-live-discovery-design.md` §6.2;
- `2026-08-19-slice1b2-no-busy-wait-pause-amendment.md`; and
- the corresponding Task 1/2/7/9 checks in
  `2026-08-19-slice1b2-production.md`.

For explicit owned-child `run --pause auto|always`, replace:

```text
cycle_deadline_ns = winner.hook_ts_ns + 100_000_000
```

with:

```text
cycle_deadline_ns = winner.hook_ts_ns + 500_000_000
```

The supersession map is exact:

| Authority | Active 100 ms sites replaced by 500 ms |
| --- | --- |
| corrective design | lines 327, 345, 480, 533, and 1183 |
| no-busy-wait amendment | lines 24, 187, 202, 219, 277, 294, 447, and 477 |
| production plan | lines 330, 1053, and 1060 |

Line numbers identify the exact base above. Historical evidence, including the
corrective design's retained 100 ms result near line 526, keeps its original
value and disposition.

No other pause, discovery, attachment, privacy, schema, or product rule changes.

## Product requirement

One accepted winner defines one checked absolute deadline at exactly 500 ms
after its hook timestamp. Userspace retains the earliest deadline through the
existing minimum/clamp rule; no stage resets, extends, adapts, configures, or
retries the epoch.

The following remain unchanged:

- one-millisecond stopped-set sampling cadence;
- exact generation and expected task-set checks;
- drain-to-empty and record timestamp/dequeue validation;
- required attachment and publication before resume;
- original-pidfd-only signalling and exactly-once resume authority;
- successor authorization and terminal cleanup rules;
- `auto` sticky partial plus rearming disablement after a safe miss;
- `always` safe cleanup and required refusal after a miss;
- pause counters, public evidence, CLI, BPF ABI/maps/programs, and privacy
  allowlist.

This is an explicit opt-in causal-work budget, not a real-time guarantee.
Scheduler starvation, observer SIGKILL, kernel stalls, or failed `SIGCONT` can
extend actual suspension beyond 500 ms. The product must not claim otherwise.

## Evidence and limitation

The completed one-line 100/500 diagnostic A/B selected this value for review:

- all four 500 ms roots passed all six Lane 02 rows (24/24 rows);
- 100 ms passed one root and failed rows in three matched roots;
- a later unchanged-100 ms target was `PASS/PASS/FAIL/PASS`;
- cleanup, exact-process absence, and normalized configuration contradicted
  residue or input drift as causes.

That evidence is Linux-7.0 host-qualified and promotion-insufficient. It did
not isolate a latency source; its roots were owner-mutable and did not retain
an exact diagnostic-diff hash. It authorizes candidate selection only.

Root-cause isolation is required before a performance optimization. It is not
required to review a conscious fixed availability trade when every miss remains
safe, explicit, bounded by the same causal state machine, and conservatively
reported.

## Availability trade

The maximum causal epoch is five times the previous value. This may pause the
owned child longer during dynamic discovery. Only the operator-selected
`auto|always` policies enable it; `never`, external PID, and cgroup capture do
not gain pause authority.

If 500 ms fails the fresh supported-kernel campaign, do not increase it again,
make it adaptive, add retries, move the anchor, or weaken `always`. The
candidate is non-pass and needs a new reviewed product decision.

## Promotion gates

The implementation is promotable only when all of the following are fresh and
source-bound:

1. The implementation diff changes only the fixed constants, constant-relative
   tests/comments/mutations, the sample cap derived from the fixed bound and
   unchanged 1 ms cadence, and isolated Gate A/B validator values.
2. Exact-bound acceptance, one-nanosecond-late rejection, overflow, earliest-
   deadline/no-reset, failure cleanup, and `always` refusal tests pass.
3. The four canonical Rust checks, Lane 02 self-test, evidence-checker
   self-test, privacy canary self-test, and diff checks pass.
4. Gate A passes once on Jammy 5.15 and once on Noble 6.8.
5. Gate B passes three cold boots × 20 children on each kernel: 120/120 exact
   semantic passes, with every child classified by the unchanged A/B oracle.
6. One fresh host Lane 02 root passes 6/6 with exact counts, confirmed
   pause-enabled rows, complete cleanup, and zero residue. This selects the
   candidate for the remaining Task 4 round; it does not discharge that round
   or unlock r3/9.2d.
7. The existing 9.3 production campaign later proves the complete product on
   Jammy 5.15 and Noble 6.8 before release; isolated Gate A/B evidence is not a
   substitute for those 480 primary plus 40 fallback attempts.
8. Independent review recomputes every identity, deadline, row, counter,
   privacy result, cleanup receipt, and retained tail from raw evidence.

No historical root substitutes for these gates. No failure is replaced or
rerun. Any timeout, partial/refusal, identity drift, missing receipt, privacy
failure, unsafe cleanup, or residue makes the candidate non-pass.

The `spike/slice1b2-loader-host` binary and campaign remain frozen historical
research artifacts. They are not built, run, or cited as authority by this
amendment; their separate 100 ms constants and retained evidence are not
changed. Kernel unit tests may continue to read that artifact's lifecycle shell
as an unchanged contract fixture. Current product two-kernel authority comes
only from the later 9.3 candidate campaign.

## Rejected alternatives

- the rejected cross-layer phase/affinity diagnostic, whose receipt ownership,
  privacy boundary, causal reducer, and size exceeded this candidate;
- adaptive or configurable deadlines;
- product affinity or real-time scheduling;
- anchor movement, per-stage reset, checkpointing, or retry-until-green;
- `uprobe_multi` as a Linux-5.15 solution;
- weakening exact identity, attachment order, bootstrap count, pause oracle,
  or `always` refusal;
- narrowing Slice 1b-2 to `never` only.
