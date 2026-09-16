# Implement the RT_ADD deferral so the scan stops racing the loader

Repo: this worktree. Read `.superpowers/sdd/w7-continuation-2026-09-12/HOUSE-RULES.md`
first — it IS present here. Precedence: **CONTROLLER RULINGS > HOUSE-RULES > DESIGN.md.**
If an instruction is ambiguous or contradictory, do the safer thing and say so in REPORT.md
— do not stall.

## Why this is being built now

`DESIGN.md` §1 (the maps-A/maps-B bracket) is ALREADY IMPLEMENTED and committed as e1c2002.
Do not reimplement it. **Your task is §2 only: the RT_ADD / `r_state` deferral.**

It was deliberately deferred, and that decision has been reversed on measurement. With the
bracket in place and no deferral, the scan still races the loader, so the bracket refuses —
correctly — and the refusal lands in published evidence. Measured with the `skip-attribution`
build feature:

    [0] "discovery unavailable" <- src/discovery/engine.rs:3301, 6761, 6910
        subject = ".../matrix-provider.so"
        reason  = "memory scan refused: mapping changed during acquisition"

and it is INTERMITTENT — the same lane produced 0 skips standalone and 1 under the release
driver; the owned lane produced 2 where 1 is expected. So the published `skipped` array is
scheduling-dependent. That is the exact defect P-2 was built to remove; refusing
nondeterministically is honester than publishing garbage nondeterministically, but it is not
determinism.

## CONTROLLER RULINGS

**RULING 1 — implement DESIGN.md §2 as written**, including its table: `announced_count`
1 or 2 marks memory discovery pending for that exact view/context and defers the scan; zero
is a scheduling OPPORTUNITY, never proof of RT_CONSISTENT.

**RULING 2 — zero is ambiguous and must stay ambiguous.** Controller-verified at
`crates/ebpf/src/main.rs:1423`: `r_state` is initialised `0u32` and stays zero for absent
state, a failed address computation, AND a failed `bpf_probe_read_user` (the latter two bump
`DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES` and fall through). Do NOT add transport
validity metadata and do NOT change any BPF record layout — that is a larger change and is
out of scope here.

**RULING 3 — the spec amendment is authorised, and its intent must be preserved.**
`docs/superpowers/specs/2026-08-18-slice1b2-corrective-live-discovery-design.md:538-551` §7.1
requires every accepted hit to run the bounded memory scan. You are changing WHEN that scan
runs, nothing else. Every scoped hit must still be submitted, accounted, and have its export
hooks armed. **Do NOT put an early return around the loader handler** — those hooks may be
the only way to observe tables handed out later. Update the spec text in the same change to
say what is now true, and say in REPORT.md exactly what you changed there.

**RULING 4 — a deferred scan that never runs is a LOSS, and must be recorded as one.**
Settle pending work explicitly on exit, context retirement, cancellation, budget exhaustion
and shutdown. Never wait forever, never silently forget. Keep pending work bounded and keyed
by **view plus loader context, never pid alone**; coalesce duplicates; a fallback must not
replay the original record or spend producer-counter authority twice.

**RULING 5 — do not weaken the bracket.** e1c2002 stays exactly as it is. This change reduces
how often the bracket must refuse; it must not change what the bracket does when it does
refuse.

**RULING 6 — change no frozen constant.** `VERSION_SHAPE_SCANNED` stays 988/104/208. If a
frozen expectation fails, STOP and report it rather than adjusting it.

## Rules

- **Mutation-first proof is mandatory**: write the test, run it against UNFIXED code, capture
  the literal failure, fix, capture the literal pass. Paste both. A claimed RED you did not
  run is a failed task.
- Required RED lanes, from DESIGN.md §5: an authenticated ADD record defers the scan and
  leaves bounded pending work; an ADD with no completion gets one bounded fallback or an
  explicit unresolved loss; exit, retirement, budget exhaustion and duplicate ADDs each
  settle; and "zero is not proof" — absent state and read-failure zero must not yield any
  relocation-ready or completeness claim.
- **An absent thing is never a pass.** Every unresolved deferral is recorded.
- Do NOT commit.

## Verification — FOCUSED RUNS ONLY

HOUSE-RULES §2 forbids delegates running workspace-wide cargo; the controller owns that gate.
Use `mise exec -- ./scripts/cargo.sh +1.88 test --locked -p p11scope --lib -- <name>` and
ASSERT THE COUNT — a mistyped filter prints "0 passed" and looks like success. Report each
run's literal `test result:` line.

## Report

Append to REPORT.md as you go: what changed by file:line; every RED with its matching GREEN;
the exact spec text you amended; anything unproven stated plainly; and any ruling you believe
is wrong — state it, do not act on it.
