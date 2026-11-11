<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Scan-seal seating on short runs and non-pid scopes (design, 2026-11-11)

Status: diagnosis proven live; message-only fix shipped (see below).
Update (round 2, v0.7.1): `--cgroup` now attempts the seal post-commit
(`ClassicDriver::finish_pass`) over the run's cgroup scope, with the
commit stashing the mint's sources — option 3 below, shipped; the
cgroup "did not run" message is retired. Seating the seal earlier
(options 1–2) and arming it under `--dashboard` (option 4) remain
design changes — this note records the options and risks.

## Diagnosis (proven)

`inventory --system --key-operations` without `--manifest` on a busy
desktop reported `key operations: requested, but per-key tracking needs
--manifest` with zero per-key endpoints, while `--pid` on the same host
showed rows. Root cause is the no-manifest scan-seal settle gate
(`src/inventory/mod.rs`: `attempt_deferred_scan_seal`), not a scope
rule and not a start failure:

- The seal seats only after `SCAN_SEAL_STABLE_PEEKS` (8) consecutive
  identical complete-provider peeks, or the `SCAN_SEAL_MAX_SETTLE_PASSES`
  (40) horizon. `--system` passes on a busy desktop run ~3 s, so a 20 s
  capture completes ~5-7 passes: the seal is never even attempted, no
  semantic lane starts, and no gap exists — so `present.rs` falls through
  to the `needs --manifest` line, which misdiagnoses a never-attempted
  seal as a missing flag.
- `--manifest` only "fixes" it incidentally: the manifest lane starts
  immediately at startup with no settle gate.
- Live proof (lu26, rc-20 base `99865eae1`, release build, SoftHSM
  signer): 20 s `--system` → 5-7 passes, gap line, zero
  `key operations unavailable` / `semantic subset refused` gaps in
  `--json` (`gaps_suppressed: 0`); the same command at 150 s (46-56
  passes) seals and shows per-key rows with no settle gap (the set was
  stable from pass 0 — the short run just ended first). Narrowed
  `--system --module <softhsm>` seals in 20 s (13 faster passes).

Two sibling shapes share the message but differ in cause:

- `--cgroup`: `ClassicDriver::apply` returns for cgroup collections
  before `attempt_deferred_scan_seal`, so the seal never runs for that
  scope at any duration.
- `--dashboard`: `run_dashboard` builds the driver with
  `scan_seal_pending: false`, so the seal is never armed there either.

## Shipped (message-only, v0.7.0)

`ClassicDriver::disclose_unseated_scan_seal` notes one terminal
`key operations unavailable` gap when the seal never seated — from
`on_lane_stopped` (native runs) and the scan-only finish (runs with no
lane; dashboard wired symmetrically, a no-op today). Noting clears the
pending flag, so the two hooks cannot double-disclose; a seated lane or
an already-disclosed refusal stays silent. The existing refusal-cause
line renders it; no `present.rs` change:

- settle held: `... did not start (the scan seal never seated: N passes
  ran, 8 stable passes over one provider set needed)` with rerun
  remedies (longer `--duration`, narrower scope, `--manifest`) in the
  full gap reason;
- nothing discovered: `... (the scan seal never seated: no provider
  table discovered within N passes)`;
- cgroup: `... (the scan seal did not run for this --cgroup capture)`.

## Design options (0.7.x, not shipped)

Any of these changes seal/start behavior and needs its own review plus
live proof on a busy multi-provider desktop; triage gated v0.7.0 to the
message fix above.

1. Time-based settle. Seat after the set holds still for N seconds
   instead of 8 passes, so slow `--system` passes seal as fast as
   quick `--pid` ones. Risk: re-opens the DEMO-4 newcomer race the
   pass gate closed (a pre-existing provider seating while the
   application's provider still arrives); the horizon and the late
   re-seat follow-up need re-tuning together.
2. Fewer stable peeks. Cheaper but blunter than (1): same newcomer
   risk, plus churned sets seat partial providers more often.
3. Attempt the seal for `--cgroup` collections. SHIPPED in round 2
   (v0.7.1), with one correction: the attempt runs from the
   post-commit `finish_pass` hook, not the apply path — apply is too
   early (the commit absorbs the mint's sources), and the commit now
   stashes them for the seal. No separate completeness rule: the mint
   covers discovered-complete providers only, undiscovered members
   stay honestly unattributed, exactly like discovery-capped legacy
   passes that seat today.
4. Arm the seal under `--dashboard`. Small (one flag plus the already
   wired finish disclosure) but unproven interactively: pass cadence
   under a live display differs, and mid-run seating must publish
   through the display path.
5. Seat over the current set at stop. Instead of disclosing, run one
   final start attempt at stop over whatever the last pass saw.
   Rejected direction: it starts BPF work during teardown, past the
   receipt windows the terminal sequence already races, and a
   stop-time seat cannot observe anything (capture is over) — rows
   would still be empty, only labeled differently.

Recommendation: (1) with the newcomer tests re-run, or keep the honest
message and document the longer-`--duration` remedy; (3) and (4) as
separate small lanes with their own live proof. (5) should stay
rejected.
