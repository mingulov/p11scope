<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Step 3: bounded deep-scan subset rule (design, 2026-11-06)

Status: design. No behavior change ships with this note: every held
configuration reproduced in R6 already attaches through a deep-scanned
holder (below), so the rule below closes the remaining theoretical
corner — a holder the selector never picks — without touching the
shared selection seam until a live reproduction demands it. This note
uses no forwarding-layer internals: grouping is by mapped `.so` file
sets only (the existing `is_provider_mapping` predicate).

## Problem

R4 found two Fedora boundaries: 843 unheld ~10 ms `trust` runs were
scan-invisible AND gap-silent (fixed by the short-lived gap: pending
EXEC hooks now reconcile against scan examinations instead of clearing
at each apply), and a Chromium-held `p11-kit-trust.so` was never
deep-scanned in 15 passes, so its trust stayed invisible too. This note
is the second boundary: the guarantee that a process holding a mapped
provider gets deep-scanned and attached.

## What the R6 cells show

All cells are `inventory --system` on Fedora 7.2.9, default 256 cap:

- Chromium-held trust attaches in every configuration: under-cap
  (221 enumerated), near-cap (257 enumerated, selection active), and
  on the fix tip. The holder pid is deep-scanned about every pass
  (29 scan lines over 27 passes; 23 over 22 on the fix tip), trust
  admits (68 endpoints, heuristic), and 10 short `trust` runs fold
  exactly (10 rows, 31990 entries).
- R4's "never deep-scanned" did not reproduce. The likely mechanism
  for such a miss is below (residual corner), not the common path:
  under the cap every enumerated process is deep-scanned every pass,
  and over the cap a unique holder sorts early by rarity.

## Current rule (exact)

`select_deep_scan_candidates` (`src/discovery/engine.rs`), shared by
capture discovery, system inspect/inventory, and cgroup inventory
(three `select_excluding_kernel_threads` call sites; kernel threads
are excluded before the cap so they never consume slots):

- Under the cap: the identity — all enumerated pids ascending, every
  pass. Every holder is deep-scanned every pass.
- Over the cap: pids group by exact mapped-`.so` set; each group sends
  its lowest pid, rarest files first (file-level census over the
  sweep, then group size, then lowest pid); pids with no provider
  mapping trail as individuals; the cap truncates the order.

Guarantee: every distinct provider SET is examined each pass (when
selected), and every PROCESS each pass under the cap. Corner: only
one member per group is ever picked, deterministically the same one
every pass (no cross-pass rotation), and leftover cap slots stay
empty when groups plus unmapped number fewer than the cap. A holder
misses its scan only if its group already sent a lower pid AND spare
slots do not reach it — persistently, when that representative's own
scan keeps failing (unreadable, transient) while a mate would decode.

## The rule

Two parts, both bounded by the existing cap:

1. Within-pass spare-slot fill (stateless). After the first
   representatives and the unmapped individuals, fill remaining cap
   slots with further group members: round-robin across groups in the
   existing rarity order, pid order within each group. A pass never
   scans more than the cap, and today's under-cap passes already scan
   that many; the fill only spends slots the current rule wastes.
2. Cross-pass rotation (bounded state). The coordinator retains, per
   enumerated pid, its last deep-scanned pass, and threads that set
   into the collector; within each group the representative becomes
   the lowest never-scanned member (falling back to the lowest stale
   one), exactly like the live-discovery `select_rotation_candidates`
   tiers. Rarity still orders groups, so a rare provider is always
   reached first; within a class, never-scanned pids beat re-scans.
   With no stale pids the order agrees with today's selection exactly.

Bounds: the 256 default cap (and its `--max-scan-pids` knob) do not
move; no budget is raised or lowered (`CaptureWorkBudget` charges
each deep scan as today, refusals stay honest); rotation state is the
enumerated pid set per pass (hundreds of entries, kilobytes); views
are never stopped (selection only orders scans — every enumerated
member still registers, and unselected members keep their C1b
maps-match attribution and unexamined record).

## Cost (measured 2026-11-06, Fedora, root, ~220 processes)

Per-pass `deep_scan` stage: ~700–1100 ms for the whole pass
(`P11SCOPE_STAGE_TIMINGS=1`), about 3–5 ms per deep scan at ~215
enumerated including ELF decode and pinning; `assemble` ~100–155 ms,
`confirm`/`absorb`/`project` single-digit ms, `reconcile` mostly
single-digit ms (13.6 ms on pass 0). Part 1 adds at most the unused
slots per over-cap pass — worst case a full cap of 256 scans, the
same order as today's under-cap passes (~820 ms), charged to the
existing pass budget. Part 2 adds O(enumerated) retained integers and
a membership test per candidate — negligible beside one deep scan.
Selection itself stays an in-memory sort over hundreds of rows.

## Follow-up test plan (when a live miss reproduces)

- Unit twins at the selection seam: spare-slot fill order (rarity,
  then group depth, then pid); rotation prefers never-scanned within
  a group and agrees with plain selection when nothing is stale;
  the cap is never exceeded; kernel-thread exclusion still applies
  first. Mirror the existing `select_rotation_candidates` twins.
- Live cell: an over-cap capture whose trust holder sits in a
  multi-member group behind a persistently failing representative
  (or 256+ rarer groups ahead of it); assert the holder is scanned
  and trust attaches within a bounded number of passes.

## Residual limitation

Short programs that exit before their first EXEC hook drains (a dead
pid the sweep never lists and the ring never reports) remain
invisible to both the short-lived gap and this rule; closing that
would need exec-time recording, which stays deferred to v0.7.0 task
7.10b. Pre-capture processes that exit during the first collection
likewise leave only an undisclosed `Exited` member.
