<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Publication-driven admission for forwarding layers (design, 2026-11-05)

Status: design for 0.6.1 (Phase 2 of the p11-kit line). Phase 1 (route B:
count at the real provider, honest default output) is separate. This note
uses no forwarding-layer internals: no closure offsets, no wrapper or
virtual-function structures, no provider symbols, no build-specific layouts.

## Problem

A forwarding layer (p11-kit proxy is the measured example) hands the
application function tables whose entries are templates. Scanning finds
67 lookalike tables and about 6,734 endpoints per copy
(`docs/notes/2026-11-01-p11kit-proxy-layer-measurement.md`). Attaching
all of them is cheap in kernel time but exceeds every current slot
ceiling (Detailed 512, Inventory 4,096 default / 8,192 max), so admission
must choose. Today's choice (Detailed): whole when it fits beside a
provider in the first plan, otherwise a reserve-capped leading-templates
prefix, otherwise only tables the process actually published. That keeps
real providers first (owner rule: never crowd them out, never raise
limits to fit templates), but a short-lived `run -- trust list` still
counts 0 of 744 backend calls: the pause cycle that publishes the proxy
table ends incomplete (`engine_incomplete_within_deadline`, 3 pause
attempts, 2 of 13 loader hits benign), the chain ends, and the backends
load unpaused. With the proxy excluded or named, the same run counts
744/744 and 746 (pause attempts 15-17, all loader hits benign). See the
Phase 1 report for the full matrix.

## Route A: attach what was actually returned

Attach only the function tables with publication evidence: a live
return of a standard `C_GetFunctionList` / `C_GetInterface` /
`C_GetInterfaceList` call to the application, interface linkage, a
manifest, or export agreement (the established
`table_observation_authorized` meaning). The observer already lowers
every live return of those exports (`process_export_record`, heap
wrappers included). Route A makes publication evidence the *only* way a
forwarding layer's tables attach in Detailed captures:

1. Scan still discovers every provider file and attaches each real
   provider's own scanned table as today (route B). A forwarding layer
   is any object whose unresolved lookalike count exceeds
   `MAX_TABLES_PER_OBJECT` (today's generic `ClosureArray` class) — no
   names, no layouts.
2. The layer's own tables attach only with publication evidence: a
   live return publishes the exact table address the application
   received, decoded at that address, attached once per distinct
   table; interface linkage, a manifest, or export agreement
   authorizes the same way. Tables with no publication evidence
   never attach and never consume slots.
3. Late-start (tables obtained before the capture began, the
   `--system` / `--pid` path): attach only the published-table sets
   that live tables in each process actually reference, found by
   scanning process memory for pointers to already-decoded tables —
   still generic address evidence, no layout knowledge. Spike round 2
   measured about 300-800 referenced endpoints per copy (about 2K
   referenced vs 18,822 mapped on the test host).
4. Per-thread nesting attribution (spike round 2, 26/26 exact against
   ledgers): the outermost template hit on a thread is one application
   call; a nested backend hit is its route; a nested template hit with
   no backend is forwarded to a remote (counted at the server as an
   ordinary late-start process); no nesting means the layer answered
   itself. Each call counts once.
5. Admission order, reserve, and ceilings are unchanged. Published
   tables are corroborated evidence and stay atomic (all fit or the
   module is refused whole with a named gap), as today. Unpublished
   layers read PARTIAL with the plain gap: calls through them are not
   counted at the layer; forwarded calls are counted at the attached
   providers (named, with counts); calls the layer answers itself are
   not counted.

## Why this is generic and safe

- The only new evidence is *which table an application was handed*,
  observed at the standard export returns the observer already hooks.
  Any proxy, shim, or aggregator that hands out tables is covered;
  providers that return their own table are counted at themselves.
- Slot use becomes proportional to tables actually used (one proxy
  table is at most 104 endpoints), so no limit change is needed and
  real providers keep priority. Remote p11-kit (server/client) keeps
  its current counting: the client's own published tables attach as
  today (54 of 56 calls measured earlier must not regress).
- Failure stays honest: a table obtained before attach, or a return
  missed in the attach-late window, leaves a named PARTIAL gap, never
  a wrong count (never-stop, JK-22a).

## Implementation outline (0.6.1)

1. Detailed admission: for `ClosureArray`, drop the heuristic
   whole/prefix passes; keep published-only in every scope and every
   arrival order. Proven exception (2026-11-05 live cell): an
   operator-named closure keeps its reserve-capped prefix, because
   `p11-kit-client.so` is itself a 66-table closure array whose
   published table races any export probe — pure published-only
   counted 0 of its 27 ledger calls, the named prefix counted 22
   (loop exact). Update `plan.rs` merge passes and the refusal
   wording together.
2. Pause: a published-only layer with nothing published is terminal
   for pause completeness (its gap is already named), so a pause cycle
   that publishes it no longer ends the chain; backend loads stay
   paused. Pin with a pause twin whose only incompleteness is an
   unpublished closure.
3. Late-start referenced-set scan for `--system` / `--pid`, bounded
   per copy, with the per-thread nesting rule in the counter
   attribution. `p11-kit server` / `remote` processes are ordinary
   late-start processes.
4. Tests: system-scale (8,192 endpoints) with three proxy copies;
   Firefox and Chromium through the proxy; `trust list` under `run`
   (744/744 at the backend, proxy self-answered calls named as not
   counted); the remote client cell (no regression); a fixture that
   loads a provider through the forwarding layer with no settle time
   (setup exact-or-covered, loop exact).

## Costs (spike round 2)

Attaching 6.5K-261K endpoints took 0.5-4.2 s, detach 0.4-2.5 s, about
256 B of kernel memory per endpoint, per-hit cost flat to 131K
endpoints. Route A attaches only referenced/published sets (hundreds
per copy), so these costs mostly disappear. Estimated work: 2-4
agent-days. Nothing here is v0.6.0-sized; Phase 1 ships route B plus
honest output.
