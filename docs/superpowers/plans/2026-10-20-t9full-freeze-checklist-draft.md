<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T9-full execution freeze checklist — DRAFT (pre-freeze)

> **Status: DRAFT.** Proposed gate order for T9-full (schema freeze).
> Drafted from read-only inspection at `47292662` plus the banked E17
> rerun recipe; no gate has been executed. The controller owns entry
> decisions, deferrals and the freeze commit itself.

Companion drafts: schema-surface inventory (`...-schema-inventory-draft.md`,
artifacts A–G) and drift analysis (`...-drift-since-g25-draft.md`,
items P1–P3). "T9-full" here means the freeze milestone in the
handoff queue (quiet-host bundle + G21 live leg → **T9-full** → T10
→ T11 installed → T12), not the whole T9 operator-journeys task.

## Gate 0 — Freeze entry (all must hold)

1. **Diet landed.** BPF-diet commits on their branch, reviewed,
   cherry-verified onto the candidate; new observer `p11_entry`
   loads on 7.2.9 (Fedora doctor leaves "capture unavailable")
   AND on 7.0.0-38 (universal-cliff twin). Byte/count/authority
   equivalence vs pre-diet capture proven on twins — diet must
   shrink verifier cost without moving B2/B4 semantics.
2. **Midfinal dispositioned.** Either landed (P1, 6 commits) with
   the `4M-file-midfinal` expectation re-derived, or explicitly
   deferred by the controller with that cell marked provisional
   (it was never exercised on post-be69 bytes).
3. **G21 round 2 dispositioned.** Either landed (P2, 5 commits)
   or explicitly deferred with the 5-capture live leg recorded
   open.
4. **Tip stable + V2 green** on the exact freeze-candidate SHA;
   no uncommitted bytes in any consumed worktree; build profile
   fixed (debug host / release BPF, Rust 1.98.1, jobs 2).
5. **Leases + lanes ready.** E17/Fedora + local leases verified
   live (banked leases lapse ~11:47 UTC 2026-10-22 if not
   renewed — re-check, never assume); cargo lane + heavy-lock
   coordination with sibling cells owned by the controller.

## Gate 1 — E17 matrix rerun (per banked recipe)

Source: `/var/tmp/p11scope-ws-tmp/wave12-e17matrix/REPORT-matrix-final.md`
(2026-10-20; 1 FAIL + 26 NOT_RUN matrix, 4 ancillary NOT_RUN,
8 reporter FAIL-readiness; blocker = verifier 1000001-insn E2BIG).

1. Renew/verify leases; run `prestep.sh` (GO: both leases,
   `sudo -n true`, quiet host).
2. Rebuild observer from the diet SHA (same profile); re-transfer
   to `fedora:/home/user/p11scope-e17matrix-20261020/inputs/`;
   re-verify arrival hashes (reusable as-is: caller, gate.so,
   reporter-probe, scripts/, tests/).
3. Representative first: `4M-file-none` must flip FAIL→PASS.
4. Full 27-cell matrix (4K/4M/16M × file/discard/slowpipe ×
   none/midcapture/midfinal), judging `4M-file-midfinal` against
   the Gate-0-re-derived expectation — never against the stale
   KNOWN-GenerationLost note.
5. Four ancillary cells (child-held-stdout, repeated-signals,
   file-limit, blocked-stderr); blocked-stderr requires
   re-qualifying reporter controls
   none/handlerblocked/wrongworker first.
6. All 8 reporter controls (none, readable, repeated, delayed,
   wrongexe, wrongprocess, handlerblocked, wrongworker).
7. Refresh `result.json` (new SHAs + outcomes), `doctor.txt`,
   `reporter-controls.log`, `e17-probe-cell.log`; keep the 37 KB
   verifier log as the pre-fix record. Release sleeps only
   after harvest; report changed bytes (new `p11scope` +
   `p11scope-discover-*` SHAs).

Pass: every runnable cell judged by the D6/D7 oracle with no
`unqualified` that hides a required positive; any remaining
NOT_RUN carries an explicit controller deferral.

## Gate 2 — Remaining live legs for the frozen surface

- **G21 5-capture live leg** (if not deferred at Gate 0): pid
  leg green including the final-bytes predicate; wrap-fixture
  `k=0`/quiesce gating from P2 is the judging oracle.
- **Quiet-host bundle** (handoff queue): `artifact_contracts`
  rerun + browser full-strict rerun on the candidate.
- **DR37 installed full-loop V4** (native-seal content is
  landed; the curated privileged cell needs its live pass) and
  **G22 U6 journeys** on the candidate bytes.
- Soak legs (`soak.1800s` vehicle) belong to T10, but the
  vehicle + oracle + manifest seeding are frozen here; a later
  soak FAIL is a product finding, not a freeze break (unless it
  forces a schema/oracle change — then see Invalidation).

## Gate 3 — Schema snapshot

On the passed candidate SHA, snapshot every inventory artifact
(A–G): schema doc SHAs, `*.schema.json` bytes, wire-struct
size-assert outputs, oracle script SHAs, manifest + the three
authority-catalog SHAs, allowlist SHAs, dashboard/promotion
contract revision, producer bytes (observer + BPF object SHAs,
arrival record). Snapshot format/location is a controller
decision (DRAFT: one JSON file next to the manifest + a
human-readable appendix). Snapshot ONLY — still not frozen.

## Gate 4 — Freeze commit

Single flat commit on the integration line declaring: the frozen
SHA set, the snapshot hash, deferred/provisional cells (if any),
and the canonical tick entry (`tick_collected_with`, given the
`b432f1b1` removal) plus any other narrowed staged interfaces.
Downstream locks engaged in the same commit where mechanical:

- H9 rule: one immutable Presentation contract — no independent
  reducers or schemas (completion plan T4/T5 boundary).
- Manifest regen guard: `*_sha256` pins + `verify_pass`
  authority checks (already in the verifier; freeze pins the
  values).
- Judge self-bind: `release-matrix-contract.py:550`
  (judge bytes == contract bytes) — freeze pins the judge SHA.
- CI BPF-parity baseline advanced to the frozen bytes under
  review (no silent re-green on new bytes).

## Gate 5 — Downstream consumption (T10/T11)

T10 measurements and T11 package/recipient/install cells consume
the frozen bytes + frozen oracles + frozen expectations only.
Any required change to a frozen artifact returns to Gate 0
(re-entry), never edits past the freeze.

## What INVALIDATES the freeze (re-entry to Gate 0)

1. Any edit to a wire struct, size constant, journal kind/flag,
   capture-policy vocabulary, or BPF map definition (B1–B5).
2. Any edit to a schema doc, `*.schema.json`, golden fixture,
   or renderer key/enum emission (A1–A8).
3. Any edit to an oracle's verdict code, marker regex, gate
   battery, or expected-outcome mapping (D1–D12) — including
   re-deriving `4M-file-midfinal` after the freeze.
4. Any edit to the manifest authority catalogs (147/43 counts,
   bounded IN/OUT partition) or verifier policy (G, D5).
5. Any allowlist change, or any new target read not already
   allowed (F1–F3; v1 never broadens implicitly).
6. Any dashboard/promotion contract change: keys, frame rules,
   request/view binding, baseline or receipt shapes (E1–E3, C6).
7. New producer bytes (observer/BPF SHA change) for any
   reason — diet follow-up, toolchain, rebuild flags: the
   matrix (Gate 1) must rerun on the new bytes.
8. Lease lapse or environment substitution without a recorded
   compatible-cell ruling (kernel/filesystem/ABI/workload must
   match the frozen campaign record).
9. A soak/T10/T11 finding that forces any of 1–6 (otherwise it
   is a product finding against the frozen surface, handled
   downstream).

Mechanical test-only changes (new pins of already-frozen
behavior, e.g. another hermetic oracle test) do NOT invalidate,
but must be reviewed as freeze-neutral and recorded.

## What T9-full still needs (blockers)

| Need | Status at draft time | Gate |
| --- | --- | --- |
| BPF diet commit + review + verifier proof (7.2.9 + 7.0.0-38) | uncommitted in `v040-bpfdiet`; branch empty | 0.1 — **hard blocker** |
| Midfinal land + expectation re-derivation, or explicit deferral | 6 commits pending, clean worktree, round 2 not started | 0.2 |
| G21 round-2 land + 5-capture live leg, or explicit deferral | 5 commits pending | 0.3 / 2 |
| E17 matrix rerun window (leases, Fedora heavy lock, quiet host) | recipe banked; leases lapse ~11:47 UTC Oct 22 | 1 |
| Quiet-host bundle (`artifact_contracts` + browser reruns) | queued | 2 |
| DR37 installed full-loop V4 + G22 U6 on candidate bytes | content landed; live passes open | 2 |
| G14 installed observer oracle (`qualify-key-operations.py`) | missing at tip | land or record open before Gate 3 |
| Snapshot format/location + freeze-commit ownership | controller decision | 3–4 |
