<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T2 first-use requirements: frozen authority

Copied verbatim on 2026-09-26 from the approved finish plan, Task 2.
Full source SHA256: `c07651f6acc76864f36ed37bae1393e6bb1253a7d4dc88c0791e740038369e8b`.
The source is preserved in the workspace client-gap review as
`inputs/03-2026-09-22-system-scale-finish.md`. The unchecked boxes below
are requirements, not current execution results. Cold CLI startup tests
are useful supporting checks; they do not replace this first-use matrix.

## Task 2 — Resolve first-use and long-runtime feasibility early

**Files:** extend `tests/fixtures/discovery-lifecycle.c` or a narrow new `tests/fixtures/system-first-use.c`; reuse `scripts/system-scope-{measure.py,receipt.py,supervisor.py}` and their raw-parser tests. Produce `docs/qualification/system-first-use.md` and a capacity decision receipt. Do not change public promises or kernel/toolchain policy during a probe.

**Consumes:** sound owned oracle, physical receipts and stable baseline. **Produces:** supported first-use boundary and selected capacity experiment constraints, or a demonstrated product blocker.

- [ ] Prepare both gated and ungated controls. Ungated sequence is `load -> verify table -> one ordinary API call -> unload/exit` without waiting for observer attachment; retain a private independently checked ledger and file identity. Run previously covered physical inode, new inode with equal bytes, never-seen provider, late heap publication and short-lived namespace cases.
- [ ] Count independent transitions and times: object known, mapped, publication returned, scan complete, attach complete, entry executed, entry observed. Missing entries cannot be reconstructed from later publication.
- [ ] Test whether retained file probes solve the known-object case and whether a safe generic pre-execution hook covers the new-object case. Compare feasibility and target-interference cost; do not silently add ptrace stops, provider interposition, active provider calls or application changes.
- [ ] For each required unsupported case, provide a minimal repeatable counterexample and alternatives: safe preattachment discovery, an explicit optional mediated mode requiring approval, or an explicitly negotiated scope guarantee. An ungated miss is not a passing all-provider result. Continue independent work while the material decision is pending.
- [ ] Freeze a preliminary resource/latency measurement protocol for T7/T12. Derive capacity from measured census and reserve, not 576 as a new ceiling. Early allocator tests include low occupancy with >16,384 sequential lifetimes and scan-only bursts.
- [ ] [ideas-2026-09-25: G-14] Measurement/loss plumbing: authoritative observer attach/loop-start/expiry timestamps (no FD-estimate fallback); diagnose early ring loss in run; simplest PID SoftHSM profile must leave PARTIAL/concrete_gap; 3.1b tick latency vs the 1,895ms max. Accept: numbers + GREEN gate.

**Gate:** no hidden first-use promise. A material unresolved feasibility issue is explicitly `BLOCKED`, with a named decision owner; the release cannot pass by burying it as a footnote.

