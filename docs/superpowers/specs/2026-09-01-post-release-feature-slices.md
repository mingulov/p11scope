# p11scope deferred feature slices (Slice 2, Slice 3, parked items)

**Date:** 2026-09-01
**Status:** Owner-approved direction record. Everything here is **deferred by
default, not excluded from v0.1.0**: depending on execution speed the owner
may pull any item into the release (owner decision 2026-09-01); a pulled item
joins a release wave with full gate coverage and gets recorded here and in
the ROADMAP. `uprobe_multi` was already pulled INTO release scope
(2026-09-01, now W3 — see the charter) and is no longer listed below. This
document exists so deferred work is planned deliberately, not re-derived;
each slice gets its own spec → plan cycle when it starts.
**Consumes:** `2026-09-01-p11scope-release-prd.md` §8 (non-goals),
`docs/superpowers/plans/ROADMAP.md`, `docs/notes/2026-09-01-ebpf-comparable-tool-pitfalls.md`.

## Slice 2 — capture quality

Deepens what a capture can express; no structural change.

| Item | What / why | Notes |
| --- | --- | --- |
| Ring/epoll capture path | Replace tick polling where it measurably drops less under load | Bench first; the per-tick frozen ordering is contract-tested (`tests/artifact_contracts.rs`) |
| Budgets as policy | Expose the W1 Task 6 computation/maps/deadline budgets as operator policy, not just constants | The constants land in wave 1 with `ponytail:` knob comments — this promotes them |
| Safe-policy params | Additional allowlisted mechanism/param metadata | Any addition is an explicit allowlist-v2 revision — never implicit (privacy contract) |
| Per-module profile sections | Split aggregate profile output per module in multi-module captures | Schema change → schema v3 discussion |
| Filters | Operator-side event filters (function/module/RV) | Kernel-side only if measurement demands it |
| Snapshots | Point-in-time capture summaries during a long run | |

## Slice 3 — structure

- **Module split:** break `src/` monolith (notably `discovery/engine.rs`,
  ~18k lines) into focused crates/modules once the release freeze is over.
  Source-text contract tests (`engine.rs:11852`, `artifact_contracts.rs`)
  must be migrated deliberately, not deleted.
- **Evidence plumbing:** unify Skipped/EVIDENCE/receipt paths behind one
  evidence module.
- **Docs consolidation:** collapse the historical docs/superpowers record into
  a maintained handbook; historical files stay as history.
- **Multi-kernel CI as default:** promote the W6 load-only matrix into the
  standing PR gate.

## Parked items (entry conditions, not schedules)

| Item | Trigger to start |
| --- | --- |
| Raw-tracepoint exec/exit variants (same object, 12→14 programs) | v0.1.0 shipped. Buys tracefs independence + offset-drift immunity, but sells a BTF/CO-RE dependency — keep BOTH variants in one object; never lose the BTF-independence currently held for free (research #12; owner note 2026-08-31) |
| AArch64 host support | First real user ask, or owner decision |
| 32-bit counting mode (full ia32 capture beyond W7's observe-target scope) | W7 evidence shows demand |
| Freezer-cgroup pause | Pause-path evidence shows SIGSTOP insufficient |
| Manifest catalog (known-provider manifests) | Recurring operator demand for offline path |
| Container image + K8s manifests as shipped artifacts | Post-release; W5 qualification report is the v0.1.0 substitute |
| deb/rpm packages | Post-release demand |
| `pkcs11-lab assess` integration (observed-profile × pkcs11-check) | pkcs11-lab side ready; owner prioritization |
| Selection-probe diagnostic: an explicit `C_GetInterface` query mode ("what would a consumer asking for name/version X get?"), recorded as clearly-labeled selection-behavior evidence, never merged into inventory (PRD §8 invariant) | Operator demand for consumer-selection diagnostics |
| Seccomp/Landlock jail around the discover helper's `dlopen` | Research Tier-1 #4 residual; requires design (helper runs vendor code as a real host user) |
| Scan rate-limiting + (dev,inode) dedupe against target `mmap_lock` stall | Research item #6 residual (measured 0.097 ms → 8020 ms target stall); W1 Task 6(f) bounds the bytes only — start on any real-world stall report |
| PID-namespace attribution verification (`NSpid` depth check at startup) | Research #14; becomes mandatory work the moment in-cluster deployment is a shipped artifact |

## Rules that survive into every slice

- Privacy allowlist is never broadened implicitly (allowlist revisions are
  explicit, versioned, owner-approved).
- Honest evidence: every degradation consumer-visible.
- Two-directory storage rule.
- Verified-anchor planning protocol (ROADMAP §"Agent execution protocol").
- The ROADMAP's standing slice gate ("the four cargo checks, the unprivileged
  suite, and the CI e2e job green; root gates owner-approved or UNRUN")
  applies to every slice here unchanged.
