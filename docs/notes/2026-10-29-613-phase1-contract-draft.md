<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Packet 6.13 phase-1 contract draft — pre-armed named providers + watch intervals

**Status:** DRAFT for root decision (phase 1 of packet 6.13). No code beyond
RED tests is authorized until the root records O1–O4; the hard gate
(contract precedes new CLI syntax) stays in force.

- **Base:** `00e38b0a3d30ea5dd1843c1ca66832a4569377e3`
- **Brief:** `tmp/muse-jobs/brief-613-draft.md` (§2 seams, §3 RED steps,
  §6 OPEN items, §7 hard gate)
- **RED tests:** `tests/prearm_watch_intervals.rs` (4 RED failing, 4 twins
  green at base; see §“RED mapping” below)
- **Scope authority:** release plan §6.13, backlog B18/B19. `--module` keeps
  meaning “narrows the scan to named providers” (`src/cli.rs:406`); the
  drain interval stays loop cadence, not a coverage guarantee.

## O1 — new input shape (recommended)

A **separate repeatable path-valued flag** (name TBD by root, e.g.
`--prearm-module`), inheriting the command scope (`--pid`/`--cgroup`/
`--system`, `run`). It names provider files to pre-arm; it is **not**
`--module` (a mapped-scan filter) and **not** `--manifest` (Detailed-subset
attestation with function claims).

Validation mirrors `read_manifest` (`src/manifest_input.rs:12-68`):
bounded read, regular-file-only open-first, structural checks before use.
Trusted operator input; every named object still passes the pin worker
(ABI/identity/export checks) before it can select an attach fd, and an
uncorroborated pre-armed object forces `PARTIAL` exactly like an
uncorroborated manifest object.

## O2 — custody + watch/cancel/replacement lifecycle (recommended)

- **Pin at startup** with the existing worker
  (`pin_manifest_objects_with_read_policy`, `src/discovery/identity.rs:6511+`):
  open-first, `(ino,size,ctime)` bracket, attach via `/proc/self/fd/N` only.
  Pre-armed targets count against the existing budgets (512 objects /
  512 MiB pinning, Detailed/Inventory/counter policy limits); no new knobs.
- **Quiet never-mapped file** renders a **bounded armed/idle interval**
  (the new `watch` object, §O3) — **not** `WatchedNoUse`, which requires
  attached endpoints (`src/discovery/inventory_coordinator.rs:2201-2226`).
- **Cancel at scope end**: the watch closes with `until_ns` (last
  proven-clean instant); no watch outlives its scope.
- **Same-path replacement** follows retained-fd detect-and-disclose: the
  old inode stays behind `/proc/self/fd`, the change is reported with a
  bounded `watch.replaced` window, the capture continues `PARTIAL`; the
  watch **never retargets** to the new file. Kernel-backed fresh-file
  attribution stays 6.12's (O5); 6.13 claims no old-vs-fresh correctness.

## O3 — output keys (recommended, additive only)

On discovery module records (consumable by 6.14's watched-provider
evidence), additive keys only; existing `attach_gap_ms` /
`unprotected_live_windows` semantics untouched:

- `watch`: `{ since_ns: u64, state: "armed_idle", cancel: "scope_end",
  until_ns?: u64, replaced?: { previous_ino: u64, at_ns: u64 } }` for
  pinned-but-unobserved files. `state` marks watched-quiet, distinct from
  any unwatched window.
- Exactness for probes-before-mapping: `attached_at_ns: u64` at or before
  the mapping instant, or an explicitly empty `unobserved_windows: []`.
  A missing key means undisclosed, never exact; no missed-call number is
  ever invented (B18).
- Schema addition (`docs/schema/observed-profile-v3.schema.json`) and any
  stdout wording land in the owning GREEN patch. stdout never says
  “observed” for a zero it cannot prove.

## O4 — privacy (recommended)

No new provider-memory or call-argument reads: held-file export reads reuse
`crates/manifest/src/elf.rs`; identity rows already allow
filesystem/operator facts (`docs/privacy/allowlist-v1.md:47-48,108-119`).
The new input is **operator attestation** with the same
uncorroborated→`PARTIAL` rule as manifests. Proposed allowlist amendment
(one row, owner/root confirms; the allowlist file itself is **unchanged**
in phase 1):

> Pre-arm file list: operator-supplied pathnames; pinning reads held-file
> headers/exports only; uncorroborated pre-armed objects force PARTIAL.
> No provider memory or call arguments are read. No new capture row.

## O5–O7 (carried from the brief, for the GREEN packet)

- **O5:** 6.13 keeps conservative detect-and-disclose; 6.12 owns the
  fresh-file witness. Coordinate shared `identity.rs` ownership.
- **O6:** existing capacity budgets apply (see O2); no expansion.
- **O7:** installed cold/warm acceptance reuses the C3/K3 shapes with a
  pre-armed primary and the generic passive-disclosure twin,
  controller-scheduled on the live lane at C6-D.

## RED mapping (phase-1 proof)

| RED | Packet bullet | Seam | Failing assert (draft key) | Twin (green) |
| --- | --- | --- | --- | --- |
| `prearm_late_dlopen_first_burst_is_exact` | late-dlopen first-call burst | `Engine::discover` pre/post dlopen + `DiscoveryEvidence` JSON | `attached_at_ns` or `unobserved_windows` present | `generic_scan_only_admits_nothing_before_mapping` |
| `prearm_quiet_interval_is_watched_not_unwatched` | quiet watched interval | manifest-backed discover, never-called file | `watch.state` present | `manifest_backed_discover_before_load_marks_module_uncorroborated` |
| `prearm_never_mapped_file_has_bounded_watch_and_cancel` | never-mapped selected file | manifest-backed discover + plan slot→pinned-id resolution | `watch.cancel` present | `never_mapped_manifest_file_stays_pinned_and_unchanged` |
| `prearm_same_path_replacement_keeps_pinned_inode_and_reports_change` | same-path replacement | engine-route pin + rename-over + fresh discover | `watch.replaced` present (or discover discloses, not errors) | `manifest_rename_over_keeps_pinned_inode_and_reports_change` |

Known phase-1 limit: unprivileged RED-2/RED-3 share the pre-mapping engine
seam (quiet-with-no-calls vs never-mapped diverge only with call
observation); full quiet-vs-unmapped distinction and BPF exact-count proof
stay privileged C6-D cells.
