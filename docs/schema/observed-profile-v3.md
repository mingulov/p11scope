<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# `observed-profile.json` schema v3

Current exact schema identifiers:

- profile: `p11scope/observed-profile/v3`
- metrics: `p11scope/observed-profile/v3-metrics`

Schema identifiers are opaque dispatch keys. A v3 profile is not accepted as
v2, and the historical v2-metrics document is not accepted as a v3
profile. All profile fields documented by
[`observed-profile-v2.md`](observed-profile-v2.md) remain unchanged except for
the profile identifier, the `lane` discriminator, the six original additions
below, the six residual additions (`drain_proven`, `verdict_detail`,
`uretprobe_override`, `handoff_child_pid`, `p11scope_env`, `pid_namespace`), the stop-gate
outcome (`stop_quiescence`), the verdict
classes (`gap_classes` and its three published inputs), and row identity
(`functions[].target`, `functions[].ordinals`, table linkage `exports`).

Under the default `allowlisted` policy, every emitted mechanism has
`params: null` with `params_omitted: "policy"` beside it, and
`templates.operations` is always empty. Every `params: null` carries a
`params_omitted` cause (`policy`, `no_shape` or `decode_failed`); the field is
absent when `params` is an array. The diagnostic
parameter/template representations in the inherited schema are not default
capture promises. Missing metadata is not evidence that the application used
none. Scan-only function slots remain semantics-unverified/count-only; an
accepted explicit manifest attests only its exact object/name/offset claims.

The observer and `p11scope inspect` make zero PKCS #11 calls. Only the explicit
offline `p11scope-discover` helper loads a provider and makes exactly ten
pre-initialization `C_GetInterface` calls. Selection evidence is therefore a
bounded observation of application calls, or an optional offline manifest
fact; it is never created by probing the observed process.

## The metrics/profile evidence split

The two v3 lanes render deliberately different evidence objects from the same
capture, and a consumer must dispatch on the top-level `lane` field
(`profile` or `metrics`) before reading `evidence`:

- The **profile** lane (`render::profile_json`, verdict
  `verdict_with_selection(true)`) embeds `versioned_evidence`: the full base
  set plus the five profile-only fields `interface_selection`,
  `attach_mechanisms`, `attach_backend`, `pid_descendant_gaps`, and
  `multi_rebuild_gaps`. Its
  verdict is selection-aware: a descendant gap, a rebuild gap, or any
  selection loss forces `PARTIAL`.
- The **metrics** lane (`render::json`, verdict
  `verdict_with_selection(false)`) embeds `Evidence` directly, so the five
  `#[serde(skip)]` profile-only fields above are absent. Its verdict is
  selection-blind by construction: the same capture that reads `PARTIAL` as
  profile over a descendant gap reads `COMPLETE`-eligible as metrics, with no
  contradiction — the metrics verdict never saw the selection state.

The terminal trace `EVIDENCE` object follows the profile lane: it carries the
four versioned-only fields and no `lane` key (it is an evidence object, not a
document). The release oracle enforces the split (`exact_evidence_keys` with
`profile=True/False`), the per-lane verdict scope, and the `lane`
discriminator value.

## Added `evidence` fields

`interface_selection` is always present and has exactly these keys:

- `providers`: sorted, unique `{module, coverage}` objects. `module` is the
  zero-based `evidence.discovery[]` index. `coverage` is exactly `observed`,
  `observed_uncovered`, `absent_covered`, or `absent_uncovered`. At most 512
  providers (fewer when fewer modules were discovered); past the bound the
  array truncates with `selection_truncated` set.
- `standard_exports`: sorted, unique `{module, status}` objects. `status` is
  exactly `present`, `outside_module`, `legacy_absent`, `required_absent`, or
  `unresolved`.
- `inventory_surfaces`: at most 512 sorted `{module, ordinal, kind}` objects.
  `kind` is `legacy` or `interface`; `ordinal` starts at zero and is contiguous
  within each module.
- `tuples`: at most 16 distinct capture-wide selection tuples, sorted by the
  fixed field-order serialization listed below. Input JSON object key order is
  irrelevant to sorting and duplicate detection. The bound is global, not per
  provider.
- `selection_truncated`: boolean; true when a tuple, match, surface, or other
  selection fact exceeded its bound or could not be retained.

Each tuple has exactly `module`, `request`, `rv`, `result`, `table_match`,
`inventory_matches`, `authority`, and `count`. `count` is a positive saturating
u64. `request` and a non-null `result` each have exactly `name`, `version`, and
`flags`. Request `flags` is the caller's scalar CK_FLAGS argument (u64). Result
`flags` is a finite class, never the returned word: `zero`, `fork_safe`
(exactly `CKF_INTERFACE_FORK_SAFE`), or `other` (any other bit pattern). The
returned word is read through caller-writable memory, so the kernel reduces it
to this class before the record leaves the probe. Name classes are `null`, `exact_standard`, `other`, and
`unreadable`; version classes are `null`, `unreadable`, `v2_40`, `v3_0`,
`v3_1`, `v3_2`, and `other`.

`inventory_matches` contains at most 16 sorted, unique
`{surface, name_agrees, version_agrees}` objects. Each surface index must exist
and belong to the tuple's module. `table_match` is true exactly when this array
is nonempty. Authority is exactly `inventory`, `selection_count_only`, or
`none`: inventory authority requires a readable successful result and at least
one match; count-only authority has no match and is limited to a successful
request and result whose names are both `exact_standard`, whose returned
version is `v3_0`, `v3_1`, or `v3_2`, and whose returned flags class is `zero`
or `fork_safe`.
Count-only authority applies to a live or offline selection-only target, grants
no inventory match, is semantically unauthorized, and forces `PARTIAL`. The
profile tuple does not expose a helper selector or `semantic_authorized` field;
those are not part of the observed-profile-v3 shape.
A successful matched result with an unreadable/null name or version retains its
match but has `none` authority. The corresponding agreement boolean is false;
legacy surfaces always have `name_agrees: false`. A nonzero `rv` has null
`result`, no matches, and `none` authority. An `rv` of zero with a null
result (a null table output) is handled uniformly with nonzero `rv`: null
`result`, no matches, `none` authority.

`attach_mechanisms` is a sorted, duplicate-free subset of `per-offset` and
`uprobe-multi`, derived only from successfully owned links. Before the
uprobe-multi attachment slice, a nonempty array can contain only `per-offset`.

`attach_backend` says how the session chose its static attach backend, as
the inventory document's `observation.attach` does. The backend is chosen by
functional probes, never by the kernel version:
- `selection`: the operator's `--attach-backend` (`auto`, `multi` or
  `singles`).
- `fallback`: why `auto` runs per-offset links instead of uprobe-multi, else
  `null`. The reason is built from fixed text and the kernel's error. It
  never names a provider path or a process. Three cases produce one: the
  uprobe-multi functional probe failed; under `--pid`, the kernel pid filter
  was not proven; or the kernel refused the uprobe-multi attach.
- `scope_filter`: under `--pid`, what keeps other processes out of the static
  probes besides the in-BPF PID guard. It is `kernel-pid+bpf` when the
  uprobe-multi links name the target, which the probe allows only after it
  proves that the kernel pid filter covers every thread of the named process
  and no other process. It is `perf-task+bpf` when each per-offset link is
  bound to the target's task. It is `null` under `--cgroup` and `--system`,
  where links are process-wide and the in-BPF scope gate decides.

A PID-scoped uprobe-multi link never names pid 0.

`pid_descendant_gaps` and `multi_rebuild_gaps` are saturating u64 counts.
`pid_descendant_gaps` is zero for exact PID scope because process-creation
tracking is not attached there. For cgroup scope it counts destination-
authenticated ingress gaps: a newly admitted child `ProcessView` after a
membership refresh, or a valid leader-exit boundary that cannot match an
admitted process generation. Initially retained views are seeded without a
count, and each admitted generation or unmatched exit is counted at most once.
Creator records are semantic hints only: ordinary fork may retain the parent's
state, while `CLONE_INTO_CGROUP` never inherits; neither creator event itself
increments this counter. The fields are always present and zero when the
corresponding path did not lose evidence. When required cgroup creation or
lifecycle tracking is unavailable, `pid_descendant_gaps: 1` is an
unavailability sentinel and lower bound, not a claim that exactly one child
was observed. Arbitrary enter-then-migrate-out before refresh or exit remains
outside W3's completeness claim. A novel unmatched exit latches one lower-bound
overflow increment when the bounded ledger is full. If admission already
counted the gap, coalescing overflow marks `PARTIAL` without another increment.
Replays and further unremembered keys do not increment again.

`task_uprobe_link_losses` is a saturating u64 count of matched leader-exit
records whose retained process generation proved that a member of the process
group remained live. It is settled from the generation-bound process view, not
from an independent process probe, and is counted at most once per process
view. A nonzero value closes that view's owned selection coverage and forces
`PARTIAL`; it is not merged into process-tracking or generic discovery-loss
counters.

`abi_refusals` is a u64 count of scoped probe processing refused because the
execution-mode selector is unsupported or does not match the target-width
specialization selected from the retained pinned object. It counts refused probe invocations,
including returns and tail-call workers, rather than complete PKCS #11 calls.
It contains no raw selector or register values. An unsupported entry adds no
entered call; an accepted entry whose return has an unsupported mode remains
an uncompleted call, with no fabricated return value. The field is always
present in v3 profile, metrics and terminal trace evidence; nonzero forces
`PARTIAL`.

`scheduling` gains the Phase 2 responsiveness sub-objects, all always
present with closed keys. `stage_ms` and `stage_invocations` split the
discovery batch into `scan`, `pin`, `bind`, `plan`, `merge`, `projection`,
`attach`, `drain`, and `cleanup` leaf-span totals and counts (a different
clock from `phase_ms`; no identity between them). `stage_unknown_clock`
counts spans dropped for a failed clock read. `longest_op` names the
longest single span (`stage`, `op`, `duration_ms`), all null when none was
recorded. `inter_drain_gap` is the bounded gap distribution (`samples`,
bucket-upper-bound `p50_ms`/`p99_ms`, exact `max_ms` agreeing with
`max_inter_drain_gap_ms` whenever samples exist). `newcomer_queue` carries
first-seen-to-admission ages (`admitted`, `max_admitted_age_ms`,
`mean_admitted_age_ms`, `pending`, `oldest_pending_age_ms`, `dropped`,
`max_dropped_age_ms`, plus `admitted_unknown`, `dropped_unknown`, and
`marks_dropped` for clock-unknown or cap-dropped marks). A refresh-overflow
drop reports the newcomer's wait since diff discovery (its first-seen diff
mark); a never-diffed pid — a refresh-first arrival dropped before any
diff marked it — reports unknown age (`dropped_unknown`), never zero.
`resource` is the `/proc/self` timeline (`start`, `readiness`, `end`
samples of `rss_kb`, `utime_ms`, `stime_ms`, `read_bytes`, `write_bytes`,
each null on a failed read; `samples`, `max_rss_kb`, `last_periodic`
summarize the bounded periodic series). `max_rss_kb` covers the periodic
samples only: a short capture with no periodic tick reports null max even
though the start/readiness/end samples hold RSS. `tail_publishes`/
`tail_skips` count executed versus provably redundant batch-tail
publications.

## Residual additions: terminal verdict, override, handoff, environment, PID namespace

These fields are always present in every v3 profile, v3-metrics, and terminal
trace evidence object. Historical documents predate them (see Migration).

- `drain_proven` (boolean) is the terminal-drain settlement latch. It is
  true only when the Detailed stop gate proved quiescence (no admitted BPF
  callback still running), the terminal drains read to the ring positions
  observed at that point (EVENTS and DISCOVERY for profile and trace;
  DISCOVERY only for v3-metrics, whose counts come from maps finalized
  behind quiescence), no drain saw a record past them, and the
  build is x86_64 (owner ruling B, 2026-09-25); other architectures keep it
  false. The producer's terminal seal forces `PARTIAL` while it is false, and
  the oracle refuses any `COMPLETE` without it.
- `stop_quiescence` is `{state, post_q_events, post_q_discovery}`, the
  terminal stop gate's outcome the latch is derived from. `state` is
  `proven` (quiescence observed), `unproven` (the 5 s stop budget expired
  first; stderr names `QuiescenceUnproven`), or `not_reached` (no terminal
  stop gate ran). `post_q_events` / `post_q_discovery` are true when the
  EVENTS / DISCOVERY ring held a record past its quiescence position — an
  ungated writer, also named on stderr; either keeps `drain_proven` false
  and only occurs with `state: proven`. A v3-metrics capture does not drain
  EVENTS, so its `post_q_events` is always false.
- `verdict_detail` is exactly `clean_proven` (no gap, latch set),
  `clean_but_unproven` (no gap, latch unset — the terminal `PARTIAL` with
  nothing concrete behind it), `attribution_only` (counts are exact; only a
  name, owner, mechanism, or semantic interpretation is withheld — for
  example every scan-found slot is count-only), or `concrete_gap` (an
  observation loss or degraded semantics forced `PARTIAL`). It is a function
  of `gap_classes` alone. Clean, names-withheld, and lossy runs no longer
  share one signal; `completeness` is `PARTIAL` for all but `clean_proven`,
  which is `COMPLETE`.
- `gap_classes` is `{observation, attribution, semantics, open_calls,
  settlement, stdout_data_sink}`. Each of the first three is `{status,
  causes}`: `causes` lists, in a fixed order, the evidence fields that put the
  class in that status (a dotted name such as
  `scheduling.sink_dropped_bytes` names a nested field; `interface_selection`
  names a selection coverage loss; `loader_discovery` a live-loader timing or
  strategy gap). `observation` is `exact` or `lossy`: a call or record could
  be missing, or a count could be wrong. `attribution` is `attested` or
  `withheld`: `semantic_unverified_slots`, `aliased`, `module_ambiguous`,
  `module_unresolved_slots`, `unregistered_mechanisms`,
  `discovery_conflicts`, `discovery_uncorroborated`, or a
  `selection_count_only` tuple. `semantics` is `complete`, `degraded`, or
  `not_applicable` (no slot carries semantics). `open_calls` is
  `in_flight_at_end`; for now a nonzero value is also an observation cause,
  because an entry whose return never arrives cannot yet be told apart from
  a lost return. `settlement` is `proven` or `unproven` (`drain_proven`).
  `stdout_data_sink` is true only for a trace written to stdout (no `-o`):
  only then are `scheduling.sink_dropped_bytes` an observation loss; a
  profile, metrics, or `-o` capture's stdout carries display frames only,
  and its drops are stated but are not a gap. A NULL function-table entry
  (`skipped` reason `null pointer`) is never a cause: a NULL pointer cannot
  be called, so no call is missed through it. The release oracle recomputes
  every class and `verdict_detail` from the counters and refuses a document
  that disagrees.
- `semantic_unverified_slots`, `unprotected_live_windows` (0 or 1: a live
  loader or export window no confirmed pause owner protected, inferred from
  `loader_discovery.hits > 0` and `pause` other than `sigstop`), and
  `module_unresolved_slots` (the number of `functions[].module_unresolved`
  rows) are the three verdict inputs that were previously unpublished.
- `uretprobe_override` is `null` when the hazard preflight proceeded clean,
  else `{flag, reason}`: the exact `--allow-uretprobe-on-confined-target`
  flag plus the preflight's reason for requiring it. Disclosed, never a
  verdict gap.
- `handoff_child_pid` is `null` except in a `run` document whose owned child
  was handed back alive, where it names that PID. It agrees with
  `child_still_running` exactly (`Some` if and only if still running) and is
  `null` in every `--pid`/`--cgroup`/`--system` document. The operator's own
  child, nameable so exit 0 never leaves an orphan unnamed.
- `p11scope_env` is the active value of every capture-visible `P11SCOPE_*`
  switch: `{name, effect, value}` objects, `value` `null` when unset.
  Absent means the narrow default.
- `pid_namespace` (DR-K8S-1/2) names which PID namespace numbers which
  PIDs, as exactly `{observer, kernel_pids, proc_pids}`. `observer` is
  `initial`, `nested`, or `unknown`: the observer's own PID namespace,
  read from `/proc/self/ns/pid` (initial means the fixed
  `PROC_PID_INIT_INO` inode; an unreadable or malformed link is `unknown`,
  never `initial`). `kernel_pids` is always `initial`: PIDs the kernel
  reports (trace `pid`/`tid`) are initial-namespace PIDs. `proc_pids` is
  `observer` when the mounted `/proc` numbers processes in the observer's
  own namespace (`/proc/self` is `getpid()` and `/proc/<getpid()>/status`
  `NSpid` is exactly `getpid()`), else `foreign` (for example `nsenter -m`
  without `-p`, or `unshare --pid` without `--mount-proc`): PIDs read from
  `/proc` (`--pid`, `run`'s child, `handoff_child_pid`, discovery subjects)
  are in that numbering. The two agree exactly when `observer` is `initial`
  and `proc_pids` is `observer`. Any other `observer` is the observation
  cause `pid_namespace`, and `proc_pids: foreign` the cause
  `proc_namespace_mismatch` (both `lossy`, `concrete_gap`): live discovery
  keys on kernel PIDs that cannot be resolved through `/proc`. A PID-scoped
  capture never reaches a document there: it is refused with
  `pid-namespace-mismatch` (see `docs/usage.md`, PID namespaces).

## Row identity and export linkage

Every `functions[]` row carries `target` (`{object: {dev, ino, sha256} |
null, file_offset}`, the exact function the row counts) and `ordinals` (sorted
`{table_file_offset, ordinal}` positions reaching it). Several rows may read
`["unknown"]`; `target` tells them apart, and `ordinals` discloses when several
positions share one target. `discovery[].tables[]` adds the linkage value
`exports` and the `exports_agreeing` count (see the v2 document's `tables[]`
and `functions[]` rows). Export linkage presents standard names only: scan-found
slots stay semantics-unverified and count-only whatever their linkage.

## Kernel control evidence

`kernel_control` is always present in every v3 profile, v3-metrics, and
terminal trace evidence object. It is read from the native kernel control
cells at every snapshot and at terminal, and carries finite names and counts
only:

- `capture_halted` (boolean) is true exactly when `owner_poison` is non-empty.
  The in-kernel call-ownership accounting detected an inconsistency and every
  probe has refused capture since; nothing after that moment was counted.
- `owner_poison`: sorted, unique reason names from `bad_control`,
  `lookup_unknown`, `bad_record`, `delete_failed`, `bookkeeping_failed`,
  `refund_failed`, `classifier_failed`, `state_delete_failed`,
  `start_key_mismatch`, `start_count_mismatch`, `start_row_missing`,
  `directory_mismatch`, `unknown`. The last four name exactly which
  bookkeeping invariant failed and always accompany `bookkeeping_failed`.
- `owner_admission_failures` (u64): owner admissions refused (limit reached,
  invalid key, or collision).
- `identity_unavailable` (u64): process identities the kernel could not
  allocate or read. This includes every fork record dropped after the
  lifetime identity budget (16,384 tickets) is spent.
- `identity_budget_exhausted` (boolean): the lifetime identity budget is
  spent. Informational on its own; the refusals it causes are counted above.
- `root_affiliation_failures`: sorted, unique names from `bad_control`,
  `capacity`, `reserve_contention`, `create_failed`, `existing_child`,
  `bad_cell`, `exit_classifier`, `exit_delete`, `refund_failed`, `unknown`.

A halt, any nonzero counter, or any root failure name forces `PARTIAL` with
`verdict_detail` = `concrete_gap`. Historical v2-metrics documents predate
this object.

## Added `capture` fields

`capture.scope` is exactly `pid`, `cgroup`, or `system`, naming which scope
selected the capture (`--pid`, `--cgroup`, or `--system`). It carries no PID
number or cgroup path. The evidence object keeps its closed exact key set;
this addition touches the `capture` section only.

## Completeness and terminal trace

Any truncation, uncovered provider, export status other than `present` or
`legacy_absent`, count-only tuple, successful tuple with `none` authority,
nonzero descendant gap, nonzero rebuild gap, or nonzero
`task_uprobe_link_losses` or `abi_refusals` forces
`evidence.completeness` to `PARTIAL`. The ordinary terminal trace
`EVIDENCE` object carries the same profile-lane fields and rules, plus five
terminal-only keys: `privacy_mode` (string), `capture_aborted` (always
`null` on the normal path), `final_drain` (equal to `drain_proven`:
detaching perf links proves nothing about quiescence, only the stop gate's
proven quiescence does), `counters_available` (always
`true`), and `trace_truncated` (boolean). A truncated trace (`trace_truncated:
true`, from `--max-events` or the default event cap) is `PARTIAL` even when
`drain_proven` is true: the drain still counts the events past the cap, but
no line was printed for them. Its `gap_classes.observation.causes` then
include `trace_truncated` (so `verdict_detail` is `concrete_gap`). Individual
trace event lines never contain request/result selection data.

The v3 profile evidence object and v3-metrics evidence object each have a
closed exact key set. Unknown fields are rejected. Historical v2-metrics
documents retain their old closed key set and do not contain the new counter.

## Migration

Consumers must migrate live profile dispatch from
`p11scope/observed-profile/v2` to
`p11scope/observed-profile/v3` and validate the closed shapes, bounds,
enums, ordering, references, and result/authority relations above. Historical
v2 profiles remain historical. Metrics consumers must dispatch live output on
`p11scope/observed-profile/v3-metrics`; historical
`p11scope/observed-profile/v2-metrics` documents remain readable as a
separate compatibility shape. That shape predates — and therefore lacks —
`task_uprobe_link_losses`, `abi_refusals`, `semantic_history_drops`,
`scheduling`, `active_slots` (U-14), the six residual fields above
(`drain_proven`, `verdict_detail`, `uretprobe_override`, `handoff_child_pid`,
`p11scope_env`, `pid_namespace`), and `stop_quiescence`.

A machine-readable JSON Schema for live v3 documents ships beside this file
(`observed-profile-v3.schema.json`); it pins the closed evidence key sets
per lane, the required enums, and the `lane` discriminator. It is a
consumer aid: the release oracle (`scripts/check-capture-evidence.py`) is the
enforcement behind it, and `tests/python/test_schema_json.py` keeps the two
in agreement.
