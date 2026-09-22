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
below, and the five residual additions (`drain_proven`, `verdict_detail`,
`uretprobe_override`, `handoff_child_pid`, `p11scope_env`).

Under the default `allowlisted` policy, every emitted mechanism has
`params: null` and `templates.operations` is always empty. The diagnostic
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
  set plus the four profile-only fields `interface_selection`,
  `attach_mechanisms`, `pid_descendant_gaps`, and `multi_rebuild_gaps`. Its
  verdict is selection-aware: a descendant gap, a rebuild gap, or any
  selection loss forces `PARTIAL`.
- The **metrics** lane (`render::json`, verdict
  `verdict_with_selection(false)`) embeds `Evidence` directly, so the four
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
`flags` (u64). Name classes are `null`, `exact_standard`, `other`, and
`unreadable`; version classes are `null`, `unreadable`, `v2_40`, `v3_0`,
`v3_1`, `v3_2`, and `other`.

`inventory_matches` contains at most 16 sorted, unique
`{surface, name_agrees, version_agrees}` objects. Each surface index must exist
and belong to the tuple's module. `table_match` is true exactly when this array
is nonempty. Authority is exactly `inventory`, `selection_count_only`, or
`none`: inventory authority requires a readable successful result and at least
one match; count-only authority has no match and is limited to a successful
request and result whose names are both `exact_standard`, whose returned
version is `v3_0`, `v3_1`, or `v3_2`, and whose returned flags are 0 or 1.
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

## Residual additions: terminal verdict, override, handoff, environment

These fields are always present in every v3 profile, v3-metrics, and terminal
trace evidence object. Historical documents predate them (see Migration).

- `drain_proven` (boolean) is the terminal-drain settlement latch. It is
  false in every document until a bounded quiescence/settlement experiment
  proves the terminal drain saw every in-flight callback; the producer's
  terminal seal forces `PARTIAL` while it is false, and the oracle refuses
  any `COMPLETE` without it.
- `verdict_detail` is exactly `clean_proven` (no gap, latch set),
  `clean_but_unproven` (no gap, latch unset — the terminal `PARTIAL` with
  nothing concrete behind it), or `concrete_gap` (a gap forced `PARTIAL`).
  Clean and lossy runs no longer share one signal.
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
`null` on the normal path), `final_drain` (always `false`: detaching perf
links proves nothing about quiescence), `counters_available` (always
`true`), and `trace_truncated` (boolean). Individual trace
event lines never contain request/result selection data.

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
`scheduling`, and the five residual fields above (`drain_proven`,
`verdict_detail`, `uretprobe_override`, `handoff_child_pid`, `p11scope_env`).

A machine-readable JSON Schema for live v3 documents ships beside this file
(`observed-profile-v3.schema.json`); it pins the closed evidence key sets
per lane, the required enums, and the `lane` discriminator. It is a
consumer aid: the release oracle (`scripts/check-capture-evidence.py`) is the
enforcement behind it, and `tests/python/test_schema_json.py` keeps the two
in agreement.
