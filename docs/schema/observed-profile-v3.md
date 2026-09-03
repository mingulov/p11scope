# `observed-profile.json` schema v3

Current exact schema identifiers:

- profile: `pkcs11-scope/observed-profile/v3`
- metrics: `pkcs11-scope/observed-profile/v3-metrics`

Schema identifiers are opaque dispatch keys. A v3 profile is not accepted as
v2, and the historical v2-metrics document is not accepted as a v3
profile. All profile fields documented by
[`observed-profile-v2.md`](observed-profile-v2.md) remain unchanged except for
the profile identifier and the five additions below.

The observer and `p11scope inspect` make zero PKCS #11 calls. Only the explicit
offline `p11scope-discover` helper loads a provider and makes exactly ten
pre-initialization `C_GetInterface` calls. Selection evidence is therefore a
bounded observation of application calls, or an optional offline manifest
fact; it is never created by probing the observed process.

## Added `evidence` fields

`interface_selection` is always present and has exactly these keys:

- `providers`: sorted, unique `{module, coverage}` objects. `module` is the
  zero-based `evidence.discovery[]` index. `coverage` is exactly `observed`,
  `observed_uncovered`, `absent_covered`, or `absent_uncovered`.
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
`result`, no matches, and `none` authority.

`attach_mechanisms` is a sorted, duplicate-free subset of `per-offset` and
`uprobe-multi`, derived only from successfully owned links. Before the
uprobe-multi attachment slice, a nonempty array can contain only `per-offset`.

`pid_descendant_gaps` and `multi_rebuild_gaps` are saturating u64 counts.
`pid_descendant_gaps` is zero for exact PID scope because process-creation
tracking is not attached there. For cgroup scope it counts observed child
creation windows before the child's per-process dynamic selection-export links
can be refreshed; static function probes still cover cgroup child calls during
that window. The fields are always present and zero when the corresponding
path did not lose evidence. When required cgroup process-creation tracking is
unavailable, `pid_descendant_gaps: 1` is an unavailability sentinel and lower
bound, not a claim that exactly one child was observed.

`task_uprobe_link_losses` is a saturating u64 count of matched leader-exit
records whose retained process generation proved that a member of the process
group remained live. It is settled from the generation-bound process view, not
from an independent process probe, and is counted at most once per process
view. A nonzero value closes that view's owned selection coverage and forces
`PARTIAL`; it is not merged into process-tracking or generic discovery-loss
counters.

## Completeness and terminal trace

Any truncation, uncovered provider, export status other than `present` or
`legacy_absent`, count-only tuple, successful tuple with `none` authority,
nonzero descendant gap, nonzero rebuild gap, or nonzero
`task_uprobe_link_losses` forces
`evidence.completeness` to `PARTIAL`. The ordinary terminal trace
`EVIDENCE` object carries the same five fields and rules. Individual trace
event lines never contain request/result selection data.

The v3 profile evidence object and v3-metrics evidence object each have a
closed exact key set. Unknown fields are rejected. Historical v2-metrics
documents retain their old closed key set and do not contain the new counter.

## Migration

Consumers must migrate live profile dispatch from
`pkcs11-scope/observed-profile/v2` to
`pkcs11-scope/observed-profile/v3` and validate the closed shapes, bounds,
enums, ordering, references, and result/authority relations above. Historical
v2 profiles remain historical. Metrics consumers must dispatch live output on
`pkcs11-scope/observed-profile/v3-metrics`; historical
`pkcs11-scope/observed-profile/v2-metrics` documents remain readable as a
separate compatibility shape and contain no `task_uprobe_link_losses` field.
