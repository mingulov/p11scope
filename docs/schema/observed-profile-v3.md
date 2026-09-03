# `observed-profile.json` schema v3

Current exact schema identifiers:

- profile: `pkcs11-scope/observed-profile/v3`
- metrics: `pkcs11-scope/observed-profile/v2-metrics`

Schema identifiers are opaque dispatch keys. A v3 profile is not accepted as
v2, and the unchanged aggregate-only metrics document is not accepted as a v3
profile. All profile fields documented by
[`observed-profile-v2.md`](observed-profile-v2.md) remain unchanged except for
the profile identifier and the four additions below.

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
exact-standard result with a known 3.x version and standard returned flags.
A successful matched result with an unreadable/null name or version retains its
match but has `none` authority. The corresponding agreement boolean is false;
legacy surfaces always have `name_agrees: false`. A nonzero `rv` has null
`result`, no matches, and `none` authority.

`attach_mechanisms` is a sorted, duplicate-free subset of `per-offset` and
`uprobe-multi`, derived only from successfully owned links. Before the
uprobe-multi attachment slice, a nonempty array can contain only `per-offset`.

`pid_descendant_gaps` and `multi_rebuild_gaps` are saturating u64 counts. They
are always present and zero when the corresponding path did not lose evidence.

## Completeness and terminal trace

Any truncation, uncovered provider, export status other than `present` or
`legacy_absent`, count-only tuple, successful tuple with `none` authority,
nonzero descendant gap, or nonzero rebuild gap forces
`evidence.completeness` to `PARTIAL`. The ordinary terminal trace
`EVIDENCE` object carries the same four fields and rules. Individual trace
event lines never contain request/result selection data.

The v3 profile evidence object and unchanged v2-metrics evidence object each
have a closed exact key set. Unknown fields are rejected; v2-metrics contains
none of the four v3-only fields.

## Migration

Consumers must migrate live profile dispatch from
`pkcs11-scope/observed-profile/v2` to
`pkcs11-scope/observed-profile/v3` and validate the closed shapes, bounds,
enums, ordering, references, and result/authority relations above. Historical
v2 profiles remain historical. Metrics consumers continue to dispatch only on
`pkcs11-scope/observed-profile/v2-metrics`; those documents contain none of the
four v3-only evidence fields.
