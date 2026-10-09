<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Inventory diff schema v1

Schema ID: `p11scope/inventory-diff/v1`. The offline command
`p11scope inventory diff BEFORE.json AFTER.json [--json] [-o DIFF.json]`
compares two saved [inventory v1](inventory-v1.md) documents. It loads no
provider, performs no live process lookup, and needs no capture privileges.
See the [operator examples](../usage.md#offline-inventory-comparison).

## Input and compatibility

Each input must be one UTF-8 JSON object with exact schema ID
`p11scope/inventory/v1`. It must contain `scope`, `clock`, `observation`,
`budgets`, `callers`, `modules`, `edges`, `gaps`, and `gaps_suppressed`, with
their required inventory v1 fields. Profiles and inventory-event JSONL are
unsupported. Duplicate object keys, trailing documents, malformed required
fields, invalid numeric types or overflow, duplicate caller/module IDs,
duplicate caller/module edge pairs, and dangling non-null references fail.
A non-null SHA-256 must be 64 ASCII hex digits; output normalizes lowercase.

Legacy additive omissions are accepted: `pid_namespace`; observation `lane`,
`settlement`, `retirement`, `attach`, `lifecycle`, and `native_witnesses`;
admission `history`; module `unbound_use`; mapping `evidence`; entries
`coverage`; edge `mechanisms` and `operations`; and budget
`inventory_endpoints`, `inventory_attach_modules`, and `native_preadmission`.
An absent `inventory_endpoints.refused` stays unknown. Missing `gaps[].repeats`
defaults to 1; a present repeat count must be positive. Missing coverage stays
unknown. Required nullable fields must still be present; null never becomes
a synthetic zero. Absent supported optional facts serialize as null in the
report, except the repeat default.

Unknown additive fields, including their subtrees, consume the same parsing
limits but are ignored and never copied through. Known optional fields are
validated when present. Unknown enum labels retain their strings and are
interpreted as unknown; they cannot establish admission, use, complete
coverage, or inactivity. Clock/start-time units retain their original values.

| Resource | Maximum per input |
| --- | ---: |
| Bytes actually read | 64 MiB (67,108,864) |
| Combined caller + module + edge + gap rows | 250,000 |
| Decoded UTF-8 bytes per string or object key | 16,384 |
| JSON nesting depth | 64 |
| JSON values plus object keys | 2,000,000 |

Every limit applies; a document below the row limit may exceed the node or
byte limit. Inputs must be regular files; symlinks to regular files are
accepted. Opening is nonblocking before checking the descriptor, so a FIFO
is refused without waiting for a writer. Reads remain bounded when file size
metadata is inaccurate or the file grows. A limit failure produces an error,
never a silently truncated successful comparison. These input bounds and the
shared report representation do not promise a numeric output-size or RSS cap.

## Root and snapshot metadata

The root contains exactly these ten fields. Numeric fields are JSON integers;
counts and timestamps use unsigned 64-bit values unless specified otherwise.
Caller/gap PIDs and module device major/minor use unsigned 32-bit values;
executable `mtime_secs` and `mtime_nanos` use signed 64-bit values. Summary,
gap-record totals and references are nonnegative indexes/counts. Consumers
must preserve large integer values rather than rounding through floating point.

| Field | Meaning |
| --- | --- |
| `schema` | `p11scope/inventory-diff/v1` |
| `before`, `after` | Independent snapshot metadata and evidence pools below |
| `comparison` | Relations and shared application-path dictionary below |
| `summary` | Projection totals below |
| `module_contents` | Union of all known module digests, including unchanged rows |
| `application_changes` | Changed recorded application-path/digest projections |
| `module_path_changes` | Changed digest sets at recorded module paths |
| `unresolved` | Source observations that cannot enter a supported projection |
| `limitations` | Sorted, duplicate-free interpretation codes |

Each snapshot has `scope`, `clock`, `observation`, `pid_namespace`,
`scope_completeness`, `reported_gaps`, `suppressed_gaps`, `refusals`, `budgets`,
`loss_evidence`, `gaps`, and `evidence`. Input filenames are not report fields.

`clock` has `basis` and `unit`. `observation` has `started_ns`, `ended_ns`,
`passes`, `usage_feed`, `lane`, `settlement`, `retirement`, `attach`,
`lifecycle`, and `native_witnesses`. The latter three objects retain these
supported inventory fields:

- `attach`: `selection`, `mechanism`, `fallback`, `scope_filter`.
- `lifecycle`: `records`, `ring_loss`, `malformed`, `failed_quanta`,
  `recovery_rescans`.
- `native_witnesses`: `rows`, `bound`, `unbound`, `pending`, `integrity`,
  `unbound_reasons` (reason-to-count object), and `placement` with `edge`,
  `module`, `ambiguous`, `unresolved` counts.

`pid_namespace` is null or `{observer, kernel_pids, proc_pids}`.
`scope_completeness` is always `unknown`, even when no gaps were reported.
`reported_gaps` counts gap records; `suppressed_gaps` retains
`gaps_suppressed`. A gap can report an admission transition, so gap count
alone does not measure loss or completeness.

`refusals` has `reported_budget_gaps` (gap records with non-null budget)
and `budget_counters`: `callers`, `modules`, `edges`, `endpoints`,
`semantic_state`, `inventory_endpoints`, `inventory_attach_modules`,
`native_preadmission`. Missing optional counters are null, not zero.
`loss_evidence` has `lifecycle` and `native_witnesses`, retaining the same
objects as `observation` for direct access to loss/settlement evidence.

`budgets` retains `callers`, `modules`, `edges`, `endpoints`, and nullable
`inventory_attach_modules`, each `{limit, occupied, refused}`; nullable
`inventory_endpoints` with `{limit, occupied, refused}` (nullable `refused`);
`counters` with `{cap, observed_edges, saturated_edges}`; `semantic_state`
with `{limit, occupied, status, unknown_edges, refused}`; `retained_history`
with `{limit, retained, suppressed}`; and nullable `native_preadmission`
with `{limit, occupied, refused, pruned}`.

Each gap has `caller`, `module`, `pid`, `subject`, `reason`, `budget`, and
`repeats`. References and `pid` may be null; `budget` is null or
`{resource, limit, requested}`. References resolve in that snapshot's pools.

## Evidence pools and references

Each snapshot's `evidence` has `callers`, `modules`, `edges`,
`caller_occurrences`, `module_occurrences`, and `edge_occurrences`.
The first three arrays contain canonical full evidence values; identical
projected values share a pool entry. The sorted occurrence arrays contain
one reference per source row and retain repetitions. Pool length is the
number of distinct projected values, not the number of source records.

References are zero-based nonnegative JSON integers. A caller reference
indexes that side's `evidence.callers`; a module reference indexes that
side's `evidence.modules`; an edge reference indexes that side's
`evidence.edges`. The namespaces are separate, side-local, and bounded by
their array lengths. Equal numbers on two sides do not identify the same
record or entity. Input IDs, caller incarnation, task cookie, and exec ID
are excluded from the output; indexes are report-local value references.

| Pool | Exact fields |
| --- | --- |
| Caller | `pid`, nullable `start_time`, `start_time_unit`, `image`, `lifecycle`, nullable `lifecycle_reason`, `first_seen_ns`, `last_seen_ns`, `retired` |
| Caller `image` | `authority`, nullable `exe`, `exec_observed` |
| Caller `image.exe` | `dev`, `ino`, `mtime_secs`, `mtime_nanos`, nullable `path` |
| Module | `paths`, `identity`, `admission`, `lifecycle`, `unloaded_observed`, nullable `unbound_use` |
| Module `identity` | `device` with `{major, minor}`, `inode`, nullable `sha256`, nullable `build_id`, nullable `source` |
| Module `admission` | `state`, nullable `class`, nullable `endpoints`, `reasons`, `note`, nullable `history` |
| Admission history element | `from`, `to`, `at_ns` |
| Module `unbound_use` | `first_ns`, `rows`, `reasons` (reason-to-count object) |
| Edge | Caller ref `caller`, module ref `module`, `mapping`, `entries`, nullable `coverage`, `semantics` |
| Edge `mapping` | `state`, nullable `evidence`, nullable `reason`, `first_seen_ns`, `last_seen_ns`, `interruptions` |
| Edge `entries` | `count`, `saturated`, `cap`, nullable `first_seen_ns`, nullable `last_seen_ns`, `in_flight`, `observation` |
| Edge `coverage` | `state`, nullable `since_ns`, nullable `until_ns`, nullable `first_ns`, nullable `lossy`, nullable `reason`, nullable `detail` |

All labels serialize as strings, including unknown labels; no `known` boolean
is emitted. Module paths and admission reasons are sorted and duplicate-free.
Detailed mechanism/operation fields are validated as supported input when
present but are not included in report pools or compared. Additive load-instance
and semantic-edge records are likewise not analysed or distributed across
physical edges. Each original edge's count remains separate.

## Comparison projections

`comparison` has `host_relation`, `boot_relation`, `process_continuity`, and
`physical_continuity`, all `unknown`; `counter_relation` is
`independent_windows`; `scope_relation` is `same_recorded_label` or
`different_recorded_labels`; and `application_paths` is a sorted, unique
array of exact nonempty executable paths on edges with known module digest.
Same scope labels do not prove equal actual scope.

All projection rows have `key`, `presence`, sorted `changes`, `before`, and
`after`. `presence` is `both`, `before_only`, or `after_only`, meaning observed
in both inputs, only before, or only after. Presence never means installation,
removal, or physical replacement.

- A `module_contents` key is `{sha256}`. `before` and `after` are sorted
  module-reference lists with one occurrence per contributing source module.
  Equal bytes at different inodes remain separate per-side evidence.
- An `application_changes` key is `{exe_path_ref, sha256}`.
  `exe_path_ref` indexes the shared `comparison.application_paths`, not a
  side-local pool. `before` and `after` are sorted edge-reference occurrence
  lists. `before_population` and `after_population` each contain `callers`
  and `modules`: refs from distinct contributing source rows before pooling.
  A source caller referenced by many edges appears once in its group
  population; two distinct source callers with identical projected facts
  appear twice as the same pool ref. Do not deduplicate those lists or
  derive source populations from edge count or pool length.
- A `module_path_changes` key is `{path}`. `before` and `after` are sorted,
  unique `{sha256}` descriptions, with null retained for unknown digest.
  A different set means different content descriptions observed at that
  recorded path, not proven file replacement. Its `changes` is
  `["content_presence"]`.

Change codes are `content_presence`, `paths`, `caller_population`,
`physical_records`, `admission`, `mapping`, `lifecycle`, `coverage`,
`entries`, and `semantics`. They describe variation in the supported
observation facts and their associations, never a paired entity's transition.
Comparison uses multisets of associated facts without guessing pairings or
summing counts across callers or physical modules. `caller_population`
includes recorded PID/start and executable metadata; it does not prove churn.

Absolute observation timestamps and capture-local IDs alone do not mark an
application changed. Coverage ending becoming known versus null remains a
coverage difference even though its timestamp value is not compared.
Recorded timestamps remain in the side evidence. Deterministic ordering and
ID normalization make source row/path reordering and consistent input-ID
renaming immaterial to the report.

`summary` contains `application_groups_compared` and
`application_groups_changed` (distinct executable paths, not change-row
counts), `content_both`, `content_before_only`, `content_after_only` (distinct
known digests), `module_paths_changed` (changed path rows), and
`unresolved_observations` (unresolved source records, with multiplicity).

## Unresolved and interpretation limits

Each unresolved row has `side` (`before` or `after`), `kind` (`caller`,
`module`, or `edge`), `reasons`, nullable caller ref `caller`, nullable module
ref `module`, and nullable edge ref `observation`. Module rows use
`missing_module_digest`; edge rows use `missing_executable_path` and/or
`missing_module_digest`; callers without edges use `no_module_observation`.
A missing-digest module and its edges may both contribute unresolved rows.
Paths and build IDs cannot repair a missing content digest.

Every report includes `absence_is_not_removal`,
`application_groups_use_recorded_paths`, `counts_are_independent_windows`,
`host_boot_continuity_unknown`, `physical_continuity_unknown`,
`process_continuity_unknown`, `scope_completeness_unknown`, and
`semantic_details_not_compared`. Inputs may add `unknown_clock_basis`,
`unknown_clock_unit`, and `unknown_start_time_unit`.

Recognized snapshot time is `CLOCK_MONOTONIC` in `ns`; caller start time
uses `clock_ticks_since_boot`. Unknown units retain raw numbers and the
corresponding limitation; `_ns` field names do not authorize conversion.
No cross-file timestamp, entry-count, gap-repeat, or budget-counter delta
is computed. Counts are lower-bound entries, including failing calls, not
completed operations or throughput. Witnessed use without a count, watched
no-use coverage, loss, saturation, and in-flight entries remain distinct.

Recorded executable paths group application observations for presentation;
they do not establish equal executable bytes, host, process, or deployment.
Digest equality identifies module content, not a physical file or load
instance. Explicit exit/unload facts describe only their own capture.
An unchanged projection never proves equal instance populations, detailed
semantics, compliance, or complete inventory. Not observed after does not
prove removal.

## Publication and exit status

Default stdout is plain readable text with application/module names and full
recorded paths; controls are escaped and long identities wrap at 80 columns.
The renderer resolves machine references for the reader. `--json` writes
one JSON document followed by a newline; decoded string data is preserved
through JSON escaping. Diagnostics go to stderr.

`-o` always saves the JSON report, regardless of stdout mode. Both inputs
are read and validated first. Output aliases of either normalized input
pathname or retained descriptor's device/inode are refused, including
hardlink/symlink aliases, before creation and again before publication.
The private 0600 temporary file is created beside the destination, fsynced,
and renamed under the existing trusted-directory and final-name checks.
Existing non-regular destinations and symlink directory components are
refused. Ancestors must satisfy the ownership/mode policy documented in
[usage](../usage.md#more-capture-options). This is not a path lock: replacement
between the final check and rename remains within that trusted directory's
same-owner write boundary.

Publication of `-o` precedes stdout. A broken stdout pipe exits 0 once any
requested file succeeds; another stdout failure exits 1, possibly after
the report was published. A stalled production stdout has the existing
inactivity bound. Differences, unknown evidence, and unchanged projections
exit 0. Input/schema/read/publication failures exit 1; usage errors exit 2.
Stdin (`-`) and `-o -` are unsupported. Use `--json` for JSON stdout, `--`
before dash-prefixed input names, and `./` before a dash-prefixed `-o` name.
