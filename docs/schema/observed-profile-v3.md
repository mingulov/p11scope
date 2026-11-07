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
classes (`gap_classes` and its three published inputs), row identity
(`functions[].target`, `functions[].ordinals`, table linkage `exports`),
the `modules_skipped[]` named-prefix delta below,
and per-provider mechanism counts (`mechanisms[].by_module`).

`modules_skipped[]` extends the inherited v2 row: a module new to a
shared-scope Detailed capture may attach in part, as a named partial
gap, instead of being refused whole. Such a module appears in both
`discovery[]` and `modules_skipped[]`; its `reason`
opens with the attached-vs-total counts — `A of N endpoints attached;
calls through the others are not counted (provider_prefix)` for an
ordinary provider, `M of N template tables attached; calls through
the others are not counted (closure_prefix)` for a late-start proxy
closure array, or `K of M template tables attached; calls through the
others are not counted (closure_published_only)` for an already-loaded
unnamed layer's published-only spill — rather than with `module needs`.
The whole-refusal (`module needs …`) and growth-omission
(`admitted module needs …`) openings are unchanged, and every kind —
whole refusal, growth omission, and any of the three named partials —
forces `PARTIAL`. The `inspect --system` catalog files a partially
admitted object under `refused` with the same named-gap reason; its
attached-vs-needed counts are in the reason text.

The inherited `functions[].latency_ns` timing-availability shapes also apply
to v3: counts has null timing, timestamps has measured total/max and null
percentiles, and latency retains the histogram object. A measured zero is
distinct from unavailable timing. These shapes do not change count authority
or combine aggregate and semantic-detail totals.

When a capture uses the prepared cumulative-counter reader, its evidence also
contains optional `counter_collection` metadata. Legacy captures omit this
object. Its exact keys are `mode`, `generation`, `read_window`, `status`,
`health`, `discontinuity`, and `failure`, plus an optional additive
`bank_gaps` object (`failed_slots` count with `health_failed`/`kernel_failed`
flags) that appears only when one bank's cells or evidence reads failed.
Exact counter reads omit `bank_gaps`. A gap read publishes the last good
snapshot as stale with the gap counts; only the first read of a generation
publishes its current rows, with zeros as unknown for the failed slots.
This is a v3-additive disclosure
that introduces no new schema revision. Mode and positive generation identify
the accepted native read. `read_window` is either the measured monotonic
`{started_ns, finished_ns}` interval or null when that interval is unavailable;
it does not assert an atomic snapshot. Cached display ticks keep the original
read window and do not acquire another native read.

`status: "fresh"` has null failure and accepted health
`{saturated: false, contended: false}`, except a fresh read with a health
gap reports null health (the health read itself failed). A failed attempt
retains the previous accepted rows, mode, generation, and window with
`status: "stale"`, null health, and a finite failure cause; observed
saturation or contention remains explicit as `saturated` or `contended`.
A generation change sets sticky `discontinuity`. A failure, discontinuity,
or `bank_gaps` object adds `counter_collection` to the observation gap
causes and requires `PARTIAL` with `verdict_detail: "concrete_gap"`.
An unavailable initial read cannot produce zero measurements. A failed
terminal read publishes the last good snapshot as stale with `PARTIAL`;
only a capture that never acquired a snapshot fails. This metadata
does not select a backend or add capture fields.

When a legacy (non-counter) aggregate read cannot read one slot's counters
or one kernel-evidence cell, its evidence also contains an optional additive
`legacy_collection` object. Exact legacy reads omit it. Its keys are
`unread_stats` (how many slots read zero as unknown), `rv_failed` (whether
the return-value table read failed), and `unknown_evidence` (finite names of
the unread evidence cells). Zeros in the rows are unknown, not exact,
whenever this object is present. Like `counter_collection`, it adds
`legacy_collection` to the observation gap causes and requires `PARTIAL`
with `verdict_detail: "concrete_gap"`. This is a v3-additive disclosure
that introduces no new schema revision.

When a metrics+counter capture carries an endpoint selection (`--select-endpoint`),
the terminal evidence also contains an optional additive `selected_detail`
envelope. Captures without the flag omit it. Its keys are `selection` (the
requested endpoint plus its resolved slot, or the named refusal when the
resolve attempt failed or the window voided), `events` (window and driver
rows in tick order), and the close products `lineage`, `aggregate`, and
`detail`, which are absent until a window closes with recorded detail
deltas. K0 windows render `aggregate` and `detail` and omit `lineage`.
The envelope never merges into `counter_summary` — aggregate and detail
ledgers stay independent, so promotion and demotion cannot double-count.
If any resolve step cannot complete, or the window voids (exec of the
watched process, slot retirement, capture loss, or an unclean close
boundary), the envelope names the refusal and the aggregate alone
carries the capture.

The envelope's nested shape is closed. `selection` always names `endpoint`
and carries `slot` together with `file_offset` exactly when the name
resolved, the slot group's `names`, and a finite `refusal` word
(`endpoint_unknown`, a `promotion_*` word or an adapter word; reports
written before K0 may carry the retired `bundle_unavailable`). A
resolved selection may still carry a refusal for a later step the host
could not complete. The selection record never publishes process
identity: there is no PID/TID field. `events` is always present
(possibly empty); each row is one closed shape — a window row
(`reserved`, `bound`, `cas_won`, `cas_refused`, `closed`,
`cancelled_unactivated`, with request/caller/provider/seq and an optional
note), a `close_refused` row (view, endpoint offset, gate word), a
`reserve_refused` row (adapter word, nullable seq), a `start_refused` row
(human reason word), or a `promotion_outcome` row (`refused`/`ended` with
the human reason word, `active` with the confirmed pair). K0 windows emit
no event rows. `lineage` joins one window to its broad rows (request,
view, endpoint offset, broad and detail generations, bracketing seqs and
marks, nullable drift, `after_read` matched/unavailable/`mismatched:*`).
`aggregate` renders the broad deltas over the window interval and
`detail` the selected slot's own broad cells over the same window; both
carry per-mode cells (counts bare, timestamps with totals, latency with
buckets) and never a combined total.

When a Detailed capture's semantic lane discloses a global-only instance
continuation, the terminal profile-lane evidence also contains an
optional additive `instance_reload_not_excluded` object. Captures
without a disclosing producer omit it (absent, never zero or null).
The key projects the capture's staged coordinator ledger at the
terminal evidence; a capture whose path stages no semantic lane (the
profile loops stage none) omits it. The metrics lane never carries
it, and the terminal trace `EVIDENCE` object carries it under the
same rule. When the router counted tainted
continuations but minted no identity to name (mint exhaustion), the key
is still present with the exact snapshots and an empty `identities`
list: the router is the producer then, so absent-never-zero does not
apply. The `identities` entries may also be incomplete while the
snapshots stay exact when the capture discloses a "reload disclosure
identities shed" gap: past an accumulator cap, identities shed
(counted) but the router totals still merge. Its keys are
`continued_across_global` and `joined_across_global` (the
capture-monotonic router snapshots: tainted continuations observed and
calls joined through a tainted entry) and `identities` (one entry per
tainted identity, in `(file_slot, ids)` order; empty under mint
exhaustion). Each entry names the
watched `file_slot` and the continued capture-local instance `ids`.
Entries carry no task cookie, exec id, epoch, range or address: the
private image key groups the ledger but never renders. The key is
informational only: it never feeds shares, verdicts, `gap_classes` or
`completeness`, and never forces `PARTIAL`. Like `selected_detail`, it
is a v3-additive disclosure that introduces no new schema revision.

When a capture passes `--exclude-module`, its evidence also contains
optional additive `excluded_modules` and `unmatched_excludes` keys.
Captures without the flag omit both. `excluded_modules` lists one row
per distinct excluded file with `path`, `dev`, `ino` (the opened file's
fstat identity) and `processes` (how many in-scope processes mapped
it); `unmatched_excludes` lists the inputs that matched no mapped
file, in operator order. Like the disclosure above, these keys never
feed shares, verdicts, `gap_classes` or `completeness`: excluded
modules are a declared choice, not a loss, and the rest of the capture
can still be `exact`.

When a capture passes `--forwarding-module`, its evidence also contains
the optional additive `unmatched_forwarding` key, listing the inputs
that matched no mapped file, in operator order. Captures without the
flag, or whose every declaration matched, omit it. Like the keys above,
it never feeds shares, verdicts, `gap_classes` or `completeness`.

Under the default `allowlisted` policy, every emitted mechanism has
`params: null` with `params_omitted: "policy"` beside it, and
`templates.operations` is always empty. Every `params: null` carries a
`params_omitted` cause (`policy`, `no_shape` or `decode_failed`); the field is
absent when `params` is an array. The diagnostic
parameter/template representations in the inherited schema are not default
capture promises. Missing metadata is not evidence that the application used
none. Scan-only function slots remain semantics-unverified/count-only; an
accepted explicit manifest attests only its exact object/name/offset claims.

Every `mechanisms[]` entry carries `registered`: `true` for an id the
BPF return path found in `MECH_SHAPE`, `false` for an unregistered
publication. Unregistered ids are public constants, so v3 documents
list each 32-bit one as a bare hex number with its call/error counts
(`params: null`, never decoded, never named) instead of only the
`evidence.unregistered_mechanisms`
total, which still counts every occurrence. Ids above `0xFFFFFFFF`
count in the total only. Like `selected_detail`,
this is a v3-additive disclosure that introduces no new schema
revision; historical v2 documents list registered ids only and lack
the `registered` key. `cgroups[].mechanisms[]` rows carry the same
`registered` flag with the same meaning.

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
  `attach_mechanisms`, `pid_descendant_gaps`, and
  `multi_rebuild_gaps`. Its
  verdict is selection-aware: a descendant gap, a rebuild gap, or any
  selection loss forces `PARTIAL`.
- The **metrics** lane (`render::json`, verdict
  `verdict_with_selection(false)`) embeds `Evidence` directly, so the four
  `#[serde(skip)]` profile-only fields above are absent. Its verdict is
  selection-blind by construction: the same capture that reads `PARTIAL` as
  profile over a descendant gap reads `COMPLETE`-eligible as metrics, with no
  contradiction — the metrics verdict never saw the selection state.

Both current v3 lanes include `attach_backend`: the existing Session's
`selection`, `fallback`, and `scope_filter` metadata. This disclosure does not
add selection verdict authority to metrics. Historical v2-metrics documents
retain their old shape without `attach_backend`.

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
  `unresolved`. The historical absence labels both describe a known absent
  optional export; neither asserts a provider-version requirement. Current
  captures emit `legacy_absent` for known absence regardless of table metadata.
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
one match. Count-only authority has no match and requires a successful query
with a non-null table observation whose targets passed identity and ABI checks.
Names, version labels and returned flag classes do not decide count-only
support. A null table cannot authorize counts; an unreadable version header
can coexist with individually validated function targets. Unknown API names
remain `unknown`, with the observed ordinals preserved.
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

`unpublished_mechanisms` is a u64 count, always present: approved mechanism
ids the `MECH_SHAPE` publication could not fit. When the approval union
(the official PKCS#11 3.2 catalog plus the configured registry) exceeds
the map's 1,024 entries, the session publishes the official catalog first
and then registered ids in ascending order up to the cap, instead of
refusing to start; this count gaps the unpublished tail. Unpublished ids
count through the existing unregistered path (counted, never decoded),
and render-side shape notes are computed over the published subset only.
With the shipped registry the count is 0. Nonzero forces `PARTIAL` with
the `unpublished_mechanisms` attribution cause.

`attach_backend` is always present in both v3 lanes and says how the session
chose its static attach backend, as
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

`object_capture` is always present in both v3 lanes and says whether this
build captures object attributes (build scope, identical for every capture
of the binary). It never gates the verdict — P0 scope is complete when P0
facts are complete; this disclaims attribute coverage instead of claiming it:
- `available`: boolean; `false` in v0.4.0 stub builds, `true` in FULL builds.
- `reason`: finite machine reason when unavailable, else `null`. The one
  v0.4.0 reason is `not_enabled`: the stub feature compiled attribute
  capture out.

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

`gap_exe_hints` is present if and only if the capture armed extensive
mode (`--track-short-lived`) over a `--cgroup`/`--system` scope;
otherwise the key is absent, never null. The trace, profile and
`--mode metrics` lanes all publish it there. On exact-`--pid` and
owned-`run` captures the flag arms the PID consumer instead (see
`target_exec_hints` below) and this key stays absent.
It classifies the novel unmatched-exit subpopulation of
`pid_descendant_gaps` (admissions and overflow sentinels carry no hint)
into finite static-linkage classes: `links_provider` (the dead
executable names a pinned watched provider within two `DT_NEEDED`
steps), `links_pkcs11_loader` (it names `libp11-kit.so.0`),
`no_static_link_within_scope` (the in-scope needed set completed with
neither), and `unknown` (unverifiable or over budget — never a partial
result presented as complete). Every publication carries
`"label": "STATIC HINT"` and the scope string
`"D-transitive depth=2 objects<=32 edges<=128 exe-bytes<=1MiB
capture-bytes<=64MiB names<=255B verdicts<=1024"`. The four counts are
saturating u64s summing to the analyzed subpopulation, never to
`pid_descendant_gaps` itself. Under `--mode metrics` the
`pid_descendant_gaps` denominator key itself is absent
(profile-only); the split still classifies the same subpopulation.
Hints are never calls, never verdicts,
never merged into call or attribution shares, and settle no birth,
admission, absence, or call (R57). `dlopen`-only provider use is
invisible by design and reads `no_static_link_within_scope`.

`target_exec_hints` is present if and only if the capture armed
extensive mode over exact-`--pid` scope (trace/profile/metrics
`--pid` or owned `run`); otherwise the key is absent, never null.
On `--cgroup`/`--system` captures this key stays absent (no single
target exists there). It classifies the
validated-target-exec subpopulation — exactly one hint per target
exec matched to the live retained target — into the same four
static-linkage classes with the same `STATIC HINT` label, scope
string, saturating-u64 counts and hint discipline as `gap_exe_hints`.
Unvalidated execs are outside the subpopulation and add no count, not
even `unknown`. A zero split means no validated target exec was
observed, never "no provider use".

`gap_exit_mappings` is present when the capture armed extensive
mode over a `--cgroup`/`--system` scope in the trace or profile
lane; absent, never null, otherwise. Unlike `gap_exe_hints`, it
never publishes under `--mode metrics`: instance hooks never
attach there, so the exit map never arms — use profile/trace for
`mapped`. It
splits the same novel unmatched-exit subpopulation of
`pid_descendant_gaps` (admissions and overflow sentinels carry no
verdict) by the kernel's exit-time answer: `mapped` (the kernel
recorded a localized mapping of a watched provider file by the
exiting leader at some point while watched, with no disqualifying
refusal; the cells persist across unmap and exec, so this never
means the file was still mapped at the exit instant) and `unknown`
(no record, shared mm, refused hooks, late watch, local fault, or
empty slots). It is a kernel observation, not a static hint, so
it carries no label or scope: the
value is exactly `{"mapped", "unknown"}` as saturating u64s summing
to the classified subpopulation, never to `pid_descendant_gaps`
itself. Multi-threaded exits read `unknown`: a process with more
than one mm user never localizes its mappings, so its empty slots
are not a negative. A late watch (inserted between the process's
exec and its exit) reads `unknown` for the same reason: mappings
established before the watch are invisible. The two counts never
feed calls, callers, shares, verdicts, or births, and an exit never
settles a call (R57). There is no "did not map" publication: nothing
here proves a process did not map a watched provider.

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

## Pre-arm watch keys on `evidence.discovery[]`

Modules named by `--prearm-module` (packet 6.13) carry `watch`; only
`watch` is pre-arm-only. `attached_at_ns` and `unobserved_windows` merge at
evidence assembly onto every module with attach stamps, including generic
captures without pre-arm watches (a module that missed the initial build
discloses `late_discovery`). `sources` gains the one new label
`"prearm"` (canonical order `scan`, `manifest`, `prearm`); pre-arm-only
modules read `corroboration: ["uncorroborated"]`, and pre-arm never emits
decoded tables. `watch` is `{since_ns, state, until_ns?, ended_by?,
changed?}`: `state` is exactly `pinned_unarmed`, `armed`, `armed_idle`,
`unavailable`, or `ended`; `since_ns` is always present (null until armed);
`until_ns`/`ended_by` appear only when the end actually happened
(`ended_by` is exactly `attached`, `scope_end`, `stop`, `object_changed`,
`health_loss`, or `scope_uncertain`); `changed` is the
`{last_ok_ns, detected_ns, previous_ino}` uncertainty bracket.
`attached_at_ns` is null or a `CLOCK_MONOTONIC` instant, merged at evidence
assembly from real attach-complete stamps. `unobserved_windows` is a list of
`{start_ns, end_ns, reason}` with `reason` exactly `pre_attach`,
`late_discovery`, `mapped_unattached`, `health_loss`, or `scope_uncertain`;
absent means undisclosed, and an explicitly empty list reads as exact only
with an R2-D1-6 proof behind it. Key presence never proves exactness. The
pause-gate proof ships for owned `run` only: `[]` appears on a pre-armed
module only when every declared probe attached at or before the barrier
release while the child was barrier-held from its start — the spawn barrier
from start to release, then the pause gate's frozen first hold (continuous,
both bounds clocked, every member stamped, every first-stamp at or before
the release) — and the window stays in every other capture, including any
declared stamp dated after the release (the child may run its command
before the first *verified* pause stop). The
ordering-evidence proof ships for `profile` and `trace` (`--pid`, `--cgroup`,
`--system`; detailed and `--mode metrics` policies): `[]` appears on a
pre-armed module exactly when the mapping-instant witness finalized `Clear`
for the object's slot with its hooks active strictly before the scope start,
the witness fd matching the pin's held fd, and the finalize walk starting
after the declared set's attach instant. `run` carries no ordering-evidence
proof (the witness is inert there; owned holds keep the pause-gate proof),
nor does inventory; the window stays wherever any condition refuses. The
empty list asserts only the pre-attach span; a later loss still discloses on
`watch` (`ended_by: health_loss`) without reopening it.

## Copy-up layer marker on `evidence.discovery[]`

When a capture observes an overlayfs copy-up pair — the same merged path
mapping two kernel files, the stale pre-copy-up lower file and the fresh
upper file, with the kernel VMA witness proving which mapping runs which
bytes — `discovery[]` carries one row per file. Both rows publish the
merge path; each carries its own file's `{dev, ino, sha256, build_id}`.
The lower file's row additionally carries `"layer": "pre_copy_up"`; the
key is absent on every ordinary row. `functions[].module` joins to either
row by identity, so stale-mapping calls count on the lower edge and fresh
calls on the upper edge. `capture.modules[]` stays the identity-only
projection and carries no `layer` key. The lowerdir host paths that
produced the lower candidates are never published. Verbose text marks the
lower file's function rows `(file before copy-up)`; concise text shows
the same counts unmarked.

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
  an unaccounted loader hit — `loader_discovery.hits` above `benign_hits` —
  and `pause` other than `sigstop`), and `module_unresolved_slots` (the
  number of `functions[].module_unresolved` rows) are the three verdict
  inputs that were previously unpublished.
- Static detach history uses the existing `skipped` record with name
  `discovery subject` and one of two fixed reasons: `static probe coverage gap
  incomplete` or `static probes detached and exact pairs reattached`. The first
  includes open or clock-unknown intervals; the second requires all affected
  exact pairs and comparable clocks to have completed. Both retain observation
  loss through the `skipped` cause after recovery. They carry no missing-call
  count or per-provider/per-call interval and do not change
  `unprotected_live_windows` or define a previously unknown `attach_gap_ms`.
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

## Initialize claim on `functions[]` rows

Every `functions[]` row that names `C_Initialize` and has at least one
positively counted return carries an optional `initialization` object,
rendered in both the profile and metrics lanes under every counter mode
from the row's own `rv_counts` at render time — no new read, no new
retention:

- `outcome` is the outcome class over that row's completed calls: `ok`
  (every counted return was `CKR_OK`), `already_initialized` (every
  counted return was `CKR_CRYPTOKI_ALREADY_INITIALIZED`), `error` (every
  counted return was anything else, `CKR_PENDING` included — the outcome
  vocabulary has no pending word), or `mixed` (more than one class
  occurred). Zero counts assert nothing observed and are ignored.
- `potential_provider` is present and `true` exactly when at least one
  completed call returned `CKR_OK` or
  `CKR_CRYPTOKI_ALREADY_INITIALIZED`: the row's module answered as an
  initialized Cryptoki at least once. It is a likelihood, never proof of
  provider identity — a stub that returns `CKR_OK` qualifies — and it
  carries no operator attestation.

The claim is row-scoped: an aliased row that names `C_Initialize` among
its names reports the row's own outcomes without splitting counts into
guessed per-name shares. Rows that do not name exactly `C_Initialize`,
and Initialize rows without positively counted returns, omit the key
(absent, never null or false): absence means Initialize was not
observed on that row (unknown, per OD35). The live function table marks
qualifying rows `[init: <outcome>]`; the PROVIDER column beside it names the
row's file.

Like `selected_detail` and `instance_reload_not_excluded`, this is a
v3-additive disclosure that introduces no new schema revision: the
`functions[]` item shape stays open and the key stays optional.

## Return-code names on `functions[]` rows

Every `functions[]` row carries `rv_names`: the `CKR_*` names for the
row's `rv_counts` keys that have a registered name, keyed by the same
16-digit hex strings (`"0x00000000000000a0": "CKR_PIN_INCORRECT"`).
Unregistered (vendor) codes are absent from `rv_names` — their
`rv_counts` hex key is the verbatim rendering, never a guessed name.
`rv_names` is always present (possibly `{}`) in both lanes; it is
render-time presentation of the already-captured full-width `CK_RV`
values through the same lookup trace lines use. `rv_counts` is
unchanged, and like `initialization` this introduces no new schema
revision: the `functions[]` item shape stays open.

The live text report explains each row's ERR count the same way: an
`ERROR REASONS:` section after the function table lists one
`NAME: CKR_X xN, …` line per function with errors, in table order.
Concise text keeps the top three reasons by count with an `and N more`
tail; `-v` lists every distinct code. `CKR_OK` and `CKR_PENDING` are
never reasons. A function with errors but no error breakdown in
`rv_counts` (the return-value table read failed) reads
`NAME: N errors (return-code breakdown unavailable)`: a named gap,
never a stopped view. Captures without failures render no section.

## Forwarding-layer split on `functions[]` rows

Every `functions[]` row carries `forwarding_layer` (boolean, always
present): true when the row counts calls at a forwarding layer (a
closure array admitted beside watched providers), false for provider
rows. The split needs an active provider in the same capture (a
non-layer row with a non-null module and a call, an error, or an
in-flight entry) and no refused backend; otherwise the layer's rows
read `forwarding_layer: false` and stay in the totals. One logical call
observed at both layers counts once, in the provider row; the forwarding
row stays explicit beside it. Consumers that sum `calls` across rows must
skip `forwarding_layer` rows to count logical calls once.
Layer-self-answered calls, including their errors, appear only in the
forwarding split, and one layer call reaching several providers counts
at each.

Top-level `layer_totals` (always present in both v3 documents, metrics
and profile) splits the same totals: `logical` (provider calls, errors
and in-flight, counted once) and `forwarding` (forwarding-layer calls,
errors and in-flight, never summed into logical). Single-layer captures
read `forwarding` zeros with both layers' rows labelled. Like
`selected_detail`, this is a v3-additive disclosure that introduces no
new schema revision: the `functions[]` item shape stays open.

## Per-provider mechanism counts

Every `mechanisms[]` row carries `by_module`: the row's `calls`/`errors`
partitioned by provider module, one entry per sole-owner module in
module-id order, each `{module: {dev, ino, sha256}, calls, errors}`.
`module` is the same reference `functions[].module` uses, resolved
through the document's discovery list.

Entries cover the attributed subset of the row: observations on slots
with no sole owner (unclaimed slots, or doubly claimed slots, which
are count-only and record nothing at all), or whose owner the
discovery list does not name, count in the row totals but in no entry —
entry sums never exceed the row. The error rule matches the row
(nonzero non-PENDING `rv`; PENDING diverts to the async queue
upstream and its completion is recorded once with the final `rv`),
so a fully attributed row partitions exactly. Each
entry takes one key from the capture's shared monotonic
semantic-state budget; a refused entry records nothing and counts the
usual `semantic_state_drops` gap.

The breakdown derives from two already-captured facts — the v1
mechanism ids and the slots' sole-owner attribution — with no new
capture; see the allowlist-v3 derived-count row. Metrics documents
carry no `mechanisms[]` and gain nothing here. Like the
forwarding-layer split above, this is a v3-additive disclosure that
introduces no new schema revision: the `mechanisms[]` item shape stays
open.

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
number or cgroup path. `run` reports `cgroup` for its dedicated tree scope
and `pid` when it degraded to its exact child. The evidence object keeps
its closed exact key set; this addition touches the `capture` section only.

## Completeness and terminal trace

Any truncation, uncovered provider, export status other than `present`,
`legacy_absent` or historical `required_absent`, count-only tuple, successful tuple with `none` authority,
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

## Never-stop gap reasons

`evidence.skipped[]` gains three finite reasons (in addition to the v2 list).
Each record is `{name: "discovery subject", reason}` with `reason` exactly one
of:

- `manifest object unavailable`: one `--manifest` object could not be pinned
  (unreadable, changed during hash, identity-mismatched with no scanned
  replacement, out-of-segment offset, or over the shared byte budget). Good
  sibling objects still pin; the capture continues and reads `PARTIAL`.
- `prearm object unavailable`: one `--prearm-module` path could not be pinned.
  Good sibling paths still pin; the capture continues and reads `PARTIAL`.
- `discovery transport unavailable`: one live discovery-ring dequeue failed
  after a prefix was already pulled. The prefix is applied, the failure is
  counted here, and the capture continues to the next tick.

Run-tree scope gaps file under their own subject. Each record is
`{name: "run process tree", reason}` with `reason` exactly one of:

- `process-tree members were still present when the command exited;
  their calls after the run end are out of scope`: the run ended while
  tree members were still present; they were handed back alive and
  their later calls are out of scope.
- `only the started command is observed`: the run cgroup could not be
  created, placed, or scoped, so the run degraded to its exact child.
  The failed step and I/O kind print on stderr; the report keeps the
  fixed reason.
- `handed-back descendants are unknown`: the run cgroup membership
  could not be read at run end.

`evidence.run_tree_handed_back` (integer, `run` documents only, required
there) counts the handed-back survivors: measured zero when the tree
retired cleanly. It is annotation only — the paired `run process tree`
skip carries the verdict through the `skipped` cause, like every other
non-null-pointer skip.

Counts are array lengths; no path, PID, or error chain leaves diagnostics.

`evidence.pause_unavailable` (integer, required, default 0) counts `--pause
always` degrades that collected unpaused instead of aborting. Each forces
`PARTIAL` via the `pause_unavailable` gap cause; `evidence.pause` reads
`partial` when either `pause_partial` or `pause_unavailable` is nonzero.

`evidence.pause_engine_incomplete_retirements` (integer, required, default
0) counts `--pause auto` chains that retired after four straight
engine-incomplete cycles. Each retirement is already one counted
`pause_partial`; the count is a subset annotation (never above
`pause_partial`), so JSON consumers can tell a retired chain from
scattered partials.

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
