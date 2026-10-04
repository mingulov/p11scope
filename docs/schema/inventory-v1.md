<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# `p11scope/inventory/v1`: module/caller inventory

Answers "which module is used by whom" for one scope (`--pid` or
`--system`) over one snapshot pass or a `--duration` observation window.
Emitted by `p11scope inventory [--json | -o <out.json>]`.

Consumers must dispatch on the exact `schema` string
(`p11scope/inventory/v1`). There is no semver-style compatibility:
a new schema id means a new contract. Within v1, additive evolution
only — new optional fields and new enum labels, each documented here
(a label this document does not list must be read as unknown) —
never a changed meaning for an existing field.

## PID numbering

`pid_namespace` (additive within v1) is the same object capture evidence
carries: `{"observer": "initial" | "nested" | "unknown", "kernel_pids":
"initial", "proc_pids": "observer" | "foreign"}`. Every PID in this
document (`callers[].pid`, `gaps[].pid`) is read through `/proc`, so it is
in the numbering `proc_pids` names; it equals the kernel's initial-namespace
PID only when `observer` is `initial` and `proc_pids` is `observer`.
`inventory --pid` is refused (`pid-namespace-mismatch`) otherwise, and
`inventory --system` then also carries one scope-level gap (`caller`,
`module` and `pid` null, `subject` `pid namespace`) from its first pass on,
so a consumer reading only `gaps[]` still sees the incompleteness: the scan
sees only the processes the mounted `/proc` shows (in a nested namespace the
host's processes are invisible, so a module only they map is never
discovered), and callers that load a module after a scan pass can be
missed. See `docs/usage.md`, PID namespaces.

## Usage lane, settlement and retirement

`inventory --capture auto|scan|native` (default `auto`) picks the usage
lane. The scan lane reads `/proc` only: its document is exactly the one
this schema always described, every edge's usage coverage reads `unknown`
(`scan_only` or `not_admitted`), and the three keys below are absent.
`auto` runs the native lane when it can start and otherwise the scan lane
plus one scope-level gap (`caller`, `module` and `pid` null, `subject`
`native usage feed unavailable`, the reason in `reason`).

A native document adds to `observation`:

- `lane`: `"native"`.
- `settlement`: always `"unsettled"`. The Inventory object has no
  quiescence protocol, so a call in flight when the capture stopped may
  have left no witness row: absence of use is claimed only through
  `watched_no_use` intervals, which end at the last clean read before
  stop (`until_ns`), never through the stop itself.
- `retirement`: `"closed"` when every probe link had its close attempt
  within the stop budget (5 s plus 150 ms per per-offset link, or plus
  100 ms per uprobe-multi link and 10 ms per entry in it; at most 10 s),
  `"unsettled"` when the budget passed first; then `gaps[]` also holds
  `subject` `native capture retirement unsettled`, and the probes are
  reclaimed (blocking) after the document is written.
- `attach` (additive): how the native lane attached the provider entries.
  - `selection`: the operator's `--attach-backend`, `"auto"`, `"multi"`
    or `"singles"`;
  - `mechanism`: `"uprobe-multi"` (one immutable link per provider object
    per extend, chosen by a functional probe) or `"per-offset"` (one link
    per entry), spelled as the classic `evidence.attach_mechanisms`;
  - `fallback`: why `auto` runs `"per-offset"` (the probe or the
    uprobe-multi preparation failed), else `null`;
  - `scope_filter`: under `--pid`, what keeps other processes out besides
    the in-BPF PID guard: `"kernel-pid+bpf"` (the uprobe-multi links name
    the target; the kernel pid filter was proven to cover every thread)
    or `"perf-task+bpf"` (each per-offset link is bound to the target's
    task); `null` under `--system`.
- `lifecycle`: the lifecycle feed's own account. The native lane drains
  the kernel's lifecycle (exec and exit) ring every 10 ms, including while
  a pass collects `/proc` on a worker thread; it stages what it drained
  after that pass's scan, in drain order.
  - `records`: lifecycle records drained;
  - `ring_loss`: records the kernel could not queue because the ring was
    full, as counted at the last readable health read;
  - `malformed`: malformed records;
  - `failed_quanta`: drains stopped by an undecodable record;
  - `recovery_rescans`: passes started at once, without the interval,
    because a loss was found. A recovery rescan is never followed by
    another. It admits what the lost records would have announced; the
    loss itself stays: the `native capture lifecycle evidence lost` gap
    and its demotion apply for the rest of the capture.

In the native lane an admitted edge no coverage note reached reads
`not_attached`, never `scan_only`. When the observer's `/proc` numbering is
not the kernel's (`pid_namespace`), native `--system` still binds witnesses
(through pidfd cookies, never PID numbers) but never claims a watch: every
admitted edge's coverage is `unknown` (`loss`) with a gap saying why.

## Privacy

Owner ruling FB-PRIV (2026-10-03): the document publishes each caller
incarnation's `pid`, `start_time` and `image.exe` (`dev`, `ino`, `mtime_*`
and `path`), read from `/proc/<pid>/stat` and `/proc/<pid>/exe` of processes
whose mappings hold a provider object — reads the scan lane already makes.
The native lane adds none: its witness rows bind through a pidfd cookie
query, and no witness gap carries the kernel tgid. No command line,
environment, `comm` or argument is read or published. See the inventory
caller identity row of [privacy allowlist v3](../privacy/allowlist-v3.md).
`callers[].image.task_cookie` and `.exec_id` are always null in v0.2.0
(`owner_image` returns `None` everywhere in production); only a future
lane returning exact owner images would fill them, and publishing
non-null values needs a new allowlist row.

## Clock and units

- `clock.basis` is always `CLOCK_MONOTONIC`; `clock.unit` is always `ns`.
  Every `*_ns` timestamp is nanoseconds on that clock.
- Caller `start_time` is raw `/proc/<pid>/stat` starttime in
  `start_time_unit` (`clock_ticks_since_boot`), for incarnation
  comparison only — never wall time.
- Entry `cap` is `18446744073709551615` (`u64::MAX`): counts saturate
  there and set `saturated`; they never wrap.

## Model

- `callers[]`: one record per caller *incarnation* — one (pid,
  start-time) generation running one executable image. `id` (`c0`,
  `c1`, …) is stable for the capture, minted monotonically, never
  reused: PID reuse and exec retire the old incarnation (evidence
  retained) and mint a new one. `image.authority` is `native_exact`
  (BPF task-cookie/exec-ID identity) or `scan_pinned` (pidfd/start-time
  pin with exe-identity exec detection); `exec_observed` is false when
  the exe identity was unreadable and exec changes were undetectable.
  `lifecycle` is `mapped`, `exited`, `exec_retired`, or `unknown`
  (with `lifecycle_reason` whenever the state is not plainly mapped).
  Under `--system`, every process with attributable mappings registers
  as a caller on every pass, whatever `--max-scan-pids` is: a process
  the deep-scan cap left unselected registers when its `/proc/<pid>/maps`
  shows, by exact `(device, inode)`, a provider object a deep scan of
  another process pinned in the same pass, and every such mapped range
  is proven to be that very file (a *maps match*, below). The
  cap bounds only how many processes are deep-scanned, i.e. the
  discovery of objects no process seen so far maps. A collected member's
  mappings project onto a caller only when its generation joins the
  incarnation reconcile holds for the pid: equal start times (both
  present), and for a maps match equal exe identities (both present; a
  deep scan refuses only when both were read and differ). Members that
  fail the join are not projected (their existing edges read
  `uncertain`) and are counted in one `caller generation join refused`
  gap per pass by category (`generation_changed`, `exec_changed`,
  `confirm_unreadable`).
- `modules[]`: one record per distinct physical module instance,
  keyed by (device, inode, SHA-256) — never by path. Two callers
  mapping different objects at the same path are distinct records;
  the path list is an attribute. `admission` carries the scan-only
  verdict (`admitted`, `refused`, `unresolved`) with class, endpoint
  count, and reasons, plus the scan-only note: manifest corroboration
  was not consulted. The run's attach set is the only admission
  source: `admitted` means the attach set holds the module's
  endpoints for this run. An object the attach set never judged (no
  comparable pin or digest) never reads `admitted` — the catalog's own
  admission is not taken over: it reads `unresolved` (or the
  catalog's `refused`, since nothing attaches either way) with a
  reason saying the attach set did not judge it. Within that one
  source the verdict only rises (`unresolved` < `refused` <
  `admitted`) and never falls back, so a module the attach set admits
  after a first refusal reads `admitted` — an instrumented module never
  reads `refused`; a lower later verdict is not applied but is
  disclosed in `reasons` (deduplicated, at most 8 entries).
  `admission.history` (additive within v1) lists each rise as
  `{from, to, at_ns}` in order (`[]` while the first verdict stands, at
  most two entries), and each rise is also a `module admission changed`
  gap. The verdict is judged against the Inventory
  endpoint budget (4096 endpoints), not the 512-slot detailed ceiling
  `inspect --system` reports, so the two can disagree either way: an
  object `inspect` refuses can read `admitted` here, and one it admits
  can read `refused` here. Each pass lowers under that budget with the
  same shared-scope reserve `inspect` applies (uncorroborated providers
  — unlinked heuristic tables, proxy closure arrays — take at most 3072
  of the 4096), and endpoints admitted earlier in the run stay counted
  for the whole run: an endpoint ID is never reused, so a module can be
  refused once earlier modules hold the budget. Refusals by the run's
  attach set — the run-lifetime endpoint or module-record budget, an
  object that could not be resolved or retained, and a module whose
  object changed identity since its endpoints were taken — are also
  recorded in `gaps[]` (`inventory attach set refused module`, or
  `inventory attach target changed identity`), once per module and
  refusal kind (bounded: past the bound one `inventory attach set
  refusal gaps bounded` gap is recorded and later refusals live in
  their verdicts only); a refusal by one pass's lowering reads `refused` with
  its reason and no gap.
  `lifecycle` is `mapped`, `unloaded` (a complete rescan proved it
  gone; sticky in `unloaded_observed` even across a reload), or
  `unknown` (no live mapping evidence remains).
  `unbound_use` is `null`, or `{first_ns, rows, reasons}`: native
  witness rows of this module that no caller edge carries — positive,
  monotonic module-level use, never attributed to a caller by pid.
  Only a row whose witness endpoint belongs to this one admitted module
  counts here; each row counts on at most one module. `first_ns` is the
  earliest row's first-association instant, `rows` the row count, and
  `reasons` counts rows per reason code: a binder reason (see
  `observation.native_witnesses`) or `no_mapping_edge` (the row bound to
  an identified caller incarnation that has no mapping edge to this
  module; a witness never invents a mapping). The first binder-reason
  row of a module records one `used by an unidentified caller image`
  gap; a `no_mapping_edge` row records instead a `native witness without
  mapping evidence` gap naming the caller (once per caller and module).
  Witness gaps never carry a `pid`: an unbound row's tgid is exactly
  what could not be identified.
  Boundary: the key is file identity, not load-instance authority —
  a same-file double-load (two loader mappings of one file, notably
  a `dlmopen` private-namespace double-load whose objects own
  distinct PKCS#11 session namespaces) merges into one record and
  one edge per caller. When the scan evidence shows the double load
  (duplicate executable file-offset coverage in the caller's
  process), the edge latches: its semantics read `unknown (same-file
  double-load)`, its calls establish no claim, and the `same-file
  double-load detected` gap names it; without that evidence the
  merge carries no marking. For `dlopen` in one namespace the merge
  is correct (same file → same loaded object → one session
  namespace); per-instance separation for `dlmopen` is S2 scope
  (instance authority — see `docs/notes/s2-instance-authority.md`).
- `edges[]`: one record per (caller incarnation, module instance)
  pair. `mapping` is scan evidence (state `mapped`, `ended`, or
  `uncertain`, with first/last seen and an interruption count of
  observed mapped→absent→mapped transitions). `mapping.evidence` says
  how the latest mapping observation was established: `deep_scan` (a
  deep scan of the caller decoded it) or `maps_match` (the caller itself
  was not decoded: its maps, re-read under a pidfd/start-time pin with
  its exe identity unchanged across the read, show the object's
  `(device, inode)`, and — because a maps key is not one file (btrfs
  renders one device for every subvolume while inode numbers repeat
  across subvolumes) — each such range's `/proc/<pid>/map_files` entry,
  read while the pin holds, is the same kernel file as a self-mapping
  of the object the deep scan pinned and still holds open. Both sides
  are the kernel's mapped file as procfs renders it, never `fstat`
  (overlayfs has installed the backing file in the mapping since Linux
  4.19; before about 6.8 procfs renders that backing file, which
  `fstat` of the overlay path never shows, and from then on it renders
  the overlay file). Following `map_files` needs `CAP_SYS_ADMIN` or
  `CAP_CHECKPOINT_RESTORE`; without it nothing is attributed by maps).
  Two races are accepted, and both can affect only whether the
  inventory is marked complete, never an edge: the per-range
  `map_files` stats of processes that match no pinned object run
  without a pidfd/start-time pin, and the identities of examined
  (scanned, not-a-provider) objects come from the deep scan's read and
  are not held open afterwards.
  The per-range `map_files` stat is skipped for one kind of key: the
  held object's own self-mapped identity equals the key's
  `(device, inode)` and that mapping's filesystem is ext2/3/4, XFS,
  squashfs or EROFS, where one device and inode numbers that no two
  live files share make the key that file everywhere. tmpfs (32-bit
  wrapping inode numbers without `inode64`), btrfs, overlayfs (as
  rendered from 6.8 on), bcachefs, FUSE and network filesystems always
  prove every range.
  Nothing about a confirmation or a proof is carried from one pass to
  the next: every pass re-reads a matched caller's maps inside its pin
  and re-reads every range that needs the proof. An identical maps line
  is not the same file across a pass (btrfs: another subvolume's file
  at the same address and path; ext4 and other identity filesystems: an
  unmapped file's inode number reused at once by a new file). An
  unmatched process whose examined range is no longer one mapping when
  it is read (unloaded, remapped or exited since the sweep) is confirmed
  the same way, so its fresh read decides rather than an unexamined
  count.
  Absence is authoritative (`ended`)
  only after a complete deep scan of the live caller: a module missing
  from a maps match reads `uncertain`. A maps match never comes from a
  ` (deleted)` mapping, an overlay-collapsed or aliased key, a rejected
  key, or a filesystem whose inode numbers are not unique (FUSE,
  network filesystems). `entries` is usage
  evidence from observed entries only: cumulative `count` plus
  first/last seen, an in-flight flag, and `observation` —
  `observed`, `unknown (not admitted)`, `unknown (usage observation
  unavailable)`, `unknown (count unavailable; use witnessed)`, or
  `unknown (usage observation lossy)`. A zero count with an `unknown`
  observation is not a fact about usage; a caller with zero observed
  entries is "mapped, quiet", never "active". Recency ("active now")
  is last-seen plus in-flight state, never a sticky bit; last-seen
  comes only from counted entries.
- `edges[].entries.coverage` (additive within v1): what this edge's
  usage columns can claim, per edge — never a run-wide flag. Always
  the seven keys `{state, since_ns, until_ns, first_ns, lossy, reason, detail}`
  (`null` where a key does not apply: `lossy` is a boolean only for
  `counted`). In v0.2.0 the producer emits `witnessed`, `watched_no_use`
  and `unknown` only; `counted` is a contract state reserved for a future
  counting feed (C7) and never appears in v0.2.0 output. `state` is:
  - `counted`: a counting feed (actual call observations) covers the
    edge since `since_ns`; `count` and `last_seen_ns` are meaningful.
    `lossy: true` means records were lost: a positive count is a lower
    bound and a zero reads `unknown (usage observation lossy)`.
  - `witnessed`: use was witnessed (first at `first_ns`) but nothing
    counts it — `count` stays 0 for old consumers, `observation` reads
    `unknown (count unavailable; use witnessed)`, and the dashboard
    activity reads `used (recency unknown)`, never quiet. A native
    `CALLER_USE` row witnesses an edge only when the binder binds it
    to this caller incarnation (see `observation.native_witnesses`);
    the row is use of the admitted module whose endpoint set holds
    the row's first entered endpoint (the same endpoint set a watch
    negates). When several admitted modules share that endpoint, the
    row witnesses this edge only if this is the only sharing module with
    an edge to the caller; otherwise it records an `ambiguous shared
    endpoint` gap per sharing module and witnesses nothing. A row that
    does not bind is module-level `modules[].unbound_use` (single-module
    endpoints only), never this edge. A shared endpoint can still read
    `watched_no_use` for each sharer: a watch negates use of every
    endpoint the module holds.
  - `watched_no_use`: every endpoint of the module is attached for
    this caller since `since_ns` with clean health, and no use was
    seen: the zero is a fact (`observation` `observed`). `since_ns`
    never precedes the last health regression's detecting read (a
    watch noted later starts there). `until_ns` is `null` while the
    native capture runs; when it stops, every watch ends at the last
    witness read that proved clean health and held scope custody —
    never past the start of the last discovery read before it that
    drained the lifecycle ring, so a lifecycle loss found later (even
    after stop) can never fall inside the interval — and
    `since_ns..until_ns` stays a frozen fact (a watch no clean read
    proved reads `unknown`/`loss` instead). A PID scope custody that
    becomes unproven or lost before stop (an exec of the target, its
    leader exiting, its exit, lost lifecycle evidence) ends every watch
    the same way, at the earlier of the custody instant and the last
    clean read, records a `native capture scope custody unproven` gap,
    and no watch starts after it. A watch also needs the capture's
    `CALLER_USE` seen set below its pair limit with no row unrecorded
    past it: once either fails, no watch starts and no read extends one
    (an ongoing interval ends at stop at the last read before). The
    watched interval also
    ends when the edge does — caller retirement or a complete-absence
    unload (`mapping.state` `ended`, `mapping.last_seen_ns`); the state
    then reads as the frozen fact for that interval.
  - `unknown`: nothing can be claimed; `reason` is one of
    `scan_only` (no native usage producer runs — every edge of a
    scan-only run), `not_admitted`, `not_attached`, `attach_failed`,
    `identity_unavailable`, `capacity_limited` (`detail` names the
    resource), `loss` (`detail` says what was lost),
    `retired_before_coverage`, or `use_before_admission`.
  - `use_before_admission` (native lane): a `CALLER_USE` row whose pid
    is this caller's pid was not bound to it — typically a use before
    the caller's admission (`before_admission`), or any other unbound
    reason. The kernel records only the first use of each (image,
    module) pair and never deletes it, so a later use leaves no row and
    no watch of that module can be a fact. The edge reads unknown for
    good: an ongoing or frozen watch is replaced, none starts again,
    and it holds whichever is read first, the row or the admission.
    Fail-safe by pid: a row of an earlier process that held the same
    pid also downgrades the callers of that pid admitted when the row is
    read; a caller admitted later is spared only when both start times
    are known and differ. Rows of exited pids, or of pids now naming
    another process, are pruned (`budgets.native_preadmission.pruned`).
    Past a bound of 4096 held (pid, module) pairs every watch of the
    capture reads `use_before_admission`, with a `native pre-admission
    rows past their bound` gap. Positive history (`counted`,
    `witnessed`) is never downgraded. The reason names what first voided
    the watch: a watch a loss already demoted keeps `loss`, and a later
    loss leaves `use_before_admission` in place (a loss demotes watch
    intervals only); no watch starts again either way.
    A row that lifecycle loss left unbound (`lifecycle_loss`) downgrades
    the same way but reads `loss` (`detail`: the lost lifecycle
    evidence), since the loss, not an early use, is what it shows.
  A zero reads `observed` only under `watched_no_use` or a loss-free
  `counted`. Positive coverage (`counted` entries, `witnessed`) is
  monotonic history: it survives loss, caller retirement, and module
  unload. A global health regression (a native identity, pair, or
  usage evidence counter rising) demotes every `watched_no_use`
  interval that reaches past the last clean read before the rise to
  `unknown`/`loss`, and is recorded as a `usage coverage health
  regression` gap. The demoted interval stays demoted; a new interval
  may start only from the read that detected the rise. The demotion is
  conservative: it also demotes edges whose watched interval had
  already ended (retired callers, unloaded modules) before the
  regression, because the failure cannot be localized in time per
  edge; only an interval frozen at capture stop before the rise
  stands. In system scope, lost lifecycle evidence (DISCOVERY ring
  loss, a malformed lifecycle record, a failed discovery read: a lost
  exec or exit of any caller) demotes the same way, under a `native capture lifecycle
  evidence lost` gap, and is sticky: no watch starts again in that
  capture. A lifecycle loss is dated at the earliest instant it can
  date from: a ring-loss rise at the last health read that saw the
  counter lower; a record that failed to decode or decoded malformed
  (it carries no instant and may have waited in the ring) at the start
  of the last discovery read proven to drain the ring before it. Coverage notes that cannot apply are gaps, once per (caller,
  module): `usage coverage without mapping evidence` (no such edge)
  and `coverage for an unadmitted module` (a counting or watch note
  for a module not `admitted`; its usage stays unknown). `observation.usage_feed` is
  a derived summary: true iff at least one edge holds non-`unknown`
  coverage.
- `observation.native_witnesses` (Task 6 C4): the native caller binder's
  census, every witness row once: `{rows, bound, unbound, pending,
  integrity, unbound_reasons, placement}`. All zero in the scan lane.
  The unbound ratio is `unbound / rows`. Counts reconcile per row:
  `rows = bound + unbound + pending`; every decided row lands in exactly
  one of `placement.{edge, module, ambiguous, unresolved}` (a caller edge
  witnessed; one module's `unbound_use`; an endpoint shared by several
  admitted modules with no single carrier; an endpoint that names no
  registered module), so `bound + unbound` equals their sum, and
  `placement.module` equals the sum of `modules[].unbound_use.rows`.
  The census and the module sums differ by design: a bound row without
  a mapping edge is module-level (`no_mapping_edge`, a reason the census
  does not carry), and an unbound row on a shared or unresolved endpoint
  is in no module. A row binds to a caller incarnation only
  when a task-cookie query through the incarnation's held pidfd
  answers the row's own ticket in the row's own capture domain (equal
  ticket values of two loaded objects never join), the row was recorded
  at or after the incarnation's admission, no exec of that process and
  no lifecycle-record loss was seen since the admission, and no other
  image of the ticket competes; the decision waits for a complete
  lifecycle drain and a readable health read that both started after
  the row's read finished (`pending` counts rows still waiting). "After"
  is decided on the capture facade's monotonic stamps, never on the
  order batches are staged, and per capture domain: a drain that stopped
  at a reserved-but-uncommitted ring head covers nothing. Exec coverage
  begins when a capture's lifecycle tracepoint is attached; an
  incarnation admitted before that instant may have exec'd unrecorded,
  so its rows wait for the first scan pass that started after coverage
  began and binds only if that pass finds the same pidfd generation,
  start time and executable identity (otherwise, or if the capture ends
  first, `exec_coverage_gap`). Named boundary: a re-exec of the same
  binary before coverage began changes none of those, so it stays the
  same incarnation (the scan lane treats it the same way); execs after
  coverage began split by exec sequence. A bound image is exact and
  later rows of it bind at once, also after the caller exited. A later
  exec sequence of a bound ticket (or a changed leader ticket) under the
  held pidfd retires the incarnation (`exec_retired`) and admits its
  successor. `unbound_reasons` codes: `no_live_caller` (nothing held the
  tgid when the row was read: the process exited before the poll),
  `caller_exited` (it exited during the query), `cookie_unavailable`,
  `cookie_mismatch` (another ticket or none: pid reuse, a nonleader
  exec), `before_admission`, `exec_after_admission`, `lifecycle_loss`,
  `exec_ambiguous`, `exec_transition` (the row proved an exec; the
  successor was admitted after it), `exec_coverage_gap` (the
  incarnation predates exec coverage and no later scan pass
  revalidated it), `evidence_incomplete` (the capture
  ended before the row's horizon), `capacity` (a binder table bound).
  `integrity` counts rows that failed validation; each read with any
  records a `native witness rows failed validation` gap, and rows whose
  endpoint names no admitted module record a `native witness without a
  module` gap. Binding never claims the exact-image contract: the
  current exec sequence is never read from userspace, so
  `callers[].image.authority` stays `scan_pinned`.
- `edges[].semantics` (S1): the per-edge semantic summary label —
  `observed` iff the edge holds at least one mechanism or operation
  claim, otherwise the reason no claim exists:
  `unknown (semantic capture withheld)` (no semantic feed ever
  observed this edge — the scan lane alone), `unknown
  (unauthoritative module)`, `unknown (ambiguous descriptor)`
  (aliased/ambiguous producing descriptors),
  `unknown (count-only slot)` (count-only or unrecognized producing
  slots), `unknown (no operation evidence)` (an authorized feed
  observed only lifecycle traffic, failed `Init`s, or orphan calls
  that establish no claim), or `unknown (same-file double-load)`
  (scan evidence shows the object loaded twice in the caller's
  process — duplicate executable file-offset coverage — so no
  observed call can attribute to one instance and every call voids;
  the `same-file double-load detected` gap names the edge).
  Unsupported or ambiguous semantics render `unknown`, never
  invented.
- `edges[].mechanisms` (S1, `null` when no mechanism was
  attributed): one row per attributed mechanism id, sorted by id,
  each with exactly these keys: `mechanism` (the verbatim `u64` id —
  vendor ids survive unchanged), `mechanism_hex` (`0x…`), `name`
  (the registered `CKM_*` name, or `null` for vendor/unregistered
  ids — never guessed), `operations` (sorted operation categories
  this id was seen initializing, from the `*Init` function names:
  `sign`, `encrypt`, …, `message_sign`, …, `generate_key`, …),
  `calls` (API calls attributed to this id), `errors` (attributed
  calls with `rv != CKR_OK`), `last_seen_ns` (last attributed call),
  and `evidence` with `functions` (sorted verbatim function names
  that established claims here), `returns` (sorted `{rv, rv_hex,
  name}` rows — `name` is the registered `CKR_*` name or `null`),
  and `truncated` (true when a provenance set hit its bound and
  stopped growing). A mechanism label never implies more than the
  label: `CKM_AES_GCM` carries no key size, `CKM_RSA_PKCS_PSS`
  carries no size or parameters, `CKM_ECDSA` carries no curve —
  there are no size/curve/parameter keys in S1 output.
- `edges[].operations` (S1, `null` when the edge holds no claims):
  the per-edge operation aggregates with exactly these keys:
  `calls` (authorized calls with semantic content),
  `started` (`*Init`-created operations plus completed-direct
  calls — an OK `*Init` with an unreadable mechanism still creates
  its operation with the mechanism unknown, contributing no
  `mechanisms` row), `completed`/`cancelled`/`failed`/`unknown` (explicit end
  states — completed ⟺ ended by an `OK` return; cancelled ⟺ ended
  by cancel, replacement, or scope end; failed ⟺ ended by an error
  return; unknown ⟺ invalidated by loss, retirement, or a
  contradicted model — never silently completed, never silently
  dropped), `orphans` (calls/completions unattributable to a
  tracked operation — unknown-origin evidence, never invented
  joins), `dropped` (keys refused past the per-edge bounds),
  `last_seen_ns`, `active` (live machines as sorted
  `{category, state, count}` rows; `state` is `initialized` or
  `in_progress`), and `evidence` (small ambiguity counters:
  `state_reconciliations`, `session_cancel_ambiguities`,
  `session_cancel_unknown_flags`, `operation_state_imports`,
  `auth_state_ambiguities`, `semantic_capture_failures`,
  `async_duplicates`, `async_evictions`, `unmatched_closes`).
  API-call counts and operation counts are separate counters: a
  retry loop is N calls, one operation. "Right now" stays three
  distinct facts — recent call (`entries.last_seen_ns`), operation
  initialized (`operations.active`), API call in flight
  (`entries.in_flight`) — never merged. Raw session handles are
  never serialized; only per-edge aggregates leave the reducer.
  Completions apply on the completing session only, so a
  cross-session async completion orphans rather than joining
  across sessions; fork-inherited sessions read as
  unknown-origin on the child's edge. Capture-loss boundaries,
  retired edges, uncertain mappings, and same-file double-load
  detection end affected operations as `unknown` (the
  `semantic capture loss` gap names pass-wide loss; the
  `same-file double-load detected` gap names double-loaded edges);
  per-edge bound overflows refuse with `dropped` plus the
  budget `refused` counter, never by evicting retained facts
  (async pending/detached records are the one oldest-evicted
  exception, counted in `async_evictions`).
- `gaps[]`: every explicit coverage loss — unadmitted members,
  unreadable pids, deferred scans, unknown identities — with subject
  and reason. Past the deep-scan cap, a pass records `discovery capped`
  only when something stayed unexamined: "`N` processes in scope; `D`
  deep-scanned by provider rarity (limit `L`); `M` attributed to
  pinned provider objects by exact maps identity; `U` processes map
  `K` shared objects no deep scan examined and may use undiscovered
  providers" (plus how many processes had no maps snapshot). When
  nothing stayed unexamined and nothing was lost, the same subject
  reads "attribution complete: …" instead — a note, not a loss.
  `maps attribution` gaps count attribution losses by category
  (`generation_changed`, `exec_changed`, `confirm_unreadable`,
  `deleted_mapping`, `object_changed`, `key_rejected`,
  `inode_not_unique`, `budget`, `identity_mismatch` — a range at the
  key is another file —, `map_files_unavailable` — the proof could not
  be read for lack of privilege —, `mapping_changed` — a range read
  inside the confirmation's pin was no longer one mapping when its
  `map_files` entry was read, an unmap or remap during the read) and name a matched caller that also
  maps shared objects no deep scan examined. A shared object counts as
  examined only where a complete deep scan's own maps read opened it
  and found no provider, and the other process's ranges are proven,
  the same way, to be that file. An object whose sweep matching was
  refused (non-unique inodes; only where a process past the cap maps
  it) or dropped (it changed after the confirmation reads) is a gap
  under its path. Admission
  failures record one `caller admission failed` gap per pass and kind:
  a single failure keeps its pid and exact reason; several aggregate
  with a count (`N admissions refused this pass: caller budget
  exhausted…` with the budget, or `N pids could not be admitted this
  pass; first: pid P: …`). Absence from the document is never evidence of
  absence; `gaps_suppressed` counts gaps dropped past the bound.
  A gap is published once per run: a gap identical to one already
  published (every published field equal: `caller`, `module`, `pid`,
  `subject`, `reason`, `budget`; gaps carry no time or pass-specific
  field) is not added again. `repeats` (integer >= 1, additive within
  v1) counts the recordings of identical published fields, 1 for a gap seen
  once. A condition whose published text is identical on every pass is
  one entry with `repeats` equal to the passes; one whose text changes
  (an aggregate carrying a per-pass count, "N admissions refused this
  pass") is a distinct gap each time, and different underlying objects
  with identical published fields (for example "module capacity
  exhausted" for several refused modules) share one entry whose
  `repeats` counts all of their recordings. Repeats consume no `--max-gaps` budget and are never
  `gaps_suppressed`; only distinct gaps past the bound are, and each
  distinct suppressed gap counts once however often it recurs. The
  registry remembers up to 4096 suppressed gaps for this (64-bit
  keyed-hash fingerprints of the identity fields); past that, a
  recurrence of an unremembered suppressed gap counts again, so
  `gaps_suppressed` can then over-count. It under-counts only on a
  64-bit fingerprint collision (about 2^-40 likely). Gaps
  about a module absent from the registry name its key (device and inode,
  or path) in the `reason`, so different modules stay distinct gaps. The first
  occurrence keeps its position in `gaps[]`.
  A gap that records a budget refusal carries `budget` with the
  `resource`, its `limit`, and the `requested` occupancy; every other
  gap carries `budget: null`. Run-lifetime admission refusals name the
  `inventory_endpoints` or `inventory_attach_modules` resource.
- `budgets`: every budgeted resource with its own limit, occupancy
  source, and loss counter — `callers`, `modules` (physical module
  instances), `edges` (caller relationships), `endpoints` (the
  retained attach-endpoint census: the sum of admitted per-module
  endpoint counts), `inventory_endpoints` (additive within v1:
  `{limit, occupied}` — the run's Inventory attach set, whose
  capture-lifetime endpoint budget the admission verdicts are judged
  against, and the endpoints it holds; IDs are never reused, so
  occupancy only grows, and its refusals are the
  `inventory_endpoints`/`inventory_attach_modules` budget gaps;
  `refused` counts per-pass module refusals on that budget, so one
  module refused on every pass counts once per pass),
  `inventory_attach_modules` (additive within v1: `{limit, occupied,
  refused}` — the attach set's module records, capped at its endpoint
  budget, with per-pass refusals on that cap),
  `counters` (per-edge entry counts: the `cap`
  plus `observed_edges` and `saturated_edges`), `semantic_state`
  (`limit`, `occupied`, `status`, `unknown_edges`, and `refused`;
  `status` is `withheld` while no edge holds semantic state — the
  scan lane alone, where `occupied` is 0 and every edge reads
  `unknown (semantic capture withheld)` — and `observed` once the
  semantic feed materializes any; `unknown_edges` counts the edges
  lacking semantic claims; `refused` counts semantic keys refused
  past budget — materializations past `limit` (each also a named
  budget gap) plus per-edge keys past the S1 bounds),
  and `retained_history` (`limit`, `retained`, `suppressed` — the gap
  retention cap and its eviction marker; `limit` is the `--max-gaps`
  bound, 1024 unless the operator overrode it), and
  `native_preadmission` (additive within v1; `null` in the scan lane:
  `{limit, occupied, refused, pruned}` — the native lane's unbound use
  rows held per (pid, module) until their caller's admission;
  `pruned` counts pairs dropped because their process exited or the pid
  now names a process with another start time, and `refused` counts
  the (pid, module) notes refused once pruning could not make room, which also records the gap
  `native pre-admission rows past their bound` and degrades every
  watched caller's scope). Refusal never erases
  retained evidence: over-budget members are dropped with a named
  gap while catalog entries and previously observed use stay.

## Example (abridged)

```json
{
  "schema": "p11scope/inventory/v1",
  "scope": "pid:4242",
  "clock": {"basis": "CLOCK_MONOTONIC", "unit": "ns"},
  "observation": {"started_ns": 100, "ended_ns": 200, "passes": 1, "usage_feed": false,
                  "native_witnesses": {"rows": 0, "bound": 0, "unbound": 0, "pending": 0,
                                       "integrity": 0, "unbound_reasons": {},
                                       "placement": {"edge": 0, "module": 0,
                                                     "ambiguous": 0, "unresolved": 0}}},
  "budgets": {
    "callers": {"limit": 4096, "occupied": 1, "refused": 0},
    "modules": {"limit": 4096, "occupied": 1, "refused": 0},
    "edges": {"limit": 32768, "occupied": 1, "refused": 0},
    "endpoints": {"limit": 1048576, "occupied": 68, "refused": 0},
    "inventory_endpoints": {"limit": 4096, "occupied": 68, "refused": 0},
    "inventory_attach_modules": {"limit": 4096, "occupied": 1, "refused": 0},
    "counters": {"cap": 18446744073709551615, "observed_edges": 0, "saturated_edges": 0},
    "semantic_state": {"limit": 32768, "occupied": 0, "status": "withheld", "unknown_edges": 1, "refused": 0},
    "retained_history": {"limit": 1024, "retained": 1, "suppressed": 0}
  },
  "callers": [
    {
      "id": "c0", "pid": 4242, "start_time": 987654, "start_time_unit": "clock_ticks_since_boot",
      "incarnation": 0,
      "image": {"authority": "scan_pinned", "task_cookie": null, "exec_id": null,
                "exe": {"dev": 8, "ino": 12345, "mtime_secs": 1700000000, "mtime_nanos": 0, "path": "/tmp/driver"},
                "exec_observed": true},
      "lifecycle": "mapped", "lifecycle_reason": null,
      "first_seen_ns": 110, "last_seen_ns": 190, "retired": false
    }
  ],
  "modules": [
    {
      "id": "m0", "paths": ["/tmp/prov.so"],
      "identity": {"device": {"major": 8, "minor": 1}, "inode": 23456,
                  "sha256": "abc…", "build_id": null, "source": "mountinfo"},
      "admission": {"state": "admitted", "class": "exact", "endpoints": 68, "reasons": [],
                   "note": "scan-only admission: manifest corroboration was not consulted",
                   "history": []},
      "lifecycle": "mapped", "unloaded_observed": false, "unbound_use": null
    }
  ],
  "edges": [
    {
      "caller": "c0", "module": "m0",
      "mapping": {"state": "mapped", "reason": null, "first_seen_ns": 110, "last_seen_ns": 190, "interruptions": 0},
      "entries": {"count": 0, "saturated": false, "cap": 18446744073709551615,
                 "first_seen_ns": null, "last_seen_ns": null, "in_flight": false,
                 "observation": "unknown (usage observation unavailable)",
                 "coverage": {"state": "unknown", "since_ns": null, "until_ns": null, "first_ns": null,
                              "lossy": null, "reason": "scan_only", "detail": null}},
      "semantics": "unknown (semantic capture withheld)",
      "mechanisms": null,
      "operations": null
    }
  ],
  "gaps": [
    {"caller": null, "module": null, "pid": null,
     "subject": "exact image authority unavailable",
     "reason": "no BPF image identity; scan-lane incarnations by pidfd/start-time with exe-identity exec detection",
     "budget": null, "repeats": 1}
  ],
  "gaps_suppressed": 0
}
```

An observed edge (S1, abridged to the semantic keys) carries the
label plus the mechanism rows and operation aggregates:

```json
{
  "caller": "c0", "module": "m0",
  "semantics": "observed",
  "mechanisms": [
    {"mechanism": 4225, "mechanism_hex": "0x1081", "name": "CKM_AES_ECB",
     "operations": ["encrypt"], "calls": 3, "errors": 0, "last_seen_ns": 190,
     "evidence": {"functions": ["C_EncryptInit", "C_EncryptUpdate"],
                 "returns": [{"rv": 0, "rv_hex": "0x0", "name": "CKR_OK"}],
                 "truncated": false}}
  ],
  "operations": {
    "calls": 3, "started": 1, "completed": 0, "cancelled": 0,
    "failed": 0, "unknown": 0, "orphans": 0, "dropped": 0,
    "last_seen_ns": 190,
    "active": [{"category": "encrypt", "state": "in_progress", "count": 1}],
    "evidence": {"state_reconciliations": 0, "session_cancel_ambiguities": 0,
               "session_cancel_unknown_flags": 0, "operation_state_imports": 0,
               "auth_state_ambiguities": 0, "semantic_capture_failures": 0,
               "async_duplicates": 0, "async_evictions": 0, "unmatched_closes": 0}
  }
}
```
