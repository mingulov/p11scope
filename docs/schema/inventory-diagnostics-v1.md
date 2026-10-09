<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Inventory diagnostics JSONL v1

Inventory diagnostics explain decisions made by a native inventory capture.
They are optional and separate from the public inventory and event-log schemas.
They do not replay attribution or prove exact whole-workload counts.

Each line is a JSON object with `schema: "p11scope/inventory-diagnostics/v1"`.
A `header` precedes data records; a `footer` closes a successfully exported file.
The header gives tool version, requested capture mode/scope, optional PID filter,
record/byte/heap limits, and clock basis. Sequences order diagnostic events within
one capture; gaps are allowed, and sequences are not wall-clock timestamps.
A sequence can identify a filtered record; assignment does not imply retention
or successful export.
Read PRE/POST, fences and baseline intervals are available monotonic nanosecond
observations copied from the producer, never reconstructed during export.

Data kinds are `count_observation`, `ownership_transition`, `count_decision`,
`publication` and `capture_health`. Their finite optional fields include actual
read origin (`initial`, `refresh`), absolute/base/staged counts, `after`/`through`
range boundaries, prior/new eligibility, actual decision, resulting edge total,
and predecessor observation/transition references. `staged` is a staging decision;
`placed` confirms placement. A publication record reports the registry state
after the recorded mutation; its edge total can include earlier observations
and can change again later in the same batch. It does not by itself prove that
the requested increment was newly placed. Direct publications without a genuine
pair/read reference leave that context unavailable. Missing producer values are
JSON null. Diagnostics never calculate missing attribution or count growth from
a newer observation.

Application and module labels come from the retained presentation records.
Unknown labels are `Unknown executable` and `Unknown module`. Labels consume
at most 96 input bytes, truncate at UTF-8 boundaries, replace control characters
with `?`, and carry explicit truncation flags. Caller/module IDs are the public
inventory IDs. PID and incarnation remain separate, so duplicate application
labels and reused numeric PIDs are not collapsed.

Pair, read, epoch and pending IDs are capture-local opaque surrogates. Read,
epoch and pending keys are scoped to their pair; equal producer integers in
different pairs or native domains do not join. Keys without proven pair scope
are unavailable. Native domain/cookie/exec/object keys never leave recorder
memory, and the recorder types cannot be formatted with Debug or serialized.
No arguments, PINs, payloads, target-memory reads or new BPF events are captured.

A predecessor reference has a capture sequence and a status of `retained` or
`not_retained`; absent references are null. `not_retained` does not distinguish
filtering, ring eviction or another unknown cause. Global loss counters cannot
prove the cause of an individual missing reference. `history_complete` is false
when a required predecessor or producer context is unavailable. A valid complete
file can describe an incomplete history.

Reasons are finite: `sole_owner`, `shared_owner`, `ownership_unknown`,
`ownership_transition`, `binding_unproven`, `identity_changed`, `scan_incomplete`,
`awaiting_fence`, `stale_observation`, `pending_publication`, `stale_decision`,
`not_admitted`, `count_invalid`, `budget_refused`, `capture_loss`, `capture_stopped`,
`native_unavailable`, and `context_unavailable`. A reason names the branch the
producer actually took; it adds no attribution predicate. Repeated refusal/stale
checks may increment reason totals without producing another record.

Two rolling rings retain recent history: 24,576 ordinary observations, allocations
and publications, and 8,192 ownership transitions, exceptional decisions and
health records. Export merges their sequences. Global health bypasses the PID
filter; other records with unknown PID may be filtered out. Recording unchanged
polls is suppressed by the producer's explicit previous-count comparison.
There are at most 32,768 fixed-size data records of at most 384 bytes each.
Requested ring capacities and all simultaneously allocated export indexes remain
within 16 MiB; allocator bookkeeping and process RSS are separate measurements.
Fixed diagnostic context in the coordinator's existing bounded pair, pending and
recovery records is accounted separately and remains present when recording is
disabled. On x86-64 it adds 56 bytes per held pair, 72 per pending observation and
168 per recovery entry. At the default limits of 65,536 held pairs and 32,768
entries in each of the other two collections, this is at most 11 MiB of
additional raw payload; allocator overhead and RSS are not included.
Appending a record performs no
per-record allocation, formatting, target identity lookup or I/O; producers use
retained userspace metadata without new target reads.
Export uses bounded indexes and fixed stack scratch, without cloning the rings.

Data lines occupy at most 1,800 bytes including their newline, after JSON escaping.
Oversized data records are omitted and counted; they are never split. Envelope
lines use at most 8 KiB scratch each, with at most 64 KiB reserved envelope space.
The file cap is 64 MiB, with space reserved for the footer. These are hard bounds,
not averages. Sequence exhaustion stops recording; counter overflow saturates
counters. Both conditions make diagnostic completeness false.

The footer independently gives capture outcome and settlement, diagnostic
completeness, retained sequence spans for each ring, kind counts for produced,
retained, evicted, filtered and omitted records, finite reason totals, sequence
exhaustion/counter-overflow flags, and emitted record/byte/oversize totals.
Kind and reason vectors use the vocabulary order listed above. Retained spans
are bounds of each ring's retained sequences, not a promise of contiguous history.
Ring eviction and filtering are expected retention policies and do not themselves
make the diagnostic file incomplete. Omitted records and recorder overflow do.
Diagnostic omissions never become BPF loss or change public capture coverage.
Current native captures report settlement as `unsettled`: successfully retiring
probes does not prove that application activity has stopped. Native-unavailable
captures report `unavailable`; `settled` is reserved for a proven quiescent capture.

Export happens after terminal capture reads and final publication. No periodic
file persistence is promised; abrupt kill/panic need not yield a file/footer.
The frontend uses atomic private regular-file publication; write/cancellation
failure must leave the existing destination intact and is reported independently
of the primary report. Cancellation is checked between records, with no retries.
Regular-file writes/fsync can block in the kernel; no hard wall-clock export
bound is claimed. Files are ordinary temporary debugging output, with no automatic
upload, archive or retention requirement.
