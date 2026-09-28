<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# First-use observer test adapter

This test adapter supplies observer facts for the [first-use matrix](first-use-contract.md).
It is compiled only under `cfg(test)` and does not add a public command,
capture policy or identity key. An external owned controller combines these
facts with the [independent workload and post-call mapping receipt](system-first-use-fixture.md).
This document defines the adapter contract; it does not record a completed
first-use qualification.

## Actual runtime path

The ignored body
`first_use_probe::native::system_capture_observer_facts` parses the real
`profile --system` CLI and calls `p11scope::capture`. Modules, manifests,
custom hook catalogs, unsafe metadata and metrics are refused by this
particular probe. Metrics has no CALL stream from which to establish an
individual first call. Normal public mode support is unchanged.

The controller supplies `P11SCOPE_FIRST_USE_PROBE_CONFIG`: a frozen JSON
file, at most 8192 bytes, with schema `p11scope/first-use-observer/v1`, a
64-character lower-case hex nonce, the owned PID, physical target
`{device,inode,sha256,file_offset}`, the public CLI argument vector,
absolute `facts` and `loop_marker` paths, an optional `attached_marker`,
and `fact_limit` in 1..8192. Duration must be positive and at most 30s; a
separate public JSON `-o` report is required. All output paths must be new.
An independent supervisor bounds startup and cleanup as well as the loop.

| Private fact | Authority and limitation |
| --- | --- |
| `known` | Successful physical pin, opened-file metadata and the pin's existing hash. Its clock is a userspace observation after pinning, not the first instant any kernel subsystem knew the inode. |
| `scan_returned` | The actual process scanner returned. It retains process-view birth/namespace, whether memory was requested, success/unavailability/error, skip count and budget-stop state. A returned scan does not by itself prove complete discovery. Raw mapping device values remain distinct from opened-file `st_dev`. |
| `publication_validated` | Successful live table lowering before pin/admission. This is a separate path for later publications, including heap tables; it is not relabeled as a process sweep. Kernel publication-hook and later validation clocks remain separate. |
| `attached` | Existing per-slot completion of retained entry/return links, bound to the opened physical object and file offset in the actual EVENTS domain. The clock is the existing post-attach observation, an upper bound on link activation. |
| `loop_started` | The existing authoritative profile-loop timestamp. It is not sampled again by the adapter. |
| `discovery_loss` | A direct read of the Session's cumulative discovery ring-loss counter, with before/after read clocks and the retained EVENTS producer domain. This is separate from the Engine's cached counter projection. Unknown reads remain null. |
| `call` | A decoded CALL from the real profile drain, before semantic reduction. Includes only domain/slot, the binding available at consumption, PID/TID, image cookie/exec ID, raw kernel return/duration, checked derived entry time and userspace consumption time. Capture failure still invalidates the run. No argument values, handles, buffers or arbitrary memory are copied. |

The workload's `mapped` phase is a post-dlopen/dlsym state observation,
not an exact kernel VMA creation time. Its body ledger and publication
return remain independent authorities. Missing facts are null or absent;
later discovery never reconstructs an earlier CALL. An unavailable or
ambiguous slot binding remains unavailable in the recorded CALL even if a
later plan resolves it.

## Bounds and custody

- Per-thread journal, at most 8192 facts and bindings; each scan retains at
  most 64 matching-inode module summaries. Loss/truncation is explicit and
  invalidates the journal. It cannot be interpreted as an unobserved call.
- The EVENTS domains are retained until the probe finishes, preventing map
  ID reuse. No runtime process identity is inferred from a later PID lookup.
- A changed binding for the same domain/slot is permanently ambiguous.
  Multi-group survivor rebuilds are outside this adapter's initial timing
  support and explicitly invalidate its evidence. Whole-group retirement
  does not invent a new attachment.
- Only two readiness notifications are sent, with nonblocking channel
  operations. A separate thread atomically publishes nonce-bound marker
  files without overwriting existing evidence. No marker file I/O occurs
  in the capture service path. Missing time or notification loss is a
  failure. The controller must check that loop and target notifications
  refer to the same successful domain before releasing a gated call.
- The fixture remains under the existing independent supervisor/pidfd
  custody. This observer body starts, pauses and terminates no workload.
  All shared leases and typed before/after BPF census belong to the
  independent test controller.

The final facts file preserves `capture_returned_ok`, marker delivery,
journal integrity and the raw metadata. Its first-use verdict is always
`external_owned_oracle_required`. A successful ignored test body proves
execution of the collector, not capture of an owned first call.

## Diagnostic boundaries and verification

The discovery-loss diagnostic samples seven boundaries: lifecycle producers
active, static attachment complete, loader arming finished, initial exports
finished, before loop start, and before/after the first actual live discovery
pass. Arming/export boundaries identify completed attempts, not universal
attachment success. Repeated ticks do not read those counters again. Both
the stage registry and facts are bounded by the journal limit, and overflow
is explicit. Domain descriptors stay retained until the probe finishes.

An external analysis must refuse missing/reordered boundaries, changed
domains, missing or invalid read clocks, unknown/saturated counters and
counter regression. Deltas span the enclosing read intervals because the
per-CPU aggregate is not an atomic global snapshot. A nonzero initial sample
must be preserved. These samples localize loss; they do not turn a globally
invalid first-use comparison into a pass. Native boundary measurement is
still required on newly frozen source and executables.

Ordinary controls cover physical identity versus equal bytes, offsets,
producer domains, slot rebinding, late binding, unknown clocks and invalid
subtraction, foreign traffic, bounded facts/bindings/scans, raw-payload
exclusion, domain descriptor lifetime, unwind cleanup, marker backpressure,
exclusive output custody and the private CLI boundary. Scanner and actual
profile-drain integration controls fail when their hooks are absent.

Before live qualification, freeze source, test executable, embedded BPF
objects, fixture, oracle and controller. Run the owned gated/ungated matrix
under the existing exclusive lane. The uninstrumented public command must
also be compared before attributing a miss to product behavior: the adapter
adds metadata bookkeeping and can change scheduling. Its metadata journal
does not establish a performance envelope, exact kernel mapping time,
callback quiescence or arbitrary first-use coverage.
