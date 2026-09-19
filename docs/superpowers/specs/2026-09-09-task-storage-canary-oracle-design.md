<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Task-storage canary oracle design

Owner-approved 2026-09-09 as part of W7 release preparation. The privacy
canary must continue to scan every observer-owned map, including Linux task
storage. This design repairs the qualification infrastructure; it does not
change production capture, the privacy allowlist, or the supported ABI set.

## Problem and invariant

`scripts/dump-owned-bpf-maps.py` currently routes every non-ring-buffer map to
`bpftool map dump`. Linux task-storage maps do not implement key iteration, so
the live canary stops on `TASK_COOKIE`, `THREAD_OWNER`, or `ROOT_AFFILIATION`.
The synthetic validator inventory also labels these maps as hash maps, allowing
the invalid dispatch to pass self-tests.

The release invariant remains: every byte of every live observer-owned map is
present in a bounded scan surface. Unsupported enumeration, absent surfaces,
partial reads, lookup ambiguity, or a changing task population fail closed.

## Chosen boundary

Keep orchestration, validation, receipts, and sentinel scanning in isolated
Python. Add one standalone test-only `SEC("iter/task")` eBPF C program and a
small native loader under `scripts/native/`. The helper imports the exact
observer map file descriptors with `bpf_map__reuse_fd()` before load; it must
never create or pin substitute task-storage maps. Production Rust and eBPF
objects remain unchanged.

The iterator walks all visible tasks and performs non-creating
`bpf_task_storage_get(..., 0)` lookups for each imported map. It writes a fixed
binary framing header and the complete raw map value through `bpf_seq_write()`.
The 544-byte `THREAD_OWNER` value is written directly from the map pointer and
is never copied onto the BPF stack. Userspace validates framing, map IDs,
types, key/value sizes, flags, duplicate records, byte/record/time bounds, and
successful EOF before publishing one raw surface per task-storage map.

## Snapshot protocol

The harness first stops the observer. In START lanes it waits until every
expected worker is blocked in the provider call, group-stops the complete
workload, records the full task roster and each task's stopped state, then runs
the iterator. It repeats the roster and state checks after collection before
resuming only processes that the harness stopped. Clone, exec, and exit are
outside this interval.

A NULL task-storage lookup is ambiguous on supported older kernels because a
trylock can fail. The oracle therefore reconciles the expected population from
the existing healthy control maps and stable task roster. Any missing expected
cell, unexpected owner, duplicate, changing roster, early EOF, truncation,
overflow, timeout, or acquisition failure is terminal. Diagnostics identify
the phase and metadata without printing map values.

## Compatibility and privacy

The helper is test-only, read-only, and bounded. It reads only the three exact
imported task-storage maps, performs no CREATE, UPDATE, DELETE, pointer chasing,
or production decoder calls, and does not broaden
`docs/privacy/allowlist-v1.md`. The helper and its loader require live
qualification on every required W7/W6 kernel row; API availability or a
successful build alone does not qualify a kernel.

Acceptance includes actual `task_storage` inventory metadata, non-leader
thread coverage, complete 544-byte values, positive cells for all three maps,
sentinels at early and late offsets, and injected failures for substitution,
NULL lookup, population mismatch, duplicate records, malformed framing,
overflow, timeout, and partial cleanup. Both default and diagnostic objects,
native64 and ia32 targets, must pass the affected canary lanes on the final
candidate.
