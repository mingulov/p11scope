# Raw tracepoint lifecycle probe report

Status: DONE_WITH_CONCERNS

This throwaway probe converts only `sched_process_exec` and
`sched_process_exit` to Aya raw tracepoints. `sched_process_fork` remains the
existing formatted tracepoint, including its trace-event record offsets. No
Cargo manifest or lockfile, map, event, consumer, privacy, capability, or
public contract changes were made.

## RED/GREEN evidence

The required artifact test was added before the implementation and run RED:

```text
test lifecycle_exec_exit_are_raw_while_fork_stays_formatted ... FAILED
thread 'lifecycle_exec_exit_are_raw_while_fork_stays_formatted' panicked:
sched_process_exec must use the raw tracepoint declaration
test result: FAILED. 0 passed; 1 failed
```

After the conversion, the exact test ran GREEN:

```text
test lifecycle_exec_exit_are_raw_while_fork_stays_formatted ... ok
test result: ok. 1 passed; 0 failed
```

## Changed symbols

- `crates/ebpf/src/main.rs`: imports `raw_tracepoint` and
  `RawTracePointContext`; `sched_process_exec` and `sched_process_exit` now
  use `#[raw_tracepoint(tracepoint = ...)]`. Their body and lifecycle record
  logic are unchanged. `sched_process_fork` still uses
  `#[tracepoint(category = "sched", name = "sched_process_fork")]` and its
  existing `read_at` offsets.
- `src/attach.rs`: loads fork as `TracePoint` and exec/exit as
  `RawTracePoint`; lifecycle callbacks use `RawTracePoint::attach` and
  `detach`; `RegisteredLink::RawTracePoint` owns `RawTracePointLinkId`; the
  existing two-link `attach_lifecycle_with` rollback remains intact. Raw links
  participate in producer ordering and are ignored by the dynamic-export
  snapshot as non-dynamic links.
- `tests/artifact_contracts.rs`: adds
  `lifecycle_exec_exit_are_raw_while_fork_stays_formatted`, which checks the
  two raw declarations, the unchanged formatted fork declaration, and raw
  userspace link ownership markers.

## Checks

All requested checks completed successfully:

```text
cargo +1.88 fmt --all -- --check                         PASS
cargo +1.88 test --test artifact_contracts lifecycle_exec_exit_are_raw_while_fork_stays_formatted
                                                         PASS (1 passed)
cargo +1.88 check --locked --workspace --all-targets    PASS
cargo +1.88 test --locked --lib attach::tests -- --nocapture
                                                         PASS (24 passed)
git diff --check                                         PASS
```

## Static-only semantics and remaining risk

The raw exec/exit functions do not read tracepoint context. Their lifecycle
semantics remain statically inferred from the unchanged `scope_auth`,
`emit_lifecycle`, PID-leader check, and discovery record paths. Aya's pinned
0.14 userspace API statically provides `RawTracePoint::load`,
`RawTracePoint::attach`, and FD-owned `RawTracePointLinkId` detach ownership.

The requested workspace check compiles the userspace workspace; the standalone
`crates/ebpf` package is not a workspace member, so this probe does not claim a
fresh standalone eBPF object build or verifier acceptance. No runtime test was
run. The artifact test is source-contract evidence, not generated-object
evidence.

Because fork remains a formatted tracepoint, cgroup event-producing
profile/trace still needs tracefs for `sched_process_fork`; only PID/owned-run
lifecycle and cgroup aggregate-only paths can be statically considered for
tracefs independence. Runtime proof with masked tracefs, capability parity,
kernel coverage, rollback under attach failure, and pause behavior remains
unrun and requires a separately authorized privileged lane.
