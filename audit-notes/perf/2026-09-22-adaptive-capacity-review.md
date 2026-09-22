<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Adaptive capacity after the updated provider/caller requirements

The leading design is initial sizing from a census, reserved headroom, and
additional allocation before exhaustion under an explicit global resource
envelope. The 512 endpoint and 256 retained-view limits are existing barriers;
576 is a test workload, not the next proposed ceiling. Discovery work renews
independently of retained identities, observation history, and cumulative loss.

This is a design assessment. No dynamic-map implementation or performance
qualification is claimed here.

## Independent review

A second requested Claude review ran once with `--model fable --effort xhigh`,
Claude CLI 2.1.278, actual model `claude-fable-5-1`. It completed successfully in
536.25 seconds. It received the updated caller, cumulative operation counter,
optional key metadata, and continuous discovery requirements. Tools were
restricted to Read/Grep/Glob. One artifact-directory Glob was denied; the design
inputs were embedded and the actual modified source was readable.

Raw prompt, response, events, metadata, preserved source hashes, and the detailed
checked assessment are under:

`/var/tmp/p11scope-ws-tmp/full-system-20260922.FbcpaT/claude-capacity-review/`.

The inspected checkout was `3fcc652` plus the stopped I1 planner/capacity patch.
I1 subsequently passed 60 planner and five capacity tests, formatting, workspace
checking and clippy, and was committed as `19ffd35`. It supplies a checked
inventory admission policy; it does not activate a live inventory loader.

## Constraints confirmed in source

- Endpoint cells, process-generation identities, scan views, scan work, caller
  rows, return-code rows, pending invocations, links and output history have
  different owners and lifetimes. Increasing one does not grow the others.
- Detailed statistics consume 296 bytes per endpoint per possible CPU before
  map overhead. The separate compact global usage component consumes eight
  payload bytes per endpoint. Neither figure includes the full product's cost.
- Retained provider-bearing views currently carry ownership proofs, so evicting
  a view as if it were only a scan cache can discard correctness state.
- A new endpoint segment does not help an old endpoint whose caller or
  return-code map becomes full. These cardinalities need independent growth.
- The current producer's endpoint IDs cannot be recycled merely because a link
  was detached. Quiescence, generation and semantic ownership remain separate
  requirements.

## Alternatives to compare

| Allocation scheme | Advantage | Required proof |
| --- | --- | --- |
| Compact object sized before load, with reserve | Small initial implementation; existing cells never migrate | Fits the supported workload and later-arrival reserve; explicit exhaustion handling |
| Append additional endpoint segments | Existing observations stay where they were recorded | Shared identity/lifecycle ownership, immutable routing, independent caller/counter growth, partial-attach receipts |
| Outer-map directory with compatible inner maps | Userspace can add backing maps without replacing the running program | Outer capacity, inner metadata compatibility, exact loader/verifier support, lookup and resource costs |

Linux permits userspace to populate an existing outer map with compatible inner
maps created later; future inner maps need not all exist when the program is
loaded. [Kernel map-in-map documentation](https://docs.kernel.org/bpf/map_of_maps.html).
Array size is fixed at creation and per-CPU arrays allocate separate values for
each possible CPU. [Kernel array documentation](https://docs.kernel.org/bpf/map_array.html).

Copying and swapping a concurrently updated live map is a different migration
protocol. It must not be described as ordinary resizing or assumed lossless.
Similarly, cloning a whole Session for every segment would duplicate discovery,
lifecycle and identity domains unless shared ownership is explicitly designed.

## Review claims that were rejected or narrowed

The claim that refusals disappear when a live pin is removed missed retained
`CaptureHistory.refusals`; no duplicate ledger is justified by that claim.
The proposed provisional-slot loss case did not account for reserved historical
allocations and was not substantiated. The ordinary CALL path already records
semantic-history rejection. These remain distinct from any future specific
failure reproduction.

Several proposed memory formulas mixed live task storage with lifetime tickets,
counted one pidfd twice, treated double virtual ring mappings as twice the
physical allocation, or omitted per-CPU values. Actual kernel allocator, program,
link, syscall and snapshot costs must be measured rather than inferred from
these estimates.

## Acceptance boundary

Within the declared supported workload, every required exercised physical
provider and caller must have positive evidence. An explicit refusal or an
expected missed first use validates reporting of failure, not all-provider
coverage. A never-seen provider that loads, executes once and unloads before
attachment remains a separate unresolved discovery boundary.

Growth tests must include new callers/return codes on old hot endpoints,
cross-segment operation identity, partial allocation and attachment failures,
more than 256 retained generations, continuing progress after work exhaustion,
stable cumulative counters, and teardown evidence from every producer. Optional
key annotation eviction may produce unknown metadata; it must not drop operation
counts or positive-use evidence.

Compiler experiments and the possible Linux 6.9 baseline are separate decisions.
No minimum-kernel change, BPF v4 default, or global LLVM replacement is made by
this plan update.
