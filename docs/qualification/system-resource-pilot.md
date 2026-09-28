<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# System resource and latency measurement protocol

This protocol freezes the pilot axes, denominators and failure rules. It
does not declare a production performance envelope. The static inventory tests
establish entry evidence in an owned fixture; they do not measure arbitrary
host workloads, public discovery fairness, sustained counts or customer
latency. Final qualification repeats applicable cells on the installed
artifact and every claimed kernel/profile combination.

## Inputs and independent truth

- Freeze source/tree, lockfiles, Rust/LLVM, binary and embedded objects,
  fixture ELF/offsets, driver/oracle, kernel/BTF/config and CPU topology.
- Hold the owned live and Cargo leases. Record actual background jobs and
  host load; another heavy build or VM setup invalidates performance data.
- Keep a workload ledger independent of report rows: physical object and
  generation receipt, intended and completed entries/returns, timestamps,
  calls before GO, calls after GO and terminal outcome. Report publication
  or later discovery cannot reconstruct an entry missed earlier.
- Require complete observer attach/loop-start/end stamps and physical
  workload attribution. Preserve missing, foreign-only and wrong-generation
  controls. Exact aggregate equality alone cannot qualify the window.
- Record the actual selected attach backend. Single-link tests do not
  establish multi-link performance, or the reverse. Include fallback and
  its resource admission decision on the supported floor kernel.

## Pilot axes

| Axis | Initial points and purpose |
| --- | --- |
| Physical targets | 1, 64, 512, 576, 1024, 2112, 4097, 6530; 8192 is the existing FD-refusal cell under soft limit 8192, not an 8192-capture claim |
| Lifetime count | More than 16384 sequential lifetimes with low concurrent occupancy; compare ordinary allocator controls with native identity/capacity evidence |
| Target arrival | Pre-existing, late file-backed publication, late heap publication, unload/reload, new inode with equal bytes, previously unseen object |
| Callers | One caller baseline, then 8, 64 and 257 concurrent owners; preserve distinct user/process/generation denominators |
| Calls | Quiet baseline, paced steady traffic and bounded bursts; pilot rates are measured achieved rates, with offered and completed counts retained separately |
| Hot state | Cold endpoints, repeatedly hot endpoint, expanding caller and return-value sets; compare equal admitted workloads |
| CPU count | One CPU, a multi-CPU guest and the documented host topology; per-CPU map cost must use actual possible CPUs, not only online CPUs |
| Output | Normal consumer, bounded slow consumer, closed pipe and unwritable/full output; final output must retain loss and stop evidence |
| Time | Short pilot first; final supported workloads later run 30 minutes, 4 hours and 24 hours with actual monotonic durations |

Do not run a blind Cartesian product. Start with one quiet baseline, one
point on each axis and the owned negative controls. Expand where an observed
limit, interaction or supported claim requires it. Keep the same fixture,
seed and completed-work denominator for a paired comparison. A refusal is
recorded independently and never counted as completed work.

## Measurements and limits

1. **Resource census:** open FDs before attach, after each admission and
   after stop; required links by chosen backend; map type/key/value/entries,
   per-CPU multiplier and resident bytes; observer RSS/CPU; evidence-file
   sizes and sink backlog. Derive admission from the available limit minus
   measured overhead and an explicit reserve. The historical 64-FD reserve
   is a pilot policy to check, not proof for every workload.
2. **Latency:** object known, mapping, publication return, scan, attach,
   first executed entry and first observed entry. Keep every timestamp and
   every missing transition. Report distribution and maximum, including
   discovery service gaps and tick wall times against the current 1895ms
   diagnostic bound. Separate deliberate wait time from tick service work.
3. **Stop:** request, acknowledgement, quiescence, final snapshot, output
   publication, last link detached, last owned kernel ID released and child
   settlement. Test cancellation during setup and each terminal phase.
   Publishing a report does not prove cleanup has completed.
4. **Target interference:** paired unobserved and observed runs at the same
   completed workload. Record elapsed time, target CPU, throughput and call
   latency; retain variance and scheduling context. A short noisy sample
   cannot establish an overhead guarantee. Repeat a pilot comparison only
   under a declared protocol, retaining all attempts.
5. **Integrity:** independent admission, entry/return, ring, reducer, sink
   and terminal-loss accounting. Preserve counter overflow/read failures,
   unresolved attribution and absent terminal records. Zero CALL-ring loss
   does not establish complete capture.

The pilot must produce a table of measured limits and proposed operational
defaults before making customer-facing performance claims. No CPU,
throughput, latency or shutdown threshold is silently inferred from a test
timeout. In particular, the static fixture's per-link retirement allowance is a harness
deadline, and the 576 point is neither a new product ceiling nor a universal
safe default. Broader acceptance belongs to the
[acceptance manifest](system-test-manifest.md).

## Stop and preserve

Stop the experiment on an owned-process ambiguity, unknown BPF object
change, unreadable census, failed boundary check, missing independent
ledger, timeout or evidence-writer failure. Preserve all raw output and the
original outcome before diagnosis. Unrelated host objects are never removed
to obtain a clean census. A new run needs a stated causal correction or a
predeclared comparison; it cannot overwrite a failed run.
