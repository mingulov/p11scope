# Phase 2 — Gate G2 induced-gap verification

`scripts/verify-induced-gaps.sh` proves the tool degrades **honestly**:
three captures, each broken a different way on purpose, each asserted
against an exact number (not just "PARTIAL appeared"). Run twice on this
host; both runs reproduced all three gaps with the same shape (event-loss
count varies run to run, as expected of a race against a full ring, but
stayed within a few hundred of 200000 both times, always `> 0`).

## Environment

- Kernel: `7.0.0-28-generic`
- SoftHSM2: `/usr/lib/softhsm/libsofthsm2.so` (gap 3)
- Fixture provider: `crates/discover/tests/fixture/{provider.c,helper.c}`
  (gap 1, reused as-is per the brief)
- New fixture/workload sources: `scripts/fixtures/{alias_workload.c,
  blocking_provider.c,blocking_workload.c,hammer.c}`

## Gap 1 — aliasing

`crates/discover/tests/fixture/provider.c` already builds a controlled
provider whose legacy table aliases `C_CancelFunction` and
`C_WaitForSlotEvent` at one address (`legacy.f[66] = legacy.f[67]`).
`scripts/fixtures/alias_workload.c` calls the two accordingly-named
function-pointer slots 25 and 17 times respectively (both physically the
same call).

Observed (`target/induced-gaps/g1_observed.json`):

```
Evidence: 186/186 probes attached · 93 slots · 1 aliased · 1 skipped ·
0 in-flight · 1 surface gaps · 1 vendor interfaces → PARTIAL

FUNCTION                                            CALLS
C_CancelFunction|C_WaitForSlotEvent (aliased)          42
```

- `evidence.aliased == [["C_CancelFunction", "C_WaitForSlotEvent"]]` —
  exactly the two names, nothing else.
- The function report for that group: `aliased: true`, `calls: 42`
  (== 25 + 17) — the counts are attributed to the **group**, not to one
  name or split between them.
- `completeness: "PARTIAL"` (also independently forced by this fixture's
  vendor interface and null-pointer skip — the aliasing assertion above
  is what's specific to this gap; the brief only requires PARTIAL
  overall, which holds).

## Gap 2 — in-flight at end

`scripts/fixtures/blocking_provider.c` is a minimal 68-entry legacy table
where every slot returns immediately except `C_WaitForSlotEvent` (index
67), which calls `sleep(60)`. `scripts/fixtures/blocking_workload.c`
calls it once and hangs; the script gives `p11scope profile` only
`--duration 6` (after a 3s attach-settle wait), so the capture window
closes while the call is still inside its 60-second sleep. The still-
blocked workload process is killed with `SIGKILL` after the profiler
exits and its JSON is captured.

Observed (`target/induced-gaps/g2_observed.json`):

```
Evidence: 4/4 probes attached · 2 slots · 1 aliased · 0 skipped ·
1 in-flight → PARTIAL

FUNCTION              CALLS  IN-FLIGHT
C_WaitForSlotEvent        0          1
```

- `evidence.in_flight_at_end == 1`.
- The `C_WaitForSlotEvent` function report: `calls: 0` (never returned —
  not counted as completed), `in_flight: 1`, and
  `latency_ns.{p50,p95,p99}` are all `null` — the stranded call is
  excluded from latency percentiles, exactly as `metrics.rs` documents
  (`in_flight = entered - returned`; a call with no return contributes
  to neither `buckets` nor `total_ns`).
- `completeness: "PARTIAL"`.

(The `1 aliased` in the evidence line is a side effect of this fixture's
67 no-op stubs all pointing at one shared `ok()` function — harmless
noise, not asserted on; only `C_WaitForSlotEvent`'s own slot, which is
unaliased, is checked.)

## Gap 3 — event loss

RING_BYTES override: `crates/ebpf-common`'s `small-ring` Cargo feature
(off by default) shrinks `RING_BYTES` from 256 KiB to 4 KiB (one page —
still power-of-two and page-aligned, the two invariants
`ring_bytes_is_page_aligned_power_of_two` pins). `build.rs` forwards
`--features small-ring` to the nightly `crates/ebpf` build only when the
environment variable `P11SCOPE_SMALL_RING=1` is set; unset (the default),
the build command is byte-for-byte what it was before this task. The
script builds this variant into its own `--target-dir
target/induced-gaps/ring-small`, so `target/release/p11scope` (what
`scripts/verify-attach-e2e.sh` uses) is never touched.

**Proof the default is unchanged:** built both variants, extracted the
BPF ELF's `maps` section with `readelf -x maps`, and diffed them —
identical except for the 4 bytes holding the ring's `max_entries` field
(`00 00 04 00` = 262144 in the default build vs. `00 10 00 00` = 4096 in
the small-ring build). Everything else in the compiled maps layout is
byte-identical. `cargo test --workspace --release` also passed in full
(pinned by the new `default_ring_bytes_is_256kib` test in
`crates/ebpf-common/src/lib.rs`), and `bash scripts/verify-attach-e2e.sh`
re-run afterward still ends `=== e2e: ALL OK ===` with `completeness:
"COMPLETE"` (see below).

`scripts/fixtures/hammer.c` opens a session against SoftHSM2 (private
token store, same pattern as `verify-attach-e2e.sh`) and fires
`C_GenerateRandom` 200000 times back-to-back with no delay (~0.17s
unattached; a few seconds attached). The `p11scope profile` under test
here is the small-ring build; `--duration 15` comfortably covers attach
settle + the hammer run.

Observed (`target/induced-gaps/g3_observed.json`, run 1 / run 2):

```
Evidence: 136/136 probes attached · 68 slots · 0 aliased · 0 skipped ·
0 in-flight → PARTIAL

event_loss:                199901 / 199903   (out of 200000 events)
C_GenerateRandom calls:    200000 / 200000   (exact both runs)
```

- `evidence.event_loss > 0` (in fact nearly all individual call events
  were dropped — the 4 KiB ring holds roughly 40-50 `Event` records,
  vastly less than 200000).
- **The cross-check that matters:** `functions[].calls` for
  `C_GenerateRandom`, read from the aggregate `STATS` map, is exactly
  200000 on both runs — matching the hammer's own count
  (`hammer OK: 200000 C_GenerateRandom calls`) exactly, despite ~99.95%
  of the ring-buffer event stream being lost. `p11_entry`/`p11_return`
  in `crates/ebpf/src/main.rs` update `STATS`/`RV_COUNTS`
  unconditionally, before the (separate, fallible) `EVENTS.reserve`
  call — the maps are the count authority; the ring is the lossy
  channel, exactly as the module docs in `src/metrics.rs` state.
- `completeness: "PARTIAL"`.

## e2e re-run (default build unaffected)

```
$ bash scripts/verify-attach-e2e.sh
...
evidence: 136 probes, COMPLETE
...
=== e2e: ALL OK ===
```

Matches `docs/notes/phase1b-e2e.md` exactly (136 probes, 68 slots, 0
aliased, 0 skipped, 0 in-flight, `COMPLETE`).

## Files

- `scripts/verify-induced-gaps.sh` — the three-gap script, `set -eu` as
  an explicit body line.
- `scripts/fixtures/alias_workload.c` — calls the two aliased slots in
  the existing discover fixture provider.
- `scripts/fixtures/blocking_provider.c` /
  `scripts/fixtures/blocking_workload.c` — minimal legacy-table provider
  with one function that blocks for 60s, and the workload that calls it.
- `scripts/fixtures/hammer.c` — fires `C_GenerateRandom` at SoftHSM2 at
  high rate, no delay, for the event-loss gap.
- `crates/ebpf-common/Cargo.toml`, `crates/ebpf-common/src/lib.rs`,
  `crates/ebpf/Cargo.toml`, `build.rs` — the `small-ring` feature and its
  `P11SCOPE_SMALL_RING` env-var trigger.
