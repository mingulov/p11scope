<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Loader/image lifetime fixtures (G16/G17 workload)

`provider.c` and `lifetime-driver.c` are the smallest bounded source that
exercises the required publication surfaces plus two useful table calls.
They drive real sequential provider-bearing processes; they do not start
an observer, prove arming, or manufacture native receipts.

## Build

```sh
gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs \
    -o /var/tmp/p11scope-ws-tmp/loader-lifetimes/provider.so \
    tests/fixtures/loader-lifetimes/provider.c
gcc -std=c11 -O2 -Wall -Wextra -Werror \
    -o /var/tmp/p11scope-ws-tmp/loader-lifetimes/lifetime-driver \
    tests/fixtures/loader-lifetimes/lifetime-driver.c -ldl
```

LP64/x86-64 only. No `pkcs11.h` is needed: both files define the minimal
LP64 types they use. The table layout (version + 6 reserved bytes + 104
pointers) puts functions at the same offsets as a real 3.2 list.

## What one lifetime does

`lifetime-driver PROVIDER LABEL` (LABEL 1..16385) stats the provider,
dlopens it, calls `C_GetFunctionList`, `C_GetInterfaceList` (count query
then one entry) and `C_GetInterface` with exact expected returns, then
calls table slots 2 (`C_GetInfo`) and 4 (`C_GetSlotList`) with exact
expected returns. It prints one JSON object to stdout and exits 0:

```json
{"label":1,"pid":1234,"starttime":456789,"provider_dev":[8,1],
 "provider_ino":987,"surfaces":{"function_list":0,"interface_list":0,
 "interface":0,"interface_count":1},"calls":[{"fn":"C_GetInfo","rv":0},
 {"fn":"C_GetSlotList","rv":0}]}
```

Any failure exits nonzero with a short stderr diagnostic and no stdout.
No stdin gates, sleeps, signals, `C_Initialize`/`C_Finalize`, PIN,
handles or payload bytes. Output is one line under 4 KiB.

The provider is one byte identity, silent, with no constructor calls:
constructor publication would add uncounted loader events and break the
exact 2-call denominator. `C_GetInfo` returns a fixed 3.2 structure;
`C_GetSlotList` reports exactly slot 1.

## Ledger role and bounds

`scripts/qualify-loader-lifetimes.py run` pins the provider (held FD hash
plus private mapping, following `scripts/mapped-provider-pin.py`),
retains that FD across the workload, executes each lifetime via the
FD-backed path, re-hashes the same FD afterwards and fails on mutation.
It binds each row's `pid` to its held child handle, and writes header +
`N` lifetime rows + done as JSONL. Bounds: 20,000 rows, 4,096 bytes per
line, 16 MiB total, at most 16,385 lifetimes, sequential launch (live 1,
within the required at most 4).

Driver `provider_dev`/`provider_ino` are the stat (file) domain. The
header pin carries both the file identity (checked against driver rows)
and the mapping identity (checked against observer reports). File and
mapping devices may differ (Btrfs); inodes must agree. Never compare a
file-domain device to a report module device.

Starttime is self-reported field 22 of `/proc/self/stat`. The harness
checks positivity and `(pid,starttime)` uniqueness, not absolute truth;
a dishonest driver could lie. Installed image identity must come from
native task proof, never from this number alone.

## What host controls prove vs installed gates

Host (unprivileged, short `N`): the fixtures compile, each lifetime
really dlopens the provider, exercises all three publication surfaces
and completes exactly 2 calls, pids/starts are distinct, and the
validator refuses duplicates, gaps, foreign providers, malformed rows
and overflows. Full `N` (300/16385) parser acceptance is checked with
synthetic rows, not 16,385 host processes; full workload runs need
controller scheduling.

Installed (blocked): one non-aggregate Detailed capture must observe
300 (G16) or 16,385 distinct leaders with exact per-function counts,
`COMPLETE`, zero loss, no foreign/ambient rows and the required scope.
The oracle additionally requires native evidence that does not exist
yet and fails `BLOCKED` without manufacturing it:

- Per-lifetime loader arming/admission and peak retained occupancy
  (proposed bounded aggregate loader transition counters, L4).
- Retained controlled loader contexts at most 8 (same counters).
- Per-context retirement cutoff (`LoaderRetirementFence`/ack).
- Successful ticket issuance across 16,384 (producer receipts/control
  accounting; `kernel_control` shows only refusals).
- Distinct `(pid,starttime)` leaders from observer output (trace rows
  lack starttime; profile aggregates).
- Single-capture guarantee (no hidden session restart; needs an
  observer invocation receipt).

G16 requires the publication surfaces; G17 ignores them and checks
only distinct leaders plus 2 calls each. The two assertions are
independent. A repeated context, 300 relabeled rows, an omitted final
44 (G16) or a missing last leader (G17) is never positive.
