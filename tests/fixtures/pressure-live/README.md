<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T8 live256 pressure workload preparation (lane D)

Preparation only. These fixtures build and run unprivileged without any
capture. No runner consumes them and no suite registers them until the
controller wires the T8/G18 live cell. Live acceptance (installed 256-key
pressure service, late-provider fairness, all-blocked/N+1 twin) is still open.

Shape source: the live-pressure qualification plan and the G18 gate
("construct exactly 256 genuine queued native request keys while 255
provider-bearing retained contexts remain obligations, including the eligible
late owner and a genuine fresh head after the retained prefix").

## Files

- `driver.c`: ledgered provider-bearing child. `driver PROVIDER MODE REPEAT
  GATEFILE` with `MODE` in `{retain, late}`. Drives the three publication
  surfaces (`C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface`)
  `REPEAT` times after the gate releases, then holds the mapping until
  SIGTERM/SIGINT. Emits `TARGET` (own-maps physical join),
  `READY pid=N`, and `LEDGER` lines on stdout in the same shape as
  `tests/fixtures/public-cli/gated.c`.
- `static-head.c`: provider-free genuine fresh-EXEC head.
  `static-head GATEFILE` emits `READY`/`LEDGER` and holds until
  SIGTERM/SIGINT. No dlopen, no provider, no TARGET lines.
- `check.sh`: isolated unprivileged self-check (build plus a small
  retain+late+head smoke with ledger validation and cleanup proof).

## Build

```sh
gcc -shared -fPIC -DMATRIX_INTERFACES=1 -o /var/tmp/p11scope-ws-tmp/pl/early.so \
  crates/discover/tests/fixture/version_matrix.c
cp /var/tmp/p11scope-ws-tmp/pl/early.so /var/tmp/p11scope-ws-tmp/pl/late.so
gcc -std=c11 -O2 -Wall -Wextra -Werror -o /var/tmp/p11scope-ws-tmp/pl/driver \
  tests/fixtures/pressure-live/driver.c -ldl
gcc -std=c11 -O2 -Wall -Wextra -Werror -static -o /var/tmp/p11scope-ws-tmp/pl/head \
  tests/fixtures/pressure-live/static-head.c
```

Prefer the static head build: provider-freedom is then structural. When the
toolchain lacks static libc, the dynamic build is equally valid; prove
provider-freedom from `/proc/PID/maps` (no provider path), as `check.sh`
does, never from the LEDGER self-report alone.

## Live256 construction recipe (for the owned live lane)

1. Start the observer capture first (installed candidate, System scope).
2. Spawn 255 `retain` children on the early provider behind the gate.
   Wait for 255 `READY` lines; each child is one sustained retained
   provider-bearing context (one loader ticket each: tickets 1..255).
3. Spawn the `late` child on the late provider behind the same gate and
   wait for its `READY`. Its request queues without a loader ticket;
   queueing mints no context (`exec_binding: None` at queue time).
4. Spawn `static-head` last and wait for its `READY`. Its genuine kernel
   EXEC record is the fresh head after the retained prefix (request key
   256). It maps no provider, so servicing it arms nothing.
5. Release the gate. The children burst, ledger, and hold; the observer
   runs the pressure episode: selected service performs the nonempty
   late-provider rescan, physical publication and loader rearm (ticket
   256), then admits the original head into the freed request slot while
   preserving unrelated ages/serials and FIFO.
6. SIGTERM every owned child, verify each exit code, verify each PID is
   reaped, and remove the work directory.

Ticket budget for the genuine positive sequence: 255 (retained) + 1 (late
rearm) + 0 (static head) = 256 of 256. No loader ticket 257 is needed; see
"Ticket-257 need analysis" below. The first live control must still prove
the actual consumption fits: count `loader_arms`, retained contexts, and
any ambient arming on the measurement host, and refuse the cell when
uncontrolled provider-bearing processes spend tickets inside the episode.

## Measurement and cleanup checklist (Task 2 shape)

Per child: TARGET join, LEDGER `complete`, attempts/successful per surface,
exit code. Per episode: pending/backlog high-water, newcomer ages, attempts
versus successful admissions, inter-drain maximum, startup versus whole-pass
timing, observer CPU/RSS/FD peaks, and owned cleanup (children, files,
descriptors). Attempted service and successful admission are reported
separately; a lower drop count alone is not acceptance.

## Negative twin and extra controls (separate declarations)

- All-blocked/N+1: 256 retained obligations plus a fresh EXEC head must
  produce exactly one head refusal, sticky loss, continued FIFO progress,
  and a must-fail strict verdict. No capacity reset.
- Equal-content/different-file: run in its own episode (fresh ticket
  budget); within one episode it would spend a further ticket. Never a
  hardlink: same bytes, distinct inode, joined by `(dev, ino)` plus digest.

## Ticket-257 need analysis: NO-NEED

Verdict: the genuine T8/G18 positive sequence does not need loader ticket
257, so the G16 loader transition does not gate T8 pressure. Conditions:
System (multi-process) scope, a provider-free head, and an episode free of
uncontrolled ambient arming. Evidence (base `a05babfe`, file:line):

- `src/discovery/loader.rs:13`: `MAX_LOADER_CONTEXTS = 256`.
- `src/discovery/loader.rs:130-172`: ids are capture-lifetime monotonic
  (`allocated` only increments; `remove` frees the slot entry but never
  reuses the id), so the 257th `prepare` in one capture is refused with
  "loader context capacity 256 is exhausted". Ticket 257 exists only after
  the G16 reuse transition lands.
- `src/discovery/engine.rs:16139-16151` (`arm_loader_or_partial`): "loader
  contexts are finite capture-lifetime IDs (256, never reused) ... they are
  spent only where a provider is owned. Provider-free views stay unarmed."
- `src/discovery/engine.rs:9501-9503` (`admits_generations`): the gate
  applies to System scope, the G18 cell scope. (Pid scope always arms; the
  G18 cell is not Pid scope.)
- `src/discovery/engine.rs:10723`: queued refresh requests carry
  `exec_binding: None`; queueing the 256 keys (request-map entries) mints
  no loader context. Contexts are minted only in live loader arming
  (`loader_registry.preflight`/`prepare` at `engine.rs:15638`/`15661`,
  reached via `arm_loader_for_view` at `engine.rs:15524`, which requires a
  real loader: PT_INTERP match plus executable `_dl_debug_state`).
- `crates/ebpf/src/main.rs:1788-1825` (`sched_process_exec`): a real EXEC
  lifecycle record (pid/tgid) is emitted whenever `scope_auth()` succeeds,
  with no task-cookie or loader lookup on that path, so the static head's
  EXEC is a genuine native request-producing record.

This flips to NEED only if the oracle requires the head itself to be a
dynamic provider-bearing process with its own post-admission PKCS#11 calls
(a 257th arming). The plan's design instead proves FIFO/request
construction with the static head and dynamic service with the late
provider (nonempty rescan, physical publication, loader rearm, independent
calls before/after admission).

## Registration: none in this prep (future points for the controller)

These fixtures need no runner registration: C fixtures are compiled on
demand by path (as `tests/pressure_late_provider.rs` compiles
`tests/fixtures/live-discovery-driver.c`), and this prep adds no
`tests/python` suite (which would require a `run-python-suites.py` entry),
no Rust target, and no shared-file edit. When the live cell is built, the
controller serializes: root's private `cfg(test)` registration for the
planned `src/discovery/pressure_native_tests.rs`, and the G18 oracle tests
(`test_live256_requires_every_owned_participant`,
`test_late_provider_cannot_be_replaced_by_ambient_counts`) into the
assigned system oracle suite. Do not replace `tests/pressure_late_provider.rs`.
