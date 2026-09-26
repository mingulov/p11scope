<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# T2 first-use workload fixture: ordinary controls

`tests/fixtures/system-first-use.c` supplies a private LP64 provider and
driver for the [first-use requirements](t2-first-use-requirements.md).
This is the workload foundation; it does not qualify eBPF capture or close
the required five-class native matrix.

The provider has a 2.40 function table with 68 distinct addresses. The
driver acquires and verifies that table, calls `C_Initialize` exactly once,
then unloads and exits. Other table endpoints are stubs and are not exercised.
The initializer records its actual body-entry time and call count; the
driver checks both independently of any observer output.

Two optional file gates control publication and the ordinary call. With
both arguments `-`, the sequence never waits for observer attachment. The
heap build allocates its table during `C_GetFunctionList`; individual
assignments avoid embedding a complete file-backed template. The normal
build supplies a file-backed table. A third build deliberately returns an
incomplete table and must refuse before the ordinary call.

The private JSONL ledger is created exclusively and records seven workload
phases: object stat, mapped, publication returned, table verified, actual
body entry, call returned and unloaded. It carries monotonic times and
workload PID/birth, file and mount-namespace identities. The body-entry
timestamp comes from the provider; it is logged after the call returns.
An existing ledger is never overwritten. Successful execution includes a
checked ledger close and a successful process exit.

These are workload facts. In particular, object stat is not observer
knowledge, and neither table publication nor successful return proves the
observer captured a call. Scan/attach/observed-entry facts remain absent.
The file stat is also not a live map_files receipt. The native adapter must
bind the actual mapped endpoint to retained physical custody, including for
a child that unloads/exits before an external collector can inspect it.
Adding an observer wait to that ungated child would change the experiment.

## Executed ordinary controls

`TMPDIR=/var/tmp/p11scope-ws-tmp python3 -I tests/python/test_system_first_use_fixture.py -v`
passes seven tests. Each run compiles the driver and three provider variants
with `-Wall -Wextra -Werror`. The tests cover actual publication/call gates,
ungated completion, body truth and ordered clocks, file/heap placement,
equal bytes on a distinct inode, malformed-table refusal and ledger custody.
Hosted CI and `scripts/gates.sh` invoke this suite.

Private mutation checks changed only temporary source copies. Bypassing
both gates was rejected by two executed controls; removing the body count
was rejected by the ungated control. The initial gate mutation exposed a
test indexing error, which was repaired to select records by phase; the
original error log and the corrected rejection logs remain in the task
worktree's ignored `.superpowers/first-use-fixture/` directory.

No namespace transition, retained-probe comparison, pre-execution mechanism,
observer timing bridge or privileged first-use case has been run by this
fixture package. Those remain required follow-up work.
