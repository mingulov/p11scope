<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Installed cgroup trace first package

This real SoftHSM caller and independent oracle prepare six bounded installed
cells. They test `trace --cgroup` and the public `run --trace --pause auto` route.
They do not implement or qualify `inventory --cgroup`.

The caller follows the existing `public-cli/gated.c` physical-target fixture:
`dlopen` the installed provider, obtain its actual LP64 function table and call
the real functions. Every invocation includes setup and teardown, successful
return, monotonic entry/completion, PID/TID and image generation. Every called
function also has the caller's actual executable VMA device/inode/file offset.
Each native exec reports its actual `/proc/self/exe`, file identity, kernel birth
and PID/time namespace. It never prints argument/environment/buffer canaries.

The harness holds provider/executable FDs. Provider device evidence comes from
`scripts/mapped-provider-pin.py` mapping the same held FD, independently of both
the fixture and candidate output. Btrfs `fstat.st_dev` is a separate domain.
The harness checks every actual process image against its expected held
executable and original birth/parent before recording an image receipt. Named
row expectations come from these receipts and the caller ledger.

| Cell | Controlled calls during capture | Required result |
| --- | --- | --- |
| stable | 20 `C_GenerateRandom`, 200 ms apart | Nonempty correct named population; report unknown share |
| onecall | Exactly one `C_GenerateRandom` after complete setup | Report actual truth; require Unknown only when fresh session, exclusive scope and sole CALL prove no upper witness could exist |
| burst | 256 `C_GenerateRandom` without delay | Exact successful population; report named/unknown shares without promising names |
| migrate | Selected A calls; outside `C_GetInfo`; unchanged A reenters | Named positive; outside function has zero captured events |
| exec | Selected A `C_GenerateRandom`; outside different-path exec B; B `C_GetSessionInfo` after reentry | Both actual images have named positives; zero wrong names and zero outside `C_GetInfo` events |
| run | Own caller, `run --trace --pause auto`, gated 20 calls | Named positive, full setup/teardown ledger, stdout/file event and terminal fact parity |

Exec phases use different selected functions, making each PID/TID/function key
identify one actual executable independently. The oracle refuses ambiguous
keys. Outside phases use a third function, so outside events cannot substitute
for missing selected events at the same function total. Controller phase counts
come from issued commands and kernel membership checks, not captured rows.

For cgroup cells, setup finishes before the observer starts, the fresh selected
cgroup contains only the caller, and teardown starts after observer reap. These
facts also prove the first CALL cannot already have a two-CALL receipt. Unknown
is never required merely because a workload is short. For `run`, every setup
call is ledgered; setup completed before observed capture readiness is an
explicitly uncertain attachment prefix, bounded by the independent ledger.
Calls after readiness are mandatory. No captured setup row is omitted.
The public run route may initially announce zero provider probes while the
caller is still loading its provider. That banner alone never opens the native
workload gate: the harness also validates the actual owned child image and held
provider target, then waits at most ten seconds for a completed successful
`C_OpenSession` event matching its independently recorded setup PID/TID/function.
Only then does it record gate-release readiness and start main work. Cgroup
cells still require a positive initial provider-probe count.

The observer's event wall clock is anchored when rendering begins. The oracle
does not use it to assign exec phases. It compares actual function populations,
return values, exact image paths/basenames, stdout/file rows and counts, privacy
canaries, declared loss and normal stop. Terminal sink accounting may change
after stdout publication; only the three sink timing/drop fields are excluded
from fact equality, and dropped bytes/timeouts fail these no-loss cells.
`final_drain=false` remains visible and cannot be called COMPLETE. Naming
qualification does not invent a final callback drain proof.

## Preparation without Cargo or privilege

Existing `gcc`, `softhsm2-util`, Python and installed SoftHSM are used; nothing
is installed. The harness tests compile the native fixture in disk scratch,
execute real provider calls and native exec as the ordinary user, then clean
their own children/files. These tests prove the fixture/oracle, not installed
BPF behavior.

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp timeout 120 python3 -I tests/python/test_cgroup_trace_oracle.py -v
TMPDIR=/var/tmp/p11scope-ws-tmp timeout 120 python3 -I tests/python/test_cgroup_trace_harness.py -v
gcc -std=c11 -O2 -Wall -Wextra -Werror -pthread -o /var/tmp/p11scope-ws-tmp/n3-prep/caller tests/fixtures/cgroup-trace/caller.c -ldl
```

## Separate installed lane

Root must provide the exact source-matched candidate and grant the live lane
before this command runs. Substitute its candidate path/revision and a new
private output directory; output is temporary debugging material, not an archive.

```sh
sudo -n timeout --kill-after=20s 300s python3 -I scripts/qualify-cgroup-trace.py \
  --binary /absolute/root-pinned/p11scope \
  --source-revision EXACT_40_HEX_COMMIT \
  --provider /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  --caller /var/tmp/p11scope-ws-tmp/n3-prep/caller \
  --uid 1000 --gid 1000 --cells stable,onecall,burst,migrate,exec,run \
  --out /var/tmp/p11scope-ws-tmp/NEW_N3_RUN
```

The root observer stays outside its newly created
`/sys/fs/cgroup/p11scope-n3-UUID/{selected,outside}` scope. Only owned callers
move. Before writes/signals the harness checks actual parent, birth, UID,
namespace and pidfd; before cgroup operations it checks both held and current
directory identity and cgroup2 filesystem. Wrong-parent/birth and filesystem
controls refuse operations. It enables no controllers, changes no ambient
scope/sysctl and touches no existing kind/container workload. Cleanup signals
only held owned processes and removes only verified empty owned directories.
Scoped TERM/INT handling enters those cleanup paths, defers signals until newly
created directories/direct Popen children are enrolled, and prevents a second
termination from interrupting bounded cleanup. A failed Cgroup open still has
the actual created directory identity; a failed process validation still has
the actual unreaped direct Popen child. Replacement directories and arbitrary
descendants receive no cleanup authority. Previous signal handlers are restored.
The outer timeout allows a 20-second cleanup grace before its last-resort KILL;
a forced kill is a failed run and cannot establish cleanup or naming qualification.
The run route drops the caller to the ordinary supplied uid/gid through its
public SUDO invocation credentials. Caller/provider setup and each cell are
bounded; cgroup observer stop uses SIGINT with a five-second limit. The run
cell measures natural child completion to observer reap separately.

CPU ticks, RSS, FD and aggregate `/proc/io` read samples are exploratory on the
loaded build host. Short samples do not prove an identity-reader budget, long
plateau, capacity or final performance qualification. The summary keeps these
limits and the remaining matrix explicit.

## Still required

- Installed execution of the prepared matrix below, and independent evidence
  of the actual fixed registration/sample deadline and equality refusal.
- The unchanged leave/sample/reenter case with an
  independently observed sample during the leave, rather than a migration alone.
- PID reuse; namespace/numbering/domain controls.
- Event/discovery loss, full entry/path/interest capacity and fairness.
- Long CPU/RSS/FD/read plateau, isolated-host performance and broader stop faults.

## Prepared next matrix, separate live grant

The default remains the original six cells. These seven additional cells require
an explicit `--cells sparse1,sparse10,sparse59,sparse61,short,reexec,nonleader`
choice and a separate installed lane grant. Source preparation and unprivileged
native controls do not qualify their live behavior.

| Cell | Actual caller schedule | ACK limit | Observer duration | Naming condition |
|---|---|---:|---:|---|
| sparse1 | 5 calls with at least 1 s between completion and next entry |14 s|34 s|Nonempty correct names; actual gaps and unknown share |
| sparse10 | 4 calls with at least 10 s gaps |40 s|60 s|Nonempty correct names; actual gaps and unknown share |
| sparse59 | 3 calls with at least 59 s gaps |128 s|148 s|Report observed names/unknowns; no deadline proof |
| sparse61 | 3 calls with at least 61 s gaps |132 s|152 s|Report observed names/unknowns; no deadline proof |
| short | Fresh selected child: setup4 + main1 + teardown2, then exit |One total second|20 s|Exact population and truth; no promised name |
| reexec | Selected A, outside same-path exec/setup, selected B |10 s per phase|30 s|Both generations named; first B scoped CALL unknown |
| nonleader | Selected A, outside different-path exec by worker TID, selected B |10 s per phase|30 s|Both generations named; distinct exec TID; first B scoped CALL unknown |

`spaced` sleeps only between calls and bounds any command to a 125-second work
span. The oracle checks the independently issued count and minimum gap against
real monotonic entry/completion stamps, and reports actual gaps. The 59/61 cells
explicitly report `deadline_boundary_proof=not_exposed_by_public_output`: the
public route does not expose registration G or first sample S0/D. Correct names
in these observations do not prove a receipt existed at a fixed deadline, and
Unknown is never forced from a cell label alone.

The short cell attaches using a separate owned idle provider seed. Its setup
finishes before observation and teardown follows observer reap, both ledgered.
The new child starts behind a pre-provider gate, is independently validated and
moved into the selected scope, then the gate opens. Spawn-start to actual pidfd
exit is an upper bound on its whole lifetime and must be at most one second;
loaded-host delay fails this condition. All seven short provider calls remain
mandatory, including initialization and teardown.

Exec requests record actual executing TID, original birth, target path and scope;
the controller records the command interval and verifies the new image through
its held expected file and original process identity. A uses GenerateRandom and
B GetSessionInfo, so event keys map uniquely to generations even when the path
and file are identical. Required positives and first scoped CALL checks use
separate image-generation populations; A's names cannot satisfy B. Equal paths
do not rescue a key spanning more than one generation. Provider setup outside
the selected scope is fully ledgered and never silently omitted.

The four sparse workload spans total 274 seconds; the two exec schedules add
about 17 seconds and short at most one. Observer durations reserve 30 seconds
beyond each sparse span, phase acknowledgements reserve 10 seconds, and normal
observer stop remains bounded by five seconds. A future combined command uses
a 600-second outer guard plus its existing 20-second TERM cleanup grace, covering
startup, final drain and owned cleanup beyond workload. The guard is a failure
bound, not a promise that every loaded-host run succeeds. No live command is
authorized by this documentation.

Successful first-package cells close only the facts they actually demonstrate.
The complete N3/U2b/U6 installed gate remains open until that matrix is exercised.
