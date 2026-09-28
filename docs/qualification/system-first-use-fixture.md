<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# First-use workload fixture and physical custody

`tests/fixtures/system-first-use.c` supplies a private LP64 provider and
driver for the [first-use contract](first-use-contract.md).
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
The `mapped` time is sampled after `dlopen` and symbol lookup return; it
is a workload observation of the loaded state, not an exact kernel VMA
creation timestamp. `publication_returned` is likewise sampled by the
driver after return. Keep those authorities explicit when comparing times.
The original file stat is not a live map_files receipt. The optional
post-call receipt described below binds the addressed mapping to retained
physical custody without adding an observer wait before the call.

## Ordinary fixture controls

`python3 -I tests/python/test_system_first_use_fixture.py -v`
exercises nine controls. Each run compiles the driver and three provider variants
with `-Wall -Wextra -Werror`. The tests cover actual publication/call gates,
ungated completion, body truth and ordered clocks, file/heap placement,
equal bytes on a distinct inode, malformed-table refusal and ledger custody.
It also verifies rejection of invalid receipt arguments and preservation
of an existing receipt file after the ordinary call has executed. Hosted
CI and `scripts/gates.sh` invoke this suite.

Use a private disk-backed `TMPDIR` as described in
[contributor verification](../../CONTRIBUTING.md#verification). A passing
ordinary fixture suite does not establish native observer first-use coverage.

## Post-call physical custody

The private driver accepts three additional arguments: an inherited Unix
`SOCK_SEQPACKET` descriptor, a 64-character lowercase hex nonce, and a
private receipt directory. After the ordinary call returns, while its
loader reference remains open, it records `receipt_started`, opens the
exact addressed `/proc/self/map_files/START-END` file and its mount namespace,
then sends both descriptors in one nonblocking `SCM_RIGHTS` message. It
records `receipt_sent`, unloads, and exits. No acknowledgement is expected.
There is no fallback to opening the provider by pathname.

Raw before/after maps and target mountinfo use exclusive files and a 2 MiB
acceptance bound; at most one extra byte is retained to demonstrate an
overflow. Failure preserves partial evidence and makes the fixture fail.
The extra post-call residency is visible in the ledger. Discovery during
that interval cannot establish that the earlier call was observed.

`scripts/system_first_use_receipt.py` requires the actual owned child's
kernel `SCM_CREDENTIALS`, retained PID/birth and pidfd, successful ordinary
wait, exactly one packet and channel EOF. The socketpair creator's
`SO_PEERCRED` is not the sender identity. Both received descriptors remain
open through validation, including namespace-type checking with the Linux
nsfs ioctl and independent file hashing. The mapping-device domain is
joined to the file-device domain through the existing addressed-mapping /
target-mountinfo bridge; equal bytes on another inode do not match.

The receiver checks nonce, namespace and generation stability, executable
mapping range, bounded raw snapshots, workload body count/return, and
ordered workload/receipt clocks. All received descriptors close on both
success and failure. `Custody.launch` now accepts an explicit `pass_fds`
list; its existing PID/birth and child-settlement behavior is retained.

This acquisition is labelled `trusted_fixture_post_call_scm_rights` in a
distinct `p11scope/first-use-mapping-receipt/v1` schema. Its authority includes
the pinned single-thread fixture and provider: neither changes the addressed
code mapping, execs, or switches namespace between the call and acquisition.
Descriptor passing alone cannot attest where an arbitrary sender obtained
a file or reconstruct a past mapping. This is neither a runtime identity
replacement nor a hostile-root attestation mechanism.

## Receipt verification

`python3 -I tests/python/test_system_first_use_receipt.py -v`
exercises fourteen ordinary controls, including actual child send/exit/unlink,
credential attribution, duplicate packets, failed child exits, timeout,
descriptor closure, malformed/duplicate JSON fields, identity mismatches,
changed mappings, bounded snapshots, and independent body/time negatives.
The positive mapping inputs in this ordinary suite are explicitly synthetic.
Both CI entry points run it. The process-custody suite independently checks
child settlement and descriptor handling.

The explicit native prerequisite is
`tests/python/probe_system_first_use_receipt.py`. It requires prebuilt pinned
driver/file/heap binaries, a fresh output directory, root, the shared leases
and an independently owned supervisor. It receives only after the actual fixture
child is terminal. Required controls are file and heap tables, a new mount
namespace, and `map_files` EPERM after dropping the relevant capabilities.
An ordinary suite's permission-related skip does not satisfy this prerequisite.

A successful native physical receipt proves the fixture's mapping custody.
It does not prove that an observer captured the earlier entry. The full
[configured first-use matrix](first-use-contract.md) still requires
independent workload, publication, scan, attachment and observed-entry facts.
