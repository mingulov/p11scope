<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Future cold leader view admission (R56)

Branch `task/v051-cold-leader-survivor` starts at
`6d6f5f13acd379d181666d65c3d21a5a51809acb`. This is future work. The
v0.5.0 candidate and its R56 limitation are unchanged.

## Reproduction and first checkpoint

The real C fixture `tests/fixtures/cold-leader-view.c` can keep zero, one,
or two workers after a controlled leader exit. The one-worker case can
execute three actual callbacks from a version-3.2 sparse common-68 table
after the leader is Z. It exports its getter and callback so discovery must
find a useful provider rather than merely report an empty successful scan.

Native checks confirmed that the Z leader's namespace, root, and exe links
are unavailable, its mountinfo cannot be read, and its maps is empty.
The live member serves these filesystem facts; its namespace matches the
one observed before leader exit. Strict GCC and the native zero/one/two
protocol controls passed; the one-worker callback ledger reports three.

The first Rust source-seam run used the actual `ProcessView::open`,
`mount_namespace_id`, pidfd acquisition/readiness, proc-stat readers, and
monotonic-clock functions from this source, with direct LP64 syscall FFI.
The test fixture's temporary-directory allocator and the unused accounting
type were stand-ins. Four real-OS controls ran: warm and whole-group-dead
passed; cold one-worker admission and the named two-worker refusal failed
at the expected namespace ENOENT. This is actual constructor RED, not a
full product build or live capture qualification.

The four engine controls are not compiled or run yet. They require a
nonempty advisory TGID sweep snapshot, a deep scan with the actual sparse
provider target and file pins, and an unavailable rather than successful
empty snapshot for an ended group. No Cargo-heavy command has started;
the release's quiet window takes priority.

## Bounded implementation contract

1. Open a cold view only through the original TGID pidfd, retained leader
   birth, Z boundary, and a fresh same-group nonleader birth/Tgid witness
   whose task is live and lacks PF_EXITING. Multiple workers are eligible
   when a bounded complete census and fresh held-member reads establish
   one common mount namespace and root (device, inode, mount ID). Differing
   or unprovable filesystems are a named refusal. Missing, stale, unreadable,
   exhausted, whole-group-dead, and pre-Z evidence grants no cold route.
2. Use a private transient filesystem proof for namespace, root, mountinfo,
   exe, and maps, preserving the TGID, scope, view admission, mapping and
   mount-namespace checks. A bare TID is never group authority. Re-prove the
   exact member and original group before and after operations. Charge and
   bound directory and metadata reads. No process-wide bypass, unbounded
   task walk, new BPF field, or public schema is needed.
3. Thread that proof through initial and reconciliation snapshots and the
   corresponding deep-scan file opens. Sweeps remain advisory, and deep
   scans retain their own original process custody. Sparse providers use
   the same existing table and target decoder; no version/shape rule is
   relaxed to make a cold test pass.

A semantic `RetainedGroupMember` must not be held for the whole view
lifetime: its unique LIVE_MINTS slot would prevent the later scan and
caller phases from minting their own transient proof. Any private readonly
filesystem proof must not mint caller/image/semantic authority.

Changes are expected in `process.rs` and a private process module; the
bounded read paths in `scan.rs` and `identity.rs`; and only the view-open,
maps/read-path/sweep functions in `engine.rs`. The separate R48 worker owns
the native retirement barrier and collected-Finish propagation. The next
checkpoint is coherent source review plus actual V1 cold/warm/dead/
ambiguous/reuse/unreadable controls and affected scan/scope neighbors.
Full product checks and installed count usefulness remain separate work.

## Source implementation checkpoint

The private `process/view_filesystem.rs` proof now routes fixed proc-owned
maps, memory, executable, mountinfo, and range identities. Target-root object
opens reject parent traversal and use `openat2` with `RESOLVE_IN_ROOT` and
`RESOLVE_NO_MAGICLINKS`; an unavailable/denied syscall is an explicit refusal.
No arbitrary proc-path rewrite or numeric kernel gate is added. Namespace
and root descriptors stay held during the operation, and each live member,
the complete member set, and the original leader are bracketed again.

`ProcessView` retains a monotonic atomic cold-boundary marker. Once the
original leader was proved Z, a worker EXEC cannot make a readable successor
renew the old view through the ordinary leader path. The marker also stays
set if later member metadata fails. The existing EXEC replacement admits a
fresh view. This grants no caller or image semantics.

Initial and reconciliation map snapshots preserve the existing fast shard
reader. Unavailable Z-leader rows get a serial cold proof against the passed
capture budget and one shared stage cutoff; each refusal remains unavailable.
Reconciliation uses its existing quantum. Deep scans and acquired-table
readers keep their own retained process view and existing decoder/ABI checks.
The private ScanIo budget arguments now reach metadata operations; canned IOs
accept the new argument without gaining a native filesystem bypass.

Twelve source/native controls now pass (zero skipped): warm/dead/lone/shared
two-worker views; native sparse-table and target-object reads; second-worker
namespace/root/mount-ID mismatch and unreadable facts; changed birth; real
member exit while the group pidfd stays non-ready; parent traversal; cached
mountinfo and object opens; and actual nonleader EXEC with old-view refusal
a fresh successor control, and an expired shared-stage cutoff that cannot renew itself. GCC is strict and rustfmt passes. The source
harness compiles the actual view, pidfd, proc-custody, filesystem, mount-cache,
and monotonic-clock functions. Its dependency adapters cover temporary dirs,
capture-budget plumbing, PID-numbering facts and bounded mountinfo text reads.
The native host was Linux 7.0.0-38-generic x86_64 with Rust 1.99.1.
It does not validate the full product's budget/window/resource integration.

Limits still to verify or retain explicitly:

- Cargo compile/check/clippy and the four engine regressions are **UNRUN**
  under the release resource/quiet hold. No full product, live capture,
  mapping-identity backend parity, pressure or installed claim is made.
- The proof admits at most 128 observed members per operation. A larger,
  changed or incomplete census refuses with an unproven-capacity/census
  reason. Descriptor pressure also refuses; all added descriptors are owned
  and transient. Product pressure behavior remains unqualified.
- Common-filesystem multiworker views do not broaden the separate
  `CallerRegistry::cold_admit_member` semantic mint, which still requires
  exactly one survivor. Multiworker caller/S1 admission remains a separate
  limitation. This checkpoint is filesystem/discovery work, not a claim that
  every R56 behavior is complete.
- A thread group alone does not prove one filesystem view. Linux permits
  per-task filesystem/namespace changes; the kernel paths used to check this
  boundary are `ksys_unshare`/`unshare_fs` and `mntns_install`:
  https://raw.githubusercontent.com/torvalds/linux/v6.6/kernel/fork.c
  and https://raw.githubusercontent.com/torvalds/linux/v6.6/fs/namespace.c .

Next: controller-scheduled V1 compile and the exact cold/process/scan/loader
neighbors, then one coherent future-branch peer review. The R48 retirement
barrier/Finish lane and v0.5.0 candidate stay separate.
