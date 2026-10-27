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

The three engine controls are not compiled or run yet. They require a
nonempty advisory TGID sweep snapshot, a deep scan with the actual sparse
provider target and file pins, and an unavailable rather than successful
empty snapshot for an ended group. No Cargo-heavy command has started;
the release's quiet window takes priority.

## Bounded implementation contract

1. Open a cold view only through the original TGID pidfd, retained leader
   birth, Z boundary, and a fresh same-group nonleader birth/Tgid witness
   whose task is live and lacks PF_EXITING. Exactly one member is eligible;
   ambiguity is a named refusal. Missing, stale, unreadable, exhausted,
   whole-group-dead, and pre-Z evidence grants no cold route.
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
