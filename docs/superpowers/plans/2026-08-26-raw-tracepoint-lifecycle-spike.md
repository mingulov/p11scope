# Raw-tracepoint lifecycle feasibility spike

**Worktree:** `/home/user/src/m/pkcs11-scope/.claude/worktrees/raw-tracepoint-lifecycle`  
**Branch/base:** `research/raw-tracepoint-lifecycle` at `24af62031c609cf546797d96fc20517d13f1f292`  
**Status:** source/API and generated-object feasibility established; verifier and
runtime probes UNRUN. The patch remains throwaway and uncommitted.

## Question

Can the three sched lifecycle/fork attachments use raw tracepoints so p11scope
does not need tracefs ID files, without adding capabilities or weakening its
all-or-nothing lifecycle, ownership, privacy, and fail-closed contracts?

## Static findings

- `sched_process_exec` and `sched_process_exit` do not read tracepoint context.
  Converting those two to Aya raw tracepoints is mechanically feasible and
  preserves existing authorization and lifecycle record emission.
- This removes tracefs dependence for PID-scoped modes and cgroup
  aggregate-only metrics.
- Cgroup event-producing profile/trace still attaches `sched_process_fork`.
  Complete tracefs independence therefore requires converting fork too.
- `tp_btf/task_newtask` runs before the child becomes runnable and supplies its
  `task_struct *` without a tracefs ID lookup. Pinned Aya can load this program
  type, but its generated bindings expose `task_struct` as opaque.
- The existing formatted fork decoder reads task IDs, while p11scope state is
  keyed by TGID. A worker-thread fork and `CLONE_THREAD` can therefore be
  misclassified today; a replacement must validate and emit process TGIDs.
- Aya 0.14 already exposes `RawTracePoint::{load, attach}` and owns links by
  file descriptor. Raw attachment uses `BPF_RAW_TRACEPOINT_OPEN`, so it removes
  tracefs filesystem access without adding a capability; existing BPF/uprobe
  authority remains required.

## Decision

Keep the completed raw-exec/exit probe. Add a separate throwaway fork probe
using `tp_btf/task_newtask` and a frozen map populated from the exact BTF bytes
used to load the program. Resolve only `task_struct.{pid,tgid}` and the
`btf_trace_task_newtask` prototype. Require unique, signed 32-bit, byte-aligned,
in-bounds fields and no compiled or fixed-offset fallback.

The BPF classifier must read `pid` and `tgid` from `bpf_get_current_task()` and
the `task_newtask` child pointer, then require the current-task pair to equal
both halves of `bpf_get_current_pid_tgid()`. The throwaway probe may count a
mismatch or read failure locally and emit no fork; product promotion separately
requires wiring that loss into explicit `PARTIAL` evidence.
Skip `child.pid != child.tgid` (`CLONE_THREAD`); otherwise emit parent and child
TGIDs. This property-based, authoritative-BTF invariant supersedes the earlier
mechanism-specific requirement for ELF CO-RE, but does not authorize product
promotion by itself.

Reject a permanent dual backend: it doubles programs, link variants, rollback,
inventory, and tests. No-tracefs cgroup event support remains a separate track
until this probe is accepted. `CLONE_VM` without `CLONE_THREAD`, PID-namespace
observer placement, cgroup movement, ring loss, and deliberate child `setsid()`
escape remain explicit limitations or runtime gates rather than guesses.

## Alternatives review

Independent Aya inventory and Sol architecture review reached the same result:

- Keep raw exec/exit and probe `tp_btf/task_newtask`; it is the smallest sound
  Linux 5.15 design that observes the fork before the child runs.
- A raw `sched_process_fork` program would need the same BTF-derived task layout
  while losing the BTF tracepoint's typed-signature check. Probe it only if the
  typed candidate fails or it deletes meaningful code.
- Reject deferred child binding, task storage, fentry/fexit, kprobe-multi,
  iterators, LSM/cgroup lifecycle hooks, BPF tokens, a privileged broker, and
  bpffs-pinned links. None preserves the required timing and ownership model
  with less machinery on the pinned kernel/toolchain.
- `uprobe_multi` is a future kernel-baseline experiment only. It may reduce link
  count and per-site perf attachment on approximately Linux 6.6+, but Aya 0.14
  has no attach API for it and adopting it now would violate the Linux 5.15
  contract or create a permanent backend matrix.

Raw lifecycle attachment does **not** lower the product's overall capability
floor. PKCS#11 uprobes still use `perf_event_open`; on the measured restrictive
host, `CAP_BPF` plus `CAP_PERFMON` did not attach them and `CAP_SYS_ADMIN` was
still required. The accepted product claim is therefore narrower: the raw/BTF
lifecycle path can remove tracefs filesystem dependence without adding
capabilities. Any lower-capability claim needs a separate uprobe experiment.

Cost if wrong: an unsafe fork decoder can silently corrupt process/session
ownership. The spike therefore fails closed on any fixed offset, missing or
invalid BTF-derived layout proof, verifier rejection, new capability, tracefs
access, or fork identity mismatch. A rejected spike changes no product ABI or
Task-10 evidence.

## Throwaway probe gates

1. Preserve the existing raw-exec/exit object proof unchanged.
2. Fork compile/static: add only the minimal `tp_btf/task_newtask` fixture,
   frozen layout map, and host BTF resolver needed to prove the candidate.
   Prove the isolated candidate object has the exact `tp_btf/task_newtask`
   section, BTF-tracepoint program/link types, no formatted fork section, and no
   fixed task offset. Do not count the unchanged product fork attachment.
3. Unprivileged parser/contract checks: synthetic malformed-BTF cases, current
   `/sys/kernel/btf/vmlinux` resolution, swapped/corrupt offsets, worker-thread
   TGID classification, `CLONE_THREAD` suppression, freeze-before-attach,
   rollback, and fatal no-fallback behavior.
4. Privileged runtime, only after static success: first prove verifier
   acceptance of the map-derived bounded reads; then mask both tracefs views
   and A/B compare formatted and candidate fork on Linux 5.15 and one current
   kernel for single-thread, worker-thread, `vfork`, process `clone3`,
   `pthread_create`, PID namespace, cgroup movement, loss, and ordering stress.
5. Accept the isolated candidate only if it opens no tracefs `id` path, exact
   TGID inheritance holds, failures are explicit/fail-closed, rollback remains
   transactional, and no new capability is needed. Product promotion additionally
   requires integrating identity loss into `PARTIAL`, replacing the existing
   formatted fork path, and fresh Luna and Sol agreement after runtime evidence.

## Current ruling

The throwaway raw-exec/exit probe compiles with pinned Aya. A fresh top-level
build produced identical copied/original eBPF objects with SHA-256
`96ebb8962fb20cd487d228a3be66ff16e9220a50f20e097815ca45d9279321e4` and exact
sections:

- `raw_tp/sched_process_exec`;
- `raw_tp/sched_process_exit`;
- `tracepoint/sched/sched_process_fork`.

The static artifact test, workspace check, and 24 attach tests passed. This is
source/API/object evidence only: verifier acceptance, masked-tracefs runtime,
capability parity, pause behavior, and cross-kernel behavior remain UNRUN.

Independent Luna and Sol reviews agree the isolated probe is worth keeping but
must not be promoted. Before a real design, it must remove the now-unreachable
exec/exit tracefs-degradation/remount contract, make raw attach errors uniformly
fatal, pin exact exec/exit/fork type selection, and add faithful raw-link rollback
and terminal-detach ordering tests. The current source-string test alone cannot
authorize product acceptance.

Full no-tracefs cgroup event support is now **conditionally feasible but
UNPROVEN** on the pinned toolchain. The next discriminating step is the minimal
unprivileged BTF-resolver/object probe; verifier and runtime claims remain
UNRUN. The main Task-10 path remains unchanged in its own worktree.
