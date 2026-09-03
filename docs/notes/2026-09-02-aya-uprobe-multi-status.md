# Aya `uprobe_multi` status and p11scope integration

**Checked:** 2026-09-02  
**Aya master:** `03bee7dca209651c2f8a951d362665294c0144c9`  
**Evaluated PR head:** `8d16163ca436e3030cbd45a0f331c62cd6c059fa`

**p11scope constraint:** Rust 1.88, Linux 5.15 per-offset fallback

## Result

A new core Aya contribution is **not needed**. Aya master already implements
multi-uprobe program sections, load-time `BPF_TRACE_UPROBE_MULTI`, batched
locations/cookies, PID scopes, link ownership, and legacy multi-point fallback.
The latest released userspace crate is still Aya 0.14.0 and predates that work.

W3 defers `uprobe_multi` and stays on released Aya 0.14.0. A future dedicated
task may evaluate an exact snapshot of upstream-unreviewed open
[PR #1696](https://github.com/aya-rs/aya/pull/1696), which exposes a public probe
for the process-scoped PID-filter behavior p11scope requires. Early
multi-uprobe kernels filtered one thread rather than every thread sharing the
process address space; using only basic link support could therefore miss
sibling-thread calls silently.

The alternatives were:

1. pin an exact reviewed Aya master revision and implement W3 now; or
2. wait for the next Aya release; or
3. explicitly defer `uprobe_multi` from v0.1.

Raising the p11scope kernel floor does not solve this dependency question and
does not remove the legacy path needed for dynamic additions.

## Upstream history

- [Issue #992](https://github.com/aya-rs/aya/issues/992) was closed as completed
  on 2026-07-31.
- [PR #1548](https://github.com/aya-rs/aya/pull/1548) added
  `#[uprobe(multi)]` / `#[uretprobe(multi)]` section emission. p11scope's
  existing `aya-ebpf = 0.2.1` already resolves the released macro containing
  this support.
- [PR #1417](https://github.com/aya-rs/aya/pull/1417), merged as
  `5c1a79e0bdc36e77b304c1a08ff8b05e6b823108`, added userspace multi attach.
- [PR #1654](https://github.com/aya-rs/aya/pull/1654) refined link ownership and
  attachment handling.
- [PR #1670](https://github.com/aya-rs/aya/pull/1670) changed Aya feature probes
  to run on demand.
- [PR #1696](https://github.com/aya-rs/aya/pull/1696) is open and has no upstream
  review at the selected, locally reviewed head. It adds
  `is_uprobe_multi_supported(UProbeMultiFeature::ProcessScopedPidFilter)`,
  following the [kernel fix](https://github.com/torvalds/linux/commit/46ba0e49)
  and [libbpf probe](https://github.com/libbpf/libbpf/blob/f5dcbae7/src/features.c#L397-L424).

The latest published Aya userspace release found was
[`aya-v0.14.0`](https://github.com/aya-rs/aya/releases/tag/aya-v0.14.0), dated
2026-06-24, before PR #1417 merged.

## Verified compatibility

Aya master declares Rust 1.87 as its MSRV. Both the exact master commit and the
selected PR head passed:

```text
cargo +1.88 check --locked -p aya
Finished dev profile ...
```

This checks the Aya userspace crate under p11scope's Rust toolchain. It does not
replace p11scope's four gates or the owner-gated 5.15/6.6 live attachment rows.

## Required p11scope shape

- Replace `aya = "=0.14.0"` with exact revision
  `8d16163ca436e3030cbd45a0f331c62cd6c059fa`; never track the PR branch.
- Keep the current ordinary entry/return programs for Linux 5.15 and dynamic
  per-offset changes.
- Add dedicated `#[uprobe(multi)]` / `#[uretprobe(multi)]` twins which call the
  same existing handlers and share the existing maps. One loaded program cannot
  serve both attach types.
- Before loading either multi twin, call the public process-scoped support probe
  exactly once. `Ok(true)` selects multi, `Ok(false)` selects sticky per-offset
  fallback, and `Err` is an environment/probe failure. Once multi is selected,
  every load or link error fails and rolls back; it is never reinterpreted as
  unsupported.
- Use the stricter process-scoped probe for every capture scope, including
  cgroup capture, so one capture cannot change mechanism semantics by scope.
- Use Aya's iterator-based `UProbe::attach` and managed `UProbeLinkId`; do not
  maintain a private `bpf_attr`, raw link syscall, direct `aya-obj` dependency,
  or custom Aya fork.
- Preserve return-before-entry ordering, logical endpoint accounting, exact
  cookies, pinned object paths, and transactional rollback.
- Later additions remain per-offset. Retiring one member of an initial multi
  bundle closes that bundle, rechecks pins, reattaches survivors per-offset,
  and records the real gap as `PARTIAL`.

## Useful upstream contribution

Do not duplicate PR #1417 or PR #1696. The useful contribution is review and
test coverage for #1696:

- add deterministic mocked coverage of its program-load, basic-link, and
  process-filter errno matrices, including permission and unexpected errors;
- exercise a pre-fix kernel where basic link support is true but the
  process-scoped result is false, and a fixed or backported kernel where both
  are true;
- add a fixed-kernel test proving `OneProcess` observes a non-leader thread;
- verify seccomp/permission failures remain errors rather than unsupported; and
- provide the p11scope dual-twin and `OneProcess` use case as API feedback.

The private future-USDT cache currently collapses a cached probe error to
`false`; it is unused by p11scope. Preserve `io::Result<bool>` before that cache
is consumed. No new attach implementation or raw syscall is warranted.

## Other Aya work checked

- [PR #1479](https://github.com/aya-rs/aya/pull/1479) is the only open ring
  consumer change with a plausible throughput benefit: it batches consumer
  cursor publication and fences. It is behind master and has no p11scope
  benchmark evidence. Keep the existing bounded drain for W3; benchmark this
  PR against ring loss in the post-release ring/epoll slice before adopting or
  helping rebase it.
- [PR #1641](https://github.com/aya-rs/aya/pull/1641) only wraps repeated
  `RingBuf::next()` calls. p11scope already has a bounded `EventDrain`, so it
  removes no meaningful code and does not change transport cost.
- [PR #1697](https://github.com/aya-rs/aya/pull/1697) adds bounded retry for a
  signal-interrupted `BPF_PROG_LOAD`. It improves a rare startup failure but not
  tracing throughput; follow it after merge instead of composing another open
  PR into the W3 dependency pin.
- [PR #1636](https://github.com/aya-rs/aya/pull/1636) adds compile-time map-layout
  checks. p11scope's shared map types already use explicit layouts and exact
  ABI tests; adopt the check with a future released Aya, not as another W3 pin.
- [PR #1565](https://github.com/aya-rs/aya/pull/1565) exposes Aya's syscall mocks.
  Task 7 needs only a small injected result seam around one public feature
  probe, so this dependency is unnecessary.
- [Issue #1331](https://github.com/aya-rs/aya/issues/1331) concerns sign extension
  of eBPF map-helper errno values on older kernels. Current p11scope eBPF paths
  test those helper results only as success/failure and do not decode the errno,
  so it does not change the W3 plan.

## W3 decision

W3 selected deferral. Keep the exact PR revision above only as a future
evaluation reference after suitable Aya support is released; do not vendor
Aya, reimplement its loader, or substitute a moving branch.
