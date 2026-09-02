# Aya `uprobe_multi` status and p11scope integration

**Checked:** 2026-09-02  
**Aya master:** `03bee7dca209651c2f8a951d362665294c0144c9`  
**p11scope constraint:** Rust 1.88, Linux 5.15 per-offset fallback

## Result

A new core Aya contribution is **not needed**. Aya master already implements
multi-uprobe program sections, load-time `BPF_TRACE_UPROBE_MULTI`, batched
locations/cookies, PID scopes, link ownership, and legacy multi-point fallback.
The latest released userspace crate is still Aya 0.14.0 and predates that work.

The practical p11scope decision is therefore dependency timing:

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
- [PR #1696](https://github.com/aya-rs/aya/pull/1696) is still open and proposes
  a public multi-uprobe support probe. It is useful to p11scope but not required:
  a fixed-attribute multi-program load attempt can be the runtime probe.

The latest published Aya userspace release found was
[`aya-v0.14.0`](https://github.com/aya-rs/aya/releases/tag/aya-v0.14.0), dated
2026-06-24, before PR #1417 merged.

## Verified compatibility

Aya master declares Rust 1.87 as its MSRV. At the exact master commit above:

```text
cargo +1.88 check --locked -p aya
Finished dev profile ...
```

This checks the Aya userspace crate under p11scope's Rust toolchain. It does not
replace p11scope's four gates or the owner-gated 5.15/6.6 live attachment rows.

## Required p11scope shape

- Replace `aya = "=0.14.0"` with one owner-approved exact upstream Git revision;
  never track a moving branch.
- Keep the current ordinary entry/return programs for Linux 5.15 and dynamic
  per-offset changes.
- Add dedicated `#[uprobe(multi)]` / `#[uretprobe(multi)]` twins which call the
  same existing handlers and share the existing maps. One loaded program cannot
  serve both attach types.
- Runtime-select the multi twins only after a positive support decision. Until
  PR #1696 lands, treat only failure of the fixed-attribute multi load—after the
  equivalent legacy twin loaded—as unsupported; never turn arbitrary
  link-create `EINVAL` into fallback.
- Use Aya's iterator-based `UProbe::attach` and managed `UProbeLinkId`; do not
  maintain a private `bpf_attr`, raw link syscall, direct `aya-obj` dependency,
  or custom Aya fork.
- Preserve return-before-entry ordering, logical endpoint accounting, exact
  cookies, pinned object paths, and transactional rollback.
- Later additions remain per-offset. Retiring one member of an initial multi
  bundle closes that bundle, rechecks pins, reattaches survivors per-offset,
  and records the real gap as `PARTIAL`.

## Useful upstream contribution

Do not duplicate PR #1417 or the open PR #1696. The useful contribution is
integration feedback on #1696:

- exercise its public support probe on one pre-6.6 kernel and one 6.6+ kernel;
- confirm the result before any multi-typed program is loaded;
- verify container/seccomp denial remains distinguishable from unsupported
  kernel behavior; and
- provide the p11scope dual-twin use case as API feedback.

If maintainers ask for code, the smallest useful addition is an upstream
integration test demonstrating runtime selection between two wrappers sharing
one handler/maps contract—not another attach implementation.

## Recommended W3 decision

Prefer an exact reviewed Aya master pin after checking whether PR #1696 will
merge imminently. If release policy rejects an unreleased Git dependency, defer
multi attach rather than vendoring Aya or reimplementing its loader. Continue
W3 Tasks 1–6 while that dependency decision is pending.
