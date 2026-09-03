# What remains after W3

## Current baseline

W3 is closed and locally integrated on `main` at `075dc5c`. The final
production change is `ec5e0ae`. All four Rust 1.88 gates pass with 1,072 tests,
the final correctness and test-quality reviews accepted zero findings, and
`docs/privacy/allowlist-v1.md` remains byte-identical.

The two pre-W3 stashes were inspected and dropped on 2026-09-03. They contained
no unique useful work: `c1226aae` was an incomplete and partly incorrect
discovery-record checker update, while `7dbe2e9` duplicated a test mutex lock
and would deadlock. Their intended changes already exist correctly on `main`.

## Immediate product qualification

These W3 runtime rows remain `UNRUN` and are the shortest path to proving the
candidate on real workloads:

1. Run the deterministic SoftHSM `trace --pid` oracle: 226 calls from
   `spike/expected.txt` plus one `C_GetFunctionList` must equal
   `stats_entered == stats_returned == raw_calls == 227`, with zero loss.
2. Run `pkcs11-check` against SoftHSM and require every oracle call to appear
   in the capture; keep capture-only bootstrap calls separately identified.
3. Repeat the per-offset path on Ubuntu 22.04 / Linux 5.15 and Ubuntu 24.04 /
   Linux 6.8 with exact binary, embedded-BPF, and kernel evidence.
4. Run the cgroup lifecycle oracle covering fork, exec, `dlopen`, calls,
   `dlclose`, replacement/reload, retirement, and absence of stale attribution.

The exact deterministic command and evidence checker are preserved in
[`2026-09-02-wave3-correctness-closure.md`](2026-09-02-wave3-correctness-closure.md).

## Remaining release waves

Execute in this order so the ia32 uprobe-path change precedes expensive runtime
requalification:

1. **W4 — hosted CI:** run canonical and unprivileged lanes on x86-64. A remote
   push remains owner-gated; without it, hosted-CI acceptance remains unmet.
2. **W7 — ia32 targets:** observe a 32-bit PKCS#11 target on x86-64 and add an
   honest refusal for unsupported corners.
3. **W5 — containers/Kubernetes:** requalify Docker, kind, and Knative; ship
   verified seccomp and SELinux artifacts rather than recommending unconfined
   operation.
4. **W6 — distro/kernel matrix:** qualify Jammy 5.15, Noble 6.8, Fedora 6.19,
   selected additional kernels, proxy-stack behavior, supported-rate/loss,
   and fork/exec/load/unload lifecycle behavior.
5. **W8 — release assembly:** freeze the release tip, repeat all provisional
   runtime rows, complete the receipt and acceptance table, perform the final
   truth/review pass, and create the ready-to-publish bundle.

Push, tag, package publication, and release remain explicit owner decisions
after W8. `uprobe_multi` is a separate post-W3 performance task and does not
block the per-offset release path; reopen it after suitable stable Aya support.

## Known W3 limits carried forward

- A process may escape observation if it enters and leaves a watched cgroup
  between destination-authenticated observations; arbitrary migration is not
  part of W3 completeness claims.
- A proven task-bound lifecycle-link loss is reported and forces `PARTIAL`, but
  W3 does not continuously re-arm that link.
- No supported throughput or public kernel-support claim exists until the W6
  runtime oracles pass.
