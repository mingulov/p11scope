# Ubuntu 26.04 Primary Development Host Plan

**Goal:** Restore a clean development baseline on the transferred Ubuntu 26.04
host, then resume the existing W7 task-storage and kernel qualification plans.

**Continuation:** Work on `hardening/release-local` from the repaired
`w7-ia32` worktree. W3 is already incorporated. Keep unfinished release work
off `main` until the existing acceptance gates pass.

## Decisions

- Ubuntu 26.04 is the primary development host.
- QEMU and qemu-img 10.2.1 are the active VM host tools. Active harnesses do
  not need compatibility with QEMU 8 or the previous Ubuntu 24.04 host.
- Product behavior and tests remain portable across older and different Linux
  distributions, supported kernels and toolchains, and GNU/uutils userlands.
  Do not add Ubuntu-specific runtime behavior or use host binary layouts as
  fixtures.
- Rust remains 1.88 with edition 2024. Mise selects the project toolchain;
  rustup and Cargo keep their standard per-user homes.
- The inaccessible pinned `pkcs11-proxy-ng` Git revision is restored from the
  transferred exact sibling repository or verified offline payload. Normal
  repository entry points must prepare generated patched sources before Cargo.
- Historical evidence and manifest-covered VM files remain unchanged.
- Linux 5.15 guest/runtime qualification remains part of the existing W7
  release plan; retiring the old development host does not narrow product or
  guest compatibility.

## Work

1. Replace the owned-child final `execveat(AT_EMPTY_PATH)` with descriptor
   execution through a precomputed `/proc/self/fd/N` path. Preserve the opened
   inode, barrier and hardening order, `CLOEXEC`, argv/environment, and refusal
   behavior. Add focused lifecycle coverage and document the procfs requirement.
2. Make the eight stale-identity discovery fixtures mutate a copied ELF without
   changing its executable layout. Keep production executable-offset validation
   strict.
3. Track the project `mise.toml`; update contributor and agent instructions to
   use `mise exec -- ./scripts/cargo.sh`; remove transferred absolute paths; and
   document the exact Ubuntu 26.04 setup and cache bootstrap.
4. Qualify exactly QEMU/qemu-img 10.2.1 in the active Slice 1b-2 harnesses and
   create a persistent operational VM derivative without changing custody bytes.
5. Run fmt, locked check, test and clippy through the maintained wrapper, plus
   focused QEMU/KVM preflight and custody/worktree checks.
6. Resume task-storage Task 3A-D at its existing restart handoff, then complete
   Linux 5.15 and final release qualification before merging W7 to `main`.

## Acceptance

- The ten Ubuntu 26 baseline failures pass without weakening production checks.
- Direct `/bin/sleep` owned launch works on the installed uutils build while
  rename/unlink identity, descriptor closure and `no_new_privs` remain covered.
- A fresh checkout has copy-pastable mise and dependency preparation commands.
- Active QEMU preflight accepts 10.2.1 and refuses other or mixed versions.
- Original evidence/VM manifests still verify and repaired worktrees remain
  valid.
- W7's canonical repository gates pass on the exact final tip before integration.
