# Productization Slice 1a — future review checkpoints

Use this after Slice 1a execution. It records review checks, not additional scope or an
implementation task list.

## Required correctness checks

1. **One-time hash must be metadata-stable.** Capture the pinned fd's `(ino, size, ctime)`
   before `inspect_file` computes SHA-256 and again afterwards; refuse the object unless the
   two pins match. Recording the pin only after hashing leaves a write-after-hash/before-pin
   window that later `check_unchanged()` cannot detect. This needs no re-hash.
2. **Replaced output temporaries are not ours to delete.** If the temp pathname is replaced,
   `AtomicFile::commit` must fail and `Drop` must not unlink the replacement. The regression
   test should assert that the impostor remains, not merely that the final output is absent.
3. **Duration parsing cannot overflow.** Use checked multiplication for `m`/`h` suffixes and
   test an overflowing value; malformed CLI input must return a usage error, never panic.

## Final evidence checks

- Confirm the eight retained artifact/behaviour tests still cover the default safe-only eBPF
  object, official safe-only build, privacy fixture/self-tests, evidence checker, shell
  syntax, byte-capped container streams, and pidfd/start-time-bound signalling.
- Confirm the active README/usage/schema/allowlist describe the landed tree and do not retain
  the removed lane or removed CLI flags as current behavior.
- Record the four Rust checks from the exact final tree. Record privileged/root gates as PASS
  only when explicitly approved and run; otherwise `UNRUN`. Record GitHub e2e as `PENDING`
  until an observed run passes.

## Accepted boundary to state plainly

Dropping the protected-output-directory policy leaves an atomic-publication contract, not
adversarial integrity for a parent directory writable by another process. If hostile output
directory mutation becomes in scope, restore a protected/retained directory policy rather
than adding timing checks around `renameat`.
