# Phase 1b — end-to-end attach verification (Gate G1)

`scripts/verify-attach-e2e.sh` runs the whole pipeline against a real
provider — `p11scope-discover` → `p11scope profile` (uprobe+uretprobe
attach) → a deterministic PKCS#11 workload (`spike/harness.c`) — and
diffs the observed call counts against the workload's exact ground
truth (`spike/expected.txt`). Run twice on this host, both runs
identical and matching exactly.

## Environment

- Kernel: `7.0.0-28-generic` (`/proc/sys/kernel/osrelease`)
- Module under test: `/usr/lib/softhsm/libsofthsm2.so` (SoftHSM2)
- `rustc 1.94.0`, `file 5.45`

## Observed vs expected

| function          | expected | observed | result |
|--------------------|---------:|---------:|:------:|
| C_CloseSession      |       10 |       10 |  ok   |
| C_Digest            |       50 |       50 |  ok   |
| C_DigestInit        |       50 |       50 |  ok   |
| C_Finalize          |        1 |        1 |  ok   |
| C_GenerateRandom    |      100 |      100 |  ok   |
| C_GetInfo           |        3 |        3 |  ok   |
| C_GetSlotList       |        1 |        1 |  ok   |
| C_Initialize        |        1 |        1 |  ok   |
| C_OpenSession       |       10 |       10 |  ok   |

All 9 functions the harness calls matched the oracle exactly, on every run.

## Evidence (from `observed.json`)

```json
{
  "aliased": [],
  "attach_failures": [],
  "attached_probes": 136,
  "completeness": "COMPLETE",
  "in_flight_at_end": 0,
  "skipped": [],
  "slots": 68,
  "table_entries": 68
}
```

136 probes attached (68 slots × uprobe+uretprobe), 0 skipped, 0 aliased, 0
attach failures, 0 in-flight at end → `COMPLETE`. `capture.kernel` in the
JSON: `7.0.0-28-generic`; `capture.module`:
`/usr/lib/softhsm/libsofthsm2.so`.

Full per-function breakdown (only functions the harness calls have nonzero
counts; the other 59 of SoftHSM2's 68 exported PKCS#11 functions correctly
show 0 calls / 0 errors — the harness never calls them):

```
C_GetFunctionList 1
C_Initialize 1
C_Finalize 1
C_GetInfo 3
C_GetSlotList 1
C_OpenSession 10
C_CloseSession 10
C_DigestInit 50
C_Digest 50
C_GenerateRandom 100
(all other 58 functions: 0)
```

## Static musl build

```
$ file target/x86_64-unknown-linux-musl/release/p11scope
target/x86_64-unknown-linux-musl/release/p11scope: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, BuildID[sha1]=7f330d59e8dc351a0d5d6b3d800e59c68da39d35, not stripped
```

`rustup target add x86_64-unknown-linux-musl` plus
`RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target
x86_64-unknown-linux-musl --bin p11scope` succeeded directly on this host —
the toolchain already had a working musl C toolchain (`musl-tools` was not
needed, no container build was required). `ldd` on the same binary confirms
"statically linked" (no dynamic interpreter / no `INTERP` program header).

## Deviations from the brief's literal script (and why)

1. **`cargo build --release --workspace`, not `cargo build --release`.**
   The root `Cargo.toml` is a combined package+workspace manifest (`p11scope`
   is both the root package and a workspace member alongside
   `crates/discover`, `crates/manifest`, `crates/ebpf-common`). Since Cargo
   1.71, running `cargo build` from a directory that is itself a package
   only builds that package by default — it does **not** build sibling
   workspace members. A plain `cargo build --release` therefore silently
   built only `p11scope` and left `p11scope-discover` missing; the
   `discover` step of the script would fail with "No such file or
   directory". Verified directly: with a workspace member binary removed,
   `cargo build --release` (no `--workspace`) left it absent, while
   `cargo build --release --workspace` rebuilt it. Fixed by adding
   `--workspace`.

2. **`file` reports musl static-PIE binaries as `static-pie linked`, not
   `statically linked`.** On this host's toolchain (`rustc 1.94`, `file
   5.45`), the crt-static musl build is a static position-independent
   executable, and `file`'s magic database describes that case with the
   string `static-pie linked` rather than `statically linked`. Grepping
   only for `statically linked` (the brief's literal check) false-negatives
   a genuinely static binary. The script now accepts either string
   (`grep -qE "statically linked|static-pie linked"`); `ldd` on the same
   binary was used to independently confirm it has no dynamic interpreter.

3. **Private SoftHSM2 token store.** `spike/harness.c` calls
   `C_GetSlotList(tokenPresent=1, ...)` and needs at least one initialized
   token, but this host's system SoftHSM2 config/token directory
   (`/etc/softhsm/softhsm2.conf`, `/var/lib/softhsm/tokens`) is
   `root:softhsm`-owned and unreadable by the running user (`sudo -n true`
   works for BPF privileges, but the harness itself is not run under
   `sudo`). Not something `spike/harness.c` or the pipeline under test can
   route around, and no crates/src change is implicated — it's host
   fixturing. The script now points `SOFTHSM2_CONF` at a private,
   disposable config/token directory under `target/e2e/`, recreated by
   `softhsm2-util --init-token` on every run, and exports it (via `sudo
   --preserve-env=SOFTHSM2_CONF`, harmless since `p11scope profile` itself
   never touches SoftHSM2) so the harness subprocess sees it.

None of these required any change to `crates/` or `src/` — the attach
pipeline itself (`p11scope-discover`, `plan::build`, `attach::Session`,
`metrics::read`) worked correctly on the first successful run once the
harness could actually reach a live token.

## Debugging notes

The pipeline matched the oracle on the very first successful invocation
once the three points above were worked out (build target set, SoftHSM2
token availability, `file` output format) — no count-mismatch debugging
(all-zero / doubled / off-by-a-few) was needed. `set -eu` is present as an
explicit line in the script body (not relying on the shebang), per the
project's established gotcha.
