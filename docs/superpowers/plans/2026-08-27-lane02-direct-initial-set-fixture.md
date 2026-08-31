# Lane 02 Direct Initial-Set Fixture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Lane 02's invalid `env -> harness` initial-set exec chain with a direct ELF whose exact SoftHSM2 provider is a forced `DT_NEEDED` dependency.

**Architecture:** Keep the existing dlopen harness unchanged. Build a second harness from the same source with `--no-as-needed`, the exact frozen provider DSO, and a RUNPATH to that provider directory; initial-set rows execute it directly, so `OwnedChild` can pre-arm and revalidate the same executable/PT_INTERP generation required by the approved contract.

**Tech Stack:** POSIX shell, GCC/ELF dynamic linking, `readelf`, Rust artifact-contract tests.

**Spec:** `docs/superpowers/specs/2026-08-18-slice1b2-corrective-live-discovery-design.md` section 7.4 and `docs/superpowers/plans/2026-08-19-slice1b2-production.md` direct-ELF/DT_NEEDED fixture requirements.

## Global Constraints

- Do not modify Rust product lifecycle, pause deadlines, the evidence checker, schema, or privacy allowlist.
- Keep Rust 1.88, edition 2024, and Linux x86-64-first support.
- Use the same exact provider bytes for direct initial-set and dlopen rows.
- Reject apparent initial-set evidence produced through `/usr/bin/env`, a shell, shebang, or another exec chain.
- Preserve the immutable failed evidence roots; every runtime rerun uses a fresh absent private root.

---

### Task 1: Enforce a direct DT_NEEDED initial-set driver

**Files:**
- Modify: `tests/artifact_contracts.rs`
- Modify: `scripts/verify-task4-lane02.sh`

**Interfaces:**
- Consumes: `MODULE`, `HARNESS`, `spike/harness.c`, `run_row()` and the existing evidence-root integrity checks.
- Produces: `HARNESS_INITIAL=$ROOT/bin/harness-initial`, its recorded SHA-256, and direct initial-set row argv.

- [x] **Step 1: Write the failing artifact-contract test**

Add beside `lane02_checker_and_driver_self_tests_execute`:

```rust
#[test]
fn lane02_initial_set_uses_a_direct_needed_harness() {
    let driver = read("scripts/verify-task4-lane02.sh");
    assert!(driver.contains("HARNESS_INITIAL=$ROOT/bin/harness-initial"));
    assert!(driver.contains("-Wl,--no-as-needed"));
    assert!(driver.contains("set -- \"$@\" \"$HARNESS_INITIAL\" \"$MODULE\" \"$go\""));
    assert!(!driver.contains("set -- \"$@\" /usr/bin/env \"LD_PRELOAD=$MODULE\""));
}
```

- [x] **Step 2: Run the test and verify RED**

Run:

```sh
cargo +1.88 test --locked --test artifact_contracts lane02_initial_set_uses_a_direct_needed_harness -- --exact --nocapture
```

Expected: FAIL because the current driver still constructs `/usr/bin/env LD_PRELOAD=...`.

- [x] **Step 3: Add the second harness to the private evidence contract**

In `scripts/verify-task4-lane02.sh`:

```sh
HARNESS=$ROOT/bin/harness
HARNESS_INITIAL=$ROOT/bin/harness-initial
```

Add `bin/harness-initial` to `validate_terminal_tree`'s required files, the self-test terminal-tree fixture, and every root/hash integrity check that currently covers `bin/harness`.

- [x] **Step 4: Build and validate the direct harness**

After building the existing harness, build the initial driver without adding a dependency:

```sh
MODULE_DIR=${MODULE%/*}
gcc -O0 -Wl,--no-as-needed -Wl,-rpath,"$MODULE_DIR" \
    -o "$HARNESS_INITIAL" spike/harness.c "$MODULE" -ldl
INITIAL_DYNAMIC=$(readelf -d "$HARNESS_INITIAL") || exit 77
[ "$(printf '%s\n' "$INITIAL_DYNAMIC" | grep -Fc 'Shared library: [libsofthsm2.so]')" -eq 1 ] || exit 77
```

Record `harness_initial_sha256` and verify it again at terminal closure. The already-recorded module path, device/inode, size, build ID, and SHA-256 remain the provider authority for both drivers.

- [x] **Step 5: Make the script self-test exercise the topology**

Build `self_root/harness-initial` against `self_root/provider.so` with `--no-as-needed`, invoke it directly with the existing go file, and require exactly one `HARNESS_PROVIDER_INITIAL_SET`. Keep the existing unlinked harness control and require `HARNESS_PROVIDER_LATE_LOAD`.

- [x] **Step 6: Execute direct initial-set rows**

Replace only the initial-set branch in `run_row`:

```sh
if [ "$load_kind" = initial-set ]; then
    set -- "$@" "$HARNESS_INITIAL" "$MODULE" "$go"
else
    set -- "$@" "$HARNESS" "$MODULE" "$go"
fi
```

No `LD_PRELOAD` or wrapper executable remains in a promotable Lane 02 row.

- [x] **Step 7: Run focused verification**

Run:

```sh
sh -n scripts/verify-task4-lane02.sh
sh scripts/verify-task4-lane02.sh --self-test
cargo +1.88 test --locked --test artifact_contracts lane02_initial_set_uses_a_direct_needed_harness -- --exact --nocapture
cargo +1.88 test --locked --test artifact_contracts lane02_checker_and_driver_self_tests_execute -- --exact --nocapture
git diff --check
```

Expected: all PASS.

- [x] **Step 8: Independent contract review and commit**

Require Sol, Terra, and Luna reviewers to agree that the driver is direct ELF, the provider identity is unchanged, dlopen rows are unchanged, and no product/oracle/privacy contract widened. Then commit only the plan, script, and artifact test:

```sh
git add docs/superpowers/plans/2026-08-27-lane02-direct-initial-set-fixture.md \
    scripts/verify-task4-lane02.sh tests/artifact_contracts.rs
git commit -m "test: use direct needed harness for lane02 initial set"
```

- [ ] **Step 9: Run a fresh six-row acceptance campaign**

Run `scripts/verify-task4-lane02.sh` with a new absent absolute private evidence root. Require all six checker results `PASS`, direct initial-set argv, exact `C_GetFunctionList == 1`, 68 slots, 136/136 probes, unchanged one-skip rule, no pause partial/truncation, and no residue. A failed row remains `NON-PASS`; do not rerun-until-green or amend the oracle.
