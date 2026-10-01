<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Owned multi-wrapper fixture provider + workload oracle

This fixture supplies independent ground truth for published-wrapper
coverage. The observer must prove coverage against published/called wrappers,
never infer it from admission counts — this fixture is the owned provider the
workload activates, and the oracle is the exact expected observation.

## Layout

- `provider.c` — owned PKCS#11-shaped provider: 64 contiguous 840-byte
  `{3,2}` template tables (53,760 bytes, the observed p11-kit shape), heap
  published wrappers with first-free-index allocation (holes on release),
  per-index distinct closures for ordinals `{0,5,13,18,43,44}`, shared
  ordinals 65/66, one never-called legacy `{2,40}` static table, and the
  standard `C_GetFunctionList` / `C_GetInterfaceList` / `C_GetInterface`
  return ABIs. Factory: `mw_alloc(fwd_mask, fail_ord)`, `mw_free`,
  `mw_index`, `mw_table`, `mw_occupied`.
- `backend.c` — separate shared object (real cross-object target) plus
  `mw_log`, the single call-record writer both objects share.
- `workload.c` — seeded deterministic driver: one scenario per process,
  writes the call log (via the provider stubs) and the oracle JSON.
- `tests/multi_wrapper_oracle.rs` — fixture self-tests (exact oracle
  assertions + pinned goldens). Coverage experiments consume the same binaries.

Selection-coverage additions (no scenario behavior change): `C_GetInterface`
with a NULL name returns the default interface (lowest-index live
wrapper, else legacy); `mw_set_version` rewrites one live wrapper's
version word in place; `mw_poke` rewrites one live entry in place (0
NULL hole, 1 unmapped, 2 provider .bss data, 3 heap data). The stage
REPL gains `G <name|-> [major minor]` (drive `C_GetInterface`, print
the result), `V <idx> <major> <minor>` and `M <idx> <ord> <mode>`.

`STRIPPED_VARIANT=1` renames/hides the template pool and packs occupancy as
a bitmap instead of a byte array; the build then runs `strip --strip-all`.
Same workload behavior, unknown layout (`layout_known: false`).

## How to run

```sh
# Everything below is what tests/multi_wrapper_oracle.rs does per test run.
d=$(mktemp -d)
gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs \
    -o "$d/backend.so" tests/fixtures/multi-wrapper/backend.c
gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs \
    -o "$d/provider.so" tests/fixtures/multi-wrapper/provider.c "$d/backend.so"
gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -Wl,-z,defs \
    -DSTRIPPED_VARIANT=1 \
    -o "$d/provider-stripped.so" tests/fixtures/multi-wrapper/provider.c "$d/backend.so"
strip --strip-all "$d/provider-stripped.so"
gcc -std=c11 -O2 -Wall -Wextra -Werror \
    -o "$d/workload" tests/fixtures/multi-wrapper/workload.c -ldl

# workload <provider.so> <scenario> <seed> <log> <oracle>
"$d/workload" "$d/provider.so" five 0 "$d/five.log" "$d/five.oracle.json"
```

Scenarios: `five` (5 wrappers, indices 0..4), `holes` (18 allocs, free
0..16, index 17 active), `reuse` (next alloc reuses 0), `pair_a` (`{0,1}`)
/ `pair_b` (`{5,6}`, same inode lane), `forward` (ordinals 5,43 direct to
backend), `fail` (ordinal 43 fails wrapper-only with `CKR_DEVICE_ERROR`),
`legacy` (publish only, zero calls).

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp ./scripts/cargo.sh +1.98.1 test \
    --locked --offline --test multi_wrapper_oracle
```

## What the oracle asserts

Each oracle JSON carries `scenario`, `seed`, `build_variant`,
`layout_known` (from a real `dlsym` of `p11scope_fixed`), `pid`,
`wrappers`, `free_at_call` / `occupied_at_call` occupancy at call time,
`legacy` publication, `reused`, the exact `expected` log lines, per-key
`counts`, and `total`. Log line format:

```text
<pid> <tid> <layer> <func> <idx> <via> <rv>
```

e.g. `1234 1234 wrapper C_Sign 4 direct 0` then
`1234 1234 backend C_Sign 4 nested 0`. The self-tests assert:

- log bytes for the scenario pid equal `expected` exactly (order included);
- recomputed per-key counts equal `counts`, and `total` matches;
- every successful wrapper entry is immediately followed by its nested
  backend entry (same func/idx/tid), 1:1 per (func, idx);
- forwarded ordinals emit backend `direct` records with no wrapper record;
- the failing ordinal emits wrapper `rv=48` records with no backend record;
- the legacy table is published (`{2,40}`, interface list non-empty) with
  zero call records; no `shared`-layer records anywhere;
- the stripped build hides `p11scope_fixed`, reports `layout_known: false`,
  and produces counts identical to the normal build at the same seed;
- reruns at a fixed seed are byte-identical (pid/tid normalized).

Pinned goldens at seed 0: `five` 120 (60 wrapper / 60 backend), `holes` 26,
`reuse` 28, `pair_a` 52, `pair_b` 52, `forward` 20 (7/13), `fail` 23
(13/10, 3× `C_Sign rv=48`), `legacy` 0; `five` at seed 1: 106.

## Using the fixture in coverage experiments

- Coverage: attach the observer to `workload … five` (active index 4 > 3),
  `holes`, and the `pair_a`/`pair_b` pair; assert observed counts/names
  match the oracle (count-only admission is not accepted); keep the
  `legacy` scan-only path working.
- Publication: the nine publication-driven cases map onto scenarios here
  (holes, five, pair lanes, forwarding, reuse, pre-published legacy,
  stripped unknown build); occupancy snapshots come from `mw_occupied`
  via `free_at_call` / `occupied_at_call`.
- Admission strategy: compare broad fixed-family attach vs
  occupancy/publication-selected attach on `five` + `holes` + `forward` +
  `fail`, asserting exact expected invocations and first-call coverage
  from the oracle.

## Catalog extension (module/caller inventory Phase 1)

The provider constructor additionally appends `getpid()` to
`$P11SCOPE_CATALOG_MARKER` when that variable names a file. Env-gated, so
every oracle scenario above (variable unset) is byte-identical; the
`inspect --system` catalog test sets it to pin that inspection executes no
provider code (only fixture pids may appear). The unactivated provider is
that test's *admitted* multi-table case: the constructor fills all 64
`{3,2}` templates, but only the 4 within the file-backed page tail are
visible to the memory scan (later statics live in anonymous .bss past the
file pages — see `scanned_tables_agree_with_the_helper_manifest_for_
every_walked_version`), so the catalog records 4 heuristic tables and
admits them. The test's *refused* p11-kit case is the separate
`../catalog-closure/provider.c` shape: 65 statically-initialized (hence
file-backed) `{3,2}` tables with no linkage, which classify as a closure
array and refuse whole over capacity.
