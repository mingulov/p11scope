# Wave 4 closure — hosted CI

Closed 2026-09-05 at `141a94e`, merged to `main` and pushed to the
owner-approved branch `ci/w4-hosted`. **Closed on owner instruction without the
zero-findings review cycle the protocol requires** — see §6, which states plainly
what that means.

## 1. What the wave set out to do

1. Fix a release-blocking drift: the frozen BPF map/program inventory in
   `scripts/check-bpf-map-defs.py` no longer matched the object the crate ships.
2. Make the hosted pipeline honest: a green job must never imply that a
   privileged or container lane ran.

Both are done. Objective 1 is verified against really built objects; objective 2
is verified by a real hosted run, which immediately did its job (§4).

## 2. Evidence — PASS / FAIL / UNRUN, not inherited

### Local, at `141a94e`

| Gate | Result |
| --- | --- |
| `cargo +1.88 fmt --all -- --check` | PASS |
| `cargo +1.88 check --locked --workspace --all-targets` | PASS |
| `cargo +1.88 test --locked --workspace --all-targets` | PASS — 1078 tests, 22 binaries |
| `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings` | PASS |
| 19 hosted `--self-test` steps, run locally | PASS (19/19) |

### Hosted

Four runs on `github.com/mingulov/p11scope`, branch `ci/w4-hosted`:

| Run | Commit | Result | Cause |
| --- | --- | --- | --- |
| `33973323902` | `5600225` | FAIL both jobs | `seccomp.h` absent on the runner; `gh api` refused to emit the log |
| `33973869629` | `4d29bc7` | FAIL `checks-and-e2e`, PASS `archive-log` | live e2e lane, reason not yet diagnosable |
| `33974684732` | `141a94e` | FAIL `checks-and-e2e`, PASS `archive-log` | live e2e lane, `os error 524` |
| `33975372955` | `73578a6` | FAIL `checks-and-e2e`, PASS `archive-log` | live e2e lane, `os error 524` — identical |

Run `33974684732`: **39 of 40 steps PASS**, one FAIL. Run `33975372955`, on the
closure commit itself, reproduces exactly that: the same single step fails and
nothing else does. Every step this wave added
or changed passes hosted — the UNRUN block, all 19 self-tests, the four gates,
the diagnostic-object inventory step (`inventory diagnostic: maps=17
programs=17 OK`, `test result: ok. 1 passed`), and the log-archive job.

All 18 privileged and container lanes remain **UNRUN** hosted, named as such in
the log and the job summary. Nothing here claims otherwise.

## 3. The release-blocking defect

W3's `02eedbd` changed `CONFIG` from `with_max_entries(1)` to `(2)` in
`crates/ebpf/src/main.rs` without updating the freeze. Nothing caught it because
`--self-test` only compared the script against its own constants — it was
self-consistent and blind to drift. Three lanes compare built objects against
that freeze, including the W8 release receipt, so all three would have failed
the moment they next ran.

The value is corrected **and the root cause is closed**: a new
`--inventory default|diagnostic <ELF>` mode compares the freeze to a really
built object, wired into the ordinary `cargo test` gate, with a negative control
requiring the same object to be *rejected* against the other variant's freeze.
Two further blind spots were found and closed: a decoder symbol reaching the
shipped object, and a program added under an attach type the section whitelist
did not name — the latter being exactly the roadmap's next BPF change.

The capture surface is unchanged: one field, no map added or removed. Not a
privacy regression. `docs/privacy/allowlist-v1.md` is byte-identical.

## 4. What the hosted run found — the wave working as intended

**The emptiness guard caught a real false-green on its first production run.**
`gh api` refused to emit the job log ("the response contains terminal escape
sequences") and wrote nothing. Without the `[ -s ]` retry check and the `test -s`
backstop, `archive-log` would have gone green having uploaded a 0-byte artifact
labelled as the retained job log — a green step standing for evidence that does
not exist. Instead the job failed loudly and named the reason. Fixed with
`--allow-escape-sequences`; `archive-log` has passed in both runs since.

Two further hosted-only findings, invisible to any local gate:

- `libseccomp-dev` is installed on the workstation and absent on `ubuntu-24.04`,
  so a test that compiles a C fixture passed locally and failed hosted.
- The live e2e failure reported only a `/tmp` path that is destroyed with the
  workspace. The readiness helpers now print the log tail, which is how §5 has a
  diagnosis at all.

## 5. Closed finding — a p11scope defect, found by CI, fixed at `56101fa`

`scripts/verify-attach-e2e.sh` failed hosted with **`Unknown error 524`
(ENOTSUPP)** from `BPF_PROG_LOAD`, after the verifier had accepted the program.

### Root cause

A frozen `BPF_F_RDONLY_PROG` map makes the verifier constant-fold
constant-offset reads of it through `map_direct_value_addr`. For arrays that is
`array_map_direct_value_addr()`, which opens with `if (map->max_entries != 1)
return -ENOTSUPP;`, and `check_mem_access()` returns it verbatim with no
`verbose()` message. So the load fails with a bare errno 524 and a verifier log
that simply stops at the offending instruction — here
`322: (79) r8 = *(u64 *)(r0 +0)`, `map=CONFIG`, 13 insns in.

`CONFIG` is a `BPF_F_RDONLY_PROG` array frozen before the load loop. W3's
`02eedbd` grew it from 1 entry to 2 to carry the `task_newtask` offsets, which
armed the path. The repository already had the workaround one map over:
`7774bf6` deferred the `DESCRIPTORS` freeze past program load for exactly this
reason, with a comment naming ENOTSUPP.

The fix (`56101fa`) states the rule instead of listing names, so no map can
rejoin the early freeze by having its `max_entries` bumped. Every freeze still
precedes every attach, so no probe can observe mutable policy. No BPF object
change, no frozen-inventory change, no capture change.

### Two claims in the previous version of this section were wrong

- **It was never specific to one program.** `expected_programs()` returns a
  `BTreeSet` (`src/attach.rs:1143`), so programs load alphabetically and
  `dl_debug_state` is *first*. Every program calls `scope_auth`, which reads
  `CONFIG`; all 13 would have failed. Nothing loaded successfully before it.
- **It was never kernel-specific.** The pre-fix binary fails on the workstation
  too. The kernel code is unchanged from 5.4 through 7.0. p11scope's attach has
  been broken on **every** kernel since `02eedbd`; hosted CI looked special only
  because hosted CI is where the attach lane actually ran.

### Evidence

Same `p11scope profile` run, before and after, on three kernels:

| Kernel | pre-fix | post-fix |
| --- | --- | --- |
| `7.0.0-30-generic` (workstation) | errno 524 | attached, capturing |
| `6.17.0-1022-azure` (the hosted runner, reproduced in a local QEMU VM) | errno 524 | attached, capturing |
| `6.8.0-137-generic` (VM) | errno 524 | attached, capturing |

Four Rust 1.88 gates PASS at `56101fa`. A regression test in `src/attach.rs`
asserts every multi-entry read-only array is in the deferred set and pins that
set; reverting to the old name list makes it fail. Three existing contract
guards pinned the old source text and were updated to assert the new rule.

The reproduction environment is `linux-image-6.17.0-1022-azure` — the runner's
exact kernel, an apt package — installed in a QEMU VM off
`p11scope-ws/vm-bases/noble`. That turns a 12-minute hosted cycle into a
40-second local one and is the reason this was findable at all.

### What CI actually bought

This wave's stated purpose was to stop a green pipeline from implying that
privileged lanes ran. It did that, and then the lane it exposed turned out to
be hiding a defect that made the product's core function fail on every kernel,
undetected on the developer's own machine for two waves.

## 5b. Open finding — spurious `task_uprobe_link_losses`

With the load fixed, the lane reaches **136/136 probes attached** and then fails
a later oracle: `task_uprobe_link_losses: want 0, got 1`, deterministically.

Reduced to a minimal reproduction with no PKCS#11 involvement: attach to any
process and let it exit while capture runs. With `0/0 probes attached` and `no
modules discovered`, evidence still reports `task_uprobe_link_losses = 1`.

`settle_leader_exit_view` (`src/discovery/engine.rs:5521`) receives
`Err("retained process view is no longer available")` when the view has been
retired — which is what a whole-process exit does — and returns `Pending`.
`finalize_pending_leader_exit_views` (`:5547`) then counts every still-pending
view as a loss at capture end. A normal target exit is recorded as a link loss
that did not occur, which is evidence corruption in the direction that matters.

This is W3 machinery (`8a0d40c`, `ec5e0ae`), not W4, and it was unreachable
while the load failed. Not yet fixed.

## 6. What this closure does NOT claim

- **No zero-findings review cycle was reached.** Seven cycles ran, finding 23,
  14, 12, 10, 12 and 15 items. None was a BLOCKER. From round 4 onward, nearly
  every finding was a defect in a guard added by the previous round rather than
  in the wave's own work; round 7 identified the shared root cause (job and
  permission blocks carved out of YAML by ad-hoc string slicing) and replaced it
  with one structural reader. The wave was closed on owner instruction at this
  point rather than by the protocol's exit gate.
- **No product code was reviewed or changed.** `src/`, `crates/` and
  `docs/privacy/` are untouched by all 18 commits. This wave found **zero
  defects in p11scope itself**; every fix is in the release-verification
  checker, the pipeline, or the test guards.
- **The hosted pipeline is not green.** §5 is open.
- **`lane13_evidence_finalizes_only_after_owned_cleanup` failed once** during
  round 7 and then passed on four consecutive runs, in isolation and in the full
  suite. Treated as a flake. Not reproduced, not explained.

## 7. Carried forward

- §5, the ENOTSUPP attach failure.
- `repository = ".../pkcs11-scope"` in `Cargo.toml` and both crate manifests;
  the remote is `.../p11scope`. Owner confirmed the rename 2026-09-05.
- Schema ids still read `pkcs11-scope/observed-profile/v3`. Owner asked for
  `p11scope/...` and questioned the version; recommendation is
  `p11scope/observed-profile/v1` for a first release, since nothing has shipped
  and the version numbers describe a history no consumer experienced.
- `docs/privacy/allowlist-v2.md` (added by W3) became public with this push.
- Commit `c495caa`, already on `main` and already public, carries a 2.3 MB
  `p11scope` binary embedding a `/home/user` build path. Only a history rewrite
  removes it.
- W5/W6 are blocked on two owner-gated network pulls: no `kindest/node` image is
  cached and the Knative `func` CLI is absent.
