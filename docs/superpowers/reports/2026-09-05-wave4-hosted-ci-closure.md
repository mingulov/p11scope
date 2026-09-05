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

Three runs on `github.com/mingulov/p11scope`, branch `ci/w4-hosted`:

| Run | Commit | Result | Cause |
| --- | --- | --- | --- |
| `33973323902` | `5600225` | FAIL both jobs | `seccomp.h` absent on the runner; `gh api` refused to emit the log |
| `33973869629` | `4d29bc7` | FAIL `checks-and-e2e`, PASS `archive-log` | live e2e lane, reason not yet diagnosable |
| `33974684732` | `141a94e` | FAIL `checks-and-e2e`, PASS `archive-log` | live e2e lane, `os error 524` |

Run `33974684732`: **39 of 40 steps PASS**, one FAIL. Every step this wave added
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

## 5. Open finding — NOT a CI defect

`scripts/verify-attach-e2e.sh` fails hosted: the observer exits before capture
readiness with **`Unknown error 524` (ENOTSUPP)** when loading or attaching its
BPF programs. The verifier log shows the program verifying cleanly (13 insns,
159 usec) before the failure, so this is not a rejected program and not a plain
permission denial.

This lane **passed hosted on 2026-08-16** (run `31935749796`), so it is a
regression between that commit and `141a94e`, or a change in the hosted runner
kernel. It is a product/environment finding, not a pipeline one, and it is the
only step of 40 that fails.

It is left open deliberately. Marking the lane UNRUN would produce a green run
and would be defensible only if the lane genuinely cannot run hosted — which is
not established. Papering over it is exactly what this wave exists to prevent.
**Owner decision needed:** diagnose the ENOTSUPP (product work), or reclassify
the lane as UNRUN with evidence that hosted attach is impossible.

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
