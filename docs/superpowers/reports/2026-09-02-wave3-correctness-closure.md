# Release Wave 3 — Correctness Engineering Closure

## Outcome

The Wave 3 engineering candidate is ready for local integration on
`hardening/wave3-correctness`, based on merged W2
`a2a264456bc0c30d3c30e727c85507940a90b75f`. The final integrated production
tip is `ec5e0aef329dbccec472bb1e0d369d5cbb9deeee`. The Rust 1.88 gates passed
on the final documented main tree: formatting, check, 1,072 tests with zero
failures, and Clippy with warnings denied.

The candidate now records bounded offline and live `C_GetInterface` request,
result, failure, alias, and coverage evidence without turning selection into
provider inventory. Live authority is tied to the exact retained process
generation and opened provider identity. Cgroup discovery uses dynamic
`task_newtask` offsets, destination-authenticated membership, bounded ingress
gap evidence, and exact generation intervals. Provider scans verify the opened
inode before parsing. `doctor` reports operational T0–T4 capability tiers, and
every known selection, lifecycle, ring, capacity, and helper loss keeps the
verdict honest.

`uprobe_multi` is intentionally not part of W3. The candidate stays on released
Aya 0.14.0 and the Linux 5.15-compatible per-offset attach path. The evaluated
upstream PR is only a future reference; no Git dependency, vendored loader, or
raw-link fallback was added.

`docs/privacy/allowlist-v1.md` remained byte-identical at SHA-256
`0cb4983d239c8c182d9c0ba632cde87ff9031ff22c7c9cab9edf4af43474797f`.
Selection output is governed by the explicit v2 allowlist and observed-profile
v3 schema; raw names, pointers, addresses, PIDs/TIDs, target paths, and provider
error text are not added to capture output.

## Verification

On the final locally integrated main tree (production tip `ec5e0ae`):

- `cargo +1.88 fmt --all -- --check`: PASS.
- `cargo +1.88 check --locked --workspace --all-targets`: PASS.
- `cargo +1.88 test --locked --workspace --all-targets`: PASS, 1,072/0.
- `cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings`: PASS.

The focused W3 checks also passed: manifest/discover selection matrices,
manifest pinning, live selection reduction and owned-run coverage,
observed-profile v3, capture-evidence and privacy-canary self-tests, dynamic
tracepoint offsets, opened-file identity, capability tiers, process creation,
and cgroup filtering. The final canonical run caught no regression after the
terminal-batch guard that prevents an empty second dispatch from advancing
terminal authority twice. The exact final unprivileged self-test commands were
`python3 -I scripts/check-capture-evidence.py --self-test`,
`sh scripts/verify-canaries.sh --self-test`, and
`sh scripts/verify-capability-tier.sh --self-test`; all returned zero.

Two independent full-diff lanes reviewed the final W3 production tree. The Sol
correctness/security lane and Luna test-quality/regression lane both accepted
zero actionable findings after the last lifecycle fix and stale Aya-note
correction. No third lane was needed.

The first merged-main gate then exposed a parallel-only false
`ProviderChanged` result in the offline helper: its selection bracket compared
unrelated anonymous worker-stack mappings. A RED mutation test and
`ec5e0ae` restrict that stability comparison to the exact file-backed mapping
class that can authorize provider/function identities. The affected fixture
binary passed five consecutive parallel runs, and independent Sol and Luna
reviews accepted the correction with zero findings before the final main gate.

## Runtime evidence boundary

These rows are deliberately not inherited from older phases:

| Exact-tip row | Status | Required result |
| --- | --- | --- |
| Ubuntu 22.04 / Linux 5.15 per-offset | `UNRUN` | real object loads; required links attach; exact-count, canary, and induced-loss checks pass |
| Ubuntu 24.04 / Linux 6.8 per-offset | `UNRUN` | same |
| `pkcs11-check` SoftHSM oracle | `UNRUN` | every completed oracle call is present; capture-only bootstrap calls remain separately identified |
| Deterministic `trace --pid` exact-count oracle | `UNRUN` | 226 calls from `spike/expected.txt` plus one `C_GetFunctionList` equal STATS entered, STATS returned, and consumed `CALL` records |
| Cgroup/container/VM lifecycle | `UNRUN` | fork, exec, `dlopen`, calls, `dlclose`, replacement/reload, retirement, and attribution all agree |

The existing operator journey is retained for those runs:

```sh
scripts/verify-inspect-doctor.sh
scripts/verify-attach-e2e.sh
scripts/verify-canaries.sh
scripts/verify-induced-gaps.sh
scripts/matrix/verify-oracle.sh
```

Run it against each exact candidate binary and embedded BPF object, recording
their hashes and the actual kernel. For the deterministic PID row, first build
the release workspace with `--target-dir "$WORK/build"`, `$WORK/harness`, and
the private SoftHSM token exactly as `verify-attach-e2e.sh` does. Then run this
exact lane from the repository root:

```sh
. scripts/lib.sh
TARGET=$WORK/build
BIN=$TARGET/release/p11scope
rm -f "$WORK/trace-go" "$WORK/trace.txt" "$WORK/trace.log"
set -- "$TARGET"/release/build/p11scope-*/out/p11scope-ebpf
[ "$#" -eq 1 ] && [ -f "$1" ] || exit 1
BPF_OBJECT=$1
sha256sum "$BIN" "$BPF_OBJECT"
uname -srvm

"$WORK/harness" "$MODULE" "$WORK/trace-go" \
  >"$WORK/trace-workload.log" 2>&1 &
WPID=$!
wait_for_mapped_provider "$WPID" "$(basename "$MODULE")"
sudo -n --preserve-env=SOFTHSM2_CONF "$BIN" trace --pid "$WPID" \
  --duration 20 -o "$WORK/trace.txt" >"$WORK/trace.log" 2>&1 &
SPID=$!
wait_for_capture_ready "$WORK/trace.log" allowlisted trace
touch "$WORK/trace-go"
wait "$WPID"
kill -INT "$SPID"
wait "$SPID"
reclaim_root_output "$WORK/trace.txt"
python3 -I - "$WORK/trace.txt" <<'PY'
import json
import pathlib
import sys

lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
counts = [json.loads(line.removeprefix("COUNT_EVIDENCE "))
          for line in lines if line.startswith("COUNT_EVIDENCE ")]
assert counts == [{"stats_entered": 227,
                   "stats_returned": 227,
                   "raw_calls": 227}]
assert not any(line.startswith("LOST ") for line in lines)
count_index = next(i for i, line in enumerate(lines)
                   if line.startswith("COUNT_EVIDENCE "))
assert lines[count_index + 1].startswith("EVIDENCE ")
PY
```

The harness's 226 declared calls plus its one post-barrier
`C_GetFunctionList` must equal every terminal aggregate, with zero loss and no
in-flight calls. Any separately instrumented bootstrap activity in the
`pkcs11-check` row is capture-only extra evidence; it does not weaken this
exact equality.

`supported_rate_loss_oracle` must select an
empirical fixed workload: generator-completed calls, STATS entered/returned,
and consumed `CALL` records agree with zero loss; a deliberately constrained
ring reports nonzero loss and `PARTIAL`. `fork_exec_loader_unload_oracle` must
exercise the lifecycle listed in the table and prove exact retirement with no
stale attribution. These are W6 and W8 release gates, not claims supplied by
this engineering closeout.

## Known product limits

- A process that enters a watched cgroup and migrates out before a
  destination-authenticated refresh or exit observation may be unobserved.
  W3 has no arbitrary-migration subsystem, so this sequence is explicitly
  excluded from `COMPLETE` and runtime-qualified claims.
- Loss of a task-bound lifecycle link is explicit and partial. W3 does not
  continuously re-arm that link after the proven generation is lost.
- Per-offset attachment remains correct but can be more expensive than future
  `uprobe_multi`; no throughput claim is made without the runtime oracle.
- Privileged real-kernel behavior, kernel support, and provider conformance are
  not established by the unprivileged suite.

This is therefore a source-reviewed and locally integrated W3 engineering
candidate, not yet a runtime-qualified or publication-ready release.

## Integration and authority

The reviewed W3 branch was fast-forwarded locally to `main` at `ba6689d`.
The integration-status update introduced no production change, and its final
main tree is the subject of the same four canonical gates. The owner's earlier
checker patch is preserved in named stash
`owner-main-check-live-discovery-object-before-w3-merge`; replaying it would
revert later reviewed checker corrections. The pre-existing
`owner-main-discovery_scan-dirty-2026-09-02` stash is unchanged. Nothing was
pushed, tagged, packaged, published, or released.
