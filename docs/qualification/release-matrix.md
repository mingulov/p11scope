<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Release matrix evidence

`scripts/qualify-release-matrix.sh` prepares and judges exact selected release
assertions. A successful selected assertion does not complete Stage5 or the
system-product qualification campaign. Owner authorization, an accepted source
revision, the exact candidate artifacts, lane custody and the remaining
filesystem, identity, performance and real-application obligations are separate
requirements. A hermetic self-test establishes the checker behavior only.

The registered lanes are Linux 5.15.221, 6.1.188, 6.6.157, Ubuntu
6.8.0-142-generic, 6.12.111, 7.2.6 and the host. Planning starts no build,
guest, workload or probe:

```sh
scripts/qualify-release-matrix.sh --dry-run
python3 -I scripts/release-matrix-contract.py --plan --lane 6.1.188
```

The plan lists required IDs, literal full libtest names, public classifications,
MT contention with `THREADS=12`, one-thread exact libtest invocations and
unready obligations. Source registration does not establish that a candidate
binary contains those tests. No historical curation count is an observed
candidate count.

Omitting the kernel selection uses all seven lanes. An explicitly empty
positional lane, empty `--kernels` value or empty resolved selection fails
before campaign directory creation, candidate enumeration or workloads.

## Exact selection and capability

Each candidate supplies its own `p11scope-lib --list --ignored` output, the
unchanged privileged runner's successful `--list` curation receipt and the
`p11scope-bpfmulti --list` output. Preparation checks complete curation against
that candidate list. Every selected literal must match exactly one curated
name and must be runnable. A missing name, static skip, duplicate or ambiguous
substring match fails before execution.

The selected privileged suite contains registered default names and these
three long breadth gates. The runner receives `--include-long` and each full
name; it does not select every long test:

- `attach::inventory::activation::privileged_tests::privileged_t7_inventory_n4097_lp64`
- `attach::inventory::activation::privileged_tests::privileged_t7_inventory_n6530_lp64`
- `attach::inventory::activation::privileged_tests::privileged_t7_inventory_n8192_boundary_lp64`

`attach::instance_tests::privileged_instance_continuity_experiment_softhsm` and
`attach::inventory::activation::privileged_tests::privileged_bench_overhead_detailed_calls`
remain separately named obligations with their controlled timing/workload
prerequisites. They are not selected by default. D4 btrfs, overlay and ext4
kernel/userspace parity selectors remain **unready** until accepted source
bodies and their real full names exist.

PID and system attachment are judged independently on every lane, including
backported kernels. PID Multi needs the executed
`tests::the_pid_filter_probe_reaches_the_kernel` log to prove `own=2`,
`other=0`, `proves=true`, plus observed `uprobe-multi` and `kernel-pid+bpf`.
Without that proof, the valid auto result is disclosed `per-offset` with
`perf-task+bpf` and the PID-filter fallback reason. System Multi needs the
doctor's functional self-link success plus observed `uprobe-multi`; its
unsupported result needs a disclosed functional-probe fallback. System scope
has no PID scope-filter. An unknown capability, inconsistent probe or
unsupported mechanism cannot establish positive coverage. Version strings
never substitute for these functional proofs.

A successful scratch probe can still precede a refused native Multi
preparation. The production `the uprobe-multi preparation failed: ...` reason
plus the corresponding per-offset mechanism/scope-filter is an explicit
`expected-fallback` assertion. It does not establish Multi coverage.

Each forced-Multi classic/capture libtest has its own capability probe. Its
own `CLASSIC_PID_SCOPE`, `C3_PID_SCOPE` or `C3_LEADER_EXIT_PROBE` diagnostic
determines positive execution versus `expected-refusal`; the later standalone
PID probe cannot classify an earlier process. Positive diagnostics must retain
the target/foreign/reused-PID or leader-exit assertions. Missing, duplicated or
contradictory branches fail. The broad p11-kit admission test similarly records
its own no-spill branch or whole-module refusal, retaining its separate selected
admission evidence; a broad refusal establishes `expected-refusal` only.

The churn assertion requires its own `rate=100 branch=lossless` evidence. A
`branch=skipped` assertion fails even when the Rust test returns success. Its
single rate1000 loss/lossless branch remains explicit: honest high-rate loss
is a disclosed-loss assertion and does not establish high-rate zero loss.

The registered tolerance policy requires `P11SCOPE_PRIV_LIFECYCLE_LOSS` and
`P11SCOPE_TEST_TIME_SCALE` to be unset or empty. The outer runner, inner writer
and generated guest refuse nonempty values before workloads. Retained opt-in
headers and `LIFECYCLE_LOSS_REPORTED` diagnostics fail judgment. These settings
are never silently cleared or promoted through a successful one-test summary.

The 5.15 kernel-identity obligation is separate. Its selected positive identity
subset excludes these strict eligible-kernel gates:

- `attach::identity_iter::tests::functional_probe_proves_hardlink_match_and_copy_none`
- `attach::identity_iter::tests::whole_system_run_covers_all_children`
- `attach::identity_iter::tests::wronly_anchor_fds_refuse_reads_with_eperm`

The underlying eligibility authority is the BTF named-fix check, including
`bpf_iter_seq_task_vma_info.mm`, rather than a version-derived attach rule.
`identity:5.15-denied` remains a distinct required, unready refusal assertion:
no existing executable guest selector proves it. Pure denial fixtures do not
prove live guest refusal. Its nonqualifying result prevents a 5.15 contract
from becoming a positive completion claim. The real anchor-map handle test
remains selected.

## Receipts and results

The versioned `p11scope/release-matrix-contract/v1` execution copy binds a
fresh run ID, exact selected IDs and argv, the three candidate binaries,
candidate lists, curation and source script/fixture snapshots with SHA-256.
The runner checks those inputs before writing or executing the inner script.
The copied binaries are the executed binaries. Changed runtime source is
refused. Existing stage/output directories are preserved and refused instead
of being overwritten.

Runtime source binding covers the scripts/checkers, public `gated.c` and `mt.c`,
and the installed inventory lanes' `inventory-ledger.c`. Prebuilt libtests read
the native ledger and churn fixture through their compiled
`CARGO_MANIFEST_DIR`; that root can differ from the runner's checkout. Both
`tests/fixtures/public-cli/inventory-ledger.c` and
`scripts/fixtures/exec_churn.c` are mandatory candidate fixture snapshots,
checked against that compiled root before execution and at judgment. Omitting
a required binding fails rather than weakening the source closure.

Prebuilt preparation and outer `--bin-dir` runs require
`--candidate-receipt FILE`, obtained from the actual candidate build producer.
Its `p11scope/release-matrix-build/v1` object contains:

- `producer: "cargo-build"`, exact `lib_sha256` and canonical absolute `source_root`;
- exact 40-character `source_revision` and `source_tree`, and `source_clean: true`;
- `build` with the actual successful libtest no-run command's `argv`, `cwd` equal to `source_root`, and integer `exit: 0`;
- `runtime_sources`, mapping the two compiled-root fixture paths above to SHA-256.

This is a provenance claim checked against trusted build custody. The JSON
and `producer` string do not authenticate themselves: arbitrary JSON can forge
them. A user declaration, a guessed current checkout, or a binary strings scan
cannot establish the compile-time root. Missing receipts, binary/root/source
mismatches and declared user provenance fail. Preserve the producer's actual
build command, output and source custody alongside the receipt. An intermediate
candidate receipt cannot qualify a later assembled candidate.

The source-build runner emits a receipt only after its actual successful Cargo
build, checks tracked source cleanliness and unchanged revision before/after,
and preserves the lib build output. No build is performed by planning,
preparation, input verification or judgment. For a separately produced candidate,
an owner-authorized manual invocation uses the producer's receipt explicitly:

```sh
scripts/qualify-release-matrix.sh --rev ACCEPTED_REV --bin-dir CANDIDATE_DIR --candidate-receipt BUILD_RECEIPT --kernels 6.1.188
```

Raw process logs carry one exit and the run ID. Each required libtest needs
one `PASS <full name> rc=0` record and its own log naming exactly that test,
with one passed, zero failed and zero ignored tests. Summary totals have no
qualification authority. The execution receipt binds the contract hash,
actual guest/host process exit and all retained public, privileged, backend
and native/scan evidence files. Missing, duplicated, changed or cross-run
evidence fails. Guest timeout or failure propagates to the final shell exit.
Failed and partial raw logs remain available.

Public terminal rows use `cell`, boolean `pass`, `detail` and `qualification`.
The accepted public runner must produce each selected cell exactly once:

| Cells | Required classification |
| --- | --- |
| profile-pid, metrics-pid, mt-exact, system | owned-provider-counts |
| names-pid | semantic-names |
| verdict-pid | verdict-consistency |
| doctor, sigint, second-sigint, fifo-refused | command-contract |
| run-short, run-cover, trace-pid | nonqualifying, pass=false |

Owned-provider counts do not authenticate system per-caller attribution.
Signal and FIFO cells retain their own process assertions in the public
runner. Matrix exit validation does not replace that independent checker.
Scan's required exit2 means valid nonqualifying plumbing; exit0 cannot turn
it into positive native coverage. Native coverage requires oracle exit0.

| Overall exit | Meaning |
| --- | --- |
| 0 | Every explicitly selected qualifying assertion passed. Scope remains the selected claim. |
| 1 | Failed, invalid, missing, duplicated, stale or inconsistent evidence. |
| 2 | Exact selected assertions are satisfied, but the contract includes valid nonqualifying evidence or an explicitly unready refusal obligation. `pass=false`. |

The default public selection includes three nonqualifying rows, so its valid
runner exit is exactly 2. Matrix accepts that exit only with every required
row and its exact declared classification, and still returns nonqualifying.
Any definite failure, conflicting exit or undeclared nonzero exit fails.
The default matrix therefore never reports whole-campaign PASS. The guest
returns 0 for a completed valid nonqualifying judgment, retaining its
`guest-verdict.json`; the outer judge preserves final exit2. A guest failure
returns nonzero and fails outer judgment.

An owner can prepare a reduced execution contract with explicit `--lib-test`
and `--public-cell` options, and `--without-scan`, then supply only that
independently executed subset. These options do not make the production public
runner select a subset. The prepared script uses its full public selection;
an incompatible reduced receipt fails. An exit0 reduced contract cannot
satisfy omitted Stage5 obligations.

For an existing execution copy, judging starts no workload:

```sh
python3 -I scripts/release-matrix-contract.py --judge STAGE --contract STAGE/contract.json
scripts/qualify-release-matrix.sh --judge-stage STAGE --contract STAGE/contract.json
```

Hermetic validation honors the caller's private disk `TMPDIR`:

```sh
python3 -I tests/python/test_release_matrix_contract.py -v
scripts/qualify-release-matrix.sh --self-test
bash -n scripts/qualify-release-matrix.sh
shellcheck scripts/qualify-release-matrix.sh
```

Before a manual campaign, reconcile the final accepted public-cell interface,
the fresh exact candidate enumeration and source/artifact receipts. Checker
tests and a planned contract do not supply those outstanding release gates.
