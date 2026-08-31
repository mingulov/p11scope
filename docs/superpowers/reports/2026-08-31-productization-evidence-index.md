# Productization evidence index

Updated: 2026-08-31

This is the durable index for local worktree results. `INTEGRATED` means the
code is reachable from `main`; it does not mean released, published, or fully
runtime-qualified. Bulky `.superpowers/sdd` and VM artifacts remain local and
are identified by hashes below.

## Integrated on `main`

- Current integration checkpoint: `5c741c79a662e132c8039747fe3a9b44466beb1d`.
- Shipping baseline: `91e21496ae4e7d151c050a9dee2e8547d2d6cb75`,
  merged by `21bfd008d79ebd1ae1292d3820855ef45889a0d8`.
- Committed MVP lifecycle fixes through
  `af5282abc018277a757ed277728def1f275c5144`, merged by
  `0874c06e1539350cb42c136a3abfe7ea9af576a5`.
- Slice 1b-2 Task 4 prerequisites through
  `eebb0fcdea1d4da50536230ed07ac7325c29f4d0`, merged by
  `b0e47d8ff1e264bff6974e6b0d8cacce0c1c63e3`.
- Stage 3A3 GREEN6 files, committed by
  `9c001c1a68e82c11caa44a33d154eb9a0012e3e6`:
  - `scripts/task4-build-subject.py`:
    `7c35402cfb3cfd66de8f7009d7a6807ac42680e45c27bbfc3369692e28f2a88c`.
  - `tests/task4_build_subjects.rs`:
    `edce9d37735253179e6a129d59aef73b68a5b5671e57bc9129ff94162b0eea81`.
- The previously untracked Slice 1b implementation plan was preserved by
  `e9ca940affc800df836d94d129e2a519f7d806a1`.
- Privacy allowlist:
  `0cb4983d239c8c182d9c0ba632cde87ff9031ff22c7c9cab9edf4af43474797f`.

Fresh integration checks:

- Task 4 build-subject negative control: silent exit 77, PASS.
- Python syntax and modified shell syntax: PASS.
- `cargo +1.88 test --locked --test task4_build_subjects`: 18/18 PASS.
- `cargo +1.88 test --locked --test artifact_contracts`: 60/60 PASS.
- Independent prerequisite-merge review: ACCEPT, no findings.
- Full four-command workspace gate, exact-tip CI, packaging, publication,
  push, tag, and release: UNRUN at this checkpoint.

## Preserved worktree snapshots

These commits preserve exact source state but are not automatically accepted
for product integration.

| Worktree / branch | Preserved commit | Disposition |
| --- | --- | --- |
| `productization/mvp-lifecycle-fix` | `fd727a86c4e4a367b0a836949c13b5956f056980` | Clean post-diagnostic candidate. Cleanup review accepted, but fresh Jammy Attempt 15 row 02 remains semantic NON-PASS; do not merge until fixed. Raw WIP remains recoverable at `dff4085778ad96e4d7741b282977b6052e47afb0`. |
| `productization/slice1b2-finish` | `5a7c9a7cfd24c8b938866d12e78089935000a9d3` | Exact GREEN6 pair plus separately unaccepted artifact-contract/contracts/report WIP. GREEN6 and prerequisites are integrated; the remaining snapshot is preserved only. |
| `research/raw-tracepoint-lifecycle` | `5e027743c01072b47ac5bb0bf7ebdfe4767c8428` | `DONE_WITH_CONCERNS`; verifier, masked-tracefs, capability-parity, and cross-kernel runtime remain UNRUN. Post-v1 unless promoted separately. |

Stage 3A3 acceptance is scoped to the exact GREEN6 pair. Its local evidence is
under
`.claude/worktrees/slice1b2-finish/.superpowers/sdd/2026-08-27-task4-receipt-closure/`;
the final report and independent review are
`stage3a3-green6-report.md` and `stage3a3-green6-final-review.md`.

## Kernel runtime evidence

Frozen candidate identities used by the 2026-08-31 campaign:

- BPF object:
  `2638906cda708c30eb69a7c6c055853bb927bcd15d6000784131ac52f53b5c93`.
- original runner:
  `672647142336c70b66cad21c73d5eb7974c11410c2aae77502365a6b65418427`.

Noble 6.8:

- Gate A: PASS 5/5.
- Product semantic rows: UNRUN.

Jammy 5.15:

- Gate A: PASS 5/5.
- Attempt 14 row 01 (`count0`): command, semantic, privacy, and cleanup PASS.
- Attempt 14 row 02 (`count1`): NON-PASS; command exited 0, semantic oracle
  failed. Rows 03-06 are UNRUN.
- Live translated and JIT bytes confirm the loaded return program preserves
  the saved state and follows the expected pointer-read/emission instruction
  flow. This excludes the attempted stack-copy workaround; it does not yet
  identify the source of the wrong table pointer.
- Complete late-dlopen diagnostic archive (29 directories):
  `5c5a6bac8120fa15c2e94b82e1e1d4310ab0281163bfbeecfc7afc12037cefa9`.
- Focused live-JIT archive:
  `3f8ad9c37701c5bea20617179ead95e86a6862d2373ed87219d84ca380cc159e`.
- Final guest census:
  `8d30924e385e5a48882f2d1dffbfe375fb642c0df1c551181bb17b49d17ea82d`.
- The VM powered off cleanly, QEMU exited in five seconds, port 2223 cleared,
  and `qemu-img check` returned 0. The disposable child overlay is preserved,
  not deleted.
- Attempt 15 rebuilt the clean post-diagnostic candidate at
  `fd727a86c4e4a367b0a836949c13b5956f056980`:
  - static-musl runner:
    `a6f30aff09e08d450609604fafae5bf8e1334aacf8a6cc0ec6b22a1c5d5d080f`;
  - eBPF object:
    `97b19c5d15bada7df00e6a92d3c2149f2e34e70fecf40665dbd028da359f6983`;
  - Gate A and the static object checker: PASS;
  - row 02 command, readiness producer, and exact-baseline cleanup: PASS;
  - provider scan: 104 entries and 208 attached probes;
  - semantic oracle: NON-PASS, `interfaces: expected 1, got 0`.
- Attempt 15 archive:
  `12e25383ed7a7d9c4e5f652ca34fba52e7e32e373e8373c865f714b1061e7afe`.
  A verified preservation copy, including the candidate runner/object and
  manifest, is under
  `/home/user/.local/state/p11scope/mvp-semantic-jammy-attempt15-clean-row02/`.
  Its disposable child was deleted after graceful shutdown and successful
  image/input checks.

Evidence paths are local under
`.claude/worktrees/mvp-lifecycle-fix/.superpowers/sdd/2026-08-31-mvp-semantic-campaign/`.
These results are diagnostic or partial runtime evidence, not release proof.

## Other worktrees

| Worktree / ref | Exact tip | Disposition |
| --- | --- | --- |
| `productization/shipping-ready` | `91e21496ae4e7d151c050a9dee2e8547d2d6cb75` | Integrated baseline; retain until final gates finish. |
| `productization/lane02-500ms` | `7b4a75306e2b49e25000256786c437723e5729da` | Accepted fixed-ceiling result already represented by shipping baseline. |
| `experiment/lane02-pause` | `37bfd424a03b64c6f7d6a0343b58b7151271141e` | Diagnostic-only sampling experiment. |
| detached lane13 error detail | `13802fa4b2ebbd567d7fea0af6c48d927be560e9` | Diagnostic-only, explicitly non-promotable. |
| detached lane13 skip diagnostic | `a70c520449b7a69f632049ec06b6d10601e7f527` | Diagnostic-only; do not make its feature default. |
| `worktree-slice1b-1` | `9b9792de58b4de86cc776cb2d4fe8e6420ea4fbd` | Already an ancestor of the integrated shipping baseline. |
| `spike/slice1b2-gates` | `7f42ad71257cdb64d292b0523733eec65cd039f3` | Unique committed Gate-B spike and recorded 120/120 evidence; stopped for controller review, not product promotion. |
| detached `/tmp/p11scope-s3a1-redfix-wt-fjQfyT` | `0afa628633f108730281d07169c420492e4970e8` | Dirty 10-line patch is already represented by `95c52305c9e48f3f02ff34ea5f27baffcd9987c0`; no unique result. |
| `.claude/worktrees/slice1b2-product` | no independent Git identity | Generated target directory only; no source result to integrate. |

No worktree or branch was deleted during consolidation. Generated `target/`
trees are not evidence and remain cleanup candidates only after all referenced
artifacts are independently retained.

## Remaining critical path

1. Identify and fix the interface-list lifecycle defect isolated by clean
   Attempt 15. Diagnostic removal and its independent review are complete.
2. Rerun the frozen Jammy row 02. Do not spend time on rows 03-06 until it
   passes.
3. Merge the reviewed lifecycle fix to `main`.
4. Run the four locked workspace commands on the exact `main` tip.
5. Run the serial Jammy 5.15 and Noble 6.8 semantic campaign, independently
   review its evidence, then run exact-tip CI and release closeout.

Deep Security Scan, full security/privacy clearance, container/deployment
lanes, exact-tip CI, packaging, publication, push, tag, and release remain
UNRUN unless a separate accepted record says otherwise.
