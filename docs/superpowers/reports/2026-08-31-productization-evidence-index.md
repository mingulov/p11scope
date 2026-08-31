# Productization evidence index

Updated: 2026-08-31

This is the durable index for local worktree results. `INTEGRATED` means the
code is reachable from `main`; it does not mean released, published, or fully
runtime-qualified. Bulky `.superpowers/sdd` and VM artifacts remain local and
are identified by hashes below.

## Integrated on `main`

- Runtime-qualified documentation checkpoint:
  `3e10be9875db7ea13bf9352cf85d482db6efbf0d`.
- Portable history merge:
  `4b626c38c39d9b50644bdd4429cf0bfcf007dc6b`. Its tree is exactly
  `f03ef58509b83486d99e64b743e883a1a3931d86`, unchanged from `3e10be9`.
  The merge makes every unique worktree tip listed below reachable from
  `main` without promoting its experimental or rejected file tree.
- Shipping baseline: `91e21496ae4e7d151c050a9dee2e8547d2d6cb75`,
  merged by `21bfd008d79ebd1ae1292d3820855ef45889a0d8`.
- Committed MVP lifecycle fixes through
  `af5282abc018277a757ed277728def1f275c5144`, merged by
  `0874c06e1539350cb42c136a3abfe7ea9af576a5`.
- Dual-kernel-qualified lifecycle fixes through
  `ae8494de65aea78384b86b2f7d05cf6fc30000f8`, merged by
  `b71b4f2c75e4324462e0d28002dbfafa40d98e83`.
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
- `cargo +1.88 test --locked --test artifact_contracts`: 63/63 PASS.
- Independent prerequisite-merge review: ACCEPT, no findings.
- Full four-command workspace gate on the combined tree: PASS (630 library,
  63 artifact-contract, and all integration tests; Clippy denies warnings).
- Exact-tip CI, complete packaging, publication, push, tag, and release:
  UNRUN at this checkpoint.

## Portable historical snapshots

These commits preserve exact source state but are not automatically accepted
for product integration. They are parents/ancestors of the portable history
merge `4b626c38`; they no longer depend on local-only branch names for
transfer.

| Worktree / branch | Preserved commit | Disposition |
| --- | --- | --- |
| `productization/mvp-lifecycle-fix` | `ae8494de65aea78384b86b2f7d05cf6fc30000f8` | Accepted six-row dual-kernel candidate; fully integrated by `b71b4f2`. Historical diagnostic WIP remains reachable in the branch history. |
| `productization/slice1b2-finish` | `5a7c9a7cfd24c8b938866d12e78089935000a9d3` | Exact GREEN6 pair plus separately unaccepted artifact-contract/contracts/report WIP. GREEN6 and prerequisites are integrated; the remaining snapshot is preserved only. |
| `research/raw-tracepoint-lifecycle` | `5e027743c01072b47ac5bb0bf7ebdfe4767c8428` | `DONE_WITH_CONCERNS`; verifier, masked-tracefs, capability-parity, and cross-kernel runtime remain UNRUN. Post-v1 unless promoted separately. |

Stage 3A3 acceptance is scoped to the exact GREEN6 pair. Its local evidence is
under
`.claude/worktrees/slice1b2-finish/.superpowers/sdd/2026-08-27-task4-receipt-closure/`;
the final report and independent review are
`stage3a3-green6-report.md` and `stage3a3-green6-final-review.md`.

## Kernel runtime evidence

Accepted frozen candidate identities used by the final 2026-08-31 campaign:

- Candidate/tree: `ae8494de65aea78384b86b2f7d05cf6fc30000f8` /
  `c273bb500fb4820a3a5bd478436db6c260960321`.
- BPF object:
  `1daaca3a77d3babbeb61d49d91a535f7f7ef941448f835c3bd1dc1fee64a6ce1`.
- runner:
  `60b2d47a752ce57de446eb4a78700f45ad0419cbb72a22d1f06fc56d010fa4b0`.
- privacy allowlist:
  `0cb4983d239c8c182d9c0ba632cde87ff9031ff22c7c9cab9edf4af43474797f`.

Jammy 22.04 / kernel 5.15.0-187:

- Separate five-program Gate A: PASS 5/5.
- Six product rows: 6/6 command, semantic, privacy, and cleanup PASS.
- Evidence archive:
  `a34461f4fea672f7a125706df5250c7bad5f84e09fb34f803408c08435f284f9`.
- Sealed manifest copy:
  `/home/user/.local/state/p11scope/mvp-semantic-jammy-attempt28-two-phase-six-row/`.

Noble 24.04 / kernel 6.8.0-137:

- Six product rows: 6/6 command, semantic, privacy, and cleanup PASS using
  the identical runner/BPF/allowlist bytes.
- Evidence archive:
  `837a560140f3f5161c6781f745059034028981b15fac793eaed109ec1abdc8fa`.
- Sealed manifest copy:
  `/home/user/.local/state/p11scope/mvp-semantic-noble-attempt29-two-phase-six-row/`.
- A separate Noble diagnostic Gate A was not repeated; all six product rows
  loaded and exercised the identical object. Independent review accepted this
  with the Jammy Gate A as sufficient for the MVP two-kernel gate.

Both roots pass their complete `EVIDENCE.sha256` manifests. Source, candidate,
base images, and initialized overlays remained unchanged; collection and
teardown passed, ports and QEMU processes cleared, and disposable children
were deleted. Independent dual-kernel evidence review: ACCEPT, no required
action before main. Noble's stale preparation label and `a27` hostname are
cosmetic deferred harness fixes, not provenance defects.

The earlier diagnostic campaign used these superseded identities:

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
The earlier results in this subsection are diagnostic or partial runtime
evidence; the accepted successor campaign above supersedes their MVP gate.

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

The source histories above are now reachable from `main`. Worktree checkout
directories and redundant branch names are cleanup-only metadata; deleting
them after portable evidence verification cannot delete the merged commits.
Generated `target/` trees are not evidence.

## Portable transfer package

The complete `main` history through `90a03acbbbaff6de39fe56d3eb4de8b8add27e43`
and the finite accepted evidence set are packaged at:

`/home/user/.local/state/p11scope/pkcs11-scope-portable-90a03ac.tar.zst`

- archive SHA-256:
  `e4d6cf6294d7717c5b89cd38bec3a608e1fc8d8696a3f86f074a6bbcb4c2d6cf`
- complete `main` Git bundle SHA-256:
  `a08004436f85f1e14517c9a68ec756d319e2b6e4bbdfa5e98d5678895685785d`
- internal manifest SHA-256:
  `b9f8f6171d0820b9a8e98def82ba804000bf174a6cf5ff1c04e6fdc69ea0ea71`
- unpacked/archive sizes: 32 MiB / 14 MiB.

`git bundle verify` reports a complete history with `refs/heads/main` at
`90a03ac`. The package contains the Jammy/Noble accepted runtime roots,
Stage 3A3 GREEN6 reports, exact security scan artifacts, and the release
binaries/receipts without rebuildable Cargo intermediates. Its adjacent
`.sha256` file is the authoritative archive checksum.

## Static security closeout

Codex Security Standard scan `ccd45755-a021-4492-a066-e3df02b0944e` reviewed
exact revision `3e10be9875db7ea13bf9352cf85d482db6efbf0d` offline. Coverage is
risk-ranked and `partial`, not a whole-repository clearance. It reported nine
validated findings: one high, six medium, and two low.

- HIGH: an elevated `p11scope run` execs the observed child without dropping
  observer uid/gid/groups/capabilities or sanitizing inherited authority.
  **Resolved in the current revision:** the child target must name one existing
  non-root account, credentials/capabilities are dropped and verified before
  barrier release, the environment and descriptors are confined, and the
  already-opened ELF is executed with `execveat`. Independent review accepted
  closure of the high finding; privileged runtime confirmation remains part of
  the exact-tip VM campaign.
- MEDIUM: discovery-helper inherited descriptors, mutable cgroup pathname
  reuse, adversarial scan complexity/pause extension, unbounded trace output,
  output-directory ancestry, and untracked/PATH-dependent release inputs.
- LOW: terminal control characters in mapped-module headings and ambiguous
  Lane 14 receipt binding.
- The default privacy allowlist and policy-map freezing surface produced no
  finding.

Durable private copy (mode 0700/0600):
`/home/user/.local/state/p11scope/security-scan-3e10be9/`.

- `scan-manifest.json`: `efe277bfb3f2a3f0c439c2239e5c2f0725bb0dfbbbd65d3b8010b8078b07d16b`
- `findings.json`: `014e94863827184010218f07cc1a28cd47c310eab7090875df7fa75fb173b8a9`
- `coverage.json`: `a62b85e8845d7242d2fa20542a4d769a5ede0e7af3b4e7f0a83b536f6aab9d72`
- `report.md`: `4bfbcf926e5434de8b3aa9e21360c2458f5728f49fa76c61c9e03fec92b1f284`
- `exports/results.sarif`: `7f8ee74bf750a5ceac39a0ac79311a0799b2a004026f28a847d660dbf996f226`

## Remaining critical path

1. Fix the smallest release-relevant identity/boundedness/build-receipt
   findings.
2. Rerun the four exact-tip local gates and exact-tip CI.
3. Complete the release build/receipt and release closeout.
4. After MVP closeout, run the approved Fedora QEMU smoke with SELinux
   `Enforcing`; do not duplicate the historical high-volume campaign unless a
   portability failure requires it.

Full security clearance, exact-final-candidate container/deployment reruns,
exact-tip CI, complete packaging, publication, push, tag, and release remain
UNRUN unless a separate accepted record says otherwise.
