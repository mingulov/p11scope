<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# G25 runbook — candidate CI, package recipient and documentation contracts

Exact source freshness and usability; no independent reproducible-build
claim. Base `fabbb0a4`; re-verify on the converged candidate.

## CI (exact-SHA discipline)

- Workflow `.github/workflows/ci.yml`, jobs: `dedupe`, `lint`, `audit`,
  `tests`, `bpf-noninterference`, `contracts-N` shards, `scripts`,
  `archive-log`, `coverage` + `coverage-report`, `quarantine` (only on
  failure), dispatch-only `release-preview`, gated `privileged-e2e`
  (ordinary hosted Ubuntu 26.04; capability checks and four required
  PID/system metrics/profile count/window positives, not scale or soak).
- Every job of the push run must pass on the exact candidate SHA. Record
  the URL of the run that EXECUTED the matrix, not a deduplicated one.
  A manual dispatch always reruns the full matrix (release-preview is not
  a package-only shortcut; budget the repeat).
- `bpf-noninterference` builds reviewed full-image baseline `ca3a181...`
  twice, then compares against the candidate in fresh sequential
  snapshots. Advance the baseline only after reviewing intentional BPF
  changes. Reconcile `e2961e08` CI versus `ca3a181` runbook policy live.
- Push shape (controller-owned, temporary branch, after V2 + `--check`):

```sh
python3 -I scripts/run-python-suites.py --check
p11scope_ci_ref=ci/v040-<date>-t11
p11scope_candidate=$(git rev-parse HEAD)
git push origin "$p11scope_candidate:refs/heads/$p11scope_ci_ref"
gh run list --workflow ci.yml --branch "$p11scope_ci_ref" \
  --commit "$p11scope_candidate" --limit 5 \
  --json databaseId,headSha,status,conclusion,url
```

## Build / package / export (official paths only)

- `scripts/build-release.sh <absent-evidence-root>` is the ONLY path to
  official bytes: safe-only static musl observer + glibc/musl discover
  helpers in digest-pinned containers, with canary/attach/hostile smokes.
  Accept only on exit 0 + receipt `status` 0 + `facts.log`
  `terminal_status`/`checker_status` 0. Binaries land in `work/dist/`.
- `scripts/package-release.py` makes the three versioned tarballs plus
  top-level `RELEASE.json` + `SHA256SUMS`; `scripts/release-artifacts.py`
  binds the four artifacts to the ledger; `scripts/release-notices.py`
  generates notices (cargo-about 0.9.2, musl 1.2.5, pinned SHAs in
  RELEASING.md step 6); `scripts/export-source.py` makes the schema-v1
  source export (committed source + two pinned Aya archives; NOT full
  offline — see `docs/build-offline.md` for the full offline recipe).
- Hosted equivalents run under CI `release-preview`; confirm the job's
  pinned tool SHAs still match RELEASING.md step 6 before trusting them.
- Recipient verification: follow `package-recipient-checklist.md` in this
  directory (clean extract, member set, modes, version/help/provenance,
  G14/G20/G22 applicable installed journeys on the packaged bytes, wrong
  libc / missing dependency / changed-input refusal twins).

## Gaps for live T11

1. `test_release_recipient_uses_selected_binary` does NOT exist. G25
   requires a test proving the recipient journey uses the selected
   candidate binary (exact executed path), not an earlier PATH binary.
   Owner: tooling lane (D); add to the accepted journey harness in the
   same patch as any registration it needs (none if it extends an already
   registered suite).
2. Doc freshness: `RELEASING.md` still walks through v0.2.0 end to end;
   `Cargo.toml` + `crates/discover/Cargo.toml` say 0.3.0; `CHANGELOG.md`
   has NO `## [Unreleased]` v0.4 section. T11 must update version,
   commands, limitations, manifests/README/changelog/runbook, support /
   permission / retention wording and schema/privacy status, then check
   links and commands. (`git grep 'TODO(release)'` and
   `TBD-MEASURED|TBD-QUALIFIED` are already clean at base.)
3. Installed recipient journeys G14/G20/G22 against packaged bytes are
   open live cells; a lane that builds its own binary remains source
   qualification, never artifact qualification.
