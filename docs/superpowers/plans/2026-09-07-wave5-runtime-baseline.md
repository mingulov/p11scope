# W5 runtime baseline plan

> **For agentic workers:** Use superpowers:executing-plans for the serial runtime
> campaign and superpowers:verification-before-completion for each evidence row.

**Goal:** Run the existing host-observer container and proxy lanes on one clean
source snapshot, identifying actual failures before designing the missing
confined-observer security artifacts.

**Architecture:** Existing scripts own their resources, cleanup and capture
oracles. Use a private temporary checkout so capture output has trusted
ancestry, then retain evidence and source identity in `p11scope-ws`.

**Tech stack:** Rust 1.88, current per-offset eBPF probes, Docker, kind,
Kubernetes, Knative, SoftHSM2 and p11-kit.

**Spec:** `../specs/2026-09-01-p11scope-release-prd.md`, W5 in
`2026-09-01-release-wave-charters.md`, and the 2026-09-07 owner amendments.

## Constraints and verified inputs

- No push, tag or publication. Privileged/container testing is authorized.
- Preserve `docs/privacy/allowlist-v1.md` and unrelated work.
- Initial target ABI scope is x86-64; ABI feasibility research runs separately.
- One Cargo-heavy or runtime lane at a time; no daemon-wide cleanup.
- Main baseline is `fe46b37a4a142729392494b6406004e6eafde401`. Existing `.codex`
  edits are unrelated. Runtime scripts consume a clean committed snapshot.
- Host inventory: kernel `7.0.0-30-generic`, Docker `29.7.2` using overlay2 and
  systemd/cgroup v2, kind `0.29.0`, kubectl `1.36.3`. No running containers or
  kind clusters were present during preflight. Recheck before execution.
- Both hardcoded p11-kit/SoftHSM library paths exist. Passwordless sudo works.
- Repository ancestors are group-writable. A private receipt parent beneath
  `p11scope-ws` alone does not make it a trusted live capture-output path.

## Task 1: Close preflight defects, freeze the runtime source and record environment

- [ ] Independently verify script arguments, working-directory rules, output
  locations and actual PASS markers below before running lanes.
- [ ] Fix the shared-layer receipt filename mismatch before running that lane:
  the body writes `broad.json`, `a-only.json` and `b-only.json`, while the wrapper
  searches for `*observed*.json`. Require all three literal captures, retain
  them under `work`, and bind `artifacts/capture.json` to `work/broad.json`.
  Add a behavioral self-test using the actual retention code, including a
  decoy observed file and missing/empty/symlink required captures. Verify RED,
  GREEN and independent review; preserve the capture oracles and cleanup.
- [ ] Commit the reviewed plan locally and refresh the clean runtime checkout
  to that commit. The staging directory is temporary; durable evidence is in
  `p11scope-ws`. Retain the exact commit, tree and privacy-allowlist checksum.

```sh
umask 077
campaign_root=$(mktemp -d /tmp/p11scope-release-local-XXXXXX)
git clone --no-hardlinks --single-branch --branch hardening/release-local \
  /home/user/src/m/pkcs11-scope "$campaign_root/source"
git -C "$campaign_root/source" status --porcelain
git -C "$campaign_root/source" rev-parse HEAD 'HEAD^{tree}'
uname -r
docker version
docker ps --format '{{.ID}} {{.Names}}'
kind get clusters
cd "$campaign_root/source"
```

Require empty source porcelain and preserve any unrelated resources. Run all
remaining commands as the ordinary caller from `$campaign_root/source`.

## Task 2: Execute existing lanes serially

- [ ] Run the host proxy lane; require the actual capacity-refusal oracle and
  final `proxy stack: ALL OK`. A `SKIP` with exit zero does not qualify it.
- [ ] Run Docker; require successful capture and all script assertions.
- [ ] Run shared-layer with an absent root under the private staging parent;
  require the script's terminal success status, not just intermediate captures.
- [ ] Run kind-pod; require successful capture and all script assertions.
- [ ] Run Knative with its distinct absent evidence root; require complete
  terminal evidence and verified cleanup.

```sh
scripts/matrix/verify-proxy-stack.sh
scripts/matrix/verify-docker.sh
scripts/matrix/verify-shared-layer.sh "$campaign_root/shared-layer"
scripts/matrix/verify-kind-pod.sh
P11SCOPE_LANE_EVIDENCE_DIR="$campaign_root/knative" \
  scripts/matrix/verify-knative.sh
```

Invoke each separately with stdout/stderr retained in a distinct log. Require
process exit zero after cleanup as well as each oracle's PASS evidence: Docker
and kind print `ALL OK` before their EXIT cleanup can still fail. A failure
stops progression into dependent lanes: inspect the actual error, preserve its
evidence, fix the root cause with a regression check if it is a product/script
defect, review the fix, and freeze a new source snapshot before rerunning.
Never make a lane pass by weakening its oracle or accepting a missing body.

## Task 3: Retain evidence and adjudicate gaps

- [ ] Copy each lane's logs, capture/checker/source identity, terminal status
  and applicable generated manifests into a new private directory beneath
  `/home/user/src/m/p11scope-ws/incoming/`; retain relevant binaries and their
  checksums where the lane retains them. Knative removes its product/work tree
  after recording binary hashes: accept its recorded binary identity for this
  provisional baseline and preserve its validated evidence root unchanged.
  Archive failures as well as successes. Never overwrite old evidence.
- [ ] Verify the copied evidence and checksums before ending temporary custody.
- [ ] Recheck Docker/kind inventories and lane-owned process cleanup against
  the initial inventory; preserve unrelated resources.
- [ ] Record one PASS/FAIL/UNRUN row per lane and its exact source/environment.

These are provisional host-observer results. They do not qualify an observer
inside a container, a localhost seccomp profile, SELinux Enforcing policy, the
full kernel matrix, either required product oracle, or the final release tip.
After the baseline, design the separate confined-observer policy lane from
measured syscall/capability/LSM failures. W5 remains open until its security
artifacts and their validation are complete; W8 still repeats qualification on
the final candidate.
