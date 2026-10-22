<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Releasing p11scope

The owner's runbook for a fully packaged release. The published
[v0.4.0 tag](https://github.com/mingulov/p11scope/tree/v0.4.0) is an intermediate
source checkpoint with explicit P0 selection, no new binary assets and open
installed/package acceptance; it does not claim completion of this runbook.
The versioned examples below use the current `0.4.0` manifest spelling. For a
new release, choose an unpublished version and fresh output paths; do not
recreate or move the existing v0.4.0 tag.

The release build uses network access and pins its source dependencies (lockfiles, the
`pkcs11-components` Git revision and hash-pinned patched crates), Rust
toolchains and digest-pinned build images. The builder records the effective host
tools and source tree in its receipt. Binary byte reproducibility has not been
established by independent builds. A full offline source export is an optional
capability, described in [docs/build-offline.md](docs/build-offline.md); the
attached source export uses network access for remaining dependencies.

Run the steps in order when assembling the final candidate. During development,
use focused regression checks per fix and affected checks at coherent integration
checkpoints; complete candidate gates follow convergence. The release receipt
binds the tree of `HEAD`. Finish tracked edits before final hosted CI and artifact
publication. Later edits invalidate affected checks and any whole-tree package
bindings; reconcile those on the final revision. Keep earlier functional results
labelled with their actual revision rather than restarting unrelated checks or
describing an old CI run as an exact-new-commit result.

## Version and schema-identifier rules

- The product version lives in two manifests: the root `Cargo.toml` and
  `crates/discover/Cargo.toml` carry the release version and must agree
  (`scripts/package-release.py` refuses to package when they differ). Every
  other crate is internal and stays `0.0.0`.
- Report schema identifiers are versioned separately from the product. They
  are opaque, exact dispatch keys: the apparent major/minor spelling grants
  no compatibility, and a consumer dispatches on the exact string. A release
  never renames a schema in place; an incompatible change ships under a new
  identifier with its schema document beside it.
- The current identifiers are `p11scope/observed-profile/v3` and
  `p11scope/observed-profile/v3-metrics` (profile lanes),
  `p11scope-manifest/5` (optional discovery input),
  `p11scope/inventory/v1` and `p11scope/inventory-events/v1` (inventory),
  `p11scope/inventory-diff/v1` (offline comparison),
  `p11scope/inventory-diagnostics/v1` (diagnostics), and
  `p11scope/inspect/v1` / `p11scope/inspect-system/v1` (inspection). Each is
  defined under [docs/schema](docs/schema) except `p11scope-manifest/5`,
  whose contract is code in
  [crates/manifest/src/manifest.rs](crates/manifest/src/manifest.rs)
  (the `SCHEMA` constant and its writer); the historical v2 profile
  documents keep their old shape.

## 1. Freeze the candidate

- Integrate release work into `main` with cherry-picks or a fast-forward and
  check out the exact commit to tag. A release branch can stage and test the
  candidate first. When `main` is
  an ancestor of that branch, use a fast-forward to preserve the candidate
  commit. A merge commit, squash, rebase or history rewrite changes its
  identity; reconcile source-bound receipts and run the affected gates on
  the final commit before tagging.
  The tree must be clean, including untracked files:
  `git status --porcelain=v1 --untracked-files=all` prints nothing.
- Confirm the versions: `Cargo.toml` and `crates/discover/Cargo.toml` both
  say the release version (`0.4.0`). The other crates are internal and stay
  `0.0.0`.
- Set the version heading in `CHANGELOG.md` to `## [0.4.0]` (drop
  ` - UNRELEASED`). Put the actual
  publication date in the GitHub release. Every tracked text change must land
  before final CI and artifact builds.
- Resolve release placeholders, then check that none remain:

  ```sh
  git grep -n 'TODO[(]release)'   # must print nothing
  git grep -n 'TBD-MEASURED\|TBD-QUALIFIED' -- docs CHANGELOG.md   # must print nothing
  ```

  Keep earlier candidate measurements revision-specific in `CHANGELOG.md`.
  Final CI URLs, artifact hashes, release-receipt identity and live lane results
  belong in the GitHub release notes, outside the commit they qualify.
- `crates/ebpf-common` is compiled into both the GPL-2.0-only BPF object and
  the GPL-3.0-or-later observer, so it is GPL-2.0-or-later. Confirm no
  GPL-3.0-only or Apache-2.0-only code has entered the BPF build
  (`cargo tree -e normal` in `crates/ebpf`).

## 2. Confirm the dependency revision is tagged

The pinned `pkcs11-components` revision must stay fetchable, so it must be
reachable from a published tag, not only from a branch a later force-push
could rewrite. The pinned `d0a47c7` is an ancestor of the published tags
`v0.2.0` and `v0.2.1`:

```sh
git ls-remote --tags https://github.com/mingulov/pkcs11-components
git -C <pkcs11-components checkout> fetch --tags origin
git -C <pkcs11-components checkout> merge-base --is-ancestor \
  d0a47c71d34294466bc41100ae6b5a5a329029d2 v0.2.0 && echo reachable
```

The revision must match the `rev =` in `Cargo.toml` and both lockfiles. The
crates.io releases of `pkcs11-types` and `pkcs11-module` (0.2.0, 0.2.1) are
later revisions with source changes, not `d0a47c7`. Moving to them is a
dependency upgrade that needs the full checks and qualification again.

## 3. Get a green hosted CI run on the exact commit

Push the frozen commit to a branch and let `ci` run. Every job of the push
run must pass on that exact SHA: `dedupe`; the check jobs `lint`, `audit`,
`tests`, `bpf-noninterference`, the eight `contracts` shards, and `scripts`;
the seven `coverage` partitions and `coverage-report`; and `archive-log`.
`quarantine` runs only when a check job failed (`if: failure()`), so a green
run skips it.

`ci` runs the full matrix once per commit. When the same commit is pushed
again under another ref (the release branch, then `main`, then the tag),
the later push run's `dedupe` job finds the earlier push or dispatch run that
already passed `lint`, `coverage-report` and `bpf-noninterference` on that SHA, skips its own check
and coverage jobs, and names the covering run in its summary. If the earlier
run is still going, `dedupe` waits for it, and runs the full matrix itself
when that run fails, is cancelled or is still unfinished after 75 minutes.
Record the URL of the run that executed the matrix, not of a deduplicated
one; a deduplicated run on the tag is green only because that covering run
passed. A manual dispatch always runs the full matrix.

`bpf-noninterference` follows `tests`, including when tests fail. It first
runs the repeat-baseline control on reviewed v0.4.0 baseline
`f1bc557e85119f8caa82160a083d2c095eb58ba4` twice, then compares that
baseline with the exact candidate commit in a fresh integration snapshot.
Advance the baseline only after reviewing intentional BPF changes, not to
clear an arbitrary comparison failure. All bytes
of the three default BPF objects must match in the same pinned tool/header environment;
a proven BTF type-order-only permutation (identical sections, same BTF
meaning) is accepted with a recorded `btf-order-only` verdict instead of
failing the gate. Its
separate artifact retains commands, source and tool receipts, object digests
and section summaries on success or failure.
After root/BPF acquisition, it fetches the selected pinned nightly's installed
`library/sysroot/Cargo.toml` with `--locked` before the offline build. Receipts
bind that manifest and `library/Cargo.lock` before/after and between snapshots;
the toolchain source inputs must stay unchanged.
The checker's command runner applies timeouts; later text parsing rejects stdout
over 64 MiB. Captured
stdout/stderr files have no byte cap and can consume disk until a command exits
or times out, including a failed build whose output is retained without parsing.
This gate does not qualify the separate identity object on a live kernel.

For a restricted network environment, pass both `--baseline-offline-payload ABS`
and `--candidate-offline-payload ABS` to the checker. Each snapshot admits its
payload against its own committed offline recipe using the existing complete
validator. The checker copies validated inputs into owned scratch, generates
only the exact source replacement config, and uses locked offline fetches and
offline nested Cargo in a fresh private home for each build. Receipts bind the
supplied and copied payloads, config and coordinator helpers before and after
execution. Use the released payload for both sides of the R/R diagnostic.
The ordinary acquisition path also fetches nightly sysroot dependencies;
root/BPF fetches alone do not provide that closure. Payload mode does not
establish hosted online/network qualification, which still needs real CI
evidence.

Then dispatch `ci` manually on the same ref (Actions → ci → Run workflow,
`release_preview` selected). The job rebuilds the musl observer, builds the
observer/holder container images (with hadolint and kubeconform checks over
`deploy/`), runs the official builder receipt, and assembles the notices,
source export and public candidate. The `release-preview-public-assets`
artifact has 30-day retention. The separately labeled container SBOM
(`sbom-observer-container-preview`) describes the preview container image,
not the official release bytes. Keep the local builder receipt while packaging,
verification or active debugging needs it; this does not require a permanent
private archive. The full hosted receipt remains on the runner only during
verification. Actions logs contain a small status, source identity, tree and
digest-checker summary; record their run URL and result.

The current preview workflow still names its source-export input
`p11scope-0.3.0-source.tar.gz`, independently of the manifest version. The
packager validates the archive's recorded revision and derives the public
source filename from the manifests. Inspect the actual output `RELEASE.json`
and `SHA256SUMS`; the preview input filename is not version evidence. Workflow
filename cleanup remains open.
`privileged-e2e` needs a `[self-hosted, bpf]` runner; select it only if one
exists. Record the run URLs and exact source SHA for the release notes. A job
judged environmental (a flaky coverage run, for example) is an explicit,
written decision, never an ignored red badge.

The workflow needs no secrets: it uses only the default `GITHUB_TOKEN`
(`contents: read`, plus `actions: read` for the `dedupe` and log-archive
jobs). Its caches hold only the cargo-installed tool binaries and the debug
build products of `lint`, `tests` and `contracts`; every job still
reconstructs and fetches its dependency sources, and coverage builds from
scratch.

## 4. Run the privileged qualification

On a quiet BPF-capable host, run the source-level qualification against the
frozen commit: the release-matrix lanes
(`scripts/qualify-release-matrix.sh`, seven lanes — 5.15.221, 6.1.188,
6.6.157, Ubuntu 6.8.0-142-generic, 6.12.111, 7.2.6 and the host; see
[docs/qualification/release-matrix.md](docs/qualification/release-matrix.md)),
privacy canaries, container lanes and overhead re-bench. Start with a plan.
For prebuilt execution, set `candidate_sha`, `bin_dir` and `candidate_receipt`
to the selected commit, binary directory and its actual build-produced receipt;
guest storage/account prerequisites are described in the matrix guide:

```sh
scripts/qualify-release-matrix.sh --dry-run
scripts/qualify-release-matrix.sh --rev "$candidate_sha" --bin-dir "$bin_dir" \
  --candidate-receipt "$candidate_receipt"
```

Record exact commands, source SHA, kernels, lanes, pass and skip counts,
and the binaries actually used. A lane that builds its own binary validates
that source, not the packaged bytes. After step 5, run every artifact-specific
qualification claimed in the release notes against the official `work/dist/`
binaries and record their hashes. Do not promote earlier candidate runs to
final tagged-artifact qualification. A fix found here invalidates the affected
results. Select the updated candidate, repeat the affected qualification and
reconcile its build/package bindings before the final candidate gates; do not
restart unrelated qualification for every fix.

## 5. Build the release artifacts

`scripts/build-release.sh` is the only path to the official bytes. It builds
the P0 static observer (`--no-default-features --features stub-object-attributes`,
musl, `+crt-static`, build-host paths remapped), builds the discover helper for
glibc and musl in digest-pinned containers, and runs the canary, attach and hostile-target
smokes against the packaged binaries. The helper lane
(`scripts/verify-discover-containers.sh`) pins `rust:1.98.1-bookworm`,
`rust:1.98.1-alpine3.22` and the `ubuntu:noble-20260810` run image by digest.

Ordinary source builds default to FULL; `--no-default-features` alone does not
select P0. The current packager still writes `p11scope_features: []` in
`RELEASE.json`, so that field alone does not establish capture mode. Report
the actual builder feature selection and the runtime object-capture disclosure;
this release metadata correctness gap remains open.

Requirements: a non-root user with passwordless `sudo` (`sudo -n true` must
succeed), a working Docker daemon, SoftHSM2 at
`/usr/lib/softhsm/libsofthsm2.so`, every tool in the script's
`RECEIPT_TOOL_INVENTORY` on `PATH` (including `bpftool`,
`llvm-objcopy`, `llvm-readelf`, `setpriv`, `softhsm2-util`, `file`), none of
the inherited build inputs in `RECEIPT_BUILD_INPUTS` set (`RUSTFLAGS`,
`CARGO_*`, `RUSTUP_*`, `RUSTC_WRAPPER`, `CC`, `CFLAGS` and the
`P11SCOPE_PREPARED_*`/`P11SCOPE_PRODUCT_BUILD_MODE` seams), a safe `TMPDIR`,
no untracked `.cargo/config.toml`, and the pinned toolchains:

```sh
rustup toolchain install 1.98.1 --profile minimal --component rustfmt,clippy
rustup target add --toolchain 1.98.1 x86_64-unknown-linux-musl
rustup toolchain install nightly-2026-05-20 --profile minimal --component rust-src
cargo +1.98.1 install bpf-linker --version 0.10.4 --locked
python3 -I scripts/prepare-dependencies.py
cargo +1.98.1 fetch --locked
cargo +nightly-2026-05-20 fetch --locked --manifest-path crates/ebpf/Cargo.toml
```

The stable version above is the release compiler, single-sourced from
`.release-rust-version` (currently 1.98.1); the release scripts and CI read
that file rather than pinning a literal. The `bpf-linker` version matches
`CI_TOOL_BPF_LINKER` in `.github/workflows/ci.yml`.

The driver checks the host tool selection before building:

- The `rustup` on `PATH` must be rustup itself. A version manager's shim
  (for example mise's) rejects `rustup which --toolchain`, and the driver
  exits 77; put `~/.cargo/bin` first on `PATH`.
- A version manager may also inject `CARGO_HOME`, `RUSTUP_HOME` or
  `RUSTUP_TOOLCHAIN`, which the release preflight rejects. If these select
  only the standard homes and the pinned toolchain, remove those inherited
  variables when launching the driver, for example
  `mise exec -- env -u CARGO_HOME -u RUSTUP_HOME -u RUSTUP_TOOLCHAIN scripts/build-release.sh /var/tmp/p11scope-release/v0.4.0`.
  A custom Cargo or rustup home requires a separate build environment.

The discover helper lane creates one dedicated Docker bridge with automatic
subnet allocation, records its identity and subnet, and removes it after its
owned containers. Its containers must resolve and reach the Ubuntu and Alpine
package archives. This avoids relying on Docker's default bridge, whose subnet
can overlap the host's DNS network (for example, WSL2 NAT at `172.17.x.x`
against `172.17.0.0/16`). No Docker daemon restart is needed. If network setup
or package access still fails, retain the failed receipt and inspect the
recorded network and the host's resolver configuration before retrying, or use the
`release-preview` CI job.

The single argument is an absent absolute evidence root whose parent is an
existing private directory outside the checkout:

```sh
mkdir -p -m 700 /var/tmp/p11scope-release && chmod 700 /var/tmp/p11scope-release
scripts/build-release.sh /var/tmp/p11scope-release/v0.4.0
```

The body prints `=== build-release: ALL OK ===` before the finalizer runs.
Accept the build only when the script exits zero, the receipt's `status` file
contains `0`, and `facts.log` records `terminal_status` and `checker_status`
as `0`. The marker alone is not a success verdict. `facts.log`, `stdout.log`,
`stderr.log` and `artifacts/` form the builder receipt; keep it intact through
packaging and verification. Completed build caches and temporary full logs do
not require permanent retention once active work no longer needs them.
The binaries are in `work/dist/`: `p11scope` (static musl observer),
`p11scope-discover-glibc`, `p11scope-discover-musl`, and `p11scope-discover`
(a copy of the glibc helper). The duplicate is for the smoke lane; package
the explicitly named glibc and musl outputs. The builder binds the four files
to `artifacts/release-artifacts.sha256` with
`scripts/release-artifacts.py record` and re-verifies the binding before it
publishes `status`.

Record the build facts for the release notes:

```sh
cd /var/tmp/p11scope-release/v0.4.0/work/dist
rustc +1.98.1 -V; rustc +nightly-2026-05-20 -V; bpf-linker --version; clang-18 --version
if strings -a p11scope | grep -Fq -- "$HOME"; then
  echo 'release binary embeds build-home path' >&2
  exit 1
fi
cd - >/dev/null
```

The official builder's smoke lanes run against the exact binaries copied into
`work/dist/`, including its packaged static observer and glibc helper. Record
those commands and results from the receipt. An external kernel, container or
long-running lane counts as final-artifact qualification only if it actually
uses these prebuilt bytes; record the binary SHA-256 with its result. A lane
that builds its own binary remains source qualification. Describe only lanes
that ran in the final release notes.

## 6. Package the release assets

`scripts/package-release.py` makes three versioned tarballs from the official
binaries:
`p11scope-0.4.0-x86_64-linux-musl.tar.gz`,
`p11scope-discover-0.4.0-x86_64-linux-gnu.tar.gz`, and
`p11scope-discover-0.4.0-x86_64-linux-musl.tar.gz`. Each archive has one
same-named top-level directory containing an executable named `p11scope` or
`p11scope-discover` (mode `0755`), project GPL license texts, `notices/`, and
`RELEASE.json` with curated build provenance. The glibc and musl helpers
must remain separately labeled: each is dynamically linked and must match the
provider's ABI and C library. Generate and verify the notices from the actual
locked dependency graph, including the statically linked Rust crates and musl
libc. Retain license texts in the bundle even though the source export also
contains them. The package directory also contains the versioned source
archive, top-level `RELEASE.json` and `SHA256SUMS` (which covers the four
archives plus `RELEASE.json`); those metadata files accompany the four
archives on GitHub.

Use `cargo-about` 0.9.2 and the official musl 1.2.5 source archive (the Rust 1.98.1 static target
builds patched musl 1.2.5; the Alpine helper links musl 1.2.5-r12). Both pins
are enforced: the notice generator accepts only `cargo-about 0.9.2` output
and the recipe-pinned musl SHA-256. Verify its SHA-256
before running the notice generator. The
example paths below are absolute; `/var/tmp/p11scope-release` was created with
mode `0700` in step 5, each output is absent, and their parent remains private:

```sh
cargo +1.98.1 install cargo-about --version 0.9.2 --locked --features cli
mkdir -m 700 /var/tmp/p11scope-release/v0.4.0-package-inputs
curl -fL https://musl.libc.org/releases/musl-1.2.5.tar.gz \
  -o /var/tmp/p11scope-release/v0.4.0-package-inputs/musl-1.2.5.tar.gz
printf '%s  %s\n' \
  a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4 \
  /var/tmp/p11scope-release/v0.4.0-package-inputs/musl-1.2.5.tar.gz | sha256sum --check
python3 -I scripts/release-notices.py \
  --cargo-about "$(command -v cargo-about)" \
  --musl-archive /var/tmp/p11scope-release/v0.4.0-package-inputs/musl-1.2.5.tar.gz \
  --output /var/tmp/p11scope-release/v0.4.0-notices
python3 -I scripts/export-source.py \
  --output /var/tmp/p11scope-release/p11scope-0.4.0-source.tar.gz
python3 -I scripts/package-release.py \
  --receipt /var/tmp/p11scope-release/v0.4.0 \
  --notices /var/tmp/p11scope-release/v0.4.0-notices \
  --source /var/tmp/p11scope-release/p11scope-0.4.0-source.tar.gz \
  --output /var/tmp/p11scope-release/v0.4.0-public-assets
```

The attached schema-v1 source export contains the committed source and the two
exact pinned Aya archives (aya 0.14.0 and aya-obj 0.3.0, recipe revision p2).
It still needs network access or a populated Cargo
cache for the remaining locked dependencies; do not describe it as a full offline
export. A separately assembled full offline export is documented in
[docs/build-offline.md](docs/build-offline.md). GitHub's automatic source
archive lacks even the two embedded Aya archives.

Verify `SHA256SUMS` against the four versioned `.tar.gz` assets and top-level
`RELEASE.json`:

```sh
(cd /var/tmp/p11scope-release/v0.4.0-public-assets && sha256sum --check SHA256SUMS)
```

Extract each archive into a fresh private
directory and inspect its exact member set, modes, executable version,
license notices and provenance. For the musl dynamic helper, use a compatible
musl host or container for its executable smoke; inspecting the archive is
still required on the build host. Then run the recipient journey from the
extracted bytes, not from `PATH`: the clean-context checklist is
[tests/fixtures/t11-package-acceptance/package-recipient-checklist.md](tests/fixtures/t11-package-acceptance/package-recipient-checklist.md)
(ledger and provenance, per-archive extract, executable smoke, installed
journeys, refusal twins, source recipient). The automated checks pin the same
journey:

```sh
python3 -I tests/python/test_release_recipient.py -v
python3 -I tests/fixtures/u6-installed-drive.py --self-test --journey ledger
python3 -I tests/fixtures/u6-installed-drive.py --dry-run --journey ledger \
  --binary <extracted-observer-dir>/p11scope
```

The first proves the journey executes the selected candidate binary (exact
path and digest; a decoy earlier in `PATH` stays unexecuted). The U6 driver
covers the ledger and named-trace installed journeys: `--self-test` runs the
synthetic twin red-green without capture (named-trace self-test needs
`--binary` for its offline diff twin), `--dry-run` validates the installed
wiring for an explicit `--binary` without capturing, and live mode (default)
runs the cells and fails closed. Test the source archive as a recipient with
network access and the pinned toolchains; its included Aya archives should
reconstruct without downloading them. For example, from the repository root:

```sh
source_recipient=$(mktemp -d /var/tmp/p11scope-source-recipient.XXXXXX)
tar --same-permissions --no-same-owner -xzf \
  /var/tmp/p11scope-release/p11scope-0.4.0-source.tar.gz \
  -C "$source_recipient"
(
  cd "$source_recipient/p11scope-source"
  python3 -I scripts/prepare-dependencies.py --offline
  mise exec -- ./scripts/cargo.sh +1.98.1 build --locked --release \
    --no-default-features --features stub-object-attributes \
    --target x86_64-unknown-linux-musl --bin p11scope
)
```

The `--offline` flag above applies only to reconstructing the two embedded
Aya archives; the Cargo build may fetch the remaining locked dependencies.
Record commands and outcomes before claiming any recipient build passed.

## 7. Tag

On the commit that steps 3–6 ran on:

1. Check that `git rev-parse HEAD` equals the `head` fact in the receipt's
   `facts.log`, the source export's recorded revision, and the SHA of the
   green CI run. Verify the package bundles contain the binaries from that
   receipt and that `SHA256SUMS` matches the files to upload.
2. Create an annotated (optionally signed) tag and push `main` and the tag:

   ```sh
   git tag -a v0.4.0 -m 'p11scope v0.4.0'    # or -s to sign
   git push origin main v0.4.0
   ```

3. Create the GitHub release with the four versioned `.tar.gz` assets,
   `RELEASE.json` and `SHA256SUMS`. Lead the notes with the commands delivered and their known
   limitations, including the `--system` preview. Link the changelog for
   detailed history. Identify the exact tag commit, hosted CI run URLs and job
   results, toolchain versions, local receipt digest and checker summary,
   artifact hashes,
   and the exact kernels, lanes, and binaries used for final qualification.
   Keep candidate-only results explicitly historical. Check the uploaded
   assets and notes after publication.

## After the tag

- Record concise source, CI, package and qualification results and unresolved
  limits. Retain private builder inputs and logs while active work needs them;
  preserve the licenses, notices and public provenance distributed with assets.
- Start the next `## [Unreleased]` section in `CHANGELOG.md` only when the
  next change lands.
