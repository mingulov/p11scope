<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Releasing p11scope

The owner's runbook for tagging a release, written for v0.1.0. The release
build uses network access and pins its source dependencies (lockfiles, the
`pkcs11-components` Git revision and hash-pinned patched crates), Rust
toolchains and discover build images. The builder records the effective host
tools and source tree in its receipt. Binary byte reproducibility has not been
established by independent builds. A full offline source export is an optional
capability, described in [docs/build-offline.md](docs/build-offline.md); the
attached v0.1.0 source export uses network access for remaining dependencies.

Run the steps in order. The release receipt binds the tree of `HEAD`. Finish
every tracked file before the final hosted CI run, qualification and artifact
build. Any later source or documentation change creates a new candidate and
requires the affected gates to run again on that new revision.

## 1. Freeze the candidate

- Merge the release work to `main` and check out the exact commit to tag.
  A release branch can stage and test the candidate first. When `main` is
  an ancestor of that branch, use a fast-forward to preserve the candidate
  commit. A merge commit, squash, rebase or history rewrite changes its
  identity; reconcile source-bound receipts and run the affected gates on
  the final commit before tagging.
  The tree must be clean, including untracked files:
  `git status --porcelain=v1 --untracked-files=all` prints nothing.
- Confirm the versions: `Cargo.toml` and `crates/discover/Cargo.toml` both
  say the release version (`0.1.0`). The other crates are internal and stay
  `0.0.0`.
- Keep the version heading in `CHANGELOG.md` (`## [0.1.0]`). Put the actual
  publication date in the GitHub release. Every tracked text change must land
  before final CI and artifact builds.
- Resolve release placeholders, then check that none remain:

  ```sh
  git grep -n 'TODO[(]release)'   # must print nothing
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

Push the frozen commit to a branch and let `ci` run. All of
`checks-and-e2e`, `coverage` and `archive-log` must pass on that exact SHA.
Then dispatch `ci` manually on the same ref (Actions → ci → Run workflow,
`release_preview` selected). Keep the `release-preview-public-assets` artifact
and the separately labeled container SBOM. The full release receipt remains
on the hosted runner only during verification; retain the full local builder
receipt privately. Actions logs contain a small status, source identity, tree
and digest-checker summary; record their run URL and result.
`privileged-e2e` needs a `[self-hosted, bpf]` runner; select it only if one
exists. Record the run URLs and exact source SHA for the release notes. A job
judged environmental (a flaky coverage run, for example) is an explicit,
written decision, never an ignored red badge.

The workflow needs no secrets: it uses only the default `GITHUB_TOKEN`
(`contents: read`, plus `actions: read` for the log-archive job).

## 4. Run the privileged qualification

On a quiet BPF-capable host, run the source-level qualification (kernel matrix,
privacy canaries, container lanes, overhead re-bench) against the frozen
commit. Record exact commands, source SHA, kernels, lanes, pass and skip counts,
and the binaries actually used. A lane that builds its own binary validates
that source, not the packaged bytes. After step 5, run every artifact-specific
qualification claimed in the release notes against the official `work/dist/`
binaries and record their hashes. Do not promote earlier candidate runs to
final tagged-artifact qualification. A fix found here invalidates the affected
results; go back to step 1.

## 5. Build the release artifacts

`scripts/build-release.sh` is the only path to the official bytes. It builds
the safe-only static observer (`--no-default-features`, musl, `+crt-static`,
build-host paths remapped), builds the discover helper for glibc and musl in
digest-pinned containers, and runs the canary, attach and hostile-target
smokes against the packaged binaries.

Requirements: a non-root user with passwordless `sudo`, a working Docker
daemon, SoftHSM2 at `/usr/lib/softhsm/libsofthsm2.so`, every tool in the
script's `RECEIPT_TOOL_INVENTORY` on `PATH` (including `bpftool`,
`llvm-objcopy`, `llvm-readelf`, `setpriv`, `softhsm2-util`, `file`), no
inherited `RUSTFLAGS`/`CARGO_*`/`RUSTUP_*` build variables, no untracked
`.cargo/config.toml`, and the pinned toolchains:

```sh
rustup toolchain install 1.88 --profile minimal --component rustfmt,clippy
rustup target add --toolchain 1.88 x86_64-unknown-linux-musl
rustup toolchain install nightly-2026-05-20 --profile minimal --component rust-src
cargo +1.88 install bpf-linker --version 0.10.4 --locked
python3 -I scripts/prepare-dependencies.py
cargo +1.88 fetch --locked
cargo +nightly-2026-05-20 fetch --locked --manifest-path crates/ebpf/Cargo.toml
```

The driver checks the host tool selection before building:

- The `rustup` on `PATH` must be rustup itself. A version manager's shim
  (for example mise's) rejects `rustup which --toolchain`, and the driver
  exits 77; put `~/.cargo/bin` first on `PATH`.
- A version manager may also inject `CARGO_HOME`, `RUSTUP_HOME` or
  `RUSTUP_TOOLCHAIN`, which the release preflight rejects. If these select
  only the standard homes and the pinned toolchain, remove those inherited
  variables when launching the driver, for example
  `mise exec -- env -u CARGO_HOME -u RUSTUP_HOME -u RUSTUP_TOOLCHAIN scripts/build-release.sh /var/tmp/p11scope-release/v0.1.0`.
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

The single argument is an absent evidence root whose parent is a private
directory outside the checkout:

```sh
mkdir -m 700 /var/tmp/p11scope-release
scripts/build-release.sh /var/tmp/p11scope-release/v0.1.0
```

The body prints `=== build-release: ALL OK ===` before the finalizer runs.
Accept the build only when the script exits zero, the receipt's `status` file
contains `0`, and `facts.log` records `terminal_status` and `checker_status`
as `0`. The marker alone is not a success verdict. Keep the whole evidence
root: `facts.log`, `stdout.log`, `stderr.log` and `artifacts/` are the receipt.
The binaries are in `work/dist/`: `p11scope` (static musl observer),
`p11scope-discover-glibc`, `p11scope-discover-musl`, and `p11scope-discover`
(a copy of the glibc helper). The duplicate is for the smoke lane; package
the explicitly named glibc and musl outputs.

Record the build facts for the release notes:

```sh
cd /var/tmp/p11scope-release/v0.1.0/work/dist
rustc +1.88 -V; rustc +nightly-2026-05-20 -V; bpf-linker --version; clang-18 --version
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
`p11scope-0.1.0-x86_64-linux-musl.tar.gz`,
`p11scope-discover-0.1.0-x86_64-linux-gnu.tar.gz`, and
`p11scope-discover-0.1.0-x86_64-linux-musl.tar.gz`. Each archive has one
same-named top-level directory containing an executable named `p11scope` or
`p11scope-discover` (mode `0755`), project GPL license texts, `notices/`, and
`RELEASE.json` with curated build provenance. The glibc and musl helpers
must remain separately labeled: each is dynamically linked and must match the
provider's ABI and C library. Generate and verify the notices from the actual
locked dependency graph, including the statically linked Rust crates and musl
libc. Retain license texts in the bundle even though the source export also
contains them. The package directory also contains top-level `RELEASE.json`
and `SHA256SUMS`; those metadata files accompany the four archives on GitHub.

Use `cargo-about` 0.9.2 and the official musl 1.2.3 and 1.2.5 source archives
for the observer and helper runtime notices. Verify each archive's SHA-256
before running the notice generator. The
example paths below are absolute; `/var/tmp/p11scope-release` was created with
mode `0700` in step 5, each output is absent, and their parent remains private:

```sh
cargo +1.88 install cargo-about --version 0.9.2 --locked
mkdir -m 700 /var/tmp/p11scope-release/package-inputs
curl -fL https://musl.libc.org/releases/musl-1.2.3.tar.gz \
  -o /var/tmp/p11scope-release/package-inputs/musl-1.2.3.tar.gz
printf '%s  %s\n' \
  7d5b0b6062521e4627e099e4c9dc8248d32a30285e959b7eecaa780cf8cfd4a4 \
  /var/tmp/p11scope-release/package-inputs/musl-1.2.3.tar.gz | sha256sum --check
curl -fL https://musl.libc.org/releases/musl-1.2.5.tar.gz \
  -o /var/tmp/p11scope-release/package-inputs/musl-1.2.5.tar.gz
printf '%s  %s\n' \
  a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4 \
  /var/tmp/p11scope-release/package-inputs/musl-1.2.5.tar.gz | sha256sum --check
python3 -I scripts/release-notices.py \
  --cargo-about "$(command -v cargo-about)" \
  --musl-archive /var/tmp/p11scope-release/package-inputs/musl-1.2.3.tar.gz \
  --musl-archive /var/tmp/p11scope-release/package-inputs/musl-1.2.5.tar.gz \
  --output /var/tmp/p11scope-release/notices
python3 -I scripts/export-source.py \
  --output /var/tmp/p11scope-release/p11scope-0.1.0-source.tar.gz
python3 -I scripts/package-release.py \
  --receipt /var/tmp/p11scope-release/v0.1.0 \
  --notices /var/tmp/p11scope-release/notices \
  --source /var/tmp/p11scope-release/p11scope-0.1.0-source.tar.gz \
  --output /var/tmp/p11scope-release/public-assets
```

The attached schema-v1 source export contains the committed source and the two
exact pinned Aya archives. It still needs network access or a populated Cargo
cache for the remaining locked dependencies; do not describe it as a full offline
export. A separately assembled full offline export is documented in
[docs/build-offline.md](docs/build-offline.md). GitHub's automatic source
archive lacks even the two embedded Aya archives.

Verify `SHA256SUMS` against the four versioned `.tar.gz` assets and top-level
`RELEASE.json`:

```sh
(cd /var/tmp/p11scope-release/public-assets && sha256sum --check SHA256SUMS)
```

Extract each archive into a fresh private
directory and inspect its exact member set, modes, executable version,
license notices and provenance. For the musl dynamic helper, use a compatible
musl host or container for its executable smoke; inspecting the archive is
still required on the build host. Test the source archive as a recipient with
network access and the pinned toolchains; its included Aya archives should
reconstruct without downloading them. For example, from the repository root:

```sh
source_recipient=$(mktemp -d /var/tmp/p11scope-source-recipient.XXXXXX)
tar --same-permissions --no-same-owner -xzf \
  /var/tmp/p11scope-release/p11scope-0.1.0-source.tar.gz \
  -C "$source_recipient"
(
  cd "$source_recipient/p11scope-source"
  python3 -I scripts/prepare-dependencies.py --offline
  mise exec -- ./scripts/cargo.sh +1.88 build --locked --release \
    --no-default-features --target x86_64-unknown-linux-musl --bin p11scope
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
   git tag -a v0.1.0 -m 'p11scope v0.1.0'    # or -s to sign
   git push origin main v0.1.0
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

- Keep the evidence root from step 5 with the release records.
- Start the next `## [Unreleased]` section in `CHANGELOG.md` only when the
  next change lands.
