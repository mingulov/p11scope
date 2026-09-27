<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Releasing p11scope

The owner's runbook for tagging a release, written for v0.1.0. The release
contract is a **reproducible build with network access**: every input is
pinned (lockfiles, the `pkcs11-components` Git revision, hash-pinned patched
crates, exact toolchains, digest-pinned discover build images). An offline
build is not required, but the offline machinery (`scripts/build-offline.*`,
`scripts/export-source.py`, `third-party/offline-dependencies.json`) must keep
working; see [docs/build-offline.md](docs/build-offline.md).

Run the steps in order. The release receipt binds the tree of `HEAD`, so any
change after step 5 means starting again from step 3.

## 1. Freeze the candidate

- Merge the release work to `main` and check out the exact commit to tag.
  The tree must be clean, including untracked files:
  `git status --porcelain=v1 --untracked-files=all` prints nothing.
- Confirm the versions: `Cargo.toml` and `crates/discover/Cargo.toml` both
  say the release version (`0.1.0`). The other crates are internal and stay
  `0.0.0`.
- Set the tag date in the `CHANGELOG.md` heading
  (`## [0.1.0] - YYYY-MM-DD`). Every text change must land now: the CI run
  and the release receipt below bind this exact tree.
- Resolve every other release placeholder, then check that none remain:

  ```sh
  git grep -n 'TODO[(]release)'   # must print nothing
  ```

  They mark the tag date, the qualification record in `CHANGELOG.md`, and
  wording that depended on work still in progress when they were written.
  Filling the qualification record needs results from steps 3–5, so run
  those on the candidate, fill the record, and repeat steps 3 and 5 on the
  final commit.
- Confirm the license of `crates/ebpf-common` (it is compiled into both the
  GPL-2.0-only BPF object and the GPL-3.0-or-later observer).

## 2. Tag the dependency first

`pkcs11-components` has no tags; the pinned revision survives only while it
is reachable from a branch. Tag it before tagging p11scope, so a later
force-push cannot make this release unbuildable:

```sh
git -C <pkcs11-components checkout> tag -a v0.2.0 \
  d0a47c71d34294466bc41100ae6b5a5a329029d2 -m 'pkcs11-components v0.2.0'
git -C <pkcs11-components checkout> push origin v0.2.0
git ls-remote --tags https://github.com/mingulov/pkcs11-components
```

The revision must match the `rev =` in `Cargo.toml` and both lockfiles.

## 3. Get a green hosted CI run on the exact commit

Push the frozen commit to a branch and let `ci` run. All of
`checks-and-e2e`, `coverage` and `archive-log` must pass on that exact SHA.
Then dispatch `ci` manually on the same ref (Actions → ci → Run workflow,
`release_preview` selected) and keep the `release-preview-receipt` artifact.
`privileged-e2e` needs a `[self-hosted, bpf]` runner; select it only if one
exists. Record the run URLs for the release notes. A job judged environmental
(a flaky coverage run, for example) is an explicit, written decision, never
an ignored red badge.

The workflow needs no secrets: it uses only the default `GITHUB_TOKEN`
(`contents: read`, plus `actions: read` for the log-archive job).

## 4. Run the privileged qualification

On a quiet BPF-capable host, run the qualification the release claims
(kernel matrix, privacy canaries, container lanes, overhead re-bench) against
the frozen commit, and record the kernels and lanes that passed in
`CHANGELOG.md` under "Qualification of this release". A fix found here
invalidates the affected results; go back to step 1.

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

The single argument is an absent evidence root whose parent is a private
directory outside the checkout:

```sh
mkdir -m 700 /var/tmp/p11scope-release
scripts/build-release.sh /var/tmp/p11scope-release/v0.1.0
```

It ends with `=== build-release: ALL OK ===`. Keep the whole evidence root:
`facts.log`, `stdout.log`, `stderr.log` and `artifacts/` are the receipt.
The binaries are in `work/dist/`: `p11scope` (static musl observer),
`p11scope-discover-glibc`, `p11scope-discover-musl`, and `p11scope-discover`
(a copy of the glibc helper).

Record the build facts for the release notes:

```sh
cd /var/tmp/p11scope-release/v0.1.0/work/dist
sha256sum p11scope p11scope-discover-glibc p11scope-discover-musl > SHA256SUMS
rustc +1.88 -V; rustc +nightly-2026-05-20 -V; bpf-linker --version; clang-18 --version
strings -a p11scope | grep -c "$HOME"   # expect 0: build-host paths are remapped
```

## 6. Package (only if binaries are attached to the release)

For a source-only release, skip this step. To attach binaries, name them
`p11scope-0.1.0-x86_64-linux-musl`, `p11scope-discover-0.1.0-x86_64-linux-gnu`
and `p11scope-discover-0.1.0-x86_64-linux-musl`, regenerate `SHA256SUMS` over
those names, and ship beside them `LICENSE`, `LICENSES/GPL-2.0-only.txt`, and
the third-party license notices of the statically linked Rust crates and musl
libc (for example generated with `cargo about`); binary distributions must
carry those notices.

## 7. Tag

On the commit that steps 3 and 5 ran on:

1. Check that `git rev-parse HEAD` equals the `head` fact in the receipt's
   `facts.log` and the SHA of the green CI run.
2. Create an annotated (optionally signed) tag and push `main` and the tag:

   ```sh
   git tag -a v0.1.0 -m 'p11scope v0.1.0'    # or -s to sign
   git push origin main v0.1.0
   ```

3. Create the GitHub release from the `CHANGELOG.md` section. Include the
   hosted CI run URL, the qualified kernels and lanes, the toolchain versions
   and `SHA256SUMS` (plus the assets from step 6, if any).

## After the tag

- Keep the evidence root from step 5 with the release records.
- Start the next `## [Unreleased]` section in `CHANGELOG.md` only when the
  next change lands.
