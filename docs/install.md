<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Install

p11scope v0.4.0 was an [intermediate source tag](https://github.com/mingulov/p11scope/tree/v0.4.0)
with no binary bundles. v0.5.0 was published on 2026-10-29
([release tag](https://github.com/mingulov/p11scope/releases/tag/v0.5.0)).
The [v0.6.0 release](https://github.com/mingulov/p11scope/releases/tag/v0.6.0)
provides the bundle set below, and the v0.7.0 release provides the same set:
a static x86-64 Linux observer bundle, optional glibc and musl discovery
helper bundles, DEB and RPM system packages, and a source export. The examples below install **v0.7.0**;
the 0.7.0 files appear on the
[Releases page](https://github.com/mingulov/p11scope/releases) when the release
is published. Download `SHA256SUMS` with the bundle you
choose. The release also provides `RELEASE.json` with curated provenance;
each bundle contains its license notices and a copy of that record.
Every release file carries a GitHub build-provenance attestation.
Older bundles remain under their release tags. To build current source
instead, see [Build locally from source](#build-locally-from-source).
GitHub's automatic source archive still needs the dependency inputs
described below (Building from source).

| Bundle | Use |
| --- | --- |
| `p11scope-0.7.0-x86_64-linux-musl.tar.gz` | Static observer, with the eBPF object embedded; needed for capture. |
| `p11scope-discover-0.7.0-x86_64-linux-gnu.tar.gz` | Optional helper for 64-bit glibc providers. |
| `p11scope-discover-0.7.0-x86_64-linux-musl.tar.gz` | Optional helper for 64-bit musl providers. |
| `p11scope_0.7.0_amd64.deb` | System package for Debian/Ubuntu: observer plus glibc helper. |
| `p11scope-0.7.0-1.x86_64.rpm` | System package for Fedora/RHEL: observer plus glibc helper. |

For example, download the observer and `SHA256SUMS` into a private directory,
then verify the archive before extraction:

```sh
download_dir=$(mktemp -d /var/tmp/p11scope-install.XXXXXX)
cd "$download_dir"
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.7.0/p11scope-0.7.0-x86_64-linux-musl.tar.gz
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.7.0/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf p11scope-0.7.0-x86_64-linux-musl.tar.gz
sudo install -m 0755 p11scope-0.7.0-x86_64-linux-musl/p11scope /usr/local/bin/p11scope
p11scope --version
sudo p11scope doctor
```

Keep the extracted bundle with its licenses, notices and `RELEASE.json` as
the record of the binary you installed.

### System packages (DEB/RPM)

The system packages install the same static observer binary plus the glibc
discovery helper (same bytes as the tarballs, no rebuild) to `/usr/bin`,
with licenses and provenance under `/usr/share/doc/p11scope`. They carry
no file capabilities, set-id bits, services or maintainer scripts. The musl
helper stays tarball-only for musl systems. The packages are
install-tested on Ubuntu 26.04 and Fedora 44. The bundled helper needs
glibc 2.34 or newer, so it does not run on older distributions. Download
the package and
`SHA256SUMS`, verify the checksum and the build attestation, then install
the file (Debian/Ubuntu shown; Fedora/RHEL uses `dnf install` with the
`.rpm` file):

```sh
download_dir=$(mktemp -d /var/tmp/p11scope-install.XXXXXX)
cd "$download_dir"
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.7.0/p11scope_0.7.0_amd64.deb
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.7.0/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify p11scope_0.7.0_amd64.deb --repo mingulov/p11scope
sudo apt install ./p11scope_0.7.0_amd64.deb
p11scope --version
sudo p11scope doctor
p11scope-discover --version
```

On Fedora/RHEL, replace the download with
`p11scope-0.7.0-1.x86_64.rpm`, verify it with
`gh attestation verify p11scope-0.7.0-1.x86_64.rpm --repo mingulov/p11scope`,
and install with `sudo dnf install ./p11scope-0.7.0-1.x86_64.rpm`.

To use attested semantic capture, download and verify the helper bundle for
the provider's C library, then extract and install its `p11scope-discover`
executable in the same way. Run `p11scope-discover --version` and the helper
itself as an ordinary user; never give it file capabilities or a set-id bit.
The observer needs Linux x86-64 and the kernel and privilege requirements
below. The helper needs the matching provider ABI and libc; a 32-bit provider
requires a separately built 32-bit helper.

The v0.7.0 release also includes `p11scope-0.7.0-source.tar.gz`. It contains the
committed source and the two pinned Aya archives needed to reconstruct the
local patches. Building it still needs network access for the remaining
locked Cargo dependencies, plus the Rust/BPF and host build tools described
above. The [offline build guide](build-offline.md) describes an optional
full export assembled separately.

### Build locally from source

`cargo install` is not supported: the root manifest patches two crates whose
trees `scripts/prepare-dependencies.py` generates. The official artifacts are
built and verified by `scripts/build-release.sh` (see
[RELEASING.md](../RELEASING.md)); the commands below are local build examples.

These commands describe current source. The published `v0.4.0` tag keeps
its own Rust 1.98.1 pin; rebuild it with the instructions from that tag.
The P0 configuration needs `--features stub-object-attributes` as well as
`--no-default-features`. Omitting that feature selects FULL;
`--no-default-features` alone does not disable object-attribute capture.
The official builder defaults to FULL; the observer example below selects P0.

**Build prerequisites** (x86-64 Linux; Ubuntu package names): the pinned
toolchains from [development setup](development.md). The scripts select
the stable toolchain as `+1.99.1`, and the static observer needs its musl
target:

```sh
sudo apt-get install -y build-essential clang-18 llvm python3 git
rustup toolchain install 1.99.1 --profile minimal
rustup target add --toolchain 1.99.1 x86_64-unknown-linux-musl
rustup toolchain install nightly-2026-05-20 --profile minimal --component rust-src
cargo +1.99.1 install bpf-linker --version 0.10.4 --locked
```

**Observer (`p11scope`).** A static musl binary with the BPF object embedded;
it never loads a provider, so one binary serves supported x86-64 Linux hosts:

```sh
RUSTFLAGS='-C target-feature=+crt-static' ./scripts/cargo.sh +1.99.1 build \
  --locked --release --no-default-features \
  --features stub-object-attributes \
  --target x86_64-unknown-linux-musl --bin p11scope
sudo install -m 0755 target/x86_64-unknown-linux-musl/release/p11scope /usr/local/bin/
```

**Optional helper (`p11scope-discover`).** Needed only for
[attested semantic capture](usage.md#attested-semantic-capture). It loads
the provider with `dlopen`, so it is dynamically linked and must match the
provider's C library: build it on (or in a container of) a glibc system for
glibc providers, and on a musl system such as Alpine for musl providers.

```sh
./scripts/cargo.sh +1.99.1 build --locked --release -p p11scope-discover
sudo install -m 0755 target/release/p11scope-discover /usr/local/bin/
```

The helper runs as an unprivileged identity with capabilities cleared. An
elevated invocation also clears supplementary groups before changing IDs;
an ordinary invocation can retain the user's non-root groups. This is not a
seccomp or Landlock sandbox: library
constructors and discovery exports execute with the helper user's access.
Use it only with provider code you trust to run as that user. The observer
does not launch it automatically. Never give it capabilities or a set-id bit.

**Kernel and privileges.** Live capture requires a Multi-capable Linux x86-64
host (normally 6.6+ or a working backport), BTF (`/sys/kernel/btf/vmlinux`) and
root or appropriate capabilities. General host eligibility is separate from
the safe scoped attachment backend. With multi active,
`CAP_BPF`+`CAP_PERFMON` suffice for the static probes of an unconfined
`--pid` target (measured 136/136 at `perf_event_paranoid=4`); full capture
at paranoid ≥ 3 (live discovery, uretprobe self-probe) needs `CAP_SYS_ADMIN`,
and on the per-probe `perf_event` path a restrictive paranoid needs
`CAP_SYS_ADMIN` too
([roles and measured matrix](usage.md#privileges-per-environment)). A broad
compatibility set is shown below. This is not a minimal set: `CAP_SYS_ADMIN`
already covers the BPF/perf permission checks.

```sh
sudo setcap 'cap_sys_admin,cap_bpf,cap_perfmon,cap_sys_ptrace,cap_dac_read_search+ep' \
  /usr/local/bin/p11scope
```

Anyone who can execute a capability-carrying observer can observe other
users' processes, so restrict who may execute it (for example, a dedicated
group and mode `0750`).

**Check the install:**

```sh
p11scope --version
sudo p11scope doctor
```

If you installed the optional helper, also run
`p11scope-discover --version` as your normal user.

## Building from source

The root manifest selects two patched crates reconstructed from
`third-party/sources.json`; their generated trees are intentionally absent from
Git. Mise selects the project's Rust 1.99.1 toolchain, and `scripts/cargo.sh`
prepares the generated sources before executing Cargo:

```sh
mise install
mise exec -- ./scripts/cargo.sh +1.99.1 build --locked
```

The release compiler is defined by `.release-rust-version` (currently 1.99.1).
CI and build scripts read that pin; `mise.toml` and host manifest floors stay
in sync with it. It is the supported host compiler, with no older MSRV, and
is updated when new stable Rust releases ship.

Preparation downloads only the recipe-pinned crates.io archives and verifies
their hashes, ordered patches, final tree hashes, and receipts. For an offline
or frozen build, place the exact archives (`aya-0.14.0.crate` and
`aya-obj-0.3.0.crate`, per `third-party/sources.json`) in
`third-party/archives/` first, or
run `python3 -I scripts/prepare-dependencies.py --archive-dir DIRECTORY`, then
use `mise exec -- ./scripts/cargo.sh +1.99.1 build --locked --offline`. An
ordinary fresh checkout therefore needs archive access. A plain Git checkout
or GitHub's automatic source archive excludes the generated trees, receipts
and local archive cache. All locked registry packages (including the
[pkcs11-components](https://github.com/mingulov/pkcs11-components/) crates
`pkcs11-types`/`pkcs11-module` 0.2.3) are separate Cargo inputs and
must already be cached for an offline build from that checkout. The published
source export embeds the two exact pinned Aya archives, but fetching the
remaining locked Cargo dependencies requires network access or a populated
cache. A separate full offline export can embed the complete dependency
payload; see below.

For a self-contained full source export and its fixed unprivileged recipient
bootstrap, use Python >=3.11, or Python 3.10 with the distro `python3-tomli`
package installed and verified before disconnection; see [the offline build
guide](build-offline.md).

See [development setup](development.md) for the Ubuntu 26.04 primary-host
packages, pinned Rust/BPF tools, and canonical checks. Ubuntu 26.04 is a
development host choice, not a product runtime dependency. The command above
is a debug build of every binary; [Install](#install) describes the release
assets and local release-mode builds.
