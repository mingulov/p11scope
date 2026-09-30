<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Build a full source export offline

The v0.1.0 GitHub release attaches a networked source export containing the
committed source and two pinned Aya archives. It is not a full offline export:
the remaining locked Cargo dependencies still require network access or a
pre-populated cache. This guide covers a separate full export that can be
produced with `scripts/export-source.py`. A plain Git checkout and GitHub's
automatically generated source archives also lack the offline dependency
payload. The producer must first assemble and verify that payload against the
committed `third-party/offline-dependencies.json` recipe, then create the full
export from a clean, committed revision with an absent absolute output path:

```sh
nightly_rustc=$(rustup which --toolchain nightly-2026-05-20 rustc)
python3 -I scripts/export-source.py \
  --output /absolute/private-parent/full-offline-source.tar.gz \
  --offline-payload /absolute/verified-offline-payload \
  --nightly-rustc "$nightly_rustc"
```

The paths are producer inputs, not directories created by this command:
replace them with the verified payload location and a new output filename
outside the checkout, under an existing private parent. An export made with
`--output` alone embeds only the two pinned patched-crate archives. It still
needs network access or pre-populated Cargo caches for the remaining locked
dependencies; do not describe it as a full offline export.

The full source export contains the complete Cargo dependency payload but does
not contain Rust toolchains or operating-system build tools. Install Rust 1.98.1,
`nightly-2026-05-20` with `rust-src`, `bpf-linker`, Clang/LLVM, the native C
toolchain, Python >=3.11 (or Python 3.10 with the distro `python3-tomli`
package), Git, and ordinary POSIX shell/archive tools before the machine is
disconnected. `rustup` and `bpf-linker` must be in the same
canonical executable directory. The Rust version above tracks
`.release-rust-version`, the single authoritative release-compiler pin.

On Debian or Ubuntu with Python 3.10, install and verify the TOML parser while
the machine is still connected:

```sh
sudo apt-get install python3-tomli
/usr/bin/python3 -I -c 'import tomli; print("python3-tomli: OK")'
```

Before disconnecting, verify the exact interpreter used by the offline path
can import the helper:

```sh
/usr/bin/python3 -I scripts/offline-dependencies.py --help
```

Python 3.11 and newer provide `tomllib` in the standard library and do not
need `python3-tomli`.

Before accepting a separately supplied full export, verify its SHA-256 against
the digest supplied by its producer. The v0.1.0 release's `SHA256SUMS` covers
its attached networked source export, not a separate full export. Extract the
full export into a private temporary parent, preserving the recorded directory
modes and rejecting archive ownership changes:

```sh
umask 077
mkdir -m 700 /absolute/export-parent
tar --same-permissions --no-same-owner -xzf /absolute/source-export.tar.gz \
  -C /absolute/export-parent
```

Change to the extracted top-level directory and choose a new, canonical
absolute work path outside it:

```sh
sh scripts/build-offline.sh /absolute/new/private-work
```

The work path may contain spaces but must not contain `:`, because it forms the
first entry in the build-only executable search path.

The bootstrap refuses inherited Cargo source/build settings, Rust wrappers and
flags, compiler overrides, prepared-build variables, small-map settings, and
competing Cargo configuration files. It selects the installed stable and
nightly tools with rustup auto-install disabled, creates a fresh private Cargo
home and target, verifies and reconstructs the embedded payload, and calls the
fixed prepared product build with locked and offline behavior. It repeats the
source, payload, recipe, configuration, prepared-tree custody, and tool checks
after the build. The verified prepared trees and their stable lock remain in
the extracted source so a later invocation can reuse them without repair.

On success, the target is under `WORK/target` and the deterministic audit
record is `WORK/evidence/build-offline.json`. The record contains tool and
input digests and the fixed logical build command. It contains no source-export
producer path or timestamp. A failed invocation removes only the fresh private
work root it created; an existing path is always refused and preserved.
