<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Upgrade fixtures: real v0.7.1 and current captures

Real observer output for the v0.7.1 file-compatibility tests, kept
small (one provider, one anchor process, a handful of short-lived
signers). The v0.7.1 files come from the official release binaries:

- `p11scope-0.7.1-x86_64-linux-musl.tar.gz`
  sha256 `7e8b206b78381375fc966cb9cef17f32d89f792d4069add8b0d5394ce2792860`
- `p11scope-discover-0.7.1-x86_64-linux-gnu.tar.gz`
  sha256 `22721e04323d84581ca4b2d0029a8d739964b2b52f16e60921b1ed3098749338`

(both verified against the release `SHA256SUMS`). The v0.7.2 files
come from this tree's debug binary. The workload is SoftHSM 2.6.1
with a long-lived catalog-driver anchor plus staggered
`shortlived-sign` children (churn), a steady creator-signer
(key-ops), and short signing anchors (profile/metrics).

Files:

- `v071-inventory-scan.json`, `v071-inventory-native.json`: one
  anchor, `--capture scan` (unprivileged) and `--capture native`.
- `v071-inventory-churn.json`, `v072-inventory-churn.json`: the same
  churn workload (anchor plus eight staggered signers, cgroup scope,
  native, 24 s) captured by each release. The v0.7.1 side keeps
  exited signers as live rows; the current side folded them into
  `departed_use`.
- `v071-inventory-keyops.json`: a real v0.7.1 `--key-operations`
  capture. It admitted no keys on the capture host (the semantic
  lane needs BPF task storage, which kernels 7.0.0-44 and 7.3.4
  refuse; both releases agree), so it proves real-shape acceptance
  only — the nonzero established-count proof needs a host where the
  lane births.
- `v071-observed-profile-signer.json`, `v071-observed-metrics.json`,
  `v072-observed-profile.json`, `v072-observed-metrics.json`: one
  signing anchor per lane and release (`--duration 20s`).
- `v071-observed-profile.json` is owned by the upgrade-cells lane
  (its own capture, read by `scripts/upgrade-gate6.py`); this
  lane's profile fixture carries the `-signer` suffix so the two
  never collide.
- `v071-manifest-softhsm.json`: `p11scope-discover --module`
  SoftHSM output. No discover emits getter-only manifests (both
  versions leave `getters` empty), and those stay covered by the
  existing unit tests.
- `v071-observed-profile-v3.schema.json`: frozen copy of the schema
  at tag `v0.7.1` (blob `250a88da2eadacc1fee792ecb57a657c1e8c773a`).
- `tools/`: the regeneration helpers (`sanitize.py`, the
  `capture-*.sh` capture scripts, and the `creator.c` /
  `steady-keys.c` workload-helper sources).

Sanitizer rules (one run, shared maps, so the same real value maps
to the same canonical value in every file): the capture prefix
(`sanitize.py`'s third argument, default the lane path) becomes
`/work`, Debian library paths become `/usr/lib/...`
counterparts, cargo shim paths become `/usr/bin/...`; PIDs (fields,
`pid:` scopes, `/proc/` and gap-reason mentions) map from 4242 up;
digests (40/64 hex) map to zero-padded indexes; device numbers map
to small constants; inodes map from 100 up; mtimes become fixed;
`launched_by` exe names become `launcher`; cgroup slices and
scopes canonicalize to `user-1000.slice` / `session-1.scope`.
Counts, labels, structures, instants, enums and offsets stay
byte-real.

## Regenerate

Prerequisites: `gcc`, SoftHSM (`softhsm2-util` and
`libsofthsm2.so`; `/usr/lib/x86_64-linux-gnu/softhsm/` on
Debian/Ubuntu, `/usr/lib64/pkcs11/` on Fedora), a `pkcs11.h`
(`libp11-kit-dev`, a system softhsm include dir, or the
`cryptoki-sys` vendored copy under `~/.cargo/registry`), the
v0.7.1 release observer/discover binaries (hashes above) plus a
current-tree observer, and passwordless sudo for the privileged
captures (the scripts take the repo privileged lock themselves).

1. Pick a work root and export it (any directory works; the
   capture scripts honor `$TMPDIR`):
   `export TMPDIR=/var/tmp/p11scope-ws-tmp/v072-compat-071`.
2. Build the workload helpers into `$TMPDIR/f2/bin`:
   `catalog-driver` from `tests/fixtures/catalog-driver.c` and
   `shortlived-sign` from
   `tests/fixtures/shortlived-sign/shortlived-sign.c` with
   `cc -O2 -o bin/<name> <src> -ldl`, plus `creator` and
   `steady-keys` from `tests/fixtures/upgrade/tools/*.c` with
   the same line plus `-I <pkcs11.h dir>`.
3. Init the token:
   `export SOFTHSM2_CONF=$TMPDIR/f2/work/softhsm2.conf`
   (tokendir `$TMPDIR/f2/work/tokens`, file backend, `ALL`
   mechanisms), then `softhsm2-util --init-token --free --label
   upgrade-f2 --so-pin 1234 --pin 1234`, then prime the id the
   signer finds: `$TMPDIR/f2/bin/creator <provider> 1234 0102`.
4. Capture every sanitizer input (tag is the observer release;
   scan is unprivileged, the rest take the privileged lock):
   - `tools/capture-single.sh <v071-observer> v071 <out>` →
     `v071-inventory-scan.json`, `v071-inventory-native.json`
   - `tools/capture-churn.sh <observer> <tag> <out>` with tags
     `v071` and `v072` → `v071-inventory-churn.json`,
     `v072-inventory-churn.json`
   - `tools/capture-ops.sh <v071-observer> v071 keyops <out>` →
     `v071-inventory-keyops.json` (v0.7.1 only)
   - `tools/capture-ops.sh <observer> <tag> profile <out>` with
     tags `v071` and `v072` → `v071-observed-profile.json`,
     `v072-observed-profile.json`
   - `tools/capture-ops.sh <observer> <tag> metrics <out>` with
     tags `v071` and `v072` → `v071-observed-metrics.json`,
     `v072-observed-metrics.json`
   - `p11scope-discover-0.7.1 --module <provider>` →
     `v071-manifest-softhsm.json` (generate before the
     `--manifest` captures)
   Rename the raw v0.7.1 profile to
   `v071-observed-profile-signer.json` (see above). The capture
   set is exactly:

   ```manifest
   v071-inventory-scan.json
   v071-inventory-native.json
   v071-inventory-churn.json
   v072-inventory-churn.json
   v071-inventory-keyops.json
   v071-observed-profile-signer.json
   v071-observed-metrics.json
   v072-observed-profile.json
   v072-observed-metrics.json
   v071-manifest-softhsm.json
   ```

   (`tests/python/test_upgrade_regenerate.py` fails if this list
   and `sanitize.py`'s `FILES` drift apart.) The frozen schema is
   not captured: `git show
   v0.7.1:docs/schema/observed-profile-v3.schema.json`.
5. Sanitize in one run (shared maps):
   `tools/sanitize.py <rawdir> <outdir> [$TMPDIR]`.

On kernels where BPF task-storage creation fails, key-operations
captures come out keyless under both releases; a host where the
semantic lane births (6.x) is needed for a nonzero established
fixture.
