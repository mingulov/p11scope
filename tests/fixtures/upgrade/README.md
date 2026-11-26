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
- `tools/`: the regeneration helpers (`sanitize.py` and the
  `capture-*.sh` capture scripts).

Sanitizer rules (one run, shared maps, so the same real value maps
to the same canonical value in every file): the worktree prefix
becomes `/work`, Debian library paths become `/usr/lib/...`
counterparts, cargo shim paths become `/usr/bin/...`; PIDs (fields,
`pid:` scopes, `/proc/` and gap-reason mentions) map from 4242 up;
digests (40/64 hex) map to zero-padded indexes; device numbers map
to small constants; inodes map from 100 up; mtimes become fixed;
`launched_by` exe names become `launcher`. Counts, labels,
structures, instants, enums and offsets stay byte-real.
