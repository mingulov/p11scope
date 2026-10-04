<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Deployment artifacts

- [`k8s/`](k8s/README.md) — the Kubernetes node observer: namespace,
  ServiceAccount (no API access), DaemonSet, the required privileges and why
  each one is needed, limits, and troubleshooting. Start there.
- `Dockerfile.observer` — the observer image: the static musl `p11scope` plus
  `scripts/k8s-profile-entry.sh` on Alpine. No shell tools beyond busybox, no
  API client.
- `Dockerfile.holder`, `holder-entry.sh` — **test-only** workload image for
  the e2e: SoftHSM2 plus the ledgered client
  `tests/fixtures/public-cli/gated.c`. Never deploy it.
- `k8s/e2e/workloads.yaml` — **test-only** ledgered pods and the idle negative
  control used by `scripts/kind-e2e.sh`.

Nothing here is a published image: build both images from this tree
(`scripts/kind-e2e.sh` shows the exact, reproducible steps; network access is
expected for the base images and packages).
