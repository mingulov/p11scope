<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Deployment artifacts

- [`k8s/`](k8s/README.md) — the Kubernetes node observer: namespace,
  ServiceAccount (no API access), DaemonSet, the required privileges and why
  each one is needed, limits, and troubleshooting. Start there.
- `Dockerfile.observer` — the observer image: the static musl `p11scope` plus
  `scripts/k8s-profile-entry.sh` on Alpine. No shell tools beyond busybox, no
  API client.
- `Dockerfile.observer-release` — the same image, but the binary comes from a
  release tarball (`p11scope-<version>-x86_64-linux-musl.tar.gz`) instead of a
  local build. Same base digest, same entrypoint; the tarball's `RELEASE.json`
  rides along for provenance. `scripts/kind-e2e.sh` uses it when
  `P11SCOPE_K8S_RELEASE_TARBALL` is set, with required
  `P11SCOPE_K8S_RELEASE_SHA256SUMS` verification; the checked hash is
  passed as `TARBALL_SHA256` and re-verified inside the build.
- `Dockerfile.holder`, `holder-entry.sh` — **test-only** workload image for
  the e2e: SoftHSM2 plus the ledgered client
  `tests/fixtures/public-cli/gated.c`. Never deploy it.
- `k8s/e2e/workloads.yaml` — **test-only** ledgered pods and the idle negative
  control used by `scripts/kind-e2e.sh`.

The observer image is published on release tags as
`ghcr.io/mingulov/p11scope:<version>` (see `RELEASING.md`); the holder image
stays test-only. The minimal container run keeps the measured capability set
(`--pid=host` plus `SYS_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH`, matching the
DaemonSet); dropping any of them refuses, as
`scripts/matrix/verify-container-image.sh` proves:

```sh
docker run --rm --pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE \
  --cap-add DAC_READ_SEARCH ghcr.io/mingulov/p11scope:0.7.0 doctor
```

To rebuild the image from this tree instead (`scripts/kind-e2e.sh` shows the
exact, reproducible steps; network access is expected for the base images and
packages):

```sh
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo +"$(cat .release-rust-version)" build \
  --locked --release --no-default-features --target x86_64-unknown-linux-musl --bin p11scope
docker build -f deploy/Dockerfile.observer -t p11scope-observer:dev .
```
