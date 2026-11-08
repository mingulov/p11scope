<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Deployment artifacts

- [`k8s/`](k8s/README.md) — the Kubernetes node observer: namespace,
  ServiceAccount (no API access), DaemonSet, the required privileges and why
  each one is needed, limits, and troubleshooting. Start there.
- `Dockerfile.observer-release` — the published observer image: the
  verified release tarball's static musl `p11scope`,
  `scripts/k8s-profile-entry.sh`, licenses, notices and `RELEASE.json` on
  scratch with a pinned static busybox for the entry script. No package
  manager, no TLS or crypto libraries, no API client.
  `scripts/kind-e2e.sh` uses it when `P11SCOPE_K8S_RELEASE_TARBALL` is set,
  with required `P11SCOPE_K8S_RELEASE_SHA256SUMS` verification; the checked
  hash is passed as `TARBALL_SHA256` and re-verified inside the build.
- `Dockerfile.observer` — the same layout for development builds from a
  staged static binary (no notices or provenance; publish uses the
  release file above).
- `Dockerfile.holder`, `holder-entry.sh` — **test-only** workload image for
  the e2e: SoftHSM2 plus the ledgered client
  `tests/fixtures/public-cli/gated.c`. Never deploy it.
- `k8s/e2e/workloads.yaml` — **test-only** ledgered pods and the idle negative
  control used by `scripts/kind-e2e.sh`.

The observer image is published on releases as
`ghcr.io/mingulov/p11scope:<version>` (see `RELEASING.md`); the holder image
stays test-only. The measured DaemonSet set keeps `--pid=host` plus
`SYS_ADMIN`, `SYS_PTRACE` and `DAC_READ_SEARCH`, with the node cgroup
hierarchy mounted read-only. `SYS_ADMIN` stands in for `CAP_BPF` +
`CAP_PERFMON` + `CAP_CHECKPOINT_RESTORE` (BPF load and perf-event attach
where the narrow grant is absent, plus `map_files` for caller attribution).
The narrow five-capability container variant (`BPF`, `PERFMON`,
`CHECKPOINT_RESTORE`, `SYS_PTRACE`, `DAC_READ_SEARCH`, no `SYS_ADMIN`) is
unmeasured. Dropping `--pid=host` or `SYS_PTRACE` refuses, as
`scripts/matrix/verify-container-image.sh` proves:

```sh
docker run --rm --pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE \
  --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  ghcr.io/mingulov/p11scope:0.7.0 doctor
```

(On AppArmor hosts add `--security-opt apparmor=unconfined`; on
SELinux-enforcing hosts `--security-opt label=disable`. The example tag is
published with the 0.7.0 release; before that, substitute a locally built
image tag from the recipe below.)

To rebuild the development image from this tree instead
(`scripts/kind-e2e.sh` shows the exact steps, repeatable but not
bit-reproducible; network access is expected for the base images and
packages):

```sh
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo +"$(cat .release-rust-version)" build \
  --locked --release --target x86_64-unknown-linux-musl --bin p11scope
docker build -f deploy/Dockerfile.observer -t p11scope-observer:dev .
```
