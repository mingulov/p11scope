<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
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
- [`seccomp-p11scope.json`](seccomp-p11scope.json) — the vendored Docker
  default seccomp profile plus one `bpf()` allow rule, for engines whose
  default cannot be used and for Kubernetes `Localhost` profiles (below).

The observer image is published on releases as
`ghcr.io/mingulov/p11scope:<version>` (see `RELEASING.md`); the holder image
stays test-only. The shipped recipe keeps `--pid=host` plus
`SYS_ADMIN`, `SYS_PTRACE` and `DAC_READ_SEARCH`, with the node cgroup
hierarchy mounted read-only. `SYS_ADMIN` stands in for `CAP_BPF` +
`CAP_PERFMON` + `CAP_CHECKPOINT_RESTORE` (BPF load and perf-event attach
where the narrow grant is absent, plus `map_files` for caller attribution).
Dropping `--pid=host` or `SYS_PTRACE` refuses, as
`scripts/matrix/verify-container-image.sh` proves:

```sh
docker run --rm --pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE \
  --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  ghcr.io/mingulov/p11scope:latest doctor
```

(On AppArmor hosts add `--security-opt apparmor=unconfined`; on
SELinux-enforcing hosts `--security-opt label=disable`. The example tag is
published with the 0.7.0 release; before that, substitute a locally built
image tag from the recipe below.)

Least privilege (measured 2026-11-11; no `--privileged`, no
`CAP_SYS_ADMIN`): the narrow five-capability set (`BPF`, `PERFMON`,
`CHECKPOINT_RESTORE`, `SYS_PTRACE`, `DAC_READ_SEARCH`) with `--cap-drop
ALL` under the Docker default seccomp profile captures exactly like the
shipped set. `doctor` exits 0 with `capture available`, and `profile
--pid`, `--cgroup` and `--system` count a ledgered SoftHSM workload
exactly. Docker 24 and later already allow `bpf()` with `CAP_BPF` and
`perf_event_open()` with `CAP_PERFMON` under the default profile, so no
`--security-opt seccomp` flag is needed there.

```sh
docker run --rm --pid=host --cap-drop ALL --cap-add BPF --cap-add PERFMON \
  --cap-add CHECKPOINT_RESTORE --cap-add SYS_PTRACE \
  --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  ghcr.io/mingulov/p11scope:latest doctor
```

(Same AppArmor and SELinux notes as above. It still needs host PID and
named capabilities, so rootless Docker, Podman and Docker Desktop's VM
boundary stay unsupported, as in [the demo](../docs/demo.md).)
Receipt, Docker 29.8.1 on Ubuntu 26.04: `docker inspect` reads
`Privileged=false`, `CapDrop=[ALL]`,
`CapAdd=[BPF CHECKPOINT_RESTORE DAC_READ_SEARCH PERFMON SYS_PTRACE]`,
`PidMode=host`; `/proc/self/status` reads `CapEff:
000001c000080004` (the five, no `SYS_ADMIN`) and `Seccomp: 2` (the
default filter active). `scripts/matrix/verify-container-image.sh`
covers the recipe as `five-cap-exact`.

Where the engine default cannot be used — Docker 20.10 and older
(whose default allows `bpf()` only with `CAP_SYS_ADMIN`), a daemon
with a custom default, or a Kubernetes `Localhost` seccomp profile —
use [`seccomp-p11scope.json`](seccomp-p11scope.json) via
`--security-opt seccomp=deploy/seccomp-p11scope.json` (Docker) or
installed at `/var/lib/kubelet/seccomp/p11scope.json` with
`localhostProfile: p11scope.json` (Kubernetes; measured exact on
kind). It is the Docker default profile vendored from moby/moby
v28.3.3 (Apache-2.0; upstream `sha256:01536f1d…`, the last release
carrying `profiles/seccomp/default.json`) plus exactly one appended
allow rule for `bpf()`; the vendored 31 groups are byte-identical to
upstream. `perf_event_open()` stays at the default (conditional),
proven unneeded on the default uprobe-multi lane. The same five-cap
matrix is exact with this file on Docker 29.7/29.8/29.9.

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
