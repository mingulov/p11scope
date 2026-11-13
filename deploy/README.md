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
- [`apparmor-p11scope`](apparmor-p11scope) — the Docker default AppArmor
  profile plus one `ptrace (read, trace) peer=unconfined` rule, for
  AppArmor-enforcing hosts (below). Load once per host with
  `apparmor_parser -r deploy/apparmor-p11scope`, then pass
  `--security-opt apparmor=p11scope-observer`.

The observer image is published on releases as
`ghcr.io/mingulov/p11scope:<version>` (see `RELEASING.md`); the holder image
stays test-only. The primary recipe keeps `--pid=host` plus the narrow
five-capability set (`BPF`, `PERFMON`, `CHECKPOINT_RESTORE`,
`SYS_PTRACE`, `DAC_READ_SEARCH`) with `--cap-drop ALL`, and the node
cgroup hierarchy mounted read-only. Dropping `--pid=host`
or `SYS_PTRACE` refuses, as `scripts/matrix/verify-container-image.sh`
proves.

Primary recipe (measured 2026-11-11; no `--privileged`, no
`CAP_SYS_ADMIN`): the five-capability set under the Docker default
seccomp profile. `doctor` exits 0 with `capture available`, and
`profile --pid`, `--cgroup` and `--system` count a ledgered SoftHSM
workload exactly. Docker 24 and later already allow `bpf()` with
`CAP_BPF` and `perf_event_open()` with `CAP_PERFMON` under the default
profile, so no `--security-opt seccomp` flag is needed there.

```sh
docker run --rm --pid=host --cap-drop ALL --cap-add BPF --cap-add PERFMON \
  --cap-add CHECKPOINT_RESTORE --cap-add SYS_PTRACE \
  --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  ghcr.io/mingulov/p11scope:latest doctor
```

(On AppArmor hosts load [`apparmor-p11scope`](apparmor-p11scope) and
add `--security-opt apparmor=p11scope-observer` (`apparmor=unconfined`
also works but drops the confinement); on SELinux-enforcing hosts no
extra flag is needed (measured 2026-11-11, below). The example tag is
published with the 0.7.0 release.)
It still needs host PID and named capabilities, so rootless Docker,
Podman and Docker Desktop's VM boundary stay unsupported, as in [the
demos](../docs/demo/README.md).
Receipt, Docker 29.8.1 on Ubuntu 26.04: `docker inspect` reads
`Privileged=false`, `CapDrop=[ALL]`,
`CapAdd=[BPF CHECKPOINT_RESTORE DAC_READ_SEARCH PERFMON SYS_PTRACE]`,
`PidMode=host`; `/proc/self/status` reads `CapEff:
000001c000080004` (the five, no `SYS_ADMIN`) and `Seccomp: 2` (the
default filter active). `scripts/matrix/verify-container-image.sh`
covers the recipe as `five-cap-exact`.

Alternative: the `SYS_ADMIN` set. Replacing the five `--cap-*` flags
above with `--cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add
DAC_READ_SEARCH` also captures:

```sh
docker run --rm --pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE \
  --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  ghcr.io/mingulov/p11scope:latest doctor
```

`CAP_SYS_ADMIN` grants very broad power — close to full root (mounts,
namespaces, many kernel admin operations) — so use it only when
needed. What it adds for p11scope is file learning (fanotify): it
catches a short-lived process's first load of a new provider file,
naming the loader and the file (the first use itself stays a
[missed window](../docs/known-limitations.md#one-shot-tools-under---system-first-use-missed-later-runs-caught));
without it that case is a named gap in the report. On Docker older
than 24, whose default seccomp allows `bpf()` only with
`CAP_SYS_ADMIN`, it is also the way to run without the vendored
seccomp file below.

Where the engine default cannot be used — Docker older than 24
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
proven unneeded on the default uprobe-multi lane. With this file the
five-cap matrix measured 8/8 on the reference host (Docker 29.9.2,
quiet host) and 6/8 on Fedora (Docker 29.7.2): the two `--system`
legs there miss
only at full-multiset level amid another lane's container workload
(host-module rows exact), so `--system` full-multiset exactness
needs a quiet host.

Saving a report: `-o` writes inside the container, and `--rm`
discards it with the container, so mount a folder for the report.
Today the output directory must be root-owned: a user-owned mount is
refused (`output directory ancestor /out is untrusted: owned by uid
1000`). Make a root-owned directory once, then mount it:

```sh
sudo install -d -m 0755 -o root -g root ~/p11out
docker run --rm --pid=host --cap-drop ALL --cap-add BPF --cap-add PERFMON \
  --cap-add CHECKPOINT_RESTORE --cap-add SYS_PTRACE \
  --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v ~/p11out:/out ghcr.io/mingulov/p11scope:latest inventory --system \
  -o /out/report.json
```

The file lands root-owned (`0600`; read it with `sudo`). Measured on
Docker 29.8.1 with the five-cap set: `inventory --system -o` into a
root-owned mount exits 0 with the file written. Easier output
ownership is planned for 0.8.0.

Mandatory access control and kernel knobs (measured 2026-11-11):

- SELinux (Fedora, Enforcing, Docker 29.7/29.9): both capability sets
  capture with the engine's default labeling — no
  `--security-opt label` flag, no policy module. Full-multiset
  exactness was shown 8/8 on the reference host plus the Fedora
  five-cap twin; Fedora system-shipped was 7/8 with one noise-only
  surplus leg.
  `--pid=host`
  containers run as `system_u:system_r:spc_t:s0` (bisected: plain and
  five-cap-only containers get `container_t` with MCS categories;
  adding `--pid=host` switches to `spc_t`), under which BPF,
  perf-event, ptrace-mode and `/proc` reads are allowed; the audit
  log held zero AVC denials across every run. Rootful Podman 5.8
  behaves the same (`doctor` exits 0, `capture available`, `spc_t`,
  no AVCs). Confined *target* workloads keep working: the observer
  reads a `container_t` victim's maps and counts it exactly (bind
  mounts into a confined victim need the usual `:z` suffix).
- AppArmor (Ubuntu 26.04, enforcing, Docker 29.8.1): the stock
  `docker-default` profile blinds the host observer — it lacks
  `ptrace read` to `unconfined` peers, so `/proc` scans see almost
  nothing (`inventory --system` exits 0 with 2 callers and 0
  providers while `doctor` still passes). [`apparmor-p11scope`]
  (apparmor-p11scope) is that default plus exactly one rule,
  `ptrace (read, trace) peer=unconfined` (maps snapshots need
  read; `/proc/<pid>/mem` scans and profile attach need trace),
  and restores the five-cap matrix: `doctor` `capture available`,
  ledgered `profile --pid` multiset-exact, `inventory --system`
  back to host visibility (142 callers, 5 providers vs 2/0 under
  `docker-default`). Confined peers (snap, cups, chronyd) stay
  unreadable by design and degrade with named gaps.
- Kernel knobs: `doctor` already reports `lockdown`,
  `kernel.perf_event_paranoid`, `kernel.yama.ptrace_scope` and
  `cgroup version` rows. The default uprobe-multi lane attaches
  through links that `perf_event_paranoid` does not gate (measured
  exact at paranoid 2 on Fedora and 4 on Ubuntu); only the
  `--attach-backend singles` fallback opens per-probe perf events.
  `kernel.unprivileged_bpf_disabled` is not reported because the
  observer always loads BPF with a BPF-capable capability held, so
  the unprivileged gate never applies. cgroup v1 is not supported
  (`doctor` fails the `cgroup version` row without a unified
  hierarchy); all measured hosts run cgroup v2.

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
