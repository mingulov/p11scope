<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# p11scope

Find which running Linux applications use PKCS#11 providers, then inspect their
observed calls, errors, latency and bounded metadata — **without replacing the
provider or changing each application's configuration**.

`p11scope` answers "which program uses my PKCS#11 token/provider, with which
mechanisms, how fast, what errors": eBPF uprobes observe the providers already
mapped by running processes, so there is no shim to install and no restart.

> **Status: v0.7.0** answers "which application used which key, and how", with opt-in
> live key operations (`inventory --key-operations`), streaming inventory events
> (`--event-log -` with `--event-interval`), and a published observer image
> (`ghcr.io/mingulov/p11scope:latest`). Read the [known
> limitations](CHANGELOG.md#known-limitations) before relying on a capture;
> [CHANGELOG.md](CHANGELOG.md#qualification-of-this-release) records what this release was qualified on.

## Install

Get the bundles from the [Releases page](https://github.com/mingulov/p11scope/releases)
(observer tarball, optional discovery helpers, DEB/RPM packages, source export).
The 0.7.0 files are listed under the v0.7.0 release.
For example, install **v0.7.0** after verifying its checksum:

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

(`doctor` loads its BPF preflight on every run, so expect about 10 s
with no interim output; that is normal.)

System packages, the discovery helper and local builds are in [Install](docs/install.md#install).
Container: the release publishes `ghcr.io/mingulov/p11scope:latest`
(`:0.7.0` pins the exact version).
Run `doctor` through it ([privileges](deploy/k8s/README.md)):

```sh
docker run --rm --pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro ghcr.io/mingulov/p11scope:latest doctor
```

On Ubuntu and other AppArmor hosts, add `--security-opt
apparmor=unconfined`: Docker confines every container with
`docker-default`, which blocks reading other processes, so without the
flag the run sees almost nothing. The [demo
pages](docs/demo/README.md) have the full copy-paste
commands, the hardened profile alternative, and the measured numbers.

## First commands

```sh
# Check this machine can capture.
sudo p11scope doctor
# List which programs use PKCS#11 providers right now.
sudo p11scope inventory --system --duration 15s
# Watch one program in detail (use a PID from the inventory above, or `pidof <name>`).
sudo p11scope profile --pid <PID> --duration 30s
```

New here? Work through the [Quickstart](docs/usage.md#quickstart): it sets up a
throwaway SoftHSM token and runs your first observed workload in a few minutes.

One-shot tools (a single `pkcs11-tool` call) under `--system` are
caught from their second run inside one capture: the provider file is
learned from the kernel, listed with the program that first loaded it,
and attached so later runs are counted. The first use itself stays a
named miss — wrap such tools in `sudo p11scope run --user $USER --
<tool>` (or pass `--prearm-module PATH`) when first-run coverage
matters.

`doctor` reports host readiness (real output, v0.7.0 on Ubuntu 26.04):

```
Doctor: requested-lane checks passed.
verdict: capture available; run startup capture not in this build (run reports stay partial; run itself works)
Next: choose --pid <PID> or --cgroup <PATH> to assess a target scope.
run with -v for details
```

Rows vary by host; `run with -v for details` lists every check.

`<PID>` is the program you picked. Add `-o report.json` to also save the full machine-readable report next to the terminal summary. If a command refuses instead of capturing, see [troubleshooting](docs/troubleshooting.md).
Text is concise by default; `-v` shows full detail. Complete output: `--json` on inspect/inventory (incl. inventory diff, cbom); `-o FILE` on profile/run/inventory; trace streams text to `-o FILE` or `-o -`; inventory streams `--event-log`; doctor is text-only.

## Requirements

- Linux x86-64 with BTF (`/sys/kernel/btf/vmlinux`).
- Kernel 6.6+ (or a working backport) for full live-capture support.
- Root, or the [documented minimal capability set](docs/usage.md#run-without-sudo) (`CAP_BPF`, `CAP_CHECKPOINT_RESTORE`, `CAP_DAC_READ_SEARCH`, `CAP_PERFMON`, `CAP_SYS_PTRACE`; no `CAP_SYS_ADMIN` on the default lane).

p11scope sends no telemetry and makes no network connections.

## Documentation

- [Install](docs/install.md#install) — bundles, packages, helper, building from source.
- [Operator's guide](docs/usage.md) — running captures and reading the evidence.
- [Overview](docs/overview.md) — what it observes, honest claims, tested targets.
- [Troubleshooting](docs/troubleshooting.md) — refusals and empty captures.
- [Kubernetes](deploy/k8s/README.md) — node DaemonSet observer.
- [Why not just pkcs11-spy?](docs/overview.md#why-not-just-pkcs11-spy) — shims compared.
- [Privacy allowlists](docs/privacy/allowlist-v1.md) ([v2](docs/privacy/allowlist-v2.md)) — captured fields.
- [Profile schema v3](docs/schema/observed-profile-v3.md) — report format.
- [Known limitations](docs/known-limitations.md) — what this release does not do.
- [Changelog](CHANGELOG.md) — per-release changes and qualification.
- [Releases](https://github.com/mingulov/p11scope/releases) — downloads and notes.

## License

Copyright (C) 2026 Denis Mingulov <denis@mingulov.com>. See [COPYRIGHT](COPYRIGHT).

Public license: GPL-3.0-or-later — see [LICENSE](LICENSE).
BPF sources: GPL-2.0-only — see
[LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt).
Shared BPF/userspace definitions (`crates/ebpf-common`): GPL-2.0-or-later — see
[LICENSES/GPL-2.0-or-later.txt](LICENSES/GPL-2.0-or-later.txt). This crate is
compiled into both the BPF object the kernel loads (used there under GPL-2.0)
and the observer (used there under GPL-3.0).

Per-file SPDX tags (`GPL-3.0-or-later` for userspace, docs, and scripts;
`GPL-2.0-only` for BPF programs; `GPL-2.0-or-later` for `crates/ebpf-common`)
remove any ambiguity.

Contributions require a CLA granting broad sublicensing/relicensing rights;
see [CONTRIBUTING.md](CONTRIBUTING.md).
