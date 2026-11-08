<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# p11scope

Find which running Linux applications use PKCS#11 providers, then inspect their
observed calls, errors, latency and bounded metadata — **without replacing the
provider or changing each application's configuration**.

`p11scope` answers "which program uses my PKCS#11 token/provider, with which
mechanisms, how fast, what errors": eBPF uprobes observe the providers already
mapped by running processes, so there is no shim to install and no restart.

> **Status: v0.6.0** answers "which application used which key, and how", with opt-in
> live key operations (`inventory --key-operations`). Read the [known
> limitations](CHANGELOG.md#known-limitations) before relying on a capture;
> [CHANGELOG.md](CHANGELOG.md#qualification-of-this-release) records what this release was qualified on.

## Install

Get the bundles from the [Releases page](https://github.com/mingulov/p11scope/releases)
(observer tarball, optional discovery helpers, DEB/RPM packages, source export).
For example, install **v0.6.0** after verifying its checksum:

```sh
download_dir=$(mktemp -d /var/tmp/p11scope-install.XXXXXX)
cd "$download_dir"
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.6.0/p11scope-0.6.0-x86_64-linux-musl.tar.gz
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.6.0/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf p11scope-0.6.0-x86_64-linux-musl.tar.gz
sudo install -m 0755 p11scope-0.6.0-x86_64-linux-musl/p11scope /usr/local/bin/p11scope
p11scope --version
sudo p11scope doctor
```

System packages, the discovery helper and local builds are in [Install](docs/install.md#install).
Container: the 0.7.0 release publishes `ghcr.io/mingulov/p11scope:0.7.0`; run `doctor` through it ([privileges](deploy/k8s/README.md)):

```sh
docker run --rm --pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro ghcr.io/mingulov/p11scope:0.7.0 doctor
```

## First commands

```sh
sudo p11scope doctor
sudo p11scope inventory --system --duration 15s
sudo p11scope profile --pid 12345 --duration 30s -o diagnostic-profile.json
```

`doctor` reports host readiness (real output, v0.6.0 on Ubuntu 26.04):

```
Doctor: requested-lane checks passed.
verdict: capture available; run initial-set capture not in this build (run reports stay PARTIAL; run itself works)
target loader build ............... warn  unbound
debug-state hook .................. warn  unavailable
loader-state live read ............ warn  unavailable
Next: sudo p11scope profile --pid <PID> (or doctor --pid <PID> to check a target).
run with -v for details
```

`12345` is a placeholder PID. If a command refuses instead of capturing, see [troubleshooting](docs/troubleshooting.md).
Text is concise by default; `-v` shows full detail and `--json` is always complete.

## Requirements

- Linux x86-64 with BTF (`/sys/kernel/btf/vmlinux`).
- Kernel 6.6+ (or a working backport) for full live-capture support.
- Root, or the [documented capabilities](docs/usage.md#privileges-per-environment) (`CAP_BPF`+`CAP_PERFMON` at `perf_event_paranoid` below 3, else `CAP_SYS_ADMIN`).

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
