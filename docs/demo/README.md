<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Demos: watch your crypto being used

p11scope watches the PKCS#11 modules (smart-card drivers, software
tokens, browser certificate stores) that your running programs already
use, and reports which program called which cryptographic function,
how often, with what result — without changing any program's settings
and without ever seeing your PINs, keys or data.

Pick one demo (each takes a few minutes):

- [SoftHSM2](softhsm2.md) — a throwaway software token on your machine.
  Start here: it is the simplest and most reliable.
- [Firefox](firefox.md) — watch your already-running Firefox do real
  cryptography while you browse.
- [Chrome or Chromium](chrome.md) — watch your already-running browser
  check certificates while you browse.

## What you need (once)

- Linux on a regular PC (x86-64), kernel 6.6 or newer, with
  `/sys/kernel/btf/vmlinux` present (most current distributions ship
  it; `sudo p11scope doctor` tells you if anything is missing).
- Docker, the normal system-wide install, with your user in the
  `docker` group (so `docker run` works without sudo). Rootless
  Docker and Docker Desktop cannot work: watching the whole
  machine needs real host capabilities, and Docker Desktop's
  `--pid=host` sees the Desktop virtual machine, not your PC.
- A few minutes per demo. The commands below use the published
  release image `ghcr.io/mingulov/p11scope:latest`. To pin this
  exact release, use `ghcr.io/mingulov/p11scope:0.7.0` instead of
  `:latest`.

## The shortest working command

This checks your machine can capture (expect about 10 seconds with no
output; that is normal):

```sh
docker run --rm --pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro --security-opt apparmor=unconfined ghcr.io/mingulov/p11scope:latest doctor
```

Every demo uses the same flags: `--pid=host` lets the container see
your machine's processes, the three `--cap-add` grants let it watch
them, and the read-only cgroup mount names container workloads. On
Ubuntu and other AppArmor systems the `--security-opt
apparmor=unconfined` flag is what lets the container read other
processes at all — without it a capture sees almost nothing (2
processes scanned, 0 providers found). On machines without AppArmor,
leave that flag out. If you prefer to keep confinement, load the
shipped profile once with `sudo apparmor_parser -r
deploy/apparmor-p11scope` from the p11scope source tree and use
`--security-opt apparmor=p11scope-observer` instead of `unconfined`.
To confirm AppArmor is the cause: `sudo dmesg |
grep 'apparmor="DENIED"' | grep docker-default`.

Prefer a system package over Docker? Install v0.7.0 and use `sudo
p11scope` in place of the `docker run ...` lines (each demo shows the
swap). On Debian/Ubuntu:

```sh
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.7.0/p11scope_0.7.0_amd64.deb
curl -fLO https://github.com/mingulov/p11scope/releases/download/v0.7.0/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
sudo apt install ./p11scope_0.7.0_amd64.deb
```

On Fedora/RHEL, download `p11scope-0.7.0-1.x86_64.rpm` instead and
install it with `sudo dnf install ./p11scope-0.7.0-1.x86_64.rpm`.

## Learn more

- [Operator's guide](../usage.md): captures, coverage and honest claims.
- [Troubleshooting](../troubleshooting.md): refusals and empty captures.
- [Privacy allowlists](../privacy/allowlist-v1.md)
  ([v2](../privacy/allowlist-v2.md)): captured fields.
- [Install](../install.md#install): packages and building from source.
- [Known limitations](../known-limitations.md): attach timing and scope edges.
