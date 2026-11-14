# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# shellcheck shell=bash disable=SC2034  # sourced interface: fetch-provider.sh reads these names
# Pinned third-party provider artifacts for the provider matrix
# (scripts/ci/fetch-provider.sh, scripts/provider-matrix/run-matrix.sh).
# URL + sha256 per artifact; the fetch script refuses on mismatch.
# Layout after unpack, relative to the fetch DESTDIR:
#   haskoki:    haskoki-0.5.0.0/{lib/libhaskoki.so,bin/haskoki-ctl,...}
#   kryoptic:   kryoptic-rpm/usr/lib64/pkcs11/libkryoptic_pkcs11.so
#   softhsm26:  softhsm-2.6.1/root/{usr/lib64/pkcs11/libsofthsm2.so,usr/bin/softhsm2-util}
HASKOKI_VERSION=0.5.0.0
HASKOKI_URL=https://github.com/mingulov/haskoki/releases/download/v0.5.0.0/haskoki-0.5.0.0-linux-x86_64.tar.gz
HASKOKI_SHA256=8102e05868c3d26855d0a351cf4f0729ba21c7316653514d32ff82eeacb0c046
KRYOPTIC_VERSION=1.5.2
KRYOPTIC_URL=https://kojipkgs.fedoraproject.org/packages/kryoptic/1.5.2/4.fc44/x86_64/kryoptic-1.5.2-4.fc44.x86_64.rpm
KRYOPTIC_SHA256=0424d224fe38908eeb1ffe1020d2f82f7eae94a97f78dbd78745ddf902dd78a6
SOFTHSM26_VERSION=2.6.1
SOFTHSM26_URL=https://kojipkgs.fedoraproject.org/packages/softhsm/2.6.1/11.fc42/x86_64/softhsm-2.6.1-11.fc42.x86_64.rpm
SOFTHSM26_SHA256=cc312bbac25e4a85541f29fdc70eabd270a43fb3fe23dd1816eabdbb571c80ab
