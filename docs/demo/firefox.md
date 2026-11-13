<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Demo: watch Firefox do cryptography

Goal: point p11scope at your already-running Firefox, browse normally,
and see the real cryptographic calls behind two page loads: key
exchange, signatures being checked, page encryption. No token, no
setup: Firefox always carries its own PKCS#11 module
(`libsoftokn3.so`), so there is always something to watch.

## What you need

- Firefox already running (yours, with your profile).
- Docker, as on the [demos front page](README.md). The `docker run`
  flags below are the same ones explained there.

## Steps

1. Find Firefox's main process id (the oldest `firefox` process):

   ```sh
   FFPID=$(pgrep firefox | sort -n | head -1)
   ps -p "$FFPID" -o pid,args
   ```

   If `pgrep` prints nothing, start Firefox first.

2. In a terminal, start watching that process for 60 seconds:

   ```sh
   docker run --rm --pid=host --cap-drop ALL --cap-add BPF --cap-add PERFMON --cap-add CHECKPOINT_RESTORE --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro --security-opt apparmor=unconfined ghcr.io/mingulov/p11scope:latest profile --pid "$FFPID" --duration 60s
   ```

   Wait until it says `capturing:` (a busy machine can take a minute).
   Only what happens after that line is counted.

   Alternative: `--cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add
   DAC_READ_SEARCH` in place of the `--cap-drop ALL` and five
   `--cap-add` flags.
   `CAP_SYS_ADMIN` grants very broad power — close to full root
   (mounts, namespaces, many kernel admin operations) — so use it
   only when needed. What it adds for p11scope is file learning
   (fanotify): it catches a short-lived process's first load of a new
   provider file; without it that case is a named gap in the report.
   On Docker older than 24, whose default seccomp allows `bpf()` only
   with `CAP_SYS_ADMIN`, it is also the way to run without the
   [seccomp file](../../deploy/seccomp-p11scope.json).

3. While it runs, open one or two sites you have not visited today (a
   news site, for example). Fresh sites make fresh cryptography;
   already-open pages mostly sit quiet.

4. Wait for the command to finish (it stops by itself), and read the
   report.

## What you will see

Real output, trimmed: desktop Firefox loading two fresh sites in the
window (your sites and counts will differ; the shape is the same).
`[...]` marks trimmed lines.

```
p11scope - PID scope - up 00:01:00 - mode profile - /snap/firefox/9057/usr/lib/firefox/libsoftokn3.so
caller: /snap/firefox/9057/usr/lib/firefox/firefox
22886 completed calls; 0 returned errors; 0 entries without an observed return.
coverage: partial - calls may be missing (function list not fully identified); names unconfirmed (21 unregistered mechanisms); call details degraded (62 session-tracking gaps)
[...]
C_DeriveKey                  libsoftokn3.so        294      0     8.2us    32.8us    65.5us         0
C_DecapsulateKey             libsoftokn3.so          7      0   524.3us     1.0ms     1.0ms         0
C_VerifyInit                 libsoftokn3.so         16      0     8.2us     1.0ms     1.0ms         0
C_Verify                     libsoftokn3.so         10      0   262.1us     1.0ms     1.0ms         0
C_EncryptMessage             libsoftokn3.so         51      0    16.4us    32.8us    65.5us         0
[...]
MECHANISM                       CALLS    ERR
CKM_HKDF_DERIVE                   244      0
CKM_AES_GCM                       129      0
CKM_ECDH1_DERIVE                    7      0
CKM_ML_KEM                          7      0
[...]
```

In plain words: `C_DeriveKey`/`CKM_HKDF_DERIVE` is the page
connection's key schedule, `C_Verify` is Firefox checking the site's
certificate signature, `C_EncryptMessage`/`CKM_AES_GCM` is the page
traffic being encrypted, and the `C_DecapsulateKey`/`CKM_ML_KEM` rows
mean at least one site negotiated post-quantum key exchange. The
`coverage: partial` line is normal on a busy machine: it names what
the observer could not prove, while your calls above it are counted
exactly.

If your site asks for a client certificate, logging in with it shows
signing rows (`C_Sign`) the same way.

## If you see something else

- `No completed calls observed`: nothing did cryptography in the
  window. Open a brand-new site (not a reload, not an already-open
  tab) while it says `capturing:` and try again.
- Almost nothing scanned, 0 providers: you dropped the
  `--security-opt apparmor=unconfined` flag on an AppArmor machine
  (Ubuntu), or you run Docker Desktop (it watches its virtual
  machine, not your PC).
- `doctor` refuses about BTF or the kernel: this PC cannot do live
  capture (needs `/sys/kernel/btf/vmlinux` and kernel 6.6+).
  See [Troubleshooting](../troubleshooting.md).

## What is not shown

p11scope never sees site names, page contents, passwords or keys —
only which cryptographic functions ran, how often and how long they
took. Calls from before the `capturing:` line are not counted, and a
site you already had open may reuse its connection and stay quiet.

Prefer a system package? Install v0.7.0 as on the [front
page](README.md), then run `sudo p11scope profile --pid "$FFPID"
--duration 60s` instead of the `docker run` line.
