<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Demo: watch Chrome check certificates

Goal: point p11scope at your already-running Chrome (or Chromium),
browse normally, and see the real certificate lookups behind a page
load and the certificates page. No token, no setup: Chrome always
carries its own PKCS#11 modules, so there is always something to
watch. (Chrome encrypts page traffic outside PKCS#11, so what you see
here is certificate checking, not the page encryption itself.)

## What you need

- Chrome or Chromium already running (yours, with your profile).
- Docker, as on the [demos front page](README.md). The `docker run`
  flags below are the same ones explained there.

## Steps

1. Find the browser's main process id (the oldest `chrome` process;
   for Chromium use `chromium` instead of `chrome`):

   ```sh
   CRPID=$(pgrep chrome | sort -n | head -1)
   ps -p "$CRPID" -o pid,args
   ```

   If `pgrep` prints nothing, start the browser first.

2. In a terminal, start watching that process for 70 seconds:

   ```sh
   docker run --rm --pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro --security-opt apparmor=unconfined ghcr.io/mingulov/p11scope:0.7.0 profile --pid "$CRPID" --duration 70s
   ```

   Wait until it says `capturing:` (a busy machine can take a minute).
   Only what happens after that line is counted.

3. While it runs, open a site you have not visited today, then open
   the certificates page: Settings, Privacy and security, Security,
   Manage certificates. Both read the certificate store.

4. Wait for the command to finish (it stops by itself), and read the
   report.

## What you will see

Real output, trimmed: Chrome opening a fresh site and the certificates
page in the window (your sites and counts will differ; the shape is
the same). `[...]` marks trimmed lines.

```
p11scope - PID scope - up 00:01:10 - mode profile - /usr/lib/x86_64-linux-gnu/libnssckbi.so (+1 more)
caller: /opt/google/chrome/chrome
78094 completed calls; 5695 returned errors; 0 entries without an observed return.
coverage: partial - calls may be missing (1 provider file not watched, 1 discovery step unavailable, 3 provider tables incompletely read, function list not fully identified); names unconfirmed (function names follow the standard PKCS#11 table but their layout was not verified from scan (add --manifest to confirm positions for mechanism decoding))
[...]
C_FindObjectsInit            libsoftokn3.so       9062      0    16.4us    65.5us   131.1us         0
C_FindObjects                libsoftokn3.so       9062      0     4.1us     8.2us    32.8us         0
C_FindObjectsFinal           libsoftokn3.so       9062      0     2.0us     8.2us    16.4us         0
function #24 (unnamed)       libnssckbi.so       28335   5695     4.1us     8.2us    32.8us         0
[...]
ERROR REASONS:
function #24 (unnamed): CKR_ATTRIBUTE_TYPE_INVALID x5695
MECHANISM                       CALLS    ERR
CKM_SHA_1                        3803      0
```

In plain words: Chrome looked certificates up about nine thousand
times (`C_FindObjects`) while checking the site against its built-in
list (`libnssckbi`, whose functions stay `unnamed` because that module
does not publish their names — the counts are still exact). The 5,695
"returned errors" are the browser asking the built-in list questions
it answers "no" to (`CKR_ATTRIBUTE_TYPE_INVALID`); that is normal
trust-list probing, not a failure. `CKM_SHA_1` counts certificate
fingerprint checks.

If a site asks for a client certificate, logging in with it shows
signing rows (`C_Sign`) the same way.

## If you see something else

- `No completed calls observed`: nothing touched the certificate
  store in the window. Open a brand-new site and the certificates
  page (step 3) while it says `capturing:` and try again.
- Almost nothing scanned, 0 providers: you dropped the
  `--security-opt apparmor=unconfined` flag on an AppArmor machine
  (Ubuntu), or you run Docker Desktop (it watches its virtual
  machine, not your PC).
- `doctor` refuses about BTF or the kernel: this PC cannot do live
  capture (needs `/sys/kernel/btf/vmlinux` and kernel 6.6+).
  See [Troubleshooting](../troubleshooting.md).

## What is not shown

p11scope never sees site names, page contents, passwords or keys —
only which certificate functions ran, how often and how long they
took. Calls from before the `capturing:` line are not counted.

Prefer a system package? Install v0.7.0 as on the [front
page](README.md), then run `sudo p11scope profile --pid "$CRPID"
--duration 70s` instead of the `docker run` line.
