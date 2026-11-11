<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Demo: which program called my token?

One command makes a throwaway SoftHSM token, runs three callers
against it, and shows p11scope naming each program. Counts, PIDs and
gap totals vary by run; the names do not.

## Run it

On Fedora or Ubuntu with SoftHSM, OpenSC, OpenSSL plus
pkcs11-provider, python3, and passwordless sudo for the captures:

```sh
scripts/demo.sh --observer /path/to/p11scope
```

The script probes the SoftHSM and provider paths on Debian and Fedora
layouts, inits a token with one RSA key, then starts `pkcs11-tool
--sign`, a python3 signing script, and `openssl pkeyutl -sign`
through pkcs11-provider.

## What you will see

`sudo p11scope inventory --system` (trimmed real output, Fedora 44):

```
inventory system (16 passes, 221 callers, 2 provider files, 4 edges)
coverage: partial — 43 gaps
unidentified executables: openssl (15129 calls, host pids 2912721, 2912724, 2912726, 2912728, 2912730 (+305 more)); pkcs11-tool (6655 calls, host pids 2912722, 2912723, 2912725, 2912727, 2912729 (+347 more))
libsofthsm2.so: mapped by 2 applications (python3.14); 110 entries observed
run with -v for details
```

The python script shows as its launcher, `python3.14`: p11scope names
the executable, never the script path or arguments. The one-shot sign
tools exit too fast to be scanned alive, so their calls group under
"unidentified executables" with per-executable call counts. Counts are
exact when the capture saw every call, as under `p11scope run --pause auto`;
under partial coverage the same figures are lower bounds, and the product
prints them as "at least". Other providers on the machine get their own
lines; anything else using SoftHSM at the same time appears beside python3.14.

`sudo p11scope profile --pid <python-pid>` (trimmed):

```
p11scope — PID scope — up 00:00:15 — mode profile — /usr/lib64/pkcs11/libsofthsm2.so
caller: /usr/bin/python3.14
295 completed calls; 0 returned errors; 0 entries without an observed return.
coverage: partial — counts complete; function names follow the standard PKCS#11 table and were not confirmed by a manifest (add --manifest to confirm)
FUNCTION                     PROVIDER            CALLS    ERR      p50~      p95~      p99~ IN-FLIGHT
C_Sign                       libsofthsm2.so        148      0   524.3µs     1.0ms     1.0ms         0
C_SignInit                   libsofthsm2.so        147      0   262.1µs   524.3µs   524.3µs         0
run with -v for details
```

Counts are exact for the window; names follow the standard table
until confirmed with `--manifest`.

## Browsers

Firefox and Chromium answer the same question through a PKCS#11 module
registered in a fresh browser profile: make a throwaway SoftHSM token,
point a fresh profile at it with a `pkcs11.txt` in the format `modutil
--add` would produce, launch the browser, and capture the whole machine
while it runs. Nothing is installed system-wide; the product's browser
cells register the module the same way.

On Fedora with SoftHSM and the Playwright browsers:

```sh
demo_dir=$(mktemp -d /var/tmp/softhsm-browser.XXXXXX)
export SOFTHSM2_CONF="$demo_dir/softhsm2.conf"
mkdir -p "$demo_dir/tokens" "$demo_dir/ffprofile" "$demo_dir/crhome/.pki/nssdb" "$demo_dir/ffhome"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$demo_dir" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --slot 0 --label demo --so-pin 1234 --pin 1234
MODULE=/usr/lib64/pkcs11/libsofthsm2.so
printf 'library=%s\nname=SoftHSM\nparameters=\nNSS=trustOrder=75 cipherOrder=100 slotParams={0x1=[slotFlags=RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,PBE,ASKPW,EMPTY]}\n' "$MODULE" > "$demo_dir/ffprofile/pkcs11.txt"
cp "$demo_dir/ffprofile/pkcs11.txt" "$demo_dir/crhome/.pki/nssdb/pkcs11.txt"
FFBIN=$(ls -d ~/p11scope-live/browser/ms-playwright/firefox-*/firefox/firefox | sort | tail -1)
CRBIN=$(ls -d ~/p11scope-live/browser/ms-playwright/chromium-[0-9]*/chrome-linux64/chrome | sort | tail -1)
HOME="$demo_dir/ffhome" "$FFBIN" --headless --no-remote --profile "$demo_dir/ffprofile" about:blank &
HOME="$demo_dir/crhome" "$CRBIN" --headless=new --no-sandbox --disable-gpu --user-data-dir="$demo_dir/crprofile" about:blank &
```

Then, while both browsers run:

```sh
sudo p11scope inventory --system --duration 15s
```

`inventory --system --duration 15s` (trimmed real output, Fedora 44,
Firefox 157, Chromium 156):

```
inventory system (5 passes, 255 callers, 7 provider files, 21 edges)
coverage: partial — 553 gaps
libsofthsm2.so: mapped by 2 applications (chrome (from bash), firefox (from bash)); no use in the covered interval; 2 of 2 mappings predate the watch, earlier calls are not counted
libsoftokn3.so: mapped by 1 application (firefox (from bash)); 19 entries observed
run with -v for details
```

Each name carries its named parent in parentheses (`firefox (from
bash)` was started from a shell). Other providers on the machine get
their own lines, as in the first demo.

To see the browsers' calls instead of their mappings, start the
observer first and launch the browsers inside its window:

```sh
sudo p11scope profile --system --duration 45 -o browser-profile.json
```

`profile --system --duration 45` (trimmed; the browsers launched about
eight seconds in):

```
p11scope — system scope — up 00:00:47 — mode profile — /usr/lib64/opensc-pkcs11.so (+3 more)
Aggregate across the selected scope; counts are not per application.
79 completed calls; 0 returned errors; 0 entries without an observed return.
FUNCTION                     PROVIDER            CALLS    ERR      p50~      p95~      p99~ IN-FLIGHT
C_FindObjects                libsofthsm2.so         26      0     8.2µs    16.4µs    16.4µs         0
C_FindObjectsFinal           libsofthsm2.so         26      0     8.2µs    16.4µs    32.8µs         0
C_FindObjectsInit            libsofthsm2.so         26      0    65.5µs   131.1µs   262.1µs         0
C_GetSessionInfo             libsofthsm2.so          1      0    16.4µs    16.4µs    16.4µs         0
run with -v for details
```

The 79 calls are the browsers' NSS startup enumeration on SoftHSM; the
system scope aggregates, so counts are not per application. Per-key
rows cover operations that start after the attach: against an
already-running browser, earlier operations are counted in named gaps
([limits](known-limitations.md#known-limitations-in-060)).

## With the container image

The same demo commands run through `ghcr.io/mingulov/p11scope:latest`
(the tags appear when the release is published; `:0.7.0` pins the exact
0.7.0 version), with the documented container flags and no extra mounts:

```sh
FLAGS="--pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro"
IMG=ghcr.io/mingulov/p11scope:latest
docker run --rm $FLAGS $IMG doctor
docker run --rm $FLAGS $IMG inventory --system --duration 15s
docker run --rm $FLAGS $IMG profile --system --duration 30s
```

(Where AppArmor is enforcing, load `deploy/apparmor-p11scope` once
with `apparmor_parser -r` and add
`--security-opt apparmor=p11scope-observer`.)

Least privilege (measured 2026-11-11; no `--privileged`, no
`CAP_SYS_ADMIN`) captures the same demo exactly with the narrow
five-capability set under the Docker default seccomp profile — no
`--security-opt seccomp` flag is needed on Docker 24 and later (where
the engine default cannot be used, pass
`--security-opt seccomp=deploy/seccomp-p11scope.json` from the
checkout):

```sh
FLAGS="--pid=host --cap-drop ALL --cap-add BPF --cap-add PERFMON --cap-add CHECKPOINT_RESTORE --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro"
```

### What the container needs

The image carries no privileges of its own; Docker grants them at
`docker run` time through the flags above. Without them captures fail
or see nothing: no `--pid=host` finds no modules and exits 0 (looks
like success); no BPF-capable grant (`SYS_ADMIN` in the shipped set,
`BPF` + `PERFMON` in the least-privilege set) fails BPF loading
(`map create EPERM`, exit 1); no `SYS_PTRACE` cannot read process
memory (`/proc/<pid>/mem` EACCES, 0 modules); no `DAC_READ_SEARCH`
leaves providers in private directories invisible. The read-only
cgroup mount names pod cgroups from the node view. Details:
[Container privileges](../deploy/k8s/README.md#privileges-and-why).

A user in the `docker` group needs no sudo: on this dev host (Ubuntu
26.04.1, rootful Docker, AppArmor enforcing) `doctor` exited 0 and
`inventory --system` scanned 175 callers with the flags above plus the
AppArmor opt. Without the opt, `doctor` fails its `process access`
check (naming the confining label and the fix) and `inventory` still
exits 0 but sees almost nothing (2 callers, 0 providers), with a
one-line stderr hint and a `process access` gap — so where AppArmor is
enforcing, the opt is what makes captures see processes.
The least-privilege set behaves the same (measured 2026-11-11: 188
callers with the opt, 2 without). The opt used to be
`apparmor=unconfined`; the shipped [`apparmor-p11scope`](../deploy/apparmor-p11scope)
profile (the Docker default plus one `ptrace (read, trace)` rule)
keeps the confinement and measures the same (142 callers, 5
providers, ledgered `profile --pid` multiset-exact).
Snap-confined apps (e.g. snap Firefox) stay unreadable from a
container even with the shipped profile (their per-process
`unreadable` gaps name them); run natively for those.

Rootless Docker or Podman cannot work: BPF loading and uprobes need real
host capabilities, which a rootless container cannot grant. Use rootful
Docker — as a `docker`-group user, or with sudo. The host needs Linux
6.6+ with BTF (`uprobe_multi`); under Docker Desktop `--pid=host` sees
the Desktop VM, not your laptop.

`doctor` (trimmed real output, Ubuntu 26.04):

```
Doctor: requested-lane checks passed.
verdict: capture available; run startup capture not in this build (run reports stay partial; run itself works)
target loader build ............... warn  unbound
debug-state hook .................. warn  unavailable
loader-state live read ............ warn  unavailable
Next: p11scope profile --pid <PID> (or doctor --pid <PID> to check a target).
run with -v for details
```

`inventory --system --duration 15s` (trimmed; the desktop Firefox maps
its NSS softokn):

```
inventory system (2 passes, 168 callers, 6 provider files, 33 edges)
coverage: partial — 401 gaps
libsoftokn3.so: mapped by 5 applications (firefox (from firefox), firefox (from xfce4-panel)); no use in the covered interval; 5 of 5 mappings predate the watch, earlier calls are not counted
run with -v for details
```

`profile --system --duration 30s` (trimmed; three calls on the desktop
Firefox's NSS softokn in the window):

```
p11scope — system scope — up 00:01:10 — mode profile — /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so (+1 more)
Aggregate across the selected scope; counts are not per application.
3 completed calls; 0 returned errors; 0 entries without an observed return.
FUNCTION                     PROVIDER            CALLS    ERR      p50~      p95~      p99~ IN-FLIGHT
C_DecryptMessage             libsoftokn3.so          1      0    32.8µs    32.8µs    32.8µs         0
C_EncryptMessage             libsoftokn3.so          1      0     8.2µs     8.2µs     8.2µs         0
C_GenerateRandom             libsoftokn3.so          1      0     4.1µs     4.1µs     4.1µs         0
run with -v for details
```

## Learn more

- [Operator's guide](usage.md): captures, coverage and honest claims.
- [Troubleshooting](troubleshooting.md): refusals and empty captures.
- [Privacy allowlists](privacy/allowlist-v1.md) ([v2](privacy/allowlist-v2.md)): captured fields.
- [Install](install.md#install): packages and building from source.
- [Known limitations](known-limitations.md): attach timing and scope edges.
- [Container privileges](../deploy/k8s/README.md): what each grant is for.
