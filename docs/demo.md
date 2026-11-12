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
coverage: partial - 43 gaps
unidentified executables: openssl (15129 calls, host pids 2912721, 2912724, 2912726, 2912728, 2912730 (+305 more)); pkcs11-tool (6655 calls, host pids 2912722, 2912723, 2912725, 2912727, 2912729 (+347 more))
/usr/lib64/pkcs11/libsofthsm2.so: mapped by 2 applications (python3.14); 110 entries observed
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
p11scope - PID scope - up 00:00:15 - mode profile - /usr/lib64/pkcs11/libsofthsm2.so
caller: /usr/bin/python3.14
295 completed calls; 0 returned errors; 0 entries without an observed return.
coverage: complete
FUNCTION                     PROVIDER            CALLS    ERR      p50~      p95~      p99~ IN-FLIGHT
C_Sign                       libsofthsm2.so        148      0   524.3us     1.0ms     1.0ms         0
C_SignInit                   libsofthsm2.so        147      0   262.1us   524.3us   524.3us         0
run with -v for details
```

Counts are exact for the window; SoftHSM's standard table layout is
verified from the scan, so no manifest is needed. `--manifest` still
matters only for providers with non-standard tables.

## Browsers

Firefox and Chromium carry their own NSS PKCS#11 provider, so an
already-running browser answers the same question with no setup: point
the observer at it while it does real cryptography — TLS
client-certificate handshakes below — and read off the calls, the
mechanism counters and the per-key rows. To register an extra
throwaway SoftHSM token instead, point a fresh profile at it with a
`pkcs11.txt` in the format `modutil --add` would produce; the
product's browser cells register the module the same way. Nothing is
installed system-wide.

On Ubuntu with SoftHSM and the Playwright browsers (`playwright
install firefox chromium` puts them under
`~/.cache/ms-playwright`):

```sh
demo_dir=$(mktemp -d /var/tmp/softhsm-browser.XXXXXX)
export SOFTHSM2_CONF="$demo_dir/softhsm2.conf"
mkdir -p "$demo_dir/tokens" "$demo_dir/ffprofile" "$demo_dir/crhome/.pki/nssdb" "$demo_dir/ffhome"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$demo_dir" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --slot 0 --label demo --so-pin 1234 --pin 1234
MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
[ -f "$MODULE" ] || MODULE=/usr/lib64/pkcs11/libsofthsm2.so
printf 'library=%s\nname=SoftHSM\nparameters=\nNSS=trustOrder=75 cipherOrder=100 slotParams={0x1=[slotFlags=RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,PBE,ASKPW,EMPTY]}\n' "$MODULE" > "$demo_dir/ffprofile/pkcs11.txt"
cp "$demo_dir/ffprofile/pkcs11.txt" "$demo_dir/crhome/.pki/nssdb/pkcs11.txt"
FFBIN=$(ls -d ~/.cache/ms-playwright/firefox-*/firefox/firefox | sort | tail -1)
CRBIN=$(ls -d ~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome ~/.cache/ms-playwright/chromium-*/chrome-linux/chrome 2>/dev/null | sort | tail -1)
HOME="$demo_dir/ffhome" "$FFBIN" --headless --no-remote --profile "$demo_dir/ffprofile" about:blank &
HOME="$demo_dir/crhome" "$CRBIN" --headless=new --no-sandbox --disable-gpu --user-data-dir="$demo_dir/crprofile" about:blank &
```

Then, while the browsers run, capture the whole machine with
per-key tracking, or one browser by its PID:

```sh
sudo p11scope inventory --system --key-operations --duration 90s
sudo p11scope profile --pid <browser-pid> --duration 45s
```

The samples below were measured 2026-11-12 on the dev host lu26
(Ubuntu 26.04.1, kernel 7.0.0-38-generic), p11scope 346d2c875
release, against an already-running headless browser (fresh
profile, own NSS database seeded with a throwaway client
credential) doing real TLS client-certificate handshakes against
a loopback server: the observer attached after the browser was
already signing. Chromium is Playwright's chrome-linux64 build
(Chrome for Testing 156); Firefox is Playwright's firefox-1555
build (Firefox 157). Your desktop browser shows the same tables
when it does cryptography: https sites, Security Devices, saved
passwords.

`inventory --system --key-operations` (trimmed; the Chromium run,
4 presented handshakes in the window):

```
inventory system (14 passes, 255 callers, 16 provider files, 52 edges)
coverage: partial - 385 gaps
key operations: 6 keys on 1 provider; rev 14 populated; 6 sessions
  /usr/lib/x86_64-linux-gnu/libsoftokn3.so: sign 3 completed, 0 returned errors, 0 active operations
  unknown keys: digest 169 completed, 0 returned errors, 0 active operations
  type unknown (not established while observed) (3 key rows)
/usr/lib/x86_64-linux-gnu/libsoftokn3.so: mapped by 1 application (chrome (from node)); 2609 entries observed
/snap/firefox/9057/usr/lib/firefox/libsoftokn3.so: mapped by 5 applications (firefox (from firefox), firefox (from xfce4-panel)); no use in the covered interval; 5 of 5 mappings predate the watch, earlier calls are not counted
run with -v for details
```

The 3 signs are 3 of the 4 presented handshakes (no event loss:
the fourth carried no new PKCS#11 signature). Each name carries
its named parent in parentheses (`chrome (from node)` runs under
Playwright's driver process). The desktop snap Firefox maps its
own softokn but stayed quiet, so its earlier calls sit in the
named "mappings predate the watch" gap. Key types stay unknown
here: the browser logged in before the observer attached, so no
key size was observed — the rows say `type unknown` instead of
guessing. Other providers on the machine get their own lines, as
in the first demo.

`profile --pid <chromium-pid>` (trimmed; same run shape):

```
p11scope - PID scope - up 00:00:45 - mode profile - /usr/lib/x86_64-linux-gnu/libnssckbi.so (+1 more)
caller: /home/user/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome
8210 completed calls; 539 returned errors; 0 entries without an observed return.
coverage: partial - calls may be missing (1 provider file not watched, 1 discovery step unavailable, 3 provider tables incompletely read, function list not fully identified); names unconfirmed (function names follow the standard PKCS#11 table but their layout was not verified from scan (add --manifest to confirm positions for mechanism decoding))
FUNCTION                     PROVIDER            CALLS    ERR      p50~      p95~      p99~ IN-FLIGHT
C_FindObjectsInit            libsoftokn3.so        742      0    16.4us    65.5us   131.1us         0
C_Sign                       libsoftokn3.so          3      0     2.1ms     4.2ms     4.2ms         0
C_SignInit                   libsoftokn3.so          3      0   524.3us     1.0ms     1.0ms         0
[13 more rows]
MECHANISM                       CALLS    ERR
CKM_SHA_1                         362      0
CKM_RSA_PKCS_PSS                    6      0
CKM_SHA256                          4      0
mechanism names from the standard table (layout evidence: interface linkage)
sessions: 5 opened, peak 1 at once, 0 still open
run with -v for details
```

The 539 errors are NSS probing trust attributes the built-in
store does not carry (`CKR_ATTRIBUTE_TYPE_INVALID`); the 3 signs
are the 3 presented handshakes, counted per mechanism as
`CKM_RSA_PKCS_PSS`. Only the browser's client-certificate use
goes through PKCS#11 here, so the table is short.

`profile --pid <firefox-pid>` (trimmed; Firefox does its whole
TLS handshake in NSS, 2 presented handshakes in the window):

```
p11scope - PID scope - up 00:00:45 - mode profile - /home/user/.cache/ms-playwright/firefox-1555/firefox/libsoftokn3.so
caller: /home/user/.cache/ms-playwright/firefox-1555/firefox/firefox
1548 completed calls; 0 returned errors; 0 entries without an observed return.
coverage: partial - calls may be missing (function list not fully identified); names unconfirmed (9 unregistered mechanisms); call details degraded (28 session-tracking gaps)
FUNCTION                     PROVIDER            CALLS    ERR      p50~      p95~      p99~ IN-FLIGHT
C_DeriveKey                  libsoftokn3.so         79      0    16.4us    65.5us   262.1us         0
C_SignInit                   libsoftokn3.so         15      0     8.2us   524.3us   524.3us         0
C_SignFinal                  libsoftokn3.so         15      0     4.1us     2.1ms     2.1ms         0
C_EncryptMessage             libsoftokn3.so         10      0    16.4us    65.5us    65.5us         0
C_DecapsulateKey             libsoftokn3.so          3      0     1.0ms     1.0ms     1.0ms         0
[32 more rows]
MECHANISM                       CALLS    ERR
CKM_HKDF_DERIVE                    58      0
CKM_AES_GCM                        44      0
CKM_SHA256_RSA_PKCS_PSS            22      0
CKM_ECDH1_DERIVE                    3      0
CKM_ML_KEM                          3      0
[13 more rows]
mechanism names from the standard table (layout evidence: interface linkage)
sessions: 102 opened, peak 6 at once, 2 still open
run with -v for details
```

The mechanism table is the handshake: ECDH and ML-KEM key
exchange, HKDF key schedule, AES-GCM records, RSA-PSS
signatures. Nine vendor mechanisms outside the registry stay
count-only. Against Firefox, per-key rows are withheld in this
shape (session tracking degrades across its hundred sessions),
so inventory keeps exact aggregates instead:

```
key operations: 0 keys on 0 providers; rev 26 partial; 0 sessions
  per-key tracking lost some calls; exact rows continue
  unknown keys: sign 14 completed, 0 returned errors, 0 active operations
  unknown keys: derive 92 completed, 0 returned errors, 0 active operations
  unknown keys: decapsulate 4 completed, 0 returned errors, 0 active operations
  unknown keys: digest 49 completed, 0 returned errors, 0 active operations
  [4 more categories]
```

Per-key rows cover operations that start after the attach:
against an already-running browser, earlier operations are
counted in named gaps
([limits](known-limitations.md#known-limitations-in-060)).

## With the container image

The same demo commands run through `ghcr.io/mingulov/p11scope:latest`
(the tags appear when the release is published; `:0.7.0` pins the exact
0.7.0 version), with the documented container flags and no extra mounts.
The image carries a build-provenance attestation; verify it first with
`gh attestation verify oci://ghcr.io/mingulov/p11scope:0.7.0 -R mingulov/p11scope`.
On Ubuntu, use the copy-paste script below — it includes the one
AppArmor flag the demo needs there:

```sh
IMG=ghcr.io/mingulov/p11scope:latest
FLAGS="--pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro --security-opt apparmor=unconfined"
docker run --rm $FLAGS $IMG doctor
docker run --rm $FLAGS $IMG inventory --system --duration 15s
docker run --rm $FLAGS $IMG profile --system --duration 30s
```

(On hosts without AppArmor, drop the `--security-opt` flag. A
least-privilege FLAGS without `CAP_SYS_ADMIN` follows below.)

### On Ubuntu and other AppArmor hosts

On Ubuntu and other AppArmor hosts, Docker confines every container
with the `docker-default` profile, which blocks reading other
processes. Without a fix the run sees almost nothing: on the owner's
Ubuntu desktop the run scanned 2 of 485 processes and found 0 provider
files. Earlier builds gave no reason for the empty result; current
builds fail `doctor`'s `process access` check (naming the confining
label and the fix) and print a one-line hint plus a `process access`
gap in `inventory` and `profile`.

The simplest fix is one flag, `--security-opt apparmor=unconfined`,
as in the script above. Measured 2026-11-12 on lu26 (Ubuntu
26.04.1, local image built from p11scope 346d2c875; the published
tags appear at release): 16 provider files including snap
Firefox's libsoftokn3 (7 are transient test fixtures from other
work on the busy host), 190 callers, 20,099 functions watched.
The trade-off is one sentence: this container runs without extra
AppArmor confinement, while the granted capabilities and the
default seccomp profile still apply.

To check that AppArmor is the cause, look for the ptrace denials:

```sh
sudo dmesg | grep 'apparmor="DENIED"' | grep docker-default
```

The hardened option keeps confinement: from the checkout, load the
shipped profile once with `sudo apparmor_parser -r
deploy/apparmor-p11scope` (the load is lost on reboot unless the file
is copied to `/etc/apparmor.d/`), then use `--security-opt
apparmor=p11scope-observer` instead of `unconfined`. Measured
2026-11-12 on the same host (local image): 4 provider files, 165
callers, 6,907 functions watched. Against non-snap targets
the shipped profile captures the same demo exactly (measured: 142
callers, 5 providers, ledgered `profile --pid` multiset-exact);
snap-confined apps such as snap Firefox stay unreadable under it
(their per-process `unreadable` gaps name them) — for those, use the
unconfined flag or run natively.

Least privilege (measured 2026-11-12 on lu26 with the local
image; no `--privileged`, no `CAP_SYS_ADMIN`) captures the same
demo exactly with the narrow
five-capability set under the Docker default seccomp profile — no
`--security-opt seccomp` flag is needed on Docker 24 and later (where
the engine default cannot be used, pass
`--security-opt seccomp=deploy/seccomp-p11scope.json` from the
checkout). Where AppArmor is enforcing, keep the `--security-opt
apparmor=...` flag alongside it:

```sh
FLAGS="--pid=host --cap-drop ALL --cap-add BPF --cap-add PERFMON --cap-add CHECKPOINT_RESTORE --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro --security-opt apparmor=unconfined"
```

Measured 2026-11-12 on lu26 (Ubuntu 26.04.1, rootful Docker
29.8.1, AppArmor enforcing, local image from p11scope 346d2c875):
the least-privilege set scans 198 callers with the opt and 2
without; the shipped-capability set scans 190 callers with the
opt and 2 without (20,099 functions watched with the opt under
both sets).

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

A user in the `docker` group needs no sudo. Where AppArmor is
enforcing, the `--security-opt apparmor=...` flag above is what makes
captures see processes at all (without it, `doctor` fails its
`process access` check and `inventory` sees almost nothing); the
shipped [`apparmor-p11scope`](../deploy/apparmor-p11scope) profile is
the Docker default plus one `ptrace (read, trace)` rule.

Rootless Docker or Podman cannot work: BPF loading and uprobes need real
host capabilities, which a rootless container cannot grant. Use rootful
Docker — as a `docker`-group user, or with sudo. The host needs Linux
6.6+ with BTF (`uprobe_multi`); under Docker Desktop `--pid=host` sees
the Desktop VM, not your laptop.

`doctor` (trimmed real output, Ubuntu 26.04, local image,
measured 2026-11-12 on lu26, p11scope 346d2c875):

```
Doctor: requested-lane checks passed.
verdict: capture available; run startup capture not in this build (run reports stay partial; run itself works)
effective capabilities ............ warn  CAP_DAC_READ_SEARCH CAP_SYS_ADMIN CAP_SYS_PTRACE - missing: needs CAP_BPF (load BPF programs and attach probes); needs CAP_CHECKPOINT_RESTORE (prove executables through /proc/<pid>/map_files); needs CAP_PERFMON (load BPF programs alongside CAP_BPF)
minimal setcap .................... warn  missing CAP_BPF, CAP_CHECKPOINT_RESTORE, CAP_PERFMON: sudo setcap 'cap_bpf,cap_checkpoint_restore,cap_dac_read_search,cap_perfmon,cap_sys_ptrace=ep' /usr/local/bin/p11scope
target loader build ............... warn  unbound
debug-state hook .................. warn  unavailable
loader-state live read ............ warn  unavailable
Next: p11scope profile --pid <PID> (or doctor --pid <PID> to check a target).
run with -v for details
```

`inventory --system --duration 15s` (trimmed; the desktop Firefox maps
its NSS softokn; measured 2026-11-12 on lu26, local image):

```
inventory system (2 passes, 190 callers, 16 provider files, 56 edges)
coverage: partial - 161 gaps
/snap/firefox/9057/usr/lib/firefox/libsoftokn3.so: mapped by 5 applications (firefox (from firefox), firefox (from xfce4-panel)); no use in the covered interval; 5 of 5 mappings predate the watch, earlier calls are not counted
run with -v for details
```

`profile --system --duration 30s` (trimmed; a quiet window — nothing
touched a provider, so the report is an honest empty with every gap
named; measured 2026-11-12 on lu26, local image):

```
p11scope - system scope - up 00:00:39 - mode profile - /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so (+4 more)
Aggregate across the selected scope; counts are not per application.
No completed calls observed; coverage incomplete.
0 completed calls; 0 returned errors; 0 entries without an observed return.
coverage: partial - calls may be missing (3 provider files not watched, 47 discovery steps unavailable, capture process-view capacity was exhausted; remaining generations were not scanned: 1, file-learning events were lost; some provider files may not have been learned: 1, file learning was unavailable; short-lived first loads of new provider files were not learned: 1, file learning cannot see filesystems outside the observer's mount namespace; provider files opened only there were not learned: 1, 9 provider tables incompletely read, library-load tracking missed loads it should have seen, function list not fully identified, 380 short-lived process gaps); names unconfirmed (function names follow the standard PKCS#11 table but their layout was not verified from scan (add --manifest to confirm positions for mechanism decoding))
Attribution: 5 of 5 mapped provider files have no manifest (/snap/firefox/9057/usr/lib/firefox/libsoftokn3.so, /usr/lib/x86_64-linux-gnu/libnssckbi.so, /usr/lib/x86_64-linux-gnu/libsoftokn3.so, and 2 more); counts are exact, names are unconfirmed.
[Module gaps section trimmed]
run with -v for details
```

### Firefox in the demo

Firefox's own NSS module, libsoftokn3, is a PKCS#11 provider, so a
desktop Firefox shows up in the demo without any setup, as in the
inventory output above (measured 2026-11-12 on lu26: 5 Firefox
mappings, quiet in the window). Activity appears when Firefox
does cryptography: opening https sites, opening Settings >
Privacy & Security > Security Devices, or viewing saved
passwords — the Browsers section shows the resulting calls and
mechanism counters from a client-certificate run. A Firefox that
was already running before the capture has its earlier calls in
named gaps ("mappings predate the watch, earlier calls are not
counted"). For snap Firefox, use the unconfined flag or run
natively — the shipped AppArmor profile cannot read
snap-confined processes.

## Learn more

- [Operator's guide](usage.md): captures, coverage and honest claims.
- [Troubleshooting](troubleshooting.md): refusals and empty captures.
- [Privacy allowlists](privacy/allowlist-v1.md) ([v2](privacy/allowlist-v2.md)): captured fields.
- [Install](install.md#install): packages and building from source.
- [Known limitations](known-limitations.md): attach timing and scope edges.
- [Container privileges](../deploy/k8s/README.md): what each grant is for.
