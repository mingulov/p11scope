<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> -->
# Demo: a throwaway software token (start here)

Goal: make a throwaway software token on your machine, run three
plain smart-card-tool commands against it (list, make a key, sign),
and see p11scope count the calls: which functions ran, the key type
and size, the signing mechanism. This is the simplest demo and the
most reliable — try it first.

You will use two terminals: one watches, one works. The token lives
in a fresh temporary directory, so your own SoftHSM setup is
untouched.

## What you need

- Docker, as on the [demos front page](README.md).
- A software token and the tool: `sudo apt install softhsm2 opensc`
  on Debian/Ubuntu, `sudo dnf install softhsm opensc` on
  Fedora/RHEL.

## Steps

1. In the working terminal, make the throwaway token (the `1234`
   values are an example PIN for this demo token only; SoftHSM needs
   at least 4 characters):

   ```sh
   demo_dir=$(mktemp -d /var/tmp/softhsm-demo.XXXXXX)
   export SOFTHSM2_CONF="$demo_dir/softhsm2.conf"
   mkdir -p "$demo_dir/tokens"
   printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$demo_dir" > "$SOFTHSM2_CONF"
   softhsm2-util --init-token --slot 0 --label demo --so-pin 1234 --pin 1234
   MODULE=/usr/lib64/pkcs11/libsofthsm2.so
   [ -f "$MODULE" ] || MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
   ```

   Keep using this same terminal for step 4: it remembers where the
   token is.

2. In the watching terminal, find the module and keep it loaded while
   you watch (one line; it stops by itself after 5 minutes):

   ```sh
   MODULE=/usr/lib64/pkcs11/libsofthsm2.so
   [ -f "$MODULE" ] || MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
   LD_PRELOAD="$MODULE" sleep 300 &
   ```

3. In the watching terminal, start the observer for 90 seconds:

   ```sh
   docker run --rm --pid=host --cap-drop ALL --cap-add BPF --cap-add PERFMON --cap-add CHECKPOINT_RESTORE --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH -v /sys/fs/cgroup:/sys/fs/cgroup:ro --security-opt apparmor=unconfined ghcr.io/mingulov/p11scope:latest profile --system --duration 90s
   ```

   Wait until it says `capturing:` (a busy machine can take a
   minute). Only what happens after that line is counted.

   Alternative: `--cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add
   DAC_READ_SEARCH` in place of the five `--cap-*` flags.
   `CAP_SYS_ADMIN` grants very broad power — close to full root
   (mounts, namespaces, many kernel admin operations) — so use it
   only when needed. What it adds for p11scope is file learning
   (fanotify): it catches a short-lived process's first load of a new
   provider file; without it that case is a named gap in the report.
   On Docker older than 24, whose default seccomp allows `bpf()` only
   with `CAP_SYS_ADMIN`, it is also the way to run without the
   [seccomp file](../../deploy/seccomp-p11scope.json).

4. In the working terminal, run the three tool commands:

   ```sh
   pkcs11-tool --module "$MODULE" -L
   pkcs11-tool --module "$MODULE" --login --pin 1234 --keypairgen --key-type rsa:2048 --label demo-key
   echo hello | pkcs11-tool --module "$MODULE" --login --pin 1234 --sign --label demo-key --mechanism SHA256-RSA-PKCS -o sig.bin
   ```

5. Wait for the observer to finish (it stops by itself), and read the
   report. Then clean up: `kill %1` in the watching terminal, and in
   the working terminal `rm -rf "$demo_dir" sig.bin` plus `unset
   SOFTHSM2_CONF`.

## What you will see

The tool's own output names the key type and size (trimmed; your slot
id will differ). `[...]` marks trimmed lines.

```
Slot 0 (0x571917fc): SoftHSM slot ID 0x571917fc
  token label        : demo
[...]
Key pair generated:
Private Key Object; RSA
  label:      demo-key
[...]
Public Key Object; RSA 2048 bits
  label:      demo-key
[...]
Using signature algorithm SHA256-RSA-PKCS
```

The observer's report counts the calls behind those commands (real
output, trimmed):

```
p11scope - system scope - up 00:01:33 - mode profile - /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so (+5 more)
Aggregate across the selected scope; counts are not per application.
152 completed calls; 3 returned errors; 0 entries without an observed return.
coverage: partial - calls may be missing ([...]); names unconfirmed ([...])
[...]
C_GetSlotList                libsofthsm2.so          6      0     8.2us    16.4us    16.4us         0
C_Login                      libsofthsm2.so          2      0     2.1ms     2.1ms     2.1ms         0
C_GenerateKeyPair            libsofthsm2.so          1      0   268.4ms   268.4ms   268.4ms         0
C_SignInit                   libsofthsm2.so          1      0   131.1us   131.1us   131.1us         0
C_Sign                       libsofthsm2.so          2      0     8.2us     2.1ms     2.1ms         0
[...]
ERROR REASONS:
C_GetAttributeValue: CKR_ATTRIBUTE_TYPE_INVALID x3
MECHANISM                       CALLS    ERR
CKM_SHA256_RSA_PKCS                 3      0
CKM_RSA_PKCS_KEY_PAIR_GEN           1      0
[...]
```

In plain words: two logins, one RSA key pair generated, one
SHA256-RSA signature made. The 3 "returned errors" are the tool
asking the token about attributes it does not have
(`CKR_ATTRIBUTE_TYPE_INVALID`); that is normal probing, not a
failure. `sessions: 2 opened ... logins: user x2` counts the two
tool logins. The `coverage: partial` line is normal on a busy
machine: it names what the observer could not prove, while your
calls above it are counted exactly. Your counts may differ by a call
or two, and anything else on your machine using a token at the same
time appears beside your rows.

## If you see something else

- `No completed calls observed`: the commands ran before the
  `capturing:` line, the keeper line from step 2 is not running
  (`jobs` should list it), or step 4 ran in a different terminal
  than step 1 (that terminal does not know where the token is).
- `slot 0` init fails or the tool sees no token: an old
  `SOFTHSM2_CONF` points elsewhere — check `echo $SOFTHSM2_CONF`.
- Almost nothing scanned, 0 providers: you dropped the
  `--security-opt apparmor=unconfined` flag on an AppArmor machine
  (Ubuntu), or you run Docker Desktop (it watches its virtual
  machine, not your PC).
- `doctor` refuses about BTF or the kernel: this PC cannot do live
  capture (needs `/sys/kernel/btf/vmlinux` and kernel 6.6+).
  See [Troubleshooting](../troubleshooting.md).

## What is not shown

The PIN you typed, the key bytes and the signed data never appear in
the report: p11scope counts the calls (`C_Login`, `C_GenerateKeyPair`,
`C_Sign`) without reading what went through them. Calls from before
the `capturing:` line are not counted. The report aggregates the
whole machine, so it does not name which program made each call.

Prefer a system package? Install v0.7.0 as on the [front
page](README.md), then run `sudo p11scope profile --system --duration
90s` instead of the `docker run` line (keep the step 2 keeper line:
it makes one-shot tools count reliably).
