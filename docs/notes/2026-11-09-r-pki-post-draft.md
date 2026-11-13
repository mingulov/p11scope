<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# r/PKI first-post text for p11scope v0.7.0 — DRAFT (owner edits before posting)

> Draft for the first public r/PKI post. Plain and non-hype by brief;
> every claim is merged on the draft base (`26884cce8`) and sourced in
> `CHANGELOG.md`, `docs/` or the tree. Link targets are placeholders the
> owner fills at publish. The example output below is real, captured on
> the dev host per the run note; it was checked to contain no secrets
> (see verification note).

---

Title: p11scope 0.7.0: see which program called your PKCS#11 token (Linux, eBPF, no shim)

Post:

p11scope finds which running Linux applications use PKCS#11 providers,
then shows their observed calls, errors, latency and bounded metadata —
without replacing the provider or changing each application's
configuration. eBPF uprobes observe the providers already mapped by
running processes, so there is no shim to install and no restart.

Version 0.7.0 answers "which program called my token?": callers running
under an interpreter now carry an app label, so the answer names the
application, not just the runtime. Also new: inventory events stream to
stdout (`inventory --event-log -` with `--event-interval`), a published
container image, Linux 7.4-rc1 in the tested kernel matrix, and a docs
pack (troubleshooting, real first-run output, a pkcs11-spy comparison).

Honest limits, up front:

- Linux x86-64 with BTF (`/sys/kernel/btf/vmlinux`) only.
- Kernel 6.6+ (or a working backport) for live capture; 6.12+ is the
  smoother path (on 6.6–6.9 the `--pid` filter falls back to per-offset
  links automatically).
- Root, or the documented capability set (`CAP_BPF`,
  `CAP_CHECKPOINT_RESTORE`, `CAP_DAC_READ_SEARCH`, `CAP_PERFMON`,
  `CAP_SYS_PTRACE`; no `CAP_SYS_ADMIN` on the default lane).
- PKCS#11 only. No payload, key-material or PIN capture, ever — the
  [privacy allowlists](https://github.com/mingulov/p11scope/blob/v0.7.0/docs/privacy/allowlist-v1.md)
  list every captured field, and anything unobserved stays unknown
  rather than guessed.
- Read the [known limitations](https://github.com/mingulov/p11scope/blob/v0.7.0/CHANGELOG.md)
  before relying on a capture.

Real example — a throwaway SoftHSM token listed through `p11scope run`
(dev host, kernel 7.0.0-38-generic; throwaway PIN `1234`, config and
tokens in a fresh directory under `/var/tmp`):

```
$ sudo --preserve-env=SOFTHSM2_CONF p11scope run --pause auto -- \
    pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -L
p11scope: starting: loading probes and scanning processes (a busy machine can take a minute or more); stop with Ctrl-C
p11scope: capturing: waiting for the command to load a provider; stop with Ctrl-C
Available slots:
Slot 0 (0x77d08576): SoftHSM slot ID 0x77d08576
  token label        : demo
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
  hardware version   : 2.6
  firmware version   : 2.6
  serial num         : cf747f9ff7d08576
  pin min/max        : 4/255
  uri                : pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=cf747f9ff7d08576;token=demo
Slot 1 (0x1): SoftHSM slot ID 0x1
  token state:   uninitialized
p11scope - cgroup scope - up 00:00:00 - mode profile - /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
Aggregate across the selected scope; counts are not per application.
9 completed calls; 0 returned errors; 0 entries without an observed return.
coverage: partial - counts complete; function names follow the standard PKCS#11 table but their layout was not verified from scan (add --manifest to confirm positions for mechanism decoding)
Attribution: 1 of 1 mapped provider file has no manifest (/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so); counts are exact, names are unconfirmed.
CALLS = completed calls; ERR = returned errors; IN-FLIGHT = entries without an observed return.
Latency units: ns/us/ms/s (microseconds shown as us); ~ = log2-bucket approximation, lower bound.
FUNCTION                     PROVIDER            CALLS    ERR      p50~      p95~      p99~ IN-FLIGHT
C_GetSlotInfo                libsofthsm2.so          2      0     8.2us    16.4us    16.4us         0
C_GetSlotList                libsofthsm2.so          2      0     4.1us    16.4us    16.4us         0
C_GetTokenInfo               libsofthsm2.so          2      0     8.2us    65.5us    65.5us         0
C_Finalize                   libsofthsm2.so          1      0    16.4us    16.4us    16.4us         0
C_GetFunctionList            libsofthsm2.so          1      0   262.1us   262.1us   262.1us         0
C_Initialize [init: ok]      libsofthsm2.so          1      0    16.8ms    16.8ms    16.8ms         0
Mechanisms: none attributed - 1 function named from the standard table, unconfirmed (see Coverage).
run with -v for details
p11scope: cleanup completed, 11/11 links released, 0 s
```

What you are looking at: the listing itself is pkcs11-tool's normal
output; below it, p11scope reports 9 observed calls (the slot and
token listing, plus initialize/finalize) with 0 errors. Coverage
reads `partial` with counts complete and names unconfirmed (no
manifest was passed) — run startup capture is still absent, so
`run` reports stay PARTIAL and say so instead of claiming
completeness. The full quickstart this came from is in the
[operator's guide](https://github.com/mingulov/p11scope/blob/v0.7.0/docs/usage.md#quickstart)
(about two minutes with a throwaway SoftHSM token).

Links:

- Repo: [REPO-URL]
- v0.7.0 release (bundles, DEB/RPM, checksums, container image):
  [RELEASE-URL]

Source: GPL-3.0-or-later userspace, GPL-2.0-only BPF programs. Feedback
welcome, especially on providers and kernels outside the tested list.

---

## Run note (not part of the post)

- Host: dev host lu26, kernel 7.0.0-38-generic, 2026-11-13 ~12:40 EET.
  Privileged commands ran via `sudo -n` under
  `flock /var/tmp/p11scope-ws-tmp/privileged.lock`, umask 022,
  `TMPDIR=/var/tmp/p11scope-ws-tmp`.
- Token setup (branch quickstart shape, lane-local dir):

  ```sh
  demo_dir=$(mktemp -d /var/tmp/p11scope-ws-tmp/demo-refresh-run.XXXXXX)
  export SOFTHSM2_CONF="$demo_dir/softhsm2.conf"
  mkdir -p "$demo_dir/tokens"
  printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$demo_dir" > "$SOFTHSM2_CONF"
  softhsm2-util --init-token --slot 0 --label demo --so-pin 1234 --pin 1234
  MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
  ```

- Observed run (exit 0; full log kept in the lane TMPDIR):

  ```sh
  sudo --preserve-env=SOFTHSM2_CONF p11scope run --pause auto -- \
    pkcs11-tool --module "$MODULE" -L
  ```

- `p11scope` binary: `p11scope 0.7.0` release, built from `26884cce8`
  via `p11-lock mise exec -- ./scripts/cargo.sh +1.99.1 build
  --locked --release --bin p11scope` (exit 0, 166 s on the um790
  build host).
- Quickstart verification (same binary): `doctor` exit 0, 4.88 s,
  verdict "capture available"; `inventory --system --duration 15s`
  exit 0 (honest PARTIAL on the loaded host: 494 callers, 32
  gaps); `profile --pid 1 --duration 30s` exit 0 (honest empty
  result, JSON report written).
- Secret check: `grep -c 1234` over the run stdout/stderr and the
  doctor, inventory and profile outputs returns 0 matches — the
  throwaway PIN appears nowhere in any p11scope output. p11scope
  never captures argv values, PINs, keys or payloads
  (allowlist-v1/v2); the check confirms the sample, it does not
  re-prove the product property.
