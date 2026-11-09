<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# r/PKI first-post text for p11scope v0.7.0 — DRAFT (owner edits before posting)

> Draft for the first public r/PKI post. Plain and non-hype by brief;
> every claim is merged on the draft base (`ddb12f2a9`) and sourced in
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
p11scope: capturing: waiting for the command to load a provider; stop with Ctrl-C
p11scope: pause: partial [pause_diag=deadline_during_engine_apply]
Available slots:
Slot 0 (0x4d1c29f8): SoftHSM slot ID 0x4d1c29f8
  token label        : demo
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
  hardware version   : 2.6
  firmware version   : 2.6
  serial num         : 85f07eaacd1c29f8
  pin min/max        : 4/255
  uri                : pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=85f07eaacd1c29f8;token=demo
Slot 1 (0x1): SoftHSM slot ID 0x1
  token state:   uninitialized
p11scope — cgroup scope — up 00:00:01 — mode profile — /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
Aggregate across the selected scope; counts are not per application.
1 completed call; 0 returned errors; 0 entries without an observed return.
coverage: partial — calls may be missing (4 discovery steps unavailable, calls made while probes were being attached may be missing, 1 discovery record truncated, 1 load only partly paused, library-load tracking could not be confirmed); names unconfirmed (function names follow the standard PKCS#11 table and were not confirmed by a manifest (add --manifest to confirm))
Attribution: 1 of 1 mapped provider file has no manifest (libsofthsm2.so); counts are exact, names are unconfirmed — rerun with --manifest for each mapped provider file.
CALLS = completed calls; ERR = returned errors; IN-FLIGHT = entries without an observed return.
Latency units: ns/us/ms/s (us displayed as µs); ~ = log2-bucket approximation, lower bound.
FUNCTION                     PROVIDER            CALLS    ERR      p50~      p95~      p99~ IN-FLIGHT
C_GetFunctionList            libsofthsm2.so          1      0    65.5µs    65.5µs    65.5µs         0
Mechanisms: none attributed — 1 function named from the standard table, unconfirmed; add --manifest for each mapped provider file (see Coverage).
run with -v for details
p11scope: cleanup completed, 9/9 links released, 0 s
```

What you are looking at: the listing itself is pkcs11-tool's normal
output; below it, p11scope reports 1 observed call (`C_GetFunctionList`,
65.5 µs) with 0 errors. Coverage reads `partial` with every gap named —
this build has no run initial-set capture, so `run` reports stay PARTIAL
and say so instead of claiming completeness. The full quickstart this
came from is in the
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

- Host: dev host, kernel 7.0.0-38-generic, 2026-11-09 ~07:05 EET.
  Privileged commands ran via `sudo -n` under
  `flock /var/tmp/p11scope-ws-tmp/privileged.lock`.
- Token setup (branch quickstart shape, lane-local dir):

  ```sh
  demo_dir=$(mktemp -d /var/tmp/p11scope-ws-tmp/post-draft/softhsm-demo.XXXXXX)
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

- `p11scope` binary: `p11scope 0.7.0` debug, built from `ddb12f2a9` via
  `p11-lock mise exec -- ./scripts/cargo.sh +1.99.1 build --locked
  --target-dir target/post-draft --bin p11scope` (exit 0, 12m16s).
- Quickstart verification (same binary): `doctor` exit 0, 11.62 s,
  verdict "capture available"; `inventory --system --duration 15s`
  exit 0 (honest PARTIAL on the loaded host, 3 named gaps);
  `profile --pid 1 --duration 30s` exit 0 (honest empty result, JSON
  report written).
- Secret check: `grep -c 1234` over the run log and all four captured
  logs returns 0 matches — the throwaway PIN appears nowhere in any
  p11scope output. p11scope never captures argv values, PINs, keys or
  payloads (allowlist-v1/v2); the check confirms the sample, it does
  not re-prove the product property.
