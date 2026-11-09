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
295 completed calls; 0 returned errors; 0 entries without an observed return.
coverage: counts complete; function names follow the standard PKCS#11 table and were not confirmed by a manifest (add --manifest to confirm)
FUNCTION                     PROVIDER            CALLS    ERR      p50~      p95~      p99~ IN-FLIGHT
C_Sign                       libsofthsm2.so        148      0   524.3µs     1.0ms     1.0ms         0
C_SignInit                   libsofthsm2.so        147      0   262.1µs   524.3µs   524.3µs         0
run with -v for details
```

Counts are exact for the window; names follow the standard table
until confirmed with `--manifest`.

## Learn more

- [Operator's guide](usage.md): captures, coverage and honest claims.
- [Troubleshooting](troubleshooting.md): refusals and empty captures.
- [Privacy allowlists](privacy/allowlist-v1.md) ([v2](privacy/allowlist-v2.md)): captured fields.
- [Install](install.md#install): packages and building from source.
