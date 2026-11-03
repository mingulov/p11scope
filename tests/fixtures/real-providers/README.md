<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Real-provider fixtures (WP-3)

The WP-3 cells run real distro tools under `p11scope run --pause auto`
with an independent call ledger: OpenSC `pkcs11-spy.so` forwards every
PKCS#11 call to the real module and appends one entry per call to a spy
log. `scripts/real-provider-oracle.py` judges each report against that
ledger plus the pinned expectations in `expected-causes.json`.

## Spy log format (established on this host, OpenSC 0.27.0~rc1-1)

A header naming the spied module, then one entry per forwarded call,
each closed by a `Returned:` line:

```
*************** OpenSC PKCS#11 spy *****************
Loaded: "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"

0: C_GetInterface
P:2309949; T:0x138493420533824 2026-11-03 02:47:22.086
...
Returned:  0 CKR_OK
```

Facts the oracle relies on (all verified by capture, not by reading
the spy source):

- The log **appends** across runs sharing one `PKCS11SPY_OUTPUT` path:
  every cell removes its spy log before running. Sequences restart at 0
  per process if several processes ever share one log file.
- Every entry must close. A trailing entry without `Returned:` is a
  truncated log, never a partial count.
- Without `PKCS11SPY` the log holds `Error: no module specified` and no
  `Loaded:` line; the oracle refuses it as a harness error.
- `spy-sample-softhsm.log` (`pkcs11-tool --module spy -L` against
  SoftHSM: 9 calls) and `spy-sample-opensc.log` (`-L` against OpenSC
  with no reader: 4 calls) are real captures; the oracle suite parses
  both exactly.

## Spy-boundary rules (why two functions never match the ledger)

The tool calls the spy; the spy forwards to the real module. Two
interface-acquisition functions behave exactly, but not 1:1:

- `C_GetFunctionList`: the spy calls the real one once per client
  process at load without logging it. The observed count at the spied
  identity is the ledger count plus the logged process count (the
  `Loaded:` header count). Proved on Fedora: observed 1, ledger 0,
  one process; the tool only ever loads the spy, so the real call must
  come from the spy.
- `C_GetInterface` / `C_GetInterfaceList`: forwarded only when the
  spied module exports them. SoftHSM (2.6 and 2.7) and p11-kit-trust
  export `C_GetFunctionList` only (`nm -D`), so the observed count
  there must be zero; OpenSC and opencryptoki export all three, so the
  observed count must equal the ledger. The receipt records the spied
  module's exports from `nm -D --defined-only`, checked per run.

Everything else is strict equality, both directions. Unknown or aliased
rows at the spied identity cannot qualify.

## p11-kit routing (the documented way, as recorded)

`trust list` loads its modules through libp11-kit, which reads (in
order) the user config under `$XDG_CONFIG_HOME/pkcs11/` (else
`~/.config/pkcs11/`), `/etc/pkcs11/` and `/usr/share/p11-kit/modules/`
(paths from libp11-kit itself; file format in `pkcs11.conf(5)`). Each
cell points `XDG_CONFIG_HOME` at an owned directory holding
`pkcs11.conf` with `user-config: only` and one `modules/spy.module`:

```
module: /usr/lib/x86_64-linux-gnu/pkcs11-spy.so
priority: 1
trust-policy: yes
x-trust-lookup: pkcs11:library-description=PKCS%2311%20Kit%20Trust%20Module
```

Without the `trust-policy` line, `trust list` reports "no modules
containing trust policy"; with it, the full CA list returns through the
spy (verified: exit 0, tens of thousands of ledger lines). `p11tool`
instead takes `--provider <spy>` directly (see `p11tool --help`).
NSS registers the spy into an owned DB with `modutil -add spy -libfile
<spy>`, falling back to `modutil -rawadd "library=<spy> name=spy"`
where `-add` verification fails (Fedora NSS 3.130 rejects even plain
SoftHSM with "Unknown PKCS #11 error", while the module loads fine at
use time). Registration is verified by listing, never by exit code
(`modutil` exits 0 on failure). The observed command is `certutil -L -h
all` alone: `run` does not track descendants, so a wrapper running two
tools would hide both; `modutil -list` exercises the same registration
unobserved in setup. An owned *empty* p11-kit user config
(`user-config: only`, no modules) blinds NSS's second SoftHSM path:
both distros ship `softhsm2.module`, and without blinding NSS executes
SoftHSM calls through p11-kit behind the spy's back (observed 2x the
ledger on Fedora).

## expected-causes.json: the ratchet

Each cell lists one entry per `(os-release ID, tool package version)`:

- `observation`: the exact pinned observation-cause set. Every entry
  carries a `reason` and an `owner`; the oracle refuses pins without
  them. A fixed cause and a new cause both fail the cell until the pin
  is updated: shrink the list on a fix, investigate on growth.
- `pause`: the pinned pause outcome (`sigstop` or `partial`) with its
  reason and owner. `partial` today means the OpenSC partial pause
  owned by the exec-real-providers lane.
- `p11kit_skip` / `p11kit_version`: where p11-kit capacity text is
  expected, the exact endpoint count the skip reason must name, tied to
  the installed p11-kit version; `null` where no capacity skip is
  expected (any skip then fails).

Counts, tool exit, report schema and the metrics skip rule are
strict and never pinned: a metrics twin must skip nothing except,
where the pin declares a p11-kit skip, exactly that pinned p11-kit
closure skip (W3-2 finding 1; any other skip still fails). Cells whose
prerequisites are missing (tool, module, SoftHSM, smart-card reader,
usable slot daemon) are recorded `nonqualifying` with `SKIP (77): ...`
and never pass.

All p11-kit closure pins are provisional until re-taken on the
integrated tree after p11kit-admission lands (batch 5b); their
`modules_skipped` rows carry that owner.
