<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# G33 browser harness

Packaged-application cells proving p11scope observes real browser PKCS#11
traffic: Firefox/NSS and Chromium driven through representative flows
against a controlled SoftHSM provider, with observed attributions asserted
end to end beside independent TLS-layer ground truth.

## Layout

- `softhsm.py` — controlled provider: isolated SoftHSM config, token init
  with known PINs, client-credential import.
- `profiles.py` — fresh Firefox profiles (`pkcs11.txt` + prefs) and fresh
  Chromium `HOME` trees (`~/.pki/nssdb/pkcs11.txt`); Playwright browser
  resolution (newest cached revision wins).
- `tls_server.py` — threaded loopback flow servers (plain HTTP, HTTPS, and
  `CERT_REQUIRED`), recording connections, requests, and presented client
  certificates as oracle ground truth.
- `cells.py` — cell runners: `run_direct` (`p11scope run` owns the browser
  child) and `attach_drive` (Playwright drives, `p11scope profile --pid`
  observes the main browser process).
- `flows.py` — Playwright flows (page visit, client-cert attempt) with wait
  strategies and bounded timeouts.
- `oracle.py` — report assertions: schema pin, module identity by SHA-256,
  per-function minimum counts, zero event loss, earned verdicts.
- `suite-test_browser_cells.py` — source of the `tests/python` suite; see
  "Registration" below. It is NOT a live suite file in this directory.
- `register-suite.patch` — wiring patch (NOT applied): adds the suite plus
  its `run-python-suites.py` entry. The controller applies it at
  integration; this worktree never registers the suite itself.

## Setup (installed gate host)

The harness needs, beyond the product checkout:

- `P11SCOPE_BIN` pointing at the candidate binary (matrix convention),
  passwordless `sudo -n` for the observer, and host tools
  `softhsm2-util`, `pkcs11-tool`, `openssl`, `pgrep`.
- Python Playwright plus downloaded browsers, user-space only:

```sh
pip install playwright
playwright install chromium firefox
```

Playwright does not know very new distros (observed: Ubuntu 26.04
"Resolute" with Playwright 1.64): downloads then fail with "does not
support chromium on …". The playwright-native escape hatch is to borrow
the previous LTS mapping:

```sh
PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu24.04-x64 playwright install chromium firefox
```

The 24.04-built browsers run unmodified on 26.04; no `install-deps` and
no `sudo apt` was needed on the dev host (all runtime libraries already
present). If a launch later fails on a missing system library, that leg
may use `sudo -n` for OS browser dependencies — and must stop and report
if sudo needs a password.

- Headless operation is mandatory (no display on gate hosts). The
  browser-automation skill's visible-browser default is overridden by the
  environment; every flow runs headless.

## Cell catalog (v1)

All cells use a fresh profile, a freshly seeded SoftHSM token, and
loopback flow servers. Floors are minimums; browsers may call more.
Background network activity is stabilized out of every cell (Chromium
flags, Firefox prefs), so every asserted call is flow-caused — this was
verified per cell by comparing stabilized against unstabilized runs and,
for FF-STARTUP, by trace-timestamp correlation (the 79-call burst lands
inside the 105 ms navigation window, all on the main browser PID).

| Cell | Mode | Flow | Asserts |
| --- | --- | --- | --- |
| FF-STARTUP | attach-drive | HTTPS visit | `C_FindObjects*` ≥ 1, `C_GetSessionInfo` ≥ 1 (typ. x26), page 200, no loss |
| CR-PLAIN | attach-drive | HTTPS visit, registered | zero calls, module never maps, page 200 |
| FF-NOMOD | run-direct, http | screenshot, unregistered | zero calls, exit 0, PNG bytes |
| FF-PINBOUND | attach-drive | `CERT_REQUIRED` visit | hang, no `C_Login`/`C_Sign` ever, server saw no cert |
| CR-PINBOUND | attach-drive, no auto-select | `CERT_REQUIRED` visit | zero calls (never maps), not loaded, server saw no cert |

What the catalog proves:

- FF-STARTUP is the healthy positive: real NSS store enumeration,
  observed and attributed to the Firefox main process.
- FF-PINBOUND pins the PIN boundary amid racy selection: the module is
  mapped and armed, the flow hangs with no cert presented, and `C_Login`
  / `C_Sign` never happen — while selection enumeration itself races the
  prompt failure (x0 or x16 across runs, both inside the handshake second;
  trace-timed) and is therefore unpinned.
- CR-PLAIN/CR-PINBOUND characterize Chromium: it never maps a registered
  external provider for any flow-related reason headless (server
  validation and client selection alike); the zero is corroborated by
  the end-of-cell mapping check, not just by empty counts.
- FF-NOMOD is the absence twin through the owned-child (`run`) path.

## Calibrated boundaries (do not "fix" in the harness)

1. **Interactive token login is unreachable headless.** NSS requires a
   PIN prompt to use private token objects; no headless path supplies
   one (verified: PIN token, empty-PIN `C_InitToken`, `CKF_LOGIN_REQUIRED`
   set in all cases). TLS client-cert *presentation* therefore cannot
   pass; the PINBOUND twins assert the stall instead. A login-free
   provider (auto-login shim over SoftHSM) would unlock a sign-positive
   cell; it is follow-up work, not v1.
2. **`p11scope run` + Chromium aborts (SIGABRT, 3/4 launches).** The
   abort precedes any mapping (single-process included; stabilized flags
   do not help), implicating the observer's loader hooks during
   Chromium's spawn storm. Chromium v1 cells are attach-drive only;
   `run_direct` stays supported for Firefox. Product-side loader-hook
   robustness for Chromium spawn is the follow-up.
3. **Firefox `--screenshot` + self-signed HTTPS hangs** (cert-error page
   never completes for the screenshot frontend; packet proof: fatal TLS
   alert, clean close, then silence). Firefox run-direct cells use HTTP;
   Firefox HTTPS flows are Playwright-driven with `ignore_https_errors`.
4. **Background browser traffic is not flow evidence.** Unstabilized runs
   showed extra enumeration (FF x58 vs stabilized x26) and Chromium
   bursts (x5/x7) from background fetches; stabilized runs remove them.
   Cells assert stabilized shapes only. `LD_PRELOAD` pre-mapping was
   evaluated as a scan-visibility aid and rejected: it suppresses
   Chromium's NSS calls entirely (behavior perturbation, not just
   visibility).
5. **Chromium ≠ Google Chrome.** G33 asks for real Chrome application
   checks; this harness drives Playwright's full Chromium build (never
   the headless shell). A Chrome-channel cell needs a Chrome install on
   the gate host and is explicitly out of v1 scope.
6. **Verdicts are `PARTIAL`, honestly.** Scan-path captures without
   operator manifests report `attribution_only` (counts exact) or
   `concrete_gap` (window caveats: loader races, unconfirmed pause,
   never-mapped modules). The oracle pins the earned verdict per cell and
   asserts zero event loss; it never requires `COMPLETE`. Trace-mode
   executable labels stay `Unknown` on these short captures (privacy
   sampling); profile cells anchor attribution via scope PID plus module
   identity instead.

## Registration

The controller wires the suite at integration (this worktree holds the
harness only):

```sh
git apply tests/fixtures/browser/register-suite.patch
python3 -I scripts/run-python-suites.py --check
```

The patch proposes `RUN` with self-skip: on hosts without `P11SCOPE_BIN`,
passwordless sudo, Playwright browsers, or SoftHSM tooling, every test
skips with its missing prerequisite named. T11 runs the positives on a
qualified installed host with `TMPDIR` on big disk:

```sh
TMPDIR=/var/tmp/p11scope-ws-tmp python3 -I scripts/run-python-suites.py test_browser_cells.py
```

## Reproducing a cell by hand

```sh
export P11SCOPE_BIN=/path/to/candidate/p11scope
python3 - <<'EOF'
import sys
sys.path.insert(0, "tests/fixtures/browser")
# ... see suite-test_browser_cells.py for the per-cell composition ...
EOF
```

Cell workdirs are `mkdtemp` (0700) roots; the observer refuses
group-writable `-o` ancestors, so never redirect a cell into a 0775 tree.
Reports are root-written and re-owned to the invoking user after capture.
