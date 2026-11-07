# SPDX-License-Identifier: GPL-3.0-or-later
"""Drive one headless Chromium client-cert page load (demo workload).

Reads the environment file written by chromium-clientauth-setup.sh, launches
Playwright's Chrome-for-Testing build headless against the prepared HOME
(auto-login shim registered, managed auto-select policy installed by setup),
visits the CERT_REQUIRED server URL, and prints one JSON result line.

Usage:
  python3 chromium-clientauth-demo.py --workdir DIR --url https://127.0.0.1:PORT/
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

#: Chromium stabilizers: background fetches must not perturb the run.
STABLE_ARGS = ("--no-first-run", "--no-default-browser-check", "--disable-sync",
               "--disable-background-networking", "--disable-component-update",
               "--disable-default-apps", "--no-service-autorun")


def read_env_file(path: Path) -> dict[str, str]:
    """Parse KEY=VALUE lines (values are plain paths; no shell quoting)."""
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip("'")
    return env


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--url", required=True)
    parser.add_argument("--timeout-ms", type=int, default=25000)
    parser.add_argument("--hold-open", type=float, default=0.0,
                        help="keep the browser alive N extra seconds after load")
    parser.add_argument("--go-file", type=Path, default=None,
                        help="wait until PATH exists before navigating "
                             "(lets an observer attach first)")
    args = parser.parse_args()

    setup_env = read_env_file(args.workdir / "env.sh")
    for required in ("SOFTHSM2_CONF", "P11SCOPE_CLIENTAUTH_UPSTREAM",
                     "P11SCOPE_CLIENTAUTH_PIN", "CHROMIUM_CLIENTAUTH_HOME"):
        if required not in setup_env:
            raise SystemExit(f"{args.workdir}/env.sh lacks {required} (run setup?)")
    missing = [k for k in ("SOFTHSM2_CONF", "P11SCOPE_CLIENTAUTH_UPSTREAM",
                            "CHROMIUM_CLIENTAUTH_HOME")
               if not Path(setup_env[k]).exists()]
    if missing:
        raise SystemExit(f"setup outputs missing: {missing} (run setup?)")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit(f"python playwright is not installed: {exc}") from exc

    browser_env = dict(os.environ)
    browser_env.update({k: setup_env[k] for k in
                        ("SOFTHSM2_CONF", "P11SCOPE_CLIENTAUTH_UPSTREAM",
                         "P11SCOPE_CLIENTAUTH_PIN")})
    browser_env["HOME"] = setup_env["CHROMIUM_CLIENTAUTH_HOME"]

    result: dict = {"loaded": False}
    with sync_playwright() as pw:
        context = pw.chromium.launch_persistent_context(
            str(args.workdir / "crprofile"), channel="chromium",
            headless=True, ignore_https_errors=True,
            args=list(STABLE_ARGS), env=browser_env)
        try:
            page = context.pages[0] if context.pages else context.new_page()
            if args.go_file is not None:
                import time
                deadline = time.monotonic() + 120.0
                while not args.go_file.exists():
                    if time.monotonic() > deadline:
                        raise SystemExit(f"--go-file {args.go_file} never appeared")
                    time.sleep(0.2)
            try:
                response = page.goto(args.url, wait_until="domcontentloaded",
                                     timeout=args.timeout_ms)
                result = {"loaded": True,
                          "http_status": response.status if response else None,
                          "url": page.url}
            except Exception as exc:  # noqa: BLE001 - TLS outcome is the result
                result = {"loaded": False,
                          "error": f"{type(exc).__name__}: {exc}".split("\n")[0][:200]}
            if args.hold_open > 0:
                import time
                time.sleep(args.hold_open)
        finally:
            context.close()
    print(json.dumps(result), flush=True)
    return 0 if result["loaded"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
