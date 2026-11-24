# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Firefox client-cert sign under ``p11scope run`` with DEFAULT flags.

``run_firefox_cc`` spawns the observer with no capture flags at all
(``p11scope run -o report.json -- <inner>``: discovery-all, ``--pause
auto``) over an owned Playwright driver (``--inner`` below) that seeds
the browser's own empty-password NSS database with a client credential
in-tree and performs exactly one client-cert TLS visit. The TLS
server's handshake record is the one-run ground truth: one full
handshake, one presented cert, one served request.

Adapted from the v0.8.0 basic-matrix cell5 driver, whose Firefox flow
completed 1/1/1 + HTTP 200 on every scored run on both Fedora hosts;
the spawn shape (sudo env prefix, ``/usr/bin/env HOME= TMPDIR=``,
short ``/var/tmp`` TMPDIR, 240 s observer bound) is unchanged.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

FIXDIR = Path(__file__).resolve().parent
sys.path.insert(0, str(FIXDIR))

from cells import main_browser_pid, p11scope_bin  # noqa: E402


#: Firefox stabilizers shared with the suite's FIREFOX_STABLE_PREFS,
#: plus the single-handshake pins: no session identifiers (every
#: handshake is full, so signs == handshakes) and no prefetch.
FF_CC_PREFS = {
    "app.update.disabledForTesting": True,
    "app.normandy.enabled": False,
    "browser.safebrowsing.malware.enabled": False,
    "browser.safebrowsing.phishing.enabled": False,
    "browser.safebrowsing.downloads.enabled": False,
    "datareporting.policy.dataSubmissionEnabled": False,
    "toolkit.telemetry.enabled": False,
    "extensions.update.enabled": False,
    "network.prefetch-next": False,
    "security.ssl.disable_session_identifiers": True,
}

#: Observer wall bound: seeding (~5 s) + browser launch (~10 s) +
#: one visit (~20 s nav bound) clears in ~60 s on the Fedora hosts;
#: 240 s matches the matrix driver and fails loud on a hung tree.
OBSERVER_TIMEOUT_SECONDS = 240


@dataclass
class FirefoxCCResult:
    """Everything one Firefox cc run produced, for the oracle."""

    name: str
    report_path: Path
    flow: dict = field(default_factory=dict)
    server: dict = field(default_factory=dict)
    observer_stderr_tail: str = ""


def _tail(text: str, lines: int = 25) -> str:
    return "\n".join(text.splitlines()[-lines:])


def _reown(path: Path) -> None:
    """Make a root-written ``path`` readable by the invoking user."""
    if not path.exists():
        return
    uid, gid = os.getuid(), os.getgid()
    subprocess.run(["sudo", "-n", "chown", f"{uid}:{gid}", str(path)],
                   capture_output=True, check=False)


def _reap_firefox_tree(profile_path: str) -> None:
    """Best-effort SIGKILL of Firefox processes bound to ``profile_path``.

    The inner normally ends its own tree via ``context.close()``; this
    covers only the hung/timeout path. The match is scoped to this
    run's unique profile directory, never a bare process name.
    """
    proc = subprocess.run(["pgrep", "-f", profile_path], capture_output=True,
                          text=True, check=False)
    for line in proc.stdout.splitlines():
        pid = line.strip()
        if pid.isdigit():
            subprocess.run(["kill", "-9", pid], capture_output=True,
                           check=False)


def inner(workdir: str, flow_url: str, key_pem: str, cert_pem: str) -> int:
    """Owned driver: seed the NSS client credential, make one cc visit."""
    import cells
    import flows
    from playwright.sync_api import sync_playwright
    from types import SimpleNamespace
    workdir = Path(workdir)
    cred = SimpleNamespace(key_pem=Path(key_pem), cert_pem=Path(cert_pem))
    facts: dict = {}
    try:
        with sync_playwright() as pw:
            context, match, _p = cells.launch_browser_context(
                pw, "firefox", workdir, register_module=None,
                extra_prefs=dict(FF_CC_PREFS), flow_url=flow_url,
                nss_credential=cred)
            try:
                bpid = main_browser_pid(match, "firefox")
            except Exception as exc:  # noqa: BLE001 - best effort
                facts["browser_pid_error"] = str(exc)[:120]
            else:
                facts["browser_pid"] = bpid
                facts["browser_match"] = match
            try:
                context.route("**/favicon.ico",
                              lambda route: route.abort())
                page = context.pages[0] if context.pages else context.new_page()
                try:
                    facts.update(flows.make_client_cert_visit(flow_url)(page, context))
                except Exception as exc:  # noqa: BLE001 - flow failure is evidence
                    facts.update({"flow": "client_cert_visit", "loaded": False,
                                  "error": f"{type(exc).__name__}: {exc}"[:200]})
            finally:
                context.close()
    except Exception as exc:  # noqa: BLE001 - setup failure is evidence
        facts.update({"flow": "client_cert_visit", "loaded": False,
                      "error": f"{type(exc).__name__}: {exc}"[:200]})
    (workdir / "flow.json").write_text(json.dumps(facts))
    print(f"INNER flow={facts}")
    return 0


def run_firefox_cc(name: str, workdir: Path, server, credential) -> FirefoxCCResult:
    """Run one default-flags ``p11scope run`` Firefox cc visit.

    ``server`` is an open ``tls_server.FlowServer`` (CERT_REQUIRED for
    the cc cell, plain for the no-sign control twin); ``credential`` a
    ``softhsm.ClientCredential``. Returns the typed result; the caller
    owns the oracle over the report beside ``result.server``.
    """
    from profiles import playwright_cache
    workdir.mkdir(parents=True, exist_ok=True)
    os.chmod(workdir, 0o700)
    inner_work = workdir / "inner"
    inner_work.mkdir(exist_ok=True)
    home = inner_work / "home"
    home.mkdir(exist_ok=True)
    report = workdir / "report.json"
    short_tmp = Path(tempfile.mkdtemp(prefix="p11ffcc-", dir="/var/tmp"))
    os.chmod(short_tmp, 0o700)
    browsers_path = playwright_cache()
    argv = ["sudo", "-n", f"PLAYWRIGHT_BROWSERS_PATH={browsers_path}",
           str(p11scope_bin()), "run", "-o", str(report), "--",
           "/usr/bin/env", f"HOME={home}", f"TMPDIR={short_tmp}",
           sys.executable, str(Path(__file__).resolve()), "--inner",
           str(inner_work), server.url,
           str(credential.key_pem), str(credential.cert_pem)]
    try:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  check=False,
                                  timeout=OBSERVER_TIMEOUT_SECONDS)
            observer_exit: int | None = proc.returncode
            stdout, stderr = proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired as exc:
            observer_exit = None
            stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
            _reap_firefox_tree(str(inner_work / "ffprofile"))
    finally:
        shutil.rmtree(short_tmp, ignore_errors=True)
    _reown(report)
    flow: dict = {}
    flow_path = inner_work / "flow.json"
    if flow_path.exists():
        try:
            flow = json.loads(flow_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            flow = {"flow": "client_cert_visit", "loaded": False,
                    "error": f"unreadable flow.json: {exc}"[:200]}
    else:
        flow = {"flow": "client_cert_visit", "loaded": False,
                "error": "NO flow.json (inner never finished the visit)"}
    server_facts = {
        "connections": server.connections,
        "handshakes_ok": server.handshakes_ok,
        "client_certs_presented": server.client_certs_presented,
        "requests_served": server.requests_served,
        "empty_certs": server.empty_certs,
        "selection_stalls": server.selection_stalls,
        "cert_refusals": server.cert_refusals,
        "abandoned": server.abandoned,
        "handshake_failures": server.handshake_failures,
        "handshake_errors": list(server.handshake_errors),
    }
    return FirefoxCCResult(
        name=name, report_path=report,
        flow={"observer_exit": observer_exit,
              "stdout_tail": _tail(stdout),
              **flow},
        server=server_facts,
        observer_stderr_tail=_tail(stderr),
    )


if __name__ == "__main__":
    if len(sys.argv) != 7 or sys.argv[1] != "--inner":
        raise SystemExit(f"usage: {sys.argv[0]} --inner WORKDIR URL KEY CERT")
    sys.exit(inner(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
