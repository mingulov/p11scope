#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Standalone diagnosis: NSS-level token login, then TLS, no Playwright.

Reproduces the blocker behind the missing Firefox sign-positive cell
(README calibrated boundary 1). The token is logged in through NSS
itself (``PK11_CheckUserPassword`` via chrome-context js-ctypes on the
already-loaded ``libnss3``), which needs no PIN prompt and makes zero
direct calls into the provider module. Firefox is then driven with
Marionette alone, so no Playwright/Juggler state is involved.

Observed 2026-11-05 on Fedora 44 (softhsm-2.7.0-0.1.rc1, nss-3.130.0):
the login succeeds (``login rv=0``, ``nssLoggedIn=true``) and the
process stays alive, but the first TLS navigation afterwards kills
the Firefox parent with SIGSEGV; ``eu-stack`` on the core puts the
faulting frame in ``libsofthsm2.so`` (offset ~0xb7f17). Control runs
without the login navigate fine. Until the provider crash is fixed
upstream (or a different provider build is used), no harness login
route can produce a client-cert sign in Firefox on that host.

Run on a gate host with Playwright browsers installed:

    PLAYWRIGHT_BROWSERS_PATH=~/.cache/ms-playwright \
        python3 -I tests/fixtures/browser/ff-mari-only.py
"""
import json, os, socket, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cells, profiles, softhsm, tls_server


class Marionette:
    def __init__(self, port, timeout=30.0):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.msgid = 0
        self.hello = self._read()

    def _read(self):
        while b":" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("marionette closed")
            self.buf += chunk
        head, rest = self.buf.split(b":", 1)
        need = int(head)
        while len(rest) < need:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("marionette closed")
            rest += chunk
        self.buf = rest[need:]
        return json.loads(rest[:need])

    def cmd(self, name, params=None):
        self.msgid += 1
        msg = json.dumps([0, self.msgid, name, params or {}]).encode()
        self.sock.sendall(str(len(msg)).encode() + b":" + msg)
        return self._read()

    def script(self, script):
        return self.cmd("WebDriver:ExecuteScript",
                        {"script": script, "args": [], "newSandbox": False,
                         "sandbox": None})

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _value(resp):
    if isinstance(resp, list) and len(resp) > 3:
        for part in (resp[2], resp[3]):
            if isinstance(part, dict) and "error" in part:
                raise RuntimeError(f"marionette error: {part}")
        if isinstance(resp[3], dict):
            return resp[3].get("value")
    raise RuntimeError(f"bad marionette response: {resp!r}")


LOGIN_SCRIPT = r"""
const { ctypes } = ChromeUtils.importESModule("resource://gre/modules/ctypes.sys.mjs");
// Resolve the NSS slot description for our token via XPCOM.
const secmoddb = Cc["@mozilla.org/security/pkcs11moduledb;1"]
  .getService(Ci.nsIPKCS11ModuleDB);
const mods = await secmoddb.listModules();
let slotDesc = null;
for (const m of mods) { for (const sl of m.slots) {
  let t = null; try { t = sl.getToken(); } catch (e) {}
  if (t && t.tokenName === TOKENNAME) { slotDesc = sl.name; break; }
} if (slotDesc) break; }
if (slotDesc === null) return "token-not-found";
// Now log in through NSS so its own sessions see the login.
const procDir = Services.dirsvc.get("XCurProcD", Ci.nsIFile).path;
let nss = null;
for (const cand of [procDir + "/libnss3.so",
                    procDir.replace(/\/[^/]+$/, "") + "/libnss3.so", "libnss3.so"]) {
  try { nss = ctypes.open(cand); break; } catch (e) {}
}
if (!nss) return "libnss3-open-failed";
const PK11_FindSlotByName = nss.declare("PK11_FindSlotByName", ctypes.default_abi,
  ctypes.voidptr_t, ctypes.char.ptr);
const PK11_CheckUserPassword = nss.declare("PK11_CheckUserPassword", ctypes.default_abi,
  ctypes.int, ctypes.voidptr_t, ctypes.char.ptr);
const PK11_FreeSlot = nss.declare("PK11_FreeSlot", ctypes.default_abi,
  ctypes.void_t, ctypes.voidptr_t);
let slot = null;
for (const name of [TOKENNAME, slotDesc]) {
  slot = PK11_FindSlotByName(name);
  if (slot && !slot.isNull()) break;
}
if (!slot || slot.isNull()) return "nss-slot-not-found desc=" + slotDesc;
const srv = PK11_CheckUserPassword(slot, PINSTR);
PK11_FreeSlot(slot);
return "login rv=" + srv + " desc=" + slotDesc;
"""


def login_token(port, token_name, pin):
    last = None
    for _ in range(40):
        try:
            m = Marionette(port)
            break
        except OSError as exc:
            last = exc
            time.sleep(1.0)
    else:
        raise RuntimeError(f"marionette connect failed: {last}")
    try:
        _value(m.cmd("WebDriver:NewSession", {"capabilities": {"alwaysMatch": {}}}))
        _value(m.cmd("Marionette:SetContext", {"value": "chrome"}))
        script = (LOGIN_SCRIPT
                  .replace("TOKENNAME", json.dumps(token_name))
                  .replace("PINSTR", json.dumps(pin)))
        result = _value(m.script(f"return (async () => {{ {script} }})();"))
        print("login:", result, flush=True)
        if not (isinstance(result, str) and result.startswith("login rv=0")):
            raise RuntimeError(f"PK11_CheckUserPassword failed: {result}")
        check = (
            'const secmoddb = Cc["@mozilla.org/security/pkcs11moduledb;1"]'
            '.getService(Ci.nsIPKCS11ModuleDB);'
            'const mods = await secmoddb.listModules();'
            'for (const mm of mods) { for (const s of mm.slots) {'
            '  let t = null; try { t = s.getToken(); } catch (e) {}'
            f'  if (t && t.tokenName === {json.dumps(token_name)})'
            '    return "nssLoggedIn=" + t.isLoggedIn; } }'
            'return "nss-token-not-found";'
        )
        seen = _value(m.script(f'return (async () => {{ {check} }})();'))
        print("nss-check:", seen, flush=True)
        if seen != "nssLoggedIn=true":
            raise RuntimeError(f"NSS does not see the login: {seen}")
    finally:
        try:
            m.cmd("WebDriver:DeleteSession", {})
        except Exception:
            pass
        m.close()


def main():
    port = 39441
    work = Path(os.environ.get("FF_MARI_WORK", "/tmp/ff-mari-only"))
    work.mkdir(parents=True, exist_ok=True)
    store = softhsm.SoftHSMStore(work / "softhsm")
    cred = softhsm.generate_client_credential(work / "cred")
    store.seed_client_token("ff-mari-only", cred)
    os.environ.update(store.env)

    key, cert = tls_server.make_server_credential(work / "srv")
    profile = profiles.FirefoxProfile.create(
        work / "ffprofile", module_lib=store.lib,
        prefs={"security.default_personal_cert": "Select Automatically",
               "marionette.port": port})
    proc = subprocess.Popen(
        [str(profiles.firefox_binary()), "-profile", str(profile.path),
         "-headless", "-marionette", "-remote-allow-system-access",
         "about:blank"],
        env=dict(os.environ), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    print("firefox pid:", proc.pid, flush=True)
    try:
        mapped = cells.wait_for_mapping(proc.pid, (store.lib.name,), 30.0)
        print("mapped:", mapped, flush=True)
        with tls_server.FlowServer(cert=cert, key=key) as plain, \
             tls_server.FlowServer(cert=cert, key=key,
                                   require_client_cert=True,
                                   client_ca=cred.cert_pem) as ccflow:
            login_token(port, "ff-mari-only", softhsm.TEST_PIN)
            print("alive after login:", proc.poll() is None, flush=True)
            m = Marionette(port)
            _value(m.cmd("WebDriver:NewSession",
                         {"capabilities":
                          {"alwaysMatch": {"acceptInsecureCerts": True}}}))
            _value(m.cmd("WebDriver:SetTimeouts", {"pageLoad": 30000}))
            _value(m.cmd("Marionette:SetContext", {"value": "content"}))
            nav = m.cmd("WebDriver:Navigate", {"url": plain.url})
            print("PLAIN NAV:", json.dumps(nav)[:300], flush=True)
            print("alive after plain:", proc.poll() is None, flush=True)
            nav = m.cmd("WebDriver:Navigate", {"url": ccflow.url})
            print("CC NAV:", json.dumps(nav)[:300], flush=True)
            print("alive after cc:", proc.poll() is None, flush=True)
            m.cmd("WebDriver:DeleteSession", {})
            m.close()
            print("CCSERVER:", json.dumps({
                "connections": ccflow.connections,
                "requests_served": ccflow.requests_served,
                "cert_requests": getattr(ccflow, "cert_requests_sent", 0),
                "empty_certs": ccflow.empty_certs,
                "stalls": ccflow.selection_stalls,
                "handshakes_ok": ccflow.handshakes_ok,
            }), flush=True)
    finally:
        if proc.poll() is None:
            proc.terminate()
        print("final poll:", proc.wait(timeout=20), flush=True)


if __name__ == "__main__":
    main()

