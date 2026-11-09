# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Fresh browser profiles for the G33 browser cells.

Firefox reads ``pkcs11.txt`` from its profile directory at NSS startup;
Chromium (and Google Chrome) on Linux reads ``pkcs11.txt`` from the NSS
shared database at ``$HOME/.pki/nssdb``. Both files are written by hand in
the format ``modutil --add`` would produce, so the harness needs no
``libnss3-tools`` install. Every cell gets a fresh profile and (for
Chromium) a fresh ``HOME``; nothing is shared between cells.

Browser binaries resolve from the Playwright browser cache
(``~/.cache/ms-playwright``), newest revision wins, so the harness tracks
``playwright install`` upgrades without edits.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

PKCS11_TXT_TEMPLATE = """library={lib}
name=SoftHSM
parameters=
NSS=trustOrder=75 cipherOrder=100 slotParams={{0x1=[slotFlags=RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,PBE,ASKPW,EMPTY]}}
"""


class ProfileError(RuntimeError):
    """A browser profile could not be built."""


def playwright_cache() -> Path:
    """Root of the Playwright browser cache."""
    override = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "ms-playwright"


def _newest_revision(cache: Path, prefix: str) -> Path:
    candidates = sorted(
        (p for p in cache.glob(f"{prefix}-*") if p.is_dir()),
        key=lambda p: p.name,
    )
    if not candidates:
        raise ProfileError(f"no {prefix} browser in {cache} (run `playwright install`)")
    return candidates[-1]


def firefox_binary() -> Path:
    """Bundled Playwright Firefox (Juggler build; required for automation)."""
    binary = _newest_revision(playwright_cache(), "firefox") / "firefox" / "firefox"
    if not binary.exists():
        raise ProfileError(f"firefox binary missing: {binary}")
    return binary


def chromium_binary() -> Path:
    """Bundled full Chromium (never the headless shell for G33 cells)."""
    binary = _newest_revision(playwright_cache(), "chromium") / "chrome-linux64" / "chrome"
    if not binary.exists():
        # Older Playwright layouts used chrome-linux/.
        legacy = _newest_revision(playwright_cache(), "chromium") / "chrome-linux" / "chrome"
        if legacy.exists():
            return legacy
        raise ProfileError(f"chromium binary missing: {binary}")
    return binary


#: Password the exported PKCS#12 carries in transit. The seeded NSS
#: database itself is empty-password, which is what keeps the
#: browser's own token usable without a PIN prompt.
_NSS_P12_PASSWORD = "g33-fixture-p12"


def seed_nss_client_credential(dbdir: Path, credential, nickname: str) -> None:
    """Create an empty-password NSS DB at ``dbdir`` holding ``credential``.

    ``credential`` is a ``softhsm.ClientCredential`` (PEM key + cert).
    The browser's own softokn token then has a client key it can use
    for TLS signing without any login or PIN prompt (an
    empty-password database needs none), so client-certificate
    handshakes produce real ``C_Sign`` calls with no external token.
    Raises :class:`ProfileError` naming the missing tool or the
    failing step; never writes outside ``dbdir`` and its parent.
    """
    for tool in ("certutil", "pk12util", "openssl"):
        if shutil.which(tool) is None:
            raise ProfileError(f"{tool} missing (NSS credential seed)")
    dbdir.mkdir(parents=True, exist_ok=True)
    dbref = f"sql:{dbdir}"

    def run(argv: list[str]) -> None:
        proc = subprocess.run(argv, capture_output=True, text=True)
        if proc.returncode != 0:
            raise ProfileError(
                f"{argv[0]} failed ({proc.returncode}): "
                f"{(proc.stderr or proc.stdout)[-300:]}")

    if not (dbdir / "cert9.db").exists():
        run(["certutil", "-N", "-d", dbref, "--empty-password"])
    with tempfile.TemporaryDirectory(dir=dbdir.parent) as tmp:
        bundle = Path(tmp) / "client.p12"
        run(["openssl", "pkcs12", "-export",
             "-inkey", str(credential.key_pem),
             "-in", str(credential.cert_pem),
             "-name", nickname,
             "-out", str(bundle),
             "-password", f"pass:{_NSS_P12_PASSWORD}"])
        run(["pk12util", "-i", str(bundle), "-d", dbref,
             "-W", _NSS_P12_PASSWORD, "-K", ""])
    # The fixture credential is self-signed; without CA trust on the
    # cert itself NSS chain validation for the client usage fails
    # (`certutil -V -u C`: issuer not trusted) and browsers filter
    # the cert out of client-auth selection entirely.
    run(["certutil", "-M", "-n", nickname, "-t", "CTu,Cu,Cu", "-d", dbref])
    keys = subprocess.run(["certutil", "-K", "-d", dbref],
                          capture_output=True, text=True)
    if keys.returncode != 0 or nickname not in keys.stdout:
        raise ProfileError(
            f"seeded NSS DB does not list key {nickname!r}: "
            f"{(keys.stdout + keys.stderr)[-300:]}")


#: Where Playwright's Chrome for Testing reads managed policies on
#: Linux (from the binary's own strings; the older
#: /etc/opt/chrome and /etc/chromium paths are not read by it).
CHROME_POLICY_DIR = Path("/etc/opt/chrome_for_testing/policies/managed")

#: Loopback pattern covering any fixture TLS-server port, so a
#: fresh phase-2 server is auto-selected too (fedora certprobe16).
CHROME_LOOPBACK_PATTERN = "https://127.0.0.1:*/*"


def chrome_auto_select_policy_document(patterns: list[str]) -> str:
    """The AutoSelectCertificateForUrls managed-policy document.

    Each entry is itself a JSON string ``{"pattern": ..., "filter": {}}``
    (the policy's list-of-strings shape); the empty filter matches any
    certificate the server's CA list admits.
    """
    entries = [json.dumps({"pattern": pattern, "filter": {}})
               for pattern in patterns]
    return json.dumps({"AutoSelectCertificateForUrls": entries})


def chrome_auto_select_patterns(flow_url: str) -> list[str]:
    """Derive auto-select patterns from a launch's ``flow_url``.

    A JSON policy string (the DEMO-4 driver's form) yields its
    patterns verbatim; a plain URL yields itself plus the loopback
    wildcard (fresh-port servers); empty yields just the wildcard.
    """
    if flow_url.startswith("["):
        try:
            entries = json.loads(flow_url)
            return [str(e["pattern"]) for e in entries]
        except (ValueError, KeyError, TypeError):
            return [CHROME_LOOPBACK_PATTERN]
    if flow_url:
        return [flow_url, CHROME_LOOPBACK_PATTERN]
    return [CHROME_LOOPBACK_PATTERN]


def install_chrome_auto_select_policy(patterns: list[str], name: str,
                                      staging: Path) -> Path:
    """Install the managed policy under CHROME_POLICY_DIR (sudo -n).

    ``staging`` is a writable directory for the staged document.
    Returns the installed path; remove it with
    :func:`remove_chrome_auto_select_policy`. Raises
    :class:`ProfileError` when passwordless sudo cannot write it —
    without the policy the headless browser never presents a
    client certificate, so a silent fallback would fake the cell.
    """
    for tool in ("sudo", "install"):
        if shutil.which(tool) is None:
            raise ProfileError(f"{tool} missing (Chrome policy install)")
    staged = staging / f"{name}.json"
    staged.write_text(chrome_auto_select_policy_document(patterns))
    target = CHROME_POLICY_DIR / f"{name}.json"

    def run(argv):
        proc = subprocess.run(argv, capture_output=True, text=True)
        if proc.returncode != 0:
            raise ProfileError(
                f"chrome policy install failed ({' '.join(argv)}): "
                f"{(proc.stdout + proc.stderr)[-300:]}")

    run(["sudo", "-n", "install", "-d", "-m", "0755", str(CHROME_POLICY_DIR)])
    run(["sudo", "-n", "install", "-m", "0644", str(staged), str(target)])
    return target


def remove_chrome_auto_select_policy(target: Path) -> None:
    """Best-effort removal of an installed policy file."""
    subprocess.run(["sudo", "-n", "rm", "-f", str(target)],
                   capture_output=True, text=True)


@dataclass
class FirefoxProfile:
    """A fresh Firefox profile directory, optionally with a PKCS#11 module."""

    path: Path

    @classmethod
    def create(cls, root: Path, module_lib: Path | None = None,
               prefs: dict | None = None) -> "FirefoxProfile":
        root.mkdir(parents=True, exist_ok=True)
        if module_lib is not None:
            (root / "pkcs11.txt").write_text(
                PKCS11_TXT_TEMPLATE.format(lib=module_lib))
        if prefs:
            lines = [f'user_pref({json.dumps(k)}, {json.dumps(v)});'
                     for k, v in prefs.items()]
            (root / "prefs.js").write_text("\n".join(lines) + "\n")
        return cls(path=root)


@dataclass
class ChromiumHome:
    """A fresh HOME carrying the NSS shared DB, optionally with a module."""

    path: Path

    @classmethod
    def create(cls, root: Path, module_lib: Path | None = None) -> "ChromiumHome":
        nssdb = root / ".pki" / "nssdb"
        nssdb.mkdir(parents=True, exist_ok=True)
        if module_lib is not None:
            (nssdb / "pkcs11.txt").write_text(
                PKCS11_TXT_TEMPLATE.format(lib=module_lib))
        return cls(path=root)
