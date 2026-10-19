# SPDX-License-Identifier: GPL-3.0-or-later
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
