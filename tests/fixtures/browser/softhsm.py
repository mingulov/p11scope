# SPDX-License-Identifier: GPL-3.0-or-later
"""Controlled SoftHSM provider for the G33 browser cells.

Every browser cell observes a real SoftHSM token through the browser's own
NSS PKCS#11 path. This module owns the token lifecycle: configuration,
initialization with a known PIN, and client-credential import. Seeding calls
happen outside any observation window and are never asserted on.

Required host tools: ``softhsm2-util``, ``pkcs11-tool``, ``openssl``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

#: PIN used for every seeded token (user and SO). Fixed so the harness and
#: any future auto-login shim agree; never used for anything but test tokens.
TEST_PIN = "1234"
TEST_SO_PIN = "1234"


class SoftHSMError(RuntimeError):
    """A SoftHSM setup step failed; the cell cannot run."""


def _need(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        raise SoftHSMError(f"required host tool missing: {tool}")
    return path


@dataclass(frozen=True)
class ClientCredential:
    """A file-backed client-auth credential (also imported into the token)."""

    key_pem: Path
    cert_pem: Path
    cert_der: Path


def generate_client_credential(workdir: Path, common_name: str = "g33-client") -> ClientCredential:
    """Generate a self-signed RSA client credential with openssl."""
    _need("openssl")
    workdir.mkdir(parents=True, exist_ok=True)
    key_pem = workdir / "client-key.pem"
    cert_pem = workdir / "client-cert.pem"
    cert_der = workdir / "client-cert.der"
    proc = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_pem), "-out", str(cert_pem),
            "-days", "2", "-subj", f"/CN={common_name}",
        ],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise SoftHSMError(f"openssl req failed: {proc.stderr.strip()}")
    proc = subprocess.run(
        ["openssl", "x509", "-in", str(cert_pem), "-outform", "DER", "-out", str(cert_der)],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise SoftHSMError(f"openssl x509 -outform DER failed: {proc.stderr.strip()}")
    return ClientCredential(key_pem=key_pem, cert_pem=cert_pem, cert_der=cert_der)


class SoftHSMStore:
    """One isolated SoftHSM configuration (config file + token directory)."""

    def __init__(self, root: Path, lib: Path | None = None) -> None:
        _need("softhsm2-util")
        _need("pkcs11-tool")
        self.root = root
        self.tokens = root / "tokens"
        self.tokens.mkdir(parents=True, exist_ok=True)
        self.lib = lib or self.default_lib()
        self.conf = root / "softhsm.conf"
        self.conf.write_text(
            f"directories.tokendir = {self.tokens}\nobjectstore.backend = file\n"
        )
        self.env = {"SOFTHSM2_CONF": str(self.conf)}

    @staticmethod
    def default_lib() -> Path:
        """Locate the system SoftHSM PKCS#11 module."""
        for candidate in (
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib/softhsm/libsofthsm2.so",
        ):
            if os.path.exists(candidate):
                return Path(candidate)
        raise SoftHSMError("libsofthsm2.so not found in the known system paths")

    def init_token(self, label: str, slot: int = 0,
                   user_pin: str = TEST_PIN, so_pin: str = TEST_SO_PIN) -> None:
        """Initialize the token in ``slot`` with known PINs."""
        proc = subprocess.run(
            [
                "softhsm2-util", "--init-token", "--slot", str(slot),
                "--label", label, "--pin", user_pin, "--so-pin", so_pin,
            ],
            capture_output=True, text=True, check=False, env={**os.environ, **self.env},
        )
        if proc.returncode != 0:
            raise SoftHSMError(f"softhsm2-util --init-token failed: {proc.stderr.strip()}")

    def import_key(self, token_label: str, key_pem: Path, label: str, key_id_hex: str) -> None:
        """Import a PEM private key into the token (user login)."""
        self._write_object(token_label, key_pem, "privkey", label, key_id_hex,
                           ["--login", "--pin", TEST_PIN])

    def import_cert(self, token_label: str, cert_der: Path, label: str, key_id_hex: str) -> None:
        """Import a DER certificate into the token (user login)."""
        self._write_object(token_label, cert_der, "cert", label, key_id_hex,
                           ["--login", "--pin", TEST_PIN])

    def _write_object(self, token_label: str, path: Path, obj_type: str,
                      label: str, key_id_hex: str, login_args: list[str]) -> None:
        proc = subprocess.run(
            [
                "pkcs11-tool", "--module", str(self.lib),
                "--token-label", token_label, *login_args,
                "--write-object", str(path), "--type", obj_type,
                "--label", label, "--id", key_id_hex,
            ],
            capture_output=True, text=True, check=False, env={**os.environ, **self.env},
        )
        if proc.returncode != 0:
            raise SoftHSMError(
                f"pkcs11-tool import {label} failed: {proc.stderr.strip()}")

    def seed_client_token(self, token_label: str, credential: ClientCredential,
                          slot: int = 0, key_id_hex: str = "0101") -> None:
        """Init one token and import the client key+cert under one ID."""
        self.init_token(token_label, slot=slot)
        stem = key_id_hex
        self.import_key(token_label, credential.key_pem, f"g33-key-{stem}", key_id_hex)
        self.import_cert(token_label, credential.cert_der, f"g33-cert-{stem}", key_id_hex)

    def token_slots(self) -> str:
        """Human-readable slot/token listing (for failure diagnostics)."""
        proc = subprocess.run(
            ["softhsm2-util", "--show-slots"],
            capture_output=True, text=True, check=False, env={**os.environ, **self.env},
        )
        return proc.stdout + proc.stderr
