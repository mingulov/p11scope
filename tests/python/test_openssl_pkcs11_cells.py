# SPDX-License-Identifier: GPL-3.0-or-later
"""OpenSSL through PKCS#11 cells: real openssl/pkcs11-tool/p11tool traffic.

Each test drives a real client (openssl 3 pkcs11-provider, legacy engine,
p11-kit-proxy, pkcs11-tool, p11tool) against a controlled SoftHSM token and
asserts p11scope observes it: provider file, C_Sign/C_SignInit (and
multi-part Update/Final) counts, mechanisms, caller, and no PIN in output.

Prerequisites (named on skip): P11SCOPE_BIN, passwordless sudo, SoftHSM
tooling, openssl, and per-cell provider/engine packages. Set
P11SCOPE_OPENSSL_STRICT=1 to turn skips into failures (CI).

Measured behavior (2026-11-08, do not re-assume):
- ``p11scope run`` observes only the owned child, not descendants: a sh
  loop spawning openssl children hides all calls. Every run cell therefore
  owns one client invocation directly (via /usr/bin/env, no shell), and
  N-sign loops aggregate N sequential runs.
- Metrics reports carry no caller names and no mechanisms (aggregate-only);
  profile reports need --manifest for mechanisms. Counts come from run
  (metrics or profile); mechanisms from run --mode profile --manifest;
  caller names from inventory (callers[].image.exe.path) and trace only.
- ``openssl dgst -sign`` uses multi-part C_SignInit/Update/Final (one each
  per sign for the fixed 144-byte input); pkcs11-tool --sign uses one-shot
  C_Sign twice per sign (length probe + data). Assertions match each
  client's shape with the reason written at the call site.
- pkcs11-provider 1.2.0 needs ``no-deinit`` with SoftHSM 2.6.1 (teardown
  segfault otherwise; sign path unaffected). s_server needs stdin=PIPE.
- ``openssl speed -provider pkcs11`` touches the token (ephemeral RSA
  keygen) but its op counts are timing-dependent (ops per N seconds), so
  it is a capability probe, not an exact-count cell. p11perftest needs
  Botan 2 (absent on ubuntu-26.04; Fedora has the package uninstalled) —
  documented, not a cell. NSS is covered by qualify-real-providers.sh.
"""

import functools
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

STRICT = os.environ.get("P11SCOPE_OPENSSL_STRICT") == "1"
TEST_PIN = "Ossl07048291"
N_SIGNS = 6
K_HANDSHAKES = 3
PROVIDER_QUIRKS = "no-deinit"


class CellError(RuntimeError):
    """A cell prerequisite is missing (named reason)."""


def p11scope_bin() -> Path:
    raw = os.environ.get("P11SCOPE_BIN")
    if not raw:
        raise CellError("P11SCOPE_BIN is not set (path to the p11scope binary under test)")
    binary = Path(raw)
    if not (binary.exists() and os.access(binary, os.X_OK)):
        raise CellError(f"P11SCOPE_BIN is not executable: {binary}")
    return binary


def discover_bin() -> Path:
    """p11scope-discover beside P11SCOPE_BIN (for --manifest cells)."""
    sibling = p11scope_bin().parent / "p11scope-discover"
    if sibling.exists() and os.access(sibling, os.X_OK):
        return sibling
    raw = os.environ.get("P11SCOPE_DISCOVER_BIN")
    if raw and Path(raw).exists() and os.access(raw, os.X_OK):
        return Path(raw)
    raise CellError("p11scope-discover not beside P11SCOPE_BIN (needed for --manifest)")


def check_sudo() -> None:
    proc = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False)
    if proc.returncode != 0:
        raise CellError("`sudo -n true` failed: cells need passwordless sudo for p11scope")


def probe_module(candidates, env_override=None) -> Path:
    if env_override:
        extra = os.environ.get(env_override)
        if extra:
            if os.path.exists(extra):
                return Path(extra)
            raise CellError(f"{env_override}={extra} does not exist")
    for candidate in candidates:
        if os.path.exists(candidate):
            return Path(candidate)
    raise CellError(f"module not found in probed paths: {candidates[0]} (+{len(candidates)-1} more)")


SOFTHSM_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
)
PROVIDER_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so",
    "/usr/lib64/ossl-modules/pkcs11.so",
)
ENGINE_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so",
    "/usr/lib64/engines-3/pkcs11.so",
)
PROXY_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so",
    "/usr/lib64/p11-kit-proxy.so",
)


def check_openssl3() -> str:
    proc = subprocess.run(["openssl", "version"], capture_output=True, text=True, check=False)
    line = (proc.stdout + proc.stderr).strip().splitlines()
    line = line[0] if line else ""
    if proc.returncode != 0 or "OpenSSL 3" not in line:
        raise CellError(f"openssl 3 required, got: {line!r}")
    return line


def gate(*tools, need_provider=False, need_engine=False, need_proxy=False,
         need_manifest=False):
    def decorator(test):
        @functools.wraps(test)
        def wrapper(self):
            try:
                p11scope_bin()
                check_sudo()
                check_openssl3()
                for tool in ("softhsm2-util", "pkcs11-tool", "openssl", *tools):
                    if shutil.which(tool) is None:
                        raise CellError(f"required host tool missing: {tool}")
                probe_module(SOFTHSM_CANDIDATES, "P11SCOPE_TEST_SOFTHSM_SO")
                if need_provider:
                    try:
                        probe_module(PROVIDER_CANDIDATES, "P11SCOPE_TEST_PROVIDER_SO")
                    except CellError:
                        raise CellError("pkcs11-provider missing (Debian/Ubuntu: pkcs11-provider; Fedora: pkcs11-provider)")
                if need_engine:
                    try:
                        probe_module(ENGINE_CANDIDATES, "P11SCOPE_TEST_ENGINE_SO")
                    except CellError:
                        raise CellError("pkcs11 engine missing (Debian/Ubuntu: libengine-pkcs11-openssl; Fedora: openssl-pkcs11)")
                if need_proxy:
                    probe_module(PROXY_CANDIDATES, "P11SCOPE_TEST_PROXY_SO")
                if need_manifest:
                    discover_bin()
            except CellError as exc:
                if STRICT:
                    raise AssertionError(f"strict mode requires this cell: {exc}") from exc
                self.skipTest(f"openssl cell prerequisite missing: {exc}")
            return test(self)
        return wrapper
    return decorator


class SoftHSMStore:
    def __init__(self, root: Path, token_label: str, pin: str = TEST_PIN) -> None:
        self.root = root
        self.tokens = root / "tokens"
        self.tokens.mkdir(parents=True, exist_ok=True)
        self.lib = probe_module(SOFTHSM_CANDIDATES, "P11SCOPE_TEST_SOFTHSM_SO")
        self.conf = root / "softhsm.conf"
        self.conf.write_text(f"directories.tokendir = {self.tokens}\nobjectstore.backend = file\n")
        self.env = {"SOFTHSM2_CONF": str(self.conf)}
        self.label = token_label
        self.pin = pin
        self._init_token()
        self._keypairgen("rsa:2048", "ossl-rsa", "01")
        self._keypairgen("EC:prime256v1", "ossl-ec", "02")

    def _run(self, argv, **kw):
        kw.setdefault("stdin", subprocess.DEVNULL)
        kw.setdefault("timeout", 60)
        return subprocess.run(argv, capture_output=True, text=True, check=False,
                              env=dict(os.environ, **self.env), **kw)

    def _init_token(self) -> None:
        proc = self._run(["softhsm2-util", "--init-token", "--slot", "0",
                          "--label", self.label, "--pin", self.pin, "--so-pin", self.pin])
        if proc.returncode != 0:
            raise CellError(f"softhsm2-util --init-token failed: {proc.stderr.strip()}")

    def _keypairgen(self, key_type: str, label: str, key_id: str) -> None:
        proc = self._run(["pkcs11-tool", "--module", str(self.lib), "--login",
                          "--pin", self.pin, "--keypairgen", "--key-type", key_type,
                          "--label", label, "--id", key_id])
        if proc.returncode != 0:
            raise CellError(f"pkcs11-tool --keypairgen {label} failed: {proc.stderr.strip()}")

    def key_uri(self, label: str, pin: str | None = None) -> str:
        uri = f"pkcs11:token={self.label};object={label};type=private"
        if pin is not None:
            uri += f";pin-value={pin}"
        return uri


def write_provider_conf(path: Path, provider_so: Path, pkcs11_module: Path, pin: str = TEST_PIN) -> Path:
    path.write_text(
        "openssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\n"
        "[provider_sect]\npkcs11 = pkcs11_sect\ndefault = default_sect\n[pkcs11_sect]\n"
        f"module = {provider_so}\npkcs11-module-path = {pkcs11_module}\n"
        f"pkcs11-module-token-pin = {pin}\npkcs11-module-quirks = {PROVIDER_QUIRKS}\n"
        "activate = 1\n[default_sect]\nactivate = 1\n")
    return path


def write_engine_conf(path: Path, engine_so: Path, pkcs11_module: Path, pin: str = TEST_PIN) -> Path:
    path.write_text(
        "openssl_conf = openssl_init\n[openssl_init]\nengines = engine_sect\n"
        "[engine_sect]\npkcs11 = pkcs11_sect\n[pkcs11_sect]\nengine_id = pkcs11\n"
        f"dynamic_path = {engine_so}\nMODULE_PATH = {pkcs11_module}\nPIN = {pin}\ninit = 1\n")
    return path


def trusted_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def reown(path: Path) -> None:
    if not path.exists():
        return
    uid, gid = os.getuid(), os.getgid()
    subprocess.run(["sudo", "-n", "chown", f"{uid}:{gid}", str(path)],
                   capture_output=True, check=False)


def make_manifest(module: Path, out: Path) -> Path:
    proc = subprocess.run([str(discover_bin()), "--module", str(module), "-o", str(out)],
                          capture_output=True, text=True, check=False,
                          stdin=subprocess.DEVNULL, timeout=120)
    if proc.returncode != 0 or not out.exists():
        raise CellError(f"p11scope-discover failed: {(proc.stderr or '')[-200:]}")
    return out


def run_single(binary: Path, module: Path, workdir: Path, child_env: dict, child_argv: list,
               mode: str = "profile", manifest: Path | None = None, duration: int = 60) -> tuple:
    """One ``p11scope run`` owning one client invocation. Returns (report, exit, out, err)."""
    trusted_dir(workdir)
    report = workdir / "observed-profile.json"
    argv = ["sudo", "-n"] + [f"{k}={v}" for k, v in child_env.items()]
    argv += [str(binary), "run", "--module", str(module)]
    if manifest is not None:
        argv += ["--manifest", str(manifest)]
    argv += ["-o", str(report), "--mode", mode, "--pause", "auto",
            "--duration", str(duration), "--kill-on-timeout",
            "--", "/usr/bin/env", *child_argv]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=duration + 120,
                            stdin=subprocess.DEVNULL)
    reown(report)
    return report, proc.returncode, proc.stdout or "", proc.stderr or ""


def function_counts(report: dict) -> dict:
    counts: dict = {}
    for row in report.get("functions", []):
        calls = row.get("calls", 0)
        for name in row.get("names", []):
            counts[name] = counts.get(name, 0) + (calls if isinstance(calls, int) else 0)
    return counts


def provider_paths(report: dict) -> set:
    paths: set = set()
    for entry in report.get("capture", {}).get("modules", []) or []:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            paths.add(entry["path"])
    for entry in report.get("evidence", {}).get("discovery", []) or []:
        if isinstance(entry, dict):
            for field in ("path",):
                if isinstance(entry.get(field), str):
                    paths.add(entry[field])
            for obj in entry.get("objects", []) or []:
                if isinstance(obj, dict) and isinstance(obj.get("path"), str):
                    paths.add(obj["path"])
    return paths


def inventory_callers(report: dict) -> set:
    names: set = set()
    for entry in report.get("callers", []) or []:
        exe = (entry.get("image", {}) or {}).get("exe", {}) or {}
        path = exe.get("path")
        if isinstance(path, str) and path:
            names.add(path)
            names.add(Path(path).name)
    return names


def inventory_modules(report: dict) -> set:
    paths: set = set()
    for entry in report.get("modules", []) or []:
        for path in entry.get("paths", []) or []:
            if isinstance(path, str):
                paths.add(path)
    return paths


def assert_no_pin(testcase: unittest.TestCase, pin: str, *blobs: str) -> None:
    for index, blob in enumerate(blobs):
        testcase.assertNotIn(pin, blob or "", f"token PIN appears in observer output blob {index}")


class OpensslPkcs11Cells(unittest.TestCase):
    maxDiff = 4096

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="ossl-p11-"))
        self.addCleanup(shutil.rmtree, self.work, True)

    def seed(self, label: str) -> SoftHSMStore:
        return SoftHSMStore(self.work / "softhsm", label)

    def data_file(self) -> Path:
        path = self.work / "data.bin"
        if not path.exists():
            path.write_bytes(b"openssl-pkcs11 cell test data 0123456789" * 4)
        return path

    def dgst_argv(self, store: SoftHSMStore, key_label: str, sig: Path, extra=()) -> list:
        # PIN in URI as well as config: provider 1.1 (Fedora) prompts without it.
        return ["openssl", "dgst", "-sha256", "-sign", store.key_uri(key_label, store.pin),
                *extra, "-out", str(sig), str(self.data_file())]

    def aggregate_runs(self, name: str, binary: Path, module: Path, store: SoftHSMStore,
                       child_env: dict, make_argv, count: int, mode: str,
                       manifest: Path | None) -> tuple:
        """N sequential single-shot runs; returns (totals, texts, stderrs).

        Each run owns exactly one client invocation (run tracks no
        descendants). Totals sum C_* calls across the N reports.
        """
        totals: dict = {}
        texts: list = []
        stderrs: list = []
        for index in range(count):
            sig = self.work / f"{name}-{index}.sig"
            report, exit_code, out, err = run_single(
                binary, module, self.work / f"obs-{name}-{index}", child_env,
                make_argv(sig), mode=mode, manifest=manifest)
            self.assertEqual(exit_code, 0, f"{name}[{index}]: observer exit: {err[-400:]}")
            self.assertTrue(report.exists(), f"{name}[{index}]: missing report")
            text = report.read_text()
            texts.append(text)
            stderrs.append(err)
            for key, value in function_counts(json.loads(text)).items():
                totals[key] = totals.get(key, 0) + value
        return totals, texts, stderrs

    def check_provider_and_pin(self, name: str, texts: list, stderrs: list, module_substr: str):
        for text in texts:
            paths = provider_paths(json.loads(text))
            self.assertTrue(any(module_substr in p for p in paths),
                            f"{name}: provider {module_substr} not in {sorted(paths)}")
        for text, err in zip(texts, stderrs):
            assert_no_pin(self, TEST_PIN, text, err)

    @gate(need_provider=True, need_manifest=True)
    def test_provider_rsa_sign_loop(self):
        """Provider RSA: N dgst signs, multi-part Init/Update/Final each.

        openssl dgst hashes in software and drives multi-part sign on the
        token (measured: 1 Init + 1 Update + 1 Final per sign for the fixed
        144-byte input); one-shot C_Sign stays 0. Mechanism CKM_SHA256_RSA_PKCS.
        """
        binary = p11scope_bin()
        store = self.seed("ossl-rsa-cell")
        provider_so = probe_module(PROVIDER_CANDIDATES, "P11SCOPE_TEST_PROVIDER_SO")
        conf = write_provider_conf(self.work / "openssl.cnf", provider_so, store.lib)
        manifest = make_manifest(store.lib, self.work / "manifest.json")
        child_env = {"SOFTHSM2_CONF": str(store.conf), "OPENSSL_CONF": str(conf)}
        totals, texts, errs = self.aggregate_runs(
            "provider-rsa", binary, store.lib, store, child_env,
            lambda sig: self.dgst_argv(store, "ossl-rsa", sig), N_SIGNS,
            mode="profile", manifest=manifest)
        self.assertEqual(totals.get("C_SignInit", 0), N_SIGNS)
        self.assertEqual(totals.get("C_SignUpdate", 0), N_SIGNS)
        self.assertEqual(totals.get("C_SignFinal", 0), N_SIGNS)
        self.assertEqual(totals.get("C_Sign", 0), 0)
        for text in texts:
            mechs = json.loads(text).get("mechanisms", [])
            ids = {m.get("mechanism") for m in mechs}
            self.assertIn(0x40, ids, f"CKM_SHA256_RSA_PKCS (0x40) missing: {mechs}")
        self.check_provider_and_pin("provider-rsa", texts, errs, "libsofthsm2.so")

    @gate(need_provider=True, need_manifest=True)
    def test_provider_ec_sign_loop(self):
        """Provider EC P-256: N dgst signs (Init exact, ECDSA mechanism)."""
        binary = p11scope_bin()
        store = self.seed("ossl-ec-cell")
        provider_so = probe_module(PROVIDER_CANDIDATES, "P11SCOPE_TEST_PROVIDER_SO")
        conf = write_provider_conf(self.work / "openssl.cnf", provider_so, store.lib)
        manifest = make_manifest(store.lib, self.work / "manifest.json")
        child_env = {"SOFTHSM2_CONF": str(store.conf), "OPENSSL_CONF": str(conf)}
        totals, texts, errs = self.aggregate_runs(
            "provider-ec", binary, store.lib, store, child_env,
            lambda sig: self.dgst_argv(store, "ossl-ec", sig), N_SIGNS,
            mode="profile", manifest=manifest)
        self.assertEqual(totals.get("C_SignInit", 0), N_SIGNS)
        self.assertGreaterEqual(totals.get("C_Sign", 0) + totals.get("C_SignFinal", 0), N_SIGNS,
                                f"no sign completions (totals={totals})")
        joined = "\n".join(texts)
        self.assertIn("0x1041", joined, "CKM_ECDSA (0x1041) missing from mechanism ids")
        self.check_provider_and_pin("provider-ec", texts, errs, "libsofthsm2.so")

    @gate(need_provider=True, need_manifest=True)
    def test_provider_metrics_mode(self):
        """Metrics lane: counts without mechanisms (aggregate-only by design)."""
        binary = p11scope_bin()
        store = self.seed("ossl-metrics")
        provider_so = probe_module(PROVIDER_CANDIDATES, "P11SCOPE_TEST_PROVIDER_SO")
        conf = write_provider_conf(self.work / "openssl.cnf", provider_so, store.lib)
        child_env = {"SOFTHSM2_CONF": str(store.conf), "OPENSSL_CONF": str(conf)}
        totals, texts, errs = self.aggregate_runs(
            "provider-metrics", binary, store.lib, store, child_env,
            lambda sig: self.dgst_argv(store, "ossl-rsa", sig), 3,
            mode="metrics", manifest=None)
        self.assertEqual(totals.get("C_SignInit", 0), 3)
        self.assertEqual(totals.get("C_SignFinal", 0), 3)
        self.check_provider_and_pin("provider-metrics", texts, errs, "libsofthsm2.so")

    @gate(need_engine=True, need_manifest=True)
    def test_engine_rsa_sign_loop(self):
        """Legacy engine RSA: N signs via -engine pkcs11 -keyform engine."""
        binary = p11scope_bin()
        store = self.seed("ossl-eng-cell")
        engine_so = probe_module(ENGINE_CANDIDATES, "P11SCOPE_TEST_ENGINE_SO")
        conf = write_engine_conf(self.work / "openssl.cnf", engine_so, store.lib)
        manifest = make_manifest(store.lib, self.work / "manifest.json")
        child_env = {"SOFTHSM2_CONF": str(store.conf), "OPENSSL_CONF": str(conf)}
        totals, texts, errs = self.aggregate_runs(
            "engine-rsa", binary, store.lib, store, child_env,
            lambda sig: self.dgst_argv(store, "ossl-rsa", sig,
                                       extra=("-engine", "pkcs11", "-keyform", "engine")),
            N_SIGNS, mode="profile", manifest=manifest)
        self.assertEqual(totals.get("C_SignInit", 0), N_SIGNS)
        self.assertGreaterEqual(totals.get("C_Sign", 0) + totals.get("C_SignFinal", 0), N_SIGNS,
                                f"no sign completions (totals={totals})")
        self.check_provider_and_pin("engine-rsa", texts, errs, "libsofthsm2.so")

    @gate(need_provider=True, need_proxy=True, need_manifest=True)
    def test_proxy_rsa_sign_loop(self):
        """Provider pointed at p11-kit-proxy with SoftHSM registered."""
        binary = p11scope_bin()
        store = self.seed("ossl-proxy-cell")
        provider_so = probe_module(PROVIDER_CANDIDATES, "P11SCOPE_TEST_PROVIDER_SO")
        proxy_so = probe_module(PROXY_CANDIDATES, "P11SCOPE_TEST_PROXY_SO")
        conf = write_provider_conf(self.work / "openssl.cnf", provider_so, proxy_so)
        manifest = make_manifest(proxy_so, self.work / "manifest.json")
        child_env = {"SOFTHSM2_CONF": str(store.conf), "OPENSSL_CONF": str(conf)}
        totals, texts, errs = self.aggregate_runs(
            "proxy-rsa", binary, proxy_so, store, child_env,
            lambda sig: self.dgst_argv(store, "ossl-rsa", sig), N_SIGNS,
            mode="profile", manifest=manifest)
        self.assertGreaterEqual(totals.get("C_SignInit", 0), N_SIGNS,
                                f"proxy inits (totals={totals})")
        for text in texts:
            paths = provider_paths(json.loads(text))
            self.assertTrue(any("p11-kit-proxy" in p for p in paths),
                            f"proxy missing from {sorted(paths)}")
        for text, err in zip(texts, errs):
            assert_no_pin(self, TEST_PIN, text, err)

    @gate(need_provider=True, need_manifest=True)
    def test_provider_tls_handshakes(self):
        """s_server (owned) with token key + K s_client handshakes.

        run owns s_server directly (descendants untracked); the harness
        drives K s_client handshakes concurrently. Each TLS 1.3 handshake
        signs once (CertificateVerify); resumption makes exact counts
        nondeterministic, so >= K with this reason.
        """
        binary = p11scope_bin()
        store = self.seed("ossl-tls-cell")
        provider_so = probe_module(PROVIDER_CANDIDATES, "P11SCOPE_TEST_PROVIDER_SO")
        conf = write_provider_conf(self.work / "openssl.cnf", provider_so, store.lib)
        manifest = make_manifest(store.lib, self.work / "manifest.json")
        srv_env = dict(os.environ, SOFTHSM2_CONF=str(store.conf), OPENSSL_CONF=str(conf))
        cert = self.work / "srv-cert.pem"
        proc = subprocess.run(
            ["openssl", "req", "-x509", "-new", "-key", store.key_uri("ossl-rsa", store.pin),
             "-out", str(cert), "-days", "2", "-subj", "/CN=ossl-tls"],
            capture_output=True, text=True, check=False, env=srv_env,
            stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual(proc.returncode, 0, f"req failed: {proc.stderr[-300:]}")
        port = 18531
        trusted_dir(self.work / "obs")
        report = self.work / "obs" / "observed-profile.json"
        child_env = {"SOFTHSM2_CONF": str(store.conf), "OPENSSL_CONF": str(conf)}
        argv = ["sudo", "-n"] + [f"{k}={v}" for k, v in child_env.items()]
        argv += [str(binary), "run", "--module", str(store.lib),
                "--manifest", str(manifest), "-o", str(report),
                "--mode", "profile", "--pause", "auto", "--duration", "90",
                "--kill-on-timeout", "--", "/usr/bin/env",
                "openssl", "s_server", "-accept", f"127.0.0.1:{port}",
                "-cert", str(cert), "-key", store.key_uri("ossl-rsa", store.pin),
                "-naccept", str(K_HANDSHAKES)]
        server = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, bufsize=1)
        time.sleep(6)
        self.assertIsNone(server.poll(), "observer/s_server exited before handshakes")
        cli_env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
        ok = 0
        for _ in range(K_HANDSHAKES):
            try:
                cli = subprocess.run(
                    ["openssl", "s_client", "-connect", f"127.0.0.1:{port}",
                     "-CAfile", str(cert), "-verify_return_error"],
                    input="Q\n", capture_output=True, text=True, timeout=15, env=cli_env)
                if cli.returncode == 0 and "Verify return code: 0" in (cli.stdout + cli.stderr):
                    ok += 1
            except Exception:
                pass
        try:
            out, err = server.communicate(input="Q\n", timeout=60)
        except subprocess.TimeoutExpired:
            server.kill()
            out, err = server.communicate()
        reown(report)
        self.assertEqual(ok, K_HANDSHAKES, f"only {ok}/{K_HANDSHAKES} handshakes ok")
        self.assertTrue(report.exists(), "missing TLS report")
        text = report.read_text()
        totals = function_counts(json.loads(text))
        inits = totals.get("C_SignInit", 0)
        completions = totals.get("C_Sign", 0) + totals.get("C_SignFinal", 0)
        self.assertGreaterEqual(inits, K_HANDSHAKES, f"tls inits (totals={totals})")
        self.assertGreaterEqual(completions, K_HANDSHAKES, f"tls completions (totals={totals})")
        assert_no_pin(self, TEST_PIN, text, err)

    @gate(need_provider=True)
    def test_provider_wrong_pin_twin(self):
        """Failure twin: wrong PIN fails cleanly; no PIN in any output."""
        binary = p11scope_bin()
        store = self.seed("ossl-fail-cell")
        store.pin = "wrong0000"
        provider_so = probe_module(PROVIDER_CANDIDATES, "P11SCOPE_TEST_PROVIDER_SO")
        conf = write_provider_conf(self.work / "openssl.cnf", provider_so, store.lib, pin="wrong0000")
        child_env = {"SOFTHSM2_CONF": str(store.conf), "OPENSSL_CONF": str(conf)}
        report, exit_code, out, err = run_single(
            binary, store.lib, self.work / "obs", child_env,
            self.dgst_argv(store, "ossl-rsa", self.work / "fail.sig"),
            mode="profile", manifest=None)
        self.assertNotEqual(exit_code, 0, "wrong-PIN workload must fail")
        if report.exists():
            text = report.read_text()
            assert_no_pin(self, TEST_PIN, text, err)
            assert_no_pin(self, "wrong0000", text, err)

    def run_inventory_on_server(self, store: SoftHSMStore, conf: Path, scope_args: list,
                                duration: str = "12s") -> tuple:
        """s_server under inventory scope; returns (report_text, stdout, stderr)."""
        binary = p11scope_bin()
        srv_env = dict(os.environ, SOFTHSM2_CONF=str(store.conf), OPENSSL_CONF=str(conf))
        cert = self.work / "inv-cert.pem"
        if not cert.exists():
            proc = subprocess.run(
                ["openssl", "req", "-x509", "-new", "-key", store.key_uri("ossl-rsa", store.pin),
                 "-out", str(cert), "-days", "2", "-subj", "/CN=ossl-inv"],
                capture_output=True, text=True, check=False, env=srv_env,
                stdin=subprocess.DEVNULL, timeout=60)
            self.assertEqual(proc.returncode, 0, f"req failed: {proc.stderr[-200:]}")
        port = 18532 if scope_args[0] == "--pid" else 18533
        srv = subprocess.Popen(
            ["openssl", "s_server", "-accept", f"127.0.0.1:{port}", "-cert", str(cert),
             "-key", store.key_uri("ossl-rsa", store.pin), "-naccept", "4"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=srv_env, text=True, bufsize=1)
        self.addCleanup(lambda: (srv.terminate(), srv.wait()))
        time.sleep(3)
        self.assertIsNone(srv.poll(), "s_server exited before inventory")
        trusted_dir(self.work / "obs")
        report = self.work / "obs" / "inventory.json"
        argv = ["sudo", "-n", str(binary), "inventory", *scope_args]
        if scope_args[0] == "--pid":
            argv += [str(srv.pid)]
        argv += ["--module", str(store.lib), "--duration", duration, "-o", str(report)]
        inv = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(2)
        cli_env = {k: v for k, v in os.environ.items() if k != "OPENSSL_CONF"}
        for _ in range(2):
            try:
                subprocess.run(
                    ["openssl", "s_client", "-connect", f"127.0.0.1:{port}",
                     "-CAfile", str(cert)],
                    input="Q\n", capture_output=True, text=True, timeout=10, env=cli_env)
            except Exception:
                pass
        try:
            out, err = inv.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            inv.kill()
            out, err = inv.communicate()
        try:
            srv.stdin.write("Q\n")
            srv.stdin.flush()
        except Exception:
            pass
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except Exception:
            pass
        reown(report)
        self.assertEqual(inv.returncode, 0, f"inventory exit: {(err or '')[-400:]}")
        text = report.read_text() if report.exists() else ""
        return text, out or "", err or ""

    @gate(need_provider=True)
    def test_inventory_pid_sees_openssl(self):
        """inventory --pid: caller openssl, provider SoftHSM, entries observed."""
        store = self.seed("ossl-invpid")
        provider_so = probe_module(PROVIDER_CANDIDATES, "P11SCOPE_TEST_PROVIDER_SO")
        conf = write_provider_conf(self.work / "openssl.cnf", provider_so, store.lib)
        text, out, err = self.run_inventory_on_server(store, conf, ["--pid"])
        parsed = json.loads(text)
        callers = inventory_callers(parsed)
        self.assertIn("openssl", callers, f"caller openssl missing: {sorted(callers)}")
        mods = inventory_modules(parsed)
        self.assertTrue(any("libsofthsm2" in m for m in mods), f"provider missing: {mods}")
        assert_no_pin(self, TEST_PIN, text, out, err)

    @gate(need_provider=True)
    def test_inventory_system_sees_openssl(self):
        """inventory --system: caller openssl observed machine-wide."""
        store = self.seed("ossl-invsys")
        provider_so = probe_module(PROVIDER_CANDIDATES, "P11SCOPE_TEST_PROVIDER_SO")
        conf = write_provider_conf(self.work / "openssl.cnf", provider_so, store.lib)
        text, out, err = self.run_inventory_on_server(store, conf, ["--system"])
        parsed = json.loads(text)
        callers = inventory_callers(parsed)
        self.assertIn("openssl", callers, f"caller openssl missing: {sorted(callers)[:10]}")
        assert_no_pin(self, TEST_PIN, text, out, err)

    @gate(need_manifest=True)
    def test_pkcs11_tool_sign_loop(self):
        """pkcs11-tool --sign: N invocations; Init==N, one-shot Sign==2N.

        Each --sign probes length then reads data (measured: 2 C_Sign per
        C_SignInit), so the exact counts are Init==N and Sign==2N.
        """
        binary = p11scope_bin()
        store = self.seed("ossl-p11tool")
        data = self.data_file()
        manifest = make_manifest(store.lib, self.work / "manifest.json")
        child_env = {"SOFTHSM2_CONF": str(store.conf)}

        def make_argv(sig: Path) -> list:
            return ["pkcs11-tool", "--module", str(store.lib), "--login",
                    "--pin", TEST_PIN, "--sign", "--mechanism", "SHA256-RSA-PKCS",
                    "--id", "01", "--input-file", str(data), "--output-file", str(sig)]

        totals, texts, errs = self.aggregate_runs(
            "p11tool-sign", binary, store.lib, store, child_env, make_argv,
            N_SIGNS, mode="profile", manifest=manifest)
        self.assertEqual(totals.get("C_SignInit", 0), N_SIGNS)
        self.assertEqual(totals.get("C_Sign", 0), 2 * N_SIGNS)
        self.check_provider_and_pin("p11tool-sign", texts, errs, "libsofthsm2.so")

    @gate(need_manifest=True)
    def test_pkcs11_tool_selftest(self):
        """pkcs11-tool --test functional self-test (lower bounds).

        --test aborts with exit 1 on the first mechanism the token keys
        do not support (measured: C_DecryptInit CKR_ARGUMENTS_BAD on
        sign-only keys); the cell asserts observation (calls seen, no PIN),
        not tool success.
        """
        binary = p11scope_bin()
        store = self.seed("ossl-selftest")
        manifest = make_manifest(store.lib, self.work / "manifest.json")
        child_env = {"SOFTHSM2_CONF": str(store.conf)}
        report, exit_code, out, err = run_single(
            binary, store.lib, self.work / "obs", child_env,
            ["pkcs11-tool", "--module", str(store.lib), "--login",
             "--pin", TEST_PIN, "--test"],
            mode="profile", manifest=manifest)
        self.assertIn(exit_code, (0, 1), f"selftest observer exit: {err[-400:]}")
        self.assertTrue(report.exists(), "selftest missing report")
        text = report.read_text()
        total = sum(function_counts(json.loads(text)).values())
        self.assertGreater(total, 0, "selftest observed no calls")
        assert_no_pin(self, TEST_PIN, text, err)

    @gate("p11tool", need_manifest=True)
    def test_p11tool_test_sign(self):
        """GnuTLS p11tool --test-sign functional cell."""
        binary = p11scope_bin()
        store = self.seed("ossl-p11tool2")
        manifest = make_manifest(store.lib, self.work / "manifest.json")
        child_env = {"SOFTHSM2_CONF": str(store.conf)}
        uri = f"pkcs11:token={store.label};object=ossl-rsa;type=private;pin-value={TEST_PIN}"
        report, exit_code, out, err = run_single(
            binary, store.lib, self.work / "obs", child_env,
            ["p11tool", "--provider", str(store.lib), "--login", "--test-sign", uri],
            mode="profile", manifest=manifest)
        self.assertEqual(exit_code, 0, f"p11tool observer exit: {err[-400:]}")
        text = report.read_text()
        totals = function_counts(json.loads(text))
        self.assertGreaterEqual(totals.get("C_SignInit", 0), 1, f"no SignInit (totals={totals})")
        assert_no_pin(self, TEST_PIN, text, err)


class ToolCapabilities(unittest.TestCase):
    def test_openssl_speed_touches_token_for_keygen(self):
        """openssl speed DOES touch the token (ephemeral keygen), but counts
        are timing-dependent (ops per N seconds vary by host), so it is not
        a p11scope exact-count cell. Sign-loop cells cover token signs."""
        try:
            provider_so = probe_module(PROVIDER_CANDIDATES, "P11SCOPE_TEST_PROVIDER_SO")
            softhsm = probe_module(SOFTHSM_CANDIDATES, "P11SCOPE_TEST_SOFTHSM_SO")
        except CellError as exc:
            if STRICT:
                raise AssertionError(f"strict mode requires this probe: {exc}") from exc
            self.skipTest(str(exc))
        work = Path(tempfile.mkdtemp(prefix="ossl-speed-"))
        self.addCleanup(shutil.rmtree, work, True)
        store = SoftHSMStore(work / "softhsm", "ossl-speed-probe")
        conf = write_provider_conf(work / "openssl.cnf", provider_so, softhsm)
        env = dict(os.environ, SOFTHSM2_CONF=str(store.conf), OPENSSL_CONF=str(conf),
                   PKCS11_PROVIDER_DEBUG="file:/dev/stderr,level:1")
        proc = subprocess.run(
            ["openssl", "speed", "-provider", "pkcs11", "-provider", "default",
             "-propquery", "?provider=pkcs11", "-seconds", "2", "rsa2048"],
            capture_output=True, text=True, check=False, timeout=60, env=env,
            stdin=subprocess.DEVNULL)
        log = proc.stderr + proc.stdout
        self.assertTrue("Initializing the module" in log, "speed did not touch token")
        self.assertTrue("C_GenerateKeyPair" in log, "speed did no token keygen")


class UnitControls(unittest.TestCase):
    def test_pin_grep_detects_pin(self):
        with self.assertRaises(AssertionError):
            assert_no_pin(self, TEST_PIN, '{"note": "x"}', f"leaked {TEST_PIN} here")

    def test_pin_grep_clean(self):
        assert_no_pin(self, TEST_PIN, '{"calls": 10}', "observer stderr clean")

    def test_probe_lists_known_paths(self):
        self.assertIn("libsofthsm2.so", SOFTHSM_CANDIDATES[0])
        self.assertIn("ossl-modules", PROVIDER_CANDIDATES[0])
        self.assertIn("engines-3", ENGINE_CANDIDATES[0])
        self.assertIn("p11-kit-proxy", PROXY_CANDIDATES[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
