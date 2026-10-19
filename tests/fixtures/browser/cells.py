# SPDX-License-Identifier: GPL-3.0-or-later
"""Cell runners for the G33 browser harness.

Two observation modes, both against a controlled SoftHSM provider:

- ``run_direct``: ``p11scope run`` owns the browser child directly.
  The flow is the browser's own deterministic CLI (``--screenshot``
  exits 0 with PNG bytes on success). Firefox runs ``--pause auto``;
  Chromium runs ``--pause never`` (it aborts under the barrier).
- ``attach_drive``: Playwright launches and drives the browser while
  ``p11scope profile --pid`` observes the main browser process. Used for
  interactive flows (TLS client-cert trigger) Playwright must drive.

``P11SCOPE_BIN`` names the product binary under test (matrix convention);
privilege comes from ``sudo -n`` and fails fast when unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from profiles import ChromiumHome, FirefoxProfile, chromium_binary, firefox_binary


class CellError(RuntimeError):
    """A cell could not run (setup/launch failure, not an oracle failure)."""


def p11scope_bin() -> Path:
    """Product binary under test from ``P11SCOPE_BIN``."""
    raw = os.environ.get("P11SCOPE_BIN")
    if not raw:
        raise CellError("P11SCOPE_BIN is not set (path to the p11scope binary under test)")
    binary = Path(raw)
    if not (binary.exists() and os.access(binary, os.X_OK)):
        raise CellError(f"P11SCOPE_BIN is not executable: {binary}")
    return binary


def check_sudo() -> None:
    """Fail fast unless passwordless sudo works (no password prompts mid-cell)."""
    proc = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False)
    if proc.returncode != 0:
        raise CellError("`sudo -n true` failed: browser cells need passwordless sudo for p11scope")


def preflight() -> Path:
    """Check every cell prerequisite; return the product binary path."""
    binary = p11scope_bin()
    check_sudo()
    for tool in ("softhsm2-util", "pkcs11-tool", "openssl", "pgrep"):
        if shutil.which(tool) is None:
            raise CellError(f"required host tool missing: {tool}")
    try:
        import playwright  # noqa: F401
    except ImportError as exc:
        raise CellError("python playwright is not installed (`pip install playwright`)") from exc
    firefox_binary()
    chromium_binary()
    return binary


@dataclass
class CellResult:
    """Everything one cell produced, for the oracle and the log."""

    name: str
    report_path: Path
    browser_exit: int | None = None
    screenshot_bytes: int = 0
    flow: dict = field(default_factory=dict)
    observer_stderr_tail: str = ""


def _tail(text: str, lines: int = 25) -> str:
    return "\n".join(text.splitlines()[-lines:])


def _trusted_dir(path: Path) -> Path:
    """Create ``path`` with owner-only writes (the observer refuses group-writable ``-o`` dirs)."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _reown_report(report: Path) -> None:
    """Make a root-written report readable by the invoking user."""
    if not report.exists():
        return
    uid, gid = os.getuid(), os.getgid()
    subprocess.run(["sudo", "-n", "chown", f"{uid}:{gid}", str(report)],
                   capture_output=True, check=False)


#: Pause policy per browser. Chromium aborts (SIGABRT) under the `auto`
#: barrier during its spawn storm (single-process included), so it runs
#: `never`. Even `never` is flaky for Chromium run-direct (loader hooks vs
#: spawn storm, ~3/4 abort); v1 Chromium cells are attach-drive only.
#: Firefox tolerates `auto`.
PAUSE_POLICY = {"firefox": "auto", "chromium": "never"}


def run_direct(name: str, browser: str, workdir: Path, flow_url: str,
               observe_module: Path, register_module: Path | None = None,
               browser_env: dict | None = None,
               extra_browser_args: tuple[str, ...] = (),
               duration_seconds: int = 120) -> CellResult:
    """Run one ``p11scope run`` cell with the browser as the owned child.

    ``observe_module`` is the ``--module`` target (always the controlled
    SoftHSM provider). ``register_module`` is the module registered in the
    fresh profile; ``None`` builds the no-module failure twin (the browser
    never maps the provider, so the cell expects zero rows for it).
    ``browser_env`` (notably ``SOFTHSM2_CONF``) rides ``sudo VAR=value``
    into the observer, whose ``run`` boundary forwards ``SOFTHSM2_CONF``
    to the owned child.
    """
    _trusted_dir(workdir)
    report = workdir / "observed-profile.json"
    screenshot = workdir / "flow.png"
    binary = p11scope_bin()
    if browser == "firefox":
        profile = FirefoxProfile.create(workdir / "ffprofile", module_lib=register_module)
        home = workdir / "home"
        home.mkdir(exist_ok=True)
        browser_argv = [
            str(firefox_binary()), "--headless", "--no-remote",
            "--profile", str(profile.path),
            f"--screenshot={screenshot}", flow_url,
        ]
        child_env = {"HOME": str(home)}
    elif browser == "chromium":
        home = ChromiumHome.create(workdir / "home", module_lib=register_module).path
        browser_argv = [
            str(chromium_binary()), "--headless=new", "--no-sandbox", "--disable-gpu",
            # Flow servers use short-lived self-signed certs; trust is
            # established by the sealed loopback URL, not by PKI.
            "--ignore-certificate-errors",
            f"--user-data-dir={workdir / 'crprofile'}",
            f"--screenshot={screenshot}", "--window-size=800,600",
            flow_url,
        ]
        child_env = {"HOME": str(home)}
    else:
        raise CellError(f"unknown browser: {browser}")
    # `run` scrubs the child environment (usage.md "run safety boundary"):
    # SOFTHSM2_CONF passes through; HOME/TMPDIR ride via /usr/bin/env.
    tmpdir = workdir / "tmp"
    tmpdir.mkdir(exist_ok=True)
    argv = ["sudo", "-n"]
    for key, value in (browser_env or {}).items():
        argv.append(f"{key}={value}")
    argv += [str(binary), "run", "--module", str(observe_module)]
    argv += [
        "-o", str(report), "--pause", PAUSE_POLICY[browser],
        "--duration", str(duration_seconds), "--kill-on-timeout",
        "--", "/usr/bin/env",
        f"HOME={child_env['HOME']}", f"TMPDIR={tmpdir}",
        *browser_argv, *extra_browser_args,
    ]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False,
                          timeout=duration_seconds + 120)
    _reown_report(report)
    shot_bytes = screenshot.stat().st_size if screenshot.exists() else 0
    return CellResult(
        name=name, report_path=report,
        browser_exit=None,  # owned-child exit is inside the observer's verdict
        screenshot_bytes=shot_bytes,
        flow={"observer_exit": proc.returncode, "flow_url": flow_url},
        observer_stderr_tail=_tail(proc.stderr),
    )


def main_browser_pid(match: str, browser: str) -> int:
    """Resolve the main browser PID by command-line match.

    Chromium children carry ``--type=``; the main process does not. Firefox
    children do not repeat the profile path, so the match is already unique.
    """
    proc = subprocess.run(["pgrep", "-f", match], capture_output=True, text=True, check=False)
    pids = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not pids:
        raise CellError(f"no {browser} process matches {match!r}")
    if browser == "chromium" and len(pids) > 1:
        for pid in pids:
            try:
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
            except FileNotFoundError:
                continue
            if b"--type=" not in cmdline:
                return int(pid)
        raise CellError(f"no main {browser} process among {len(pids)} matches")
    if len(pids) > 1:
        raise CellError(f"{len(pids)} {browser} processes match {match!r}; expected one")
    return int(pids[0])


def wait_for_mapping(pid: int, needles: tuple[str, ...], timeout_seconds: float = 20.0) -> bool:
    """Poll ``/proc/<pid>/maps`` until a line contains one of ``needles``.

    Attach-mode discovery scans once at profiler start; a module the
    browser maps after the scan is never attached. Waiting for the mapping
    first makes attach deterministic. Returns False on timeout (the caller
    decides whether that is a skip or a failure).
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            maps = Path(f"/proc/{pid}/maps").read_text()
        except FileNotFoundError:
            return False
        if any(needle in maps for needle in needles):
            return True
        time.sleep(0.2)
    return False


def _parse_capture_ready(line: str) -> int | None:
    """Parse ``p11scope: capturing: N probe(s) attached``; None otherwise."""
    prefix = "p11scope: capturing: "
    if not line.startswith(prefix):
        return None
    try:
        return int(line[len(prefix):].split(" probe(s) attached", 1)[0])
    except ValueError:
        return None


class _ProfilerSession:
    """A running profiler with capture-readiness detection over stderr.

    Two daemon threads drain stdout (discarded, as before) and stderr
    (kept for the tail); the stderr thread watches for the
    ``p11scope: capturing:`` marker the observer prints once probes are
    attached and the capture loop starts. Navigation must only begin
    after ``wait_for_ready`` returns.
    """

    def __init__(self, argv: list[str]) -> None:
        self._proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self._stderr_lines: list[str] = []
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._attached: int | None = None
        self._stdout_thread = threading.Thread(target=self._drain_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

    def _drain_stdout(self) -> None:
        assert self._proc.stdout is not None
        while self._proc.stdout.readline():
            pass
        self._proc.stdout.close()

    def _drain_stderr(self) -> None:
        assert self._proc.stderr is not None
        while True:
            line = self._proc.stderr.readline()
            if not line:
                break
            with self._lock:
                self._stderr_lines.append(line)
                if self._attached is None:
                    parsed = _parse_capture_ready(line.rstrip("\n"))
                    if parsed is not None:
                        self._attached = parsed
                        self._ready.set()
        self._proc.stderr.close()

    def wait_for_ready(self, timeout_seconds: float) -> int:
        """Block until the capture marker arrives; return attached probes.

        Raises CellError when the profiler exits first or the marker
        never arrives inside the grace period (the profiler is killed).
        """
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._ready.wait(0.05):
                with self._lock:
                    assert self._attached is not None
                    return self._attached
            if self._proc.poll() is not None:
                raise CellError(
                    f"profiler exited (rc={self._proc.returncode}) before capture "
                    f"readiness: {_tail(self.stderr_text())}")
        self._proc.kill()
        raise CellError(
            f"profiler never became ready within {timeout_seconds:g}s "
            f"(no `p11scope: capturing:` marker): {_tail(self.stderr_text())}")

    def poll(self):
        """The profiler's exit code, or None while it runs."""
        return self._proc.poll()

    def stderr_text(self) -> str:
        """Stderr collected so far."""
        with self._lock:
            return "".join(self._stderr_lines)

    def finish(self, timeout_seconds: float) -> tuple[int | None, str]:
        """Wait for profiler exit (killing on timeout); join the drains."""
        try:
            returncode = self._proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            returncode = self._proc.wait(timeout=10)
        self._stderr_thread.join(timeout=10)
        self._stdout_thread.join(timeout=10)
        return returncode, self.stderr_text()


def _target_liveness(pid: int, match: str) -> tuple[bool, bool]:
    """(alive, identity_ok) for the browser main process.

    ``identity_ok`` requires the live PID's command line to still contain
    the launch match, so a reused PID is never mistaken for the target.
    """
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
    except (FileNotFoundError, PermissionError):
        return False, False
    return True, match.encode() in cmdline


def _require_liveness(pid: int, match: str, profiler: _ProfilerSession, when: str) -> None:
    """Fail the cell unless the observer and the browser target are alive."""
    if profiler.poll() is not None:
        raise CellError(
            f"profiler exited (rc={profiler.poll()}) {when}: "
            f"{_tail(profiler.stderr_text())}")
    alive, identity_ok = _target_liveness(pid, match)
    if not alive:
        raise CellError(f"browser target pid {pid} disappeared {when}")
    if not identity_ok:
        raise CellError(
            f"browser target pid {pid} no longer matches {match!r} {when} (PID reused?)")


def attach_drive(name: str, browser: str, workdir: Path, flow_url: str,
                 flow, observe_module: Path, register_module: Path | None = None,
                 browser_env: dict | None = None,
                 duration_seconds: int = 90,
                 attach_grace_seconds: int = 5,
                 wait_for_map: tuple[str, ...] | None = None,
                 extra_browser_args: tuple[str, ...] = (),
                 auto_select_cert: bool = True,
                 extra_prefs: dict | None = None,
                 expect_attached: bool | None = None) -> CellResult:
    """Drive ``flow(page, context)`` under ``p11scope profile --pid``.

    ``flow`` is a Playwright callable returning a JSON-able fact dict. The
    profiler observes ``observe_module`` and starts first
    (duration-bounded); the flow runs only after the profiler prints its
    capture-readiness marker (``attach_grace_seconds`` bounds the wait),
    so early flow traffic is inside the window. ``register_module`` is the
    provider registered in the fresh profile (`None` leaves the profile
    without one, for absence twins). ``browser_env`` (notably
    ``SOFTHSM2_CONF``) is applied to this process so the Playwright-launched
    browser inherits it. ``wait_for_map`` names ``/proc/PID/maps``
    substrings (e.g. the module file name) the profiler waits for before
    starting, so its opening scan sees the module. ``expect_attached``
    pins the probe state the readiness marker must show: True (the scan
    hooked the mapped module), False (nothing attached — the module
    stayed unmapped), None (either). The ``mapped_at_end`` fact is None
    (not False) when the target is gone: disappearance is distinct from
    non-mapping.
    """
    saved_env = dict(os.environ)
    os.environ.update(browser_env or {})
    try:
        return _attach_drive_inner(
            name, browser, workdir, flow_url, flow, observe_module,
            register_module, duration_seconds, attach_grace_seconds,
            wait_for_map, extra_browser_args, auto_select_cert,
            extra_prefs or {}, expect_attached)
    finally:
        os.environ.clear()
        os.environ.update(saved_env)


def launch_browser_context(pw, browser: str, workdir: Path, *,
                           register_module: Path | None = None,
                           extra_browser_args: tuple[str, ...] = (),
                           extra_prefs: dict | None = None,
                           flow_url: str = "",
                           auto_select_cert: bool = True):
    """Launch a persistent Playwright context on a fresh profile.

    Returns ``(context, match, profile_path)``: the context, the
    command-line match resolving the main browser PID, and the fresh
    Firefox profile (or Chromium HOME) carrying the registration.
    """
    if browser == "firefox":
        ff_prefs = {"security.default_personal_cert": "Select Automatically"}
        ff_prefs.update(extra_prefs or {})
        profile = FirefoxProfile.create(
            workdir / "ffprofile", module_lib=register_module,
            prefs=ff_prefs)
        # Explicit environment: the Playwright driver keeps the environment
        # it inherited at startup, so anything set afterwards (notably the
        # fresh Chromium HOME below) must ride `env=` to reach the browser.
        context = pw.firefox.launch_persistent_context(
            str(profile.path), headless=True, ignore_https_errors=True,
            args=list(extra_browser_args), env=dict(os.environ))
        return context, str(profile.path), profile.path
    elif browser == "chromium":
        home = ChromiumHome.create(workdir / "home", module_lib=register_module).path
        browser_env = dict(os.environ)
        browser_env["HOME"] = str(home)
        cr_args = list(extra_browser_args)
        if auto_select_cert:
            cr_args.append(f"--auto-select-certificate-for-urls={flow_url}")
        context = pw.chromium.launch_persistent_context(
            str(workdir / "crprofile"), channel="chromium",
            headless=True, ignore_https_errors=True,
            args=cr_args, env=browser_env)
        return context, str(workdir / "crprofile"), home
    raise CellError(f"unknown browser: {browser}")


#: NSS shared-database locations Chromium may open under its HOME: the
#: legacy ``.pki/nssdb`` (used when pre-created, as the harness does) and
#: the ``.local/share/pki/nssdb`` fallback.
NSS_DB_CANDIDATES = (".pki/nssdb", ".local/share/pki/nssdb")


def wait_for_nss_db(fresh_home: Path, timeout_seconds: float = 15.0) -> Path | None:
    """Poll ``fresh_home`` for a Chromium-created NSS database; return its dir.

    Chromium initializes NSS eagerly at startup, creating ``cert9.db`` /
    ``key4.db`` in exactly one shared-DB dir under its effective HOME.
    Whichever dir gains a database proves which HOME the browser used; the
    caller additionally requires its own ``pkcs11.txt`` to be the one in
    that dir. Returns None on timeout.
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for candidate in NSS_DB_CANDIDATES:
            dbdir = fresh_home / candidate
            if (dbdir / "cert9.db").exists() or (dbdir / "key4.db").exists():
                return dbdir
        time.sleep(0.2)
    return None


def _attach_drive_inner(name, browser, workdir, flow_url, flow, observe_module,
                        register_module, duration_seconds, attach_grace_seconds,
                        wait_for_map, extra_browser_args,
                        auto_select_cert, extra_prefs, expect_attached) -> CellResult:
    """``attach_drive`` body with the environment already applied."""
    _trusted_dir(workdir)
    report = workdir / "observed-profile.json"
    # Import here so collection never requires playwright before preflight.
    from playwright.sync_api import sync_playwright  # noqa: PLC0415

    with sync_playwright() as pw:
        context, match, profile_path = launch_browser_context(
            pw, browser, workdir, register_module=register_module,
            extra_browser_args=tuple(extra_browser_args), extra_prefs=extra_prefs,
            flow_url=flow_url, auto_select_cert=auto_select_cert)
        launch_facts: dict = {}
        if browser == "chromium":
            # Registration-effective witness (P2-1): no absence below may
            # be interpreted until the browser's own NSS database proves
            # it runs under the fresh HOME with our registration visible.
            nss_db_dir = wait_for_nss_db(profile_path)
            if nss_db_dir is None:
                context.close()
                raise CellError(
                    f"chromium never initialized NSS under fresh HOME "
                    f"{profile_path} in 15s (registration not effective)")
            if register_module is not None:
                try:
                    listed = (nss_db_dir / "pkcs11.txt").read_text()
                except OSError:
                    listed = ""
                if str(register_module) not in listed:
                    context.close()
                    raise CellError(
                        f"chromium NSS DB {nss_db_dir} does not list "
                        f"{register_module} (registration not effective)")
            launch_facts["nss_db_dir"] = str(nss_db_dir)
        else:
            launch_facts["profile_module_registered"] = (
                (profile_path / "pkcs11.txt").exists())
        try:
            pid = main_browser_pid(match, browser)
            if wait_for_map and not wait_for_mapping(pid, wait_for_map):
                context.close()
                raise CellError(
                    f"{browser} pid {pid} never mapped {wait_for_map} in 20s")
            profiler = _ProfilerSession(
                ["sudo", "-n", str(p11scope_bin()), "profile", "--pid", str(pid),
                 "--module", str(observe_module), "--duration", str(duration_seconds),
                 "-o", str(report)])
            try:
                ready_attached = profiler.wait_for_ready(attach_grace_seconds)
                if expect_attached is True and ready_attached < 1:
                    raise CellError(
                        f"profiler ready with 0 probes attached "
                        f"(module {observe_module} expected mapped)")
                if expect_attached is False and ready_attached != 0:
                    raise CellError(
                        f"profiler attached {ready_attached} probes "
                        f"(module {observe_module} expected unmapped)")
                _require_liveness(pid, match, profiler, "before navigation")
                page = context.pages[0] if context.pages else context.new_page()
                try:
                    facts = flow(page, context)
                except Exception as exc:  # noqa: BLE001 - flow failure is cell evidence
                    facts = {"flow_error": f"{type(exc).__name__}: {exc}".split("\n")[0]}
                _require_liveness(pid, match, profiler, "after the flow")
            finally:
                profiler_exit, stderr = profiler.finish(duration_seconds + 60)
            alive, identity_ok = _target_liveness(pid, match)
            maps_text = ""
            if alive:
                try:
                    maps_text = Path(f"/proc/{pid}/maps").read_text()
                except FileNotFoundError:
                    alive, identity_ok = False, False
            mapped_at_end = Path(observe_module).name in maps_text if alive else None
        finally:
            context.close()
    _reown_report(report)
    return CellResult(
        name=name, report_path=report,
        flow={"profiler_exit": profiler_exit, "flow_url": flow_url,
              "browser_pid": pid, "mapped_at_end": mapped_at_end,
              "target_alive": alive, "target_identity": identity_ok,
              **launch_facts, **facts},
        observer_stderr_tail=_tail(stderr),
    )
