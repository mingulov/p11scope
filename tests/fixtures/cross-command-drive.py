#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged saved-inventory journey against an explicit binary.

Default mode checks synthetic contracts using the reviewed scan-current input.
--before/--after instead checks existing, nonempty saved inventories; the caller
must verify their capture origins separately. Neither mode captures live data.
All output is bounded, child process groups are owned, and temporary files live
under TMPDIR (default /var/tmp/p11scope-ws-tmp) and are removed after the run.
"""

import argparse
import copy
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SCHEMA = "p11scope/inventory-diff/v1"
INPUT_LIMIT = 64 * 1024 * 1024
OUTPUT_LIMIT = 4 * 1024 * 1024
FIXTURE = Path(__file__).resolve().parent / "inventory-diff/scan-current.json"


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def run(argv, *, timeout=20, output_limit=OUTPUT_LIMIT):
    """Drain both streams without unbounded communicate() allocation."""
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, f"command timed out: {argv!r}")
                for key, _ in selector.select(min(remaining, 0.1)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    streams[key.data].extend(data)
                    require(sum(map(len, streams.values())) <= output_limit,
                            f"command output exceeded {output_limit} bytes: {argv!r}")
            remaining = deadline - time.monotonic()
            require(remaining > 0, f"command timed out: {argv!r}")
            code = child.wait(timeout=remaining)
        return code, bytes(streams["stdout"]), bytes(streams["stderr"])
    finally:
        # Signal only while the unreaped leader retains this group's numeric
        # identity. A normal wait() ended custody; that PID/PGID may be reused.
        # There is no competing poller/reaper for this owned child.
        if child.returncode is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait()
        child.stdout.close()
        child.stderr.close()


def success(result):
    code, stdout, stderr = result
    require(code == 0, f"exit {code}: {stderr[:4096]!r}")
    require(not stderr, f"unexpected stderr: {stderr[:4096]!r}")
    return stdout


def report_document(raw):
    require(raw.endswith(b"\n") and not raw.endswith(b"\n\n"),
            "JSON stdout must have exactly one final newline")
    report = json.loads(raw)
    require(report.get("schema") == SCHEMA, "wrong diff schema")
    require(report["comparison"]["counter_relation"] == "independent_windows",
            "counts lost their independent-window meaning")
    for limitation in ("absence_is_not_removal", "counts_are_independent_windows"):
        require(limitation in report["limitations"], f"missing {limitation}")
    return report


def readable(raw, expected=()):
    text = raw.decode("utf-8")
    require("\x1b" not in text, "redirected text contains terminal controls")
    for phrase in ("Not observed after does not prove removal",
                   "independent observation windows", "no count delta", *expected):
        require(phrase in text, f"missing readable conclusion {phrase!r}")
    return text


def summary_counts(report, **expected):
    for key, value in expected.items():
        require(report["summary"][key] == value,
                f"unexpected {key}: {report['summary'][key]!r}, wanted {value}")


def same_report(stdout, saved):
    require(stdout == saved, "saved JSON differs from JSON stdout")


def read_input(path):
    with path.open("rb") as source:
        raw = source.read(INPUT_LIMIT + 1)
    require(len(raw) <= INPUT_LIMIT, f"input exceeds 64 MiB: {path}")
    return raw, json.loads(raw)


def saved_bytes(path):
    with path.open("rb") as source:
        raw = source.read(OUTPUT_LIMIT + 1)
    require(len(raw) <= OUTPUT_LIMIT, "saved report exceeds output bound")
    return raw


def write_input(path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


class Journey:
    def __init__(self, binary, root):
        self.binary = binary
        self.root = root
        self.cells = []

    def diff(self, before, after, *options):
        return run([self.binary, "inventory", "diff", str(before), str(after), *options])

    def help(self):
        top = success(run([self.binary, "--help"])).decode()
        inventory = success(run([self.binary, "inventory", "--help"])).decode()
        diff = success(run([self.binary, "inventory", "diff", "--help"])).decode()
        require("inventory" in top, "top-level help omits inventory")
        require("diff" in inventory, "inventory help omits comparison next step")
        for phrase in ("BEFORE.json AFTER.json", "offline", "--json", "-o",
                       "independent windows", "absence does not prove removal"):
            require(phrase in diff, f"diff help omits {phrase!r}")
        self.cells.append("help-to-offline-diff")

    def parity(self, before, after):
        destination = self.root / "report.json"
        destination.write_bytes(b"old report")
        raw = success(self.diff(before, after, "--json", "-o", str(destination)))
        same_report(raw, saved_bytes(destination))
        report = report_document(raw)
        plain = success(self.diff(before, after, "--json"))
        same_report(plain, raw)
        return report

    def fixtures(self):
        value = json.loads(FIXTURE.read_bytes())
        before, after = self.root / "before.json", self.root / "after.json"
        write_input(before, value)
        changed = copy.deepcopy(value)
        changed["modules"][0]["identity"]["sha256"] = "b" * 64
        write_input(after, changed)
        readable(success(self.diff(before, after)), (
            "1 application group changed", "/bin/driver", "m0.so", "/scale/m0.so",
            "Different module content observed at this path"))
        summary_counts(self.parity(before, after), application_groups_changed=1,
                       content_before_only=1, content_after_only=1, module_paths_changed=1)
        self.cells.append("fixture-known-content-change-and-json-file-parity")

        write_input(after, value)
        readable(success(self.diff(before, after)), (
            "No differences in the compared inventory observations", "scope completeness",
            "unknown", "fixture coverage unknown"))
        summary_counts(self.parity(before, after), application_groups_changed=0,
                       content_before_only=0, content_after_only=0, module_paths_changed=0)
        self.cells.append("fixture-unchanged-partial-coverage")

        # Exercise the saved-input validator with known synthetic observations,
        # including different independent-window counts, before using real files.
        count_before, count_after = copy.deepcopy(value), copy.deepcopy(value)
        count_before["edges"][0]["entries"]["count"] = 3
        count_after["edges"][0]["entries"]["count"] = 7
        write_input(before, count_before)
        write_input(after, count_after)
        self.saved(before, after, label="fixture-independent-window-accounting")
        write_input(before, value)

        escaped = copy.deepcopy(value)
        escaped["callers"][0]["image"]["exe"]["path"] = "/bin/app\n\x1b[31m"
        escaped["modules"][0]["paths"] = ["/lib/module\t\r.so"]
        write_input(after, escaped)
        readable(success(self.diff(before, after)), (
            "/bin/app\\n\\u{1b}[31m", "/lib/module\\t\\r.so"))
        report = self.parity(before, after)
        require("/bin/app\n\x1b[31m" in report["comparison"]["application_paths"],
                "JSON lost decoded executable path")
        self.cells.append("fixture-terminal-escaping-and-json-data")

        write_input(after, value)
        originals = before.read_bytes(), after.read_bytes()
        alias = self.root / "after-hardlink.json"
        os.link(after, alias)
        for destination in (before, after, alias):
            code, stdout, stderr = self.diff(before, after, "-o", str(destination))
            require(code == 1 and not stdout and b"alias" in stderr and b"input" in stderr,
                    "input alias was not refused safely")
            require((before.read_bytes(), after.read_bytes()) == originals,
                    "alias rejection modified an input")
        destination = self.root / "report.json"
        destination.write_bytes(b"old report")
        after.write_text('{"schema":"wrong"}\n', encoding="utf-8")
        code, stdout, _ = self.diff(before, after, "-o", str(destination))
        require(code == 1 and not stdout, "invalid input did not fail cleanly")
        require(destination.read_bytes() == b"old report", "invalid input replaced report")
        self.cells.append("fixture-input-alias-and-failure-preservation")

    def saved(self, before, after, *, label="saved-input-offline-comparison-and-json-file-parity"):
        snapshots = [read_input(path) for path in (before, after)]
        for path, (_, document) in zip((before, after), snapshots):
            require(document.get("schema") == "p11scope/inventory/v1", f"wrong input: {path}")
            require(document.get("callers") and document.get("modules") and document.get("edges"),
                    f"saved input lacks caller/module/edge population: {path}")
        report = self.parity(before, after)
        text = readable(success(self.diff(before, after)))
        require(report["summary"]["application_groups_compared"] > 0,
                "saved-input acceptance has no application groups")
        dictionary = report["comparison"]["application_paths"]
        require(dictionary, "saved-input acceptance has no resolved application path")
        # Resolve only output references and retain each independent count; no
        # inventory comparison or continuity algorithm is reproduced here.
        for side, (_, document) in zip(("before", "after"), snapshots):
            evidence = report[side]["evidence"]
            counts = [evidence["edges"][index]["entries"]["count"]
                      for index in evidence["edge_occurrences"]]
            require(sorted(counts) == sorted(edge["entries"]["count"] for edge in document["edges"]),
                    f"{side} independent counts differ from saved observations")
            paths = [caller.get("image", {}).get("exe", {}).get("path")
                     for caller in document["callers"] if caller.get("image")
                     and caller["image"].get("exe")]
            require(any(path in dictionary for path in paths if path),
                    f"{side} has no resolvable recorded application group")
            require(evidence["modules"], f"{side} diff evidence has no module")
        require("Recorded application:" in text and "Module:" in text,
                "saved-input text omits application/module conclusions")
        for path, (original, _) in zip((before, after), snapshots):
            require(read_input(path)[0] == original, f"saved input was changed: {path}")
        self.cells.append(label)


class HarnessControls(unittest.TestCase):
    def test_wrong_schema_and_continuity_claim_fail(self):
        for doc in ({"schema": "wrong"},
                    {"schema": SCHEMA, "comparison": {"counter_relation": "delta"}}):
            with self.assertRaises(AssertionError):
                report_document(json.dumps(doc).encode() + b"\n")

    def test_wrong_change_counts_fail(self):
        with self.assertRaises(AssertionError):
            summary_counts({"summary": {"content_before_only": 0}}, content_before_only=1)

    def test_mismatched_saved_report_fails(self):
        with self.assertRaises(AssertionError):
            same_report(b'{"complete":true}\n', b'{"complete":false}\n')

    def test_unsafe_text_and_missing_conclusion_fail(self):
        for text in (b"\x1b[31m", b"machine unchanged\n"):
            with self.assertRaises(AssertionError):
                readable(text)

    def test_stalled_child_is_killed_and_reaped(self):
        started = time.monotonic()
        children = []
        spawn = subprocess.Popen

        def recorded_spawn(*args, **kwargs):
            child = spawn(*args, **kwargs)
            children.append(child)
            return child

        with mock.patch.object(subprocess, "Popen", side_effect=recorded_spawn):
            with self.assertRaisesRegex(AssertionError, "timed out"):
                run([sys.executable, "-I", "-c", "import time; time.sleep(60)"], timeout=0.1)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(children[0].returncode, -signal.SIGKILL)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)

    def test_unbounded_output_fails(self):
        with self.assertRaisesRegex(AssertionError, "output exceeded"):
            run([sys.executable, "-I", "-c", "import os; os.write(1, b'x' * 65536)"],
                output_limit=1024)

    def test_successful_child_never_signals_retired_identifier(self):
        with mock.patch.object(os, "killpg", wraps=os.killpg) as signal_group:
            code, stdout, stderr = run([sys.executable, "-I", "-c", "print('finished')"])
        self.assertEqual((code, stdout, stderr), (0, b"finished\n", b""))
        signal_group.assert_not_called()

    def test_saved_acceptance_rejects_empty_population(self):
        base = Path(os.environ.get("TMPDIR", "/var/tmp/p11scope-ws-tmp"))
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="journey-control-", dir=base) as directory:
            root = Path(directory)
            empty = root / "empty.json"
            write_input(empty, {"schema": "p11scope/inventory/v1", "callers": [],
                                "modules": [], "edges": []})
            with self.assertRaisesRegex(AssertionError, "population"):
                Journey("unused-before-command", root).saved(empty, empty)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", help="explicit installed or Cargo-built p11scope path")
    parser.add_argument("--before", type=Path, help="existing saved inventory (capture origin checked by caller)")
    parser.add_argument("--after", type=Path, help="existing saved inventory (capture origin checked by caller)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(HarnessControls))
        return 0 if result.wasSuccessful() else 1
    if not args.binary or bool(args.before) != bool(args.after):
        parser.error("--binary is required; --before and --after must be paired")
    binary = str(Path(args.binary).resolve(strict=True))
    base = Path(os.environ.get("TMPDIR", "/var/tmp/p11scope-ws-tmp"))
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cross-command-", dir=base) as directory:
        journey = Journey(binary, Path(directory))
        journey.help()
        if args.before:
            journey.saved(args.before.resolve(strict=True), args.after.resolve(strict=True))
            mode = "saved-input-offline; capture origins require separate verification"
        else:
            journey.fixtures()
            mode = "synthetic-contracts; no live capture or real-input acceptance"
        print(json.dumps({"mode": mode, "binary": binary, "passed": journey.cells}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"cross-command journey failed: {error}", file=sys.stderr)
        sys.exit(1)
