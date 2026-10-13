#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Application-ledger controls; no observer, bootstrap or object authority."""

from collections import Counter
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "key_operation_ledger", ROOT / "scripts" / "key-operation-ledger.py"
)
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


def application_rows():
    """Synthetic parser inputs, deliberately separate from real-provider tests."""
    rows = []
    clock = 1
    counts = Counter()

    def emit(kind, **facts):
        nonlocal clock
        clock += 1
        row = {"seq": len(rows) + 1, "kind": kind, "time_ns": clock}
        row.update(facts)
        rows.append(row)

    def call(fn, operation=0, phase="setup", rv=0, **facts):
        nonlocal clock
        start = clock + 1
        clock += 2
        rows.append({"seq": len(rows) + 1, "kind": "call", "operation": operation,
                     "phase": phase, "fn": fn, "rv": rv,
                     "start_ns": start, "end_ns": clock, **facts})
        counts[fn] += 1

    emit("header", version=1, layout="lp64", mechanism="CKM_SHA256_RSA_PKCS",
         requested={"public": {"class": 2, "key_type": 0, "token": False,
                                "modulus_bits": 2048},
                    "private": {"class": 3, "key_type": 0, "token": False}})
    emit("ready")
    emit("go")
    for fn in ("C_GetFunctionList", "C_Initialize", "C_GetSlotList", "C_OpenSession",
               "C_Login", "C_GenerateKeyPair"):
        call(fn)
    for key, class_id in (("public", 2), ("private", 3)):
        call("C_GetAttributeValue", phase="metadata", key=key)
        emit("metadata", key=key, origin="provider_query", attributes={
            "class": {"status": "value", "value": class_id},
            "key_type": {"status": "value", "value": 0},
            "token": {"status": "value", "value": False},
            "modulus_bits": {"status": "value", "value": 2048},
        })
    for operation in range(1, 11):
        mode = "one_shot" if operation <= 7 else "multipart"
        emit("operation", event="begin", operation=operation, category="sign",
             mode=mode, key="private")
        call("C_SignInit", operation, "init")
        if operation == 1:
            call("C_Sign", operation, "query")
            call("C_Sign", operation, "too_small", 0x150)
        if mode == "multipart":
            for _ in range(3):
                call("C_SignUpdate", operation, "update")
            call("C_SignFinal", operation, "terminal")
        else:
            call("C_Sign", operation, "terminal")
        emit("operation", event="end", operation=operation, outcome="completed")
    for operation in range(11, 23):
        sign_operation = operation - 10 if operation <= 20 else operation - 20
        emit("operation", event="begin", operation=operation, category="verify",
             mode="one_shot", key="public", sign_operation=sign_operation,
             expectation="valid" if operation <= 20 else "invalid")
        call("C_VerifyInit", operation, "init")
        rv = 0 if operation <= 20 else 0xC0
        call("C_Verify", operation, "terminal", rv)
        emit("operation", event="end", operation=operation,
             outcome="completed" if rv == 0 else "failed")
    for fn in ("C_DestroyObject", "C_DestroyObject", "C_Logout", "C_CloseSession", "C_Finalize"):
        call(fn, phase="cleanup")
    emit("done", api_calls=sum(counts.values()), calls_by_function=dict(counts),
         operations={"sign": {"completed": 10, "failed": 0},
                     "verify": {"completed": 10, "failed": 2}})
    return rows


def resequence(rows):
    """Make mutations reach protocol checks beyond sequence/clock validation."""
    for index, row in enumerate(rows, 1):
        row["seq"] = index
        if "time_ns" in row:
            row["time_ns"] = index * 10
        else:
            row["start_ns"], row["end_ns"] = index * 10, index * 10 + 1
    return rows


class ApplicationLedgerTests(unittest.TestCase):
    def assert_refused(self, rows):
        with self.assertRaises(ORACLE.LedgerError):
            ORACLE.validate_ledger(rows)

    def test_independent_call_and_operation_denominators(self):
        result = ORACLE.validate_ledger(application_rows())
        self.assertEqual(result["api_calls"], 68)
        self.assertEqual(result["operations"], {"sign": {"completed": 10, "failed": 0},
                                               "verify": {"completed": 10, "failed": 2}})
        self.assertEqual(result["calls_by_function"]["C_Sign"], 9)
        self.assertEqual(result["calls_by_function"]["C_SignUpdate"], 9)
        self.assertEqual(result["calls_by_function"]["C_Verify"], 12)

    def test_requested_bits_do_not_fill_unknown_private_metadata(self):
        rows = application_rows()
        row = next(r for r in rows if r["kind"] == "metadata" and r["key"] == "private")
        row["attributes"]["modulus_bits"] = {"status": "unsupported"}
        call = next(r for r in rows if r["kind"] == "call" and r.get("key") == "private")
        call["rv"] = 0x12
        result = ORACLE.validate_ledger(rows)
        self.assertEqual(result["established"]["private"]["modulus_bits"],
                         {"status": "unsupported"})
        self.assertEqual(result["requested"]["public"]["modulus_bits"], 2048)

    def test_ledger_mutations_cannot_preserve_acceptance(self):
        mutations = {
            "empty": lambda r: r.clear(),
            "missing_done": lambda r: r.pop(),
            "duplicate_done": lambda r: r.append(copy.deepcopy(r[-1])),
            "duplicate_sequence": lambda r: r[4].update(seq=r[3]["seq"]),
            "sequence_gap": lambda r: r[4].update(seq=999),
            "unexpected_payload": lambda r: r[0].update(pin="fixture-secret"),
            "unsupported_version": lambda r: r[0].update(version=2),
            "bool_version": lambda r: r[0].update(version=True),
            "wrong_requested_bits": lambda r: r[0]["requested"]["public"].update(modulus_bits=3072),
            "provider_bits": lambda r: next(x for x in r if x["kind"] == "metadata")["attributes"]["modulus_bits"].update(value=3072),
            "provider_role": lambda r: next(x for x in r if x["kind"] == "metadata")["attributes"]["class"].update(value=3),
            "requested_as_established": lambda r: next(x for x in r if x["kind"] == "metadata").update(origin="requested"),
            "unavailable_with_value": lambda r: next(x for x in r if x["kind"] == "metadata")["attributes"]["modulus_bits"].update(status="unsupported"),
            "signature_payload": lambda r: next(x for x in r if x["kind"] == "operation").update(signature="forbidden"),
            "fabricated_operation": lambda r: next(x for x in r if x["kind"] == "operation").update(operation=23),
            "inflated_done": lambda r: r[-1].update(api_calls=69),
            "erased_failed_verify": lambda r: next(x for x in r if x["kind"] == "call" and x["rv"] == 0xC0).update(rv=0),
            "negative_duration": lambda r: r[3].update(end_ns=r[3]["start_ns"] - 1),
            "unknown_function": lambda r: r[3].update(fn="C_Fabricated"),
            "unknown_kind": lambda r: r[3].update(kind="captured_object"),
            "boolean_rv": lambda r: r[3].update(rv=False),
            "retry_as_completion": lambda r: next(x for x in r if x["kind"] == "call" and x["phase"] == "too_small").update(phase="terminal"),
            "missing_query": lambda r: r.remove(next(x for x in r if x["kind"] == "call" and x["phase"] == "query")),
            "missing_update": lambda r: r.remove(next(x for x in r if x["kind"] == "call" and x["fn"] == "C_SignUpdate")),
            "wrong_signature_origin": lambda r: next(x for x in r if x["kind"] == "operation" and x.get("category") == "verify").update(sign_operation=10),
            "duplicate_operation_id": lambda r: next(x for x in r if x["kind"] == "operation" and x.get("event") == "begin" and x["operation"] == 2).update(operation=1),
            "erased_failure_outcome": lambda r: next(x for x in r if x["kind"] == "operation" and x.get("outcome") == "failed").update(outcome="completed"),
            "missing_operation_end": lambda r: r.remove(next(x for x in r if x["kind"] == "operation" and x.get("event") == "end")),
            "inflated_operations": lambda r: r[-1]["operations"]["sign"].update(completed=12),
            "boolean_function_count": lambda r: r[-1]["calls_by_function"].update(C_Login=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                rows = application_rows()
                mutate(rows)
                if name in ("missing_query", "missing_update", "missing_operation_end"):
                    resequence(rows)
                self.assert_refused(rows)

    def test_extra_retry_is_refused_even_with_matching_summary(self):
        rows = application_rows()
        index = next(i for i, r in enumerate(rows) if r["kind"] == "call" and r["phase"] == "query")
        rows.insert(index + 1, copy.deepcopy(rows[index]))
        rows[-1]["api_calls"] += 1
        rows[-1]["calls_by_function"]["C_Sign"] += 1
        self.assert_refused(resequence(rows))

    def test_metadata_cannot_move_after_first_key_use(self):
        rows = application_rows()
        index = next(i for i, r in enumerate(rows) if r["kind"] == "metadata")
        metadata = rows.pop(index)
        use = next(i for i, r in enumerate(rows) if r.get("fn") == "C_SignInit")
        rows.insert(use + 1, metadata)
        self.assert_refused(resequence(rows))

    def test_provider_setup_call_order_is_checked(self):
        rows = application_rows()
        rows[7], rows[8] = rows[8], rows[7]
        self.assert_refused(resequence(rows))

    def test_resequenced_duplicate_operation_is_refused(self):
        rows = application_rows()
        begin = next(i for i, r in enumerate(rows) if r["kind"] == "operation")
        end = next(i for i, r in enumerate(rows) if r["kind"] == "operation" and r.get("event") == "end")
        rows[end + 1:end + 1] = copy.deepcopy(rows[begin:end + 1])
        self.assert_refused(resequence(rows))

    def test_parser_rejects_duplicate_json_keys_and_bounded_input(self):
        cases = ('{"seq":1,"seq":1}\n', '[]\n', '{"x":"' + 'x' * 4096 + '"}\n',
                 '\n', '{"seq":NaN}\n')
        for content in cases:
            with self.subTest(content=content[:30]):
                with self.assertRaises(ORACLE.LedgerError):
                    ORACLE.read_ledger(io.StringIO(content))

    def test_jsonl_roundtrip(self):
        text = "".join(json.dumps(r) + "\n" for r in application_rows())
        result = ORACLE.validate_ledger(ORACLE.read_ledger(io.StringIO(text)))
        self.assertEqual(result["api_calls"], 68)

    def test_parser_enforces_total_bytes_and_row_count(self):
        for content in ('{"x":0}\n' * 1025, ('{"x":"' + 'x' * 4000 + '"}\n') * 300):
            with self.assertRaises(ORACLE.LedgerError):
                ORACLE.read_ledger(io.StringIO(content))

    def test_cli_accepts_application_stream_and_redacts_refusal(self):
        ledger = "".join(json.dumps(row) + "\n" for row in application_rows())
        command = [os.sys.executable, str(ROOT / "scripts/key-operation-ledger.py"), "-"]
        result = subprocess.run(command, input=ledger, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["api_calls"], 68)
        result = subprocess.run(command, input='{"pin":"secret-must-not-print"}\n',
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("secret-must-not-print", result.stderr)


class RealProviderFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = Path(os.environ.get("P11SCOPE_KEY_FIXTURE_MODULE",
                                         "/usr/lib/softhsm/libsofthsm2.so"))
        candidates = [Path(os.environ["PKCS11_HEADER_DIR"])] if "PKCS11_HEADER_DIR" in os.environ else []
        candidates.extend((Path("/usr/include"), Path("/usr/include/softhsm"),
                           Path("/usr/include/p11-kit-1/p11-kit")))
        candidates.extend(path.parent for path in sorted(
            (Path.home() / ".cargo/registry/src").glob("*/cryptoki-sys-*/vendor/pkcs11.h")))
        cls.header_dir = next((path for path in candidates if (path / "pkcs11.h").is_file()), None)
        if not (shutil.which("gcc") and shutil.which("softhsm2-util")
                and cls.module.is_file() and cls.header_dir):
            raise unittest.SkipTest("gcc, SoftHSM module/tool and pkcs11.h are required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="p11scope-key-fixture-")
        cls.directory = Path(cls.temporary.name)
        cls.binary = cls.directory / "rsa-ledger"
        result = subprocess.run(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                                 "-I", str(cls.header_dir),
                                 str(ROOT / "tests/fixtures/key-operations/rsa-ledger.c"),
                                 "-ldl", "-o", str(cls.binary)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            cls.temporary.cleanup()
            raise AssertionError("fixture compilation failed: " + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def owned_token(self, root):
        (root / "tokens").mkdir(mode=0o700)
        config = root / "softhsm2.conf"
        config.write_text(f"directories.tokendir = {root / 'tokens'}\n"
                          "objectstore.backend = file\nlog.level = ERROR\n"
                          "slots.removable = false\n", encoding="utf-8")
        config.chmod(0o600)
        env = {**os.environ, "SOFTHSM2_CONF": str(config), "P11SCOPE_KEY_FIXTURE_PIN": "1234"}
        token = subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "key-ledger",
                                "--so-pin", "5678", "--pin", "1234"],
                               env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(token.returncode, 0, "owned token initialization failed")
        return env

    def test_real_rsa_signature_results_and_application_denominators(self):
        with tempfile.TemporaryDirectory(prefix="p11scope-key-token-") as directory:
            env = self.owned_token(Path(directory))
            child = subprocess.Popen([str(self.binary), str(self.module)], env=env,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
            try:
                lines = [child.stdout.readline(), child.stdout.readline()]
                self.assertEqual([json.loads(line)["kind"] for line in lines], ["header", "ready"])
                self.assertIsNone(child.poll())
                child.stdin.write("G")
                child.stdin.flush()
                for line in child.stdout:
                    lines.append(line)
                    if json.loads(line)["kind"] == "done":
                        break
                self.assertEqual(json.loads(lines[-1])["kind"], "done")
                self.assertIsNone(child.poll(), "DONE must retain the controlled process until FINISH")
                child.stdin.write("F")
                child.stdin.flush()
                tail, stderr = child.communicate(timeout=5)
                stdout = "".join(lines) + tail
                self.assertEqual(child.returncode, 0, stderr)
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                for stream in (child.stdin, child.stdout, child.stderr):
                    stream.close()
            try:
                summary = ORACLE.validate_ledger(ORACLE.read_ledger(io.StringIO(stdout)))
            except ORACLE.LedgerError as error:
                self.fail("real fixture did not produce its required operation ledger: " + str(error))
            self.assertEqual(summary["api_calls"], 68)
            self.assertEqual(summary["operations"]["sign"]["completed"], 10)
            self.assertEqual(summary["operations"]["verify"], {"completed": 10, "failed": 2})
            self.assertEqual(summary["established"]["public"]["modulus_bits"]["value"], 2048)
            for forbidden in ('"1234"', '"5678"', "fixture message", "signature", '"pin"', "handle", "pValue"):
                self.assertNotIn(forbidden, stdout)
                self.assertNotIn(forbidden, stderr)

    def test_failed_provider_call_records_owned_cleanup_and_never_done(self):
        with tempfile.TemporaryDirectory(prefix="p11scope-key-token-") as directory:
            env = self.owned_token(Path(directory))
            env["P11SCOPE_KEY_FIXTURE_PIN"] = "wrong-owned-token-pin"
            result = subprocess.run([str(self.binary), str(self.module)], input="GF", env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            rows = ORACLE.read_ledger(io.StringIO(result.stdout))
            self.assertNotIn("done", [row["kind"] for row in rows])
            calls = [row for row in rows if row["kind"] == "call"]
            self.assertEqual([row["fn"] for row in calls[-2:]], ["C_CloseSession", "C_Finalize"])
            self.assertNotIn(env["P11SCOPE_KEY_FIXTURE_PIN"], result.stdout + result.stderr)
            with self.assertRaises(ORACLE.LedgerError):
                ORACLE.validate_ledger(rows)

    def test_bad_go_and_eof_permit_no_application_calls(self):
        env = {**os.environ, "P11SCOPE_KEY_FIXTURE_PIN": "owned-test-pin",
               "P11SCOPE_KEY_FIXTURE_TIMEOUT_MS": "2000"}
        for command in ("", "XF"):
            with self.subTest(command=command):
                result = subprocess.run([str(self.binary), str(self.module)], input=command, env=env,
                                        capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                rows = ORACLE.read_ledger(io.StringIO(result.stdout))
                self.assertEqual([row["kind"] for row in rows], ["header", "ready"])

    def test_control_wait_has_absolute_deadline(self):
        env = {**os.environ, "P11SCOPE_KEY_FIXTURE_PIN": "owned-test-pin",
               "P11SCOPE_KEY_FIXTURE_TIMEOUT_MS": "100"}
        child = subprocess.Popen([str(self.binary), str(self.module)], env=env,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        try:
            child.wait(timeout=2)
            self.assertNotEqual(child.returncode, 0)
            rows = ORACLE.read_ledger(child.stdout)
            self.assertEqual([row["kind"] for row in rows], ["header", "ready"])
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()


if __name__ == "__main__":
    unittest.main()
