# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
"""Provider-info oracle controls; every assertion has a failing twin."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def ledger_payload(ledger):
    for line in ledger:
        if line.startswith("LEDGER "):
            return json.loads(line[len("LEDGER ") :])
    raise AssertionError("no LEDGER line")


def replace_ledger(ledger, payload):
    for i, line in enumerate(ledger):
        if line.startswith("LEDGER "):
            ledger[i] = "LEDGER " + json.dumps(payload)
            return
    raise AssertionError("no LEDGER line")


ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts/inventory-provider-info-oracle.py"
CELL = "inventory-provider-info-pid"
INFO_NAMES = (
    "C_GetInfo",
    "C_GetSlotList",
    "C_GetTokenInfo",
    "C_GetMechanismList",
    "C_GetMechanismInfo",
)
OWNED_SHA = "a" * 64


def provider_pin():
    return {
        "dev": [8, 1],
        "ino": 71,
        "sha256": OWNED_SHA,
        "file_identity": {
            "dev": [0, 38],
            "ino": 71,
            "size": 8192,
            "mtime_ns": 123,
            "ctime_ns": 456,
        },
        "mapping": {
            "dev": [8, 1],
            "ino": 71,
            "file_offset": 0,
            "length": 4096,
            "permissions": "r--p",
        },
    }


def token_entry(slot, manufacturer="SoftHSM project", model="SoftHSM v2"):
    return {
        "slot": slot,
        "token": True,
        "manufacturer": manufacturer,
        "model": model,
        "flags": 0,
        "pin_min_len": 4,
        "pin_max_len": 255,
        "hardware_major": 2,
        "hardware_minor": 6,
        "firmware_major": 2,
        "firmware_minor": 6,
        "mechanisms": [
            {"id": 0x250, "min_key_size": 0, "max_key_size": 0, "flags": 0},
            {"id": 0x1080, "min_key_size": 16, "max_key_size": 32, "flags": 1},
        ],
    }


def ledger_lines(pid=123, prime=11):
    lines = [
        "TARGET "
        + json.dumps(
            {"name": name, "dev": [8, 1], "ino": 71, "file_offset": 4096 + i * 16}
        )
        for i, name in enumerate(INFO_NAMES)
    ]
    lines.append("READY pid=%d" % pid)
    lines.append("PRIME calls=%d" % prime)
    lines.append(
        "LEDGER "
        + json.dumps(
            {
                "schema": "p11scope/provider-info-ledger/v1",
                "pid": pid,
                "complete": True,
                "info": {
                    "cryptoki_major": 2,
                    "cryptoki_minor": 40,
                    "manufacturer": "SoftHSM",
                    "description": "Implementation of PKCS11",
                    "flags": 0,
                    "library_major": 2,
                    "library_minor": 6,
                },
                "slots": [
                    token_entry(7),
                    {"slot": 9, "token": False, "mechanisms": []},
                ],
            }
        )
    )
    return lines


def receipt(pid=123):
    return {
        "schema": "p11scope/public-cli-receipt/v1",
        "cell": CELL,
        "scope": "pid",
        "count_domain": "owned-provider",
        "launched_pid": pid,
        "generation": 456,
        "ready_pid": pid,
        "ready_generation": 456,
        "workload_ready": True,
        "capture_ready": True,
        "gate_released": True,
        "observer_exit": 0,
        "workload_exit": 0,
        "ledger_complete": True,
        "provider_before": provider_pin(),
        "provider_after": provider_pin(),
    }


def token_row(slot, manufacturer="SoftHSM project", model="SoftHSM v2"):
    return {
        "module": "m1",
        "caller": "c0",
        "slot": slot,
        "manufacturer": manufacturer,
        "model": model,
        "hardware_major": 2,
        "hardware_minor": 6,
        "firmware_major": 2,
        "firmware_minor": 6,
        "flags": 0,
        "pin_min_len": 4,
        "pin_max_len": 255,
        "completions": 1,
        "changes": 0,
    }


def mech_row(slot, mid, min_key, max_key, flags):
    return {
        "module": "m1",
        "caller": "c0",
        "slot": slot,
        "mechanism": mid,
        "min_key_size": min_key,
        "max_key_size": max_key,
        "flags": flags,
        "completions": 1,
        "changes": 0,
    }


def inputs(pid=123):
    # Post-gate calls: 11 priming + GetInfo + GetSlotList (2), per
    # slot GetTokenInfo (2), per token slot GetMechanismList (1) +
    # GetMechanismInfo (2).
    total = 18
    report = {
        "schema": "p11scope/inventory/v1",
        "scope": "pid:%d" % pid,
        "modules": [
            {
                "id": "m1",
                "admission": {"state": "admitted"},
                "identity": {
                    "device": {"major": 8, "minor": 1},
                    "inode": 71,
                    "sha256": OWNED_SHA,
                },
                "provider_info": {
                    "cryptoki_major": 2,
                    "cryptoki_minor": 40,
                    "manufacturer": "SoftHSM",
                    "description": "Implementation of PKCS11",
                    "flags": 0,
                    "library_major": 2,
                    "library_minor": 6,
                },
            }
        ],
        "callers": [{"id": "c0", "pid": pid}],
        "edges": [
            {
                "caller": "c0",
                "module": "m1",
                "mapping": {"state": "mapped"},
                "entries": {
                    "count": total,
                    "observation": "observed",
                    "coverage": {"state": "counted", "lossy": False, "reason": None},
                },
            }
        ],
        "gaps": [],
        "provider_observations": {
            "version": 8,
            "tokens": [token_row(7)],
            "mechanisms": [mech_row(7, 0x250, 0, 0, 0), mech_row(7, 0x1080, 16, 32, 1)],
            "gaps": [],
        },
    }
    events = [
        {"seq": 1, "kind": "started", "event": {"scope": report["scope"]}},
        {"seq": 2, "kind": "edge_observed", "event": copy.deepcopy(report["edges"][0])},
        {"seq": 3, "kind": "ended", "event": {}},
    ]
    return report, ledger_lines(pid), receipt(pid), events


class ProviderInfoOracleTests(unittest.TestCase):
    def run_case(self, mutate=None, *, want=0, pid=123):
        report, ledger, receipt_value, events = inputs(pid)
        if mutate:
            mutate(report, ledger, receipt_value, events)
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            paths = {}
            for key, value in (("report", report), ("receipt", receipt_value)):
                paths[key] = tmp / key
                paths[key].write_text(json.dumps(value))
            paths["ledger"] = tmp / "ledger"
            paths["ledger"].write_text("\n".join(ledger) + "\n")
            paths["event-log"] = tmp / "events"
            paths["event-log"].write_text(
                "\n".join(json.dumps(row) for row in events) + "\n"
            )
            args = [
                sys.executable,
                "-I",
                str(ORACLE),
                "--cell",
                CELL,
                *sum((["--" + key, str(path)] for key, path in paths.items()), []),
            ]
            proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, want, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(result["cell"], CELL)
        self.assertEqual(result["pass"], want == 0)
        return result

    def test_healthy_passes(self):
        result = self.run_case()
        self.assertEqual(result["qualification"], "provider-info-exact")
        self.assertIn("1 token rows and 2 mechanism rows", result["detail"])
        self.assertIn("serial/label absent", result["detail"])
        self.assertEqual(
            result["proof"],
            {
                "manufacturer": "SoftHSM",
                "library_major": 2,
                "library_minor": 6,
                "token_rows": 1,
                "mechanism_rows": 2,
                "slots": 2,
            },
        )

    def test_manufacturer_mismatch_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["modules"][0]["provider_info"].update(
                manufacturer="SoftHSM2"
            ),
            want=1,
        )
        self.assertIn("differs from the fixture C_GetInfo", result["detail"])

    def test_library_version_mismatch_fails(self):
        self.run_case(
            lambda d, l, r, e: d["modules"][0]["provider_info"].update(library_minor=7),
            want=1,
        )

    def test_receipt_identity_change_fails(self):
        # The binding physical-provider identity check (AGENTS.md):
        # the independently hashed provider must be identical
        # before and after the capture window.
        def mutate(d, l, r, e):
            r["provider_after"]["sha256"] = "b" * 64

        result = self.run_case(mutate, want=1)
        self.assertIn("provider physical identity or hash changed", result["detail"])

    def test_owned_not_admitted_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["modules"][0].update(admission={"state": "refused"}),
            want=1,
        )
        self.assertIn("owned provider not admitted", result["detail"])

    def test_duplicate_owned_module_fails(self):
        def mutate(d, l, r, e):
            twin = copy.deepcopy(d["modules"][0])
            twin["id"] = "m2"
            d["modules"].append(twin)

        result = self.run_case(mutate, want=1)
        self.assertIn("duplicate owned provider module", result["detail"])

    def test_caller_not_unique_fails(self):
        def mutate(d, l, r, e):
            twin = copy.deepcopy(d["callers"][0])
            twin["id"] = "c9"
            d["callers"].append(twin)

        result = self.run_case(mutate, want=1)
        self.assertIn("not exactly one caller", result["detail"])

    def test_observations_version_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"].update(version=7),
            want=1,
        )
        self.assertIn("not section version 8", result["detail"])

    def test_mechanism_completions_two_fails(self):
        self.run_case(
            lambda d, l, r, e: d["provider_observations"]["mechanisms"][0].update(
                completions=2
            ),
            want=1,
        )

    def test_token_changes_nonzero_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"]["tokens"][0].update(
                changes=1
            ),
            want=1,
        )
        self.assertIn("want 0", result["detail"])

    def test_mechanism_changes_nonzero_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"]["mechanisms"][0].update(
                changes=1
            ),
            want=1,
        )
        self.assertIn("want 0", result["detail"])

    def test_missing_provider_info_fails(self):
        self.run_case(lambda d, l, r, e: d["modules"][0].pop("provider_info"), want=1)

    def test_refused_manufacturer_fails(self):
        def mutate(d, l, r, e):
            d["modules"][0]["provider_info"].update(
                manufacturer=None, manufacturer_reason="non_utf8_bytes"
            )

        self.run_case(mutate, want=1)

    def test_spurious_refusal_reason_fails(self):
        # The value matches the ledger but a refusal reason rides
        # along: only the reason-absence guard names this (the
        # fixture read clean bytes, so any reason is a lie).
        def mutate(d, l, r, e):
            d["modules"][0]["provider_info"].update(
                manufacturer_reason="non_utf8_bytes"
            )

        result = self.run_case(mutate, want=1)
        self.assertIn("refused although the fixture read clean bytes", result["detail"])

    def test_missing_token_row_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"].update(tokens=[]), want=1
        )
        self.assertIn("token row slots", result["detail"])

    def test_extra_token_row_fails(self):
        def mutate(d, l, r, e):
            d["provider_observations"]["tokens"].append(token_row(9))

        self.run_case(mutate, want=1)

    def test_token_model_mismatch_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"]["tokens"][0].update(
                model="SoftHSM v3"
            ),
            want=1,
        )
        self.assertIn("differs from the ledger", result["detail"])

    def test_token_completions_two_fails(self):
        self.run_case(
            lambda d, l, r, e: d["provider_observations"]["tokens"][0].update(
                completions=2
            ),
            want=1,
        )

    def test_missing_mechanism_row_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"]["mechanisms"].pop(), want=1
        )
        self.assertIn("mechanism row keys differ", result["detail"])

    def test_mechanism_size_mismatch_fails(self):
        self.run_case(
            lambda d, l, r, e: d["provider_observations"]["mechanisms"][1].update(
                max_key_size=16
            ),
            want=1,
        )

    def test_observation_gaps_fail(self):
        self.run_case(
            lambda d, l, r, e: d["provider_observations"].update(
                gaps=[{"reason": "info_return_deferred", "count": 1}]
            ),
            want=1,
        )

    def test_serial_key_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"]["tokens"][0].update(
                serialNumber="deadbeef"
            ),
            want=1,
        )
        self.assertIn("unknown keys", result["detail"])

    def test_label_key_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"]["tokens"][0].update(
                label="qual"
            ),
            want=1,
        )
        self.assertIn("unknown keys", result["detail"])

    def test_pin_key_fails(self):
        # Allowlist v1 excludes PINs: a smuggled PIN-class key dies
        # at the exact key set (pin_min/max_len stay the only
        # PIN-adjacent keys).
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"]["tokens"][0].update(
                pin="1234"
            ),
            want=1,
        )
        self.assertIn("unknown keys", result["detail"])

    def test_value_key_fails(self):
        # CKA_VALUE / key-material class: never a row key.
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"]["mechanisms"][0].update(
                value="key-bytes"
            ),
            want=1,
        )
        self.assertIn("unknown keys", result["detail"])

    def test_argv_key_fails(self):
        # Process-argument class: never captured, never a row key.
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"]["tokens"][0].update(
                argv=["--pin", "1234"]
            ),
            want=1,
        )
        self.assertIn("unknown keys", result["detail"])

    def test_env_key_fails(self):
        # Environment class: never captured, never a row key.
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"]["mechanisms"][0].update(
                env={"PIN": "1234"}
            ),
            want=1,
        )
        self.assertIn("unknown keys", result["detail"])

    def test_excluded_v3_token_fields_fail(self):
        # Allowlist v3 excludes session counts, memory sizes and
        # clock readings from token rows; the reviewer's exact
        # triple must fail.
        def mutate(d, l, r, e):
            d["provider_observations"]["tokens"][0].update(
                sessionCount=3, totalPublicMemory=4096, utcTime="20261125000000"
            )

        result = self.run_case(mutate, want=1)
        self.assertIn("unknown keys", result["detail"])

    def test_top_level_serial_key_fails(self):
        # The report-wide scan is the second layer: an excluded key
        # outside any row (where no exact key set applies) still
        # dies, here and only here.
        result = self.run_case(
            lambda d, l, r, e: d.update(serialNumber="deadbeef"), want=1
        )
        self.assertIn("excluded key", result["detail"])

    def test_arbitrary_extra_key_fails(self):
        # The row schema is closed: any unrelated extra key dies.
        result = self.run_case(
            lambda d, l, r, e: d["provider_observations"]["tokens"][0].update(
                notes="not in the schema"
            ),
            want=1,
        )
        self.assertIn("unknown keys", result["detail"])

    def test_provider_info_extra_key_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["modules"][0]["provider_info"].update(
                serialNumber="deadbeef"
            ),
            want=1,
        )
        self.assertIn("unknown keys", result["detail"])

    def test_missing_required_row_key_fails(self):
        def mutate(d, l, r, e):
            del d["provider_observations"]["tokens"][0]["model"]

        result = self.run_case(mutate, want=1)
        self.assertIn("misses required keys", result["detail"])

    def test_approved_optional_keys_pass(self):
        # instance (the schema-approved optional) rides rows without
        # tripping the key set; values still judge exactly.
        def mutate(d, l, r, e):
            d["provider_observations"]["tokens"][0]["instance"] = "i-1"
            for row in d["provider_observations"]["mechanisms"]:
                row["instance"] = "i-1"

        result = self.run_case(mutate)
        self.assertEqual(result["qualification"], "provider-info-exact")

    def test_owned_module_gap_fails(self):
        self.run_case(
            lambda d, l, r, e: d["gaps"].append({"module": "m1", "reason": "x"}), want=1
        )

    def test_edge_undercount_fails(self):
        result = self.run_case(
            lambda d, l, r, e: d["edges"][0]["entries"].update(count=17), want=1
        )
        self.assertIn("differs from the independent ledger total", result["detail"])

    def test_edge_overcount_fails(self):
        self.run_case(
            lambda d, l, r, e: d["edges"][0]["entries"].update(count=19), want=1
        )

    def test_missing_prime_fails(self):
        def mutate(d, l, r, e):
            l[:] = [line for line in l if not line.startswith("PRIME ")]

        self.run_case(mutate, want=1)

    def test_malformed_prime_fails(self):
        def mutate(d, l, r, e):
            for i, line in enumerate(l):
                if line.startswith("PRIME "):
                    l[i] = "PRIME calls=many"

        self.run_case(mutate, want=1)

    def test_prime_count_feeds_the_edge_total(self):
        def mutate(d, l, r, e):
            for i, line in enumerate(l):
                if line.startswith("PRIME "):
                    l[i] = "PRIME calls=12"

        result = self.run_case(mutate, want=1)
        self.assertIn("differs from the independent ledger total", result["detail"])

    def test_lossy_coverage_fails(self):
        self.run_case(
            lambda d, l, r, e: d["edges"][0]["entries"]["coverage"].update(lossy=True),
            want=1,
        )

    def test_stream_missing_ended_fails(self):
        self.run_case(lambda d, l, r, e: e.pop(), want=1)

    def test_consistent_edge_overcount_fails_at_the_ledger(self):
        # Snapshot and stream agree on 19, but the ledger says 18:
        # only the snapshot-vs-ledger equality catches a
        # consistent lie (neither leg alone does).
        def mutate(d, l, r, e):
            d["edges"][0]["entries"]["count"] = 19
            e[1]["event"]["entries"]["count"] = 19

        result = self.run_case(mutate, want=1)
        self.assertIn("independent ledger total", result["detail"])

    def test_same_count_wrong_mechanism_keys_fail(self):
        # Same row count, wrong keys: only the key-set equality
        # names the extra/missing pair (a bare count check passes
        # this, and the value loop would die on KeyError instead).
        def mutate(d, l, r, e):
            d["provider_observations"]["mechanisms"][0]["mechanism"] = 0x999

        result = self.run_case(mutate, want=1)
        self.assertIn("mechanism row keys differ", result["detail"])

    def test_stream_edge_total_drift_fails(self):
        def mutate(d, l, r, e):
            e[1]["event"]["entries"]["count"] = 100

        result = self.run_case(mutate, want=1)
        self.assertIn("differs from the snapshot row", result["detail"])

    def test_vacuous_token_ledger_fails(self):
        def mutate(d, l, r, e):
            payload = ledger_payload(l)
            payload["slots"] = [{"slot": 9, "token": False, "mechanisms": []}]
            replace_ledger(l, payload)

        self.run_case(mutate, want=1)

    def test_wrong_cell_fails(self):
        report, ledger, receipt_value, events = inputs()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            paths = {}
            for key, value in (("report", report), ("receipt", receipt_value)):
                paths[key] = tmp / key
                paths[key].write_text(json.dumps(value))
            paths["ledger"] = tmp / "ledger"
            paths["ledger"].write_text("\n".join(ledger) + "\n")
            paths["event-log"] = tmp / "events"
            paths["event-log"].write_text(
                "\n".join(json.dumps(row) for row in events) + "\n"
            )
            args = [
                sys.executable,
                "-I",
                str(ORACLE),
                "--cell",
                "inventory-mt-pid",
                *sum((["--" + key, str(path)] for key, path in paths.items()), []),
            ]
            proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("undeclared cell", proc.stdout)

    def test_scope_mismatch_fails(self):
        self.run_case(lambda d, l, r, e: d.update(scope="pid:999"), want=1)


if __name__ == "__main__":
    unittest.main()
