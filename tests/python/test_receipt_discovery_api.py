"""Candidate-only discovery API contracts."""

import inspect
from pathlib import Path
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO / "scripts/receipt-build-subject.py"
MODULE_NAME = "receipt_build_subject_discovery_api_test"
MISSING = object()

sys.path.insert(0, str(REPO / "scripts"))
sys.dont_write_bytecode = True
from _loader import load_path


def load_subject(test):
    previous_module = sys.modules.get(MODULE_NAME, MISSING)
    previous_dont_write_bytecode = sys.dont_write_bytecode

    def restore():
        sys.dont_write_bytecode = previous_dont_write_bytecode
        if previous_module is MISSING:
            sys.modules.pop(MODULE_NAME, None)
        else:
            sys.modules[MODULE_NAME] = previous_module

    sys.dont_write_bytecode = True
    test.addCleanup(restore)
    try:
        module = load_path(SCRIPT_PATH, MODULE_NAME)
    except FileNotFoundError:
        test.fail("could not import receipt build-subject script")
    sys.modules[MODULE_NAME] = module
    return module


class DiscoveryApiTests(unittest.TestCase):
    def setUp(self):
        self.module = load_subject(self)

    def test_candidate_only_api_contract(self):
        discover = getattr(self.module, "discover_input_v1", None)
        self.assertTrue(callable(discover), "discover_input_v1 is missing or not callable")

        parameters = list(inspect.signature(discover).parameters.values())
        required = [
            "trace",
            "root_pid",
            "initial_cwd",
            "repo_root",
            "vendor_relative",
            "build_root",
            "stable_sysroot_root",
            "nightly_sysroot_root",
        ]
        self.assertEqual(
            [parameter.name for parameter in parameters],
            required,
            "discover_input_v1 signature drifted",
        )
        self.assertIs(
            parameters[0].kind,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            "discover_input_v1 trace is not positional",
        )
        self.assertFalse(
            any(
                parameter.kind is not inspect.Parameter.KEYWORD_ONLY
                for parameter in parameters[1:]
            ),
            "discover_input_v1 roots are not keyword-only",
        )
        self.assertFalse(
            any(
                parameter.kind
                in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
                for parameter in parameters
            ),
            "discover_input_v1 accepts variadic arguments",
        )
        self.assertFalse(
            any(parameter.default is not inspect.Parameter.empty for parameter in parameters),
            "discover_input_v1 arguments are not all required",
        )
        self.assertFalse(
            callable(getattr(self.module, "reconcile_input_v1", None)),
            "reconcile_input_v1 is callable on the candidate-only module",
        )

        runner = getattr(self.module, "run_reconciled_build", None)
        self.assertTrue(callable(runner), "run_reconciled_build is missing or not callable")

        kwargs = dict(
            root_pid=1,
            initial_cwd="/",
            repo_root="/",
            vendor_relative="vendor",
            build_root="/tmp/build",
            stable_sysroot_root="/tmp/stable",
            nightly_sysroot_root="/tmp/nightly",
        )
        for name in ("expected", "production"):
            with self.subTest(forbidden_keyword=name):
                with self.assertRaises(TypeError):
                    discover(b"", **kwargs, **{name: b""})

        runner_parameters = list(inspect.signature(runner).parameters.values())
        runner_names = [parameter.name for parameter in runner_parameters]
        self.assertEqual(
            runner_names,
            [
                "expected_ledger_fd",
                "repo_root",
                "vendor_relative",
                "stable_sysroot_root",
                "nightly_sysroot_root",
                "private_parent_fd",
            ],
            "run_reconciled_build signature drifted",
        )
        self.assertFalse(
            any(
                parameter.kind is not inspect.Parameter.KEYWORD_ONLY
                for parameter in runner_parameters
            ),
            "run_reconciled_build parameters are not keyword-only",
        )
        self.assertFalse(
            any(
                parameter.kind
                in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
                for parameter in runner_parameters
            ),
            "run_reconciled_build accepts variadic arguments",
        )
        self.assertFalse(
            any(
                parameter.default is not inspect.Parameter.empty
                for parameter in runner_parameters
            ),
            "run_reconciled_build arguments are not all required",
        )
        by_name = {parameter.name: parameter for parameter in runner_parameters}
        for name in ("expected_ledger_fd", "private_parent_fd"):
            self.assertIs(
                by_name[name].annotation,
                int,
                f"run_reconciled_build {name} annotation drifted",
            )
        self.assertIs(
            by_name["vendor_relative"].annotation,
            str,
            "run_reconciled_build vendor_relative annotation drifted",
        )
        for name in ("repo_root", "stable_sysroot_root", "nightly_sysroot_root"):
            self.assertIs(
                by_name[name].annotation,
                inspect.Parameter.empty,
                f"run_reconciled_build {name} must be unannotated",
            )
        self.assertEqual(
            inspect.signature(runner).return_annotation,
            "ProductionFreeze",
            "run_reconciled_build return annotation drifted",
        )
        for name in ("run", "capture", "produce", "reconcile_input_v1"):
            with self.subTest(absent_entrypoint=name):
                self.assertFalse(
                    callable(getattr(self.module, name, None)),
                    f"{name} is callable on the refusal-only module",
                )


if __name__ == "__main__":
    program = unittest.main(exit=False)
    raise SystemExit(
        program.result.testsRun == 0
        or not program.result.wasSuccessful()
        or bool(program.result.skipped)
    )
