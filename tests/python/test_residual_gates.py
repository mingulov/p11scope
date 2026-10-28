# SPDX-License-Identifier: GPL-3.0-or-later
"""SYSPLAN residual CI/doc gates (F-04, F-28, F-27, F-63, F-40, F-30, F-29).

Each test pins one residual finding's recurring gate: a privileged E2E job,
a release-preview job, an advisory/deny gate, a scripts lint gate, a
coverage gate with a ratchet, a help/usage drift check, and the flake
quarantine mapping. All fail until the gates land (RED); the suite stays
green by implementation, never by weakening.

Run: python3 -I tests/python/test_residual_gates.py -v
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
DENY_TOML = ROOT / "deny.toml"
QUARANTINE = ROOT / "docs" / "notes" / "test-quarantine.md"


def ci_text():
    return CI_YML.read_text(encoding="utf-8")


def hosted_job():
    return ci_text().split("\n  privileged-e2e:\n", 1)[1].split("\n  release-preview:\n", 1)[0]


def hosted_step(name):
    marker = f"      - name: {name}\n"
    block = hosted_job()
    if marker not in block:
        raise AssertionError(f"hosted capture step missing: {name}")
    step = block.split(marker, 1)[1].split("\n      - ", 1)[0]
    if "        run: |\n" not in step:
        raise AssertionError(f"hosted capture step has no shell body: {name}")
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


def hosted_python(name):
    return hosted_step(name).split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]


class PackagedBpftool(unittest.TestCase):
    def install_step(self, job):
        block = ci_text().split(f"\n  {job}:\n", 1)[1]
        step = block.split("      - name: Install packaged bpftool\n", 1)[1]
        return textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n      - ", 1)[0])

    def exercise(self, job, layout="standalone", **overrides):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            (root / "usr/local/bin").mkdir(parents=True)
            source = root / ("usr/lib/linux-tools/6.8.0-90-generic/bpftool"
                             if layout.startswith("legacy") else "usr/sbin/bpftool")
            source.parent.mkdir(parents=True)
            source.write_text('#!/bin/sh\nprintf "version\\n" >> "$STUB_LOG"\nexit "${STUB_VERSION_RC:-0}"\n')
            source.chmod(0o644 if layout == "not-executable" else 0o755)
            package = tools / "dpkg-query"
            package.write_text(textwrap.dedent("""\
                #!/bin/sh
                if [ "$1" = -L ] && [ "$2" = bpftool ]; then
                    case $STUB_LAYOUT in
                        legacy*) exit 1 ;;
                        query-error) exit 2 ;;
                        missing) exit 0 ;;
                        foreign) printf '%s/usr/local/bin/bpftool\n' "$STUB_ROOT" ;;
                        duplicate) printf '%s/usr/sbin/bpftool\n%s/usr/bin/bpftool\n' "$STUB_ROOT" "$STUB_ROOT" ;;
                        *) printf '%s/usr/sbin/bpftool\n' "$STUB_ROOT" ;;
                    esac
                elif [ "$1" = -W ]; then
                    if [ "$STUB_LAYOUT" = legacy-malformed ]; then printf 'unrelated-package\n'
                    else printf 'linux-tools-6.8.0-90-generic\n'; fi
                elif [ "$1" = -L ] && [ "$2" = linux-tools-6.8.0-90-generic ]; then
                    if [ "$STUB_LAYOUT" = legacy-unowned ]; then printf '/foreign/bpftool\n'
                    else printf '%s/usr/lib/linux-tools/6.8.0-90-generic/bpftool\n' "$STUB_ROOT"; fi
                else exit 2; fi
                """))
            package.chmod(0o755)
            sudo = tools / "sudo"
            sudo.write_text(textwrap.dedent("""\
                #!/bin/sh
                printf '%s\n' "$*" >> "$STUB_LOG"
                if [ "$1" = apt-get ]; then exit "${STUB_APT_RC:-0}"; fi
                if [ "$1" = bpftool ] && [ "${STUB_SUDO_VERSION_RC:-0}" != 0 ]; then
                    exit "$STUB_SUDO_VERSION_RC"
                fi
                exec "$@"
                """))
            sudo.chmod(0o755)
            # Rebase only fixed system paths into the owned fixture; execute
            # the actual shell discovery, file checks, install and probes.
            program = self.install_step(job).replace("/usr/", str(root) + "/usr/")
            environment = os.environ | {"PATH": os.pathsep.join((str(root / "usr/local/bin"),
                                            str(tools), "/usr/bin", "/bin")),
                                        "STUB_LAYOUT": layout, "STUB_ROOT": str(root),
                                        "STUB_LOG": str(root / "commands.log")} | overrides
            result = subprocess.run(["bash", "-c", program], env=environment,
                                    text=True, capture_output=True, timeout=10)
            log = (root / "commands.log").read_text().splitlines()
            installed = root / "usr/local/bin/bpftool"
            return result, log, installed.read_bytes() if installed.exists() else None, source.read_bytes()

    def test_standalone_and_legacy_packages_execute_both_version_probes(self):
        for job in ("bpf-noninterference", "release-preview"):
            for layout in ("standalone", "legacy"):
                with self.subTest(job=job, layout=layout):
                    result, log, installed, source = self.exercise(job, layout)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(installed, source)
                    self.assertEqual(log.count("version"), 2)
                    self.assertIn("bpftool version", log)

    def test_invalid_package_layout_never_runs_a_version_probe(self):
        for job in ("bpf-noninterference", "release-preview"):
            for layout in ("missing", "foreign", "duplicate", "not-executable", "query-error",
                           "legacy-malformed", "legacy-unowned"):
                with self.subTest(job=job, layout=layout):
                    result, log, _, _ = self.exercise(job, layout)
                    self.assertNotEqual(result.returncode, 0, "invalid package layout was accepted")
                    self.assertNotIn("version", log)

    def test_package_install_and_each_version_probe_failures_propagate(self):
        for job in ("bpf-noninterference", "release-preview"):
            for variable, status in (("STUB_APT_RC", "3"), ("STUB_VERSION_RC", "7"),
                                     ("STUB_SUDO_VERSION_RC", "8")):
                with self.subTest(job=job, variable=variable):
                    result, _, _, _ = self.exercise(job, **{variable: status})
                    self.assertEqual(result.returncode, int(status), result.stderr)


class KnativeManifestSchema(unittest.TestCase):
    def schema(self):
        return {"type": "object", "properties": {"spec": {"type": "object",
                "required": ["template"], "properties": {"template": {"type": "object"}}}}}

    def crd(self):
        return {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
                "metadata": {"name": "services.serving.knative.dev"},
                "spec": {"group": "serving.knative.dev", "names": {"kind": "Service"},
                         "versions": [{"name": "v1", "served": True,
                                       "schema": {"openAPIV3Schema": self.schema()}}]}}

    def exercise(self, documents, *, bad_digest=False, validator_status=0):
        import hashlib

        block = ci_text().split("\n  release-preview:\n", 1)[1]
        marker = "      - name: Validate Kubernetes and Knative manifests\n"
        if marker not in block:
            self.fail("release preview lacks the scoped Knative schema input")
        step = block.split(marker, 1)[1].split("\n      - ", 1)[0]
        lines = []
        for line in step.split("        run: |\n", 1)[1].splitlines():
            if line and not line.startswith("          "):
                break
            lines.append(line)
        program = textwrap.dedent("\n".join(lines)) + "\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            source = root / "crds.yaml"
            source.write_text("\n---\n".join(json.dumps(row) for row in documents))
            digest = "0" * 64 if bad_digest else hashlib.sha256(source.read_bytes()).hexdigest()
            (root / "scripts/knative-e2e.sh").write_text(
                f"KNATIVE_VERSION=knative-v1.23.0\nCRDS_SHA256={digest}\n")
            tools = root / "tools"
            tools.mkdir()
            curl = tools / "curl"
            curl.write_text(textwrap.dedent("""\
                #!/usr/bin/python3
                import os, pathlib, shutil, sys
                pathlib.Path(os.environ['STUB_URL']).write_text(sys.argv[-1])
                shutil.copyfile(os.environ['STUB_SOURCE'], sys.argv[sys.argv.index('-o') + 1])
                """))
            curl.chmod(0o755)
            release_tools = root / "release-tools"
            release_tools.mkdir()
            validator = release_tools / "kubeconform"
            validator.write_text(textwrap.dedent("""\
                #!/usr/bin/python3
                import json, os, pathlib, sys
                template = sys.argv[sys.argv.index('default') + 2]
                schemas = pathlib.Path(template.split('/{{', 1)[0])
                files = {str(p.relative_to(schemas)): json.loads(p.read_text())
                         for p in schemas.rglob('*.json')}
                pathlib.Path(os.environ['STUB_LOG']).write_text(json.dumps([sys.argv[1:], files]))
                sys.exit(int(os.environ['STUB_VALIDATOR_STATUS']))
                """))
            validator.chmod(0o755)
            environment = os.environ | {"PATH": str(tools) + ":/usr/bin:/bin",
                                        "RUNNER_TEMP": str(root), "STUB_SOURCE": str(source),
                                        "STUB_LOG": str(root / "validator.json"),
                                        "STUB_URL": str(root / "url.txt"),
                                        "STUB_VALIDATOR_STATUS": str(validator_status)}
            result = subprocess.run(["bash", "-c", program], cwd=root, env=environment,
                                    text=True, capture_output=True, timeout=10)
            log = root / "validator.json"
            return (result, json.loads(log.read_text()) if log.exists() else None,
                    (root / "url.txt").read_text())

    def test_only_served_knative_service_v1_is_materialized_with_scoped_fallback(self):
        irrelevant = self.crd()
        irrelevant["metadata"]["name"] = "configurations.serving.knative.dev"
        irrelevant["spec"]["names"]["kind"] = "Configuration"
        crd = self.crd()
        crd["spec"]["versions"].append({"name": "v1beta1", "served": True,
                                        "schema": {"openAPIV3Schema": {"type": "string"}}})
        result, log, url = self.exercise([irrelevant, crd])
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments, files = log
        self.assertEqual(arguments[:4], ["-summary", "-schema-location", "default", "-schema-location"])
        self.assertTrue(arguments[4].endswith("/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"))
        self.assertEqual(arguments[5:], ["deploy/k8s/"])
        self.assertEqual(files, {"serving.knative.dev/service_v1.json": self.schema()})
        self.assertEqual(url, "https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml")

    def test_wrong_identity_unserved_or_missing_schema_refuses_before_validation(self):
        for mutation in ("group", "kind", "unserved", "schema"):
            with self.subTest(mutation=mutation):
                crd = self.crd()
                if mutation == "group":
                    crd["spec"]["group"] = "foreign.example"
                elif mutation == "kind":
                    crd["spec"]["names"]["kind"] = "Configuration"
                elif mutation == "unserved":
                    crd["spec"]["versions"][0]["served"] = False
                else:
                    del crd["spec"]["versions"][0]["schema"]
                result, log, _ = self.exercise([crd])
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(log)

    def test_duplicate_crd_or_served_version_refuses_before_validation(self):
        crd = self.crd()
        duplicate_version = self.crd()
        duplicate_version["spec"]["versions"] *= 2
        for documents in ([crd, crd], [duplicate_version]):
            with self.subTest(documents=documents):
                result, log, _ = self.exercise(documents)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(log)

    def test_crd_digest_mismatch_refuses_before_validation(self):
        result, log, _ = self.exercise([self.crd()], bad_digest=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(log)

    def test_validator_failure_is_the_step_failure(self):
        result, log, _ = self.exercise([self.crd()], validator_status=7)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIsNotNone(log)


class ResidualGates(unittest.TestCase):
    def test_privileged_e2e_job_exists(self):
        """F-04: one privileged CI E2E job running the gated capture cells."""
        text = ci_text()
        self.assertIn("privileged-e2e", text)
        self.assertIn("system-scope-measure", text)
        block = hosted_job()
        self.assertIn("runs-on: ubuntu-26.04", block)
        self.assertNotIn("self-hosted", block)
        timeout = re.search(r"(?m)^    timeout-minutes: (\d+)$", block)
        self.assertIsNotNone(timeout, "hosted capture needs a finite job deadline")
        self.assertGreater(int(timeout[1]), 0)
        self.assertLessEqual(int(timeout[1]), 60)
        self.assertLess(block.index("Build observer and discovery helper"),
                        block.index("Run four gated system-scope cells"))
        self.assertIn("--release -p p11scope -p p11scope-discover", block)

    def test_hosted_system_cell_validator_refuses_missing_or_unproven(self):
        program = hosted_python("Validate four required capture records")
        expected = ("pid/metrics", "pid/profile", "system/metrics", "system/profile")
        records = {}
        for key in expected:
            scope, mode = key.split("/")
            records[key] = {
                "condition": {"scope": scope, "mode": mode, "n_calls": 20000},
                "truth_vs_observed": {"counts_match": True, "truth": {"C_GenerateRandom": 20000}},
                "window": {"window_valid": True},
                "harness": {"observer_exit": 0, "observer_timed_out": False, "observer_signal": None},
                "evidence": {"counters": {"event_loss": 0, "semantic_capture_failures": 0},
                             "in_flight_at_end": 0},
            }
        good = {"schema": "p11scope/system-scope-matrix/v1", "records": records}
        with tempfile.TemporaryDirectory() as temporary:
            matrix = Path(temporary) / "matrix.json"
            for key, row in records.items():
                report = Path(temporary) / (key.replace("/", "-") + ".json")
                row["artifacts"] = {"report": str(report)}
            cases = [("complete", good, True)]
            missing = json.loads(json.dumps(good))
            del missing["records"]["system/profile"]
            cases.append(("missing cell", missing, False))
            for field, bad in (("counts_match", False), ("counts_match", "true"),
                               ("window_valid", False), ("observer_exit", 1),
                               ("observer_timed_out", True), ("observer_signal", 2),
                               ("n_calls", 0), ("C_GenerateRandom", 0), ("scope", "pid"),
                               ("event_loss", 1), ("semantic_capture_failures", 1),
                               ("in_flight_at_end", 1), ("event_loss", False)):
                changed = json.loads(json.dumps(good))
                row = changed["records"]["system/profile"]
                section = ({"counts_match": "truth_vs_observed", "window_valid": "window",
                            "observer_exit": "harness", "observer_timed_out": "harness",
                            "observer_signal": "harness", "n_calls": "condition", "scope": "condition",
                            "in_flight_at_end": "evidence"})
                if field == "C_GenerateRandom":
                    row["truth_vs_observed"]["truth"][field] = bad
                elif field in ("event_loss", "semantic_capture_failures"):
                    row["evidence"]["counters"][field] = bad
                else:
                    row[section[field]][field] = bad
                cases.append((field, changed, False))
            cases.extend((control, good, False) for control in ("drain unproven", "drain missing"))
            for control, document, passes in cases:
                with self.subTest(control=control):
                    for row in records.values():
                        evidence = {"drain_proven": True}
                        if control == "drain unproven":
                            evidence["drain_proven"] = False
                        elif control == "drain missing":
                            evidence = {}
                        Path(row["artifacts"]["report"]).write_text(json.dumps({"evidence": evidence}))
                    matrix.write_text(json.dumps(document))
                    result = subprocess.run([sys.executable, "-I", "-", str(matrix)],
                                            input=program, text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, passes, result.stderr)
                    if passes:
                        self.assertEqual(result.stdout.count("PASS "), 4)

    def test_hosted_capture_step_uses_prebuilt_pair_and_propagates_failure(self):
        program = hosted_step("Run four gated system-scope cells")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "bin"
            tools.mkdir()
            release = root / "target/release"
            release.mkdir(parents=True)
            for name in ("p11scope", "p11scope-discover"):
                executable = release / name
                executable.write_text(textwrap.dedent("""\
                    #!/bin/sh
                    mode=${STUB_DOCTOR_MODE:-clean}
                    printf 'uprobe-multi attach (own libc) ... ok\\n'
                    if [ "$mode" != missing ]; then
                        word=ok
                        [ "$mode" != bad ] || word=fail
                        printf 'uretprobe vs seccomp ... %s\\n' "$word"
                    fi
                    if [ "$mode" = duplicate ]; then printf 'uretprobe vs seccomp ... ok\\n'; fi
                    exit "${STUB_DOCTOR_RC:-0}"
                    """))
                executable.chmod(0o755)
            sudo = tools / "sudo"
            sudo.write_text('#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n')
            sudo.chmod(0o755)
            pgrep = tools / "pgrep"
            pgrep.write_text('#!/bin/sh\nexit "${STUB_PGREP_RC:-1}"\n')
            pgrep.chmod(0o755)
            scripts = root / "scripts"
            scripts.mkdir()
            harness = scripts / "system-scope-measure.sh"
            harness.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$@" > "$TMPDIR/argv.txt"\nexit "${CAPTURE_EXIT:-0}"\n')
            harness.chmod(0o755)
            environment = os.environ | {"PATH": str(tools) + os.pathsep + os.environ["PATH"],
                                        "TMPDIR": str(root)}
            result = subprocess.run(["bash", "-c", program], cwd=root, env=environment,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            args = (root / "argv.txt").read_text().splitlines()
            self.assertEqual(args[args.index("--binary") + 1], str(release / "p11scope"))
            self.assertIn("--no-build", args)
            self.assertNotIn("--discover", args, "helper must use the harness's real sibling interface")
            self.assertEqual(args[args.index("--scope") + 1], "both")
            self.assertEqual(args[args.index("--mode") + 1], "both")
            result = subprocess.run(["bash", "-c", program], cwd=root,
                                    env=environment | {"CAPTURE_EXIT": "9"}, text=True, capture_output=True)
            self.assertEqual(result.returncode, 9, "a failed real capture must fail the job")
            doctor_cases = [(1, "clean", True), (2, "clean", False), (127, "clean", False)]
            doctor_cases.extend((status, mode, False) for status in (0, 1)
                                for mode in ("bad", "missing", "duplicate"))
            for status, mode, passes in doctor_cases:
                with self.subTest(doctor_status=status, rows=mode):
                    result = subprocess.run(["bash", "-c", program], cwd=root,
                                            env=environment | {"STUB_DOCTOR_RC": str(status),
                                                               "STUB_DOCTOR_MODE": mode},
                                            text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, passes, result.stderr)
                    if passes:
                        self.assertEqual((root / "hosted-doctor-status.txt").read_text(), "1\n")
            for status in (0, 2, 3, 127):
                with self.subTest(pgrep_status=status):
                    result = subprocess.run(["bash", "-c", program], cwd=root,
                                            env=environment | {"STUB_PGREP_RC": str(status)},
                                            text=True, capture_output=True)
                    self.assertNotEqual(result.returncode, 0, "busy or failed process inspection must prevent capture")

    def test_hosted_failure_context_is_bounded_and_owned(self):
        program = hosted_python("Collect bounded capture context")
        for failed in (False, True):
            with (self.subTest(failed=failed), tempfile.TemporaryDirectory() as temporary,
                  tempfile.TemporaryDirectory() as foreign_directory):
                root = Path(temporary)
                (root / "hosted-doctor.txt").write_bytes(b"d" * 20000)
                (root / "hosted-doctor-status.txt").write_text("1\n")
                cells = root / "hosted-system-e2e"
                cell = cells / "pid-metrics"
                cell.mkdir(parents=True)
                (cell / "stderr.txt").write_bytes(b"e" * 30000)
                (cell / "workload.log").write_bytes(b"w" * 30000)
                (cell / "foreign.log").write_text("PRIVATE_UNSELECTED_CONTENT")
                foreign = Path(foreign_directory)
                (foreign / "stderr.txt").write_text("PRIVATE_UNSELECTED_CONTENT")
                (foreign / "workload.log").write_text("PRIVATE_UNSELECTED_CONTENT")
                (cells / "pid-profile").symlink_to(foreign, target_is_directory=True)
                result = subprocess.run([sys.executable, "-I", "-", str(root)], input=program,
                                        env=os.environ | {"CAPTURE_FAILED": str(failed).lower()},
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs = list((root / "hosted-context").iterdir())
                self.assertEqual(len(outputs), 4 if failed else 2)
                for output in outputs:
                    self.assertLessEqual(output.stat().st_size, 16384)
                    self.assertNotIn(b"PRIVATE_UNSELECTED_CONTENT", output.read_bytes())

    def test_hosted_step_env_does_not_call_if_only_status_functions(self):
        # GitHub Context availability permits these functions in steps.if,
        # not steps.env. YAML and shell parsing cannot validate that API.
        block = hosted_job().split("      - name: Collect bounded capture context\n", 1)[1]
        environment = block.split("        env:\n", 1)[1].split("        run:", 1)[0]
        self.assertNotRegex(environment, r"\b(?:always|cancelled|failure|success)\s*\(")

    def test_release_preview_job_exists(self):
        """F-28: release-preview CI job (musl/docker/SBOM/build-release)."""
        text = ci_text()
        self.assertIn("release-preview", text)
        self.assertIn("build-release.sh", text)

    def test_dispatch_only_jobs_can_be_dispatched(self):
        """F-28: jobs gated on workflow_dispatch need that trigger in `on:`;
        without it they can never run."""
        text = ci_text()
        on_line = next(line for line in text.splitlines() if line.startswith("on:"))
        on_block = on_line
        if on_line == "on:":
            on_block = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn("workflow_dispatch", on_block)
        for job in ("privileged-e2e", "release-preview"):
            block = text.split(f"\n  {job}:\n", 1)[1]
            gate = block.splitlines()[0].strip()
            self.assertTrue(
                gate.startswith("if: ${{ github.event_name == 'workflow_dispatch'"),
                f"{job}: {gate}",
            )

    def test_release_preview_passes_an_evidence_root(self):
        """F-28: build-release.sh exits 2 without its one evidence-root
        argument, whose parent also supplies the private temporary directory."""
        block = ci_text().split("\n  release-preview:\n", 1)[1]
        block = block.split("\n  coverage:\n", 1)[0]
        self.assertIn('mkdir -m 700 "$RUNNER_TEMP/release-evidence"', block)
        self.assertIn(
            '- run: TMPDIR="$RUNNER_TEMP/release-evidence" '
            'scripts/build-release.sh "$RUNNER_TEMP/release-evidence/receipt"',
            block,
        )
        self.assertNotIn("- run: scripts/build-release.sh\n", block)

    def test_advisory_gate_exists(self):
        """F-27: cargo audit/deny CI gate + deny.toml."""
        text = ci_text()
        self.assertTrue(
            "cargo-audit" in text or "cargo audit" in text, "no cargo audit gate"
        )
        self.assertTrue(
            "cargo-deny" in text or "cargo deny" in text, "no cargo deny gate"
        )
        self.assertTrue(DENY_TOML.is_file(), "deny.toml missing")

    def test_release_summary_exposes_fixed_diagnostics_without_private_log_text(self):
        block = ci_text().split("      - name: Release receipt summary\n", 1)[1]
        program = textwrap.dedent(
            block.split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0]
        )
        private = "PRIVATE_CANARY_/secret-path/::error::untrusted"
        cases = (
            (
                "=== release privacy gate ===\n"
                "=== live safe START policy: hostile exact-name and mechanism controls ===\n",
                "capture-stopped-canary: observer-readiness: CustodyError\n",
                "privacy-gate", "canary-safe-start", "matched-signature",
                ["observer-readiness-custody-error"], [], [],
            ),
            (
                "=== p11scope: isolated safe-only official static build ===\n",
                "error[E0463]: private compiler input\nPermission denied (os error 13)\n",
                "static-build", "unknown", "matched-signature", [], ["E0463"], ["EACCES"],
            ),
            (
                "=== release privacy gate === " + private + "\n",
                private + "\n",
                "unknown", "unknown", "unknown", [], [], [],
            ),
        )
        for stdout, stderr, stage, substage, classification, signatures, codes, errnos in cases:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                receipt = root / "receipt"
                receipt.mkdir()
                (receipt / "stdout.log").write_text(stdout + private + "\n")
                (receipt / "stderr.log").write_text(stderr + private + "\n")
                (receipt / "facts.log").write_text("head\t" + private + "\n")
                (receipt / "status").write_text("1\n")
                summary = root / "summary.md"
                result = subprocess.run(
                    [sys.executable, "-I", "-", str(receipt), str(summary)],
                    input=program, text=True, capture_output=True, check=True,
                )
                self.assertIn("release-diagnostic: ", result.stdout)
                report = json.loads(result.stdout.split("release-diagnostic: ", 1)[1])
                self.assertEqual(report["last_recorded_stage"], stage)
                self.assertEqual(report["last_recorded_substage"], substage)
                self.assertEqual(report["stderr_classification"], classification)
                self.assertEqual(report["observed_signature_ids"], signatures)
                self.assertEqual(report["rustc_error_codes"], codes)
                self.assertEqual(report["observed_errno_names"], errnos)
                rendered = result.stdout + result.stderr + summary.read_text()
                self.assertNotIn(private, rendered)
                self.assertNotIn("private compiler input", rendered)

    def test_release_summary_locates_canary_assertions_without_their_values(self):
        block = ci_text().split("      - name: Release receipt summary\n", 1)[1]
        program = textwrap.dedent(
            block.split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0]
        )
        private = "PRIVATE_::error::canary-bytes"
        stderr = (
            "Traceback (most recent call last):\n"
            f'  File "/{private}/scripts/check-canary-evidence.py", line 705, in private_function\n'
            "    assert evidence_total == 2, evidence_total\n"
            f"AssertionError: {private}\n"
            f'  File "/{private}/unknown.py", line 123, in unknown_function\n'
            f'  File "/{private}/capture-stopped-canary.py", line 0, in unknown_function\n'
            f'  File "/{private}/check-canary-evidence.py", line 1234567, in unknown_function\n'
            'canary-failure-location: capture-stopped-canary.py:773\n'
            f'canary-failure-location: {private}:123\n'
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt"
            receipt.mkdir()
            (receipt / "stderr.log").write_text(stderr)
            summary = root / "summary.md"
            result = subprocess.run(
                [sys.executable, "-I", "-", str(receipt), str(summary)],
                input=program, text=True, capture_output=True, check=True,
            )
            report = json.loads(result.stdout.split("release-diagnostic: ", 1)[1])
            self.assertEqual(report.get("python_failure_locations"), [
                {"script": "capture-stopped-canary.py", "line": 773},
                {"script": "check-canary-evidence.py", "line": 705},
            ])
            self.assertIn("python-assertion-failed", report["observed_signature_ids"])
            rendered = result.stdout + result.stderr + summary.read_text()
            for forbidden in (private, "private_function", "unknown.py", "unknown_function",
                              "assert evidence_total", "1234567"):
                self.assertNotIn(forbidden, rendered)

    def test_scripts_lint_gate_exists(self):
        """F-63: shellcheck/ruff CI over scripts/."""
        text = ci_text()
        self.assertIn("shellcheck", text)
        self.assertIn("ruff", text)

    def test_caught_capture_rejection_is_located_without_publishing_its_data(self):
        block = ci_text().split("      - name: Release receipt summary\n", 1)[1]
        program = textwrap.dedent(
            block.split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0]
        )
        private = "PRIVATE_CAPTURE_SCHEMA_AND_PATH"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / private
            capture.write_text(json.dumps({"schema": private, "evidence": {}}))
            rejected = subprocess.run(
                [sys.executable, "-I", str(ROOT / "scripts/check-capture-evidence.py"),
                 "canary", "owned-default-metrics", str(capture)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(rejected.returncode, 1)
            receipt = root / "receipt"
            receipt.mkdir()
            (receipt / "stderr.log").write_text(rejected.stderr)
            (receipt / "stdout.log").write_text(
                "=== release privacy gate ===\n"
                "=== live diagnostic START policy: distinct template faults ===\n"
                "=== owned-default-metrics (default owned metrics) ===\n"
            )
            summary = root / "summary.md"
            result = subprocess.run(
                [sys.executable, "-I", "-", str(receipt), str(summary)],
                input=program, text=True, capture_output=True, check=True,
            )
            report = json.loads(result.stdout.split("release-diagnostic: ", 1)[1])
            self.assertEqual(report["last_recorded_substage"], "canary-owned-default-metrics")
            self.assertIn("capture-evidence-rejected", report["observed_signature_ids"])
            locations = report["python_failure_locations"]
            self.assertTrue(locations)
            self.assertTrue(all(row["script"] == "check-capture-evidence.py" for row in locations))
            source = (ROOT / "scripts/check-capture-evidence.py").read_text().splitlines()
            self.assertTrue(any('"schema"' in source[row["line"] - 1] for row in locations))
            for forbidden in (private, str(root), "capture evidence rejected:"):
                self.assertNotIn(forbidden, result.stdout + result.stderr + summary.read_text())

    def test_release_summary_reports_only_known_bounded_counter_mismatches(self):
        import runpy

        checker = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))
        block = ci_text().split("      - name: Release receipt summary\n", 1)[1]
        program = textwrap.dedent(block.split("<<'PY'\n", 1)[1].split("\n          PY\n", 1)[0])
        errors = []
        for name in checker["COUNTERS"]:
            values = dict.fromkeys(checker["COUNTERS"], 0)
            values[name] = 3
            with self.assertRaises(AssertionError) as caught:
                checker["exact_counters"](values)
            errors.append(f"capture evidence rejected: {caught.exception}\n")
        errors.extend([
            "capture evidence rejected: PRIVATE_COUNTER_NAME: want 0, got 3\n",
            "capture evidence rejected: event_loss: want 0, got 18446744073709551616\n",
            "capture evidence rejected: event_loss: want -1, got 3\n",
            "capture evidence rejected: event_loss: want 0, got True\n",
            "capture evidence rejected: event_loss: want 0, got 4 PRIVATE_VALUE\n",
        ])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "stderr.log").write_text("".join(errors))
            summary = root / "summary.md"
            result = subprocess.run(
                [sys.executable, "-I", "-", str(root), str(summary)],
                input=program, text=True, capture_output=True, check=True,
            )
            report = json.loads(result.stdout.split("release-diagnostic: ", 1)[1])
            self.assertEqual(report["counter_mismatches"], [
                {"counter": name, "expected": 0, "observed": 3}
                for name in sorted(checker["COUNTERS"])
            ])
            public = result.stdout + result.stderr + summary.read_text()
            for private in ("PRIVATE_COUNTER_NAME", "PRIVATE_VALUE", "18446744073709551616"):
                self.assertNotIn(private, public)

    def test_coverage_gate_exists(self):
        """F-40: llvm-cov/tarpaulin CI gate with a ratchet."""
        text = ci_text()
        self.assertTrue(
            "llvm-cov" in text or "tarpaulin" in text, "no coverage gate"
        )

    def test_help_drift_check_exists(self):
        """F-30: CI drift check for flags/help/usage agreement."""
        text = ci_text()
        self.assertTrue(
            "help-drift" in text or "test_help_usage_drift" in text,
            "no help/usage drift check in CI",
        )

    def test_flake_quarantine_mapping_exists(self):
        """F-29: the 7 documented flakes have a quarantine mapping."""
        self.assertTrue(QUARANTINE.is_file(), f"{QUARANTINE} missing")
        text = QUARANTINE.read_text(encoding="utf-8")
        for name in (
            "lane13_evidence_finalizes_only_after_owned_cleanup",
            "metadata_canary_matrix",
            "stopped_canary_capture_lifecycle",
            "native_helper_suite_recorded_launcher_requires_authenticated_generations_and_bounded_cleanup",
            "actual_handoff_helpers_preserve_errno_and_retry_without_renewing_deadlines",
            "release_seal_denies_the_caller_path_to_every_reached_command",
            "signal_settlement_observes_second_sigint_during_fallback_term_grace",
        ):
            self.assertIn(name, text)

    def test_quarantine_tool_cache_preserves_failure_policy(self):
        block = ci_text().split("\n  quarantine:\n", 1)[1]
        self.assertTrue(block.startswith(
            "    needs: [lint, audit, tests, bpf-noninterference, contracts, scripts]\n"))
        condition = block.splitlines()[1].strip()
        prefix, suffix = "if: ${{ failure() && (", ") }}"
        self.assertTrue(condition.startswith(prefix) and condition.endswith(suffix), condition)
        terms = condition[len(prefix):-len(suffix)].split(" || ")
        test_jobs = ("tests", "contracts", "scripts", "bpf-noninterference")
        self.assertEqual(terms, [f"needs.{job}.result == 'failure'" for job in test_jobs])
        selected_jobs = [term.split(".")[1] for term in terms]
        check_jobs = ("lint", "audit", *test_jobs)
        # The fixed failure()/OR form is pinned above. These local result
        # vectors check its selected terms; GitHub scheduling still needs CI.
        cases = (
            ("success", {}, False),
            ("lint-only", {"lint": "failure"}, False),
            ("audit-only", {"audit": "failure"}, False),
            ("lint-and-audit", {"lint": "failure", "audit": "failure"}, False),
            ("tests", {"tests": "failure"}, True),
            ("contracts", {"contracts": "failure"}, True),
            ("scripts", {"scripts": "failure"}, True),
            ("bpf", {"bpf-noninterference": "failure"}, True),
            ("mixed-lint", {"lint": "failure", "tests": "failure"}, True),
            ("mixed-audit", {"audit": "failure", "contracts": "failure"}, True),
            ("cancelled", dict.fromkeys(check_jobs, "cancelled"), False),
            ("cancelled-test", {"tests": "cancelled"}, False),
            ("lint-and-cancelled", {"lint": "failure", "tests": "cancelled"}, False),
            ("skipped", dict.fromkeys(check_jobs, "skipped"), False),
        )
        for name, overrides, expected in cases:
            with self.subTest(trigger=name):
                results = dict.fromkeys(check_jobs, "success")
                results.update(overrides)
                selected = "failure" in results.values() and any(
                    results[job] == "failure" for job in selected_jobs)
                self.assertEqual(selected, expected)
        self.assertIn("      - id: bpf-linker\n", block)
        self.assertIn("          path: ~/.cargo/bin/bpf-linker\n", block)
        self.assertIn(
            "          key: bpf-linker-${{ env.CI_TOOL_BPF_LINKER }}-"
            "${{ steps.keys.outputs.image }}-rust-${{ hashFiles('.release-rust-version') }}\n", block)
        install = 'run: cargo +"$(cat .release-rust-version)" install bpf-linker --version "$CI_TOOL_BPF_LINKER" --locked'
        self.assertIn("      - if: steps.bpf-linker.outputs.cache-hit != 'true'\n        " + install, block)
        self.assertEqual(block.count(install), 1)
        self.assertIn('echo "image=$ImageOS-$ImageVersion" >>"$GITHUB_OUTPUT"', block)
        self.assertNotIn("restore-keys:", block)
        self.assertNotIn("target/debug", block)


QUARANTINE_CASES = (
    ("artifact", "lane13_evidence_finalizes_only_after_owned_cleanup"),
    ("artifact", "metadata_canary_matrix"),
    ("artifact", "stopped_canary_capture_lifecycle"),
    ("artifact", "native_helper_suite_recorded_launcher_requires_authenticated_generations_and_bounded_cleanup"),
    ("lib", "run::tests::actual_handoff_helpers_preserve_errno_and_retry_without_renewing_deadlines"),
    ("artifact", "release_seal_denies_the_caller_path_to_every_reached_command"),
    ("lib", "run::tests::signal_settlement_observes_second_sigint_during_fallback_term_grace"),
)

QUARANTINE_CARGO = '''#!/usr/bin/python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['QUARANTINE_CONTROL'])
args = sys.argv[1:]
with (root / 'events.jsonl').open('a') as stream:
 stream.write(json.dumps({'event': 'compile' if '--no-run' in args else 'cargo-run',
                          'argv': args, 'target': os.environ.get('CARGO_TARGET_DIR')}) + '\\n')
if '--no-run' not in args:
 print('running 1 test\\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;')
 sys.exit(0)
if os.environ['QUARANTINE_MODE'] == 'build-failure':
 print('controlled Cargo build failure', file=sys.stderr)
 sys.exit(37)
print((root / 'build.jsonl').read_text(), end='')
'''

QUARANTINE_TEST = '''#!/usr/bin/python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['QUARANTINE_CONTROL'])
role = @ROLE@
args = sys.argv[1:]
allowed = {name: kind for kind, name in json.loads((root / 'cases.json').read_text())}
if len(args) != 4 or args[1:] != ['--exact', '--nocapture', '--test-threads=1'] or allowed.get(args[0]) != role:
 sys.exit(91)
active = root / 'active-test'
fd = os.open(active, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
 with (root / 'events.jsonl').open('a') as stream:
  stream.write(json.dumps({'event': 'start', 'role': role, 'argv': args}) + '\\n')
 mode = os.environ['QUARANTINE_MODE']
 selected = args[0] == 'metadata_canary_matrix'
 if selected and mode == 'failed-case':
  print('running 1 test\\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;')
  sys.exit(1)
 if selected and mode == 'zero-match':
  print('running 0 tests\\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;')
 else:
  print('running 1 test\\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;')
finally:
 os.close(fd)
 active.unlink()
 with (root / 'events.jsonl').open('a') as stream:
  stream.write(json.dumps({'event': 'finish', 'role': role, 'argv': args}) + '\\n')
'''


class QuarantineRunnerTests(unittest.TestCase):
    def run_case(self, mode="healthy", *, custom_target=False):
        with tempfile.TemporaryDirectory(prefix="quarantine-control-") as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            (checkout / "scripts").mkdir(parents=True)
            script = checkout / "scripts/run-flake-quarantine.sh"
            script.write_bytes((ROOT / "scripts/run-flake-quarantine.sh").read_bytes())
            release = (ROOT / ".release-rust-version").read_text().strip()
            (checkout / ".release-rust-version").write_text(release + "\n")
            (root / "cases.json").write_text(json.dumps(QUARANTINE_CASES))
            private_tmp = root / "private tmp"
            private_tmp.mkdir(mode=0o700)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            cargo = bin_dir / "cargo"
            cargo.write_text(QUARANTINE_CARGO)
            cargo.chmod(0o755)
            target = root / "custom target" if custom_target else checkout / "target/quarantine"
            executables = target / "debug/deps"
            executables.mkdir(parents=True)
            records = []
            for role, name, kind, source in (
                ("lib", "p11scope", "lib", "src/lib.rs"),
                ("artifact", "artifact_contracts", "test", "tests/artifact_contracts.rs"),
            ):
                executable = executables / (role + " test executable")
                if role == "artifact" and mode == "outside-target":
                    executable = root / "foreign executable"
                executable.write_text(QUARANTINE_TEST.replace("@ROLE@", json.dumps(role)))
                executable.chmod(0o644 if role == "artifact" and mode == "nonexecutable" else 0o755)
                record = {"reason": "compiler-artifact", "profile": {"test": True},
                          "target": {"name": name, "kind": [kind], "src_path": str(checkout / source)},
                          "executable": str(executable)}
                if role == "artifact":
                    # Other packages and normal builds must not license a stale executable.
                    records.append(dict(record, target={**record["target"], "src_path": str(root / "other-package.rs")}))
                    records.append(dict(record, profile={"test": False}))
                if role != "artifact" or mode != "missing":
                    records.append(record)
                if role == "artifact" and mode == "ambiguous":
                    records.append(record)
            payload = "\n".join(json.dumps(record) for record in records) + "\n"
            if mode == "malformed":
                payload += "not Cargo JSON\n"
            (root / "build.jsonl").write_text(payload)
            env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                       TMPDIR=str(private_tmp), QUARANTINE_CONTROL=str(root), QUARANTINE_MODE=mode)
            env.pop("CARGO_TARGET_DIR", None)
            if custom_target:
                env["CARGO_TARGET_DIR"] = str(target)
            result = subprocess.run(["sh", str(script)], env=env, text=True, capture_output=True, timeout=5)
            event_file = root / "events.jsonl"
            events = [json.loads(line) for line in event_file.read_text().splitlines()] if event_file.exists() else []
            self.assertFalse((root / "active-test").exists())
            return result, events, release, str(target)

    def assert_seven_serial_runs(self, events):
        self.assertEqual([event["event"] for event in events], ["compile"] + ["start", "finish"] * 7)
        for event, (role, selector) in zip(events[1::2], QUARANTINE_CASES):
            self.assertEqual((event["role"], event["argv"]),
                             (role, [selector, "--exact", "--nocapture", "--test-threads=1"]))
        self.assertEqual(events[1::2], [{**event, "event": "start"} for event in events[2::2]])

    def test_one_compile_runs_seven_exact_serial_cases(self):
        result, events, release, _target = self.run_case()
        self.assertEqual(result.returncode, 0, result.stdout[-1000:] + result.stderr[-1000:])
        self.assert_seven_serial_runs(events)
        self.assertEqual(events[0]["argv"], ["+" + release, "test", "--locked", "--offline", "--lib",
                                             "--test", "artifact_contracts", "--no-run", "--message-format=json"])
        self.assertEqual(events[0]["target"], "target/quarantine")
        self.assertIn("quarantine: 7 passed, 0 failed in isolation", result.stdout)

    def test_custom_target_directory_is_preserved(self):
        result, events, _release, target = self.run_case(custom_target=True)
        self.assertEqual(result.returncode, 0, result.stdout[-1000:] + result.stderr[-1000:])
        self.assert_seven_serial_runs(events)
        self.assertEqual(events[0]["target"], target)

    def test_failed_case_does_not_skip_later_cases(self):
        result, events, _release, _target = self.run_case("failed-case")
        self.assertNotEqual(result.returncode, 0)
        self.assert_seven_serial_runs(events)
        self.assertIn("quarantine: 6 passed, 1 failed in isolation", result.stdout)

    def test_zero_match_does_not_skip_later_cases(self):
        result, events, _release, _target = self.run_case("zero-match")
        self.assertNotEqual(result.returncode, 0)
        self.assert_seven_serial_runs(events)
        self.assertIn("quarantine: 6 passed, 1 failed in isolation", result.stdout)

    def test_build_failure_prevents_execution(self):
        result, events, _release, _target = self.run_case("build-failure")
        self.assertEqual(result.returncode, 37)
        self.assertEqual([event["event"] for event in events], ["compile"])
        self.assertIn("controlled Cargo build failure", result.stderr)

    def assert_bad_metadata(self, mode):
        result, events, _release, _target = self.run_case(mode)
        self.assertNotEqual(result.returncode, 0, result.stdout[-1000:] + result.stderr[-1000:])
        self.assertEqual([event["event"] for event in events], ["compile"])

    def test_missing_test_executable_is_rejected(self):
        self.assert_bad_metadata("missing")

    def test_ambiguous_test_executable_is_rejected(self):
        self.assert_bad_metadata("ambiguous")

    def test_nonexecutable_output_is_rejected(self):
        self.assert_bad_metadata("nonexecutable")

    def test_malformed_build_output_is_rejected(self):
        self.assert_bad_metadata("malformed")

    def test_executable_outside_private_target_is_rejected(self):
        self.assert_bad_metadata("outside-target")


class ResidualOracleKeys(unittest.TestCase):
    def test_oracle_pins_new_evidence_keys(self):
        """F-02/F-01/F-15: oracle pins drain_proven, verdict_detail,
        uretprobe_override, handoff_child_pid."""
        import runpy

        checker = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))
        keys = checker["BASE_EVIDENCE_KEYS"]
        for key in (
            "drain_proven",
            "verdict_detail",
            "uretprobe_override",
            "handoff_child_pid",
        ):
            self.assertIn(key, keys)


class VerdictRecompute(unittest.TestCase):
    """Review answer (a) / F-1: the oracle recomputes `verdict_detail` from
    the published counters and refuses a document that disagrees."""

    def setUp(self):
        import runpy

        self.checker = runpy.run_path(str(ROOT / "scripts/check-capture-evidence.py"))

    def evidence(self, **counters):
        checker = self.checker
        evidence = checker["evidence_fixture"](checker["LEGACY_SURFACES"])
        evidence.update(table_entries=68, slots=68, active_slots=68, attached_probes=136)
        evidence.update(counters)
        settle = checker.get("settle_fixture_verdict")
        if settle is not None:
            settle(evidence)
        return evidence

    def test_a_lossy_document_cannot_claim_a_clean_detail(self):
        evidence = self.evidence(unmatched_returns=1)
        self.checker["exact_terminal_verdict"](evidence)
        evidence["verdict_detail"] = "clean_but_unproven"
        with self.assertRaises(AssertionError):
            self.checker["exact_terminal_verdict"](evidence)

    def proven(self, **stop):
        """A clean document whose drain the stop gate proved (ruling B)."""
        evidence = self.evidence()
        evidence["stop_quiescence"] = dict(
            {"state": "proven", "post_q_events": False, "post_q_discovery": False}, **stop
        )
        evidence["drain_proven"] = True
        self.checker["settle_fixture_verdict"](evidence)
        evidence["completeness"] = self.checker["expected_terminal_completeness"](evidence)
        return evidence

    def test_a_proven_clean_drain_is_complete(self):
        evidence = self.proven()
        self.assertEqual(evidence["verdict_detail"], "clean_proven")
        self.assertEqual(evidence["completeness"], "COMPLETE")
        self.checker["exact_terminal_verdict"](evidence)
        partial = dict(evidence, completeness="PARTIAL")
        with self.assertRaises(AssertionError):
            self.checker["exact_terminal_verdict"](partial)

    def test_the_latch_needs_a_proven_quiescence_without_post_q_records(self):
        for stop in (
            {"post_q_events": True},
            {"post_q_discovery": True},
            {"state": "unproven"},
            {"state": "not_reached"},
        ):
            with self.subTest(stop=stop), self.assertRaises(AssertionError):
                self.checker["exact_terminal_verdict"](self.proven(**stop))

    def test_a_post_q_flag_needs_a_proven_quiescence(self):
        evidence = self.evidence()
        evidence["stop_quiescence"] = {
            "state": "unproven", "post_q_events": True, "post_q_discovery": False,
        }
        with self.assertRaises(AssertionError):
            self.checker["exact_terminal_verdict"](evidence)
        evidence["stop_quiescence"]["state"] = "proven"
        self.checker["exact_terminal_verdict"](evidence)

    def test_withheld_names_alone_are_attribution_only(self):
        evidence = self.evidence(semantic_unverified_slots=68)
        self.assertEqual(evidence["verdict_detail"], "attribution_only")
        self.checker["exact_terminal_verdict"](evidence)
        for wrong in ("concrete_gap", "clean_but_unproven"):
            bad = dict(evidence, verdict_detail=wrong)
            with self.assertRaises(AssertionError):
                self.checker["exact_terminal_verdict"](bad)


if __name__ == "__main__":
    unittest.main()
