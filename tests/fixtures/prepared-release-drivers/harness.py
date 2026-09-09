"""Load uniquely delimited actual function definitions for native EXIT tests."""

import json
import os
from pathlib import Path
import shutil
import sys

NATIVE = Path(__file__).resolve().parent


def run_finalizer(fixture, scenario):
    lane = fixture.lane
    source = (fixture.repo / "scripts" / ("build-release.sh" if lane == "release" else "verify-task4-lane16.sh")).read_text()
    start = "MODULE=/usr/lib/softhsm/libsofthsm2.so\n" if lane == "release" else "prepare_root() {\n"
    end = "task4_receipt_run() {\n" if lane == "release" else '[ "$#" -ge 1 ] || usage\n'
    if source.count(start) != 1 or source.count(end) != 1:
        raise AssertionError("actual finalizer definition boundary changed")
    definitions = fixture.base / "definitions.sh"
    definitions.write_text(source[source.index(start):source.index(end)])
    alternate = fixture.base / "redirected-root.json"
    metadata = json.loads(fixture.prepared.root_metadata.read_text())
    metadata["resolve"]["nodes"][0]["features"] = ["redirected-fixture-selection"]
    alternate.write_text(json.dumps(metadata))
    selection = fixture.base / "redirected-selection.json"
    selection.write_text(json.dumps({"root": str(alternate), "bpf": str(fixture.prepared.bpf_metadata)}))
    fixture.prepared.config["redirect_selection"] = str(selection)
    fixture.prepared.write_config()
    harness = fixture.base / "finalize.sh"
    fixture.template(str(NATIVE / "finalize.sh.in"), harness, DEFINITIONS=definitions, REPO=fixture.repo,
                     ROOT=fixture.root, SCENARIO=scenario, LANE=lane, SEALED_BIN=fixture.base / "sealed-bin",
                     FIND=shutil.which("find"), PYTHON=sys.executable, MUTATOR=NATIVE / "mutate.py",
                     CONFIG=fixture.prepared.config_path, PREPARED_SOURCE=fixture.prepared.base.output / "src/lib.rs")
    environment = dict(os.environ)
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET",
                 "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTC_WRAPPER", "CC", "CFLAGS",
                 "P11SCOPE_PRODUCT_BUILD_MODE", "P11SCOPE_PREPARED_STABLE_CARGO",
                 "P11SCOPE_PREPARED_STABLE_RUSTC", "P11SCOPE_PREPARED_BPF_CARGO",
                 "P11SCOPE_PREPARED_BPF_RUSTC"):
        environment.pop(name, None)
    overrides = {"PATH": str(fixture.fake_bin) + ":" + os.environ["PATH"], "HOME": str(fixture.home)}
    environment.update(overrides)
    return fixture.command(["/bin/sh", str(harness)], environment=environment, overrides=overrides)
