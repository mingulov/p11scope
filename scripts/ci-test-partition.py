# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic partition of the workspace test gate across hosted CI jobs.

The workspace gate is one command:

    cargo +"$(cat .release-rust-version)" test --locked --offline --workspace --all-targets

and coverage runs the same selection under `cargo llvm-cov`. One integration
target, `artifact_contracts`, takes most of the wall time, so the hosted
pipeline runs that gate as several jobs. Every job passes this script the
SAME command; the script narrows `--all-targets` to one partition:

- `rest`: every target the gate selects except `artifact_contracts`
  (`--lib --bins --examples --benches` plus one `--test` per integration test
  target, read from `cargo metadata`, so a new test target joins `rest`
  without anyone editing the workflow). `rest` proves from the combined
  cargo output that every binary cargo ran printed a libtest summary
  with total > 0 (the one testless bin is pinned, not proved) and that
  every selected target ran a section (a silently skipped target fails).
- `contracts:K/N`: shard K of N of `artifact_contracts`. The test list comes
  from the compiled binary (`-- --list --format terse`), the shards from a
  greedy longest-first assignment over the checked-in weights
  (scripts/ci-test-weights.json; an unweighted test gets the default weight,
  so a new test is never left out), and the shard runs its tests with
  `-- --exact NAME...`.

Fail closed: a contracts shard proves from libtest's own output that it ran
exactly its assigned tests (`running N tests` and the final `test result:`
line: passed + failed + ignored + measured == assigned, filtered out ==
listed - assigned). A shard with no tests is an error, never a silent green
(libtest with no filter would run everything; with a filter that matches
nothing it runs nothing and exits 0). Every shard computes the same plan
from the same list, so the N shards together run every listed test exactly
once; `plan` prints that partition and checks it. `rest` proves from the
combined output that every binary cargo ran printed a libtest summary
with total > 0, naming any binary that prints none or runs zero (the
testless p11scope bin is pinned, and a nonzero pin fails as stale),
and that every selected target ran (an expected target with no
`Running` section fails naming it).

Under `cargo llvm-cov` the script names the raw profiles after the partition
(LLVM_PROFILE_FILE_NAME) so profiles from different runners never collide,
and `coverage-pack` / `coverage-unpack` move a shard's profiles and
instrumented executables between runners for one merged
`cargo llvm-cov report`.

Usage:
  python3 -I scripts/ci-test-partition.py --self-test
  python3 -I scripts/ci-test-partition.py run --partition PART -- CARGO_COMMAND...
  python3 -I scripts/ci-test-partition.py plan --shards N (--list-file FILE | -- CARGO_COMMAND...)
  python3 -I scripts/ci-test-partition.py weights LIBTEST_JSON... > scripts/ci-test-weights.json
  python3 -I scripts/ci-test-partition.py coverage-pack --partition PART --target-dir DIR --output DIR
  python3 -I scripts/ci-test-partition.py coverage-unpack --contracts-shards N --target-dir DIR INPUT_DIR

PART is `rest` or `contracts:K/N` (1 <= K <= N).
`weights` reads `cargo test ... -- -Z unstable-options --format json
--report-time` output (RUSTC_BOOTSTRAP=1 lets a stable-built test binary
accept it).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEIGHTS = ROOT / "scripts" / "ci-test-weights.json"
SHARDED_TARGET = "artifact_contracts"
SUBCOMMANDS = ("test", "llvm-cov")
MAX_COVERAGE_OBJECT_BYTES = 256 * 1024 * 1024
# Selectors the partition owns. A command that already narrows the selection
# would be narrowed twice, and the union would no longer be the gate.
FORBIDDEN = {
    "--lib", "--bins", "--bin", "--examples", "--example", "--tests",
    "--test", "--benches", "--bench", "--doc", "-p", "--package",
    "--exclude", "--no-run", "--list",
}
RUNNING = re.compile(r"^running (\d+) tests?$")
RESULT = re.compile(
    r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out;"
)
RUNNING_HEADER = re.compile(r"^\s*Running (\S+) (\S+) \((.*?)\)\s*$")
# Integration tests and benches print the target source without a kind word:
# `Running tests/foo.rs (target/debug/deps/foo-<hash>)`.
RUNNING_SRC_HEADER = re.compile(r"^\s*Running (\S+) \((.*?)\)\s*$")
BARE_RUNNING_HEADER = re.compile(r"^\s*Running (\S+)\s*$")
DOCTEST_HEADER = re.compile(r"^\s*Doc-tests (\S+)\s*$")
# A header-looking line that matches none of the known forms: failing
# closed keeps a future cargo format from merging its summary into the
# previous section and masking that section's verdict.
UNKNOWN_HEADER = re.compile(r"^\s*(Running|Doc-tests)\b")
# The one rest binary that legitimately holds no tests: the p11scope bin
# is CLI dispatch only (src/main.rs), so its total-0 summary is pinned,
# not proved. (binary stem, target source) from the Running header; a
# nonzero pinned binary fails the pin as stale, so the exemption cannot
# linger after a test is added.
REST_ZERO_TEST_PIN = ("p11scope", "src/main.rs")


class PartitionError(Exception):
    pass


def parse_partition(spec):
    """`rest` -> ("rest", None, None); `contracts:K/N` -> ("contracts", K, N)."""
    if spec == "rest":
        return ("rest", None, None)
    match = re.fullmatch(r"contracts:([1-9][0-9]*)/([1-9][0-9]*)", spec)
    if not match:
        raise PartitionError(f"bad partition {spec!r}: want rest or contracts:K/N")
    shard, shards = int(match[1]), int(match[2])
    if shard > shards:
        raise PartitionError(f"bad partition {spec!r}: shard {shard} > {shards}")
    return ("contracts", shard, shards)


def slug(spec):
    kind, shard, shards = parse_partition(spec)
    return "rest" if kind == "rest" else f"contracts-{shard}-of-{shards}"


def check_command(command):
    """The gate command, unmodified except for its one `--all-targets`."""
    if len(command) < 3 or command[0] != "cargo" or not command[1].startswith("+"):
        raise PartitionError("command must be `cargo +TOOLCHAIN test|llvm-cov ...`")
    if command[2] not in SUBCOMMANDS:
        raise PartitionError(f"unsupported cargo subcommand {command[2]!r}")
    if "--" in command:
        raise PartitionError("the command must not carry test-binary arguments (`--`)")
    if command.count("--all-targets") != 1:
        raise PartitionError("the command must select --all-targets exactly once")
    if "--workspace" not in command:
        raise PartitionError("the command must select --workspace")
    for argument in command:
        if argument.split("=", 1)[0] in FORBIDDEN:
            raise PartitionError(f"the command already narrows the selection: {argument}")
    return command


def narrowed(command, selection):
    at = command.index("--all-targets")
    return command[:at] + selection + command[at + 1:]


def test_targets(metadata):
    """Integration test targets the gate runs, as {name: [package, ...]}."""
    members = set(metadata["workspace_members"])
    targets = {}
    for package in metadata["packages"]:
        if package["id"] not in members:
            continue
        for target in package["targets"]:
            if target["kind"] == ["test"] and target.get("test", True):
                targets.setdefault(target["name"], []).append(package["name"])
    return targets


def rest_selection(metadata):
    targets = test_targets(metadata)
    owners = targets.get(SHARDED_TARGET)
    if owners is None:
        raise PartitionError(f"no {SHARDED_TARGET} test target in the workspace")
    if len(owners) != 1:
        raise PartitionError(f"{SHARDED_TARGET} names test targets in {owners}")
    selection = ["--lib", "--bins", "--examples", "--benches"]
    for name in sorted(targets):
        if name != SHARDED_TARGET:
            selection += ["--test", name]
    return selection


def parse_list(output):
    """Test names from `--list --format terse`; anything unexpected fails."""
    names = []
    for line in output.splitlines():
        if not line.strip():
            continue
        if line.endswith(": test"):
            names.append(line[: -len(": test")])
        else:
            raise PartitionError(f"unexpected --list line: {line!r}")
    if not names:
        raise PartitionError("the test binary listed no tests")
    if len(set(names)) != len(names):
        raise PartitionError("the test binary listed a test twice")
    return names


def load_weights(path=WEIGHTS):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("target") != SHARDED_TARGET:
        raise PartitionError(f"{path}: weights are not for {SHARDED_TARGET}")
    default = data.get("default_seconds")
    seconds = data.get("seconds")
    if not isinstance(default, (int, float)) or default <= 0 or not isinstance(seconds, dict):
        raise PartitionError(f"{path}: malformed weights")
    for name, value in seconds.items():
        if not isinstance(value, (int, float)) or value <= 0:
            raise PartitionError(f"{path}: bad weight for {name}")
    return default, seconds


def plan(names, shards, weights):
    """Greedy longest-first: deterministic for a given set of names."""
    if shards < 1:
        raise PartitionError("need at least one shard")
    default, seconds = weights
    order = sorted(names, key=lambda name: (-seconds.get(name, default), name))
    loads = [0.0] * shards
    assigned = [[] for _ in range(shards)]
    for name in order:
        target = min(range(shards), key=lambda index: (loads[index], index))
        assigned[target].append(name)
        loads[target] += seconds.get(name, default)
    for index, tests in enumerate(assigned):
        if not tests:
            raise PartitionError(f"shard {index + 1}/{shards} would run no tests")
    every = [name for tests in assigned for name in tests]
    if sorted(every) != sorted(names) or len(set(every)) != len(every):
        raise PartitionError("internal: the plan is not a partition of the list")
    return [sorted(tests) for tests in assigned], loads


def verify_summary(output, assigned, listed):
    """libtest's own counts must say exactly the assigned tests ran."""
    lines = output.splitlines()
    running = [int(m[1]) for m in map(RUNNING.match, lines) if m]
    results = [m for m in map(RESULT.match, lines) if m]
    if not running or not results:
        raise PartitionError("no libtest summary in the shard output")
    # The binary prints its own `running` line first and its own result line
    # last; a nested libtest run inside a test can only print in between.
    if running[0] != assigned:
        raise PartitionError(f"libtest ran {running[0]} tests, the shard assigned {assigned}")
    passed, failed, ignored, measured, filtered = map(int, results[-1].groups())
    if passed + failed + ignored + measured != assigned:
        raise PartitionError(
            f"libtest accounted for {passed + failed + ignored + measured} tests, "
            f"the shard assigned {assigned}"
        )
    if filtered != listed - assigned:
        raise PartitionError(
            f"libtest filtered out {filtered} tests, expected {listed - assigned}"
        )


def rest_binary_stem(path):
    """Binary name minus the cargo metadata hash (`p11scope-<hash>`)."""
    return re.sub(r"-[0-9a-f]{16}$", "", path.rsplit("/", 1)[-1])


def rest_expected_targets(metadata):
    """(binary stem, package-relative source) cargo must run for rest.

    Lib, bin and integration-test targets run only when their `test` flag
    is set; examples and benches run under `--examples`/`--benches` even
    with `test = false` (observed on cargo 1.99.1), so they are always
    expected. The sharded `artifact_contracts` target runs in the
    contracts partitions, never here.
    """
    members = set(metadata["workspace_members"])
    expected = set()
    for package in metadata["packages"]:
        if package["id"] not in members:
            continue
        root = str(Path(package["manifest_path"]).parent) + "/"
        for target in package["targets"]:
            kind = tuple(target["kind"])
            if kind == ("test",) and target["name"] == SHARDED_TARGET:
                continue
            if kind in (("lib",), ("bin",), ("test",), ("bench",)) \
                    and not target.get("test", True):
                continue
            if kind not in (("lib",), ("bin",), ("example",), ("bench",), ("test",)):
                continue
            src = target["src_path"]
            src = src.removeprefix(root)
            expected.add((target["name"].replace("-", "_"), src))
    return expected


def verify_rest_output(output, expected=None):
    """Every binary cargo ran proved a nonzero libtest selection.

    Cargo's `Running` headers (stderr) delimit one section per binary;
    the binary's own summary is its section's last `test result:` line
    (a nested libtest run inside a test can only print earlier). A
    `Doc-tests` header starts its own section so a doctest summary can
    never stand in for its lib's. A header-looking line that matches
    none of the known forms fails naming the line, so every section
    ends at the next header of any form. When `expected` (from
    `rest_expected_targets`) is given, every expected target must have
    run a section: a selected target cargo silently skips fails naming
    it instead of passing invisibly.
    """
    sections = []  # [(src, binary, [lines])]
    for line in output.splitlines():
        modern = RUNNING_HEADER.match(line)
        if modern is not None:
            _kind, src, binary = modern.groups()
            sections.append((src, binary, []))
            continue
        srcheader = RUNNING_SRC_HEADER.match(line)
        if srcheader is not None:
            src, binary = srcheader.groups()
            sections.append((src, binary, []))
            continue
        doctest = DOCTEST_HEADER.match(line)
        if doctest is not None:
            sections.append((None, f"Doc-tests {doctest.group(1)}", []))
            continue
        bare = BARE_RUNNING_HEADER.match(line)
        if bare is not None:
            sections.append((None, bare.group(1), []))
            continue
        if UNKNOWN_HEADER.match(line):
            raise PartitionError(f"unrecognized rest header: {line.strip()}")
        if sections:
            sections[-1][2].append(line)
    if not sections:
        raise PartitionError("no test binaries ran in the rest output")
    for src, binary, lines in sections:
        results = [match for match in map(RESULT.match, lines) if match]
        if not results:
            raise PartitionError(
                f"rest binary {binary} printed no libtest summary")
        passed, failed, ignored, measured, _filtered = map(
            int, results[-1].groups())
        total = passed + failed + ignored + measured
        pinned = (rest_binary_stem(binary), src) == REST_ZERO_TEST_PIN
        if total == 0 and not pinned:
            raise PartitionError(f"rest binary {binary} ran 0 tests")
        if total > 0 and pinned:
            raise PartitionError(
                f"rest binary {binary} ran {total} tests but is pinned as "
                "testless in REST_ZERO_TEST_PIN; delete the pin")
    if expected is not None:
        ran = {(rest_binary_stem(binary), src)
               for src, binary, _lines in sections if src is not None}
        for stem, src in sorted(expected):
            if (stem, src) not in ran:
                raise PartitionError(
                    f"rest never ran target {src} ({stem}): no Running section")


def run_capture(command, env=None, capture_stderr=False):
    """Run, echo output as it arrives, and return (status, output).

    With capture_stderr, cargo's stderr (the Running headers) joins the
    captured output so rest sections delimit; otherwise stderr flows to
    the console as before.
    """
    print("+ " + " ".join(command), flush=True)
    with subprocess.Popen(
        command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if capture_stderr else None,
        text=True, encoding="utf-8", errors="replace",
    ) as process:
        captured = []
        for line in process.stdout:
            # Line by line: a hung or killed shard must still have its log.
            sys.stdout.write(line)
            sys.stdout.flush()
            captured.append(line)
        return process.wait(), "".join(captured)


def cargo_metadata(command):
    query = command[:2] + ["metadata", "--no-deps", "--format-version", "1"]
    query += [flag for flag in ("--locked", "--offline") if flag in command]
    output = subprocess.run(query, cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True)
    return json.loads(output.stdout)


def coverage_env(command, spec):
    env = dict(os.environ)
    if command[2] == "llvm-cov":
        env["LLVM_PROFILE_FILE_NAME"] = f"p11scope-{slug(spec)}-%p-%m.profraw"
    return env


def list_tests(command, env, runner):
    status, output = runner(
        narrowed(command, ["--test", SHARDED_TARGET]) + ["--", "--list", "--format", "terse"],
        env,
    )
    if status != 0:
        raise PartitionError(f"listing {SHARDED_TARGET} failed with status {status}")
    return parse_list(output)


def run_partition(spec, command, runner=run_capture, metadata=cargo_metadata,
                  weights=None):
    check_command(command)
    kind, shard, shards = parse_partition(spec)
    env = coverage_env(command, spec)
    if kind == "rest":
        meta = metadata(command)
        status, output = runner(
            narrowed(command, rest_selection(meta)), env,
            capture_stderr=True,
        )
        if status != 0:
            return status  # cargo or a test already failed the partition
        verify_rest_output(output, rest_expected_targets(meta))
        return status
    names = list_tests(command, env, runner)
    assigned, loads = plan(names, shards, weights or load_weights())
    mine = assigned[shard - 1]
    print(
        f"ci-test-partition: {spec}: {len(mine)} of {len(names)} {SHARDED_TARGET} tests, "
        f"estimated {loads[shard - 1]:.0f}s",
        flush=True,
    )
    status, output = runner(
        narrowed(command, ["--test", SHARDED_TARGET]) + ["--", "--exact", *mine], env
    )
    if status != 0:
        return status  # cargo or a test already failed the shard
    verify_summary(output, len(mine), len(names))
    return status


def print_plan(names, shards, weights):
    assigned, loads = plan(names, shards, weights)
    default, seconds = weights
    for index, tests in enumerate(assigned):
        print(f"shard contracts:{index + 1}/{shards}: {len(tests)} tests, estimated {loads[index]:.0f}s")
        for name in sorted(tests, key=lambda n: (-seconds.get(n, default), n)):
            print(f"  {seconds.get(name, default):8.1f}s  {name}")
    every = [name for tests in assigned for name in tests]
    print(
        f"partition: {len(names)} listed, {len(every)} assigned, "
        f"{len(set(every))} distinct, each exactly once: {sorted(every) == sorted(names)}"
    )


def weights_from_reports(paths, floor=0.5):
    """A weights table from libtest JSON (--report-time) event streams."""
    times = {}
    for path in paths:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            event = json.loads(line)
            if event.get("type") == "test" and "exec_time" in event:
                times[event["name"]] = max(times.get(event["name"], 0.0), event["exec_time"])
    if not times:
        raise PartitionError("no timed test events in the reports")
    light = sorted(value for value in times.values() if value < floor)
    default = round(max(sum(light) / len(light) if light else floor, 0.1), 1)
    seconds = {name: round(value, 1) for name, value in sorted(times.items()) if value >= floor}
    return {
        "target": SHARDED_TARGET,
        "default_seconds": default,
        "seconds": seconds,
    }


def coverage_objects(debug_dir):
    """Executables cargo-llvm-cov reads as objects, minus build-script output."""
    found = []
    for path in sorted(Path(debug_dir).rglob("*")):
        relative = path.relative_to(debug_dir)
        if relative.parts[0] in ("build", "incremental", ".fingerprint"):
            continue
        if path.suffix in (".d", ".rlib", ".rmeta", ".so") or path.is_symlink():
            continue
        if path.is_file():
            metadata = os.stat(path)
            if metadata.st_mode & 0o111:
                if metadata.st_size >= MAX_COVERAGE_OBJECT_BYTES:
                    raise PartitionError(
                        f"coverage executable reaches the 256 MiB scanner limit: "
                        f"{path} ({metadata.st_size} bytes)"
                    )
                found.append(relative)
    return found


def coverage_pack(spec, target_dir, output_dir):
    target_dir, output_dir = Path(target_dir), Path(output_dir)
    prefix = f"p11scope-{slug(spec)}-"
    profiles = sorted(p for p in target_dir.glob("*.profraw") if p.name.startswith(prefix))
    strays = sorted(p.name for p in target_dir.glob("*.profraw") if not p.name.startswith(prefix))
    if not profiles:
        raise PartitionError(f"no {prefix}*.profraw in {target_dir}")
    if strays:
        raise PartitionError(f"profiles not named for {spec}: {strays}")
    objects = coverage_objects(target_dir / "debug")
    if not objects:
        raise PartitionError(f"no instrumented executables under {target_dir}/debug")
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"coverage-{slug(spec)}.tar"
    with tarfile.open(archive, "w") as tar:
        for profile in profiles:
            tar.add(profile, arcname=f"profraw/{profile.name}")
        for relative in objects:
            tar.add(target_dir / "debug" / relative, arcname=f"objects/{relative}")
    print(
        f"ci-test-partition: packed {len(profiles)} profiles and {len(objects)} "
        f"executables into {archive} ({archive.stat().st_size // 1_000_000} MB)"
    )
    return archive


def coverage_unpack(contracts_shards, target_dir, input_dir):
    """Every partition's archive, exactly once, into one report tree.

    Profiles land in the target dir (cargo-llvm-cov merges `*.profraw` there);
    each partition's executables land under `debug/<partition>/`, which the
    report's recursive object walk reads, so no partition's objects overwrite
    another's.
    """
    target_dir, input_dir = Path(target_dir), Path(input_dir)
    expected = ["rest"] + [f"contracts:{k}/{contracts_shards}" for k in range(1, contracts_shards + 1)]
    archives = sorted(input_dir.rglob("coverage-*.tar"))
    by_name = {}
    for archive in archives:
        if archive.name in by_name:
            raise PartitionError(f"two archives named {archive.name}")
        by_name[archive.name] = archive
    wanted = {f"coverage-{slug(spec)}.tar": spec for spec in expected}
    if sorted(by_name) != sorted(wanted):
        raise PartitionError(
            f"coverage archives {sorted(by_name)} are not exactly the partitions {sorted(wanted)}"
        )
    target_dir.mkdir(parents=True, exist_ok=True)
    if list(target_dir.glob("*.profraw")):
        raise PartitionError(f"{target_dir} already holds profiles")
    profiles = 0
    for name, spec in sorted(wanted.items()):
        destination = target_dir / "debug" / slug(spec)
        if destination.exists():
            raise PartitionError(f"{destination} already exists")
        with tempfile.TemporaryDirectory(dir=target_dir) as staging:
            with tarfile.open(by_name[name]) as tar:
                tar.extractall(staging, filter="data")
            staged = Path(staging)
            for profile in sorted((staged / "profraw").glob("*.profraw")):
                if not profile.name.startswith(f"p11scope-{slug(spec)}-"):
                    raise PartitionError(f"{name} carries a foreign profile {profile.name}")
                shutil.move(profile, target_dir / profile.name)
                profiles += 1
            if not (staged / "objects").is_dir():
                raise PartitionError(f"{name} carries no executables")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(staged / "objects", destination)
    print(f"ci-test-partition: unpacked {len(wanted)} partitions, {profiles} profiles")
    return profiles


# ---------------------------------------------------------------- self-test


def _expect_error(function, *args):
    try:
        function(*args)
    except PartitionError:
        return
    raise AssertionError(f"{function.__name__}{args!r} did not fail")


def _fake_metadata(extra=()):
    targets = [
        {"name": "p11scope", "kind": ["lib"], "test": True,
         "src_path": "/fake/src/lib.rs"},
        {"name": "p11scope", "kind": ["bin"], "test": True,
         "src_path": "/fake/src/main.rs"},
        {"name": "example", "kind": ["example"], "test": False,
         "src_path": "/fake/examples/example.rs"},
        {"name": SHARDED_TARGET, "kind": ["test"], "test": True,
         "src_path": "/fake/tests/artifact_contracts.rs"},
        {"name": "zeta", "kind": ["test"], "test": True,
         "src_path": "/fake/tests/zeta.rs"},
        {"name": "alpha", "kind": ["test"], "test": True,
         "src_path": "/fake/tests/alpha.rs"},
        {"name": "untested", "kind": ["test"], "test": False,
         "src_path": "/fake/tests/untested.rs"},
        {"name": "build-script-build", "kind": ["custom-build"], "test": False,
         "src_path": "/fake/build.rs"},
    ]
    return {
        "workspace_members": ["root", "member"],
        "packages": [
            {"id": "root", "name": "p11scope", "targets": targets,
             "manifest_path": "/fake/Cargo.toml"},
            {"id": "member", "name": "member",
             "targets": [{"name": "beta", "kind": ["test"], "test": True,
                          "src_path": "/fake/member/tests/beta.rs"}, *extra],
             "manifest_path": "/fake/member/Cargo.toml"},
            {"id": "dep", "name": "dep",
             "targets": [{"name": "outside", "kind": ["test"], "test": True,
                          "src_path": "/fake/dep/tests/outside.rs"}],
             "manifest_path": "/fake/dep/Cargo.toml"},
        ],
    }


def _full_rest_sections(extra=()):
    """Every fake rest target healthy: lib, pinned-zero bin, example, alpha, member beta, zeta."""
    return [
        ("p11scope-1a2b3c4d5e6f7890", "src/lib.rs", (10, 0, 0, 0)),
        ("p11scope-1a2b3c4d5e6f7891", "src/main.rs", (0, 0, 0, 0)),
        ("example-1a2b3c4d5e6f7892", "examples/example.rs", (1, 0, 0, 0)),
        ("alpha-1a2b3c4d5e6f7893", "tests/alpha.rs", (3, 0, 2, 0)),
        ("beta-1a2b3c4d5e6f7895", "tests/beta.rs", (3, 0, 0, 0)),
        ("zeta-1a2b3c4d5e6f7894", "tests/zeta.rs", (2, 0, 0, 0)),
        *extra,
    ]


class _FakeLibtest:
    """Answers --list and --exact like libtest; records what ran."""

    def __init__(self, names, nested=False, drop=None):
        self.names, self.nested, self.drop = names, nested, drop
        self.ran, self.commands = [], []

    def __call__(self, command, env, capture_stderr=False):
        self.commands.append((command, env, capture_stderr))
        args = command[command.index("--") + 1:]
        if args[:1] == ["--list"]:
            return 0, "".join(f"{name}: test\n" for name in self.names)
        assert args[0] == "--exact", args
        selected = [name for name in self.names if name in args[1:] and name != self.drop]
        self.ran.extend(selected)
        lines = [f"running {len(selected)} tests"]
        lines += [f"test {name} ... ok" for name in selected]
        if self.nested:
            lines += ["running 1 test", "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s"]
        lines.append(
            f"test result: ok. {len(selected)} passed; 0 failed; 0 ignored; 0 measured; "
            f"{len(self.names) - len(selected)} filtered out; finished in 0.01s"
        )
        return 0, "\n".join(lines) + "\n"


class _FakeRest:
    """Canned combined cargo output: Running headers plus libtest summaries."""

    def __init__(self, sections, status=0):
        # sections: [(binary, src, summary)] where summary is
        # (passed, failed, ignored, measured) or None for no summary.
        # A ("Doc-tests <lib>", None, summary) section renders a doctest
        # header. Header forms mirror real cargo 1.99.1 output: the
        # three-token `unittests` form for lib/bin/example targets, the
        # two-token form for integration tests and benches.
        self.sections, self.status = sections, status
        self.commands = []

    def __call__(self, command, env, capture_stderr=False):
        self.commands.append((command, env, capture_stderr))
        lines = []
        for binary, src, summary in self.sections:
            if src is None and binary.startswith("Doc-tests "):
                lines.append(f"     {binary}")
            elif src is None:
                lines.append(f"     Running target/debug/deps/{binary}")
            elif src.startswith(("tests/", "benches/")):
                lines.append(f"     Running {src} (target/debug/deps/{binary})")
            else:
                lines.append(f"     Running unittests {src} (target/debug/deps/{binary})")
            lines.append("")
            if summary is None:
                continue
            total = sum(summary)
            noun = "test" if total == 1 else "tests"
            lines.append(f"running {total} {noun}")
            passed, failed, ignored, measured = summary
            lines.append(
                f"test result: ok. {passed} passed; {failed} failed; "
                f"{ignored} ignored; {measured} measured; 0 filtered out; finished in 0.01s"
            )
        return self.status, "\n".join(lines) + "\n"


def self_test():
    gate = ["cargo", "+1.0.0", "test", "--locked", "--offline", "--workspace", "--all-targets"]
    cov = ["cargo", "+1.0.0", "llvm-cov", "--locked", "--offline", "--workspace", "--all-targets", "--no-report"]

    # Partition specs.
    assert parse_partition("rest") == ("rest", None, None)
    assert parse_partition("contracts:2/4") == ("contracts", 2, 4)
    for bad in ("", "contracts", "contracts:0/4", "contracts:5/4", "contracts:1/0",
                "contracts:01/4", "contract:1/4", "rest ", "contracts:1/4/"):
        _expect_error(parse_partition, bad)
    assert slug("contracts:3/4") == "contracts-3-of-4" and slug("rest") == "rest"

    # Command checks: the gate, unmodified but for its one --all-targets.
    check_command(gate)
    check_command(cov)
    for bad in (
        gate[:-1], gate + ["--all-targets"], gate + ["--"], gate[:5] + gate[6:],
        gate + ["--test", "x"], gate + ["-p", "x"], gate + ["--package=x"],
        gate + ["--exclude", "x"], gate + ["--lib"], gate + ["--no-run"],
        ["cargo", "test", "--workspace", "--all-targets"],
        ["cargo", "+1", "build", "--workspace", "--all-targets"],
    ):
        _expect_error(check_command, bad)

    # rest: every workspace integration target with test = true but the sharded one.
    selection = rest_selection(_fake_metadata())
    assert selection == ["--lib", "--bins", "--examples", "--benches",
                         "--test", "alpha", "--test", "beta", "--test", "zeta"], selection
    assert narrowed(gate, selection) == gate[:-1] + selection
    _expect_error(rest_selection, {"workspace_members": [], "packages": []})
    _expect_error(rest_selection, _fake_metadata(
        [{"name": SHARDED_TARGET, "kind": ["test"], "test": True}]))

    # --list parsing fails closed.
    assert parse_list("a: test\n\nb: test\n") == ["a", "b"]
    for bad in ("", "a: test\na: test\n", "a: benchmark\n", "warning: x\na: test\n"):
        _expect_error(parse_list, bad)

    # The plan: a deterministic partition, longest first, balanced.
    weights = (1.0, {"heavy": 100.0, "mid": 40.0, "mid2": 40.0, "small": 5.0})
    names = ["small", "heavy", "mid", "mid2"] + [f"t{i}" for i in range(20)]
    first, loads = plan(names, 3, weights)
    again, _ = plan(list(reversed(names)), 3, weights)
    assert first == again, "the plan depends on list order"
    every = [name for tests in first for name in tests]
    assert sorted(every) == sorted(names) and len(every) == len(set(every))
    assert first[0] == ["heavy"], first
    assert max(loads) - min(loads) <= 100.0
    assert abs(sum(loads) - (185.0 + 20.0)) < 1e-9
    _expect_error(plan, names, 0, weights)
    _expect_error(plan, ["a", "b"], 3, weights)  # an empty shard is an error

    # Summary verification.
    ok = ("running 2 tests\ntest a ... ok\ntest b ... ok\n\n"
          "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 1s\n")
    verify_summary(ok, 2, 5)
    verify_summary(ok.replace("2 passed", "1 passed").replace("0 ignored", "1 ignored"), 2, 5)
    _expect_error(verify_summary, ok, 3, 6)
    _expect_error(verify_summary, ok, 2, 6)
    _expect_error(verify_summary, "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;", 2, 5)
    _expect_error(verify_summary, "running 2 tests\n", 2, 5)
    nested = ("running 2 tests\nrunning 7 tests\n"
              "test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n"
              "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;\n")
    verify_summary(nested, 2, 5)

    # End to end against a fake libtest: N shards run every test exactly once.
    listed = [f"case_{i:03d}" for i in range(37)]
    table = (0.2, {"case_000": 30.0, "case_001": 20.0, "case_002": 12.5})
    for shards in (1, 2, 4, 5):
        fake = _FakeLibtest(listed, nested=True)
        for shard in range(1, shards + 1):
            status = run_partition(f"contracts:{shard}/{shards}", gate, runner=fake,
                                   metadata=None, weights=table)
            assert status == 0
        assert sorted(fake.ran) == sorted(listed), (shards, len(fake.ran))
        for command, env, capture_stderr in fake.commands:
            assert command[:7] == gate[:6] + ["--test"] and command[7] == SHARDED_TARGET, command
            assert env.get("LLVM_PROFILE_FILE_NAME") == os.environ.get("LLVM_PROFILE_FILE_NAME")
            assert capture_stderr is False
    # A test that silently does not run makes its shard fail.
    dropped = _FakeLibtest(listed, drop="case_010")
    try:
        for shard in (1, 2):
            run_partition(f"contracts:{shard}/2", gate, runner=dropped, metadata=None, weights=table)
    except PartitionError:
        pass
    else:
        raise AssertionError("a dropped test went unnoticed")
    # rest runs the narrowed gate once; llvm-cov profiles are named per partition.
    seen = []

    def rest_ok(command, env, capture_stderr=False):
        seen.append((command, env, capture_stderr))
        _, output = _FakeRest(_full_rest_sections())(command, env)
        return 0, output

    status = run_partition("rest", cov, runner=rest_ok,
                           metadata=lambda c: _fake_metadata(), weights=table)
    assert status == 0 and len(seen) == 1
    assert seen[0][0] == narrowed(cov, ["--lib", "--bins", "--examples", "--benches",
                                        "--test", "alpha", "--test", "beta", "--test", "zeta"])
    assert seen[0][1]["LLVM_PROFILE_FILE_NAME"] == "p11scope-rest-%p-%m.profraw"
    assert seen[0][2] is True
    fake = _FakeLibtest(listed)
    run_partition("contracts:2/3", cov, runner=fake, metadata=None, weights=table)
    assert all(env["LLVM_PROFILE_FILE_NAME"] == "p11scope-contracts-2-of-3-%p-%m.profraw"
               for _, env, _ in fake.commands)

    # rest proves a nonzero selection per binary: every binary cargo ran
    # must print a libtest summary with total > 0, else the partition fails
    # naming the binary. The exit status rule stays: a failing run fails
    # without summary verification.
    healthy = _FakeRest(_full_rest_sections())
    assert run_partition("rest", gate, runner=healthy,
                         metadata=lambda c: _fake_metadata()) == 0
    # The expected set is exactly the runnable rest targets: the sharded
    # target, the test=false integration target, the build script and the
    # non-member package stay out, while the test=false example stays in.
    assert rest_expected_targets(_fake_metadata()) == {
        ("p11scope", "src/lib.rs"), ("p11scope", "src/main.rs"),
        ("example", "examples/example.rs"), ("alpha", "tests/alpha.rs"),
        ("beta", "tests/beta.rs"), ("zeta", "tests/zeta.rs"),
    }
    # Benches run under `--benches` even with `test = false`, so a
    # test=false bench is expected like the test=false example above;
    # test=false lib/bin targets never run under the rest selection.
    with_bench = _fake_metadata([{
        "name": "criterion-bench", "kind": ["bench"], "test": False,
        "src_path": "/fake/member/benches/criterion-bench.rs",
    }])
    assert ("criterion_bench", "benches/criterion-bench.rs") in \
        rest_expected_targets(with_bench)
    not_built = _fake_metadata([
        {"name": "member-lib", "kind": ["lib"], "test": False,
         "src_path": "/fake/member/src/lib.rs"},
        {"name": "member-bin", "kind": ["bin"], "test": False,
         "src_path": "/fake/member/src/main.rs"},
    ])
    selected = rest_expected_targets(not_built)
    assert ("member_lib", "src/lib.rs") not in selected
    assert ("member_bin", "src/main.rs") not in selected
    zero = _FakeRest([
        ("p11scope-1a2b3c4d5e6f7890", "src/lib.rs", (10, 0, 0, 0)),
        ("zeta-1a2b3c4d5e6f7892", "tests/zeta.rs", (0, 0, 0, 0)),
    ])
    try:
        run_partition("rest", gate, runner=zero,
                      metadata=lambda c: _fake_metadata())
    except PartitionError as error:
        assert "zeta-1a2b3c4d5e6f7892" in str(error), error
    else:
        raise AssertionError("a zero-test rest binary went unnoticed")
    missing = _FakeRest([
        ("p11scope-1a2b3c4d5e6f7890", "src/lib.rs", (10, 0, 0, 0)),
        ("alpha-1a2b3c4d5e6f7891", "tests/alpha.rs", None),
    ])
    try:
        run_partition("rest", gate, runner=missing,
                      metadata=lambda c: _fake_metadata())
    except PartitionError as error:
        assert "alpha-1a2b3c4d5e6f7891" in str(error), error
    else:
        raise AssertionError("a rest binary without a summary went unnoticed")
    failing = _FakeRest([
        ("p11scope-1a2b3c4d5e6f7890", "src/lib.rs", (10, 0, 0, 0)),
    ], status=101)
    assert run_partition("rest", gate, runner=failing,
                         metadata=lambda c: _fake_metadata()) == 101
    bare_zero = _FakeRest([
        ("bare-1a2b3c4d5e6f7893", None, (0, 0, 0, 0)),
    ])
    try:
        run_partition("rest", gate, runner=bare_zero,
                      metadata=lambda c: _fake_metadata())
    except PartitionError as error:
        assert "bare-1a2b3c4d5e6f7893" in str(error), error
    else:
        raise AssertionError("a bare-form zero-test binary went unnoticed")
    bare_healthy = _FakeRest(_full_rest_sections([
        ("bare-1a2b3c4d5e6f7893", None, (2, 0, 0, 0)),
    ]))
    assert run_partition("rest", gate, runner=bare_healthy,
                         metadata=lambda c: _fake_metadata()) == 0
    # The p11scope bin is CLI dispatch only (src/main.rs holds no tests),
    # so its total-0 summary is pinned, not proved: any other zero-test
    # binary still fails, and a nonzero bin fails the pin as stale.
    pinned_zero = _FakeRest(_full_rest_sections())
    assert run_partition("rest", gate, runner=pinned_zero,
                         metadata=lambda c: _fake_metadata()) == 0
    pinned_nonzero = _FakeRest([
        ("p11scope-1a2b3c4d5e6f7890", "src/main.rs", (1, 0, 0, 0)),
    ])
    try:
        run_partition("rest", gate, runner=pinned_nonzero,
                      metadata=lambda c: _fake_metadata())
    except PartitionError as error:
        assert "REST_ZERO_TEST_PIN" in str(error), error
    else:
        raise AssertionError("a stale zero-test pin went unnoticed")
    # A Doc-tests section is its own proof: its summary must not stand in
    # for the lib's, and a zero doctest run fails naming the doctests.
    doctest_healthy = _FakeRest(_full_rest_sections([
        ("Doc-tests p11scope", None, (4, 0, 0, 0)),
    ]))
    assert run_partition("rest", gate, runner=doctest_healthy,
                         metadata=lambda c: _fake_metadata()) == 0
    doctest_zero = _FakeRest([
        ("p11scope-1a2b3c4d5e6f7890", "src/lib.rs", (10, 0, 0, 0)),
        ("Doc-tests p11scope", None, (0, 0, 0, 0)),
    ])
    try:
        run_partition("rest", gate, runner=doctest_zero,
                      metadata=lambda c: _fake_metadata())
    except PartitionError as error:
        assert "Doc-tests p11scope" in str(error), error
    else:
        raise AssertionError("a zero-test doctest run went unnoticed")
    # A selected target cargo never runs leaves no section and must fail
    # naming it, instead of passing silently.
    skipped = _FakeRest([
        ("p11scope-1a2b3c4d5e6f7890", "src/lib.rs", (10, 0, 0, 0)),
        ("p11scope-1a2b3c4d5e6f7891", "src/main.rs", (0, 0, 0, 0)),
        ("example-1a2b3c4d5e6f7892", "examples/example.rs", (1, 0, 0, 0)),
        ("alpha-1a2b3c4d5e6f7893", "tests/alpha.rs", (3, 0, 0, 0)),
        ("beta-1a2b3c4d5e6f7895", "tests/beta.rs", (3, 0, 0, 0)),
    ])
    try:
        run_partition("rest", gate, runner=skipped,
                      metadata=lambda c: _fake_metadata())
    except PartitionError as error:
        assert "tests/zeta.rs" in str(error), error
    else:
        raise AssertionError("a selected target with no section went unnoticed")
    # The member target is expected and required: a run missing only
    # its section fails naming it, so member coverage cannot hide
    # behind a root target of the same name.
    member_missing = _FakeRest([
        section for section in _full_rest_sections()
        if not section[0].startswith("beta-")
    ])
    try:
        run_partition("rest", gate, runner=member_missing,
                      metadata=lambda c: _fake_metadata())
    except PartitionError as error:
        assert "tests/beta.rs" in str(error), error
    else:
        raise AssertionError("a missing member section went unnoticed")
    # An unrecognized header form fails closed naming the line: the
    # unknown section's healthy summary must not merge into the
    # previous section and mask its zero.
    def unknown_header(command, env, unknown, capture_stderr=False):
        head, tail = _full_rest_sections()[0], _full_rest_sections()[1:]
        _, before = _FakeRest([(head[0], head[1], (0, 0, 0, 0))])(command, env)
        _, after = _FakeRest(tail)(command, env)
        return 0, before + unknown + after

    for unknown in (
        "     Running test suites for extra-stuff\n\n"
        "running 3 tests\n"
        "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; "
        "0 filtered out; finished in 0.01s\n",
        "     Doc-tests extra-stuff 1.0\n\n"
        "running 2 tests\n"
        "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; "
        "0 filtered out; finished in 0.01s\n",
    ):
        header = unknown.splitlines()[0].strip()
        try:
            run_partition("rest", gate,
                          runner=lambda c, e, capture_stderr=False, u=unknown: unknown_header(c, e, u),
                          metadata=lambda c: _fake_metadata())
        except PartitionError as error:
            assert header in str(error), error
        else:
            raise AssertionError(f"an unrecognized rest header went unnoticed: {header}")
    assert healthy.commands and healthy.commands[0][2] is True, \
        "rest must capture stderr so Running headers delimit binaries"

    # The checked-in table loads and is a real table.
    default, seconds = load_weights()
    assert default > 0 and len(seconds) >= 5, "scripts/ci-test-weights.json looks empty"

    # weights: libtest JSON -> table.
    with tempfile.TemporaryDirectory() as temporary:
        report = Path(temporary) / "report.jsonl"
        report.write_text(
            '{ "type": "suite", "event": "started", "test_count": 3 }\n'
            '{ "type": "test", "name": "slow", "event": "ok", "exec_time": 12.34 }\n'
            '{ "type": "test", "name": "fast", "event": "ok", "exec_time": 0.01 }\n'
            '{ "type": "test", "name": "faster", "event": "ok", "exec_time": 0.03 }\n',
            encoding="utf-8",
        )
        table = weights_from_reports([report])
        assert table == {"target": SHARDED_TARGET, "default_seconds": 0.1,
                         "seconds": {"slow": 12.3}}, table

    # Only selected coverage executables meet the scanner's size limit.
    # Sparse boundary fixtures exercise real stat sizes without a large archive.
    with tempfile.TemporaryDirectory() as temporary:
        tree = Path(temporary) / "llvm-cov-target"
        debug = tree / "debug"
        (debug / "deps").mkdir(parents=True)
        limit = 256 * 1024 * 1024
        library = debug / "deps" / "liblarge.rlib"
        with library.open("wb") as output:
            output.truncate(limit + 1)
        library.chmod(0o755)
        executable = debug / "deps" / "coverage-test"
        with executable.open("wb") as output:
            output.truncate(limit - 1)
        executable.chmod(0o755)
        assert coverage_objects(debug) == [Path("deps/coverage-test")]
        with executable.open("r+b") as output:
            output.truncate(limit)
        _expect_error(coverage_objects, debug)
        (tree / "p11scope-rest-1-boundary.profraw").write_bytes(b"raw")
        destination = Path(temporary) / "packed"
        _expect_error(coverage_pack, "rest", tree, destination)
        assert not destination.exists(), "reject before creating coverage output"

    # coverage-pack / coverage-unpack round trip, fail-closed on gaps.
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        artifacts = base / "artifacts"
        for spec in ("rest", "contracts:1/2", "contracts:2/2"):
            tree = base / slug(spec) / "llvm-cov-target"
            (tree / "debug" / "deps").mkdir(parents=True)
            (tree / "debug" / "build" / "x").mkdir(parents=True)
            (tree / "debug" / "incremental").mkdir()
            (tree / f"p11scope-{slug(spec)}-1-abc.profraw").write_bytes(b"raw")
            exe = tree / "debug" / "deps" / f"bin-{slug(spec)}"
            exe.write_bytes(b"\x7fELF")
            exe.chmod(0o755)
            (tree / "debug" / "p11scope").write_bytes(b"\x7fELF")
            (tree / "debug" / "p11scope").chmod(0o755)
            for skipped in ("deps/x.d", "deps/libx.rlib", "build/x/build-script-build",
                            "incremental/y"):
                (tree / "debug" / skipped).write_bytes(b"")
                (tree / "debug" / skipped).chmod(0o755)
            (tree / "debug" / "deps" / "data").write_bytes(b"")
            assert coverage_objects(tree / "debug") == [
                Path(f"deps/bin-{slug(spec)}"), Path("p11scope")], coverage_objects(tree / "debug")
            if spec == "rest":
                stray = tree / "p11scope-other-1-abc.profraw"
                stray.write_bytes(b"raw")
                _expect_error(coverage_pack, spec, tree, artifacts / slug(spec))
                stray.unlink()
            coverage_pack(spec, tree, artifacts / slug(spec))
        merged = base / "merged" / "llvm-cov-target"
        _expect_error(coverage_unpack, 3, merged, artifacts)  # wrong shard count
        assert coverage_unpack(2, merged, artifacts) == 3
        assert sorted(p.name for p in merged.glob("*.profraw")) == sorted(
            f"p11scope-{s}-1-abc.profraw" for s in ("rest", "contracts-1-of-2", "contracts-2-of-2"))
        for s in ("rest", "contracts-1-of-2", "contracts-2-of-2"):
            exe = merged / "debug" / s / "deps" / f"bin-{s}"
            assert exe.is_file() and os.stat(exe).st_mode & 0o111, exe
            assert (merged / "debug" / s / "p11scope").is_file()
        _expect_error(coverage_unpack, 2, merged, artifacts)  # never twice into one tree
        (artifacts / "rest" / "coverage-rest.tar").unlink()
        _expect_error(coverage_unpack, 2, base / "again", artifacts)  # a missing shard

    print("ci-test-partition: self-test ok")


def main(argv):
    if argv[:1] == ["--self-test"] and len(argv) == 1:
        self_test()
        return 0
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    command, rest = argv[0], argv[1:]
    cargo = []
    if "--" in rest:
        at = rest.index("--")
        rest, cargo = rest[:at], rest[at + 1:]
    options, positional = {}, []
    while rest:
        word = rest.pop(0)
        if word in ("--partition", "--shards", "--list-file", "--target-dir", "--output",
                    "--contracts-shards"):
            if not rest:
                raise PartitionError(f"{word} needs a value")
            options[word] = rest.pop(0)
        else:
            positional.append(word)
    if command == "run" and set(options) == {"--partition"} and not positional and cargo:
        return run_partition(options["--partition"], cargo)
    if command == "plan" and "--shards" in options and not positional:
        if "--list-file" in options and not cargo:
            names = parse_list(Path(options["--list-file"]).read_text(encoding="utf-8"))
        elif cargo and "--list-file" not in options:
            check_command(cargo)
            names = list_tests(cargo, dict(os.environ), run_capture)
        else:
            raise PartitionError("plan needs --list-file FILE or -- CARGO_COMMAND")
        print_plan(names, int(options["--shards"]), load_weights())
        return 0
    if command == "weights" and positional and not options and not cargo:
        print(json.dumps(weights_from_reports(positional), indent=2, sort_keys=True))
        return 0
    if command == "coverage-pack" and set(options) == {"--partition", "--target-dir", "--output"} \
            and not positional and not cargo:
        coverage_pack(options["--partition"], options["--target-dir"], options["--output"])
        return 0
    if command == "coverage-unpack" and set(options) == {"--contracts-shards", "--target-dir"} \
            and len(positional) == 1 and not cargo:
        coverage_unpack(int(options["--contracts-shards"]), options["--target-dir"], positional[0])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except PartitionError as error:
        print(f"ci-test-partition: {error}", file=sys.stderr)
        sys.exit(1)
