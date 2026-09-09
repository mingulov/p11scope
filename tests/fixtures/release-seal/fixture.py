"""Native setup for the actual release seal CLI, ending at a harmless probe."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess


FIXTURES = Path(__file__).resolve().parent
ROOT = FIXTURES.parents[2]
EXPECTED = json.loads((FIXTURES / "expected.json").read_text())
# Task7 still owns its Rust fixture; this small setup boundary is intentionally
# copied while the Task11 caller fixture moves to a reusable native module.
BUILD_INPUT_VARIABLES = (
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET",
    "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTC_WRAPPER", "CC", "CFLAGS",
)


@dataclass
class Task11FixtureOptions:
    external_rust_src_symlink: bool = False
    internal_rust_src_symlink: bool = False
    cargo_proxy_mismatch: bool = False
    cargo_proxy_regular_mismatch: bool = False
    cargo_home_raw_target_newline: bool = False
    cargo_home_canonical_target_newline: bool = False
    cargo_home_inventory_shadow: bool = False
    missing_musl: bool = False


class SealedDriverRun:
    def __init__(self, fixture, output):
        self.fixture = fixture
        self.output = output
        self.root = fixture.root
        self.repo = fixture.repo
        self.environment_dump = fixture.environment_dump
        self.seal_parent = fixture.seal_parent
        facts = self.root / "facts.log"
        self.facts = facts.read_text() if facts.exists() else ""

    def fact(self, name):
        return next((line[len(name) + 1:] for line in self.facts.splitlines()
                     if line.startswith(name + "\t")), None)

    def tripped(self):
        path = self.fixture.tripwire_log
        return path.read_text() if path.exists() else ""


class ReleaseSealFixture:
    def __init__(self, base, options=None):
        self.base = Path(base)
        self.base.mkdir(mode=0o700)
        options = options or Task11FixtureOptions()
        self.repo = self.base / "repo"
        self.repo.mkdir(mode=0o700)
        (self.repo / "scripts").mkdir()
        for name in ("build-release.sh", "lib.sh", "check-capture-evidence.py"):
            shutil.copy2(ROOT / "scripts" / name, self.repo / "scripts" / name)
        for arguments in (
            ["init", "--quiet", "-b", "task7"], ["add", "-A"],
            ["-c", "user.email=task7@example.invalid", "-c", "user.name=task7",
             "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "pristine release driver"],
        ):
            result = self.command(["git", "-C", str(self.repo), *arguments])
            if result.returncode:
                raise RuntimeError(f"fixture git setup failed ({result.returncode}): {result.stderr}")
        self.fake_bin = self.base / "bin"
        self.tripwire_bin = self.base / "tripwire-bin"
        self.home = self.base / "home"
        self.seal_parent = self.base / "tmp"
        campaign = self.base / "campaign"
        for directory in (self.fake_bin, self.tripwire_bin, self.home, self.seal_parent, campaign):
            directory.mkdir()
        campaign.chmod(0o700)
        self.root = campaign / "evidence"
        self.tripwire_log = self.base / "tripwire.log"
        self.environment_dump = self.base / "sealed-environment"

        sysroot = self.base / "sysroot"
        rust_src = sysroot / "lib/rustlib/src/rust"
        (rust_src / "library/core/src").mkdir(parents=True)
        musl = sysroot / "lib/rustlib/x86_64-unknown-linux-musl/lib"
        musl.mkdir(parents=True)
        (sysroot / "lib/librustc_driver.so").write_bytes(b"rustc-driver\n")
        (musl / "libc.rlib").write_bytes(b"musl-target\n")
        if options.missing_musl:
            shutil.rmtree(musl)
        (rust_src / "library/core/src/lib.rs").write_text("#![no_std]\n")
        (rust_src / "library/core/Cargo.toml").write_text('[package]\nname = "core"\n')
        if options.internal_rust_src_symlink:
            (rust_src / "library/core/src/internal-link").symlink_to("lib.rs")
        if options.external_rust_src_symlink:
            (rust_src / "library/core/planted").symlink_to("/etc/passwd")
        cargo_bin = self.home / ".cargo/bin"
        cargo_bin.mkdir(parents=True)
        self.inert(cargo_bin / "bpf-linker")
        toolchain = self.base / "toolchain-binary"
        self.template("sysroot.sh.in", toolchain, SYSROOT=sysroot)
        rustup_target = self.fake_bin / "rustup"
        self.template("rustup.sh.in", rustup_target, TOOLCHAIN=toolchain)
        proxy_target = self.fake_bin / "rustup-proxy-target"
        self.inert(proxy_target)
        cargo_target = rustup_target
        if options.cargo_home_canonical_target_newline:
            newline_target = self.fake_bin / "rustup\n"
            self.inert(newline_target)
            cargo_target = self.fake_bin / "cargo-intermediate"
            cargo_target.symlink_to(newline_target)
        if options.cargo_proxy_regular_mismatch:
            self.inert(cargo_bin / "cargo")
        else:
            (cargo_bin / "cargo").symlink_to(proxy_target if options.cargo_proxy_mismatch else cargo_target)
        for name in ("rustc", "rustup"):
            (cargo_bin / name).symlink_to(rustup_target)
        self.inert(cargo_bin / "cargo-third-party")
        third_party_target = cargo_bin / "cargo-third-party-target"
        self.inert(third_party_target)
        if options.cargo_home_raw_target_newline:
            self.inert(self.fake_bin / "third-party-target")
            third_party_target = self.fake_bin / "third-party-target\n"
            self.inert(third_party_target)
        (cargo_bin / "cargo-third-party-link").symlink_to(third_party_target)
        if options.cargo_home_inventory_shadow:
            self.inert(cargo_bin / "date")
        tripwire = self.base / "tripwire"
        self.template("tripwire.sh.in", tripwire, LOG=self.tripwire_log)
        self.template("sudo.sh.in", self.fake_bin / "sudo", LOG=self.tripwire_log,
                      DUMP=self.environment_dump, BIN=self.tripwire_bin, TRIPWIRE=tripwire,
                      INVENTORY=EXPECTED["tool_inventory"])

    def command(self, argv, *, environment=None, overrides=None, removed=()):
        result = subprocess.run(argv, cwd=ROOT, env=environment, input="", text=True,
                                capture_output=True, timeout=60)
        row = {"argv": argv, "cwd": str(ROOT), "stdin": "", "status": result.returncode,
               "stdout": result.stdout, "stderr": result.stderr, "environment_inherited": True,
               "environment_overrides": overrides or {}, "environment_removed": list(removed)}
        with (self.base / "commands.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        return result

    def template(self, name, destination, **data):
        source = (FIXTURES / name).read_text()
        for key, value in data.items():
            words = value if isinstance(value, list) else [value]
            source = source.replace("@" + key + "@", " ".join(shlex.quote(str(word)) for word in words))
        destination.write_text(source)
        destination.chmod(0o700)

    def inert(self, destination):
        shutil.copyfile(FIXTURES / "inert.sh", destination)
        destination.chmod(0o700)

    def run_to_sudo_probe(self, extra_env=()):
        caller_path = ":".join((str(self.tripwire_bin), str(self.fake_bin), os.environ.get("PATH", ""),
                                "/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin"))
        overrides = {"PATH": caller_path, "HOME": str(self.home), "TMPDIR": str(self.seal_parent)}
        overrides.update(extra_env)
        environment = dict(os.environ)
        for name in BUILD_INPUT_VARIABLES:
            environment.pop(name, None)
        environment.update(overrides)
        output = self.command(["/bin/sh", str(self.repo / "scripts/build-release.sh"), str(self.root)],
                              environment=environment, overrides=overrides, removed=BUILD_INPUT_VARIABLES)
        return SealedDriverRun(self, output)
