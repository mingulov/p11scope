#!/usr/bin/python3
"""Coordinate a fixed, unprivileged build from a full offline source export."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys


class Refusal(Exception):
    """An unsafe or inconsistent input."""


class Interrupted(Exception):
    """A termination signal received while private work was owned."""


REFUSED = {
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_HOME", "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
    "CC", "CFLAGS", "HOST_CC", "TARGET_CC", "HOST_CFLAGS", "TARGET_CFLAGS",
    "P11SCOPE_PRODUCT_BUILD_MODE", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET",
}
PRIVATE = ("cargo-home", "cargo-home/bin", "target", "evidence",
           "evidence/private", "home")
TOOL_KEYS = ("python", "rustup", "stable_cargo", "stable_rustc",
             "bpf_cargo", "bpf_rustc", "bpf_linker")


def refused_environment(name: str) -> bool:
    return name in REFUSED or name.startswith((
        "CARGO_SOURCE_", "CARGO_BUILD_", "CARGO_TARGET_", "CC_", "CFLAGS_",
        "RUST", "P11SCOPE_PREPARED_", "P11SCOPE_SMALL_",
    ))


def canonical(path: Path, label: str, *, directory: bool = False) -> Path:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise Refusal(f"{label} must be a normalized absolute path")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise Refusal(f"{label} is unavailable: {error}") from error
    if resolved != path or stat.S_ISLNK(metadata.st_mode):
        raise Refusal(f"{label} must not contain symbolic links")
    if directory and not stat.S_ISDIR(metadata.st_mode):
        raise Refusal(f"{label} must be a directory")
    return path


def contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def digest(path: Path) -> str:
    result = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                result.update(block)
    except OSError as error:
        raise Refusal(f"cannot hash selected tool: {error}") from error
    return result.hexdigest()


def tool_identity(path: Path, label: str) -> dict:
    path = canonical(path, label)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
        raise Refusal(f"{label} is not an executable regular file")
    if metadata.st_uid not in (0, os.getuid()):
        raise Refusal(f"{label} has unexpected ownership")
    return {"path": path, "dev": metadata.st_dev, "ino": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode), "size": metadata.st_size,
            "sha256": digest(path)}


class Coordinator:
    def __init__(self, source: Path, work: Path, rustup: Path):
        self.source = source
        self.work = work
        self.rustup = rustup
        self.tools: dict[str, dict] = {}
        self.parent_fd: int | None = None
        self.directories: dict[str, tuple[int, os.stat_result]] = {}
        self.root_identity: tuple[int, int] | None = None
        self.created = False
        self.active: subprocess.Popen | None = None
        self.pending_signal: int | None = None
        self.handlers: dict[int, object] = {}

    def install_signals(self) -> None:
        for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            self.handlers[number] = signal.signal(number, self._signal)

    def restore_signals(self) -> None:
        for number, handler in self.handlers.items():
            signal.signal(number, handler)

    def _signal(self, number: int, _frame: object) -> None:
        self.pending_signal = number
        if self.active is not None:
            self._forward_signal(number)

    def _forward_signal(self, number: int) -> None:
        """Signal the child session, falling back during its setsid boundary."""
        assert self.active is not None
        try:
            os.killpg(self.active.pid, number)
        except ProcessLookupError:
            try:
                self.active.send_signal(number)
            except ProcessLookupError:
                pass

    def check_signal(self) -> None:
        if self.pending_signal is not None:
            raise Interrupted

    def child(self, arguments: list[str], environment: dict[str, str], label: str,
              *, capture: bool = False) -> bytes:
        self.check_signal()
        try:
            self.active = subprocess.Popen(
                arguments, cwd=self.source, env=environment, start_new_session=True,
                stdout=subprocess.PIPE if capture else None,
            )
            if self.pending_signal is not None:
                self._forward_signal(self.pending_signal)
            output, _ = self.active.communicate()
            status = self.active.returncode
        except OSError as error:
            raise Refusal(f"cannot run {label}: {error}") from error
        finally:
            self.active = None
        self.check_signal()
        if status != 0:
            raise Refusal(f"{label} failed with status {status}")
        return output or b""

    def select_tools(self) -> dict[str, dict]:
        glue = (
            '. "$1" || exit; p11scope_prepared_tools_select "$2" "$3" || exit; '
            'printf "%s\\n" "$P11SCOPE_PREPARED_PYTHON" "$P11SCOPE_PREPARED_RUSTUP" '
            '"$P11SCOPE_PREPARED_STABLE_CARGO" "$P11SCOPE_PREPARED_STABLE_RUSTC" '
            '"$P11SCOPE_PREPARED_BPF_CARGO" "$P11SCOPE_PREPARED_BPF_RUSTC"'
        )
        selection_environment = {"LC_ALL": "C", "PATH": "/usr/bin:/bin",
                                 "RUSTUP_AUTO_INSTALL": "0"}
        if os.environ.get("HOME"):
            selection_environment["HOME"] = os.environ["HOME"]
        output = self.child(
            ["/bin/sh", "-c", glue, "build-offline",
             str(self.source / "scripts/prepared-dependency-tools.sh"),
             "/usr/bin/python3", str(self.rustup)],
            selection_environment,
            "prepared tool selection", capture=True,
        )
        try:
            value = output.decode("utf-8")
        except UnicodeError as error:
            raise Refusal("selected tool path is not UTF-8") from error
        lines = value.splitlines()
        if (len(lines) != 6 or any(not item for item in lines)
                or any(any(ord(character) < 32 or ord(character) == 127
                           for character in item) for item in lines)):
            raise Refusal("prepared tool selector returned an unsafe tool path")
        paths = [Path(item) for item in lines] + [self.rustup.parent / "bpf-linker"]
        return {key: tool_identity(path, f"selected {key}")
                for key, path in zip(TOOL_KEYS, paths, strict=True)}

    def compare_tools(self, selected: dict[str, dict]) -> None:
        for key in TOOL_KEYS:
            if selected[key] != self.tools[key]:
                raise Refusal(f"selected {key} changed after build")

    def create_work(self) -> None:
        if not self.work.is_absolute() or Path(os.path.normpath(str(self.work))) != self.work:
            raise Refusal("work root must be a normalized absolute path")
        if ":" in str(self.work):
            raise Refusal("work root must not contain a colon")
        if os.path.lexists(self.work):
            raise Refusal("work root must not already exist")
        parent = canonical(self.work.parent, "work root parent", directory=True)
        payload = canonical(self.source / "third-party/offline",
                            "embedded offline payload", directory=True)
        if (contains(self.source, self.work) or contains(self.work, self.source)
                or contains(payload, self.work) or contains(self.work, payload)):
            raise Refusal("work root must be external to source and payload")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        self.parent_fd = os.open(parent, flags)
        os.mkdir(self.work.name, 0o700, dir_fd=self.parent_fd)
        self.created = True
        created_stat = os.stat(self.work.name, dir_fd=self.parent_fd, follow_symlinks=False)
        self.root_identity = (created_stat.st_dev, created_stat.st_ino)
        root_fd = os.open(self.work.name, flags, dir_fd=self.parent_fd)
        root_stat = os.fstat(root_fd)
        if (root_stat.st_dev, root_stat.st_ino) != self.root_identity:
            raise Refusal("private work root changed during creation")
        self.directories[""] = (root_fd, root_stat)
        for relative in PRIVATE:
            path = self.work / relative
            path.mkdir(mode=0o700)
            fd = os.open(path, flags)
            self.directories[relative] = (fd, os.fstat(fd))
        os.symlink(str(self.tools["bpf_linker"]["path"]), "bpf-linker",
                   dir_fd=self.directories["cargo-home/bin"][0])
        self.check_directories()

    def check_directories(self) -> None:
        for relative, (fd, original) in self.directories.items():
            current = os.fstat(fd)
            path = self.work if not relative else self.work / relative
            try:
                observed = path.lstat()
            except OSError as error:
                raise Refusal(f"private directory disappeared: {relative}: {error}") from error
            if (current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) != 0o700
                    or (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino)
                    or not stat.S_ISDIR(observed.st_mode)
                    or (observed.st_dev, observed.st_ino) != (original.st_dev, original.st_ino)
                    or path.resolve() != path):
                raise Refusal(f"private directory custody changed: {relative or 'work root'}")
        bin_path = self.work / "cargo-home/bin"
        try:
            names = os.listdir(bin_path)
            target = os.readlink(bin_path / "bpf-linker")
        except OSError as error:
            raise Refusal(f"selected bpf-linker exposure changed: {error}") from error
        if names != ["bpf-linker"] or Path(target) != self.tools["bpf_linker"]["path"]:
            raise Refusal("fresh Cargo home exposes an unexpected executable")

    @staticmethod
    def _clear_directory(directory_fd: int) -> None:
        """Clear one retained directory using only no-follow descriptor operations."""
        os.lseek(directory_fd, 0, os.SEEK_SET)
        for entry in sorted(os.scandir(directory_fd), key=lambda item: os.fsencode(item.name)):
            name = entry.name
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                        raise Refusal(f"cleanup entry changed before open: {name}")
                    Coordinator._clear_directory(child_fd)
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                        raise Refusal(f"cleanup directory changed before removal: {name}")
                    os.rmdir(name, dir_fd=directory_fd)
                finally:
                    os.close(child_fd)
            else:
                after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                    raise Refusal(f"cleanup entry changed before removal: {name}")
                os.unlink(name, dir_fd=directory_fd)

    def cleanup(self) -> None:
        cleanup_error = None
        root_entry = self.directories.get("")
        for relative, (fd, _metadata) in reversed(tuple(self.directories.items())):
            if not relative:
                continue
            try:
                os.close(fd)
            except OSError:
                pass
        if (self.created and self.parent_fd is not None and self.root_identity is not None
                and root_entry is not None):
            root_fd = root_entry[0]
            try:
                self._clear_directory(root_fd)
                observed = os.stat(self.work.name, dir_fd=self.parent_fd, follow_symlinks=False)
                if (stat.S_ISDIR(observed.st_mode)
                        and (observed.st_dev, observed.st_ino) == self.root_identity):
                    os.rmdir(self.work.name, dir_fd=self.parent_fd)
                else:
                    raise Refusal("named private work root changed; preserved replacement")
            except (OSError, Refusal) as error:
                cleanup_error = error
        if root_entry is not None:
            try:
                os.close(root_entry[0])
            except OSError:
                pass
        self.directories.clear()
        if self.parent_fd is not None:
            try:
                os.close(self.parent_fd)
            except OSError:
                pass
        self.parent_fd = None
        self.created = False
        if cleanup_error is not None:
            print(f"build-offline: cleanup refusal: {cleanup_error}", file=sys.stderr)

    def environment(self, *, build: bool = False) -> dict[str, str]:
        result = {"LC_ALL": "C", "PATH": "/usr/bin:/bin",
                  "HOME": str(self.work / "home"),
                  "CARGO_HOME": str(self.work / "cargo-home"),
                  "CARGO_NET_OFFLINE": "true", "RUSTUP_AUTO_INSTALL": "0"}
        if build:
            result["PATH"] = f"{self.work / 'cargo-home/bin'}:/usr/bin:/bin"
            for key in ("stable_cargo", "stable_rustc", "bpf_cargo", "bpf_rustc"):
                result["P11SCOPE_PREPARED_" + key.upper()] = str(self.tools[key]["path"])
        return result

    def load_exporter(self):
        path = self.source / "scripts/export-source.py"
        spec = importlib.util.spec_from_file_location("p11scope_build_exporter", path)
        if spec is None or spec.loader is None:
            raise Refusal("cannot load extracted source validator")
        module = importlib.util.module_from_spec(spec)
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            spec.loader.exec_module(module)
        except (OSError, ImportError) as error:
            raise Refusal(f"cannot load extracted source validator: {error}") from error
        finally:
            sys.dont_write_bytecode = previous
        return module

    def validate(self, exporter, prepared: str) -> tuple[dict, dict]:
        prior = os.environ.copy()
        try:
            os.environ.clear()
            os.environ.update({"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
            result = exporter.validate_extracted(
                self.source, self.work / "cargo-home", prepared=prepared)
        except Exception as error:
            if isinstance(error, Interrupted):
                raise
            raise Refusal(f"extracted source validation failed: {error}") from error
        finally:
            os.environ.clear()
            os.environ.update(prior)
        self.check_signal()
        if (not isinstance(result, dict) or not isinstance(result.get("identity"), dict)
                or not isinstance(result.get("prepared"), dict)):
            raise Refusal("extracted validator returned incomplete custody")
        return result["identity"], result["prepared"]

    def verify(self, check: bool) -> None:
        arguments = ["/usr/bin/python3", "-I",
                     str(self.source / "scripts/offline-dependencies.py"), "verify",
                     "--payload", str(self.source / "third-party/offline"),
                     "--nightly-rustc", str(self.tools["bpf_rustc"]["path"]),
                     "--prefix", str(self.work / "evidence/private" /
                                     ("final" if check else "initial"))]
        if check:
            arguments.append("--check-prepared")
        self.child(arguments, self.environment(),
                   "read-only offline verification" if check else "offline reconstruction")
        self.check_directories()

    def build(self) -> None:
        arguments = ["/bin/sh", "-c", '. "$1"; shift; p11scope_product_build "$@"',
                     "build-offline", str(self.source / "scripts/product-build.sh"),
                     "prepared", "--release", "--workspace", "--no-default-features",
                     "--target-dir", str(self.work / "target")]
        self.child(arguments, self.environment(build=True), "offline product build")
        self.check_directories()

    def publish(self, identity: dict) -> None:
        self.check_directories()
        evidence = {
            "command": ["p11scope_product_build", "prepared", "--release", "--workspace",
                        "--no-default-features", "--target-dir", "$WORK/target"],
            "inputs": identity, "outcome": {"status": 0}, "schema_version": 1,
            "tools": {key: {name: value[name] for name in ("mode", "sha256", "size")}
                      for key, value in sorted(self.tools.items())},
            "verification": {"final": "passed", "initial": "passed"},
        }
        encoded = (json.dumps(evidence, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True) + "\n").encode("ascii")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            fd = os.open("build-offline.json", flags, 0o600,
                         dir_fd=self.directories["evidence"][0])
            try:
                view = memoryview(encoded)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError("short evidence write")
                    view = view[count:]
                os.fchmod(fd, 0o600)
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as error:
            raise Refusal(f"cannot publish exclusive build evidence: {error}") from error

    def run(self) -> None:
        for relative in (
            "scripts/export-source.py", "scripts/offline-dependencies.py",
            "scripts/prepare-dependencies.py", "scripts/prepared-dependency-tools.sh",
            "scripts/product-build.sh", ".p11scope-source-export.json",
            "third-party/offline-dependencies.json", "third-party/offline", ".cargo/config.toml",
        ):
            if not os.path.lexists(self.source / relative):
                raise Refusal(f"missing offline build prerequisite: {relative}")
        self.install_signals()
        try:
            self.tools = self.select_tools()
            self.create_work()
            exporter = self.load_exporter()
            initial, _initial_prepared = self.validate(exporter, "allow")
            self.verify(False)
            reconstructed_identity, reconstructed_prepared = self.validate(exporter, "require")
            if reconstructed_identity != initial:
                raise Refusal("source identity changed during reconstruction")
            self.build()
            self.compare_tools(self.select_tools())
            self.verify(True)
            self.compare_tools({key: tool_identity(value["path"], f"selected {key}")
                                for key, value in self.tools.items()})
            final, final_prepared = self.validate(exporter, "require")
            if final != initial or final_prepared != reconstructed_prepared:
                raise Refusal("source identity changed during build")
            # Below this point, do not call source, tool, verifier, preparer, or build code.
            self.check_signal()
            self.publish(final)
            self.check_signal()
            self.created = False
            self.cleanup()
        finally:
            self.restore_signals()


def _main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if len(values) != 1:
        print("build-offline: refusal: usage: build-offline.py ABS_NEW_WORK_ROOT", file=sys.stderr)
        return 64
    inherited = sorted(name for name, value in os.environ.items()
                       if value and refused_environment(name))
    if inherited:
        print(f"build-offline: refusal: refusing inherited build environment: {inherited[0]}",
              file=sys.stderr)
        return 1
    try:
        work = Path(values[0])
        if not work.is_absolute() or Path(os.path.normpath(str(work))) != work:
            raise Refusal("work root must be a normalized absolute path")
        if ":" in str(work):
            raise Refusal("work root must not contain a colon")
        source = canonical(Path.cwd(), "extracted source root", directory=True)
        rustup_name = shutil.which("rustup", path=os.environ.get("PATH"))
        if rustup_name is None:
            raise Refusal("rustup is unavailable")
        coordinator = Coordinator(source, work, Path(rustup_name).resolve())
        coordinator.run()
    except Interrupted:
        number = coordinator.pending_signal or signal.SIGTERM
        coordinator.cleanup()
        return 128 + number
    except (Refusal, OSError, ValueError) as error:
        print(f"build-offline: refusal: {error}", file=sys.stderr)
        if "coordinator" in locals():
            coordinator.cleanup()
        return 1
    finally:
        if "coordinator" in locals() and coordinator.created:
            coordinator.cleanup()
    return 0


def main(arguments: list[str] | None = None) -> int:
    previous_umask = os.umask(0o077)
    try:
        return _main(arguments)
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
