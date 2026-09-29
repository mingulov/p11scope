#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate an offline release notice bundle; never compile dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _loader import load_sibling


class NoticeError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_bytes(path, expected=None):
    path = Path(path).absolute()
    parent_fd = file_fd = None
    try:
        parent_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise NoticeError(f"not a regular notice input: {path}")
        chunks = []
        while chunk := os.read(file_fd, 1024 * 1024):
            chunks.append(chunk)
        data = b"".join(chunks)
        after = os.fstat(file_fd)
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current) or len(data) != after.st_size:
            raise NoticeError(f"notice input changed while reading: {path}")
    except OSError as error:
        raise NoticeError(f"cannot read regular notice input without symlinks: {path}: {error}") from error
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if parent_fd is not None:
            os.close(parent_fd)
    if expected is not None and digest(data) != expected:
        raise NoticeError(f"notice input hash mismatch: {path}")
    return data


def package_id(package, root):
    if package["id"].startswith("path+"):
        try:
            rel = Path(package["manifest_path"]).parent.relative_to(root).as_posix()
        except ValueError as error:
            raise NoticeError("path dependency outside source tree") from error
        return f"workspace:{rel}#{package['name']}@{package['version']}"
    return package["id"]


def normalize_report(report, metadata, root, inputs):
    """Validate coverage and text provenance without interpreting SPDX ourselves."""
    expected = {p["id"]: p for p in metadata["packages"]}
    actual = {p["package"]["id"]: p for p in report["crates"]}
    if set(actual) != set(expected) or len(actual) != len(report["crates"]):
        raise NoticeError("cargo-about package coverage differs from locked metadata")
    normalized = {}
    for ident, package in expected.items():
        # Cargo accepts this historical spelling; cargo-about canonicalizes it.
        # This exact alias is not a general SPDX parser or a license selection.
        canonical = {"MIT/Apache-2.0": "MIT OR Apache-2.0"}.get(package["license"], package["license"])
        if actual[ident]["license"] != canonical:
            raise NoticeError(f"declared license expression changed: {package['name']}")
        normalized[ident] = package_id(package, root)
    allowed_roots = [root, inputs, *[Path(p["manifest_path"]).parent for p in expected.values()]]
    notices = []
    covered = set()
    for entry in report["licenses"]:
        source = entry.get("source_path")
        if not source:
            raise NoticeError("cargo-about synthesized a notice without a source file")
        path = Path(source)
        if not path.is_absolute() or not any(path.is_relative_to(p) for p in allowed_roots):
            raise NoticeError("notice source outside resolved packages and pinned inputs")
        raw = checked_bytes(path)
        owners = {p["crate"]["id"] for p in entry["used_by"]}
        if not owners or not owners <= expected.keys():
            raise NoticeError("invalid notice coverage")
        covered.update(owners)
        text = entry["text"]
        if not isinstance(text, str) or not text.strip():
            raise NoticeError("empty notice text")
        notices.append({"license": entry["id"], "text": text,
                        "text_sha256": digest(text.encode()), "source_sha256": digest(raw),
                        "packages": sorted(normalized[p] for p in owners)})
    if covered != expected.keys():
        raise NoticeError("notice coverage omits resolved packages")
    packages = [{"id": normalized[p["id"]], "name": p["name"], "version": p["version"],
                 "source": p["source"], "declared_license": p["license"]}
                for p in expected.values()]
    return {"packages": sorted(packages, key=lambda p: p["id"]),
            "notices": sorted(notices, key=lambda n: (n["license"], n["text_sha256"], n["packages"]))}


def prepared_files(root, package_root):
    preparer = load_sibling("prepare-dependencies.py")
    try:
        manifest = preparer.load_manifest(root)
        for record in manifest["packages"]:
            expected = root / "third-party/src" / preparer.output_name(record)
            if package_root != expected:
                continue
            patches = preparer.read_patch_bytes(root, record)
            identity = preparer.compute_recipe_identity(record, patches)
            inventory = preparer.verified_prepared_inventory(expected, record, identity)
            return [expected / name for name, _mode, _sha in inventory]
    except preparer.PreparationError as error:
        raise NoticeError(f"prepared dependency notice inventory is invalid: {error}") from error
    raise NoticeError("unrecognized generated dependency source")


def committed_files(root):
    return {name for name in run(["git", "ls-tree", "-r", "--name-only", "-z", "HEAD"], root).split("\0") if name}


def collect_license_files(metadata, root, committed_paths=None):
    """Retain originals independently of SPDX choice or cargo-about harvesting."""
    prefixes = ("license", "licence", "copying", "copyright", "notice", "authors")
    records, payload = [], {}
    package_roots = {Path(p["manifest_path"]).parent for p in metadata["packages"]}
    for package in metadata["packages"]:
        package_root = Path(package["manifest_path"]).parent
        source_kind = package["source"] or "workspace"
        if source_kind == "workspace":
            if package_root.is_relative_to(root / "third-party/src"):
                candidates = prepared_files(root, package_root)
            else:
                if not package_root.is_relative_to(root):
                    raise NoticeError("workspace package outside source checkout")
                if committed_paths is None:
                    committed_paths = committed_files(root)
                candidates = [root / name for name in committed_paths
                              if (root / name).is_relative_to(package_root)]
        elif source_kind.startswith("git+"):
            candidates = [package_root / name for name in committed_files(package_root)]
        else:
            candidates = []
            for directory, dirs, names in os.walk(package_root, followlinks=False):
                directory = Path(directory)
                dirs[:] = sorted(d for d in dirs if d not in {".git", "target", "__pycache__"}
                                 and not (directory / d).is_symlink())
                candidates.extend(directory / name for name in names)
        for source in sorted(candidates):
            if not source.name.casefold().startswith(prefixes):
                continue
            # Attribute a nested resolved package's files to that package only.
            if any(other != package_root and other.is_relative_to(package_root)
                   and source.is_relative_to(other) for other in package_roots):
                continue
            data = checked_bytes(source)
            sha = digest(data)
            destination = f"licenses/package-files/{sha}.txt"
            payload[destination] = data
            records.append({"package": package_id(package, root),
                            "package_relative_path": source.relative_to(package_root).as_posix(),
                            "sha256": sha, "file": destination})
    return sorted(records, key=lambda r: (r["package"], r["package_relative_path"])), payload


def validate_output(root, output):
    if not output.is_absolute() or os.path.lexists(output):
        raise NoticeError("output must be an absolute, absent directory")
    if output.is_relative_to(root) or output.parent.resolve() != output.parent:
        raise NoticeError("output must have a canonical parent outside the checkout")
    parent = output.parent.stat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise NoticeError("output parent must be a private directory owned by the current user")


def run(argv, cwd, env=None):
    if Path(argv[0]).name == "git":
        env = {key: value for key, value in (os.environ if env is None else env).items()
               if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise NoticeError(f"command failed: {argv[0]}: {result.stderr.strip()}")
    return result.stdout.strip()


def source_identity(root):
    if run(["git", "status", "--porcelain", "--untracked-files=all"], root):
        raise NoticeError("release notices require a clean tracked source tree")
    return {"head": run(["git", "rev-parse", "HEAD"], root),
            "tree": run(["git", "rev-parse", "HEAD^{tree}"], root)}


def load_inputs(root, recipe):
    inputs = root / "third-party/licenses"
    verified = {}
    for name, item in recipe["files"].items():
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise NoticeError("invalid recipe input name")
        verified[name] = checked_bytes(inputs / name, item["sha256"])
    return verified


def make_config(metadata, root, recipe):
    inputs = root / "third-party/licenses"
    text = 'accepted = ["MIT", "ISC", "Zlib", "Unicode-3.0", "Apache-2.0", "GPL-2.0-or-later", "GPL-3.0-or-later", "GPL-2.0-only"]\n'
    text += 'ignore-build-dependencies = false\nignore-dev-dependencies = false\nignore-transitive-dependencies = false\nmax-depth = 10\n'
    project = {"p11scope", "p11scope-discover", "p11scope-bpf-multi", "p11scope-manifest", "p11scope-ebpf", "p11scope-ebpf-common"}
    for package in metadata["packages"]:
        name, expression = package["name"], package["license"]
        files = []
        if name in project:
            license_path = root / ("LICENSE" if expression == "GPL-3.0-or-later" else f"LICENSES/{expression}.txt")
            files = [(license_path, expression, digest(checked_bytes(license_path)))]
        elif name in recipe["clarifications"]:
            item = recipe["clarifications"][name]
            if package["version"] != item["version"] or expression != item["license"] or package["source"] != item["source"]:
                raise NoticeError(f"clarification package identity changed: {name}")
            for entry in item["files"]:
                path = inputs / entry["path"]
                expected = recipe["files"][entry["path"]]["sha256"]
                checked_bytes(path, expected)
                files.append((path, entry["license"], expected))
        if files:
            text += f'\n[{name}.clarify]\nlicense = {json.dumps(expression)}\n'
            for path, license_id, sha in files:
                text += f'[[{name}.clarify.files]]\npath = {json.dumps(str(path))}\nlicense = {json.dumps(license_id)}\nchecksum = "{sha}"\n'
    return text


def toolchain_payload(root, recipe):
    payload, facts = {}, []
    for item in recipe["toolchains"]:
        rustc = Path(run(["rustup", "which", "--toolchain", item["name"], "rustc"], root))
        version = run([str(rustc), "-Vv"], root)
        if version != item["rustc_verbose_version"]:
            raise NoticeError(f"unexpected Rust toolchain version: {item['name']}")
        sysroot = Path(run([str(rustc), "--print", "sysroot"], root))
        for entry in item["files"]:
            payload[entry["payload"]] = checked_bytes(sysroot / entry["source"], entry["sha256"])
        facts.append({"name": item["name"], "rustc_verbose_version": version})
    return payload, facts


def musl_payload(archive_paths, records):
    required = {item["sha256"]: item for item in records}
    if not required or len(required) != len(records) or len(archive_paths) != len(required):
        raise NoticeError("supply exactly one musl archive for each required SHA-256")
    found, payload = set(), {}
    for path in archive_paths:
        if not path.is_absolute():
            raise NoticeError("musl archive paths must be absolute")
        data = checked_bytes(path)
        sha = digest(data)
        if sha not in required or sha in found:
            raise NoticeError("duplicate or unrecognized musl archive SHA-256")
        found.add(sha)
        payload[f"licenses/musl-{required[sha]['version']}-source.tar.gz"] = data
    return payload


def generate(root, cargo_about, musl_archives, output):
    root = root.resolve()
    validate_output(root, output)
    if not cargo_about.is_absolute():
        raise NoticeError("cargo-about path must be absolute")
    identity = source_identity(root)
    version = run([str(cargo_about), "--version"], root)
    if version != "cargo-about 0.9.2":
        raise NoticeError("cargo-about 0.9.2 is required")
    recipe_path = root / "third-party/licenses/sources.json"
    recipe_bytes = checked_bytes(recipe_path)
    recipe = json.loads(recipe_bytes)
    if recipe.get("schema_version") != 1:
        raise NoticeError("unsupported notice recipe schema")
    verified = load_inputs(root, recipe)
    payload, toolchains = toolchain_payload(root, recipe)
    payload.update(musl_payload(musl_archives, recipe["musl"]))
    for name, data in verified.items():
        payload["licenses/upstream/" + name] = data
    payload["licenses/p11scope-GPL-3.0-or-later.txt"] = checked_bytes(root / "LICENSE")
    for name in ["GPL-2.0-only", "GPL-2.0-or-later"]:
        payload[f"licenses/p11scope-{name}.txt"] = checked_bytes(root / f"LICENSES/{name}.txt")
    graphs = {}
    environment = dict(os.environ, RUSTUP_TOOLCHAIN="1.88")
    temporary_root = Path(os.environ.get("TMPDIR", "/var/tmp/p11scope-ws-tmp"))
    temporary_root.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="p11scope-notices-", dir=temporary_root) as temporary:
        temporary = Path(temporary)
        for graph, manifest in [("host", root / "Cargo.toml"), ("bpf", root / "crates/ebpf/Cargo.toml")]:
            metadata = json.loads(run(["cargo", "metadata", "--locked", "--offline", "--no-default-features", "--format-version", "1", "--manifest-path", str(manifest)], root, environment))
            config = temporary / f"{graph}.toml"
            config.write_text(make_config(metadata, root, recipe))
            raw = json.loads(run([str(cargo_about), "generate", "--locked", "--offline", "--workspace", "--no-default-features", "--fail", "--format", "json", "--config", str(config), "--manifest-path", str(manifest)], root, environment))
            graphs[graph] = normalize_report(raw, metadata, root, root / "third-party/licenses")
            originals, additional_payload = collect_license_files(metadata, root)
            graphs[graph]["original_license_files"] = originals
            payload.update(additional_payload)
    if source_identity(root) != identity:
        raise NoticeError("source identity changed during notice generation")
    text = "# Third-party notices\n\n"
    text += "This bundle inventories both locked Cargo workspaces with normal, build, and development dependencies, all target conditions, and the default release feature selection. It includes packages used only by build tools or tests; inclusion does not establish that code is linked into a released binary.\n\n"
    text += "The observer and helper use the project GPL-3.0-or-later license. Embedded BPF programs use GPL-2.0-only; shared definitions use GPL-2.0-or-later, permitting the respective GPL2 and GPL3 choices. Original third-party terms are retained.\n\n"
    text += "The licenses directory also carries exact Rust library copyright reports, LLVM native-runtime notices, GCC and glibc helper-startup notices, and musl 1.2.3 and 1.2.5 COPYRIGHT plus complete source archives (including individual file notices). Original license, notice, copyright, and authors files from the resolved package trees are retained separately from cargo-about's selected license expressions, including nested and alternate-license notices. These supplements are deliberately inclusive; helper startup/runtime membership requires the official build evidence. See notices.json for provenance, package declarations, and payload hashes.\n\n"
    for graph, data in graphs.items():
        text += f"## {graph} Cargo workspace\n\n"
        for item in data["notices"]:
            name = f"licenses/cargo/{item['text_sha256']}.txt"
            payload[name] = item["text"].encode()
            item["file"] = name
            del item["text"]
            text += f"### {item['license']}\n\n" + ", ".join(f"`{p}`" for p in item["packages"]) + f"\n\n[Full notice]({name}).\n\n"
    payload["NOTICES.md"] = text.encode()
    inventory = {"schema_version": 1, **identity, "cargo_about_version": "0.9.2",
                 "scope": "overinclusive source inventory; normal/build/dev; no-default-features; all target conditions",
                 "recipe_sha256": digest(recipe_bytes), "graphs": graphs,
                 "toolchains": toolchains, "upstream_inputs": recipe["files"], "musl": recipe["musl"],
                 "native_runtime": recipe["native_runtime"],
                 "files": {name: digest(data) for name, data in sorted(payload.items())}}
    public_json = (json.dumps(inventory, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    if str(root).encode() in public_json or str(Path.home()).encode() in public_json:
        raise NoticeError("public inventory contains a build-host path")
    output.mkdir(mode=0o700)
    try:
        for name, data in sorted(payload.items()):
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (output / "notices.json").write_bytes(public_json)
        if source_identity(root) != identity or checked_bytes(recipe_path) != recipe_bytes:
            raise NoticeError("source or notice recipe changed during bundle publication")
    except BaseException:
        shutil.rmtree(output)
        raise
    return inventory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-about", required=True, type=Path)
    parser.add_argument("--musl-archive", required=True, action="append", type=Path,
                        help="repeat once for each recipe-pinned musl source archive")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = generate(Path(__file__).resolve().parents[1], args.cargo_about, args.musl_archive, args.output)
    except (NoticeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(f"release-notices: {error}", file=sys.stderr)
        return 1
    print(f"release notices: {len(result['files'])} payload files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
