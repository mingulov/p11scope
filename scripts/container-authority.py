#!/usr/bin/env python3
"""Prepare and prove container attachment authority without trusting stored paths."""

import copy
import ctypes
import fcntl
import json
import os
import signal
import stat
import sys
import tempfile
from pathlib import Path


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def write_json(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        temporary = output.name
    os.replace(temporary, path)


def validate_copy(root, module):
    root = Path(root).resolve(strict=True)
    module = Path(module).resolve(strict=True)
    require(module.is_relative_to(root), f"module escapes safe copy: {module}")
    require(module.is_file(), f"module is not a regular file: {module}")
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        require(not stat.S_ISLNK(mode), f"safe copy contains a symlink: {path}")
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), f"safe copy contains a non-file: {path}")
    return root, module


def rewrite_manifest(source, destination, safe_root, target_root):
    manifest = json.loads(Path(source).read_text(encoding="utf-8"))
    require(manifest.get("schema") == "p11scope-manifest/4", "container manifest is not schema v4")
    require(manifest.get("objects"), "container manifest has no attach objects")
    require(manifest.get("provenance_objects"), "container manifest has no provenance closure")
    safe_root, module = validate_copy(safe_root, manifest["module_path"])
    target_root = Path(target_root)
    require(target_root.is_absolute(), f"target root is not absolute: {target_root}")
    def target(path):
        resolved = Path(path).resolve(strict=True)
        try:
            relative = resolved.relative_to(safe_root)
        except ValueError as error:
            raise AssertionError(f"attach object escapes safe copy: {resolved}") from error
        return str(target_root / relative)

    manifest["module_path"] = target(module)
    for item in manifest["objects"]:
        item["path"] = target(item["path"])
    require(manifest["objects"][0]["path"] == manifest["module_path"], "object zero is not the module")
    write_json(destination, manifest)


class StatFs(ctypes.Structure):
    _fields_ = [
        ("f_type", ctypes.c_long),
        ("f_bsize", ctypes.c_long),
        ("f_blocks", ctypes.c_ulong),
        ("f_bfree", ctypes.c_ulong),
        ("f_bavail", ctypes.c_ulong),
        ("f_files", ctypes.c_ulong),
        ("f_ffree", ctypes.c_ulong),
        ("f_fsid", ctypes.c_int * 2),
        ("f_namelen", ctypes.c_long),
        ("f_frsize", ctypes.c_long),
        ("f_flags", ctypes.c_long),
        ("f_spare", ctypes.c_long * 4),
    ]


def filesystem_type(fd):
    value = StatFs()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.fstatfs(fd, ctypes.byref(value)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return f"0x{value.f_type & ((1 << 64) - 1):x}"


def open_regular(path):
    pinned = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(pinned)
        require(stat.S_ISREG(metadata.st_mode), f"authority object is not regular: {path}")
        fd = os.open(f"/proc/self/fd/{pinned}", os.O_RDONLY | os.O_CLOEXEC)
        reopened = os.fstat(fd)
        if (reopened.st_dev, reopened.st_ino) != (metadata.st_dev, metadata.st_ino):
            os.close(fd)
            raise AssertionError(f"authority object changed while opening: {path}")
        return fd, metadata
    finally:
        os.close(pinned)


def lease_evidence(manifest_path, output_path):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    require(manifest.get("schema") == "p11scope-manifest/4", "container manifest is not schema v4")
    requested = []
    for role, items in (("attach", manifest.get("objects", [])), ("authorization", manifest.get("provenance_objects", []))):
        for item in items:
            requested.append((role, item["path"]))
    require(requested, "container manifest has no authority objects")

    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGIO})
    opened = {}
    try:
        for role, path in requested:
            require(Path(path).is_absolute(), f"authority path is not absolute: {path}")
            fd, metadata = open_regular(path)
            key = (metadata.st_dev, metadata.st_ino)
            if key in opened:
                os.close(fd)
                opened[key]["roles"].add(role)
                opened[key]["paths"].add(path)
                continue
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
            opened[key] = {"fd": fd, "roles": {role}, "paths": {path}, "stat": metadata}

        records = []
        for (device, inode), item in sorted(opened.items()):
            require(fcntl.fcntl(item["fd"], fcntl.F_GETLEASE) == fcntl.F_RDLCK, "read lease was not retained")
            records.append(
                {
                    "device": device,
                    "inode": inode,
                    "filesystem": filesystem_type(item["fd"]),
                    "roles": sorted(item["roles"]),
                    "paths": sorted(item["paths"]),
                    "lease": "read",
                }
            )
        timeout = int(Path("/proc/sys/fs/lease-break-time").read_text(encoding="ascii").strip())
        require(timeout >= 0, "negative lease-break-time")
        write_json(
            output_path,
            {
                "schema": "p11scope-container-lease-evidence/1",
                "lease_break_time": timeout,
                "objects": records,
            },
        )
    finally:
        for item in opened.values():
            os.close(item["fd"])
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def self_test():
    with tempfile.TemporaryDirectory(prefix=".container-authority-", dir=".") as temporary:
        root = Path(temporary).resolve()
        safe = root / "safe"
        target = root / "target"
        safe.mkdir()
        target.mkdir()
        module = safe / "provider.so"
        sibling = safe / "sibling.so"
        module.write_bytes(b"provider")
        sibling.write_bytes(b"sibling")
        (target / module.name).write_bytes(module.read_bytes())
        (target / sibling.name).write_bytes(sibling.read_bytes())
        validate_copy(safe, module)
        link = safe / "forbidden-link"
        link.symlink_to(module.name)
        try:
            validate_copy(safe, module)
        except AssertionError:
            pass
        else:
            raise AssertionError("safe-copy symlink was accepted")
        link.unlink()
        fifo = safe / "forbidden-fifo"
        os.mkfifo(fifo)
        try:
            validate_copy(safe, module)
        except AssertionError:
            pass
        else:
            raise AssertionError("safe-copy special file was accepted")
        try:
            open_regular(fifo)
        except AssertionError:
            pass
        else:
            raise AssertionError("authority FIFO reached readable-open semantics")
        fifo.unlink()
        print("container safe-copy validation: OK")

        provenance = [{"path": str(module), "identity": {"sha256": "a" * 64}}]
        raw = root / "raw.json"
        rewritten = root / "rewritten.json"
        write_json(
            raw,
            {
                "schema": "p11scope-manifest/4",
                "module_path": str(module),
                "objects": [{"id": 0, "path": str(module)}, {"id": 1, "path": str(sibling)}],
                "provenance_objects": provenance,
            },
        )
        rewrite_manifest(raw, rewritten, safe, target)
        result = json.loads(rewritten.read_text(encoding="utf-8"))
        require(result["module_path"] == str(target / module.name), result)
        require(result["objects"][1]["path"] == str(target / sibling.name), result)
        require(result["provenance_objects"] == provenance, result)
        bad = copy.deepcopy(result)
        bad["schema"] = "p11scope-manifest/3"
        write_json(raw, bad)
        try:
            rewrite_manifest(raw, rewritten, safe, target)
        except AssertionError:
            pass
        else:
            raise AssertionError("non-v4 manifest was accepted")
        bad = copy.deepcopy(result)
        bad["module_path"] = __file__
        write_json(raw, bad)
        try:
            rewrite_manifest(raw, rewritten, safe, target)
        except AssertionError:
            pass
        else:
            raise AssertionError("escaping attach path was accepted")
        write_json(rewritten, result)
        print("manifest attach-path rewrite: OK")

        evidence_path = root / "leases.json"
        lease_evidence(rewritten, evidence_path)
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        require(evidence["schema"] == "p11scope-container-lease-evidence/1", evidence)
        require(evidence["lease_break_time"] >= 0, evidence)
        require(len(evidence["objects"]) == 3, evidence)
        require(all(item["lease"] == "read" and item["filesystem"] for item in evidence["objects"]), evidence)
        target_link = target / "linked.so"
        target_link.symlink_to(module.name)
        bad = copy.deepcopy(result)
        bad["objects"][0]["path"] = str(target_link)
        bad["module_path"] = str(target_link)
        write_json(rewritten, bad)
        try:
            lease_evidence(rewritten, evidence_path)
        except (AssertionError, OSError):
            pass
        else:
            raise AssertionError("symlink authority object was opened")
        print("read-lease and filesystem evidence: OK")


def main(arguments):
    if arguments == ["--self-test"]:
        self_test()
    elif len(arguments) == 3 and arguments[0] == "validate-copy":
        validate_copy(*arguments[1:])
    elif len(arguments) == 5 and arguments[0] == "rewrite":
        rewrite_manifest(*arguments[1:])
    elif len(arguments) == 3 and arguments[0] == "lease-evidence":
        lease_evidence(*arguments[1:])
    else:
        raise AssertionError(
            "usage: container-authority.py validate-copy SAFE_ROOT MODULE | "
            "rewrite INPUT OUTPUT SAFE_ROOT TARGET_ROOT | "
            "lease-evidence MANIFEST OUTPUT | --self-test"
        )


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (AssertionError, KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"container authority rejected: {error}", file=sys.stderr)
        raise SystemExit(1)
