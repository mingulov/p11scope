#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny external command fixture; no compiler or real Cargo is invoked."""

import json
import os
from pathlib import Path
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
control = json.loads(Path(os.environ["BPF_FIXTURE_CONTROL"]).read_text())
cwd = Path.cwd()
record = {"tool": tool, "argv": args, "cwd": str(cwd)}
if tool == "cargo" and "fetch" in args:
    record["offline"] = os.environ.get("CARGO_NET_OFFLINE")

if tool == "cargo" and "build" in args:
    record["fresh"] = not (cwd / "build-already-ran").exists()
    record["offline"] = os.environ.get("CARGO_NET_OFFLINE")
    home = Path(os.environ["CARGO_HOME"])
    record["home_fresh"] = not (home / "fixture-build-marker").exists()
    record["config"] = (home / "config.toml").read_text() if (home / "config.toml").exists() else None
    record["inherited_overrides"] = {key: os.environ[key] for key in (
        "RUSTFLAGS", "RUSTC_WRAPPER", "CARGO_PROFILE_RELEASE_DEBUG", "CFLAGS",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "P11SCOPE_SMALL_RING",
        "P11SCOPE_SMALL_STATE_MAPS", "P11SCOPE_SMALL_DISCOVERY_RING") if key in os.environ}
with Path(os.environ["BPF_FIXTURE_LOG"]).open("a") as log:
    log.write(json.dumps(record) + "\n")

if tool == "rustup":
    if args[:1] == ["which"]:
        print(Path(control.get("toolchain_dir", Path(sys.argv[0]).parent)) / args[-1])
    elif args == ["--help"]:
        help_text = control.get("rustup_help", "rustup 1.29.1 (d95a37b6a 2026-08-13)\n\nThe Rust toolchain installer\n\nUsage: rustup [OPTIONS] [COMMAND]\n")
        if control.get("change_rustup_version") and (cwd / "build-already-ran").exists():
            help_text = "rustup 2.30.1 (012345678 2026-10-09)\n\nThe Rust toolchain installer\n"
        sys.stdout.write(help_text)
        if control.get("rustup_help_status"):
            print("controlled rustup help failure", file=sys.stderr)
            sys.exit(control["rustup_help_status"])
    elif args == ["--version"]:
        sys.exit("rustup --version tripwire: the own-version query must use --help")
    else:
        sys.exit("unexpected rustup query")
elif tool == "clang-18" and args == ["-print-resource-dir"]:
    print(Path(sys.argv[0]).parent)
elif tool == "dpkg-query":
    print("clang-18=1:18.1.8\nlinux-libc-dev=7.0\nlibc6-dev=2.43")
elif tool == "llvm-readelf":
    print(".text PROGBITS .maps PROGBITS .BTF PROGBITS .debug_str PROGBITS")
elif tool == "cargo" and "metadata" in args:
    if not any((cwd / name).is_file() for name in ("prepared", "third-party/.prepare-dependencies.lock")):
        sys.exit("metadata before dependency preparation")
    print(json.dumps({"packages": [{"name": "p11scope", "id": "fixture-root-package",
                                  "manifest_path": str(cwd / "Cargo.toml")}],
                      "workspace_root": str(cwd)}))
elif tool == "cargo" and "fetch" in args:
    if not any((cwd / name).is_file() for name in ("prepared", "third-party/.prepare-dependencies.lock")):
        sys.exit("fetch before dependency preparation")
    if os.environ.get("CARGO_NET_OFFLINE") == "true" and "--offline" not in args:
        sys.exit("fetch unexpectedly offline")
    if "crates/ebpf/Cargo.toml" in args:
        (cwd / "bpf-fetched").write_text("yes")
    elif args[-1] == str(Path(control["sysroot"]) / "lib/rustlib/src/rust/library/sysroot/Cargo.toml"):
        if not all((cwd / name).exists() for name in ("root-fetched", "bpf-fetched")):
            sys.exit("sysroot fetch before root and BPF fetches")
        if not control.get("skip_sysroot_fetch"):
            (cwd / "sysroot-fetched").write_text("yes")
    else:
        (cwd / "root-fetched").write_text("yes")
elif tool == "cargo" and "build" in args:
    if (not any((cwd / name).is_file() for name in ("prepared", "third-party/.prepare-dependencies.lock"))
            or not all((cwd / name).is_file() for name in ("root-fetched", "bpf-fetched"))):
        sys.exit("build before dependency preparation and both fetches")
    if control.get("require_sysroot") and not (cwd / "sysroot-fetched").exists():
        sys.exit("build before required sysroot fetch")
    (cwd / "build-already-ran").write_text("yes")
    (home / "fixture-build-marker").write_text("built")
    if control.get("build_failure"):
        sys.exit("controlled Cargo build failure")
    out = Path(os.environ["CARGO_BUILD_BUILD_DIR"]) / "fixture-root/out"
    out.mkdir(parents=True)
    (out / "p11scope-identity-build-info.txt").write_text("executed fixture compiler receipt\n")
    names = ("p11scope-ebpf", "p11scope-ebpf-inventory", "p11scope-ebpf-inventory-callers")
    for name in names:
        payload = b"whole ELF with debug" + name.encode()
        if name == control.get("mutate_flavor"):
            payload += (cwd / "object-source").read_bytes()
        (out / name).write_bytes(payload)
    if control.get("output") == "empty":
        (out / names[0]).write_bytes(b"")
    if control.get("output") == "missing":
        (out / names[0]).unlink()
    if control.get("output") == "symlink":
        (out / names[0]).unlink()
        (out / names[0]).symlink_to(out / names[1])
    if control.get("output") == "hardlink":
        (out / names[1]).unlink()
        os.link(out / names[0], out / names[1])
    if control.get("output") == "outside":
        out = Path(os.environ["BPF_FIXTURE_CONTROL"]).parent
    message = {"reason": "build-script-executed", "package_id": "fixture-root-package", "out_dir": str(out)}
    if control.get("output") == "foreign":
        message["package_id"] = "another-package"
    if control.get("output") == "malformed":
        print("malformed Cargo JSON")
    elif control.get("output") != "no-root-message":
        print(json.dumps(message))
    if control.get("output") == "duplicate":
        print(json.dumps(message))
    if control.get("output") != "no-finished-message":
        print(json.dumps({"reason": "build-finished", "success": not control.get("finished_failure", False)}))
    if control.get("change_source"):
        (cwd / "object-source").write_text("changed during build")
    if control.get("change_tool"):
        with (Path(sys.argv[0]).parent / "clang-18").open("a") as changed:
            changed.write("\n# controlled tool replacement\n")
    if control.get("change_dispatcher"):
        with Path(sys.argv[0]).open("a") as changed:
            changed.write("\n# controlled Cargo dispatcher replacement\n")
    if control.get("change_rustup_content"):
        with (Path(sys.argv[0]).parent / "rustup").open("a") as changed:
            changed.write("\n# controlled rustup replacement\n")
    if control.get("change_config"):
        (home / "config.toml").write_text("[net]\noffline = false\n")
    if control.get("change_payload"):
        (cwd.parent / "offline-payload/vendor/registry-1.2.3/src.rs").write_text("copied payload corruption")
    if control.get("change_coordinator_helper"):
        with Path(control["change_coordinator_helper"]).open("a") as changed:
            changed.write("\n# coordinator helper changed during build\n")
    if control.get("change_sysroot"):
        relative = "sysroot/Cargo.toml" if control["change_sysroot"] == "manifest" else "Cargo.lock"
        with (Path(control["sysroot"]) / "lib/rustlib/src/rust/library" / relative).open("a") as changed:
            changed.write("\n# nightly source changed during build\n")
elif tool == "bpf-linker":
    print("bpf-linker 0.10.4")
elif tool == "rustc":
    if args == ["--print", "sysroot"]:
        sysroot = Path(control["sysroot"])
        counter = sysroot / "fixture-query-count"
        count = int(counter.read_text()) + 1 if counter.exists() else 1
        counter.write_text(str(count))
        if count == control.get("change_sysroot_at_query"):
            with (sysroot / "lib/rustlib/src/rust/library/Cargo.lock").open("a") as changed:
                changed.write("\n# source changed between snapshots\n")
        print(sysroot)
    else:
        print("rustc 1.98.1\nhost: x86_64-unknown-linux-gnu")
elif tool == "cargo":
    print("cargo 1.98.1")
else:
    print("Ubuntu clang version 18.1.8")
