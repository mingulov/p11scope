#!/usr/bin/env python3
"""Controlled external tools; never compile or execute a frozen artifact."""
import json
import os
from pathlib import Path
import runpy
import shutil
import sys

config = json.loads(Path(os.environ["P11SCOPE_LIVE_FREEZE_FIXTURE"]).read_text())
name = Path(sys.argv[0]).name
args = sys.argv[1:]
private = Path(config["private"])
prefix = private / "dependencies" / "prepared"
with Path(config["events"]).open("a") as stream:
    stream.write(json.dumps({
        "tool": name, "argv": args, "cwd": os.getcwd(),
        "rustc": os.environ.get("RUSTC"),
        "bpf_cargo": os.environ.get("P11SCOPE_PREPARED_BPF_CARGO"),
        "bpf_rustc": os.environ.get("P11SCOPE_PREPARED_BPF_RUSTC"),
        "private_ready": private.is_dir() and private.stat().st_mode & 0o777 == 0o700,
        "initial_ready": Path(str(prefix) + ".initial.receipt.json").is_file(),
        "published": (private / "execution-manifest.json").exists(),
    }) + "\n")
if name == "rustup":
    assert args[:2] == ["which", "--toolchain"] and len(args) == 4
    print(config["tools"][":".join(args[2:])])
elif name in ("stable cargo", "bpf cargo") and args[0] == "metadata":
    runpy.run_path(config["metadata_tool"], run_name="__main__")
elif name == "stable cargo" and args[0] == "build":
    assert private.is_dir() and Path(str(prefix) + ".initial.receipt.json").is_file()
    target = Path(args[args.index("--target-dir") + 1])
    out = target / "release/build/p11scope-fixture/out/p11scope-ebpf"
    out.parent.mkdir(parents=True)
    out.write_bytes(b"controlled BPF build bytes\n")
    shutil.copyfile("/bin/true", target / "release/p11scope")
    if config.get("mutate"):
        with Path(config["mutate"]).open("a") as stream:
            stream.write("\n# changed during controlled build\n")
    if config.get("final_bpf_status"):
        metadata_config = Path(os.environ["P11SCOPE_FAKE_CARGO_CONFIG"])
        value = json.loads(metadata_config.read_text())
        value.update(bpf_status=config["final_bpf_status"],
                     bpf_stdout="partial final query", bpf_stderr="failed final query")
        metadata_config.write_text(json.dumps(value))
    raise SystemExit(config.get("build_status", 0))
elif name in ("gcc", "ld") and args == ["--version"]:
    print(name + " controlled fixture version")
elif name == "gcc":
    out = Path(args[args.index("-o") + 1])
    if out.name.endswith(".so"):
        content = Path(config["libc"]).read_bytes()
        if out.name == "provider-exported.so":
            assert b"__libc_start_main\0" in content
            content = content.replace(b"__libc_start_main\0", b"C_GetFunctionList\0")
        out.write_bytes(content)
    else:
        shutil.copyfile("/bin/true", out)
elif name == "ldd":
    if args == ["--version"]:
        print(os.confstr("CS_GNU_LIBC_VERSION"))
    else:
        print("libc.so.6 => " + config["libc"] + " (0x0)")
else:
    print("unexpected tool execution: " + name, file=sys.stderr)
    raise SystemExit(88)
