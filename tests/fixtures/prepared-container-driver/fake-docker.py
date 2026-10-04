#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stateful Docker stand-in; container command bodies are never evaluated."""

import json
import os
from pathlib import Path
import signal
import sys
from fixture_common import CONFIG, record, refuse, save, state


arguments = sys.argv[1:]
record("docker")
if not arguments:
    refuse("missing docker operation")
operation = arguments[0]
current = state()


def resolve(target):
    return target if target in current["ids"] else current["names"].get(target)


if operation == "network":
    if len(arguments) < 2:
        refuse("missing network operation")
    network_operation = arguments[1]
    failure = CONFIG.get("network_failure")
    if network_operation == "create":
        if len(arguments) != 7 or arguments[2:5] != ["--driver", "bridge", "--label"]:
            refuse("unsupported network create")
        label, owner = arguments[5].split("=", 1)
        if label != "io.p11scope.discover.owner" or len(owner) != 32:
            refuse("network create lacks per-run owner")
        identity = "f" * 64 if failure == "collision" else "a" * 64
        current["networks"][identity] = {
            "Id": identity, "Name": arguments[6], "Driver": "bridge", "Scope": "local",
            "Labels": {label: "foreign" if failure == "collision" else owner},
            "IPAM": {"Driver": "default", "Config": [{"Subnet": "172.28.0.0/16", "Gateway": "172.28.0.1"}]},
        }
        if failure == "ambiguous":
            duplicate = dict(current["networks"][identity], Id="b" * 64)
            current["networks"]["b" * 64] = duplicate
        save(current)
        if failure == "interrupted":
            os.kill(os.getpid(), signal.SIGTERM)
        if failure in ("collision", "lost-reply", "ambiguous"):
            print("injected network create failure: " + failure, file=sys.stderr)
            raise SystemExit(125)
        print(identity)
    elif network_operation == "inspect":
        if len(arguments) != 3:
            refuse("unsupported network inspect")
        if arguments[2] not in current["networks"]:
            raise SystemExit(1)
        data = current["networks"][arguments[2]]
        if failure in ("facts-replaced", "facts-symlink") and not current.get("facts_mutated"):
            facts = Path(CONFIG["facts"])
            retained = facts.with_name("original.facts")
            facts.rename(retained)
            current["facts_before_tamper"] = retained.read_text()
            if failure == "facts-replaced":
                facts.write_text("foreign receipt bytes\n")
            else:
                facts.symlink_to(retained)
            current["facts_mutated"] = True
            save(current)
        if failure == "wrong-owner":
            data["Labels"] = {"io.p11scope.discover.owner": "foreign"}
        print(json.dumps([data]))
    elif network_operation == "ls":
        if (len(arguments) != 7 or arguments[2:4] != ["--no-trunc", "--filter"]
                or arguments[5:] != ["--format", "{{.ID}}"]):
            refuse("unsupported network list")
        if failure == "query":
            print("injected network query failure", file=sys.stderr)
            raise SystemExit(42)
        selector = arguments[4]
        for identity, network in current["networks"].items():
            if selector.startswith("label="):
                label, value = selector[len("label="):].split("=", 1)
                selected = network["Labels"].get(label) == value
            elif selector.startswith("id="):
                selected = identity == selector[len("id="):]
            else:
                refuse("unsupported network selector")
            if selected:
                print(identity)
    elif network_operation == "rm":
        if len(arguments) != 3 or arguments[2] not in current["networks"]:
            refuse("unsupported network removal")
        if any(identity in current["ids"] and network == arguments[2]
               for identity, network in current["container_networks"].items()):
            print("network retains active container endpoints", file=sys.stderr)
            raise SystemExit(32)
        if failure == "remove":
            raise SystemExit(31)
        if failure != "absence":
            current["networks"].pop(arguments[2])
            save(current)
    else:
        refuse("unsupported network operation: " + network_operation)
elif operation == "pull":
    if len(arguments) != 3 or arguments[1] != "-q":
        refuse("unsupported pull")
elif operation == "create":
    if "--name" not in arguments:
        refuse("create needs a name")
    name = arguments[arguments.index("--name") + 1]
    if CONFIG.get("collision"):
        foreign = "f" * 64
        current["ids"][foreign] = name
        current["names"][name] = foreign
        save(current)
    if name in current["names"]:
        print("docker fixture: foreign name collision", file=sys.stderr)
        raise SystemExit(125)
    current["count"] += 1
    identity = f'{current["count"]:064d}'
    current["ids"][identity] = name
    current["names"][name] = identity
    mounts = [arguments[i + 1] for i, value in enumerate(arguments[:-1]) if value == "-v"]
    for mount in mounts:
        parts = mount.split(":")
        if len(parts) >= 2 and parts[1] in ("/src", "/receipt"):
            current.setdefault("mounts", {}).setdefault(identity, {})[parts[1]] = parts[0]
    if "--network" in arguments:
        network = arguments[arguments.index("--network") + 1]
        if network not in current["networks"]:
            refuse("container uses an unknown network")
        current["container_networks"][identity] = network
    save(current)
    print(identity)
elif operation == "inspect":
    formatted = len(arguments) == 4 and arguments[1:3] == ["-f", "{{.Id}}"]
    if not formatted and len(arguments) != 2:
        refuse("unsupported inspect")
    identity = resolve(arguments[-1])
    if identity is None:
        raise SystemExit(1)
    if formatted:
        print(identity)
elif operation == "start":
    if len(arguments) != 3 or arguments[1] != "-a" or resolve(arguments[-1]) is None:
        refuse("unsupported start or absent container")
    # A build container that mounts /receipt leaves the approved Alpine
    # closure there, as the pinned image does: the fixture reads it from
    # the production script's own heredoc, so the driver's cmp still runs.
    mounted = current.get("mounts", {}).get(resolve(arguments[-1]), {})
    if "/src" in mounted and "/receipt" in mounted:
        script = Path(mounted["/src"]) / "scripts/verify-discover-containers.sh"
        text = script.read_text()
        marker = 'cat > "$DISCOVER_WORK/musl-apk-expected.txt" <<\'EOF\'\n'
        if marker in text:
            closure = text.split(marker, 1)[1].split("\nEOF\n", 1)[0] + "\n"
            (Path(mounted["/receipt"]) / "musl-apk-info.txt").write_text(closure)
    if not current["mutated"] and CONFIG.get("mutation"):
        if CONFIG["mutation"] == "tree":
            with Path(CONFIG["prepared_source"]).open("a") as stream:
                stream.write("// persistent fixture mutation\n")
        elif CONFIG["mutation"] == "metadata":
            path = Path(CONFIG["root_metadata"])
            metadata = json.loads(path.read_text())
            metadata["resolve"]["nodes"][0]["features"] = ["fixture-persistent-change"]
            path.write_text(json.dumps(metadata))
        else:
            refuse("unsupported mutation")
        current["mutated"] = True
        save(current)
elif operation == "rm":
    if len(arguments) != 3 or arguments[1] != "-f":
        refuse("unsupported removal")
    identity = resolve(arguments[-1])
    if identity is None:
        raise SystemExit(1)
    if identity == f'{1:064d}':
        if CONFIG.get("cleanup") == "remove_failure":
            raise SystemExit(31)
        if CONFIG.get("cleanup") == "absence_failure":
            raise SystemExit(0)
    name = current["ids"].pop(identity)
    current["names"].pop(name, None)
    save(current)
else:
    refuse("unsupported docker operation: " + operation)
