#!/usr/bin/env python3
"""Stateful Docker stand-in; container command bodies are never evaluated."""

import json
from pathlib import Path
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


if operation == "pull":
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
