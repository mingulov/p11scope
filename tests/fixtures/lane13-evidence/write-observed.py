import json
import pathlib
import runpy
import sys

check = runpy.run_path("scripts/check-capture-evidence.py")
evidence = check["evidence_fixture"](
    check["LEGACY_SURFACES"], sources=("manifest",), discovery_skipped=0
)
evidence["skipped"] = [{
    "name": check["DISCOVERY_SUBJECT"],
    "reason": check["SHARED_OVERLAY_UNCERTAINTY"],
}]
evidence.update(table_entries=68, slots=68, attached_probes=136)
document = check["document_fixture"](
    evidence,
    schema=check["METRICS_SCHEMA"],
    mode="metrics",
    privacy="aggregate-only",
)
pairs = [(["C_GetFunctionList"], 1)]
for line in pathlib.Path("spike/expected.txt").read_text().splitlines():
    name, calls = line.split()
    pairs.append(([name], int(calls)))
document["functions"] = check["function_items"](pairs)
pathlib.Path(sys.argv[1]).write_text(json.dumps(document), encoding="utf-8")
