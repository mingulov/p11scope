#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

if [ "${1-}" = "--self-test" ]; then
    [ "$#" -eq 1 ] || {
        echo "usage: $0 --self-test | --discover DISCOVER --facts ABS/provider.facts" >&2
        exit 2
    }
    PROVIDER_MATRIX_MODE=--self-test
    shift
elif [ "$#" -eq 4 ] && [ "$1" = "--discover" ] && [ "$3" = "--facts" ]; then
    PROVIDER_MATRIX_MODE=--run
    PROVIDER_MATRIX_DISCOVER=$2
    PROVIDER_MATRIX_FACTS=$4
    case $PROVIDER_MATRIX_FACTS in
        /*) ;;
        *) echo "provider matrix facts path must be absolute" >&2; exit 2 ;;
    esac
    [ "${PROVIDER_MATRIX_FACTS##*/}" = "provider.facts" ] || {
        echo "provider matrix facts basename must be provider.facts" >&2
        exit 1
    }
    PROVIDER_MATRIX_ARTIFACTS=${PROVIDER_MATRIX_FACTS%/*}
    [ -n "$PROVIDER_MATRIX_ARTIFACTS" ] || PROVIDER_MATRIX_ARTIFACTS=/
    [ -d "$PROVIDER_MATRIX_ARTIFACTS" ] && [ ! -L "$PROVIDER_MATRIX_ARTIFACTS" ] || {
        echo "provider matrix facts parent must be a real directory" >&2
        exit 1
    }
    [ "$(stat -Lc %u:%a "$PROVIDER_MATRIX_ARTIFACTS")" = "$(id -u):700" ] || {
        echo "provider matrix facts parent must be caller-owned with mode 700" >&2
        exit 1
    }
    [ ! -e "$PROVIDER_MATRIX_FACTS" ] && [ ! -L "$PROVIDER_MATRIX_FACTS" ] || {
        echo "provider matrix facts file must not already exist" >&2
        exit 1
    }
    umask 077
    : > "$PROVIDER_MATRIX_FACTS"
    chmod 600 "$PROVIDER_MATRIX_FACTS"
    PROVIDER_MATRIX_FACTS_ID=$(stat -Lc %d:%i "$PROVIDER_MATRIX_FACTS")
    shift 4
else
    echo "usage: $0 --self-test | --discover DISCOVER --facts ABS/provider.facts" >&2
    exit 2
fi

python3 -I - "$PROVIDER_MATRIX_MODE" "${PROVIDER_MATRIX_DISCOVER-}" \
    "${PROVIDER_MATRIX_FACTS-}" "${PROVIDER_MATRIX_FACTS_ID-}" <<'PY'
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


# The measured provider matrix is the oracle. Surface order is significant.
MATRIX = (
    (
        "softhsm2",
        ("/usr/lib/softhsm/libsofthsm2.so",),
        "absent",
        (("legacy_function_list", 2, 40, 68, "full"),),
    ),
    (
        "p11-kit-trust",
        ("/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so",),
        "absent",
        (("legacy_function_list", 2, 40, 68, "full"),),
    ),
    (
        "gnome-keyring",
        ("/usr/lib/x86_64-linux-gnu/pkcs11/gnome-keyring-pkcs11.so",),
        "absent",
        (("legacy_function_list", 2, 20, 68, "full"),),
    ),
    (
        "nss-softokn",
        ("/usr/lib/x86_64-linux-gnu/libsoftokn3.so",),
        "ok",
        (
            ("legacy_function_list", 2, 40, 68, "full"),
            ("interface", 3, 2, 104, "full"),
            ("interface", 3, 0, 92, "full"),
            ("interface", 2, 40, 68, "full"),
        ),
    ),
    (
        "opencryptoki",
        ("/usr/lib/x86_64-linux-gnu/pkcs11/libopencryptoki.so",),
        "ok",
        (
            ("legacy_function_list", 2, 40, 68, "full"),
            ("interface", 3, 0, 92, "full"),
            ("interface", 2, 40, 68, "full"),
        ),
    ),
)


class MatrixMismatch(Exception):
    pass


def mismatch(name, field, expected, observed):
    raise MatrixMismatch(
        f"{name}: {field}: expected {expected!r}, observed {observed!r}"
    )


def validate(provider, document):
    name, _, expected_interface_status, expected_surfaces = provider
    try:
        observed_interface_status = document["interface_list"]["status"]
    except (KeyError, TypeError) as error:
        mismatch(name, "interface_list.status", expected_interface_status, f"missing: {error}")
    if observed_interface_status != expected_interface_status:
        mismatch(
            name,
            "interface_list.status",
            expected_interface_status,
            observed_interface_status,
        )

    observed_surfaces = []
    try:
        for surface in document["surfaces"]:
            observed_surfaces.append(
                (
                    surface["source"]["kind"],
                    surface["version"]["major"],
                    surface["version"]["minor"],
                    len(surface["functions"]),
                    surface["walk"]["status"],
                )
            )
    except (KeyError, TypeError) as error:
        mismatch(name, "surfaces (ordered full tuples)", expected_surfaces, f"malformed: {error}")
    observed_surfaces = tuple(observed_surfaces)
    if observed_surfaces != expected_surfaces:
        if len(observed_surfaces) != len(expected_surfaces):
            mismatch(
                name,
                "surfaces.length",
                len(expected_surfaces),
                len(observed_surfaces),
            )
        differing_index = next(
            index
            for index, (expected, observed) in enumerate(
                zip(expected_surfaces, observed_surfaces)
            )
            if expected != observed
        )
        mismatch(
            name,
            f"surfaces[{differing_index}] ordered full tuple",
            expected_surfaces[differing_index],
            observed_surfaces[differing_index],
        )


def synthetic(provider):
    name, _, interface_status, surfaces = provider
    return {
        "schema": "p11scope-manifest/5",
        "module_path": f"/synthetic/{name}.so",
        "objects": [],
        "provenance_objects": [],
        "interface_list": {"status": interface_status},
        "surfaces": [
            {
                "source": {"kind": kind},
                "acquisition": {"status": "ok"},
                "version": {"major": major, "minor": minor},
                "walk": {"status": walk},
                "functions": [{} for _ in range(count)],
            }
            for kind, major, minor, count, walk in surfaces
        ],
        "vendor_interfaces": [],
        "alias_groups": [],
        "selection_evidence": {
            "acquisition": "export_absent",
            "queries": [],
            "tables": [],
            "selection_truncated": False,
        },
    }


def self_test():
    nss = next(provider for provider in MATRIX if provider[0] == "nss-softokn")
    softhsm = next(provider for provider in MATRIX if provider[0] == "softhsm2")
    gnome = next(provider for provider in MATRIX if provider[0] == "gnome-keyring")
    validate(nss, synthetic(nss))
    print("provider matrix positive control: accepted nss-softokn")

    count_changed = synthetic(nss)
    count_changed["surfaces"][1]["functions"].pop()
    surface_dropped = synthetic(nss)
    surface_dropped["surfaces"].pop()
    surface_added = synthetic(nss)
    surface_added["surfaces"].append(copy.deepcopy(surface_added["surfaces"][-1]))
    ok_to_absent = synthetic(nss)
    ok_to_absent["interface_list"]["status"] = "absent"
    absent_to_ok = synthetic(softhsm)
    absent_to_ok["interface_list"]["status"] = "ok"
    version_changed = synthetic(gnome)
    version_changed["surfaces"][0]["version"]["minor"] = 40
    walk_changed = synthetic(nss)
    walk_changed["surfaces"][1]["walk"]["status"] = "partial"
    surfaces_reordered = synthetic(nss)
    surfaces_reordered["surfaces"][1], surfaces_reordered["surfaces"][2] = (
        surfaces_reordered["surfaces"][2],
        surfaces_reordered["surfaces"][1],
    )

    mutations = (
        ("function count 104 -> 103", nss, count_changed),
        ("surface dropped", nss, surface_dropped),
        ("surface added", nss, surface_added),
        ("interface_list ok -> absent", nss, ok_to_absent),
        ("interface_list absent -> ok", softhsm, absent_to_ok),
        ("table version 2.20 -> 2.40", gnome, version_changed),
        ("walk.status full -> partial", nss, walk_changed),
        ("surfaces reordered", nss, surfaces_reordered),
    )
    for label, provider, document in mutations:
        try:
            validate(provider, document)
        except MatrixMismatch as error:
            print(f"provider matrix mutation refused: {label}: {error}")
        else:
            raise SystemExit(f"provider matrix mutation accepted: {label}")

    recorded = (("provider_softhsm2", "PASS"), ("provider_opencryptoki", "UNRUN"))
    exercised = sum(status == "PASS" for _, status in recorded)
    unrun = sum(status == "UNRUN" for _, status in recorded)
    if exercised != 1 or unrun != 1 or exercised + unrun != len(recorded):
        raise SystemExit(
            f"UNRUN accounting laundered a provider: exercised={exercised}, UNRUN={unrun}"
        )
    print("provider matrix UNRUN accounting: OK (1 exercised, 1 UNRUN)")
    print(f"provider matrix mutations rejected: OK ({len(mutations)} lanes)")


def observed_document(discover, provider, module, output):
    completed = subprocess.run(
        [discover, "--module", module, "-o", str(output)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
        mismatch(provider[0], "discover exit status", 0, f"{completed.returncode}: {detail}")
    try:
        with output.open(encoding="utf-8") as source:
            return json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        mismatch(provider[0], "manifest JSON", "valid document", str(error))


def run_matrix(discover, facts_path, expected_identity):
    if not os.path.isfile(discover) or not os.access(discover, os.X_OK):
        raise SystemExit(f"discover binary is not an executable file: {discover}")

    facts_flags = os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        facts_flags |= os.O_NOFOLLOW
    facts_fd = os.open(facts_path, facts_flags)
    exercised = 0
    unrun = 0
    try:
        facts_stat = os.fstat(facts_fd)
        observed_identity = f"{facts_stat.st_dev}:{facts_stat.st_ino}"
        if observed_identity != expected_identity:
            raise SystemExit(
                f"provider matrix facts identity changed: expected {expected_identity}, "
                f"observed {observed_identity}"
            )
        with os.fdopen(facts_fd, "a", encoding="utf-8", closefd=False) as facts:
            facts.write(f"facts_identity {expected_identity}\n")
            with tempfile.TemporaryDirectory(prefix="p11scope-provider-matrix-") as work:
                work_path = Path(work)
                for provider in MATRIX:
                    name, candidates, _, _ = provider
                    module = next((path for path in candidates if os.path.exists(path)), None)
                    if module is None:
                        facts.write(f"provider_{name} UNRUN\n")
                        facts.flush()
                        print(f"provider_{name}: UNRUN")
                        unrun += 1
                        continue
                    output = work_path / f"{name}.json"
                    document = observed_document(discover, provider, module, output)
                    validate(provider, document)
                    facts.write(f"provider_{name} PASS\n")
                    facts.flush()
                    print(f"provider_{name}: PASS")
                    exercised += 1
            facts.write(f"provider_matrix_exercised {exercised}\n")
            facts.write(f"provider_matrix_unrun {unrun}\n")
            facts.flush()
            os.fsync(facts.fileno())
    finally:
        os.close(facts_fd)

    final_stat = os.lstat(facts_path)
    final_identity = f"{final_stat.st_dev}:{final_stat.st_ino}"
    if final_identity != expected_identity:
        raise SystemExit(
            f"provider matrix facts identity changed: expected {expected_identity}, "
            f"observed {final_identity}"
        )
    print(f"provider matrix: {exercised} exercised, {unrun} UNRUN")


mode, discover, facts_path, facts_identity = sys.argv[1:]
if mode == "--self-test":
    self_test()
    print("verify-provider-matrix self-test: OK")
elif mode == "--run":
    try:
        run_matrix(discover, facts_path, facts_identity)
    except MatrixMismatch as error:
        raise SystemExit(str(error)) from None
else:
    raise SystemExit(f"unknown provider matrix mode: {mode}")
PY
