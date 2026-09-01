#!/bin/sh -eu
# Gate G1: p11scope-discover runs against SoftHSM2 and the deterministic
# 68/92/104 table fixture in ubuntu (glibc) and alpine (musl). Both helper
# builds are DYNAMIC (a static helper cannot dlopen providers sanely).
# The glibc binary is built in rust:1.88.0-bookworm
# (glibc 2.36) so it runs on ubuntu 24.04 (2.39) — the host glibc may be
# newer than the container's, so a host build is not portable.
#
# Both --target-dir paths below are under the private receipt mount (/receipt),
# not the container's own /tmp, so the built artifacts survive the container's
# --rm and are reused as-is by scripts/build-release.sh, which supplies its own
# P11SCOPE_TASK4_WORK base, instead of building them a second time.
set -eu
cd "$(dirname "$0")/.."

ORACLE=scripts/fixtures/discover-manifest.jq
SOFTHSM_FUNCTION_RECORDS=68

# Both container lanes assert the same two things: SoftHSM2 publishes exactly
# 68 function records, and the deterministic version-matrix manifest satisfies
# $ORACLE. `--self-test` runs those assertions unprivileged over synthetic
# manifests and requires every claimed field to refuse a mutation. It needs no
# docker, no network and no container image.
self_test() {
    command -v jq >/dev/null || { echo "jq required"; exit 1; }
    st_work=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-discover-selftest-XXXXXX")
    trap 'rm -rf "$st_work"' EXIT INT TERM
    python3 - "$st_work" "$ORACLE" "$SOFTHSM_FUNCTION_RECORDS" <<'PY'
import copy
import json
from pathlib import Path
import subprocess
import sys

work, oracle, records = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])


def surface(major, minor, count, name=None, error=None):
    return {
        "version": {"major": major, "minor": minor},
        "walk": {"status": "full"},
        "functions": [{"name": f"C_{index}"} for index in range(count)],
        "source": {
            "classification": "corroborated_standard_prefix" if name or error else "exact",
            "name_lossy": name,
            "name_error": error,
        },
    }


GOOD = {
    "surfaces": [
        surface(2, 40, 68),
        surface(3, 0, 92),
        surface(3, 1, 92),
        surface(3, 2, 104),
        surface(3, 2, 104, name="Acme Standard ABI"),
        surface(3, 0, 92, error="null name pointer"),
    ],
    "vendor_interfaces": [{"name_lossy": "Vendor Pretend"}],
}


def accepted(document):
    path = work / "candidate.json"
    path.write_text(json.dumps(document))
    return subprocess.run(
        ["jq", "-e", "-f", oracle, str(path)], capture_output=True
    ).returncode == 0


def mutate(index, **changes):
    document = copy.deepcopy(GOOD)
    document["surfaces"][index].update(changes)
    return document


def mutate_version(major, minor, **changes):
    """Every surface publishing this version, so no sibling surface can still
    satisfy the claim under test."""
    document = copy.deepcopy(GOOD)
    for entry in document["surfaces"]:
        if entry["version"] == {"major": major, "minor": minor}:
            entry.update(changes)
    return document


if not accepted(GOOD):
    raise SystemExit("the unmutated version-matrix oracle document was rejected")

mutations = [
    ("2.40 slot count", mutate_version(2, 40, functions=[{}] * 67)),
    ("3.0 slot count", mutate_version(3, 0, functions=[{}] * 68)),
    ("3.1 slot count", mutate_version(3, 1, functions=[{}] * 104)),
    ("3.2 slot count", mutate_version(3, 2, functions=[{}] * 92)),
    ("full walk status", mutate_version(2, 40, walk={"status": "partial"})),
    ("published version", mutate_version(2, 40, version={"major": 2, "minor": 41})),
    (
        "alternate name classification",
        mutate(4, source={"classification": "vendor", "name_lossy": "Acme Standard ABI"}),
    ),
    (
        "alternate name spelling",
        mutate(4, source={"classification": "corroborated_standard_prefix", "name_lossy": "Other"}),
    ),
    (
        "null name error",
        mutate(5, source={"classification": "corroborated_standard_prefix", "name_error": None}),
    ),
    ("vendor interface", {**copy.deepcopy(GOOD), "vendor_interfaces": []}),
]
for label, document in mutations:
    if accepted(document):
        raise SystemExit(f"mutation accepted: {label}")

# The SoftHSM record-count claim both container lanes make, with the exact
# pattern they count with: an exact-count manifest passes and a short one does
# not, so `test "$n" = 68` cannot pass on a truncated manifest.
def counted(total):
    path = work / f"softhsm-{total}.json"
    path.write_text(
        json.dumps({"functions": [{"name": f"C_{index}"} for index in range(total)]}, indent=2)
    )
    return int(
        subprocess.run(
            ["sh", "-c", f'grep -c \'"name": "C_\' {path}'], capture_output=True, text=True
        ).stdout.strip()
    )


if counted(records) != records:
    raise SystemExit(f"record-count oracle counted {counted(records)}, want {records}")
if counted(records - 1) == records:
    raise SystemExit("record-count oracle cannot distinguish a short manifest")
print(f"discover-containers oracle mutations rejected: OK ({len(mutations)} lanes)")
PY
    echo "verify-discover-containers self-test: OK"
    exit 0
}

[ "${1-}" != "--self-test" ] || { [ "$#" -eq 1 ] || exit 2; self_test; }

[ "$#" -eq 2 ] && [ "$1" = --lane14-facts ] || {
    echo "usage: $0 --self-test | --lane14-facts ABSENT_ARTIFACTS_FILE" >&2
    exit 2
}
LANE14_FACTS=$2
LANE14_ARTIFACTS=${LANE14_FACTS%/*}
[ "${LANE14_FACTS##*/}" = discover.facts ] || exit 1
[ "${LANE14_ARTIFACTS##*/}" = artifacts ] || exit 1
[ -d "$LANE14_ARTIFACTS" ] && [ ! -L "$LANE14_ARTIFACTS" ] || exit 1
[ "$(stat -Lc %u:%a "$LANE14_ARTIFACTS")" = "$(id -u):700" ] || exit 1
[ ! -e "$LANE14_FACTS" ] && [ ! -L "$LANE14_FACTS" ] || exit 1
umask 077
: > "$LANE14_FACTS"
chmod 600 "$LANE14_FACTS"
LANE14_FACTS_ID=$(stat -Lc %d:%i "$LANE14_FACTS")
printf 'facts_identity\t%s\nstarted_utc\t%s\n' "$LANE14_FACTS_ID" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LANE14_FACTS"
# docker refuses a relative -v source, so the receipt mount must be absolute: a
# supplied base is required to be absolute (the sibling gates' contract) and the
# standalone default is rooted in a private 0700 directory on sticky /tmp rather
# than in the checkout, which root-owned container build output must not litter.
if [ -n "${P11SCOPE_TASK4_WORK:-}" ]; then
    case $P11SCOPE_TASK4_WORK in /*) ;; *) echo "P11SCOPE_TASK4_WORK must be absolute" >&2; exit 2 ;; esac
    DISCOVER_WORK=$P11SCOPE_TASK4_WORK/discover
else
    DISCOVER_WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-verify-XXXXXX")/target/discover
    echo "work root: $DISCOVER_WORK"
fi
(umask 077; mkdir -p "$DISCOVER_WORK")

TOKEN=$$
GLIBC_BUILD="p11scope-discover-glibc-build-$TOKEN"
GLIBC_RUN="p11scope-discover-glibc-run-$TOKEN"
MUSL_BUILD="p11scope-discover-musl-build-$TOKEN"
# Ownership follows creation. Each id stays empty until `docker create` returns
# one and an exact-id readback confirms it, so a lane that fails after its own
# container exists is still removed by the trap (Task 10 F5), while a name
# collision fails creation with nothing recorded and the trap deletes nothing:
# mutable names alone never authorize deletion
# (docs/superpowers/reports/2026-08-28-task4-receipt-architecture-decision.md).
GLIBC_BUILD_ID=
GLIBC_RUN_ID=
MUSL_BUILD_ID=
cleanup() {
    status=$?
    trap - EXIT INT TERM
    for owned_id in "$GLIBC_BUILD_ID" "$GLIBC_RUN_ID" "$MUSL_BUILD_ID"; do
        [ -z "$owned_id" ] || timeout --signal=TERM --kill-after=5s 30s \
            docker rm -f "$owned_id" >/dev/null 2>&1 || status=1
    done
    if [ "$(stat -Lc %d:%i "$LANE14_FACTS" 2>/dev/null)" != "$LANE14_FACTS_ID" ]; then
        status=1
    else
        for owned_id in "$GLIBC_BUILD_ID" "$GLIBC_RUN_ID" "$MUSL_BUILD_ID"; do
            [ -z "$owned_id" ] || if docker inspect "$owned_id" >/dev/null 2>&1; then status=1; fi
        done
        printf 'cleanup_query\tcontainers-absent\nended_utc\t%s\nchild_exit\t%s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$status" >> "$LANE14_FACTS" || status=1
        sync -f "$LANE14_FACTS" 2>/dev/null || status=1
    fi
    exit "$status"
}
. scripts/cleanup-traps.sh

# Prints the immutable id of a newly created container, refusing anything the
# daemon does not hand back under that exact id. The caller records the id
# before `docker start`, so cleanup authority is never held over a name.
create_owned() {
    owned=$(timeout --signal=TERM --kill-after=5s 60s docker create "$@")
    [ -n "$owned" ] || { echo "docker create returned no container id" >&2; exit 1; }
    readback=$(timeout --signal=TERM --kill-after=5s 30s docker inspect -f '{{.Id}}' "$owned")
    [ "$readback" = "$owned" ] || { echo "container id readback mismatch" >&2; exit 1; }
    printf '%s\n' "$owned"
}

timeout --signal=TERM --kill-after=5s 300s docker pull -q ubuntu:24.04
timeout --signal=TERM --kill-after=5s 300s docker pull -q rust:1.88.0-bookworm
timeout --signal=TERM --kill-after=5s 300s docker pull -q rust:1.88.0-alpine

# Vendored so container builds need no network (sandbox git quirks).
# The vendor config is rewritten with absolute /src paths because it is
# copied into $CARGO_HOME inside the containers.
mkdir -p "$DISCOVER_WORK/vendor"
timeout --signal=TERM --kill-after=5s 600s \
    cargo +1.88 vendor --locked "$DISCOVER_WORK/vendor/src" > "$DISCOVER_WORK/vendor/config.toml"
sed 's|directory = ".*"|directory = "/receipt/vendor/src"|' \
    "$DISCOVER_WORK/vendor/config.toml" > "$DISCOVER_WORK/vendor/config.container.toml"

echo "=== glibc: build in rust:1.88.0-bookworm, run in ubuntu:24.04 ==="
GLIBC_BUILD_ID=$(create_owned --name "$GLIBC_BUILD" \
    -v "$PWD:/src:ro" -v "$DISCOVER_WORK:/receipt" -w /src rust:1.88.0-bookworm sh -ec '
  export CARGO_HOME=/tmp/cargo
  mkdir -p /tmp/cargo && cp /receipt/vendor/config.container.toml /tmp/cargo/config.toml
  cargo build --locked --release -p p11scope-discover --offline --target-dir /receipt/glibc-build')
printf 'container_glibc_build\t%s\n' "$GLIBC_BUILD_ID" >> "$LANE14_FACTS"
timeout --signal=TERM --kill-after=5s 600s docker start -a "$GLIBC_BUILD_ID"
GLIBC_RUN_ID=$(create_owned --name "$GLIBC_RUN" \
    -v "$PWD:/src:ro" \
    -v "$DISCOVER_WORK/glibc-build/release/p11scope-discover:/usr/local/bin/p11scope-discover:ro" \
    ubuntu:24.04 sh -ec '
  apt-get update -q >/dev/null && apt-get install -qy gcc jq softhsm2 util-linux >/dev/null
  run_discover() {
    setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
      p11scope-discover "$@"
  }
  run_discover --module /usr/lib/softhsm/libsofthsm2.so -o /tmp/m.json
  n=$(grep -c "\"name\": \"C_" /tmp/m.json)
  test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
  gcc -shared -fPIC -DLEGACY_MAJOR=2 -DLEGACY_MINOR=40 -DMATRIX_INTERFACES=1 \
      -o /tmp/matrix.so /src/crates/discover/tests/fixture/version_matrix.c
  run_discover --module /tmp/matrix.so -o /tmp/matrix.json
  jq -e -f /src/scripts/fixtures/discover-manifest.jq /tmp/matrix.json >/dev/null
  echo "ubuntu glibc: SoftHSM 68 + fixture 68/92/104 + alternate/null names OK"')
printf 'container_glibc_run\t%s\n' "$GLIBC_RUN_ID" >> "$LANE14_FACTS"
timeout --signal=TERM --kill-after=5s 300s docker start -a "$GLIBC_RUN_ID"

echo "=== musl-dynamic: build + run in rust:1.88.0-alpine ==="
MUSL_BUILD_ID=$(create_owned --name "$MUSL_BUILD" \
    -v "$PWD:/src:ro" -v "$DISCOVER_WORK:/receipt" -w /src rust:1.88.0-alpine sh -ec '
  apk add -q musl-dev gcc softhsm file jq util-linux
  export CARGO_HOME=/tmp/cargo
  mkdir -p /tmp/cargo && cp /receipt/vendor/config.container.toml /tmp/cargo/config.toml
  export RUSTFLAGS="-C target-feature=-crt-static"
  cargo build --locked --release -p p11scope-discover --offline --target-dir /receipt/musl-build
  file /receipt/musl-build/release/p11scope-discover | grep -q "dynamically linked" \
      || { echo "helper is NOT dynamic"; exit 1; }
  ldd /receipt/musl-build/release/p11scope-discover
  # /receipt is the private 0700 receipt mount, which uid 65534 cannot traverse,
  # so the dropped-privilege runner gets the helper from a 0755 directory --
  # exactly where the glibc lane bind-mounts its own binary. Same file, same
  # dynamic links: `file` and `ldd` above still check the built artifact itself.
  install -m 0755 /receipt/musl-build/release/p11scope-discover /usr/local/bin/p11scope-discover
  run_discover() {
    setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
      p11scope-discover "$@"
  }
  run_discover --module /usr/lib/softhsm/libsofthsm2.so -o /tmp/m.json
  n=$(grep -c "\"name\": \"C_" /tmp/m.json)
  test "$n" = 68 || { echo "expected 68 function records, got $n"; exit 1; }
  gcc -shared -fPIC -DLEGACY_MAJOR=2 -DLEGACY_MINOR=40 -DMATRIX_INTERFACES=1 \
      -o /tmp/matrix.so /src/crates/discover/tests/fixture/version_matrix.c
  run_discover --module /tmp/matrix.so -o /tmp/matrix.json
  jq -e -f /src/scripts/fixtures/discover-manifest.jq /tmp/matrix.json >/dev/null
  echo "alpine musl-dynamic: SoftHSM 68 + fixture 68/92/104 + alternate/null names OK"')
printf 'container_musl_build\t%s\n' "$MUSL_BUILD_ID" >> "$LANE14_FACTS"
timeout --signal=TERM --kill-after=5s 600s docker start -a "$MUSL_BUILD_ID"

echo "=== container verification: ALL OK ==="
printf 'oracle\tsofthsm-68-and-fixture-68-92-104\n' >> "$LANE14_FACTS"
