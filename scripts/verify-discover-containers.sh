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
# Official registry index digests acquired on 2026-09-08. Each PLATFORM_IMAGE is
# the single linux/amd64 entry of the index above it, read back from
# registry-1.docker.io on 2026-09-12 and compared digest-for-digest -- not
# inferred. Retain Rust 1.88 and Ubuntu 24.04; changing a tag, index or selected
# platform must not silently change the qualification inputs.
DISCOVER_GLIBC_BUILD_IMAGE=rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0
DISCOVER_GLIBC_BUILD_PLATFORM_IMAGE=rust:1.88.0-bookworm@sha256:4727898c104ecd2e22d780925832502faee9fe4e70581b8572af081370b315a0
DISCOVER_GLIBC_RUN_IMAGE=ubuntu:noble-20260810@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517
DISCOVER_GLIBC_RUN_PLATFORM_IMAGE=ubuntu:noble-20260810@sha256:1e0a86e57d247923571b75e0aaf48a1449cf8c543d51fb3e07a4a7d7bfa79316
DISCOVER_MUSL_IMAGE=rust:1.88.0-alpine@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d
DISCOVER_MUSL_PLATFORM_IMAGE=rust:1.88.0-alpine@sha256:64eba3726734dcfe89e0a62a0485007a3ab7c7372ce5b38c621d8812f70215f0
# Ubuntu 24.04's signed snapshot service freezes the complete apt dependency
# closure. Alpine has no equivalent archive snapshot, so every requested v3.22
# package is exact-versioned and restricted to the official main repository.
UBUNTU_APT_SNAPSHOT=20260810T000000Z
ALPINE_MAIN_REPOSITORY=https://dl-cdn.alpinelinux.org/alpine/v3.22/main

# Both container lanes assert the same two things: SoftHSM2 publishes exactly
# 68 function records, and the deterministic version-matrix manifest satisfies
# $ORACLE. `--self-test` runs those assertions unprivileged over synthetic
# manifests and requires every claimed field to refuse a mutation. It needs no
# docker, no network and no container image.
self_test() {
    command -v jq >/dev/null || { echo "jq required"; exit 1; }
    st_work=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-discover-selftest-XXXXXX")
    trap 'rm -rf "$st_work"' EXIT INT TERM
    python3 -I - "$st_work" "$ORACLE" "$SOFTHSM_FUNCTION_RECORDS" "$0" \
        scripts/matrix/Dockerfile <<'PY'
import copy
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

work, oracle, records = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
script_path, matrix_path = Path(sys.argv[4]), Path(sys.argv[5])

EXPECTED_PINS = (
    "DISCOVER_GLIBC_BUILD_IMAGE=rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0",
    "DISCOVER_GLIBC_BUILD_PLATFORM_IMAGE=rust:1.88.0-bookworm@sha256:4727898c104ecd2e22d780925832502faee9fe4e70581b8572af081370b315a0",
    "DISCOVER_GLIBC_RUN_IMAGE=ubuntu:noble-20260810@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517",
    "DISCOVER_GLIBC_RUN_PLATFORM_IMAGE=ubuntu:noble-20260810@sha256:1e0a86e57d247923571b75e0aaf48a1449cf8c543d51fb3e07a4a7d7bfa79316",
    "DISCOVER_MUSL_IMAGE=rust:1.88.0-alpine@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d",
    "DISCOVER_MUSL_PLATFORM_IMAGE=rust:1.88.0-alpine@sha256:64eba3726734dcfe89e0a62a0485007a3ab7c7372ce5b38c621d8812f70215f0",
    "UBUNTU_APT_SNAPSHOT=20260810T000000Z",
    "ALPINE_MAIN_REPOSITORY=https://dl-cdn.alpinelinux.org/alpine/v3.22/main",
)
EXPECTED_APK_PACKAGES = (
    "binutils=2.44-r3",
    "file=5.46-r2",
    "gcc=14.2.0-r6",
    "gmp=6.3.0-r3",
    "isl26=0.26-r1",
    "jansson=2.14.1-r0",
    "jq=1.8.2-r0",
    "libatomic=14.2.0-r6",
    "libcap-ng=0.8.5-r0",
    "libcrypto3=3.5.8-r0",
    "libgcc=14.2.0-r6",
    "libgomp=14.2.0-r6",
    "libmagic=5.46-r2",
    "libncursesw=6.5_p20250503-r0",
    "libstdc++=14.2.0-r6",
    "mpc1=1.3.1-r1",
    "mpfr4=4.2.1_p1-r0",
    "musl=1.2.5-r12",
    "musl-dev=1.2.5-r12",
    "ncurses-terminfo-base=6.5_p20250503-r0",
    "oniguruma=6.9.10-r0",
    "readline=8.2.13-r1",
    "setpriv=2.41.6-r1",
    "softhsm=2.6.1-r6",
    "sqlite=3.49.2-r1",
    "sqlite-libs=3.49.2-r1",
    "zlib=1.3.2-r0",
    "zstd-libs=1.5.7-r0",
)
PRODUCTION_CA_BOOTSTRAP = (
    "apt-get update -q >/dev/null",
    "apt-get install -qy --no-install-recommends ca-certificates >/dev/null",
)
MATRIX_CA_BOOTSTRAP = (
    "apt-get update ",
    "apt-get install -y --no-install-recommends ca-certificates ",
)
MATRIX_FROM = (
    "FROM ubuntu:noble-20260810@sha256:"
    "1e0a86e57d247923571b75e0aaf48a1449cf8c543d51fb3e07a4a7d7bfa79316"
)


def check_container_pins(script, matrix):
    try:
        production = script.split("\nPY\n", 1)[1].replace("\\\n", " ")
        declarations = script.split("    python3 -I -", 1)[0]
    except IndexError as error:
        raise ValueError("cannot isolate production shell after self-test heredoc") from error
    contract_source = declarations + production
    normalized_matrix = matrix.replace("\\\n", " ")

    for pin in EXPECTED_PINS:
        if contract_source.count(pin) != 1:
            raise ValueError(f"missing or duplicated pin: {pin}")
    production_tokens = production.split()
    for package in EXPECTED_APK_PACKAGES:
        if production_tokens.count(package) != 1:
            raise ValueError(f"missing or duplicated Alpine package pin: {package}")
    matrix_froms = [
        line.strip() for line in matrix.splitlines()
        if line.lstrip().startswith("FROM ")
    ]
    if matrix_froms != [MATRIX_FROM]:
        raise ValueError("matrix base is not the approved linux/amd64 manifest")
    if "ARG UBUNTU_APT_SNAPSHOT=20260810T000000Z" not in matrix:
        raise ValueError("matrix apt snapshot is absent")
    # ubuntu:noble carries no trust store at all, and -S rewrites the archive to
    # HTTPS snapshot.ubuntu.com, so exactly one bare apt pair is permitted per
    # source: fetch ca-certificates and nothing else. Every other apt operation
    # must carry the snapshot selector. Each allowed line is stripped once, then
    # any surviving bare apt-get is a live operation.
    for label, text, allowed in (
        ("driver", production, PRODUCTION_CA_BOOTSTRAP),
        ("matrix", normalized_matrix, MATRIX_CA_BOOTSTRAP),
    ):
        remainder = text
        for line in allowed:
            if remainder.count(line) != 1:
                raise ValueError(
                    f"{label} ca-certificates bootstrap is missing or duplicated: {line}"
                )
            remainder = remainder.replace(line, "", 1)
        if re.search(r"\bapt-get\s+(?:update|install)\b", remainder):
            raise ValueError(
                f"{label} live apt operation lacks an intervening snapshot selector"
            )
    if not re.search(
        r'--no-deps\s+--repositories-file\s+/dev/null\s+'
        r'--repository\s+"\$ALPINE_MAIN_REPOSITORY"\s+add\b',
        production,
    ):
        raise ValueError("Alpine package origin or dependency closure is not exclusive")
    apk_lines = [
        line.strip() for line in production.splitlines()
        if line.lstrip().startswith("apk ")
    ]
    if len(apk_lines) != 1:
        raise ValueError("expected exactly one Alpine package install")
    apk_words = shlex.split(apk_lines[0])
    try:
        add_index = apk_words.index("add")
    except ValueError as error:
        raise ValueError("Alpine package install lacks add operation") from error
    apk_packages = tuple(
        word for word in apk_words[add_index + 1:]
        if not word.startswith("-")
    )
    for package in apk_packages:
        if "=" not in package:
            raise ValueError(f"Alpine package is not exact-versioned: {package}")
    if apk_packages != EXPECTED_APK_PACKAGES:
        raise ValueError("Alpine package set differs from the approved closure")
    if re.search(r"\bdocker\s+manifest\b", production):
        raise ValueError("driver path performs a runtime docker manifest operation")
    compact_production = re.sub(r"\s+", " ", production)
    required_driver_uses = (
        'docker pull -q "$DISCOVER_GLIBC_RUN_PLATFORM_IMAGE"',
        'docker pull -q "$DISCOVER_GLIBC_BUILD_PLATFORM_IMAGE"',
        'docker pull -q "$DISCOVER_MUSL_PLATFORM_IMAGE"',
        '"$DISCOVER_GLIBC_BUILD_PLATFORM_IMAGE" sh -ec',
        '"$DISCOVER_GLIBC_RUN_PLATFORM_IMAGE" sh -ec',
        '"$DISCOVER_MUSL_PLATFORM_IMAGE" sh -ec',
    )
    for use in required_driver_uses:
        if compact_production.count(use) != 1:
            raise ValueError(f"missing or duplicated recorded platform use: {use}")


script_source = script_path.read_text()
matrix_source = matrix_path.read_text()
check_container_pins(script_source, matrix_source)


def mutate_production(source, old, new):
    before, production = source.split("\nPY\n", 1)
    if old not in production:
        raise SystemExit(f"self-test mutation target absent: {old}")
    return before + "\nPY\n" + production.replace(old, new, 1)


pin_mutations = (
    (
        "mutable matrix base",
        script_source,
        matrix_source.replace(MATRIX_FROM, "FROM ubuntu:24.04"),
    ),
    (
        "live apt",
        mutate_production(
            script_source,
            'apt-get -S "$UBUNTU_APT_SNAPSHOT" update',
            "apt-get update",
        ),
        matrix_source,
    ),
    (
        "live matrix apt",
        script_source,
        matrix_source.replace(
            'apt-get -S "$UBUNTU_APT_SNAPSHOT" update',
            "apt-get update",
            1,
        ),
    ),
    (
        "unpinned Alpine package",
        mutate_production(script_source, "musl-dev=1.2.5-r12", "musl-dev"),
        matrix_source,
    ),
    (
        "new unpinned Alpine package",
        mutate_production(
            script_source,
            "zstd-libs=1.5.7-r0",
            "zstd-libs=1.5.7-r0 curl",
        ),
        matrix_source,
    ),
    (
        "implicit Alpine dependency resolution",
        mutate_production(script_source, "--no-deps ", ""),
        matrix_source,
    ),
    (
        "added mutable matrix stage",
        script_source,
        matrix_source + "\nFROM ubuntu:24.04\n",
    ),
    (
        "ca-certificates bootstrap widened to a second package",
        mutate_production(
            script_source,
            "apt-get install -qy --no-install-recommends ca-certificates >/dev/null",
            "apt-get install -qy --no-install-recommends ca-certificates curl >/dev/null",
        ),
        matrix_source,
    ),
    (
        "ca-certificates bootstrap removed from the matrix",
        script_source,
        matrix_source.replace(
            "    && apt-get install -y --no-install-recommends ca-certificates \\\n",
            "",
            1,
        ),
    ),
    (
        "wrong linux platform manifest",
        script_source.replace(
            "64eba3726734dcfe89e0a62a0485007a3ab7c7372ce5b38c621d8812f70215f0",
            "4cd7a3f9ccccbdf1825d14a015a30ac19bf8b959ec3d18aa5da8e6a17ce7ec70",
            1,
        ),
        matrix_source,
    ),
)
for label, mutated_script, mutated_matrix in pin_mutations:
    try:
        check_container_pins(mutated_script, mutated_matrix)
    except ValueError as error:
        print(f"container pin mutation rejected: {label}: {error}")
    else:
        raise SystemExit(f"container pin mutation accepted: {label}")
print(f"container pin mutations rejected: OK ({len(pin_mutations)} lanes)")


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
LANE14_PREPARED_ADMITTED=0
bind_prepared_ledger() {
    ledger=$LANE14_PREPARED_PREFIX.$1.ledger.sha256
    ledger_digest=$(sha256sum < "$ledger") || return 1
    [ "$(stat -Lc %d:%i "$LANE14_FACTS" 2>/dev/null)" = "$LANE14_FACTS_ID" ] || return 1
    printf 'prepared_%s_ledger\t%s\t%s\n' "$1" "${ledger##*/}" "${ledger_digest%% *}" >> "$LANE14_FACTS"
}
cleanup() {
    status=$?
    trap - EXIT INT TERM
    for owned_id in "$GLIBC_BUILD_ID" "$GLIBC_RUN_ID" "$MUSL_BUILD_ID"; do
        [ -z "$owned_id" ] || timeout --signal=TERM --kill-after=5s 30s \
            docker rm -f "$owned_id" >/dev/null 2>&1 || status=1
    done
    for owned_id in "$GLIBC_BUILD_ID" "$GLIBC_RUN_ID" "$MUSL_BUILD_ID"; do
        [ -z "$owned_id" ] || if docker inspect "$owned_id" >/dev/null 2>&1; then status=1; fi
    done
    # Final verification follows every owned-container cleanup attempt, even
    # when cleanup failed. Successful verification cannot erase that failure.
    if [ "$LANE14_PREPARED_ADMITTED" -eq 1 ]; then
        if "$LANE14_PYTHON" -I scripts/prepared-dependency-evidence.py recheck \
            --prefix "$LANE14_PREPARED_PREFIX"; then
            recheck_status=0
        else
            recheck_status=$?
            status=1
        fi
    fi
    if [ "$(stat -Lc %d:%i "$LANE14_FACTS" 2>/dev/null)" != "$LANE14_FACTS_ID" ]; then
        status=1
    else
        if [ "$LANE14_PREPARED_ADMITTED" -eq 1 ]; then
            printf 'prepared_recheck_status\t%s\n' "$recheck_status" >> "$LANE14_FACTS" || status=1
            if [ "$recheck_status" -eq 0 ]; then bind_prepared_ledger final || status=1; fi
        fi
        printf 'cleanup_query\tcontainers-absent\nended_utc\t%s\nchild_exit\t%s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$status" >> "$LANE14_FACTS" || status=1
        sync -f "$LANE14_FACTS" 2>/dev/null || status=1
    fi
    exit "$status"
}
. scripts/cleanup-traps.sh

# Resolve only the selected installed tools; preparation and acquisition belong
# outside this sealed caller. The helper retains these identities for recheck.
. scripts/prepared-dependency-tools.sh
LANE14_PYTHON=$(command -v python3) || exit 77
LANE14_RUSTUP=$(command -v rustup) || exit 77
p11scope_prepared_tools_select "$LANE14_PYTHON" "$LANE14_RUSTUP" || exit 77
LANE14_PYTHON=$P11SCOPE_PREPARED_PYTHON
LANE14_RUSTUP=$P11SCOPE_PREPARED_RUSTUP
LANE14_STABLE_CARGO=$P11SCOPE_PREPARED_STABLE_CARGO
LANE14_STABLE_RUSTC=$P11SCOPE_PREPARED_STABLE_RUSTC
LANE14_BPF_CARGO=$P11SCOPE_PREPARED_BPF_CARGO
LANE14_BPF_RUSTC=$P11SCOPE_PREPARED_BPF_RUSTC
# `realpath -e`, not `readlink -f`: build-release runs this lane under a sealed
# PATH whose tool set includes realpath and NOT readlink, so readlink here fails
# with "not found" only in the release driver and never in a standalone run. The
# artifacts directory is already required to exist and not be a symlink above, so
# -e is exact rather than merely equivalent.
LANE14_PREPARED_PREFIX=$(realpath -e "$LANE14_ARTIFACTS") || exit 77
LANE14_PREPARED_PREFIX=$LANE14_PREPARED_PREFIX/discover.prepared
"$LANE14_PYTHON" -I scripts/prepared-dependency-evidence.py capture \
    --prefix "$LANE14_PREPARED_PREFIX" \
    --stable-cargo "$LANE14_STABLE_CARGO" --stable-rustc "$LANE14_STABLE_RUSTC" \
    --bpf-cargo "$LANE14_BPF_CARGO" --bpf-rustc "$LANE14_BPF_RUSTC" || exit 77
LANE14_PREPARED_ADMITTED=1
bind_prepared_ledger initial || exit 77

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

# Keep the index pins above as the recorded supply-chain identities. Pull and
# create use the statically recorded linux/amd64 manifests directly, so the
# driver does not need a live manifest-resolution operation.
timeout --signal=TERM --kill-after=5s 300s docker pull -q \
    "$DISCOVER_GLIBC_RUN_PLATFORM_IMAGE"
timeout --signal=TERM --kill-after=5s 300s docker pull -q \
    "$DISCOVER_GLIBC_BUILD_PLATFORM_IMAGE"
timeout --signal=TERM --kill-after=5s 300s docker pull -q \
    "$DISCOVER_MUSL_PLATFORM_IMAGE"

# Vendored so container builds need no network (sandbox git quirks).
# The vendor config is rewritten with absolute /src paths because it is
# copied into $CARGO_HOME inside the containers.
mkdir -p "$DISCOVER_WORK/vendor"
RUSTC="$LANE14_STABLE_RUSTC" timeout --signal=TERM --kill-after=5s 600s \
    "$LANE14_STABLE_CARGO" vendor --locked --offline --respect-source-config \
    "$DISCOVER_WORK/vendor/src" > "$DISCOVER_WORK/vendor/config.toml"
sed 's|directory = ".*"|directory = "/receipt/vendor/src"|' \
    "$DISCOVER_WORK/vendor/config.toml" > "$DISCOVER_WORK/vendor/config.container.toml"

echo "=== glibc: build in $DISCOVER_GLIBC_BUILD_PLATFORM_IMAGE, run in $DISCOVER_GLIBC_RUN_PLATFORM_IMAGE ==="
GLIBC_BUILD_ID=$(create_owned --name "$GLIBC_BUILD" \
    --platform linux/amd64 -v "$PWD:/src:ro" -v "$DISCOVER_WORK:/receipt" -w /src \
    "$DISCOVER_GLIBC_BUILD_PLATFORM_IMAGE" sh -ec '
  export CARGO_HOME=/tmp/cargo
  mkdir -p /tmp/cargo && cp /receipt/vendor/config.container.toml /tmp/cargo/config.toml
  cargo build --locked --release -p p11scope-discover --offline --target-dir /receipt/glibc-build
  # The build runs as container root, so its tree lands root-owned on the
  # receipt mount. Hand it to the mount owner (the calling user) while still
  # root, or a mode-strict receipt cannot normalize this work root.
  chown -R "$(stat -c %u:%g /receipt)" /receipt/glibc-build')
printf 'container_glibc_build\t%s\n' "$GLIBC_BUILD_ID" >> "$LANE14_FACTS"
timeout --signal=TERM --kill-after=5s 600s docker start -a "$GLIBC_BUILD_ID"
GLIBC_RUN_ID=$(create_owned --name "$GLIBC_RUN" \
    --platform linux/amd64 -e UBUNTU_APT_SNAPSHOT="$UBUNTU_APT_SNAPSHOT" \
    -v "$PWD:/src:ro" \
    -v "$DISCOVER_WORK/glibc-build/release/p11scope-discover:/usr/local/bin/p11scope-discover:ro" \
    "$DISCOVER_GLIBC_RUN_PLATFORM_IMAGE" sh -ec '
  apt-get update -q >/dev/null
  apt-get install -qy --no-install-recommends ca-certificates >/dev/null
  apt-get -S "$UBUNTU_APT_SNAPSHOT" update -q >/dev/null
  apt-get -S "$UBUNTU_APT_SNAPSHOT" install -qy gcc jq softhsm2 util-linux >/dev/null
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

echo "=== musl-dynamic: build + run in $DISCOVER_MUSL_PLATFORM_IMAGE ==="
MUSL_BUILD_ID=$(create_owned --name "$MUSL_BUILD" \
    --platform linux/amd64 -e ALPINE_MAIN_REPOSITORY="$ALPINE_MAIN_REPOSITORY" \
    -v "$PWD:/src:ro" -v "$DISCOVER_WORK:/receipt" -w /src \
    "$DISCOVER_MUSL_PLATFORM_IMAGE" sh -ec '
  apk --no-cache --no-deps --repositories-file /dev/null \
      --repository "$ALPINE_MAIN_REPOSITORY" add -q \
      binutils=2.44-r3 file=5.46-r2 gcc=14.2.0-r6 \
      gmp=6.3.0-r3 isl26=0.26-r1 jansson=2.14.1-r0 \
      jq=1.8.2-r0 libatomic=14.2.0-r6 libcap-ng=0.8.5-r0 \
      libcrypto3=3.5.8-r0 libgcc=14.2.0-r6 libgomp=14.2.0-r6 \
      libmagic=5.46-r2 libncursesw=6.5_p20250503-r0 libstdc++=14.2.0-r6 \
      mpc1=1.3.1-r1 mpfr4=4.2.1_p1-r0 musl=1.2.5-r12 \
      musl-dev=1.2.5-r12 ncurses-terminfo-base=6.5_p20250503-r0 oniguruma=6.9.10-r0 \
      readline=8.2.13-r1 setpriv=2.41.6-r1 softhsm=2.6.1-r6 \
      sqlite=3.49.2-r1 sqlite-libs=3.49.2-r1 zlib=1.3.2-r0 \
      zstd-libs=1.5.7-r0
  export CARGO_HOME=/tmp/cargo
  mkdir -p /tmp/cargo && cp /receipt/vendor/config.container.toml /tmp/cargo/config.toml
  export RUSTFLAGS="-C target-feature=-crt-static"
  cargo build --locked --release -p p11scope-discover --offline --target-dir /receipt/musl-build
  # Same root-ownership handover as the glibc build above.
  chown -R "$(stat -c %u:%g /receipt)" /receipt/musl-build
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
