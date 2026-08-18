#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
root=$(cd "$(dirname "$0")" && pwd)
evidence=${P11SCOPE_LOADER_EVIDENCE:-$HOME/src/m/pkcs11-scope-evidence/slice1b2/loader}
kind=${SPIKE_LOAD_KIND:-dlopen}
install -d -m 0700 "$evidence/round3/artifacts"
cp "$root"/{dso.c,fixture.c,fixture-needed.c,rdebug-layout.c,elf_meta.py,gdb-direct-witness.py,inside.sh} "$evidence/round3/"
filter=${1:-}   # empty = all lanes; otherwise a lane-name substring

run_lane() {
    local lane=$1 family=$2 image_ref=$3 name=$4
    [[ -z $filter || $lane == *$filter* ]] || return 0
    local transcript="$evidence/${lane}-${kind}-transcript.log"
    {
        printf 'ROUND3_LANE=%s SPIKE_LOAD_KIND=%s\n' "$lane" "$kind"
        printf 'OUTER_DOCKER_COMMAND='
        printf '%q ' docker run --rm --name "$name" --cap-add=SYS_PTRACE --security-opt=seccomp=unconfined \
            -e SPIKE_LOAD_KIND="$kind" \
            -v "$evidence":/evidence "$image_ref" /bin/sh \
            /evidence/round3/inside.sh "$family" "$image_ref" "$lane"
        printf '\nOUTER_ADDITIONAL_CAPABILITY=SYS_PTRACE\nOUTER_ADDITIONAL_SECCOMP_RELAXATION=unconfined\n'
        printf 'OUTER_IMAGE_INSPECT='; docker image inspect "$image_ref" --format '{{index .RepoDigests 0}} {{.Id}}'
        printf 'GIT_HEAD_BEFORE='; git -C "$repo" rev-parse HEAD
        printf 'GIT_STATUS_BEFORE_BEGIN\n'; git -C "$repo" status --short; printf 'GIT_STATUS_BEFORE_END\n'
        printf 'HOST_SOURCE_HASHES_BEGIN\n'; sha256sum "$root"/fixture.c "$root"/fixture-needed.c "$root"/dso.c "$root"/elf_meta.py \
            "$root"/gdb-direct-witness.py "$root"/rdebug-layout.c "$root"/inside.sh "$root"/run-lanes.sh; printf 'HOST_SOURCE_HASHES_END\n'
        set +e
        docker run --rm --name "$name" --cap-add=SYS_PTRACE --security-opt=seccomp=unconfined \
            -e SPIKE_LOAD_KIND="$kind" \
            -v "$evidence":/evidence "$image_ref" /bin/sh \
            /evidence/round3/inside.sh "$family" "$image_ref" "$lane"
        local rc=$?
        set -e
        printf 'OUTER_DOCKER_EXIT=%s\n' "$rc"
        printf 'DOCKER_PS_NAMED_AFTER_BEGIN\n'; docker ps -a --filter "name=$name" --format '{{.Names}} {{.Status}}'; printf 'DOCKER_PS_NAMED_AFTER_END\n'
        printf 'GIT_HEAD_AFTER='; git -C "$repo" rev-parse HEAD
        printf 'GIT_STATUS_AFTER_BEGIN\n'; git -C "$repo" status --short; printf 'GIT_STATUS_AFTER_END\n'
        case "$rc" in
            0) printf 'LANE_FINAL_STATUS=PASS\n' ;;
            3) printf 'LANE_FINAL_STATUS=FAIL\n' ;;
            *) printf 'LANE_FINAL_STATUS=BLOCKED\n' ;;
        esac
        return "$rc"
    } >"$transcript" 2>&1
}

overall=0
if ! run_lane musl-alpine3241 musl \
    alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b \
    p11scope-slice1b2-r2-musl3241; then overall=1; fi
if ! run_lane glibc-235-ubuntu2204 glibc \
    ubuntu@sha256:3b06811b2afd352be909dd088a004166d665dc76d38b13eada33522a9d915c6f \
    p11scope-slice1b2-r2-glibc235; then overall=1; fi
if ! run_lane glibc-239-ubuntu2404 glibc \
    ubuntu@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea \
    p11scope-slice1b2-r2-glibc239; then overall=1; fi
if ! run_lane glibc-241-debian13 glibc \
    debian@sha256:34cd9e9fd437c0a095ec39cb2e73422c9f30821b0d0848ed74fd0d43bae4d958 \
    p11scope-slice1b2-r3-glibc241; then overall=1; fi
if ! run_lane glibc-24x-ubuntu2604 glibc \
    ubuntu@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03 \
    p11scope-slice1b2-r3-glibc24x; then overall=1; fi

{
    printf 'AGGREGATE_DOCKER_PS_BEGIN\n'
    docker ps -a --filter 'name=p11scope-slice1b2' --format '{{.Names}} {{.Status}}'
    printf 'AGGREGATE_DOCKER_PS_END\n'
    printf 'AGGREGATE_GIT_HEAD='; git -C "$repo" rev-parse HEAD
    printf 'AGGREGATE_GIT_STATUS_BEGIN\n'; git -C "$repo" status --short; printf 'AGGREGATE_GIT_STATUS_END\n'
    printf 'AGGREGATE_DRIVER_STATUS=%s\n' "$overall"
} >"$evidence/aggregate-cleanup.log" 2>&1

exit "$overall"
