#!/bin/sh
family=$1
image_ref=$2
lane=$3
if [ "${SPIKE_BASH:-}" != 1 ]; then
    if [ "$family" = musl ]; then
        apk add --no-cache bash
    fi
    exec env SPIKE_BASH=1 bash "$0" "$@"
fi
set -euo pipefail

kind=${SPIKE_LOAD_KIND:-dlopen}
status=BLOCKED
step=init
trap 'rc=$?; printf "INNER_FINAL_STATUS=%s rc=%s step=%s kind=%s\\n" "$status" "$rc" "$step" "$kind"' EXIT

echo "INNER_BEGIN family=$family image_ref=$image_ref lane=$lane kind=$kind"
step=install_tools
if [ "$family" = musl ]; then
    apk add --no-cache build-base gdb binutils file python3
else
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends gcc libc6-dev gdb binutils file python3
fi
echo "STEP_OK=$step"

step=environment
id
grep '^CapEff:' /proc/self/status
if [ -r /proc/sys/kernel/yama/ptrace_scope ]; then echo "YAMA_PTRACE_SCOPE=$(cat /proc/sys/kernel/yama/ptrace_scope)"; else echo 'YAMA_PTRACE_SCOPE=unavailable'; fi
if [ -r /proc/self/attr/current ]; then echo "LSM_CURRENT=$(cat /proc/self/attr/current)"; else echo 'LSM_CURRENT=unavailable'; fi
if [ "$family" = glibc ]; then
    dpkg-query -W -f 'LIBC6_VERSION=${Version}\n' libc6
    echo "GNU_LIBC_VERSION=$(getconf GNU_LIBC_VERSION)"
fi
echo "ENVIRONMENT_BOUNDARY=recorded-effective-container-state; SYS_PTRACE/seccomp-unconfined-are-command-line-relaxations-not-minimum-authority-claim"
echo "STEP_OK=$step"

if [ "$family" = glibc ]; then
    step=source_provenance
    # Enable deb-src for both deb822 (.sources) and classic (.list) layouts.
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/*.sources 2>/dev/null || true
    if [ -f /etc/apt/sources.list ] && grep -q '^deb ' /etc/apt/sources.list; then
        grep '^deb ' /etc/apt/sources.list | sed 's/^deb /deb-src /' >> /etc/apt/sources.list
    fi
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends dpkg-dev
    mkdir -p /work
    cd /work
    if apt-get source -qq glibc >provenance-aptsource.log 2>&1; then
        echo "PROVENANCE_APT_SOURCE=ok"
        dsc=$(ls -1 /work/glibc_*.dsc 2>/dev/null | head -1)
        echo "PROVENANCE_DSC=$(basename "$dsc")"
        sha256sum "$dsc"
        grep -E '^(Package|Version): ' "$dsc" || true
        dl_open=$(find /work -maxdepth 2 -path '*/elf/dl-open.c' | head -1)
        echo "PROVENANCE_DL_OPEN_PATH=$dl_open"
        sha256sum "$dl_open"
        echo "PROVENANCE_DL_OPEN_BEGIN"
        grep -n -B12 -A6 -E '_dl_debug_state|dl_open_worker' "$dl_open" || true
        echo "PROVENANCE_DL_OPEN_END"
        echo "PROVENANCE_DEBIAN_PATCHES_TOUCHING_DL_OPEN_BEGIN"
        hits=$(grep -l 'dl-open\.c' /work/glibc-*/debian/patches/* 2>/dev/null || true)
        if [ -n "$hits" ]; then
            echo "$hits"
            for p in $hits; do echo "--- $p"; grep -n 'dl-open' "$p" | head -5 || true; done
        else
            echo NONE
        fi
        echo "PROVENANCE_DEBIAN_PATCHES_TOUCHING_DL_OPEN_END"
    else
        echo "PROVENANCE_SOURCE_UNAVAILABLE"
        cat provenance-aptsource.log || true
        case "$lane" in
            glibc-241-debian13|glibc-24x-ubuntu2604) exit 4 ;;
        esac
    fi
    cd /
    echo "STEP_OK=$step"
fi

step=copy_sources
mkdir -p /work
cp /evidence/round3/fixture.c /evidence/round3/fixture-needed.c /evidence/round3/dso.c /evidence/round3/elf_meta.py \
    /evidence/round3/gdb-direct-witness.py /evidence/round3/rdebug-layout.c /work/
cd /work
sha256sum fixture.c fixture-needed.c dso.c elf_meta.py gdb-direct-witness.py rdebug-layout.c
echo "STEP_OK=$step"

step=compile
gcc -shared -fPIC -g -Wl,--build-id -o libfixture.so dso.c
gcc -g -Wl,--build-id -o fixture fixture.c -ldl
gcc -g -Wl,--build-id -o fixture-needed fixture-needed.c -L. -lfixture -Wl,-rpath,'$ORIGIN'
if [ "$family" = glibc ]; then
    gcc -g -Wl,--build-id -o rdebug-layout rdebug-layout.c
    ./rdebug-layout
fi
file fixture fixture-needed libfixture.so
sha256sum fixture fixture-needed libfixture.so
readelf -nW fixture fixture-needed libfixture.so
echo "DT_NEEDED_FIXTURE_NEEDED_BEGIN"; readelf -dW fixture-needed | grep -E 'NEEDED|RPATH|RUNPATH' || true; echo "DT_NEEDED_FIXTURE_NEEDED_END"
echo "STEP_OK=$step"

step=loader_and_object_identity
interpreter=$(readelf -lW fixture | awk '/Requesting program interpreter/ && !found {gsub(/\[/,"",$NF); gsub(/\]/,"",$NF); print $NF; found=1} END {if (!found) exit 1}')
if [ "$family" = musl ]; then
    libc=$interpreter
else
    libc=$(ldd ./fixture | awk '/libc.so.6/ && !found {print $3; found=1} END {if (!found) exit 1}')
fi
loader=$(readlink -f "$interpreter")
libc=$(readlink -f "$libc")
dso=$(readlink -f ./libfixture.so)
echo "INTERPRETER=$interpreter"
echo "LOADER=$loader"
echo "LIBC=$libc"
echo "DSO=$dso"
echo "LOADER_VERSION_BEGIN"; "$loader" --version 2>&1 || [ "$family" = musl ]; echo "LOADER_VERSION_END"
echo "LIBC_VERSION_BEGIN"; "$libc" 2>&1 || [ "$family" = musl ]; echo "LIBC_VERSION_END"
for f in "$dso" "$libc" "$loader"; do
    echo "OBJECT_IDENTITY path=$f"
    stat -Lc 'dev=%d inode=%i size=%s' "$f"
    sha256sum "$f"
    readelf -nW "$f" | awk '/Build ID:/ {print}'
done
echo "STEP_OK=$step"

step=elf_and_direct_metadata
for f in "$dso" "$libc" "$loader"; do
    echo "PT_LOAD_BEGIN path=$f"
    readelf -lW "$f" | awk '$1 == "LOAD" {print}'
    echo "PT_LOAD_END path=$f"
done
echo "DYNSYM_DSO_BEGIN"; readelf --dyn-syms -W "$dso" | awk '$NF == "fixture_relocated_puts" {print}'; echo "DYNSYM_DSO_END"
echo "DYNSYM_LIBC_PUTS_BEGIN"; readelf --dyn-syms -W "$libc" | awk '$NF ~ /^puts(@|$)/ {print}'; echo "DYNSYM_LIBC_PUTS_END"
echo "DYNSYM_LOADER_BEGIN"; readelf --dyn-syms -W "$loader" | awk '$NF ~ /^_dl_debug_state(@|$)|^_r_debug(@|$)|^dlopen(@|$)/ {print}'; echo "DYNSYM_LOADER_END"
echo "RELOCATIONS_DSO_BEGIN"; readelf -rW "$dso"; echo "RELOCATIONS_DSO_END"
if [ "$family" = glibc ]; then
    python3 ./elf_meta.py direct-meta.json dso "$dso" fixture_relocated_puts libc "$libc" puts loader "$loader" _r_debug
else
    python3 ./elf_meta.py direct-meta.json dso "$dso" fixture_relocated_puts libc "$libc" puts
fi
echo "DIRECT_META_BEGIN"; cat direct-meta.json; echo "DIRECT_META_END"
echo "STEP_OK=$step"

step=retain_artifacts
artifact_dir="/evidence/round3/artifacts/${lane}-${kind}"
mkdir -p "$artifact_dir"
cp fixture fixture-needed libfixture.so direct-meta.json "$artifact_dir/"
sha256sum "$artifact_dir/fixture" "$artifact_dir/fixture-needed" "$artifact_dir/libfixture.so" "$artifact_dir/direct-meta.json"
echo "STEP_OK=$step"

step=runtime_gdb
if [ "$kind" = initial_set ]; then
    target=./fixture-needed
else
    target=./fixture
fi
set +e
SPIKE_FAMILY="$family" SPIKE_META=/work/direct-meta.json \
    gdb -q --batch -x gdb-direct-witness.py --args "$target" > gdb-direct.log 2>&1
gdb_rc=$?
set -e
cat gdb-direct.log
if [ "$gdb_rc" -ne 0 ]; then
    status=BLOCKED
    echo "GDB_EXECUTION_ERROR=$gdb_rc"
    exit 2
fi
classification=$(awk -F'[ =]' '/^GDB_FINAL_CLASSIFICATION=/ {print $2; found=1} END {if (!found) exit 1}' gdb-direct.log)
echo "RUNTIME_CLASSIFICATION=$classification"
case "$classification" in
    PASS) status=PASS; step=complete; exit 0 ;;
    FAIL) status=FAIL; exit 3 ;;
    BLOCKED) status=BLOCKED; exit 2 ;;
    *) status=BLOCKED; echo "UNKNOWN_CLASSIFICATION=$classification"; exit 2 ;;
esac
