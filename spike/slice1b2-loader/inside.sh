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

status=BLOCKED
step=init
trap 'rc=$?; printf "INNER_FINAL_STATUS=%s rc=%s step=%s\\n" "$status" "$rc" "$step"' EXIT

echo "INNER_BEGIN family=$family image_ref=$image_ref lane=$lane"
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
echo "ENVIRONMENT_BOUNDARY=recorded-effective-container-state; SYS_PTRACE/seccomp-unconfined-are-command-line-relaxations-not-minimum-authority-claim"
echo "STEP_OK=$step"

step=copy_sources
mkdir -p /work
cp /evidence/round2/fixture.c /evidence/round2/dso.c /evidence/round2/elf_meta.py \
    /evidence/round2/gdb-direct-witness.py /evidence/round2/rdebug-layout.c /work/
cd /work
sha256sum fixture.c dso.c elf_meta.py gdb-direct-witness.py rdebug-layout.c
echo "STEP_OK=$step"

step=compile
gcc -shared -fPIC -g -Wl,--build-id -o libfixture.so dso.c
gcc -g -Wl,--build-id -o fixture fixture.c -ldl
if [ "$family" = glibc ]; then
    gcc -g -Wl,--build-id -o rdebug-layout rdebug-layout.c
    ./rdebug-layout
fi
file fixture libfixture.so
sha256sum fixture libfixture.so
readelf -nW fixture libfixture.so
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
artifact_dir="/evidence/round2/artifacts/$lane"
mkdir -p "$artifact_dir"
cp fixture libfixture.so direct-meta.json "$artifact_dir/"
sha256sum "$artifact_dir/fixture" "$artifact_dir/libfixture.so" "$artifact_dir/direct-meta.json"
echo "STEP_OK=$step"

step=runtime_gdb
set +e
SPIKE_FAMILY="$family" SPIKE_META=/work/direct-meta.json \
    gdb -q --batch -x gdb-direct-witness.py --args ./fixture > gdb-direct.log 2>&1
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
