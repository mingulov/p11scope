#!/bin/sh -eu
# Regression pin for aya's uprobe offset semantics (Gate G0 carry-over).
cd "$(dirname "$0")"
mkdir -p work
gcc -no-pie -O0 -o work/target target.c

VADDR=$(readelf -sW work/target | awk '$8=="probe_me" {print $2; exit}')
set -- $(readelf -SW work/target | sed 's/\[ *[0-9]*\]//' | awk '$1==".text" {print $3, $4}')
TEXT_ADDR=$1 TEXT_OFF=$2
FILE_OFF=$(printf '%x' $((0x$VADDR - 0x$TEXT_ADDR + 0x$TEXT_OFF)))
echo "probe_me: vaddr=0x$VADDR file_offset=0x$FILE_OFF (.text addr=0x$TEXT_ADDR off=0x$TEXT_OFF)"
# Numeric compare — readelf pads vaddr with leading zeros, printf does not.
[ $((0x$VADDR)) -ne $((0x$FILE_OFF)) ] || { echo "control invalid: vaddr == file offset"; exit 1; }

cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core \
    --manifest-path pin-ebpf/Cargo.toml
cargo build --release

EBPF=pin-ebpf/target/bpfel-unknown-none/release/pin-ebpf
sudo ./target/release/aya-offset-pin "$EBPF" "$PWD/work/target" "0x$FILE_OFF" 7
echo "PASS: file-offset attach observed exactly 7 calls"

if sudo ./target/release/aya-offset-pin "$EBPF" "$PWD/work/target" "0x$VADDR" 7; then
    echo "FAIL: vaddr interpretation also observed the calls — semantics ambiguous"
    exit 1
fi
echo "PASS: vaddr interpretation does not observe the calls"
