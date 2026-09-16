#!/bin/sh
set -eu

repository=$1
evidence_root=$2
P11SCOPE_PREPARED_PYTHON=$3
P11SCOPE_PREPARED_STABLE_CARGO=$4
P11SCOPE_PREPARED_STABLE_RUSTC=$5
P11SCOPE_PREPARED_BPF_CARGO=$6
P11SCOPE_PREPARED_BPF_RUSTC=$7

cd "$repository"
ABI_ROUTING_DRIVER_LIBRARY_ONLY=1 . scripts/matrix/verify-abi-routing.sh
abi_prepare_evidence_root "$evidence_root"
EVIDENCE=$ABI_EVIDENCE_PIN
WORK=$EVIDENCE/work
mkdir -m 700 "$WORK"
ABI_PREPARED_PREFIX=$ABI_EVIDENCE/abi.prepared
"$P11SCOPE_PREPARED_PYTHON" -I scripts/prepared-dependency-evidence.py \
    capture --prefix "$ABI_PREPARED_PREFIX" \
    --stable-cargo "$P11SCOPE_PREPARED_STABLE_CARGO" \
    --stable-rustc "$P11SCOPE_PREPARED_STABLE_RUSTC" \
    --bpf-cargo "$P11SCOPE_PREPARED_BPF_CARGO" \
    --bpf-rustc "$P11SCOPE_PREPARED_BPF_RUSTC"
ABI_SOURCE_INPUTS=$WORK/source-inputs.list
abi_write_source_inventory
abi_write_merged_source_snapshot initial
ABI_PREPARED_ADMITTED=1
finalize_root_recorded_process() { return 1; }
abi_driver_cleanup
