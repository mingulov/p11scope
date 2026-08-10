#!/bin/sh
# gen-bt.sh <manifest> [path-prefix]  — emit a bpftrace program on stdout.
# Uses column $4. For SoftHSM2 the file-offset ($3) and vaddr ($4) columns are
# numerically EQUAL (its executable LOAD segment has p_offset == p_vaddr), so
# the spike cannot tell which one bpftrace's `uprobe:binary:NUMBER` form wants —
# both attach. That is a known limitation of this spike, not a resolved fact
# (see the fallback note). path-prefix is for /proc/<pid>/root.
awk -v prefix="${2:-}" '$2 != "UNRESOLVED" {
    path = prefix $2
    printf "uprobe:%s:%s { @call[\"%s\"] = count(); }\n",    path, $4, $1
    printf "uretprobe:%s:%s { @rv[\"%s\", retval] = count(); }\n", path, $4, $1
}' "$1"
