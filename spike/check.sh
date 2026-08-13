#!/bin/sh
# check.sh <expected.txt> <bpftrace-output> — assert exact call counts.
if [ "$#" -ne 2 ]; then
    echo "usage: $0 <expected.txt> <bpftrace-output>" >&2
    exit 2
fi
fail=0
while read -r name count; do
    if ! grep -q "@call\[$name\]: $count\$" "$2"; then
        echo "MISMATCH $name: want $count, got: $(grep "@call\[$name\]" "$2" || echo none)"
        fail=1
    fi
done < "$1"
[ "$fail" = 0 ] && echo "ALL COUNTS MATCH"
exit "$fail"
