#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

if [ "$#" -ne 8 ]; then
    echo "usage: oracle-workload.sh PIDFILE FIFO CWD CONF CLIENT MODULE OUTPUT RELEASE_TIMEOUT_SECONDS" >&2
    exit 2
fi

pidfile=$1
fifo=$2
client_cwd=$3
softhsm_conf=$4
client=$5
module=$6
output=$7
release_timeout=$8

for path in "$pidfile" "$fifo" "$client_cwd" "$softhsm_conf" "$client" "$module" "$output"; do
    case $path in
        /*) ;;
        *) echo "oracle workload paths must be absolute" >&2; exit 2 ;;
    esac
done
case $release_timeout in
    ''|*[!0-9]*) echo "invalid FIFO release timeout" >&2; exit 2 ;;
esac
[ "$release_timeout" -gt 0 ] && [ "$release_timeout" -le 600 ] || {
    echo "invalid FIFO release timeout" >&2
    exit 2
}

umask 077
starttime=$(awk '{ sub(/^[0-9]+ \(.*\) /, ""); split($0, tail, " "); print tail[20]; exit }' "/proc/$$/stat")
case $starttime in
    ''|*[!0-9]*) echo "could not read workload process generation" >&2; exit 1 ;;
esac
set -C
printf '%s %s\n' "$$" "$starttime" > "$pidfile" || {
    echo "workload identity already exists" >&2
    exit 1
}
set +C
chmod 600 "$pidfile"
sync -f "$pidfile"

timeout --signal=TERM --kill-after=2s "${release_timeout}s" \
    dd if="$fifo" of=/dev/null bs=1 count=1 status=none || {
        echo "FIFO release failed" >&2
        exit 1
    }

cd "$client_cwd"
export SOFTHSM2_CONF=$softhsm_conf
exec "$client" test --module "$module" --pin 1234 --slot 0 --marker smoke \
    --isolation file --rv-trace --output json --output-file "$output"
