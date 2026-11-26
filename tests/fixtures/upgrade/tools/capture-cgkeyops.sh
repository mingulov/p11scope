#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Fixture capture helper: cgroup --key-operations capture with a gated
# steady-keys anchor.
# usage: capture-cgkeyops.sh <observer-bin> <tag> <outdir>
set -eu
BIN=$1; TAG=$2; OUT=$3
TMPDIR=${TMPDIR:-/var/tmp/p11scope-ws-tmp/v072-compat-071}
case $0 in */*) TOOLS_DIR=${0%/*};; *) TOOLS_DIR=.;; esac
# shellcheck source=capture-env.sh
. "$TOOLS_DIR/capture-env.sh"
PROV=$(probe_provider) || exit 2
export SOFTHSM2_CONF=$TMPDIR/f2/work/softhsm2.conf
export STEADY_GO=$OUT/$TAG.cggo
ME=$(id -un)
CG=/sys/fs/cgroup/p11compat071
LOCK="flock /var/tmp/p11scope-ws-tmp/privileged.lock"

$LOCK sudo -n sh -c "mkdir -p $CG"
rm -f $OUT/$TAG.anchor.ready $OUT/$TAG.go $STEADY_GO
mkfifo $OUT/$TAG.go

cat > $OUT/$TAG.workload.sh <<EOF
#!/bin/sh
set -eu
read _ < $OUT/$TAG.go
export SOFTHSM2_CONF=$SOFTHSM2_CONF
export STEADY_GO=$STEADY_GO
rm -f $OUT/$TAG.anchor.ready
$TMPDIR/f2/bin/steady-keys $PROV 1234 75 ${HEXID:-e200} >$OUT/$TAG.anchor.log 2>&1 &
APID=\$!
for i in \$(seq 1 200); do
  grep -q "mapped pid=" $OUT/$TAG.anchor.log 2>/dev/null && break
  sleep 0.1
done
grep -q "mapped pid=" $OUT/$TAG.anchor.log || { echo "anchor never mapped"; kill \$APID; exit 3; }
echo "anchor pid=\$APID"
wait \$APID
echo workload-done
EOF
chmod +x $OUT/$TAG.workload.sh
sh $OUT/$TAG.workload.sh >$OUT/$TAG.workload.log 2>&1 &
WPID=$!
$LOCK sudo -n sh -c "echo $WPID > $CG/cgroup.procs"
echo go > $OUT/$TAG.go
for i in $(seq 1 200); do
  grep -q "mapped pid=" $OUT/$TAG.anchor.log 2>/dev/null && break
  sleep 0.1
done
grep -q "mapped pid=" $OUT/$TAG.anchor.log || { echo "anchor never mapped"; kill $WPID; exit 3; }
sleep 1
echo "== $TAG cgkeyops (root, 65s)"
$LOCK sudo -n --preserve-env=TMPDIR $BIN inventory --cgroup $CG --module $PROV \
  --capture native --key-operations --manifest $OUT/v071-manifest-softhsm.json \
  --duration 65s -o $OUT/$TAG-inventory-cgkeyops.json 2>$OUT/$TAG.cgkeyops.stderr &
OPID=$!
for i in $(seq 1 600); do
  grep -q "semantic lane ready" $OUT/$TAG.cgkeyops.stderr 2>/dev/null && break
  sleep 0.2
done
grep -q "semantic lane ready" $OUT/$TAG.cgkeyops.stderr || echo "WARNING: semantic lane never ready"
touch $STEADY_GO
wait $OPID
echo "rc=$?"
$LOCK sudo -n chown $ME:$ME $OUT/$TAG-inventory-cgkeyops.json
wait $WPID
rm -f $OUT/$TAG.go
$LOCK sudo -n rmdir $CG
ls -la $OUT/$TAG-inventory-cgkeyops.json
