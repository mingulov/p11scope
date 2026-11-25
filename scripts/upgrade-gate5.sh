#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Gate 5: package upgrade from v0.7.1 to this tree.
#
# Installs the official v0.7.1 DEB or RPM, runs doctor plus one short
# capture, upgrades to packages built from this tree, runs doctor plus
# one short capture again, and proves old config/state survived.
#
# The observer keeps no /etc config or /var/lib state (docs/install.md):
# "old config and state" here means the operator's own files the upgrade
# must never touch: a canary in the per-user recovery dir
# (/var/tmp/p11scope-recovered-<euid>/) and a saved -o report plus its
# --event-log. The cell hashes them before the upgrade and requires
# byte-identical bytes after.
#
# Usage (as root):
#   scripts/upgrade-gate5.sh --format deb \
#     --old /path/p11scope_0.7.1_amd64.deb \
#     --new /path/p11scope_0.7.2_amd64.deb \
#     --workdir /tmp/gate5-deb
#   scripts/upgrade-gate5.sh --format rpm \
#     --old /path/p11scope-0.7.1-1.x86_64.rpm \
#     --new /path/p11scope-0.7.2-1.x86_64.rpm \
#     --workdir /tmp/gate5-rpm
#
# Exit 0 on pass, 1 on fail. Writes typed JSON to $WORKDIR/gate5-result.json
# and the same to stdout.
set -u
FORMAT=""; OLD=""; NEW=""; WORKDIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --format) FORMAT="$2"; shift 2;;
    --old) OLD="$2"; shift 2;;
    --new) NEW="$2"; shift 2;;
    --workdir) WORKDIR="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ "$FORMAT" = deb ] || [ "$FORMAT" = rpm ] || { echo "--format deb|rpm required" >&2; exit 2; }
[ -n "$OLD" ] && [ -n "$NEW" ] && [ -n "$WORKDIR" ] || { echo "--old/--new/--workdir required" >&2; exit 2; }
[ -f "$OLD" ] || { echo "old package missing: $OLD" >&2; exit 2; }
[ -f "$NEW" ] || { echo "new package missing: $NEW" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "must run as root (installs system packages)" >&2; exit 2; }
mkdir -p "$WORKDIR"
RESULT="$WORKDIR/gate5-result.json"

# Typed result fields; filled as the cell runs.
OLD_VERSION=""; NEW_VERSION=""
DOCTOR_OLD_RC=-1; DOCTOR_NEW_RC=-1
CAPTURE_OLD_RC=-1; CAPTURE_NEW_RC=-1
CANARY_RECOVERY_SHA_BEFORE=""; CANARY_RECOVERY_SHA_AFTER=""
CANARY_REPORT_SHA_BEFORE=""; CANARY_REPORT_SHA_AFTER=""
FAIL_REASON=""

fail() {
  FAIL_REASON="$1"
  emit_result "fail"
  echo "GATE5 FAIL: $1" >&2
  exit 1
}

emit_result() {
  status="$1"
  python3 - "$RESULT" "$status" <<PY
import json, sys
result = {
  "gate": 5,
  "format": "$FORMAT",
  "status": sys.argv[2],
  "old_package": "$OLD",
  "new_package": "$NEW",
  "old_version": "$OLD_VERSION",
  "new_version": "$NEW_VERSION",
  "doctor_old_rc": $DOCTOR_OLD_RC,
  "doctor_new_rc": $DOCTOR_NEW_RC,
  "capture_old_rc": $CAPTURE_OLD_RC,
  "capture_new_rc": $CAPTURE_NEW_RC,
  "canary_recovery_sha_before": "$CANARY_RECOVERY_SHA_BEFORE",
  "canary_recovery_sha_after": "$CANARY_RECOVERY_SHA_AFTER",
  "canary_report_sha_before": "$CANARY_REPORT_SHA_BEFORE",
  "canary_report_sha_after": "$CANARY_REPORT_SHA_AFTER",
  "canary_survived": "$CANARY_RECOVERY_SHA_BEFORE" != "" and "$CANARY_RECOVERY_SHA_BEFORE" == "$CANARY_RECOVERY_SHA_AFTER" and "$CANARY_REPORT_SHA_BEFORE" == "$CANARY_REPORT_SHA_AFTER",
  "fail_reason": "$FAIL_REASON",
}
open(sys.argv[1], "w").write(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps(result, indent=2, sort_keys=True))
PY
}

# Canary state: recovery dir + saved report. Created before the old install
# so even the old install must preserve them; hashed before upgrade.
EUID_VAL="$(id -u)"
RECOVERY_DIR="/var/tmp/p11scope-recovered-$EUID_VAL"
mkdir -p "$RECOVERY_DIR"
chmod 700 "$RECOVERY_DIR"
CANARY_RECOVERY="$RECOVERY_DIR/gate5-canary-$FORMAT"
printf 'gate5-canary %s old-state must survive\n' "$FORMAT" > "$CANARY_RECOVERY"
chmod 600 "$CANARY_RECOVERY"
CANARY_REPORT="$WORKDIR/operator-report-$FORMAT.json"
printf '{"gate":5,"format":"%s","operator":"saved report must survive"}\n' "$FORMAT" > "$CANARY_REPORT"

install_old() {
  if [ "$FORMAT" = deb ]; then
    dpkg -i "$OLD" > "$WORKDIR/install-old.log" 2>&1 || return $?
  else
    rpm -i --force "$OLD" > "$WORKDIR/install-old.log" 2>&1 || return $?
  fi
}

upgrade_new() {
  if [ "$FORMAT" = deb ]; then
    dpkg -i "$NEW" > "$WORKDIR/install-new.log" 2>&1 || return $?
  else
    rpm -U "$NEW" > "$WORKDIR/install-new.log" 2>&1 || return $?
  fi
}

# 1. Install old.
install_old || fail "old install failed (see install-old.log)"
# 2. Old version must be 0.7.1.
OLD_VERSION="$(p11scope --version 2>/dev/null | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"
[ "$OLD_VERSION" = "0.7.1" ] || fail "old version is '$OLD_VERSION', expected 0.7.1"
# 3. Old doctor (no scope: must exit 0 even when capture unavailable).
set +e
p11scope doctor > "$WORKDIR/doctor-old.out" 2>&1
DOCTOR_OLD_RC=$?
set -e
[ "$DOCTOR_OLD_RC" = 0 ] || fail "old doctor rc=$DOCTOR_OLD_RC"
grep -q '^Doctor:' "$WORKDIR/doctor-old.out" || fail "old doctor output has no Doctor line"
# 4. Old short capture: scan-only PID inventory, no privileges needed.
set +e
p11scope inventory --pid 1 --capture scan --json -o "$WORKDIR/pre-upgrade.json" > "$WORKDIR/capture-old.out" 2>&1
CAPTURE_OLD_RC=$?
set -e
[ "$CAPTURE_OLD_RC" = 0 ] || fail "old capture rc=$CAPTURE_OLD_RC"
python3 -c "import json; d=json.load(open('$WORKDIR/pre-upgrade.json')); assert d.get('schema')=='p11scope/inventory/v1', d.get('schema')" \
  || fail "old capture report has wrong schema"
# Hash canaries before upgrade.
CANARY_RECOVERY_SHA_BEFORE="$(sha256sum "$CANARY_RECOVERY" | cut -d' ' -f1)"
CANARY_REPORT_SHA_BEFORE="$(sha256sum "$CANARY_REPORT" | cut -d' ' -f1)"
# 5. Upgrade to new.
upgrade_new || fail "upgrade to new failed (see install-new.log)"
# 6. New version must match the tree (Cargo.toml).
EXPECTED_NEW="$(python3 -c "import re; t=open('Cargo.toml').read(); p=t.split('[package]',1)[1].split('\n[',1)[0]; print(re.search(r'^version\s*=\s*\"([0-9.]+)\"', p, re.M).group(1))")"
NEW_VERSION="$(p11scope --version 2>/dev/null | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"
[ "$NEW_VERSION" = "$EXPECTED_NEW" ] || fail "new version is '$NEW_VERSION', expected '$EXPECTED_NEW'"
# 7. New doctor.
set +e
p11scope doctor > "$WORKDIR/doctor-new.out" 2>&1
DOCTOR_NEW_RC=$?
set -e
[ "$DOCTOR_NEW_RC" = 0 ] || fail "new doctor rc=$DOCTOR_NEW_RC"
grep -q '^Doctor:' "$WORKDIR/doctor-new.out" || fail "new doctor output has no Doctor line"
# 8. New short capture.
set +e
p11scope inventory --pid 1 --capture scan --json -o "$WORKDIR/post-upgrade.json" > "$WORKDIR/capture-new.out" 2>&1
CAPTURE_NEW_RC=$?
set -e
[ "$CAPTURE_NEW_RC" = 0 ] || fail "new capture rc=$CAPTURE_NEW_RC"
python3 -c "import json; d=json.load(open('$WORKDIR/post-upgrade.json')); assert d.get('schema')=='p11scope/inventory/v1', d.get('schema')" \
  || fail "new capture report has wrong schema"
# 9. Canaries byte-identical.
CANARY_RECOVERY_SHA_AFTER="$(sha256sum "$CANARY_RECOVERY" | cut -d' ' -f1)"
CANARY_REPORT_SHA_AFTER="$(sha256sum "$CANARY_REPORT" | cut -d' ' -f1)"
[ "$CANARY_RECOVERY_SHA_BEFORE" = "$CANARY_RECOVERY_SHA_AFTER" ] || fail "recovery canary changed across upgrade"
[ "$CANARY_REPORT_SHA_BEFORE" = "$CANARY_REPORT_SHA_AFTER" ] || fail "saved-report canary changed across upgrade"
# 10. Package manager agrees the new version is installed.
if [ "$FORMAT" = deb ]; then
  dpkg -l p11scope 2>/dev/null | grep -q "$NEW_VERSION" || fail "dpkg does not list $NEW_VERSION"
else
  rpm -q p11scope 2>/dev/null | grep -q "$NEW_VERSION" || fail "rpm does not list $NEW_VERSION"
fi

emit_result "pass"
echo "GATE5 PASS ($FORMAT): 0.7.1 -> $NEW_VERSION, doctor+capture ok, canaries survived" >&2
