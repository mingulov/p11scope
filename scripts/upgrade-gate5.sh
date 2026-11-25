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
# (/var/tmp/p11scope-recovered-<euid>/) and a saved report-shaped JSON
# file. The cell hashes them before the upgrade and requires
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
set -eu

FORMAT=""; OLD=""; NEW=""; WORKDIR=""; SELF_TEST_DIR=""
# Typed result fields; filled as the cell runs.  The binary path is absolute
# so a PATH shadow cannot make the cell attest a different executable.  Tests
# source this file and assign the variable only in their own shell; normal
# execution always reinitializes it here before main() runs.
P11SCOPE_BIN="/usr/bin/p11scope"
EXPECTED_NEW=""
OLD_VERSION=""; NEW_VERSION=""
OLD_PACKAGE_VERSION=""; NEW_PACKAGE_VERSION=""
OLD_INSTALLED_PACKAGE_VERSION=""; NEW_INSTALLED_PACKAGE_VERSION=""
DOCTOR_OLD_RC=-1; DOCTOR_NEW_RC=-1
CAPTURE_OLD_RC=-1; CAPTURE_NEW_RC=-1
CANARY_RECOVERY_SHA_BEFORE=""; CANARY_RECOVERY_SHA_AFTER=""
CANARY_REPORT_SHA_BEFORE=""; CANARY_REPORT_SHA_AFTER=""
FAIL_REASON=""
RESULT=""
SYNTHETIC=0

need_value() {
  [ "$2" -ge 2 ] || { echo "$1 requires a value" >&2; exit 2; }
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --format) need_value "$1" "$#"; FORMAT="$2"; shift 2;;
      --old) need_value "$1" "$#"; OLD="$2"; shift 2;;
      --new) need_value "$1" "$#"; NEW="$2"; shift 2;;
      --workdir) need_value "$1" "$#"; WORKDIR="$2"; shift 2;;
      --self-test) need_value "$1" "$#"; SELF_TEST_DIR="$2"; shift 2;;
      *) echo "unknown arg: $1" >&2; exit 2;;
    esac
  done
}

emit_result() {
  status="$1"
  output="$2"
  GATE5_FORMAT="$FORMAT" \
  GATE5_OLD="$OLD" \
  GATE5_NEW="$NEW" \
  GATE5_BINARY="$P11SCOPE_BIN" \
  GATE5_OLD_VERSION="$OLD_VERSION" \
  GATE5_NEW_VERSION="$NEW_VERSION" \
  GATE5_OLD_PACKAGE_VERSION="$OLD_PACKAGE_VERSION" \
  GATE5_NEW_PACKAGE_VERSION="$NEW_PACKAGE_VERSION" \
  GATE5_OLD_INSTALLED_PACKAGE_VERSION="$OLD_INSTALLED_PACKAGE_VERSION" \
  GATE5_NEW_INSTALLED_PACKAGE_VERSION="$NEW_INSTALLED_PACKAGE_VERSION" \
  GATE5_DOCTOR_OLD_RC="$DOCTOR_OLD_RC" \
  GATE5_DOCTOR_NEW_RC="$DOCTOR_NEW_RC" \
  GATE5_CAPTURE_OLD_RC="$CAPTURE_OLD_RC" \
  GATE5_CAPTURE_NEW_RC="$CAPTURE_NEW_RC" \
  GATE5_CANARY_RECOVERY_SHA_BEFORE="$CANARY_RECOVERY_SHA_BEFORE" \
  GATE5_CANARY_RECOVERY_SHA_AFTER="$CANARY_RECOVERY_SHA_AFTER" \
  GATE5_CANARY_REPORT_SHA_BEFORE="$CANARY_REPORT_SHA_BEFORE" \
  GATE5_CANARY_REPORT_SHA_AFTER="$CANARY_REPORT_SHA_AFTER" \
  GATE5_FAIL_REASON="$FAIL_REASON" \
  GATE5_SYNTHETIC="$SYNTHETIC" \
  python3 - "$output" "$status" <<'PY'
import json
import os
import sys


def text(name):
    return os.environ.get(name, "")


def integer(name):
    try:
        return int(text(name))
    except ValueError:
        return -1


doctor_old = integer("GATE5_DOCTOR_OLD_RC")
doctor_new = integer("GATE5_DOCTOR_NEW_RC")
recovery_before = text("GATE5_CANARY_RECOVERY_SHA_BEFORE")
recovery_after = text("GATE5_CANARY_RECOVERY_SHA_AFTER")
report_before = text("GATE5_CANARY_REPORT_SHA_BEFORE")
report_after = text("GATE5_CANARY_REPORT_SHA_AFTER")
result = {
    "gate": 5,
    "format": text("GATE5_FORMAT"),
    "status": sys.argv[2],
    "old_package": text("GATE5_OLD"),
    "new_package": text("GATE5_NEW"),
    "binary": text("GATE5_BINARY"),
    "old_version": text("GATE5_OLD_VERSION"),
    "new_version": text("GATE5_NEW_VERSION"),
    "old_package_version": text("GATE5_OLD_PACKAGE_VERSION"),
    "new_package_version": text("GATE5_NEW_PACKAGE_VERSION"),
    "old_installed_package_version": text("GATE5_OLD_INSTALLED_PACKAGE_VERSION"),
    "new_installed_package_version": text("GATE5_NEW_INSTALLED_PACKAGE_VERSION"),
    "doctor_old_rc": doctor_old,
    "doctor_new_rc": doctor_new,
    "doctor_rcs_equal": doctor_old in (0, 1) and doctor_old == doctor_new,
    "capture_old_rc": integer("GATE5_CAPTURE_OLD_RC"),
    "capture_new_rc": integer("GATE5_CAPTURE_NEW_RC"),
    "canary_recovery_sha_before": recovery_before,
    "canary_recovery_sha_after": recovery_after,
    "canary_report_sha_before": report_before,
    "canary_report_sha_after": report_after,
    "canary_survived": bool(recovery_before)
    and recovery_before == recovery_after
    and bool(report_before)
    and report_before == report_after,
    "fail_reason": text("GATE5_FAIL_REASON"),
    "synthetic": text("GATE5_SYNTHETIC") == "1",
}
encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
with open(sys.argv[1], "w", encoding="utf-8") as out:
    out.write(encoded)
print(encoded, end="")
PY
}

fail() {
  FAIL_REASON="$1"
  if [ -n "$RESULT" ]; then
    emit_result "fail" "$RESULT"
  fi
  echo "GATE5 FAIL: $1" >&2
  exit 1
}

run_self_test() {
  dir="$1"
  mkdir -p "$dir" 2>/dev/null || { echo "self-test directory unavailable: $dir" >&2; exit 2; }
  SYNTHETIC=1
  FORMAT="selftest"
  OLD="old-package"
  NEW="new-package"
  OLD_VERSION="0.7.1"
  NEW_VERSION="0.7.2"
  OLD_PACKAGE_VERSION="0.7.1"
  NEW_PACKAGE_VERSION="0.7.2"
  OLD_INSTALLED_PACKAGE_VERSION="0.7.1"
  NEW_INSTALLED_PACKAGE_VERSION="0.7.2"
  DOCTOR_OLD_RC=0
  DOCTOR_NEW_RC=0
  CAPTURE_OLD_RC=0
  CAPTURE_NEW_RC=0
  CANARY_RECOVERY_SHA_BEFORE="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  CANARY_RECOVERY_SHA_AFTER="$CANARY_RECOVERY_SHA_BEFORE"
  CANARY_REPORT_SHA_BEFORE="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  CANARY_REPORT_SHA_AFTER="$CANARY_REPORT_SHA_BEFORE"
  emit_result "pass" "$dir/gate5-result.json"
  CANARY_REPORT_SHA_AFTER="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  FAIL_REASON="self-test mismatch"
  emit_result "fail" "$dir/gate5-result-mismatch.json"
  CANARY_REPORT_SHA_AFTER="$CANARY_REPORT_SHA_BEFORE"
  DOCTOR_NEW_RC=1
  FAIL_REASON="self-test doctor mismatch"
  emit_result "fail" "$dir/gate5-result-doctor-mismatch.json"
  DOCTOR_NEW_RC=0
  CANARY_RECOVERY_SHA_BEFORE=""
  CANARY_RECOVERY_SHA_AFTER=""
  FAIL_REASON="self-test empty hash"
  emit_result "fail" "$dir/gate5-result-empty-hash.json"
}

package_version() {
  if [ "$FORMAT" = deb ]; then
    dpkg-deb -f "$1" Version 2>/dev/null
  else
    rpm -qp --queryformat '%{VERSION}' "$1" 2>/dev/null
  fi
}

hash_file() {
  output="$(sha256sum "$1")" || return 1
  [ -n "$output" ] || return 1
  printf '%s' "${output%% *}"
}

installed_version() {
  version_output="$("$P11SCOPE_BIN" --version 2>/dev/null)" || return 1
  IFS= read -r first_line <<< "$version_output"
  # shellcheck disable=SC2086
  set -- $first_line
  [ "${1:-}" = "p11scope" ] && [ -n "${2:-}" ] || return 1
  printf '%s' "$2"
}

validate_inventory_report() {
  validator="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/upgrade_artifact_validation.py" || return 1
  python3 "$validator" inventory "$1" 2>&1
}

install_old() {
  if [ "$FORMAT" = deb ]; then
    dpkg -i "$OLD" > "$WORKDIR/install-old.log" 2>&1
  else
    rpm -i --force "$OLD" > "$WORKDIR/install-old.log" 2>&1
  fi
}

upgrade_new() {
  if [ "$FORMAT" = deb ]; then
    dpkg -i "$NEW" > "$WORKDIR/install-new.log" 2>&1
  else
    rpm -U "$NEW" > "$WORKDIR/install-new.log" 2>&1
  fi
}

installed_package_version() {
  if [ "$FORMAT" = deb ]; then
    dpkg-query -W -f='${Version}' p11scope 2>/dev/null
  else
    rpm -q --queryformat '%{VERSION}' p11scope 2>/dev/null
  fi
}

run_doctor() {
  log="$1"
  if "$P11SCOPE_BIN" doctor > "$log" 2>&1; then
    return 0
  else
    return $?
  fi
}

find_provider_module() {
  for candidate in     /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so     /usr/lib64/pkcs11/libsofthsm2.so     /usr/lib/softhsm/libsofthsm2.so; do
    if [ -f "$candidate" ]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

run_capture() {
  output="$1"
  log="$2"
  module="$(find_provider_module)" || return 90
  target_out="$log.target"
  python3 -c 'import ctypes, sys, time; ctypes.CDLL(sys.argv[1]); print("ready", flush=True); time.sleep(20)' "$module" > "$target_out" 2>&1 &
  target_pid=$!
  ready=0
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if grep -q ready "$target_out" 2>/dev/null; then
      ready=1
      break
    fi
    sleep 0.1
  done
  if [ "$ready" != 1 ]; then
    kill "$target_pid" 2>/dev/null || true
    wait "$target_pid" 2>/dev/null || true
    return 91
  fi
  # OUTPUT_OWNER_ARGS is either empty or a numeric uid pair constructed above.
  # The scan target is the known SoftHSM workload: the resulting typed report
  # must carry at least one caller, provider module and caller-provider edge.
  # shellcheck disable=SC2086
  "$P11SCOPE_BIN" inventory --pid "$target_pid" --capture scan --json -o "$output" $OUTPUT_OWNER_ARGS > "$log" 2>&1
  rc=$?
  kill "$target_pid" 2>/dev/null || true
  wait "$target_pid" 2>/dev/null || true
  return "$rc"
}

recovery_dir() {
  printf '%s' "/var/tmp/p11scope-recovered-$EUID_VAL"
}

run_gate_body() {
  OLD_PACKAGE_VERSION="$(package_version "$OLD")" || fail "cannot read old package metadata"
  NEW_PACKAGE_VERSION="$(package_version "$NEW")" || fail "cannot read new package metadata"
  [ -n "$OLD_PACKAGE_VERSION" ] || fail "old package metadata version empty"
  [ -n "$NEW_PACKAGE_VERSION" ] || fail "new package metadata version empty"
  [ "$OLD_PACKAGE_VERSION" = "0.7.1" ] || fail "old package is version '$OLD_PACKAGE_VERSION', expected 0.7.1"
  [ "$NEW_PACKAGE_VERSION" = "$EXPECTED_NEW" ] || fail "new package is version '$NEW_PACKAGE_VERSION', expected '$EXPECTED_NEW'"

  # Canary state: recovery dir + saved report. Created before the old install
  # so even the old install must preserve them; hashed before upgrade.
  EUID_VAL="$(id -u)"
  WORKDIR_UID="$(stat -c %u "$WORKDIR")" || fail "cannot stat workdir"
  OUTPUT_OWNER_ARGS=""
  if [ "$EUID_VAL" = 0 ] && [ "$WORKDIR_UID" != 0 ]; then
    OUTPUT_OWNER_ARGS="--output-owner $WORKDIR_UID"
  fi
  RECOVERY_DIR="$(recovery_dir)"
  mkdir -p "$RECOVERY_DIR" || fail "cannot create recovery canary dir"
  chmod 700 "$RECOVERY_DIR" || fail "cannot secure recovery canary dir"
  CANARY_RECOVERY="$RECOVERY_DIR/gate5-canary-$FORMAT"
  printf 'gate5-canary %s old-state must survive\n' "$FORMAT" > "$CANARY_RECOVERY" || fail "cannot create recovery canary"
  chmod 600 "$CANARY_RECOVERY" || fail "cannot secure recovery canary"
  CANARY_REPORT="$WORKDIR/operator-report-$FORMAT.json"
  printf '{"gate":5,"format":"%s","operator":"saved report must survive"}\n' "$FORMAT" > "$CANARY_REPORT" || fail "cannot create saved-report canary"

  # 1. Install old.
  install_old || fail "old install failed (see install-old.log)"
  [ -x "$P11SCOPE_BIN" ] || fail "installed old binary missing at $P11SCOPE_BIN"
  # 2. Old installed version must be 0.7.1.
  OLD_VERSION="$(installed_version)" || fail "cannot run installed old binary"
  [ "$OLD_VERSION" = "0.7.1" ] || fail "old version is '$OLD_VERSION', expected 0.7.1"
  OLD_INSTALLED_PACKAGE_VERSION="$(installed_package_version)" || fail "package manager does not list old p11scope"
  [ "$OLD_INSTALLED_PACKAGE_VERSION" = "$OLD_VERSION" ] || fail "old package manager version is '$OLD_INSTALLED_PACKAGE_VERSION', expected '$OLD_VERSION'"
  # 3. Old doctor (no scope). rc 0 (all requested lanes passed) or 1 (a
  # requested lane unavailable, e.g. no CAP_BPF in a container) both prove
  # the binary runs and reports; only 2+ (usage/crash) or a missing Doctor
  # line fails.
  if run_doctor "$WORKDIR/doctor-old.out"; then
    DOCTOR_OLD_RC=0
  else
    DOCTOR_OLD_RC=$?
  fi
  [ "$DOCTOR_OLD_RC" = 0 ] || [ "$DOCTOR_OLD_RC" = 1 ] || fail "old doctor rc=$DOCTOR_OLD_RC"
  grep -q '^Doctor:' "$WORKDIR/doctor-old.out" || fail "old doctor output has no Doctor line"
  # 4. Old short capture: a scan of the known SoftHSM target (no BPF, so it
  # works on hosts and in containers, but with a positive provider payload).
  if run_capture "$WORKDIR/pre-upgrade.json" "$WORKDIR/capture-old.out"; then
    CAPTURE_OLD_RC=0
  else
    CAPTURE_OLD_RC=$?
  fi
  [ "$CAPTURE_OLD_RC" = 0 ] || fail "old capture rc=$CAPTURE_OLD_RC"
  validation_detail="$(validate_inventory_report "$WORKDIR/pre-upgrade.json")" || fail "old capture report failed typed validation: $validation_detail"
  # Hash canaries before upgrade; an empty hash is a failure, never equality.
  CANARY_RECOVERY_SHA_BEFORE="$(hash_file "$CANARY_RECOVERY")" || fail "cannot hash recovery canary before upgrade"
  CANARY_REPORT_SHA_BEFORE="$(hash_file "$CANARY_REPORT")" || fail "cannot hash saved-report canary before upgrade"
  [ -n "$CANARY_RECOVERY_SHA_BEFORE" ] || fail "recovery canary hash empty before upgrade"
  [ -n "$CANARY_REPORT_SHA_BEFORE" ] || fail "saved-report canary hash empty before upgrade"
  # 5. Upgrade to new.
  upgrade_new || fail "upgrade to new failed (see install-new.log)"
  [ -x "$P11SCOPE_BIN" ] || fail "installed new binary missing at $P11SCOPE_BIN"
  # 6. New installed version must match the tree.
  NEW_VERSION="$(installed_version)" || fail "cannot run installed new binary"
  [ "$NEW_VERSION" = "$EXPECTED_NEW" ] || fail "new version is '$NEW_VERSION', expected '$EXPECTED_NEW'"
  # 7. New doctor (same 0/1 acceptance as old) and no doctor-result regression.
  if run_doctor "$WORKDIR/doctor-new.out"; then
    DOCTOR_NEW_RC=0
  else
    DOCTOR_NEW_RC=$?
  fi
  [ "$DOCTOR_NEW_RC" = 0 ] || [ "$DOCTOR_NEW_RC" = 1 ] || fail "new doctor rc=$DOCTOR_NEW_RC"
  grep -q '^Doctor:' "$WORKDIR/doctor-new.out" || fail "new doctor output has no Doctor line"
  [ "$DOCTOR_NEW_RC" = "$DOCTOR_OLD_RC" ] || fail "doctor rc flipped $DOCTOR_OLD_RC->$DOCTOR_NEW_RC"
  # 8. New short capture (same system scan as old).
  if run_capture "$WORKDIR/post-upgrade.json" "$WORKDIR/capture-new.out"; then
    CAPTURE_NEW_RC=0
  else
    CAPTURE_NEW_RC=$?
  fi
  [ "$CAPTURE_NEW_RC" = 0 ] || fail "new capture rc=$CAPTURE_NEW_RC"
  validation_detail="$(validate_inventory_report "$WORKDIR/post-upgrade.json")" || fail "new capture report failed typed validation: $validation_detail"
  # 9. Canaries byte-identical, with non-empty hashes on both sides.
  CANARY_RECOVERY_SHA_AFTER="$(hash_file "$CANARY_RECOVERY")" || fail "cannot hash recovery canary after upgrade"
  CANARY_REPORT_SHA_AFTER="$(hash_file "$CANARY_REPORT")" || fail "cannot hash saved-report canary after upgrade"
  [ -n "$CANARY_RECOVERY_SHA_AFTER" ] || fail "recovery canary hash empty after upgrade"
  [ -n "$CANARY_REPORT_SHA_AFTER" ] || fail "saved-report canary hash empty after upgrade"
  [ "$CANARY_RECOVERY_SHA_BEFORE" = "$CANARY_RECOVERY_SHA_AFTER" ] || fail "recovery canary changed across upgrade"
  [ "$CANARY_REPORT_SHA_BEFORE" = "$CANARY_REPORT_SHA_AFTER" ] || fail "saved-report canary changed across upgrade"
  # 10. Package manager agrees the new version is installed.
  NEW_INSTALLED_PACKAGE_VERSION="$(installed_package_version)" || fail "package manager does not list new p11scope"
  [ "$NEW_INSTALLED_PACKAGE_VERSION" = "$NEW_VERSION" ] || fail "package manager version is '$NEW_INSTALLED_PACKAGE_VERSION', expected '$NEW_VERSION'"

  emit_result "pass" "$RESULT"
  echo "GATE5 PASS ($FORMAT): 0.7.1 -> $NEW_VERSION, doctor+capture ok, canaries survived" >&2
}

main() {
  parse_args "$@"

  if [ -n "$SELF_TEST_DIR" ]; then
    [ -z "$FORMAT" ] && [ -z "$OLD" ] && [ -z "$NEW" ] && [ -z "$WORKDIR" ] || {
      echo "--self-test cannot be combined with gate arguments" >&2
      exit 2
    }
    run_self_test "$SELF_TEST_DIR"
    exit 0
  fi

  [ "$FORMAT" = deb ] || [ "$FORMAT" = rpm ] || { echo "--format deb|rpm required" >&2; exit 2; }
  [ -n "$OLD" ] && [ -n "$NEW" ] && [ -n "$WORKDIR" ] || { echo "--old/--new/--workdir required" >&2; exit 2; }
  [ -f "$OLD" ] || { echo "old package missing: $OLD" >&2; exit 2; }
  [ -f "$NEW" ] || { echo "new package missing: $NEW" >&2; exit 2; }
  [ "$(id -u)" = 0 ] || { echo "must run as root (installs system packages)" >&2; exit 2; }
  if ! mkdir -p "$WORKDIR" 2>/dev/null; then
    echo "workdir unavailable: $WORKDIR" >&2
    exit 2
  fi
  RESULT="$WORKDIR/gate5-result.json"

  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
  if ! EXPECTED_NEW="$(python3 - "$REPO_ROOT/Cargo.toml" <<'PY'
import re
import sys

try:
    text = open(sys.argv[1], encoding="utf-8").read()
    package = text.split("[package]", 1)[1].split("\n[", 1)[0]
    found = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', package, re.M)
except (OSError, IndexError) as exc:
    print(f"cannot read tree version: {exc}", file=sys.stderr)
    raise SystemExit(1)
if not found:
    print("cannot parse strict tree version", file=sys.stderr)
    raise SystemExit(1)
print(found[1])
PY
)"; then
    fail "cannot read repo version"
  fi

  run_gate_body
}

# Source-only is available solely when the file is genuinely being sourced
# into another shell.  The environment variable alone can never suppress the
# gate in normal execution (BASH_SOURCE and $0 are the same there).
if [ "${BASH_SOURCE[0]}" != "$0" ] && [ "${P11SCOPE_GATE5_SOURCE_ONLY:-0}" = "1" ]; then
  :
else
  main "$@"
fi
