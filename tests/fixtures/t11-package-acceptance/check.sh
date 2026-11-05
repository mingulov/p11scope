#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# T11 prep isolated self-check: every path/name this directory references
# must exist (or be absent, where a gap is claimed) at the pinned base.
# Read-only: no builds, no privilege, no network, no writes outside a
# private TMPDIR scratch dir. Exit 0 = prep is consistent; exit 1 = drift.
set -eu
cd "$(dirname "$0")/../../.."
FAIL=0
say() { printf '%s\n' "$*"; }
need_path() {
    if [ -e "$1" ]; then say "ok: path $1";
    else say "DRIFT: missing path $1"; FAIL=1; fi
}
need_name() {
    file=$1; name=$2
    if grep -rq -- "$name" "$file" 2>/dev/null; then say "ok: '$name' present in $file";
    else say "DRIFT: '$name' not found in $file"; FAIL=1; fi
}
need_absent() {
    name=$1; shift
    if grep -rq --exclude-dir=t11-package-acceptance -- "$name" "$@" 2>/dev/null; then say "DRIFT: '$name' now exists under $* (gap closed? update prep)";
    else say "ok: '$name' still absent under $* (outside this prep dir)"; fi
}

say "== referenced scripts =="
for p in scripts/verify-canaries.sh scripts/check-canary-evidence.py \
    scripts/release-matrix-contract.py scripts/qualify-release-matrix.sh \
    scripts/build-release.sh scripts/package-release.py \
    scripts/release-artifacts.py scripts/release-notices.py \
    scripts/export-source.py scripts/build-offline.py scripts/run-python-suites.py \
    scripts/verify-system-test-manifest.py scripts/verify-provider-matrix.sh \
    scripts/kind-e2e.sh scripts/attach-pod.sh .github/workflows/ci.yml \
    .release-rust-version RELEASING.md CHANGELOG.md docs/build-offline.md \
    docs/qualification/release-matrix.md \
    docs/qualification/system-test-manifest.md docs/privacy/allowlist-v1.md; do
    need_path "$p"
done
for p in scripts/matrix/verify-ia32-compat.sh \
    scripts/matrix/verify-uretprobe-seccomp.sh \
    scripts/matrix/verify-kind-pod.sh scripts/matrix/verify-knative.sh \
    scripts/matrix/verify-docker.sh scripts/matrix/verify-shared-layer.sh \
    scripts/matrix/verify-proxy-stack.sh scripts/matrix/verify-pidns.sh \
    deploy/k8s/20-daemonset.yaml deploy/Dockerfile.observer \
    deploy/Dockerfile.holder; do
    need_path "$p"
done

say "== claim/carry artifacts =="
for p in tests/fixtures/system-qualification/closure-ledger.json \
    tests/fixtures/system-qualification/system-deferred-gates.json \
    tests/fixtures/system-qualification/system-test-manifest.json \
    tests/fixtures/system-qualification/system-bounded-scope.json; do
    need_path "$p"
done
for p in tests/python/test_release_matrix_contract.py \
    tests/python/test_system_test_manifest.py \
    tests/python/test_package_release.py \
    tests/python/test_bench_count_overhead.py \
    tests/python/test_stopped_canary_capture.py \
    tests/python/test_entry_object.py; do
    need_path "$p"
done

say "== EXISTS claims (must still be true) =="
need_name tests/python/test_stopped_canary_capture.py test_image_map_flag_validation_preserves_protection
need_name tests/python/test_bench_count_overhead.py count_overhead_rejects_missing_counts_and_rounds
need_name tests/python/test_system_test_manifest.py bounded_claim_cannot_pass_full_system_product
need_name scripts/run-python-suites.py test_release_matrix_contract.py
need_name scripts/release-matrix-contract.py 'identity:5.15-denied'

say "== GAP claims (must still be absent; drift only warns) =="
need_absent privileged_identity_515_denial_is_disclosed scripts tests src docs
need_absent test_release_recipient_uses_selected_binary scripts tests src docs
need_absent required_positive_rejects_skipped_selector scripts tests src docs

say "== freshness markers =="
if grep -q 'proposed-for-owner-approval' tests/fixtures/system-qualification/system-bounded-scope.json; then
    say "ok: bounded scope still proposed-for-owner-approval"
else say "DRIFT: bounded scope status changed (update prep)"; fi
if [ -e src/scheduler.rs ]; then say "note: src/scheduler.rs exists now (G26 runbook mapping may simplify)";
else say "ok: src/scheduler.rs still absent (G26 mapping note stands)"; fi
if grep -q '## \[Unreleased\]' CHANGELOG.md; then say "note: CHANGELOG gained Unreleased (G25 gap may be closing)";
else say "ok: CHANGELOG still has no Unreleased section"; fi

say "== prep files well-formed =="
for f in tests/fixtures/t11-package-acceptance/*.md; do
    if head -n 1 "$f" | grep -q 'SPDX-License-Identifier'; then say "ok: header $f";
    else say "DRIFT: missing SPDX header $f"; FAIL=1; fi
done
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -S error tests/fixtures/t11-package-acceptance/check.sh && say "ok: shellcheck -S error clean"
else say "SKIP: shellcheck not installed"; fi

if [ "$FAIL" -ne 0 ]; then say "RESULT: DRIFT (exit 1)"; else say "RESULT: CONSISTENT (exit 0)"; fi
exit "$FAIL"
