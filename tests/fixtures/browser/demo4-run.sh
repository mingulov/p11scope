#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# demo4-run.sh — DEMO-4 late-attach browser cell (runs ON fedora).
#
# The user already has the browser running: the browser launches
# FIRST, presents its client certificate once (session, login and
# key lookup all happen before p11scope exists), and only then does
# `p11scope inventory --system --key-operations` attach — with NO
# manifest. A fresh TLS server then forces a new signature inside
# the window. Chromium must show per-key rows for the new signs
# (its own NSS softokn token, empty-password database, so no PIN
# prompt can stall the handshake); Firefox must show mechanisms
# and functions for its own NSS token. MODE=first is the
# p11scope-first twin (observer seals before the browser launches).
#
# Usage: demo4-run.sh SRC_MIRROR P11SCOPE OUTDIR RUN_LABEL BROWSER MODE
#   BROWSER: chromium | firefox
#   MODE:    late | first
# Runs bare (locks the shared bpf lane internally per phase).
set -u
umask 022

SRC=${1:?usage: demo4-run.sh SRC_MIRROR P11SCOPE OUTDIR RUN_LABEL BROWSER MODE}
P11SCOPE=${2:?usage: demo4-run.sh SRC_MIRROR P11SCOPE OUTDIR RUN_LABEL BROWSER MODE}
OUT=${3:?usage: demo4-run.sh SRC_MIRROR P11SCOPE OUTDIR RUN_LABEL BROWSER MODE}
LABEL=${4:?usage: demo4-run.sh SRC_MIRROR P11SCOPE OUTDIR RUN_LABEL BROWSER MODE}
BROWSER=${5:?usage: demo4-run.sh SRC_MIRROR P11SCOPE OUTDIR RUN_LABEL BROWSER MODE}
MODE=${6:?usage: demo4-run.sh SRC_MIRROR P11SCOPE OUTDIR RUN_LABEL BROWSER MODE}

[ -d "$SRC/tests/fixtures/browser" ] || { echo "SRC_MIRROR has no browser harness: $SRC" >&2; exit 2; }
[ -x "$P11SCOPE" ] || { echo "P11SCOPE is not executable: $P11SCOPE" >&2; exit 2; }
case "$BROWSER" in chromium|firefox) ;; *) echo "browser must be chromium|firefox" >&2; exit 2;; esac
case "$MODE" in late|first) ;; *) echo "mode must be late|first" >&2; exit 2;; esac
install -d -m 0755 "$OUT" || exit 2
OUT=$(cd "$OUT" && pwd -P)
install -d -m 0700 "$OUT/tmp" || exit 2
export TMPDIR=$OUT/tmp

LANE=/home/user/p11scope-live/lane-run.sh
[ -x "$LANE" ] || { echo "lane-run.sh missing: $LANE" >&2; exit 2; }
BROWSER_ENV=/home/user/p11scope-live/browser/env/bin/python
export PLAYWRIGHT_BROWSERS_PATH=/home/user/p11scope-live/browser/ms-playwright

sudo -n true 2>/dev/null || { echo "passwordless sudo required" >&2; exit 2; }
[ -x "$BROWSER_ENV" ] || { echo "SKIP browser-venv-missing" >&2; exit 0; }
for tool in certutil pk12util openssl; do
    command -v "$tool" >/dev/null || { echo "FAIL $tool-missing" >&2; exit 1; }
done

work=$OUT/$LABEL
install -d -m 0755 "$work/cell" || exit 2

cat >"$work/driver.py" <<'PYEOF'
import json, os, sys, time
from pathlib import Path
work = Path(sys.argv[1])
browser = sys.argv[3]
mode = sys.argv[4]
sys.path.insert(0, sys.argv[2])
import cells, flows, softhsm, tls_server
from playwright.sync_api import sync_playwright
STABLE_ARGS = (
    "--no-first-run", "--no-default-browser-check", "--disable-sync",
    "--disable-background-networking", "--disable-component-update",
    "--disable-default-apps", "--no-service-autorun",
)
FF_STABLE = {
    "app.update.disabledForTesting": True,
    "app.normandy.enabled": False,
    "browser.safebrowsing.malware.enabled": False,
    "browser.safebrowsing.phishing.enabled": False,
    "browser.safebrowsing.downloads.enabled": False,
    "datareporting.policy.dataSubmissionEnabled": False,
    "toolkit.telemetry.enabled": False,
}

def wait_file(name, seconds):
    deadline = time.monotonic() + seconds
    while not (work / name).exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    return (work / name).exists()

def server_facts(flow, ccflow):
    return {
        "plain": {"connections": flow.connections,
                  "requests_served": flow.requests_served,
                  "handshakes_ok": flow.handshakes_ok},
        "cc": {"connections": ccflow.connections,
               "requests_served": ccflow.requests_served,
               "cert_requests": ccflow.cert_requests_sent,
               "presented": ccflow.client_certs_presented,
               "empty_certs": ccflow.empty_certs,
               "stalls": ccflow.selection_stalls},
    }

cred = softhsm.generate_client_credential(work / "cred")
key, cert = tls_server.make_server_credential(work / "srv")
(work / "setup-done").touch()
if mode == "first" and not wait_file("launch", 1200):
    (work / "flow.json").write_text(json.dumps(
        {"error": "observer never launched the browser"}))
    raise SystemExit(0)

with tls_server.FlowServer(cert=cert, key=key) as flow, \
     tls_server.FlowServer(cert=cert, key=key, require_client_cert=True,
                           client_ca=cred.cert_pem) as ccflow:
    with sync_playwright() as pw:
        # Chromium's auto-select switch takes a JSON policy, not a
        # bare URL; cover every loopback port so the phase-2 fresh
        # server (a new port) is auto-selected too.
        auto_policy = json.dumps(
            [{"pattern": "https://127.0.0.1:*/*", "filter": {}}])
        context, match, home = cells.launch_browser_context(
            pw, browser, work / "cell",
            extra_browser_args=STABLE_ARGS if browser == "chromium" else (),
            extra_prefs=FF_STABLE if browser == "firefox" else None,
            flow_url=auto_policy if browser == "chromium" else ccflow.url,
            auto_select_cert=True,
            nss_credential=cred)
        try:
            pid = cells.main_browser_pid(match, browser)
            page = context.new_page()
            facts = {"browser": browser, "mode": mode, "pid": pid}
            # Plain visit first: NSS initializes and softokn maps.
            facts["warm"] = flows.make_visit(flow.url)(page, context)
            facts["mapped"] = cells.wait_for_mapping(
                pid, ("softokn",), 30.0)
            if mode == "late":
                # Phase 1, before any observer exists: one real
                # client-certificate handshake (session, login and
                # key lookup predate attach by construction).
                facts["pre_client_cert"] = flows.make_client_cert_visit(
                    ccflow.url)(page, context)
                facts["pre_server"] = server_facts(flow, ccflow)
                (work / "pidfile.json").write_text(json.dumps(facts))
                if not wait_file("go", 900):
                    facts["error"] = "observer never signalled go"
                    (work / "flow.json").write_text(json.dumps(facts))
                    raise SystemExit(0)
            else:
                (work / "pidfile.json").write_text(json.dumps(facts))
                if not wait_file("go", 900):
                    facts["error"] = "observer never signalled go"
                    (work / "flow.json").write_text(json.dumps(facts))
                    raise SystemExit(0)
            # Phase 2, inside the observation window: a FRESH TLS
            # server (new port, no resumable session) forces new
            # signatures on the already-known key.
            with tls_server.FlowServer(
                    cert=cert, key=key, require_client_cert=True,
                    client_ca=cred.cert_pem) as ccflow2:
                visits = []
                for _ in range(2):
                    visits.append(flows.make_client_cert_visit(
                        ccflow2.url)(page, context))
                plain = flows.make_visit(flow.url)(page, context)
                facts["post_client_cert"] = visits
                facts["post_plain"] = plain
                facts["post_server"] = server_facts(flow, ccflow2)
            (work / "flow.json").write_text(json.dumps(facts))
            wait_file("stop", 900)
        finally:
            context.close()
PYEOF

"$BROWSER_ENV" -I "$work/driver.py" "$work" "$SRC/tests/fixtures/browser" \
    "$BROWSER" "$MODE" >"$work/driver.out" 2>"$work/driver.err" &
driver_pid=$!
observer_pid=""
trap 'kill $driver_pid $observer_pid 2>/dev/null' RETURN
waited=0
while [ ! -f "$work/setup-done" ] && [ $waited -lt 180 ]; do
    kill -0 "$driver_pid" 2>/dev/null \
        || { echo "FAIL driver-exited-during-setup"; tail -15 "$work/driver.err"; trap - RETURN; exit 1; }
    sleep 1; waited=$((waited+1))
done
[ -f "$work/setup-done" ] \
    || { echo "FAIL no-setup-done"; tail -15 "$work/driver.err"; kill "$driver_pid" 2>/dev/null; trap - RETURN; exit 1; }

# DEMO4_LANE_HELD=1: the caller already holds the shared bpf lane
# for a batch of cells (one lock wait instead of one per cell), so
# the observer runs without a nested lane lock.
start_observer() {
    local lane=("$LANE" shared bpf)
    [ "${DEMO4_LANE_HELD:-0}" = 1 ] && lane=()
    "${lane[@]}" timeout --signal=TERM --kill-after=10s 1200s sudo -n \
        "$P11SCOPE" inventory --system --key-operations --duration 150 \
        -o "$work/inventory.json" >"$work/inventory.out" 2>"$work/inventory.err" &
    observer_pid=$!
}
# The observer is running (past any lane-lock wait): its own process
# exists. A head start counted from the lock request would launch the
# browser before the observer on a busy lane, turning a first-mode
# cell into an unlabelled late-attach one.
wait_observer_running() {
    local waited=0
    while [ $waited -lt 3600 ]; do
        pgrep -f -- "^$P11SCOPE inventory --system .*-o $work/inventory.json" >/dev/null \
            && return 0
        kill -0 "$observer_pid" 2>/dev/null || return 1
        sleep 1; waited=$((waited+1))
    done
    return 1
}
wait_seal() {
    local limit=${1:-900}
    local waited=0
    while [ $waited -lt "$limit" ]; do
        grep -q 'p11scope: semantic lane ready' "$work/inventory.err" 2>/dev/null && return 0
        kill -0 "$observer_pid" 2>/dev/null || return 1
        sleep 1; waited=$((waited+1))
    done
    return 1
}
wait_pidfile() {
    local waited=0
    while [ ! -f "$work/pidfile.json" ] && [ $waited -lt 300 ]; do
        kill -0 "$driver_pid" 2>/dev/null \
            || { echo "FAIL driver-exited-before-pidfile"; tail -15 "$work/driver.err"; return 1; }
        sleep 1; waited=$((waited+1))
    done
    [ -f "$work/pidfile.json" ]
}

t0=$(date +%s)
if [ "$MODE" = first ]; then
    start_observer
    wait_observer_running \
        || { echo "FAIL observer-never-ran mode=first"; tail -15 "$work/inventory.err"; trap - RETURN; exit 1; }
    # p11scope starts first, but without a manifest the scan seal
    # can only mint once a complete provider exists to discover:
    # give the observer a head start, then launch the browser and
    # let the seal complete over its softokn, all before the
    # post-attach signs are signalled.
    # DEMO4_HEAD_START (seconds, default 20) varies the browser's
    # launch against the observer's startup for race exploration.
    wait_seal "${DEMO4_HEAD_START:-20}" || true
    kill -0 "$observer_pid" 2>/dev/null \
        || { echo "FAIL observer-exited-before-launch"; tail -15 "$work/inventory.err"; trap - RETURN; exit 1; }
    : >"$work/launch"
    wait_pidfile || { trap - RETURN; exit 1; }
    if ! wait_seal; then
        echo "FAIL observer-never-sealed mode=first"
        kill "$observer_pid" "$driver_pid" 2>/dev/null; tail -15 "$work/inventory.err"
        trap - RETURN; exit 1
    fi
    seal_wall=$(( $(date +%s)-t0 ))
else
    # Late attach: the browser runs (and signs) first.
    wait_pidfile || { trap - RETURN; exit 1; }
    pre_wall=$(( $(date +%s)-t0 ))
    echo "INFO pre-attach browser phase done in ${pre_wall}s"
    start_observer
    if ! wait_seal; then
        echo "FAIL observer-never-sealed mode=late"
        kill "$observer_pid" "$driver_pid" 2>/dev/null; tail -15 "$work/inventory.err"
        trap - RETURN; exit 1
    fi
    seal_wall=$(( $(date +%s)-t0-pre_wall ))
fi
pid=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' "$work/pidfile.json")
mapped=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["mapped"])' "$work/pidfile.json")
[ "$mapped" = True ] \
    || { echo "FAIL softokn-never-mapped pid=$pid"; : >"$work/stop"; tail -15 "$work/driver.err"; trap - RETURN; exit 1; }
: >"$work/go"
wait "$observer_pid"; rc=$?
obs_wall=$(( $(date +%s)-t0 ))
: >"$work/stop"
wait "$driver_pid" 2>/dev/null
trap - RETURN
if [ $rc -ne 0 ]; then
    echo "FAIL rc=$rc pid=$pid seal=${seal_wall}s obs=${obs_wall}s"
    tail -15 "$work/inventory.err"; exit 1
fi
sudo -n chown "$(id -u):$(id -g)" "$work/inventory.json" 2>/dev/null || true
python3 -I - "$work/inventory.json" "$work/flow.json" "$BROWSER" "$MODE" "$LABEL" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
flow = json.load(open(sys.argv[2]))
browser, mode, label = sys.argv[3], sys.argv[4], sys.argv[5]
if doc.get("schema") != "p11scope/inventory/v1":
    raise SystemExit(f"bad-schema {doc.get('schema')}")
oo = doc.get("object_observations") or {}
rows = oo.get("key_operations") or []
sign_completed = sum(r.get("completed", 0) for r in rows
                     if r.get("category") == "sign")
unknown_type = [r for r in rows if r.get("metadata_at_use") == "unknown"]
unattributed = oo.get("unattributed") or []
edges = doc.get("semantic_edges") or []
mech_used = sum(len(e.get("mechanisms") or []) for e in edges
                if isinstance(e, dict))
functions_used = len({
    f for e in edges if isinstance(e, dict)
    for m in (e.get("mechanisms") or [])
    for f in ((m.get("evidence") or {}).get("functions") or [])})
pre_presented = (flow.get("pre_server") or {}).get("cc", {}).get("presented", 0)
post_presented = (flow.get("post_server") or {}).get("cc", {}).get("presented", 0)
gaps = (doc.get("evidence") or {}).get("gap_classes") or []
gap_names = sorted({g.get("cause") or g.get("reason") or "?"
                    for g in gaps if isinstance(g, dict)})
print(f"RESULT label={label} browser={browser} mode={mode} "
      f"keyrows={len(rows)} sign_completed={sign_completed} "
      f"unknown_type_rows={len(unknown_type)} "
      f"unknown={len(oo.get('unknown_key_operations') or [])} "
      f"sessions={len(oo.get('sessions') or [])} "
      f"objects={len(oo.get('objects') or [])} "
      f"oover={oo.get('version')} oostatus={oo.get('status')} "
      f"ooreason={oo.get('reason')} unattributed={unattributed} "
      f"mechanisms={mech_used} functions={functions_used} "
      f"pre_presented={pre_presented} "
      f"post_presented={post_presented} "
      f"callers={len(doc.get('callers') or [])} gaps={','.join(gap_names)}")
ok = post_presented >= 1
if mode == "late":
    ok = ok and pre_presented >= 1
if browser == "chromium":
    ok = ok and sign_completed >= 1
else:
    ok = ok and mech_used >= 1 and functions_used >= 1
print(f"CELL demo4-{browser}-{mode} {'PASS' if ok else 'FAIL'} label={label}")
raise SystemExit(0 if ok else 1)
PY
