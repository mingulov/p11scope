#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Cell K3: Knative scale-from-zero pod using a PKCS#11 provider (dev host).
#
# A private kind cluster gets the smallest real Knative install (Serving
# knative-v1.23.0 CRDs + core and net-kourier knative-v1.23.0, all three YAMLs
# sha256-verified before apply, no Istio), the KService
# (deploy/k8s/e2e/knative-service.yaml: scale-to-zero, containerConcurrency 1,
# kind.local image tag, node image id checked) and the documented DaemonSet (same render as
# scripts/kind-e2e.sh). The serving pod's main process is the ledgered `gated`
# client (deploy/Dockerfile.knative-holder): one GET on /ledger releases its
# single ledger run and the HTTP handler returns the LEDGER line, so the pod
# makes an exactly known number of PKCS#11 calls per request.
#
# Flow (controller): install Knative, wait Ready, load the holder image, apply
# the KService, prove it scaled to zero, apply the DaemonSet, send ONE request
# through a port-forward to kourier-internal, run `p11scope inventory --system`
# in the observer pod while the serving pod lives (primary: serving PID has an
# edge to the provider, nested observer, the one `pid namespace` scope gap),
# then scale back to zero, run the gated secondary (`profile --system`
# spanning one woken request: wake with GET /, wait the attach window, run
# the ledger on the same pod, exact LEDGER total, event_loss == 0), scale
# back to zero, run the reported-only boundary (`profile --system` spanning
# one cold-first request: a record-only BOUNDARY line disclosing the measured
# tail; malformed, excess, ambiguous or lossy measurements fail) and the
# failure twin (inventory after scale-to-zero: the dead
# serving PID is absent with no stale edge).
#
# The CONTROLLER runs every docker/kind/kubectl/curl command below. Workers
# only run `sh $0 --self-test`, which is unprivileged (PATH stubs) and proves
# the arg refusals, every pin (base-image digests, YAML sha256 checked before
# `kubectl apply`), the private kubeconfig, the scale-to-zero/request parsing,
# the cleanup trap and the oracle hooks.
#
# Never kubectl/docker exec into a captured pod or container while a capture
# runs: exec staging adds short-lived processes the capture counts as
# pid_descendant_gaps. All PID resolution (crictl in the node) happens with no
# capture running; kubectl API reads and the host-side curl are the only
# mid-capture contact.
set -eu
cd "$(dirname "$0")/.."

ORACLE=scripts/kind-e2e-oracle.py
KNATIVE_DOCKERFILE=deploy/Dockerfile.knative-holder
KNATIVE_KSVC=deploy/k8s/e2e/knative-service.yaml
KNATIVE_VERSION=knative-v1.23.0
# YAML pins re-verified against scripts/matrix/verify-knative.sh by self-test.
CRDS_SHA256=b172ff4901ed50f8e4e09ff8616e54d22e264df7086ce8cb74f513a04812fe74
CORE_SHA256=be3f16c9c0ac9276cc173ef04871aaeac78537f9edb116310caa02f016e9cbc2
KOURIER_SHA256=cded0c3c1d7669b1aa9f7484234b454ff3940a2b54a27d5ec4825c2d4003d01d
# Pinned base reused from deploy/Dockerfile.holder (both FROM lines there and
# both stages here); the self-test requires this digest exactly twice here.
HOLDER_BASE=ubuntu:26.04@sha256:3595d7fc4286a33fad0fd853a4063e654287a9c3787437d7937c94ca3f7a804e
PROVIDER_SUFFIX=libsofthsm2.so
ITERS_DEFAULT=200
SLEEP_US_DEFAULT=200
PROFILE_SECONDS=60
# Worst-case live-admission bound for a mid-capture provider, doubled:
# profile frames tick every 1 s (src/run.rs PROFILE_CADENCE) and every 5th
# frame forces a full /proc sweep (src/run.rs FULL_DISCOVERY_EVERY_N_FRAMES),
# so a quiet-skip deferral is bounded to 5 frame intervals; the sweep's
# newcomers admit same-tick (at most 64, scheduler MAX_NEW_VIEWS_PER_TICK;
# measured queue ages 17-39 ms in the K3 diag runs) and attach takes ~20 ms.
# Worst case ~= 7 s; 15 s is generous. It fits Knative's 30 s scale-to-zero
# grace, and the same-pod check fails closed on any pod churn in between.
ATTACH_WAIT_S=15
OBS_NS=p11scope
KNS=p11scope-knative
KSVC=p11scope-k3

usage() {
    cat >&2 <<'EOF'
usage: scripts/knative-e2e.sh [--token TOKEN] [--work DIR] [--iters N] [--keep]
       scripts/knative-e2e.sh --self-test | --help

  Cell K3 driver. Its own kind cluster (run token, refuse reuse, private
  kubeconfig), Knative Serving + Kourier knative-v1.23.0 from sha256-verified
  YAMLs, the KService by its kind.local tag (node image id checked), the documented
  DaemonSet, one request per serving pod, inventory + system-profile evidence
  checked with scripts/kind-e2e-oracle.py.

  --token TOKEN   run token, short [a-z0-9-] (default <time>-<pid>)
  --work DIR      evidence directory (must not exist; default fresh 0700
                  under $TMPDIR)
  --iters N       ledger iterations per request (default 200; must match the
                  LEDGER_ITERS baked into deploy/Dockerfile.knative-holder)
  --keep          keep the cluster and images for debugging (prints the delete
                  commands, including the Knative removals)
  --self-test     unprivileged checks (PATH stubs, no docker/kind/kubectl)
  --help          this text

Environment:
  P11SCOPE_KNATIVE_CLUSTER      cluster name (default p11scope-k3-<token>);
                                refused if a cluster of that name already exists
  P11SCOPE_KNATIVE_OBSERVER_BIN prebuilt static x86-64 p11scope to package
  P11SCOPE_KNATIVE_TOOLCHAIN    cargo toolchain (default: .release-rust-version)
  P11SCOPE_KNATIVE_NODE_IMAGE   kind node image (default: kind's own)
  P11SCOPE_KNATIVE_LOCK         lock file serializing each docker/kind/capture
                                step with other privileged lanes on this host

Exit codes: 0 PASS, 1 FAIL, 2 usage, 3 UNRUN (cell not run, see SUMMARY reason).
Every run prints a single SUMMARY line: SUMMARY cell=K3 verdict=... reason="...".
A passing run also prints one BOUNDARY k3-cold-start counted=<n> of <N> ... line
for the reported-only cold-first-request measurement. A bounded partial tail
is a disclosed limitation; malformed, excess, ambiguous or lossy data fails.

CONTROLLER (from the repo root; needs docker, kind, kubectl, curl):
  sh scripts/knative-e2e.sh --token <TOKEN>
EOF
    exit 2
}

valid_token() {
    case $1 in
        ''|*[!a-z0-9-]*|-*|*-) return 1 ;;
        *) [ "${#1}" -le 40 ] ;;
    esac
}

valid_count() {
    case $1 in
        ''|*[!0-9]*|0*) return 1 ;;
        *) [ "${#1}" -le 7 ] ;;
    esac
}

knative_pin() {
    case $1 in
        serving-crds.yaml) printf '%s\n' "$CRDS_SHA256" ;;
        serving-core.yaml) printf '%s\n' "$CORE_SHA256" ;;
        kourier.yaml) printf '%s\n' "$KOURIER_SHA256" ;;
        *) return 1 ;;
    esac
}

knative_url() {
    case $1 in
        serving-crds.yaml|serving-core.yaml)
            printf 'https://github.com/knative/serving/releases/download/%s/%s\n' "$KNATIVE_VERSION" "$1" ;;
        kourier.yaml)
            printf 'https://github.com/knative-extensions/net-kourier/releases/download/%s/%s\n' "$KNATIVE_VERSION" "$1" ;;
        *) return 1 ;;
    esac
}

# The embedded handler and entry script, extracted from the Dockerfile between
# their marker comments (the markers ship inside the image files as comments).
server_block() {
    sed -n '/^# K3-SERVER-BEGIN$/,/^# K3-SERVER-END$/p' "$KNATIVE_DOCKERFILE" | sed '1d;$d'
}

entry_block() {
    sed -n '/^# K3-ENTRY-BEGIN$/,/^# K3-ENTRY-END$/p' "$KNATIVE_DOCKERFILE" | sed '1d;$d'
}

prepare_work() {
    if [ -n "${WORK_OPT-}" ]; then
        [ ! -e "$WORK_OPT" ] || { echo "work dir $WORK_OPT already exists" >&2; return 1; }
        mkdir -m 0700 "$WORK_OPT"
        WORK=$(cd "$WORK_OPT" && pwd -P)
    else
        WORK=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-k3-XXXXXX")
        chmod 0700 "$WORK"
    fi
    KUBECONFIG=$WORK/kubeconfig
    export KUBECONFIG
}

refuse_existing_cluster() {
    if kind get clusters 2>/dev/null | grep -Fqx "$1"; then
        echo "kind cluster $1 already exists; refusing to reuse or delete it" >&2
        return 1
    fi
}

# One step holds the host lock at a time; fd 9 is never held across steps.
lock_step() {
    [ -z "${LOCK-}" ] || { exec 9>>"$LOCK" && flock 9; }
}
unlock_step() {
    [ -z "${LOCK-}" ] || { flock -u 9; exec 9>&-; }
}

kc() {
    timeout --signal=TERM --kill-after=10s 300s kubectl "$@"
}

# Download one Knative release file over strict https and verify its sha256
# before the caller hands it to kubectl. Refuses on any mismatch.
download_release() {
    dl_url=$1 dl_name=$2 dl_dest=$3
    dl_pin=$(knative_pin "$dl_name") || return 1
    [ ! -e "$dl_dest" ] || { echo "$dl_dest already exists" >&2; return 1; }
    curl --fail --silent --show-error --retry 0 --connect-timeout 30 --max-time 180 \
        --max-filesize 16777216 --proto '=https' --proto-redir '=https' \
        --location --max-redirs 1 --output "$dl_dest" "$dl_url" || return 1
    dl_size=$(stat -Lc %s "$dl_dest") || return 1
    case $dl_size in ''|*[!0-9]*) echo "bad size for $dl_name" >&2; return 1 ;; esac
    [ "$dl_size" -gt 0 ] && [ "$dl_size" -le 16777216 ] \
        || { echo "$dl_name has bad size $dl_size" >&2; return 1; }
    dl_got=$(sha256sum "$dl_dest" | awk '{print $1}') || return 1
    [ "$dl_got" = "$dl_pin" ] \
        || { echo "$dl_name sha256 mismatch: got $dl_got, want $dl_pin" >&2; return 1; }
}

# The kind-e2e.sh DaemonSet render: copy the documented directory, move exactly
# the observer image anchor.
render_daemonset() {
    mkdir -p "$2"
    for manifest in "$1"/*.yaml; do
        sed "s#image: p11scope-observer:1\$#image: $3#" "$manifest" > "$2/${manifest##*/}" || return 1
    done
    [ "$(grep -Fc "image: $3" "$2/20-daemonset.yaml")" -eq 1 ] \
        || { echo "daemonset render lost its image anchor" >&2; return 1; }
}

# Fill the KService tag placeholder with the kind.local holder reference.
# `kind load` gives the image no registry digest, and Knative skips registry
# tag resolution for kind.local (serving-core config-deployment
# registries-skipping-tag-resolving), so the revision runs the loaded image by
# tag; resolve_serving then proves the running container uses the node image
# id recorded before the apply.
render_ksvc() {
    rk_ref=$3
    case $rk_ref in
        kind.local/p11scope-knative-holder:*) ;;
        *) echo "not a kind.local holder reference: $rk_ref" >&2; return 1 ;;
    esac
    rk_tag=${rk_ref#kind.local/p11scope-knative-holder:}
    case $rk_tag in ''|*[!A-Za-z0-9._-]*) echo "bad holder tag: $rk_tag" >&2; return 1 ;; esac
    [ "$(grep -Fc 'image: kind.local/p11scope-knative-holder:KNATIVE_HOLDER_TAG' "$1")" -eq 1 ] \
        || { echo "ksvc lost its tag placeholder" >&2; return 1; }
    sed "s#image: kind.local/p11scope-knative-holder:KNATIVE_HOLDER_TAG#image: $rk_ref#" "$1" > "$2" || return 1
    grep -Fq "image: $rk_ref" "$2" || { echo "ksvc render lost its tag" >&2; return 1; }
}

# The running serving container's image ref must equal the node image id.
serving_image_is() {
    [ -n "$1" ] && [ "$1" = "$2" ] \
        || { echo "serving container runs '$1', not the loaded $2" >&2; return 1; }
}

wait_scale_zero() {
    wz_i=0
    while [ "$wz_i" -lt "$(($3 * 2))" ]; do
        wz_pods=$(kc get pods -l "serving.knative.dev/service=$1" -n "$2" -o name 2>/dev/null) || return 1
        [ -z "$wz_pods" ] && return 0
        sleep 0.5
        wz_i=$((wz_i + 1))
    done
    echo "service $1 never scaled to zero" >&2
    return 1
}

wait_pf_ready() {
    wp_i=0
    while [ "$wp_i" -lt "$(($2 * 2))" ]; do
        if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$1/" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
        wp_i=$((wp_i + 1))
    done
    echo "port-forward on $1 never became ready" >&2
    return 1
}

# Sleep the attach window so a pod woken inside the capture is discovered
# and attached before its ledger runs. Too short a wait can only fail the
# exact oracle below, never pass it.
wait_attach_window() {
    sleep "$ATTACH_WAIT_S"
}

# Exactly one Running serving pod, by name, from `kubectl get pods -o json`.
serving_pod() {
    python3 -I - "$1" <<'PY'
import json, sys
items = [i for i in json.load(open(sys.argv[1], encoding="utf-8"))["items"]
         if (i.get("status") or {}).get("phase") == "Running"]
if len(items) != 1:
    raise SystemExit(f"want exactly 1 running serving pod, got {len(items)}")
name = (items[0].get("metadata") or {}).get("name")
if not name or not isinstance(name, str):
    raise SystemExit("serving pod has no name")
print(name)
PY
}

# The serving pod's workload container (the non-queue-proxy one) and its
# queue-proxy, as bare container IDs: workload first, proxy second.
serving_cids() {
    python3 -I - "$1" <<'PY'
import json, re, sys
statuses = (json.load(open(sys.argv[1], encoding="utf-8")).get("status") or {}).get("containerStatuses") or []
proxy = [s for s in statuses if s.get("name") == "queue-proxy"]
user = [s for s in statuses if s.get("name") != "queue-proxy"]
if len(proxy) != 1 or len(user) != 1:
    raise SystemExit(f"want 1 queue-proxy and 1 workload container, got {len(proxy)} and {len(user)}")
def cid(entry):
    raw = entry.get("containerID") or ""
    if not raw.startswith("containerd://"):
        raise SystemExit(f"not a containerd id: {raw!r}")
    value = raw[len("containerd://"):]
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SystemExit(f"bad container id: {value!r}")
    return value
print(cid(user[0]))
print(cid(proxy[0]))
PY
}

# Both pod listings hold exactly one Running serving pod, and it is the same
# one: prints its name. A pod churn between the wake and the ledger would
# silently re-enter the cold race, so any difference refuses.
same_serving_pod() {
    sp_wake=$(serving_pod "$1") || return 1
    sp_during=$(serving_pod "$2") || return 1
    [ -n "$sp_wake" ] && [ "$sp_wake" = "$sp_during" ] || {
        echo "serving pod is not stable across wake and ledger" >&2
        return 1
    }
    printf '%s\n' "$sp_wake"
}

# A container's init PID as the node numbers it (hostPID observer view).
crictl_pid() {
    cp_pid=$(docker exec "$1" crictl inspect -o go-template --template '{{.info.pid}}' "$2") || return 1
    case $cp_pid in ''|*[!0-9]*) echo "bad node pid for $2: $cp_pid" >&2; return 1 ;; esac
    [ "$cp_pid" -gt 0 ] 2>/dev/null || { echo "bad node pid for $2: $cp_pid" >&2; return 1; }
    printf '%s\n' "$cp_pid"
}

# Every running container's declared and resolved image lands in facts.log.
dump_pod_images() {
    python3 -I - "$1" "$FACTS" <<'PY'
import json, sys
path, facts = sys.argv[1], sys.argv[2]
with open(facts, "a", encoding="utf-8") as out:
    for item in json.load(open(path, encoding="utf-8"))["items"]:
        meta, status = item.get("metadata") or {}, item.get("status") or {}
        for container in status.get("containerStatuses") or []:
            out.write(f"image-download: {meta.get('namespace')}/{meta.get('name')}/{container.get('name')} "
                      f"{container.get('image')} {container.get('imageID')}\n")
PY
}

# The node's own image id for our loaded tag, verbatim (exactly one, or refuse).
resolve_holder_id() {
    python3 -I - "$1" "$2" <<'PY'
import json, re, sys
path, tag = sys.argv[1], sys.argv[2]
ids = [image.get("id") for image in json.load(open(path, encoding="utf-8")).get("images") or []
       if tag in (image.get("repoTags") or [])]
if len(ids) != 1:
    raise SystemExit(f"want exactly 1 node image for {tag}, got {len(ids)}")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", ids[0] or ""):
    raise SystemExit(f"bad node image id: {ids[0]!r}")
print(ids[0])
PY
}

# The HTTP response carries exactly one complete gated JSON ledger with 6xN.
response_ledger_is() {
    python3 -I - "$1" "$2" <<'PY'
import json, sys
path, iters = sys.argv[1], int(sys.argv[2])
ledgers = []
with open(path, encoding="utf-8") as handle:
    for line in handle:
        if line.startswith("LEDGER "):
            ledgers.append(json.loads(line[len("LEDGER "):]))
if len(ledgers) != 1:
    raise SystemExit(f"want 1 LEDGER line, got {len(ledgers)}")
ledger = ledgers[0]
if ledger.get("schema") != "p11scope/public-cli-ledger/v1":
    raise SystemExit("bad ledger schema")
if ledger.get("complete") is not True:
    raise SystemExit("ledger incomplete")
functions = ledger.get("functions")
if not isinstance(functions, list) or len(functions) != 6:
    raise SystemExit("want 6 ledger functions")
names = set()
for row in functions:
    if row.get("attempts") != iters or row.get("successful") != iters:
        raise SystemExit(f"ledger row is not 6x{iters}: {row}")
    names.add(row.get("name"))
if len(names) != 6:
    raise SystemExit("ledger function names are not distinct")
PY
}

# ONE request; the response must carry exactly one complete 6xN ledger.
request_ledger() {
    curl --fail --silent --show-error -H "Host: $HOST" \
        "http://127.0.0.1:$PF_PORT/ledger" --max-time 120 -o "$1" \
        || fail_cell "request to the service failed"
    response_ledger_is "$1" "$ITERS" || fail_cell "response is not exactly one 6x$ITERS ledger"
    fact "ledger-response[$(basename "$1")]=$(cat "$1")"
}

# The wake answer is exactly "ready\n": any other body (notably a LEDGER
# line, which would mean the gate moved) refuses.
response_wake_is() {
    printf 'ready\n' | cmp -s - "$1" || {
        echo "wake response is not exactly ready" >&2
        return 1
    }
}

# Wake the scale-from-zero pod with a request that cannot release the ledger
# gate: any path other than /ledger answers 200 without touching it, so the
# exact "ready\n" body proves the pod (not the activator) served the wake.
wake_service() {
    curl --fail --silent --show-error -H "Host: $HOST" \
        "http://127.0.0.1:$PF_PORT/" --max-time 120 -o "$1" \
        || fail_cell "wake request to the service failed"
    response_wake_is "$1" || fail_cell "wake response is not exactly ready"
    fact "wake-response=$(cat "$1")"
}

# The deterministic secondary's mid-capture requests in order: wake (no gate
# release), one pod proven, attach window waited, ledger run, same pod
# proven. Prints the shared serving pod name. The pod still starts from zero
# inside the capture; only the ledger waits for the attach.
deterministic_requests() {
    wake_service "$WORK/response-wake.txt"
    kc get pods -l "serving.knative.dev/service=$KSVC" -n "$KNS" -o json > "$WORK/serving-wake.json" \
        || fail_cell "cannot list serving pods after wake"
    wait_attach_window
    request_ledger "$WORK/response-secondary.txt"
    kc get pods -l "serving.knative.dev/service=$KSVC" -n "$KNS" -o json > "$WORK/serving-during.json" \
        || fail_cell "cannot list serving pods mid-capture"
    same_serving_pod "$WORK/serving-wake.json" "$WORK/serving-during.json" \
        || fail_cell "wake and ledger did not share one serving pod"
}

# Gated secondary: `profile --system` spanning one request counts exactly the
# LEDGER total with zero loss. Any ambient row breaks exactness (refused, never
# merged); extra observation causes beyond the nested numbering are recorded
# but not failed (the serving pod legitimately starts mid-capture).
profile_system_is() {
    python3 -I - "$1" "$2" <<'PY'
import json, sys
path, iters = sys.argv[1], int(sys.argv[2])
document = json.load(open(path, encoding="utf-8"))
if document["capture"]["scope"] != "system":
    raise SystemExit("not a system capture")
evidence = document["evidence"]
pidns = evidence["pid_namespace"]
if pidns["observer"] != "nested" or pidns["kernel_pids"] != "initial":
    raise SystemExit(f"not a nested-observer capture: {pidns}")
causes = set(evidence["gap_classes"]["observation"]["causes"])
if "pid_namespace" not in causes:
    raise SystemExit(f"nested observer without its cause: {sorted(causes)}")
if evidence["attached_probes"] <= 0:
    raise SystemExit("no probes attached")
if evidence["event_loss"] != 0:
    raise SystemExit(f"event loss: {evidence['event_loss']}")
if evidence["in_flight_at_end"] != 0:
    raise SystemExit("calls in flight at end")
want = {"C_GenerateRandom", "C_DigestInit", "C_Digest",
        "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"}
rows = [f for f in document["functions"] if f["calls"]]
if len(rows) != 6:
    raise SystemExit(f"want 6 counted rows, got {len(rows)}")
names = set()
for row in rows:
    if row["calls"] != iters or row["errors"] != 0 or len(row["names"]) != 1:
        raise SystemExit(f"row is not exactly {iters} clean calls: {row}")
    names.add(row["names"][0])
if names != want:
    raise SystemExit(f"wrong function set: {sorted(names)}")
print(json.dumps({"check": "profile-system-exact", "ok": True,
      "calls": sum(r["calls"] for r in rows), "observed_causes": sorted(causes)}))
PY
}

# Reported-only cold-start measurement: the /ledger request as the pod's
# first request. Prints the BOUNDARY line plus a record-only JSON line (never
# "ok": true, so the gated count stays exact). Every bounded observed tail
# from 0 through 6xN is a limitation report, not a complete-capture claim.
# Exit 2 for a shaped but invalid measurement (loss, errors, excess counts or
# ambiguous attribution); exit 1 for unreadable or malformed required data.
boundary_report() {
    python3 -I - "$1" "$2" <<'PY'
import json, re, sys

def require(condition, message):
    if not condition:
        raise ValueError(message)

def count(value):
    require(type(value) is int and value >= 0, "count must be a nonnegative integer")
    return value

def optional_count(value):
    return None if value is None else count(value)

def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result

def field(value):
    return "null" if value is None else str(value)

try:
    path, iterations = sys.argv[1:]
    require(re.fullmatch(r"[1-9][0-9]*", iterations), "invalid iteration count")
    iters = int(iterations)
    require(iters <= 1000000, "invalid iteration count")
    total = 6 * iters
    with open(path, encoding="utf-8") as source:
        document = json.load(source, object_pairs_hook=unique_object,
                             parse_constant=lambda _: require(False, "invalid JSON constant"))
    require(isinstance(document, dict)
            and document.get("schema") == "p11scope/observed-profile/v3"
            and document.get("lane") == "profile"
            and document["capture"]["scope"] == "system", "not a system profile document")
    evidence = document["evidence"]
    for name in ("event_loss", "attached_probes", "pid_descendant_gaps", "discovery_ring_loss",
                 "unprotected_live_windows", "in_flight_at_end"):
        count(evidence[name])
    require(evidence["completeness"] in ("COMPLETE", "PARTIAL"), "invalid capture completeness")
    cause_list = evidence["gap_classes"]["observation"]["causes"]
    require(isinstance(cause_list, list) and all(isinstance(cause, str) and cause
            and not any(ord(char) < 32 for char in cause) for cause in cause_list), "invalid gap causes")
    causes = ",".join(sorted(cause_list)) or "none"
    newcomer = evidence["scheduling"]["newcomer_queue"]
    count(newcomer["admitted"])
    optional_count(newcomer["max_admitted_age_ms"])
    optional_count(evidence["attach_gap_ms"])
    dlopen_unproven = count(evidence["loader_discovery"]["dlopen_timing"]["unproven"])
    rows = document["functions"]
    require(isinstance(rows, list), "functions must be an array")
    want = {"C_GenerateRandom", "C_DigestInit", "C_Digest",
            "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"}
    by_name = dict.fromkeys(want, 0)
    extra = []
    ambiguous = []
    row_errors = 0
    for row in rows:
        names = row["names"]
        require(isinstance(names, list) and names
                and all(isinstance(name, str) and name for name in names), "invalid function names")
        calls = count(row["calls"])
        row_errors += count(row["errors"])
        if len(names) == 1 and names[0] in want:
            # Distinct providers and retired/re-attached cells may repeat a
            # name or target; bound the aggregate, never require six rows.
            by_name[names[0]] += calls
        elif calls:
            extra.append(row)
            if want.intersection(names):
                ambiguous.append(row)
    counted = sum(by_name.values())
    extra_calls = sum(row["calls"] for row in extra)
    failures = []
    if any(calls > iters for calls in by_name.values()) or counted > total:
        failures.append("target-count-excess")
    if ambiguous:
        failures.append("ambiguous-target-alias")
    if evidence["event_loss"]:
        failures.append("event-loss")
    if evidence["discovery_ring_loss"]:
        failures.append("discovery-loss")
    if row_errors:
        failures.append("row-errors")
    classification = "none" if counted == 0 else "full" if counted == total else "partial"
    print(f"BOUNDARY k3-cold-start counted={counted} of {total} "
          f"event_loss={evidence['event_loss']} "
          f"attached_probes={evidence['attached_probes']} "
          f"completeness={evidence['completeness']} causes={causes} "
          f"pid_descendant_gaps={evidence['pid_descendant_gaps']} "
          f"dlopen_unproven={dlopen_unproven} "
          f"newcomer_admitted={newcomer['admitted']} "
          f"newcomer_max_age_ms={field(newcomer['max_admitted_age_ms'])} "
          f"attach_gap_ms={field(evidence['attach_gap_ms'])} "
          f"discovery_ring_loss={evidence['discovery_ring_loss']} "
          f"unprotected_windows={evidence['unprotected_live_windows']} "
          f"in_flight={evidence['in_flight_at_end']} "
          f"extra_rows={len(extra)} extra_calls={extra_calls} row_errors={row_errors} "
          f"classification={classification} ambiguous_rows={len(ambiguous)} "
          f"measurement_valid={str(not failures).lower()}")
    print(json.dumps({"check": "boundary-k3-cold-start", "record_only": True,
          "counted": counted, "of": total, "extra_rows": len(extra),
          "classification": classification, "limitation": "cold-first-request-observed-tail",
          "measurement_valid": not failures, "measurement_failures": failures}))
    sys.exit(2 if failures else 0)
except (OSError, ValueError, KeyError, TypeError) as error:
    print(f"cold boundary report invalid: {error}", file=sys.stderr)
    sys.exit(1)
PY
}

# Record the cold observation without adding a gated check. A failed shaped
# measurement retains the same BOUNDARY diagnostics before the cell refuses.
record_boundary_report() {
    BND_STATUS=0
    BND_OUT=$(boundary_report "$1" "$2") || BND_STATUS=$?
    BND_LINE=$(printf '%s\n' "$BND_OUT" | sed -n '1p')
    BND_JSON=$(printf '%s\n' "$BND_OUT" | sed -n '2p')
    case $BND_STATUS in
        0|2) : ;;
        *) fail_cell "boundary report failed" ;;
    esac
    case $BND_LINE in
        "BOUNDARY k3-cold-start "*) : ;;
        *) fail_cell "boundary report printed no BOUNDARY line" ;;
    esac
    say "$BND_LINE"
    fact "$BND_LINE"
    record "$BND_JSON"
    [ "$BND_STATUS" -eq 0 ] || fail_cell "boundary k3-cold-start measurement failed"
}

# Failure twin: after scale-to-zero the dead serving PID is absent from
# callers[] with no stale edge. The twin capture must itself be healthy (the
# one nested scope gap, a non-empty scan), so the absence is proven, not empty.
inventory_absent() {
    python3 -I - "$1" "$2" <<'PY'
import json, sys
path, dead = sys.argv[1], int(sys.argv[2])
document = json.load(open(path, encoding="utf-8"))
if document["schema"] != "p11scope/inventory/v1":
    raise SystemExit("bad schema")
pidns = document["pid_namespace"]
if pidns["observer"] != "nested" or pidns["kernel_pids"] != "initial":
    raise SystemExit(f"not a nested-observer capture: {pidns}")
scope_gaps = [g for g in document["gaps"] if g["subject"] == "pid namespace"
              and g["caller"] is None and g["module"] is None and g["pid"] is None]
if len(scope_gaps) != 1:
    raise SystemExit(f"want the one pid-namespace scope gap, got {len(scope_gaps)}")
pid_of = {c["id"]: c["pid"] for c in document["callers"]}
if not pid_of:
    raise SystemExit("twin scanned nothing")
if dead in pid_of.values():
    raise SystemExit(f"dead serving pid {dead} still a caller")
edge_pids = {pid_of[e["caller"]] for e in document["edges"]}
if dead in edge_pids:
    raise SystemExit(f"stale edge for dead serving pid {dead}")
print(json.dumps({"check": "failure-twin-absent", "ok": True,
      "absent_pid": dead, "scanned_callers": len(pid_of)}))
PY
}

# Its own cluster and images, nothing else (the trap calls this).
cleanup_owned() {
    kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
    docker image rm -f "$OBS_IMAGE" "$KNATIVE_IMAGE" >/dev/null
}

say() {
    printf '%s\n' "$1"
}

fact() {
    printf '%s\n' "$1" >>"$FACTS"
}

# Gated results carry "ok": true; record-only lines carry "record_only": true
# and never count as a passed check.
record() {
    printf '%s\n' "$1" | tee -a "$SUMMARY_JSONL"
}

summarize() {
    line="SUMMARY cell=K3 verdict=$1 reason=\"$2\""
    printf '%s\n' "$line"
    if [ -n "${FACTS-}" ]; then
        printf '%s\n' "$line" >>"$FACTS"
    fi
}

unrun() {
    summarize UNRUN "$1"
    exit 3
}

fail_cell() {
    summarize FAIL "$1"
    exit 1
}

pass_cell() {
    summarize PASS "$1"
    exit 0
}

self_test() {
    [ "$#" -eq 0 ] || usage
    command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }
    for name in ok p11scope-k3-1-2 a; do
        valid_token "$name" || { echo "valid_token rejected $name" >&2; exit 1; }
    done
    for name in "" -x x- Upper under_score "a.b" 01234567890123456789012345678901234567890; do
        if valid_token "$name" >/dev/null 2>&1; then echo "valid_token accepted $name" >&2; exit 1; fi
    done
    for count in 1 200 1000000; do
        valid_count "$count" || { echo "valid_count rejected $count" >&2; exit 1; }
    done
    for count in "" 0 01 x -1 10000000; do
        if valid_count "$count" >/dev/null 2>&1; then echo "valid_count accepted $count" >&2; exit 1; fi
    done
    # The three YAML pins and the Knative version are the in-tree ones: each
    # pin must appear verbatim in scripts/matrix/verify-knative.sh.
    [ "$(knative_pin serving-crds.yaml)" = "$CRDS_SHA256" ] || { echo "crds pin drifted" >&2; exit 1; }
    [ "$(knative_pin serving-core.yaml)" = "$CORE_SHA256" ] || { echo "core pin drifted" >&2; exit 1; }
    [ "$(knative_pin kourier.yaml)" = "$KOURIER_SHA256" ] || { echo "kourier pin drifted" >&2; exit 1; }
    if knative_pin other.yaml >/dev/null 2>&1; then echo "knative_pin accepted other.yaml" >&2; exit 1; fi
    for sha in "$CRDS_SHA256" "$CORE_SHA256" "$KOURIER_SHA256"; do
        grep -Fq "$sha" scripts/matrix/verify-knative.sh \
            || { echo "pin $sha is not an in-tree hash" >&2; exit 1; }
    done
    grep -Fq "KNATIVE_VERSION=$KNATIVE_VERSION" scripts/matrix/verify-knative.sh \
        || { echo "$KNATIVE_VERSION is not the in-tree version" >&2; exit 1; }
    [ "$(knative_url serving-crds.yaml)" = "https://github.com/knative/serving/releases/download/$KNATIVE_VERSION/serving-crds.yaml" ] \
        || { echo "crds url drifted" >&2; exit 1; }
    [ "$(knative_url serving-core.yaml)" = "https://github.com/knative/serving/releases/download/$KNATIVE_VERSION/serving-core.yaml" ] \
        || { echo "core url drifted" >&2; exit 1; }
    [ "$(knative_url kourier.yaml)" = "https://github.com/knative-extensions/net-kourier/releases/download/$KNATIVE_VERSION/kourier.yaml" ] \
        || { echo "kourier url drifted" >&2; exit 1; }
    # The holder base pin: both stages of the Knative holder carry exactly the
    # deploy/Dockerfile.holder digest.
    [ "$(grep -c "FROM $HOLDER_BASE" "$KNATIVE_DOCKERFILE")" -eq 2 ] \
        || { echo "knative holder base pin drifted" >&2; exit 1; }
    [ "$(grep -c "FROM $HOLDER_BASE" deploy/Dockerfile.holder)" -eq 2 ] \
        || { echo "holder base pin drifted" >&2; exit 1; }
    grep -Fq "ENV LEDGER_ITERS=$ITERS_DEFAULT LEDGER_SLEEP_US=$SLEEP_US_DEFAULT" "$KNATIVE_DOCKERFILE" \
        || { echo "Dockerfile ledger defaults drifted" >&2; exit 1; }
    # The embedded HTTP handler and entry script: markers, syntax, behavior.
    for marker in 'PORT' '"/ledger"' 'K3_GATE' 'LEDGER ' 'ledger already ran' 'FileExistsError'; do
        server_block | grep -Fq "$marker" \
            || { echo "server block lost its marker: $marker" >&2; exit 1; }
    done
    for marker in 'softhsm2-util --init-token' 'python3 /server.py &' 'exec /usr/local/bin/p11scope-ledger-gated'; do
        entry_block | grep -Fq "$marker" \
            || { echo "entry block lost its marker: $marker" >&2; exit 1; }
    done
    server_block | python3 -c 'import sys; compile(sys.stdin.read(), "server.py", "exec")' \
        || { echo "embedded server does not compile" >&2; exit 1; }
    entry_block | sh -n || { echo "embedded entry does not parse" >&2; exit 1; }
    # Each embedded script's first line (right after its heredoc RUN line)
    # is its shebang: the kernel execs the entry directly (ENTRYPOINT), so a
    # marker comment above the shebang is an exec format error in the pod.
    [ "$(sed -n "/<<'SHEOF'\$/{n;p;q}" "$KNATIVE_DOCKERFILE")" = '#!/bin/sh' ] \
        || { echo "embedded entry does not start with its shebang" >&2; exit 1; }
    [ "$(sed -n "/<<'PYEOF'\$/{n;p;q}" "$KNATIVE_DOCKERFILE")" = '#!/usr/bin/env python3' ] \
        || { echo "embedded server does not start with its shebang" >&2; exit 1; }
    # The KService shape: kind.local tag placeholder, scale-to-zero, one request.
    [ "$(grep -c 'image: kind.local/p11scope-knative-holder:KNATIVE_HOLDER_TAG' "$KNATIVE_KSVC")" -eq 1 ] \
        || { echo "ksvc lost its tag placeholder" >&2; exit 1; }
    grep -Fq 'containerConcurrency: 1' "$KNATIVE_KSVC" \
        || { echo "ksvc lost containerConcurrency: 1" >&2; exit 1; }
    grep -Fq 'autoscaling.knative.dev/min-scale: "0"' "$KNATIVE_KSVC" \
        || { echo "ksvc lost min-scale 0" >&2; exit 1; }
    grep -Fq 'imagePullPolicy: Never' "$KNATIVE_KSVC" \
        || { echo "ksvc lost imagePullPolicy: Never" >&2; exit 1; }
    # The DaemonSet render this cell reuses (same anchors scripts/kind-e2e.sh
    # requires): one observer image anchor, namespace first.
    [ "$(cat deploy/k8s/*.yaml | grep -c 'image: p11scope-observer:1$')" -eq 1 ] \
        || { echo "deploy/k8s lost its single observer image anchor" >&2; exit 1; }
    set -- deploy/k8s/*.yaml
    [ "$1" = deploy/k8s/00-namespace.yaml ] \
        || { echo "deploy/k8s/00-namespace.yaml must sort first" >&2; exit 1; }
    for bad in "--bogus" "--token" "--token UPPER" "--token -x" \
               "--token ok --token ok" "--work" "--work /tmp --work /tmp" \
               "--iters" "--iters 0" "--iters 01" "--iters x" \
               "--keep --bogus" "--self-test extra"; do
        status=0
        # shellcheck disable=SC2086
        sh "$0" $bad >/dev/null 2>&1 || status=$?
        [ "$status" -eq 2 ] || {
            echo "k3 driver exited $status (want 2) for: [$bad]" >&2
            exit 1
        }
    done
    k3_help_self_test
    k3_stub_self_test
    k3_server_self_test
    python3 -I "$ORACLE" --self-test
    echo "knative-e2e self-test: OK"
    exit 0
}

k3_help_self_test() {
    help=$(sh "$0" --help 2>&1 || true)
    for marker in "sh scripts/knative-e2e.sh --token <TOKEN>" "SUMMARY cell=K3" \
                  "--iters N" "P11SCOPE_KNATIVE_OBSERVER_BIN"; do
        case $help in
            *"$marker"*) ;;
            *) echo "help lost its controller line: $marker" >&2; exit 1 ;;
        esac
    done
}

k3_stub_self_test() {
    stub=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-k3-stub-XXXXXX")
    # shellcheck disable=SC2064
    trap "rm -rf '$stub'" EXIT
    : > "$stub/calls.txt"
    # Private work dir: fresh 0700, kubeconfig inside, exported.
    WORK_OPT= KUBECONFIG=
    prepare_work
    work1=$WORK
    [ -d "$WORK" ] || { echo "prepare_work made no dir" >&2; exit 1; }
    [ "$(stat -c %a "$WORK")" = 700 ] || { echo "work dir is not 0700" >&2; exit 1; }
    [ "$KUBECONFIG" = "$WORK/kubeconfig" ] || { echo "kubeconfig is not private: $KUBECONFIG" >&2; exit 1; }
    WORK_OPT=$stub/explicit-work
    prepare_work
    [ "$WORK" = "$stub/explicit-work" ] && [ "$KUBECONFIG" = "$stub/explicit-work/kubeconfig" ] \
        || { echo "explicit work dir lost" >&2; exit 1; }
    mkdir -p "$stub/taken"
    if WORK_OPT=$stub/taken prepare_work >/dev/null 2>&1; then
        echo "existing work dir accepted" >&2
        exit 1
    fi
    WORK_OPT=
    # Existing clusters are refused before anything is created or deleted.
    cat > "$stub/kind" <<'EOF'
#!/bin/sh
if [ "$1" = "get" ] && [ "$2" = "clusters" ]; then printf '%s\n' "$STUB_CLUSTERS"; exit 0; fi
printf '%s\n' "kind $*" >> "$STUB_CALLS"
EOF
    chmod +x "$stub/kind"
    if STUB_CLUSTERS="p11scope-k3-t" PATH="$stub:$PATH" refuse_existing_cluster p11scope-k3-t \
            >/dev/null 2>&1; then
        echo "existing cluster accepted" >&2
        exit 1
    fi
    STUB_CLUSTERS="other" PATH="$stub:$PATH" refuse_existing_cluster p11scope-k3-t \
        || { echo "free cluster name refused" >&2; exit 1; }
    # YAML bytes are verified before kubectl ever sees them: a mismatch
    # refuses and the stub kubectl records no apply.
    printf 'fake-yaml-bytes' > "$stub/serving-crds.yaml"
    good_sha=$(sha256sum "$stub/serving-crds.yaml" | awk '{print $1}')
    cat > "$stub/curl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$STUB_ARGV"
out=
prev=
for arg in "$@"; do
    if [ "$prev" = "--output" ]; then out=$arg; fi
    prev=$arg
done
cat "$STUB_YAML" > "$out"
EOF
    cat > "$stub/kubectl" <<'EOF'
#!/bin/sh
printf '%s\n' "kubectl $*" >> "$STUB_CALLS"
EOF
    chmod +x "$stub/curl" "$stub/kubectl"
    : > "$stub/curl-argv.txt"
    CRDS_SHA256=$good_sha STUB_YAML=$stub/serving-crds.yaml STUB_CALLS=$stub/calls.txt STUB_ARGV=$stub/curl-argv.txt \
        PATH="$stub:$PATH" download_release https://example.invalid/crds serving-crds.yaml "$stub/got.yaml" \
        || { echo "good YAML refused" >&2; exit 1; }
    cmp "$stub/serving-crds.yaml" "$stub/got.yaml" \
        || { echo "downloaded YAML differs" >&2; exit 1; }
    for flag in "--proto =https" "--proto-redir =https" "--max-redirs 1" "--retry 0" "--fail"; do
        grep -Fq -- "$flag" "$stub/curl-argv.txt" \
            || { echo "curl lost its strict flag: $flag" >&2; exit 1; }
    done
    printf 'tampered' > "$stub/bad.yaml"
    if CRDS_SHA256=$good_sha STUB_YAML=$stub/bad.yaml STUB_CALLS=$stub/calls.txt STUB_ARGV=$stub/curl-argv.txt \
            PATH="$stub:$PATH" download_release https://example.invalid/crds serving-crds.yaml "$stub/got2.yaml" \
            >/dev/null 2>&1; then
        echo "tampered YAML accepted" >&2
        exit 1
    fi
    if grep -q 'kubectl apply' "$stub/calls.txt"; then
        echo "kubectl ran before verification" >&2
        exit 1
    fi
    # DaemonSet render (the kind-e2e.sh shape): exactly the anchor moves.
    mkdir -p "$stub/k8s"
    printf 'image: p11scope-observer:1\n' > "$stub/k8s/20-daemonset.yaml"
    PATH="$stub:$PATH" render_daemonset "$stub/k8s" "$stub/rendered" img:t \
        || { echo "daemonset render refused" >&2; exit 1; }
    grep -Fq 'image: img:t' "$stub/rendered/20-daemonset.yaml" \
        || { echo "render lost the image" >&2; exit 1; }
    printf 'image: something-else:1\n' > "$stub/k8s/20-daemonset.yaml"
    if PATH="$stub:$PATH" render_daemonset "$stub/k8s" "$stub/rendered2" img:t \
            >/dev/null 2>&1; then
        echo "anchorless daemonset rendered" >&2
        exit 1
    fi
    # KService render: the tag placeholder is filled with the validated
    # kind.local holder reference, nothing else moves.
    printf 'image: kind.local/p11scope-knative-holder:KNATIVE_HOLDER_TAG\n' > "$stub/ksvc.yaml"
    PATH="$stub:$PATH" render_ksvc "$stub/ksvc.yaml" "$stub/ksvc-out.yaml" \
        "kind.local/p11scope-knative-holder:k3-t1" \
        || { echo "ksvc render refused" >&2; exit 1; }
    grep -Fq "image: kind.local/p11scope-knative-holder:k3-t1" "$stub/ksvc-out.yaml" \
        || { echo "render lost the tag" >&2; exit 1; }
    for bad_ref in "p11scope-knative-holder:k3-t1" "docker.io/library/p11scope-knative-holder:k3-t1" \
            "kind.local/other:k3-t1" "kind.local/p11scope-knative-holder:" \
            "kind.local/p11scope-knative-holder:k3 t1" "kind.local/p11scope-knative-holder:k3#t1" ""; do
        if PATH="$stub:$PATH" render_ksvc "$stub/ksvc.yaml" "$stub/ksvc-bad.yaml" "$bad_ref" \
                >/dev/null 2>&1; then
            echo "bad holder reference accepted: $bad_ref" >&2
            exit 1
        fi
    done
    k3_waiter_self_test "$stub"
    k3_parser_self_test "$stub"
    k3_check_self_test "$stub"
    k3_sequencing_self_test "$stub"
    k3_cleanup_self_test "$stub"
    rm -rf "$stub" "$work1" "$WORK"
    trap - EXIT
}

k3_waiter_self_test() {
    stub=$1
    # Scale-to-zero waiter: pods drain to none, or the waiter refuses.
    cat > "$stub/kubectl" <<'EOF'
#!/bin/sh
if [ "$1" = "get" ] && [ "$2" = "pods" ]; then
    n=$(cat "$STUB_PODS_LEFT")
    if [ "$n" -gt 0 ]; then
        i=0
        while [ "$i" -lt "$n" ]; do printf 'pod/k-%s\n' "$i"; i=$((i + 1)); done
        printf '%s' "$((n - 1))" > "$STUB_PODS_LEFT"
    fi
    exit 0
fi
echo "unexpected kubectl call: $*" >&2; exit 1
EOF
    chmod +x "$stub/kubectl"
    printf '2' > "$stub/pods-left.txt"
    STUB_PODS_LEFT=$stub/pods-left.txt PATH="$stub:$PATH" wait_scale_zero svc ns 5 \
        || { echo "draining pods missed" >&2; exit 1; }
    printf '99' > "$stub/pods-left.txt"
    if STUB_PODS_LEFT=$stub/pods-left.txt PATH="$stub:$PATH" wait_scale_zero svc ns 1 \
            >/dev/null 2>&1; then
        echo "stuck pods counted as scaled to zero" >&2
        exit 1
    fi
    # Port-forward readiness: the poll succeeds once curl answers.
    cat > "$stub/curl" <<'EOF'
#!/bin/sh
n=$(cat "$STUB_CURL_LEFT")
if [ "$n" -gt 0 ]; then printf '%s' "$((n - 1))" > "$STUB_CURL_LEFT"; exit 7; fi
exit 0
EOF
    chmod +x "$stub/curl"
    printf '2' > "$stub/curl-left.txt"
    STUB_CURL_LEFT=$stub/curl-left.txt PATH="$stub:$PATH" wait_pf_ready 18080 5 \
        || { echo "ready port-forward missed" >&2; exit 1; }
    printf '99' > "$stub/curl-left.txt"
    if STUB_CURL_LEFT=$stub/curl-left.txt PATH="$stub:$PATH" wait_pf_ready 18080 1 \
            >/dev/null 2>&1; then
        echo "dead port-forward counted as ready" >&2
        exit 1
    fi
}

k3_parser_self_test() {
    stub=$1
    # Exactly one Running serving pod, or refusal.
    cat > "$stub/pods.json" <<'EOF'
{"items": [{"metadata": {"name": "k3-00001-deployment-abc", "namespace": "p11scope-knative"},
  "status": {"phase": "Running"}}]}
EOF
    [ "$(serving_pod "$stub/pods.json")" = k3-00001-deployment-abc ] \
        || { echo "serving pod missed" >&2; exit 1; }
    printf '{"items": []}' > "$stub/pods-empty.json"
    if serving_pod "$stub/pods-empty.json" >/dev/null 2>&1; then
        echo "zero serving pods accepted" >&2
        exit 1
    fi
    cat > "$stub/pods-two.json" <<'EOF'
{"items": [{"metadata": {"name": "a"}, "status": {"phase": "Running"}},
  {"metadata": {"name": "b"}, "status": {"phase": "Running"}}]}
EOF
    if serving_pod "$stub/pods-two.json" >/dev/null 2>&1; then
        echo "two serving pods accepted" >&2
        exit 1
    fi
    # Container selection: the non-queue-proxy container is the workload; both
    # container IDs must be well formed.
    cat > "$stub/pod.json" <<'EOF'
{"metadata": {"name": "k3-00001-deployment-abc"},
 "status": {"containerStatuses": [
   {"name": "queue-proxy", "containerID": "containerd://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
   {"name": "user-container", "containerID": "containerd://fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}]}}
EOF
    cids=$(serving_cids "$stub/pod.json") \
        || { echo "serving containers missed" >&2; exit 1; }
    [ "$cids" = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ] \
        || { echo "wrong container selection: $cids" >&2; exit 1; }
    cat > "$stub/pod-noproxy.json" <<'EOF'
{"status": {"containerStatuses": [
  {"name": "user-container", "containerID": "containerd://fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}]}}
EOF
    if serving_cids "$stub/pod-noproxy.json" >/dev/null 2>&1; then
        echo "pod without queue-proxy accepted" >&2
        exit 1
    fi
    cat > "$stub/pod-badcid.json" <<'EOF'
{"status": {"containerStatuses": [
  {"name": "queue-proxy", "containerID": "containerd://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
  {"name": "user-container", "containerID": "docker://xyz"}]}}
EOF
    if serving_cids "$stub/pod-badcid.json" >/dev/null 2>&1; then
        echo "bad container id accepted" >&2
        exit 1
    fi
    # crictl pid: numeric only.
    cat > "$stub/docker" <<'EOF'
#!/bin/sh
printf '%s\n' "$STUB_PID"
EOF
    chmod +x "$stub/docker"
    [ "$(STUB_PID=4106 PATH="$stub:$PATH" crictl_pid node abcdef)" = 4106 ] \
        || { echo "node pid missed" >&2; exit 1; }
    if STUB_PID="nope" PATH="$stub:$PATH" crictl_pid node abcdef >/dev/null 2>&1; then
        echo "bad node pid accepted" >&2
        exit 1
    fi
    # Image-download dump: every running container's resolved digest lands in
    # facts; pods without statuses are skipped, never fatal.
    cat > "$stub/all-pods.json" <<'EOF'
{"items": [
  {"metadata": {"namespace": "knative-serving", "name": "controller-abc"},
   "status": {"containerStatuses": [
     {"name": "controller", "image": "gcr.io/knative/controller@sha256:aaaa", "imageID": "gcr.io/knative/controller@sha256:aaaa"}]}},
  {"metadata": {"namespace": "kourier-system", "name": "kourier-abc"},
   "status": {"containerStatuses": [
     {"name": "kourier", "image": "gcr.io/kourier@sha256:bbbb", "imageID": "gcr.io/kourier@sha256:bbbb"}]}},
  {"metadata": {"namespace": "p11scope-knative", "name": "pending"},
   "status": {}}]}
EOF
    : > "$stub/facts.txt"
    FACTS=$stub/facts.txt dump_pod_images "$stub/all-pods.json" \
        || { echo "image dump refused" >&2; exit 1; }
    grep -Fq 'image-download: knative-serving/controller-abc/controller gcr.io/knative/controller@sha256:aaaa gcr.io/knative/controller@sha256:aaaa' "$stub/facts.txt" \
        || { echo "controller image missing from facts" >&2; exit 1; }
    grep -Fq 'image-download: kourier-system/kourier-abc/kourier gcr.io/kourier@sha256:bbbb gcr.io/kourier@sha256:bbbb' "$stub/facts.txt" \
        || { echo "kourier image missing from facts" >&2; exit 1; }
    # Node image id: exactly one node image carries our tag; its id, verbatim.
    cat > "$stub/images.json" <<EOF
{"images": [{"id": "sha256:$good_sha", "repoTags": ["kind.local/p11scope-knative-holder:k3-t"],
  "repoDigests": []}]}
EOF
    [ "$(resolve_holder_id "$stub/images.json" kind.local/p11scope-knative-holder:k3-t)" \
        = "sha256:$good_sha" ] \
        || { echo "node image id missed" >&2; exit 1; }
    cat > "$stub/images-none.json" <<'EOF'
{"images": [{"id": "sha256:aaaa", "repoTags": ["docker.io/library/p11scope-knative-holder:k3-t"]}]}
EOF
    if resolve_holder_id "$stub/images-none.json" kind.local/p11scope-knative-holder:k3-t \
            >/dev/null 2>&1; then
        echo "untagged node image accepted" >&2
        exit 1
    fi
    cat > "$stub/images-two.json" <<EOF
{"images": [{"id": "sha256:$good_sha", "repoTags": ["kind.local/p11scope-knative-holder:k3-t"]},
  {"id": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
   "repoTags": ["kind.local/p11scope-knative-holder:k3-t"]}]}
EOF
    if resolve_holder_id "$stub/images-two.json" kind.local/p11scope-knative-holder:k3-t \
            >/dev/null 2>&1; then
        echo "ambiguous node images accepted" >&2
        exit 1
    fi
    cat > "$stub/images-badid.json" <<'EOF'
{"images": [{"id": "sha256:XYZ", "repoTags": ["kind.local/p11scope-knative-holder:k3-t"]}]}
EOF
    if resolve_holder_id "$stub/images-badid.json" kind.local/p11scope-knative-holder:k3-t \
            >/dev/null 2>&1; then
        echo "malformed node image id accepted" >&2
        exit 1
    fi
    # The running serving container must use that node image id.
    serving_image_is "sha256:$good_sha" "sha256:$good_sha" \
        || { echo "matching serving image refused" >&2; exit 1; }
    for bad_image in "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ""; do
        if serving_image_is "$bad_image" "sha256:$good_sha" >/dev/null 2>&1; then
            echo "foreign serving image accepted: $bad_image" >&2
            exit 1
        fi
    done
}

k3_ledger_fixture() {
    # $1 = complete (true|false), $2 = attempts, $3 = successful
    python3 - "$1" "$2" "$3" <<'PY'
import json, sys
complete, attempts, successful = sys.argv[1] == "true", int(sys.argv[2]), int(sys.argv[3])
names = ["C_GenerateRandom", "C_DigestInit", "C_Digest", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"]
print("LEDGER " + json.dumps({"schema": "p11scope/public-cli-ledger/v1", "pid": 7, "complete": complete,
      "functions": [{"name": n, "attempts": attempts, "successful": successful} for n in names]}))
PY
}

k3_check_self_test() {
    stub=$1
    # The HTTP response carries exactly one complete JSON ledger with 6xN.
    k3_ledger_fixture true 200 200 > "$stub/response.txt"
    response_ledger_is "$stub/response.txt" 200 \
        || { echo "good LEDGER response refused" >&2; exit 1; }
    k3_ledger_fixture false 200 200 > "$stub/r-incomplete.txt"
    k3_ledger_fixture true 199 199 > "$stub/r-short.txt"
    k3_ledger_fixture true 200 199 > "$stub/r-failed.txt"
    printf 'nothing here\n' > "$stub/r-missing.txt"
    { k3_ledger_fixture true 200 200; k3_ledger_fixture true 200 200; } > "$stub/r-two.txt"
    for bad in incomplete short failed missing two; do
        if response_ledger_is "$stub/r-$bad.txt" 200 >/dev/null 2>&1; then
            echo "bad LEDGER response accepted: $bad" >&2
            exit 1
        fi
    done
    # System-profile secondary: exact LEDGER total, zero loss, system scope,
    # nested observer; ambient rows break exactness (no silent merge).
    python3 - "$stub/system-good.json" <<'PY'
import json, sys
names = ["C_GenerateRandom", "C_DigestInit", "C_Digest", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"]
json.dump({
  "capture": {"scope": "system", "modules": [{"path": "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"}]},
  "evidence": {"attached_probes": 136, "event_loss": 0, "in_flight_at_end": 0,
    "verdict_detail": "concrete_gap",
    "pid_namespace": {"observer": "nested", "kernel_pids": "initial", "proc_pids": "observer"},
    "gap_classes": {"observation": {"causes": ["pid_namespace"], "status": "lossy"}}},
  "functions": [{"calls": 200, "errors": 0, "names": [n]} for n in names],
}, open(sys.argv[1], "w"))
PY
    got=$(profile_system_is "$stub/system-good.json" 200) \
        || { echo "good system profile refused" >&2; exit 1; }
    case $got in
        '{"check": "profile-system-exact", "ok": true'*) ;;
        *) echo "bad secondary result: $got" >&2; exit 1 ;;
    esac
    python3 - "$stub/system-good.json" "$stub" <<'PY'
import copy, json, sys
src, stub = sys.argv[1], sys.argv[2]
good = json.load(open(src))
def save(name, mutate):
    bad = copy.deepcopy(good)
    mutate(bad)
    json.dump(bad, open(f"{stub}/system-{name}.json", "w"))
save("scope", lambda d: d["capture"].update(scope="cgroup"))
save("loss", lambda d: d["evidence"].update(event_loss=1))
save("flight", lambda d: d["evidence"].update(in_flight_at_end=1))
save("short", lambda d: d["functions"][0].update(calls=100))
save("extra", lambda d: d["functions"].append({"calls": 1, "errors": 0, "names": ["C_Login"]}))
save("initial", lambda d: d["evidence"].update(
    pid_namespace={"observer": "initial", "kernel_pids": "initial", "proc_pids": "observer"},
    gap_classes={"observation": {"causes": [], "status": "exact"}}))
PY
    for bad in scope loss flight short extra initial; do
        if profile_system_is "$stub/system-$bad.json" 200 >/dev/null 2>&1; then
            echo "bad system profile accepted: $bad" >&2
            exit 1
        fi
    done
    # Failure twin: the dead serving PID is absent from callers with no stale
    # edge, and the twin capture itself was healthy (nested scope gap).
    python3 - "$stub/twin-good.json" <<'PY'
import json, sys
json.dump({"schema": "p11scope/inventory/v1",
  "callers": [{"id": "c0", "pid": 10}],
  "modules": [{"id": "m0", "paths": ["/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"]}],
  "edges": [{"caller": "c0", "module": "m0"}],
  "gaps": [{"subject": "pid namespace", "caller": None, "module": None, "pid": None}],
  "pid_namespace": {"observer": "nested", "kernel_pids": "initial", "proc_pids": "observer"},
}, open(sys.argv[1], "w"))
PY
    got=$(inventory_absent "$stub/twin-good.json" 4106) \
        || { echo "good twin refused" >&2; exit 1; }
    case $got in
        '{"check": "failure-twin-absent", "ok": true'*) ;;
        *) echo "bad twin result: $got" >&2; exit 1 ;;
    esac
    python3 - "$stub/twin-good.json" "$stub" <<'PY'
import copy, json, sys
src, stub = sys.argv[1], sys.argv[2]
good = json.load(open(src))
def save(name, mutate):
    bad = copy.deepcopy(good)
    mutate(bad)
    json.dump(bad, open(f"{stub}/twin-{name}.json", "w"))
save("present", lambda d: d["callers"].append({"id": "c1", "pid": 4106}))
save("stale", lambda d: (d["callers"].append({"id": "c1", "pid": 4106}),
                         d["edges"].append({"caller": "c1", "module": "m0"})))
save("gapless", lambda d: d.update(gaps=[]))
save("initial", lambda d: d.update(
    pid_namespace={"observer": "initial", "kernel_pids": "initial", "proc_pids": "observer"}, gaps=[]))
PY
    for bad in present stale gapless initial; do
        if inventory_absent "$stub/twin-$bad.json" 4106 >/dev/null 2>&1; then
            echo "bad twin accepted: $bad" >&2
            exit 1
        fi
    done
    k3_wake_self_test "$stub"
    k3_boundary_self_test "$stub"
}

k3_wake_self_test() {
    stub=$1
    # The wake answer is exactly "ready\n": any other body (or a ledger body,
    # which would mean the gate moved) refuses.
    printf 'ready\n' > "$stub/wake-good.txt"
    response_wake_is "$stub/wake-good.txt" \
        || { echo "good wake response refused" >&2; exit 1; }
    printf 'nope\n' > "$stub/wake-bad.txt"
    : > "$stub/wake-empty.txt"
    printf 'ready' > "$stub/wake-nonl.txt"
    printf 'ready\n\n' > "$stub/wake-extra.txt"
    k3_ledger_fixture true 200 200 > "$stub/wake-ledger.txt"
    for bad in bad empty nonl extra ledger; do
        if response_wake_is "$stub/wake-$bad.txt" >/dev/null 2>&1; then
            echo "bad wake response accepted: $bad" >&2
            exit 1
        fi
    done
    # The wake and the ledger share exactly one serving pod, or refusal.
    cat > "$stub/wake-pods.json" <<'EOF'
{"items": [{"metadata": {"name": "k3-00002-deployment-xyz"}, "status": {"phase": "Running"}}]}
EOF
    cp "$stub/wake-pods.json" "$stub/during-same.json"
    cat > "$stub/during-other.json" <<'EOF'
{"items": [{"metadata": {"name": "k3-00003-deployment-xyz"}, "status": {"phase": "Running"}}]}
EOF
    printf '{"items": []}' > "$stub/during-none.json"
    [ "$(same_serving_pod "$stub/wake-pods.json" "$stub/during-same.json")" \
        = k3-00002-deployment-xyz ] \
        || { echo "stable serving pod refused" >&2; exit 1; }
    for bad in other none; do
        if same_serving_pod "$stub/wake-pods.json" "$stub/during-$bad.json" \
                >/dev/null 2>&1; then
            echo "unstable serving pod accepted: $bad" >&2
            exit 1
        fi
    done
    if same_serving_pod "$stub/during-none.json" "$stub/during-same.json" \
            >/dev/null 2>&1; then
        echo "missing wake pod accepted" >&2
        exit 1
    fi
    # The attach window is the derived 15 s bound, slept exactly once.
    [ "$ATTACH_WAIT_S" = 15 ] \
        || { echo "attach wait is not the derived 15 s bound" >&2; exit 1; }
    cat > "$stub/sleep" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$STUB_CALLS"
EOF
    chmod +x "$stub/sleep"
    : > "$stub/sleep-calls.txt"
    STUB_CALLS=$stub/sleep-calls.txt PATH="$stub:$PATH" wait_attach_window \
        || { echo "attach wait refused" >&2; exit 1; }
    [ "$(cat "$stub/sleep-calls.txt")" = 15 ] \
        || { echo "attach wait did not sleep the bound" >&2; exit 1; }
}

k3_boundary_self_test() {
    stub=$1
    # R45: every well-formed bounded cold total reports a measured tail.
    # Missing rows are unobserved; repeated physical cells sum by name.
    # Loss, errors, excess counts and positive aliases refuse measurement
    # while retaining diagnostics. Malformed/unreadable data exits 1.
    python3 - "$stub/boundary-full.json" <<'PY'
import json, sys
names = ["C_GenerateRandom", "C_DigestInit", "C_Digest", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal"]
json.dump({
  "schema": "p11scope/observed-profile/v3", "lane": "profile", "capture": {"scope": "system"},
  "evidence": {"attached_probes": 136, "event_loss": 0, "in_flight_at_end": 0,
    "completeness": "PARTIAL", "pid_descendant_gaps": 262, "attach_gap_ms": None,
    "discovery_ring_loss": 0, "unprotected_live_windows": 0,
    "gap_classes": {"observation": {"causes": ["skipped", "pid_namespace", "pid_descendant_gaps"], "status": "lossy"}},
    "loader_discovery": {"dlopen_timing": {"unproven": 1}},
    "scheduling": {"newcomer_queue": {"admitted": 6, "max_admitted_age_ms": 25}}},
  "functions": [{"calls": 200, "errors": 0, "names": [n],
                 "target": {"object": None, "file_offset": i * 8}} for i, n in enumerate(names)],
}, open(sys.argv[1], "w"))
PY
    boundary_report "$stub/boundary-full.json" 200 > "$stub/bnd-full.txt" \
        || { echo "full boundary refused" >&2; exit 1; }
    k3_boundary_line_is "$stub/bnd-full.txt" "counted=1200 of 1200" \
        "newcomer_admitted=6" "attach_gap_ms=null" "classification=full" "measurement_valid=true"
    python3 - "$stub/boundary-full.json" "$stub" <<'PY'
import copy, json, sys
src, stub = sys.argv[1], sys.argv[2]
good = json.load(open(src))
def save(name, mutate):
    bad = copy.deepcopy(good)
    mutate(bad)
    json.dump(bad, open(f"{stub}/boundary-{name}.json", "w"))
save("empty", lambda d: [r.update(calls=0) for r in d["functions"]])
save("absent", lambda d: d.update(functions=[]))
save("tail", lambda d: [r.update(calls=14) for r in d["functions"]])
save("sparse", lambda d: d.update(functions=[{**d["functions"][0], "calls": 84}]))
save("short", lambda d: d["functions"][0].update(calls=100))
save("over", lambda d: d["functions"][0].update(calls=201))
save("extra", lambda d: d["functions"].append({"calls": 5, "errors": 0, "names": ["C_Login"]}))
save("ambient-alias", lambda d: d["functions"].append({"calls": 5, "errors": 0, "names": ["C_Login", "C_Logout"]}))
save("split", lambda d: (d["functions"][0].update(calls=100), d["functions"].append(copy.deepcopy(d["functions"][0]))))
save("aggregate-over", lambda d: d.update(functions=[{**d["functions"][0], "calls": 150},
                                                      {**d["functions"][0], "calls": 51}]))
save("alias", lambda d: d["functions"][0].update(names=["C_GenerateRandom", "C_Login"]))
save("zero-alias", lambda d: d["functions"][0].update(calls=0, names=["C_GenerateRandom", "C_Login"]))
save("gap-tail", lambda d: ([r.update(calls=14) for r in d["functions"]],
                            d["evidence"].update(in_flight_at_end=2, unprotected_live_windows=5, attach_gap_ms=11)))
save("event-loss", lambda d: ([r.update(calls=14) for r in d["functions"]], d["evidence"].update(event_loss=1)))
save("discovery-loss", lambda d: ([r.update(calls=14) for r in d["functions"]], d["evidence"].update(discovery_ring_loss=1)))
save("row-errors", lambda d: ([r.update(calls=14) for r in d["functions"]], d["functions"][0].update(errors=1)))
save("ambient-error", lambda d: d["functions"].append({"calls": 5, "errors": 1, "names": ["C_Login"]}))
for field in ("calls", "errors"):
    for label, value in (("negative", -1), ("string", "0"), ("boolean", True), ("float", 0.0), ("null", None)):
        save(f"{field}-{label}", lambda d, field=field, value=value: d["functions"][0].update({field: value}))
    save(f"missing-{field}", lambda d, field=field: d["functions"][0].pop(field))
for label, value in (("empty", []), ("string", "C_GenerateRandom"), ("null", None), ("number", [1])):
    save(f"names-{label}", lambda d, value=value: d["functions"][0].update(names=value))
save("missing-names", lambda d: d["functions"][0].pop("names"))
save("missing-functions", lambda d: d.pop("functions"))
save("functions-object", lambda d: d.update(functions={}))
save("functions-null", lambda d: d.update(functions=None))
save("wrong-schema", lambda d: d.update(schema="p11scope/observed-profile/v2"))
save("wrong-lane", lambda d: d.update(lane="metrics"))
save("wrong-scope", lambda d: d["capture"].update(scope="cgroup"))
save("missing-scheduling", lambda d: d["evidence"].pop("scheduling"))
save("bad-causes", lambda d: d["evidence"]["gap_classes"]["observation"].update(causes="pid_namespace"))
save("negative-loss", lambda d: d["evidence"].update(event_loss=-1))
save("bad-gap", lambda d: d["evidence"].update(attach_gap_ms=-1))
save("bad-age", lambda d: d["evidence"]["scheduling"]["newcomer_queue"].update(max_admitted_age_ms=False))
save("nan", lambda d: d.update(unused=float("nan")))
with open(f"{stub}/boundary-duplicate-field.json", "w") as output:
    output.write(json.dumps(good).replace('"calls": 200', '"calls": 100, "calls": 200', 1))
PY
    boundary_report "$stub/boundary-empty.json" 200 > "$stub/bnd-empty.txt" \
        || { echo "empty boundary refused" >&2; exit 1; }
    k3_boundary_line_is "$stub/bnd-empty.txt" "counted=0 of 1200" \
        "causes=pid_descendant_gaps,pid_namespace,skipped" "dlopen_unproven=1" "classification=none"
    boundary_report "$stub/boundary-tail.json" 200 > "$stub/bnd-tail.txt" \
        || { echo "approved cold tail 84/1200 refused" >&2; exit 1; }
    k3_boundary_line_is "$stub/bnd-tail.txt" "counted=84 of 1200" "classification=partial" "measurement_valid=true"
    boundary_report "$stub/boundary-extra.json" 200 > "$stub/bnd-extra.txt" \
        || { echo "boundary with ambient rows refused" >&2; exit 1; }
    k3_boundary_line_is "$stub/bnd-extra.txt" "counted=1200 of 1200" \
        "extra_rows=1 extra_calls=5"
    for good in absent sparse short ambient-alias split zero-alias gap-tail; do
        boundary_report "$stub/boundary-$good.json" 200 > "$stub/bnd-$good.txt" \
            || { echo "valid cold observation refused: $good" >&2; exit 1; }
        k3_boundary_line_is "$stub/bnd-$good.txt" "measurement_valid=true"
    done
    k3_boundary_line_is "$stub/bnd-absent.txt" "counted=0 of 1200" "classification=none"
    k3_boundary_line_is "$stub/bnd-sparse.txt" "counted=84 of 1200" "classification=partial"
    k3_boundary_line_is "$stub/bnd-short.txt" "counted=1100 of 1200" "classification=partial"
    k3_boundary_line_is "$stub/bnd-split.txt" "counted=1200 of 1200" "classification=full"
    k3_boundary_line_is "$stub/bnd-zero-alias.txt" "counted=1000 of 1200" "classification=partial"
    k3_boundary_line_is "$stub/bnd-gap-tail.txt" "in_flight=2" "unprotected_windows=5" "attach_gap_ms=11"
    for bad in over aggregate-over alias event-loss discovery-loss row-errors ambient-error; do
        status=0
        boundary_report "$stub/boundary-$bad.json" 200 > "$stub/bnd-$bad.txt" 2>/dev/null \
            || status=$?
        [ "$status" -eq 2 ] || {
            echo "invalid measurement exited $status (want 2): $bad" >&2
            exit 1
        }
        k3_boundary_line_is "$stub/bnd-$bad.txt" "measurement_valid=false"
    done
    k3_boundary_line_is "$stub/bnd-event-loss.txt" "event_loss=1"
    k3_boundary_line_is "$stub/bnd-discovery-loss.txt" "discovery_ring_loss=1"
    k3_boundary_line_is "$stub/bnd-row-errors.txt" "row_errors=1"
    k3_boundary_line_is "$stub/bnd-alias.txt" "ambiguous_rows=1" "extra_rows=1 extra_calls=200"
    for bad in event-loss discovery-loss row-errors; do
        k3_boundary_line_is "$stub/bnd-$bad.txt" "counted=84 of 1200" "classification=partial"
    done
    printf '{"no": "evidence"}\n' > "$stub/boundary-broken.json"
    for bad in broken absent-file calls-negative calls-string calls-boolean calls-float calls-null \
        errors-negative errors-string errors-boolean errors-float errors-null missing-calls missing-errors \
        names-empty names-string names-null names-number missing-names missing-functions functions-object \
        functions-null wrong-schema wrong-lane wrong-scope missing-scheduling bad-causes negative-loss \
        bad-gap bad-age nan duplicate-field; do
        status=0
        boundary_report "$stub/boundary-$bad.json" 200 > "$stub/bnd-$bad.txt" 2> "$stub/bnd-$bad.err" \
            || status=$?
        [ "$status" -eq 1 ] && [ ! -s "$stub/bnd-$bad.txt" ] && [ -s "$stub/bnd-$bad.err" ] || {
            echo "malformed boundary exited $status or lost its refusal diagnostic: $bad" >&2
            exit 1
        }
    done
    # Exercise the same recording/failure seam used after the real capture.
    # The three seeded gated results must remain three on every cold report.
    for case in full empty absent tail sparse extra split zero-alias gap-tail over aggregate-over alias \
        event-loss discovery-loss row-errors ambient-error broken absent-file; do
        status=0
        (
            FACTS=$stub/driver-$case.facts
            SUMMARY_JSONL=$stub/driver-$case.jsonl
            : > "$FACTS"
            printf '%s\n' '{"check": "primary", "ok": true}' \
                '{"check": "warm", "ok": true}' '{"check": "twin", "ok": true}' > "$SUMMARY_JSONL"
            record_boundary_report "$stub/boundary-$case.json" 200
        ) > "$stub/driver-$case.out" 2> "$stub/driver-$case.err" || status=$?
        case $case in
            over|aggregate-over|alias|event-loss|discovery-loss|row-errors|ambient-error)
                [ "$status" -eq 1 ] || { echo "driver accepted invalid measurement: $case" >&2; exit 1; }
                head -n 2 "$stub/driver-$case.out" > "$stub/driver-$case.boundary"
                k3_boundary_line_is "$stub/driver-$case.boundary" "measurement_valid=false"
                grep -Fq 'verdict=FAIL' "$stub/driver-$case.facts" \
                    || { echo "driver lost its measurement failure: $case" >&2; exit 1; }
                ;;
            broken|absent-file)
                [ "$status" -eq 1 ] || { echo "driver accepted missing shape: $case" >&2; exit 1; }
                ;;
            *)
                [ "$status" -eq 0 ] || { echo "driver refused measured cold tail: $case" >&2; exit 1; }
                k3_boundary_line_is "$stub/driver-$case.out" "measurement_valid=true"
                ;;
        esac
        [ "$(grep -c '"ok": true' "$stub/driver-$case.jsonl")" -eq 3 ] \
            || { echo "cold report changed the three gated checks: $case" >&2; exit 1; }
    done
}

# The boundary output shape: line 1 is the BOUNDARY line carrying each named
# field; line 2 is the record-only JSON, which must never carry "ok": true
# (the gated count stays exactly 3).
k3_boundary_line_is() {
    bl_out=$1
    [ "$(wc -l < "$bl_out")" = 2 ] || { echo "boundary printed no JSON line" >&2; exit 1; }
    head -n 1 "$bl_out" | grep -Fq "BOUNDARY k3-cold-start " \
        || { echo "boundary line lost its marker" >&2; exit 1; }
    shift
    for bl_want in "$@"; do
        head -n 1 "$bl_out" | grep -Fq "$bl_want" \
            || { echo "boundary line lost its field: $bl_want" >&2; exit 1; }
    done
    bl_json=$(tail -n 1 "$bl_out")
    case $bl_json in
        '{"check": "boundary-k3-cold-start", "record_only": true'*) ;;
        *) echo "bad boundary JSON: $bl_json" >&2; exit 1 ;;
    esac
    case $bl_json in
        *'"ok": true'*) echo "boundary JSON counts as a gated check" >&2; exit 1 ;;
    esac
    python3 -I - "$bl_json" <<'PY'
import json, sys
report = json.loads(sys.argv[1])
assert report["record_only"] is True and "ok" not in report
assert report["classification"] in ("full", "none", "partial")
assert report["limitation"] == "cold-first-request-observed-tail"
assert report["measurement_valid"] is (not report["measurement_failures"])
PY
}

k3_sequencing_self_test() {
    stub=$1
    # The deterministic secondary's mid-capture requests in order — wake (no
    # gate release), one pod proven, attach window waited, ledger run, same
    # pod proven — against stub curl/kubectl/sleep. Dropping the wake, the
    # wait, or any gate below breaks the order/wait/identity assertions.
    seq=$stub/seq
    mkdir -p "$seq/work"
    printf 'ready\n' > "$seq/wake-body.txt"
    printf 'nope\n' > "$seq/wake-bad.txt"
    k3_ledger_fixture true 200 200 > "$seq/ledger-body.txt"
    k3_ledger_fixture false 200 200 > "$seq/ledger-bad.txt"
    cat > "$seq/pods-a.json" <<'EOF'
{"items": [{"metadata": {"name": "k3-00002-deployment-xyz"}, "status": {"phase": "Running"}}]}
EOF
    cat > "$seq/pods-b.json" <<'EOF'
{"items": [{"metadata": {"name": "k3-00003-deployment-xyz"}, "status": {"phase": "Running"}}]}
EOF
    printf '{"items": []}' > "$seq/pods-none.json"
    cat > "$stub/curl" <<'EOF'
#!/bin/sh
[ -z "${STUB_CURL_FAIL-}" ] || exit 7
out= prev= url=
for arg in "$@"; do
    if [ "$prev" = "-o" ]; then out=$arg; fi
    case $arg in http://*) url=$arg ;; esac
    prev=$arg
done
case $url in
    */ledger) printf '/ledger\n' >> "$STUB_ORDER"; cat "$STUB_LEDGER" > "$out" ;;
    */) printf '/\n' >> "$STUB_ORDER"; cat "$STUB_WAKE" > "$out" ;;
    *) echo "unexpected url: $url" >&2; exit 1 ;;
esac
EOF
    cat > "$stub/kubectl" <<'EOF'
#!/bin/sh
[ -z "${STUB_KUBECTL_FAIL-}" ] || exit 1
n=$(cat "$STUB_COUNT")
printf '%s' "$((n + 1))" > "$STUB_COUNT"
if [ "$n" -eq 0 ]; then cat "$STUB_PODS_1"; else cat "$STUB_PODS_2"; fi
EOF
    cat > "$stub/sleep" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$STUB_SLEEP"
EOF
    chmod +x "$stub/curl" "$stub/kubectl" "$stub/sleep"
    k3_seq_env() {
        printf '0' > "$stub/seq-count.txt"
        : > "$stub/seq-order.txt"; : > "$stub/seq-sleep.txt"
        rm -rf "$seq/work"; mkdir -p "$seq/work"
        : > "$seq/facts.txt"
    }
    k3_seq_env
    got=$(
        FACTS=$seq/facts.txt HOST=example.invalid PF_PORT=18080 \
        KSVC=p11scope-k3 KNS=p11scope-knative ITERS=200 WORK=$seq/work \
        STUB_ORDER=$stub/seq-order.txt STUB_SLEEP=$stub/seq-sleep.txt \
        STUB_WAKE=$seq/wake-body.txt STUB_LEDGER=$seq/ledger-body.txt \
        STUB_PODS_1=$seq/pods-a.json STUB_PODS_2=$seq/pods-a.json \
        STUB_COUNT=$stub/seq-count.txt PATH="$stub:$PATH" \
        deterministic_requests
    ) || { echo "deterministic requests refused" >&2; exit 1; }
    [ "$got" = k3-00002-deployment-xyz ] \
        || { echo "wrong stable pod: $got" >&2; exit 1; }
    [ "$(cat "$stub/seq-order.txt")" = "$(printf '/\n/ledger')" ] \
        || { echo "wake/wait/ledger order lost" >&2; exit 1; }
    [ "$(cat "$stub/seq-sleep.txt")" = 15 ] \
        || { echo "attach wait lost" >&2; exit 1; }
    grep -Fq 'wake-response=ready' "$seq/facts.txt" \
        || { echo "wake response missing from facts" >&2; exit 1; }
    grep -Fq 'ledger-response[response-secondary.txt]=LEDGER ' "$seq/facts.txt" \
        || { echo "ledger response missing from facts" >&2; exit 1; }
    # Each gate fails the run named: the wake request, the wake body, the
    # pod listings, the pod identity, and the ledger body after the wake.
    k3_seq_fails() {
        # $1 = variant name, $2 = SUMMARY reason, $3 = wake body key,
        # $4 = ledger body key, $5/$6 = pod listing keys, rest = VAR=val
        sq_name=$1 sq_reason=$2 sq_wake=$3 sq_ledger=$4 sq_p1=$5 sq_p2=$6
        shift 6
        k3_seq_env
        status=0
        ( for sq_var in "$@"; do export "$sq_var"; done
          FACTS=$seq/facts.txt HOST=example.invalid PF_PORT=18080 \
          KSVC=p11scope-k3 KNS=p11scope-knative ITERS=200 WORK=$seq/work \
          STUB_ORDER=$stub/seq-order.txt STUB_SLEEP=$stub/seq-sleep.txt \
          STUB_WAKE=$seq/$sq_wake.txt STUB_LEDGER=$seq/$sq_ledger.txt \
          STUB_PODS_1=$seq/pods-$sq_p1.json STUB_PODS_2=$seq/pods-$sq_p2.json \
          STUB_COUNT=$stub/seq-count.txt PATH="$stub:$PATH" \
          deterministic_requests ) >"$seq/fail-$sq_name.txt" 2>&1 || status=$?
        [ "$status" -eq 1 ] || {
            echo "sequencing accepted $sq_name (exit $status)" >&2
            exit 1
        }
        grep -Fq "$sq_reason" "$seq/fail-$sq_name.txt" \
            || { echo "$sq_name failed unnamed" >&2; exit 1; }
    }
    k3_seq_fails wake-request 'wake request to the service failed' \
        wake-body ledger-body a a STUB_CURL_FAIL=1
    k3_seq_fails wake-body 'wake response is not exactly ready' \
        wake-bad ledger-body a a
    k3_seq_fails pods-list 'cannot list serving pods after wake' \
        wake-body ledger-body a a STUB_KUBECTL_FAIL=1
    k3_seq_fails pod-stable 'wake and ledger did not share one serving pod' \
        wake-body ledger-body a b
    k3_seq_fails pods-none 'wake and ledger did not share one serving pod' \
        wake-body ledger-body a none
    k3_seq_fails ledger-body 'response is not exactly one 6x200 ledger' \
        wake-body ledger-bad a a
}

k3_cleanup_self_test() {
    stub=$1
    # Cleanup deletes its own cluster and images, nothing else.
    cat > "$stub/kind" <<'EOF'
#!/bin/sh
printf '%s\n' "kind $*" >> "$STUB_CALLS"
EOF
    cat > "$stub/docker" <<'EOF'
#!/bin/sh
printf '%s\n' "docker $*" >> "$STUB_CALLS"
EOF
    chmod +x "$stub/kind" "$stub/docker"
    : > "$stub/calls.txt"
    STUB_CALLS=$stub/calls.txt PATH="$stub:$PATH" \
        CLUSTER=p11scope-k3-t KUBECONFIG=$stub/kubeconfig \
        OBS_IMAGE=obs:t KNATIVE_IMAGE=kn:t cleanup_owned \
        || { echo "cleanup_owned failed" >&2; exit 1; }
    grep -Fq "kind delete cluster --name p11scope-k3-t --kubeconfig $stub/kubeconfig" "$stub/calls.txt" \
        || { echo "cleanup lost its cluster deletion" >&2; exit 1; }
    grep -Fq "docker image rm -f obs:t kn:t" "$stub/calls.txt" \
        || { echo "cleanup lost its image removal" >&2; exit 1; }
}

k3_server_self_test() {
    stub=$(mktemp -d "${TMPDIR:-/tmp}/p11scope-k3-server-XXXXXX")
    # shellcheck disable=SC2064
    trap "rm -rf '$stub'" EXIT
    # The embedded handler, exercised for real: a fake gated client waits for
    # the gate file the handler creates, then appends its LEDGER line.
    server_block > "$stub/server.py"
    k3_ledger_fixture true 200 200 > "$stub/ledger.txt"
    cat > "$stub/fake-gated.sh" <<EOF
#!/bin/sh
while [ ! -e "$stub/gate" ]; do sleep 0.05; done
printf 'READY pid=99\n' >> "$stub/gated.log"
cat "$stub/ledger.txt" >> "$stub/gated.log"
EOF
    chmod +x "$stub/fake-gated.sh"
    "$stub/fake-gated.sh" &
    fake_pid=$!
    port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    PORT=$port K3_GATE=$stub/gate K3_LEDGER_LOG=$stub/gated.log K3_RAN=$stub/ran \
        K3_LEDGER_TIMEOUT_S=10 python3 "$stub/server.py" &
    server_pid=$!
    sleep 1
    if ! kill -0 "$server_pid" 2>/dev/null; then
        echo "embedded server did not start" >&2
        kill "$fake_pid" 2>/dev/null || true
        exit 1
    fi
    status=0
    K3_PORT=$port K3_GATE=$stub/gate K3_LEDGER=$(cat "$stub/ledger.txt") python3 - <<'PY' || status=$?
import os, urllib.request, urllib.error
base = f"http://127.0.0.1:{os.environ['K3_PORT']}"
want = os.environ["K3_LEDGER"]
with urllib.request.urlopen(base + "/", timeout=20) as response:
    assert response.status == 200, response.status
    assert response.read() == b"ready\n"
assert not os.path.exists(os.environ["K3_GATE"]), "the wake request touched the gate"
with urllib.request.urlopen(base + "/ledger", timeout=20) as response:
    assert response.status == 200, response.status
    assert response.read().decode() == want + "\n", "ledger body differs"
try:
    urllib.request.urlopen(base + "/ledger", timeout=20)
except urllib.error.HTTPError as exc:
    assert exc.code == 500, exc.code
else:
    raise SystemExit("second ledger run accepted")
PY
    kill "$server_pid" "$fake_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    wait "$fake_pid" 2>/dev/null || true
    [ "$status" -eq 0 ] || { echo "embedded server behaved wrongly" >&2; exit 1; }
    [ -e "$stub/gate" ] || { echo "handler never created the gate" >&2; exit 1; }
    grep -Fq "$(cat "$stub/ledger.txt")" "$stub/gated.log" \
        || { echo "fake gated never ran" >&2; exit 1; }
    rm -rf "$stub"
    trap - EXIT
}

TOKEN=
WORK_OPT=
ITERS=$ITERS_DEFAULT
KEEP=0

while [ "$#" -gt 0 ]; do
    case $1 in
        --self-test) [ "$#" -eq 1 ] || usage; self_test ;;
        -h|--help) usage ;;
        --token) [ "$#" -ge 2 ] || usage; [ -z "$TOKEN" ] || usage; TOKEN=$2; shift 2 ;;
        --work) [ "$#" -ge 2 ] || usage; [ -z "$WORK_OPT" ] || usage; WORK_OPT=$2; shift 2 ;;
        --iters) [ "$#" -ge 2 ] || usage; ITERS=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

[ -z "$TOKEN" ] || valid_token "$TOKEN" || usage
TOKEN=${TOKEN:-$(date +%s)-$$}
valid_token "$TOKEN" || usage
valid_count "$ITERS" || usage

. scripts/lib.sh
require_non_root_caller || unrun "run as a non-root user with passwordless sudo"
[ "$(uname -m)" = x86_64 ] || unrun "the images are x86-64 only"
for command in docker kind kubectl python3 timeout curl sha256sum awk grep stat cmp; do
    command -v "$command" >/dev/null || unrun "$command required"
done

CLUSTER=${P11SCOPE_KNATIVE_CLUSTER:-p11scope-k3-$TOKEN}
case $CLUSTER in
    ''|*[!a-z0-9-]*|-*|*-) echo "cluster name must be a DNS label: $CLUSTER" >&2; exit 2 ;;
esac
# The kind node is "$CLUSTER-control-plane" (14 more chars), still a DNS label.
[ "${#CLUSTER}" -le 49 ] || { echo "cluster name too long: $CLUSTER" >&2; exit 2; }
NODE=$CLUSTER-control-plane
TOOLCHAIN=${P11SCOPE_KNATIVE_TOOLCHAIN:-$(cat .release-rust-version)}
OBSERVER_BIN=${P11SCOPE_KNATIVE_OBSERVER_BIN:-}
LOCK=${P11SCOPE_KNATIVE_LOCK:-}
[ -z "$LOCK" ] || command -v flock >/dev/null || { echo "flock required for P11SCOPE_KNATIVE_LOCK" >&2; exit 2; }
OBS_IMAGE=p11scope-observer:k3-$TOKEN
KNATIVE_IMAGE=kind.local/p11scope-knative-holder:k3-$TOKEN
prepare_work || exit 2
FACTS=$WORK/facts.log
SUMMARY_JSONL=$WORK/summary.jsonl
: >"$FACTS"
: >"$SUMMARY_JSONL"
CLUSTER_CREATED=
IMAGES_BUILT=
CAPTURE_PIDS=
PF_PID=

cleanup() {
    CLEANUP_STATUS=$?
    trap - EXIT INT TERM
    set +e
    for capture_pid in ${CAPTURE_PIDS-}; do
        kill "$capture_pid" 2>/dev/null
    done
    unlock_step 2>/dev/null
    if [ -n "$CLUSTER_CREATED" ] && [ "$KEEP" -eq 1 ]; then
        echo "kept cluster $CLUSTER (--keep): KUBECONFIG=$KUBECONFIG" >&2
        echo "the KService and Knative die with the cluster; to remove them alone:" >&2
        echo "kubectl delete -f $WORK/releases/kourier.yaml -f $WORK/releases/serving-core.yaml -f $WORK/releases/serving-crds.yaml" >&2
        echo "delete with: kind delete cluster --name $CLUSTER --kubeconfig $KUBECONFIG" >&2
        echo "delete with: docker image rm -f $OBS_IMAGE $KNATIVE_IMAGE" >&2
    elif [ -n "$CLUSTER_CREATED" ]; then
        lock_step
        cleanup_step timeout --signal=TERM --kill-after=10s 300s \
            kind delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG"
        unlock_step
    fi
    if [ -n "$IMAGES_BUILT" ] && [ "$KEEP" -eq 0 ]; then
        cleanup_step docker image rm -f "$OBS_IMAGE" "$KNATIVE_IMAGE" >/dev/null
    fi
    echo "evidence directory: $WORK" >&2
    exit "$CLEANUP_STATUS"
}
. scripts/cleanup-traps.sh

observe() {
    kc -n "$OBS_NS" exec "$OBS" -- "$@"
}

# wait_ready NAME PID: the capture's stderr must name readiness while the
# local kubectl exec still lives.
wait_ready() {
    wr_i=0
    while [ "$wr_i" -lt 360 ]; do
        grep -q 'p11scope: capturing:' "$WORK/$1.err" 2>/dev/null && return 0
        kill -0 "$2" 2>/dev/null || break
        sleep 0.5
        wr_i=$((wr_i + 1))
    done
    echo "capture $1 never became ready" >&2
    cat "$WORK/$1.err" >&2
    return 1
}

start_port_forward() {
    PF_PORT=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    case $PF_PORT in ''|*[!0-9]*) fail_cell "no free port for the port-forward" ;; esac
    # Plain kubectl, not the timeout-wrapped kc: the forward outlives the 300 s
    # call budget (primary, scale-to-zero waits, secondary) and dies by explicit
    # kill plus the cleanup trap.
    kubectl port-forward -n kourier-system svc/kourier-internal "$PF_PORT:80" >"$WORK/pf.log" 2>&1 &
    PF_PID=$!
    CAPTURE_PIDS="$CAPTURE_PIDS $PF_PID"
    wait_pf_ready "$PF_PORT" 60 || fail_cell "port-forward never became ready"
    fact "port-forward=127.0.0.1:$PF_PORT -> kourier-internal:80"
}

# Resolve the live serving pod and its node PIDs. No capture may be running:
# crictl runs through docker exec in the node.
resolve_serving() {
    kc get pods -l "serving.knative.dev/service=$KSVC" -n "$KNS" -o json > "$WORK/serving-pods.json" \
        || fail_cell "cannot list serving pods"
    SERVING_POD=$(serving_pod "$WORK/serving-pods.json") || fail_cell "no single serving pod"
    kc get pod "$SERVING_POD" -n "$KNS" -o json > "$WORK/serving-pod.json" \
        || fail_cell "cannot describe $SERVING_POD"
    cids=$(serving_cids "$WORK/serving-pod.json") || fail_cell "cannot select serving containers"
    SERVING_CID=$(printf '%s\n' "$cids" | sed -n '1p')
    PROXY_CID=$(printf '%s\n' "$cids" | sed -n '2p')
    SERVING_IMAGE=$(docker exec "$NODE" crictl inspect -o go-template --template '{{.status.imageRef}}' "$SERVING_CID") \
        || fail_cell "cannot read the serving container image"
    serving_image_is "$SERVING_IMAGE" "$HOLDER_ID" || fail_cell "serving container image is not the loaded holder"
    SERVING_PID=$(crictl_pid "$NODE" "$SERVING_CID") || fail_cell "no node pid for the serving container"
    PROXY_PID=$(crictl_pid "$NODE" "$PROXY_CID") || fail_cell "no node pid for queue-proxy"
    fact "serving-pod=$SERVING_POD serving-pid=$SERVING_PID proxy-pid=$PROXY_PID"
}

refuse_existing_cluster "$CLUSTER" || unrun "cluster $CLUSTER already exists"

fact "cell=K3 token=$TOKEN date=$(date -u +%Y-%m-%dT%H:%M:%SZ) iters=$ITERS"
fact "knative=$KNATIVE_VERSION"
fact "kernel=$(uname -sr) $(uname -m)"
# {{.ServerVersion}}: the nested {{.Server.Version}} form is wrong on Docker
# 29.8.1 (first D1 runs).
docker_info=$(docker info --format '{{.Driver}} {{.ServerVersion}}' 2>/dev/null) \
    || unrun "docker info failed"
fact "docker-info=$docker_info"
fact "cgroup-driver=$(docker info --format '{{.CgroupDriver}}' 2>/dev/null || echo unknown)"
docker_root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null) \
    || unrun "docker info failed"
fact "docker-root=$docker_root backing-fs=$(stat -f -c '%T' "$docker_root" 2>/dev/null || echo unknown)"
fact "kind-version=$(kind version 2>/dev/null || echo unknown)"
fact "kubectl-version=$(kubectl version --client 2>/dev/null | head -n 1 || echo unknown)"

if [ -z "$OBSERVER_BIN" ]; then
    say "=== build the static observer (cargo +$TOOLCHAIN, x86_64-unknown-linux-musl) ==="
    command -v musl-gcc >/dev/null || unrun "musl-gcc required (musl-tools)"
    SYSROOT=$(rustc "+$TOOLCHAIN" --print sysroot 2>/dev/null) \
        || unrun "toolchain $TOOLCHAIN is not installed"
    [ -d "$SYSROOT/lib/rustlib/x86_64-unknown-linux-musl" ] \
        || unrun "toolchain $TOOLCHAIN has no x86_64-unknown-linux-musl target"
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
        timeout --signal=TERM --kill-after=10s 3600s scripts/cargo.sh "+$TOOLCHAIN" build \
        --locked --release --no-default-features \
        --target x86_64-unknown-linux-musl --bin p11scope \
        || fail_cell "static observer build failed"
    OBSERVER_BIN=target/x86_64-unknown-linux-musl/release/p11scope
fi
[ -x "$OBSERVER_BIN" ] || unrun "observer $OBSERVER_BIN is not an executable"

say "=== stage minimal build contexts ==="
OCTX=$WORK/context-observer
HCTX=$WORK/context-knative
mkdir -p "$OCTX/target/x86_64-unknown-linux-musl/release" "$OCTX/scripts" \
    "$HCTX/tests/fixtures/public-cli"
cp "$OBSERVER_BIN" "$OCTX/target/x86_64-unknown-linux-musl/release/p11scope"
cp scripts/k8s-profile-entry.sh "$OCTX/scripts/"
cp tests/fixtures/public-cli/gated.c "$HCTX/tests/fixtures/public-cli/"
sha256sum "$OBSERVER_BIN" | tee "$WORK/observer.sha256"

say "=== build images $OBS_IMAGE $KNATIVE_IMAGE ==="
lock_step
IMAGES_BUILT=1
timeout --signal=TERM --kill-after=10s 1200s \
    docker build -q -f deploy/Dockerfile.observer -t "$OBS_IMAGE" "$OCTX" \
    || fail_cell "observer image build failed"
timeout --signal=TERM --kill-after=10s 1200s \
    docker build -q -f "$KNATIVE_DOCKERFILE" -t "$KNATIVE_IMAGE" "$HCTX" \
    || fail_cell "knative holder image build failed"
unlock_step
fact "observer-image=$OBS_IMAGE id=$(docker inspect --format '{{.Id}}' "$OBS_IMAGE" || echo unknown)"
fact "holder-image=$KNATIVE_IMAGE id=$(docker inspect --format '{{.Id}}' "$KNATIVE_IMAGE" || echo unknown)"
fact "base-image=$HOLDER_BASE (both stages of $KNATIVE_DOCKERFILE; apt packages float)"
# The apt packages float with the archive: record what this build resolved.
HOLDER_APT=$(docker run --rm --entrypoint dpkg-query "$KNATIVE_IMAGE" \
    -W -f '${Package}=${Version} ' softhsm2 python3) \
    || fail_cell "cannot read the holder image apt versions"
fact "holder-apt=$HOLDER_APT"
fact "observer-base-image=$(grep '^FROM ' deploy/Dockerfile.observer | head -n 1) (no apk installs there)"

say "=== create kind cluster $CLUSTER (private kubeconfig) ==="
lock_step
# Set before create: a create killed half-way must still be deleted. The name
# was proven unused above and carries this run's token by default.
CLUSTER_CREATED=1
timeout --signal=TERM --kill-after=10s 900s kind create cluster --name "$CLUSTER" \
    --kubeconfig "$KUBECONFIG" --wait 180s \
    ${P11SCOPE_KNATIVE_NODE_IMAGE:+--image "$P11SCOPE_KNATIVE_NODE_IMAGE"} \
    || fail_cell "kind cluster creation failed"
unlock_step
fact "node-image-ref=$(docker inspect --format '{{.Config.Image}}' "$NODE" || echo unknown)"
fact "node-image-id=$(docker inspect --format '{{.Image}}' "$NODE" || echo unknown)"
lock_step
timeout --signal=TERM --kill-after=10s 1200s \
    kind load docker-image --name "$CLUSTER" "$OBS_IMAGE" "$KNATIVE_IMAGE" \
    || fail_cell "kind load failed"
unlock_step

say "=== install Knative $KNATIVE_VERSION (sha256-verified) ==="
mkdir -p "$WORK/releases"
for yaml in serving-crds.yaml serving-core.yaml kourier.yaml; do
    download_release "$(knative_url "$yaml")" "$yaml" "$WORK/releases/$yaml" \
        || fail_cell "$yaml download or sha256 verification failed"
    fact "release=$yaml url=$(knative_url "$yaml") sha256=$(knative_pin "$yaml")"
done
kc apply -f "$WORK/releases/serving-crds.yaml" >"$WORK/apply-crds.log" 2>&1 \
    || fail_cell "serving-crds apply failed"
kc apply -f "$WORK/releases/serving-core.yaml" >"$WORK/apply-core.log" 2>&1 \
    || fail_cell "serving-core apply failed"
kc apply -f "$WORK/releases/kourier.yaml" >"$WORK/apply-kourier.log" 2>&1 \
    || fail_cell "kourier apply failed"
kc patch configmap/config-network -n knative-serving --type merge \
    -p '{"data":{"ingress-class":"kourier.ingress.networking.knative.dev"}}' \
    || fail_cell "config-network ingress patch failed"
kc wait --for=condition=Available deployment --all -n knative-serving --timeout=180s \
    || fail_cell "knative-serving never became Available"
kc wait --for=condition=Available deployment --all -n kourier-system --timeout=180s \
    || fail_cell "kourier-system never became Available"

say "=== record every image the install references ==="
kc get pods -A -o json > "$WORK/pods-all.json" || fail_cell "cannot list cluster pods"
dump_pod_images "$WORK/pods-all.json" || fail_cell "cannot dump pod images"
fact "downloads: 3 Knative YAMLs (release lines above) + kind node image (node-image lines above) + every image-download line above + base $HOLDER_BASE"

say "=== apply the KService by its kind.local tag (node image id recorded) ==="
docker exec "$NODE" crictl images -o json > "$WORK/node-images.json" \
    || fail_cell "cannot list node images"
HOLDER_ID=$(resolve_holder_id "$WORK/node-images.json" "$KNATIVE_IMAGE") \
    || fail_cell "no single node image for $KNATIVE_IMAGE"
fact "holder-node-image-id=$HOLDER_ID"
docker exec "$NODE" crictl inspecti "$HOLDER_ID" >/dev/null \
    || fail_cell "node does not resolve $HOLDER_ID"
render_ksvc "$KNATIVE_KSVC" "$WORK/knative-service.yaml" "$KNATIVE_IMAGE" \
    || fail_cell "kservice render failed"
kc apply -f "$WORK/knative-service.yaml" || fail_cell "kservice apply failed"
kc wait --for=condition=Ready "ksvc/$KSVC" -n "$KNS" --timeout=180s \
    || fail_cell "kservice never became Ready"
HOST=$(kc get "ksvc/$KSVC" -n "$KNS" -o jsonpath='{.status.url}' | sed 's#http://##') \
    || fail_cell "cannot read kservice url"
case $HOST in ''|*[!a-zA-Z0-9.:-]*) fail_cell "bad kservice host: $HOST" ;; esac
fact "kservice-host=$HOST"
say "=== prove the service scaled to zero ==="
wait_scale_zero "$KSVC" "$KNS" 180 || fail_cell "service never scaled to zero"

say "=== apply deploy/k8s as documented (directory apply; image names rendered) ==="
render_daemonset deploy/k8s "$WORK/manifests" "$OBS_IMAGE" || fail_cell "daemonset render failed"
kc apply -f "$WORK/manifests/" || fail_cell "daemonset apply failed"
kc -n "$OBS_NS" rollout status daemonset/p11scope-observer --timeout=240s \
    || fail_cell "observer rollout failed"
OBS=$(kc -n "$OBS_NS" get pod -l app.kubernetes.io/component=observer -o jsonpath='{.items[0].metadata.name}')
[ -n "$OBS" ] || fail_cell "no observer pod"
fact "observer-pod=$OBS"

say "=== primary: one request, inventory while the pod lives ==="
lock_step
start_port_forward
request_ledger "$WORK/response-primary.txt"
resolve_serving
observe p11scope inventory --system --caller-metadata none -o /tmp/k3-primary.json \
    >"$WORK/primary.out" 2>"$WORK/primary.err" \
    || { cat "$WORK/primary.err" >&2; fail_cell "primary inventory failed"; }
kc -n "$OBS_NS" cp "$OBS:/tmp/k3-primary.json" "$WORK/k3-primary.json" >/dev/null \
    || fail_cell "cannot fetch the primary inventory"
unlock_step
kc get pod "$SERVING_POD" -n "$KNS" -o jsonpath='{.status.phase}' 2>/dev/null | grep -qx Running \
    || fail_cell "serving pod $SERVING_POD died during the primary inventory"
RESULT=$(python3 -I "$ORACLE" --expect-observer nested inventory "$WORK/k3-primary.json" \
    --caller "$SERVING_PID" --non-caller "$PROXY_PID") || fail_cell "primary oracle refused"
record "$RESULT"
PRIMARY_PID=$SERVING_PID

say "=== scale back to zero ==="
wait_scale_zero "$KSVC" "$KNS" 180 || fail_cell "service never scaled back to zero"

say "=== secondary: system profile spanning one woken request ==="
lock_step
kc -n "$OBS_NS" exec "$OBS" -- p11scope profile --system --duration "$PROFILE_SECONDS" \
    -o /tmp/k3-system.json >"$WORK/system.out" 2>"$WORK/system.err" &
SEC_PID=$!
CAPTURE_PIDS="$CAPTURE_PIDS $SEC_PID"
wait_ready system "$SEC_PID" || fail_cell "system profile never became ready"
# The requests and the API reads below are the only mid-capture contact: the
# curls run on the host (invisible to the node observer) and no exec enters
# any container while the capture runs.
deterministic_requests > "$WORK/secondary-pod.txt"
fact "secondary-pod=$(cat "$WORK/secondary-pod.txt")"
# The ledger must finish while the capture still runs: a window miss is a
# named harness failure, never a silent 0-count.
kill -0 "$SEC_PID" 2>/dev/null || fail_cell "system profile ended before the ledger request finished"
fact "serving-during=$(python3 -I -c 'import json,sys; print(sorted(i["metadata"]["name"] for i in json.load(open(sys.argv[1]))["items"]))' "$WORK/serving-during.json")"
wait "$SEC_PID" || fail_cell "system profile failed"
kc -n "$OBS_NS" cp "$OBS:/tmp/k3-system.json" "$WORK/k3-system.json" >/dev/null \
    || fail_cell "cannot fetch the system profile"
unlock_step
RESULT=$(profile_system_is "$WORK/k3-system.json" "$ITERS") || fail_cell "secondary oracle refused"
record "$RESULT"

say "=== scale back to zero ==="
wait_scale_zero "$KSVC" "$KNS" 180 || fail_cell "service never scaled to zero after the secondary"

say "=== boundary: cold-first-request profile (reported only) ==="
lock_step
kc -n "$OBS_NS" exec "$OBS" -- p11scope profile --system --duration "$PROFILE_SECONDS" \
    -o /tmp/k3-boundary.json >"$WORK/boundary.out" 2>"$WORK/boundary.err" &
BND_PID=$!
CAPTURE_PIDS="$CAPTURE_PIDS $BND_PID"
wait_ready boundary "$BND_PID" || fail_cell "boundary profile never became ready"
# This ledger request is the pod's first: the scale-from-zero race, measured
# and reported, never gated. Host-side curl plus API reads only, as above.
request_ledger "$WORK/response-boundary.txt"
kill -0 "$BND_PID" 2>/dev/null || fail_cell "boundary profile ended before the ledger request finished"
kc get pods -l "serving.knative.dev/service=$KSVC" -n "$KNS" -o json > "$WORK/serving-boundary.json" \
    || fail_cell "cannot list serving pods mid-capture"
BND_POD=$(serving_pod "$WORK/serving-boundary.json") || fail_cell "no single boundary pod"
fact "boundary-pod=$BND_POD"
wait "$BND_PID" || fail_cell "boundary profile failed"
kc -n "$OBS_NS" cp "$OBS:/tmp/k3-boundary.json" "$WORK/k3-boundary.json" >/dev/null \
    || fail_cell "cannot fetch the boundary profile"
unlock_step
record_boundary_report "$WORK/k3-boundary.json" "$ITERS"

say "=== scale back to zero ==="
wait_scale_zero "$KSVC" "$KNS" 180 || fail_cell "service never scaled to zero after the boundary"

say "=== failure twin: no stale edge after scale-to-zero ==="
lock_step
observe p11scope inventory --system --caller-metadata none -o /tmp/k3-twin.json \
    >"$WORK/twin.out" 2>"$WORK/twin.err" \
    || { cat "$WORK/twin.err" >&2; fail_cell "twin inventory failed"; }
kc -n "$OBS_NS" cp "$OBS:/tmp/k3-twin.json" "$WORK/k3-twin.json" >/dev/null \
    || fail_cell "cannot fetch the twin inventory"
unlock_step
RESULT=$(inventory_absent "$WORK/k3-twin.json" "$PRIMARY_PID") || fail_cell "twin oracle refused"
record "$RESULT"

kill "$PF_PID" 2>/dev/null || true
# grep -c exits 1 on a zero count; keep errexit from skipping the SUMMARY line.
GATED=$(grep -c '"ok": true' "$SUMMARY_JSONL" || true)
[ "$GATED" -eq 3 ] || fail_cell "want 3 gated checks, got $GATED"
say "=== knative e2e: ALL OK ($GATED gated checks passed; summary $SUMMARY_JSONL) ==="
pass_cell "K3 Knative scale-from-zero attributed while serving"
