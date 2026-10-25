#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Cell K3: Knative scale-from-zero pod using a PKCS#11 provider (dev host).
#
# A private kind cluster gets the smallest real Knative install (Serving
# knative-v1.23.0 CRDs + core and net-kourier knative-v1.23.0, all three YAMLs
# sha256-verified before apply, no Istio), the KService
# (deploy/k8s/e2e/knative-service.yaml: scale-to-zero, containerConcurrency 1,
# image by node-resolved digest) and the documented DaemonSet (same render as
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
# spanning one request: exact LEDGER total, event_loss == 0) and the failure
# twin (inventory after scale-to-zero: the dead serving PID is absent with no
# stale edge).
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
OBS_NS=p11scope
KNS=p11scope-knative
KSVC=p11scope-k3

usage() {
    cat >&2 <<'EOF'
usage: scripts/knative-e2e.sh [--token TOKEN] [--work DIR] [--iters N] [--keep]
       scripts/knative-e2e.sh --self-test | --help

  Cell K3 driver. Its own kind cluster (run token, refuse reuse, private
  kubeconfig), Knative Serving + Kourier knative-v1.23.0 from sha256-verified
  YAMLs, the KService at its node-resolved image digest, the documented
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

# Fill the KService digest placeholder with the node-resolved digest reference
# (verbatim from crictl, shape-validated: repo@sha256:64 lowercase hex).
render_ksvc() {
    rk_ref=$3
    case $rk_ref in
        *@sha256:*) ;;
        *) echo "not a digest reference: $rk_ref" >&2; return 1 ;;
    esac
    rk_hex=${rk_ref##*@sha256:}
    rk_repo=${rk_ref%@sha256:*}
    [ "${#rk_hex}" -eq 64 ] || { echo "bad digest length" >&2; return 1; }
    case $rk_hex in ''|*[!0-9a-f]*) echo "bad digest hex" >&2; return 1 ;; esac
    case $rk_repo in
        ''|*[!a-z0-9./:_-]*|*..*|*//*) echo "bad digest repo: $rk_repo" >&2; return 1 ;;
    esac
    [ "$(grep -Fc 'image: p11scope-knative-holder@sha256:KNATIVE_HOLDER_DIGEST' "$1")" -eq 1 ] \
        || { echo "ksvc lost its digest placeholder" >&2; return 1; }
    sed "s#image: p11scope-knative-holder@sha256:KNATIVE_HOLDER_DIGEST#image: $rk_ref#" "$1" > "$2" || return 1
    grep -Fq "image: $rk_ref" "$2" || { echo "ksvc render lost its digest" >&2; return 1; }
}

wait_scale_zero() {
    wz_i=0
    while [ "$wz_i" -lt "$(($3 * 2))" ]; do
        wz_pods=$(kubectl get pods -l "serving.knative.dev/service=$1" -n "$2" -o name 2>/dev/null) || return 1
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

# The node's own digest for our loaded tag, verbatim (exactly one, or refuse).
resolve_holder_digest() {
    python3 -I - "$1" "$2" <<'PY'
import json, re, sys
path, tag = sys.argv[1], sys.argv[2]
digests = []
for image in json.load(open(path, encoding="utf-8")).get("images") or []:
    if tag in (image.get("repoTags") or []):
        digests.extend(image.get("repoDigests") or [])
if len(digests) != 1:
    raise SystemExit(f"want exactly 1 node digest for {tag}, got {len(digests)}")
if not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", digests[0]):
    raise SystemExit(f"bad node digest: {digests[0]!r}")
print(digests[0])
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
    # The KService shape: digest placeholder, scale-to-zero, one request.
    [ "$(grep -c 'image: p11scope-knative-holder@sha256:KNATIVE_HOLDER_DIGEST' "$KNATIVE_KSVC")" -eq 1 ] \
        || { echo "ksvc lost its digest placeholder" >&2; exit 1; }
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
    # KService render: the digest placeholder is filled with a validated
    # node-resolved digest reference, nothing else moves.
    printf 'image: p11scope-knative-holder@sha256:KNATIVE_HOLDER_DIGEST\n' > "$stub/ksvc.yaml"
    PATH="$stub:$PATH" render_ksvc "$stub/ksvc.yaml" "$stub/ksvc-out.yaml" \
        "docker.io/library/p11scope-knative-holder@sha256:$good_sha" \
        || { echo "ksvc render refused" >&2; exit 1; }
    grep -Fq "image: docker.io/library/p11scope-knative-holder@sha256:$good_sha" "$stub/ksvc-out.yaml" \
        || { echo "render lost the digest" >&2; exit 1; }
    for bad_ref in "img:t" "img@sha256:xyz" "img@md5:$good_sha" "" \
            "img@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; do
        if PATH="$stub:$PATH" render_ksvc "$stub/ksvc.yaml" "$stub/ksvc-bad.yaml" "$bad_ref" \
                >/dev/null 2>&1; then
            echo "bad digest reference accepted: $bad_ref" >&2
            exit 1
        fi
    done
    k3_waiter_self_test "$stub"
    k3_parser_self_test "$stub"
    k3_check_self_test "$stub"
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
    # Node digest resolution: exactly one repo digest for our tag, verbatim.
    cat > "$stub/images.json" <<EOF
{"images": [{"repoTags": ["p11scope-knative-holder:e2e-t"],
  "repoDigests": ["docker.io/library/p11scope-knative-holder@sha256:$good_sha"]}]}
EOF
    [ "$(resolve_holder_digest "$stub/images.json" p11scope-knative-holder:e2e-t)" \
        = "docker.io/library/p11scope-knative-holder@sha256:$good_sha" ] \
        || { echo "node digest missed" >&2; exit 1; }
    cat > "$stub/images-none.json" <<'EOF'
{"images": [{"repoTags": ["p11scope-knative-holder:e2e-t"], "repoDigests": []}]}
EOF
    if resolve_holder_digest "$stub/images-none.json" p11scope-knative-holder:e2e-t \
            >/dev/null 2>&1; then
        echo "digestless image accepted" >&2
        exit 1
    fi
    cat > "$stub/images-two.json" <<EOF
{"images": [{"repoTags": ["p11scope-knative-holder:e2e-t"],
  "repoDigests": ["docker.io/library/p11scope-knative-holder@sha256:$good_sha",
    "docker.io/library/p11scope-knative-holder@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}]}
EOF
    if resolve_holder_digest "$stub/images-two.json" p11scope-knative-holder:e2e-t \
            >/dev/null 2>&1; then
        echo "ambiguous digests accepted" >&2
        exit 1
    fi
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
    K3_PORT=$port K3_LEDGER=$(cat "$stub/ledger.txt") python3 - <<'PY' || status=$?
import os, urllib.request, urllib.error
base = f"http://127.0.0.1:{os.environ['K3_PORT']}"
want = os.environ["K3_LEDGER"]
with urllib.request.urlopen(base + "/", timeout=20) as response:
    assert response.status == 200, response.status
    assert response.read() == b"ready\n"
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

echo "run path not implemented" >&2
exit 3
