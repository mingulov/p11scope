#!/bin/sh
name=${D2_COMMAND_NAME:-$(basename "$0")}
# The tool pinning layer identifies its executables by behaviour (it runs
# `--version` and requires a `rustup `/`Python ` banner), so the stubs
# standing in for rustup and python3 must answer as the tools they replace.
# Answer before the call is recorded: the probe is a capability check, not
# a tool use.
case "$name:$1" in
rustup:--version) printf '%s\n' "rustup 1.99.0 (p11scope test fixture)"; exit 0 ;;
python3:--version) printf 'Python 3.14.0 (p11scope test fixture)\n'; exit 0 ;;
esac
work=$(dirname "${KUBECONFIG:-/tmp/none}")
echo "$name $*" >> "$D2_STATE/calls"
cluster="p11scope-knative-$P11SCOPE_LANE13_TOKEN"
image="kind.local/p11scope-matrix-knative:$P11SCOPE_LANE13_TOKEN"
record_fixture_pid() {
    fixture_kind=$1
    /usr/bin/python3 - "$D2_STATE/fixture-pids" "$D2_OWNER_ID" \
        "$P11SCOPE_LANE_EVIDENCE_DIR" "$fixture_kind" "$$" <<'PY' || exit 1
import json
import os
import pathlib
import sys

ledger, owner, evidence, kind, raw_pid = sys.argv[1:]
pid = int(raw_pid)
raw = pathlib.Path(f"/proc/{pid}/stat").read_bytes()
_, separator, tail = raw.rpartition(b") ")
fields = tail.split()
if not separator or len(fields) < 20:
    raise SystemExit("malformed fixture proc stat")
argv = [os.fsdecode(item) for item in pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if item]
exe = os.path.realpath(f"/proc/{pid}/exe")
record = {
    "version": 1,
    "record_id": f"{owner}:{kind}:{pid}:{int(fields[19])}",
    "owner": owner,
    "evidence": evidence,
    "kind": kind,
    "pid": pid,
    "starttime": int(fields[19]),
    "ppid": int(fields[1]),
    "pgid": int(fields[2]),
    "sid": int(fields[3]),
    "exe": exe,
    "argv": argv,
}
with open(ledger, "a", encoding="utf-8") as stream:
    stream.write(json.dumps(record, separators=(",", ":")) + "\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
}
observe_release_deletion() {
    [ -f "$D2_STATE/last-release-path" ] || return 0
    previous_release=$(cat "$D2_STATE/last-release-path") || return 1
    [ ! -e "$previous_release" ] && [ ! -L "$previous_release" ] || return 1
    basename "$previous_release" >> "$D2_STATE/release-deletion-observed" || return 1
    rm -f "$D2_STATE/last-release-path"
}
case "$name" in
mkdir)
    mkdir_target=
    for argument do
        case "$argument" in
            -*) ;;
            *) mkdir_target=$argument ;;
        esac
    done
    case "$D2_MODE" in
        mkdir-failure-symlink|mkdir-failure-symlink-signal)
            /bin/ln -s "$D2_FOREIGN_TARGET" "$mkdir_target"
            if [ "$D2_MODE" = mkdir-failure-symlink-signal ]; then
                kill -TERM "$PPID"
            fi
            exit 1 ;;
        mkdir-failure-directory|mkdir-failure-directory-signal)
            /bin/mkdir -m 700 "$mkdir_target"
            printf '%s\n' foreign-directory-sentinel-a > "$mkdir_target/sentinel-a"
            printf '%s\n' foreign-directory-sentinel-b > "$mkdir_target/sentinel-b"
            [ "${D2_SENTINEL_OVERWRITE-0}" = 1 ] \
                && printf '%s\n' overwritten > "$mkdir_target/sentinel-a"
            chmod 640 "$mkdir_target/sentinel-a"
            chmod 600 "$mkdir_target/sentinel-b"
            if [ "$D2_MODE" = mkdir-failure-directory-signal ]; then
                kill -TERM "$PPID"
            fi
            exit 1 ;;
    esac
    /bin/mkdir "$@"
    mkdir_status=$?
    if [ "$D2_MODE" = mkdir-signal ] && [ "$mkdir_status" -eq 0 ] && [ ! -e "$D2_STATE/mkdir-signal" ]; then
        : > "$D2_STATE/mkdir-signal"
        kill -TERM "$PPID"
    fi
    exit "$mkdir_status" ;;
git)
    echo "$*" >> "$D2_STATE/git.calls"
    if [ "$D2_MODE" = signal-after-root ] && [ "$1" = rev-parse ] && [ "$2" = --show-object-format ] && [ ! -e "$D2_STATE/signal-after-root" ]; then
        : > "$D2_STATE/signal-after-root"
        kill -TERM "${P11SCOPE_LANE13_OUTER_PID:?}"
    fi
    if [ "$1" = diff ]; then [ ! -e "$D2_STATE/mutate-head" ]; exit $?; fi
    if [ "$1" = rev-parse ] && [ "$2" = HEAD ]; then
        if [ -e "$D2_STATE/mutate-head" ]; then printf '%040d\n' 2; else printf '%040d\n' 1; fi; exit 0
    fi
    if [ "$1" = rev-parse ] && [ "$2" = 'HEAD^{tree}' ]; then
        if [ -e "$D2_STATE/mutate-head" ]; then printf '%040d\n' 2; else printf '%040d\n' 1; fi; exit 0
    fi
    case " $* " in
        *" --show-object-format "*) echo sha1; exit 0 ;;
        *" ls-files --others --exclude-standard -- "*) exec "$D2_UNTRACKED_FIXTURE" "$@" ;;
        *" ls-files -z -- "*) exec "$D2_FIXTURES/candidate-git.py" "$@" ;;
        *" status --porcelain=v1 "*) [ ! -e "$D2_STATE/mutate-head" ] || echo ' M scripts/matrix/verify-knative.sh'; exit 0 ;;
        *" diff --quiet "*|*" diff --cached --quiet "*) [ ! -e "$D2_STATE/mutate-head" ]; exit $? ;;
    esac
    exit 1 ;;
cargo|"stable cargo"|"bpf cargo")
    if [ "${1-}" = --version ]; then echo 'cargo 1.88.0 (fake)'; exit 0; fi
    [ "${1-}" != metadata ] || exec /usr/bin/python3 -I "$D2_METADATA_CARGO" "$@"
    if [ "${1-}" = build ]; then
        printf 'selected-build-rustc %s\n' "${RUSTC-}" >> "$D2_STATE/calls"
        printf 'selected-build-stable-cargo %s\n' "$0" >> "$D2_STATE/calls"
        printf 'selected-build-stable-rustc %s\n' "${RUSTC-}" >> "$D2_STATE/calls"
        printf 'selected-build-bpf-cargo %s\n' \
            "${P11SCOPE_PREPARED_BPF_CARGO-}" >> "$D2_STATE/calls"
        printf 'selected-build-bpf-rustc %s\n' \
            "${P11SCOPE_PREPARED_BPF_RUSTC-}" >> "$D2_STATE/calls"
    fi
    target=target; previous=
    for argument do [ "$previous" = --target-dir ] && target=$argument; previous=$argument; done
    mkdir -p "$target/release/build/p11scope-1/out" "$target/release"
    /bin/cp "$D2_EBPF_OBJECT" "$target/release/build/p11scope-1/out/p11scope-ebpf"
    /bin/cp "$D2_FIXTURES/fake-p11scope.sh" "$target/release/p11scope"
    /bin/cp "$D2_FIXTURES/fake-p11scope-discover.sh" "$target/release/p11scope-discover"
    chmod 755 "$target/release/p11scope" "$target/release/p11scope-discover"
    if [ "$D2_MODE" = sleep-build ]; then
        : > "$D2_STATE/sleep-build-ready"
        record_fixture_pid dispatch-sleep-build
        sleep "$D2_HOLD_SECONDS"
    fi
    [ "$D2_MODE" = mutate-head ] && : > "$D2_STATE/mutate-head"
    exit 0 ;;
rustc|"stable rustc"|"bpf rustc") echo 'rustc 1.88.0 (fake)'; exit 0 ;;
rustup)
    [ "$#" -eq 4 ] && [ "$1" = which ] && [ "$2" = --toolchain ] || exit 64
    case "$3:$4" in
        1.88:cargo) printf '%s\n' "$D2_STABLE_CARGO" ;;
        1.88:rustc) printf '%s\n' "$D2_STABLE_RUSTC" ;;
        nightly-2026-05-20:cargo) printf '%s\n' "$D2_BPF_CARGO" ;;
        nightly-2026-05-20:rustc) printf '%s\n' "$D2_BPF_RUSTC" ;;
        *) exit 65 ;;
    esac ;;
python3)
    if [ "$D2_MODE" = outer-final-snapshot-unknown ] \
        && [ -z "${P11SCOPE_LANE13_BODY-}" ] \
        && [ "$#" -eq 3 ] && [ "$1" = -I ] && [ "$2" = - ]; then
        exit 75
    fi
    if [ "$1" = -I ] && [ "$2" = scripts/lane13-input-ledger.py ] \
        && [ "$3" = snapshot ]; then
        case "$D2_MODE:$*" in
            start-ledger-failure:*" --phase start "*) exit 73 ;;
            end-ledger-failure:*" --phase end "*) exit 74 ;;
        esac
    fi
    if [ "$1" = scripts/check-capture-evidence.py ]; then
        printf '%s\n' checker >> "$D2_STATE/checker.calls"
    fi
    if [ "$D2_MODE" = terminal-readiness-failure ] && [ "$1" = - ]; then
        record_fixture_pid dispatch-terminal-readiness
        : > "$D2_STATE/terminal-readiness-hold"
        sleep "$D2_HOLD_SECONDS"
    fi
    if [ "$D2_MODE" = terminal-signal ] || [ "$D2_MODE" = terminal-communication-timeout ]; then
      if [ "$1" = - ] \
        && [ "${2-}" = "${P11SCOPE_LANE_EVIDENCE_DIR-}" ] \
        && [ -e "$P11SCOPE_LANE_EVIDENCE_DIR/facts.log" ] \
        && [ ! -e "$D2_STATE/terminal-signal-ready" ]; then
        record_fixture_pid dispatch-terminal-signal
        : > "$D2_STATE/terminal-signal-ready"
        while [ ! -e "$D2_STATE/terminal-signal-go" ] \
            && [ ! -e "$D2_STATE/terminal-communication-go" ]; do sleep 0.01; done
      fi
    fi
    if [ "$1" = -c ] && printf '%s\n' "$2" | grep -Fq socket.create_connection; then
        [ -e "$D2_STATE/portforward-ready" ]
        exit $?
    fi
    exec /usr/bin/python3 "$@" ;;
gcc)
    if [ "$1" = --version ]; then echo 'gcc (fake) 14.0.0'; exit 0; fi
    output=; previous=
    for argument do [ "$previous" = -o ] && output=$argument; previous=$argument; done
    : > "$output"; chmod 755 "$output"; exit 0 ;;
curl)
    if [ "$#" -eq 1 ] && [ "$1" = --version ]; then echo 'curl 8.4.0'; exit 0; fi
    if [ "$#" -eq 6 ] && [ "$1" = -fsS ] && [ "$2" = -H ] \
        && [ "$3" = 'Host: fake.example' ] && [ "$5" = --max-time ] \
        && [ "$6" = 60 ]; then
        case "$4" in http://127.0.0.1:*/ ) exit 0 ;; *) exit 66 ;; esac
    fi
    observe_release_deletion || exit 1
    exec /usr/bin/python3 -I "$D2_FIXTURES/release-fetch.py" "$@" ;;
docker)
    case " $* " in
        *" version --format "*)
            [ "$D2_MODE" = setup-failure ] && exit 1
            if [ "$D2_MODE" = work-collision ]; then
                /bin/mkdir -p "$work"
                printf '%s\n' foreign > "$work/foreign-sentinel"
                printf '%s\n' "$work" > "$D2_STATE/work-collision-path"
            fi
            echo 27.0.0; exit 0 ;;
        *" info --format "*) echo overlay2; exit 0 ;;
        *" image ls "*)
            [ "$D2_MODE" = image-query-failure ] && exit 1
            [ "$D2_MODE" = cleanup-image-query-failure ] && [ -e "$D2_STATE/image-created" ] && exit 1
            if [ -e "$D2_STATE/image-created" ] && [ ! -e "$D2_STATE/image-removed" ]; then
                printf '%s\t%s\tsha256:workload\n' \
                    kind.local/p11scope-matrix-knative "$P11SCOPE_LANE13_TOKEN"
            fi
            exit 0 ;;
        *" pull "*) exit 0 ;;
        *" build "*) case " $* " in *" --pull=false "*) ;; *) exit 64 ;; esac; : > "$D2_STATE/image-created"; echo sha256:workload; exit 0 ;;
        *" image rm "*) : > "$D2_STATE/image-cleaned"; [ "$D2_MODE" = cleanup-image-failure ] && exit 1; : > "$D2_STATE/image-removed"; exit 0 ;;
        *" container inspect "*)
            case " $* " in *" {{.Id}} "*) echo node-id ;; *" {{.Image}} "*) echo sha256:nodeimage ;; *) echo kindest/node:v1.33 ;; esac; exit 0 ;;
        *" container ls "*)
            [ "$D2_MODE" = cleanup-node-query-failure ] && [ -e "$D2_STATE/cluster-delete-called" ] && exit 1
            [ ! -e "$D2_STATE/cluster" ] || printf 'node-id\tfake-node\n'; exit 0 ;;
        *" image inspect "*)
            case " $* " in *" --format "*) case " $* " in *"$image"*) echo sha256:workload ;; *) echo sha256:nodeimage ;; esac; exit 0 ;; esac
            target=; for argument do target=$argument; done
            [ "$target" = "$image" ] && [ -e "$D2_STATE/image-removed" ] && exit 1
            if [ "$D2_MODE" = partial-image-creation ] && [ "$target" = "$image" ] \
                && [ ! -e "$D2_STATE/partial-image-failed" ]; then
                : > "$D2_STATE/partial-image-failed"; exit 1
            fi
            if [ "$D2_MODE" = cluster-replacement ] && [ "$target" = sha256:nodeimage ] \
                && [ ! -e "$D2_STATE/cluster-replacement-failed" ]; then
                : > "$D2_STATE/cluster-replacement-failed"; exit 1
            fi
            case "$target" in ubuntu:24.04) echo '[{"Id":"sha256:base","RepoDigests":["ubuntu@sha256:base"],"RootFS":{"Layers":["sha256:base"]}}]' ;; sha256:nodeimage) echo '[{"Id":"sha256:nodeimage","RepoDigests":["kindest/node@sha256:node"],"RootFS":{"Layers":["sha256:node-layer-1","sha256:node-layer-2"]}}]' ;; *) echo '[{"Id":"sha256:workload","RepoDigests":["kind.local/p11scope-matrix-knative@sha256:workload"],"RootFS":{"Layers":["sha256:base","sha256:work-layer"]}}]' ;; esac; exit 0 ;;
    esac
    exit 1 ;;
kind)
    case " $* " in
        *" version "*) echo kind-v0.25.0; exit 0 ;;
        *" get clusters "*)
            [ "$D2_MODE" = cleanup-cluster-query-failure ] && [ -e "$D2_STATE/cluster-delete-called" ] && exit 1
            [ ! -e "$D2_STATE/cluster" ] || echo "$cluster"; exit 0 ;;
        *" get nodes "*)
            if [ "$D2_MODE" = partial-cluster-creation ] \
                && [ ! -e "$D2_STATE/partial-cluster-failed" ]; then
                : > "$D2_STATE/partial-cluster-failed"; exit 1
            fi
            if [ "$D2_MODE" = cluster-replacement ]; then
                if [ -e "$D2_STATE/cluster-node-observed" ]; then echo decoy-node; else : > "$D2_STATE/cluster-node-observed"; echo fake-node; fi
                exit 0
            fi
            echo fake-node; exit 0 ;;
        *" create cluster "*) mkdir -p "$(dirname "$KUBECONFIG")"; : > "$KUBECONFIG"; chmod 600 "$KUBECONFIG"; : > "$D2_STATE/cluster"; exit 0 ;;
        *" load docker-image "*) exit 0 ;;
        *" delete cluster "*) : > "$D2_STATE/cluster-delete-called"; [ "$D2_MODE" = cleanup-cluster-failure ] || rm -f "$D2_STATE/cluster"; if [ "$D2_MODE" = cleanup-cluster-failure ]; then echo 'controlled cluster cleanup failure' >&2; exit 1; fi; exit 0 ;;
    esac
    exit 1 ;;
kubectl)
    [ "${1-}" = apply ] || observe_release_deletion || exit 1
    case " $* " in
        *" version --client "*) echo gitVersion: v1.33.0; exit 0 ;;
        *" get deployment "*) exit 1 ;;
        *" get pods -n knative-serving "*) echo knative-pod; exit 0 ;;
        *" get pods -n kourier-system "*) echo kourier-pod; exit 0 ;;
        *" get pods "*" --sort-by=.metadata.creationTimestamp "*) echo fake-cold-pod; exit 0 ;;
        *" get pods "*" -l "*) exit 0 ;;
        *" get ksvc "*) echo fake.example; exit 0 ;;
        *" exec "*" readlink -f "*) echo /usr/lib/softhsm/libsofthsm2.so; exit 0 ;;
        *" exec "*" tar "*) exec /usr/bin/tar -chC "$D2_PROVIDER" . ;;
        *" apply "*)
            file=; previous=
            for argument do [ "$previous" = -f ] && file=$argument; previous=$argument; done
            case "$file" in
                *serving-crds.yaml|*serving-core.yaml|*kourier.yaml)
                    [ "$#" -eq 5 ] && [ "$1" = apply ] && [ "$2" = -f ] \
                        && [ "$4" = -o ] && [ "$5" = name ] || exit 64
                    release_name=${file##*/}
                    release_dir=$(cd "${file%/*}" && pwd -P) || exit 1
                    [ "$release_dir/$release_name" = "$work/releases/$release_name" ] || exit 65
                    printf '%s\n' "$release_name" >> "$D2_STATE/release-applies"
                    if [ "$D2_MODE" = during-apply-release-corruption ] \
                        && [ "$release_name" = "${D2_CORRUPT_RELEASE:?}" ]; then
                        /bin/cp -- "$D2_CORRUPT_RELEASE_FIXTURES/$release_name" "$file" \
                            || exit 1
                    fi
                    case "$release_name" in
                        serving-crds.yaml) printf '%s\n' namespace/knative-serving customresourcedefinitions.apiextensions.k8s.io/fake ;;
                        serving-core.yaml) printf '%s\n' service/controller deployment.apps/controller ;;
                        kourier.yaml) printf '%s\n' service/kourier namespace/kourier-system ;;
                    esac
                    printf '%s\n' "$release_dir/$release_name" > "$D2_STATE/last-release-path"
                    exit 0 ;;
                *ksvc.yaml) for name in observed.json manifest-host.json profile.log portforward.log portforward.group.before.json portforward.group.after.json; do : > "$work/$name"; done; : > "$work/foreign-unrelated.tmp"; case "$D2_MODE" in body-success|end-ledger-failure|terminal-signal|terminal-communication-timeout|terminal-readiness-failure|body-port-forward-hold|cleanup-image-query-failure|cleanup-cluster-query-failure|cleanup-node-query-failure|outer-final-snapshot-unknown) exit 0 ;; esac; exit 1 ;;
                *) exit 0 ;;
            esac ;;
    esac
    if [ "$1" = get ] && [ "$2" = pod ]; then
        pod=$3; namespace=default; pod_query=$*; shift 3
        while [ "$#" -gt 0 ]; do [ "$1" = -n ] && namespace=$2 && shift; shift; done
        case " $pod_query " in
            *creationTimestamp*) /usr/bin/date -u -d '+1 minute' '+%Y-%m-%dT%H:%M:%SZ'; exit 0 ;;
            *containerID*) echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; exit 0 ;;
        esac
        printf '{"metadata":{"namespace":"%s","name":"%s","uid":"uid-%s"},"spec":{"containers":[{"name":"anchor","image":"kind.local/fake:tag"}]},"status":{"containerStatuses":[{"name":"anchor","containerID":"containerd://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","imageID":"sha256:runtime","ready":true,"restartCount":0}]}}\n' "$namespace" "$pod" "$pod"; exit 0
    fi
    case " $* " in
        *" config use-context "*) observe_release_deletion || exit 1; exit 0 ;;
        *" wait "*|*" patch "*|*" set env "*) exit 0 ;;
        *" port-forward "*)
            record_fixture_pid dispatch-kubectl
            case "$D2_MODE" in body-success|end-ledger-failure|terminal-signal|terminal-communication-timeout|terminal-readiness-failure|body-port-forward-hold|cleanup-image-query-failure|cleanup-cluster-query-failure|cleanup-node-query-failure|outer-final-snapshot-unknown) exec "$D2_PORT_FORWARD_HELPER" "$@" ;; *) sleep "$D2_HOLD_SECONDS"; exit 143 ;; esac ;;
    esac
    exit 0 ;;
sudo)
    [ "$1" = -n ] && shift
    case "$D2_MODE:$*" in
        mutate-prepared-*:true)
            /usr/bin/python3 -I "$D2_FIXTURES/prepared-mutation.py" || exit 1 ;;
    esac
    if [ "$1" = timeout ]; then
        shift
        while [ "$#" -gt 0 ]; do case "$1" in --signal=*|--kill-after=*) shift ;; --signal|--kill-after) shift 2 ;; *s) shift; break ;; *) break ;; esac; done
        case "$1" in find) echo /sys/fs/cgroup/kubepods.slice/fake.scope; exit 0 ;; awk) echo 4242; exit 0 ;; stat) echo 0:123; exit 0 ;; esac
    fi
    case "$1" in
        stat) case " $* " in *" %s "*) /usr/bin/stat -Lc %s "$D2_PROVIDER/libsofthsm2.so" ;; *) echo 0:123 ;; esac; exit 0 ;;
        sha256sum) /usr/bin/sha256sum "$D2_PROVIDER/libsofthsm2.so"; exit 0 ;;
        readelf) echo '    Build ID: deadbeef'; exit 0 ;;
    esac
    exec "$@" ;;
timeout)
    while [ "$#" -gt 0 ]; do case "$1" in --signal=*|--kill-after=*) shift ;; --signal|--kill-after) shift 2 ;; *s) shift; break ;; *) break ;; esac; done
    exec "$@" ;;
readelf)
    case "$*" in
        *p11scope-ebpf|*/proc/*/fd/*) exec /usr/bin/readelf "$@" ;;
        *) echo '    Build ID: deadbeef'; exit 0 ;;
    esac ;;
cp) case "$D2_MODE:$*" in copy-failure:*observed.json*) exit 1 ;; esac; exec /bin/cp "$@" ;;
tar) exec /usr/bin/tar "$@" ;;
sha256sum) exec /usr/bin/sha256sum "$@" ;;
cmp) : > "$D2_STATE/git-compare-called"; exec /usr/bin/cmp "$@" ;;
*) exec "/usr/bin/$name" "$@" ;;
esac
