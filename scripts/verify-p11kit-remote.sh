#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# verify-p11kit-remote.sh: Part 0 no-regression cell for p11-kit remote access.
#
# A p11-kit remote client (p11-kit-client.so in the application, p11-kit
# server on the far side) has no local provider: its only observation point
# is the closure array inside p11-kit-client.so. This cell pins today's
# prefix coverage so the round-1 deferral ("closure arrays behind real
# providers") can never silently lose it.
#
# Layout: a SoftHSM token, a user-owned `p11-kit server` on the default
# socket, and `pkcs11-tool -O --login` under `p11scope run --pause auto`.
# Oracle: the same workload against libsofthsm2.so directly. Twins: a
# provider+closure capture (`trust list`) in two halves — twin 1 pins the
# template prefix present with any count (stable under load, green even
# when starved), twin 1b re-runs the workload until the trust backend is
# admitted with a substantial count or all N attempts stay tiny
# (systematic starvation fails, one loader-timing flake does not) — and
# the remote workload with `--exclude-module` (excluded to 0, reported
# "excluded by you").
#
# Needs root for the observer (sudo -n), plus p11-kit, opensc (pkcs11-tool),
# softhsm2 and trust on PATH. Provider paths are probed (Debian and Fedora
# layouts); nothing is hard-coded.
set -eu
cd "$(dirname "$0")/.."

MODE=""
BINARY=""
WORK=""
KEEP=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --self-test) MODE=self; shift ;;
        --binary) [ "$#" -ge 2 ] || { echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--keep]" >&2; exit 2; }
            BINARY=$2; shift 2 ;;
        --work) [ "$#" -ge 2 ] || { echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--keep]" >&2; exit 2; }
            WORK=$2; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--keep]" >&2; exit 2 ;;
    esac
done

if [ "$MODE" = self ]; then
    [ -z "$BINARY$WORK" ] && [ "$KEEP" -eq 0 ] || {
        echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--keep]" >&2; exit 2
    }
else
    [ -n "$BINARY" ] && [ -n "$WORK" ] || {
        echo "usage: $0 --self-test | --binary P11SCOPE --work DIR [--keep]" >&2; exit 2
    }
    [ -x "$BINARY" ] || { echo "observer is not executable: $BINARY" >&2; exit 2; }
    umask 077
    if [ -e "$WORK" ] || [ -L "$WORK" ]; then
        [ -d "$WORK" ] && [ ! -L "$WORK" ] && [ "$(stat -Lc %u "$WORK")" = "$(id -u)" ] || {
            echo "work dir must be a caller-owned real directory: $WORK" >&2; exit 2
        }
        [ "$(stat -c %a "$WORK")" = 700 ] || {
            echo "work dir must have mode 700: $WORK" >&2; exit 2
        }
    else
        mkdir -p "$WORK"
        chmod 700 "$WORK"
    fi
fi

python3 -I - "$MODE" "$BINARY" "$WORK" "$KEEP" <<'PY'
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

SOFTHSM_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
)
CLIENT_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so",
    "/usr/lib64/pkcs11/p11-kit-client.so",
)
TEMPLATE_RE = re.compile(r"(\d+) of (\d+) template tables attached")


def require(ok, reason):
    if not ok:
        raise SystemExit("cell failed: " + reason)


def probe(candidates):
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def doc_totals(doc):
    fns = [f for f in doc.get("functions", []) if f.get("calls", 0) > 0]
    total = sum(f["calls"] for f in fns)
    return total, sorted(f["calls"] for f in fns)


def doc_template(doc, name_part):
    for skipped in doc.get("evidence", {}).get("modules_skipped", []):
        name = skipped.get("name", "")
        if name_part not in name:
            continue
        match = TEMPLATE_RE.search(skipped.get("reason", ""))
        if match:
            return int(match.group(1)), int(match.group(2))
    return None


def self_test():
    doc = {
        "functions": [
            {"calls": 39, "names": ["C_GetAttributeValue"]},
            {"calls": 3, "names": ["C_FindObjects"]},
            {"calls": 1, "names": ["C_GetFunctionList"]},
            {"calls": 0, "names": ["C_Unused"]},
        ],
        "evidence": {
            "modules_skipped": [
                {
                    "name": "/x/p11-kit-client.so",
                    "reason": "4 of 66 template tables attached; calls through the others are not counted",
                }
            ],
            "excluded_modules": [{"path": "/x/p11-kit-client.so"}],
        },
    }
    total, multi = doc_totals(doc)
    require(total == 43, "totals %r" % (total,))
    require(multi == [1, 3, 39], "multiset %r" % (multi,))
    require(doc_template(doc, "p11-kit-client.so") == (4, 66), "template parse")
    require(doc_template(doc, "libnope.so") is None, "template miss")
    # The oracle relation: remote is direct minus exactly one singleton.
    direct = [1, 1, 2, 3, 39]
    remote = [1, 2, 3, 39]
    require(sorted(direct)[:-1] != sorted(remote), "self-test sanity")
    rest = sorted(direct)
    rest.remove(1)
    require(rest == sorted(remote), "singleton-difference check")
    print("self-test: parsers and the oracle relation OK")


def run_observer(binary, conf, work, name, args, timeout=300):
    out_path = work / (name + ".out")
    err_path = work / (name + ".err")
    proc = subprocess.run(
        ["sudo", "-n", "env", "SOFTHSM2_CONF=" + str(conf), binary, *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    out_path.write_text(proc.stdout)
    err_path.write_text(proc.stderr)
    # The observer runs as root: take back any -o file it wrote.
    owned = []
    for index, word in enumerate(args):
        if word == "-o" and index + 1 < len(args):
            owned.append(args[index + 1])
    if owned:
        subprocess.run(
            ["sudo", "-n", "chown", "%d:%d" % (os.getuid(), os.getgid()), *owned],
            check=True,
        )
    return proc


def race_flags(doc):
    ev = doc.get("evidence", {})
    return [key for key in ("discovery_truncated", "unprotected_live_windows", "pause_partial")
            if ev.get(key, 0) not in (0, False, None)]


def capture_until_counted(binary, conf, work, name, args_for, attempts=3, clean=None):
    for attempt in range(1, attempts + 1):
        tag = "%s-try%d" % (name, attempt)
        run_observer(binary, conf, work, tag, args_for(work / (tag + ".json")))
        doc = json.loads((work / (tag + ".json")).read_text())
        total, _ = doc_totals(doc)
        if total > 0 and (clean is None or clean(doc)):
            (work / (name + ".json")).write_text(json.dumps(doc, indent=1) + "\n")
            return doc, attempt
    require(False, "%s never counted cleanly after %d attempts" % (name, attempts))
    return None, 0


def direct_is_clean(doc):
    # The oracle must be a whole run, not a loader race: short-lived
    # workloads can starve mid-attach under load, and the product says
    # so honestly (discovery_truncated / unprotected_live_windows /
    # pause_partial). Retry those; the relation below stays strict.
    return not race_flags(doc)


def main(binary, work, keep):
    for tool in ("p11-kit", "pkcs11-tool", "softhsm2-util", "trust"):
        require(shutil.which(tool), "missing tool on PATH: " + tool)
    softhsm = probe(SOFTHSM_CANDIDATES)
    require(softhsm, "no libsofthsm2.so at probed paths")
    client = probe(CLIENT_CANDIDATES)
    require(client, "no p11-kit-client.so at probed paths")
    sudo = subprocess.run(["sudo", "-n", "true"])
    require(sudo.returncode == 0, "sudo -n is required for the observer")

    uid = os.getuid()
    sock = Path("/run/user/%d/p11-kit/pkcs11" % uid)
    require(not sock.exists(), "default socket is occupied: %s" % sock)
    sock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    conf = work / "softhsm2.conf"
    tokens = work / "tokens"
    tokens.mkdir(mode=0o700, exist_ok=True)
    conf.write_text(
        "directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n" % tokens
    )
    env = dict(os.environ, SOFTHSM2_CONF=str(conf))
    subprocess.run(
        ["softhsm2-util", "--init-token", "--slot", "0", "--label", "remote-t",
         "--pin", "1234", "--so-pin", "1234"],
        env=env, check=True, capture_output=True, text=True,
    )
    listing = subprocess.run(
        ["pkcs11-tool", "--module", softhsm, "-L"],
        env=env, check=True, capture_output=True, text=True,
    ).stdout
    require("remote-t" in listing, "token remote-t not listed:\n" + listing)
    # No --slot: pkcs11-tool opens the first slot holding a token itself.
    subprocess.run(
        ["pkcs11-tool", "--module", softhsm, "--login", "--pin", "1234",
         "--keypairgen", "--key-type", "rsa:2048", "--label", "k1", "--id", "01"],
        env=env, check=True, capture_output=True, text=True,
    )

    server = subprocess.Popen(
        ["p11-kit", "server", "-f", "-n", str(sock), "--provider", softhsm,
         "pkcs11:token=remote-t"],
        env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    results = {}
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            if sock.exists():
                break
            require(server.poll() is None, "p11-kit server exited early")
            time.sleep(0.2)
        require(sock.exists(), "p11-kit server never bound %s" % sock)

        def tool_args(module, out, extra=()):
            return ["run", "--pause", "auto", "--module", module,
                    "-o", str(out), *extra, "--", "pkcs11-tool",
                    "--module", module, "-O", "--login", "--pin", "1234"]

        # The direct oracle.
        direct_doc, _ = capture_until_counted(
            binary, conf, work, "direct",
            lambda out: tool_args(softhsm, out),
            attempts=5,
            clean=direct_is_clean,
        )
        direct_total, direct_multi = doc_totals(direct_doc)
        results["direct"] = {"total": direct_total, "multiset": direct_multi,
                             "module": softhsm}
        print("direct: %d calls %s" % (direct_total, direct_multi))

        remote_doc, _ = capture_until_counted(
            binary, conf, work, "remote",
            lambda out: tool_args(client, out),
        )
        remote_total, remote_multi = doc_totals(remote_doc)
        results["remote"] = {"total": remote_total, "multiset": remote_multi,
                             "module": client}
        print("remote: %d calls %s" % (remote_total, remote_multi))

        prefix = doc_template(remote_doc, "p11-kit-client.so")
        require(prefix is not None, "remote report names no template prefix")
        covered, total_tables = prefix
        require(0 < covered < total_tables, "template prefix %r" % (prefix,))
        print("remote: %d of %d template tables attached" % (covered, total_tables))
        require(remote_total == direct_total - 1,
                "remote %d != direct %d minus one" % (remote_total, direct_total))
        rest = sorted(direct_multi)
        rest.remove(1)
        require(rest == sorted(remote_multi),
                "multisets differ by more than one singleton: %r vs %r"
                % (direct_multi, remote_multi))
        print("remote is direct minus C_GetFunctionList: the client entry point "
              "is served from its own code, never a closure slot")

        # Twin 1: provider + closure array together. Stable by design:
        # the template prefix is present with any count, green even when
        # the backend is starved — twin 1b below guards the admission.
        trust_doc, _ = capture_until_counted(
            binary, conf, work, "trust",
            lambda out: ["run", "--pause", "auto", "-o", str(out),
                         "--", "trust", "list", "--filter=ca-anchors"],
        )
        trust_total, _ = doc_totals(trust_doc)
        trust_prefix = doc_template(trust_doc, "libp11-kit.so.0")
        if trust_prefix is None:
            trust_prefix = doc_template(trust_doc, "libp11-kit.so")
        require(trust_prefix is not None, "trust report names no template prefix")
        require(trust_total > 0, "trust counted nothing")
        results["trust"] = {"total": trust_total, "prefix": trust_prefix}
        print("trust twin: %d calls, libp11-kit prefix %d of %d"
              % (trust_total, *trust_prefix))

        # Twin 1b: the trust backend must be ADMITTED, not only prefixed.
        # Twin 1 passes even when starved (7 calls locally, 11 on Fedora);
        # this loop fails only if the backend is never admitted with a
        # substantial count across N attempts. Substantial is 100 calls:
        # starved runs count only the closure templates (~7/~11) while
        # healthy runs count the backend (~744 locally, ~3184 on Fedora),
        # so any attempt at or above 100 proves admission without
        # asserting an exact total under load. One loader-timing flake
        # stays green; systematic starvation fails.
        admission_totals = []
        for attempt in range(1, 6):
            tag = "trust-adm-try%d" % attempt
            run_observer(
                binary, conf, work, tag,
                ["run", "--pause", "auto", "-o", str(work / (tag + ".json")),
                 "--", "trust", "list", "--filter=ca-anchors"],
            )
            doc = json.loads((work / (tag + ".json")).read_text())
            total, _ = doc_totals(doc)
            admission_totals.append(total)
            print("trust admission try%d: %d calls%s" % (
                attempt, total,
                " %s" % race_flags(doc) if race_flags(doc) else "",
            ))
        best = max(admission_totals)
        require(best >= 100,
                "trust backend never admitted in 5 attempts: %r"
                % (admission_totals,))
        results["trust_admission"] = {"attempts": admission_totals, "best": best}
        print("trust admission twin: best of 5 is %d calls" % best)

        # Twin 2: the remote workload excluded to 0, never silent. No
        # --module: discovery stays automatic and the exclusion removes
        # the client (naming both would be the conflict refusal).
        excl = run_observer(
            binary, conf, work, "remote-excl",
            ["run", "--pause", "auto",
             "--exclude-module", "p11-kit-client.so",
             "-o", str(work / "remote-excl.json"), "--", "pkcs11-tool",
             "--module", client, "-O", "--login", "--pin", "1234"],
        )
        excl_doc = json.loads((work / "remote-excl.json").read_text())
        excl_total, _ = doc_totals(excl_doc)
        excluded = excl_doc.get("evidence", {}).get("excluded_modules", [])
        require(excl_total == 0, "excluded remote counted %d" % excl_total)
        require(any(client in row.get("path", "") for row in excluded),
                "excluded_modules names no client: %r" % (excluded,))
        require("excluded by you" in (work / "remote-excl.out").read_text(),
                "excluded remote names no exclusion in text")
        results["remote_excl"] = {"total": 0, "excluded": excluded}
        print("exclude twin: 0 calls, client listed as excluded by you")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=10)

    results["paths"] = {"softhsm": softhsm, "client": client}
    (work / "results.json").write_text(json.dumps(results, indent=1) + "\n")
    print("PASS: p11-kit remote prefix holds (%s)" % work)


if __name__ == "__main__":
    mode, binary, workdir, keep = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    if mode == "self":
        self_test()
    else:
        main(binary, Path(workdir), keep == "1")
PY
