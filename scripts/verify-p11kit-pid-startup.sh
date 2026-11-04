#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# verify-p11kit-pid-startup.sh: privileged cell for a named capture starting
# beside an unpublished p11-kit closure array.
#
# `profile --pid` on a holder with libp11-kit mapped but no provider loaded
# yet must START (exit 0, PARTIAL) with the closure named as an unpublished
# gap, then attach the three providers the holder loads after attach and
# count exactly the holder's calls: 5 C_GetInfo plus 1 C_Finalize per
# backend, 18 calls over 242 slots. The pre-fix observer refuses to start
# here ("every module discovery found was refused at the 512 attach-slot
# ceiling"), so this cell is the live guard for that startup rule.
#
# Layout: the holder (scripts/fixtures/p11kit-pid-holder.c, compiled at run
# time) dlopens libp11-kit.so.0, waits for the observer's capture-start
# line, loads three managed modules (p11-kit-trust, softhsm2, opensc) from a
# private XDG_CONFIG_HOME, then drives 5 C_GetInfo calls through each.
# Oracle: exit 0, PARTIAL, 242 slots, per-backend tables [68] / [68] /
# [68, 92, 104], 18 calls (6 per backend; softhsm and opensc name C_GetInfo
# x5 plus C_Finalize x1), and the closure gap text with no capacity
# sentence. Per-module function-row counts are recorded, not pinned.
#
# Needs root for the observer (sudo -n), plus gcc, the p11-kit trust and
# proxy modules, opensc and softhsm2. Provider paths are probed (Debian and
# Fedora layouts); nothing is hard-coded.
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
import copy
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

TRUST_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so",
    "/usr/lib64/pkcs11/p11-kit-trust.so",
)
SOFTHSM_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
)
OPENSC_CANDIDATES = (
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib64/pkcs11/opensc-pkcs11.so",
)
HOLDER_SRC = Path("scripts/fixtures/p11kit-pid-holder.c")
CALLS = 5
EXPECTED_SLOTS = 242
EXPECTED_TABLES = {
    "p11-kit-trust.so": [68],
    "libsofthsm2.so": [68],
    "opensc-pkcs11.so": [68, 92, 104],
}
GAP_MUST_CONTAIN = (
    "(a proxy closure array is admitted whole",
    "is published yet",
)
GAP_MUST_LACK = (
    "attach slots are available",
    "more;",
)


def require(ok, reason):
    if not ok:
        raise SystemExit("cell failed: " + reason)


def probe(candidates):
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def tables_of(doc, base):
    for row in doc.get("evidence", {}).get("discovery", []):
        if os.path.basename(row.get("path", "")) == base:
            return sorted(t.get("entries", 0) for t in row.get("tables", []))
    return None


def calls_by_module(doc):
    ino = {m["ino"]: m["path"] for m in doc.get("evidence", {}).get("discovery", [])}
    per_module = {}
    for row in doc.get("functions", []):
        if not row.get("calls"):
            continue
        base = os.path.basename(ino.get(row["module"]["ino"], "?"))
        names = ",".join(row.get("names", [])) or "unknown"
        per_module.setdefault(base, []).append((names, row["calls"]))
    return per_module


def rows_by_module(doc):
    ino = {m["ino"]: m["path"] for m in doc.get("evidence", {}).get("discovery", [])}
    rows = {}
    for row in doc.get("functions", []):
        base = os.path.basename(ino.get(row["module"]["ino"], "?"))
        rows[base] = rows.get(base, 0) + 1
    return rows


def check_capture(doc):
    ev = doc.get("evidence", {})
    require(ev.get("completeness") == "PARTIAL",
            "completeness %r, want PARTIAL" % (ev.get("completeness"),))
    require(ev.get("slots") == EXPECTED_SLOTS,
            "slots %r, want %d" % (ev.get("slots"), EXPECTED_SLOTS))
    skipped = ev.get("modules_skipped", [])
    require(len(skipped) == 1,
            "%d module gaps, want exactly the closure one" % len(skipped))
    gap = skipped[0]
    require("libp11-kit" in gap.get("name", ""),
            "gap names %r, want the libp11-kit closure" % (gap.get("name"),))
    reason = gap.get("reason", "")
    for text in GAP_MUST_CONTAIN:
        require(text in reason, "gap lacks %r" % (text,))
    for text in GAP_MUST_LACK:
        require(text not in reason, "gap carries capacity text %r" % (text,))
    return gap


def check_tables(doc):
    got = {}
    for base, want in EXPECTED_TABLES.items():
        entries = tables_of(doc, base)
        require(entries is not None, "no discovery row for " + base)
        require(entries == want, "%s tables %r, want %r" % (base, entries, want))
        got[base] = entries
    return got


def check_calls(doc):
    per = calls_by_module(doc)
    # The grand total covers every counted module, not just the three
    # backends: a call counted anywhere else breaks the exact shape.
    total = sum(calls for entries in per.values() for _, calls in entries)
    for base in ("libsofthsm2.so", "opensc-pkcs11.so"):
        agg = {}
        for names, calls in per.get(base, []):
            agg[names] = agg.get(names, 0) + calls
        want = {"C_GetInfo": CALLS, "C_Finalize": 1}
        require(agg == want, "%s calls %r, want %r" % (base, agg, want))
    trust_total = sum(calls for _, calls in per.get("p11-kit-trust.so", []))
    require(trust_total == CALLS + 1,
            "trust calls %d, want %d" % (trust_total, CALLS + 1))
    require(total == 3 * (CALLS + 1),
            "total %d calls, want %d" % (total, 3 * (CALLS + 1)))
    return per


def fixture_doc():
    return {
        "functions": [
            {"module": {"ino": 1}, "names": ["C_GetInfo"], "calls": 5},
            {"module": {"ino": 1}, "names": ["C_Finalize"], "calls": 1},
            {"module": {"ino": 2}, "names": ["C_GetInfo"], "calls": 5},
            {"module": {"ino": 2}, "names": ["C_Finalize"], "calls": 1},
            {"module": {"ino": 3}, "names": ["unknown"], "calls": 5},
            {"module": {"ino": 3}, "names": ["unknown"], "calls": 1},
            {"module": {"ino": 1}, "names": ["C_Unused"], "calls": 0},
        ],
        "evidence": {
            "completeness": "PARTIAL",
            "slots": 242,
            "discovery": [
                {"ino": 1, "path": "/x/libsofthsm2.so",
                 "tables": [{"entries": 68}]},
                {"ino": 2, "path": "/y/opensc-pkcs11.so",
                 "tables": [{"entries": 104}, {"entries": 68},
                            {"entries": 92}]},
                {"ino": 3, "path": "/z/p11-kit-trust.so",
                 "tables": [{"entries": 68}]},
            ],
            "modules_skipped": [
                {"name": "/w/libp11-kit.so.0.4.8",
                 "reason": "a proxy closure array alone in the capture's "
                           "first plan attaches only its published tables, "
                           "and none of its 67 lookalike function tables is "
                           "published yet, so calls through it are not "
                           "counted (a proxy closure array is admitted whole, "
                           "as a prefix when mapped before the capture's "
                           "first plan beside a provider or named by the "
                           "operator, or as published tables); the providers "
                           "it forwards to attach when they load"},
            ],
        },
    }


def gap_reason(doc):
    return doc["evidence"]["modules_skipped"][0]["reason"]


def set_gap_reason(doc, reason):
    doc["evidence"]["modules_skipped"][0]["reason"] = reason


def self_test():
    doc = fixture_doc()
    check_capture(doc)
    check_tables(doc)
    check_calls(doc)
    print("self-test: positive fixture passes "
          "(PARTIAL, 242 slots, exact tables and calls)")

    def tweak_slots(doc):
        doc["evidence"]["slots"] = 241

    def tweak_completeness(doc):
        doc["evidence"]["completeness"] = "COMPLETE"

    def tweak_gap_missing(doc):
        doc["evidence"]["modules_skipped"] = []

    def tweak_gap_second(doc):
        doc["evidence"]["modules_skipped"].append(
            {"name": "/x/libsofthsm2.so", "reason": "module needs 1 more;"})

    def tweak_gap_name(doc):
        doc["evidence"]["modules_skipped"][0]["name"] = "/x/libsofthsm2.so"

    def tweak_gap_more(doc):
        set_gap_reason(doc, gap_reason(doc) + " (module needs 5 more;)")

    def tweak_gap_slots(doc):
        set_gap_reason(
            doc, gap_reason(doc) + " (only 512 attach slots are available)")

    def tweak_gap_unpublished(doc):
        set_gap_reason(doc, gap_reason(doc).replace("is published yet",
                                                    "are published"))

    def tweak_gap_marker(doc):
        set_gap_reason(doc, gap_reason(doc).replace(
            "(a proxy closure array is admitted whole",
            "(a proxy closure array is admitted"))

    def tweak_trust_tables(doc):
        doc["evidence"]["discovery"][2]["tables"] = [{"entries": 67}]

    def tweak_opensc_shape(doc):
        doc["evidence"]["discovery"][1]["tables"] = [{"entries": 68},
                                                     {"entries": 92}]

    def tweak_softhsm_missing(doc):
        doc["evidence"]["discovery"] = doc["evidence"]["discovery"][1:]

    def tweak_softhsm_calls(doc):
        doc["functions"][0]["calls"] = 4

    def tweak_opensc_names(doc):
        doc["functions"][3]["names"] = []

    def tweak_trust_short(doc):
        doc["functions"][4]["calls"] = 4

    def tweak_extra_module(doc):
        doc["functions"].append(
            {"module": {"ino": 9}, "names": ["C_X"], "calls": 1})

    negatives = [
        ("slots", tweak_slots, check_capture),
        ("completeness", tweak_completeness, check_capture),
        ("gap-missing", tweak_gap_missing, check_capture),
        ("gap-second", tweak_gap_second, check_capture),
        ("gap-name", tweak_gap_name, check_capture),
        ("gap-more", tweak_gap_more, check_capture),
        ("gap-slots", tweak_gap_slots, check_capture),
        ("gap-unpublished", tweak_gap_unpublished, check_capture),
        ("gap-marker", tweak_gap_marker, check_capture),
        ("trust-tables", tweak_trust_tables, check_tables),
        ("opensc-shape", tweak_opensc_shape, check_tables),
        ("softhsm-missing", tweak_softhsm_missing, check_tables),
        ("softhsm-calls", tweak_softhsm_calls, check_calls),
        ("opensc-names", tweak_opensc_names, check_calls),
        ("trust-short", tweak_trust_short, check_calls),
        ("extra-module", tweak_extra_module, check_calls),
    ]
    for name, tweak, check in negatives:
        bad = copy.deepcopy(doc)
        tweak(bad)
        try:
            check(bad)
        except SystemExit:
            continue
        require(False, "self-test negative %r did not fail" % (name,))
    print("self-test: %d negatives rejected" % len(negatives))


def tail(path, n=30):
    try:
        return "\n".join(path.read_text().splitlines()[-n:])
    except OSError:
        return "<unreadable>"


def wait_for(cond, deadline_s, what, logs):
    end = time.time() + deadline_s
    while time.time() < end:
        if cond():
            return
        time.sleep(0.1)
    tails = "\n".join("--- %s tail ---\n%s" % (name, tail(path))
                      for name, path in logs)
    require(False, "%s (timed out)\n%s" % (what, tails))


def main(binary, work, keep):
    require(shutil.which("gcc"), "missing tool on PATH: gcc")
    trust = probe(TRUST_CANDIDATES)
    require(trust, "no p11-kit-trust.so at probed paths")
    softhsm = probe(SOFTHSM_CANDIDATES)
    require(softhsm, "no libsofthsm2.so at probed paths")
    opensc = probe(OPENSC_CANDIDATES)
    require(opensc, "no opensc-pkcs11.so at probed paths")
    try:
        ctypes.CDLL("libp11-kit.so.0")
    except OSError as err:
        require(False, "libp11-kit.so.0 does not resolve: %s" % (err,))
    sudo = subprocess.run(["sudo", "-n", "true"])
    require(sudo.returncode == 0, "sudo -n is required for the observer")
    require(HOLDER_SRC.is_file(), "holder source missing: %s" % HOLDER_SRC)

    holder = work / "holder"
    build = subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-Werror",
         "-o", str(holder), str(HOLDER_SRC), "-ldl"],
        capture_output=True, text=True,
    )
    require(build.returncode == 0, "holder build failed:\n" + build.stderr)
    xdg = work / "xdg" / "pkcs11" / "modules"
    xdg.mkdir(mode=0o700, parents=True, exist_ok=True)
    (work / "xdg" / "pkcs11" / "pkcs11.conf").write_text("user-config: only\n")
    (xdg / "a-trust.module").write_text("module: %s\n" % trust)
    (xdg / "b-softhsm.module").write_text("module: %s\n" % softhsm)
    (xdg / "c-opensc.module").write_text("module: %s\n" % opensc)
    tokens = work / "tokens"
    tokens.mkdir(mode=0o700, exist_ok=True)
    conf = work / "softhsm2.conf"
    conf.write_text(
        "directories.tokendir = %s\nobjectstore.backend = file\n"
        "log.level = ERROR\n" % tokens
    )
    sig = work / "sig"
    sig.mkdir(mode=0o700, exist_ok=True)
    holder_log = work / "holder.log"
    profile_log = work / "profile.log"
    observed = work / "observed.json"
    logs = [("profile", profile_log), ("holder", holder_log)]

    holder_proc = None
    observer = None
    status = None
    try:
        with open(holder_log, "w") as log:
            holder_proc = subprocess.Popen(
                [str(holder), str(sig), str(CALLS)],
                env=dict(os.environ, XDG_CONFIG_HOME=str(work / "xdg"),
                         SOFTHSM2_CONF=str(conf)),
                stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, text=True,
            )
        wait_for(lambda: "mapped" in holder_log.read_text(), 60,
                 "holder never mapped libp11-kit", logs)
        maps = Path("/proc/%d/maps" % holder_proc.pid).read_text()
        require("libp11-kit" in maps,
                "libp11-kit not mapped in holder %d" % holder_proc.pid)
        with open(profile_log, "w") as log:
            observer = subprocess.Popen(
                ["sudo", "-n", binary, "profile", "--pid",
                 str(holder_proc.pid), "--duration", "40",
                 "-o", str(observed)],
                stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, text=True,
            )

        def ready():
            if observer.poll() is not None:
                require(False, "observer exited %d before readiness:\n%s"
                               % (observer.returncode, tail(profile_log)))
            text = profile_log.read_text()
            return "p11scope: capturing: " in text or " — privacy=" in text

        wait_for(ready, 120, "observer never became ready", logs)
        (sig / "go").touch()
        wait_for(lambda: (sig / "loaded").exists(), 120,
                 "holder never loaded its modules", logs)
        # Let live discovery see and attach the newly mapped providers.
        time.sleep(8)
        (sig / "calls").touch()
        wait_for(lambda: "called" in holder_log.read_text(), 120,
                 "holder never drove its calls", logs)
        (sig / "done").touch()
        try:
            holder_proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            require(False, "holder never exited:\n%s" % tail(holder_log))
        try:
            status = observer.wait(timeout=120)
        except subprocess.TimeoutExpired:
            require(False, "observer never exited:\n%s" % tail(profile_log))
    finally:
        for proc in (observer, holder_proc):
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()
    require(status == 0, "profile exit %r, want 0:\n%s"
                         % (status, tail(profile_log)))
    require(observed.is_file(), "observer wrote no %s" % observed)
    subprocess.run(
        ["sudo", "-n", "chown", "%d:%d" % (os.getuid(), os.getgid()),
         str(observed)],
        check=True,
    )
    holder_text = holder_log.read_text()
    require("called 3 x %d" % CALLS in holder_text,
            "holder drove no 3 x %d calls:\n%s" % (CALLS, holder_text))
    modules = [line for line in holder_text.splitlines()
               if line.startswith("module ")]

    doc = json.loads(observed.read_text())
    gap = check_capture(doc)
    tables = check_tables(doc)
    calls = check_calls(doc)
    rows = rows_by_module(doc)
    results = {
        "paths": {"trust": trust, "softhsm": softhsm, "opensc": opensc},
        "slots": doc["evidence"]["slots"],
        "completeness": doc["evidence"]["completeness"],
        "tables": tables,
        "rows": rows,
        "calls": {base: {names: sum(c for n, c in entries if n == names)
                          for names, _ in entries}
                  for base, entries in sorted(calls.items())},
        "gap": {"name": gap["name"], "reason": gap["reason"]},
        "holder_modules": modules,
    }
    (work / "results.json").write_text(json.dumps(results, indent=1) + "\n")
    print("PASS: p11-kit pid startup holds (%s)" % work)


if __name__ == "__main__":
    mode, binary, workdir, keep = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    if mode == "self":
        self_test()
    else:
        main(binary, Path(workdir), keep == "1")
PY
