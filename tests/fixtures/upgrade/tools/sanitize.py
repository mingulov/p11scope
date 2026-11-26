#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Fixture sanitizer for the upgrade captures. Replaces host identity
# (paths, PIDs, digests, device numbers, mtimes, parent exe names)
# with canonical constants, preserving every count, label, structure,
# instant and enum. One run over all fixtures with shared maps, so
# the same real value maps to the same canonical value in every file
# (the T2 pair stays comparable).
"""Usage: sanitize.py <rawdir> <outdir>"""
import json
import sys

RAW, OUT = sys.argv[1], sys.argv[2]
TMPDIR = "/var/tmp/p11scope-ws-tmp/v072-compat-071"
PREFIXES = [
    (TMPDIR, "/work"),
    ("/usr/lib/x86_64-linux-gnu/softhsm", "/usr/lib/softhsm"),
    ("/usr/lib/x86_64-linux-gnu", "/usr/lib"),
    ("/usr/lib/cargo/bin/coreutils", "/usr/bin"),
]

pid_map, ino_map, dev_map, pair_map, digest_map = {}, {}, {}, {}, {}
counters = {"pid": 4242, "ino": 100, "dev": 1, "pair": 1, "digest": 1}


def canon(mapping, key, counter, fmt):
    if key not in mapping:
        mapping[key] = fmt(counters[counter])
        counters[counter] += 1
    return mapping[key]


import re


def scrub_string(s):
    for old, new in PREFIXES:
        s = s.replace(old, new)
    whole = re.fullmatch(r"pid:(\d+)", s)
    if whole:
        return f"pid:{canon(pid_map, int(whole.group(1)), 'pid', lambda n: n)}"
    s = re.sub(r"/proc/(\d+)",
               lambda m: f"/proc/{canon(pid_map, int(m.group(1)), 'pid', lambda n: n)}",
               s)
    return re.sub(r"\bpid (\d+)",
                  lambda m: f"pid {canon(pid_map, int(m.group(1)), 'pid', lambda n: n)}",
                  s)


def is_hex(s, lengths=(40, 64)):
    return (isinstance(s, str) and len(s) in lengths
            and all(c in "0123456789abcdefABCDEF" for c in s))


def walk(node, path=""):
    if isinstance(node, dict):
        out = {}
        # Joint device_major/device_minor pair (manifest provenance).
        if isinstance(node.get("device_major"), int) and isinstance(
                node.get("device_minor"), int):
            major, minor = canon(pair_map,
                                 (node["device_major"], node["device_minor"]),
                                 "pair", lambda n: (8, n))
            out["device_major"], out["device_minor"] = major, minor
        for key, value in node.items():
            if key in ("device_major", "device_minor") and key in out:
                continue
            child = f"{path}/{key}"
            if key in ("pid", "pid_host", "handoff_child_pid") \
                    and isinstance(value, int):
                out[key] = canon(pid_map, value, "pid", lambda n: n)
            elif key == "dev" and isinstance(value, int):
                out[key] = canon(dev_map, ("s", value), "dev", lambda n: n)
            elif key in ("dev", "device") and isinstance(value, dict):
                major, minor = canon(
                    pair_map, (value.get("major"), value.get("minor")),
                    "pair", lambda n: (8, n))
                out[key] = {"major": major, "minor": minor}
            elif key == "dev" and isinstance(value, list):
                major, minor = canon(pair_map, tuple(value), "pair",
                                     lambda n: (8, n))
                out[key] = [major, minor]
            elif key in ("ino", "inode") and isinstance(value, int):
                out[key] = canon(ino_map, value, "ino", lambda n: n)
            elif key in ("sha256", "build_id") and isinstance(value, str):
                out[key] = canon(digest_map, value, "digest",
                                 lambda n, ln=len(value): f"{n:0{ln}x}")
            elif key == "value" and path.endswith("/identity") \
                    and is_hex(value):
                out[key] = canon(digest_map, value, "digest",
                                 lambda n, ln=len(value): f"{n:0{ln}x}")
            elif key == "mtime_secs":
                out[key] = 10
            elif key == "mtime_nanos":
                out[key] = 0
            elif key == "exe" and isinstance(value, str) \
                    and "/launched_by" in path:
                out[key] = "launcher"
            elif key in ("task_cookie", "exec_id") \
                    and isinstance(value, int):
                out[key] = canon(ino_map, ("cookie", value), "ino", lambda n: n)
            else:
                out[key] = walk(value, child)
        return out
    if isinstance(node, list):
        return [walk(v, path) for v in node]
    if isinstance(node, str):
        return scrub_string(node)
    return node


# Raw captures keep their capture names, except the v0.7.1 profile:
# rename it to v071-observed-profile-signer.json before sanitizing
# (the bare v071-observed-profile.json name belongs to the
# upgrade-cells lane's own capture).
FILES = [
    "v071-inventory-scan.json",
    "v071-inventory-native.json",
    "v071-inventory-churn.json",
    "v072-inventory-churn.json",
    "v071-inventory-keyops.json",
    "v071-observed-profile-signer.json",
    "v071-observed-metrics.json",
    "v072-observed-profile.json",
    "v072-observed-metrics.json",
    "v071-manifest-softhsm.json",
]
import os
os.makedirs(OUT, exist_ok=True)
for name in sorted(FILES):
    with open(f"{RAW}/{name}", encoding="utf-8") as fh:
        doc = json.load(fh)
    clean = walk(doc)
    with open(f"{OUT}/{name}", "w", encoding="utf-8") as fh:
        json.dump(clean, fh, indent=2)
        fh.write("\n")
    print(f"{name}: {os.path.getsize(f'{OUT}/{name}')} bytes")
print("maps:", {k: len(v) for k, v in
      [("pid", pid_map), ("ino", ino_map), ("dev", dev_map),
       ("pair", pair_map), ("digest", digest_map)]})
