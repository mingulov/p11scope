#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
# Fixture sanitizer for the upgrade captures. Replaces host identity
# (paths, PIDs, digests, device numbers, mtimes, parent exe names)
# with canonical constants, preserving every count, label, structure,
# instant and enum. One run over all fixtures with shared maps, so
# the same real value maps to the same canonical value in every file
# (the T2 pair stays comparable).
"""Usage: sanitize.py <rawdir> <outdir> [prefix]"""
import json
import os
import re
import sys

DEFAULT_PREFIX = "/var/tmp/p11scope-ws-tmp/v072-compat-071"

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

pid_map, ino_map, dev_map, pair_map, digest_map = {}, {}, {}, {}, {}
counters = {"pid": 4242, "ino": 100, "dev": 1, "pair": 1, "digest": 1}


def fresh_state():
    """Reset the shared canonical maps (one sanitize_tree run per state)."""
    global pid_map, ino_map, dev_map, pair_map, digest_map, counters
    pid_map, ino_map, dev_map, pair_map, digest_map = {}, {}, {}, {}, {}
    counters = {"pid": 4242, "ino": 100, "dev": 1, "pair": 1, "digest": 1}


def build_prefixes(prefix):
    return [
        (prefix, "/work"),
        ("/usr/lib/x86_64-linux-gnu/softhsm", "/usr/lib/softhsm"),
        ("/usr/lib/x86_64-linux-gnu", "/usr/lib"),
        # Fedora SoftHSM lands in the same canonical provider dir, so a
        # Fedora re-capture produces the same fixtures as a Debian one.
        ("/usr/lib64/pkcs11", "/usr/lib/softhsm"),
        ("/usr/lib/cargo/bin/coreutils", "/usr/bin"),
    ]


def canon(mapping, key, counter, fmt):
    if key not in mapping:
        mapping[key] = fmt(counters[counter])
        counters[counter] += 1
    return mapping[key]


def scrub_string(s, prefixes):
    for old, new in prefixes:
        s = s.replace(old, new)
    whole = re.fullmatch(r"pid:(\d+)", s)
    if whole:
        return f"pid:{canon(pid_map, int(whole.group(1)), 'pid', lambda n: n)}"
    s = re.sub(r"/proc/(\d+)",
               lambda m: f"/proc/{canon(pid_map, int(m.group(1)), 'pid', lambda n: n)}",
               s)
    s = re.sub(r"\bpid (\d+)",
               lambda m: f"pid {canon(pid_map, int(m.group(1)), 'pid', lambda n: n)}",
               s)
    s = re.sub(r"user-\d+\.slice", "user-1000.slice", s)
    return re.sub(r"session-[A-Za-z0-9_.-]+\.scope", "session-1.scope", s)


def is_hex(s, lengths=(40, 64)):
    return (isinstance(s, str) and len(s) in lengths
            and all(c in "0123456789abcdefABCDEF" for c in s))


def walk(node, path, prefixes):
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
                out[key] = walk(value, child, prefixes)
        return out
    if isinstance(node, list):
        return [walk(v, path, prefixes) for v in node]
    if isinstance(node, str):
        return scrub_string(node, prefixes)
    return node


def sanitize_tree(rawdir, outdir, prefix):
    fresh_state()
    prefixes = build_prefixes(prefix)
    os.makedirs(outdir, exist_ok=True)
    for name in sorted(FILES):
        with open(f"{rawdir}/{name}", encoding="utf-8") as fh:
            doc = json.load(fh)
        clean = walk(doc, "", prefixes)
        with open(f"{outdir}/{name}", "w", encoding="utf-8") as fh:
            json.dump(clean, fh, indent=2)
            fh.write("\n")
        print(f"{name}: {os.path.getsize(f'{outdir}/{name}')} bytes")
    print("maps:", {k: len(v) for k, v in
          [("pid", pid_map), ("ino", ino_map), ("dev", dev_map),
           ("pair", pair_map), ("digest", digest_map)]})


if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        sys.exit("Usage: sanitize.py <rawdir> <outdir> [prefix]")
    _raw, _out = sys.argv[1], sys.argv[2]
    _prefix = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_PREFIX
    sanitize_tree(_raw, _out, _prefix)
