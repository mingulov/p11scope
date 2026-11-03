#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Sum EVIDENCE[0] (ring loss) over CPUs and maps from bpftool JSON.

Pure JSON parsing (no bpftool calls here; the caller runs bpftool with
sudo and hands over captured files, so unit tests feed canned inputs).

Modes:
  --show SHOW --list-ids
      Print the id of every map named EVIDENCE in SHOW (bpftool map
      show -j output), one per line. Any max_entries qualifies: the main
      and journal objects each own an EVIDENCE map and the double-count
      check needs both.
  --show SHOW --dump ID=FILE [...]
      Print a summary JSON object to stdout:
      {"maps": [{"id", "ring_loss_sum", "cpus"}...],
       "total_ring_loss_sum": N}.
      ring_loss_sum is the sum of the per-CPU values of the all-zero key
      (index 0, EVIDENCE_RING_LOSS) in that map's dump (bpftool map dump
      -j output); a map without key 0 contributes 0 with cpus 0.
      Maps named other than EVIDENCE in SHOW are ignored, as are --dump
      files for ids not listed. Exit 2 on unreadable or malformed input.
"""

import argparse
import json
import sys


def _load_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _evidence_ids(show):
    return [entry["id"] for entry in show
            if entry.get("name") == "EVIDENCE" and "id" in entry]


def _is_zero_key(key):
    if key == 0:
        return True
    return isinstance(key, list) and len(key) > 0 and all(v == 0 for v in key)


def _key_zero_sum(dump):
    for row in dump:
        if _is_zero_key(row.get("key")):
            values = row.get("values", [])
            if isinstance(values, list):
                return sum(values), len(values)
            return 0, 0
    return 0, 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--show", required=True)
    parser.add_argument("--list-ids", action="store_true")
    parser.add_argument("--dump", action="append", default=[],
                        metavar="ID=FILE")
    args = parser.parse_args(argv)
    try:
        show = _load_json(args.show)
    except (OSError, ValueError) as exc:
        print(f"bpf-evidence-sum: cannot read show file: {exc}",
              file=sys.stderr)
        return 2
    if not isinstance(show, list):
        print("bpf-evidence-sum: show JSON must be a list", file=sys.stderr)
        return 2
    ids = _evidence_ids(show)
    if args.list_ids:
        for map_id in ids:
            print(map_id)
        return 0
    dumps = {}
    for spec in args.dump:
        try:
            text_id, path = spec.split("=", 1)
            dumps[int(text_id)] = path
        except ValueError:
            print(f"bpf-evidence-sum: bad --dump spec: {spec!r}",
                  file=sys.stderr)
            return 2
    maps = []
    total = 0
    for map_id in ids:
        path = dumps.get(map_id)
        if path is None:
            continue
        try:
            dump = _load_json(path)
        except (OSError, ValueError) as exc:
            print(f"bpf-evidence-sum: cannot read dump for {map_id}: {exc}",
                  file=sys.stderr)
            return 2
        if not isinstance(dump, list):
            print(f"bpf-evidence-sum: dump for {map_id} must be a list",
                  file=sys.stderr)
            return 2
        ring_sum, cpus = _key_zero_sum(dump)
        maps.append({"id": map_id, "ring_loss_sum": ring_sum, "cpus": cpus})
        total += ring_sum
    print(json.dumps({"maps": maps, "total_ring_loss_sum": total}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
