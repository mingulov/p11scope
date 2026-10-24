#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Uprobe perf-event close-throughput probe (A2.0 pre-measurement).

Question: does closing uprobe perf-event FDs scale with closer threads, or
does every close serialize on the kernel's global `event_mutex` plus one
tracepoint grace period (`perf_uprobe_destroy`, true on v5.15 and master)?
The answer gates the Singles width-64 close pool: if per-close wall time is
flat across widths, width cannot buy the 30 s link-close share of the 60 s
stop budget and the Singles ceiling must be narrowed from the measured rate
instead (preflight refusal; Multi carries 8192 on >= 6.6).

What it does, per width W in {1,4,16}: creates N uprobe tracepoints at
distinct file offsets of a local test binary (never executed), opens one
perf event FD per tracepoint, closes all N FDs with W worker threads while
wall-clocking only the close phase, then deletes its own tracepoints.
Stdout is exactly one JSON line per width; diagnostics go to stderr.

Needs root (tracefs write + perf_event_open) and a disk TMPDIR-free host;
it performs no capture and leaves no tracepoints behind on success or
failure (each width's probes are deleted in a `finally`). A crashed run
may leave `p11close_<pid>_<w>_*` probes behind; remove them with, e.g.::

    echo '-:p11close_<pid>_<w>/*' > /sys/kernel/debug/tracing/uprobe_events

Controller command (quiet lane, blocking slot not needed -- no Cargo)::

    sudo python3 -I scripts/uprobe-close-throughput-probe.py \
        --events 1026 --widths 1,4,16 --binary /bin/true

Expected stdout (illustrative timings, one line per width)::

    {"probe": "uprobe-close-throughput", "width": 1, "events": 1026,
     "total_s": 28.412000, "per_close_ms": 27.6940,
     "binary": "/bin/true", "kernel": "6.6.1", "tracefs": "/sys/kernel/debug/tracing"}

Measured example (dev host, kernel 7.0.0-38, 1026 events): per-close
49.4 ms at width 1, 49.2 ms at width 4, 47.7 ms at width 16 -- flat,
no scaling.

Interpretation: compare `per_close_ms` across widths. Flat means no
scaling (rule OQ5 now). The S2 gate is `16384 / measured_links_per_s <= 30`
with `measured_links_per_s = 1000 / per_close_ms` at the best width.
"""

import argparse
import ctypes
import gc
import json
import os
import platform
import resource
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DEFAULT_EVENTS = 1026
DEFAULT_WIDTHS = (1, 4, 16)
GROUP_PREFIX = "p11close"
NR_PERF_EVENT_OPEN = 298  # x86-64
PERF_ATTR_SIZE = 128
PERF_FLAG_FD_CLOEXEC = 8  # 1 << 3; not O_CLOEXEC (0o2000000)
PERF_TYPE_TRACEPOINT = 2
FD_HEADROOM = 64


class PerfEventAttr(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("config", ctypes.c_uint64),
        ("rest", ctypes.c_uint8 * (PERF_ATTR_SIZE - 16)),
    ]


def parse_widths(text):
    """Parse `--widths 1,4,16` into a list of positive ints."""
    widths = []
    for piece in text.split(","):
        piece = piece.strip()
        if not piece:
            raise ValueError("empty width in %r" % (text,))
        try:
            width = int(piece, 10)
        except ValueError:
            raise ValueError("non-integer width %r" % (piece,)) from None
        if width <= 0:
            raise ValueError("width must be positive, got %d" % (width,))
        widths.append(width)
    if not widths:
        raise ValueError("no widths in %r" % (text,))
    return widths


def parse_args(argv):
    """Parse CLI args; defaults are the A2.0 measurement (1026 x 1/4/16)."""
    parser = argparse.ArgumentParser(
        description="close N uprobe perf events with W threads per width")
    parser.add_argument("--events", type=int, default=DEFAULT_EVENTS,
                        help="perf events per width (default %(default)s)")
    parser.add_argument("--widths", type=parse_widths,
                        default=list(DEFAULT_WIDTHS),
                        help="comma-separated worker counts")
    parser.add_argument("--binary", default="/bin/true",
                        help="local test binary to probe (never executed)")
    parser.add_argument("--base-offset", type=lambda v: int(v, 0),
                        default=0x1000, help="first probe file offset")
    args = parser.parse_args(argv)
    if args.events <= 0:
        parser.error("--events must be positive")
    if args.base_offset < 0:
        parser.error("--base-offset must be non-negative")
    return args


def plan_offsets(file_size, base, count):
    """Return `count` distinct probe offsets in [base, file_size).

    The binary is never executed, so any in-range offset registers; the
    stride spreads probes across the file so no two share an address.
    """
    if count <= 0:
        raise ValueError("need a positive event count")
    if base < 0 or base >= file_size:
        raise ValueError("base %#x outside file of %d bytes" % (base, file_size))
    stride = max(1, (file_size - base) // count)
    offsets = [base + i * stride for i in range(count)]
    if offsets[-1] >= file_size:
        raise ValueError("file of %d bytes holds no %d distinct offsets"
                         % (file_size, count))
    return offsets


def build_uprobe_spec(group, name, binary, offset):
    """One `uprobe_events` line creating `group/name` at `binary:offset`."""
    return "p:%s/%s %s:%#x" % (group, name, binary, offset)


def build_uprobe_delete(group, name):
    """One `uprobe_events` line deleting exactly `group/name`."""
    return "-:%s/%s" % (group, name)


def required_fds(event_count):
    """FD budget: one per event plus headroom for stdio/tracefs/threads."""
    return event_count + FD_HEADROOM


def per_close_ms(total_s, count):
    """Mean close wall time in ms; fails closed on empty input."""
    if count <= 0:
        raise ValueError("need a positive event count")
    if total_s < 0:
        raise ValueError("negative wall time")
    return total_s * 1000.0 / count


def format_result_line(width, events, total_s, binary, kernel, tracefs):
    """One JSON object per width, no embedded newline."""
    record = {
        "probe": "uprobe-close-throughput",
        "width": width,
        "events": events,
        "total_s": round(total_s, 6),
        "per_close_ms": round(per_close_ms(total_s, events), 4),
        "binary": binary,
        "kernel": kernel,
        "tracefs": tracefs,
    }
    return json.dumps(record, sort_keys=True)


def find_tracefs():
    """Locate the mounted tracefs (debugfs-era and standalone mounts)."""
    for candidate in ("/sys/kernel/debug/tracing", "/sys/kernel/tracing"):
        if (Path(candidate) / "uprobe_events").is_file():
            return candidate
    raise RuntimeError("no mounted tracefs with uprobe_events found")


def ensure_root():
    if os.geteuid() != 0:
        raise RuntimeError("must run as root (tracefs write + perf_event_open)")


def ensure_fds(event_count):
    need = required_fds(event_count)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < need:
        if hard < need:
            raise RuntimeError(
                "need %d FDs for %d events, hard limit is %d"
                % (need, event_count, hard))
        resource.setrlimit(resource.RLIMIT_NOFILE, (need, hard))


def perf_event_open(uprobe_type, config):
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    attr = PerfEventAttr()
    attr.type = uprobe_type
    attr.size = PERF_ATTR_SIZE
    attr.config = config
    fd = libc.syscall(NR_PERF_EVENT_OPEN, ctypes.byref(attr), -1, 0, -1,
                      PERF_FLAG_FD_CLOEXEC)
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, "perf_event_open failed: %s" % os.strerror(err))
    return fd


def write_uprobe_line(uprobe_events, line):
    """Append one line to `uprobe_events` without disturbing other probes.

    Must use O_APPEND via raw os.open: opening with "w" truncates the
    file and deletes every uprobe on the host, while "a" fails with
    EINVAL because Python lseeks tracefs.
    """
    fd = os.open(uprobe_events, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
    try:
        os.write(fd, line.encode("ascii"))
    finally:
        os.close(fd)


def create_events(tracefs, group, binary, offsets):
    """Create one uprobe + one perf FD per offset; returns (fds, names)."""
    tracing = Path(tracefs)
    uprobe_events = tracing / "uprobe_events"
    # No events/uprobes/type exists under tracefs; tracefs-created uprobe
    # events open as PERF_TYPE_TRACEPOINT with config = events/<group>/<name>/id.
    uprobe_type = PERF_TYPE_TRACEPOINT
    event_dir = tracing / "events" / group
    fds, names = [], []
    try:
        for i, offset in enumerate(offsets):
            name = "w%d_%d" % (os.getpid(), i)
            write_uprobe_line(
                uprobe_events, build_uprobe_spec(group, name, binary, offset))
            names.append(name)
            config = int((event_dir / name / "id").read_text().strip())
            fds.append(perf_event_open(uprobe_type, config))
    except BaseException:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass
        delete_probes(tracefs, group, names)
        raise
    return fds, names


def delete_probes(tracefs, group, names):
    uprobe_events = Path(tracefs) / "uprobe_events"
    for name in names:
        try:
            write_uprobe_line(uprobe_events, build_uprobe_delete(group, name))
        except OSError as exc:
            print("warning: cannot delete %s/%s: %s" % (group, name, exc),
                  file=sys.stderr)


def close_with_width(fds, width):
    """Close every FD with `width` threads; returns close-phase seconds."""
    slices = [fds[i::width] for i in range(width)]

    def close_some(owned):
        for fd in owned:
            os.close(fd)

    gc.disable()
    try:
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=width) as pool:
            list(pool.map(close_some, slices))
        return time.perf_counter() - start
    finally:
        gc.enable()


def measure_width(tracefs, group, binary, offsets, width):
    fds, names = create_events(tracefs, group, binary, offsets)
    try:
        return close_with_width(fds, width)
    finally:
        delete_probes(tracefs, group, names)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        ensure_root()
        ensure_fds(args.events)
        tracefs = find_tracefs()
        size = os.path.getsize(args.binary)
        offsets = plan_offsets(size, args.base_offset, args.events)
        kernel = platform.release()
    except (RuntimeError, ValueError, OSError) as exc:
        print("p11close-probe: %s" % (exc,), file=sys.stderr)
        return 2
    tag = "%s_%d" % (GROUP_PREFIX, os.getpid())
    for width in args.widths:
        group = "%s_w%d" % (tag, width)
        try:
            total = measure_width(tracefs, group, args.binary, offsets, width)
        except (RuntimeError, OSError) as exc:
            print("p11close-probe: width %d: %s" % (width, exc),
                  file=sys.stderr)
            return 1
        print(format_result_line(width, args.events, total, args.binary,
                                 kernel, tracefs),
              flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
