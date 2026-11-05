#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed H6 ia32 leader/failed-exec gate: eight required public-command legs.

Singles and Multi each run leader trace/profile/metrics and continuing failed
leader-exec trace. Native use requires the separately authorized root lane and
an ordinary workload uid/gid. Unit controls only run unprivileged ELF32 libc
workloads. No nonleader, Inventory, S1, System, Cgroup or fallback cells.

The exact H6 Case, readers, process custody, phase budgets, public readiness,
stop, cleanup and evaluators are reused through runpy without replacing their
globals. Each fixture independently ledgers actual calls and image identities.
ELF32 targets are checked against child maps and the same calibrated held DSO;
the 64-bit observer process never dlopens the ia32 provider.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
H6 = runpy.run_path(str(ROOT / "scripts/qualify-automatic-exec.py"))
CELLS = ("pid-leader", "pid-failed-exec")
BACKENDS = ("singles", "multi")
REQUIRED_LEGS = {"pid-leader": ("trace", "profile", "metrics"), "pid-failed-exec": ("trace",)}
APIS = ("C_Initialize", "C_GetInfo", "C_GetSessionInfo", "C_OpenSession")
MAX_U64 = (1 << 64) - 1


def compile_fixtures(directory):
    """No new dependencies: fail explicitly if the ordinary ia32 libc is absent."""
    directory = Path(directory)
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    source = ROOT / "tests/fixtures/ia32-automatic-exec.c"
    paths = {name: directory / name for name in ("before", "after", "provider.so")}
    common = ["cc", "-m32", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    for name, path in paths.items():
        flags = (["-DH6_IA32_PROVIDER", "-shared", "-fPIC"] if name == "provider.so"
                 else [f"-DIA32_IMAGE={int(name == 'after')}"])
        result = subprocess.run([*common, *flags, str(source), "-o", str(path), "-ldl"],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise H6["SetupError"](f"ia32 fixture compile failed ({name}): {result.stderr[-2000:]}")
    return paths


def elf32_metadata(pin, symbols=()):
    """Read only the held file: ELFCLASS32/EM_386 excludes LP64 and x32."""
    pin.verify()
    size = pin.initial.st_size
    def read(offset, count):
        if not 0 <= offset <= size or count <= 0 or offset + count > size:
            raise ValueError("truncated held ELF32 file")
        data = os.pread(pin.fd, count, offset)
        if len(data) != count:
            raise ValueError("truncated held ELF32 read")
        return data
    head = read(0, 52)
    if head[:7] != b"\x7fELF\x01\x01\x01" or struct.unpack_from("<H", head, 18)[0] != 3:
        raise ValueError("expected ELFCLASS32 EM_386 (ia32), never ELF64 or x32")
    fields = struct.unpack_from("<HHIIIIIHHHHHH", head, 16)
    (_kind, _machine, version, _entry, phoff, shoff, _flags, ehsize,
     phsize, phnum, shsize, shnum, _shstr) = fields
    if version != 1 or ehsize != 52 or phsize != 32 or not 0 < phnum <= 128:
        raise ValueError("malformed ELF32 header/program table")
    segments = []
    for index in range(phnum):
        kind, offset, va, _pa, length, _mem, flags, _alignment = struct.unpack(
            "<IIIIIIII", read(phoff + index * phsize, phsize))
        if kind == 1 and flags & 1:
            if not length or offset + length > size:
                raise ValueError("truncated ELF32 executable segment")
            segments.append({"offset": offset, "vaddr": va, "size": length})
    if not segments:
        raise ValueError("held ELF32 has no executable segment")
    offsets = {}
    if symbols:
        if shsize != 40 or not 0 < shnum <= 4096:
            raise ValueError("malformed ELF32 section table")
        sections = [struct.unpack("<IIIIIIIIII", read(shoff + i * shsize, shsize))
                    for i in range(shnum)]
        for section in sections:
            if section[1] != 11:  # SHT_DYNSYM survives normal stripping
                continue
            if section[9] != 16 or section[5] % 16 or not 0 <= section[6] < shnum:
                raise ValueError("malformed ELF32 dynamic symbols")
            strings = sections[section[6]]
            if strings[5] > 1024 * 1024 or section[5] > 1024 * 1024:
                raise ValueError("ELF32 symbol metadata exceeds bounded limit")
            names = read(strings[4], strings[5])
            for off in range(section[4], section[4] + section[5], 16):
                name, value, _length, _info, _other, defined = struct.unpack("<IIIBBH", read(off, 16))
                if name >= len(names):
                    raise ValueError("ELF32 symbol name is out of bounds")
                end = names.find(b"\0", name)
                if end < 0:
                    raise ValueError("unterminated ELF32 symbol name")
                symbol = names[name:end].decode("ascii", errors="replace")
                if symbol in symbols and defined:
                    matching = [s for s in segments if s["vaddr"] <= value < s["vaddr"] + s["size"]]
                    if len(matching) != 1 or symbol in offsets:
                        raise ValueError("ELF32 endpoint lacks one distinct executable definition")
                    offsets[symbol] = value - matching[0]["vaddr"] + matching[0]["offset"]
        if set(offsets) != set(symbols) or len(set(offsets.values())) != len(symbols):
            raise ValueError("ELF32 provider is missing distinct required endpoints")
    return {"elf_class": 32, "machine": 3, "pointer_bytes": 4, "ck_ulong_bytes": 4,
            "symbol_offsets": offsets}


def target_receipts(owner, rows, provider_pin, provider, abi):
    """Compare actual child VMAs and wide inode data with held-FD calibration."""
    owner.verify()
    provider_pin.verify()
    mappings = []
    for line in (Path("/proc") / str(owner.pid) / "maps").read_text().splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            raise ValueError("truncated owned child maps")
        low, high = (int(value, 16) for value in fields[0].split("-"))
        mappings.append({"map_start": low, "map_end": high, "permissions": fields[1],
                         "map_offset": int(fields[2], 16),
                         "dev": [int(value, 16) for value in fields[3].split(":")],
                         "ino": int(fields[4])})
    receipts = []
    if len(rows) != len(APIS) or {row["fn"] for row in rows} != set(APIS):
        raise ValueError("owned image lacks exactly the exercised independent API targets")
    for row in rows:
        matching = [m for m in mappings if m["map_start"] <= row["vaddr"] < m["map_end"]]
        if len(matching) != 1:
            raise ValueError("ia32 endpoint is absent from actual child maps")
        actual = matching[0]
        if (actual["dev"] != provider["dev"] or actual["ino"] != provider["ino"]
                or actual["permissions"][2] != "x"
                or any(row[key] != actual[key] for key in actual)
                or row["file_offset"] != row["vaddr"] - actual["map_start"] + actual["map_offset"]
                or row["file_offset"] != abi["symbol_offsets"][row["fn"]]):
            raise ValueError("ia32 ledger target disagrees with held provider/actual mapping/symbol")
        receipts.append(dict(row))
    owner.verify()
    return receipts


class Ia32Driver:
    """One original OwnedProcess/pidfd, retained across a real leader exec."""
    def __init__(self, ctx, directory, pins, mode, env, delay_ms=300):
        if mode not in ("leader", "failed") or not 0 <= delay_ms <= 1000:
            raise ValueError("unsupported ia32 workload mode/delay")
        self.ctx, self.directory, self.pins, self.mode = ctx, Path(directory), pins, mode
        self.images, self.targets, self.exec_transitions = [], [], []
        self.failed_exec, self.held = None, None
        self.trace_shared_key_guard = None
        self.index, self.stamps = 0, {}
        self.abi = {key: elf32_metadata(pin, APIS if key == "provider.so" else ())
                    for key, pin in pins.items() if key in ("before", "after", "provider.so")}
        self.provider_before = H6["provider_receipt"](pins["provider.so"])
        self.absent = self.directory / "must-not-exist"
        if os.path.lexists(self.absent):
            raise ValueError("failed-exec path is not independently absent")
        budget = H6["ACTIVE_LEG"].get()
        if budget is None:
            raise ValueError("ia32 driver requires the exact H6 owned_leg context")
        self.spawned_ns = H6["monotonic_ns"]()
        argv = [str(pins["before"].path), str(pins["provider.so"].path), str(pins["after"].path),
                str(self.absent), mode, "0", "0", str(budget.deadline_ns),
                str(budget.deadlines["setup", 0]), "15000", "60000", "65000", str(delay_ms)]
        credentials = {"user": ctx.args.uid, "group": ctx.args.gid, "extra_groups": []} if os.geteuid() == 0 else {}
        if not credentials and (ctx.args.uid, ctx.args.gid) != (os.getuid(), os.getgid()):
            raise ValueError("ordinary protocol run must use its current uid/gid")
        try:
            self.owned = H6["spawn_owned"](ctx.owners, argv, ctx.args.uid,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=env, start_new_session=True, **credentials)
            self.stdout = H6["owned_reader"](ctx.readers, H6["Reader"], self.owned.popen.stdout,
                                               self.directory / "caller.stdout.txt")
            self.stderr = H6["owned_reader"](ctx.readers, H6["Reader"], self.owned.popen.stderr,
                                               self.directory / "caller.stderr.txt")
        except BaseException as error:
            ctx.case.cleanup_failed = True
            ctx.case.cleanup_errors.append(f"ia32 caller construction: {type(error).__name__}: {error}")
            raise  # exact H6 owned_leg still reaps every enrolled partial input
        self.pid, self.birth = self.owned.pid, self.owned.identity["start_time"]

    def expect_ack(self, phase, seconds=10):
        deadline = H6["wait_deadline"](seconds)
        while True:
            line, self.index = H6["expect_line"](self.stdout, self.index, "N3LEDGER ",
                                                H6["remaining_until"](deadline))
            row = json.loads(line[9:])
            if row.get("kind") == "ack":
                if row.get("phase") != phase or row.get("pid") != self.pid or row.get("tid") != self.pid:
                    raise ValueError(f"unexpected ia32 acknowledgment while waiting for {phase}")
                self.stamps[phase + "-ack"] = H6["monotonic_ns"]()
                return row

    def send(self, byte, phase):
        H6["check_dispatch"]()
        self.owned.verify()
        self.stamps[phase] = H6["monotonic_ns"]()
        self.owned.popen.stdin.write(byte)
        self.owned.popen.stdin.flush()

    def image_ready(self, number):
        self.expect_ack("ready")
        rows = list(self.stdout.records)
        images = [r for r in rows if r["kind"] == "image" and r["image"] == number]
        if len(images) != 1:
            raise ValueError("ia32 ready lacks one real executable image")
        pin = self.pins["after" if number else "before"]
        pin.verify()
        receipt = pin.image_receipt(images[0], self.owned)
        receipt.update(t=images[0]["t"], pointer_bytes=4, ck_ulong_bytes=4)
        if any(images[0].get(k) != receipt[k] for k in H6["IMAGE_FIELDS"]):
            raise ValueError("ia32 image disagrees with original birth/held executable")
        targets = [r for r in rows if r["kind"] == "target" and r["image"] == number]
        self.targets.extend(target_receipts(self.owned, targets, self.pins["provider.so"],
                                           self.provider_before, self.abi["provider.so"]))
        self.images.append(receipt)
        return receipt

    def ready(self):
        return self.image_ready(0)

    def start_held(self):
        self.send("G", "pre-start")
        self.expect_ack("pre")
        self.expect_ack("held")
        held = [r for r in self.stdout.records if r["kind"] == "held"]
        if len(held) != 1 or held[0]["vaddr"] != next(
                r["vaddr"] for r in self.targets if r["image"] == 0 and r["fn"] == "C_Initialize"):
            raise ValueError("held frame lacks the independently checked provider endpoint")
        self.held = dict(held[0])
        self.owned.verify()

    def do_exec(self):
        H6["enter_phase"]("successor-recovery", key=1)
        if os.path.lexists(self.absent):
            raise ValueError("failed-exec path appeared before the actual attempt")
        self.send("X", "exec-start")
        if self.mode == "failed":
            self.expect_ack("failed-exec")
            rows = [r for r in self.stdout.records if r["kind"] == "failed-exec"]
            if len(rows) != 1 or rows[0]["errno"] != 2 or rows[0]["path"] != str(self.absent):
                raise ValueError("held leader exec did not actually fail with ENOENT")
            self.failed_exec = dict(rows[0])
            # The original frame remains live until R. Independently recheck
            # unchanged exe and birth now; no successor is created.
            self.pins["before"].image_receipt(self.images[0], self.owned)
            return
        successor = self.image_ready(1)
        requests = [r for r in self.stdout.records if r["kind"] == "exec"]
        if len(requests) != 1:
            raise ValueError("successor lacks one real leader exec request")
        self.exec_transitions = [{"from_image": 0, "to_image": 1, "mode": "leader", "same_path": False,
                                 "t0": self.stamps["exec-start"], "t1": self.stamps["ready-ack"],
                                 "request": dict(requests[0])}]
        if successor["start_time"] != self.birth:
            raise ValueError("ia32 leader exec changed the original process birth")

    def warm_attempt(self, sequence, remaining):
        if self.mode != "leader":
            raise ValueError("failed exec cannot manufacture successor readiness")
        phase = f"successor-1-{sequence}"
        self.send("W", phase)
        self.expect_ack(phase, remaining)
        calls = [r for r in self.stdout.records if r.get("phase") == phase and r["kind"] == "call"]
        if (len(calls) != 1 or calls[0]["fn"] != "C_GetInfo" or calls[0]["rv"] != 0
                or not self.stamps[phase] <= calls[0]["t0"] <= calls[0]["t1"] <= self.stamps[phase + "-ack"]):
            raise ValueError("warm-up lacks one real acknowledged current-image marker")
        return phase

    def measure(self):
        H6["enter_phase"]("fixed-measurement")
        self.send("R", "post-start")
        if self.mode == "failed":
            self.expect_ack("held-return")
        self.expect_ack("post", 60)
        self.pins["after" if self.mode == "leader" else "before"].image_receipt(self.images[-1], self.owned)

    def snapshot(self):
        return {"ledger": list(self.stdout.records), "images": list(self.images),
                "targets": list(self.targets), "exec_transitions": list(self.exec_transitions),
                "held": self.held, "failed_exec": self.failed_exec, "absent_path": str(self.absent),
                "provider_before": self.provider_before,
                "provider_after": H6["provider_receipt"](self.pins["provider.so"]),
                "pid": self.pid, "birth": self.birth, "abi": self.abi,
                "spawned_ns": self.spawned_ns, "finished_ns": H6["monotonic_ns"](),
                "trace_shared_key_guard": self.trace_shared_key_guard,
                "command_stamps": dict(self.stamps)}

    def finish(self):
        H6["enter_phase"]("cleanup")
        self.send("F", "finish-start")
        self.expect_ack("done", 5)
        rc = H6["wait_process"](self.owned.popen, 5)
        if rc:
            raise H6["LegCleanupError"](f"ia32 caller returned {rc}")
        return rc


def workload_errors(ledger, receipt, mode):
    """Strict independent workload contract before the unchanged H6 evaluators."""
    try:
        return _workload_errors(ledger, receipt, mode)
    except (KeyError, TypeError, ValueError, IndexError, OverflowError) as error:
        return [f"malformed ia32 independent ledger/receipt: {type(error).__name__}: {error}"]


def _workload_errors(ledger, receipt, mode):
    errors = []
    if mode not in ("leader", "failed") or not isinstance(ledger, list) or not 1 <= len(ledger) <= 256:
        return ["unsupported mode or bounded ia32 ledger exhausted"]
    if [r["seq"] for r in ledger] != list(range(1, len(ledger) + 1)):
        errors.append("missing, duplicate or reordered ia32 ledger sequence")
    images = [r for r in ledger if r["kind"] == "image"]
    want_images = [0, 1] if mode == "leader" else [0]
    if [r["image"] for r in images] != want_images or [r["image"] for r in receipt["images"]] != want_images:
        return [*errors, "unexpected ia32 executable image/successor population"]
    for actual, trusted in zip(images, receipt["images"]):
        if any(actual[k] != trusted[k] for k in H6["IMAGE_FIELDS"]):
            errors.append("ia32 image disagrees with independently held executable/birth")
        if actual["pointer_bytes"] != 4 or actual["ck_ulong_bytes"] != 4:
            errors.append("ia32 pointer/CK_ULONG width is not four bytes")
        if actual["pid"] != receipt["pid"] or actual["start_time"] != receipt["birth"]:
            errors.append("ia32 image lost the original process/birth")
    for key in ("before", "after", "provider.so"):
        abi = receipt["abi"][key]
        if abi["elf_class"] != 32 or abi["machine"] != 3 or abi["pointer_bytes"] != 4 or abi["ck_ulong_bytes"] != 4:
            errors.append("held fixture is not ia32 ELFCLASS32 EM_386")
    before, after = receipt["provider_before"], receipt["provider_after"]
    if before != after or before["mapping"]["dev"] != before["dev"] or before["mapping"]["ino"] != before["ino"]:
        errors.append("held calibrated ia32 provider pin changed")
    targets = [r for r in ledger if r["kind"] == "target"]
    if targets != receipt["targets"] or len(targets) != len(want_images) * len(APIS):
        errors.append("missing or duplicated independent ia32 provider targets")
    for r in targets:
        if (r["dev"] != before["dev"] or r["ino"] != before["ino"]
                or not 0 < r["map_start"] <= r["vaddr"] < r["map_end"] <= 2**32
                or r["file_offset"] != r["vaddr"] - r["map_start"] + r["map_offset"]
                or r["file_offset"] != receipt["abi"]["provider.so"]["symbol_offsets"][r["fn"]]):
            errors.append("ia32 target mapping/offset/VA/64-bit inode mismatch")
    allowed = {"image", "target", "ready", "call", "ack", "held", "exec", "failed-exec"}
    for r in ledger:
        if r["kind"] not in allowed or r["image"] not in want_images or r["pid"] != receipt["pid"] or r["tid"] != receipt["pid"]:
            errors.append("foreign or unsupported ia32 ledger event/task")
        if r["kind"] in ("call", "exec") and r["scope"] != "selected":
            errors.append("ia32 observable call/exec escaped the exact selected PID population")
        for key in (("t0", "t1") if r["kind"] == "call" else ("t",)):
            if type(r[key]) is not int or not receipt["spawned_ns"] <= r[key] <= receipt["finished_ns"] <= MAX_U64:
                errors.append("ia32 truncated/wrapped/outside-lifetime timestamp")
    calls = [r for r in ledger if r["kind"] == "call"]
    pre = [r for r in calls if r["phase"] == "pre"]
    post = [r for r in calls if r["phase"] == "post"]
    held_returns = [r for r in calls if r["phase"] == "held-return"]
    warm = [r for r in calls if r["phase"].startswith("successor-")]
    setup = [r for r in calls if r["phase"] == "setup"]
    if (len(setup) != len(want_images) or [r["image"] for r in setup] != want_images
            or any(r["fn"] != "C_OpenSession" or r["rv"] != 0 or r["sess"] != 1 for r in setup)):
        errors.append("ia32 session reuse lacks actual successful C_OpenSession output handles")
    if (len(pre) != 11 or [r["rv"] for r in pre] != [0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0]
            or any(r["fn"] != "C_Initialize" or r["image"] != 0 or r["sess"] != 0 for r in pre)):
        errors.append("ia32 original stable11 RV/function population mismatch")
    if (len(post) != 17 or [r["rv"] for r in post] != [0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0, 5, 0]
            or any(r["fn"] != "C_GetSessionInfo" or r["sess"] != 1 or r["image"] != want_images[-1] for r in post)):
        errors.append("ia32 measured17 RV/session/function population mismatch")
    if len(calls) != len(pre) + len(post) + len(held_returns) + len(warm) + len(setup) or any(
            r["t0"] > r["t1"] for r in calls):
        errors.append("unexpected or inverted ia32 API call population")
    held = [r for r in ledger if r["kind"] == "held"]
    requests = [r for r in ledger if r["kind"] == "exec"]
    if len(held) != 1 or held[0] != receipt["held"] or len(requests) != 1:
        return [*errors, "ia32 exec lacks exactly one actual held provider frame/request"]
    request, frame = requests[0], held[0]
    if (frame["fn"] != "C_Initialize" or frame["image"] != 0
            or frame["vaddr"] != next(r["vaddr"] for r in targets if r["image"] == 0 and r["fn"] == "C_Initialize")
            or not pre[-1]["t1"] <= frame["t0"] <= frame["t"] <= request["t"] <= post[0]["t0"]
            or request["mode"] != "leader" or request["image"] != 0 or request["start_time"] != receipt["birth"]):
        errors.append("ia32 exec/held frame lacks authentic leader target/timestamp/birth")
    ready = [r for r in ledger if r["kind"] == "ready"]
    if len(ready) != len(want_images) or [r["image"] for r in ready] != want_images:
        errors.append("ia32 fixture readiness image population mismatch")
    failed = [r for r in ledger if r["kind"] == "failed-exec"]
    if mode == "failed":
        if (receipt["exec_transitions"] or receipt.get("successor_ready")
                or receipt.get("successor_policy", "no-transition") != "no-transition"
                or receipt.get("abandoned_expected", 0) != 0):
            errors.append("failed ia32 exec fabricated a successor/abandoned frame")
        if (len(failed) != 1 or failed[0] != receipt["failed_exec"] or failed[0]["errno"] != 2
                or request["path"] != receipt["absent_path"] or failed[0]["path"] != receipt["absent_path"]
                or len(held_returns) != 1 or held_returns[0]["rv"] != 5 or held_returns[0]["fn"] != "C_Initialize"
                or held_returns[0]["t0"] != frame["t0"]
                or not request["t"] <= failed[0]["t"] <= held_returns[0]["t1"] <= post[0]["t0"]
                or warm):
            errors.append("failed ia32 exec lost its actual ENOENT/held RV5 return/continuation")
    elif (failed or receipt["failed_exec"] or held_returns or len(receipt["exec_transitions"]) != 1
            or receipt["exec_transitions"][0]["request"] != request
            or request["path"] != images[1]["path"] or not request["t"] < images[1]["t"]
            or images[0]["ino"] == images[1]["ino"] or images[0]["path"] == images[1]["path"]):
        errors.append("successful ia32 exec lacks the distinct real successor/abandoned frame")
    if mode == "leader" and (not 1 <= len(warm) <= 20 or any(
            r["fn"] != "C_GetInfo" or r["rv"] != 0 or r["image"] != 1 for r in warm)
            or [r["phase"] for r in warm] != [f"successor-1-{i}" for i in range(1, len(warm) + 1)]):
        errors.append("ia32 successor attempts lack their exact finite real call ledger")
    return errors


def required_coverage(results):
    expected = {(cell, f"{mode}/{backend}") for cell in CELLS for mode in REQUIRED_LEGS[cell] for backend in BACKENDS}
    seen = Counter((r.get("cell"), r.get("leg")) for r in results)
    missing = sorted(expected - set(seen))
    duplicate = sorted(key for key in expected if seen[key] != 1 and seen[key])
    failed = [(r.get("cell"), r.get("leg")) for r in results
              if r.get("pass") is not True or r.get("status") != "pass"]
    extra = sorted(set(seen) - expected)
    return {"complete": not (missing or duplicate or failed or extra), "missing": missing,
            "duplicates": duplicate, "nonpositive": failed, "unexpected": extra}


def build_receipt(snapshot, mode, backend, observer_kind, observer, proof=None):
    ledger = snapshot["ledger"]
    calls = [row for row in ledger if row["kind"] == "call"]
    pre = [row for row in calls if row["phase"] == "pre"]
    post = [row for row in calls if row["phase"] == "post"]
    phases = [{"image": 0, "fn": "C_Initialize", "phase": "pre", "scope": "selected",
               "count": 11, "t0": snapshot["command_stamps"]["pre-start"], "t1": pre[-1]["t1"]}]
    if mode == "failed":
        returned = next(row for row in calls if row["phase"] == "held-return")
        phases.append({"image": 0, "fn": "C_Initialize", "phase": "held-return", "scope": "selected",
                       "count": 1, "t0": returned["t0"], "t1": returned["t1"]})
    for row in calls:
        if row["phase"].startswith("successor-"):
            phases.append({"image": 1, "fn": "C_GetInfo", "phase": row["phase"], "scope": "selected",
                           "count": 1, "t0": row["t0"], "t1": row["t1"]})
    phases.append({"image": 1 if mode == "leader" else 0, "fn": "C_GetSessionInfo", "phase": "post",
                   "scope": "selected", "count": 17, "t0": post[0]["t0"], "t1": post[-1]["t1"]})
    abandoned = int(mode == "leader")
    namespaces = {key: snapshot["images"][0][key] for key in ("pid_namespace", "time_namespace")}
    warmup = H6["warmup_receipt"](phases, post[0]["t0"])
    setup = [row for row in calls if row["phase"] == "setup"]
    warmup["expected_calls"] += len(setup)
    warmup["phases"].append("setup")
    return {**snapshot, **namespaces,
            "cell": "pid-leader" if mode == "leader" else "pid-failed-exec",
            "leg": f"{observer_kind}/{backend}", "scope_kind": "pid", "known_tids": [snapshot["pid"]],
            "owned_pids": [snapshot["pid"]], "observer_argv": list(observer["argv"]),
            "observer_started_ns": observer["started_ns"], "observer_ready_ns": observer["ready_ns"],
            "observer_stopped_ns": observer["stopped_ns"], "scope_created_ns": snapshot["spawned_ns"] - 1,
            "observer_rc": observer["rc"], "caller_rc": observer["caller_rc"],
            "observer_stderr": observer["stderr"], "privacy_canaries": [], **observer["stop"],
            "successor_policy": "public-successor" if mode == "leader" else "no-transition",
            "successor_ready": [proof] if proof is not None else [],
            "measured": {"label": "fixed17", "t0": post[0]["t0"], "t1": post[-1]["t1"],
                         "expected_calls": 17, "phases": ["post"]},
            "warmup": warmup, "phases": phases,
            "require_named": True, "require_named_images": [1] if mode == "leader" else [0],
            "first_unknown_images": [], "manual_rebind": False,
            "abandoned_expected": abandoned, "abandoned_by_fn": {"C_Initialize": 1} if abandoned else {},
            "reuse_expected": {"session": mode == "leader"},
            "session_reuse": H6["session_reuse_from"](ledger),
            "va_reuse": H6["va_reuse_from"](ledger), "requested_backend": backend}


def shared_setup_call(ledger, image):
    calls = [r for r in ledger if r["kind"] == "call" and r["image"] == 0
             and r["fn"] == "C_OpenSession"]
    if len(calls) != 1 or any(calls[0][k] != v for k, v in {
            "pid": image["pid"], "tid": image["pid"], "phase": "setup", "rv": 0, "sess": 1}.items()):
        raise ValueError("ia32 shared-key guard lacks one actual old setup return")
    return calls[0]


def shared_setup_rows(lines, image):
    rows = [row for line in lines if (row := H6["ROW"].fullmatch(line.strip()))
            and row["fn"] == "C_OpenSession"]
    for row in rows:
        unknown = row["label"] == "Unknown executable"
        if (int(row["pid"]) != image["pid"] or int(row["tid"]) != image["pid"]
                or row["rv"] != "CKR_OK" or (unknown and row["path"] is not None)
                or (not unknown and (not row["path"] or json.loads(row["path"]) != image["path"]
                                     or json.loads(row["label"]) != Path(image["path"]).name))):
            raise ValueError("ia32 shared-key return disagrees with owned old image/task/RV")
    if len(rows) > 1:
        raise ValueError("duplicate ia32 old shared-key return before exec")
    return rows


def drain_old_shared_return(driver, capture, observer, errors, cursor, started_ns):
    """X is still held: drain only the key that both generations will reuse.

    Unique C_Initialize returns may remain unobserved or arrive later. They do
    not need a cursor to identify their ledger generation. The shared setup
    return does, so a missing one must fail within the existing finite wait.
    """
    image = driver.images[0]
    call = shared_setup_call(driver.stdout.records, image)
    deadline = min(H6["wait_deadline"](10), driver.held["t0"] + 15_000_000_000)

    def verify_original():
        current = driver.pins["before"].image_receipt(image, driver.owned)
        driver.pins["provider.so"].verify()
        if any(current[key] != image[key] for key in H6["IMAGE_FIELDS"]):
            raise ValueError("ia32 old image changed before the shared-key drain")

    verify_original()
    def population():
        require_observer_live(observer, capture, errors)
        end = len(capture.lines)
        if not shared_setup_rows(capture.lines[cursor:end], image):
            return None
        return {"image": 0, "ledger_seq": call["seq"], "output_cursor": cursor,
                "output_end": end, "started_ns": started_ns,
                "observed_ns": H6["monotonic_ns"](), "deadline_ns": deadline}
    guard = H6["_output_wait"](capture, population, deadline)
    verify_original()
    return guard


def shared_key_guard_errors(text, ledger, receipt):
    """A caller ACK alone cannot authorize the public generation cursor."""
    try:
        guard = receipt["trace_shared_key_guard"]
        image = receipt["images"][0]
        call = shared_setup_call(ledger, image)
        proof, = receipt["successor_ready"]
        request, = [r for r in ledger if r["kind"] == "exec"]
        held_ack, = [r for r in ledger if r["kind"] == "ack" and r["phase"] == "held"]
        stamps = receipt["command_stamps"]
        start, end = guard["output_cursor"], guard["output_end"]
        lines = text.splitlines()
        if (guard["image"] != 0 or guard["ledger_seq"] != call["seq"]
                or type(start) is not int or type(end) is not int
                or not 0 <= start < end <= len(lines) or proof["output_cursor"] != end
                or not receipt["observer_ready_ns"] <= guard["started_ns"] <= stamps["pre-start"]
                <= call["t0"] <= call["t1"] <= receipt["held"]["t0"] <= receipt["held"]["t"]
                <= held_ack["t"] <= stamps["held-ack"] <= guard["observed_ns"]
                <= stamps["exec-start"] <= request["t"]
                or not guard["observed_ns"] < guard["deadline_ns"] <= receipt["held"]["t0"] + 15_000_000_000
                or len(shared_setup_rows(lines[start:end], image)) != 1
                or shared_setup_rows(lines[:start], image)):
            raise ValueError("ia32 shared-key drain lacks its ledger/held-X/public-cursor boundary")
    except (KeyError, TypeError, ValueError, IndexError, OverflowError) as error:
        return [f"invalid ia32 pre-exec shared-key guard: {error}"]
    return []


def evaluate_ia32(text, doc, ledger, receipt, mode, file_text=None):
    """Keep H6's positive/early-gap/naming tests; add the finite ia32 contract."""
    if receipt.get("backend_refused"):
        return {"cell": receipt.get("cell"), "leg": receipt.get("leg"), "pass": False,
                "status": "negative", "errors": ["backend refused: " + receipt["backend_refused"]]}
    workload = "failed" if receipt.get("cell") == "pid-failed-exec" else "leader"
    errors = workload_errors(ledger, receipt, workload)
    try:
        if mode not in REQUIRED_LEGS.get(receipt["cell"], ()):
            errors.append("ia32 mode/cell is not an installed required leg")
        argv = receipt["observer_argv"]
        pin = receipt["provider_before"]
        backend = receipt["requested_backend"]
        if (backend not in BACKENDS or receipt["scope_kind"] != "pid"
                or receipt["owned_pids"] != [receipt["pid"]]
                or receipt["leg"] != f"{mode}/{backend}"
                or argv[1] != ("trace" if mode == "trace" else "profile")
                or any(flag in argv for flag in ("--system", "--cgroup", "--manifest"))
                or any(arg.startswith(("--pid=", "--module=", "--attach-backend=")) for arg in argv)
                or any(argv.count(flag) != 1 for flag in ("--pid", "--module", "--attach-backend"))
                or argv[argv.index("--pid") + 1] != str(receipt["pid"])
                or argv[argv.index("--module") + 1] != pin["path"]
                or argv[argv.index("--attach-backend") + 1] != backend
                or (mode != "trace" and (argv.count("--mode") != 1 or argv[argv.index("--mode") + 1] != mode))):
            errors.append("ia32 command differs from exact requested PID/module/backend/mode")
        if receipt["measured"]["expected_calls"] != 17 or receipt["measured"]["phases"] != ["post"]:
            errors.append("ia32 measurement is not the fixed17 API population")
        for proof in receipt.get("successor_ready", []):
            if (proof["max_attempts"] != 20 or proof["deadline_ns"] - proof["started_ns"] > 15_000_000_000
                    or proof["marker_fn"] != "C_GetInfo"):
                errors.append("ia32 successor warm-up exceeded20 attempts/15seconds or changed marker")
        if mode == "trace":
            if workload == "leader":
                errors.extend(shared_key_guard_errors(text, ledger, receipt))
            result = H6["evaluate_trace_h6"](text, ledger, receipt, file_text)
            _rows, _counts, evidence, parse_errors = H6["N3_PARSE_TRACE"](text)
            errors.extend(parse_errors)
            ev = evidence[0] if len(evidence) == 1 else {}
        else:
            result = H6["evaluate_metrics_h6" if mode == "metrics" else "evaluate_profile_h6"](
                doc, text, ledger, receipt)
            ev = doc.get("evidence", {})
        observed_backend = ev.get("attach_backend", {})
        if (observed_backend.get("selection") != backend or observed_backend.get("fallback") is not None
                or observed_backend.get("scope_filter") != ("perf-task+bpf" if backend == "singles" else "kernel-pid+bpf")):
            errors.append("ia32 capture changed its requested backend/filter or installed fallback")
        if workload == "failed" and ev.get("task_uprobe_link_losses", 0) != 0:
            errors.append("failed ia32 exec induced task uprobe link loss")
        if ev.get("attach_failures"):
            errors.append("ia32 observer reports failed attachment")
    except (KeyError, TypeError, ValueError, IndexError) as error:
        result = {"cell": receipt.get("cell"), "leg": receipt.get("leg"), "errors": []}
        errors.append(f"malformed ia32 installed command/public evidence: {type(error).__name__}: {error}")
    result["errors"] = list(dict.fromkeys([*result["errors"], *errors]))
    result.update({"pass": not result["errors"], "status": "fail" if result["errors"] else "pass", "abi": "ia32"})
    return result


def require_observer_live(owned, capture, errors):
    """A final row from an ended stream cannot arm a new measurement."""
    if (owned.popen.poll() is not None or any(
            reader.errors or not reader.thread.is_alive() for reader in (capture, errors))):
        raise H6["LegCleanupError"]("ia32 observer ended or transport failed before fixed measurement")
    owned.verify()


@H6["owned_leg"](stop_b=True)
def run_leg(ctx, cell, backend, mode, directory):
    if ctx.case.cleanup_failed:
        raise H6["LegCleanupError"]("prior unsettled owned resources prevent another ia32 leg")
    directory = Path(directory)
    directory.mkdir(mode=0o755, parents=True)
    pins = {name: H6["leg_pin"](ctx, path) for name, path in ctx.fixtures.items()}
    observer_pin = H6["leg_pin"](ctx, ctx.args.binary)
    observer_metadata = observer_pin.metadata()
    if hasattr(ctx, "input_metadata"):
        for name, pin in {**pins, "observer": observer_pin}.items():
            if pin.metadata() != ctx.input_metadata[name]:
                raise ValueError("held ia32 matrix input changed before a leg")
    env = dict(os.environ)
    workload = "failed" if cell == "pid-failed-exec" else "leader"
    driver = Ia32Driver(ctx, directory, pins, workload, env)
    driver.ready()
    argv = [str(observer_pin.path), "trace" if mode == "trace" else "profile",
            "--pid", str(driver.pid), "--module", str(pins["provider.so"].path),
            "--attach-backend", backend, "--duration", "180s"]
    output = directory / ("trace.file.txt" if mode == "trace" else f"{mode}.json")
    if mode != "trace":
        argv += ["--mode", mode]
    argv += ["-o", str(output)]
    ctx.observer_start = len(ctx.owners)
    try:
        owned, capture, errors, started = H6["spawn_observer"](
            ctx.owners, ctx.readers, directory, argv, env, live=mode != "trace")
    except BaseException as error:
        ctx.case.cleanup_failed = True
        ctx.case.cleanup_errors.append(f"ia32 observer construction: {type(error).__name__}: {error}")
        raise
    ctx.observer_owned = owned
    try:
        ready = H6["observer_ready"](owned, errors, backend)
    except H6["BackendRefused"] as refused:
        # The exact H6 scope still reaps the idle caller and settles its
        # enrolled streams. A refusal is a negative result, never recovery.
        return {"cell": cell, "leg": f"{mode}/{backend}", "pass": False, "status": "negative",
                "abi": "ia32", "backend_refused": str(refused), "errors": [str(refused)]}
    shared_cursor = len(capture.lines)
    shared_started = H6["monotonic_ns"]()
    driver.start_held()
    if mode == "trace" and workload == "leader":
        driver.trace_shared_key_guard = drain_old_shared_return(
            driver, capture, owned, errors, shared_cursor, shared_started)
        cursor = driver.trace_shared_key_guard["output_end"]
    else:
        cursor = len(capture.lines) if mode == "trace" else None
    driver.do_exec()
    proof = None
    if workload == "leader":
        proof = H6["warm_successor"](capture, driver.images[1], driver.warm_attempt,
                                       mode, max_attempts=20, timeout=15, output_cursor=cursor)
    require_observer_live(owned, capture, errors)
    driver.measure()
    rc, stopped, latency = H6["stop_b_observer"](ctx, owned)
    # Caller remains alive at its F barrier and all pins remain held while
    # both observer streams reach final EOF and public files are read.
    H6["finish_readers"]([capture, errors])
    observer_pin.verify()
    if observer_pin.metadata() != observer_metadata:
        raise ValueError("held installed observer metadata changed")
    text = "".join(capture.lines)
    file_text, doc = (output.read_text(), None) if mode == "trace" else (None, json.loads(output.read_text()))
    snapshot = driver.snapshot()
    caller_rc = driver.finish()  # only after successful normal observer stop
    H6["finish_readers"]([driver.stdout, driver.stderr])
    snapshot.update(ledger=list(driver.stdout.records), finished_ns=H6["monotonic_ns"](),
                    command_stamps=dict(driver.stamps))
    observer = {"argv": argv, "started_ns": started, "ready_ns": ready, "stopped_ns": stopped,
                "rc": rc, "caller_rc": caller_rc, "stderr": "".join(errors.lines),
                "stop": H6["stop_receipt"](owned, latency)}
    receipt = build_receipt(snapshot, workload, backend, mode, observer, proof)
    result = evaluate_ia32(text, doc, snapshot["ledger"], receipt, mode, file_text)
    result.update(source_revision=ctx.args.source_revision, observer=observer_metadata)
    # One normal result is sufficient; transport files only help an active
    # failed leg. No snapshots, hash manifests or duplicate evidence bundles.
    H6["write_json"](directory / "result.json", result)
    return result


def run_selected(ctx, cells, backends, runner=run_leg):
    """Finite dispatch; an unsettled owned scope prevents every later leg."""
    results, refused = [], set()
    for cell in cells:
        for backend in backends:
            if backend in refused:
                continue
            for mode in REQUIRED_LEGS[cell]:
                if ctx.cleanup_failed:
                    return results
                directory = ctx.out / cell / backend / mode
                try:
                    result = runner(ctx, cell, backend, mode, directory)
                except (H6["SetupError"], H6["LegCleanupError"], TimeoutError, AssertionError,
                        OSError, ValueError, subprocess.SubprocessError) as error:
                    if isinstance(error, H6["LegCleanupError"]):
                        ctx.cleanup_failed = True
                    result = {"cell": cell, "leg": f"{mode}/{backend}", "pass": False,
                              "status": "error", "abi": "ia32",
                              "errors": [f"{type(error).__name__}: {error}"]}
                results.append(result)
                print(json.dumps(result), flush=True)
                if result.get("status") == "negative" and result.get("backend_refused"):
                    refused.add(backend)
                    break  # unsupported remains negative/missing; never retry or fall back
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--binary", type=Path, required=True, help="absolute installed observer binary")
    parser.add_argument("--source-revision", required=True, help="exact 40-hex source SHA from its build command")
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True, help="new directory under /var/tmp/p11scope-ws-tmp")
    parser.add_argument("--cells", default=",".join(CELLS))
    parser.add_argument("--backends", default=",".join(BACKENDS))
    args = parser.parse_args(argv)
    cells, backends = args.cells.split(","), args.backends.split(",")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_revision):
        parser.error("supply the exact 40-hex source commit from the installed binary build")
    for label, selected, supported in (("cells", cells, CELLS), ("backends", backends, BACKENDS)):
        if len(selected) != len(set(selected)):
            parser.error(f"duplicate {label} are not permitted")
        if any(name not in supported for name in selected):
            parser.error(f"supported {label}: {','.join(supported)}")
    disk = Path("/var/tmp/p11scope-ws-tmp").resolve()
    if (not args.out.is_absolute() or not args.out.resolve().is_relative_to(disk)
            or args.out.resolve() == disk):
        parser.error("output must be a new directory under /var/tmp/p11scope-ws-tmp")
    if not args.binary.is_absolute():
        parser.error("installed observer binary path must be absolute")
    if os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0:
        parser.error("live harness requires root observer and an ordinary workload uid/gid")
    if os.path.lexists(args.out) or not args.out.parent.is_dir():
        parser.error("output must be new-only with an existing disk parent")
    if not args.binary.is_file() or not os.access(args.binary, os.X_OK):
        parser.error("installed observer must be an executable regular file")
    args.out = args.out.resolve()
    args.binary = args.binary.resolve(strict=True)
    os.umask(0o022)
    args.out.mkdir(mode=0o755)
    ctx = H6["Case"](args)
    results, candidate, fixtures, interrupted = [], None, {}, None
    try:
        with H6["signal_cleanup"]():
            try:
                binary = H6["leg_pin"](ctx, args.binary)
                candidate = binary.metadata()
                ctx.fixtures = compile_fixtures(args.out / "bin")
                fixture_pins = {name: H6["leg_pin"](ctx, path) for name, path in ctx.fixtures.items()}
                fixtures = {name: pin.metadata() for name, pin in fixture_pins.items()}
                ctx.input_metadata = {**fixtures, "observer": candidate}
                # Verify all three ABI files before any native observer is
                # spawned; do not use the LP64 ctypes symbol helper here.
                for name, pin in fixture_pins.items():
                    elf32_metadata(pin, APIS if name == "provider.so" else ())
                results = run_selected(ctx, cells, backends)
            finally:
                with H6["cleanup_section"]():
                    for scope in reversed(ctx.scopes):
                        try:
                            H6["cleanup_leg_resources"](scope)
                        except H6["LegCleanupError"]:
                            pass  # exact H6 adapter retains the failure on Case
                    try:
                        H6["cleanup_leg_resources"](ctx)
                    except H6["LegCleanupError"]:
                        pass
    except H6["N3HARNESS"]["TerminationRequested"] as error:
        interrupted = error.signum
        results = list(ctx.completed_results)
        results.append({"cell": "harness", "leg": "interrupted", "pass": False,
                        "status": "error", "errors": [f"terminated by signal {error.signum}"]})
    except (H6["SetupError"], OSError, ValueError, subprocess.SubprocessError) as error:
        results.append({"cell": "harness", "leg": "setup", "pass": False, "status": "error",
                        "errors": [f"{type(error).__name__}: {error}"]})
    if ctx.cleanup_failed:
        results.append({"cell": "harness", "leg": "cleanup", "pass": False, "status": "error",
                        "errors": list(ctx.cleanup_errors)})
    coverage = required_coverage(results)
    summary = {"source_revision": args.source_revision, "candidate": candidate, "fixtures": fixtures,
               "abi": "Linux ia32 ELFCLASS32 EM_386", "kernel": os.uname().release,
               "cells": cells, "backends": backends, "legs": results,
               "required_coverage": coverage, "complete": coverage["complete"] and not ctx.cleanup_failed,
               "cleanup": {**ctx.cleanup_totals, "errors": list(ctx.cleanup_errors)}}
    H6["write_json"](args.out / "summary.json", summary)
    print(json.dumps({"complete": summary["complete"], "out": str(args.out),
                      "required_coverage": coverage}), flush=True)
    return 128 + interrupted if interrupted is not None else (0 if summary["complete"] else 1)


if __name__ == "__main__":
    raise SystemExit(main())
